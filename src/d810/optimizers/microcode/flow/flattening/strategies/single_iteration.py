"""Shared helpers and engine strategy wrapper for single-iteration loop cleanup."""
from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass

from d810.cfg.flowgraph import FlowGraph
from d810.cfg.graph_modification import GraphModification, RedirectGoto
from d810.core.typing import TYPE_CHECKING
from d810.optimizers.microcode.flow.flattening.engine.strategy import (
    FAMILY_CLEANUP,
    BenefitMetrics,
    OwnershipScope,
    PlanFragment,
)
from d810.recon.flow.loop_prover import prove_single_iteration

if TYPE_CHECKING:
    from d810.optimizers.microcode.flow.flattening.engine.snapshot import (
        AnalysisSnapshot,
    )


SINGLE_ITERATION_FIXES_METADATA_KEY = "single_iteration_fixes"
DEFAULT_MIN_MAGIC = 0x1000
DEFAULT_MAX_MAGIC = 0xFFFFFFFF


@dataclass(frozen=True)
class SingleIterationPredFix:
    """Validated per-predecessor redirect around a single-iteration loop header."""

    loop_header: int
    pred_block: int
    new_target: int


def _is_magic_constant(
    value: int | None,
    *,
    min_magic: int = DEFAULT_MIN_MAGIC,
    max_magic: int = DEFAULT_MAX_MAGIC,
) -> bool:
    if value is None:
        return False
    unsigned_value = value & 0xFFFFFFFF
    return min_magic <= unsigned_value <= max_magic


def _coerce_single_iteration_fixes(raw: object) -> dict[int, dict[int, int]]:
    if not isinstance(raw, Mapping):
        return {}

    fixes: dict[int, dict[int, int]] = {}
    for loop_header, pred_map in raw.items():
        try:
            loop_header_int = int(loop_header)
        except (TypeError, ValueError):
            continue
        if not isinstance(pred_map, Mapping):
            continue

        coerced_pred_map: dict[int, int] = {}
        for pred_block, new_target in pred_map.items():
            try:
                coerced_pred_map[int(pred_block)] = int(new_target)
            except (TypeError, ValueError):
                continue
        if coerced_pred_map:
            fixes[loop_header_int] = coerced_pred_map
    return fixes


def _is_valid_single_iteration_fix(
    cfg: FlowGraph,
    fix: SingleIterationPredFix,
) -> bool:
    loop_header = cfg.blocks.get(fix.loop_header)
    pred_block = cfg.blocks.get(fix.pred_block)
    target_block = cfg.blocks.get(fix.new_target)

    if loop_header is None or pred_block is None or target_block is None:
        return False
    if pred_block.nsucc != 1:
        return False
    if pred_block.succs[0] != fix.loop_header:
        return False
    if fix.new_target == fix.pred_block:
        return False
    if fix.new_target not in loop_header.succs:
        return False
    return True


def _normalize_single_iteration_fixes(
    cfg: FlowGraph,
    raw: object,
) -> tuple[SingleIterationPredFix, ...]:
    fixes_by_key: dict[tuple[int, int], SingleIterationPredFix] = {}
    conflicts: set[tuple[int, int]] = set()

    for loop_header, pred_map in _coerce_single_iteration_fixes(raw).items():
        for pred_block, new_target in pred_map.items():
            fix = SingleIterationPredFix(
                loop_header=loop_header,
                pred_block=pred_block,
                new_target=new_target,
            )
            if not _is_valid_single_iteration_fix(cfg, fix):
                continue

            key = (fix.loop_header, fix.pred_block)
            previous = fixes_by_key.get(key)
            if previous is None:
                fixes_by_key[key] = fix
                continue
            if previous.new_target != fix.new_target:
                conflicts.add(key)

    for key in conflicts:
        fixes_by_key.pop(key, None)

    return tuple(fixes_by_key[key] for key in sorted(fixes_by_key))


def _serialize_single_iteration_fixes(
    fixes: Sequence[SingleIterationPredFix],
) -> dict[int, dict[int, int]]:
    serialized: dict[int, dict[int, int]] = {}
    for fix in fixes:
        serialized.setdefault(fix.loop_header, {})[fix.pred_block] = fix.new_target
    return serialized


def serialize_single_iteration_fixes(
    fixes: Sequence[SingleIterationPredFix],
) -> dict[int, dict[int, int]]:
    """Serialize per-predecessor single-iteration redirects into metadata."""
    return _serialize_single_iteration_fixes(fixes)


def extract_single_iteration_fixes(
    flow_graph: FlowGraph | None,
) -> tuple[SingleIterationPredFix, ...]:
    """Read validated single-iteration redirects from FlowGraph metadata."""
    if flow_graph is None:
        return ()
    return _normalize_single_iteration_fixes(
        flow_graph,
        flow_graph.metadata.get(SINGLE_ITERATION_FIXES_METADATA_KEY),
    )


def build_single_iteration_modifications(
    fixes: Sequence[SingleIterationPredFix],
) -> list[RedirectGoto]:
    """Translate validated single-iteration redirects into RedirectGoto edits."""
    return [
        RedirectGoto(
            from_serial=fix.pred_block,
            old_target=fix.loop_header,
            new_target=fix.new_target,
        )
        for fix in fixes
    ]


def _get_jnz_comparison_info(blk: object) -> tuple[object | None, int | None]:
    import ida_hexrays

    if blk is None or blk.tail is None:
        return None, None
    if blk.tail.opcode != ida_hexrays.m_jnz:
        return None, None

    if blk.tail.r and blk.tail.r.t == ida_hexrays.mop_n:
        return blk.tail.l, blk.tail.r.signed_value()
    if blk.tail.l and blk.tail.l.t == ida_hexrays.mop_n:
        return blk.tail.r, blk.tail.l.signed_value()
    return None, None


def _find_live_state_assignment(blk: object, state_mop: object) -> int | None:
    import ida_hexrays

    if blk is None or state_mop is None:
        return None

    insn = blk.tail
    while insn:
        if insn.opcode == ida_hexrays.m_mov:
            if insn.d and insn.d.equal_mops(state_mop, ida_hexrays.EQ_IGNSIZE):
                if insn.l and insn.l.t == ida_hexrays.mop_n:
                    return insn.l.signed_value()
        insn = insn.prev
    return None


def _get_conditional_targets(blk: object) -> tuple[int | None, int | None]:
    if blk is None or blk.tail is None or not hasattr(blk, "succset"):
        return None, None

    taken_target = getattr(getattr(blk.tail, "d", None), "b", None)
    if taken_target is None:
        return None, None

    successors = tuple(int(serial) for serial in getattr(blk, "succset", ()))
    fallthrough_candidates = tuple(
        serial for serial in successors if serial != int(taken_target)
    )
    if len(fallthrough_candidates) != 1:
        return None, None
    return int(taken_target), int(fallthrough_candidates[0])


def collect_live_single_iteration_block_fixes(
    blk: object,
    *,
    logger: object | None = None,
    min_magic: int = DEFAULT_MIN_MAGIC,
    max_magic: int = DEFAULT_MAX_MAGIC,
) -> tuple[SingleIterationPredFix, ...]:
    """Analyze one live loop header and derive proven single-iteration redirects."""
    state_mop, check_const = _get_jnz_comparison_info(blk)
    if state_mop is None or not _is_magic_constant(
        check_const,
        min_magic=min_magic,
        max_magic=max_magic,
    ):
        return ()

    taken_target, fallthrough_target = _get_conditional_targets(blk)
    if taken_target is None or fallthrough_target is None:
        return ()

    preds = tuple(int(serial) for serial in getattr(blk, "predset", ()))
    succs = set(int(serial) for serial in getattr(blk, "succset", ()))
    backedge_preds = tuple(pred for pred in preds if pred in succs)
    if not backedge_preds:
        return ()

    entry_preds = tuple(pred for pred in preds if pred not in succs)
    if not entry_preds:
        return ()

    fixes_by_key: dict[tuple[int, int], SingleIterationPredFix] = {}
    conflicts: set[tuple[int, int]] = set()

    for backedge_pred in backedge_preds:
        backedge_blk = blk.mba.get_mblock(backedge_pred)
        if backedge_blk is None or backedge_blk.nsucc() != 1:
            continue
        if int(backedge_blk.succ(0)) != int(blk.serial):
            continue

        update_const = _find_live_state_assignment(backedge_blk, state_mop)
        if not _is_magic_constant(
            update_const,
            min_magic=min_magic,
            max_magic=max_magic,
        ):
            continue

        for entry_pred in entry_preds:
            entry_blk = blk.mba.get_mblock(entry_pred)
            if entry_blk is None or entry_blk.nsucc() != 1:
                continue
            if int(entry_blk.succ(0)) != int(blk.serial):
                continue

            init_const = _find_live_state_assignment(entry_blk, state_mop)
            if not _is_magic_constant(
                init_const,
                min_magic=min_magic,
                max_magic=max_magic,
            ):
                continue

            if not prove_single_iteration(init_const, check_const, update_const):
                continue

            if logger is not None:
                logger.info(
                    "Detected single-iteration loop at block %d: init=0x%X, check=0x%X, update=0x%X",
                    int(blk.serial),
                    int(init_const),
                    int(check_const),
                    int(update_const),
                )

            for pred_block, new_target in (
                (int(entry_pred), int(fallthrough_target)),
                (int(backedge_pred), int(taken_target)),
            ):
                key = (int(blk.serial), pred_block)
                fix = SingleIterationPredFix(
                    loop_header=int(blk.serial),
                    pred_block=pred_block,
                    new_target=new_target,
                )
                existing = fixes_by_key.get(key)
                if existing is None:
                    fixes_by_key[key] = fix
                    continue
                if existing.new_target != new_target:
                    conflicts.add(key)

    for key in conflicts:
        fixes_by_key.pop(key, None)

    return tuple(fixes_by_key[key] for key in sorted(fixes_by_key))


def collect_live_single_iteration_fixes(
    mba: object,
    *,
    logger: object | None = None,
    min_magic: int = DEFAULT_MIN_MAGIC,
    max_magic: int = DEFAULT_MAX_MAGIC,
    allowed_maturities: Sequence[int] | None = None,
) -> tuple[SingleIterationPredFix, ...]:
    """Derive validated single-iteration redirects from a live mba."""
    if mba is None:
        return ()

    maturity = getattr(mba, "maturity", None)
    if allowed_maturities is not None and maturity not in set(allowed_maturities):
        return ()

    fixes_by_key: dict[tuple[int, int], SingleIterationPredFix] = {}
    conflicts: set[tuple[int, int]] = set()

    qty = int(getattr(mba, "qty", 0))
    for serial in range(qty):
        blk = mba.get_mblock(serial)
        for fix in collect_live_single_iteration_block_fixes(
            blk,
            logger=logger,
            min_magic=min_magic,
            max_magic=max_magic,
        ):
            key = (fix.loop_header, fix.pred_block)
            existing = fixes_by_key.get(key)
            if existing is None:
                fixes_by_key[key] = fix
                continue
            if existing.new_target != fix.new_target:
                conflicts.add(key)

    for key in conflicts:
        fixes_by_key.pop(key, None)

    return tuple(fixes_by_key[key] for key in sorted(fixes_by_key))


def _build_ownership(modifications: Sequence[GraphModification]) -> OwnershipScope:
    blocks: set[int] = set()
    edges: set[tuple[int, int]] = set()

    for mod in modifications:
        if isinstance(mod, RedirectGoto):
            blocks.add(mod.from_serial)
            edges.add((mod.from_serial, mod.old_target))

    return OwnershipScope(
        blocks=frozenset(blocks),
        edges=frozenset(edges),
        transitions=frozenset(),
    )


class SingleIterationStrategy:
    """Engine strategy wrapper for validated single-iteration loop redirects."""

    name = "single_iteration"
    family = FAMILY_CLEANUP

    def is_applicable(self, snapshot: AnalysisSnapshot) -> bool:
        return bool(extract_single_iteration_fixes(snapshot.flow_graph))

    def plan(self, snapshot: AnalysisSnapshot) -> PlanFragment | None:
        fixes = extract_single_iteration_fixes(snapshot.flow_graph)
        if not fixes:
            return None

        modifications = build_single_iteration_modifications(fixes)
        if not modifications:
            return None

        return PlanFragment(
            strategy_name=self.name,
            family=self.family,
            ownership=_build_ownership(modifications),
            prerequisites=[],
            expected_benefit=BenefitMetrics(
                handlers_resolved=0,
                transitions_resolved=0,
                blocks_freed=len(modifications),
                conflict_density=0.0,
            ),
            risk_score=0.1,
            metadata={
                SINGLE_ITERATION_FIXES_METADATA_KEY: _serialize_single_iteration_fixes(
                    fixes
                ),
                "safeguard_min_required": 1,
            },
            modifications=list(modifications),
        )


__all__ = [
    "DEFAULT_MAX_MAGIC",
    "DEFAULT_MIN_MAGIC",
    "SINGLE_ITERATION_FIXES_METADATA_KEY",
    "SingleIterationPredFix",
    "SingleIterationStrategy",
    "build_single_iteration_modifications",
    "collect_live_single_iteration_block_fixes",
    "collect_live_single_iteration_fixes",
    "extract_single_iteration_fixes",
    "serialize_single_iteration_fixes",
]
