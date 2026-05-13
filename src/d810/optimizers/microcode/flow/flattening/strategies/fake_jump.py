"""Shared helpers and engine strategy wrapper for fake-jump cleanup."""
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

if TYPE_CHECKING:
    from d810.optimizers.microcode.flow.flattening.engine.snapshot import (
        AnalysisSnapshot,
    )

FAKE_JUMP_FIXES_METADATA_KEY = "fake_jump_fixes"


@dataclass(frozen=True)
class FakeJumpResolution:
    """Decision for one fake-jump predecessor."""

    new_target: int | None
    always_taken: bool = False
    always_not_taken: bool = False


@dataclass(frozen=True)
class FakeJumpPredFix:
    """Validated per-predecessor redirect around a fake-jump block."""

    fake_block: int
    pred_block: int
    new_target: int


def should_skip_fake_jump_predecessor(
    resolved_count: int,
    unresolved_count: int,
) -> bool:
    """Return True when unresolved histories make the fix unsafe."""
    if resolved_count <= 0:
        return True
    return resolved_count < 3 and unresolved_count > 10 * resolved_count


def resolve_fake_jump_target(
    *,
    opcode: int,
    compared_value: int,
    pred_comparison_values: Sequence[int],
    taken_target: int,
    fallthrough_target: int,
    jz_opcode: int,
    jnz_opcode: int,
) -> FakeJumpResolution:
    """Resolve the deterministic target for a fake conditional jump."""
    if not pred_comparison_values:
        return FakeJumpResolution(new_target=None)

    if opcode == jz_opcode:
        always_taken = all(
            value == compared_value for value in pred_comparison_values
        )
        always_not_taken = all(
            value != compared_value for value in pred_comparison_values
        )
    elif opcode == jnz_opcode:
        always_taken = all(
            value != compared_value for value in pred_comparison_values
        )
        always_not_taken = all(
            value == compared_value for value in pred_comparison_values
        )
    else:
        return FakeJumpResolution(new_target=None)

    if always_taken:
        return FakeJumpResolution(
            new_target=taken_target,
            always_taken=True,
            always_not_taken=False,
        )
    if always_not_taken:
        return FakeJumpResolution(
            new_target=fallthrough_target,
            always_taken=False,
            always_not_taken=True,
        )
    return FakeJumpResolution(new_target=None)


def _coerce_fake_jump_fixes(raw: object) -> dict[int, dict[int, int]]:
    if not isinstance(raw, Mapping):
        return {}

    fixes: dict[int, dict[int, int]] = {}
    for fake_block, pred_map in raw.items():
        try:
            fake_block_int = int(fake_block)
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
            fixes[fake_block_int] = coerced_pred_map
    return fixes


def _is_valid_fake_jump_fix(cfg: FlowGraph, fix: FakeJumpPredFix) -> bool:
    fake_block = cfg.blocks.get(fix.fake_block)
    pred_block = cfg.blocks.get(fix.pred_block)
    target_block = cfg.blocks.get(fix.new_target)

    if fake_block is None or pred_block is None or target_block is None:
        return False
    if fix.pred_block == cfg.entry_serial:
        return False
    if fix.new_target == fix.pred_block:
        return False
    if pred_block.nsucc != 1:
        return False
    if pred_block.succs[0] != fix.fake_block:
        return False
    if fix.new_target not in fake_block.succs:
        return False
    return True


def _normalize_fake_jump_fixes(
    cfg: FlowGraph,
    raw: object,
) -> tuple[FakeJumpPredFix, ...]:
    fixes: list[FakeJumpPredFix] = []
    for fake_block, pred_map in _coerce_fake_jump_fixes(raw).items():
        for pred_block, new_target in pred_map.items():
            fix = FakeJumpPredFix(
                fake_block=fake_block,
                pred_block=pred_block,
                new_target=new_target,
            )
            if _is_valid_fake_jump_fix(cfg, fix):
                fixes.append(fix)
    return tuple(fixes)


def _serialize_fake_jump_fixes(
    fixes: Sequence[FakeJumpPredFix],
) -> dict[int, dict[int, int]]:
    serialized: dict[int, dict[int, int]] = {}
    for fix in fixes:
        serialized.setdefault(fix.fake_block, {})[fix.pred_block] = fix.new_target
    return serialized


def serialize_fake_jump_fixes(
    fixes: Sequence[FakeJumpPredFix],
) -> dict[int, dict[int, int]]:
    """Serialize per-predecessor fixes into FlowGraph metadata payload."""
    return _serialize_fake_jump_fixes(fixes)


def extract_fake_jump_fixes(
    flow_graph: FlowGraph | None,
) -> tuple[FakeJumpPredFix, ...]:
    """Read validated per-predecessor fake-jump fixes from FlowGraph metadata."""
    if flow_graph is None:
        return ()
    return _normalize_fake_jump_fixes(
        flow_graph,
        flow_graph.metadata.get(FAKE_JUMP_FIXES_METADATA_KEY),
    )


def build_fake_jump_modifications(
    fixes: Sequence[FakeJumpPredFix],
) -> list[RedirectGoto]:
    """Translate validated per-predecessor fixes into RedirectGoto edits."""
    return [
        RedirectGoto(
            from_serial=fix.pred_block,
            old_target=fix.fake_block,
            new_target=fix.new_target,
        )
        for fix in fixes
    ]


def collect_live_fake_jump_block_fixes(
    blk: object,
    *,
    logger: object | None = None,
    max_nb_block: int = 100,
    max_path: int = 1000,
) -> tuple[FakeJumpPredFix, ...]:
    """Analyze one live mblock and derive deterministic per-predecessor fixes."""
    import ida_hexrays

    from d810.evaluator.hexrays_microcode.tracker import (
        MopTracker,
        get_all_possibles_values,
    )
    from d810.hexrays.utils.hexrays_formatters import format_minsn_t

    if blk is None or blk.tail is None:
        return ()
    if blk.tail.opcode not in (ida_hexrays.m_jz, ida_hexrays.m_jnz):
        return ()
    if blk.get_reginsn_qty() != 1:
        return ()
    if blk.tail.r.t != ida_hexrays.mop_n:
        return ()
    if blk.nextb is None:
        return ()

    if logger is not None:
        logger.info(
            "Checking if block %s is fake loop: %s",
            blk.serial,
            format_minsn_t(blk.tail),
        )

    op_compared = ida_hexrays.mop_t(blk.tail.l)
    fixes: list[FakeJumpPredFix] = []

    for pred_serial in list(blk.predset):
        pred_blk = blk.mba.get_mblock(pred_serial)
        if pred_blk is None or pred_blk.tail is None:
            continue

        cmp_variable_tracker = MopTracker(
            [op_compared],
            max_nb_block=max_nb_block,
            max_path=max_path,
        )
        cmp_variable_tracker.reset()
        pred_histories = cmp_variable_tracker.search_backward(
            pred_blk,
            pred_blk.tail,
        )

        resolved_histories = [h for h in pred_histories if h.is_resolved()]
        unresolved_count = len(pred_histories) - len(resolved_histories)

        if len(resolved_histories) == 0:
            if logger is not None:
                logger.debug(
                    "No resolved histories for pred %s, skipping",
                    pred_serial,
                )
            continue

        if should_skip_fake_jump_predecessor(
            len(resolved_histories),
            unresolved_count,
        ):
            if logger is not None:
                logger.warning(
                    "Pred %s has extreme unresolved:resolved ratio (%d vs %d) with few resolved - "
                    "unsafe to ignore unresolved, skipping",
                    pred_serial,
                    unresolved_count,
                    len(resolved_histories),
                )
            continue

        if unresolved_count > 0 and logger is not None:
            logger.debug(
                "Pred %s has %d unresolved and %d resolved paths - using resolved only",
                pred_serial,
                unresolved_count,
                len(resolved_histories),
            )

        pred_values = get_all_possibles_values(resolved_histories, [op_compared])
        pred_values = [value[0] for value in pred_values]
        if None in pred_values:
            if logger is not None:
                logger.info("Some path are not resolved, can't fix jump")
            return ()

        if logger is not None:
            logger.info(
                "Pred %s has %s possible path (%s different cst): %s",
                pred_blk.serial,
                len(pred_values),
                len(set(pred_values)),
                pred_values,
            )

        resolution = resolve_fake_jump_target(
            opcode=blk.tail.opcode,
            compared_value=blk.tail.r.nnn.value,
            pred_comparison_values=pred_values,
            taken_target=blk.tail.d.b,
            fallthrough_target=blk.nextb.serial,
            jz_opcode=ida_hexrays.m_jz,
            jnz_opcode=ida_hexrays.m_jnz,
        )
        if resolution.new_target is None:
            if logger is not None:
                logger.debug(
                    "Jump seems legit '%s' from %s: %s",
                    format_minsn_t(blk.tail),
                    pred_blk.serial,
                    pred_values,
                )
            continue

        fixes.append(
            FakeJumpPredFix(
                fake_block=int(blk.serial),
                pred_block=int(pred_blk.serial),
                new_target=int(resolution.new_target),
            )
        )

    return tuple(fixes)


def collect_live_fake_jump_fixes(
    mba: object,
    *,
    logger: object | None = None,
    max_nb_block: int = 100,
    max_path: int = 1000,
    allowed_maturities: Sequence[int] | None = None,
) -> tuple[FakeJumpPredFix, ...]:
    """Derive validated FakeJump fixes from a live mba without mutating it."""
    if mba is None:
        return ()

    maturity = getattr(mba, "maturity", None)
    if allowed_maturities is not None and maturity not in set(allowed_maturities):
        return ()

    fixes: list[FakeJumpPredFix] = []
    qty = int(getattr(mba, "qty", 0))
    for serial in range(qty):
        blk = mba.get_mblock(serial)
        fixes.extend(
            collect_live_fake_jump_block_fixes(
                blk,
                logger=logger,
                max_nb_block=max_nb_block,
                max_path=max_path,
            )
        )
    return tuple(fixes)


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


class FakeJumpStrategy:
    """Engine strategy wrapper for validated per-predecessor fake-jump redirects."""

    name = "fake_jump"
    family = FAMILY_CLEANUP

    def is_applicable(self, snapshot: AnalysisSnapshot) -> bool:
        return bool(extract_fake_jump_fixes(snapshot.flow_graph))

    def plan(self, snapshot: AnalysisSnapshot) -> PlanFragment | None:
        fixes = extract_fake_jump_fixes(snapshot.flow_graph)
        if not fixes:
            return None

        modifications = build_fake_jump_modifications(fixes)
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
                FAKE_JUMP_FIXES_METADATA_KEY: _serialize_fake_jump_fixes(fixes),
                "safeguard_min_required": 1,
            },
            modifications=list(modifications),
        )


__all__ = [
    "FAKE_JUMP_FIXES_METADATA_KEY",
    "FakeJumpPredFix",
    "FakeJumpResolution",
    "FakeJumpStrategy",
    "build_fake_jump_modifications",
    "collect_live_fake_jump_block_fixes",
    "collect_live_fake_jump_fixes",
    "extract_fake_jump_fixes",
    "resolve_fake_jump_target",
    "serialize_fake_jump_fixes",
    "should_skip_fake_jump_predecessor",
]
