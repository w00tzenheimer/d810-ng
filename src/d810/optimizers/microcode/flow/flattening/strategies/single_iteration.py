"""Shared helpers and engine strategy wrapper for single-iteration loop cleanup."""
from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass

from d810.cfg.flowgraph import FlowGraph
from d810.transforms.graph_modification import ConvertToGoto, GraphModification, RedirectGoto
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


SINGLE_ITERATION_FIXES_METADATA_KEY = "single_iteration_fixes"
SINGLE_ITERATION_CONVERTS_METADATA_KEY = "single_iteration_converts"
DEFAULT_MIN_MAGIC = 0x1000
DEFAULT_MAX_MAGIC = 0xFFFFFFFF


@dataclass(frozen=True)
class SingleIterationPredFix:
    """Validated per-predecessor redirect around a single-iteration loop header."""

    loop_header: int
    pred_block: int
    new_target: int


@dataclass(frozen=True)
class SingleIterationConvertFix:
    """Validated conversion of a self-loop equality header to a goto."""

    loop_header: int
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


def _coerce_single_iteration_converts(raw: object) -> dict[int, int]:
    if not isinstance(raw, Mapping):
        return {}

    converts: dict[int, int] = {}
    for loop_header, new_target in raw.items():
        try:
            converts[int(loop_header)] = int(new_target)
        except (TypeError, ValueError):
            continue
    return converts


def _is_valid_single_iteration_convert(
    cfg: FlowGraph,
    fix: SingleIterationConvertFix,
) -> bool:
    loop_header = cfg.blocks.get(fix.loop_header)
    target_block = cfg.blocks.get(fix.new_target)

    if loop_header is None or target_block is None:
        return False
    if loop_header.nsucc != 2:
        return False
    if fix.new_target == fix.loop_header:
        return False
    if fix.new_target not in loop_header.succs:
        return False
    return True


def _serialize_single_iteration_converts(
    fixes: Sequence[SingleIterationConvertFix],
) -> dict[int, int]:
    return {
        int(fix.loop_header): int(fix.new_target)
        for fix in sorted(
            fixes,
            key=lambda fix: (int(fix.loop_header), int(fix.new_target)),
        )
    }


def serialize_single_iteration_converts(
    fixes: Sequence[SingleIterationConvertFix],
) -> dict[int, int]:
    """Serialize single-iteration header conversions into metadata."""
    return _serialize_single_iteration_converts(fixes)


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


def extract_single_iteration_converts(
    flow_graph: FlowGraph | None,
) -> tuple[SingleIterationConvertFix, ...]:
    """Read validated single-iteration header conversions from metadata."""
    if flow_graph is None:
        return ()

    fixes = tuple(
        SingleIterationConvertFix(loop_header=loop_header, new_target=new_target)
        for loop_header, new_target in _coerce_single_iteration_converts(
            flow_graph.metadata.get(SINGLE_ITERATION_CONVERTS_METADATA_KEY)
        ).items()
    )
    return tuple(
        fix
        for fix in sorted(fixes, key=lambda fix: (fix.loop_header, fix.new_target))
        if _is_valid_single_iteration_convert(flow_graph, fix)
    )


def build_single_iteration_modifications(
    fixes: Sequence[SingleIterationPredFix],
    converts: Sequence[SingleIterationConvertFix] = (),
) -> list[GraphModification]:
    """Translate validated single-iteration evidence into graph edits."""
    modifications: list[GraphModification] = [
        RedirectGoto(
            from_serial=fix.pred_block,
            old_target=fix.loop_header,
            new_target=fix.new_target,
        )
        for fix in fixes
    ]
    modifications.extend(
        ConvertToGoto(
            block_serial=fix.loop_header,
            goto_target=fix.new_target,
        )
        for fix in converts
    )
    return modifications


def _build_ownership(modifications: Sequence[GraphModification]) -> OwnershipScope:
    blocks: set[int] = set()
    edges: set[tuple[int, int]] = set()

    for mod in modifications:
        if isinstance(mod, RedirectGoto):
            blocks.add(mod.from_serial)
            edges.add((mod.from_serial, mod.old_target))
        elif isinstance(mod, ConvertToGoto):
            blocks.add(mod.block_serial)

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
        return bool(
            extract_single_iteration_fixes(snapshot.flow_graph)
            or extract_single_iteration_converts(snapshot.flow_graph)
        )

    def plan(self, snapshot: AnalysisSnapshot) -> PlanFragment | None:
        fixes = extract_single_iteration_fixes(snapshot.flow_graph)
        converts = extract_single_iteration_converts(snapshot.flow_graph)
        if not fixes and not converts:
            return None

        modifications = build_single_iteration_modifications(fixes, converts)
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
                SINGLE_ITERATION_CONVERTS_METADATA_KEY: (
                    _serialize_single_iteration_converts(converts)
                ),
                "safeguard_min_required": 1,
            },
            modifications=list(modifications),
        )


__all__ = [
    "DEFAULT_MAX_MAGIC",
    "DEFAULT_MIN_MAGIC",
    "SINGLE_ITERATION_CONVERTS_METADATA_KEY",
    "SINGLE_ITERATION_FIXES_METADATA_KEY",
    "SingleIterationConvertFix",
    "SingleIterationPredFix",
    "SingleIterationStrategy",
    "build_single_iteration_modifications",
    "extract_single_iteration_converts",
    "extract_single_iteration_fixes",
    "serialize_single_iteration_converts",
    "serialize_single_iteration_fixes",
]
