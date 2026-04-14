"""Engine strategy for the extracted emulated-dispatcher family path."""
from __future__ import annotations

from dataclasses import dataclass

from d810.cfg.flowgraph import FlowGraph
from d810.cfg.graph_modification import (
    ConvertToGoto,
    GraphModification,
    InsertBlock,
    RedirectGoto,
)
from d810.optimizers.microcode.flow.flattening.engine.strategy import (
    FAMILY_FALLBACK,
    BenefitMetrics,
    OwnershipScope,
    PlanFragment,
)
from d810.core.typing import cast


EMULATED_DISPATCHER_METADATA_KEY = "emulated_dispatcher"
EMULATED_DISPATCHER_MODIFICATIONS_KEY = "emulated_dispatcher_modifications"


@dataclass(frozen=True)
class EmulatedDispatcherMetadata:
    """Detection + enrichment summary for the current dispatcher-emulation pass."""

    dispatcher_shape: str = "none"
    state_transport: str = "none"
    lowering_mode: str = "none"
    provenance_hints: tuple[str, ...] = ()
    analysis_dispatchers: tuple[int, ...] = ()
    state_constants: tuple[int, ...] = ()
    collector_dispatchers: tuple[int, ...] = ()
    planning_ready: bool = False
    planning_blocker: str | None = None
    candidate_count: int = 0
    rejected_fathers: int = 0
    candidate_kinds: tuple[str, ...] = ()
    rejection_reasons: tuple[str, ...] = ()

    @property
    def detected(self) -> bool:
        return bool(self.analysis_dispatchers or self.collector_dispatchers)


def extract_emulated_dispatcher_metadata(
    flow_graph,
) -> EmulatedDispatcherMetadata | None:
    """Return typed emulated-dispatcher metadata from a FlowGraph snapshot."""
    if flow_graph is None:
        return None
    metadata = getattr(flow_graph, "metadata", {}) or {}
    item = metadata.get(EMULATED_DISPATCHER_METADATA_KEY)
    if isinstance(item, EmulatedDispatcherMetadata):
        return item
    return None


def _coerce_emulated_dispatcher_modifications(
    raw: object,
) -> tuple[GraphModification, ...]:
    if not isinstance(raw, tuple):
        return ()
    allowed = (RedirectGoto, ConvertToGoto, InsertBlock)
    items: list[GraphModification] = []
    for item in raw:
        if isinstance(item, allowed):
            items.append(cast(GraphModification, item))
    return tuple(items)


def extract_emulated_dispatcher_modifications(
    flow_graph: FlowGraph | None,
) -> tuple[GraphModification, ...]:
    """Return validated dispatcher-emulation lowering candidates."""
    if flow_graph is None:
        return ()
    return _normalize_emulated_dispatcher_modifications(
        flow_graph,
        _coerce_emulated_dispatcher_modifications(
            flow_graph.metadata.get(EMULATED_DISPATCHER_MODIFICATIONS_KEY)
        ),
    )


def _is_valid_emulated_dispatcher_modification(
    cfg: FlowGraph,
    mod: GraphModification,
) -> bool:
    match mod:
        case RedirectGoto(from_serial=src, new_target=dst):
            return src in cfg.blocks and dst in cfg.blocks and src != dst
        case ConvertToGoto(block_serial=src, goto_target=dst):
            return src in cfg.blocks and dst in cfg.blocks and src != dst
        case InsertBlock(pred_serial=pred, succ_serial=succ, instructions=insns):
            return (
                pred in cfg.blocks
                and succ in cfg.blocks
                and pred != succ
                and len(insns) > 0
            )
        case _:
            return False


def _normalize_emulated_dispatcher_modifications(
    cfg: FlowGraph,
    raw: tuple[GraphModification, ...],
) -> tuple[GraphModification, ...]:
    return tuple(mod for mod in raw if _is_valid_emulated_dispatcher_modification(cfg, mod))


def _build_ownership(
    modifications: tuple[GraphModification, ...],
) -> OwnershipScope:
    blocks: set[int] = set()
    edges: set[tuple[int, int]] = set()
    for mod in modifications:
        match mod:
            case RedirectGoto(from_serial=src, old_target=old, new_target=new):
                blocks.add(src)
                edges.add((src, old))
                edges.add((src, new))
            case ConvertToGoto(block_serial=src, goto_target=dst):
                blocks.add(src)
                edges.add((src, dst))
            case InsertBlock(pred_serial=pred, succ_serial=succ):
                blocks.add(pred)
                edges.add((pred, succ))
    return OwnershipScope(
        blocks=frozenset(blocks),
        edges=frozenset(edges),
        transitions=frozenset(),
    )


class EmulatedDispatcherStrategy:
    """Planner-visible lowering strategy for emulated-dispatcher families."""

    name = "emulated_dispatcher"
    family = FAMILY_FALLBACK

    def is_applicable(self, snapshot) -> bool:
        observation = extract_emulated_dispatcher_metadata(snapshot.flow_graph)
        if observation is None or not observation.detected or not observation.planning_ready:
            return False
        return bool(extract_emulated_dispatcher_modifications(snapshot.flow_graph))

    def plan(self, snapshot):
        observation = extract_emulated_dispatcher_metadata(snapshot.flow_graph)
        if observation is None or not observation.planning_ready:
            return None
        modifications = extract_emulated_dispatcher_modifications(snapshot.flow_graph)
        if not modifications:
            return None
        inserted_side_effects = sum(
            1 for mod in modifications if isinstance(mod, InsertBlock)
        )
        return PlanFragment(
            strategy_name=self.name,
            family=self.family,
            ownership=_build_ownership(modifications),
            prerequisites=[],
            expected_benefit=BenefitMetrics(
                handlers_resolved=max(1, len(modifications)),
                transitions_resolved=max(1, len(modifications)),
                blocks_freed=0,
                conflict_density=0.0,
            ),
            risk_score=min(0.65, 0.45 + (0.1 * inserted_side_effects)),
            metadata={
                "safeguard_profile": "engine",
                "safeguard_min_required": 1,
            },
            modifications=list(modifications),
        )


__all__ = [
    "EMULATED_DISPATCHER_METADATA_KEY",
    "EMULATED_DISPATCHER_MODIFICATIONS_KEY",
    "EmulatedDispatcherMetadata",
    "EmulatedDispatcherStrategy",
    "extract_emulated_dispatcher_metadata",
    "extract_emulated_dispatcher_modifications",
]
