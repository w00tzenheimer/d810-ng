"""Engine strategy for the extracted emulated-dispatcher family path."""
from __future__ import annotations

from dataclasses import dataclass

from d810.cfg.mod_claims import collect_mod_claims
from d810.cfg.flowgraph import FlowGraph
from d810.cfg.graph_modification import (
    CreateConditionalRedirect,
    ConvertToGoto,
    DirectTerminalLoweringGroup,
    DuplicateBlock,
    EdgeRedirectViaPredSplit,
    GraphModification,
    InsertBlock,
    PrivateTerminalSuffix,
    PrivateTerminalSuffixGroup,
    PromoteOperandToScalar,
    ReorderBlocks,
    RedirectBranch,
    RedirectGoto,
    ZeroStateWrite,
)
from d810.optimizers.microcode.flow.flattening.engine.strategy import (
    FAMILY_DIRECT,
    FAMILY_FALLBACK,
    BenefitMetrics,
    OwnershipScope,
    PlanFragment,
)
from d810.core.typing import cast


EMULATED_DISPATCHER_METADATA_KEY = "emulated_dispatcher"
EMULATED_DISPATCHER_MODIFICATIONS_KEY = "emulated_dispatcher_modifications"
EMULATED_DISPATCHER_FALLBACK_MODIFICATIONS_KEY = "emulated_dispatcher_fallback_modifications"
EMULATED_DISPATCHER_LOOP_RECOVERY_MODIFICATIONS_KEY = "emulated_dispatcher_loop_recovery_modifications"
EMULATED_DISPATCHER_CANDIDATE_RECORDS_KEY = "emulated_dispatcher_candidate_records"
EMULATED_DISPATCHER_PHASE_ARTIFACT_KEY = "emulated_dispatcher_phase_artifact"
EMULATED_DISPATCHER_PHASE_CONTEXT_KEY = "emulated_dispatcher_phase_context"


@dataclass(frozen=True)
class EmulatedDispatcherCandidateRecord:
    """Per-father lowering record used for parity triage and bisecting."""

    dispatcher_entry_serial: int
    father_serial: int
    state_signature: tuple[int, ...] = ()
    target_serial: int | None = None
    source_nsucc: int = 0
    raw_side_effect_count: int = 0
    safe_side_effect_count: int = 0
    selection_reason: str | None = None
    blocker: str | None = None
    selected_modification_indexes: tuple[int, ...] = ()
    selected_modification_kinds: tuple[str, ...] = ()
    selected_modification_summaries: tuple[str, ...] = ()
    legacy_analogue_kind: str | None = None
    semantically_valid: bool | None = None
    structurally_legacy_equivalent: bool | None = None
    payload_signature: tuple[str, ...] = ()
    source_scc: tuple[int, ...] = ()
    target_scc: tuple[int, ...] = ()
    cluster_key: tuple[str, ...] = ()
    cluster_candidate: bool = False


@dataclass(frozen=True)
class EmulatedDispatcherPhaseArtifact:
    """Typed summary of the richer recon artifact for one dispatcher family."""

    dispatcher_entry_serial: int
    state_var_stkoff: int | None = None
    pre_header_serial: int | None = None
    initial_state: int | None = None
    bst_node_blocks: tuple[int, ...] = ()
    handler_state_map: tuple[tuple[int, int], ...] = ()
    handler_range_map: tuple[tuple[int, int | None, int | None], ...] = ()
    transition_rows: int = 0
    dag_node_count: int = 0
    dag_edge_count: int = 0
    semantic_state_labels: tuple[str, ...] = ()
    semantic_reference_variant: str | None = None
    semantic_reference_line_count: int = 0
    semantic_reference_node_count: int = 0
    semantic_reference_program: str = ""


@dataclass(frozen=True)
class EmulatedDispatcherPhaseContext:
    """Raw recon objects backing the summarized phase artifact."""

    bst_result: object
    transition_result: object
    transition_report: object
    dag: object
    semantic_reference_program: object
    state_dispatcher_map: object | None = None
    switch_case_transition_facts: tuple[object, ...] = ()
    predecessor_dispatcher_target_facts: tuple[object, ...] = ()
    dispatcher_discovery_fact_observations: tuple[object, ...] = ()


@dataclass(frozen=True)
class EmulatedDispatcherMetadata:
    """Detection + enrichment summary for the current dispatcher-emulation pass."""

    dispatcher_shape: str = "none"
    state_transport: str = "none"
    lowering_mode: str = "none"
    provenance_hints: tuple[str, ...] = ()
    analysis_dispatchers: tuple[int, ...] = ()
    state_dispatcher_entries: tuple[int, ...] = ()
    state_constants: tuple[int, ...] = ()
    collector_dispatchers: tuple[int, ...] = ()
    planning_ready: bool = False
    planning_blocker: str | None = None
    candidate_count: int = 0
    rejected_fathers: int = 0
    candidate_kinds: tuple[str, ...] = ()
    rejection_reasons: tuple[str, ...] = ()
    # Reasons the selected rewrite is intentionally partial. These are the
    # waived proof obligations for selected partial rewrites, not hard blockers.
    partial_rewrite_reasons: tuple[str, ...] = ()
    candidate_records: tuple[EmulatedDispatcherCandidateRecord, ...] = ()
    phase_artifact: EmulatedDispatcherPhaseArtifact | None = None
    selected_lowering_mode: str | None = None
    selected_modification_count: int = 0
    loop_recovery_modification_count: int = 0

    @property
    def detected(self) -> bool:
        return bool(
            self.analysis_dispatchers
            or self.collector_dispatchers
            or self.state_dispatcher_entries
        )

    @property
    def is_partial(self) -> bool:
        return bool(self.partial_rewrite_reasons)


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


def extract_emulated_dispatcher_candidate_records(
    flow_graph: FlowGraph | None,
) -> tuple[EmulatedDispatcherCandidateRecord, ...]:
    """Return typed dispatcher candidate records from a FlowGraph snapshot."""
    if flow_graph is None:
        return ()
    metadata = getattr(flow_graph, "metadata", {}) or {}
    item = metadata.get(EMULATED_DISPATCHER_CANDIDATE_RECORDS_KEY)
    if not isinstance(item, tuple):
        return ()
    return tuple(
        record
        for record in item
        if isinstance(record, EmulatedDispatcherCandidateRecord)
    )


def extract_emulated_dispatcher_phase_artifact(
    flow_graph: FlowGraph | None,
) -> EmulatedDispatcherPhaseArtifact | None:
    """Return the typed phase artifact captured for one dispatcher family."""
    if flow_graph is None:
        return None
    metadata = getattr(flow_graph, "metadata", {}) or {}
    item = metadata.get(EMULATED_DISPATCHER_PHASE_ARTIFACT_KEY)
    if isinstance(item, EmulatedDispatcherPhaseArtifact):
        return item
    observation = extract_emulated_dispatcher_metadata(flow_graph)
    if observation is not None and observation.phase_artifact is not None:
        return observation.phase_artifact
    return None


def extract_emulated_dispatcher_phase_context(
    flow_graph: FlowGraph | None,
) -> EmulatedDispatcherPhaseContext | None:
    """Return the raw phase context captured for future lowering work."""
    if flow_graph is None:
        return None
    metadata = getattr(flow_graph, "metadata", {}) or {}
    item = metadata.get(EMULATED_DISPATCHER_PHASE_CONTEXT_KEY)
    if isinstance(item, EmulatedDispatcherPhaseContext):
        return item
    return None


def _summarize_emulated_dispatcher_modification(mod: GraphModification) -> str:
    match mod:
        case RedirectGoto(from_serial=src, old_target=old, new_target=new):
            return f"RedirectGoto({src}:{old}->{new})"
        case ZeroStateWrite(block_serial=serial, insn_ea=ea):
            return f"ZeroStateWrite({serial}@{hex(ea)})"
        case ConvertToGoto(block_serial=src, goto_target=dst):
            return f"ConvertToGoto({src}->{dst})"
        case CreateConditionalRedirect(
            source_block=src,
            ref_block=ref,
            conditional_target=conditional,
            fallthrough_target=fallthrough,
            instructions=instructions,
        ):
            return (
                "CreateConditionalRedirect("
                f"src={src},ref={ref},jcc={conditional},ft={fallthrough},"
                f"insns={len(instructions)})"
            )
        case InsertBlock(
            pred_serial=pred,
            succ_serial=succ,
            old_target_serial=old_target,
            instructions=instructions,
        ):
            return (
                "InsertBlock("
                f"pred={pred},succ={succ},old={old_target},insns={len(instructions)})"
            )
    return type(mod).__name__


def _graph_modification_analogue_kind(mod: GraphModification) -> str | None:
    if isinstance(mod, RedirectGoto):
        return "redirect_goto"
    if isinstance(mod, ZeroStateWrite):
        return None
    if isinstance(mod, ConvertToGoto):
        return "convert_to_goto"
    if isinstance(mod, CreateConditionalRedirect):
        return "create_conditional_redirect"
    if isinstance(mod, InsertBlock):
        return "insert_block"
    return None


def _coerce_selected_emulated_dispatcher_modifications(
    raw: object,
) -> tuple[GraphModification, ...]:
    if not isinstance(raw, tuple):
        return ()
    allowed = (
        RedirectGoto,
        RedirectBranch,
        ZeroStateWrite,
        ConvertToGoto,
        EdgeRedirectViaPredSplit,
        CreateConditionalRedirect,
        InsertBlock,
        PromoteOperandToScalar,
        DuplicateBlock,
        PrivateTerminalSuffix,
        PrivateTerminalSuffixGroup,
        DirectTerminalLoweringGroup,
        ReorderBlocks,
    )
    items: list[GraphModification] = []
    for item in raw:
        if isinstance(item, allowed):
            items.append(cast(GraphModification, item))
    return tuple(items)


def _coerce_emulated_dispatcher_modifications(
    raw: object,
) -> tuple[GraphModification, ...]:
    return _coerce_selected_emulated_dispatcher_modifications(raw)


def extract_emulated_dispatcher_modifications(
    flow_graph: FlowGraph | None,
) -> tuple[GraphModification, ...]:
    """Return validated dispatcher-emulation lowering candidates."""
    if flow_graph is None:
        return ()
    return _coerce_emulated_dispatcher_modifications(
        flow_graph.metadata.get(EMULATED_DISPATCHER_MODIFICATIONS_KEY)
    )


def extract_emulated_dispatcher_fallback_modifications(
    flow_graph: FlowGraph | None,
) -> tuple[GraphModification, ...]:
    """Return the father-local fallback batch kept for diagnostics/triage."""
    if flow_graph is None:
        return ()
    metadata = getattr(flow_graph, "metadata", {}) or {}
    raw = metadata.get(EMULATED_DISPATCHER_FALLBACK_MODIFICATIONS_KEY)
    if raw is None:
        raw = metadata.get(EMULATED_DISPATCHER_MODIFICATIONS_KEY)
    return _normalize_emulated_dispatcher_modifications(
        flow_graph,
        _coerce_emulated_dispatcher_modifications(raw),
    )


def _extract_selected_emulated_dispatcher_modifications(
    flow_graph: FlowGraph | None,
) -> tuple[GraphModification, ...]:
    """Return the strategy batch selected by the family snapshot.

    ``EMULATED_DISPATCHER_MODIFICATIONS_KEY`` is the canonical selected batch:
    normally the father-history fallback, but richer profiles can replace it
    with phase/DAG lowerings.  The explicit fallback key remains available for
    diagnostics and parity comparisons; executing it here would silently ignore
    the selected lowering mode.
    """

    if flow_graph is None:
        return ()
    metadata = getattr(flow_graph, "metadata", {}) or {}
    raw = metadata.get(EMULATED_DISPATCHER_MODIFICATIONS_KEY)
    return _normalize_emulated_dispatcher_modifications(
        flow_graph,
        _coerce_emulated_dispatcher_modifications(raw),
    )


def _is_valid_emulated_dispatcher_modification(
    cfg: FlowGraph,
    mod: GraphModification,
) -> bool:
    if isinstance(mod, RedirectGoto):
        return mod.from_serial in cfg.blocks and mod.new_target in cfg.blocks and mod.from_serial != mod.new_target
    if isinstance(mod, RedirectBranch):
        return (
            mod.from_serial in cfg.blocks
            and mod.old_target in cfg.blocks
            and mod.new_target in cfg.blocks
            and mod.from_serial != mod.new_target
            and mod.old_target != mod.new_target
            and mod.old_target in cfg.blocks[mod.from_serial].succs
        )
    if isinstance(mod, ConvertToGoto):
        return mod.block_serial in cfg.blocks and mod.goto_target in cfg.blocks and mod.block_serial != mod.goto_target
    if isinstance(mod, CreateConditionalRedirect):
        return (
            mod.source_block in cfg.blocks
            and mod.ref_block in cfg.blocks
            and mod.conditional_target in cfg.blocks
            and mod.fallthrough_target in cfg.blocks
            and mod.source_block != mod.conditional_target
            and mod.source_block != mod.fallthrough_target
            and mod.conditional_target != mod.fallthrough_target
        )
    if isinstance(mod, InsertBlock):
        effective_old_target = (
            mod.succ_serial if mod.old_target_serial is None else mod.old_target_serial
        )
        return (
            mod.pred_serial in cfg.blocks
            and mod.succ_serial in cfg.blocks
            and effective_old_target in cfg.blocks
            and mod.pred_serial != mod.succ_serial
            and mod.pred_serial != effective_old_target
            and effective_old_target in cfg.blocks[mod.pred_serial].succs
            and (len(mod.instructions) > 0 or mod.captured_body is not None)
        )
    if isinstance(mod, ZeroStateWrite):
        return mod.block_serial in cfg.blocks
    if isinstance(mod, PromoteOperandToScalar):
        return mod.block_serial in cfg.blocks
    if isinstance(mod, EdgeRedirectViaPredSplit):
        return (
            mod.src_block in cfg.blocks
            and mod.old_target in cfg.blocks
            and mod.new_target in cfg.blocks
            and mod.via_pred in cfg.blocks
            and mod.src_block != mod.new_target
            and mod.old_target != mod.new_target
        )
    if isinstance(mod, DuplicateBlock):
        if mod.source_block not in cfg.blocks:
            return False
        if mod.pred_serial is not None and mod.pred_serial not in cfg.blocks:
            return False
        if mod.target_block is not None and mod.target_block not in cfg.blocks:
            return False
        if mod.conditional_target is not None and mod.conditional_target not in cfg.blocks:
            return False
        if mod.fallthrough_target is not None and mod.fallthrough_target not in cfg.blocks:
            return False
        return True
    if isinstance(mod, (PrivateTerminalSuffix, PrivateTerminalSuffixGroup)):
        return True
    if isinstance(mod, DirectTerminalLoweringGroup):
        return True
    if isinstance(mod, ReorderBlocks):
        mentioned = set(mod.dfs_block_order) | set(mod.non_2way_serials) | set(mod.two_way_serials)
        return all(serial in cfg.blocks for serial in mentioned)
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
            case RedirectBranch(from_serial=src, old_target=old, new_target=new):
                blocks.add(src)
                edges.add((src, old))
                edges.add((src, new))
            case ConvertToGoto(block_serial=src, goto_target=dst):
                blocks.add(src)
                edges.add((src, dst))
            case CreateConditionalRedirect(
                source_block=src,
                ref_block=ref,
                conditional_target=conditional,
                fallthrough_target=fallthrough,
            ):
                blocks.add(src)
                blocks.add(ref)
                edges.add((src, conditional))
                edges.add((src, fallthrough))
            case InsertBlock(
                pred_serial=pred,
                succ_serial=succ,
                old_target_serial=old_target,
            ):
                blocks.add(pred)
                edges.add((pred, succ if old_target is None else old_target))
                if old_target is not None:
                    edges.add((pred, succ))
            case ZeroStateWrite(block_serial=serial):
                blocks.add(serial)
            case PromoteOperandToScalar(block_serial=serial):
                blocks.add(serial)
            case EdgeRedirectViaPredSplit(
                src_block=src,
                old_target=old,
                new_target=new,
                via_pred=via_pred,
            ):
                blocks.add(src)
                blocks.add(via_pred)
                edges.add((src, old))
                edges.add((src, new))
            case DuplicateBlock(
                source_block=src,
                target_block=target,
                pred_serial=pred,
                conditional_target=conditional,
                fallthrough_target=fallthrough,
            ):
                blocks.add(src)
                if pred is not None:
                    blocks.add(pred)
                for target_block in (target, conditional, fallthrough):
                    if target_block is not None:
                        blocks.add(target_block)
            case ReorderBlocks():
                pass
    return OwnershipScope(
        blocks=frozenset(blocks),
        edges=frozenset(edges),
        transitions=frozenset(),
    )


def _build_generic_ownership(
    modifications: tuple[GraphModification, ...],
) -> OwnershipScope:
    claimed_sources, claimed_targets = collect_mod_claims(list(modifications))
    blocks = frozenset(int(serial) for serial in claimed_sources | claimed_targets)
    return OwnershipScope(
        blocks=blocks,
        edges=frozenset(),
        transitions=frozenset(),
    )


class DispatcherLoopRecoveryStrategy:
    """Prefer phase-artifact-based reconstruction over edge-local rewrites."""

    name = "dispatcher_loop_recovery"
    family = FAMILY_DIRECT

    def is_applicable(self, snapshot) -> bool:
        observation = extract_emulated_dispatcher_metadata(snapshot.flow_graph)
        if observation is None or not observation.detected or not observation.planning_ready:
            return False
        if observation.selected_lowering_mode != "dispatcher_loop_recovery":
            return False
        metadata = getattr(snapshot.flow_graph, "metadata", {}) or {}
        modifications = _coerce_selected_emulated_dispatcher_modifications(
            metadata.get(EMULATED_DISPATCHER_LOOP_RECOVERY_MODIFICATIONS_KEY)
        )
        return bool(modifications)

    def plan(self, snapshot):
        observation = extract_emulated_dispatcher_metadata(snapshot.flow_graph)
        if observation is None or not observation.planning_ready:
            return None
        if observation.selected_lowering_mode != "dispatcher_loop_recovery":
            return None
        metadata = getattr(snapshot.flow_graph, "metadata", {}) or {}
        modifications = _coerce_selected_emulated_dispatcher_modifications(
            metadata.get(EMULATED_DISPATCHER_LOOP_RECOVERY_MODIFICATIONS_KEY)
        )
        if not modifications:
            return None
        return PlanFragment(
            strategy_name=self.name,
            family=self.family,
            ownership=_build_generic_ownership(modifications),
            prerequisites=[],
            expected_benefit=BenefitMetrics(
                handlers_resolved=max(1, len(modifications)),
                transitions_resolved=max(1, len(modifications)),
                blocks_freed=0,
                conflict_density=0.0,
            ),
            risk_score=0.35,
            metadata={
                "safeguard_profile": "engine",
                "safeguard_min_required": 1,
                "recovery_kind": "phase_artifact",
            },
            modifications=list(modifications),
        )


class EmulatedDispatcherStrategy:
    """Planner-visible lowering strategy for emulated-dispatcher families."""

    name = "emulated_dispatcher"
    family = FAMILY_FALLBACK

    def is_applicable(self, snapshot) -> bool:
        observation = extract_emulated_dispatcher_metadata(snapshot.flow_graph)
        if observation is None or not observation.detected or not observation.planning_ready:
            return False
        if observation.selected_lowering_mode == "dispatcher_loop_recovery":
            return False
        return bool(_extract_selected_emulated_dispatcher_modifications(snapshot.flow_graph))

    def plan(self, snapshot):
        observation = extract_emulated_dispatcher_metadata(snapshot.flow_graph)
        if observation is None or not observation.planning_ready:
            return None
        if observation.selected_lowering_mode == "dispatcher_loop_recovery":
            return None
        modifications = _extract_selected_emulated_dispatcher_modifications(
            snapshot.flow_graph
        )
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
    "EMULATED_DISPATCHER_CANDIDATE_RECORDS_KEY",
    "EMULATED_DISPATCHER_FALLBACK_MODIFICATIONS_KEY",
    "EMULATED_DISPATCHER_LOOP_RECOVERY_MODIFICATIONS_KEY",
    "EMULATED_DISPATCHER_METADATA_KEY",
    "EMULATED_DISPATCHER_MODIFICATIONS_KEY",
    "EMULATED_DISPATCHER_PHASE_ARTIFACT_KEY",
    "EMULATED_DISPATCHER_PHASE_CONTEXT_KEY",
    "DispatcherLoopRecoveryStrategy",
    "EmulatedDispatcherCandidateRecord",
    "EmulatedDispatcherMetadata",
    "EmulatedDispatcherPhaseArtifact",
    "EmulatedDispatcherPhaseContext",
    "EmulatedDispatcherStrategy",
    "extract_emulated_dispatcher_fallback_modifications",
    "extract_emulated_dispatcher_candidate_records",
    "extract_emulated_dispatcher_metadata",
    "extract_emulated_dispatcher_modifications",
    "extract_emulated_dispatcher_phase_artifact",
    "extract_emulated_dispatcher_phase_context",
    "_graph_modification_analogue_kind",
    "_summarize_emulated_dispatcher_modification",
]
