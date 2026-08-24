"""Exact post-plan coverage accounting for dispatcher-entry corridors.

The minimal unflatten emitter historically counted only unresolved transition
rows.  That is not a completion signal: a state-write/merge corridor can be
reachable and still enter the dispatcher even when every *emitted* transition
has a concrete target.  This module applies the planned CFG redirects to the
portable graph and records the original corridors as covered or residual.

It is deliberately planner-side and SQLite-free.  Callers publish the returned
typed observations through the observability bus; diagnostic subscribers own
persistence.
"""

from __future__ import annotations

from collections import deque
from collections.abc import Mapping
from dataclasses import dataclass

from d810.analyses.control_flow.graph_checks import (
    check_effectful_reachability_preserved,
    reachable_terminal_blocks,
)
from d810.analyses.control_flow.edit_simulation import simulate_edits
from d810.analyses.control_flow.minimal_state_recovery import (
    CandidatePrefixAlternateCorridorProof,
    build_current_u32_decision_forest,
    validate_candidate_prefix_alternate_corridor_proof,
)
from d810.analyses.value_flow.observation import FactObservation
from d810.ir.flowgraph import (
    BlockKind,
    FlowGraph,
    InsnKind,
)
from d810.ir.expressions import ValueOpKind
from d810.ir.insn_projection import (
    InstructionProjection,
    is_effect_free_operand_tree,
)
from d810.ir.semantics import ControlTransferKind
from d810.analyses.control_flow.instruction_semantics import (
    split_const_storage_identity_from_branch,
)
from d810.ir.storage_identity import (
    StorageIdentity,
)
from d810.transforms.graph_modification import (
    ConvertToGoto,
    EdgeRedirectViaPredSplit,
    LowerConditionalStateTransition,
    RedirectBranch,
    RedirectGoto,
)
from d810.transforms.edit_simulator import graph_modifications_to_simulated_edits
from d810.transforms.plan import (
    PatchPlan,
    PatchRedirectGoto,
)
from d810.transforms.unflatten_authority.legacy_keys import (
    DISPATCHER_CORRIDOR_COVERAGE_METADATA,
    DISPATCHER_REMOVAL_PREFLIGHT_PROOF_METADATA,
    FULL_UNFLATTENING_CLAIM_METADATA,
    UNFLATTEN_COMPLETION_STATUS_METADATA,
    USE_DEF_SEVERANCE_AUDIT_METADATA,
)


_MAX_CORRIDOR_DEPTH = 64
_MAX_CORRIDORS = 128

__all__ = [
    "DISPATCHER_CORRIDOR_COVERAGE_METADATA",
    "DISPATCHER_REMOVAL_PREFLIGHT_PROOF_METADATA",
    "FULL_UNFLATTENING_CLAIM_METADATA",
    "USE_DEF_SEVERANCE_AUDIT_METADATA",
    "UNFLATTEN_COMPLETION_STATUS_METADATA",
    "DispatcherBlockAnchor",
    "DispatcherCorridor",
    "DispatcherCorridorCoverage",
    "DispatcherCorridorCoverageValidation",
    "ComparisonCorridorRetirementProof",
    "DispatcherRemovalPreflightProof",
    "DispatcherRemovalPreflightValidation",
    "DetachedDeadHandlerComponentAnalysis",
    "IntervalStateNormalizerRetirementProof",
    "IntervalStateNormalizerRouteProof",
    "IntervalStateSourceRouteProof",
    "StateTransitionPlumbingRetirementProof",
    "StateTransitionPlumbingRouteProof",
    "TerminalSwitchCycleBreakProof",
    "RetiredDispatcherInfrastructure",
    "analyze_dispatcher_corridor_coverage",
    "build_dispatcher_removal_preflight_proof",
    "build_detached_dead_handler_component_analysis",
    "collect_dispatcher_corridor_coverage_observations",
    "collect_dispatcher_corridor_coverage_observations_from_metadata",
    "collect_dispatcher_removal_preflight_proof_observations_from_metadata",
    "collect_use_def_severance_observations_from_metadata",
    "collect_unflatten_dispatcher_outcome_observations_from_metadata",
    "validate_terminal_switch_cycle_break_allowance",
]


@dataclass(frozen=True, slots=True)
class DispatcherBlockAnchor:
    """Snapshot-local serial paired with its stable native-EA anchor."""

    serial: int
    ea: int

    @property
    def label(self) -> str:
        return f"blk{int(self.serial)}@0x{int(self.ea):x}"

    def to_payload(self) -> dict[str, int | str]:
        return {
            "serial": int(self.serial),
            "ea": int(self.ea),
            "label": self.label,
        }


@dataclass(frozen=True, slots=True)
class DispatcherCorridor:
    """One finite upstream route that still ends at the dispatcher."""

    path: tuple[DispatcherBlockAnchor, ...]
    state_merge_anchor: DispatcherBlockAnchor | None = None

    @property
    def source(self) -> DispatcherBlockAnchor:
        return self.path[0]

    @property
    def feeder(self) -> DispatcherBlockAnchor:
        return self.path[-2]

    @property
    def state_merge(self) -> DispatcherBlockAnchor | None:
        """Nearest explicit state/merge node before the dispatcher feeder.

        A direct source -> feeder -> dispatcher corridor has no shared merge.
        For the actionable source -> merge -> feeder -> dispatcher shape, this
        anchor is retained separately from the full path so DB consumers do not
        have to infer the safety-relevant merge identity from a JSON array.
        """
        return self.state_merge_anchor

    @property
    def dispatcher(self) -> DispatcherBlockAnchor:
        return self.path[-1]

    @property
    def label(self) -> str:
        return " -> ".join(anchor.label for anchor in self.path)

    def to_payload(self) -> dict[str, object]:
        return {
            "source": self.source.to_payload(),
            "state_merge": (
                None if self.state_merge is None else self.state_merge.to_payload()
            ),
            "dispatcher_feeder": self.feeder.to_payload(),
            "dispatcher": self.dispatcher.to_payload(),
            "path": [anchor.to_payload() for anchor in self.path],
            "label": self.label,
        }


@dataclass(frozen=True, slots=True)
class RetiredDispatcherInfrastructure:
    """One loss that is explicitly classified as non-semantic router plumbing."""

    role: str
    anchor: DispatcherBlockAnchor

    def to_payload(self) -> dict[str, object]:
        return {
            "role": self.role,
            "anchor": self.anchor.to_payload(),
        }


@dataclass(frozen=True, slots=True)
class DispatcherRemovalPreflightProof:
    """Exact, narrow allowance for intentional comparison-dispatcher removal.

    The generic entry-reachability gate remains the default.  This proof can
    only admit its failure when the post-plan graph retains every authoritative
    handler and reachable terminal, and every lost pre-plan block has an
    explicit router-infrastructure role with a serial plus EA anchor.
    """

    function_ea: int
    dispatcher: DispatcherBlockAnchor | None
    authoritative_handlers: tuple[DispatcherBlockAnchor, ...]
    post_reachable_handlers: tuple[DispatcherBlockAnchor, ...]
    pre_reachable_terminals: tuple[DispatcherBlockAnchor, ...]
    post_reachable_terminals: tuple[DispatcherBlockAnchor, ...]
    retired_infrastructure: tuple[RetiredDispatcherInfrastructure, ...]
    lost_blocks: frozenset[int]
    lost_block_anchors: tuple[DispatcherBlockAnchor, ...]
    state_plumbing: tuple[DispatcherBlockAnchor, ...]
    producer_safety: tuple[tuple[str, bool], ...]
    coverage_enumeration_complete: bool
    residual_corridor_count: int
    passed: bool
    reason: str

    def to_metadata(self) -> dict[str, object]:
        return {
            "function_ea": int(self.function_ea),
            "dispatcher": (
                None if self.dispatcher is None else self.dispatcher.to_payload()
            ),
            "proof_status": "accepted" if self.passed else "rejected",
            "reason": self.reason,
            "authoritative_handlers": [
                anchor.to_payload() for anchor in self.authoritative_handlers
            ],
            "post_reachable_handlers": [
                anchor.to_payload() for anchor in self.post_reachable_handlers
            ],
            "pre_reachable_terminals": [
                anchor.to_payload() for anchor in self.pre_reachable_terminals
            ],
            "post_reachable_terminals": [
                anchor.to_payload() for anchor in self.post_reachable_terminals
            ],
            "retired_infrastructure": [
                item.to_payload() for item in self.retired_infrastructure
            ],
            "lost_blocks": [anchor.to_payload() for anchor in self.lost_block_anchors],
            "state_plumbing": [anchor.to_payload() for anchor in self.state_plumbing],
            "producer_safety": dict(self.producer_safety),
            "coverage_enumeration_complete": bool(self.coverage_enumeration_complete),
            "residual_corridor_count": int(self.residual_corridor_count),
        }


@dataclass(frozen=True, slots=True)
class IntervalStateNormalizerRouteProof:
    """One comparison-forest exit that canonicalizes an interval state."""

    normalizer: DispatcherBlockAnchor
    state_feeder: DispatcherBlockAnchor
    normalized_value: int
    routed_handler: DispatcherBlockAnchor

    def to_payload(self) -> dict[str, object]:
        return {
            "normalizer": self.normalizer.to_payload(),
            "state_feeder": self.state_feeder.to_payload(),
            "normalized_value": int(self.normalized_value),
            "routed_handler": self.routed_handler.to_payload(),
        }


@dataclass(frozen=True, slots=True)
class IntervalStateSourceRouteProof:
    """One source-owned constant route around a retired state feeder."""

    source: DispatcherBlockAnchor
    state_feeder: DispatcherBlockAnchor
    state_value: int
    projected_successor: DispatcherBlockAnchor
    routed_handler: DispatcherBlockAnchor
    retired_normalizers: tuple[DispatcherBlockAnchor, ...] = ()

    def to_payload(self) -> dict[str, object]:
        return {
            "source": self.source.to_payload(),
            "state_feeder": self.state_feeder.to_payload(),
            "state_value": int(self.state_value),
            "projected_successor": self.projected_successor.to_payload(),
            "routed_handler": self.routed_handler.to_payload(),
            "retired_normalizers": [
                anchor.to_payload() for anchor in self.retired_normalizers
            ],
        }


@dataclass(frozen=True, slots=True)
class IntervalStateNormalizerRetirementProof:
    """Independent authority for retiring interval state-normalization plumbing."""

    dispatcher: DispatcherBlockAnchor
    state_identity: StorageIdentity
    normalizers: tuple[IntervalStateNormalizerRouteProof, ...]
    retired_state_plumbing: tuple[RetiredDispatcherInfrastructure, ...]
    semantic_handlers: tuple[DispatcherBlockAnchor, ...]
    post_reachable_handlers: tuple[DispatcherBlockAnchor, ...]
    lost_blocks: tuple[DispatcherBlockAnchor, ...]
    source_routes: tuple[IntervalStateSourceRouteProof, ...] = ()

    def to_payload(self) -> dict[str, object]:
        return {
            "dispatcher": self.dispatcher.to_payload(),
            "state_identity": self.state_identity.to_record(),
            "normalizers": [route.to_payload() for route in self.normalizers],
            "source_routes": [route.to_payload() for route in self.source_routes],
            "retired_state_plumbing": [
                item.to_payload() for item in self.retired_state_plumbing
            ],
            "semantic_handlers": [
                anchor.to_payload() for anchor in self.semantic_handlers
            ],
            "post_reachable_handlers": [
                anchor.to_payload() for anchor in self.post_reachable_handlers
            ],
            "lost_blocks": [anchor.to_payload() for anchor in self.lost_blocks],
        }


@dataclass(frozen=True, slots=True)
class StateTransitionPlumbingRouteProof:
    """One handler edge that bypasses a retired state-expression corridor."""

    source: DispatcherBlockAnchor
    path: tuple[DispatcherBlockAnchor, ...]
    state_writer: DispatcherBlockAnchor
    routed_handler: DispatcherBlockAnchor

    def to_payload(self) -> dict[str, object]:
        return {
            "source": self.source.to_payload(),
            "path": [anchor.to_payload() for anchor in self.path],
            "state_writer": self.state_writer.to_payload(),
            "routed_handler": self.routed_handler.to_payload(),
        }


@dataclass(frozen=True, slots=True)
class StateTransitionPlumbingRetirementProof:
    """Independent authority for retiring pure dispatcher-state expressions."""

    dispatcher: DispatcherBlockAnchor
    state_identity: StorageIdentity
    routes: tuple[StateTransitionPlumbingRouteProof, ...]
    retired_state_plumbing: tuple[RetiredDispatcherInfrastructure, ...]
    semantic_handlers: tuple[DispatcherBlockAnchor, ...]
    post_reachable_handlers: tuple[DispatcherBlockAnchor, ...]
    lost_blocks: tuple[DispatcherBlockAnchor, ...]

    def to_payload(self) -> dict[str, object]:
        return {
            "dispatcher": self.dispatcher.to_payload(),
            "state_identity": self.state_identity.to_record(),
            "routes": [route.to_payload() for route in self.routes],
            "retired_state_plumbing": [
                item.to_payload() for item in self.retired_state_plumbing
            ],
            "semantic_handlers": [
                anchor.to_payload() for anchor in self.semantic_handlers
            ],
            "post_reachable_handlers": [
                anchor.to_payload() for anchor in self.post_reachable_handlers
            ],
            "lost_blocks": [anchor.to_payload() for anchor in self.lost_blocks],
        }


@dataclass(frozen=True, slots=True)
class ComparisonCorridorRetirementProof:
    """Immutable authority for retiring exact covered control-only corridors."""

    dispatcher: DispatcherBlockAnchor
    covered_corridors: tuple[DispatcherCorridor, ...]
    retired_corridor: tuple[RetiredDispatcherInfrastructure, ...]
    semantic_handlers: tuple[DispatcherBlockAnchor, ...]
    post_reachable_handlers: tuple[DispatcherBlockAnchor, ...]
    lost_blocks: tuple[DispatcherBlockAnchor, ...]

    def to_payload(self) -> dict[str, object]:
        return {
            "dispatcher": self.dispatcher.to_payload(),
            "covered_corridors": [
                corridor.to_payload() for corridor in self.covered_corridors
            ],
            "retired_corridor": [item.to_payload() for item in self.retired_corridor],
            "semantic_handlers": [
                anchor.to_payload() for anchor in self.semantic_handlers
            ],
            "post_reachable_handlers": [
                anchor.to_payload() for anchor in self.post_reachable_handlers
            ],
            "lost_blocks": [anchor.to_payload() for anchor in self.lost_blocks],
        }


@dataclass(frozen=True, slots=True)
class DispatcherRemovalPreflightValidation:
    """Result of recomputing a plan's narrow removal proof at preflight."""

    passed: bool
    reason: str
    proof: DispatcherRemovalPreflightProof | None = None
    terminal_switch_cycle_break: "TerminalSwitchCycleBreakProof | None" = None
    interval_state_normalizer_retirement: (
        IntervalStateNormalizerRetirementProof | None
    ) = None
    state_transition_plumbing_retirement: (
        StateTransitionPlumbingRetirementProof | None
    ) = None
    comparison_corridor_retirement: ComparisonCorridorRetirementProof | None = None
    detached_dead_handler_component: "DetachedDeadHandlerComponentAnalysis | None" = None

    def to_payload(self) -> dict[str, object]:
        """Return compact typed evidence for a projected or observed verdict."""
        payload = {
            "validation_status": "accepted" if self.passed else "rejected",
            "reason": str(self.reason),
            "proof": None if self.proof is None else self.proof.to_metadata(),
        }
        if self.terminal_switch_cycle_break is not None:
            payload["terminal_switch_cycle_break"] = (
                self.terminal_switch_cycle_break.to_payload()
            )
        if self.interval_state_normalizer_retirement is not None:
            payload["interval_state_normalizer_retirement"] = (
                self.interval_state_normalizer_retirement.to_payload()
            )
        if self.state_transition_plumbing_retirement is not None:
            payload["state_transition_plumbing_retirement"] = (
                self.state_transition_plumbing_retirement.to_payload()
            )
        if self.comparison_corridor_retirement is not None:
            payload["comparison_corridor_retirement"] = (
                self.comparison_corridor_retirement.to_payload()
            )
        return payload


@dataclass(frozen=True, slots=True)
class DetachedDeadHandlerComponentAnalysis:
    """Producer-only source anchors for one candidate dead handler component.

    This is deliberately not metadata and contains no candidate authority.
    The canonical binder re-establishes every topology and effect premise.
    """

    dispatcher: DispatcherBlockAnchor
    dead_handlers: tuple[DispatcherBlockAnchor, ...]
    retained_handlers: tuple[DispatcherBlockAnchor, ...]
    component: tuple[DispatcherBlockAnchor, ...]


@dataclass(frozen=True, slots=True)
class TerminalSwitchCycleBreakProof:
    """Exact structural authority for retiring one detached switch residue."""

    dispatcher: DispatcherBlockAnchor
    terminal_source: DispatcherBlockAnchor
    shared_merge: DispatcherBlockAnchor
    terminal_target: DispatcherBlockAnchor
    terminal_stop: DispatcherBlockAnchor
    retired_residue: tuple[DispatcherBlockAnchor, ...]

    def to_payload(self) -> dict[str, object]:
        return {
            "dispatcher": self.dispatcher.to_payload(),
            "terminal_source": self.terminal_source.to_payload(),
            "shared_merge": self.shared_merge.to_payload(),
            "terminal_target": self.terminal_target.to_payload(),
            "terminal_stop": self.terminal_stop.to_payload(),
            "retired_residue": [anchor.to_payload() for anchor in self.retired_residue],
        }


@dataclass(frozen=True, slots=True)
class DispatcherCorridorCoverageValidation:
    """Result of recomputing planned corridor coverage against a real CFG."""

    passed: bool
    reason: str
    observed_coverage: "DispatcherCorridorCoverage | None" = None
    function_ea: int | None = None

    def to_payload(self) -> dict[str, object]:
        """Return the actual topology verdict without trusting plan metadata."""
        payload = {
            "validation_status": "accepted" if self.passed else "rejected",
            "reason": str(self.reason),
            "observed_coverage": (
                None
                if self.observed_coverage is None
                else self.observed_coverage.to_metadata()
            ),
        }
        if self.function_ea is not None:
            payload["function_ea"] = int(self.function_ea)
        return payload


@dataclass(frozen=True, slots=True)
class DispatcherCorridorCoverage:
    """Projected dispatcher-corridor status, never an applied-result claim."""

    function_ea: int
    dispatcher: DispatcherBlockAnchor | None
    covered_corridors: tuple[DispatcherCorridor, ...]
    residual_corridors: tuple[DispatcherCorridor, ...]
    enumeration_complete: bool
    semantic_exclusions: tuple[CandidatePrefixAlternateCorridorProof, ...] = ()

    @property
    def planned_completion_status(self) -> str:
        """What the immutable projection would establish if it commits."""
        if self.dispatcher is None:
            return "abstained_dispatcher_missing"
        if self.residual_corridors:
            return "planned_partial_residual_dispatcher"
        if not self.enumeration_complete:
            return "abstained_incomplete_corridor_enumeration"
        return "planned_dispatcher_corridors_covered"

    @property
    def completion_status(self) -> str:
        """Current status before a PatchPlan transaction outcome exists."""
        if self.dispatcher is None:
            return "abstained_dispatcher_missing"
        return "pending_patch_application"

    @property
    def applied_completion_status(self) -> str:
        """Topology-only status for a committed exact projection."""
        if self.dispatcher is None:
            return "abstained_dispatcher_missing"
        if self.residual_corridors:
            return "partial_residual_dispatcher"
        if not self.enumeration_complete:
            return "abstained_incomplete_corridor_enumeration"
        return "dispatcher_corridors_covered"

    @property
    def full_unflattening_claim(self) -> bool:
        """Topology coverage alone is never a semantic full-unflattening proof."""
        return False

    def to_metadata(self) -> dict[str, object]:
        metadata = {
            "function_ea": int(self.function_ea),
            "dispatcher": (
                None if self.dispatcher is None else self.dispatcher.to_payload()
            ),
            "completion_status": self.completion_status,
            "planned_completion_status": self.planned_completion_status,
            "application_status": "pending",
            "full_unflattening_claim": self.full_unflattening_claim,
            "enumeration_complete": bool(self.enumeration_complete),
            "covered_corridors": [
                corridor.to_payload() for corridor in self.covered_corridors
            ],
            "residual_corridors": [
                corridor.to_payload() for corridor in self.residual_corridors
            ],
        }
        if self.semantic_exclusions:
            metadata["semantic_exclusions"] = [
                _candidate_prefix_exclusion_payload(proof)
                for proof in self.semantic_exclusions
            ]
        return metadata


def _anchor(flow_graph: FlowGraph, serial: int) -> DispatcherBlockAnchor:
    block = flow_graph.get_block(int(serial))
    return DispatcherBlockAnchor(
        serial=int(serial),
        ea=int(getattr(block, "start_ea", 0) if block is not None else 0),
    )


def _rewired_successors(
    flow_graph: FlowGraph,
    modifications: tuple[object, ...] | list[object],
) -> dict[int, tuple[int, ...]]:
    """Apply the planner's edge-changing primitives exactly to portable edges."""
    successors = {
        int(serial): tuple(int(target) for target in block.succs)
        for serial, block in flow_graph.blocks.items()
    }
    for modification in modifications:
        if isinstance(modification, EdgeRedirectViaPredSplit):
            simulated = simulate_edits(
                {serial: list(targets) for serial, targets in successors.items()},
                graph_modifications_to_simulated_edits([modification]),
            )
            successors = {
                int(serial): tuple(int(target) for target in targets)
                for serial, targets in simulated.adj.items()
            }
            continue
        if isinstance(modification, LowerConditionalStateTransition):
            successors[int(modification.source_serial)] = (
                int(modification.false_target_serial),
                int(modification.true_target_serial),
            )
            continue
        if isinstance(modification, ConvertToGoto):
            successors[int(modification.block_serial)] = (
                int(modification.goto_target),
            )
            continue
        if not isinstance(modification, (RedirectGoto, RedirectBranch)):
            continue
        source = int(modification.from_serial)
        old_target = int(modification.old_target)
        new_target = int(modification.new_target)
        current = list(successors.get(source, ()))
        if old_target not in current:
            continue
        current[current.index(old_target)] = new_target
        successors[source] = tuple(current)
    return successors


def _reachable_from_entry(
    successors: dict[int, tuple[int, ...]],
    entry_serial: int,
) -> set[int]:
    reachable: set[int] = set()
    pending = deque((int(entry_serial),))
    while pending:
        serial = pending.popleft()
        if serial in reachable:
            continue
        reachable.add(serial)
        for target in successors.get(serial, ()):
            if target not in reachable:
                pending.append(int(target))
    return reachable


def _predecessors(
    successors: dict[int, tuple[int, ...]],
) -> dict[int, tuple[int, ...]]:
    predecessors: dict[int, list[int]] = {serial: [] for serial in successors}
    for source, targets in successors.items():
        for target in targets:
            predecessors.setdefault(int(target), []).append(int(source))
    return {
        serial: tuple(sorted(set(sources))) for serial, sources in predecessors.items()
    }


def _upstream_corridor_paths(
    successors: dict[int, tuple[int, ...]],
    *,
    feeder_serial: int,
    dispatcher_serial: int,
) -> tuple[tuple[tuple[int, ...], ...], bool]:
    """Return bounded corridors from the nearest upstream split into ``feeder``.

    A direct dispatcher predecessor is too little evidence for a shared merge:
    it hides the individual incoming paths that were not redirected.  Walking
    backwards through a one-predecessor glue chain until its first split gives
    every immediately actionable corridor while remaining finite in cyclic CFGs.
    If that split has a single-successor, multi-predecessor merge input, descend
    exactly one additional layer so a merge behind a shared feeder retains its
    real incoming anchors (for example ``45 -> 123 -> 3 -> dispatcher``).
    """
    predecessors = _predecessors(successors)
    paths: list[tuple[int, ...]] = []
    complete = True

    def append(path: tuple[int, ...]) -> None:
        nonlocal complete
        if len(paths) >= _MAX_CORRIDORS:
            complete = False
            return
        if path not in paths:
            paths.append(path)

    def is_dispatcher_self_reentry_input(
        *,
        predecessor: int,
        merge_input: int,
        suffix: tuple[int, ...],
        seen: frozenset[int],
    ) -> bool:
        """Accept only the feeder repeated by its exact dispatcher cycle.

        A reverse walk can encounter a node already in ``seen`` when a
        dispatcher routes through a shared merge and feeder back to itself.
        That one bounded shape is safe to enumerate as a corridor; arbitrary
        repeated merge/body nodes remain incomplete.  Keep the proof tied to
        the current suffix and exact one-successor cycle so a repeated node
        cannot be admitted merely because it happens to be reachable.
        """
        if predecessor != int(dispatcher_serial) or len(suffix) < 3:
            return False
        if int(suffix[-1]) != int(dispatcher_serial):
            return False
        merge_serial = int(suffix[0])
        feeder_serial = int(suffix[-2])
        if merge_serial in {int(dispatcher_serial), feeder_serial}:
            return False
        if merge_input != feeder_serial or feeder_serial not in seen:
            return False
        if successors.get(int(dispatcher_serial), ()) != (merge_serial,):
            return False
        if successors.get(feeder_serial, ()) != (int(dispatcher_serial),):
            return False
        if feeder_serial in {int(serial) for serial in suffix[:-2]}:
            return False
        if any(
            int(target) not in successors.get(int(source), ())
            for source, target in zip(suffix, suffix[1:])
        ):
            return False
        return int(dispatcher_serial) in predecessors.get(merge_serial, ())

    def append_split_predecessor(
        predecessor: int,
        suffix: tuple[int, ...],
        seen: frozenset[int],
    ) -> None:
        """Expose one explicit merge immediately behind a shared feeder.

        Do not recursively enumerate arbitrary upstream paths: that would turn
        a diagnostic into an unbounded reverse-CFG traversal.  The one-hop
        extension is enough to make a state/merge corridor explicit while the
        single-successor predicate prevents unrelated branch bodies from being
        reclassified as a merge.
        """
        nonlocal complete
        incoming_to_predecessor = predecessors.get(int(predecessor), ())
        if len(incoming_to_predecessor) > 1 and successors.get(
            int(predecessor), ()
        ) == (int(suffix[0]),):
            for merge_input in incoming_to_predecessor:
                merge_input = int(merge_input)
                if merge_input in seen:
                    if is_dispatcher_self_reentry_input(
                        predecessor=int(predecessor),
                        merge_input=merge_input,
                        suffix=suffix,
                        seen=seen,
                    ):
                        append((merge_input, int(predecessor), *suffix))
                    else:
                        complete = False
                    continue
                append((merge_input, int(predecessor), *suffix))
            return
        append((int(predecessor), *suffix))

    def walk(current: int, suffix: tuple[int, ...], seen: frozenset[int]) -> None:
        nonlocal complete
        if len(suffix) > _MAX_CORRIDOR_DEPTH:
            complete = False
            return
        incoming = predecessors.get(int(current), ())
        if not incoming:
            append(suffix)
            return
        if len(incoming) != 1:
            for predecessor in incoming:
                append_split_predecessor(int(predecessor), suffix, seen)
            return
        predecessor = int(incoming[0])
        if predecessor in seen:
            if predecessor == int(dispatcher_serial):
                append((predecessor, *suffix))
            else:
                complete = False
            return
        walk(predecessor, (predecessor, *suffix), seen | {predecessor})

    walk(
        int(feeder_serial),
        (int(feeder_serial), int(dispatcher_serial)),
        frozenset((int(feeder_serial), int(dispatcher_serial))),
    )
    return tuple(paths), complete


def _reachable_dispatcher_corridors(
    flow_graph: FlowGraph,
    successors: dict[int, tuple[int, ...]],
    dispatcher_serial: int,
) -> tuple[tuple[DispatcherCorridor, ...], bool]:
    reachable = _reachable_from_entry(successors, int(flow_graph.entry_serial))
    corridors: list[DispatcherCorridor] = []
    complete = True
    for feeder in sorted(
        serial
        for serial, targets in successors.items()
        if int(dispatcher_serial) in targets and serial in reachable
    ):
        paths, paths_complete = _upstream_corridor_paths(
            successors,
            feeder_serial=int(feeder),
            dispatcher_serial=int(dispatcher_serial),
        )
        complete = complete and paths_complete
        for path in paths:
            state_merge = _structural_state_merge_anchor(
                flow_graph,
                successors,
                path,
            )
            corridor = DispatcherCorridor(
                tuple(_anchor(flow_graph, serial) for serial in path),
                state_merge_anchor=state_merge,
            )
            if corridor not in corridors:
                corridors.append(corridor)
    return tuple(corridors), complete


def _structural_state_merge_anchor(
    flow_graph: FlowGraph,
    successors: Mapping[int, tuple[int, ...]],
    path: tuple[int, ...],
) -> DispatcherBlockAnchor | None:
    """Return only a structurally proven merge immediately before a feeder.

    A corridor's third-from-last node is not inherently state plumbing: a
    linear body block occupies the same position.  The narrow dispatcher
    retirement proof accepts the identity only when the node is an actual
    merge (multiple incoming edges) and has exactly the feeder as successor.
    """
    if len(path) < 4:
        return None
    merge_serial = int(path[-3])
    feeder_serial = int(path[-2])
    predecessors = _predecessors(dict(successors))
    if len(predecessors.get(merge_serial, ())) < 2:
        return None
    if successors.get(merge_serial, ()) != (feeder_serial,):
        return None
    if flow_graph.get_block(merge_serial) is None:
        return None
    return _anchor(flow_graph, merge_serial)


def _corridor_key(corridor: DispatcherCorridor) -> tuple[tuple[int, int], ...]:
    return tuple((int(anchor.serial), int(anchor.ea)) for anchor in corridor.path)


def _candidate_prefix_exclusion_payload(
    proof: CandidatePrefixAlternateCorridorProof,
) -> dict[str, object]:
    return {
        "normalized_state": int(proof.normalized_state) & 0xFFFFFFFF,
        "source": {
            "serial": int(proof.source_serial),
            "ea": int(proof.source_ea),
        },
        "feeder": (
            None
            if proof.feeder_serial is None or proof.feeder_ea is None
            else {
                "serial": int(proof.feeder_serial),
                "ea": int(proof.feeder_ea),
            }
        ),
        "prefix": {
            "serial": int(proof.prefix_serial),
            "ea": int(proof.prefix_ea),
        },
        "root": {
            "serial": int(proof.root_serial),
            "ea": int(proof.root_ea),
        },
        "state_identity": proof.state_identity.to_record(),
    }


def _candidate_prefix_exclusion_suffix(
    proof: CandidatePrefixAlternateCorridorProof,
) -> tuple[tuple[int, int], ...]:
    anchors = [(int(proof.source_serial), int(proof.source_ea))]
    if proof.feeder_serial is not None and proof.feeder_ea is not None:
        anchors.append((int(proof.feeder_serial), int(proof.feeder_ea)))
    anchors.extend(
        (
            (int(proof.prefix_serial), int(proof.prefix_ea)),
            (int(proof.root_serial), int(proof.root_ea)),
        )
    )
    return tuple(anchors)


def _corridor_matches_semantic_exclusion(
    corridor: DispatcherCorridor,
    proof: CandidatePrefixAlternateCorridorProof,
) -> bool:
    key = _corridor_key(corridor)
    suffix = _candidate_prefix_exclusion_suffix(proof)
    return len(key) >= len(suffix) and key[-len(suffix) :] == suffix


def _coverage_from_post_successors(
    flow_graph: FlowGraph,
    *,
    post_successors: Mapping[int, tuple[int, ...]],
    dispatcher_entry_serial: int | None,
    semantic_exclusions: tuple[CandidatePrefixAlternateCorridorProof, ...] = (),
) -> DispatcherCorridorCoverage:
    """Classify original corridors against an already-projected successor map.

    Preflight has the immutable post-projection graph, rather than the original
    modification objects.  Sharing this classifier prevents plan metadata from
    relabeling a still-reachable dispatcher corridor as covered.
    """
    if (
        dispatcher_entry_serial is None
        or flow_graph.get_block(int(dispatcher_entry_serial)) is None
    ):
        return DispatcherCorridorCoverage(
            function_ea=int(flow_graph.func_ea),
            dispatcher=None,
            covered_corridors=(),
            residual_corridors=(),
            enumeration_complete=True,
        )

    dispatcher_serial = int(dispatcher_entry_serial)
    validated_exclusions = tuple(
        proof
        for proof in semantic_exclusions
        if validate_candidate_prefix_alternate_corridor_proof(
            flow_graph,
            proof,
            dispatcher_entry_serial=dispatcher_serial,
        )
    )
    normalized_post_successors = {
        int(serial): tuple(int(target) for target in targets)
        for serial, targets in post_successors.items()
    }
    original_successors = _rewired_successors(flow_graph, ())
    original_corridors, original_complete = _reachable_dispatcher_corridors(
        flow_graph,
        original_successors,
        dispatcher_serial,
    )
    residual_corridors, post_complete = _reachable_dispatcher_corridors(
        flow_graph,
        normalized_post_successors,
        dispatcher_serial,
    )
    residual_corridors = tuple(
        corridor
        for corridor in residual_corridors
        if not any(
            _corridor_matches_semantic_exclusion(corridor, proof)
            for proof in validated_exclusions
        )
    )
    residual_keys = {_corridor_key(corridor) for corridor in residual_corridors}
    covered_corridors = tuple(
        corridor
        for corridor in original_corridors
        if _corridor_key(corridor) not in residual_keys
    )
    return DispatcherCorridorCoverage(
        function_ea=int(flow_graph.func_ea),
        dispatcher=_anchor(flow_graph, dispatcher_serial),
        covered_corridors=covered_corridors,
        residual_corridors=residual_corridors,
        enumeration_complete=original_complete and post_complete,
        semantic_exclusions=validated_exclusions,
    )


def analyze_dispatcher_corridor_coverage(
    flow_graph: FlowGraph,
    *,
    modifications: tuple[object, ...] | list[object],
    dispatcher_entry_serial: int | None,
    semantic_exclusions: tuple[CandidatePrefixAlternateCorridorProof, ...] = (),
) -> DispatcherCorridorCoverage:
    """Classify every reachable original dispatcher corridor after planned edits."""
    post_successors = _rewired_successors(flow_graph, modifications)
    return _coverage_from_post_successors(
        flow_graph,
        post_successors=post_successors,
        dispatcher_entry_serial=dispatcher_entry_serial,
        semantic_exclusions=semantic_exclusions,
    )


def _stable_block_start_ea(block: object) -> int | None:
    """Return the earliest native identity carried by one block snapshot.

    Generated Hex-Rays blocks can have ``BADADDR`` as their block coordinate
    while their instructions still retain native origins.  The instruction
    origin is the same address correspondence used by pseudocode/text-view
    synchronization and is valid portable identity for immediate post-mutation
    reconciliation.
    """
    for field_name in ("native_start_ea", "start_ea"):
        try:
            value = int(getattr(block, field_name))
        except (AttributeError, TypeError, ValueError):
            continue
        if 0 <= value < 0xFFFFFFFFFFFFFFFF:
            return value
    instructions = tuple(getattr(block, "insn_snapshots", ()) or ())
    for field_name in ("native_ea", "ea"):
        for instruction in instructions:
            try:
                value = int(getattr(instruction, field_name))
            except (AttributeError, TypeError, ValueError):
                continue
            if 0 <= value < 0xFFFFFFFFFFFFFFFF:
                return value
    return None


def _native_instruction_eas(block: object) -> frozenset[int]:
    """Return valid native instruction origins carried by one block."""
    origins: set[int] = set()
    for instruction in tuple(getattr(block, "insn_snapshots", ()) or ()):
        value = getattr(instruction, "native_ea", None)
        if value is None:
            value = getattr(instruction, "ea", None)
        try:
            origin = int(value)
        except (TypeError, ValueError):
            continue
        if 0 <= origin < 0xFFFFFFFFFFFFFFFF:
            origins.add(origin)
    return frozenset(origins)


def _addressless_block_signature(block: object) -> tuple[object, ...]:
    """Return a conservative identity for a native-addressless sentinel.

    This deliberately excludes topology: the transaction is validating a CFG
    rewrite, so predecessor/successor changes are expected.  Multiple blocks
    with the same signature remain ambiguous below.
    """
    instructions = tuple(getattr(block, "insn_snapshots", ()) or ())
    return (
        getattr(block, "kind", None),
        getattr(block, "block_type", None),
        getattr(block, "raw_block_type", None),
        getattr(block, "tail_kind", None),
        getattr(block, "tail_opcode", None),
        getattr(block, "raw_tail_opcode", None),
        tuple(
            (
                getattr(instruction, "kind", None),
                getattr(instruction, "opcode", None),
                getattr(instruction, "raw_opcode", None),
                getattr(instruction, "predicate_kind", None),
                getattr(instruction, "compare_width", None),
            )
            for instruction in instructions
        ),
    )


def _anchors_for_serials(
    flow_graph: FlowGraph,
    serials: set[int] | frozenset[int],
) -> tuple[DispatcherBlockAnchor, ...]:
    return tuple(
        _anchor(flow_graph, serial)
        for serial in sorted(int(serial) for serial in serials)
        if flow_graph.get_block(int(serial)) is not None
    )


def _retired_dispatcher_infrastructure(
    flow_graph: FlowGraph,
    coverage: DispatcherCorridorCoverage,
    *,
    dispatcher_entry_serial: int,
    dispatcher_region_serials: frozenset[int],
    state_plumbing_serials: frozenset[int],
    lost_blocks: frozenset[int],
) -> tuple[RetiredDispatcherInfrastructure, ...]:
    """Return only roles that are explicit in router or corridor evidence.

    A generic block on a corridor is deliberately *not* accepted.  The narrow
    proof admits only the known comparison region plus the exact feeder and
    shared state-merge anchors surfaced by corridor enumeration.
    """
    # ``retired_infrastructure`` is diagnostic evidence, not authority.  The
    # proof must therefore recompute the comparison region from the immutable
    # source CFG rather than accept a producer/metadata role label.  Retain the
    # argument for API compatibility with profile discovery, but deliberately
    # do not let it broaden the proved region.
    del dispatcher_region_serials
    roles_by_serial: dict[int, str] = {
        int(serial): "comparison_dispatcher"
        for serial in _independent_comparison_dispatcher_region(
            flow_graph,
            dispatcher_entry_serial=int(dispatcher_entry_serial),
        )
        if int(serial) in lost_blocks
    }
    dispatcher_block = flow_graph.get_block(int(dispatcher_entry_serial))
    if (
        int(dispatcher_entry_serial) in lost_blocks
        and _is_effect_free_dispatcher_router(dispatcher_block)
    ):
        roles_by_serial.setdefault(int(dispatcher_entry_serial), "comparison_dispatcher")
    for corridor in coverage.covered_corridors:
        feeder = corridor.feeder
        if int(feeder.serial) in lost_blocks and _feeder_is_retireable(
            flow_graph,
            feeder_serial=int(feeder.serial),
            state_plumbing_serials=state_plumbing_serials,
        ):
            roles_by_serial.setdefault(int(feeder.serial), "dispatcher_feeder")
        state_merge = corridor.state_merge
        if (
            state_merge is not None
            and int(state_merge.serial) in lost_blocks
            and _is_effect_free_dispatcher_router(
            flow_graph.get_block(int(state_merge.serial))
            )
        ):
            roles_by_serial.setdefault(int(state_merge.serial), "state_merge")
    corridor_safe, corridor_serials = _covered_control_only_comparison_corridor_region(
        flow_graph,
        coverage,
        dispatcher_entry_serial=int(dispatcher_entry_serial),
    )
    if corridor_safe:
        for serial in corridor_serials & set(lost_blocks):
            roles_by_serial.setdefault(int(serial), "comparison_corridor")
    return tuple(
        RetiredDispatcherInfrastructure(
            role=role,
            anchor=_anchor(flow_graph, serial),
        )
        for serial, role in sorted(roles_by_serial.items())
    )


def _covered_control_only_comparison_corridor_region(
    flow_graph: FlowGraph,
    coverage: DispatcherCorridorCoverage,
    *,
    dispatcher_entry_serial: int,
) -> tuple[bool, frozenset[int]]:
    """Revalidate exact covered multi-forest paths as control-only infrastructure.

    Corridor metadata is not authority.  Each path is checked against the
    immutable source graph, including its EAs, edges, and structural merge
    anchor.  A path is eligible only when it carries merge evidence for a
    comparison forest and every block is an effect-free control router.  One
    semantic instruction, memory operation, call, or unknown node vetoes the
    complete extension rather than allowing a sibling forest to be retired.
    """
    dispatcher_serial = int(dispatcher_entry_serial)
    if (
        coverage.dispatcher is None
        or int(coverage.dispatcher.serial) != dispatcher_serial
    ):
        return False, frozenset()
    candidates: set[int] = set()
    saw_comparison_corridor = False
    for corridor in coverage.covered_corridors:
        path = tuple(int(anchor.serial) for anchor in corridor.path)
        if len(path) < 2 or path[-1] != dispatcher_serial:
            return False, frozenset()
        if any(
            flow_graph.get_block(serial) is None
            or int(corridor.path[index].ea)
            != int(getattr(flow_graph.get_block(serial), "start_ea", 0) or 0)
            for index, serial in enumerate(path)
        ):
            return False, frozenset()
        for source, target in zip(path, path[1:]):
            block = flow_graph.get_block(source)
            if block is None or int(target) not in {
                int(successor) for successor in getattr(block, "succs", ()) or ()
            }:
                return False, frozenset()
        state_merge = corridor.state_merge
        if state_merge is None:
            # A direct corridor is eligible only when one of its source-path
            # nodes independently carries a comparison branch.  A purely
            # linear body remains semantic by default, even if its snapshot
            # happens to omit instructions.
            if not any(
                len(tuple(getattr(flow_graph.get_block(serial), "succs", ()) or ()))
                >= 2
                for serial in path[:-1]
            ):
                continue
        else:
            if len(path) < 4:
                return False, frozenset()
            merge_serial = int(state_merge.serial)
            if merge_serial != path[-3] or int(state_merge.ea) != int(
                getattr(flow_graph.get_block(merge_serial), "start_ea", 0) or 0
            ):
                return False, frozenset()
            merge = flow_graph.get_block(merge_serial)
            feeder_serial = path[-2]
            if (
                merge is None
                or len(
                    {
                        int(predecessor)
                        for predecessor in getattr(merge, "preds", ()) or ()
                    }
                )
                < 2
                or tuple(int(target) for target in getattr(merge, "succs", ()) or ())
                != (feeder_serial,)
            ):
                return False, frozenset()
        saw_comparison_corridor = True
        for serial in path[:-1]:
            if not _is_effect_free_dispatcher_router(flow_graph.get_block(serial)):
                return False, frozenset()
            candidates.add(int(serial))
    if not saw_comparison_corridor:
        return True, frozenset()
    return True, frozenset(candidates)


def _is_effect_free_dispatcher_router(block: object) -> bool:
    """Recognize only control-only comparison infrastructure.

    The proof is intentionally narrower than normal CFG analysis: an empty
    portable snapshot is an accepted control-only node, while populated blocks
    must contain only branch/no-op tails.  Any unclassified instruction keeps
    the node semantic and makes the narrow allowance abstain.
    """
    if block is None:
        return False
    insns = tuple(getattr(block, "insn_snapshots", ()) or ())
    if not insns:
        return True
    for insn in insns:
        if getattr(insn, "kind", None) not in {
            InsnKind.NOP,
            InsnKind.GOTO,
            InsnKind.COND_JUMP,
            InsnKind.EQUALITY_JUMP,
        }:
            return False
        # A control-only opcode can still carry an effectful expression in its
        # predicate or target operand.  In particular, an ``mop_a`` address,
        # global, call-shaped nested sub-instruction, or unresolved operand is
        # not made pure merely because the enclosing instruction is a branch.
        if (
            getattr(insn, "is_call", False)
            or getattr(insn, "call_kind", None) is not None
        ):
            return False
        if not all(
            _is_effect_free_dispatcher_router_operand(operand)
            for operand in (
                getattr(insn, "l", None),
                getattr(insn, "r", None),
                getattr(insn, "d", None),
            )
        ):
            return False
    return True


def _is_effect_free_dispatcher_router_operand(
    operand: object | None,
    *,
    _seen: set[int] | None = None,
) -> bool:
    """Compatibility wrapper for the shared portable operand-tree proof."""
    return is_effect_free_operand_tree(operand, _seen=_seen)


def _independent_comparison_dispatcher_region(
    flow_graph: FlowGraph,
    *,
    dispatcher_entry_serial: int,
) -> frozenset[int]:
    """Derive a comparison-only dispatcher forest from immutable topology.

    This is independent of plan metadata.  It follows only reachable two-way
    control-only router nodes beginning at the bound dispatcher anchor; a
    linear semantic body (even one self-labelled ``comparison_dispatcher`` in
    metadata) never enters the authority set.
    """
    start = int(dispatcher_entry_serial)
    seen: set[int] = set()
    pending = deque(((start, False),))
    while pending:
        serial, allow_exit_leaf = pending.popleft()
        serial = int(serial)
        if serial in seen:
            continue
        block = flow_graph.get_block(serial)
        if block is None:
            continue
        successors = tuple(getattr(block, "succs", ()) or ())
        is_comparison = len(successors) == 2 and getattr(block, "kind", None) in {
            BlockKind.TWO_WAY,
            BlockKind.N_WAY,
        }
        is_control_only_exit_leaf = allow_exit_leaf and len(successors) == 1
        if not (is_comparison or is_control_only_exit_leaf):
            continue
        if not _is_effect_free_dispatcher_router(block):
            continue
        seen.add(serial)
        for successor in successors:
            pending.append((int(successor), True))
    return frozenset(seen)


def _dispatcher_state_identity(
    flow_graph: FlowGraph,
    dispatcher_entry_serial: int,
) -> StorageIdentity | None:
    """Recover the exact state storage compared at the dispatcher entry."""
    block = flow_graph.get_block(int(dispatcher_entry_serial))
    if block is None:
        return None
    instructions = InstructionProjection.from_block(block)
    branches = tuple(
        (index, instruction)
        for index, instruction in enumerate(instructions)
        if instruction.control is not None
        and instruction.control.transfer is ControlTransferKind.CONDITIONAL_BRANCH
    )
    if len(branches) != 1:
        return None
    index, _branch = branches[0]
    _constant, identity = split_const_storage_identity_from_branch(
        instructions,
        index,
        min_const=-1,
    )
    return identity


def _feeder_is_retireable(
    flow_graph: FlowGraph,
    *,
    feeder_serial: int,
    state_plumbing_serials: frozenset[int],
) -> bool:
    """Allow a feeder loss only with effect-free or bound state evidence."""
    block = flow_graph.get_block(int(feeder_serial))
    if block is None:
        return False
    if _is_effect_free_dispatcher_router(block):
        return True
    return int(feeder_serial) in {int(serial) for serial in state_plumbing_serials}


def _exact_planned_stop_relocation(
    flow_graph: FlowGraph,
    *,
    post_graph: FlowGraph,
    patch_plan: PatchPlan | None,
) -> tuple[int, int] | None:
    """Return the source/projected STOP pair for an exact typed relocation."""
    if patch_plan is None or not patch_plan.new_blocks:
        return None
    source_stop_ref = patch_plan.relocation_map.source_stop
    source_stop_serial = (
        None
        if source_stop_ref is None
        else dict(patch_plan.source_coordinates).get(source_stop_ref)
    )
    if source_stop_serial is None:
        return None
    relocated_stop_serial = int(source_stop_serial) + len(patch_plan.new_blocks)
    source_stop = flow_graph.get_block(int(source_stop_serial))
    relocated_stop = post_graph.get_block(int(relocated_stop_serial))
    if (
        source_stop is None
        or relocated_stop is None
        or source_stop.kind is not BlockKind.STOP
        or relocated_stop.kind is not BlockKind.STOP
        or source_stop.succs
        or relocated_stop.succs
        or int(source_stop.start_ea) != int(relocated_stop.start_ea)
        or tuple(source_stop.insn_snapshots) != tuple(relocated_stop.insn_snapshots)
        or source_stop.tail_kind is not relocated_stop.tail_kind
    ):
        return None
    return int(source_stop_serial), int(relocated_stop_serial)


def _semantic_lost_blocks(
    flow_graph: FlowGraph,
    *,
    post_graph: FlowGraph,
    patch_plan: PatchPlan | None,
) -> frozenset[int]:
    """Return true lost blocks, excluding an exact typed STOP relocation."""
    pre_reachable = _reachable_from_entry(
        flow_graph.as_adjacency_dict(), int(flow_graph.entry_serial)
    )
    post_reachable = _reachable_from_entry(
        post_graph.as_adjacency_dict(), int(post_graph.entry_serial)
    )
    lost = frozenset(int(serial) for serial in pre_reachable - post_reachable)
    relocation = _exact_planned_stop_relocation(
        flow_graph,
        post_graph=post_graph,
        patch_plan=patch_plan,
    )
    if relocation is None:
        return lost
    source_stop_serial, _ = relocation
    return frozenset(serial for serial in lost if serial != source_stop_serial)


def build_dispatcher_removal_preflight_proof(
    flow_graph: FlowGraph,
    *,
    post_graph: FlowGraph,
    coverage: DispatcherCorridorCoverage,
    dispatcher_entry_serial: int | None,
    authoritative_handler_serials: frozenset[int],
    dispatcher_region_serials: frozenset[int],
    producer_safety: Mapping[str, bool],
    state_plumbing_serials: frozenset[int] = frozenset(),
    patch_plan: PatchPlan | None = None,
) -> DispatcherRemovalPreflightProof:
    """Prove the exact exception to raw entry-count preservation.

    The raw count gate intentionally remains conservative.  A comparison
    forest can be entirely dead after every state route becomes direct, though,
    so its removal lowers the count without losing executable handler or return
    behavior.  This proof records the only accepted shape and fails closed for
    unknown loss.
    """
    normalized_safety = tuple(
        sorted((str(name), bool(value)) for name, value in producer_safety.items())
    )
    required_safety = {
        "fragment_atomic": True,
        "non_state_use_def_veto": True,
        "non_state_use_def_checked": True,
        "non_state_use_def_severances_zero": True,
    }
    post_reachable = _reachable_from_entry(
        post_graph.as_adjacency_dict(),
        int(post_graph.entry_serial),
    )
    lost_blocks = _semantic_lost_blocks(
        flow_graph,
        post_graph=post_graph,
        patch_plan=patch_plan,
    )
    dispatcher = coverage.dispatcher
    handlers = frozenset(int(serial) for serial in authoritative_handler_serials)
    handler_anchors = _anchors_for_serials(flow_graph, handlers)
    post_handlers = _anchors_for_serials(
        post_graph,
        frozenset(serial for serial in handlers if serial in post_reachable),
    )
    pre_terminals = frozenset(
        int(serial) for serial in reachable_terminal_blocks(flow_graph)
    )
    post_terminal_serials = frozenset(
        int(serial) for serial in reachable_terminal_blocks(post_graph)
    )
    pre_terminal_anchors = _anchors_for_serials(flow_graph, pre_terminals)
    post_terminal_anchors = _anchors_for_serials(post_graph, post_terminal_serials)
    stop_relocation = _exact_planned_stop_relocation(
        flow_graph,
        post_graph=post_graph,
        patch_plan=patch_plan,
    )
    if stop_relocation is not None:
        source_stop_serial, relocated_stop_serial = stop_relocation
        if (
            source_stop_serial in pre_terminals
            and relocated_stop_serial in post_terminal_serials
        ):
            post_terminal_anchors = tuple(
                _anchor(flow_graph, source_stop_serial)
                if int(anchor.serial) == relocated_stop_serial
                else anchor
                for anchor in post_terminal_anchors
            )
    plumbing = frozenset(int(serial) for serial in state_plumbing_serials)
    plumbing_anchors = _anchors_for_serials(flow_graph, plumbing)
    retired = (
        ()
        if dispatcher_entry_serial is None
        else _retired_dispatcher_infrastructure(
            flow_graph,
            coverage,
            dispatcher_entry_serial=int(dispatcher_entry_serial),
            dispatcher_region_serials=frozenset(
                int(serial) for serial in dispatcher_region_serials
            ),
            state_plumbing_serials=plumbing,
            lost_blocks=lost_blocks,
        )
    )
    allowed_lost = {item.anchor.serial for item in retired}
    safety = dict(normalized_safety)

    if dispatcher_entry_serial is None or dispatcher is None:
        passed = False
        reason = "dispatcher_missing"
    elif int(dispatcher.serial) != int(dispatcher_entry_serial):
        passed = False
        reason = "dispatcher_anchor_mismatch"
    elif not coverage.enumeration_complete:
        passed = False
        reason = "corridor_enumeration_incomplete"
    elif coverage.residual_corridors:
        passed = False
        reason = "residual_dispatcher_corridor"
    elif not handlers:
        passed = False
        reason = "authoritative_handlers_empty"
    elif len(handler_anchors) != len(handlers):
        passed = False
        reason = "authoritative_handler_missing"
    elif set(post_handlers) != set(handler_anchors):
        passed = False
        if any(serial not in post_reachable for serial in handlers):
            reason = "authoritative_handler_lost"
        else:
            reason = "authoritative_handler_identity_drift"
    elif set(post_terminal_anchors) != set(pre_terminal_anchors):
        passed = False
        pre_terminal_serials = {anchor.serial for anchor in pre_terminal_anchors}
        if not pre_terminal_serials.issubset(post_terminal_serials):
            reason = "reachable_terminal_lost"
        else:
            reason = "reachable_terminal_identity_drift"
    elif not lost_blocks.issubset(allowed_lost):
        passed = False
        reason = "untyped_lost_block"
    elif any(
        safety.get(name) is not expected for name, expected in required_safety.items()
    ):
        passed = False
        reason = "producer_safety_missing"
    else:
        passed = True
        reason = "typed_dispatcher_infrastructure_removed"

    return DispatcherRemovalPreflightProof(
        function_ea=int(flow_graph.func_ea),
        dispatcher=dispatcher,
        authoritative_handlers=handler_anchors,
        post_reachable_handlers=post_handlers,
        pre_reachable_terminals=pre_terminal_anchors,
        post_reachable_terminals=post_terminal_anchors,
        retired_infrastructure=retired,
        lost_blocks=lost_blocks,
        lost_block_anchors=_anchors_for_serials(flow_graph, lost_blocks),
        state_plumbing=plumbing_anchors,
        producer_safety=normalized_safety,
        coverage_enumeration_complete=bool(coverage.enumeration_complete),
        residual_corridor_count=len(coverage.residual_corridors),
        passed=passed,
        reason=reason,
    )


def build_detached_dead_handler_component_analysis(
    flow_graph: FlowGraph,
    *,
    post_graph: FlowGraph,
    coverage: DispatcherCorridorCoverage,
    authoritative_handler_serials: frozenset[int],
    patch_plan: PatchPlan | None = None,
) -> DetachedDeadHandlerComponentAnalysis | None:
    """Produce source anchors only when the mainline dead-island shape holds."""

    dispatcher = coverage.dispatcher
    handlers = frozenset(int(value) for value in authoritative_handler_serials)
    if (
        dispatcher is None
        or not coverage.enumeration_complete
        or coverage.residual_corridors
        or len(handlers) < 2
    ):
        return None
    dispatcher_serial = int(dispatcher.serial)
    state_identity = _dispatcher_state_identity(flow_graph, dispatcher_serial)
    if state_identity is None:
        return None
    comparison_region = _independent_comparison_dispatcher_region(
        flow_graph, dispatcher_entry_serial=dispatcher_serial,
    )
    if dispatcher_serial not in comparison_region:
        decision_forest = build_current_u32_decision_forest(
            flow_graph,
            dispatcher_serial,
            expected_identities=frozenset({state_identity}),
        )
        if decision_forest is not None:
            comparison_region = frozenset(
                {*decision_forest.nodes, *decision_forest.aliases}
            )
    if dispatcher_serial not in comparison_region:
        # Hex-Rays may retain an operand wrapper that the strict operand-tree
        # classifier cannot normalize.  This fallback remains bounded to the
        # dispatcher-connected, pure-control portion of the CFG and stops at
        # semantic handler entries; it proposes no loss authority itself.
        relaxed_region: set[int] = set()
        pending = [dispatcher_serial]
        while pending:
            serial = int(pending.pop())
            if serial in relaxed_region:
                continue
            if serial != dispatcher_serial and serial in handlers:
                continue
            block = flow_graph.get_block(serial)
            if block is None or len(tuple(block.succs)) not in {1, 2}:
                continue
            instructions = InstructionProjection.from_block(block)
            if serial != dispatcher_serial and any(
                instruction.effects
                or instruction.memory is not None
                or (
                    instruction.control is None
                    and not (
                        instruction.operation is ValueOpKind.VENDOR
                        and not instruction.inputs
                        and instruction.result is None
                    )
                )
                for instruction in instructions
            ):
                continue
            if serial != dispatcher_serial and instructions and not any(
                instruction.control is not None for instruction in instructions
            ):
                continue
            relaxed_region.add(serial)
            pending.extend(int(target) for target in block.succs)
        comparison_region = frozenset(relaxed_region)
    if dispatcher_serial in comparison_region:
        bounded_region: set[int] = set()
        pending = [dispatcher_serial]
        while pending:
            serial = int(pending.pop())
            if serial in bounded_region or serial not in comparison_region:
                continue
            if serial != dispatcher_serial and serial in handlers:
                continue
            bounded_region.add(serial)
            block = flow_graph.get_block(serial)
            if block is not None:
                pending.extend(int(target) for target in block.succs)
        comparison_region = frozenset(bounded_region)
    if dispatcher_serial not in comparison_region:
        return None
    pre_reachable = _reachable_from_entry(
        flow_graph.as_adjacency_dict(), int(flow_graph.entry_serial)
    )
    post_reachable = _reachable_from_entry(
        post_graph.as_adjacency_dict(), int(post_graph.entry_serial)
    )
    dead_handlers = frozenset(handlers - post_reachable)
    retained_handlers = frozenset(handlers & post_reachable)
    if not dead_handlers or not retained_handlers or not dead_handlers <= pre_reachable:
        return None
    if set(reachable_terminal_blocks(flow_graph)) != set(reachable_terminal_blocks(post_graph)):
        return None
    for serial in dead_handlers:
        block = flow_graph.get_block(serial)
        if block is None:
            return None
        reachable_preds = frozenset(int(pred) for pred in block.preds if int(pred) in pre_reachable)
        if not reachable_preds or not reachable_preds <= comparison_region:
            return None
    if check_effectful_reachability_preserved(
        flow_graph, post_adj=post_graph.as_adjacency_dict(),
    ).lost_block_serials:
        return None
    lost = _semantic_lost_blocks(flow_graph, post_graph=post_graph, patch_plan=patch_plan)
    component: set[int] = set()
    pending = list(dead_handlers)
    while pending:
        serial = int(pending.pop())
        if serial in component or serial == dispatcher_serial or serial in post_reachable or serial not in lost:
            continue
        component.add(serial)
        block = flow_graph.get_block(serial)
        if block is not None:
            pending.extend(int(target) for target in block.succs)
    if not dead_handlers <= component:
        return None
    for serial in component:
        block = flow_graph.get_block(serial)
        if block is None or any(insn.is_call or insn.kind in {InsnKind.CALL, InsnKind.STORE} for insn in block.insn_snapshots):
            return None
        if any(int(pred) in pre_reachable and int(pred) not in component and int(pred) not in comparison_region for pred in block.preds):
            return None
    remainder = frozenset(lost - component - comparison_region)
    for serial in remainder:
        block = flow_graph.get_block(serial)
        if block is None or any(insn.is_call or insn.kind in {InsnKind.CALL, InsnKind.STORE} for insn in block.insn_snapshots):
            return None
        if not tuple(int(target) for target in block.succs):
            return None
        if any(int(target) not in remainder and int(target) not in comparison_region and int(target) not in component for target in block.succs):
            return None
    if len(component) * 2 >= max(1, len(pre_reachable)):
        return None
    return DetachedDeadHandlerComponentAnalysis(
        dispatcher=dispatcher,
        dead_handlers=_anchors_for_serials(flow_graph, dead_handlers),
        retained_handlers=_anchors_for_serials(flow_graph, retained_handlers),
        component=_anchors_for_serials(flow_graph, frozenset(component)),
    )


def collect_dispatcher_corridor_coverage_observations(
    coverage: DispatcherCorridorCoverage,
    *,
    maturity: str,
    phase: str,
    application_status: str = "pending",
    outcome_reason: str | None = None,
    observed_coverage_validation: DispatcherCorridorCoverageValidation | None = None,
    projected_coverage_validation: DispatcherCorridorCoverageValidation | None = None,
    plan_id: str | None = None,
    attempt_id: str | None = None,
) -> tuple[FactObservation, ...]:
    """Turn exact CFG coverage into outcome-qualified diagnostic observations."""
    if application_status == "pending":
        completion_status = coverage.completion_status
    elif application_status == "applied":
        completion_status = coverage.applied_completion_status
    elif (
        application_status.startswith("rejected_")
        or application_status == "poisoned_restart_required"
    ):
        completion_status = f"abstained_{application_status}"
    else:
        raise ValueError(
            "dispatcher coverage application status must be pending, applied, "
            "rejected_*, or poisoned_restart_required"
        )
    dispatcher_label = (
        coverage.dispatcher.label if coverage.dispatcher is not None else "dispatcher@?"
    )
    scope = _diagnostic_outcome_scope(plan_id=plan_id, attempt_id=attempt_id)
    scope_suffix = f":{scope}" if scope else ""
    summary_payload = coverage.to_metadata()
    summary_payload.update(
        {
            "application_status": application_status,
            "completion_status": completion_status,
            "planned_completion_status": coverage.planned_completion_status,
            "outcome_reason": outcome_reason,
            "observed_coverage_validation": (
                None
                if observed_coverage_validation is None
                else observed_coverage_validation.to_payload()
            ),
            "projected_coverage_validation": (
                None
                if projected_coverage_validation is None
                else projected_coverage_validation.to_payload()
            ),
            "plan_id": plan_id,
            "attempt_id": attempt_id,
        }
    )
    observations: list[FactObservation] = [
        FactObservation(
            fact_id=(
                "unflatten-dispatcher-corridor-summary:"
                f"{application_status}:func=0x{int(coverage.function_ea):x}:"
                f"{dispatcher_label}{scope_suffix}"
            ),
            kind="UnflattenDispatcherCorridorCoverageSummary",
            semantic_key=(
                "unflatten_dispatcher_corridor_summary:"
                f"func=0x{int(coverage.function_ea):x}:{dispatcher_label}"
            ),
            maturity=str(maturity),
            phase=str(phase),
            confidence=1.0,
            source_block=(
                None if coverage.dispatcher is None else coverage.dispatcher.serial
            ),
            source_ea=(None if coverage.dispatcher is None else coverage.dispatcher.ea),
            payload=summary_payload,
            evidence=(() if coverage.dispatcher is None else (dispatcher_label,)),
        )
    ]
    for planned_coverage, corridors in (
        ("covered", coverage.covered_corridors),
        ("residual", coverage.residual_corridors),
    ):
        for corridor in corridors:
            if application_status == "pending":
                coverage_status = (
                    "pending" if planned_coverage == "covered" else "residual"
                )
            elif application_status == "applied":
                coverage_status = planned_coverage
            else:
                coverage_status = "residual"
            path_label = "->".join(anchor.label for anchor in corridor.path)
            observations.append(
                FactObservation(
                    fact_id=(
                        "unflatten-dispatcher-corridor:"
                        f"{application_status}:{planned_coverage}:{path_label}{scope_suffix}"
                    ),
                    kind="UnflattenDispatcherCorridorCoverage",
                    semantic_key=(
                        "unflatten_dispatcher_corridor:"
                        f"{corridor.source.label}:{corridor.dispatcher.label}"
                    ),
                    maturity=str(maturity),
                    phase=str(phase),
                    confidence=1.0,
                    source_block=corridor.source.serial,
                    source_ea=corridor.source.ea,
                    block_fingerprint=path_label,
                    payload={
                        "coverage": coverage_status,
                        "planned_coverage": planned_coverage,
                        "application_status": application_status,
                        "completion_status": completion_status,
                        "planned_completion_status": coverage.planned_completion_status,
                        "full_unflattening_claim": coverage.full_unflattening_claim,
                        "enumeration_complete": coverage.enumeration_complete,
                        "outcome_reason": outcome_reason,
                        "observed_coverage_validation": (
                            None
                            if observed_coverage_validation is None
                            else observed_coverage_validation.to_payload()
                        ),
                        "projected_coverage_validation": (
                            None
                            if projected_coverage_validation is None
                            else projected_coverage_validation.to_payload()
                        ),
                        "plan_id": plan_id,
                        "attempt_id": attempt_id,
                        **corridor.to_payload(),
                    },
                    evidence=tuple(anchor.label for anchor in corridor.path),
                )
            )
    return tuple(observations)


def _diagnostic_outcome_scope(*, plan_id: str | None, attempt_id: str | None) -> str:
    """Name a fact lifecycle without conflating separate PatchPlans."""
    if plan_id is None and attempt_id is None:
        return ""
    normalized_plan = str(plan_id).strip() if plan_id is not None else "unknown"
    normalized_attempt = (
        str(attempt_id).strip() if attempt_id is not None else "unknown"
    )
    return (
        f"plan={normalized_plan or 'unknown'}:attempt={normalized_attempt or 'unknown'}"
    )


def _use_def_optional_int(value: object) -> int | None:
    if value is None:
        return None
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def _use_def_anchor_payload(value: object) -> dict[str, int | str | None]:
    """Normalize an evidence anchor so a serial never survives without its EA."""
    if not isinstance(value, Mapping):
        return {"serial": None, "ea": None, "label": "unknown"}
    serial = _use_def_optional_int(value.get("serial"))
    ea = _use_def_optional_int(value.get("ea"))
    if serial is None or ea is None:
        return {"serial": None, "ea": None, "label": "unknown"}
    return {
        "serial": serial,
        "ea": ea,
        "label": f"blk{serial}@0x{ea:x}",
    }


def collect_use_def_severance_observations_from_metadata(
    metadata: object,
    *,
    function_ea: int | None = None,
    maturity: str,
    phase: str,
    application_status: str = "pending",
    outcome_reason: str | None = None,
    plan_id: str | None = None,
    attempt_id: str | None = None,
) -> tuple[FactObservation, ...]:
    """Turn immutable use-def audit metadata into one fact per violation."""
    if not isinstance(metadata, Mapping):
        return ()
    resolved_function_ea = _use_def_optional_int(metadata.get("function_ea"))
    if resolved_function_ea is None:
        resolved_function_ea = _use_def_optional_int(function_ea)
    if resolved_function_ea is None:
        return ()
    raw_violations = metadata.get("violations", ())
    if not isinstance(raw_violations, (tuple, list)):
        raw_violations = ()
    severance_count = _use_def_optional_int(metadata.get("severance_count"))
    if severance_count is None:
        severance_count = len(raw_violations)
    enforced = bool(
        metadata.get("enforced", metadata.get("enforcement_enabled", False))
    )
    executed = bool(metadata.get("executed", False))
    if not executed:
        enforcement_status = "safety_unavailable"
    elif severance_count > 0:
        enforcement_status = "fragment_rejected" if enforced else "heuristic_observed"
    else:
        enforcement_status = "clean"
    scope = _diagnostic_outcome_scope(plan_id=plan_id, attempt_id=attempt_id)
    scope_suffix = f":{scope}" if scope else ""
    shared_payload = {
        "function_ea": int(resolved_function_ea),
        "application_status": application_status,
        "enforcement_status": enforcement_status,
        "executed": executed,
        "clean": bool(metadata.get("clean", False)),
        "severance_count": int(severance_count),
        "enforced": enforced,
        "enforcement_enabled": enforced,
        "failure_reason": metadata.get("failure_reason"),
        "outcome_reason": outcome_reason,
        "plan_id": plan_id,
        "attempt_id": attempt_id,
    }
    summary_payload = dict(metadata)
    summary_payload.update(shared_payload)
    observations: list[FactObservation] = [
        FactObservation(
            fact_id=(
                "unflatten-use-def-severance-summary:"
                f"{application_status}:func=0x{int(resolved_function_ea):x}"
                f"{scope_suffix}"
            ),
            kind="UnflattenUseDefSeveranceSummary",
            semantic_key=(
                "unflatten_use_def_severance_summary:"
                f"func=0x{int(resolved_function_ea):x}"
            ),
            maturity=str(maturity),
            phase=str(phase),
            confidence=1.0,
            payload=summary_payload,
            evidence=(enforcement_status,),
        )
    ]
    for index, raw_violation in enumerate(raw_violations):
        if not isinstance(raw_violation, Mapping):
            raw_violation = {}
        source = _use_def_anchor_payload(raw_violation.get("source"))
        old_target = _use_def_anchor_payload(raw_violation.get("old_target"))
        new_target = _use_def_anchor_payload(raw_violation.get("new_target"))
        use = _use_def_anchor_payload(raw_violation.get("use"))
        stack_offset = _use_def_optional_int(raw_violation.get("stack_offset"))
        stack_size = _use_def_optional_int(raw_violation.get("stack_size"))
        use_instruction_ea = _use_def_optional_int(
            raw_violation.get("use_instruction_ea")
        )
        payload = {
            **shared_payload,
            "source": source,
            "old_target": old_target,
            "new_target": new_target,
            "stack_offset": stack_offset,
            "stack_size": stack_size,
            "use": use,
            "use_instruction_ea": use_instruction_ea,
            "observation_index": index,
        }
        source_label = str(source["label"])
        observations.append(
            FactObservation(
                fact_id=(
                    "unflatten-use-def-severance:"
                    f"{application_status}:func=0x{int(resolved_function_ea):x}:"
                    f"{index}:{source_label}{scope_suffix}"
                ),
                kind="UnflattenUseDefSeverance",
                semantic_key=(
                    "unflatten_use_def_severance:"
                    f"func=0x{int(resolved_function_ea):x}:{index}"
                ),
                maturity=str(maturity),
                phase=str(phase),
                confidence=1.0,
                source_block=source["serial"],
                source_ea=source["ea"],
                block_fingerprint=source_label,
                payload=payload,
                evidence=tuple(
                    str(anchor["label"])
                    for anchor in (source, old_target, new_target, use)
                    if anchor["serial"] is not None
                ),
            )
        )
    return tuple(observations)


def _anchor_from_payload(value: object) -> DispatcherBlockAnchor | None:
    if not isinstance(value, Mapping):
        return None
    try:
        return DispatcherBlockAnchor(
            serial=int(value["serial"]),
            ea=int(value["ea"]),
        )
    except (KeyError, TypeError, ValueError):
        return None


def _corridors_from_payload(value: object) -> tuple[DispatcherCorridor, ...]:
    if not isinstance(value, (tuple, list)):
        return ()
    corridors: list[DispatcherCorridor] = []
    for item in value:
        if not isinstance(item, Mapping):
            continue
        raw_path = item.get("path")
        if not isinstance(raw_path, (tuple, list)):
            continue
        path = tuple(
            anchor
            for anchor in (_anchor_from_payload(raw_anchor) for raw_anchor in raw_path)
            if anchor is not None
        )
        if len(path) < 2:
            continue
        state_merge = _anchor_from_payload(item.get("state_merge"))
        if state_merge is not None and state_merge not in path:
            state_merge = None
        corridor = DispatcherCorridor(path, state_merge_anchor=state_merge)
        if corridor not in corridors:
            corridors.append(corridor)
    return tuple(corridors)


def collect_dispatcher_corridor_coverage_observations_from_metadata(
    metadata: object,
    *,
    maturity: str,
    phase: str,
    application_status: str = "pending",
    outcome_reason: str | None = None,
    observed_coverage_validation: DispatcherCorridorCoverageValidation | None = None,
    projected_coverage_validation: DispatcherCorridorCoverageValidation | None = None,
    plan_id: str | None = None,
    attempt_id: str | None = None,
) -> tuple[FactObservation, ...]:
    """Rehydrate emitter metadata for the pass-layer observability publisher."""
    if not isinstance(metadata, Mapping):
        return ()
    try:
        function_ea = int(metadata["function_ea"])
    except (KeyError, TypeError, ValueError):
        return ()
    coverage = DispatcherCorridorCoverage(
        function_ea=function_ea,
        dispatcher=_anchor_from_payload(metadata.get("dispatcher")),
        covered_corridors=_corridors_from_payload(metadata.get("covered_corridors")),
        residual_corridors=_corridors_from_payload(metadata.get("residual_corridors")),
        enumeration_complete=bool(metadata.get("enumeration_complete", False)),
    )
    return collect_dispatcher_corridor_coverage_observations(
        coverage,
        maturity=maturity,
        phase=phase,
        application_status=application_status,
        outcome_reason=outcome_reason,
        observed_coverage_validation=observed_coverage_validation,
        projected_coverage_validation=projected_coverage_validation,
        plan_id=plan_id,
        attempt_id=attempt_id,
    )


def collect_dispatcher_removal_preflight_proof_observations_from_metadata(
    metadata: object,
    *,
    coverage_metadata: object | None = None,
    maturity: str,
    phase: str,
    application_status: str = "pending",
    outcome_reason: str | None = None,
    observed_validation: DispatcherRemovalPreflightValidation | None = None,
    projected_validation: DispatcherRemovalPreflightValidation | None = None,
    observed_coverage_validation: DispatcherCorridorCoverageValidation | None = None,
    projected_coverage_validation: DispatcherCorridorCoverageValidation | None = None,
    plan_id: str | None = None,
    attempt_id: str | None = None,
) -> tuple[FactObservation, ...]:
    """Persist the proof payload without making runtime code read diagnostic DBs."""
    if application_status == "applied" and observed_validation is None:
        # A transaction can apply a partial cleanup plan while the producer's
        # dispatcher-removal proof remains rejected.  Without a post-apply
        # validation there is no applied removal claim to publish; coverage is
        # still emitted independently by the companion collector.
        return ()
    validation_only = not isinstance(metadata, Mapping)
    if validation_only:
        coverage_validation = (
            observed_coverage_validation
            if observed_validation is not None
            else projected_coverage_validation
        )
        if (
            (observed_validation is None and projected_validation is None)
            or coverage_validation is None
            or not coverage_validation.passed
            or not isinstance(coverage_metadata, Mapping)
        ):
            return ()
        try:
            function_ea = int(coverage_metadata["function_ea"])
        except (KeyError, TypeError, ValueError):
            return ()
        dispatcher = _anchor_from_payload(coverage_metadata.get("dispatcher"))
        if dispatcher is None:
            return ()
        payload = {
            "function_ea": function_ea,
            "dispatcher": dispatcher.to_payload(),
            "validation_only": True,
            "raw_proof_present": False,
        }
        lost_blocks: tuple[object, ...] = ()
    else:
        try:
            function_ea = int(metadata["function_ea"])
        except (KeyError, TypeError, ValueError):
            return ()
        dispatcher = _anchor_from_payload(metadata.get("dispatcher"))
        payload = dict(metadata)
        raw_lost_blocks = metadata.get("lost_blocks", ())
        if isinstance(raw_lost_blocks, (tuple, list)):
            lost_blocks = tuple(raw_lost_blocks)
        else:
            lost_blocks = ()
            payload["lost_blocks_malformed"] = True
    dispatcher_label = "dispatcher@?" if dispatcher is None else dispatcher.label
    scope = _diagnostic_outcome_scope(plan_id=plan_id, attempt_id=attempt_id)
    scope_suffix = f":{scope}" if scope else ""
    if application_status == "applied" and observed_validation is not None:
        if "proof_status" in payload:
            payload["producer_proof_status"] = payload["proof_status"]
        if "reason" in payload:
            payload["producer_reason"] = payload["reason"]
        payload["proof_status"] = (
            "accepted" if observed_validation.passed else "rejected"
        )
        payload["reason"] = str(observed_validation.reason)
    payload.update(
        {
            "application_status": application_status,
            "outcome_reason": outcome_reason,
            "plan_id": plan_id,
            "attempt_id": attempt_id,
        }
    )
    if observed_validation is not None:
        payload["observed_validation"] = observed_validation.to_payload()
    if projected_validation is not None:
        payload["projected_validation"] = projected_validation.to_payload()
    if observed_coverage_validation is not None:
        payload["observed_coverage_validation"] = (
            observed_coverage_validation.to_payload()
        )
    if projected_coverage_validation is not None:
        payload["projected_coverage_validation"] = (
            projected_coverage_validation.to_payload()
        )
    evidence = [dispatcher_label]
    for item in lost_blocks:
        anchor = _anchor_from_payload(item)
        if anchor is not None:
            evidence.append(anchor.label)
    return (
        FactObservation(
            fact_id=(
                "unflatten-dispatcher-removal-preflight:"
                f"{application_status}:func=0x{function_ea:x}:{dispatcher_label}"
                f"{':validation-only' if validation_only else ''}{scope_suffix}"
            ),
            kind="UnflattenDispatcherRemovalPreflightProof",
            semantic_key=(
                "unflatten_dispatcher_removal_preflight:"
                f"func=0x{function_ea:x}:{dispatcher_label}"
            ),
            maturity=str(maturity),
            phase=str(phase),
            confidence=1.0,
            source_block=None if dispatcher is None else dispatcher.serial,
            source_ea=None if dispatcher is None else dispatcher.ea,
            payload=payload,
            evidence=tuple(evidence),
        ),
    )


def collect_unflatten_dispatcher_outcome_observations_from_metadata(
    plan_metadata: object,
    *,
    maturity: str,
    phase: str,
    application_status: str = "pending",
    outcome_reason: str | None = None,
    observed_coverage_validation: DispatcherCorridorCoverageValidation | None = None,
    projected_coverage_validation: DispatcherCorridorCoverageValidation | None = None,
    observed_validation: DispatcherRemovalPreflightValidation | None = None,
    projected_validation: DispatcherRemovalPreflightValidation | None = None,
    plan_id: str | None = None,
    attempt_id: str | None = None,
) -> tuple[FactObservation, ...]:
    """Collect pending or final transaction facts from immutable plan metadata."""
    if not isinstance(plan_metadata, Mapping):
        return ()
    coverage = collect_dispatcher_corridor_coverage_observations_from_metadata(
        plan_metadata.get(DISPATCHER_CORRIDOR_COVERAGE_METADATA),
        maturity=maturity,
        phase=phase,
        application_status=application_status,
        outcome_reason=outcome_reason,
        observed_coverage_validation=observed_coverage_validation,
        projected_coverage_validation=projected_coverage_validation,
        plan_id=plan_id,
        attempt_id=attempt_id,
    )
    if not coverage:
        coverage_validation = (
            observed_coverage_validation
            if observed_coverage_validation is not None
            else projected_coverage_validation
        )
        function_ea = (
            None
            if coverage_validation is None
            else _use_def_optional_int(
                getattr(coverage_validation, "function_ea", None)
            )
        )
        if function_ea is not None:
            # A malformed present claim cannot be rehydrated into corridors,
            # but its rejected validation still needs a durable terminal fact.
            coverage = collect_dispatcher_corridor_coverage_observations(
                DispatcherCorridorCoverage(
                    function_ea=function_ea,
                    dispatcher=None,
                    covered_corridors=(),
                    residual_corridors=(),
                    enumeration_complete=False,
                ),
                maturity=maturity,
                phase=phase,
                application_status=application_status,
                outcome_reason=outcome_reason,
                observed_coverage_validation=observed_coverage_validation,
                projected_coverage_validation=projected_coverage_validation,
                plan_id=plan_id,
                attempt_id=attempt_id,
            )
    proof = collect_dispatcher_removal_preflight_proof_observations_from_metadata(
        plan_metadata.get(DISPATCHER_REMOVAL_PREFLIGHT_PROOF_METADATA),
        coverage_metadata=plan_metadata.get(DISPATCHER_CORRIDOR_COVERAGE_METADATA),
        maturity=maturity,
        phase=phase,
        application_status=application_status,
        outcome_reason=outcome_reason,
        observed_validation=observed_validation,
        projected_validation=projected_validation,
        observed_coverage_validation=observed_coverage_validation,
        projected_coverage_validation=projected_coverage_validation,
        plan_id=plan_id,
        attempt_id=attempt_id,
    )
    coverage_metadata = plan_metadata.get(DISPATCHER_CORRIDOR_COVERAGE_METADATA)
    function_ea = (
        coverage_metadata.get("function_ea")
        if isinstance(coverage_metadata, Mapping)
        else None
    )
    use_def = collect_use_def_severance_observations_from_metadata(
        plan_metadata.get(USE_DEF_SEVERANCE_AUDIT_METADATA),
        function_ea=_use_def_optional_int(function_ea),
        maturity=maturity,
        phase=phase,
        application_status=application_status,
        outcome_reason=outcome_reason,
        plan_id=plan_id,
        attempt_id=attempt_id,
    )
    return (*coverage, *proof, *use_def)


def _resolved_goto_redirects(
    patch_plan: PatchPlan,
) -> tuple[tuple[int, int, int], ...] | None:
    """Resolve exact typed goto steps onto the immutable source coordinates."""
    coordinates = dict(patch_plan.source_coordinates)
    redirects: list[tuple[int, int, int]] = []
    for step in patch_plan.steps:
        if type(step) is not PatchRedirectGoto:
            continue
        refs = (step.from_serial, step.old_target, step.new_target)
        if any(ref not in coordinates for ref in refs):
            return None
        redirects.append(tuple(int(coordinates[ref]) for ref in refs))
    return tuple(redirects)


def _unique_one_way_stop(
    flow_graph: FlowGraph,
    start_serial: int,
) -> int | None:
    """Return the unique STOP reached through a finite one-way corridor."""
    current = int(start_serial)
    seen: set[int] = set()
    while current not in seen:
        seen.add(current)
        block = flow_graph.get_block(current)
        if block is None:
            return None
        successors = tuple(int(target) for target in block.succs)
        if block.kind is BlockKind.STOP:
            return current if not successors else None
        if len(successors) != 1:
            return None
        current = successors[0]
    return None


def _detached_dispatcher_residue(
    post_graph: FlowGraph,
    dispatcher_serial: int,
) -> frozenset[int] | None:
    """Return dispatcher-rooted residue only when detached from live entry."""
    successors = post_graph.as_adjacency_dict()
    reachable = _reachable_from_entry(successors, int(post_graph.entry_serial))
    dispatcher = int(dispatcher_serial)
    if dispatcher in reachable or dispatcher not in successors:
        return None
    unreachable = set(successors) - reachable
    residue: set[int] = set()
    pending = deque((dispatcher,))
    while pending:
        serial = int(pending.popleft())
        if serial in residue or serial not in unreachable:
            continue
        residue.add(serial)
        pending.extend(
            int(target)
            for target in successors.get(serial, ())
            if int(target) in unreachable
        )

    return frozenset(residue)


def _residue_is_acyclic(
    post_graph: FlowGraph,
    residue: frozenset[int],
) -> bool:
    successors = post_graph.as_adjacency_dict()
    indegree = {serial: 0 for serial in residue}
    for serial in residue:
        for target in successors.get(serial, ()):
            target = int(target)
            if target in residue:
                indegree[target] += 1
    roots = deque(serial for serial, degree in indegree.items() if degree == 0)
    visited_count = 0
    while roots:
        serial = int(roots.popleft())
        visited_count += 1
        for target in successors.get(serial, ()):
            target = int(target)
            if target not in indegree:
                continue
            indegree[target] -= 1
            if indegree[target] == 0:
                roots.append(target)
    return visited_count == len(residue)


def validate_terminal_switch_cycle_break_allowance(
    pre_graph: FlowGraph,
    *,
    post_graph: FlowGraph,
    patch_plan: PatchPlan,
    removal_validation: DispatcherRemovalPreflightValidation,
) -> DispatcherRemovalPreflightValidation:
    """Accept only an exact terminal redirect that makes switch residue acyclic.

    The ordinary removal proof remains rejected: this allowance does not
    reclassify arbitrary lost blocks as dispatcher infrastructure.  It proves
    a different fact from immutable plan and CFG structure: a terminal handler
    bypasses one shared merge, and that same merge is redirected away from the
    switch dispatcher so the now-detached residue cannot spin Hex-Rays.
    """
    proof = removal_validation.proof
    dispatcher = None if proof is None else proof.dispatcher
    if (
        proof is None
        or dispatcher is None
        or proof.reason != "untyped_lost_block"
        or proof.passed
        or not proof.authoritative_handlers
    ):
        return removal_validation
    dispatcher_block = pre_graph.get_block(int(dispatcher.serial))
    if dispatcher_block is None or dispatcher_block.kind is not BlockKind.N_WAY:
        return removal_validation
    redirects = _resolved_goto_redirects(patch_plan)
    if redirects is None:
        return removal_validation
    handler_serials = {int(anchor.serial) for anchor in proof.authoritative_handlers}
    candidates: list[tuple[int, int, int, int]] = []
    for merge, old_dispatcher, target in redirects:
        if old_dispatcher != int(dispatcher.serial):
            continue
        merge_block = pre_graph.get_block(merge)
        if merge_block is None or tuple(merge_block.succs) != (old_dispatcher,):
            continue
        for source, old_merge, terminal_target in redirects:
            if old_merge != merge or terminal_target != target:
                continue
            source_block = pre_graph.get_block(source)
            if (
                source == merge
                or source_block is None
                or tuple(source_block.succs) != (merge,)
                or source not in handler_serials
                or target not in handler_serials
            ):
                continue
            stop = _unique_one_way_stop(pre_graph, target)
            if stop is not None:
                candidates.append((source, merge, target, stop))
    if len(candidates) != 1:
        return removal_validation
    terminal_source, shared_merge, terminal_target, terminal_stop = candidates[0]
    projected_source = post_graph.get_block(terminal_source)
    projected_merge = post_graph.get_block(shared_merge)
    if (
        projected_source is None
        or tuple(projected_source.succs) != (terminal_target,)
        or projected_merge is None
        or tuple(projected_merge.succs) != (terminal_target,)
    ):
        return removal_validation
    residue = _detached_dispatcher_residue(post_graph, int(dispatcher.serial))
    if (
        residue is None
        or shared_merge not in residue
        or residue != proof.lost_blocks
        or not _residue_is_acyclic(post_graph, residue)
    ):
        return removal_validation
    cycle_break = TerminalSwitchCycleBreakProof(
        dispatcher=dispatcher,
        terminal_source=_anchor(pre_graph, terminal_source),
        shared_merge=_anchor(pre_graph, shared_merge),
        terminal_target=_anchor(pre_graph, terminal_target),
        terminal_stop=_anchor(pre_graph, terminal_stop),
        retired_residue=_anchors_for_serials(pre_graph, residue),
    )
    return DispatcherRemovalPreflightValidation(
        passed=True,
        reason="terminal_switch_cycle_break",
        proof=proof,
        terminal_switch_cycle_break=cycle_break,
    )
