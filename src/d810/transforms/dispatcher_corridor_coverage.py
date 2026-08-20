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
from dataclasses import dataclass, replace

from d810.analyses.control_flow.graph_checks import reachable_terminal_blocks
from d810.analyses.control_flow.edit_simulation import simulate_edits
from d810.analyses.control_flow.state_carrier import (
    prove_exact_u32_carrier_state_write,
    prove_exact_u32_state_transform_feeder,
)
from d810.analyses.control_flow.minimal_state_recovery import (
    CandidatePrefixAlternateCorridorProof,
    build_current_u32_decision_forest,
    route_current_u32_decision_forest,
    validate_candidate_prefix_alternate_corridor_proof,
)
from d810.analyses.control_flow.route_predicate import DecisionDag
from d810.analyses.control_flow.instruction_semantics import (
    comparison_width,
    evaluate_branch_predicate,
    split_const_storage_identity_from_branch,
)
from d810.analyses.value_flow.observation import FactObservation
from d810.ir.expressions import ValueOpKind
from d810.ir.flowgraph import (
    BlockKind,
    FlowGraph,
    InsnKind,
    MopSnapshot,
    OperandKind,
    PredicateKind,
)
from d810.ir.insn_projection import (
    InstructionProjection,
    is_effect_free_operand_tree,
)
from d810.ir.instructions import Instruction
from d810.ir.semantics import ControlTransferKind
from d810.ir.storage_identity import (
    StorageIdentity,
    StorageIdentityKind,
    storage_identity_from_record,
    storage_identity_from_varnode,
)
from d810.ir.varnode import Space, Varnode
from d810.transforms.cfg_transaction import LogicalBlockRef, NativeBlockRef
from d810.transforms.graph_modification import (
    ConvertToGoto,
    EdgeRedirectViaPredSplit,
    LowerConditionalStateTransition,
    RedirectBranch,
    RedirectGoto,
)
from d810.transforms.edit_simulator import graph_modifications_to_simulated_edits
from d810.transforms.plan import (
    PatchLowerConditionalStateTransition,
    PatchPlan,
    PatchRedirectBranch,
    PatchRedirectGoto,
)

DISPATCHER_CORRIDOR_COVERAGE_METADATA = "dispatcher_corridor_coverage"
DISPATCHER_REMOVAL_PREFLIGHT_PROOF_METADATA = "dispatcher_removal_preflight_proof"
UNFLATTEN_COMPLETION_STATUS_METADATA = "unflatten_completion_status"
FULL_UNFLATTENING_CLAIM_METADATA = "full_unflattening_claim"
USE_DEF_SEVERANCE_AUDIT_METADATA = "use_def_severance_audit"

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
    "IntervalStateNormalizerRetirementProof",
    "IntervalStateNormalizerRouteProof",
    "IntervalStateSourceRouteProof",
    "StateTransitionPlumbingRetirementProof",
    "StateTransitionPlumbingRouteProof",
    "TerminalSwitchCycleBreakProof",
    "RetiredDispatcherInfrastructure",
    "analyze_dispatcher_corridor_coverage",
    "build_dispatcher_removal_preflight_proof",
    "collect_dispatcher_corridor_coverage_observations",
    "collect_dispatcher_corridor_coverage_observations_from_metadata",
    "collect_dispatcher_removal_preflight_proof_observations_from_metadata",
    "collect_use_def_severance_observations_from_metadata",
    "collect_unflatten_dispatcher_outcome_observations_from_metadata",
    "has_unreachable_cyclic_switch_dispatcher_residue",
    "canonicalize_observed_dispatcher_graph",
    "validate_dispatcher_corridor_coverage_metadata",
    "validate_dispatcher_removal_preflight_proof",
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
        if int(predecessor) == int(dispatcher_serial):
            # The dispatcher is the corridor boundary, not another shared
            # merge to expand.  Following its predecessors re-enters the same
            # state-machine feeders and falsely turns a finite dispatcher
            # cycle into incomplete enumeration.
            append((int(predecessor), *suffix))
            return
        incoming_to_predecessor = predecessors.get(int(predecessor), ())
        if len(incoming_to_predecessor) > 1 and successors.get(
            int(predecessor), ()
        ) == (int(suffix[0]),):
            for merge_input in incoming_to_predecessor:
                merge_input = int(merge_input)
                if merge_input in seen:
                    if merge_input == int(dispatcher_serial) or is_dispatcher_self_reentry_input(
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


def _candidate_prefix_exclusion_from_payload(
    payload: object,
) -> CandidatePrefixAlternateCorridorProof | None:
    if not isinstance(payload, Mapping):
        return None

    def anchor(name: str) -> tuple[int, int] | None:
        value = payload.get(name)
        if not isinstance(value, Mapping):
            return None
        try:
            return int(value["serial"]), int(value["ea"])
        except (KeyError, TypeError, ValueError):
            return None

    source = anchor("source")
    prefix = anchor("prefix")
    root = anchor("root")
    feeder_payload = payload.get("feeder")
    feeder = None if feeder_payload is None else anchor("feeder")
    identity_payload = payload.get("state_identity")
    if (
        source is None
        or prefix is None
        or root is None
        or (feeder_payload is not None and feeder is None)
        or not isinstance(identity_payload, Mapping)
    ):
        return None
    try:
        state = int(payload["normalized_state"])
        identity = storage_identity_from_record(identity_payload)
    except (KeyError, TypeError, ValueError):
        return None
    if state < 0 or state > 0xFFFFFFFF:
        return None
    return CandidatePrefixAlternateCorridorProof(
        normalized_state=state,
        source_serial=source[0],
        source_ea=source[1],
        feeder_serial=None if feeder is None else feeder[0],
        feeder_ea=None if feeder is None else feeder[1],
        prefix_serial=prefix[0],
        prefix_ea=prefix[1],
        root_serial=root[0],
        root_ea=root[1],
        state_identity=identity,
    )


def _semantic_exclusions_from_coverage_metadata(
    coverage: Mapping[str, object],
) -> tuple[CandidatePrefixAlternateCorridorProof, ...] | None:
    raw_exclusions = coverage.get("semantic_exclusions", ())
    if not isinstance(raw_exclusions, (tuple, list)):
        return None
    parsed = tuple(
        _candidate_prefix_exclusion_from_payload(payload)
        for payload in raw_exclusions
    )
    if any(proof is None for proof in parsed):
        return None
    return tuple(proof for proof in parsed if proof is not None)


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


def canonicalize_observed_dispatcher_graph(
    pre_graph: FlowGraph,
    observed_graph: FlowGraph,
    plan: object,
) -> FlowGraph:
    """Map live helper/serial topology back onto stable pre-CFG identities.

    Conditional state lowering must create a physically adjacent fall-through
    helper.  That helper shifts later snapshot-local serials, so raw observed
    adjacency is not comparable with pre-snapshot coverage metadata.  Original
    blocks are matched by their native block-start anchors.  When Hex-Rays
    merely resegments a block, a unique and mutually unambiguous overlap in
    native instruction origins may recover that identity.  Helper chains are
    admitted only when they are reachable from a typed conditional lowering
    and terminate at one of its declared arms.  Every other identity or
    topology drift fails closed.
    """
    if not isinstance(pre_graph, FlowGraph) or not isinstance(
        observed_graph, FlowGraph
    ):
        raise TypeError("dispatcher observation canonicalization requires FlowGraphs")

    lowerings: list[PatchLowerConditionalStateTransition] = []
    branch_redirects: list[PatchRedirectBranch] = []
    for step in getattr(plan, "steps", ()) or ():
        match step:
            case PatchLowerConditionalStateTransition() as lowering:
                lowerings.append(lowering)
            case PatchRedirectBranch() as redirect:
                branch_redirects.append(redirect)
    if not lowerings and not any(
        redirect.fallthrough_helper_block_id is not None
        for redirect in branch_redirects
    ):
        return observed_graph

    def drift(reason: str) -> ValueError:
        return ValueError(f"dispatcher_corridor_coverage_identity_drift: {reason}")

    if int(pre_graph.func_ea) != int(observed_graph.func_ea):
        raise drift("function identity changed")

    pre_by_anchor: dict[int, list[int]] = {}
    addressless_pre: list[int] = []
    for serial, block in pre_graph.blocks.items():
        anchor = _stable_block_start_ea(block)
        if anchor is None:
            addressless_pre.append(int(serial))
            continue
        pre_by_anchor.setdefault(anchor, []).append(int(serial))

    observed_by_anchor: dict[int, list[int]] = {}
    addressless_observed: list[int] = []
    for serial, block in observed_graph.blocks.items():
        anchor = _stable_block_start_ea(block)
        if anchor is None:
            addressless_observed.append(int(serial))
            continue
        observed_by_anchor.setdefault(anchor, []).append(int(serial))

    observed_for_pre: dict[int, int] = {}
    claimed_observed: set[int] = set()
    # Hex-Rays commonly clones a block without assigning a distinct native
    # start EA.  A preserved serial plus the same native anchor is stronger
    # identity than the anchor alone, so bind those exact pairs first.
    for anchor, pre_serials in pre_by_anchor.items():
        candidates = set(observed_by_anchor.get(anchor, ()))
        for pre_serial in pre_serials:
            if pre_serial in candidates:
                observed_for_pre[pre_serial] = pre_serial
                claimed_observed.add(pre_serial)

    # Helper insertion can shift a remaining original serial.  After the exact
    # pairs have been claimed, accept only a one-to-one residual anchor match.
    for anchor, pre_serials in pre_by_anchor.items():
        unmatched_pre = tuple(
            serial for serial in pre_serials if serial not in observed_for_pre
        )
        unmatched_observed = tuple(
            serial
            for serial in observed_by_anchor.get(anchor, ())
            if serial not in claimed_observed
        )
        # Extra observed blocks at an already-matched anchor can be generated
        # conditional-lowering helpers. Their exact ownership is validated
        # below; they must not make the preserved original appear missing.
        if not unmatched_pre:
            continue
        if len(unmatched_pre) != len(unmatched_observed):
            # A mutation can move the first instruction and therefore change a
            # live block's start anchor without changing its native identity.
            # Defer this block to the instruction-origin reconciliation below.
            continue
        if len(unmatched_pre) > 1:
            raise drift(
                f"pre block-start EA 0x{anchor:x} has ambiguous residual serials"
            )
        if unmatched_pre:
            observed_for_pre[unmatched_pre[0]] = unmatched_observed[0]
            claimed_observed.add(unmatched_observed[0])

    # Block-boundary resegmentation is accepted only when instruction origins
    # establish a one-to-one relation in both directions.  This cannot turn a
    # missing or split block into a guessed identity: empty, competing, and
    # many-to-one overlaps all remain fatal.
    unresolved_pre = tuple(
        serial
        for serials in pre_by_anchor.values()
        for serial in serials
        if serial not in observed_for_pre
    )
    unclaimed_observed = tuple(
        int(serial)
        for serial in observed_graph.blocks
        if int(serial) not in claimed_observed
    )
    overlap_candidates: dict[int, tuple[int, ...]] = {}
    reverse_candidates: dict[int, list[int]] = {}
    for pre_serial in unresolved_pre:
        pre_origins = _native_instruction_eas(pre_graph.blocks[pre_serial])
        candidates = tuple(
            observed_serial
            for observed_serial in unclaimed_observed
            if pre_origins
            & _native_instruction_eas(observed_graph.blocks[observed_serial])
        )
        overlap_candidates[pre_serial] = candidates
        for observed_serial in candidates:
            reverse_candidates.setdefault(observed_serial, []).append(pre_serial)

    for pre_serial in unresolved_pre:
        candidates = overlap_candidates[pre_serial]
        if len(candidates) != 1 or len(reverse_candidates[candidates[0]]) != 1:
            anchor = _stable_block_start_ea(pre_graph.blocks[pre_serial])
            overlap_detail = tuple(
                (
                    observed_serial,
                    tuple(
                        sorted(
                            _native_instruction_eas(pre_graph.blocks[pre_serial])
                            & _native_instruction_eas(
                                observed_graph.blocks[observed_serial]
                            )
                        )
                    ),
                )
                for observed_serial in candidates
            )
            anchor_text = "addressless" if anchor is None else f"0x{anchor:x}"
            raise drift(
                f"pre block {pre_serial}@{anchor_text} is missing or ambiguous; "
                f"instruction_overlap={overlap_detail}"
            )
        observed_serial = candidates[0]
        observed_for_pre[pre_serial] = observed_serial
        claimed_observed.add(observed_serial)

    addressless_observed_set = set(addressless_observed)
    for pre_serial in addressless_pre:
        if pre_serial in addressless_observed_set and _addressless_block_signature(
            pre_graph.blocks[pre_serial]
        ) == _addressless_block_signature(observed_graph.blocks[pre_serial]):
            observed_for_pre[pre_serial] = pre_serial
            claimed_observed.add(pre_serial)

    unmatched_addressless_pre: dict[tuple[object, ...], list[int]] = {}
    unmatched_addressless_observed: dict[tuple[object, ...], list[int]] = {}
    for serial in addressless_pre:
        if serial not in observed_for_pre:
            unmatched_addressless_pre.setdefault(
                _addressless_block_signature(pre_graph.blocks[serial]), []
            ).append(serial)
    for serial in addressless_observed:
        if serial not in claimed_observed:
            unmatched_addressless_observed.setdefault(
                _addressless_block_signature(observed_graph.blocks[serial]), []
            ).append(serial)
    for signature, pre_serials in unmatched_addressless_pre.items():
        candidates = unmatched_addressless_observed.get(signature, [])
        if len(pre_serials) != 1 or len(candidates) != 1:
            raise drift(
                "addressless pre block identity is missing or ambiguous: "
                f"pre={tuple(pre_serials)} observed={tuple(candidates)}"
            )
        observed_for_pre[pre_serials[0]] = candidates[0]
        claimed_observed.add(candidates[0])

    pre_for_observed = {
        observed_serial: pre_serial
        for pre_serial, observed_serial in observed_for_pre.items()
    }

    observed_serials = {int(serial) for serial in observed_graph.blocks}
    for serial, block in observed_graph.blocks.items():
        serial = int(serial)
        succs = tuple(int(target) for target in block.succs)
        preds = tuple(int(source) for source in block.preds)
        if len(set(succs)) != len(succs) or len(set(preds)) != len(preds):
            raise drift(f"CFG_50858 duplicate edge data at observed block {serial}")
        if any(target not in observed_serials for target in succs):
            raise drift(
                f"CFG_50858 observed block {serial} references a missing successor"
            )
        if any(source not in observed_serials for source in preds):
            raise drift(
                f"CFG_50858 observed block {serial} references a missing predecessor"
            )
        expected_preds = tuple(
            sorted(
                source
                for source, source_block in observed_graph.blocks.items()
                if serial in source_block.succs
            )
        )
        if tuple(sorted(set(preds))) != expected_preds:
            raise drift(
                f"CFG_50858 observed block {serial} predecessor mismatch: "
                f"declared={preds} expected={expected_preds}"
            )

    source_coordinates = dict(getattr(plan, "source_coordinates", ()) or ())

    def pre_serial_for_ref(ref: object, field_name: str) -> int:
        if isinstance(ref, int) and not isinstance(ref, bool):
            serial = int(ref)
        elif isinstance(ref, (NativeBlockRef, LogicalBlockRef)):
            serial = source_coordinates.get(ref)
            if serial is None:
                raise drift(f"conditional {field_name} lacks a source coordinate")
            serial = int(serial)
        else:
            raise drift(f"conditional {field_name} is unresolved")
        if serial not in pre_graph.blocks:
            raise drift(f"conditional {field_name} points to missing block {serial}")
        return serial

    lower_by_source: dict[
        int, tuple[PatchLowerConditionalStateTransition, int, int, int]
    ] = {}
    for lowering in lowerings:
        source = pre_serial_for_ref(lowering.source_serial, "source")
        old_dispatcher = pre_serial_for_ref(
            lowering.old_dispatcher_serial,
            "old dispatcher",
        )
        false_target = pre_serial_for_ref(lowering.false_target_serial, "false target")
        true_target = pre_serial_for_ref(lowering.true_target_serial, "true target")
        if old_dispatcher not in pre_graph.blocks[source].succs:
            raise drift(
                f"conditional source {source} does not target dispatcher {old_dispatcher}"
            )
        if false_target == true_target:
            raise drift(f"conditional source {source} has identical arms")
        existing = lower_by_source.get(source)
        arms = (old_dispatcher, false_target, true_target)
        if existing is not None and existing[1:] != arms:
            raise drift(f"conditional source {source} has conflicting lowerings")
        lower_by_source[source] = (lowering, *arms)

    redirects_by_source: dict[
        int, dict[int, tuple[PatchRedirectBranch, int]]
    ] = {}
    for redirect in branch_redirects:
        source = pre_serial_for_ref(redirect.from_serial, "redirect source")
        old_target = pre_serial_for_ref(redirect.old_target, "redirect old target")
        new_target = pre_serial_for_ref(redirect.new_target, "redirect new target")
        source_block = pre_graph.blocks[source]
        if source in lower_by_source:
            raise drift(
                f"conditional source {source} mixes lowering and branch redirect"
            )
        if (
            source_block.kind is not BlockKind.TWO_WAY
            or source_block.tail_kind
            not in {InsnKind.COND_JUMP, InsnKind.EQUALITY_JUMP}
            or old_target not in source_block.succs
        ):
            raise drift(f"branch redirect source {source} lacks its old arm")
        source_redirects = redirects_by_source.setdefault(source, {})
        existing = source_redirects.get(old_target)
        if existing is not None and existing[1] != new_target:
            raise drift(f"branch redirect source {source} has conflicting arms")
        source_redirects[old_target] = (redirect, new_target)

    def true_is_taken(lowering: PatchLowerConditionalStateTransition) -> bool:
        marker = getattr(lowering.condition_operand, "true_is_taken", True)
        if marker not in (True, False):
            raise drift("conditional lowering has an untyped true_is_taken marker")
        return bool(marker)

    def instruction_eas(insn: object) -> tuple[int, ...]:
        eas: list[int] = []
        for field_name in ("ea", "native_ea"):
            value = getattr(insn, field_name, None)
            if value is None:
                continue
            try:
                eas.append(int(value))
            except (TypeError, ValueError):
                continue
        return tuple(eas)

    def predicate_signature(insn: object) -> tuple[object, ...]:
        return (
            getattr(insn, "opcode", None),
            getattr(insn, "raw_opcode", None),
            getattr(insn, "kind", None),
            getattr(insn, "predicate_kind", None),
            getattr(insn, "branch_predicate", None),
            getattr(insn, "compare_width", None),
            getattr(insn, "l", None),
            getattr(insn, "r", None),
        )

    def validate_synthetic_predicate(
        source: int,
        observed_tail: object,
        condition: object,
    ) -> None:
        left = getattr(observed_tail, "l", None)
        right = getattr(observed_tail, "r", None)
        if (
            getattr(condition, "predicate_reg", None) is not None
            and getattr(condition, "predicate_size", None) is not None
        ):
            if not (
                getattr(observed_tail, "predicate_kind", None) is PredicateKind.NE
                and isinstance(left, MopSnapshot)
                and left.kind is OperandKind.REGISTER
                and left.reg == int(condition.predicate_reg)
                and left.size == int(condition.predicate_size)
                and isinstance(right, MopSnapshot)
                and right.kind is OperandKind.NUMBER
                and right.value == 0
                and right.size == int(condition.predicate_size)
            ):
                raise drift(
                    f"conditional source {source} synthetic register predicate identity mismatch"
                )
            return

        nested = left
        nested_left = getattr(nested, "sub_l", None)
        nested_right = getattr(nested, "sub_r", None)
        if (
            getattr(condition, "stack_stkoff", None) is not None
            and getattr(condition, "stack_size", None) is not None
            and getattr(condition, "value", None) is not None
        ):
            tail_predicate = getattr(observed_tail, "predicate_kind", None)
            direct_comparison = tail_predicate is PredicateKind.EQ
            wrapped_comparison = (
                tail_predicate is PredicateKind.NE
                and isinstance(nested, MopSnapshot)
                and nested.kind is OperandKind.SUBINSN
                and nested.sub_predicate_kind is PredicateKind.EQ
                and isinstance(right, MopSnapshot)
                and right.kind is OperandKind.NUMBER
                and right.value == 0
            )
            compared_left = left if direct_comparison else nested_left
            compared_right = right if direct_comparison else nested_right
            size = int(condition.stack_size)
            if not (
                (direct_comparison or wrapped_comparison)
                and isinstance(compared_left, MopSnapshot)
                and compared_left.kind is OperandKind.STACK
                and compared_left.stkoff == int(condition.stack_stkoff)
                and compared_left.size == size
                and isinstance(compared_right, MopSnapshot)
                and compared_right.kind is OperandKind.NUMBER
                and compared_right.value
                == int(condition.value) & ((1 << (8 * size)) - 1)
                and compared_right.size == size
            ):
                raise drift(
                    f"conditional source {source} synthetic stack predicate identity mismatch"
                )
            return

        if (
            getattr(condition, "bound", None) is not None
            and getattr(condition, "counter_size", None) is not None
            and (
                getattr(condition, "counter_reg", None) is not None
                or getattr(condition, "counter_stkoff", None) is not None
            )
        ):
            expected_predicate = (
                PredicateKind.SLT
                if bool(getattr(condition, "signed", True))
                else PredicateKind.ULT
            )
            expected_counter_kind = (
                OperandKind.REGISTER
                if getattr(condition, "counter_reg", None) is not None
                else OperandKind.STACK
            )
            expected_counter = (
                getattr(condition, "counter_reg", None)
                if expected_counter_kind is OperandKind.REGISTER
                else getattr(condition, "counter_stkoff", None)
            )
            size = int(condition.counter_size)
            tail_predicate = getattr(observed_tail, "predicate_kind", None)
            direct_comparison = tail_predicate is expected_predicate
            wrapped_comparison = (
                tail_predicate is PredicateKind.NE
                and isinstance(nested, MopSnapshot)
                and nested.kind is OperandKind.SUBINSN
                and nested.sub_predicate_kind is expected_predicate
                and isinstance(right, MopSnapshot)
                and right.kind is OperandKind.NUMBER
                and right.value == 0
            )
            compared_left = left if direct_comparison else nested_left
            compared_right = right if direct_comparison else nested_right
            actual_counter = (
                compared_left.reg
                if isinstance(compared_left, MopSnapshot)
                and expected_counter_kind is OperandKind.REGISTER
                else compared_left.stkoff
                if isinstance(compared_left, MopSnapshot)
                else None
            )
            if not (
                (direct_comparison or wrapped_comparison)
                and isinstance(compared_left, MopSnapshot)
                and compared_left.kind is expected_counter_kind
                and actual_counter == int(expected_counter)
                and compared_left.size == size
                and isinstance(compared_right, MopSnapshot)
                and compared_right.kind is OperandKind.NUMBER
                and compared_right.value
                == int(condition.bound) & ((1 << (8 * size)) - 1)
                and compared_right.size == size
            ):
                raise drift(
                    f"conditional source {source} synthetic counter predicate identity mismatch"
                )
            return

        raise drift(
            f"conditional source {source} synthetic predicate identity is untyped"
        )

    def validate_lowering_identity(
        source: int,
        observed_block: object,
        lowering: PatchLowerConditionalStateTransition,
    ) -> None:
        if getattr(observed_block, "kind", None) is not BlockKind.TWO_WAY:
            raise drift(f"conditional source {source} is not observed as TWO_WAY")
        if getattr(observed_block, "tail_kind", None) not in {
            InsnKind.COND_JUMP,
            InsnKind.EQUALITY_JUMP,
        }:
            raise drift(
                f"conditional source {source} lacks an observed conditional tail"
            )
        rewrite_ea = int(lowering.rewrite_from_ea)
        insns = tuple(getattr(observed_block, "insn_snapshots", ()) or ())
        matches = tuple(insn for insn in insns if rewrite_ea in instruction_eas(insn))
        if not insns or len(matches) != 1 or matches[0] is not insns[-1]:
            raise drift(
                f"conditional source {source} predicate/rewrite identity mismatch"
            )
        observed_tail = matches[0]
        if getattr(observed_tail, "kind", None) not in {
            InsnKind.COND_JUMP,
            InsnKind.EQUALITY_JUMP,
        }:
            raise drift(
                f"conditional source {source} predicate/rewrite identity mismatch"
            )
        condition = lowering.condition_operand
        if bool(getattr(condition, "preserve_live_predicate", False)):
            predicate_ea = getattr(condition, "predicate_ea", None)
            if predicate_ea is None or int(predicate_ea) != rewrite_ea:
                raise drift(
                    f"conditional source {source} preserved predicate identity mismatch"
                )
            if (
                getattr(observed_tail, "predicate_kind", None) is None
                and getattr(observed_tail, "branch_predicate", None) is None
            ):
                raise drift(
                    f"conditional source {source} preserved predicate identity is untyped"
                )
            pre_block = pre_graph.get_block(source)
            pre_insns = tuple(getattr(pre_block, "insn_snapshots", ()) or ())
            pre_matches = tuple(
                insn for insn in pre_insns if rewrite_ea in instruction_eas(insn)
            )
            if (
                not pre_insns
                or len(pre_matches) != 1
                or pre_matches[0] is not pre_insns[-1]
                or predicate_signature(pre_matches[0])
                != predicate_signature(observed_tail)
            ):
                raise drift(
                    f"conditional source {source} preserved predicate identity mismatch"
                )
        else:
            validate_synthetic_predicate(source, observed_tail, condition)
        expected_predicate = getattr(condition, "predicate_kind", None)
        if expected_predicate is None:
            expected_predicate = getattr(condition, "branch_predicate", None)
        observed_predicate = getattr(observed_tail, "predicate_kind", None)
        if observed_predicate is None:
            observed_predicate = getattr(observed_tail, "branch_predicate", None)
        if expected_predicate is not None and observed_predicate != expected_predicate:
            raise drift(
                f"conditional source {source} predicate/rewrite identity mismatch"
            )
        true_is_taken(lowering)

    helper_serials = set(observed_graph.blocks) - set(pre_for_observed)
    owned_helpers: set[int] = set()

    def validate_helper(
        *,
        source: int,
        observed_source: int,
        helper: int,
        expected_target: int,
        role: str,
        state_register: int | None = None,
        state_size: int | None = None,
        state_value: int | None = None,
        rewrite_ea: int | None = None,
    ) -> None:
        if helper not in helper_serials:
            raise drift(
                f"conditional source {source} {role} arm is not an observed helper"
            )
        if helper in owned_helpers:
            raise drift(f"observed helper {helper} is shared by conditional arms")
        expected_offset = 1 if role == "fallthrough" else 2
        stateful_helper = all(
            value is not None for value in (state_register, state_size, state_value)
        )
        if (
            role == "fallthrough" or stateful_helper
        ) and helper != observed_source + expected_offset:
            raise drift(
                f"conditional source {source} {role} helper is not physically adjacent"
            )
        block = observed_graph.get_block(helper)
        if (
            block is None
            or block.kind is not BlockKind.ONE_WAY
            or block.tail_kind is not InsnKind.GOTO
            or len(block.succs) != 1
        ):
            raise drift(
                f"observed helper {helper} is not an owned ONE_WAY/GOTO one-hop helper"
            )
        if tuple(int(pred) for pred in block.preds) != (observed_source,):
            raise drift(f"observed helper {helper} has multiple or foreign owners")
        target_pre = pre_for_observed.get(int(block.succs[0]))
        if target_pre != expected_target:
            raise drift(f"observed helper {helper} is not a direct {role} arm helper")
        incoming_edges = sum(
            sum(int(target) == helper for target in source_block.succs)
            for source_block in observed_graph.blocks.values()
        )
        if incoming_edges != 1:
            raise drift(f"observed helper {helper} is shared or multiply referenced")
        if stateful_helper:
            insns = tuple(getattr(block, "insn_snapshots", ()) or ())
            if len(insns) != 2:
                raise drift(f"observed helper {helper} lacks its exact state write")
            assignment, goto = insns
            size = int(state_size)
            mask = (1 << (8 * size)) - 1
            source_operand = getattr(assignment, "l", None)
            dest_operand = getattr(assignment, "d", None)
            # Hex-Rays m_goto carries its block reference in ``l``; portable
            # InsnSnapshot preserves that canonical slot.
            goto_dest = getattr(goto, "l", None)
            if not (
                getattr(assignment, "kind", None) is InsnKind.MOV
                and rewrite_ea is not None
                and int(rewrite_ea) in instruction_eas(assignment)
                and getattr(source_operand, "kind", None) is OperandKind.NUMBER
                and getattr(source_operand, "size", None) == size
                and getattr(source_operand, "value", None) == int(state_value) & mask
                and getattr(dest_operand, "kind", None) is OperandKind.REGISTER
                and getattr(dest_operand, "reg", None) == int(state_register)
                and getattr(dest_operand, "size", None) == size
                and getattr(goto, "kind", None) is InsnKind.GOTO
                and getattr(goto_dest, "kind", None) is OperandKind.BLOCK
                and getattr(goto_dest, "block_ref", None) == int(block.succs[0])
            ):
                raise drift(f"observed helper {helper} has the wrong state write")
        owned_helpers.add(helper)

    canonical_successors: dict[int, tuple[int, ...]] = {}
    for pre_serial, observed_serial in observed_for_pre.items():
        observed_block = observed_graph.get_block(observed_serial)
        if observed_block is None:
            raise drift(f"observed block {observed_serial} disappeared")
        lowering_entry = lower_by_source.get(pre_serial)
        if lowering_entry is not None:
            lowering, _old_dispatcher, false_target, true_target = lowering_entry
            validate_lowering_identity(pre_serial, observed_block, lowering)
            if len(observed_block.succs) != 2:
                raise drift(
                    f"conditional source {pre_serial} is not observed as two-way"
                )
            is_true_taken = true_is_taken(lowering)
            fallthrough_target = false_target if is_true_taken else true_target
            taken_target = true_target if is_true_taken else false_target
            state_fields = (
                lowering.state_register,
                lowering.state_size,
                lowering.false_state,
                lowering.true_state,
            )
            if any(value is not None for value in state_fields) and not all(
                value is not None for value in state_fields
            ):
                raise drift(
                    f"conditional source {pre_serial} has partial arm-state proof"
                )
            stateful = all(value is not None for value in state_fields)
            observed_fallthrough = int(observed_block.succs[0])
            observed_taken = int(observed_block.succs[1])
            validate_helper(
                source=pre_serial,
                observed_source=observed_serial,
                helper=observed_fallthrough,
                expected_target=fallthrough_target,
                role="fallthrough",
                state_register=lowering.state_register if stateful else None,
                state_size=lowering.state_size if stateful else None,
                state_value=(
                    lowering.false_state if is_true_taken else lowering.true_state
                )
                if stateful
                else None,
                rewrite_ea=int(lowering.rewrite_from_ea),
            )
            if stateful:
                validate_helper(
                    source=pre_serial,
                    observed_source=observed_serial,
                    helper=observed_taken,
                    expected_target=taken_target,
                    role="taken",
                    state_register=lowering.state_register,
                    state_size=lowering.state_size,
                    state_value=(
                        lowering.true_state if is_true_taken else lowering.false_state
                    ),
                    rewrite_ea=int(lowering.rewrite_from_ea),
                )
            else:
                if observed_taken not in pre_for_observed:
                    raise drift(
                        f"conditional source {pre_serial} has an unexpected taken helper"
                    )
                if pre_for_observed[observed_taken] != taken_target:
                    raise drift(
                        f"conditional source {pre_serial} observed arms differ from plan"
                    )
            canonical_successors[pre_serial] = (false_target, true_target)
        elif pre_serial in redirects_by_source:
            pre_block = pre_graph.blocks[pre_serial]
            pre_insns = tuple(getattr(pre_block, "insn_snapshots", ()) or ())
            observed_insns = tuple(
                getattr(observed_block, "insn_snapshots", ()) or ()
            )
            if (
                observed_block.kind is not BlockKind.TWO_WAY
                or observed_block.tail_kind
                not in {InsnKind.COND_JUMP, InsnKind.EQUALITY_JUMP}
                or len(pre_insns) == 0
                or len(observed_insns) == 0
                or predicate_signature(pre_insns[-1])
                != predicate_signature(observed_insns[-1])
                or len(observed_block.succs) != len(pre_block.succs)
            ):
                raise drift(
                    f"branch redirect source {pre_serial} predicate identity mismatch"
                )
            canonical_targets: list[int] = []
            redirects = redirects_by_source[pre_serial]
            for arm_index, old_target in enumerate(pre_block.succs):
                redirect_entry = redirects.get(int(old_target))
                expected_target = (
                    int(old_target)
                    if redirect_entry is None
                    else int(redirect_entry[1])
                )
                observed_target = int(observed_block.succs[arm_index])
                if (
                    redirect_entry is not None
                    and redirect_entry[0].fallthrough_helper_block_id is not None
                ):
                    validate_helper(
                        source=pre_serial,
                        observed_source=observed_serial,
                        helper=observed_target,
                        expected_target=expected_target,
                        role="fallthrough",
                    )
                elif pre_for_observed.get(observed_target) != expected_target:
                    raise drift(
                        f"branch redirect source {pre_serial} observed arms differ "
                        "from plan"
                    )
                canonical_targets.append(expected_target)
            canonical_successors[pre_serial] = tuple(canonical_targets)
        else:
            translated: list[int] = []
            for target in observed_block.succs:
                stable_target = pre_for_observed.get(int(target))
                if stable_target is None:
                    raise drift(f"unplanned observed block {int(target)} is referenced")
                translated.append(stable_target)
            canonical_successors[pre_serial] = tuple(translated)

    if helper_serials != owned_helpers:
        unconsumed = sorted(helper_serials - owned_helpers)
        raise drift(f"unconsumed observed helper serials: {unconsumed}")

    predecessors: dict[int, list[int]] = {
        int(serial): [] for serial in pre_graph.blocks
    }
    for source, targets in canonical_successors.items():
        for target in targets:
            if target not in predecessors:
                raise drift(f"canonical target {target} is outside the pre-CFG")
            predecessors[target].append(source)

    blocks = {}
    for serial, observed_serial in observed_for_pre.items():
        observed_block = observed_graph.get_block(observed_serial)
        if observed_block is None:
            raise drift(f"observed block {observed_serial} disappeared")
        blocks[int(serial)] = replace(
            observed_block,
            # The observed block supplies all live semantic fields. Only its
            # snapshot-local serial is remapped to the stable pre-CFG key.
            succs=canonical_successors[int(serial)],
            preds=tuple(predecessors[int(serial)]),
            serial=int(serial),
        )
    return FlowGraph(
        blocks=blocks,
        entry_serial=int(pre_graph.entry_serial),
        func_ea=int(pre_graph.func_ea),
        metadata={
            **dict(observed_graph.metadata),
            "dispatcher_observed_identity_canonicalized": True,
        },
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
    }
    for corridor in coverage.covered_corridors:
        feeder = corridor.feeder
        if _feeder_is_retireable(
            flow_graph,
            feeder_serial=int(feeder.serial),
            state_plumbing_serials=state_plumbing_serials,
        ):
            roles_by_serial.setdefault(int(feeder.serial), "dispatcher_feeder")
        state_merge = corridor.state_merge
        if state_merge is not None and _is_effect_free_dispatcher_router(
            flow_graph.get_block(int(state_merge.serial))
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


def validate_dispatcher_corridor_coverage_metadata(
    pre_graph: FlowGraph,
    *,
    post_graph: FlowGraph,
    plan_metadata: object,
) -> DispatcherCorridorCoverageValidation:
    """Exact-match planned coverage against the actual post-transaction CFG.

    This deliberately does not depend on a dispatcher-removal proof.  Partial
    plans are allowed to retain residual corridors and need not carry the
    narrow full-retirement authority, but they still cannot publish a planned
    covered corridor when the observed CFG reaches that dispatcher again.
    """

    def rejected(reason: str) -> DispatcherCorridorCoverageValidation:
        return DispatcherCorridorCoverageValidation(
            passed=False,
            reason=reason,
            function_ea=int(pre_graph.func_ea),
        )

    if not isinstance(plan_metadata, Mapping):
        return rejected("dispatcher_corridor_coverage_missing")
    raw_coverage = plan_metadata.get(DISPATCHER_CORRIDOR_COVERAGE_METADATA)
    if not isinstance(raw_coverage, Mapping):
        return rejected("dispatcher_corridor_coverage_missing")
    if not all(
        isinstance(raw_coverage.get(field), (tuple, list))
        for field in ("covered_corridors", "residual_corridors")
    ):
        return rejected("dispatcher_corridor_coverage_malformed")
    try:
        function_ea = int(raw_coverage["function_ea"])
    except (KeyError, TypeError, ValueError):
        return rejected("dispatcher_corridor_coverage_malformed")
    if function_ea != int(pre_graph.func_ea):
        return rejected("dispatcher_corridor_coverage_function_mismatch")
    dispatcher = _anchor_from_payload(raw_coverage.get("dispatcher"))
    if dispatcher is None:
        return rejected("dispatcher_corridor_coverage_dispatcher_malformed")
    pre_dispatcher = pre_graph.get_block(int(dispatcher.serial))
    if pre_dispatcher is None or int(
        getattr(pre_dispatcher, "start_ea", 0) or 0
    ) != int(dispatcher.ea):
        return rejected("dispatcher_corridor_coverage_dispatcher_anchor_stale")
    semantic_exclusions = _semantic_exclusions_from_coverage_metadata(raw_coverage)
    if semantic_exclusions is None:
        return rejected("dispatcher_corridor_coverage_semantic_exclusions_malformed")
    observed_coverage = _coverage_from_post_successors(
        pre_graph,
        post_successors=post_graph.as_adjacency_dict(),
        dispatcher_entry_serial=int(dispatcher.serial),
        semantic_exclusions=semantic_exclusions,
    )
    if dict(raw_coverage) != observed_coverage.to_metadata():
        return DispatcherCorridorCoverageValidation(
            passed=False,
            reason="dispatcher_corridor_coverage_drift",
            observed_coverage=observed_coverage,
        )
    return DispatcherCorridorCoverageValidation(
        passed=True,
        reason="dispatcher_corridor_coverage_matches_observed",
        observed_coverage=observed_coverage,
    )


_STATE_WRITER_OPERATIONS = frozenset(
    operation
    for operation in ValueOpKind
    if operation
    not in {
        ValueOpKind.LOAD,
        ValueOpKind.STORE,
        ValueOpKind.VENDOR,
    }
)


def _value_instructions(block: object) -> tuple[Instruction, ...]:
    """Return canonical non-control instructions, never raw operand slots."""
    return tuple(
        instruction
        for instruction in InstructionProjection.from_block(block)
        if instruction.control is None
    )


def _dispatcher_state_identity(
    flow_graph: FlowGraph,
    dispatcher_entry_serial: int,
) -> StorageIdentity | None:
    """Recover state authority from the bound dispatcher entry itself.

    A dispatcher forest can lead directly into retained semantic handlers that
    contain unrelated conditionals.  Those downstream predicates are not
    competing state-slot evidence: the immutable dispatcher anchor is.  Fail
    closed unless that exact block contains one canonical constant/storage
    branch.
    """
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


@dataclass(frozen=True, slots=True)
class _DispatcherStateResolution:
    """Resolved comparison entry behind a dispatcher state-write prefix."""

    comparison_entry_serial: int
    state_identity: StorageIdentity
    state_width: int
    prefix_input_carrier: Varnode | None = None


@dataclass(frozen=True, slots=True)
class _DispatcherStateCarrier:
    """One pure storage carrier derived from the dispatcher state.

    Storage identity is intentionally size-agnostic, so the widths remain
    explicit evidence on the carrier.  This is what lets a 32-bit state pass
    through a 64-bit ``ZEXT`` register while accepting only its 32-bit
    subregister in a downstream comparison.
    """

    source_space: Space
    source_offset: int
    source_width: int
    result_space: Space
    result_offset: int
    result_width: int
    operation: ValueOpKind


@dataclass(frozen=True, slots=True)
class _DispatcherStateCarrierAnalysis:
    """Fail-closed authority shared by region discovery and route evaluation."""

    state_width: int
    region: frozenset[int]
    carriers: tuple[_DispatcherStateCarrier, ...]
    valid: bool

    def carrier_for_operand(self, operand: Varnode) -> _DispatcherStateCarrier | None:
        return next(
            (
                carrier
                for carrier in self.carriers
                if carrier.result_space is operand.space
                and int(carrier.result_offset) == int(operand.offset)
            ),
            None,
        )

    def resolves_state_operand(
        self,
        operand: Varnode,
        *,
        state_identity: StorageIdentity,
    ) -> bool:
        """Accept the state or a correctly sized slice of a pure carrier."""

        identity = storage_identity_from_varnode(operand)
        if identity == state_identity:
            return int(operand.size) == int(self.state_width)
        carrier = self.carrier_for_operand(operand)
        if carrier is None:
            return False
        # A carrier can widen the value, but a comparison must consume the
        # original state-width slice.  This rejects a full-width RAX compare
        # after STACK4 -> RAX8 while accepting EAX4.
        return (
            int(operand.size) == int(carrier.source_width)
            and int(operand.size) == int(self.state_width)
            and int(operand.size) <= int(carrier.result_width)
        )


def _dispatcher_state_width(
    flow_graph: FlowGraph,
    *,
    dispatcher_entry_serial: int,
    state_identity: StorageIdentity,
) -> int | None:
    """Recover the bound state's source width from the dispatcher branch."""

    block = flow_graph.get_block(int(dispatcher_entry_serial))
    if block is None:
        return None
    instructions = InstructionProjection.from_block(block)
    branches = tuple(
        instruction
        for instruction in instructions
        if instruction.control is not None
        and instruction.control.transfer is ControlTransferKind.CONDITIONAL_BRANCH
    )
    if len(branches) != 1:
        return None
    operands = tuple(
        operand
        for operand in branches[0].inputs
        if storage_identity_from_varnode(operand) == state_identity
    )
    if len(operands) != 1 or int(operands[0].size) <= 0:
        return None
    return int(operands[0].size)


def _dispatcher_state_branch_is_pure(block: object) -> bool:
    """Apply the recursive operand-tree safety gate to the branch snapshot."""

    branches = tuple(
        instruction
        for instruction in tuple(getattr(block, "insn_snapshots", ()) or ())
        if getattr(instruction, "control_transfer_kind", None)
        is ControlTransferKind.CONDITIONAL_BRANCH
    )
    if len(branches) != 1:
        return False
    branch = branches[0]
    if (
        bool(getattr(branch, "is_call", False))
        or getattr(branch, "call_kind", None) is not None
    ):
        return False
    return all(
        is_effect_free_operand_tree(operand)
        for operand in (
            getattr(branch, "l", None),
            getattr(branch, "r", None),
            getattr(branch, "d", None),
        )
    )


def _state_carrier_from_instruction(
    instruction: Instruction,
    *,
    state_identity: StorageIdentity,
    state_width: int,
) -> _DispatcherStateCarrier | None:
    """Recognize exactly one pure MOVE/ZEXT carrier definition."""

    if (
        instruction.operation not in {ValueOpKind.MOVE, ValueOpKind.ZEXT}
        or instruction.effects
        or instruction.memory is not None
        or instruction.control is not None
        or len(instruction.inputs) != 1
        or instruction.result is None
        or instruction.result.space not in {Space.REGISTER, Space.TEMP}
    ):
        return None
    source = instruction.inputs[0]
    source_identity = storage_identity_from_varnode(source)
    source_width = int(source.size)
    result_width = int(instruction.result.size)
    if (
        instruction.result.space not in {Space.REGISTER, Space.TEMP}
        or source_width <= 0
        or result_width <= 0
        or source_width != int(state_width)
    ):
        return None
    # Definitions are admitted only from the original state in the bound
    # dispatcher.  A result may then be consumed as an existing carrier by
    # downstream comparisons, but child definitions are deliberately outside
    # this first exact-C authority because they require path-sensitive joins.
    if source_identity != state_identity:
        return None
    if instruction.operation is ValueOpKind.MOVE:
        if result_width != source_width:
            return None
    elif result_width <= source_width:
        return None
    return _DispatcherStateCarrier(
        source_space=source.space,
        source_offset=int(source.offset),
        source_width=source_width,
        result_space=instruction.result.space,
        result_offset=int(instruction.result.offset),
        result_width=result_width,
        operation=instruction.operation,
    )


def _analyze_dispatcher_state_carriers(
    flow_graph: FlowGraph,
    *,
    dispatcher_entry_serial: int,
    state_identity: StorageIdentity,
) -> _DispatcherStateCarrierAnalysis:
    """Walk the comparison forest and derive pure state-carrier authority.

    This intentionally has a smaller admission surface than the generic
    router predicate.  A comparison block may contain only one or more exact
    MOVE/ZEXT definitions followed by a scalar state/constant branch.  Any
    unknown, effectful, global, memory, call, vendor, or competing definition
    makes the whole analysis invalid.
    """

    state_width = _dispatcher_state_width(
        flow_graph,
        dispatcher_entry_serial=int(dispatcher_entry_serial),
        state_identity=state_identity,
    )
    if state_width is None:
        return _DispatcherStateCarrierAnalysis(0, frozenset(), (), False)

    seen: set[int] = set()
    pending = deque(((int(dispatcher_entry_serial), False),))
    carriers: dict[tuple[Space, int], _DispatcherStateCarrier] = {}
    region: set[int] = set()
    while pending:
        serial, allow_exit_leaf = pending.popleft()
        serial = int(serial)
        if serial in seen:
            continue
        block = flow_graph.get_block(serial)
        if block is None:
            continue
        branch: Instruction | None = None
        instructions = InstructionProjection.from_block(block)
        successors = tuple(int(target) for target in block.succs)
        if len(successors) == 2 and block.kind in {
            BlockKind.TWO_WAY,
            BlockKind.N_WAY,
        }:
            branches = tuple(
                instruction
                for instruction in instructions
                if instruction.control is not None
                and instruction.control.transfer
                is ControlTransferKind.CONDITIONAL_BRANCH
            )
            if len(branches) != 1:
                continue
            branch = branches[0]
            if branch.control is None or branch.control.target not in successors:
                continue
        elif not (allow_exit_leaf and len(successors) == 1):
            continue

        block_carriers: list[_DispatcherStateCarrier] = []
        invalid_value = False
        for instruction in instructions:
            if instruction.control is not None:
                continue
            carrier = _state_carrier_from_instruction(
                instruction,
                state_identity=state_identity,
                state_width=state_width,
            )
            if carrier is None:
                # A projected VENDOR with no value/result is the portable
                # representation of a NOP.  Any other value instruction is
                # semantic/unknown and stops this candidate path.  The bound
                # dispatcher itself is stricter: malformed carrier plumbing
                # there invalidates the complete authority.
                if not (
                    instruction.operation is ValueOpKind.VENDOR
                    and not instruction.inputs
                    and instruction.result is None
                    and not instruction.effects
                    and instruction.memory is None
                ):
                    invalid_value = True
                    break
                continue
            block_carriers.append(carrier)

        if invalid_value:
            if serial == int(dispatcher_entry_serial):
                return _DispatcherStateCarrierAnalysis(
                    state_width, frozenset(), (), False
                )
            continue

        # Definitions in a non-dominating child would make a global carrier
        # map unsound at sibling joins.  Keep this first lifting narrow: all
        # accepted definitions must be in the bound dispatcher block, where
        # they dominate every comparison-forest successor.
        if block_carriers and serial != int(dispatcher_entry_serial):
            return _DispatcherStateCarrierAnalysis(
                state_width, frozenset(), (), False
            )

        if branch is not None and not _dispatcher_state_branch_is_pure(block):
            if serial == int(dispatcher_entry_serial):
                return _DispatcherStateCarrierAnalysis(
                    state_width, frozenset(), (), False
                )
            continue

        for carrier in block_carriers:
            result_key = (carrier.result_space, int(carrier.result_offset))
            previous = carriers.get(result_key)
            if previous is not None:
                return _DispatcherStateCarrierAnalysis(
                    state_width, frozenset(), (), False
                )
            carriers[result_key] = carrier

        if branch is not None:
            if len(branch.inputs) != 2:
                if serial == int(dispatcher_entry_serial):
                    return _DispatcherStateCarrierAnalysis(
                        state_width, frozenset(), (), False
                    )
                continue
            saw_state = False
            saw_constant = False
            invalid_branch = False
            for operand in branch.inputs:
                if operand.space is Space.CONST:
                    saw_constant = True
                elif _DispatcherStateCarrierAnalysis(
                    state_width, frozenset(), tuple(carriers.values()), True
                ).resolves_state_operand(
                    operand,
                    state_identity=state_identity,
                ):
                    saw_state = True
                else:
                    invalid_branch = True
                    break
            if invalid_branch or not saw_state or not saw_constant:
                if serial == int(dispatcher_entry_serial):
                    return _DispatcherStateCarrierAnalysis(
                        state_width, frozenset(), (), False
                    )
                continue
        elif not block_carriers and not _is_effect_free_dispatcher_router(block):
            return _DispatcherStateCarrierAnalysis(
                state_width, frozenset(), (), False
            )

        seen.add(serial)
        region.add(serial)
        pending.extend((target, True) for target in successors)
    return _DispatcherStateCarrierAnalysis(
        state_width,
        frozenset(region),
        tuple(
            sorted(
                carriers.values(),
                key=lambda item: (item.result_space.value, int(item.result_offset)),
            )
        ),
        True,
    )


def _state_dispatcher_comparison_region(
    flow_graph: FlowGraph,
    *,
    dispatcher_entry_serial: int,
    state_identity: StorageIdentity,
) -> frozenset[int]:
    """Derive only state-comparison routers plus their one-way exit glue.

    The broader structural comparison-region helper is useful for diagnostics,
    but it can walk into a retained handler whose only operation happens to be
    another conditional.  Retirement authority stops at that boundary unless
    the conditional compares the dispatcher entry's exact state identity.
    """
    analysis = _analyze_dispatcher_state_carriers(
        flow_graph,
        dispatcher_entry_serial=int(dispatcher_entry_serial),
        state_identity=state_identity,
    )
    if not analysis.valid:
        return frozenset()
    return analysis.region


def _pure_dispatcher_state_writer(
    flow_graph: FlowGraph,
    *,
    serial: int,
    dispatcher_serial: int,
    state_identity: StorageIdentity,
) -> Instruction | None:
    """Recognize one side-effect-free expression whose sole result is state."""
    block = flow_graph.get_block(int(serial))
    if block is None or tuple(int(target) for target in block.succs) != (
        int(dispatcher_serial),
    ):
        return None
    values = _value_instructions(block)
    if len(values) != 1:
        return None
    instruction = values[0]
    if (
        instruction.operation not in _STATE_WRITER_OPERATIONS
        or instruction.effects
        or instruction.memory is not None
        or not instruction.inputs
        or storage_identity_from_varnode(instruction.result) != state_identity
    ):
        return None
    return instruction


def _resolve_dispatcher_state_comparison_entry(
    flow_graph: FlowGraph,
    *,
    dispatcher_entry_serial: int,
) -> _DispatcherStateResolution | None:
    """Resolve a comparison forest behind an exact one-way state writer.

    Most dispatchers bind directly to their first comparison block.  Some
    native lifts instead bind the preceding ``MOVE carrier, state`` prefix.
    Admit only that one-hop shape: a single pure MOVE in a one-way block, one
    successor, and a successor whose sole constant comparison reads the MOVE
    result.  The original bound anchor remains the receipt identity; callers
    use ``comparison_entry_serial`` only for forest analysis.
    """

    start = int(dispatcher_entry_serial)
    direct_identity = _dispatcher_state_identity(flow_graph, start)
    if direct_identity is not None:
        width = _dispatcher_state_width(
            flow_graph,
            dispatcher_entry_serial=start,
            state_identity=direct_identity,
        )
        if width is not None:
            return _DispatcherStateResolution(start, direct_identity, width)

    block = flow_graph.get_block(start)
    if block is None or getattr(block, "kind", None) is not BlockKind.ONE_WAY:
        return None
    successors = tuple(int(target) for target in getattr(block, "succs", ()) or ())
    if len(successors) != 1:
        return None
    instructions = InstructionProjection.from_block(block)
    values = tuple(
        instruction for instruction in instructions if instruction.control is None
    )
    controls = tuple(
        instruction for instruction in instructions if instruction.control is not None
    )
    if len(values) != 1:
        return None
    # Native block snapshots commonly omit an unconditional tail instruction;
    # the one-way topology and tail metadata still provide the exact transfer
    # evidence.  If a control snapshot is present, accept only one GOTO and
    # reject every other control shape.
    if controls:
        if len(controls) != 1:
            return None
        control = controls[0].control
        if control is None or control.transfer is not ControlTransferKind.GOTO:
            return None
        if (
            control.target is not None
            and int(control.target) != successors[0]
        ):
            return None
    writer = values[0]
    if (
        writer.operation is not ValueOpKind.MOVE
        or writer.effects
        or writer.memory is not None
        or len(writer.inputs) != 1
        or writer.result is None
        or writer.result.space not in {Space.REGISTER, Space.STACK, Space.LVAR}
        or writer.inputs[0].space is Space.GLOBAL
    ):
        return None
    source_identity = storage_identity_from_varnode(writer.inputs[0])
    state_identity = storage_identity_from_varnode(writer.result)
    if source_identity is None or state_identity is None:
        return None
    source_width = int(writer.inputs[0].size)
    state_width = int(writer.result.size)
    if source_width <= 0 or state_width <= 0 or source_width != state_width:
        return None
    comparison_entry = successors[0]
    comparison_identity = _dispatcher_state_identity(flow_graph, comparison_entry)
    if comparison_identity != state_identity:
        return None
    comparison_width = _dispatcher_state_width(
        flow_graph,
        dispatcher_entry_serial=comparison_entry,
        state_identity=comparison_identity,
    )
    if comparison_width != state_width:
        return None
    return _DispatcherStateResolution(
        comparison_entry,
        state_identity,
        state_width,
        writer.inputs[0],
    )


def _constant_register_normalizer(
    flow_graph: FlowGraph,
    *,
    serial: int,
    feeder_serial: int,
    feeder: Instruction,
) -> tuple[int, Varnode] | None:
    """Recognize exactly ``const -> register -> state`` before redispatch."""
    block = flow_graph.get_block(int(serial))
    if block is None or tuple(int(target) for target in block.succs) != (
        int(feeder_serial),
    ):
        return None
    values = _value_instructions(block)
    if len(values) != 1:
        return None
    instruction = values[0]
    if (
        instruction.operation is not ValueOpKind.MOVE
        or instruction.effects
        or instruction.memory is not None
        or len(instruction.inputs) != 1
        or instruction.result is None
        or instruction.result.space is not Space.REGISTER
    ):
        return None
    source = instruction.inputs[0]
    if source.space is not Space.CONST:
        return None
    if (
        feeder.operation is not ValueOpKind.MOVE
        or len(feeder.inputs) != 1
        or feeder.inputs[0] != instruction.result
    ):
        return None
    return int(source.offset), instruction.result


@dataclass(frozen=True, slots=True)
class _DispatcherConstantRoute:
    """Deterministic comparison nodes and the first non-router exit."""

    comparison_path: tuple[int, ...]
    exit_serial: int


def _route_dispatcher_constant_with_analysis(
    flow_graph: FlowGraph,
    *,
    start_serial: int,
    comparison_region: frozenset[int],
    state_identity: StorageIdentity,
    carrier_analysis: _DispatcherStateCarrierAnalysis,
    value: int,
) -> _DispatcherConstantRoute | None:
    """Evaluate one constant from an exact node in a proven comparison forest."""

    current = int(start_serial)
    if current not in comparison_region:
        return None
    seen: set[int] = set()
    path: list[int] = []
    while current in comparison_region and current not in seen:
        seen.add(current)
        path.append(current)
        block = flow_graph.get_block(current)
        if block is None:
            return None
        successors = tuple(int(target) for target in block.succs)
        if len(successors) == 1:
            current = successors[0]
            continue
        if len(successors) != 2:
            return None
        instructions = InstructionProjection.from_block(block)
        branches = tuple(
            instruction
            for instruction in instructions
            if instruction.control is not None
            and instruction.control.transfer
            is ControlTransferKind.CONDITIONAL_BRANCH
        )
        if len(branches) != 1:
            return None
        branch = branches[0]
        control = branch.control
        if control is None or control.target not in successors:
            return None
        if len(branch.inputs) != 2:
            return None
        evaluated: list[int] = []
        saw_state = False
        saw_constant = False
        for operand in branch.inputs:
            if carrier_analysis.resolves_state_operand(
                operand,
                state_identity=state_identity,
            ):
                evaluated.append(int(value))
                saw_state = True
            elif operand.space is Space.CONST:
                evaluated.append(int(operand.offset))
                saw_constant = True
            else:
                return None
        if not saw_state or not saw_constant:
            return None
        taken = evaluate_branch_predicate(
            control.predicate,
            evaluated[0],
            evaluated[1],
            comparison_width(branch),
        )
        if taken is None:
            return None
        fallthrough = next(
            (target for target in successors if target != int(control.target)),
            None,
        )
        if fallthrough is None:
            return None
        current = int(control.target) if taken else int(fallthrough)
    if current in seen:
        return None
    return _DispatcherConstantRoute(tuple(path), current)


def _route_dispatcher_constant(
    flow_graph: FlowGraph,
    *,
    dispatcher_serial: int,
    comparison_region: frozenset[int],
    state_identity: StorageIdentity,
    value: int,
) -> int | None:
    """Evaluate one constant through the canonical comparison forest."""
    carrier_analysis = _analyze_dispatcher_state_carriers(
        flow_graph,
        dispatcher_entry_serial=int(dispatcher_serial),
        state_identity=state_identity,
    )
    if not carrier_analysis.valid or carrier_analysis.region != comparison_region:
        return None
    route = _route_dispatcher_constant_with_analysis(
        flow_graph,
        start_serial=int(dispatcher_serial),
        comparison_region=comparison_region,
        state_identity=state_identity,
        carrier_analysis=carrier_analysis,
        value=value,
    )
    return None if route is None else int(route.exit_serial)


def _is_stable_post_reachable_semantic_route_target(
    pre_graph: FlowGraph,
    *,
    post_graph: FlowGraph,
    serial: int,
    comparison_region: frozenset[int],
    lost: frozenset[int],
    post_reachable: frozenset[int],
) -> bool:
    """Prove one routed target semantic without producer handler authority.

    This is deliberately an alternative to, not a replacement for, the
    producer's authoritative-handler set.  The route must leave the proven
    comparison forest at a stable pre/post block anchor, remain reachable
    after mutation, and land on a block that the existing portable purity
    classifier independently rejects as control-only dispatcher plumbing.
    """

    target = int(serial)
    if (
        target in comparison_region
        or target in lost
        or target not in post_reachable
    ):
        return False
    pre_block = pre_graph.get_block(target)
    post_block = post_graph.get_block(target)
    if pre_block is None or post_block is None:
        return False
    pre_ea = int(getattr(pre_block, "start_ea", 0) or 0)
    post_ea = int(getattr(post_block, "start_ea", 0) or 0)
    if pre_ea != post_ea:
        return False
    return not _is_effect_free_dispatcher_router(pre_block)


@dataclass(frozen=True, slots=True)
class _RetiredNormalizerRouteResolution:
    """Acyclic substitution through exact lost-normalizer receipts."""

    target_serial: int
    normalizers: tuple[int, ...]


def _resolve_retired_normalizer_route_target(
    start_serial: int,
    *,
    routes: Mapping[int, int],
    lost: frozenset[int],
) -> _RetiredNormalizerRouteResolution | None:
    """Resolve only lost intermediates named by exact normalizer receipts."""

    current = int(start_serial)
    seen: set[int] = set()
    normalizers: list[int] = []
    while current in lost:
        if current in seen:
            return None
        seen.add(current)
        target = routes.get(current)
        if target is None:
            return None
        normalizers.append(current)
        current = int(target)
    return _RetiredNormalizerRouteResolution(current, tuple(normalizers))


def _final_constant_assignment_to_carrier(
    block: object,
    *,
    carrier: Varnode,
    state_width: int,
) -> int | None:
    """Recover the final exact constant definition of one prefix carrier.

    Effects and unrelated values before the final exact overwrite remain owned
    by the source block.  Once a constant is recovered, any later effect,
    memory operation, or unknown operation invalidates it because the portable
    projection cannot prove that instruction preserves the carrier.
    """

    carrier_identity = storage_identity_from_varnode(carrier)
    if carrier_identity is None or int(carrier.size) != int(state_width):
        return None
    candidate: int | None = None
    for instruction in InstructionProjection.from_block(block):
        result_identity = storage_identity_from_varnode(instruction.result)
        if result_identity != carrier_identity:
            if candidate is not None and (
                instruction.effects
                or instruction.memory is not None
                or instruction.operation is ValueOpKind.VENDOR
                or (
                    instruction.control is not None
                    and instruction.control.transfer is not ControlTransferKind.GOTO
                )
            ):
                candidate = None
            continue
        candidate = None
        if (
            instruction.operation is not ValueOpKind.MOVE
            or instruction.effects
            or instruction.memory is not None
            or instruction.control is not None
            or instruction.result != carrier
            or len(instruction.inputs) != 1
        ):
            continue
        source = instruction.inputs[0]
        if source.space is not Space.CONST or int(source.size) != int(state_width):
            continue
        bits = int(state_width) * 8
        if bits <= 0:
            continue
        candidate = int(source.offset) & ((1 << bits) - 1)
    return candidate


def _prove_source_owned_state_route(
    pre_graph: FlowGraph,
    *,
    post_graph: FlowGraph,
    source_serial: int,
    state_feeder_serial: int,
    prefix_input_carrier: Varnode,
    state_width: int,
    comparison_entry_serial: int,
    comparison_region: frozenset[int],
    state_identity: StorageIdentity,
    normalizer_routes: Mapping[int, int],
    handler_serials: set[int],
    lost: frozenset[int],
    post_reachable: frozenset[int],
) -> IntervalStateSourceRouteProof | None:
    """Prove a surviving source's exact route around one retired state feeder."""

    source = int(source_serial)
    feeder = int(state_feeder_serial)
    pre_source = pre_graph.get_block(source)
    post_source = post_graph.get_block(source)
    if (
        pre_source is None
        or post_source is None
        or tuple(int(target) for target in pre_source.succs) != (feeder,)
    ):
        return None
    state_value = _final_constant_assignment_to_carrier(
        pre_source,
        carrier=prefix_input_carrier,
        state_width=int(state_width),
    )
    if state_value is None:
        return None
    projected_successors = tuple(int(target) for target in post_source.succs)
    if len(projected_successors) != 1:
        return None
    projected_successor = projected_successors[0]
    if projected_successor in lost or projected_successor not in post_reachable:
        return None
    pre_projected = pre_graph.get_block(projected_successor)
    post_projected = post_graph.get_block(projected_successor)
    if pre_projected is None or post_projected is None:
        return None
    if int(pre_projected.start_ea) != int(post_projected.start_ea):
        return None

    routed_handler = _route_dispatcher_constant(
        pre_graph,
        dispatcher_serial=comparison_entry_serial,
        comparison_region=comparison_region,
        state_identity=state_identity,
        value=state_value,
    )
    carrier_analysis = _analyze_dispatcher_state_carriers(
        pre_graph,
        dispatcher_entry_serial=comparison_entry_serial,
        state_identity=state_identity,
    )
    if (
        routed_handler is None
        or not carrier_analysis.valid
        or carrier_analysis.region != comparison_region
    ):
        return None
    pre_route = _route_dispatcher_constant_with_analysis(
        pre_graph,
        start_serial=comparison_entry_serial,
        comparison_region=comparison_region,
        state_identity=state_identity,
        carrier_analysis=carrier_analysis,
        value=state_value,
    )
    if pre_route is None or int(pre_route.exit_serial) != int(routed_handler):
        return None
    resolved_pre = _resolve_retired_normalizer_route_target(
        int(routed_handler),
        routes=normalizer_routes,
        lost=lost,
    )
    if resolved_pre is None:
        return None

    retired_normalizers = list(resolved_pre.normalizers)
    routed_receipt_target: int | None = None
    if projected_successor == int(resolved_pre.target_serial):
        if any(serial not in lost for serial in pre_route.comparison_path):
            return None
        routed_receipt_target = int(resolved_pre.target_serial)
    elif projected_successor in pre_route.comparison_path:
        projected_index = pre_route.comparison_path.index(projected_successor)
        if any(
            serial not in lost
            for serial in pre_route.comparison_path[:projected_index]
        ):
            return None
        post_route = _route_dispatcher_constant_with_analysis(
            post_graph,
            start_serial=projected_successor,
            comparison_region=comparison_region,
            state_identity=state_identity,
            carrier_analysis=carrier_analysis,
            value=state_value,
        )
        if post_route is None:
            return None
        for serial in post_route.comparison_path:
            if serial in lost or serial not in post_reachable:
                return None
            pre_route_block = pre_graph.get_block(serial)
            post_route_block = post_graph.get_block(serial)
            if pre_route_block is None or post_route_block is None:
                return None
            if int(pre_route_block.start_ea) != int(post_route_block.start_ea):
                return None
        resolved_post = _resolve_retired_normalizer_route_target(
            int(post_route.exit_serial),
            routes=normalizer_routes,
            lost=lost,
        )
        if (
            resolved_post is None
            or int(resolved_post.target_serial) != int(resolved_pre.target_serial)
        ):
            return None
        for serial in resolved_post.normalizers:
            if serial not in retired_normalizers:
                retired_normalizers.append(serial)
        # A producer-authoritative handler root may itself be a pure one-way
        # exit corridor.  The generic comparison walk deliberately continues
        # through that glue, but the applied redirect receipt targets the
        # handler root, not the eventual STOP.  Bind that root only after the
        # complete pre/post route has exact-matched above; a non-handler
        # intermediate remains router plumbing and cannot gain authority.
        routed_receipt_target = (
            projected_successor
            if projected_successor in handler_serials
            else int(resolved_pre.target_serial)
        )
    else:
        return None

    if routed_receipt_target is None:
        return None
    final_target = int(routed_receipt_target)
    if final_target in lost or final_target not in post_reachable:
        return None
    if final_target not in handler_serials and not (
        _is_stable_post_reachable_semantic_route_target(
            pre_graph,
            post_graph=post_graph,
            serial=final_target,
            comparison_region=comparison_region,
            lost=lost,
            post_reachable=post_reachable,
        )
    ):
        return None
    return IntervalStateSourceRouteProof(
        source=_anchor(pre_graph, source),
        state_feeder=_anchor(pre_graph, feeder),
        state_value=state_value,
        projected_successor=_anchor(pre_graph, projected_successor),
        routed_handler=_anchor(pre_graph, final_target),
        retired_normalizers=tuple(
            _anchor(pre_graph, serial) for serial in retired_normalizers
        ),
    )


def _payload_anchor_set(value: object) -> frozenset[DispatcherBlockAnchor] | None:
    if not isinstance(value, (tuple, list)):
        return None
    anchors = tuple(_anchor_from_payload(item) for item in value)
    if any(anchor is None for anchor in anchors):
        return None
    return frozenset(anchor for anchor in anchors if anchor is not None)


def _interval_state_normalizer_retirement_allowance(
    pre_graph: FlowGraph,
    *,
    post_graph: FlowGraph,
    raw_proof: Mapping[str, object],
    proof: DispatcherRemovalPreflightProof,
    coverage: DispatcherCorridorCoverage,
    patch_plan: PatchPlan | None = None,
) -> IntervalStateNormalizerRetirementProof | None:
    """Independently prove the exact interval-normalizer retirement shape."""
    dispatcher = proof.dispatcher
    if (
        dispatcher is None
        or not coverage.enumeration_complete
        or coverage.residual_corridors
        or not proof.authoritative_handlers
    ):
        return None
    state_resolution = _resolve_dispatcher_state_comparison_entry(
        pre_graph,
        dispatcher_entry_serial=int(dispatcher.serial),
    )
    if state_resolution is None:
        return None
    comparison_entry_serial = int(state_resolution.comparison_entry_serial)
    state_identity = state_resolution.state_identity
    comparison_region = _state_dispatcher_comparison_region(
        pre_graph,
        dispatcher_entry_serial=comparison_entry_serial,
        state_identity=state_identity,
    )
    if comparison_entry_serial not in comparison_region:
        return None
    post_reachable = _reachable_from_entry(
        post_graph.as_adjacency_dict(),
        int(post_graph.entry_serial),
    )
    lost = _semantic_lost_blocks(
        pre_graph,
        post_graph=post_graph,
        patch_plan=patch_plan,
    )
    if lost != proof.lost_blocks:
        return None
    raw_lost = _payload_anchor_set(raw_proof.get("lost_blocks"))
    if raw_lost != frozenset(proof.lost_block_anchors):
        return None
    raw_pre_terminals = _payload_anchor_set(raw_proof.get("pre_reachable_terminals"))
    if raw_pre_terminals != frozenset(proof.pre_reachable_terminals):
        return None
    if (
        raw_proof.get("coverage_enumeration_complete") is not True
        or raw_proof.get("residual_corridor_count") != 0
    ):
        return None

    state_writers: dict[int, Instruction] = {}
    for serial in lost:
        writer = _pure_dispatcher_state_writer(
            pre_graph,
            serial=int(serial),
            dispatcher_serial=comparison_entry_serial,
            state_identity=state_identity,
        )
        if writer is not None:
            state_writers[int(serial)] = writer

    handler_serials = {int(anchor.serial) for anchor in proof.authoritative_handlers}
    normalizer_routes: list[IntervalStateNormalizerRouteProof] = []
    normalizer_serials: set[int] = set()
    routed_semantic_serials: set[int] = set()
    for serial in sorted(lost & handler_serials):
        block = pre_graph.get_block(int(serial))
        if block is None:
            continue
        predecessors = {int(pred) for pred in block.preds}
        if not predecessors or not predecessors.issubset(comparison_region & lost):
            continue
        successors = tuple(int(target) for target in block.succs)
        if len(successors) != 1:
            continue
        feeder_serial = successors[0]
        feeder = state_writers.get(feeder_serial)
        if feeder is None:
            continue
        normalized = _constant_register_normalizer(
            pre_graph,
            serial=int(serial),
            feeder_serial=feeder_serial,
            feeder=feeder,
        )
        if normalized is None:
            continue
        normalized_value, _carrier = normalized
        routed_handler = _route_dispatcher_constant(
            pre_graph,
            dispatcher_serial=comparison_entry_serial,
            comparison_region=comparison_region,
            state_identity=state_identity,
            value=normalized_value,
        )
        if routed_handler is None or routed_handler == int(serial):
            continue
        if routed_handler not in post_reachable:
            continue
        if routed_handler not in handler_serials:
            if not _is_stable_post_reachable_semantic_route_target(
                pre_graph,
                post_graph=post_graph,
                serial=routed_handler,
                comparison_region=comparison_region,
                lost=lost,
                post_reachable=post_reachable,
            ):
                continue
            routed_semantic_serials.add(int(routed_handler))
        normalizer_serials.add(int(serial))
        normalizer_routes.append(
            IntervalStateNormalizerRouteProof(
                normalizer=_anchor(pre_graph, int(serial)),
                state_feeder=_anchor(pre_graph, feeder_serial),
                normalized_value=normalized_value,
                routed_handler=_anchor(pre_graph, routed_handler),
            )
        )
    if not normalizer_routes:
        return None

    semantic_handler_serials = (
        handler_serials - normalizer_serials
    ) | routed_semantic_serials
    if not semantic_handler_serials:
        return None
    semantic_handlers = _anchors_for_serials(pre_graph, semantic_handler_serials)
    post_handlers = _anchors_for_serials(
        post_graph,
        frozenset(
            serial for serial in semantic_handler_serials if serial in post_reachable
        ),
    )
    if set(semantic_handlers) != set(post_handlers):
        return None
    if set(proof.pre_reachable_terminals) != set(proof.post_reachable_terminals):
        return None

    normalizer_route_map = {
        int(route.normalizer.serial): int(route.routed_handler.serial)
        for route in normalizer_routes
    }
    if len(normalizer_route_map) != len(normalizer_routes):
        return None
    source_routes: list[IntervalStateSourceRouteProof] = []
    for serial in state_writers:
        block = pre_graph.get_block(serial)
        if block is None:
            return None
        for predecessor in (int(pred) for pred in block.preds):
            if predecessor in lost:
                continue
            projected = post_graph.get_block(predecessor)
            if projected is None:
                return None
            projected_successors = {int(target) for target in projected.succs}
            if serial in projected_successors:
                return None
            prefix_input_carrier = state_resolution.prefix_input_carrier
            writer = state_writers[serial]
            is_prefix_writer = (
                int(serial) == int(dispatcher.serial)
                and prefix_input_carrier is not None
                and tuple(writer.inputs) == (prefix_input_carrier,)
            )
            if not is_prefix_writer:
                if projected_successors & semantic_handler_serials:
                    continue
                return None
            if prefix_input_carrier is None:
                return None
            source_route = _prove_source_owned_state_route(
                pre_graph,
                post_graph=post_graph,
                source_serial=predecessor,
                state_feeder_serial=serial,
                prefix_input_carrier=prefix_input_carrier,
                state_width=state_resolution.state_width,
                comparison_entry_serial=comparison_entry_serial,
                comparison_region=comparison_region,
                state_identity=state_identity,
                normalizer_routes=normalizer_route_map,
                handler_serials=handler_serials,
                lost=lost,
                post_reachable=post_reachable,
            )
            if source_route is None:
                return None
            source_routes.append(source_route)

    allowed_lost = (
        comparison_region | frozenset(state_writers) | frozenset(normalizer_serials)
    )
    if not lost.issubset(allowed_lost):
        return None
    retired: list[RetiredDispatcherInfrastructure] = []
    for serial, writer in sorted(state_writers.items()):
        role = (
            "dispatcher_state_feeder"
            if writer.operation is ValueOpKind.MOVE
            else "dispatcher_state_merge"
        )
        retired.append(
            RetiredDispatcherInfrastructure(
                role=role, anchor=_anchor(pre_graph, serial)
            )
        )
    retired.extend(
        RetiredDispatcherInfrastructure(
            role="state_normalizer",
            anchor=_anchor(pre_graph, serial),
        )
        for serial in sorted(normalizer_serials)
    )
    return IntervalStateNormalizerRetirementProof(
        dispatcher=dispatcher,
        state_identity=state_identity,
        normalizers=tuple(normalizer_routes),
        retired_state_plumbing=tuple(retired),
        semantic_handlers=semantic_handlers,
        post_reachable_handlers=post_handlers,
        lost_blocks=_anchors_for_serials(pre_graph, lost),
        source_routes=tuple(source_routes),
    )


def _pure_state_transition_plumbing_role(
    block: object,
    *,
    state_identity: StorageIdentity,
    dispatcher_serial: int,
    proved_downstream: frozenset[int],
) -> str | None:
    """Classify one pure one-way state expression without metadata authority."""
    if block is None or getattr(block, "kind", None) is not BlockKind.ONE_WAY:
        return None
    successors = tuple(int(target) for target in getattr(block, "succs", ()) or ())
    if len(successors) != 1:
        return None
    instructions = InstructionProjection.from_block(block)
    if any(
        instruction.control is not None
        and instruction.control.transfer is not ControlTransferKind.GOTO
        for instruction in instructions
    ):
        return None
    values = tuple(
        instruction for instruction in instructions if instruction.control is None
    )
    if not values:
        return None
    state_writes: list[int] = []
    for index, instruction in enumerate(values):
        if (
            instruction.operation not in _STATE_WRITER_OPERATIONS
            or instruction.effects
            or instruction.memory is not None
            or instruction.result is None
            or any(value.space is Space.GLOBAL for value in instruction.inputs)
        ):
            return None
        result_identity = storage_identity_from_varnode(instruction.result)
        if result_identity == state_identity:
            state_writes.append(index)
            continue
        if instruction.result.space not in {Space.REGISTER, Space.TEMP}:
            return None
    successor = successors[0]
    if state_writes:
        if state_writes != [len(values) - 1] or successor != int(dispatcher_serial):
            return None
        return "dispatcher_state_writer"
    if successor in proved_downstream:
        return "state_expression"
    return None


def _exact_partitioned_state_transition_plumbing_retirement(
    pre_graph: FlowGraph,
    *,
    post_graph: FlowGraph,
    proof: DispatcherRemovalPreflightProof,
    state_identity: StorageIdentity,
    comparison_region: frozenset[int],
    main_decision_forest: DecisionDag,
    lost: frozenset[int],
    pre_reachable: frozenset[int],
    post_reachable: frozenset[int],
    handler_serials: frozenset[int],
    post_handlers: tuple[DispatcherBlockAnchor, ...],
) -> StateTransitionPlumbingRetirementProof | None:
    """Prove exact source partitions that bypass state writers and forests.

    Unlike the legacy structural allowance below, this path admits a state
    writer whose physical successor is an internal node of the main dispatcher
    forest or the root of a smaller same-state comparison forest.  Every
    reachable source partition must be redirected to the handler selected by
    replaying its exact source-owned U32 state through that actual comparison
    entry.  The proof reuses the existing carrier/state-transform evaluator and
    comparison router; it introduces no new symbolic authority.
    """

    if state_identity.kind is StorageIdentityKind.STACK:
        state_var_stkoff = int(state_identity.offset)
        state_var_reg = None
    elif state_identity.kind is StorageIdentityKind.REGISTER:
        state_var_stkoff = None
        state_var_reg = int(state_identity.offset)
    else:
        return None

    dispatcher = proof.dispatcher
    if dispatcher is None:
        return None
    untyped = frozenset(int(serial) for serial in lost - comparison_region)
    if not untyped:
        return None

    feeder_routes: dict[int, tuple[int, DecisionDag, frozenset[int]]] = {}
    secondary_regions: set[frozenset[int]] = set()
    for serial in sorted(untyped):
        block = pre_graph.get_block(serial)
        if block is None or getattr(block, "kind", None) is not BlockKind.ONE_WAY:
            continue
        successors = tuple(int(target) for target in block.succs)
        if len(successors) != 1:
            continue
        instructions = InstructionProjection.from_block(block)
        if not any(
            instruction.control is None
            and instruction.result is not None
            and int(instruction.result.size) == 4
            and storage_identity_from_varnode(instruction.result) == state_identity
            for instruction in instructions
        ):
            continue
        comparison_entry = successors[0]
        if comparison_entry in {
            *main_decision_forest.nodes,
            *main_decision_forest.aliases,
        }:
            route_forest = main_decision_forest
            secondary_region = frozenset()
        else:
            route_forest = build_current_u32_decision_forest(
                pre_graph,
                comparison_entry,
                expected_identities=frozenset({state_identity}),
            )
            secondary_region = frozenset(
                ()
                if route_forest is None
                else {*route_forest.nodes, *route_forest.aliases}
            )
            if (
                route_forest is None
                or comparison_entry not in secondary_region
                or secondary_region & comparison_region
                or not secondary_region.issubset(untyped)
            ):
                continue
            secondary_regions.add(secondary_region)
        feeder_routes[serial] = (
            comparison_entry,
            route_forest,
            secondary_region,
        )

    feeder_serials = frozenset(feeder_routes)
    secondary_serials = frozenset().union(*secondary_regions)
    if not feeder_serials or feeder_serials & secondary_serials:
        return None
    if feeder_serials | secondary_serials != untyped:
        return None

    # A secondary forest may retain stale unreachable predecessor metadata,
    # but every pre-reachable incoming edge must be one of the exact state
    # writer partitions proved below.
    for region in secondary_regions:
        entering_feeders = frozenset(
            feeder
            for feeder, (entry, _forest, _secondary) in feeder_routes.items()
            if entry in region
        )
        for serial in region:
            block = pre_graph.get_block(serial)
            if block is None:
                return None
            for predecessor in (int(pred) for pred in block.preds):
                if predecessor in region or predecessor in entering_feeders:
                    continue
                if predecessor in pre_reachable:
                    return None

    routes: list[StateTransitionPlumbingRouteProof] = []
    routed_untyped: set[int] = set()
    for feeder_serial in sorted(feeder_routes):
        feeder = pre_graph.get_block(feeder_serial)
        if feeder is None:
            return None
        comparison_entry, route_forest, _secondary_region = feeder_routes[
            feeder_serial
        ]
        reachable_sources = tuple(
            sorted(int(pred) for pred in feeder.preds if int(pred) in pre_reachable)
        )
        if not reachable_sources:
            return None
        for source in reachable_sources:
            if source not in post_reachable:
                return None
            pre_source = pre_graph.get_block(source)
            post_source = post_graph.get_block(source)
            if pre_source is None or post_source is None:
                return None
            before = set(int(target) for target in pre_source.succs)
            after = set(int(target) for target in post_source.succs)
            if feeder_serial not in before or feeder_serial in after:
                return None
            added = after - (before - {feeder_serial})
            if len(added) != 1 or after != (before - {feeder_serial}) | added:
                return None
            replacement_target = next(iter(added))
            if (
                replacement_target not in post_reachable
                or replacement_target == source
            ):
                return None

            carrier = prove_exact_u32_carrier_state_write(
                pre_graph,
                source,
                feeder_serial,
                state_var_stkoff=state_var_stkoff,
                state_var_reg=state_var_reg,
                required_comparison_serials=frozenset({comparison_entry}),
            )
            transform = prove_exact_u32_state_transform_feeder(
                pre_graph,
                source,
                feeder_serial,
                state_var_stkoff=state_var_stkoff,
                state_var_reg=state_var_reg,
                required_comparison_serials=frozenset({comparison_entry}),
                expected_state=None,
            )
            exact_proofs = tuple(
                candidate for candidate in (carrier, transform) if candidate is not None
            )
            if len(exact_proofs) != 1:
                return None
            exact_proof = exact_proofs[0]
            if (
                getattr(exact_proof, "state_identity", None) != state_identity
                or bool(getattr(exact_proof, "requires_feeder_clone", False))
            ):
                return None
            bound_route = route_current_u32_decision_forest(
                pre_graph,
                route_forest,
                int(exact_proof.state),
                entry_serial=comparison_entry,
            )
            route = (
                None
                if bound_route is None
                else _DispatcherConstantRoute(
                    comparison_path=bound_route[1],
                    exit_serial=bound_route[0],
                )
            )
            if (
                route is None
                or int(route.exit_serial) not in post_reachable
                or int(route.exit_serial) == source
            ):
                return None
            routed_handler = int(route.exit_serial)

            if replacement_target == routed_handler:
                post_routed_handler = replacement_target
            elif routed_handler in handler_serials:
                post_route_forest = build_current_u32_decision_forest(
                    post_graph,
                    replacement_target,
                    expected_identities=frozenset({state_identity}),
                )
                if post_route_forest is None:
                    return None
                post_bound_route = route_current_u32_decision_forest(
                    post_graph,
                    post_route_forest,
                    int(exact_proof.state),
                    entry_serial=replacement_target,
                )
                if post_bound_route is None:
                    return None
                post_routed_handler = int(post_bound_route[0])
                post_full_route = (*post_bound_route[1], post_routed_handler)
                for left, right in zip(
                    post_full_route,
                    post_full_route[1:],
                    strict=False,
                ):
                    left_block = post_graph.get_block(left)
                    right_block = post_graph.get_block(right)
                    if (
                        left_block is None
                        or right_block is None
                        or right
                        not in tuple(int(target) for target in left_block.succs)
                        or left not in tuple(int(pred) for pred in right_block.preds)
                    ):
                        return None
            else:
                return None
            if (
                post_routed_handler != routed_handler
                or post_routed_handler not in post_reachable
            ):
                return None
            full_route = (*route.comparison_path, int(route.exit_serial))
            for left, right in zip(full_route, full_route[1:], strict=False):
                left_block = pre_graph.get_block(left)
                right_block = pre_graph.get_block(right)
                if (
                    left_block is None
                    or right_block is None
                    or right not in tuple(int(target) for target in left_block.succs)
                    or left not in tuple(int(pred) for pred in right_block.preds)
                ):
                    return None
            path_serials = (feeder_serial, *route.comparison_path)
            routed_untyped.update(
                serial for serial in path_serials if serial in untyped
            )
            routes.append(
                StateTransitionPlumbingRouteProof(
                    source=_anchor(pre_graph, source),
                    path=tuple(
                        _anchor(pre_graph, serial) for serial in path_serials
                    ),
                    state_writer=_anchor(pre_graph, feeder_serial),
                    routed_handler=_anchor(post_graph, routed_handler),
                )
            )

    if not routes or routed_untyped != set(untyped):
        return None
    retired = tuple(
        RetiredDispatcherInfrastructure(
            role=(
                "dispatcher_state_writer"
                if serial in feeder_serials
                else "state_comparison_corridor"
            ),
            anchor=_anchor(pre_graph, serial),
        )
        for serial in sorted(untyped)
    )
    return StateTransitionPlumbingRetirementProof(
        dispatcher=dispatcher,
        state_identity=state_identity,
        routes=tuple(routes),
        retired_state_plumbing=retired,
        semantic_handlers=proof.authoritative_handlers,
        post_reachable_handlers=post_handlers,
        lost_blocks=_anchors_for_serials(pre_graph, lost),
    )


def _state_transition_plumbing_retirement_allowance(
    pre_graph: FlowGraph,
    *,
    post_graph: FlowGraph,
    raw_proof: Mapping[str, object],
    proof: DispatcherRemovalPreflightProof,
    coverage: DispatcherCorridorCoverage,
    validated_exact_effect_exclusion_serials: frozenset[int] = frozenset(),
    patch_plan: PatchPlan | None = None,
) -> StateTransitionPlumbingRetirementProof | None:
    """Independently prove pure state-expression corridors retired by routes.

    This allowance does not trust producer ``state_plumbing`` labels or safety
    booleans.  It derives the dispatcher state from the bound comparison,
    accepts only side-effect-free one-way value expressions, requires every
    component to end in an exact write to that state, and binds every incoming
    handler edge to its exact projected handler target.
    """
    dispatcher = proof.dispatcher
    if (
        dispatcher is None
        or not coverage.enumeration_complete
        or coverage.residual_corridors
        or not proof.authoritative_handlers
    ):
        return None
    state_identity = _dispatcher_state_identity(
        pre_graph,
        int(dispatcher.serial),
    )
    if state_identity is None:
        return None
    comparison_region = _independent_comparison_dispatcher_region(
        pre_graph,
        dispatcher_entry_serial=int(dispatcher.serial),
    )
    if int(dispatcher.serial) not in comparison_region:
        return None
    main_decision_forest = build_current_u32_decision_forest(
        pre_graph,
        int(dispatcher.serial),
        expected_identities=frozenset({state_identity}),
    )
    if (
        main_decision_forest is None
        or not frozenset(
            {*main_decision_forest.nodes, *main_decision_forest.aliases}
        ).issubset(comparison_region)
    ):
        return None
    pre_reachable = _reachable_from_entry(
        pre_graph.as_adjacency_dict(),
        int(pre_graph.entry_serial),
    )
    post_reachable = _reachable_from_entry(
        post_graph.as_adjacency_dict(),
        int(post_graph.entry_serial),
    )
    lost = _semantic_lost_blocks(
        pre_graph,
        post_graph=post_graph,
        patch_plan=patch_plan,
    )
    if lost != proof.lost_blocks:
        return None
    retirement_lost = frozenset(
        int(serial)
        for serial in lost
        if int(serial) not in validated_exact_effect_exclusion_serials
    )
    raw_lost = _payload_anchor_set(raw_proof.get("lost_blocks"))
    if raw_lost != frozenset(_anchors_for_serials(pre_graph, retirement_lost)):
        return None
    raw_pre_terminals = _payload_anchor_set(raw_proof.get("pre_reachable_terminals"))
    if raw_pre_terminals != frozenset(proof.pre_reachable_terminals):
        return None
    if (
        raw_proof.get("coverage_enumeration_complete") is not True
        or raw_proof.get("residual_corridor_count") != 0
    ):
        return None
    handler_serials = frozenset(
        int(anchor.serial) for anchor in proof.authoritative_handlers
    )
    post_handlers = _anchors_for_serials(
        post_graph,
        frozenset(serial for serial in handler_serials if serial in post_reachable),
    )
    if set(proof.authoritative_handlers) != set(post_handlers):
        return None
    if set(proof.pre_reachable_terminals) != set(proof.post_reachable_terminals):
        return None

    partitioned = _exact_partitioned_state_transition_plumbing_retirement(
        pre_graph,
        post_graph=post_graph,
        proof=proof,
        state_identity=state_identity,
        comparison_region=comparison_region,
        main_decision_forest=main_decision_forest,
        lost=retirement_lost,
        pre_reachable=pre_reachable,
        post_reachable=post_reachable,
        handler_serials=handler_serials,
        post_handlers=post_handlers,
    )
    if partitioned is not None:
        return partitioned

    untyped = set(int(serial) for serial in retirement_lost - comparison_region)
    if not untyped:
        return None
    roles: dict[int, str] = {}
    changed = True
    while changed:
        changed = False
        downstream = frozenset(roles)
        for serial in sorted(untyped - set(roles)):
            role = _pure_state_transition_plumbing_role(
                pre_graph.get_block(serial),
                state_identity=state_identity,
                dispatcher_serial=int(dispatcher.serial),
                proved_downstream=downstream,
            )
            if role is None:
                continue
            roles[serial] = role
            changed = True
    if set(roles) != untyped:
        return None

    routes: list[StateTransitionPlumbingRouteProof] = []
    routed_plumbing: set[int] = set()
    for root in sorted(roles):
        block = pre_graph.get_block(root)
        if block is None:
            return None
        for source in sorted(
            int(pred) for pred in block.preds if int(pred) not in roles
        ):
            if source in comparison_region or source not in handler_serials:
                return None
            pre_source = pre_graph.get_block(source)
            post_source = post_graph.get_block(source)
            if (
                pre_source is None
                or post_source is None
                or source not in post_reachable
            ):
                return None
            before = set(int(target) for target in pre_source.succs)
            after = set(int(target) for target in post_source.succs)
            if root not in before or root in after:
                return None
            added = after - (before - {root})
            if len(added) != 1 or after != (before - {root}) | added:
                return None
            routed_handler = next(iter(added))
            if (
                routed_handler not in handler_serials
                or routed_handler not in post_reachable
                or routed_handler == source
            ):
                return None

            path: list[int] = []
            current = root
            state_writer: int | None = None
            while current in roles and current not in path:
                path.append(current)
                if roles[current] == "dispatcher_state_writer":
                    state_writer = current
                current_block = pre_graph.get_block(current)
                if current_block is None or len(current_block.succs) != 1:
                    return None
                current = int(current_block.succs[0])
            if current != int(dispatcher.serial) or state_writer is None:
                return None
            routed_plumbing.update(path)
            routes.append(
                StateTransitionPlumbingRouteProof(
                    source=_anchor(pre_graph, source),
                    path=tuple(_anchor(pre_graph, serial) for serial in path),
                    state_writer=_anchor(pre_graph, state_writer),
                    routed_handler=_anchor(post_graph, routed_handler),
                )
            )
    if not routes or routed_plumbing != set(roles):
        return None
    retired = tuple(
        RetiredDispatcherInfrastructure(
            role=role,
            anchor=_anchor(pre_graph, serial),
        )
        for serial, role in sorted(roles.items())
    )
    return StateTransitionPlumbingRetirementProof(
        dispatcher=dispatcher,
        state_identity=state_identity,
        routes=tuple(routes),
        retired_state_plumbing=retired,
        semantic_handlers=proof.authoritative_handlers,
        post_reachable_handlers=post_handlers,
        lost_blocks=_anchors_for_serials(pre_graph, retirement_lost),
    )


def _comparison_corridor_retirement_allowance(
    pre_graph: FlowGraph,
    *,
    post_graph: FlowGraph,
    raw_proof: Mapping[str, object],
    proof: DispatcherRemovalPreflightProof,
    coverage: DispatcherCorridorCoverage,
    patch_plan: PatchPlan | None = None,
) -> ComparisonCorridorRetirementProof | None:
    """Recompute the control-only corridor exception at transaction preflight."""
    dispatcher = proof.dispatcher
    if (
        dispatcher is None
        or not coverage.enumeration_complete
        or coverage.residual_corridors
        or not proof.authoritative_handlers
    ):
        return None
    lost = _semantic_lost_blocks(
        pre_graph,
        post_graph=post_graph,
        patch_plan=patch_plan,
    )
    if lost != proof.lost_blocks:
        return None
    raw_lost = _payload_anchor_set(raw_proof.get("lost_blocks"))
    if raw_lost != frozenset(proof.lost_block_anchors):
        return None
    raw_pre_terminals = _payload_anchor_set(raw_proof.get("pre_reachable_terminals"))
    if raw_pre_terminals != frozenset(proof.pre_reachable_terminals):
        return None
    raw_post_handlers = _payload_anchor_set(raw_proof.get("post_reachable_handlers"))
    if raw_post_handlers != frozenset(proof.post_reachable_handlers):
        return None
    if (
        raw_proof.get("coverage_enumeration_complete") is not True
        or raw_proof.get("residual_corridor_count") != 0
    ):
        return None
    corridor_safe, corridor_serials = _covered_control_only_comparison_corridor_region(
        pre_graph,
        coverage,
        dispatcher_entry_serial=int(dispatcher.serial),
    )
    if not corridor_safe or not corridor_serials:
        return None
    derived_retired = _retired_dispatcher_infrastructure(
        pre_graph,
        coverage,
        dispatcher_entry_serial=int(dispatcher.serial),
        dispatcher_region_serials=frozenset(),
        state_plumbing_serials=frozenset(),
        lost_blocks=lost,
    )
    derived_retired_serials = frozenset(
        int(item.anchor.serial) for item in derived_retired
    )
    # The comparison-corridor exception is only an alternative *proof* for
    # the exact infrastructure the immutable source CFG classified.  It must
    # not turn a mixed loss (a valid corridor plus an unrelated semantic,
    # unknown, or effectful block) into an accepted retirement.
    if not lost.issubset(derived_retired_serials):
        return None
    expected_roles = {
        (item.role, int(item.anchor.serial), int(item.anchor.ea))
        for item in derived_retired
    }
    raw_infrastructure = raw_proof.get("retired_infrastructure")
    if not isinstance(raw_infrastructure, (tuple, list)):
        return None
    raw_roles: set[tuple[str, int, int]] = set()
    for item in raw_infrastructure:
        if not isinstance(item, Mapping):
            return None
        anchor = _anchor_from_payload(item.get("anchor"))
        role = item.get("role")
        if anchor is None or not isinstance(role, str):
            return None
        raw_roles.add((role, int(anchor.serial), int(anchor.ea)))
    if raw_roles != expected_roles:
        return None
    raw_state_plumbing = _payload_anchor_set(raw_proof.get("state_plumbing", ()))
    if raw_state_plumbing is None or any(
        int(anchor.serial) in lost for anchor in raw_state_plumbing
    ):
        return None
    retired_corridor = tuple(
        item for item in derived_retired if item.role == "comparison_corridor"
    )
    if not retired_corridor:
        return None
    semantic_handlers = proof.authoritative_handlers
    post_handlers = _anchors_for_serials(
        post_graph,
        frozenset(int(anchor.serial) for anchor in semantic_handlers),
    )
    if set(post_handlers) != set(semantic_handlers):
        return None
    if set(proof.pre_reachable_terminals) != set(proof.post_reachable_terminals):
        return None
    return ComparisonCorridorRetirementProof(
        dispatcher=dispatcher,
        covered_corridors=tuple(
            corridor
            for corridor in coverage.covered_corridors
            if corridor.state_merge is not None
        ),
        retired_corridor=retired_corridor,
        semantic_handlers=semantic_handlers,
        post_reachable_handlers=post_handlers,
        lost_blocks=_anchors_for_serials(pre_graph, lost),
    )


def validate_dispatcher_removal_preflight_proof(
    pre_graph: FlowGraph,
    *,
    post_graph: FlowGraph,
    plan_metadata: object,
    validated_exact_effect_exclusion_serials: frozenset[int] = frozenset(),
    patch_plan: PatchPlan | None = None,
) -> DispatcherRemovalPreflightValidation:
    """Recompute and exact-match the producer proof at transaction preflight.

    Metadata is evidence, not authority by itself.  The transaction accepts the
    narrow router-removal path only when its payload round-trips exactly against
    the immutable pre- and projected post-CFGs.
    """
    if not isinstance(plan_metadata, Mapping):
        return DispatcherRemovalPreflightValidation(
            passed=False,
            reason="dispatcher_removal_proof_missing",
        )
    raw_proof = plan_metadata.get(DISPATCHER_REMOVAL_PREFLIGHT_PROOF_METADATA)
    raw_coverage = plan_metadata.get(DISPATCHER_CORRIDOR_COVERAGE_METADATA)
    if not isinstance(raw_proof, Mapping) or not isinstance(raw_coverage, Mapping):
        return DispatcherRemovalPreflightValidation(
            passed=False,
            reason="dispatcher_removal_proof_missing",
        )
    try:
        function_ea = int(raw_proof["function_ea"])
        coverage_function_ea = int(raw_coverage["function_ea"])
    except (KeyError, TypeError, ValueError):
        return DispatcherRemovalPreflightValidation(
            passed=False,
            reason="dispatcher_removal_proof_malformed",
        )
    if function_ea != int(pre_graph.func_ea) or coverage_function_ea != function_ea:
        return DispatcherRemovalPreflightValidation(
            passed=False,
            reason="dispatcher_removal_proof_function_mismatch",
        )
    dispatcher = _anchor_from_payload(raw_proof.get("dispatcher"))
    coverage_dispatcher = _anchor_from_payload(raw_coverage.get("dispatcher"))
    if (
        dispatcher is None
        or coverage_dispatcher is None
        or dispatcher != coverage_dispatcher
    ):
        return DispatcherRemovalPreflightValidation(
            passed=False,
            reason="dispatcher_removal_proof_dispatcher_mismatch",
        )
    block = pre_graph.get_block(int(dispatcher.serial))
    if block is None or int(getattr(block, "start_ea", 0) or 0) != int(dispatcher.ea):
        return DispatcherRemovalPreflightValidation(
            passed=False,
            reason="dispatcher_removal_proof_dispatcher_anchor_stale",
        )
    semantic_exclusions = _semantic_exclusions_from_coverage_metadata(raw_coverage)
    if semantic_exclusions is None:
        return DispatcherRemovalPreflightValidation(
            passed=False,
            reason="dispatcher_removal_proof_semantic_exclusions_malformed",
        )
    projected_coverage = _coverage_from_post_successors(
        pre_graph,
        post_successors=post_graph.as_adjacency_dict(),
        dispatcher_entry_serial=int(dispatcher.serial),
        semantic_exclusions=semantic_exclusions,
    )
    if dict(raw_coverage) != projected_coverage.to_metadata():
        return DispatcherRemovalPreflightValidation(
            passed=False,
            reason="dispatcher_removal_proof_coverage_drift",
        )
    raw_handlers = raw_proof.get("authoritative_handlers")
    if not isinstance(raw_handlers, (tuple, list)):
        return DispatcherRemovalPreflightValidation(
            passed=False,
            reason="dispatcher_removal_proof_handlers_malformed",
        )
    handler_anchors = tuple(
        anchor
        for anchor in (_anchor_from_payload(value) for value in raw_handlers)
        if anchor is not None
    )
    if len(handler_anchors) != len(raw_handlers):
        return DispatcherRemovalPreflightValidation(
            passed=False,
            reason="dispatcher_removal_proof_handlers_malformed",
        )
    handlers = frozenset(int(anchor.serial) for anchor in handler_anchors)
    if len(handlers) != len(handler_anchors):
        return DispatcherRemovalPreflightValidation(
            passed=False,
            reason="dispatcher_removal_proof_handlers_duplicate",
        )
    if any(
        (block := pre_graph.get_block(int(anchor.serial))) is None
        or int(getattr(block, "start_ea", 0) or 0) != int(anchor.ea)
        for anchor in handler_anchors
    ):
        return DispatcherRemovalPreflightValidation(
            passed=False,
            reason="dispatcher_removal_proof_handler_anchor_stale",
        )
    raw_infrastructure = raw_proof.get("retired_infrastructure")
    if not isinstance(raw_infrastructure, (tuple, list)):
        return DispatcherRemovalPreflightValidation(
            passed=False,
            reason="dispatcher_removal_proof_infrastructure_malformed",
        )
    for item in raw_infrastructure:
        if not isinstance(item, Mapping):
            return DispatcherRemovalPreflightValidation(
                passed=False,
                reason="dispatcher_removal_proof_infrastructure_malformed",
            )
        role = item.get("role")
        anchor = _anchor_from_payload(item.get("anchor"))
        if (
            role
            not in {
                "comparison_dispatcher",
                "comparison_corridor",
                "dispatcher_feeder",
                "state_merge",
            }
            or anchor is None
        ):
            return DispatcherRemovalPreflightValidation(
                passed=False,
                reason="dispatcher_removal_proof_infrastructure_malformed",
            )
        block = pre_graph.get_block(int(anchor.serial))
        if block is None or int(getattr(block, "start_ea", 0) or 0) != int(anchor.ea):
            return DispatcherRemovalPreflightValidation(
                passed=False,
                reason="dispatcher_removal_proof_infrastructure_anchor_stale",
            )
    raw_state_plumbing = raw_proof.get("state_plumbing", ())
    if not isinstance(raw_state_plumbing, (tuple, list)):
        return DispatcherRemovalPreflightValidation(
            passed=False,
            reason="dispatcher_removal_proof_state_plumbing_malformed",
        )
    state_plumbing_anchors = tuple(
        anchor
        for anchor in (_anchor_from_payload(value) for value in raw_state_plumbing)
        if anchor is not None
    )
    if len(state_plumbing_anchors) != len(raw_state_plumbing) or any(
        (block := pre_graph.get_block(int(anchor.serial))) is None
        or int(getattr(block, "start_ea", 0) or 0) != int(anchor.ea)
        for anchor in state_plumbing_anchors
    ):
        return DispatcherRemovalPreflightValidation(
            passed=False,
            reason="dispatcher_removal_proof_state_plumbing_anchor_stale",
        )
    raw_safety = raw_proof.get("producer_safety")
    if not isinstance(raw_safety, Mapping) or any(
        not isinstance(value, bool) for value in raw_safety.values()
    ):
        return DispatcherRemovalPreflightValidation(
            passed=False,
            reason="dispatcher_removal_proof_safety_malformed",
        )
    proof = build_dispatcher_removal_preflight_proof(
        pre_graph,
        post_graph=post_graph,
        coverage=projected_coverage,
        dispatcher_entry_serial=int(dispatcher.serial),
        authoritative_handler_serials=handlers,
        # Never derive authority from raw retired-role labels.  The builder
        # independently reconstructs the comparison forest from ``pre_graph``.
        dispatcher_region_serials=frozenset(),
        # These are producer diagnostics, not transaction authority.  A
        # coverage-bearing PatchPlan can be constructed externally, so raw
        # ``state_plumbing`` anchors and literal safety booleans must never
        # authorize the narrow entry-count exception.  Without a bound
        # use-def execution receipt / state-write provenance at this boundary,
        # rebuild only from independently observable effect-free CFG shape.
        producer_safety={},
        state_plumbing_serials=frozenset(),
        patch_plan=patch_plan,
    )
    interval_normalizer = _interval_state_normalizer_retirement_allowance(
        pre_graph,
        post_graph=post_graph,
        raw_proof=raw_proof,
        proof=proof,
        coverage=projected_coverage,
        patch_plan=patch_plan,
    )
    if interval_normalizer is not None:
        return DispatcherRemovalPreflightValidation(
            passed=True,
            reason="interval_state_normalizer_retirement",
            proof=proof,
            interval_state_normalizer_retirement=interval_normalizer,
        )
    state_transition_plumbing = _state_transition_plumbing_retirement_allowance(
        pre_graph,
        post_graph=post_graph,
        raw_proof=raw_proof,
        proof=proof,
        coverage=projected_coverage,
        validated_exact_effect_exclusion_serials=(
            validated_exact_effect_exclusion_serials
        ),
        patch_plan=patch_plan,
    )
    if state_transition_plumbing is not None:
        return DispatcherRemovalPreflightValidation(
            passed=True,
            reason="state_transition_plumbing_retirement",
            proof=proof,
            state_transition_plumbing_retirement=state_transition_plumbing,
        )
    comparison_corridor = _comparison_corridor_retirement_allowance(
        pre_graph,
        post_graph=post_graph,
        raw_proof=raw_proof,
        proof=proof,
        coverage=projected_coverage,
        patch_plan=patch_plan,
    )
    if comparison_corridor is not None:
        return DispatcherRemovalPreflightValidation(
            passed=True,
            reason="comparison_corridor_retirement",
            proof=proof,
            comparison_corridor_retirement=comparison_corridor,
        )
    if dict(raw_proof) != proof.to_metadata():
        return DispatcherRemovalPreflightValidation(
            passed=False,
            reason="dispatcher_removal_proof_drift",
            proof=proof,
        )
    return DispatcherRemovalPreflightValidation(
        passed=proof.passed,
        reason=proof.reason,
        proof=proof,
    )


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


def has_unreachable_cyclic_switch_dispatcher_residue(
    pre_graph: FlowGraph,
    *,
    post_graph: FlowGraph,
    plan_metadata: object,
) -> bool:
    """Detect the native-optimizer hazard without trusting proof role labels."""
    if not isinstance(plan_metadata, Mapping):
        return False
    raw_coverage = plan_metadata.get(DISPATCHER_CORRIDOR_COVERAGE_METADATA)
    if not isinstance(raw_coverage, Mapping):
        return False
    dispatcher = _anchor_from_payload(raw_coverage.get("dispatcher"))
    if dispatcher is None:
        return False
    block = pre_graph.get_block(int(dispatcher.serial))
    if (
        block is None
        or int(getattr(block, "start_ea", 0) or 0) != int(dispatcher.ea)
        or block.kind is not BlockKind.N_WAY
    ):
        return False
    residue = _detached_dispatcher_residue(post_graph, int(dispatcher.serial))
    return residue is not None and not _residue_is_acyclic(post_graph, residue)


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
