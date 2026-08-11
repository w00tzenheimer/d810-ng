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
from d810.ir.insn_projection import InstructionProjection
from d810.ir.instructions import Instruction
from d810.ir.semantics import ControlTransferKind
from d810.ir.storage_identity import StorageIdentity, storage_identity_from_varnode
from d810.ir.varnode import Space, Varnode
from d810.transforms.cfg_transaction import LogicalBlockRef, NativeBlockRef
from d810.transforms.graph_modification import (
    ConvertToGoto,
    LowerConditionalStateTransition,
    RedirectBranch,
    RedirectGoto,
)
from d810.transforms.plan import (
    PatchLowerConditionalStateTransition,
    PatchPlan,
    PatchRedirectGoto,
)

DISPATCHER_CORRIDOR_COVERAGE_METADATA = "dispatcher_corridor_coverage"
DISPATCHER_REMOVAL_PREFLIGHT_PROOF_METADATA = (
    "dispatcher_removal_preflight_proof"
)
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
    "DispatcherRemovalPreflightProof",
    "DispatcherRemovalPreflightValidation",
    "IntervalStateNormalizerRetirementProof",
    "IntervalStateNormalizerRouteProof",
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
            "lost_blocks": [
                anchor.to_payload() for anchor in self.lost_block_anchors
            ],
            "state_plumbing": [
                anchor.to_payload() for anchor in self.state_plumbing
            ],
            "producer_safety": dict(self.producer_safety),
            "coverage_enumeration_complete": bool(
                self.coverage_enumeration_complete
            ),
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
class IntervalStateNormalizerRetirementProof:
    """Independent authority for retiring interval state-normalization plumbing."""

    dispatcher: DispatcherBlockAnchor
    state_identity: StorageIdentity
    normalizers: tuple[IntervalStateNormalizerRouteProof, ...]
    retired_state_plumbing: tuple[RetiredDispatcherInfrastructure, ...]
    semantic_handlers: tuple[DispatcherBlockAnchor, ...]
    post_reachable_handlers: tuple[DispatcherBlockAnchor, ...]
    lost_blocks: tuple[DispatcherBlockAnchor, ...]

    def to_payload(self) -> dict[str, object]:
        return {
            "dispatcher": self.dispatcher.to_payload(),
            "state_identity": self.state_identity.to_record(),
            "normalizers": [route.to_payload() for route in self.normalizers],
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
class DispatcherRemovalPreflightValidation:
    """Result of recomputing a plan's narrow removal proof at preflight."""

    passed: bool
    reason: str
    proof: DispatcherRemovalPreflightProof | None = None
    terminal_switch_cycle_break: "TerminalSwitchCycleBreakProof | None" = None
    interval_state_normalizer_retirement: (
        IntervalStateNormalizerRetirementProof | None
    ) = None

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
            "retired_residue": [
                anchor.to_payload() for anchor in self.retired_residue
            ],
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
        return {
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
        serial: tuple(sorted(set(sources)))
        for serial, sources in predecessors.items()
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
        if (
            len(incoming_to_predecessor) > 1
            and successors.get(int(predecessor), ()) == (int(suffix[0]),)
        ):
            for merge_input in incoming_to_predecessor:
                merge_input = int(merge_input)
                if merge_input in seen:
                    if merge_input == int(dispatcher_serial):
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


def _coverage_from_post_successors(
    flow_graph: FlowGraph,
    *,
    post_successors: Mapping[int, tuple[int, ...]],
    dispatcher_entry_serial: int | None,
) -> DispatcherCorridorCoverage:
    """Classify original corridors against an already-projected successor map.

    Preflight has the immutable post-projection graph, rather than the original
    modification objects.  Sharing this classifier prevents plan metadata from
    relabeling a still-reachable dispatcher corridor as covered.
    """
    if dispatcher_entry_serial is None or flow_graph.get_block(
        int(dispatcher_entry_serial)
    ) is None:
        return DispatcherCorridorCoverage(
            function_ea=int(flow_graph.func_ea),
            dispatcher=None,
            covered_corridors=(),
            residual_corridors=(),
            enumeration_complete=True,
        )

    dispatcher_serial = int(dispatcher_entry_serial)
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
    )


def analyze_dispatcher_corridor_coverage(
    flow_graph: FlowGraph,
    *,
    modifications: tuple[object, ...] | list[object],
    dispatcher_entry_serial: int | None,
) -> DispatcherCorridorCoverage:
    """Classify every reachable original dispatcher corridor after planned edits."""
    post_successors = _rewired_successors(flow_graph, modifications)
    return _coverage_from_post_successors(
        flow_graph,
        post_successors=post_successors,
        dispatcher_entry_serial=dispatcher_entry_serial,
    )


def _stable_block_start_ea(block: object) -> int | None:
    """Return the native block-start identity, if the snapshot carries one."""
    for field_name in ("native_start_ea", "start_ea"):
        try:
            value = int(getattr(block, field_name))
        except (AttributeError, TypeError, ValueError):
            continue
        if 0 <= value < 0xFFFFFFFFFFFFFFFF:
            return value
    return None


def canonicalize_observed_dispatcher_graph(
    pre_graph: FlowGraph,
    observed_graph: FlowGraph,
    plan: object,
) -> FlowGraph:
    """Map live helper/serial topology back onto stable pre-CFG identities.

    Conditional state lowering must create a physically adjacent fall-through
    helper.  That helper shifts later snapshot-local serials, so raw observed
    adjacency is not comparable with pre-snapshot coverage metadata.  Original
    blocks are matched by their native block-start anchors; helper chains are
    admitted only when they are reachable from a typed conditional lowering and
    terminate at one of its declared arms.  Every other identity or topology
    drift fails closed.
    """
    if not isinstance(pre_graph, FlowGraph) or not isinstance(observed_graph, FlowGraph):
        raise TypeError("dispatcher observation canonicalization requires FlowGraphs")

    lowerings: list[PatchLowerConditionalStateTransition] = []
    for step in getattr(plan, "steps", ()) or ():
        match step:
            case PatchLowerConditionalStateTransition() as lowering:
                lowerings.append(lowering)
    if not lowerings:
        return observed_graph

    def drift(reason: str) -> ValueError:
        return ValueError(f"dispatcher_corridor_coverage_identity_drift: {reason}")

    if int(pre_graph.func_ea) != int(observed_graph.func_ea):
        raise drift("function identity changed")

    pre_by_anchor: dict[int, int] = {}
    for serial, block in pre_graph.blocks.items():
        anchor = _stable_block_start_ea(block)
        if anchor is None:
            raise drift(f"pre block {int(serial)} lacks a stable block-start EA")
        if anchor in pre_by_anchor:
            raise drift(f"pre block-start EA 0x{anchor:x} is ambiguous")
        pre_by_anchor[anchor] = int(serial)

    observed_by_anchor: dict[int, list[int]] = {}
    for serial, block in observed_graph.blocks.items():
        anchor = _stable_block_start_ea(block)
        if anchor is None:
            raise drift(f"observed block {int(serial)} lacks a stable block-start EA")
        observed_by_anchor.setdefault(anchor, []).append(int(serial))

    observed_for_pre: dict[int, int] = {}
    for anchor, pre_serial in pre_by_anchor.items():
        candidates = tuple(observed_by_anchor.get(anchor, ()))
        if not candidates:
            raise drift(f"pre block {pre_serial}@0x{anchor:x} is missing")
        if pre_serial in candidates:
            observed_for_pre[pre_serial] = pre_serial
        elif len(candidates) == 1:
            observed_for_pre[pre_serial] = candidates[0]
        else:
            raise drift(
                f"pre block {pre_serial}@0x{anchor:x} has ambiguous observed serials"
            )

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
            raise drift(f"CFG_50858 observed block {serial} references a missing successor")
        if any(source not in observed_serials for source in preds):
            raise drift(f"CFG_50858 observed block {serial} references a missing predecessor")
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
            if not (
                getattr(observed_tail, "predicate_kind", None) is PredicateKind.NE
                and isinstance(nested, MopSnapshot)
                and nested.kind is OperandKind.SUBINSN
                and nested.sub_predicate_kind is PredicateKind.EQ
                and isinstance(nested_left, MopSnapshot)
                and nested_left.kind is OperandKind.STACK
                and nested_left.stkoff == int(condition.stack_stkoff)
                and nested_left.size == int(condition.stack_size)
                and isinstance(nested_right, MopSnapshot)
                and nested_right.kind is OperandKind.NUMBER
                and nested_right.value
                == int(condition.value) & ((1 << (8 * int(condition.stack_size))) - 1)
                and nested_right.size == int(condition.stack_size)
                and isinstance(right, MopSnapshot)
                and right.kind is OperandKind.NUMBER
                and right.value == 0
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
            actual_counter = (
                nested_left.reg
                if isinstance(nested_left, MopSnapshot)
                and expected_counter_kind is OperandKind.REGISTER
                else nested_left.stkoff
                if isinstance(nested_left, MopSnapshot)
                else None
            )
            size = int(condition.counter_size)
            if not (
                getattr(observed_tail, "predicate_kind", None) is PredicateKind.NE
                and isinstance(nested, MopSnapshot)
                and nested.kind is OperandKind.SUBINSN
                and nested.sub_predicate_kind is expected_predicate
                and isinstance(nested_left, MopSnapshot)
                and nested_left.kind is expected_counter_kind
                and actual_counter == int(expected_counter)
                and nested_left.size == size
                and isinstance(nested_right, MopSnapshot)
                and nested_right.kind is OperandKind.NUMBER
                and nested_right.value
                == int(condition.bound) & ((1 << (8 * size)) - 1)
                and nested_right.size == size
                and isinstance(right, MopSnapshot)
                and right.kind is OperandKind.NUMBER
                and right.value == 0
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
            raise drift(f"conditional source {source} lacks an observed conditional tail")
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
        if (role == "fallthrough" or stateful_helper) and helper != observed_source + expected_offset:
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
                and getattr(source_operand, "value", None)
                == int(state_value) & mask
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
                raise drift(f"conditional source {pre_serial} has partial arm-state proof")
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
                ) if stateful else None,
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

    predecessors: dict[int, list[int]] = {int(serial): [] for serial in pre_graph.blocks}
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
        if (
            state_merge is not None
            and _is_effect_free_dispatcher_router(
                flow_graph.get_block(int(state_merge.serial))
            )
        ):
            roles_by_serial.setdefault(int(state_merge.serial), "state_merge")
    return tuple(
        RetiredDispatcherInfrastructure(
            role=role,
            anchor=_anchor(flow_graph, serial),
        )
        for serial, role in sorted(roles_by_serial.items())
    )


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
    return all(
        getattr(insn, "kind", None)
        in {InsnKind.NOP, InsnKind.GOTO, InsnKind.COND_JUMP, InsnKind.EQUALITY_JUMP}
        for insn in insns
    )


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
        is_comparison = (
            len(successors) == 2
            and getattr(block, "kind", None) in {BlockKind.TWO_WAY, BlockKind.N_WAY}
        )
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
    return int(feeder_serial) in {
        int(serial) for serial in state_plumbing_serials
    }


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
    pre_reachable = _reachable_from_entry(
        flow_graph.as_adjacency_dict(),
        int(flow_graph.entry_serial),
    )
    post_reachable = _reachable_from_entry(
        post_graph.as_adjacency_dict(),
        int(post_graph.entry_serial),
    )
    lost_blocks = frozenset(int(serial) for serial in pre_reachable - post_reachable)
    dispatcher = coverage.dispatcher
    handlers = frozenset(int(serial) for serial in authoritative_handler_serials)
    handler_anchors = _anchors_for_serials(flow_graph, handlers)
    post_handlers = _anchors_for_serials(
        post_graph,
        frozenset(serial for serial in handlers if serial in post_reachable),
    )
    pre_terminals = frozenset(int(serial) for serial in reachable_terminal_blocks(flow_graph))
    post_terminal_serials = frozenset(
        int(serial) for serial in reachable_terminal_blocks(post_graph)
    )
    pre_terminal_anchors = _anchors_for_serials(flow_graph, pre_terminals)
    post_terminal_anchors = _anchors_for_serials(post_graph, post_terminal_serials)
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
        safety.get(name) is not expected
        for name, expected in required_safety.items()
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
    normalized_attempt = str(attempt_id).strip() if attempt_id is not None else "unknown"
    return f"plan={normalized_plan or 'unknown'}:attempt={normalized_attempt or 'unknown'}"


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
        enforcement_status = (
            "fragment_rejected" if enforced else "heuristic_observed"
        )
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
            else _use_def_optional_int(getattr(coverage_validation, "function_ea", None))
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
    if (
        pre_dispatcher is None
        or int(getattr(pre_dispatcher, "start_ea", 0) or 0) != int(dispatcher.ea)
    ):
        return rejected("dispatcher_corridor_coverage_dispatcher_anchor_stale")
    observed_coverage = _coverage_from_post_successors(
        pre_graph,
        post_successors=post_graph.as_adjacency_dict(),
        dispatcher_entry_serial=int(dispatcher.serial),
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
    if operation not in {
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
        and instruction.control.transfer
        is ControlTransferKind.CONDITIONAL_BRANCH
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
    start = int(dispatcher_entry_serial)
    seen: set[int] = set()
    pending = deque(((start, False),))
    while pending:
        serial, allow_exit_leaf = pending.popleft()
        serial = int(serial)
        if serial in seen:
            continue
        block = flow_graph.get_block(serial)
        if block is None or not _is_effect_free_dispatcher_router(block):
            continue
        successors = tuple(int(target) for target in block.succs)
        if len(successors) == 2 and block.kind in {
            BlockKind.TWO_WAY,
            BlockKind.N_WAY,
        }:
            instructions = InstructionProjection.from_block(block)
            branches = tuple(
                index
                for index, instruction in enumerate(instructions)
                if instruction.control is not None
                and instruction.control.transfer
                is ControlTransferKind.CONDITIONAL_BRANCH
            )
            if len(branches) != 1:
                continue
            _constant, identity = split_const_storage_identity_from_branch(
                instructions,
                branches[0],
                min_const=-1,
            )
            if identity != state_identity:
                continue
        elif not (allow_exit_leaf and len(successors) == 1):
            continue
        seen.add(serial)
        pending.extend((target, True) for target in successors)
    return frozenset(seen)


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


def _route_dispatcher_constant(
    flow_graph: FlowGraph,
    *,
    dispatcher_serial: int,
    comparison_region: frozenset[int],
    state_identity: StorageIdentity,
    value: int,
) -> int | None:
    """Evaluate one constant through the canonical comparison forest."""
    current = int(dispatcher_serial)
    seen: set[int] = set()
    while current in comparison_region and current not in seen:
        seen.add(current)
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
            if storage_identity_from_varnode(operand) == state_identity:
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
    return None if current in seen else current


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
    state_identity = _dispatcher_state_identity(
        pre_graph,
        int(dispatcher.serial),
    )
    if state_identity is None:
        return None
    comparison_region = _state_dispatcher_comparison_region(
        pre_graph,
        dispatcher_entry_serial=int(dispatcher.serial),
        state_identity=state_identity,
    )
    if int(dispatcher.serial) not in comparison_region:
        return None
    pre_reachable = _reachable_from_entry(
        pre_graph.as_adjacency_dict(),
        int(pre_graph.entry_serial),
    )
    post_reachable = _reachable_from_entry(
        post_graph.as_adjacency_dict(),
        int(post_graph.entry_serial),
    )
    lost = frozenset(pre_reachable - post_reachable)
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
            dispatcher_serial=int(dispatcher.serial),
            state_identity=state_identity,
        )
        if writer is not None:
            state_writers[int(serial)] = writer

    handler_serials = {
        int(anchor.serial) for anchor in proof.authoritative_handlers
    }
    normalizer_routes: list[IntervalStateNormalizerRouteProof] = []
    normalizer_serials: set[int] = set()
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
            dispatcher_serial=int(dispatcher.serial),
            comparison_region=comparison_region,
            state_identity=state_identity,
            value=normalized_value,
        )
        if (
            routed_handler is None
            or routed_handler == int(serial)
            or routed_handler not in handler_serials
            or routed_handler not in post_reachable
        ):
            continue
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

    semantic_handler_serials = handler_serials - normalizer_serials
    if not semantic_handler_serials:
        return None
    semantic_handlers = _anchors_for_serials(pre_graph, semantic_handler_serials)
    post_handlers = _anchors_for_serials(
        post_graph,
        frozenset(serial for serial in semantic_handler_serials if serial in post_reachable),
    )
    if set(semantic_handlers) != set(post_handlers):
        return None
    if set(proof.pre_reachable_terminals) != set(proof.post_reachable_terminals):
        return None

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
            if serial in projected_successors or not (
                projected_successors & semantic_handler_serials
            ):
                return None

    allowed_lost = comparison_region | frozenset(state_writers) | frozenset(
        normalizer_serials
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
            RetiredDispatcherInfrastructure(role=role, anchor=_anchor(pre_graph, serial))
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
    )


def validate_dispatcher_removal_preflight_proof(
    pre_graph: FlowGraph,
    *,
    post_graph: FlowGraph,
    plan_metadata: object,
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
    if dispatcher is None or coverage_dispatcher is None or dispatcher != coverage_dispatcher:
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
    projected_coverage = _coverage_from_post_successors(
        pre_graph,
        post_successors=post_graph.as_adjacency_dict(),
        dispatcher_entry_serial=int(dispatcher.serial),
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
        if role not in {
            "comparison_dispatcher",
            "dispatcher_feeder",
            "state_merge",
        } or anchor is None:
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
        for anchor in (
            _anchor_from_payload(value) for value in raw_state_plumbing
        )
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
    )
    interval_normalizer = _interval_state_normalizer_retirement_allowance(
        pre_graph,
        post_graph=post_graph,
        raw_proof=raw_proof,
        proof=proof,
        coverage=projected_coverage,
    )
    if interval_normalizer is not None:
        return DispatcherRemovalPreflightValidation(
            passed=True,
            reason="interval_state_normalizer_retirement",
            proof=proof,
            interval_state_normalizer_retirement=interval_normalizer,
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
    handler_serials = {
        int(anchor.serial) for anchor in proof.authoritative_handlers
    }
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
