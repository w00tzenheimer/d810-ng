"""Exact post-plan coverage accounting for dispatcher-entry corridors.

The minimal unflatten emitter historically counted only unresolved transition
rows.  That is not a completion signal: a state-write/merge corridor can be
reachable and still enter the dispatcher even when every *emitted* transition
has a concrete target.  This module applies the planned CFG redirects to the
portable graph and records the original corridors as covered or residual.

It is deliberately planner-side and SQLite-free.  The returned coverage and
forecast models are consumed by the transaction authority; canonical diagnostic
facts are published by the authority-phase observability facade.
"""

from __future__ import annotations

from collections import deque
from collections.abc import Mapping
from dataclasses import dataclass, replace

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
from d810.analyses.control_flow.instruction_semantics import (
    split_const_storage_identity_from_branch,
)
from d810.ir.expressions import ValueOpKind
from d810.ir.flowgraph import (
    BlockKind,
    FlowGraph,
    InsnKind,
    OperandKind,
)
from d810.ir.insn_projection import (
    InstructionProjection,
    is_effect_free_operand_tree,
)
from d810.ir.semantics import ControlTransferKind
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
    "DispatcherCycleBreakForecast",
    "DetachedDeadHandlerComponentAnalysis",
    "RetiredDispatcherInfrastructure",
    "analyze_dispatcher_corridor_coverage",
    "build_dispatcher_removal_forecast",
    "build_detached_dead_handler_component_analysis",
    "forecast_terminal_switch_cycle_break",
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
class DispatcherCycleBreakForecast:
    """Producer-only topology forecast for one detached terminal residue."""

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
class DetachedDeadHandlerComponentAnalysis:
    """Producer-only source anchors for one candidate dead-handler island.

    This proposal contains no allowance or candidate verdict.  Canonical
    transaction binding re-establishes every topology and semantic premise.
    """

    dispatcher: DispatcherBlockAnchor
    dead_handlers: tuple[DispatcherBlockAnchor, ...]
    retained_handlers: tuple[DispatcherBlockAnchor, ...]
    component: tuple[DispatcherBlockAnchor, ...]
    comparison_region: tuple[DispatcherBlockAnchor, ...]


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
    # These are producer forecasts only.  They are deliberately absent from
    # the canonical forecast identity and cannot carry a pass/fail verdict.
    retirement_candidates: tuple[RetiredDispatcherInfrastructure, ...] = ()
    cycle_break: DispatcherCycleBreakForecast | None = None
    detached_dead_handler_component: DetachedDeadHandlerComponentAnalysis | None = None

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

    @property
    def whole_function_proof_status(self) -> str:
        """Human-facing status; lack of a claim is not a failed coverage test."""
        return "claimed" if self.full_unflattening_claim else "not_claimed"

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
    if int(feeder_serial) == int(dispatcher_serial):
        # A direct dispatcher self-edge is one edge, not an upstream walk
        # through the dispatcher again. Other incoming corridors are enumerated
        # independently; retain this edge so reachable residue stays visible.
        return (((int(dispatcher_serial), int(dispatcher_serial)),), True)
    predecessors = _predecessors(successors)
    # Every immediate feeder input is already an explicit graph edge, so a
    # wide merge needs at least that many output rows. Keep further upstream
    # expansion bounded independently of this output-linear fan-in floor.
    path_limit = max(_MAX_CORRIDORS, len(predecessors.get(int(feeder_serial), ())))
    paths: list[tuple[int, ...]] = []
    complete = True

    def append(path: tuple[int, ...]) -> None:
        nonlocal complete
        if len(paths) >= path_limit:
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

    def is_terminal_dispatcher_reentry(
        predecessor: int,
        suffix: tuple[int, ...],
    ) -> bool:
        """Accept a terminal dispatcher boundary, never an internal cycle."""
        if predecessor != int(dispatcher_serial) or len(suffix) < 2:
            return False
        if int(suffix[-1]) != int(dispatcher_serial):
            return False
        merge_serial = int(suffix[0])
        feeder_serial = int(suffix[-2])
        if successors.get(feeder_serial, ()) != (int(dispatcher_serial),):
            return False
        if merge_serial not in successors.get(int(dispatcher_serial), ()):
            return False
        # A direct dispatcher -> handler -> dispatcher loop is its own
        # terminal boundary.  In longer paths, an edge from the upstream merge
        # back to the dispatcher instead proves an internal repeated cycle.
        return merge_serial == feeder_serial or int(dispatcher_serial) not in successors.get(
            merge_serial, ()
        )

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
        if predecessor in seen:
            if is_terminal_dispatcher_reentry(predecessor, suffix):
                append(suffix)
            elif (
                len(suffix) >= 3
                and predecessor == int(suffix[0])
                and set(successors.get(predecessor, ()))
                == {predecessor, int(suffix[1])}
            ):
                # A payload self-loop has one finite exit corridor regardless
                # of how many times its body runs. Keep that body as the path
                # boundary, without repeating its identity or classifying it
                # as single-successor state plumbing. This proves coverage of
                # the exit only; it does not authorize removing the loop.
                append(suffix)
            else:
                complete = False
            return
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
                        # Preserve the merge boundary while omitting the
                        # already-recorded dispatcher re-entry node.
                        append((int(predecessor), *suffix))
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
            if is_terminal_dispatcher_reentry(predecessor, suffix):
                # The dispatcher re-entry is the corridor boundary, not a
                # second path node.  Keeping it would manufacture a cyclic
                # corridor that cannot be represented by the typed coverage
                # path model.
                append(suffix)
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
) -> tuple[RetiredDispatcherInfrastructure, ...]:
    """Return only roles that are explicit in router or corridor evidence.

    A generic block on a corridor is deliberately *not* forecast.  The
    producer admits only the known comparison region plus exact feeder and
    shared state-merge anchors surfaced by corridor enumeration.
    """
    # ``retirement_candidates`` field is diagnostic evidence, not authority. The
    # candidate is recomputed from the immutable source CFG rather than from
    # producer/metadata role labels.
    roles_by_serial: dict[int, str] = {
        int(serial): "comparison_dispatcher"
        for serial in _independent_comparison_dispatcher_region(
            flow_graph,
            dispatcher_entry_serial=int(dispatcher_entry_serial),
        )
    }
    dispatcher_block = flow_graph.get_block(int(dispatcher_entry_serial))
    if _is_effect_free_dispatcher_router(dispatcher_block):
        roles_by_serial.setdefault(int(dispatcher_entry_serial), "comparison_dispatcher")
    for corridor in coverage.covered_corridors:
        feeder = corridor.feeder
        if _is_effect_free_dispatcher_router(flow_graph.get_block(int(feeder.serial))):
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
    """Recognize control-only comparison or literal switch infrastructure.

    The proof is intentionally narrower than normal CFG analysis: an empty
    portable snapshot is an accepted control-only node, while populated blocks
    must contain only branch/no-op instructions, with literal switch targets
    checked against the block's edges. Any unclassified instruction keeps
    the node semantic and makes the narrow allowance abstain.
    """
    if block is None:
        return False
    insns = tuple(getattr(block, "insn_snapshots", ()) or ())
    if not insns:
        return True
    for insn in insns:
        if getattr(insn, "kind", None) is InsnKind.TABLE_JUMP:
            # Literal case rows describe control destinations, not executable
            # operand expressions. Check the whole block as usual; admit only
            # a final table branch with a pure selector and exact CFG targets.
            selector = getattr(insn, "l", None)
            cases = getattr(insn, "r", None)
            destination = getattr(insn, "d", None)
            rows = tuple(getattr(cases, "switch_cases", ()) or ())
            if (
                insn is not insns[-1]
                or getattr(insn, "is_call", False)
                or getattr(insn, "call_kind", None) is not None
                or selector is None
                or getattr(selector, "kind", None) is OperandKind.EMPTY
                or not is_effect_free_operand_tree(selector)
                or getattr(cases, "kind", None) is not OperandKind.CASE_LIST
                or getattr(cases, "args", ())
                or getattr(cases, "sub_l", None) is not None
                or getattr(cases, "sub_r", None) is not None
                or not rows
                or any(
                    type(row) is not tuple or len(row) != 2
                    or type(row[0]) is not tuple or type(row[1]) is not int
                    or any(type(value) is not int for value in row[0])
                    for row in rows
                )
                or {row[1] for row in rows} != set(getattr(block, "succs", ()))
                or (destination is not None and getattr(destination, "kind", None) is not OperandKind.EMPTY)
            ):
                return False
            continue
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


def build_dispatcher_removal_forecast(
    flow_graph: FlowGraph,
    *,
    coverage: DispatcherCorridorCoverage,
    dispatcher_entry_serial: int | None,
) -> DispatcherCorridorCoverage:
    """Return producer-only retirement candidates from source CFG structure.

    This function does not inspect candidate reachability, terminal identity,
    use-def safety, or loss sets.  Those are transaction obligations.  A
    candidate is emitted only when the source dispatcher and corridor anchors
    are structurally bindable; an incomplete coverage forecast is preserved so
    the authority phase can reject it with the complete evidence attached.
    """
    if (
        dispatcher_entry_serial is None
        or coverage.dispatcher is None
        or int(coverage.dispatcher.serial) != int(dispatcher_entry_serial)
    ):
        return coverage
    retired = _retired_dispatcher_infrastructure(
        flow_graph,
        coverage,
        dispatcher_entry_serial=int(dispatcher_entry_serial),
    )
    return replace(coverage, retirement_candidates=tuple(retired))


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


def build_detached_dead_handler_component_analysis(
    flow_graph: FlowGraph,
    *,
    post_graph: FlowGraph,
    coverage: DispatcherCorridorCoverage,
    authoritative_handler_serials: frozenset[int],
    patch_plan: PatchPlan | None = None,
) -> DetachedDeadHandlerComponentAnalysis | None:
    """Propose one bounded dead-handler island for canonical binding.

    The planner may name only source anchors.  It does not classify loss or
    decide whether the projected or observed candidate is acceptable.
    """
    del patch_plan
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
        flow_graph,
        dispatcher_entry_serial=dispatcher_serial,
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
        # Hex-Rays can preserve an operand wrapper the strict classifier does
        # not normalize.  Keep this fallback bounded to dispatcher-connected,
        # pure-control nodes and stop at semantic handler entries.
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
        flow_graph.as_adjacency_dict(),
        int(flow_graph.entry_serial),
    )
    post_reachable = _reachable_from_entry(
        post_graph.as_adjacency_dict(),
        int(post_graph.entry_serial),
    )
    dead_handlers = frozenset(handlers - post_reachable)
    retained_handlers = frozenset(handlers & post_reachable)
    if not dead_handlers or not retained_handlers or not dead_handlers <= pre_reachable:
        return None
    if set(reachable_terminal_blocks(flow_graph)) != set(
        reachable_terminal_blocks(post_graph)
    ):
        return None
    for serial in dead_handlers:
        block = flow_graph.get_block(serial)
        if block is None:
            return None
        reachable_preds = frozenset(
            int(pred) for pred in block.preds if int(pred) in pre_reachable
        )
        if not reachable_preds or not reachable_preds <= comparison_region:
            return None
    if not check_effectful_reachability_preserved(
        flow_graph,
        post_adj=post_graph.as_adjacency_dict(),
    ).passed:
        return None
    lost = frozenset(pre_reachable - post_reachable)
    component: set[int] = set()
    pending = list(dead_handlers)
    while pending:
        serial = int(pending.pop())
        if (
            serial in component
            or serial == dispatcher_serial
            or serial in post_reachable
            or serial not in lost
        ):
            continue
        component.add(serial)
        block = flow_graph.get_block(serial)
        if block is not None:
            pending.extend(int(target) for target in block.succs)
    if not dead_handlers <= component:
        return None
    for serial in component:
        block = flow_graph.get_block(serial)
        if block is None or any(
            instruction.is_call
            or instruction.kind in {InsnKind.CALL, InsnKind.STORE}
            for instruction in block.insn_snapshots
        ):
            return None
        if any(
            int(pred) in pre_reachable
            and int(pred) not in component
            and int(pred) not in comparison_region
            for pred in block.preds
        ):
            return None
    if len(component) * 2 >= max(1, len(pre_reachable)):
        return None
    return DetachedDeadHandlerComponentAnalysis(
        dispatcher=dispatcher,
        dead_handlers=_anchors_for_serials(flow_graph, dead_handlers),
        retained_handlers=_anchors_for_serials(flow_graph, retained_handlers),
        component=_anchors_for_serials(flow_graph, frozenset(component)),
        comparison_region=_anchors_for_serials(flow_graph, comparison_region),
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


def forecast_terminal_switch_cycle_break(
    pre_graph: FlowGraph,
    *,
    post_graph: FlowGraph,
    patch_plan: PatchPlan,
    coverage: DispatcherCorridorCoverage,
    dispatcher_entry_serial: int,
    authoritative_handler_serials: frozenset[int],
) -> DispatcherCorridorCoverage:
    """Forecast an exact terminal redirect that makes switch residue acyclic.

    This producer fact is only a candidate for the canonical terminal-cycle
    claim.  Transaction binding still checks the source/candidate residue and
    all route obligations before producing a verdict.
    """
    dispatcher = coverage.dispatcher
    if (
        dispatcher is None
        or int(dispatcher.serial) != int(dispatcher_entry_serial)
        or not authoritative_handler_serials
    ):
        return coverage
    dispatcher_block = pre_graph.get_block(int(dispatcher.serial))
    if dispatcher_block is None or dispatcher_block.kind is not BlockKind.N_WAY:
        return coverage
    redirects = _resolved_goto_redirects(patch_plan)
    if redirects is None:
        return coverage
    handler_serials = {int(serial) for serial in authoritative_handler_serials}
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
        return coverage
    terminal_source, shared_merge, terminal_target, terminal_stop = candidates[0]
    projected_source = post_graph.get_block(terminal_source)
    projected_merge = post_graph.get_block(shared_merge)
    if (
        projected_source is None
        or tuple(projected_source.succs) != (terminal_target,)
        or projected_merge is None
        or tuple(projected_merge.succs) != (terminal_target,)
    ):
        return coverage
    residue = _detached_dispatcher_residue(post_graph, int(dispatcher.serial))
    if (
        residue is None
        or shared_merge not in residue
        or not _residue_is_acyclic(post_graph, residue)
    ):
        return coverage
    cycle_break = DispatcherCycleBreakForecast(
        dispatcher=dispatcher,
        terminal_source=_anchor(pre_graph, terminal_source),
        shared_merge=_anchor(pre_graph, shared_merge),
        terminal_target=_anchor(pre_graph, terminal_target),
        terminal_stop=_anchor(pre_graph, terminal_stop),
        retired_residue=_anchors_for_serials(pre_graph, residue),
    )
    return replace(coverage, cycle_break=cycle_break)
