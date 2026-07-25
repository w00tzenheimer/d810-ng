"""Plan PREOPT boundary ports from state-transition microcode facts.

The planner is intentionally portable and mutation-free.  It converts exact
reaching state definitions, or an explicit two-arm state choice, into the same
closure-owned boundary-port requests used by the PREOPT importer.  Unknown
definitions and ambiguous state-to-handler mappings abstain.
"""

from __future__ import annotations

from dataclasses import dataclass

from d810.analyses.control_flow.materialized_indirect_transfer import (
    TerminalReturnCarrierRequest,
)
from d810.analyses.control_flow.residual_entry_bridge import EntryBridgeEvidence
from d810.core.typing import Collection, Mapping, Sequence

try:
    from .preopt_boundary_port import (
        PreoptBoundaryEndpointOwner,
        PreoptBoundaryPortAbstention,
        PreoptBoundaryPortAbstentionReason,
        PreoptBoundaryPortPlan,
        PreoptConditionalBoundaryPort,
        PreoptDirectBoundaryPort,
        classify_preopt_boundary_endpoint_owner,
    )
    from .preopt_boundary_port_capture import (
        PreoptPortBlockFact,
        PreoptPortTailKind,
        reaching_register_definitions,
    )
except ImportError:  # Direct execution from this investigation directory.
    from preopt_boundary_port import (
        PreoptBoundaryEndpointOwner,
        PreoptBoundaryPortAbstention,
        PreoptBoundaryPortAbstentionReason,
        PreoptBoundaryPortPlan,
        PreoptConditionalBoundaryPort,
        PreoptDirectBoundaryPort,
        classify_preopt_boundary_endpoint_owner,
    )
    from preopt_boundary_port_capture import (
        PreoptPortBlockFact,
        PreoptPortTailKind,
        reaching_register_definitions,
    )


_MASK32 = 0xFFFFFFFF


def extend_semantic_seed_eas_with_terminal_targets(
    seed_eas: Sequence[int],
    requests: Sequence[TerminalReturnCarrierRequest],
    *,
    state_register: int,
) -> tuple[int, ...]:
    """Add exact terminal endpoints for the selected state identity."""
    register = int(state_register)
    return tuple(
        dict.fromkeys(
            (
                *(int(ea) for ea in seed_eas),
                *(
                    int(request.terminal_target_ea)
                    for request in requests
                    if int(request.state_var_reg) == register
                ),
            )
        )
    )


@dataclass(frozen=True, slots=True)
class PreoptUnresolvedStateCut:
    """One PREOPT indirect tail whose state transfer is not yet connected."""

    source_block_ea: int
    tail_ea: int
    state_register: int


@dataclass(frozen=True, slots=True)
class PreoptConditionalStateChoice:
    """An exact native predicate selecting two concrete dispatcher states."""

    consumer_tail_ea: int
    predicate_block_ea: int
    predicate_ea: int
    state_register: int
    taken_state: int
    fallthrough_state: int
    resolver_kind: str
    source_owner: PreoptBoundaryEndpointOwner | None = None
    logical_source_anchor_ea: int | None = None
    predicate_ida_stkoff: int | None = None
    predicate_size: int | None = None
    condition_code: int | None = None


@dataclass(frozen=True, slots=True)
class PreoptConditionalTopologyFact:
    """Native arm orientation for one exact PREOPT conditional tail."""

    source_block_ea: int
    predicate_ea: int
    taken_successor_ea: int
    fallthrough_successor_ea: int

    def __post_init__(self) -> None:
        if int(self.taken_successor_ea) == int(self.fallthrough_successor_ea):
            raise ValueError("conditional topology requires two distinct arms")


def merge_exact_state_payload_handler_eas(
    current: Mapping[int, Collection[int]],
    *,
    state_register: int,
    exact_routes: Collection[tuple[int, int, int]],
) -> dict[int, set[int]]:
    """Overlay exact state targets while preserving exact-proof ambiguity.

    Each route is ``(state_register, state_constant, target_ea)``.  Evidence
    for another state cell is ignored.  Exact targets replace weaker current
    targets for the same state.  Multiple conflicting exact targets remain
    visible so the downstream boundary planner abstains instead of choosing.
    """
    selected_register = int(state_register)
    merged = {
        int(state) & _MASK32: {int(target_ea) for target_ea in target_eas}
        for state, target_eas in current.items()
    }
    exact_by_state: dict[int, set[int]] = {}
    for route_register, state_constant, target_ea in exact_routes:
        if int(route_register) != selected_register or int(target_ea) <= 0:
            continue
        exact_by_state.setdefault(
            int(state_constant) & _MASK32,
            set(),
        ).add(int(target_ea))
    merged.update(exact_by_state)
    return merged


def preopt_entry_bridge_source_fact(
    evidence: EntryBridgeEvidence,
) -> PreoptPortBlockFact | None:
    """Project proven live PREOPT entry topology into one capture fact."""
    source_ea = evidence.predicate_block_ea
    taken_ea = evidence.taken_arm_entry_ea
    fallthrough_ea = evidence.fallthrough_arm_entry_ea
    conditional_tail_ea = evidence.conditional_tail_ea
    if (
        source_ea is None
        or taken_ea is None
        or fallthrough_ea is None
        or conditional_tail_ea is None
        or int(taken_ea) == int(fallthrough_ea)
    ):
        return None
    predicate_ea = int(conditional_tail_ea)
    return PreoptPortBlockFact(
        start_ea=int(source_ea),
        end_ea=max(int(source_ea) + 1, predicate_ea + 1),
        instruction_eas=(predicate_ea,),
        successor_eas=(int(taken_ea), int(fallthrough_ea)),
        successors_complete=True,
        has_side_effects=False,
        tail_ea=predicate_ea,
        taken_successor_ea=int(taken_ea),
        fallthrough_successor_ea=int(fallthrough_ea),
        tail_kind=PreoptPortTailKind.CONDITIONAL,
    )


def _preopt_cut_block_ea(
    cut: PreoptUnresolvedStateCut,
    blocks_by_ea: Mapping[int, PreoptPortBlockFact],
) -> int | None:
    tail_ea = int(cut.tail_ea)
    exact_tail = {
        int(block_ea)
        for block_ea, block in blocks_by_ea.items()
        if block.tail_ea is not None and int(block.tail_ea) == tail_ea
    }
    if len(exact_tail) == 1:
        return next(iter(exact_tail))
    if exact_tail:
        return None
    containing = {
        int(block_ea)
        for block_ea, block in blocks_by_ea.items()
        if tail_ea in map(int, block.instruction_eas)
    }
    if len(containing) == 1:
        return next(iter(containing))
    if containing:
        return None
    source_block_ea = int(cut.source_block_ea)
    return source_block_ea if source_block_ea in blocks_by_ea else None


def _writes_to_register(
    block: PreoptPortBlockFact,
    register: int,
) -> tuple[int, ...]:
    return tuple(
        sorted(
            {
                int(write_ea)
                for write_register, write_ea in block.register_write_eas
                if int(write_register) == int(register)
            }
        )
    )


def _unique_constant_write(
    block: PreoptPortBlockFact,
    register: int,
) -> tuple[int, int] | None:
    writes = {
        (int(constant) & _MASK32, int(write_ea))
        for write_register, constant, write_ea in block.register_constant_writes
        if int(write_register) == int(register)
    }
    return next(iter(writes)) if len(writes) == 1 else None


def _conditional_skip_arms(
    block: PreoptPortBlockFact,
    *,
    blocks_by_ea: Mapping[int, PreoptPortBlockFact],
) -> tuple[int, PreoptPortBlockFact, bool] | None:
    """Return ``(join_ea, copy_block, copy_is_taken)`` for a skip diamond."""
    if (
        block.tail_kind is not PreoptPortTailKind.CONDITIONAL
        or block.tail_ea is None
        or block.taken_successor_ea is None
        or block.fallthrough_successor_ea is None
        or not block.successors_complete
    ):
        return None
    taken_ea = int(block.taken_successor_ea)
    fallthrough_ea = int(block.fallthrough_successor_ea)
    if set(map(int, block.successor_eas)) != {taken_ea, fallthrough_ea}:
        return None
    for direct_ea, copy_ea, copy_is_taken in (
        (taken_ea, fallthrough_ea, False),
        (fallthrough_ea, taken_ea, True),
    ):
        copy_block = blocks_by_ea.get(copy_ea)
        if (
            copy_block is not None
            and copy_block.successors_complete
            and tuple(map(int, copy_block.successor_eas)) == (direct_ea,)
        ):
            return direct_ea, copy_block, copy_is_taken
    return None


def recognize_preopt_conditional_state_choices(
    cuts: Sequence[PreoptUnresolvedStateCut],
    *,
    blocks_by_ea: Mapping[int, PreoptPortBlockFact],
) -> tuple[PreoptConditionalStateChoice, ...]:
    """Recognize PREOPT's conditional-skip lowering of a two-state choice.

    Hex-Rays lowers a native conditional move into a conditional block whose
    direct arm skips a one-block register copy.  Recognition requires the two
    resulting state definitions to be the exact reaching definitions at the
    unresolved indirect cut.  Ambiguous candidates are ignored.
    """
    normalized_cuts = tuple(
        sorted(
            set(cuts),
            key=lambda row: (
                int(row.tail_ea),
                int(row.source_block_ea),
                int(row.state_register),
            ),
        )
    )
    definitions_by_register = {
        int(cut.state_register): reaching_register_definitions(
            blocks_by_ea,
            int(cut.state_register),
        )[1]
        for cut in normalized_cuts
    }
    recognized: list[PreoptConditionalStateChoice] = []
    for cut in normalized_cuts:
        state_register = int(cut.state_register)
        cut_block_ea = _preopt_cut_block_ea(cut, blocks_by_ea)
        if cut_block_ea is None:
            continue
        reaching = definitions_by_register[state_register].get(
            cut_block_ea,
            frozenset(),
        )
        if not reaching or any(int(definition) < 0 for definition in reaching):
            continue
        candidates: set[PreoptConditionalStateChoice] = set()
        for predicate_block_ea, predicate_block in blocks_by_ea.items():
            arms = _conditional_skip_arms(
                predicate_block,
                blocks_by_ea=blocks_by_ea,
            )
            if arms is None:
                continue
            _join_ea, copy_block, copy_is_taken = arms
            state_default = _unique_constant_write(
                predicate_block,
                state_register,
            )
            if state_default is None:
                continue
            default_state, default_write_ea = state_default
            copies = {
                (int(source_register), int(write_ea))
                for dest_register, source_register, write_ea in copy_block.register_copy_writes
                if int(dest_register) == state_register
            }
            if len(copies) != 1:
                continue
            source_register, copy_write_ea = next(iter(copies))
            if _writes_to_register(copy_block, state_register) != (copy_write_ea,):
                continue
            alternate = _unique_constant_write(
                predicate_block,
                source_register,
            )
            if alternate is None:
                continue
            alternate_state, _alternate_write_ea = alternate
            if default_state == alternate_state:
                continue
            if set(map(int, reaching)) != {
                default_write_ea,
                copy_write_ea,
            }:
                continue
            taken_state = alternate_state if copy_is_taken else default_state
            fallthrough_state = default_state if copy_is_taken else alternate_state
            assert predicate_block.tail_ea is not None
            candidates.add(
                PreoptConditionalStateChoice(
                    consumer_tail_ea=int(cut.tail_ea),
                    predicate_block_ea=int(predicate_block_ea),
                    predicate_ea=int(predicate_block.tail_ea),
                    state_register=state_register,
                    taken_state=taken_state,
                    fallthrough_state=fallthrough_state,
                    resolver_kind="preopt_conditional_state_choice",
                )
            )
        if len(candidates) == 1:
            recognized.append(next(iter(candidates)))
    return tuple(
        sorted(
            recognized,
            key=lambda row: (
                int(row.consumer_tail_ea),
                int(row.predicate_block_ea),
                int(row.predicate_ea),
                int(row.state_register),
            ),
        )
    )


def recognize_preopt_pruned_conditional_state_choices(
    *,
    blocks_by_ea: Mapping[int, PreoptPortBlockFact],
    native_topology_by_ea: Mapping[int, PreoptConditionalTopologyFact],
    state_register: int,
    source_owner: PreoptBoundaryEndpointOwner,
) -> tuple[PreoptConditionalStateChoice, ...]:
    """Recover a two-state choice whose PREOPT successor edges were pruned.

    The live PREOPT graph proves the predicate and state writes.  Native CFG
    evidence supplies only the lost taken/fallthrough orientation.  A choice
    is accepted when the predicate block writes one default state, exactly one
    native arm writes one different literal state, and the other arm either
    preserves or explicitly repeats the default.  Any missing or ambiguous
    state-write fact abstains.
    """
    register = int(state_register)
    recognized: list[PreoptConditionalStateChoice] = []
    for source_ea, topology in sorted(native_topology_by_ea.items()):
        source_block_ea = int(source_ea)
        if int(topology.source_block_ea) != source_block_ea:
            continue
        source = blocks_by_ea.get(source_block_ea)
        if (
            source is None
            or source.tail_kind is not PreoptPortTailKind.CONDITIONAL
            or source.tail_ea is None
            or int(source.tail_ea) != int(topology.predicate_ea)
            or not source.successors_complete
            or source.successor_eas
            or source.has_synthetic_function_exit_successor
        ):
            continue
        default_write = _unique_constant_write(source, register)
        if default_write is None:
            continue
        default_state, default_write_ea = default_write
        if _writes_to_register(source, register) != (default_write_ea,):
            continue

        arm_states: dict[bool, int | None] = {}
        invalid_arm = False
        for is_taken, target_ea in (
            (True, int(topology.taken_successor_ea)),
            (False, int(topology.fallthrough_successor_ea)),
        ):
            arm = blocks_by_ea.get(target_ea)
            if arm is None:
                invalid_arm = True
                break
            writes = _writes_to_register(arm, register)
            if not writes:
                arm_states[is_taken] = None
                continue
            constant_write = _unique_constant_write(arm, register)
            if constant_write is None or writes != (constant_write[1],):
                invalid_arm = True
                break
            arm_states[is_taken] = int(constant_write[0]) & _MASK32
        if invalid_arm:
            continue

        alternate_arms = tuple(
            (is_taken, state)
            for is_taken, state in arm_states.items()
            if state is not None and int(state) != int(default_state)
        )
        if len(alternate_arms) != 1:
            continue
        alternate_is_taken, alternate_state = alternate_arms[0]
        other_state = arm_states[not alternate_is_taken]
        if other_state is not None and int(other_state) != int(default_state):
            continue
        recognized.append(
            PreoptConditionalStateChoice(
                consumer_tail_ea=int(topology.predicate_ea),
                predicate_block_ea=source_block_ea,
                predicate_ea=int(topology.predicate_ea),
                state_register=register,
                taken_state=(
                    int(alternate_state) if alternate_is_taken else int(default_state)
                ),
                fallthrough_state=(
                    int(default_state) if alternate_is_taken else int(alternate_state)
                ),
                resolver_kind="preopt_pruned_conditional_state_choice",
                source_owner=source_owner,
            )
        )
    return tuple(
        sorted(
            set(recognized),
            key=lambda row: (
                int(row.predicate_block_ea),
                int(row.predicate_ea),
                int(row.state_register),
            ),
        )
    )


def prove_preopt_pruned_conditional_fixed_state_sources(
    *,
    blocks_by_ea: Mapping[int, PreoptPortBlockFact],
    native_topology_by_ea: Mapping[int, PreoptConditionalTopologyFact],
    state_register: int,
    dispatcher_router_eas: Collection[int],
    resolver_bridge_targets_by_source_ea: Mapping[int, Collection[int]] | None = None,
    expected_target_eas_by_source_ea: Mapping[int, Collection[int]] | None = None,
    expected_state_write_eas_by_source_ea: Mapping[int, Collection[int]] | None = None,
    proven_indirect_source_block_eas: Collection[int] = (),
    excluded_source_eas: Collection[int] = (),
) -> frozenset[int]:
    """Prove pruned conditionals are router traversal after a fixed state."""
    register = int(state_register)
    bridge_targets = resolver_bridge_targets_by_source_ea or {}
    expected_targets_by_source = expected_target_eas_by_source_ea or {}
    expected_write_eas_by_source = expected_state_write_eas_by_source_ea or {}
    proven_indirect_sources = {
        int(source_ea) for source_ea in proven_indirect_source_block_eas
    }

    def expand_router_bridges(seed_eas: Collection[int]) -> set[int]:
        routers = {int(ea) for ea in seed_eas}
        while True:
            additions = {
                int(source_ea)
                for source_ea, target_eas in bridge_targets.items()
                if int(source_ea) not in routers
                and bool(normalized_targets := {int(ea) for ea in target_eas})
                and normalized_targets.issubset(routers)
            }
            if not additions:
                return routers
            routers.update(additions)

    base_routers = expand_router_bridges(dispatcher_router_eas)
    excluded = {int(ea) for ea in excluded_source_eas}
    proven: set[int] = set()
    candidate_source_eas = set(map(int, native_topology_by_ea)) | set(
        map(int, expected_targets_by_source)
    )
    for source_block_ea in sorted(candidate_source_eas):
        topology = native_topology_by_ea.get(source_block_ea)
        source = blocks_by_ea.get(source_block_ea)
        if (
            source_block_ea in excluded
            or (
                topology is not None
                and int(topology.source_block_ea) != source_block_ea
            )
            or source is None
            or source.tail_kind is not PreoptPortTailKind.CONDITIONAL
            or source.tail_ea is None
            or (
                topology is not None
                and int(source.tail_ea) != int(topology.predicate_ea)
            )
            or not source.successors_complete
            or source.successor_eas
            or source.has_synthetic_function_exit_successor
        ):
            continue
        expected_targets = {
            int(ea) for ea in expected_targets_by_source.get(source_block_ea, ())
        }
        if len(expected_targets) > 1:
            continue
        if expected_targets:
            expected_write_eas = {
                int(ea) for ea in expected_write_eas_by_source.get(source_block_ea, ())
            }
            if len(expected_write_eas) != 1 or not expected_write_eas.issubset(
                {int(ea) for ea in source.instruction_eas}
            ):
                continue
        else:
            state_write = _unique_constant_write(source, register)
            if state_write is None or _writes_to_register(source, register) != (
                state_write[1],
            ):
                continue
        if topology is None:
            if not expected_targets or source_block_ea not in proven_indirect_sources:
                continue
            proven.add(source_block_ea)
            continue
        source_routers = (
            base_routers
            if not expected_targets
            else expand_router_bridges((*base_routers, *expected_targets))
        )
        if {
            int(topology.taken_successor_ea),
            int(topology.fallthrough_successor_ea),
        }.issubset(source_routers):
            proven.add(source_block_ea)
    return frozenset(proven)


def _bounded_reaches(
    start_ea: int,
    target_ea: int,
    *,
    blocks_by_ea: Mapping[int, PreoptPortBlockFact],
    max_hops: int = 4,
) -> bool:
    pending = [(int(start_ea), 0)]
    seen: set[int] = set()
    while pending:
        block_ea, depth = pending.pop()
        if block_ea == int(target_ea):
            return True
        if block_ea in seen or depth >= int(max_hops):
            continue
        seen.add(block_ea)
        block = blocks_by_ea.get(block_ea)
        if block is None or not block.successors_complete:
            continue
        pending.extend(
            (int(successor_ea), depth + 1) for successor_ea in block.successor_eas
        )
    return False


def recognize_preopt_stack_carried_state_choices(
    cuts: Sequence[PreoptUnresolvedStateCut],
    *,
    blocks_by_ea: Mapping[int, PreoptPortBlockFact],
    entry_bridge_evidence: Sequence[EntryBridgeEvidence],
) -> tuple[PreoptConditionalStateChoice, ...]:
    """Bind proven entry predicates to later state-register stack loads.

    The live PREOPT recognizer already proves the predicate, both constants,
    and their merged stack store.  This adapter accepts that proof only when
    the generated PREOPT graph contains the same unique predicate block and
    store, and the matching stack load is the exact reaching definition of the
    unresolved state register.
    """
    normalized_cuts = tuple(
        sorted(
            set(cuts),
            key=lambda row: (
                int(row.tail_ea),
                int(row.source_block_ea),
                int(row.state_register),
            ),
        )
    )
    definitions_by_register = {
        int(cut.state_register): reaching_register_definitions(
            blocks_by_ea,
            int(cut.state_register),
        )[1]
        for cut in normalized_cuts
    }
    recognized: list[PreoptConditionalStateChoice] = []
    for cut in normalized_cuts:
        state_register = int(cut.state_register)
        cut_block_ea = _preopt_cut_block_ea(cut, blocks_by_ea)
        if cut_block_ea is None:
            continue
        reaching = definitions_by_register[state_register].get(
            cut_block_ea,
            frozenset(),
        )
        if not reaching or any(int(definition) < 0 for definition in reaching):
            continue
        candidates: set[PreoptConditionalStateChoice] = set()
        for evidence in entry_bridge_evidence:
            stack_identity = (
                evidence.canonical_stack_cell_identity
                if evidence.canonical_stack_cell_identity is not None
                else evidence.stack_cell_identity
            )
            stack_off, stack_size = map(int, stack_identity)
            loads = {
                int(load_ea)
                for block in blocks_by_ea.values()
                for dest_register, load_off, load_size, load_ea in block.register_stack_loads
                if int(dest_register) == state_register
                and int(load_off) == stack_off
                and int(load_size) == stack_size
            }
            if len(loads) != 1 or set(map(int, reaching)) != loads:
                continue
            load_ea = next(iter(loads))
            if int(evidence.source_store_ea) >= load_ea:
                continue
            external_source = preopt_entry_bridge_source_fact(evidence)
            if external_source is not None:
                if external_source.tail_ea is None:
                    continue
                predicate_stack_identity = evidence.canonical_predicate_stack_identity
                if predicate_stack_identity is None:
                    continue
                predicate_ida_stkoff, predicate_size = map(
                    int,
                    predicate_stack_identity,
                )
                candidates.add(
                    PreoptConditionalStateChoice(
                        consumer_tail_ea=int(cut.tail_ea),
                        predicate_block_ea=int(external_source.start_ea),
                        predicate_ea=int(external_source.tail_ea),
                        state_register=state_register,
                        taken_state=int(evidence.taken_state_constant) & _MASK32,
                        fallthrough_state=(
                            int(evidence.fallthrough_state_constant) & _MASK32
                        ),
                        resolver_kind="preopt_stack_carried_state_choice",
                        source_owner=PreoptBoundaryEndpointOwner.LIVE,
                        logical_source_anchor_ea=int(evidence.source_store_ea),
                        predicate_ida_stkoff=predicate_ida_stkoff,
                        predicate_size=predicate_size,
                        condition_code=int(evidence.condition_code),
                    )
                )
                continue
            store_blocks = {
                int(block_ea)
                for block_ea, block in blocks_by_ea.items()
                if any(
                    int(store_off) == stack_off
                    and int(store_size) == stack_size
                    and int(store_ea) == int(evidence.source_store_ea)
                    for store_off, store_size, _source_register, store_ea in block.stack_register_stores
                )
            }
            if len(store_blocks) != 1:
                continue
            store_block_ea = next(iter(store_blocks))
            predicate_blocks = {
                int(block_ea)
                for block_ea, block in blocks_by_ea.items()
                if int(evidence.predicate_ea) in map(int, block.instruction_eas)
                and block.tail_kind is PreoptPortTailKind.CONDITIONAL
                and block.tail_ea is not None
                and block.taken_successor_ea is not None
                and block.fallthrough_successor_ea is not None
                and _bounded_reaches(
                    int(block.taken_successor_ea),
                    store_block_ea,
                    blocks_by_ea=blocks_by_ea,
                )
                and _bounded_reaches(
                    int(block.fallthrough_successor_ea),
                    store_block_ea,
                    blocks_by_ea=blocks_by_ea,
                )
            }
            if len(predicate_blocks) != 1:
                continue
            predicate_block_ea = next(iter(predicate_blocks))
            predicate_block = blocks_by_ea[predicate_block_ea]
            assert predicate_block.tail_ea is not None
            taken_state = int(evidence.taken_state_constant) & _MASK32
            fallthrough_state = int(evidence.fallthrough_state_constant) & _MASK32
            if taken_state == fallthrough_state:
                continue
            candidates.add(
                PreoptConditionalStateChoice(
                    consumer_tail_ea=int(cut.tail_ea),
                    predicate_block_ea=predicate_block_ea,
                    predicate_ea=int(predicate_block.tail_ea),
                    state_register=state_register,
                    taken_state=taken_state,
                    fallthrough_state=fallthrough_state,
                    resolver_kind="preopt_stack_carried_state_choice",
                )
            )
        if len(candidates) == 1:
            recognized.append(next(iter(candidates)))
    return tuple(
        sorted(
            recognized,
            key=lambda row: (
                int(row.consumer_tail_ea),
                int(row.predicate_block_ea),
                int(row.predicate_ea),
                int(row.state_register),
            ),
        )
    )


def _handler_target(
    state_handler_eas: Mapping[int, Collection[int]],
    state: int,
    *,
    state_payload_handler_eas: Mapping[int, Collection[int]] | None = None,
) -> tuple[int | None, PreoptBoundaryPortAbstentionReason | None]:
    state_key = int(state) & _MASK32
    handler_eas = state_handler_eas
    if state_payload_handler_eas is not None and state_key in state_payload_handler_eas:
        handler_eas = state_payload_handler_eas
    targets = {
        int(target_ea)
        for target_ea in handler_eas.get(state_key, ())
        if int(target_ea) > 0
    }
    if not targets:
        return None, PreoptBoundaryPortAbstentionReason.MISSING_STATE_HANDLER
    if len(targets) != 1:
        return None, PreoptBoundaryPortAbstentionReason.AMBIGUOUS_STATE_HANDLER
    return next(iter(targets)), None


def _constant_definitions(
    blocks_by_ea: Mapping[int, PreoptPortBlockFact],
    state_register: int,
) -> tuple[dict[int, set[int]], dict[int, set[int]]]:
    states_by_write_ea: dict[int, set[int]] = {}
    blocks_by_write_ea: dict[int, set[int]] = {}
    register = int(state_register)
    for block_ea, block in blocks_by_ea.items():
        for write_register, state, write_ea in block.register_constant_writes:
            if int(write_register) != register:
                continue
            states_by_write_ea.setdefault(int(write_ea), set()).add(
                int(state) & _MASK32
            )
            blocks_by_write_ea.setdefault(int(write_ea), set()).add(int(block_ea))
    return states_by_write_ea, blocks_by_write_ea


def _direct_port_for_definition(
    *,
    definition_ea: int,
    state_register: int,
    states_by_write_ea: Mapping[int, Collection[int]],
    blocks_by_write_ea: Mapping[int, Collection[int]],
    state_handler_eas: Mapping[int, Collection[int]],
    state_payload_handler_eas: Mapping[int, Collection[int]] | None,
    imported_block_ranges: Mapping[int, tuple[int, int]],
    live_native_eas: Collection[int],
    preferred_source_owner: PreoptBoundaryEndpointOwner | None = None,
) -> tuple[PreoptDirectBoundaryPort | None, PreoptBoundaryPortAbstention | None]:
    states = {
        int(state) & _MASK32 for state in states_by_write_ea.get(int(definition_ea), ())
    }
    source_blocks = {
        int(block_ea) for block_ea in blocks_by_write_ea.get(int(definition_ea), ())
    }
    if not states:
        return None, PreoptBoundaryPortAbstention(
            int(definition_ea),
            PreoptBoundaryPortAbstentionReason.UNRESOLVED_STATE_DEFINITION,
        )
    if len(states) != 1 or len(source_blocks) != 1:
        return None, PreoptBoundaryPortAbstention(
            int(definition_ea),
            PreoptBoundaryPortAbstentionReason.CONFLICTING_SOURCE,
        )
    state = next(iter(states))
    source_block_ea = next(iter(source_blocks))
    target_ea, target_error = _handler_target(
        state_handler_eas,
        state,
        state_payload_handler_eas=state_payload_handler_eas,
    )
    if target_error is not None:
        return None, PreoptBoundaryPortAbstention(
            int(definition_ea),
            target_error,
        )
    assert target_ea is not None
    source_owner = classify_preopt_boundary_endpoint_owner(
        int(definition_ea),
        block_ea=source_block_ea,
        imported_block_ranges=imported_block_ranges,
        live_native_eas=live_native_eas,
        preferred_owner=preferred_source_owner,
    )
    target_owner = classify_preopt_boundary_endpoint_owner(
        target_ea,
        block_ea=target_ea,
        imported_block_ranges=imported_block_ranges,
        live_native_eas=live_native_eas,
    )
    if source_owner is None:
        return None, PreoptBoundaryPortAbstention(
            int(definition_ea),
            PreoptBoundaryPortAbstentionReason.MISSING_SOURCE_OWNER,
            target_ea,
        )
    if target_owner is None:
        return None, PreoptBoundaryPortAbstention(
            int(definition_ea),
            PreoptBoundaryPortAbstentionReason.MISSING_TARGET_OWNER,
            target_ea,
        )
    return (
        PreoptDirectBoundaryPort(
            source_block_ea=source_block_ea,
            source_instruction_ea=int(definition_ea),
            target_ea=target_ea,
            state_register=int(state_register),
            state_constant=state,
            source_owner=source_owner,
            target_owner=target_owner,
            resolver_kind="preopt_state_transition",
        ),
        None,
    )


def plan_preopt_literal_state_write_boundary_ports(
    *,
    blocks_by_ea: Mapping[int, PreoptPortBlockFact],
    state_register: int,
    state_handler_eas: Mapping[int, Collection[int]],
    state_payload_handler_eas: Mapping[int, Collection[int]] | None = None,
    imported_block_ranges: Mapping[int, tuple[int, int]],
    live_native_eas: Collection[int],
    preferred_source_owner: PreoptBoundaryEndpointOwner | None = None,
    candidate_state_constants: Collection[int] | None = None,
) -> PreoptBoundaryPortPlan:
    """Plan every exact literal state write that has one proven handler.

    Unlike cut-driven recovery, this inventory is intentionally independent of
    the current dispatcher frontier.  The capture phase still has to prove that
    each write owns a source-sensitive corridor into the dispatcher before a
    mutation record can be emitted.
    """
    register = int(state_register)
    states_by_write_ea, blocks_by_write_ea = _constant_definitions(
        blocks_by_ea,
        register,
    )
    candidate_states = (
        None
        if candidate_state_constants is None
        else {
            int(state_constant) & _MASK32
            for state_constant in candidate_state_constants
        }
    )
    direct: set[PreoptDirectBoundaryPort] = set()
    abstentions: set[PreoptBoundaryPortAbstention] = set()
    for definition_ea in sorted(states_by_write_ea):
        if candidate_states is not None and states_by_write_ea[
            int(definition_ea)
        ].isdisjoint(candidate_states):
            continue
        port, abstention = _direct_port_for_definition(
            definition_ea=int(definition_ea),
            state_register=register,
            states_by_write_ea=states_by_write_ea,
            blocks_by_write_ea=blocks_by_write_ea,
            state_handler_eas=state_handler_eas,
            state_payload_handler_eas=state_payload_handler_eas,
            imported_block_ranges=imported_block_ranges,
            live_native_eas=live_native_eas,
            preferred_source_owner=preferred_source_owner,
        )
        if port is not None:
            direct.add(port)
        if abstention is not None:
            abstentions.add(abstention)
    return PreoptBoundaryPortPlan(
        direct=tuple(
            sorted(
                direct,
                key=lambda row: (
                    int(row.source_block_ea),
                    int(row.source_instruction_ea),
                    int(row.target_ea),
                ),
            )
        ),
        conditional=(),
        abstentions=tuple(
            sorted(
                abstentions,
                key=lambda row: (
                    int(row.source_ea),
                    row.reason.value,
                    row.target_ea is None,
                    row.target_ea or 0,
                ),
            )
        ),
    )


def plan_preopt_owned_literal_state_write_boundary_ports(
    *,
    imported_blocks_by_ea: Mapping[int, PreoptPortBlockFact],
    live_blocks_by_ea: Mapping[int, PreoptPortBlockFact],
    state_register: int,
    state_handler_eas: Mapping[int, Collection[int]],
    state_payload_handler_eas: Mapping[int, Collection[int]] | None = None,
    imported_block_ranges: Mapping[int, tuple[int, int]],
    live_native_eas: Collection[int],
) -> PreoptBoundaryPortPlan:
    """Plan mapped state writes in each physical PREOPT graph.

    The imported and live graphs are analyzed separately so equal native EAs
    cannot merge reaching definitions from two physical CFGs.  Live-to-live
    routes remain actionable because they bypass a resolver-owned dispatcher
    even when neither endpoint belongs to the imported union.  Unmapped states
    remain unresolved and are never interpreted as returns.
    """
    handler_map = (
        state_payload_handler_eas
        if state_payload_handler_eas is not None
        else state_handler_eas
    )
    mapped_states = {
        int(state) & _MASK32
        for state, targets in handler_map.items()
        if any(int(target_ea) > 0 for target_ea in targets)
    }
    plans = (
        plan_preopt_literal_state_write_boundary_ports(
            blocks_by_ea=imported_blocks_by_ea,
            state_register=int(state_register),
            state_handler_eas=state_handler_eas,
            state_payload_handler_eas=state_payload_handler_eas,
            imported_block_ranges=imported_block_ranges,
            live_native_eas=live_native_eas,
            preferred_source_owner=PreoptBoundaryEndpointOwner.IMPORTED,
            candidate_state_constants=mapped_states,
        ),
        plan_preopt_literal_state_write_boundary_ports(
            blocks_by_ea=live_blocks_by_ea,
            state_register=int(state_register),
            state_handler_eas=state_handler_eas,
            state_payload_handler_eas=state_payload_handler_eas,
            imported_block_ranges=imported_block_ranges,
            live_native_eas=live_native_eas,
            preferred_source_owner=PreoptBoundaryEndpointOwner.LIVE,
            candidate_state_constants=mapped_states,
        ),
    )
    abstentions = {abstention for plan in plans for abstention in plan.abstentions}
    abstained_sources = {int(abstention.source_ea) for abstention in abstentions}
    candidates = {
        port
        for plan in plans
        for port in plan.direct
        if int(port.source_instruction_ea) not in abstained_sources
    }
    candidates_by_source: dict[
        tuple[PreoptBoundaryEndpointOwner, int, int],
        set[PreoptDirectBoundaryPort],
    ] = {}
    for port in candidates:
        candidates_by_source.setdefault(
            (
                port.source_owner,
                int(port.source_block_ea),
                int(port.source_instruction_ea),
            ),
            set(),
        ).add(port)
    direct: list[PreoptDirectBoundaryPort] = []
    for (_owner, _source_block_ea, source_ea), source_candidates in sorted(
        candidates_by_source.items(),
        key=lambda row: (row[0][0].value, row[0][1], row[0][2]),
    ):
        if len(source_candidates) == 1:
            direct.append(next(iter(source_candidates)))
            continue
        abstentions.add(
            PreoptBoundaryPortAbstention(
                source_ea,
                PreoptBoundaryPortAbstentionReason.CONFLICTING_SOURCE,
            )
        )
    return PreoptBoundaryPortPlan(
        direct=tuple(
            sorted(
                direct,
                key=lambda row: (
                    int(row.source_block_ea),
                    int(row.source_instruction_ea),
                    row.source_owner.value,
                    int(row.target_ea),
                ),
            )
        ),
        conditional=(),
        abstentions=tuple(
            sorted(
                abstentions,
                key=lambda row: (
                    int(row.source_ea),
                    row.reason.value,
                    row.target_ea is None,
                    row.target_ea or 0,
                ),
            )
        ),
    )


def _conditional_port_for_choice(
    choice: PreoptConditionalStateChoice,
    *,
    state_handler_eas: Mapping[int, Collection[int]],
    state_payload_handler_eas: Mapping[int, Collection[int]] | None,
    imported_block_ranges: Mapping[int, tuple[int, int]],
    live_native_eas: Collection[int],
) -> tuple[
    PreoptConditionalBoundaryPort | None,
    PreoptBoundaryPortAbstention | None,
]:
    taken_state = int(choice.taken_state) & _MASK32
    fallthrough_state = int(choice.fallthrough_state) & _MASK32
    taken_target, taken_error = _handler_target(
        state_handler_eas,
        taken_state,
        state_payload_handler_eas=state_payload_handler_eas,
    )
    fallthrough_target, fallthrough_error = _handler_target(
        state_handler_eas,
        fallthrough_state,
        state_payload_handler_eas=state_payload_handler_eas,
    )
    target_error = taken_error or fallthrough_error
    if target_error is not None:
        return None, PreoptBoundaryPortAbstention(
            int(choice.predicate_ea),
            target_error,
        )
    assert taken_target is not None
    assert fallthrough_target is not None
    source_owner = classify_preopt_boundary_endpoint_owner(
        int(choice.predicate_ea),
        block_ea=int(choice.predicate_block_ea),
        imported_block_ranges=imported_block_ranges,
        live_native_eas=live_native_eas,
        preferred_owner=choice.source_owner,
    )
    taken_owner = classify_preopt_boundary_endpoint_owner(
        taken_target,
        block_ea=taken_target,
        imported_block_ranges=imported_block_ranges,
        live_native_eas=live_native_eas,
    )
    fallthrough_owner = classify_preopt_boundary_endpoint_owner(
        fallthrough_target,
        block_ea=fallthrough_target,
        imported_block_ranges=imported_block_ranges,
        live_native_eas=live_native_eas,
    )
    if source_owner is None:
        return None, PreoptBoundaryPortAbstention(
            int(choice.predicate_ea),
            PreoptBoundaryPortAbstentionReason.MISSING_PREDICATE_SOURCE,
        )
    missing_target = next(
        (
            target_ea
            for target_ea, owner in (
                (taken_target, taken_owner),
                (fallthrough_target, fallthrough_owner),
            )
            if owner is None
        ),
        None,
    )
    if missing_target is not None:
        return None, PreoptBoundaryPortAbstention(
            int(choice.predicate_ea),
            PreoptBoundaryPortAbstentionReason.MISSING_TARGET_OWNER,
            int(missing_target),
        )
    assert taken_owner is not None
    assert fallthrough_owner is not None
    return (
        PreoptConditionalBoundaryPort(
            source_block_ea=int(choice.predicate_block_ea),
            predicate_ea=int(choice.predicate_ea),
            taken_target_ea=taken_target,
            fallthrough_target_ea=fallthrough_target,
            state_register=int(choice.state_register),
            taken_state=taken_state,
            fallthrough_state=fallthrough_state,
            source_owner=source_owner,
            taken_target_owner=taken_owner,
            fallthrough_target_owner=fallthrough_owner,
            resolver_kind=str(choice.resolver_kind),
            logical_source_anchor_ea=choice.logical_source_anchor_ea,
            predicate_ida_stkoff=choice.predicate_ida_stkoff,
            predicate_size=choice.predicate_size,
            condition_code=choice.condition_code,
        ),
        None,
    )


def plan_preopt_conditional_state_choice_boundary_ports(
    choices: Sequence[PreoptConditionalStateChoice],
    *,
    state_handler_eas: Mapping[int, Collection[int]],
    state_payload_handler_eas: Mapping[int, Collection[int]] | None = None,
    imported_block_ranges: Mapping[int, tuple[int, int]],
    live_native_eas: Collection[int],
) -> PreoptBoundaryPortPlan:
    """Map exact conditional state choices to uniquely owned handlers."""
    choices_by_source: dict[tuple[int, int], set[PreoptConditionalStateChoice]] = {}
    for choice in choices:
        choices_by_source.setdefault(
            (int(choice.predicate_block_ea), int(choice.predicate_ea)),
            set(),
        ).add(choice)

    conditional: set[PreoptConditionalBoundaryPort] = set()
    abstentions: set[PreoptBoundaryPortAbstention] = set()
    for (_source_block_ea, predicate_ea), candidates in sorted(
        choices_by_source.items()
    ):
        if len(candidates) != 1:
            abstentions.add(
                PreoptBoundaryPortAbstention(
                    predicate_ea,
                    PreoptBoundaryPortAbstentionReason.CONFLICTING_SOURCE,
                )
            )
            continue
        port, abstention = _conditional_port_for_choice(
            next(iter(candidates)),
            state_handler_eas=state_handler_eas,
            state_payload_handler_eas=state_payload_handler_eas,
            imported_block_ranges=imported_block_ranges,
            live_native_eas=live_native_eas,
        )
        if port is not None:
            conditional.add(port)
        if abstention is not None:
            abstentions.add(abstention)
    return PreoptBoundaryPortPlan(
        direct=(),
        conditional=tuple(
            sorted(
                conditional,
                key=lambda row: (
                    int(row.source_block_ea),
                    int(row.predicate_ea),
                    int(row.taken_target_ea),
                    int(row.fallthrough_target_ea),
                ),
            )
        ),
        abstentions=tuple(
            sorted(
                abstentions,
                key=lambda row: (
                    int(row.source_ea),
                    row.reason.value,
                    row.target_ea is None,
                    row.target_ea or 0,
                ),
            )
        ),
    )


def plan_preopt_state_transition_boundary_ports(
    cuts: Sequence[PreoptUnresolvedStateCut],
    *,
    blocks_by_ea: Mapping[int, PreoptPortBlockFact],
    state_handler_eas: Mapping[int, Collection[int]],
    state_payload_handler_eas: Mapping[int, Collection[int]] | None = None,
    conditional_choices: Sequence[PreoptConditionalStateChoice] = (),
    imported_block_ranges: Mapping[int, tuple[int, int]],
    live_native_eas: Collection[int],
) -> PreoptBoundaryPortPlan:
    """Resolve every relevant cut from exact PREOPT state evidence or abstain."""
    normalized_cuts = tuple(
        sorted(
            set(cuts),
            key=lambda row: (
                int(row.tail_ea),
                int(row.source_block_ea),
                int(row.state_register),
            ),
        )
    )
    choices_by_cut: dict[tuple[int, int], set[PreoptConditionalStateChoice]] = {}
    for choice in conditional_choices:
        choices_by_cut.setdefault(
            (int(choice.consumer_tail_ea), int(choice.state_register)),
            set(),
        ).add(choice)

    definitions_by_register = {
        int(cut.state_register): reaching_register_definitions(
            blocks_by_ea,
            int(cut.state_register),
        )
        for cut in normalized_cuts
    }
    constants_by_register = {
        register: _constant_definitions(blocks_by_ea, register)
        for register in definitions_by_register
    }
    direct_candidates: set[PreoptDirectBoundaryPort] = set()
    conditional_candidates: set[PreoptConditionalBoundaryPort] = set()
    abstentions: set[PreoptBoundaryPortAbstention] = set()

    for cut in normalized_cuts:
        cut_key = (int(cut.tail_ea), int(cut.state_register))
        choices = choices_by_cut.get(cut_key, set())
        if len(choices) > 1:
            abstentions.add(
                PreoptBoundaryPortAbstention(
                    int(cut.tail_ea),
                    PreoptBoundaryPortAbstentionReason.CONFLICTING_SOURCE,
                )
            )
            continue
        if choices:
            port, abstention = _conditional_port_for_choice(
                next(iter(choices)),
                state_handler_eas=state_handler_eas,
                state_payload_handler_eas=state_payload_handler_eas,
                imported_block_ranges=imported_block_ranges,
                live_native_eas=live_native_eas,
            )
            if port is not None:
                conditional_candidates.add(port)
            if abstention is not None:
                abstentions.add(abstention)
            continue

        block_ea = _preopt_cut_block_ea(cut, blocks_by_ea)
        if block_ea is None:
            abstentions.add(
                PreoptBoundaryPortAbstention(
                    int(cut.tail_ea),
                    PreoptBoundaryPortAbstentionReason.UNRESOLVED_STATE_DEFINITION,
                )
            )
            continue
        definitions = definitions_by_register[int(cut.state_register)][1].get(
            block_ea,
            frozenset(),
        )
        if not definitions or any(int(definition) < 0 for definition in definitions):
            abstentions.add(
                PreoptBoundaryPortAbstention(
                    int(cut.tail_ea),
                    PreoptBoundaryPortAbstentionReason.UNRESOLVED_STATE_DEFINITION,
                )
            )
            continue
        states_by_write_ea, blocks_by_write_ea = constants_by_register[
            int(cut.state_register)
        ]
        cut_ports: list[PreoptDirectBoundaryPort] = []
        cut_abstentions: list[PreoptBoundaryPortAbstention] = []
        for definition_ea in sorted(definitions):
            port, abstention = _direct_port_for_definition(
                definition_ea=int(definition_ea),
                state_register=int(cut.state_register),
                states_by_write_ea=states_by_write_ea,
                blocks_by_write_ea=blocks_by_write_ea,
                state_handler_eas=state_handler_eas,
                state_payload_handler_eas=state_payload_handler_eas,
                imported_block_ranges=imported_block_ranges,
                live_native_eas=live_native_eas,
            )
            if port is not None:
                cut_ports.append(port)
            if abstention is not None:
                cut_abstentions.append(abstention)
        if cut_abstentions:
            abstentions.update(cut_abstentions)
            continue
        direct_candidates.update(cut_ports)

    direct_by_source: dict[tuple[int, int], set[PreoptDirectBoundaryPort]] = {}
    for port in direct_candidates:
        direct_by_source.setdefault(
            (int(port.source_block_ea), int(port.source_instruction_ea)),
            set(),
        ).add(port)
    direct: list[PreoptDirectBoundaryPort] = []
    for (_source_block_ea, source_ea), candidates in sorted(direct_by_source.items()):
        if len(candidates) == 1:
            direct.append(next(iter(candidates)))
        else:
            abstentions.add(
                PreoptBoundaryPortAbstention(
                    source_ea,
                    PreoptBoundaryPortAbstentionReason.CONFLICTING_SOURCE,
                )
            )

    return PreoptBoundaryPortPlan(
        direct=tuple(
            sorted(
                direct,
                key=lambda row: (
                    int(row.source_block_ea),
                    int(row.source_instruction_ea),
                    int(row.target_ea),
                ),
            )
        ),
        conditional=tuple(
            sorted(
                conditional_candidates,
                key=lambda row: (
                    int(row.source_block_ea),
                    int(row.predicate_ea),
                    int(row.taken_target_ea),
                    int(row.fallthrough_target_ea),
                ),
            )
        ),
        abstentions=tuple(
            sorted(
                abstentions,
                key=lambda row: (
                    int(row.source_ea),
                    row.reason.value,
                    row.target_ea is None,
                    row.target_ea or 0,
                ),
            )
        ),
    )


__all__ = [
    "PreoptConditionalStateChoice",
    "PreoptConditionalTopologyFact",
    "PreoptUnresolvedStateCut",
    "extend_semantic_seed_eas_with_terminal_targets",
    "merge_exact_state_payload_handler_eas",
    "preopt_entry_bridge_source_fact",
    "plan_preopt_literal_state_write_boundary_ports",
    "plan_preopt_owned_literal_state_write_boundary_ports",
    "plan_preopt_conditional_state_choice_boundary_ports",
    "plan_preopt_state_transition_boundary_ports",
    "prove_preopt_pruned_conditional_fixed_state_sources",
    "recognize_preopt_conditional_state_choices",
    "recognize_preopt_pruned_conditional_state_choices",
    "recognize_preopt_stack_carried_state_choices",
]
