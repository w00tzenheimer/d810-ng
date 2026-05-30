from d810.analyses.control_flow.dispatcher_kind import DispatcherType
from d810.analyses.control_flow.dispatcher_discovery_facts import (
    DISPATCHER_ARTIFACT_STATE_FACT_TYPE,
    DISPATCHER_DISCOVERY_GAP_FACT_TYPE,
    DISPATCHER_INITIAL_STATE_FACT_TYPE,
    PREDECESSOR_DISPATCHER_TARGET_FACT_TYPE,
    STATE_DISPATCHER_TOPOLOGY_FACT_TYPE,
    STATE_VARIABLE_IDENTITY_FACT_TYPE,
    collect_state_dispatcher_discovery_fact_observations,
)
from d810.analyses.control_flow.dispatcher_resolution import StateDispatcherMap, StateDispatcherRow
from d810.analyses.control_flow.predecessor_dispatcher_target import (
    resolve_predecessor_dispatcher_target,
)


def _dispatch_map(
    *,
    initial_state: int | None = 0x10,
    state_var_stkoff: int | None = 0x3C,
) -> StateDispatcherMap:
    return StateDispatcherMap(
        rows=(
            StateDispatcherRow(
                state_const=0x10,
                target_block=5,
                dispatcher_block=2,
                compare_block=2,
                branch_kind="switch_case",
                source=DispatcherType.SWITCH_TABLE,
            ),
            StateDispatcherRow(
                state_const=0x20,
                target_block=2,
                dispatcher_block=2,
                compare_block=2,
                branch_kind="switch_case",
                source=DispatcherType.SWITCH_TABLE,
                row_kind="dispatcher_self_loop",
            ),
        ),
        dispatcher_entry_block=2,
        dispatcher_blocks=frozenset({2}),
        state_var_stkoff=state_var_stkoff,
        state_var_lvar_idx=None,
        source=DispatcherType.SWITCH_TABLE,
        initial_state=initial_state,
    )


def test_collects_generic_state_dispatcher_discovery_observations() -> None:
    observations = collect_state_dispatcher_discovery_fact_observations(
        state_dispatcher_map=_dispatch_map(),
        maturity="MMAT_GLBOPT1",
        phase="pre_d810",
        profile_name="profile_fixture",
        predecessor_serials=(9, 7),
        pre_header_serial=1,
    )

    by_kind = {observation.kind: observation for observation in observations}

    topology = by_kind[STATE_DISPATCHER_TOPOLOGY_FACT_TYPE]
    assert topology.semantic_key == "state_dispatcher:profile_fixture:entry=2"
    assert topology.payload["dispatcher_blocks"] == [2]
    assert topology.payload["predecessor_serials"] == [7, 9]
    assert topology.payload["handler_targets"] == [5]
    assert topology.payload["dispatcher_source"] == "SWITCH_TABLE"

    state_var = by_kind[STATE_VARIABLE_IDENTITY_FACT_TYPE]
    assert state_var.payload["storage_kind"] == "stack_slot"
    assert state_var.payload["state_var_stkoff"] == 0x3C

    initial = by_kind[DISPATCHER_INITIAL_STATE_FACT_TYPE]
    assert initial.source_block == 1
    assert initial.payload["initial_state"] == 0x10
    assert initial.payload["target_block_serial"] == 5

    artifact = by_kind[DISPATCHER_ARTIFACT_STATE_FACT_TYPE]
    assert artifact.payload["classification"] == "dispatcher_self_loop"
    assert artifact.payload["state_const"] == 0x20
    assert artifact.payload["target_block_serial"] == 2


def test_collects_dispatcher_discovery_gap_observations() -> None:
    observations = collect_state_dispatcher_discovery_fact_observations(
        state_dispatcher_map=_dispatch_map(
            initial_state=None,
            state_var_stkoff=None,
        ),
        maturity="MMAT_CALLS",
        phase="pre_d810",
        profile_name="profile_fixture",
    )

    gap_reasons = {
        observation.payload["reason"]
        for observation in observations
        if observation.kind == DISPATCHER_DISCOVERY_GAP_FACT_TYPE
    }

    assert gap_reasons == {
        "initial_state_missing",
        "state_variable_identity_missing",
    }


def test_mirrors_predecessor_dispatcher_target_as_observation() -> None:
    dispatch_map = _dispatch_map()
    predecessor_fact = resolve_predecessor_dispatcher_target(
        predecessor_block_serial=9,
        dispatcher_entry_serial=2,
        state_const=0x10,
        state_dispatcher_map=dispatch_map,
    )
    assert predecessor_fact is not None

    observations = collect_state_dispatcher_discovery_fact_observations(
        state_dispatcher_map=dispatch_map,
        maturity="MMAT_GLBOPT1",
        phase="pre_d810",
        profile_name="profile_fixture",
        predecessor_target_facts=(predecessor_fact,),
    )

    predecessor_observations = [
        observation
        for observation in observations
        if observation.kind == PREDECESSOR_DISPATCHER_TARGET_FACT_TYPE
    ]

    assert len(predecessor_observations) == 1
    observation = predecessor_observations[0]
    assert observation.source_block == 9
    assert observation.payload["target_block_serial"] == 5
    assert observation.evidence == ("state_dispatcher_map_exact_row",)
