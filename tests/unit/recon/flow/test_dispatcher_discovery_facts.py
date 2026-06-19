from d810.capabilities.dispatcher import RouterKind
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
from d810.analyses.value_flow.contract_evidence import contract_evidence_tokens


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
                router_kind=RouterKind.TABLE,
            ),
            StateDispatcherRow(
                state_const=0x20,
                target_block=2,
                dispatcher_block=2,
                compare_block=2,
                branch_kind="switch_case",
                router_kind=RouterKind.TABLE,
                row_kind="dispatcher_self_loop",
            ),
        ),
        dispatcher_entry_block=2,
        dispatcher_blocks=frozenset({2}),
        state_var_stkoff=state_var_stkoff,
        state_var_lvar_idx=None,
        router_kind=RouterKind.TABLE,
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
    assert topology.payload["dispatcher_source"] == "TABLE"
    assert contract_evidence_tokens(topology) == frozenset({"branch_targets"})

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


def test_dispatcher_topology_without_handler_targets_has_no_branch_target_token() -> None:
    dispatch_map = StateDispatcherMap(
        rows=(
            StateDispatcherRow(
                state_const=0x20,
                target_block=2,
                dispatcher_block=2,
                compare_block=2,
                branch_kind="switch_case",
                router_kind=RouterKind.TABLE,
                row_kind="dispatcher_self_loop",
            ),
        ),
        dispatcher_entry_block=2,
        dispatcher_blocks=frozenset({2}),
        state_var_stkoff=0x3C,
        state_var_lvar_idx=None,
        router_kind=RouterKind.TABLE,
    )

    observations = collect_state_dispatcher_discovery_fact_observations(
        state_dispatcher_map=dispatch_map,
        maturity="MMAT_GLBOPT1",
        phase="pre_d810",
    )
    topology = next(
        observation
        for observation in observations
        if observation.kind == STATE_DISPATCHER_TOPOLOGY_FACT_TYPE
    )

    assert topology.payload["handler_targets"] == []
    assert contract_evidence_tokens(topology) == frozenset()


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
    for observation in observations:
        if observation.kind == DISPATCHER_DISCOVERY_GAP_FACT_TYPE:
            assert contract_evidence_tokens(observation) == frozenset()


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
    assert contract_evidence_tokens(observation) == frozenset(
        {"branch_targets", "dispatcher_predicates"}
    )


def test_predecessor_dispatcher_target_without_predicate_proof_only_proves_target() -> None:
    predecessor_fact = resolve_predecessor_dispatcher_target(
        predecessor_block_serial=9,
        dispatcher_entry_serial=2,
        state_const=0x30,
        range_evidence=type(
            "_RangeEvidence",
            (),
            {
                "dispatcher": None,
                "handler_state_map": {5: 0x30},
                "handler_range_map": {},
            },
        )(),
    )
    assert predecessor_fact is not None

    observations = collect_state_dispatcher_discovery_fact_observations(
        state_dispatcher_map=_dispatch_map(),
        maturity="MMAT_GLBOPT1",
        phase="pre_d810",
        predecessor_target_facts=(predecessor_fact,),
    )
    observation = next(
        observation
        for observation in observations
        if observation.kind == PREDECESSOR_DISPATCHER_TARGET_FACT_TYPE
    )

    assert observation.payload["target_block_serial"] == 5
    assert observation.payload["branch_kind"] is None
    assert observation.payload["compare_block_serial"] is None
    assert observation.payload["condition_block_serial"] is None
    assert contract_evidence_tokens(observation) == frozenset({"branch_targets"})
