import ast
import inspect
from types import SimpleNamespace

from d810.hexrays.preanalysis import flowchart_preanalysis
from d810.hexrays.preanalysis import indirect_jump_labels as labels
from d810.hexrays.preanalysis.indirect_jump_discovery import (
    DiscoveredIndirectJumpTable,
)
from d810.hexrays.preanalysis.indirect_jump_labels import (
    materialized_indirect_transfers,
    merge_materialized_indirect_transfers,
    merge_terminal_return_carrier_requests,
    plan_indirect_label_materialization,
    terminal_return_carrier_requests,
)
from d810.analyses.control_flow.materialized_indirect_transfer import (
    MaterializedIndirectTransfer,
    TerminalReturnCarrierRequest,
    mutation_authoritative_materialized_transfers,
)
from d810.analyses.control_flow.native_preanalysis_session import (
    NativePreanalysisSessionState,
)
from d810.optimizers.microcode.flow.jumps.resolver_session_state import (
    resolver_session_state,
)
from tests.native_preanalysis import make_native_key


NATIVE_KEY = make_native_key()


def _resolver_state() -> object:
    return resolver_session_state(
        SimpleNamespace(
            native_key=NATIVE_KEY,
            native_preanalysis=NativePreanalysisSessionState(),
            resolver_attachment=None,
        )
    )


def test_indirect_label_materialization_plan_uses_configured_bounds() -> None:
    plan = plan_indirect_label_materialization(
        function_ea=0x1800175C0,
        table_address=0x180019F10,
        target_eas=(0x1800178E3, 0x18001761A, 0x1800178E3),
        configured_label_start=0x180017600,
        configured_label_end=0x180017D2F,
        discovered_function_end=0x180017610,
    )

    assert plan is not None
    assert plan.label_start == 0x180017600
    assert plan.label_end == 0x180017D2F
    assert plan.target_eas == (0x18001761A, 0x1800178E3)


def test_indirect_label_materialization_plan_uses_next_function_boundary() -> None:
    plan = plan_indirect_label_materialization(
        function_ea=0x1800175C0,
        table_address=0x180019F10,
        target_eas=(0x18001761A, 0x180017CE5),
        discovered_function_end=0x180017610,
        discovered_next_function_start=0x180017D30,
    )

    assert plan is not None
    assert plan.label_start == 0x18001761A
    assert plan.label_end == 0x180017D30


def test_indirect_label_materialization_plan_rejects_unbounded_range() -> None:
    assert (
        plan_indirect_label_materialization(
            function_ea=0x1800175C0,
            table_address=0x180019F10,
            target_eas=(0x18001761A, 0x180017CE5),
            discovered_function_end=0x180017610,
        )
        is None
    )


def test_direct_writer_is_reduced_to_a_native_patch_plan_request() -> None:
    """The preanalysis writer may discover, but it may not mutate IDA.

    This is intentionally scoped to the known migration target.  The Task 4
    inventory still owns classification of other IDA maintenance helpers.
    """
    source = inspect.getsource(labels.materialize_indirect_label_targets)
    tree = ast.parse(source)
    calls = {
        node.func.attr
        for node in ast.walk(tree)
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)
    }

    assert "NativePatchPlanRequest" in source
    assert not calls.intersection(
        {
            "del_items",
            "create_insn",
            "reanalyze_function",
            "auto_wait",
            "mark_cfunc_dirty",
            "add_cref",
            "append_func_tail",
            "set_switch_info",
        }
    )


def test_materialized_transfer_evidence_is_session_scoped() -> None:
    transfer = MaterializedIndirectTransfer(
        source_jmp_ea=0x401000,
        source_block_ea=0x400FF0,
        materialized_anchor_eas=(0x400FFC,),
        target_eas=(0x402000,),
    )
    session = SimpleNamespace(
        native_key=NATIVE_KEY,
        native_preanalysis=NativePreanalysisSessionState(),
        resolver_attachment=None,
    )
    state = resolver_session_state(session)
    other_state = _resolver_state()

    assert merge_materialized_indirect_transfers(state, (transfer,))

    assert materialized_indirect_transfers(state) == (transfer,)
    assert materialized_indirect_transfers(other_state) == ()

    second = MaterializedIndirectTransfer(
        source_jmp_ea=0x401010,
        source_block_ea=0x401000,
        materialized_anchor_eas=(0x401010,),
        target_eas=(0x402100,),
        resolver_kind="residual_state_route_evidence",
    )
    assert merge_materialized_indirect_transfers(state, (second,))
    assert materialized_indirect_transfers(state) == (transfer, second)

    labels.reset_indirect_materialization()
    assert materialized_indirect_transfers(state) == (transfer, second)


def test_session_evidence_retains_conflicting_conditional_bridge_generations() -> None:
    predicate_ea = 0x401020
    stale = MaterializedIndirectTransfer(
        source_jmp_ea=predicate_ea,
        source_block_ea=0x401000,
        materialized_anchor_eas=(predicate_ea,),
        target_eas=(0x402000, 0x403000),
        true_target_ea=0x402000,
        false_target_ea=0x403000,
        resolver_kind="conditional_handler_bridge",
    )
    unrelated = MaterializedIndirectTransfer(
        source_jmp_ea=0x401080,
        source_block_ea=0x401070,
        materialized_anchor_eas=(),
        target_eas=(0x404000,),
        resolver_kind="residual_state_route_evidence",
    )
    refreshed = MaterializedIndirectTransfer(
        source_jmp_ea=predicate_ea,
        source_block_ea=0x401000,
        materialized_anchor_eas=(predicate_ea,),
        target_eas=(0x405000, 0x406000),
        true_target_ea=0x405000,
        false_target_ea=0x406000,
        resolver_kind="conditional_handler_bridge",
    )
    state = _resolver_state()

    assert merge_materialized_indirect_transfers(state, (stale, unrelated))
    assert merge_materialized_indirect_transfers(state, (refreshed,))

    assert materialized_indirect_transfers(state) == (
        stale,
        refreshed,
        unrelated,
    )
    assert (
        mutation_authoritative_materialized_transfers(
            materialized_indirect_transfers(state)
        )
        == ()
    )


def test_terminal_return_carrier_evidence_is_session_scoped() -> None:
    request = TerminalReturnCarrierRequest(
        source_handler_ea=0x40C7E5,
        terminal_target_ea=0x40C898,
        state_var_reg=20,
        state_constant=0x19A7218A,
    )
    session = SimpleNamespace(
        native_key=NATIVE_KEY,
        native_preanalysis=NativePreanalysisSessionState(),
        resolver_attachment=None,
    )
    state = resolver_session_state(session)
    other_state = _resolver_state()

    assert merge_terminal_return_carrier_requests(state, (request,))

    assert terminal_return_carrier_requests(state) == (request,)
    assert terminal_return_carrier_requests(other_state) == ()
    labels.reset_indirect_materialization()
    assert terminal_return_carrier_requests(state) == (request,)


def test_releasing_live_bindings_does_not_create_an_address_keyed_clear_path() -> None:
    transfer = MaterializedIndirectTransfer(
        source_jmp_ea=0x401080,
        source_block_ea=0x401070,
        materialized_anchor_eas=(0x401078,),
        target_eas=(0x402000,),
    )
    request = TerminalReturnCarrierRequest(
        source_handler_ea=0x401100,
        terminal_target_ea=0x402100,
        state_var_reg=20,
        state_constant=0x12345678,
    )
    state = _resolver_state()
    labels.mark_indirect_dispatcher(state)
    merge_materialized_indirect_transfers(state, (transfer,))
    merge_terminal_return_carrier_requests(state, (request,))

    state.release_live_bindings()

    assert labels.is_materialized_indirect_dispatcher(state)
    assert materialized_indirect_transfers(state) == (transfer,)
    assert terminal_return_carrier_requests(state) == (request,)


def test_current_function_materialization_uses_discovered_state_slot(
    monkeypatch,
) -> None:
    discovered = DiscoveredIndirectJumpTable(
        function_ea=0x180013BD0,
        dispatch_jump_ea=0x180013DB8,
        table_address=0x18001DF00,
        table_count=37,
        target_eas=(0x180013C2A, 0x180013C80),
        label_start=0x180013C2A,
        label_end=0x18001433F,
        source="operand_decode",
        state_var_stkoff=0x30,
        initial_state=0x22,
        stack_table_offset=0x28,
    )
    calls: list[dict[str, object]] = []

    def materialize(**kwargs):
        calls.append(kwargs)
        return labels.IndirectLabelMaterializationResult(
            function_ea=int(kwargs["function_ea"]),
            table_address=int(kwargs["table_address"]),
            table_count=int(kwargs["table_count"]),
            label_start=int(kwargs["label_start"]),
            label_end=int(kwargs["label_end"]),
            target_count=2,
            materialized_target_count=2,
            dispatch_jump_ea=int(kwargs["dispatch_jump_ea"]),
            jump_xref_count=2,
            switch_info_installed=False,
            appended_tail=False,
            success=True,
            reason="materialized",
            resolved_state_xref_count=2,
        )

    monkeypatch.setattr(
        labels,
        "discover_indirect_jump_table",
        lambda function_ea: (
            discovered if function_ea == discovered.function_ea else None
        ),
    )
    monkeypatch.setattr(labels, "materialize_indirect_label_targets", materialize)

    result = labels.materialize_indirect_label_targets_for_function(
        discovered.function_ea
    )

    assert result is not None
    assert calls
    assert calls[0]["state_var_stkoff"] == 0x30
    assert calls[0]["install_switch_info"] is False


def test_indirect_materialization_subscribes_to_flowchart_event(
    monkeypatch,
) -> None:
    monkeypatch.setattr(
        flowchart_preanalysis,
        "_FLOWCHART_PREANALYSIS_HANDLERS",
        {},
    )
    result = labels.IndirectLabelMaterializationResult(
        function_ea=0x180013BD0,
        table_address=0x18001DF00,
        table_count=37,
        label_start=0x180013C2A,
        label_end=0x18001433F,
        target_count=2,
        materialized_target_count=2,
        dispatch_jump_ea=0x180013DB8,
        jump_xref_count=2,
        switch_info_installed=False,
        appended_tail=False,
        success=True,
        reason="materialized",
        resolved_state_xref_count=2,
    )
    calls: list[int] = []
    session = SimpleNamespace(
        native_key=NATIVE_KEY,
        native_preanalysis=NativePreanalysisSessionState(),
        resolver_attachment=None,
    )
    resolver_session_state(session)

    def materialize(function_ea: int, *, state: object):
        calls.append(function_ea)
        return result

    monkeypatch.setattr(
        labels, "run_indirect_materialization_for_function", materialize
    )

    labels.register_indirect_materialization({})
    decision: dict[str, object] = {
        "request_redo": False,
        "session": session,
    }
    flowchart_preanalysis.run_flowchart_preanalysis_handlers(
        function_ea=0x180013BD0,
        mba=object(),
        decision=decision,
    )

    assert calls == [0x180013BD0]
    assert decision["request_redo"] is True
    assert decision["reason"] == "indirect_jump_label_materialized"
    assert decision["details"] == {
        "function_ea": 0x180013BD0,
        "target_count": 2,
        "materialized_target_count": 2,
    }

    labels.reset_indirect_materialization()
    decision = {"request_redo": False}
    flowchart_preanalysis.run_flowchart_preanalysis_handlers(
        function_ea=0x180013BD0,
        mba=object(),
        decision=decision,
    )
    assert decision == {"request_redo": False}
