"""Runtime regressions for detached computed-goto island delivery."""

from __future__ import annotations

from types import SimpleNamespace

import ida_hexrays
from d810.analyses.control_flow.detached_handler_island import (
    DetachedSnippetBoundaryPortOwner,
)
from d810.analyses.control_flow.native_preanalysis_session import (
    NativePreanalysisSessionState,
)
from d810.optimizers.microcode.flow.jumps import (
    materialized_computed_goto_island as island,
)
from tests.native_preanalysis import make_native_key
from tests.system.runtime.mutation_gateway import make_mutation_gateway

NATIVE_KEY = make_native_key()


class _Instruction:
    def __init__(self, ea: int) -> None:
        self.ea = ea
        self.next: _Instruction | None = None


class _Block:
    def __init__(self, start: int, instruction_eas: tuple[int, ...]) -> None:
        self.start = start
        instructions = tuple(_Instruction(ea) for ea in instruction_eas)
        for current, following in zip(instructions, instructions[1:]):
            current.next = following
        self.head = instructions[0] if instructions else None
        self.tail = instructions[-1] if instructions else None


class _MBA:
    def __init__(self, block: _Block) -> None:
        self.entry_ea = 0x1000
        self.qty = 1
        self._block = block

    def get_mblock(self, serial: int) -> _Block:
        assert serial == 0
        return self._block


class _LiveBlock:
    def __init__(self, *, instruction_backed: bool = True) -> None:
        self.head = object() if instruction_backed else None


def _resolver_state():
    session = SimpleNamespace(
        native_preanalysis=NativePreanalysisSessionState(),
        resolver_attachment=None,
        native_key=NATIVE_KEY,
    )
    return session, island.resolver_session_state(session)


def _bind_rule_state(rule, state) -> None:
    gateway_mba = SimpleNamespace(qty=0, entry_ea=0, maturity=0)
    rule.set_flow_context(
        SimpleNamespace(
            resolver_session_state=lambda: state,
            new_mba_mutation_gateway=lambda: make_mutation_gateway(gateway_mba),
        )
    )


def test_detached_planner_uses_first_surviving_instruction_as_live_target(
    monkeypatch,
) -> None:
    captured: dict[str, frozenset[int]] = {}

    def capture_planner(_transfers, **kwargs):
        captured.update(kwargs)
        return ()

    monkeypatch.setattr(island, "plan_detached_snippet_routes", capture_planner)
    monkeypatch.setattr(
        island,
        "imported_detached_snippet_target_eas",
        lambda _mba: (),
    )

    mba = _MBA(_Block(0x1020, (0x1028, 0x1030)))
    island._materialize_missing_detached_snippets(
        mba,
        (),
        mutation_gateway=make_mutation_gateway(mba),
    )

    assert captured["live_eas"] == frozenset({0x1020, 0x1028, 0x1030})
    assert captured["live_target_eas"] == frozenset({0x1020, 0x1028})


def test_detached_planner_excludes_empty_external_placeholder_target(
    monkeypatch,
) -> None:
    captured: dict[str, frozenset[int]] = {}

    def capture_planner(_transfers, **kwargs):
        captured.update(kwargs)
        return ()

    monkeypatch.setattr(island, "plan_detached_snippet_routes", capture_planner)
    monkeypatch.setattr(
        island,
        "imported_detached_snippet_target_eas",
        lambda _mba: (),
    )

    mba = _MBA(_Block(0x40CD46, ()))
    island._materialize_missing_detached_snippets(
        mba,
        (),
        mutation_gateway=make_mutation_gateway(mba),
    )

    assert captured["live_eas"] == frozenset({0x40CD46})
    assert captured["live_target_eas"] == frozenset()


def test_preopt_success_records_session_owned_union_ownership(monkeypatch) -> None:
    _session, state = _resolver_state()
    mba = object()
    monkeypatch.setattr(island, "stable_mba_identity", lambda _mba: 91)
    monkeypatch.setattr(
        island,
        "detached_snippet_template_generation",
        lambda _function_ea: 7,
    )
    state.preopt_union_imported_mbas.add((0x1000, 91, 7))

    assert island._preopt_union_owns_mba(state, 0x1000, mba)


def test_preopt_union_ownership_suppresses_late_bridge_applicators(
    monkeypatch,
) -> None:
    _session, state = _resolver_state()
    monkeypatch.setattr(island, "stable_mba_identity", lambda _mba: 91)
    monkeypatch.setattr(
        island,
        "detached_snippet_template_generation",
        lambda _function_ea: 7,
    )
    monkeypatch.setattr(island, "restore_terminal_return_carriers", lambda *_: 0)
    monkeypatch.setattr(
        island,
        "reconcile_imported_callinfo_with_live_native_calls",
        lambda _mba: 0,
    )
    monkeypatch.setattr(
        island,
        "_recover_imported_conditional_bridge_transfers",
        lambda _mba, transfers, *, state: transfers,
    )
    monkeypatch.setattr(
        island,
        "restore_detached_call_result_definitions",
        lambda *_: 0,
    )
    monkeypatch.setattr(island, "is_computed_goto_materialized", lambda _state: False)
    monkeypatch.setattr(
        island,
        "_keep_cached_detached_snippet_blocks",
        lambda *_: 0,
    )
    monkeypatch.setattr(
        island,
        "_candidate_conditional_bridge_plans",
        lambda _state: (object(),),
    )

    def reject_late_bridge(*_args, **_kwargs):
        raise AssertionError("PREOPT-owned MBAs must not receive late bridge edits")

    monkeypatch.setattr(
        island,
        "_apply_detached_snippet_terminal_routes",
        reject_late_bridge,
    )
    monkeypatch.setattr(
        island,
        "_apply_residual_state_route_bridges",
        reject_late_bridge,
    )
    monkeypatch.setattr(
        island,
        "_apply_conditional_bridge_plans",
        reject_late_bridge,
    )

    rule = island.MaterializedComputedGotoIslandRule()
    _bind_rule_state(rule, state)
    for maturity in (
        island.ida_hexrays.MMAT_LOCOPT,
        island.ida_hexrays.MMAT_CALLS,
    ):
        mba = SimpleNamespace(entry_ea=0x1000, maturity=maturity)
        state.preopt_union_imported_mbas.add((0x1000, 91, 7))
        assert rule.optimize(SimpleNamespace(mba=mba)) == 0


def test_rule_has_no_legacy_importer_configuration_surface() -> None:
    rule = island.MaterializedComputedGotoIslandRule()

    assert not hasattr(rule, "enable_legacy_locopt_calls_importer")
    assert all(
        getattr(parameter, "name", None) != "enable_legacy_locopt_calls_importer"
        for parameter in rule.CONFIG_SCHEMA
    )


def test_configure_does_not_install_adapter_owned_preopt_mutation(
    monkeypatch,
) -> None:
    unregistered: list[str] = []
    monkeypatch.setattr(
        island,
        "unregister_locopt_preanalysis_handler",
        lambda name: unregistered.append(name),
    )
    monkeypatch.setattr(
        island,
        "unregister_calls_done_preanalysis_handler",
        lambda name: unregistered.append(name),
    )
    monkeypatch.setattr(island, "register_project_reload_cleanup", lambda *_: None)

    rule = island.MaterializedComputedGotoIslandRule()
    rule.configure({})

    assert not hasattr(island, "register_locopt_preanalysis_handler")
    assert not hasattr(island, "register_calls_done_preanalysis_handler")
    assert not hasattr(island, "register_preopt_preanalysis_handler")
    assert unregistered == [
        island._CALLS_HANDLER_NAME,
        island._LOCOPT_HANDLER_NAME,
    ]


def test_applied_preopt_boundary_prevents_legacy_residual_route_overwrite(
    monkeypatch,
) -> None:
    from d810.analyses.control_flow.detached_handler_island import (
        AppliedDetachedSnippetDirectBoundaryPort,
        DetachedSnippetDirectBoundaryPort,
    )
    from d810.analyses.control_flow.materialized_indirect_transfer import (
        MaterializedIndirectTransfer,
    )

    source_write_ea = 0x40CDBA
    terminal_ea = 0x40CDD0
    target_ea = 0x40CEAB
    state = 0x255387B6
    source = SimpleNamespace(serial=3, succset=(41,), nsucc=lambda: 1)
    external_target = SimpleNamespace(serial=58)
    mba = SimpleNamespace(
        get_mblock=lambda serial: source if int(serial) == 3 else None
    )
    transfer = MaterializedIndirectTransfer(
        source_jmp_ea=source_write_ea,
        source_block_ea=0x40CDB7,
        materialized_anchor_eas=(),
        target_eas=(target_ea,),
        selector_state_var_reg=16,
        selector_state_constant=state,
        resolver_kind="residual_state_route_evidence",
    )
    port = DetachedSnippetDirectBoundaryPort(
        source_block_ea=0x40CDB7,
        source_instruction_ea=terminal_ea,
        endpoint_block_ea=terminal_ea,
        old_successor_eas=(0x40CDF8,),
        target_ea=target_ea,
        state_register=16,
        state_constant=state,
        source_owner=DetachedSnippetBoundaryPortOwner.LIVE,
        endpoint_owner=DetachedSnippetBoundaryPortOwner.LIVE,
        target_owner=DetachedSnippetBoundaryPortOwner.IMPORTED,
        delivery_mode="redirect_edge",
        resolver_kind="residual_state_route_evidence",
    )
    applied = AppliedDetachedSnippetDirectBoundaryPort(
        port=port,
        endpoint_anchor_eas=(terminal_ea,),
        target_anchor_eas=(0xF10000,),
    )

    def find_block(_mba, ea, **_kwargs):
        if int(ea) in {source_write_ea, terminal_ea}:
            return source
        if int(ea) == target_ea:
            return external_target
        return None

    monkeypatch.setattr(island, "find_unique_live_block_by_ea", find_block)
    monkeypatch.setattr(
        island,
        "find_unique_live_block_by_native_ea",
        lambda _mba, ea: external_target if int(ea) == target_ea else None,
    )
    monkeypatch.setattr(
        island,
        "imported_detached_snippet_direct_boundary_evidence",
        lambda _mba: (applied,),
    )
    monkeypatch.setattr(
        island,
        "plan_residual_state_route_bridges",
        lambda *_args, **_kwargs: (
            SimpleNamespace(
                source_block_serial=3,
                target_block_serial=58,
                source_write_ea=source_write_ea,
                state_constant=state,
                target_ea=target_ea,
            ),
        ),
    )
    monkeypatch.setattr(
        island,
        "DeferredGraphModifier",
        lambda _mba: (_ for _ in ()).throw(
            AssertionError("legacy LOCOPT route must not replace PREOPT ownership")
        ),
    )

    assert (
        island._apply_residual_state_route_bridges(
            mba,
            (transfer,),
            mutation_gateway=make_mutation_gateway(mba),
        )
        == 0
    )


def test_residual_state_route_targets_instruction_backed_native_owner(
    monkeypatch,
) -> None:
    from d810.analyses.control_flow.materialized_indirect_transfer import (
        MaterializedIndirectTransfer,
    )

    source_write_ea = 0x40CDBA
    target_ea = 0x40CEAB
    source = SimpleNamespace(serial=3, nsucc=lambda: 1)
    external_placeholder = SimpleNamespace(serial=79)
    imported_target = SimpleNamespace(serial=45)
    captured_live_blocks: dict[int, int] = {}
    transfer = MaterializedIndirectTransfer(
        source_jmp_ea=source_write_ea,
        source_block_ea=0x40CDB7,
        materialized_anchor_eas=(),
        target_eas=(target_ea,),
        selector_state_var_reg=16,
        selector_state_constant=0x255387B6,
        resolver_kind="residual_state_route_evidence",
    )

    def find_live(_mba, ea, **_kwargs):
        if int(ea) == source_write_ea:
            return source
        if int(ea) == target_ea:
            return external_placeholder
        return None

    monkeypatch.setattr(island, "find_unique_live_block_by_ea", find_live)
    monkeypatch.setattr(
        island,
        "find_unique_live_block_by_native_ea",
        lambda _mba, ea: imported_target if int(ea) == target_ea else None,
    )

    def capture_plan(_transfers, *, live_blocks_by_ea, **_kwargs):
        captured_live_blocks.update(live_blocks_by_ea)
        return ()

    monkeypatch.setattr(island, "plan_residual_state_route_bridges", capture_plan)

    mba = SimpleNamespace(qty=0, entry_ea=0, maturity=0)
    assert (
        island._apply_residual_state_route_bridges(
            mba,
            (transfer,),
            mutation_gateway=make_mutation_gateway(mba),
        )
        == 0
    )
    assert captured_live_blocks == {
        source_write_ea: 3,
        target_ea: 45,
    }


def test_live_resolver_cut_counterpart_routes_through_atomic_gateway(
    monkeypatch,
) -> None:
    source_ea = 0x40DACE
    target_ea = 0x40D370

    class _LiveBlock:
        def __init__(self, serial: int, *, tail=None, successors=()) -> None:
            self.serial = int(serial)
            self.tail = tail
            self._successors = tuple(int(value) for value in successors)

        def nsucc(self) -> int:
            return len(self._successors)

    source = _LiveBlock(
        7,
        tail=SimpleNamespace(ea=source_ea, opcode=ida_hexrays.m_ijmp),
    )
    target = _LiveBlock(9)
    mba = SimpleNamespace(entry_ea=0x40D200)
    evidence = SimpleNamespace(
        port=SimpleNamespace(
            delivery_mode="terminal_goto",
            source_instruction_ea=source_ea,
            endpoint_block_ea=0x40DABB,
            target_ea=target_ea,
        )
    )
    monkeypatch.setattr(
        island,
        "imported_detached_snippet_direct_boundary_evidence",
        lambda _mba: (evidence,),
    )
    monkeypatch.setattr(
        island,
        "find_unique_live_block_by_ea",
        lambda _mba, ea: (
            source
            if int(ea) == source_ea
            else (target if int(ea) == target_ea else None)
        ),
    )

    queued: list[tuple[int, int]] = []

    class _Modifier:
        def __init__(self, current_mba, *, mutation_gateway) -> None:
            assert current_mba is mba
            assert mutation_gateway is not None

        def queue_terminal_goto_change(
            self,
            *,
            block_serial: int,
            goto_target: int,
            **_kwargs,
        ) -> None:
            queued.append((int(block_serial), int(goto_target)))

        def apply(self, **kwargs) -> int:
            assert kwargs == {"transactional": True, "staged_atomic": True}
            return 1

    monkeypatch.setattr(island, "DeferredGraphModifier", _Modifier)

    assert (
        island._apply_live_resolver_cut_counterparts(
            mba,
            mutation_gateway=make_mutation_gateway(mba),
        )
        == 1
    )
    assert queued == [(7, 9)]
