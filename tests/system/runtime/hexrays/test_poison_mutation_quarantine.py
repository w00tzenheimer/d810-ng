"""Runtime contracts for mutation abstention after a poisoned MBA generation."""

from __future__ import annotations

from types import SimpleNamespace

import ida_hexrays
import pytest

from d810.analyses.control_flow.native_preanalysis_session import (
    GeneratedRestartConsumer,
    NativeMutationBoundary,
)
from d810.core.stats import OptimizationStatistics
from d810.hexrays.hooks.ctree_hooks import (
    CtreeOptimizerManager,
    CtreeOptimizationRule,
)
from d810.hexrays.hooks.hexrays_hooks import HexraysDecompilationHook
from d810.hexrays.hooks.optblock_adapter import BlockOptimizerManager
from d810.hexrays.hooks.optinsn_adapter import InstructionOptimizerManager
from d810.manager.decompilation_lifecycle import DecompilationLifecycleCoordinator
from tests.native_preanalysis import make_native_key


FUNCTION_EA = 0x40A560


class _CountingLifecycle:
    def __init__(self, *, quarantined: bool = True) -> None:
        self.quarantined = quarantined
        self.generation = 3
        self.observations: list[tuple[int, int, NativeMutationBoundary]] = []

    def observe_native_mutation_quarantine(
        self,
        *,
        function_ea: int,
        maturity: int,
        boundary: NativeMutationBoundary,
    ) -> bool:
        self.observations.append((int(function_ea), int(maturity), boundary))
        return self.quarantined


def test_instruction_callback_abstains_before_optimizer_and_nested_visitor() -> None:
    lifecycle = _CountingLifecycle()
    counts = {"log": 0, "optimizer": 0, "visitor": 0}
    manager = object.__new__(InstructionOptimizerManager)
    manager._decompilation_lifecycle = lifecycle
    manager.log_info_on_input = lambda *_args: counts.__setitem__(
        "log", counts["log"] + 1
    )
    manager.optimize = lambda *_args: counts.__setitem__(
        "optimizer", counts["optimizer"] + 1
    )
    manager.instruction_visitor = SimpleNamespace(
        __call__=lambda *_args: counts.__setitem__(
            "visitor", counts["visitor"] + 1
        )
    )
    mba = SimpleNamespace(entry_ea=FUNCTION_EA, maturity=ida_hexrays.MMAT_LOCOPT)
    block = SimpleNamespace(mba=mba)
    instruction = SimpleNamespace(ea=FUNCTION_EA + 1)

    assert InstructionOptimizerManager.func(manager, block, instruction) is False
    assert counts == {"log": 0, "optimizer": 0, "visitor": 0}
    assert lifecycle.observations == [
        (FUNCTION_EA, ida_hexrays.MMAT_LOCOPT, NativeMutationBoundary.OPTINSN)
    ]


def test_block_callback_abstains_before_pass_pipeline_and_goto_sync(monkeypatch) -> None:
    lifecycle = _CountingLifecycle()
    counts = {"func": 0, "pipeline": 0, "sync": 0}
    manager = object.__new__(BlockOptimizerManager)
    manager._decompilation_lifecycle = lifecycle
    manager._func = lambda *_args: counts.__setitem__("func", counts["func"] + 1)
    manager._run_pass_pipeline_once = lambda *_args, **_kwargs: counts.__setitem__(
        "pipeline", counts["pipeline"] + 1
    )
    monkeypatch.setattr(
        "d810.hexrays.hooks.optblock_adapter.synchronize_explicit_goto_flag",
        lambda _block: counts.__setitem__("sync", counts["sync"] + 1),
    )
    mba = SimpleNamespace(entry_ea=FUNCTION_EA, maturity=ida_hexrays.MMAT_LOCOPT)
    block = SimpleNamespace(mba=mba)

    assert BlockOptimizerManager.func(manager, block) == 0
    assert counts == {"func": 0, "pipeline": 0, "sync": 0}
    assert lifecycle.observations == [
        (FUNCTION_EA, ida_hexrays.MMAT_LOCOPT, NativeMutationBoundary.OPTBLOCK)
    ]


def test_ctree_callback_keeps_read_only_lifecycle_but_skips_rules() -> None:
    lifecycle = _CountingLifecycle()
    counts = {"capture": 0, "analyze": 0, "rule": 0}
    lifecycle.capture_ctree = lambda *_args, **_kwargs: counts.__setitem__(
        "capture", counts["capture"] + 1
    )
    lifecycle.analyze_current_function = lambda **_kwargs: counts.__setitem__(
        "analyze", counts["analyze"] + 1
    )

    class CountingRule(CtreeOptimizationRule):
        NAME = "counting_quarantine_rule"

        def optimize_ctree(self, _cfunc):
            counts["rule"] += 1
            return 1

    manager = CtreeOptimizerManager(
        OptimizationStatistics(),
        decompilation_lifecycle=lifecycle,
    )
    manager.add_rule(CountingRule())
    cfunc = SimpleNamespace(entry_ea=FUNCTION_EA)

    assert manager.on_maturity(cfunc, ida_hexrays.CMAT_FINAL) == 0
    assert counts == {"capture": 1, "analyze": 1, "rule": 0}
    assert lifecycle.observations == [
        (FUNCTION_EA, ida_hexrays.CMAT_FINAL, NativeMutationBoundary.CTREE)
    ]


def test_locopt_keeps_read_only_session_setup_but_skips_mutation_dispatch() -> None:
    counts = {"ensure": 0, "index": 0, "gateway": 0, "callback": 0}
    lifecycle = _CountingLifecycle()
    session = SimpleNamespace(native_preanalysis_depth=0)
    lifecycle.ensure_hexrays_session = lambda **_kwargs: (
        counts.__setitem__("ensure", counts["ensure"] + 1) or (session, False)
    )
    lifecycle.current_session = lambda _function_ea: session
    lifecycle.build_current_mba_identity_index = lambda **_kwargs: (
        counts.__setitem__("index", counts["index"] + 1) or object()
    )
    lifecycle.new_current_mba_mutation_gateway = lambda **_kwargs: (
        counts.__setitem__("gateway", counts["gateway"] + 1) or object()
    )
    hook = SimpleNamespace(
        callback=lambda *_args, **_kwargs: counts.__setitem__(
            "callback", counts["callback"] + 1
        ),
        _decompilation_lifecycle=lifecycle,
    )
    mba = SimpleNamespace(entry_ea=FUNCTION_EA, maturity=ida_hexrays.MMAT_LOCOPT)

    assert HexraysDecompilationHook.locopt(hook, mba) == 0
    assert counts == {"ensure": 1, "index": 0, "gateway": 0, "callback": 0}
    assert lifecycle.observations == [
        (FUNCTION_EA, ida_hexrays.MMAT_LOCOPT, NativeMutationBoundary.LOCOPT)
    ]


def test_locopt_checks_quarantine_before_transient_return_refinement(monkeypatch) -> None:
    calls: list[str] = []
    lifecycle = _CountingLifecycle()
    session = SimpleNamespace(native_preanalysis_depth=0)
    lifecycle.ensure_hexrays_session = lambda **_kwargs: (session, False)
    lifecycle.current_session = lambda _function_ea: session

    monkeypatch.setattr(
        HexraysDecompilationHook,
        "_refine_session_terminal_return_type",
        staticmethod(lambda *_args: calls.append("refine")),
    )
    hook = SimpleNamespace(
        callback=lambda *_args, **_kwargs: calls.append("callback"),
        _database_identity="",
        _decompilation_lifecycle=lifecycle,
    )
    mba = SimpleNamespace(entry_ea=FUNCTION_EA, maturity=ida_hexrays.MMAT_LOCOPT)

    assert HexraysDecompilationHook.locopt(hook, mba) == 0
    assert calls == []


def test_locopt_refines_only_after_quarantine_gate(monkeypatch) -> None:
    calls: list[str] = []
    lifecycle = _CountingLifecycle(quarantined=False)
    session = SimpleNamespace(native_preanalysis_depth=0)
    lifecycle.ensure_hexrays_session = lambda **_kwargs: (session, False)
    lifecycle.current_session = lambda _function_ea: session

    def observe(**kwargs):
        del kwargs
        calls.append("observe")
        return False

    lifecycle.observe_native_mutation_quarantine = observe
    monkeypatch.setattr(
        HexraysDecompilationHook,
        "_refine_session_terminal_return_type",
        staticmethod(lambda *_args: calls.append("refine")),
    )
    hook = SimpleNamespace(
        callback=lambda *_args, **_kwargs: calls.append("callback"),
        _database_identity="",
        _decompilation_lifecycle=lifecycle,
    )
    mba = SimpleNamespace(entry_ea=FUNCTION_EA, maturity=ida_hexrays.MMAT_LOCOPT)

    assert HexraysDecompilationHook.locopt(hook, mba) == 0
    assert calls == ["observe", "refine", "callback"]


def test_coordinator_deduplicates_quarantine_events_per_generation_boundary(
    monkeypatch,
) -> None:
    import d810.manager.decompilation_lifecycle as lifecycle_module

    observed: list[object] = []
    monkeypatch.setattr(lifecycle_module, "emit_diagnostic", observed.append)
    coordinator = DecompilationLifecycleCoordinator(
        preanalysis_runtime=None,
        analysis_runtime=None,
        execution_scope_service=None,
        native_preanalysis_key_provider=lambda _function_ea: make_native_key(),
    )
    session, _created = coordinator.ensure_hexrays_session(
        function_ea=FUNCTION_EA,
        database_identity="poison-quarantine-idb",
    )
    assert session.native_preanalysis.request_poisoned_generation_restart(
        reason="poisoned MBA"
    )
    assert coordinator.consume_generated_restart(
        FUNCTION_EA,
        consumer=GeneratedRestartConsumer.MANAGER,
    ) is not None

    assert coordinator.observe_native_mutation_quarantine(
        function_ea=FUNCTION_EA,
        maturity=ida_hexrays.MMAT_LOCOPT,
        boundary=NativeMutationBoundary.OPTINSN,
    )
    assert coordinator.observe_native_mutation_quarantine(
        function_ea=FUNCTION_EA,
        maturity=ida_hexrays.MMAT_LOCOPT,
        boundary=NativeMutationBoundary.OPTINSN,
    )
    session.current_mba_generation = 2
    assert coordinator.observe_native_mutation_quarantine(
        function_ea=FUNCTION_EA,
        maturity=ida_hexrays.MMAT_LOCOPT,
        boundary=NativeMutationBoundary.OPTINSN,
    )

    quarantine_events = [
        event
        for event in observed
        if getattr(event, "event_kind", "") == "native_mutation_quarantined"
    ]
    assert len(quarantine_events) == 2


def test_adapter_quarantine_events_use_real_coordinator_deduplication(
    monkeypatch,
) -> None:
    import d810.manager.decompilation_lifecycle as lifecycle_module

    observed: list[object] = []
    monkeypatch.setattr(lifecycle_module, "emit_diagnostic", observed.append)
    coordinator = DecompilationLifecycleCoordinator(
        preanalysis_runtime=None,
        analysis_runtime=None,
        execution_scope_service=None,
        native_preanalysis_key_provider=lambda _function_ea: make_native_key(),
    )
    session, _created = coordinator.ensure_hexrays_session(
        function_ea=FUNCTION_EA,
        database_identity="poison-adapter-idb",
    )
    assert session.native_preanalysis.request_poisoned_generation_restart(
        reason="poisoned MBA"
    )
    assert coordinator.consume_generated_restart(
        FUNCTION_EA,
        consumer=GeneratedRestartConsumer.MANAGER,
    ) is not None

    mba = SimpleNamespace(entry_ea=FUNCTION_EA, maturity=ida_hexrays.MMAT_LOCOPT)
    block = SimpleNamespace(mba=mba)
    instruction = SimpleNamespace(ea=FUNCTION_EA + 1)

    instruction_manager = object.__new__(InstructionOptimizerManager)
    instruction_manager._decompilation_lifecycle = coordinator
    assert InstructionOptimizerManager.func(instruction_manager, block, instruction) is False
    assert InstructionOptimizerManager.func(instruction_manager, block, instruction) is False

    mba.maturity = ida_hexrays.MMAT_CALLS
    assert InstructionOptimizerManager.func(instruction_manager, block, instruction) is False

    coordinator.begin_current_mba_generation(function_ea=FUNCTION_EA)
    mba.maturity = ida_hexrays.MMAT_LOCOPT
    assert InstructionOptimizerManager.func(instruction_manager, block, instruction) is False

    block_manager = object.__new__(BlockOptimizerManager)
    block_manager._decompilation_lifecycle = coordinator
    assert BlockOptimizerManager.func(block_manager, block) == 0
    assert BlockOptimizerManager.func(block_manager, block) == 0

    ctree_manager = CtreeOptimizerManager(
        OptimizationStatistics(),
        decompilation_lifecycle=coordinator,
    )
    cfunc = SimpleNamespace(entry_ea=FUNCTION_EA)
    assert ctree_manager.on_maturity(cfunc, ida_hexrays.CMAT_FINAL) == 0
    assert ctree_manager.on_maturity(cfunc, ida_hexrays.CMAT_FINAL) == 0
    assert ctree_manager.on_maturity(cfunc, ida_hexrays.CMAT_ZERO) == 0

    hook = SimpleNamespace(
        callback=lambda *_args, **_kwargs: pytest.fail(
            "quarantined LOCOPT callback must not dispatch"
        ),
        _database_identity="poison-adapter-idb",
        _decompilation_lifecycle=coordinator,
    )
    mba.maturity = ida_hexrays.MMAT_LOCOPT
    assert HexraysDecompilationHook.locopt(hook, mba) == 0
    assert HexraysDecompilationHook.locopt(hook, mba) == 0

    quarantine_events = [
        event
        for event in observed
        if getattr(event, "event_kind", "") == "native_mutation_quarantined"
    ]
    event_keys = {
        (
            int(event.payload["current_mba_generation"]),
            int(event.payload["maturity"]),
            event.payload["boundary"],
        )
        for event in quarantine_events
    }
    assert event_keys == {
        (0, ida_hexrays.MMAT_LOCOPT, NativeMutationBoundary.OPTINSN.value),
        (0, ida_hexrays.MMAT_CALLS, NativeMutationBoundary.OPTINSN.value),
        (1, ida_hexrays.MMAT_LOCOPT, NativeMutationBoundary.OPTINSN.value),
        (1, ida_hexrays.MMAT_LOCOPT, NativeMutationBoundary.OPTBLOCK.value),
        (1, ida_hexrays.CMAT_FINAL, NativeMutationBoundary.CTREE.value),
        (1, ida_hexrays.CMAT_ZERO, NativeMutationBoundary.CTREE.value),
        (1, ida_hexrays.MMAT_LOCOPT, NativeMutationBoundary.LOCOPT.value),
    }
    assert len(quarantine_events) == len(event_keys)


def test_coordinator_does_not_create_gateway_while_quarantined() -> None:
    factory_calls: list[object] = []
    coordinator = DecompilationLifecycleCoordinator(
        preanalysis_runtime=None,
        analysis_runtime=None,
        execution_scope_service=None,
        native_preanalysis_key_provider=lambda _function_ea: make_native_key(),
        mba_mutation_gateway_factory=lambda **kwargs: (
            factory_calls.append(kwargs) or object()
        ),
    )
    session, _created = coordinator.ensure_hexrays_session(
        function_ea=FUNCTION_EA,
        database_identity="poison-gateway-idb",
    )
    coordinator.bind_current_mba_identity_index(
        function_ea=FUNCTION_EA,
        index=object(),
    )
    assert session.native_preanalysis.request_poisoned_generation_restart(
        reason="poisoned MBA"
    )
    assert coordinator.consume_generated_restart(
        FUNCTION_EA,
        consumer=GeneratedRestartConsumer.MANAGER,
    ) is not None

    assert (
        coordinator.new_current_mba_mutation_gateway(
            function_ea=FUNCTION_EA,
            maturity=ida_hexrays.MMAT_LOCOPT,
        )
        is None
    )
    assert factory_calls == []
