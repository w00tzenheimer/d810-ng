from __future__ import annotations

import ast
import importlib.util
import sys
from pathlib import Path
from types import ModuleType, SimpleNamespace

from d810.manager.workbench_models import (
    OutcomeStatus,
    WorkbenchCommandRequest,
    WorkbenchCommandResult,
)
from d810.ui import workbench_commands as command_module


def test_workbench_commands_module_exists() -> None:
    assert importlib.util.find_spec("d810.ui.workbench_commands") is not None


def _request(command: str) -> WorkbenchCommandRequest:
    return WorkbenchCommandRequest(
        command=command,
        function_ea=0x401000,
        expected_generation=8,
        function_fingerprint="sha256:abc",
    )


def _result(request: WorkbenchCommandRequest) -> WorkbenchCommandResult:
    return WorkbenchCommandResult(
        command=request.command,
        function_ea=request.function_ea,
        requested_generation=request.expected_generation,
        function_fingerprint=request.function_fingerprint,
        status=OutcomeStatus.READY,
        succeeded=True,
        accepted=True,
        refresh_requested=True,
        message="done",
    )


def test_analyze_passes_current_mba_and_provider_phase_without_decompiling() -> None:
    mba = SimpleNamespace(maturity=5)
    vdui = SimpleNamespace(cfunc=SimpleNamespace(mba=mba))
    calls: list[dict[str, object]] = []

    def execute_analyze(request, *, target, provider_phase):
        calls.append(
            {
                "request": request,
                "target": target,
                "provider_phase": provider_phase,
            }
        )
        return _result(request)

    state = SimpleNamespace(execute_workbench_analyze=execute_analyze)
    shim = SimpleNamespace(get_widget_vdui=lambda widget: vdui)
    adapter = command_module.WorkbenchCommandAdapter(
        state,
        shim,
        SimpleNamespace(widget=object()),
    )
    request = _request("analyze")

    result = adapter.analyze(request)

    assert result.succeeded is True
    assert len(calls) == 1
    assert calls[0]["request"] is request
    assert calls[0]["target"] is mba
    phase = calls[0]["provider_phase"]
    assert phase.provider_name == "hexrays_microcode"
    assert phase.provider_level == 5


def test_analyze_without_current_mba_returns_failed_result() -> None:
    state = SimpleNamespace(
        execute_workbench_analyze=lambda *args, **kwargs: (_ for _ in ()).throw(
            AssertionError("manager should not be called")
        )
    )
    shim = SimpleNamespace(get_widget_vdui=lambda widget: None)
    adapter = command_module.WorkbenchCommandAdapter(
        state,
        shim,
        SimpleNamespace(widget=object()),
    )

    result = adapter.analyze(_request("analyze"))

    assert result.status is OutcomeStatus.FAILED
    assert result.succeeded is False
    assert result.refresh_requested is False


def test_adapter_reacquires_vdui_from_stable_widget_after_action_context_expires() -> (
    None
):
    original_widget = object()
    stable_widget = object()
    mba = SimpleNamespace(maturity=5)
    vdui = SimpleNamespace(
        ct=stable_widget,
        cfunc=SimpleNamespace(entry_ea=0x401000, mba=mba),
    )
    original_lookups = 0
    manager_calls: list[object] = []

    def get_widget_vdui(widget):
        nonlocal original_lookups
        if widget is stable_widget:
            return vdui
        if widget is original_widget:
            original_lookups += 1
            return vdui if original_lookups == 1 else None
        return None

    state = SimpleNamespace(
        execute_workbench_analyze=lambda request, *, target, provider_phase: (
            manager_calls.append((target, provider_phase)) or _result(request)
        )
    )
    adapter = command_module.WorkbenchCommandAdapter(
        state,
        SimpleNamespace(get_widget_vdui=get_widget_vdui),
        SimpleNamespace(widget=original_widget),
    )

    result = adapter.analyze(_request("analyze"))

    assert result.succeeded is True
    assert manager_calls[0][0] is mba
    assert adapter._widget is stable_widget
    assert original_lookups == 1


def test_analyze_rejects_widget_that_navigated_to_a_different_function() -> None:
    mba = SimpleNamespace(maturity=5)
    vdui = SimpleNamespace(
        cfunc=SimpleNamespace(entry_ea=0x402000, mba=mba),
    )
    state = SimpleNamespace(
        execute_workbench_analyze=lambda *args, **kwargs: (_ for _ in ()).throw(
            AssertionError("manager should not analyze the wrong function")
        )
    )
    adapter = command_module.WorkbenchCommandAdapter(
        state,
        SimpleNamespace(get_widget_vdui=lambda widget: vdui),
        SimpleNamespace(widget=object()),
    )

    result = adapter.analyze(_request("analyze"))

    assert result.status is OutcomeStatus.FAILED
    assert "different function" in result.message


def test_deobfuscate_reuses_existing_action_exactly_once(monkeypatch) -> None:
    action_calls: list[object] = []
    state_calls: list[object] = []

    class FakeAction:
        def __init__(self, state, ida_modules) -> None:
            action_calls.append((state, ida_modules))

        def execute(self, ctx) -> int:
            action_calls.append(ctx)
            return 1

    module = ModuleType("d810.ui.actions.deobfuscate_this")
    module.DeobfuscateThisFunction = FakeAction
    monkeypatch.setitem(sys.modules, module.__name__, module)

    def execute_command(request, *, lifecycle):
        state_calls.append(request)
        assert lifecycle() is True
        return _result(request)

    state = SimpleNamespace(execute_workbench_deobfuscate=execute_command)
    shim = object()
    ctx = SimpleNamespace(widget=object())
    adapter = command_module.WorkbenchCommandAdapter(state, shim, ctx)
    request = _request("deobfuscate")

    result = adapter.deobfuscate(request)

    assert result.succeeded is True
    assert state_calls == [request]
    assert action_calls == [(state, {"idaapi": shim}), ctx]


def test_function_override_reuses_existing_action_exactly_once(monkeypatch) -> None:
    action_calls: list[object] = []

    class FakeAction:
        def __init__(self, state, ida_modules) -> None:
            action_calls.append((state, ida_modules))

        def execute(self, ctx) -> int:
            action_calls.append(ctx)
            return 1

    module = ModuleType("d810.ui.actions.function_rules")
    module.FunctionRules = FakeAction
    monkeypatch.setitem(sys.modules, module.__name__, module)

    def execute_command(request, *, lifecycle):
        assert lifecycle() is True
        return _result(request)

    state = SimpleNamespace(execute_workbench_function_override=execute_command)
    shim = object()
    ctx = SimpleNamespace(widget=object())
    adapter = command_module.WorkbenchCommandAdapter(state, shim, ctx)
    request = _request("function_override")

    result = adapter.function_override(request)

    assert result.succeeded is True
    assert action_calls == [(state, {"idaapi": shim}), ctx]


def test_analyze_adapter_source_does_not_refresh_decompile_or_import_actions() -> None:
    path = Path(command_module.__file__)
    tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    analyze = next(
        item
        for node in ast.walk(tree)
        if isinstance(node, ast.ClassDef) and node.name == "WorkbenchCommandAdapter"
        for item in node.body
        if isinstance(item, ast.FunctionDef) and item.name == "analyze"
    )
    source = ast.unparse(analyze)

    assert "refresh_view" not in source
    assert "decompile" not in source
    assert "d810.ui.actions" not in source
