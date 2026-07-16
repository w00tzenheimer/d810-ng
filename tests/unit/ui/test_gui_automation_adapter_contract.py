"""Contract tests for the thin, live-IDA named GUI automation adapter."""

from __future__ import annotations

import ast
import importlib
import inspect
from pathlib import Path
from types import ModuleType, SimpleNamespace


ROOT = Path(__file__).resolve().parents[3]
ADAPTER = ROOT / "src" / "d810" / "ui" / "gui_automation.py"
LOGIC = ROOT / "src" / "d810" / "ui" / "gui_automation_logic.py"


def _adapter() -> ModuleType:
    return importlib.import_module("d810.ui.gui_automation")


def _logic() -> ModuleType:
    return importlib.import_module("d810.ui.gui_automation_logic")


class FakeScheduler:
    def __init__(self) -> None:
        self.active = False
        self.calls = 0

    def run(self, callback):
        self.calls += 1
        self.active = True
        try:
            return callback()
        finally:
            self.active = False

    def assert_main_thread(self) -> None:
        assert self.active, "live seam was called outside the main-thread scheduler"


class FakeGUI:
    def __init__(self, scheduler: FakeScheduler, events: list[object]) -> None:
        self._scheduler = scheduler
        self._events = events
        self.show_calls = 0

    def show_windows(self) -> None:
        self._scheduler.assert_main_thread()
        self.show_calls += 1
        self._events.append("show-config")


class FakeState:
    def __init__(self, gui: FakeGUI, scheduler: FakeScheduler) -> None:
        self.gui = gui
        self._scheduler = scheduler
        self.lifecycle_calls: list[str] = []

    def is_loaded(self) -> bool:
        self._scheduler.assert_main_thread()
        return True

    def unload(self) -> None:
        self.lifecycle_calls.append("unload")

    def stop_d810(self) -> None:
        self.lifecycle_calls.append("stop_d810")

    def term(self) -> None:
        self.lifecycle_calls.append("term")


class FakeFunctionResolver:
    def __init__(
        self,
        scheduler: FakeScheduler,
        events: list[object],
        function=None,
    ) -> None:
        self._scheduler = scheduler
        self._events = events
        self.function = function
        self.selectors: list[object] = []

    def resolve(self, selector):
        self._scheduler.assert_main_thread()
        self.selectors.append(selector)
        self._events.append(("resolve", selector))
        return self.function


class FakeActionInvoker:
    def __init__(
        self,
        scheduler: FakeScheduler,
        events: list[object],
        *,
        pseudocode_widget: object | None = None,
        action_result: bool = True,
        captured_ea: int | None = 0x401000,
    ) -> None:
        self._scheduler = scheduler
        self._events = events
        self.pseudocode_widget = (
            object() if pseudocode_widget is None else pseudocode_widget
        )
        self.action_result = action_result
        self.captured_ea = captured_ea
        self.opened_eas: list[int] = []
        self.activated_widgets: list[object] = []
        self.action_ids: list[str] = []

    def open_pseudocode(self, function_ea: int):
        self._scheduler.assert_main_thread()
        self.opened_eas.append(function_ea)
        self._events.append(("open-pseudocode", function_ea))
        return self.pseudocode_widget

    def activate_pseudocode(self, widget: object) -> bool:
        self._scheduler.assert_main_thread()
        self.activated_widgets.append(widget)
        self._events.append("activate-pseudocode")
        return True

    def invoke(self, action_id: str) -> bool:
        self._scheduler.assert_main_thread()
        self.action_ids.append(action_id)
        self._events.append(("invoke", action_id))
        return self.action_result

    def captured_function_ea(self) -> int | None:
        self._scheduler.assert_main_thread()
        self._events.append(("captured", self.captured_ea))
        return self.captured_ea


class FakeWidgetRegistry:
    def __init__(
        self,
        scheduler: FakeScheduler,
        events: list[object],
        *,
        found: bool = True,
    ) -> None:
        self._scheduler = scheduler
        self._events = events
        self.found = found
        self.waits: list[tuple[str, float]] = []

    def wait_until_focused(self, title: str, timeout_seconds: float):
        self._scheduler.assert_main_thread()
        self.waits.append((title, timeout_seconds))
        self._events.append(("verify-widget", title))
        return object() if self.found else None


def _runtime(
    adapter: ModuleType,
    *,
    state: object = ...,
    function=None,
    pseudocode_widget: object | None = None,
    action_result: bool = True,
    captured_ea: int | None = 0x401000,
    widget_found: bool = True,
):
    events: list[object] = []
    scheduler = FakeScheduler()
    gui = FakeGUI(scheduler, events)
    resolved_state = FakeState(gui, scheduler) if state is ... else state
    resolver = FakeFunctionResolver(scheduler, events, function=function)
    invoker = FakeActionInvoker(
        scheduler,
        events,
        pseudocode_widget=pseudocode_widget,
        action_result=action_result,
        captured_ea=captured_ea,
    )
    widgets = FakeWidgetRegistry(
        scheduler,
        events,
        found=widget_found,
    )

    def state_provider():
        scheduler.assert_main_thread()
        events.append("get-state")
        return resolved_state

    runtime = adapter._AutomationRuntime(
        state_provider=state_provider,
        function_resolver=resolver,
        widget_registry=widgets,
        action_invoker=invoker,
        scheduler=scheduler,
    )
    return SimpleNamespace(
        runtime=runtime,
        state=resolved_state,
        gui=gui,
        resolver=resolver,
        invoker=invoker,
        widgets=widgets,
        scheduler=scheduler,
        events=events,
    )


def _request(*, config: bool, workbench: bool, selector=None, timeout=3.0):
    logic = _logic()
    return logic.GuiAutomationRequest(
        request_id="request-adapter",
        created_at_utc="2026-07-16T20:00:00Z",
        commands=logic.ordered_commands(config, workbench),
        function_selector=selector,
        timeout_seconds=timeout,
    )


def test_public_adapter_contract_is_one_typed_entry_point() -> None:
    adapter = _adapter()

    assert adapter.__all__ == ["run_named_commands"]
    signature = inspect.signature(adapter.run_named_commands)
    assert tuple(signature.parameters) == ("request",)
    assert signature.return_annotation in (
        "GuiAutomationResult",
        _logic().GuiAutomationResult,
    )


def test_open_config_reuses_loaded_gui_and_verifies_actual_widget(monkeypatch) -> None:
    adapter = _adapter()
    fake = _runtime(adapter)
    monkeypatch.setattr(adapter, "_runtime_factory", lambda: fake.runtime)

    result = adapter.run_named_commands(
        _request(config=True, workbench=False, timeout=2.5)
    )

    assert result.status == "succeeded"
    assert len(result.commands) == 1
    assert result.commands[0].status == "succeeded"
    assert dict(result.commands[0].details) == {"widget_title": "D-810 Configuration"}
    assert fake.gui.show_calls == 1
    assert fake.widgets.waits == [("D-810 Configuration", 2.5)]
    assert fake.scheduler.calls == 1
    assert fake.state.lifecycle_calls == []


def test_open_workbench_establishes_pseudocode_context_and_reuses_stats_action(
    monkeypatch,
) -> None:
    adapter = _adapter()
    function = adapter._ResolvedFunction(ea=0x401000, name="target")
    fake = _runtime(adapter, function=function)
    monkeypatch.setattr(adapter, "_runtime_factory", lambda: fake.runtime)

    result = adapter.run_named_commands(
        _request(config=False, workbench=True, selector="target")
    )

    assert result.status == "succeeded"
    assert dict(result.commands[0].details) == {
        "action_id": "d810ng:deobfuscation_stats",
        "function_ea": 0x401000,
        "function_name": "target",
        "widget_title": "d810-ng Deobfuscation Workbench",
    }
    assert fake.resolver.selectors == ["target"]
    assert fake.invoker.opened_eas == [0x401000]
    assert fake.invoker.activated_widgets == [fake.invoker.pseudocode_widget]
    assert fake.invoker.action_ids == ["d810ng:deobfuscation_stats"]
    assert fake.widgets.waits == [("d810-ng Deobfuscation Workbench", 3.0)]
    assert fake.events == [
        "get-state",
        ("resolve", "target"),
        ("open-pseudocode", 0x401000),
        "activate-pseudocode",
        ("invoke", "d810ng:deobfuscation_stats"),
        ("captured", 0x401000),
        ("verify-widget", "d810-ng Deobfuscation Workbench"),
    ]
    assert fake.state.lifecycle_calls == []


def test_both_commands_preserve_config_then_workbench_order(monkeypatch) -> None:
    adapter = _adapter()
    function = adapter._ResolvedFunction(ea=0x401000, name="target")
    fake = _runtime(adapter, function=function)
    monkeypatch.setattr(adapter, "_runtime_factory", lambda: fake.runtime)

    result = adapter.run_named_commands(
        _request(config=True, workbench=True, selector=0x401000)
    )

    assert [command.name.value for command in result.commands] == [
        "open-config",
        "open-workbench",
    ]
    assert fake.events.index("show-config") < fake.events.index(("resolve", 0x401000))


def test_missing_plugin_state_is_a_structured_failure(monkeypatch) -> None:
    adapter = _adapter()
    fake = _runtime(adapter, state=None)
    monkeypatch.setattr(adapter, "_runtime_factory", lambda: fake.runtime)

    result = adapter.run_named_commands(_request(config=True, workbench=False))

    assert result.status == "failed"
    assert result.commands[0].status == "failed"
    assert "plugin state" in (result.commands[0].error or "")
    assert fake.gui.show_calls == 0


def test_missing_function_is_a_structured_failure_without_lifecycle_mutation(
    monkeypatch,
) -> None:
    adapter = _adapter()
    fake = _runtime(adapter, function=None)
    monkeypatch.setattr(adapter, "_runtime_factory", lambda: fake.runtime)

    result = adapter.run_named_commands(
        _request(config=False, workbench=True, selector="missing")
    )

    assert result.status == "failed"
    assert result.commands[0].status == "failed"
    assert "function not found" in (result.commands[0].error or "")
    assert fake.invoker.action_ids == []
    assert fake.state.lifecycle_calls == []


def test_hexrays_failure_is_structured_and_does_not_invoke_action(monkeypatch) -> None:
    adapter = _adapter()
    function = adapter._ResolvedFunction(ea=0x401000, name="target")
    fake = _runtime(adapter, function=function)
    fake.invoker.pseudocode_widget = None
    monkeypatch.setattr(adapter, "_runtime_factory", lambda: fake.runtime)

    result = adapter.run_named_commands(
        _request(config=False, workbench=True, selector="target")
    )

    assert result.status == "failed"
    assert "Hex-Rays" in (result.commands[0].error or "")
    assert fake.invoker.action_ids == []
    assert fake.state.lifecycle_calls == []


def test_action_failure_is_structured(monkeypatch) -> None:
    adapter = _adapter()
    function = adapter._ResolvedFunction(ea=0x401000, name="target")
    fake = _runtime(adapter, function=function, action_result=False)
    monkeypatch.setattr(adapter, "_runtime_factory", lambda: fake.runtime)

    result = adapter.run_named_commands(
        _request(config=False, workbench=True, selector="target")
    )

    assert result.status == "failed"
    assert "d810ng:deobfuscation_stats" in (result.commands[0].error or "")
    assert fake.widgets.waits == []
    assert fake.state.lifecycle_calls == []


def test_captured_function_must_match_resolved_function(monkeypatch) -> None:
    adapter = _adapter()
    function = adapter._ResolvedFunction(ea=0x401000, name="target")
    fake = _runtime(adapter, function=function, captured_ea=0x402000)
    monkeypatch.setattr(adapter, "_runtime_factory", lambda: fake.runtime)

    result = adapter.run_named_commands(
        _request(config=False, workbench=True, selector="target")
    )

    assert result.status == "failed"
    assert "captured function" in (result.commands[0].error or "")
    assert fake.widgets.waits == []


def test_widget_timeout_is_structured_and_bounded(monkeypatch) -> None:
    adapter = _adapter()
    function = adapter._ResolvedFunction(ea=0x401000, name="target")
    fake = _runtime(adapter, function=function, widget_found=False)
    monkeypatch.setattr(adapter, "_runtime_factory", lambda: fake.runtime)

    result = adapter.run_named_commands(
        _request(config=False, workbench=True, selector="target", timeout=1.25)
    )

    assert result.status == "timed_out"
    assert result.commands[0].status == "timed_out"
    assert "timeout" in (result.commands[0].error or "")
    assert fake.widgets.waits == [("d810-ng Deobfuscation Workbench", 1.25)]
    assert fake.state.lifecycle_calls == []


def test_live_widget_registry_requires_focus_not_action_truthiness() -> None:
    adapter = _adapter()
    widget = object()
    calls: list[object] = []
    kernwin = SimpleNamespace(
        find_widget=lambda title: calls.append(("find", title)) or widget,
        activate_widget=lambda found, take_focus: calls.append(
            ("activate", found, take_focus)
        ),
        get_current_widget=lambda: calls.append("current") or widget,
    )
    registry = adapter._IDAWidgetRegistry(
        kernwin,
        process_events=lambda: calls.append("events"),
    )

    assert registry.wait_until_focused("Expected Widget", 0.25) is widget
    assert calls == [
        ("find", "Expected Widget"),
        ("activate", widget, True),
        "events",
        "current",
    ]


def _imports(path: Path) -> set[str]:
    imported: set[str] = set()
    for node in ast.walk(ast.parse(path.read_text(encoding="utf-8"))):
        if isinstance(node, ast.Import):
            imported.update(alias.name for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module:
            imported.add(node.module)
    return imported


def test_adapter_imports_contract_while_pure_logic_imports_neither_ida_nor_qt() -> None:
    adapter_imports = _imports(ADAPTER)
    logic_imports = _imports(LOGIC)

    assert "d810.ui.gui_automation_logic" in adapter_imports
    prohibited_roots = ("ida", "PyQt", "PySide", "d810.qt_shim")
    assert not any(name.startswith(prohibited_roots) for name in logic_imports)
