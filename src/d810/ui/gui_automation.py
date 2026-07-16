"""Thin live-IDA adapter for the closed named GUI automation contract."""

from __future__ import annotations

import dataclasses
import datetime
import sys
import time

from d810.core import typing
from d810.ui.gui_automation_logic import (
    GuiAutomationRequest,
    GuiAutomationResult,
    GuiCommand,
    GuiCommandResult,
)


_CONFIG_TITLE = "D-810 Configuration"
_WORKBENCH_TITLE = "d810-ng Deobfuscation Workbench"
_WORKBENCH_ACTION = "d810ng:deobfuscation_stats"


@dataclasses.dataclass(frozen=True, slots=True)
class _ResolvedFunction:
    ea: int
    name: str


@dataclasses.dataclass(frozen=True, slots=True)
class _AutomationRuntime:
    state_provider: typing.Callable[[], typing.Any | None]
    function_resolver: typing.Any
    widget_registry: typing.Any
    action_invoker: typing.Any
    scheduler: typing.Any


class _AutomationFailure(Exception):
    def __init__(self, message: str, *, status: str = "failed") -> None:
        super().__init__(message)
        self.status = status


class _IDAFunctionResolver:
    def __init__(
        self,
        ida_funcs_module: typing.Any,
        ida_kernwin_module: typing.Any,
        ida_name_module: typing.Any,
        badaddr: int,
    ) -> None:
        self._ida_funcs = ida_funcs_module
        self._ida_kernwin = ida_kernwin_module
        self._ida_name = ida_name_module
        self._badaddr = int(badaddr)

    def resolve(self, selector: str | int | None) -> _ResolvedFunction | None:
        if selector is None:
            candidate = int(self._ida_kernwin.get_screen_ea())
        elif isinstance(selector, str):
            candidate = int(self._ida_name.get_name_ea(self._badaddr, selector))
        else:
            candidate = int(selector)

        if candidate == self._badaddr:
            return None
        function = self._ida_funcs.get_func(candidate)
        if function is None:
            return None
        function_ea = int(function.start_ea)
        return _ResolvedFunction(
            ea=function_ea,
            name=str(self._ida_funcs.get_func_name(function_ea) or ""),
        )


class _IDAActionInvoker:
    def __init__(
        self,
        ida_hexrays_module: typing.Any,
        ida_kernwin_module: typing.Any,
        stats_action_type: typing.Any,
        process_events: typing.Callable[[], None],
    ) -> None:
        self._ida_hexrays = ida_hexrays_module
        self._ida_kernwin = ida_kernwin_module
        self._stats_action_type = stats_action_type
        self._process_events = process_events

    def open_pseudocode(self, function_ea: int) -> typing.Any | None:
        vdui = self._ida_hexrays.open_pseudocode(int(function_ea), 0)
        if vdui is None:
            return None
        return getattr(vdui, "ct", None)

    def activate_pseudocode(self, widget: typing.Any) -> bool:
        self._ida_kernwin.activate_widget(widget, True)
        self._process_events()
        current = self._ida_kernwin.get_current_widget()
        return current is widget or current == widget

    def invoke(self, action_id: str) -> bool:
        return bool(self._ida_kernwin.process_ui_action(action_id, 0))

    def captured_function_ea(self) -> int | None:
        panel = self._stats_action_type._panel
        captured = getattr(panel, "_func_ea", None)
        return None if captured is None else int(captured)


class _IDAWidgetRegistry:
    def __init__(
        self,
        ida_kernwin_module: typing.Any,
        *,
        process_events: typing.Callable[[], None],
        monotonic: typing.Callable[[], float] = time.monotonic,
        sleep: typing.Callable[[float], None] = time.sleep,
    ) -> None:
        self._ida_kernwin = ida_kernwin_module
        self._process_events = process_events
        self._monotonic = monotonic
        self._sleep = sleep

    def wait_until_focused(
        self,
        title: str,
        timeout_seconds: float,
    ) -> typing.Any | None:
        deadline = self._monotonic() + float(timeout_seconds)
        while True:
            widget = self._ida_kernwin.find_widget(title)
            if widget is not None:
                self._ida_kernwin.activate_widget(widget, True)
                self._process_events()
                current = self._ida_kernwin.get_current_widget()
                if current is widget or current == widget:
                    return widget

            remaining = deadline - self._monotonic()
            if remaining <= 0:
                return None
            self._process_events()
            self._sleep(min(0.01, remaining))


class _IDAMainThreadScheduler:
    def __init__(self, ida_kernwin_module: typing.Any) -> None:
        self._ida_kernwin = ida_kernwin_module

    def run(self, callback: typing.Callable[[], typing.Any]) -> typing.Any:
        outcome: dict[str, typing.Any] = {}

        def execute() -> int:
            try:
                outcome["result"] = callback()
            except Exception as exc:
                outcome["error"] = exc
            return 1

        scheduler_result = self._ida_kernwin.execute_sync(
            execute,
            self._ida_kernwin.MFF_FAST,
        )
        if "error" in outcome:
            raise outcome["error"]
        if "result" not in outcome:
            raise RuntimeError(
                "IDA did not execute the main-thread request "
                f"(execute_sync returned {scheduler_result!r})"
            )
        return outcome["result"]


def _loaded_state() -> typing.Any | None:
    main_module = sys.modules.get("__main__")
    plugin_wrapper = getattr(main_module, "D810", None)
    return getattr(plugin_wrapper, "plugin", None)


def _build_live_runtime() -> _AutomationRuntime:
    import ida_funcs
    import ida_hexrays
    import ida_kernwin
    import ida_name
    import idaapi

    from d810.qt_shim import QtWidgets
    from d810.ui.actions.deobfuscation_stats import DeobfuscationStats

    process_events = QtWidgets.QApplication.processEvents
    return _AutomationRuntime(
        state_provider=_loaded_state,
        function_resolver=_IDAFunctionResolver(
            ida_funcs,
            ida_kernwin,
            ida_name,
            idaapi.BADADDR,
        ),
        widget_registry=_IDAWidgetRegistry(
            ida_kernwin,
            process_events=process_events,
        ),
        action_invoker=_IDAActionInvoker(
            ida_hexrays,
            ida_kernwin,
            DeobfuscationStats,
            process_events,
        ),
        scheduler=_IDAMainThreadScheduler(ida_kernwin),
    )


_runtime_factory = _build_live_runtime


def _utc_now() -> str:
    value = datetime.datetime.now(datetime.timezone.utc).isoformat()
    return value.replace("+00:00", "Z")


def _require_loaded_state(runtime: _AutomationRuntime) -> typing.Any:
    state = runtime.state_provider()
    if state is None:
        raise _AutomationFailure("d810-ng plugin state is not loaded")
    is_loaded = getattr(state, "is_loaded", None)
    if not callable(is_loaded) or not is_loaded():
        raise _AutomationFailure("d810-ng plugin state is not loaded")
    return state


def _wait_for_widget(
    runtime: _AutomationRuntime,
    title: str,
    timeout_seconds: float,
) -> None:
    widget = runtime.widget_registry.wait_until_focused(title, timeout_seconds)
    if widget is None:
        raise _AutomationFailure(
            f"timeout waiting for widget: {title}",
            status="timed_out",
        )


def _open_config(
    runtime: _AutomationRuntime,
    timeout_seconds: float,
) -> dict[str, object]:
    state = _require_loaded_state(runtime)
    gui = getattr(state, "gui", None)
    if gui is None or not callable(getattr(gui, "show_windows", None)):
        raise _AutomationFailure("loaded d810-ng plugin has no configuration GUI")
    gui.show_windows()
    _wait_for_widget(runtime, _CONFIG_TITLE, timeout_seconds)
    return {"widget_title": _CONFIG_TITLE}


def _open_workbench(
    runtime: _AutomationRuntime,
    selector: str | int | None,
    timeout_seconds: float,
) -> dict[str, object]:
    _require_loaded_state(runtime)
    try:
        function = runtime.function_resolver.resolve(selector)
    except Exception as exc:
        raise _AutomationFailure(f"function resolution failed: {exc}") from exc
    if function is None:
        raise _AutomationFailure(f"function not found for selector: {selector!r}")

    try:
        pseudocode_widget = runtime.action_invoker.open_pseudocode(function.ea)
    except Exception as exc:
        raise _AutomationFailure(f"Hex-Rays failed to open pseudocode: {exc}") from exc
    if pseudocode_widget is None:
        raise _AutomationFailure(
            f"Hex-Rays could not open pseudocode for {function.ea:#x}"
        )

    try:
        activated = runtime.action_invoker.activate_pseudocode(pseudocode_widget)
    except Exception as exc:
        raise _AutomationFailure(
            f"failed to activate pseudocode widget: {exc}"
        ) from exc
    if not activated:
        raise _AutomationFailure(
            f"failed to activate pseudocode widget for {function.ea:#x}"
        )

    try:
        action_succeeded = runtime.action_invoker.invoke(_WORKBENCH_ACTION)
    except Exception as exc:
        raise _AutomationFailure(f"action {_WORKBENCH_ACTION} failed: {exc}") from exc
    if not action_succeeded:
        raise _AutomationFailure(f"action {_WORKBENCH_ACTION} failed")

    captured_ea = runtime.action_invoker.captured_function_ea()
    if captured_ea != function.ea:
        actual = "none" if captured_ea is None else f"{captured_ea:#x}"
        raise _AutomationFailure(
            f"workbench captured function {actual} instead of {function.ea:#x}"
        )

    _wait_for_widget(runtime, _WORKBENCH_TITLE, timeout_seconds)
    return {
        "action_id": _WORKBENCH_ACTION,
        "function_ea": function.ea,
        "function_name": function.name,
        "widget_title": _WORKBENCH_TITLE,
    }


def _run_command(
    runtime: _AutomationRuntime,
    request: GuiAutomationRequest,
    command: GuiCommand,
) -> GuiCommandResult:
    started_at = _utc_now()
    try:
        if command is GuiCommand.OPEN_CONFIG:
            details = _open_config(runtime, request.timeout_seconds)
        else:
            details = _open_workbench(
                runtime,
                request.function_selector,
                request.timeout_seconds,
            )
        status = "succeeded"
        error = None
    except _AutomationFailure as exc:
        details = {}
        status = exc.status
        error = str(exc)
    except Exception as exc:
        details = {}
        status = "failed"
        error = f"{command.value} failed: {exc}"
    return GuiCommandResult(
        name=command,
        started_at_utc=started_at,
        finished_at_utc=_utc_now(),
        status=status,
        details=details,
        error=error,
    )


def _result_status(commands: tuple[GuiCommandResult, ...]) -> tuple[str, str | None]:
    statuses = {command.status for command in commands}
    if "failed" in statuses:
        return "failed", "one or more commands failed"
    if "timed_out" in statuses:
        return "timed_out", "one or more commands timed out"
    return "succeeded", None


def _run_on_main_thread(
    runtime: _AutomationRuntime,
    request: GuiAutomationRequest,
) -> GuiAutomationResult:
    commands = tuple(
        _run_command(runtime, request, command) for command in request.commands
    )
    status, error = _result_status(commands)
    return GuiAutomationResult(
        request_id=request.request_id,
        completed_at_utc=_utc_now(),
        commands=commands,
        status=status,
        error=error,
    )


def _failed_result(request: GuiAutomationRequest, error: str) -> GuiAutomationResult:
    commands = tuple(
        GuiCommandResult(
            name=command,
            started_at_utc=_utc_now(),
            finished_at_utc=_utc_now(),
            status="failed",
            details={},
            error=error,
        )
        for command in request.commands
    )
    return GuiAutomationResult(
        request_id=request.request_id,
        completed_at_utc=_utc_now(),
        commands=commands,
        status="failed",
        error=error,
    )


def run_named_commands(request: GuiAutomationRequest) -> GuiAutomationResult:
    """Run the request's closed named-command set on IDA's main thread."""
    if not isinstance(request, GuiAutomationRequest):
        raise TypeError("request must be a GuiAutomationRequest")
    try:
        runtime = _runtime_factory()
    except Exception as exc:
        return _failed_result(request, f"IDA runtime unavailable: {exc}")
    try:
        return runtime.scheduler.run(lambda: _run_on_main_thread(runtime, request))
    except Exception as exc:
        return _failed_result(request, f"IDA main-thread execution failed: {exc}")


__all__ = ["run_named_commands"]
