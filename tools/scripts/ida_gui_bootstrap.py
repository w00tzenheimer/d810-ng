"""Fresh-launch IDAPython bootstrap for closed named GUI automation."""

from __future__ import annotations

import datetime
import importlib
import json
import os
import pathlib
import re
import sys
import tempfile
import time
import typing

from d810.ui import gui_automation_logic as gui_logic


POLL_INTERVAL_MS = 250
MCP_PACKAGE_PATH = pathlib.Path("/root/.idapro/plugins/ida-pro-mcp/src/ida_pro_mcp")
_MCP_ENDPOINT_PATTERN = re.compile(r"http://127\.0\.0\.1:([0-9]{1,5})/mcp\Z")
_D810_MCP_SERVER: object | None = None


class BootstrapRuntime:
    """Explicit seams for every live IDA or clock interaction."""

    def __init__(
        self,
        *,
        plugin_loaded: typing.Callable[[], bool],
        mcp_running: typing.Callable[[], bool],
        start_mcp: typing.Callable[[], None],
        dispatch: typing.Callable[
            [gui_logic.GuiAutomationRequest],
            gui_logic.GuiAutomationResult,
        ],
        register_timer: typing.Callable[[int, typing.Callable[[], int]], object],
        monotonic: typing.Callable[[], float],
        utc_now: typing.Callable[[], str],
    ) -> None:
        self.plugin_loaded = plugin_loaded
        self.mcp_running = mcp_running
        self.start_mcp = start_mcp
        self.dispatch = dispatch
        self.register_timer = register_timer
        self.monotonic = monotonic
        self.utc_now = utc_now


class BootstrapFilesystem(typing.Protocol):
    def read_text(self, path: pathlib.Path) -> str: ...

    def temporary_path(self, destination: pathlib.Path) -> pathlib.Path: ...

    def write_text(self, path: pathlib.Path, content: str) -> None: ...

    def replace(self, source: pathlib.Path, destination: pathlib.Path) -> None: ...

    def unlink(self, path: pathlib.Path) -> None: ...


class LocalFilesystem:
    """Filesystem implementation whose final publication is one replace."""

    def read_text(self, path: pathlib.Path) -> str:
        return path.read_text(encoding="utf-8")

    def temporary_path(self, destination: pathlib.Path) -> pathlib.Path:
        descriptor, name = tempfile.mkstemp(
            dir=destination.parent,
            prefix=f".{destination.name}.",
            suffix=".tmp",
        )
        os.close(descriptor)
        return pathlib.Path(name)

    def write_text(self, path: pathlib.Path, content: str) -> None:
        with path.open("w", encoding="utf-8") as stream:
            stream.write(content)
            stream.flush()
            os.fsync(stream.fileno())

    def replace(self, source: pathlib.Path, destination: pathlib.Path) -> None:
        os.replace(source, destination)

    def unlink(self, path: pathlib.Path) -> None:
        path.unlink(missing_ok=True)


def _request_from_document(
    document: object,
) -> tuple[gui_logic.GuiAutomationRequest, dict[str, object]]:
    if not isinstance(document, dict) or set(document) != {"request", "context"}:
        raise ValueError("automation request envelope must contain request and context")
    raw_request = document["request"]
    if not isinstance(raw_request, dict):
        raise TypeError("automation request must be a JSON object")
    expected_fields = {
        "request_id",
        "created_at_utc",
        "commands",
        "function_selector",
        "timeout_seconds",
    }
    if set(raw_request) != expected_fields:
        raise ValueError("automation request fields do not match the strict contract")
    commands = raw_request["commands"]
    if not isinstance(commands, list):
        raise TypeError("automation request commands must be a JSON array")
    request = gui_logic.GuiAutomationRequest(
        request_id=raw_request["request_id"],
        created_at_utc=raw_request["created_at_utc"],
        commands=tuple(commands),
        function_selector=raw_request["function_selector"],
        timeout_seconds=raw_request["timeout_seconds"],
    )
    context = document["context"]
    if not isinstance(context, dict):
        raise TypeError("automation request context must be a JSON object")
    _mcp_endpoint(context)
    return request, context


def _mcp_endpoint(context: dict[str, object]) -> str | None:
    endpoint = context.get("mcp_endpoint")
    if endpoint is None:
        return None
    if type(endpoint) is not str:
        raise TypeError("MCP endpoint must be a string or null")
    match = _MCP_ENDPOINT_PATTERN.fullmatch(endpoint)
    if match is None:
        raise ValueError("MCP endpoint must use loopback HTTP and the /mcp path")
    port = int(match.group(1), 10)
    if not 1024 <= port <= 65535:
        raise ValueError("MCP endpoint port must be from 1024 through 65535")
    return endpoint


def _load_request(
    request_path: pathlib.Path,
    filesystem: BootstrapFilesystem,
) -> tuple[gui_logic.GuiAutomationRequest, dict[str, object]]:
    document = json.loads(filesystem.read_text(request_path))
    return _request_from_document(document)


def _write_json_atomic(
    destination: pathlib.Path,
    document: dict[str, object],
    filesystem: BootstrapFilesystem,
) -> None:
    content = (
        json.dumps(
            document,
            allow_nan=False,
            indent=2,
            sort_keys=True,
        )
        + "\n"
    )
    temporary_path = filesystem.temporary_path(destination)
    try:
        filesystem.write_text(temporary_path, content)
        filesystem.replace(temporary_path, destination)
    except Exception:
        filesystem.unlink(temporary_path)
        raise


def _terminal_result(
    request: gui_logic.GuiAutomationRequest,
    *,
    status: str,
    error: str,
    completed_at_utc: str,
) -> gui_logic.GuiAutomationResult:
    commands = tuple(
        gui_logic.GuiCommandResult(
            name=command,
            started_at_utc=completed_at_utc,
            finished_at_utc=completed_at_utc,
            status=status,
            details={},
            error=error,
        )
        for command in request.commands
    )
    return gui_logic.GuiAutomationResult(
        request_id=request.request_id,
        completed_at_utc=completed_at_utc,
        commands=commands,
        status=status,
        error=error,
    )


class GuiAutomationBootstrap:
    """Poll for a loaded plugin, dispatch once, and publish one audit."""

    def __init__(
        self,
        *,
        request: gui_logic.GuiAutomationRequest,
        context: dict[str, object],
        audit_path: pathlib.Path,
        runtime: BootstrapRuntime,
        filesystem: BootstrapFilesystem,
    ) -> None:
        self.request = request
        self.context = context
        self.audit_path = audit_path
        self.runtime = runtime
        self.filesystem = filesystem
        self.mcp_endpoint = _mcp_endpoint(context)
        self.finished = False
        self._mcp_checked = False
        self._dispatch_started = False
        self._timer: object | None = None
        self._started_at = runtime.monotonic()

    def start(self) -> None:
        try:
            timer = self.runtime.register_timer(POLL_INTERVAL_MS, self.poll)
            if timer is None:
                raise RuntimeError("register_timer returned no timer object")
        except Exception as exc:
            self._finish(self._failure("timer registration failed", exc))
            return
        self._timer = timer

    def _finish(self, result: gui_logic.GuiAutomationResult) -> None:
        self.finished = True
        document = gui_logic.audit_document(
            self.request,
            result,
            self.context,
        )
        _write_json_atomic(self.audit_path, document, self.filesystem)

    def _failure(self, prefix: str, exc: Exception) -> gui_logic.GuiAutomationResult:
        error = f"{prefix}: {exc}"
        return _terminal_result(
            self.request,
            status="failed",
            error=error,
            completed_at_utc=self.runtime.utc_now(),
        )

    def poll(self) -> int:
        if self.finished:
            return -1

        elapsed = self.runtime.monotonic() - self._started_at
        if elapsed >= self.request.timeout_seconds:
            timeout = f"{self.request.timeout_seconds:g}"
            error = f"timeout waiting for d810-ng plugin after {timeout} seconds"
            self._finish(
                _terminal_result(
                    self.request,
                    status="timed_out",
                    error=error,
                    completed_at_utc=self.runtime.utc_now(),
                )
            )
            return -1

        try:
            plugin_loaded = self.runtime.plugin_loaded()
        except Exception as exc:
            self._finish(self._failure("bootstrap readiness check failed", exc))
            return -1
        if not plugin_loaded:
            return POLL_INTERVAL_MS

        if self.mcp_endpoint is not None and not self._mcp_checked:
            self._mcp_checked = True
            try:
                if not self.runtime.mcp_running():
                    self.runtime.start_mcp()
                    if not self.runtime.mcp_running():
                        raise RuntimeError("MCP server did not report running")
            except Exception as exc:
                self._finish(self._failure("bootstrap MCP startup failed", exc))
                return -1

        if self._dispatch_started:
            return -1
        self._dispatch_started = True
        try:
            result = self.runtime.dispatch(self.request)
            if not isinstance(result, gui_logic.GuiAutomationResult):
                raise TypeError("named-command adapter returned an invalid result")
        except Exception as exc:
            result = self._failure("bootstrap dispatch failed", exc)
        self._finish(result)
        return -1


def start_bootstrap(
    request_path: pathlib.Path | str,
    *,
    runtime: BootstrapRuntime,
    filesystem: BootstrapFilesystem | None = None,
) -> GuiAutomationBootstrap:
    """Load one validated request and register its one-shot poll timer."""
    resolved_path = pathlib.Path(request_path)
    active_filesystem = LocalFilesystem() if filesystem is None else filesystem
    request, context = _load_request(resolved_path, active_filesystem)
    audit_path = resolved_path.with_name(f"automation-{request.request_id}.json")
    session = GuiAutomationBootstrap(
        request=request,
        context=context,
        audit_path=audit_path,
        runtime=runtime,
        filesystem=active_filesystem,
    )
    session.start()
    return session


def _live_plugin_loaded() -> bool:
    main_module = sys.modules.get("__main__")
    wrapper = getattr(main_module, "D810", None)
    plugin = getattr(wrapper, "plugin", None)
    is_loaded = getattr(plugin, "is_loaded", None)
    return bool(callable(is_loaded) and is_loaded())


def _live_dispatch(
    request: gui_logic.GuiAutomationRequest,
) -> gui_logic.GuiAutomationResult:
    adapter = importlib.import_module("d810.ui.gui_automation")
    return adapter.run_named_commands(request)


def _live_mcp_running() -> bool:
    server = _D810_MCP_SERVER
    if server is None:
        loaded_package = sys.modules.get("ida_mcp")
        server = getattr(loaded_package, "MCP_SERVER", None)
    return bool(getattr(server, "_running", False))


def _live_start_mcp() -> None:
    global _D810_MCP_SERVER
    if _live_mcp_running():
        return

    plugin_package_path = str(MCP_PACKAGE_PATH)
    if plugin_package_path not in sys.path:
        sys.path.insert(0, plugin_package_path)
    package = importlib.import_module("ida_mcp")
    server = package.MCP_SERVER
    package.init_caches()
    server.serve(
        os.environ.get("IDA_MCP_HOST", "127.0.0.1"),
        int(os.environ.get("IDA_MCP_PORT", "13337"), 10),
        background=True,
        request_handler=package.IdaMcpHttpRequestHandler,
    )
    _D810_MCP_SERVER = server


def _utc_now() -> str:
    value = datetime.datetime.now(datetime.timezone.utc).isoformat()
    return value.replace("+00:00", "Z")


def _live_runtime() -> BootstrapRuntime:
    import ida_kernwin

    return BootstrapRuntime(
        plugin_loaded=_live_plugin_loaded,
        mcp_running=_live_mcp_running,
        start_mcp=_live_start_mcp,
        dispatch=_live_dispatch,
        register_timer=ida_kernwin.register_timer,
        monotonic=time.monotonic,
        utc_now=_utc_now,
    )


def start_live_bootstrap() -> GuiAutomationBootstrap:
    """Start from the single launcher-provided request environment variable."""
    request_path = os.environ.get("D810_GUI_AUTOMATION_REQUEST")
    if not request_path:
        raise RuntimeError("D810_GUI_AUTOMATION_REQUEST is not set")
    return start_bootstrap(request_path, runtime=_live_runtime())


if __name__ == "__main__":
    try:
        _D810_GUI_AUTOMATION_SESSION = start_live_bootstrap()
    except Exception as exc:
        print(f"D810 GUI automation bootstrap failed: {exc}")
