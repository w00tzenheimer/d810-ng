"""Tests for the fresh-launch named GUI automation bootstrap."""

from __future__ import annotations

import ast
import importlib.util
import json
from pathlib import Path
from types import ModuleType

import pytest


ROOT = Path(__file__).resolve().parents[3]
BOOTSTRAP_PATH = ROOT / "tools" / "scripts" / "ida_gui_bootstrap.py"


def _bootstrap() -> ModuleType:
    spec = importlib.util.spec_from_file_location("ida_gui_bootstrap", BOOTSTRAP_PATH)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class FakeFilesystem:
    def __init__(self, request_path: Path, document: dict[str, object]) -> None:
        self.files = {
            request_path: json.dumps(document, allow_nan=False),
        }
        self.temporary_paths: list[tuple[Path, Path]] = []
        self.writes: list[Path] = []
        self.replacements: list[tuple[Path, Path]] = []
        self.unlinks: list[Path] = []

    def read_text(self, path: Path) -> str:
        return self.files[path]

    def temporary_path(self, destination: Path) -> Path:
        path = destination.with_name(f".{destination.name}.atomic.tmp")
        self.temporary_paths.append((destination, path))
        return path

    def write_text(self, path: Path, content: str) -> None:
        self.writes.append(path)
        self.files[path] = content

    def replace(self, source: Path, destination: Path) -> None:
        self.replacements.append((source, destination))
        self.files[destination] = self.files.pop(source)

    def unlink(self, path: Path) -> None:
        self.unlinks.append(path)
        self.files.pop(path, None)


class FakeTimerRuntime:
    def __init__(self, bootstrap: ModuleType) -> None:
        self.now = 100.0
        self.loaded = False
        self.callback = None
        self.registered_intervals: list[int] = []
        self.unregistered: list[object] = []
        self.dispatch_calls: list[object] = []
        self.dispatch_result = None
        self.dispatch_error: Exception | None = None
        self.events: list[str] = []
        self.mcp_running_value = False
        self.mcp_running_error: Exception | None = None
        self.mcp_running_calls = 0
        self.mcp_start_error: Exception | None = None
        self.mcp_start_calls = 0
        self.registration_error: Exception | None = None
        self.timer = object()
        self.register_result = self.timer
        self.runtime = bootstrap.BootstrapRuntime(
            plugin_loaded=self.plugin_loaded,
            mcp_running=self.mcp_running,
            start_mcp=self.start_mcp,
            dispatch=self.dispatch,
            register_timer=self.register_timer,
            monotonic=lambda: self.now,
            utc_now=lambda: "2026-07-16T21:00:30Z",
        )

    def plugin_loaded(self) -> bool:
        return self.loaded

    def dispatch(self, request):
        self.events.append("dispatch")
        self.dispatch_calls.append(request)
        if self.dispatch_error is not None:
            raise self.dispatch_error
        assert self.dispatch_result is not None
        return self.dispatch_result

    def mcp_running(self) -> bool:
        self.events.append("mcp-running")
        self.mcp_running_calls += 1
        if self.mcp_running_error is not None:
            raise self.mcp_running_error
        return self.mcp_running_value

    def start_mcp(self) -> None:
        self.events.append("mcp-start")
        self.mcp_start_calls += 1
        if self.mcp_start_error is not None:
            raise self.mcp_start_error
        self.mcp_running_value = True

    def register_timer(self, interval: int, callback):
        self.registered_intervals.append(interval)
        if self.registration_error is not None:
            raise self.registration_error
        self.callback = callback
        return self.register_result

    def fire(self) -> int:
        result = self.callback()
        if result == -1 and not self.unregistered:
            self.unregistered.append(self.timer)
        return result


def _request_document(
    *,
    commands: list[str] | None = None,
    selector: str | int | None = None,
    mcp_endpoint: object = None,
) -> dict[str, object]:
    return {
        "request": {
            "request_id": "request-bootstrap",
            "created_at_utc": "2026-07-16T21:00:00Z",
            "commands": ["open-config"] if commands is None else commands,
            "function_selector": selector,
            "timeout_seconds": 30.0,
        },
        "context": {
            "mode": "launch",
            "worktree": "/work",
            "idb": {
                "path": "/work/.tmp/ida-gui/sample.i64",
                "sha256": "abc123",
            },
            "mcp_endpoint": mcp_endpoint,
        },
    }


def _result(bootstrap: ModuleType, *, status: str = "succeeded"):
    logic = bootstrap.gui_logic
    error = None if status == "succeeded" else "command failed"
    command = logic.GuiCommandResult(
        name=logic.GuiCommand.OPEN_CONFIG,
        started_at_utc="2026-07-16T21:00:29Z",
        finished_at_utc="2026-07-16T21:00:30Z",
        status=status,
        details=(
            {"widget_title": "D-810 Configuration"} if status == "succeeded" else {}
        ),
        error=error,
    )
    return logic.GuiAutomationResult(
        request_id="request-bootstrap",
        completed_at_utc="2026-07-16T21:00:30Z",
        commands=(command,),
        status=status,
        error=error,
    )


def _session(
    bootstrap: ModuleType,
    *,
    document: dict[str, object] | None = None,
    register_result=...,
    registration_error: Exception | None = None,
):
    request_path = Path("/work/.tmp/ida-gui/automation-request-request-bootstrap.json")
    filesystem = FakeFilesystem(
        request_path,
        _request_document() if document is None else document,
    )
    timer = FakeTimerRuntime(bootstrap)
    if register_result is not ...:
        timer.register_result = register_result
    timer.registration_error = registration_error
    session = bootstrap.start_bootstrap(
        request_path,
        runtime=timer.runtime,
        filesystem=filesystem,
    )
    return session, timer, filesystem


def _audit(filesystem: FakeFilesystem) -> dict[str, object]:
    path = Path("/work/.tmp/ida-gui/automation-request-request-bootstrap.json")
    audit_path = path.with_name("automation-request-bootstrap.json")
    return json.loads(filesystem.files[audit_path])


def test_module_import_is_ida_free_and_live_calls_are_deferred_to_seams() -> None:
    tree = ast.parse(BOOTSTRAP_PATH.read_text(encoding="utf-8"))
    top_level_imports = {
        alias.name
        for node in tree.body
        if isinstance(node, ast.Import)
        for alias in node.names
    }
    top_level_imports.update(
        node.module
        for node in tree.body
        if isinstance(node, ast.ImportFrom) and node.module
    )

    assert not any(name.startswith("ida") for name in top_level_imports)


def test_timer_registration_returning_none_publishes_atomic_failed_audit() -> None:
    bootstrap = _bootstrap()
    session, timer, filesystem = _session(bootstrap, register_result=None)

    audit = _audit(filesystem)
    assert audit["schema_version"] == 1
    assert audit["status"] == "failed"
    assert audit["error"] == (
        "timer registration failed: register_timer returned no timer object"
    )
    assert audit["commands"][0]["status"] == "failed"
    assert session.finished is True
    assert timer.dispatch_calls == []
    assert timer.unregistered == []
    assert timer.callback() == -1
    audit_path = Path("/work/.tmp/ida-gui/automation-request-bootstrap.json")
    temporary_path = audit_path.with_name(f".{audit_path.name}.atomic.tmp")
    assert filesystem.replacements == [(temporary_path, audit_path)]


def test_timer_registration_exception_publishes_atomic_failed_audit() -> None:
    bootstrap = _bootstrap()
    session, timer, filesystem = _session(
        bootstrap,
        registration_error=RuntimeError("timer service unavailable"),
    )

    audit = _audit(filesystem)
    assert audit["schema_version"] == 1
    assert audit["status"] == "failed"
    assert audit["error"] == ("timer registration failed: timer service unavailable")
    assert audit["commands"][0]["status"] == "failed"
    assert session.finished is True
    assert timer.dispatch_calls == []
    assert timer.callback is None
    assert timer.unregistered == []
    audit_path = Path("/work/.tmp/ida-gui/automation-request-bootstrap.json")
    temporary_path = audit_path.with_name(f".{audit_path.name}.atomic.tmp")
    assert filesystem.replacements == [(temporary_path, audit_path)]


def test_polling_waits_for_loaded_plugin_then_dispatches_exactly_once() -> None:
    bootstrap = _bootstrap()
    session, timer, filesystem = _session(bootstrap)
    timer.dispatch_result = _result(bootstrap)

    assert timer.registered_intervals == [bootstrap.POLL_INTERVAL_MS]
    assert timer.fire() == bootstrap.POLL_INTERVAL_MS
    assert timer.dispatch_calls == []
    assert timer.unregistered == []
    timer.loaded = True

    assert timer.fire() == -1
    assert len(timer.dispatch_calls) == 1
    assert timer.dispatch_calls[0].request_id == "request-bootstrap"
    assert timer.unregistered == [timer.timer]
    assert _audit(filesystem)["status"] == "succeeded"

    assert timer.fire() == -1
    assert len(timer.dispatch_calls) == 1
    assert timer.unregistered == [timer.timer]
    assert session.finished is True


def test_mcp_starts_once_after_readiness_and_before_named_dispatch() -> None:
    bootstrap = _bootstrap()
    session, timer, filesystem = _session(
        bootstrap,
        document=_request_document(
            mcp_endpoint="http://127.0.0.1:13337/mcp",
        ),
    )
    timer.dispatch_result = _result(bootstrap)

    assert timer.fire() == bootstrap.POLL_INTERVAL_MS
    assert timer.events == []
    timer.loaded = True

    assert timer.fire() == -1
    assert timer.events == [
        "mcp-running",
        "mcp-start",
        "mcp-running",
        "dispatch",
    ]
    assert timer.mcp_start_calls == 1
    assert len(timer.dispatch_calls) == 1
    audit = _audit(filesystem)
    assert audit["status"] == "succeeded"
    assert audit["mcp_endpoint"] == "http://127.0.0.1:13337/mcp"

    assert timer.fire() == -1
    assert timer.mcp_start_calls == 1
    assert len(timer.dispatch_calls) == 1
    assert session.finished is True


def test_already_running_mcp_is_reused_without_restart() -> None:
    bootstrap = _bootstrap()
    _session_object, timer, filesystem = _session(
        bootstrap,
        document=_request_document(
            mcp_endpoint="http://127.0.0.1:14444/mcp",
        ),
    )
    timer.mcp_running_value = True
    timer.dispatch_result = _result(bootstrap)
    timer.loaded = True

    assert timer.fire() == -1

    assert timer.events == ["mcp-running", "dispatch"]
    assert timer.mcp_start_calls == 0
    assert len(timer.dispatch_calls) == 1
    assert _audit(filesystem)["mcp_endpoint"] == "http://127.0.0.1:14444/mcp"


def test_live_running_probe_reuses_server_started_by_loaded_mcp_plugin() -> None:
    bootstrap = _bootstrap()
    loaded_package = ModuleType("ida_mcp")
    loaded_package.MCP_SERVER = type("Server", (), {"_running": True})()
    previous = bootstrap.sys.modules.get("ida_mcp")
    bootstrap.sys.modules["ida_mcp"] = loaded_package
    try:
        assert bootstrap._live_mcp_running() is True
    finally:
        if previous is None:
            bootstrap.sys.modules.pop("ida_mcp", None)
        else:
            bootstrap.sys.modules["ida_mcp"] = previous


def test_live_mcp_start_uses_retained_headless_package_without_plugin_lifecycle(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    bootstrap = _bootstrap()
    events: list[object] = []

    class FakeServer:
        def __init__(self) -> None:
            self._running = False

        def serve(self, host: str, port: int, **kwargs: object) -> None:
            events.append(("serve", host, port, kwargs))
            self._running = True

    server = FakeServer()
    handler = type("IdaMcpHttpRequestHandler", (), {})
    package = ModuleType("ida_mcp")
    package.MCP_SERVER = server
    package.IdaMcpHttpRequestHandler = handler
    package.init_caches = lambda: events.append("init-caches")
    package.PLUGIN_ENTRY = lambda: pytest.fail("plugin entry must not be used")
    package.unload_package = lambda _name: pytest.fail("package must not be unloaded")

    def import_package(name: str) -> ModuleType:
        events.append(("import", name))
        assert name == "ida_mcp"
        return package

    monkeypatch.setattr(bootstrap.importlib, "import_module", import_package)
    monkeypatch.setattr(bootstrap.sys, "path", list(bootstrap.sys.path))
    monkeypatch.setenv("IDA_MCP_HOST", "0.0.0.0")
    monkeypatch.setenv("IDA_MCP_PORT", "13337")

    bootstrap._live_start_mcp()
    bootstrap._live_start_mcp()

    assert events == [
        ("import", "ida_mcp"),
        "init-caches",
        (
            "serve",
            "0.0.0.0",
            13337,
            {
                "background": True,
                "request_handler": handler,
            },
        ),
    ]
    assert bootstrap._D810_MCP_SERVER is server
    assert bootstrap._live_mcp_running() is True


def test_mcp_start_exception_is_a_terminal_failure_without_dispatch() -> None:
    bootstrap = _bootstrap()
    session, timer, filesystem = _session(
        bootstrap,
        document=_request_document(
            mcp_endpoint="http://127.0.0.1:13337/mcp",
        ),
    )
    timer.mcp_start_error = RuntimeError("server initialization exploded")
    timer.loaded = True

    assert timer.fire() == -1

    audit = _audit(filesystem)
    assert audit["status"] == "failed"
    assert audit["error"] == (
        "bootstrap MCP startup failed: server initialization exploded"
    )
    assert audit["commands"][0]["status"] == "failed"
    assert audit["mcp_endpoint"] == "http://127.0.0.1:13337/mcp"
    assert timer.mcp_start_calls == 1
    assert timer.dispatch_calls == []
    assert timer.unregistered == [timer.timer]
    assert session.finished is True


def test_mcp_start_must_report_running_before_dispatch() -> None:
    bootstrap = _bootstrap()
    _session_object, timer, filesystem = _session(
        bootstrap,
        document=_request_document(
            mcp_endpoint="http://127.0.0.1:13337/mcp",
        ),
    )

    def start_without_server() -> None:
        timer.events.append("mcp-start")
        timer.mcp_start_calls += 1

    timer.runtime.start_mcp = start_without_server
    timer.loaded = True

    assert timer.fire() == -1

    audit = _audit(filesystem)
    assert audit["status"] == "failed"
    assert audit["error"] == (
        "bootstrap MCP startup failed: MCP server did not report running"
    )
    assert timer.events == ["mcp-running", "mcp-start", "mcp-running"]
    assert timer.dispatch_calls == []


@pytest.mark.parametrize(
    "endpoint",
    (
        True,
        "https://127.0.0.1:13337/mcp",
        "http://0.0.0.0:13337/mcp",
        "http://127.0.0.1:80/mcp",
        "http://127.0.0.1:65536/mcp",
        "http://127.0.0.1:13337/config.html",
    ),
)
def test_mcp_endpoint_intent_is_strictly_loopback_http(endpoint: object) -> None:
    bootstrap = _bootstrap()

    with pytest.raises((TypeError, ValueError), match="MCP endpoint"):
        _session(
            bootstrap,
            document=_request_document(mcp_endpoint=endpoint),
        )


def test_live_mcp_path_uses_headless_package_without_plugin_lifecycle() -> None:
    source = BOOTSTRAP_PATH.read_text(encoding="utf-8")

    assert 'importlib.import_module("ida_mcp")' in source
    assert ".init_caches()" in source
    assert ".serve(" in source
    assert "PLUGIN_ENTRY" not in source
    assert "plugin.init()" not in source
    assert "plugin.start_server()" not in source
    assert "unload_package" not in source
    assert "McpConfigDialog" not in source
    assert "run_plugin" not in source
    assert "stop_server" not in source
    assert "unload_plugin" not in source


def test_success_audit_uses_schema_v1_and_atomic_replace() -> None:
    bootstrap = _bootstrap()
    _session_object, timer, filesystem = _session(bootstrap)
    timer.dispatch_result = _result(bootstrap)
    timer.loaded = True

    assert timer.fire() == -1

    audit = _audit(filesystem)
    assert audit["schema_version"] == 1
    assert audit["requested_commands"] == ["open-config"]
    assert audit["commands"][0]["details"] == {"widget_title": "D-810 Configuration"}
    audit_path = Path("/work/.tmp/ida-gui/automation-request-bootstrap.json")
    temporary_path = audit_path.with_name(f".{audit_path.name}.atomic.tmp")
    assert filesystem.writes == [temporary_path]
    assert filesystem.replacements == [(temporary_path, audit_path)]
    assert temporary_path not in filesystem.files


def test_structured_command_failure_is_written_without_lifecycle_side_effects() -> None:
    bootstrap = _bootstrap()
    _session_object, timer, filesystem = _session(bootstrap)
    timer.dispatch_result = _result(bootstrap, status="failed")
    timer.loaded = True

    assert timer.fire() == -1

    audit = _audit(filesystem)
    assert audit["status"] == "failed"
    assert audit["commands"][0]["status"] == "failed"
    assert audit["error"] == "command failed"
    assert timer.unregistered == [timer.timer]


def test_dispatch_exception_is_captured_as_a_structured_failed_audit() -> None:
    bootstrap = _bootstrap()
    _session_object, timer, filesystem = _session(
        bootstrap,
        document=_request_document(
            commands=["open-config", "open-workbench"],
            selector="target",
        ),
    )
    timer.dispatch_error = RuntimeError("adapter exploded")
    timer.loaded = True

    assert timer.fire() == -1

    audit = _audit(filesystem)
    assert audit["status"] == "failed"
    assert audit["error"] == "bootstrap dispatch failed: adapter exploded"
    assert [command["status"] for command in audit["commands"]] == [
        "failed",
        "failed",
    ]
    assert len(timer.dispatch_calls) == 1
    assert timer.unregistered == [timer.timer]


def test_unloaded_plugin_times_out_at_30_seconds_and_unregisters_timer() -> None:
    bootstrap = _bootstrap()
    session, timer, filesystem = _session(bootstrap)

    timer.now = 129.999
    assert timer.fire() == bootstrap.POLL_INTERVAL_MS
    assert timer.unregistered == []

    timer.now = 130.0
    assert timer.fire() == -1

    audit = _audit(filesystem)
    assert audit["status"] == "timed_out"
    assert audit["commands"][0]["status"] == "timed_out"
    assert audit["error"] == "timeout waiting for d810-ng plugin after 30 seconds"
    assert timer.dispatch_calls == []
    assert timer.unregistered == [timer.timer]
    assert session.finished is True
