"""Integration tests for the fixed loopback IDA MCP client."""

from __future__ import annotations

import ast
import base64
import http.client
import importlib.util
import json
import re
import socket
import sys
import threading
import time
from contextlib import contextmanager
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from types import ModuleType

import pytest

from d810.core import typing
from d810.ui import gui_automation_logic as gui_logic


REPO_ROOT = Path(__file__).resolve().parents[3]
CONNECTOR_PATH = REPO_ROOT / "tools" / "scripts" / "ida_gui_connect.py"


def _connector() -> ModuleType:
    if not CONNECTOR_PATH.is_file():
        pytest.fail(f"connector missing: {CONNECTOR_PATH}")
    spec = importlib.util.spec_from_file_location("ida_gui_connect", CONNECTOR_PATH)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _request(selector: str | int | None = "namespace::target") -> object:
    return gui_logic.GuiAutomationRequest(
        request_id="request-123",
        created_at_utc="2026-07-16T20:00:00Z",
        commands=gui_logic.ordered_commands(True, True),
        function_selector=selector,
        timeout_seconds=30.0,
    )


def _request_envelope(code: str) -> dict[str, object]:
    match = re.search(r'base64\.b64decode\("([A-Za-z0-9+/=]+)"\)', code)
    assert match is not None, code
    payload = base64.b64decode(match.group(1), validate=True)
    decoded = json.loads(payload.decode("utf-8"))
    assert isinstance(decoded, dict)
    return decoded


def _result_document(
    request: dict[str, object],
    *,
    status: str = "succeeded",
) -> dict[str, object]:
    command_status = status
    command_error = None if status == "succeeded" else f"command {status}"
    return {
        "request_id": request["request_id"],
        "completed_at_utc": "2026-07-16T20:00:01Z",
        "commands": [
            {
                "name": name,
                "started_at_utc": "2026-07-16T20:00:00Z",
                "finished_at_utc": "2026-07-16T20:00:01Z",
                "status": command_status,
                "details": {"widget_title": str(name)},
                "error": command_error,
            }
            for name in request["commands"]
        ],
        "status": status,
        "error": None if status == "succeeded" else f"one or more commands {status}",
    }


class _FakeMcpServer(ThreadingHTTPServer):
    daemon_threads = True

    def __init__(self, scenario: str) -> None:
        super().__init__(("127.0.0.1", 0), _FakeMcpHandler)
        self.scenario = scenario
        self.requests: list[dict[str, object]] = []


class _FakeMcpHandler(BaseHTTPRequestHandler):
    server: _FakeMcpServer

    def log_message(self, format: str, *args: object) -> None:
        del format, args

    def do_POST(self) -> None:
        assert self.path == "/mcp"
        body = self.rfile.read(int(self.headers["Content-Length"]))
        request = json.loads(body.decode("utf-8"))
        assert isinstance(request, dict)
        self.server.requests.append(request)

        if request["method"] == "tools/call" and self.server.scenario == "timeout":
            time.sleep(0.2)
        if request["method"] == "tools/call" and self.server.scenario == "http-error":
            self.send_error(503, "fake unavailable")
            return
        if request["method"] == "tools/call" and self.server.scenario == "redirect":
            self.send_response(302)
            self.send_header("Location", "http://192.0.2.1:1/mcp")
            self.send_header("Content-Length", "0")
            self.end_headers()
            return
        if (
            request["method"] == "tools/call"
            and self.server.scenario == "malformed-json"
        ):
            self._write(200, b"{")
            return
        if request["method"] == "tools/call" and self.server.scenario == "slow-header":
            try:
                self.connection.sendall(b"HTTP/1.1 200 OK\r\nX-Slow: ")
                for _ in range(20):
                    self.connection.sendall(b"x")
                    time.sleep(0.02)
            except (BrokenPipeError, ConnectionResetError, OSError):
                pass
            return
        if (
            request["method"] == "initialize"
            and self.server.scenario == "duplicate-key"
        ):
            self._write(
                200,
                b'{"jsonrpc":"2.0","id":1,"id":1,"result":{}}',
            )
            return
        if request["method"] == "initialize" and self.server.scenario == "non-finite":
            self._write(
                200,
                b'{"jsonrpc":"2.0","id":1,"result":{"value":NaN}}',
            )
            return
        if request["method"] == "initialize" and self.server.scenario in (
            "positive-overflow",
            "negative-overflow",
        ):
            number = (
                b"1e400" if self.server.scenario == "positive-overflow" else b"-1e400"
            )
            self._write(
                200,
                b'{"jsonrpc":"2.0","id":1,"result":'
                b'{"protocolVersion":"2025-06-18","capabilities":{"value":'
                + number
                + b'},"serverInfo":{"name":"fake-ida","version":"1"}}}',
            )
            return
        if request["method"] == "initialize" and self.server.scenario == "deep-json":
            nested = b"[" * 10_000 + b"0" + b"]" * 10_000
            self._write(
                200,
                b'{"jsonrpc":"2.0","id":1,"result":' + nested + b"}",
            )
            return

        if request["method"] == "initialize":
            result: object = {
                "protocolVersion": "2025-06-18",
                "capabilities": {"tools": {}},
                "serverInfo": {"name": "fake-ida", "version": "1"},
            }
        elif request["method"] == "ping":
            result = {}
        else:
            params = request["params"]
            assert isinstance(params, dict)
            arguments = params["arguments"]
            assert isinstance(arguments, dict)
            code = arguments["code"]
            assert isinstance(code, str)
            envelope = _request_envelope(code)
            result_document = _result_document(
                envelope,
                status=(
                    "failed"
                    if self.server.scenario == "command-failure"
                    else "succeeded"
                ),
            )
            self._apply_contradictory_result(self.server.scenario, result_document)
            if self.server.scenario == "tool-error":
                result = {
                    "content": [{"type": "text", "text": "fake tool failure"}],
                    "isError": True,
                }
            else:
                if self.server.scenario == "invalid-result":
                    result_document.pop("commands")
                stderr = "remote traceback" if self.server.scenario == "stderr" else ""
                result = {
                    "content": [{"type": "text", "text": "structured below"}],
                    "structuredContent": {
                        "result": json.dumps(result_document, sort_keys=True),
                        "stdout": "",
                        "stderr": stderr,
                    },
                    "isError": False,
                }
        response_id = request["id"]
        if request["method"] == "initialize" and self.server.scenario == "boolean-id":
            response_id = True
        if request["method"] == "initialize" and self.server.scenario == "float-id":
            response_id = 1.0
        response = json.dumps(
            {"jsonrpc": "2.0", "id": response_id, "result": result}
        ).encode("utf-8")
        try:
            if (
                request["method"] == "tools/call"
                and self.server.scenario == "slow-drip"
            ):
                self._write_slow(200, response)
            else:
                self._write(200, response)
        except BrokenPipeError:
            pass

    @staticmethod
    def _apply_contradictory_result(
        scenario: str,
        result: dict[str, object],
    ) -> None:
        commands = result["commands"]
        assert isinstance(commands, list)
        if scenario == "command-success-error":
            commands[0]["error"] = "unexpected error"
        elif scenario == "command-failed-no-error":
            result.update(status="failed", error="one or more commands failed")
            for command in commands:
                command.update(status="failed", error=None)
        elif scenario == "command-timed-out-no-error":
            result.update(status="timed_out", error="one or more commands timed out")
            for command in commands:
                command.update(status="timed_out", error="")
        elif scenario == "aggregate-success-error":
            result["error"] = "unexpected aggregate error"
        elif scenario == "aggregate-failed-no-error":
            result.update(status="failed", error=None)
            for command in commands:
                command.update(status="failed", error="command failed")
        elif scenario == "aggregate-timed-out-no-error":
            result.update(status="timed_out", error="")
            for command in commands:
                command.update(status="timed_out", error="command timed out")

    def _write(self, status: int, body: bytes) -> None:
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _write_slow(self, status: int, body: bytes) -> None:
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        for offset in range(0, len(body), 64):
            self.wfile.write(body[offset : offset + 64])
            self.wfile.flush()
            time.sleep(0.02)


@contextmanager
def _fake_server(scenario: str = "success") -> typing.Iterator[_FakeMcpServer]:
    server = _FakeMcpServer(scenario)
    thread = threading.Thread(
        target=server.serve_forever,
        kwargs={"poll_interval": 0.01},
        daemon=True,
    )
    thread.start()
    try:
        yield server
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=1)


def _endpoint(server: _FakeMcpServer) -> str:
    return f"http://127.0.0.1:{server.server_port}/mcp"


def test_client_uses_exact_rpc_sequence_and_writes_atomic_schema_v1_audit(
    tmp_path: Path,
) -> None:
    connector = _connector()
    request = _request()
    audit_dir = tmp_path / ".tmp" / "ida-gui"
    with _fake_server() as server:
        result, audit_path = connector.connect_named_commands(
            request,
            endpoint=_endpoint(server),
            worktree=tmp_path,
            audit_dir=audit_dir,
            http_timeout=0.5,
        )

    assert [item["method"] for item in server.requests] == [
        "initialize",
        "ping",
        "tools/call",
    ]
    assert [item["id"] for item in server.requests] == [1, 2, 3]
    assert server.requests[0] == {
        "jsonrpc": "2.0",
        "id": 1,
        "method": "initialize",
        "params": {
            "protocolVersion": "2025-06-18",
            "capabilities": {},
            "clientInfo": {"name": "d810-gui-connect", "version": "1"},
        },
    }
    assert server.requests[1] == {
        "jsonrpc": "2.0",
        "id": 2,
        "method": "ping",
    }
    tool_request = server.requests[2]
    assert tool_request["params"]["name"] == "py_eval"
    assert set(tool_request["params"]["arguments"]) == {"code"}
    assert result.status == "succeeded"
    assert connector.result_exit_code(result) == 0
    assert audit_path == audit_dir / "automation-request-123.json"
    audit = json.loads(audit_path.read_text(encoding="utf-8"))
    assert audit["schema_version"] == 1
    assert audit["mode"] == "connect"
    assert audit["worktree"] == str(tmp_path)
    assert audit["idb"] == {"path": None, "sha256": None}
    assert audit["mcp_endpoint"] == _endpoint(server)
    assert audit["requested_commands"] == ["open-config", "open-workbench"]
    assert list(audit_dir.glob("*.tmp")) == []


def test_selector_is_validated_data_and_never_plaintext_remote_source() -> None:
    connector = _connector()
    selector = "?target@@YAXXZ"
    request = _request(selector)

    code = connector.build_remote_code(request)
    envelope = _request_envelope(code)

    assert selector not in code
    assert envelope["function_selector"] == selector
    assert envelope["commands"] == ["open-config", "open-workbench"]
    assert "py_eval" not in code
    assert "action_id" not in code
    assert "PLUGIN_ENTRY" not in code


def test_fixed_remote_template_has_only_approved_import_and_dispatch_boundary() -> None:
    connector = _connector()
    code = connector.build_remote_code(_request())
    tree = ast.parse(code)
    imports = {
        alias.name
        for node in ast.walk(tree)
        if isinstance(node, ast.Import)
        for alias in node.names
    }
    imports_from = {
        (node.module, tuple(alias.name for alias in node.names))
        for node in ast.walk(tree)
        if isinstance(node, ast.ImportFrom)
    }

    assert imports == {"base64", "json"}
    assert imports_from == {
        ("d810.ui.gui_automation", ("run_named_commands",)),
        (
            "d810.ui.gui_automation_logic",
            ("GuiAutomationRequest", "GuiCommand"),
        ),
    }
    assert "base64.b64decode" in code
    assert "json.loads" in code
    assert code.count("run_named_commands(") == 1
    assert "json.dumps" in code
    compile(code, "<fixed-d810-gui-connect>", "exec")


def test_fixed_remote_template_runs_under_mcp_split_exec_namespaces(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    connector = _connector()
    request = _request()
    captured: list[gui_logic.GuiAutomationRequest] = []

    def run_named_commands(
        remote_request: gui_logic.GuiAutomationRequest,
    ) -> gui_logic.GuiAutomationResult:
        captured.append(remote_request)
        commands = tuple(
            gui_logic.GuiCommandResult(
                name=command,
                started_at_utc="2026-07-16T20:00:00Z",
                finished_at_utc="2026-07-16T20:00:01Z",
                status="succeeded",
                details={"widget_title": command.value},
                error=None,
            )
            for command in remote_request.commands
        )
        return gui_logic.GuiAutomationResult(
            request_id=remote_request.request_id,
            completed_at_utc="2026-07-16T20:00:01Z",
            commands=commands,
            status="succeeded",
            error=None,
        )

    adapter = ModuleType("d810.ui.gui_automation")
    adapter.run_named_commands = run_named_commands
    monkeypatch.setitem(sys.modules, "d810.ui.gui_automation", adapter)

    code = connector.build_remote_code(request)
    tree = ast.parse(code)
    assert isinstance(tree.body[-1], ast.Expr)
    exec_tree = ast.Module(body=tree.body[:-1], type_ignores=[])
    exec_globals: dict[str, object] = {}
    exec_locals: dict[str, object] = {}

    exec(compile(exec_tree, "<mcp-py-eval>", "exec"), exec_globals, exec_locals)
    exec_globals.update(exec_locals)
    eval_tree = ast.Expression(body=tree.body[-1].value)
    result = eval(compile(eval_tree, "<mcp-py-eval>", "eval"), exec_globals)

    assert captured == [request]
    document = json.loads(result)
    assert document["request_id"] == request.request_id
    assert [command["name"] for command in document["commands"]] == [
        "open-config",
        "open-workbench",
    ]


@pytest.mark.parametrize(
    "endpoint",
    (
        "https://127.0.0.1:13337/mcp",
        "http://192.0.2.1:13337/mcp",
        "http://127.0.0.2:13337/mcp",
        "http://user@localhost:13337/mcp",
        "http://localhost:13337/mcp?ext=dbg",
        "http://localhost:13337/mcp#fragment",
        "http://localhost:13337/sse",
        "http://localhost:13337/mcp/",
        "http://localhost:99999/mcp",
    ),
)
def test_endpoint_rejects_every_non_fixed_loopback_form(endpoint: str) -> None:
    with pytest.raises(ValueError, match="loopback HTTP"):
        _connector().validate_endpoint(endpoint)


@pytest.mark.parametrize(
    "endpoint",
    (
        "http://127.0.0.1:13337/mcp",
        "http://localhost/mcp",
        "http://[::1]:13337/mcp",
    ),
)
def test_endpoint_accepts_only_fixed_loopback_http_forms(endpoint: str) -> None:
    assert _connector().validate_endpoint(endpoint) == endpoint


def test_localhost_resolution_is_pinned_once_to_a_deterministic_numeric_loopback() -> (
    None
):
    connector = _connector()
    calls: list[tuple[str, int, int]] = []

    def resolver(host: str, port: int, *, type: int) -> list[tuple[object, ...]]:
        calls.append((host, port, type))
        return [
            (socket.AF_INET6, socket.SOCK_STREAM, 6, "", ("::1", port, 0, 0)),
            (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("127.0.0.1", port)),
            (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("127.0.0.1", port)),
        ]

    resolved = connector.resolve_endpoint(
        "http://localhost:13337/mcp",
        resolver=resolver,
    )

    assert resolved == "http://127.0.0.1:13337/mcp"
    assert calls == [("localhost", 13337, socket.SOCK_STREAM)]


def test_localhost_resolution_rejects_mixed_loopback_and_non_loopback_answers() -> None:
    connector = _connector()

    def resolver(host: str, port: int, *, type: int) -> list[tuple[object, ...]]:
        del host, type
        return [
            (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("127.0.0.1", port)),
            (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("192.0.2.1", port)),
        ]

    with pytest.raises(connector.McpClientError, match="only to loopback"):
        connector.resolve_endpoint(
            "http://localhost:13337/mcp",
            resolver=resolver,
        )


def test_localhost_connection_uses_resolved_numeric_endpoint_but_audits_original(
    tmp_path: Path,
) -> None:
    connector = _connector()
    calls: list[tuple[str, int, int]] = []
    with _fake_server() as server:
        endpoint = f"http://localhost:{server.server_port}/mcp"

        def resolver(host: str, port: int, *, type: int) -> list[tuple[object, ...]]:
            calls.append((host, port, type))
            return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("127.0.0.1", port))]

        result, audit_path = connector.connect_named_commands(
            _request(),
            endpoint=endpoint,
            worktree=tmp_path,
            audit_dir=tmp_path / ".tmp" / "ida-gui",
            http_timeout=0.5,
            resolver=resolver,
        )

    assert result.status == "succeeded"
    assert calls == [("localhost", server.server_port, socket.SOCK_STREAM)]
    audit = json.loads(audit_path.read_text(encoding="utf-8"))
    assert audit["mcp_endpoint"] == endpoint


def test_blocking_localhost_resolver_is_bounded_by_the_overall_deadline(
    tmp_path: Path,
) -> None:
    connector = _connector()
    release = threading.Event()
    finished = threading.Event()
    calls = 0

    def resolver(host: str, port: int, *, type: int) -> list[tuple[object, ...]]:
        nonlocal calls
        calls += 1
        assert (host, type) == ("localhost", socket.SOCK_STREAM)
        try:
            release.wait(timeout=0.35)
            return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("127.0.0.1", port))]
        finally:
            finished.set()

    started = time.monotonic()
    try:
        with _fake_server() as server:
            with pytest.raises(connector.McpClientError, match="resolution timed out"):
                connector.connect_named_commands(
                    _request(),
                    endpoint=f"http://localhost:{server.server_port}/mcp",
                    worktree=tmp_path,
                    audit_dir=tmp_path / ".tmp" / "ida-gui",
                    http_timeout=0.08,
                    resolver=resolver,
                )
            assert server.requests == []
    finally:
        release.set()
    elapsed = time.monotonic() - started

    assert finished.wait(timeout=0.25)
    assert elapsed < 0.25
    assert calls == 1


@pytest.mark.parametrize(
    "endpoint",
    (
        "\nhttp://127.0.0.1:13337/mcp",
        "http://127.0.0.1:13337/mcp\t",
        "http://127.0.0.1:13337/\x7fmcp",
    ),
)
def test_endpoint_rejects_ascii_controls_and_del_before_url_parsing(
    endpoint: str,
) -> None:
    with pytest.raises(ValueError, match="loopback HTTP"):
        _connector().validate_endpoint(endpoint)


def test_endpoint_requires_canonical_url_round_trip() -> None:
    with pytest.raises(ValueError, match="loopback HTTP"):
        _connector().validate_endpoint("HTTP://127.0.0.1:13337/mcp")


@pytest.mark.parametrize(
    ("scenario", "message"),
    (
        ("tool-error", "fake tool failure"),
        ("malformed-json", "valid JSON"),
        ("http-error", "HTTP 503"),
        ("redirect", "HTTP 302"),
        ("timeout", "timed out"),
        ("invalid-result", "result fields"),
        ("stderr", "remote traceback"),
    ),
)
def test_client_rejects_transport_tool_and_structured_result_failures_without_retry(
    tmp_path: Path,
    scenario: str,
    message: str,
) -> None:
    connector = _connector()
    with _fake_server(scenario) as server:
        with pytest.raises(connector.McpClientError, match=message):
            connector.connect_named_commands(
                _request(),
                endpoint=_endpoint(server),
                worktree=tmp_path,
                audit_dir=tmp_path / ".tmp" / "ida-gui",
                http_timeout=0.03 if scenario == "timeout" else 0.5,
            )

    assert [item["method"] for item in server.requests] == [
        "initialize",
        "ping",
        "tools/call",
    ]
    assert not (tmp_path / ".tmp" / "ida-gui").exists()


def test_valid_command_failure_is_audited_and_returns_nonzero(tmp_path: Path) -> None:
    connector = _connector()
    with _fake_server("command-failure") as server:
        result, audit_path = connector.connect_named_commands(
            _request(),
            endpoint=_endpoint(server),
            worktree=tmp_path,
            audit_dir=tmp_path / ".tmp" / "ida-gui",
            http_timeout=0.5,
        )

    assert result.status == "failed"
    assert connector.result_exit_code(result) == 1
    assert json.loads(audit_path.read_text(encoding="utf-8"))["status"] == "failed"
    assert [item["method"] for item in server.requests].count("tools/call") == 1


def test_slow_drip_response_cannot_extend_rpc_past_total_deadline(
    tmp_path: Path,
) -> None:
    connector = _connector()
    started = time.monotonic()
    with _fake_server("slow-drip") as server:
        with pytest.raises(connector.McpClientError, match="timed out"):
            connector.connect_named_commands(
                _request(),
                endpoint=_endpoint(server),
                worktree=tmp_path,
                audit_dir=tmp_path / ".tmp" / "ida-gui",
                http_timeout=0.08,
            )
    elapsed = time.monotonic() - started

    assert elapsed < 0.3
    assert [item["method"] for item in server.requests] == [
        "initialize",
        "ping",
        "tools/call",
    ]


def test_slow_incomplete_response_headers_cannot_extend_overall_deadline(
    tmp_path: Path,
) -> None:
    connector = _connector()
    started = time.monotonic()
    with _fake_server("slow-header") as server:
        with pytest.raises(connector.McpClientError, match="timed out"):
            connector.connect_named_commands(
                _request(),
                endpoint=_endpoint(server),
                worktree=tmp_path,
                audit_dir=tmp_path / ".tmp" / "ida-gui",
                http_timeout=0.08,
            )
    elapsed = time.monotonic() - started

    assert elapsed < 0.25
    assert [item["method"] for item in server.requests] == [
        "initialize",
        "ping",
        "tools/call",
    ]
    assert [item["method"] for item in server.requests].count("tools/call") == 1


@pytest.mark.parametrize("scenario", ("boolean-id", "float-id"))
def test_response_id_must_be_an_exact_builtin_integer(
    tmp_path: Path,
    scenario: str,
) -> None:
    connector = _connector()
    with _fake_server(scenario) as server:
        with pytest.raises(connector.McpClientError, match="JSON-RPC identity"):
            connector.connect_named_commands(
                _request(),
                endpoint=_endpoint(server),
                worktree=tmp_path,
                audit_dir=tmp_path / ".tmp" / "ida-gui",
                http_timeout=0.5,
            )

    assert [item["method"] for item in server.requests] == ["initialize"]


@pytest.mark.parametrize(
    "scenario",
    (
        "command-success-error",
        "command-failed-no-error",
        "command-timed-out-no-error",
        "aggregate-success-error",
        "aggregate-failed-no-error",
        "aggregate-timed-out-no-error",
    ),
)
def test_status_error_invariants_reject_contradictory_results(
    tmp_path: Path,
    scenario: str,
) -> None:
    connector = _connector()
    with _fake_server(scenario) as server:
        with pytest.raises(connector.McpClientError, match="error invariant"):
            connector.connect_named_commands(
                _request(),
                endpoint=_endpoint(server),
                worktree=tmp_path,
                audit_dir=tmp_path / ".tmp" / "ida-gui",
                http_timeout=0.5,
            )


@pytest.mark.parametrize("scenario", ("duplicate-key", "non-finite"))
def test_response_json_rejects_duplicate_keys_and_non_finite_numbers(
    tmp_path: Path,
    scenario: str,
) -> None:
    connector = _connector()
    with _fake_server(scenario) as server:
        with pytest.raises(connector.McpClientError, match="not valid JSON"):
            connector.connect_named_commands(
                _request(),
                endpoint=_endpoint(server),
                worktree=tmp_path,
                audit_dir=tmp_path / ".tmp" / "ida-gui",
                http_timeout=0.5,
            )

    assert [item["method"] for item in server.requests] == ["initialize"]


@pytest.mark.parametrize("scenario", ("positive-overflow", "negative-overflow"))
def test_response_json_rejects_exponent_overflow_as_non_finite(
    tmp_path: Path,
    scenario: str,
) -> None:
    connector = _connector()
    with _fake_server(scenario) as server:
        with pytest.raises(connector.McpClientError, match="non-finite JSON number"):
            connector.connect_named_commands(
                _request(),
                endpoint=_endpoint(server),
                worktree=tmp_path,
                audit_dir=tmp_path / ".tmp" / "ida-gui",
                http_timeout=0.5,
            )

    assert [item["method"] for item in server.requests] == ["initialize"]


def test_deeply_nested_response_json_is_normalized_as_a_client_error(
    tmp_path: Path,
) -> None:
    connector = _connector()
    with _fake_server("deep-json") as server:
        with pytest.raises(connector.McpClientError, match="not valid JSON"):
            connector.connect_named_commands(
                _request(),
                endpoint=_endpoint(server),
                worktree=tmp_path,
                audit_dir=tmp_path / ".tmp" / "ida-gui",
                http_timeout=0.5,
            )

    assert [item["method"] for item in server.requests] == ["initialize"]


def test_http_connection_exceptions_are_normalized_as_client_errors() -> None:
    connector = _connector()

    def invalid_connection(*args: object, **kwargs: object) -> object:
        del args, kwargs
        raise http.client.InvalidURL("invalid transport URL")

    with pytest.raises(connector.McpClientError, match="request failed during ping"):
        connector._post_json(
            "http://127.0.0.1:13337/mcp",
            {"jsonrpc": "2.0", "id": 2, "method": "ping"},
            timeout=0.5,
            connection_factory=invalid_connection,
        )


def test_injected_clock_and_connection_receive_decreasing_phase_deadlines() -> None:
    connector = _connector()
    timeouts: list[float] = []
    current = 0.0

    def clock() -> float:
        nonlocal current
        current += 0.01
        return current

    class FakeSocket:
        def settimeout(self, value: float) -> None:
            timeouts.append(value)

    class FakeResponse:
        status = 200

        def __init__(self) -> None:
            self.closed = False

        def isclosed(self) -> bool:
            return self.closed

        def read1(self, amount: int) -> bytes:
            assert amount > 0
            self.closed = True
            return b"{}"

        def close(self) -> None:
            self.closed = True

    class FakeConnection:
        def __init__(self, host: str, port: int, *, timeout: float) -> None:
            assert (host, port) == ("127.0.0.1", 13337)
            timeouts.append(timeout)
            self.sock = FakeSocket()

        def connect(self) -> None:
            pass

        def request(self, *args: object, **kwargs: object) -> None:
            del args, kwargs

        def getresponse(self) -> FakeResponse:
            return FakeResponse()

        def close(self) -> None:
            pass

    content = connector._post_json(
        "http://127.0.0.1:13337/mcp",
        {"jsonrpc": "2.0", "id": 2, "method": "ping"},
        timeout=1.0,
        connection_factory=FakeConnection,
        clock=clock,
    )

    assert content == b"{}"
    assert len(timeouts) >= 5
    assert all(left > right for left, right in zip(timeouts, timeouts[1:]))
