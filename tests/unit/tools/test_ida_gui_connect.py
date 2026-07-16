"""Integration tests for the fixed loopback IDA MCP client."""

from __future__ import annotations

import ast
import base64
import importlib.util
import json
import re
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
    command_status = "succeeded" if status == "succeeded" else "failed"
    command_error = None if status == "succeeded" else "command failed"
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
        "error": None if status == "succeeded" else "one or more commands failed",
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
        response = json.dumps(
            {"jsonrpc": "2.0", "id": request["id"], "result": result}
        ).encode("utf-8")
        try:
            self._write(200, response)
        except BrokenPipeError:
            pass

    def _write(self, status: int, body: bytes) -> None:
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


@contextmanager
def _fake_server(scenario: str = "success") -> typing.Iterator[_FakeMcpServer]:
    server = _FakeMcpServer(scenario)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
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
