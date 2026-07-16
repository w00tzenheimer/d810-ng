#!/usr/bin/env python3
"""Run closed D810 GUI commands through an existing loopback IDA MCP server."""

from __future__ import annotations

import argparse
import base64
import datetime
import http.client
import ipaddress
import json
import math
import os
import pathlib
import secrets
import socket
import sys
import tempfile
import threading
import time
import urllib.parse
from collections.abc import Callable, Mapping, Sequence

from d810.ui import gui_automation_logic as gui_logic


DEFAULT_ENDPOINT = "http://127.0.0.1:13337/mcp"
HTTP_TIMEOUT_SECONDS = 5.0
MAX_RESPONSE_BYTES = 4 * 1024 * 1024
MCP_PROTOCOL_VERSION = "2025-06-18"

REMOTE_CODE_TEMPLATE = """import base64
import json

from d810.ui.gui_automation import run_named_commands
from d810.ui.gui_automation_logic import GuiAutomationRequest, GuiCommand

_request_data = json.loads(
    base64.b64decode("__D810_REQUEST_B64__").decode("utf-8")
)
_request = GuiAutomationRequest(
    request_id=_request_data["request_id"],
    created_at_utc=_request_data["created_at_utc"],
    commands=tuple(map(GuiCommand, _request_data["commands"])),
    function_selector=_request_data["function_selector"],
    timeout_seconds=_request_data["timeout_seconds"],
)
_result = run_named_commands(_request)
json.dumps(
    {
        "request_id": _result.request_id,
        "completed_at_utc": _result.completed_at_utc,
        "commands": [
            {
                "name": command.name.value,
                "started_at_utc": command.started_at_utc,
                "finished_at_utc": command.finished_at_utc,
                "status": command.status,
                "details": command.details,
                "error": command.error,
            }
            for command in _result.commands
        ],
        "status": _result.status,
        "error": _result.error,
    },
    allow_nan=False,
    default=dict,
    sort_keys=True,
)
"""


class McpClientError(RuntimeError):
    """The fixed MCP exchange failed before a typed result was available."""


_ENDPOINT_ERROR = "MCP endpoint must use loopback HTTP and the exact /mcp path"
_AddressInfo = tuple[object, object, object, object, tuple[object, ...]]
_Resolver = Callable[..., Sequence[_AddressInfo]]
_ConnectionFactory = Callable[..., http.client.HTTPConnection]
_Clock = Callable[[], float]


def _run_with_deadline(
    operation: Callable[[], object],
    *,
    deadline: float,
    clock: _Clock,
    timeout_message: str,
    cancel: Callable[[], None] | None = None,
) -> object:
    """Bound one blocking standard-library operation by an absolute deadline."""
    completed = threading.Event()
    outcome: dict[str, object] = {}

    def run() -> None:
        try:
            outcome["value"] = operation()
        except BaseException as exc:
            outcome["error"] = exc
        finally:
            completed.set()

    remaining = deadline - clock()
    if remaining <= 0:
        raise McpClientError(timeout_message)
    worker = threading.Thread(target=run, daemon=True, name="d810-mcp-deadline")
    worker.start()
    if not completed.wait(timeout=remaining):
        if cancel is not None:
            try:
                cancel()
            except OSError:
                pass
        raise McpClientError(timeout_message)
    if clock() >= deadline:
        if cancel is not None:
            try:
                cancel()
            except OSError:
                pass
        raise McpClientError(timeout_message)
    error = outcome.get("error")
    if isinstance(error, BaseException):
        raise error
    return outcome.get("value")


def _parse_endpoint(endpoint: str) -> urllib.parse.SplitResult:
    if type(endpoint) is not str:
        raise TypeError("MCP endpoint must be a string")
    if any(ord(character) < 32 or ord(character) == 127 for character in endpoint):
        raise ValueError(_ENDPOINT_ERROR)
    try:
        parsed = urllib.parse.urlsplit(endpoint)
        port = parsed.port
        host = parsed.hostname
        canonical = urllib.parse.urlunsplit(
            (parsed.scheme, parsed.netloc, parsed.path, parsed.query, parsed.fragment)
        )
    except (UnicodeError, ValueError) as exc:
        raise ValueError(_ENDPOINT_ERROR) from exc

    expected_authority = ""
    if host in ("127.0.0.1", "localhost"):
        expected_authority = host if port is None else f"{host}:{port}"
    elif host == "::1":
        expected_authority = "[::1]" if port is None else f"[::1]:{port}"

    if (
        endpoint != canonical
        or parsed.scheme != "http"
        or not expected_authority
        or parsed.netloc != expected_authority
        or parsed.username is not None
        or parsed.password is not None
        or parsed.path != "/mcp"
        or parsed.query
        or parsed.fragment
        or (port is not None and not 1 <= port <= 65535)
    ):
        raise ValueError(_ENDPOINT_ERROR)
    return parsed


def validate_endpoint(endpoint: str) -> str:
    """Accept only canonical HTTP loopback authorities and the exact MCP path."""
    _parse_endpoint(endpoint)
    return endpoint


def resolve_endpoint(
    endpoint: str,
    *,
    resolver: _Resolver = socket.getaddrinfo,
    deadline: float | None = None,
    clock: _Clock = time.monotonic,
) -> str:
    """Pin a localhost endpoint once and return a canonical numeric URL."""
    parsed = _parse_endpoint(endpoint)
    host = parsed.hostname
    if host is None:
        raise McpClientError("MCP endpoint has no host")
    try:
        numeric = ipaddress.ip_address(host)
    except ValueError:
        numeric = None
    if numeric is not None:
        if not numeric.is_loopback:
            raise McpClientError("MCP endpoint must resolve only to loopback addresses")
    else:
        if host != "localhost":
            raise McpClientError("MCP endpoint host is not an approved loopback")
        port = parsed.port if parsed.port is not None else 80
        try:
            if deadline is None:
                answers = resolver(host, port, type=socket.SOCK_STREAM)
            else:
                answers = _run_with_deadline(
                    lambda: resolver(host, port, type=socket.SOCK_STREAM),
                    deadline=deadline,
                    clock=clock,
                    timeout_message="MCP endpoint resolution timed out",
                )
            if not isinstance(answers, Sequence):
                raise TypeError("resolver did not return an address sequence")
            candidates: set[ipaddress.IPv4Address | ipaddress.IPv6Address] = set()
            for answer in answers:
                family = answer[0]
                raw_address = answer[4][0]
                if type(raw_address) is not str or "%" in raw_address:
                    raise ValueError("non-canonical address")
                address = ipaddress.ip_address(raw_address)
                if family == socket.AF_INET and address.version != 4:
                    raise ValueError("address family mismatch")
                if family == socket.AF_INET6 and address.version != 6:
                    raise ValueError("address family mismatch")
                if family not in (socket.AF_INET, socket.AF_INET6):
                    raise ValueError("unsupported address family")
                if not address.is_loopback:
                    raise McpClientError(
                        "MCP endpoint must resolve only to loopback addresses"
                    )
                candidates.add(address)
        except McpClientError:
            raise
        except (IndexError, OSError, TypeError, ValueError) as exc:
            raise McpClientError(f"MCP endpoint resolution failed: {exc}") from exc
        if not candidates:
            raise McpClientError("MCP endpoint resolution returned no addresses")
        numeric = min(candidates, key=lambda value: (value.version, int(value)))

    authority = f"[{numeric}]" if numeric.version == 6 else str(numeric)
    if parsed.port is not None:
        authority = f"{authority}:{parsed.port}"
    return urllib.parse.urlunsplit(("http", authority, "/mcp", "", ""))


def _request_document(request: gui_logic.GuiAutomationRequest) -> dict[str, object]:
    if not isinstance(request, gui_logic.GuiAutomationRequest):
        raise TypeError("request must be a GuiAutomationRequest")
    return {
        "request_id": request.request_id,
        "created_at_utc": request.created_at_utc,
        "commands": [command.value for command in request.commands],
        "function_selector": request.function_selector,
        "timeout_seconds": request.timeout_seconds,
    }


def build_remote_code(request: gui_logic.GuiAutomationRequest) -> str:
    """Encode validated request data into the sole fixed remote source template."""
    payload = json.dumps(
        _request_document(request),
        allow_nan=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")
    encoded = base64.b64encode(payload).decode("ascii")
    return REMOTE_CODE_TEMPLATE.replace("__D810_REQUEST_B64__", encoded)


def _reject_json_constant(value: str) -> object:
    raise ValueError(f"non-finite JSON number: {value}")


def _strict_json_float(value: str) -> float:
    number = float(value)
    if not math.isfinite(number):
        raise ValueError(f"non-finite JSON number: {value}")
    return number


def _strict_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"duplicate JSON object key: {key}")
        result[key] = value
    return result


def _load_json(content: bytes | str, description: str) -> object:
    try:
        if isinstance(content, bytes):
            content = content.decode("utf-8")
        return json.loads(
            content,
            object_pairs_hook=_strict_object,
            parse_constant=_reject_json_constant,
            parse_float=_strict_json_float,
        )
    except (RecursionError, UnicodeDecodeError, ValueError) as exc:
        raise McpClientError(f"{description} is not valid JSON: {exc}") from exc


def _post_json(
    endpoint: str,
    document: dict[str, object],
    *,
    timeout: float | None = None,
    deadline: float | None = None,
    connection_factory: _ConnectionFactory = http.client.HTTPConnection,
    clock: _Clock = time.monotonic,
) -> bytes:
    method = document["method"]
    body = json.dumps(
        document,
        allow_nan=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")
    try:
        parsed = _parse_endpoint(endpoint)
        host = parsed.hostname
        if host is None or ipaddress.ip_address(host).is_loopback is not True:
            raise ValueError("transport endpoint is not numeric loopback")
        port = parsed.port if parsed.port is not None else 80
    except (TypeError, ValueError) as exc:
        raise McpClientError(f"MCP {method} transport URL is invalid: {exc}") from exc

    if deadline is None:
        if timeout is None:
            raise TypeError("MCP request requires a timeout or absolute deadline")
        deadline = clock() + timeout
    elif timeout is not None:
        raise TypeError("MCP request accepts only one deadline source")

    holder_lock = threading.Lock()
    holder: dict[str, object] = {}
    cancelled = threading.Event()

    def set_remaining_timeout(transport: socket.socket) -> None:
        if cancelled.is_set():
            raise McpClientError(f"MCP {method} timed out")
        remaining = deadline - clock()
        if remaining <= 0:
            raise McpClientError(f"MCP {method} timed out")
        transport.settimeout(remaining)

    def cancel() -> None:
        cancelled.set()
        with holder_lock:
            transport = holder.get("transport")
            connection = holder.get("connection")
        shutdown = getattr(transport, "shutdown", None)
        if callable(shutdown):
            try:
                shutdown(socket.SHUT_RDWR)
            except (OSError, ValueError):
                pass
        close_transport = getattr(transport, "close", None)
        if callable(close_transport):
            try:
                close_transport()
            except (OSError, ValueError):
                pass
        close_connection = getattr(connection, "close", None)
        if callable(close_connection):
            try:
                close_connection()
            except (OSError, ValueError):
                pass

    def exchange() -> object:
        connection: http.client.HTTPConnection | None = None
        response: http.client.HTTPResponse | None = None
        try:
            remaining = deadline - clock()
            if remaining <= 0:
                raise McpClientError(f"MCP {method} timed out")
            connection = connection_factory(
                host,
                port,
                timeout=remaining,
            )
            with holder_lock:
                holder["connection"] = connection
            if cancelled.is_set():
                raise McpClientError(f"MCP {method} timed out")
            connection.connect()
            transport = connection.sock
            if transport is None:
                raise McpClientError(f"MCP request failed during {method}: no socket")
            with holder_lock:
                holder["transport"] = transport

            set_remaining_timeout(transport)
            connection.request(
                "POST",
                parsed.path,
                body=body,
                headers={
                    "Accept": "application/json",
                    "Content-Type": "application/json",
                },
            )
            set_remaining_timeout(transport)
            response = connection.getresponse()
            set_remaining_timeout(transport)
            status = response.status
            if status != 200:
                raise McpClientError(f"MCP {method} failed with HTTP {status}")

            content_parts: list[bytes] = []
            content_size = 0
            while not response.isclosed():
                set_remaining_timeout(transport)
                chunk = response.read1(
                    min(64 * 1024, MAX_RESPONSE_BYTES + 1 - content_size)
                )
                if clock() >= deadline:
                    raise McpClientError(f"MCP {method} timed out")
                if not chunk:
                    break
                content_parts.append(chunk)
                content_size += len(chunk)
                if content_size > MAX_RESPONSE_BYTES:
                    raise McpClientError(f"MCP {method} response exceeds size limit")
            return b"".join(content_parts)
        except McpClientError:
            raise
        except (TimeoutError, socket.timeout) as exc:
            raise McpClientError(f"MCP {method} timed out") from exc
        except (http.client.HTTPException, OSError, UnicodeError, ValueError) as exc:
            raise McpClientError(f"MCP request failed during {method}: {exc}") from exc
        finally:
            if response is not None:
                try:
                    response.close()
                except OSError:
                    pass
            if connection is not None:
                try:
                    connection.close()
                except OSError:
                    pass
            with holder_lock:
                holder.clear()

    content = _run_with_deadline(
        exchange,
        deadline=deadline,
        clock=clock,
        timeout_message=f"MCP {method} timed out",
        cancel=cancel,
    )
    if not isinstance(content, bytes):
        raise McpClientError(f"MCP {method} response body is invalid")
    return content


def _rpc_call(
    endpoint: str,
    request_id: int,
    method: str,
    *,
    params: dict[str, object] | None,
    deadline: float,
    connection_factory: _ConnectionFactory = http.client.HTTPConnection,
    clock: _Clock = time.monotonic,
) -> object:
    document: dict[str, object] = {
        "jsonrpc": "2.0",
        "id": request_id,
        "method": method,
    }
    if params is not None:
        document["params"] = params
    raw_response = _post_json(
        endpoint,
        document,
        deadline=deadline,
        connection_factory=connection_factory,
        clock=clock,
    )
    response = _load_json(raw_response, f"MCP {method} response")
    if not isinstance(response, dict):
        raise McpClientError(f"MCP {method} response must be a JSON object")
    response_id = response.get("id")
    if (
        response.get("jsonrpc") != "2.0"
        or type(response_id) is not int
        or response_id != request_id
    ):
        raise McpClientError(f"MCP {method} response has invalid JSON-RPC identity")
    if "error" in response:
        error = response["error"]
        if isinstance(error, dict):
            message = error.get("message", "unknown JSON-RPC error")
        else:
            message = "malformed JSON-RPC error"
        raise McpClientError(f"MCP {method} error: {message}")
    if set(response) != {"jsonrpc", "id", "result"}:
        raise McpClientError(f"MCP {method} response fields are invalid")
    return response["result"]


def _require_exact_fields(
    document: Mapping[str, object],
    expected: set[str],
    description: str,
) -> None:
    if set(document) != expected:
        raise McpClientError(f"{description} fields do not match the strict contract")


def _require_status_error_invariant(
    status: str,
    error: str | None,
    description: str,
) -> None:
    if status == "pending":
        raise McpClientError(f"{description} is not terminal")
    if status == "succeeded" and error is not None:
        raise McpClientError(f"{description} violates the status/error invariant")
    if status in ("failed", "timed_out") and not error:
        raise McpClientError(f"{description} violates the status/error invariant")


def _command_result(document: object) -> gui_logic.GuiCommandResult:
    if not isinstance(document, dict):
        raise McpClientError("MCP command result must be a JSON object")
    _require_exact_fields(
        document,
        {
            "name",
            "started_at_utc",
            "finished_at_utc",
            "status",
            "details",
            "error",
        },
        "MCP command result",
    )
    try:
        result = gui_logic.GuiCommandResult(
            name=document["name"],
            started_at_utc=document["started_at_utc"],
            finished_at_utc=document["finished_at_utc"],
            status=document["status"],
            details=document["details"],
            error=document["error"],
        )
    except (TypeError, ValueError) as exc:
        raise McpClientError(f"MCP command result is invalid: {exc}") from exc
    _require_status_error_invariant(result.status, result.error, "MCP command result")
    return result


def _automation_result(
    request: gui_logic.GuiAutomationRequest,
    document: object,
) -> gui_logic.GuiAutomationResult:
    if not isinstance(document, dict):
        raise McpClientError("MCP automation result must be a JSON object")
    _require_exact_fields(
        document,
        {"request_id", "completed_at_utc", "commands", "status", "error"},
        "MCP automation result",
    )
    raw_commands = document["commands"]
    if not isinstance(raw_commands, list):
        raise McpClientError("MCP automation result commands must be a JSON array")
    commands = tuple(_command_result(command) for command in raw_commands)
    try:
        result = gui_logic.GuiAutomationResult(
            request_id=document["request_id"],
            completed_at_utc=document["completed_at_utc"],
            commands=commands,
            status=document["status"],
            error=document["error"],
        )
    except (TypeError, ValueError) as exc:
        raise McpClientError(f"MCP automation result is invalid: {exc}") from exc
    if result.request_id != request.request_id:
        raise McpClientError("MCP automation result request ID does not match")
    if tuple(command.name for command in commands) != request.commands:
        raise McpClientError("MCP automation result command order does not match")
    statuses = {command.status for command in commands}
    expected_status = (
        "failed"
        if "failed" in statuses
        else "timed_out" if "timed_out" in statuses else "succeeded"
    )
    _require_status_error_invariant(
        result.status,
        result.error,
        "MCP automation result",
    )
    if result.status != expected_status:
        raise McpClientError("MCP automation result status is inconsistent")
    return result


def _tool_result(
    request: gui_logic.GuiAutomationRequest,
    response: object,
) -> gui_logic.GuiAutomationResult:
    if not isinstance(response, dict):
        raise McpClientError("MCP tools/call result must be a JSON object")
    is_error = response.get("isError")
    if type(is_error) is not bool:
        raise McpClientError("MCP tools/call isError must be a boolean")
    content = response.get("content")
    if not isinstance(content, list):
        raise McpClientError("MCP tools/call content must be a JSON array")
    if is_error:
        messages = [
            item.get("text")
            for item in content
            if isinstance(item, dict) and isinstance(item.get("text"), str)
        ]
        message = "; ".join(messages) or "MCP py_eval reported a tool error"
        raise McpClientError(message)
    _require_exact_fields(
        response,
        {"content", "structuredContent", "isError"},
        "MCP tools/call result",
    )
    structured = response["structuredContent"]
    if not isinstance(structured, dict):
        raise McpClientError("MCP structured content must be a JSON object")
    _require_exact_fields(
        structured,
        {"result", "stdout", "stderr"},
        "MCP py_eval structured content",
    )
    result_text = structured["result"]
    stdout = structured["stdout"]
    stderr = structured["stderr"]
    if not all(isinstance(value, str) for value in (result_text, stdout, stderr)):
        raise McpClientError("MCP py_eval structured values must be strings")
    if stderr:
        raise McpClientError(f"MCP py_eval stderr: {stderr}")
    document = _load_json(result_text, "MCP py_eval result")
    return _automation_result(request, document)


def _write_json_atomic(path: pathlib.Path, document: dict[str, object]) -> None:
    content = json.dumps(document, allow_nan=False, indent=2, sort_keys=True) + "\n"
    descriptor, temporary_name = tempfile.mkstemp(
        dir=path.parent,
        prefix=f".{path.name}.",
        suffix=".tmp",
    )
    temporary_path = pathlib.Path(temporary_name)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
            stream.write(content)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary_path, path)
    except Exception:
        try:
            os.close(descriptor)
        except OSError:
            pass
        temporary_path.unlink(missing_ok=True)
        raise


def connect_named_commands(
    request: gui_logic.GuiAutomationRequest,
    *,
    endpoint: str,
    worktree: pathlib.Path | str,
    audit_dir: pathlib.Path | str,
    http_timeout: float = HTTP_TIMEOUT_SECONDS,
    resolver: _Resolver = socket.getaddrinfo,
    connection_factory: _ConnectionFactory = http.client.HTTPConnection,
    clock: _Clock = time.monotonic,
) -> tuple[gui_logic.GuiAutomationResult, pathlib.Path]:
    """Perform the fixed one-shot exchange and atomically publish its audit."""
    _request_document(request)
    endpoint = validate_endpoint(endpoint)
    if isinstance(http_timeout, bool) or not isinstance(http_timeout, (int, float)):
        raise TypeError("HTTP timeout must be a positive number")
    if http_timeout <= 0:
        raise ValueError("HTTP timeout must be a positive number")
    resolved_worktree = pathlib.Path(worktree).resolve(strict=True)
    resolved_audit_dir = pathlib.Path(audit_dir).resolve(strict=False)
    expected_audit_dir = resolved_worktree / ".tmp" / "ida-gui"
    if resolved_audit_dir != expected_audit_dir:
        raise ValueError("audit directory must be the worktree .tmp/ida-gui path")
    deadline = clock() + float(http_timeout)
    transport_endpoint = resolve_endpoint(
        endpoint,
        resolver=resolver,
        deadline=deadline,
        clock=clock,
    )

    initialize = _rpc_call(
        transport_endpoint,
        1,
        "initialize",
        params={
            "protocolVersion": MCP_PROTOCOL_VERSION,
            "capabilities": {},
            "clientInfo": {"name": "d810-gui-connect", "version": "1"},
        },
        deadline=deadline,
        connection_factory=connection_factory,
        clock=clock,
    )
    if not isinstance(initialize, dict):
        raise McpClientError("MCP initialize result must be a JSON object")
    if initialize.get("protocolVersion") != MCP_PROTOCOL_VERSION:
        raise McpClientError("MCP initialize returned an unsupported protocol")
    ping = _rpc_call(
        transport_endpoint,
        2,
        "ping",
        params=None,
        deadline=deadline,
        connection_factory=connection_factory,
        clock=clock,
    )
    if ping != {}:
        raise McpClientError("MCP ping result must be an empty JSON object")
    response = _rpc_call(
        transport_endpoint,
        3,
        "tools/call",
        params={
            "name": "py_eval",
            "arguments": {"code": build_remote_code(request)},
        },
        deadline=deadline,
        connection_factory=connection_factory,
        clock=clock,
    )
    result = _tool_result(request, response)
    context = {
        "mode": "connect",
        "worktree": str(resolved_worktree),
        "idb": {"path": None, "sha256": None},
        "mcp_endpoint": endpoint,
    }
    audit = gui_logic.audit_document(request, result, context)
    resolved_audit_dir.mkdir(parents=True, exist_ok=True)
    audit_path = resolved_audit_dir / f"automation-{request.request_id}.json"
    _write_json_atomic(audit_path, audit)
    return result, audit_path


def result_exit_code(result: gui_logic.GuiAutomationResult) -> int:
    if not isinstance(result, gui_logic.GuiAutomationResult):
        raise TypeError("result must be a GuiAutomationResult")
    return int(
        result.status != "succeeded"
        or any(command.status != "succeeded" for command in result.commands)
    )


def _utc_now() -> str:
    value = datetime.datetime.now(datetime.timezone.utc).isoformat()
    return value.replace("+00:00", "Z")


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Run fixed named D810 GUI commands through loopback MCP."
    )
    parser.add_argument("--worktree", required=True)
    parser.add_argument("--endpoint", default=DEFAULT_ENDPOINT)
    parser.add_argument("--open-config", action="store_true")
    parser.add_argument("--open-workbench", action="store_true")
    parser.add_argument("--function")
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    try:
        worktree = pathlib.Path(args.worktree).resolve(strict=True)
        if args.function is not None and not args.open_workbench:
            raise ValueError("--function requires --open-workbench")
        request = gui_logic.GuiAutomationRequest(
            request_id=secrets.token_hex(16),
            created_at_utc=_utc_now(),
            commands=gui_logic.ordered_commands(
                args.open_config,
                args.open_workbench,
            ),
            function_selector=gui_logic.parse_function_selector(args.function),
            timeout_seconds=30.0,
        )
        result, audit_path = connect_named_commands(
            request,
            endpoint=args.endpoint,
            worktree=worktree,
            audit_dir=worktree / ".tmp" / "ida-gui",
        )
    except (McpClientError, OSError, TypeError, ValueError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 2
    print(f"D810 GUI automation audit: {audit_path}")
    return result_exit_code(result)


if __name__ == "__main__":
    raise SystemExit(main())
