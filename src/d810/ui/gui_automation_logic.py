"""Pure request, result, and audit logic for named GUI automation."""

from __future__ import annotations

import dataclasses
import enum
import math
import re
from collections.abc import Mapping
from types import MappingProxyType


class GuiCommand(str, enum.Enum):
    OPEN_CONFIG = "open-config"
    OPEN_WORKBENCH = "open-workbench"


_RESULT_STATUSES = frozenset(("pending", "succeeded", "failed", "timed_out"))
_DECIMAL_EA = re.compile(r"[0-9]+\Z")
_HEX_EA = re.compile(r"0[xX][0-9a-fA-F]+\Z")
_EXACT_NAME = re.compile(r"[A-Za-z_?$@~][A-Za-z0-9_?$@.~:]*\Z")


def parse_function_selector(value: str | None) -> str | int | None:
    """Parse an exact function name or a decimal/hexadecimal integer EA."""
    if value is None:
        return None
    if not isinstance(value, str):
        raise TypeError("function selector must be a string or None")
    if _DECIMAL_EA.fullmatch(value):
        return int(value, 10)
    if _HEX_EA.fullmatch(value):
        return int(value, 16)
    if _EXACT_NAME.fullmatch(value):
        return value
    raise ValueError("function selector must be an exact name or integer EA")


def ordered_commands(config: bool, workbench: bool) -> tuple[GuiCommand, ...]:
    """Return selected named commands in their deterministic execution order."""
    if not isinstance(config, bool) or not isinstance(workbench, bool):
        raise TypeError("command selectors must be bool values")
    commands: list[GuiCommand] = []
    if config:
        commands.append(GuiCommand.OPEN_CONFIG)
    if workbench:
        commands.append(GuiCommand.OPEN_WORKBENCH)
    if not commands:
        raise ValueError("at least one named GUI command is required")
    return tuple(commands)


def _required_text(value: object, field_name: str) -> str:
    if not isinstance(value, str) or not value:
        raise ValueError(f"{field_name} must be a non-empty string")
    return value


def _status(value: object) -> str:
    if not isinstance(value, str) or value not in _RESULT_STATUSES:
        raise ValueError(f"unsupported GUI automation status: {value!r}")
    return value


def _command(value: object) -> GuiCommand:
    try:
        return GuiCommand(value)
    except (TypeError, ValueError) as exc:
        raise ValueError(f"unsupported GUI automation command: {value!r}") from exc


def _freeze_json(value: object) -> object:
    if isinstance(value, enum.Enum):
        return _freeze_json(value.value)
    if value is None or type(value) is bool:
        return value
    if isinstance(value, str):
        return str(value)
    if isinstance(value, int):
        return int(value)
    if isinstance(value, float):
        normalized = float(value)
        if not math.isfinite(normalized):
            raise ValueError("JSON numbers must be finite")
        return normalized
    if isinstance(value, Mapping):
        frozen: dict[str, object] = {}
        for key, item in value.items():
            if type(key) is not str:
                raise TypeError("JSON object keys must be strings")
            frozen[key] = _freeze_json(item)
        return MappingProxyType(frozen)
    if isinstance(value, (list, tuple)):
        return tuple(_freeze_json(item) for item in value)
    raise TypeError(f"value is not JSON-native: {value!r}")


def _json_native(value: object) -> object:
    if isinstance(value, enum.Enum):
        return _json_native(value.value)
    if value is None or type(value) is bool:
        return value
    if isinstance(value, str):
        return str(value)
    if isinstance(value, int):
        return int(value)
    if isinstance(value, float):
        normalized = float(value)
        if not math.isfinite(normalized):
            raise ValueError("JSON numbers must be finite")
        return normalized
    if isinstance(value, Mapping):
        native: dict[str, object] = {}
        for key, item in value.items():
            if type(key) is not str:
                raise TypeError("JSON object keys must be strings")
            native[key] = _json_native(item)
        return native
    if isinstance(value, (list, tuple)):
        return [_json_native(item) for item in value]
    raise TypeError(f"value is not JSON-native: {value!r}")


@dataclasses.dataclass(frozen=True, slots=True)
class GuiAutomationRequest:
    request_id: str
    created_at_utc: str
    commands: tuple[GuiCommand, ...]
    function_selector: str | int | None = None
    timeout_seconds: float = 30.0

    def __post_init__(self) -> None:
        _required_text(self.request_id, "request_id")
        _required_text(self.created_at_utc, "created_at_utc")
        commands = tuple(_command(command) for command in self.commands)
        if not commands:
            raise ValueError("at least one named GUI command is required")
        object.__setattr__(self, "commands", commands)

        selector = self.function_selector
        if isinstance(selector, str) or selector is None:
            selector = parse_function_selector(selector)
        elif (
            isinstance(selector, bool) or not isinstance(selector, int) or selector < 0
        ):
            raise ValueError("function selector must be an exact name or integer EA")
        object.__setattr__(self, "function_selector", selector)

        timeout = self.timeout_seconds
        if isinstance(timeout, bool) or not isinstance(timeout, (int, float)):
            raise TypeError("timeout_seconds must be a positive finite number")
        if not math.isfinite(timeout) or timeout <= 0:
            raise ValueError("timeout_seconds must be a positive finite number")
        object.__setattr__(self, "timeout_seconds", float(timeout))


@dataclasses.dataclass(frozen=True, slots=True)
class GuiCommandResult:
    name: GuiCommand
    started_at_utc: str
    finished_at_utc: str
    status: str
    details: Mapping[str, object] = dataclasses.field(default_factory=dict)
    error: str | None = None

    def __post_init__(self) -> None:
        object.__setattr__(self, "name", _command(self.name))
        _required_text(self.started_at_utc, "started_at_utc")
        _required_text(self.finished_at_utc, "finished_at_utc")
        object.__setattr__(self, "status", _status(self.status))
        if not isinstance(self.details, Mapping):
            raise TypeError("details must be a JSON object")
        object.__setattr__(self, "details", _freeze_json(self.details))
        if self.error is not None and not isinstance(self.error, str):
            raise TypeError("error must be a string or None")


@dataclasses.dataclass(frozen=True, slots=True)
class GuiAutomationResult:
    request_id: str
    completed_at_utc: str
    commands: tuple[GuiCommandResult, ...]
    status: str
    error: str | None = None

    def __post_init__(self) -> None:
        _required_text(self.request_id, "request_id")
        _required_text(self.completed_at_utc, "completed_at_utc")
        commands = tuple(self.commands)
        if not all(isinstance(command, GuiCommandResult) for command in commands):
            raise TypeError("commands must contain GuiCommandResult values")
        object.__setattr__(self, "commands", commands)
        object.__setattr__(self, "status", _status(self.status))
        if self.error is not None and not isinstance(self.error, str):
            raise TypeError("error must be a string or None")


def audit_document(
    request: GuiAutomationRequest,
    result: GuiAutomationResult,
    context: Mapping[str, object],
) -> dict[str, object]:
    """Build the exact schema-v1 JSON audit document."""
    if result.request_id != request.request_id:
        raise ValueError("request and result IDs do not match")
    if not isinstance(context, Mapping):
        raise TypeError("audit context must be a mapping")
    mode = context.get("mode")
    if mode not in ("launch", "connect"):
        raise ValueError("audit mode must be 'launch' or 'connect'")
    worktree = _required_text(context.get("worktree"), "worktree")
    idb = context.get("idb")
    if not isinstance(idb, Mapping):
        raise TypeError("audit idb context must be a mapping")
    idb_document = {
        "path": _json_native(idb.get("path")),
        "sha256": _json_native(idb.get("sha256")),
    }
    mcp_endpoint = _json_native(context.get("mcp_endpoint"))

    document = {
        "schema_version": 1,
        "request_id": request.request_id,
        "mode": mode,
        "created_at_utc": request.created_at_utc,
        "completed_at_utc": result.completed_at_utc,
        "worktree": worktree,
        "idb": idb_document,
        "mcp_endpoint": mcp_endpoint,
        "requested_commands": [command.value for command in request.commands],
        "function_selector": request.function_selector,
        "commands": [
            {
                "name": command.name.value,
                "started_at_utc": command.started_at_utc,
                "finished_at_utc": command.finished_at_utc,
                "status": command.status,
                "details": _json_native(command.details),
                "error": command.error,
            }
            for command in result.commands
        ],
        "status": result.status,
        "error": result.error,
    }
    native_document = _json_native(document)
    if not isinstance(native_document, dict):
        raise TypeError("audit document must be a JSON object")
    return native_document


__all__ = [
    "GuiAutomationRequest",
    "GuiAutomationResult",
    "GuiCommand",
    "GuiCommandResult",
    "audit_document",
    "ordered_commands",
    "parse_function_selector",
]
