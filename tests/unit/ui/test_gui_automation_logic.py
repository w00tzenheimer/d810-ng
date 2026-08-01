"""Tests for the IDA-independent named GUI automation contract."""

from __future__ import annotations

import ast
import dataclasses
import enum
import importlib
import json
from collections.abc import Mapping
from pathlib import Path
from types import ModuleType

import pytest


def _logic() -> ModuleType:
    return importlib.import_module("d810.ui.gui_automation_logic")


@pytest.mark.parametrize(
    ("member", "value"),
    (
        ("OPEN_CONFIG", "open-config"),
        ("OPEN_WORKBENCH", "open-workbench"),
    ),
)
def test_gui_command_is_the_exact_closed_named_command_set(
    member: str,
    value: str,
) -> None:
    logic = _logic()

    assert getattr(logic.GuiCommand, member).value == value
    assert {command.name for command in logic.GuiCommand} == {
        "OPEN_CONFIG",
        "OPEN_WORKBENCH",
    }
    with pytest.raises(ValueError):
        logic.GuiCommand("py-eval")


@pytest.mark.parametrize(
    ("config", "workbench", "expected"),
    (
        (True, False, ("open-config",)),
        (False, True, ("open-workbench",)),
        (True, True, ("open-config", "open-workbench")),
    ),
)
def test_ordered_commands_has_a_deterministic_action_matrix(
    config: bool,
    workbench: bool,
    expected: tuple[str, ...],
) -> None:
    logic = _logic()

    assert (
        tuple(command.value for command in logic.ordered_commands(config, workbench))
        == expected
    )


def test_ordered_commands_rejects_an_empty_or_non_boolean_request() -> None:
    logic = _logic()

    with pytest.raises(ValueError, match="at least one"):
        logic.ordered_commands(False, False)
    with pytest.raises(TypeError, match="bool"):
        logic.ordered_commands(1, False)


@pytest.mark.parametrize(
    ("raw", "expected"),
    (
        (None, None),
        ("sub_401000", "sub_401000"),
        ("namespace::target", "namespace::target"),
        ("?target@@YAXXZ", "?target@@YAXXZ"),
        ("4198400", 0x401000),
        ("0x401000", 0x401000),
        ("0X401000", 0x401000),
    ),
)
def test_parse_function_selector_accepts_only_exact_names_or_integer_eas(
    raw: str | None,
    expected: str | int | None,
) -> None:
    assert _logic().parse_function_selector(raw) == expected


@pytest.mark.parametrize(
    "raw",
    (
        "",
        " target",
        "target ",
        "0x",
        "0xGG",
        "123abc",
        "-1",
        "target()",
        "target; __import__('os')",
        "target\nnext",
        "0x401000 + 4",
    ),
)
def test_parse_function_selector_rejects_empty_ambiguous_or_executable_input(
    raw: str,
) -> None:
    with pytest.raises(ValueError):
        _logic().parse_function_selector(raw)


def _request(logic: ModuleType, **changes: object) -> object:
    values = {
        "request_id": "request-123",
        "created_at_utc": "2026-07-16T18:30:00Z",
        "commands": logic.ordered_commands(True, True),
        "function_selector": "target",
        "timeout_seconds": 30.0,
    }
    values.update(changes)
    return logic.GuiAutomationRequest(**values)


def _command_result(
    logic: ModuleType,
    *,
    name: object | None = None,
    status: str = "succeeded",
    error: str | None = None,
    details: Mapping[str, object] | None = None,
) -> object:
    return logic.GuiCommandResult(
        name=logic.GuiCommand.OPEN_CONFIG if name is None else name,
        started_at_utc="2026-07-16T18:30:00Z",
        finished_at_utc="2026-07-16T18:30:00Z",
        status=status,
        details={} if details is None else details,
        error=error,
    )


def test_request_models_are_immutable_and_timeout_is_bounded() -> None:
    logic = _logic()
    request = _request(logic)

    assert request.timeout_seconds == 30.0
    assert request.commands == (
        logic.GuiCommand.OPEN_CONFIG,
        logic.GuiCommand.OPEN_WORKBENCH,
    )
    with pytest.raises(dataclasses.FrozenInstanceError):
        request.timeout_seconds = 1.0

    for invalid in (0, -1, float("inf"), True, "30"):
        with pytest.raises((TypeError, ValueError)):
            _request(logic, timeout_seconds=invalid)


@pytest.mark.parametrize(
    "status",
    ("pending", "succeeded", "failed", "timed_out"),
)
def test_result_models_accept_exactly_the_four_statuses(status: str) -> None:
    logic = _logic()
    command = _command_result(logic, status=status)
    result = logic.GuiAutomationResult(
        request_id="request-123",
        completed_at_utc="2026-07-16T18:30:01Z",
        commands=(command,),
        status=status,
        error=None,
    )

    assert command.status == status
    assert result.status == status
    with pytest.raises(dataclasses.FrozenInstanceError):
        command.status = "failed"


def test_unknown_commands_and_statuses_fail_closed() -> None:
    logic = _logic()

    with pytest.raises(ValueError):
        _request(logic, commands=("arbitrary-python",))
    with pytest.raises(ValueError):
        _command_result(logic, name="arbitrary-python")
    with pytest.raises(ValueError):
        _command_result(logic, status="complete")
    with pytest.raises(ValueError):
        logic.GuiAutomationResult(
            request_id="request-123",
            completed_at_utc="2026-07-16T18:30:01Z",
            commands=(),
            status="complete",
            error=None,
        )


def _assert_json_native(value: object) -> None:
    if value is None or type(value) in (bool, int, float, str):
        return
    if type(value) is dict:
        assert all(isinstance(key, str) for key in value)
        for item in value.values():
            _assert_json_native(item)
        return
    assert type(value) is list, f"non-JSON-native value: {value!r}"
    for item in value:
        _assert_json_native(item)


def test_audit_document_matches_schema_v1_for_partial_failure() -> None:
    logic = _logic()
    request = _request(logic)
    config_result = _command_result(
        logic,
        details={"widget_title": "D-810 Configuration"},
    )
    workbench_result = logic.GuiCommandResult(
        name=logic.GuiCommand.OPEN_WORKBENCH,
        started_at_utc="2026-07-16T18:30:00Z",
        finished_at_utc="2026-07-16T18:30:01Z",
        status="failed",
        details={},
        error="function not found",
    )
    result = logic.GuiAutomationResult(
        request_id="request-123",
        completed_at_utc="2026-07-16T18:30:01Z",
        commands=(config_result, workbench_result),
        status="failed",
        error="one or more commands failed",
    )
    context = {
        "mode": "launch",
        "worktree": "/work",
        "idb": {
            "path": "/work/.tmp/ida-gui/sample.i64",
            "sha256": "hex-digest",
        },
        "mcp_endpoint": None,
    }

    document = logic.audit_document(request, result, context)

    assert document == {
        "schema_version": 1,
        "request_id": "request-123",
        "mode": "launch",
        "created_at_utc": "2026-07-16T18:30:00Z",
        "completed_at_utc": "2026-07-16T18:30:01Z",
        "worktree": "/work",
        "idb": {
            "path": "/work/.tmp/ida-gui/sample.i64",
            "sha256": "hex-digest",
        },
        "mcp_endpoint": None,
        "requested_commands": ["open-config", "open-workbench"],
        "function_selector": "target",
        "commands": [
            {
                "name": "open-config",
                "started_at_utc": "2026-07-16T18:30:00Z",
                "finished_at_utc": "2026-07-16T18:30:00Z",
                "status": "succeeded",
                "details": {"widget_title": "D-810 Configuration"},
                "error": None,
            },
            {
                "name": "open-workbench",
                "started_at_utc": "2026-07-16T18:30:00Z",
                "finished_at_utc": "2026-07-16T18:30:01Z",
                "status": "failed",
                "details": {},
                "error": "function not found",
            },
        ],
        "status": "failed",
        "error": "one or more commands failed",
    }
    _assert_json_native(document)
    assert json.loads(json.dumps(document)) == document


def test_audit_document_preserves_timed_out_status_and_nested_json_details() -> None:
    logic = _logic()
    request = _request(logic, commands=(logic.GuiCommand.OPEN_CONFIG,))
    command = _command_result(
        logic,
        status="timed_out",
        error="timeout after 30 seconds",
        details={"attempts": [1, 2], "visible": False},
    )
    result = logic.GuiAutomationResult(
        request_id="request-123",
        completed_at_utc="2026-07-16T18:30:30Z",
        commands=(command,),
        status="timed_out",
        error="timeout after 30 seconds",
    )

    document = logic.audit_document(
        request,
        result,
        {
            "mode": "connect",
            "worktree": "/work",
            "idb": {"path": None, "sha256": None},
            "mcp_endpoint": "http://127.0.0.1:13337/mcp",
        },
    )

    assert document["status"] == "timed_out"
    assert document["commands"][0]["status"] == "timed_out"
    assert document["commands"][0]["details"] == {
        "attempts": [1, 2],
        "visible": False,
    }
    _assert_json_native(document)


class _PlainAuditValue(enum.Enum):
    CONFIG = "config"


class _StringAuditValue(str, enum.Enum):
    CONFIG = "config"


class _TextSubclass(str):
    pass


class _IntegerSubclass(int):
    pass


class _FloatSubclass(float):
    pass


class _SubclassBackedAuditValue(enum.Enum):
    TEXT = _TextSubclass("text")
    COUNT = _IntegerSubclass(7)
    RATIO = _FloatSubclass(1.25)


def _audit_with_details(logic: ModuleType, details: Mapping[str, object]) -> object:
    request = _request(logic, commands=(logic.GuiCommand.OPEN_CONFIG,))
    command = _command_result(logic, details=details)
    result = logic.GuiAutomationResult(
        request_id=request.request_id,
        completed_at_utc="2026-07-16T18:30:01Z",
        commands=(command,),
        status="succeeded",
        error=None,
    )
    return logic.audit_document(
        request,
        result,
        {
            "mode": "launch",
            "worktree": "/work",
            "idb": {"path": "/work/sample.i64", "sha256": "hex-digest"},
            "mcp_endpoint": None,
        },
    )


def test_audit_normalizes_string_backed_enums_to_builtin_strings() -> None:
    logic = _logic()

    document = _audit_with_details(logic, {"label": _StringAuditValue.CONFIG})

    label = document["commands"][0]["details"]["label"]
    assert type(label) is str
    assert label == "config"


def test_audit_normalizes_plain_enums_and_strictly_serializes() -> None:
    logic = _logic()

    document = _audit_with_details(
        logic,
        {"nested": [{"label": _PlainAuditValue.CONFIG}]},
    )

    _assert_json_native(document)
    assert json.loads(json.dumps(document, allow_nan=False)) == document


@pytest.mark.parametrize(
    ("value", "expected_type", "expected"),
    (
        (_TextSubclass("text"), str, "text"),
        (_IntegerSubclass(7), int, 7),
        (_FloatSubclass(1.25), float, 1.25),
    ),
)
def test_nested_details_normalize_scalar_subclasses_for_storage_and_output(
    value: object,
    expected_type: type[object],
    expected: object,
) -> None:
    logic = _logic()

    document = _audit_with_details(logic, {"nested": [{"value": value}]})
    projected = document["commands"][0]["details"]["nested"][0]["value"]
    command = _command_result(logic, details={"nested": [{"value": value}]})
    frozen = command.details["nested"][0]["value"]

    assert type(projected) is expected_type
    assert projected == expected
    assert type(frozen) is expected_type
    assert frozen == expected
    _assert_json_native(document)


@pytest.mark.parametrize(
    ("value", "expected_type", "expected"),
    (
        (_SubclassBackedAuditValue.TEXT, str, "text"),
        (_SubclassBackedAuditValue.COUNT, int, 7),
        (_SubclassBackedAuditValue.RATIO, float, 1.25),
    ),
)
def test_enum_normalization_recurses_to_exact_builtin_scalar_types(
    value: enum.Enum,
    expected_type: type[object],
    expected: object,
) -> None:
    logic = _logic()

    document = _audit_with_details(logic, {"value": value})
    projected = document["commands"][0]["details"]["value"]
    command = _command_result(logic, details={"value": value})
    frozen = command.details["value"]

    assert type(projected) is expected_type
    assert projected == expected
    assert type(frozen) is expected_type
    assert frozen == expected


def test_audit_context_normalizes_string_subclasses() -> None:
    logic = _logic()
    request = _request(logic, commands=(logic.GuiCommand.OPEN_CONFIG,))
    command = _command_result(logic)
    result = logic.GuiAutomationResult(
        request_id=request.request_id,
        completed_at_utc="2026-07-16T18:30:01Z",
        commands=(command,),
        status="succeeded",
        error=None,
    )

    document = logic.audit_document(
        request,
        result,
        {
            "mode": _TextSubclass("launch"),
            "worktree": _TextSubclass("/work"),
            "idb": {
                "path": _TextSubclass("/work/sample.i64"),
                "sha256": _TextSubclass("hex-digest"),
            },
            "mcp_endpoint": _TextSubclass("http://127.0.0.1:13337/mcp"),
        },
    )

    assert type(document["mode"]) is str
    assert type(document["worktree"]) is str
    assert type(document["idb"]["path"]) is str
    assert type(document["idb"]["sha256"]) is str
    assert type(document["mcp_endpoint"]) is str
    _assert_json_native(document)


def test_audit_normalizes_direct_model_string_subclasses() -> None:
    logic = _logic()
    request = logic.GuiAutomationRequest(
        request_id=_TextSubclass("request-123"),
        created_at_utc=_TextSubclass("2026-07-16T18:30:00Z"),
        commands=(logic.GuiCommand.OPEN_CONFIG,),
        function_selector=_TextSubclass("target"),
        timeout_seconds=30.0,
    )
    command = logic.GuiCommandResult(
        name=logic.GuiCommand.OPEN_CONFIG,
        started_at_utc=_TextSubclass("2026-07-16T18:30:00Z"),
        finished_at_utc=_TextSubclass("2026-07-16T18:30:01Z"),
        status=_TextSubclass("failed"),
        details={},
        error=_TextSubclass("command failed"),
    )
    result = logic.GuiAutomationResult(
        request_id=_TextSubclass("request-123"),
        completed_at_utc=_TextSubclass("2026-07-16T18:30:01Z"),
        commands=(command,),
        status=_TextSubclass("failed"),
        error=_TextSubclass("automation failed"),
    )

    document = logic.audit_document(
        request,
        result,
        {
            "mode": "launch",
            "worktree": "/work",
            "idb": {"path": "/work/sample.i64", "sha256": "hex-digest"},
            "mcp_endpoint": None,
        },
    )

    _assert_json_native(document)
    assert json.loads(json.dumps(document, allow_nan=False)) == document


@pytest.mark.parametrize("value", (float("nan"), float("inf"), float("-inf")))
def test_json_native_rejects_non_finite_floats(value: float) -> None:
    with pytest.raises(ValueError, match="finite"):
        _logic()._json_native(value)


def test_json_native_rejects_non_string_mapping_keys() -> None:
    with pytest.raises(TypeError, match="keys must be strings"):
        _logic()._json_native({1: "not allowed"})


def test_gui_automation_logic_has_no_ida_qt_sqlite_docker_or_mcp_imports() -> None:
    logic = _logic()
    path = Path(logic.__file__)
    tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    imports = {
        node.module
        for node in ast.walk(tree)
        if isinstance(node, ast.ImportFrom) and node.module
    }
    imports.update(
        alias.name
        for node in ast.walk(tree)
        if isinstance(node, ast.Import)
        for alias in node.names
    )

    forbidden = ("ida", "PyQt", "PySide", "sqlite", "docker", "mcp")
    assert not any(
        token.lower() in name.lower() for name in imports for token in forbidden
    )
