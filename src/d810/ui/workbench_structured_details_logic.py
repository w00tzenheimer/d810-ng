"""Qt-free field/value and JSON-tree projections for Workbench details."""

from __future__ import annotations

import dataclasses
import json

from d810.core import typing


JsonPathSegment = str | int


@dataclasses.dataclass(frozen=True, slots=True)
class DetailField:
    """One display-ready field/value pair from an authoritative snapshot."""

    label: str
    value: str
    emphasis: str = "normal"


@dataclasses.dataclass(frozen=True, slots=True)
class DetailSection:
    """One titled group of structured details."""

    section_id: str
    title: str
    fields: tuple[DetailField, ...]


@dataclasses.dataclass(frozen=True, slots=True)
class JsonTreeNode:
    """One JSON value with stable path identity for a native tree editor."""

    key: str
    path: tuple[JsonPathSegment, ...]
    value: object | None
    children: tuple["JsonTreeNode", ...]
    editable: bool

    @property
    def is_scalar(self) -> bool:
        return not self.children


def _address(value: int | None) -> str:
    return f"0x{value:X}" if value is not None else "Unavailable"


def _count_fields(values: tuple[str, ...], *, prefix: str) -> tuple[DetailField, ...]:
    if not values:
        return (DetailField("Count", "0"),)
    return (DetailField("Count", str(len(values))),) + tuple(
        DetailField(f"{prefix} {index}", value)
        for index, value in enumerate(values, start=1)
    )


def _shape_fields(shape_lines: tuple[str, ...]) -> tuple[DetailField, ...]:
    fields: list[DetailField] = []
    for line in shape_lines:
        label, separator, value = str(line).partition(":")
        fields.append(
            DetailField(
                label.strip() if separator else "Observed",
                value.strip() if separator else label.strip(),
            )
        )
    return tuple(fields)


def build_dossier_sections(dossier: typing.Any) -> tuple[DetailSection, ...]:
    """Render a function dossier as fields, never a joined prose block."""

    generic = str(getattr(dossier, "protection_label", "")) == "Generic cleanup"
    protection_fields = (
        DetailField("Classification", str(dossier.protection_label), "status"),
        DetailField("Evidence", "Not classified" if generic else "Classified"),
    ) + (() if generic else _shape_fields(tuple(getattr(dossier, "shape_lines", ()) or ())))
    evidence_lines = tuple(getattr(dossier, "evidence_lines", ()) or ())
    diagnostic_lines = tuple(getattr(dossier, "diagnostic_lines", ()) or ())
    return (
        DetailSection(
            "function",
            "Function",
            (
                DetailField("Name", str(dossier.function_name), "identity"),
                DetailField("Address", _address(dossier.function_ea), "identity"),
            ),
        ),
        DetailSection("protection", "Protection shape", protection_fields),
        DetailSection(
            "evidence",
            "Case evidence",
            (DetailField("Records", str(len(evidence_lines))),),
        ),
        DetailSection(
            "diagnostics",
            "Diagnostics",
            (DetailField("Records", str(len(diagnostic_lines))),),
        ),
    )


def _port_fields(node: typing.Any, direction: str) -> tuple[DetailField, ...]:
    ports = tuple(
        port for port in tuple(getattr(node, f"{direction}s", ()) or ())
        if str(getattr(port, "direction", direction)) == direction
    )
    if not ports:
        return (DetailField("Count", "0"),)
    return (DetailField("Count", str(len(ports))),) + tuple(
        DetailField(
            f"{getattr(port, 'artifact_type', 'value')}",
            str(getattr(port, "label", "")),
        )
        for port in ports
    )


def build_node_sections(
    node: typing.Any,
    evidence_references: tuple[str, ...] = (),
) -> tuple[DetailSection, ...]:
    """Project a canvas node into inspector property groups."""

    return (
        DetailSection(
            "node",
            "Selected node",
            (
                DetailField("Name", str(getattr(node, "label", "")), "identity"),
                DetailField("State", str(getattr(node, "state", "unknown")), "status"),
                DetailField("Provenance", str(getattr(node, "provenance", "recipe"))),
                DetailField(
                    "Maturity",
                    str(getattr(getattr(node, "maturity", None), "label", "Unavailable")),
                ),
            ),
        ),
        DetailSection("inputs", "Inputs", _port_fields(node, "input")),
        DetailSection("outputs", "Outputs", _port_fields(node, "output")),
        DetailSection(
            "evidence",
            "Evidence",
            _count_fields(tuple(evidence_references), prefix="Reference"),
        ),
    )


def _node_for_value(
    key: str,
    value: object,
    path: tuple[JsonPathSegment, ...],
    *,
    editable: bool,
) -> JsonTreeNode:
    if isinstance(value, dict):
        children = tuple(
            _node_for_value(str(child_key), child_value, path + (str(child_key),), editable=editable)
            for child_key, child_value in value.items()
        )
        return JsonTreeNode(key, path, None, children, editable)
    if isinstance(value, list):
        children = tuple(
            _node_for_value(str(index), child_value, path + (index,), editable=editable)
            for index, child_value in enumerate(value)
        )
        return JsonTreeNode(key, path, None, children, editable)
    return JsonTreeNode(key, path, value, (), editable)


def json_value_tree(value: object, *, editable: bool) -> tuple[JsonTreeNode, ...]:
    """Return the ordered child nodes for a JSON mapping/list/root scalar."""

    if isinstance(value, dict):
        return tuple(
            _node_for_value(str(key), child, (str(key),), editable=editable)
            for key, child in value.items()
        )
    if isinstance(value, list):
        return tuple(
            _node_for_value(str(index), child, (index,), editable=editable)
            for index, child in enumerate(value)
        )
    return (_node_for_value("value", value, (), editable=editable),)


def parse_contract_detail(detail: object) -> object:
    """Decode a node's canonical contract without treating annotations as JSON."""

    contract, _separator, _annotation = str(detail).partition("\n")
    try:
        return json.loads(contract)
    except json.JSONDecodeError:
        return {"contract": contract or "Unavailable"}


def _parse_edited_scalar(raw: str) -> object:
    try:
        return json.loads(raw)
    except json.JSONDecodeError:
        return raw


def _replace_path(value: object, path: tuple[JsonPathSegment, ...], replacement: object) -> object:
    if not path:
        return replacement
    head, *tail = path
    if isinstance(value, dict) and isinstance(head, str) and head in value:
        copied = dict(value)
        copied[head] = _replace_path(copied[head], tuple(tail), replacement)
        return copied
    if isinstance(value, list) and isinstance(head, int) and 0 <= head < len(value):
        copied = list(value)
        copied[head] = _replace_path(copied[head], tuple(tail), replacement)
        return copied
    raise ValueError(f"JSON path is not editable: {path!r}")


def apply_json_tree_scalar(
    value: object,
    path: tuple[JsonPathSegment, ...],
    raw: str,
) -> object:
    """Return a copied JSON value with one edited scalar parsed faithfully."""

    return _replace_path(value, path, _parse_edited_scalar(raw))


__all__ = [
    "DetailField",
    "DetailSection",
    "JsonPathSegment",
    "JsonTreeNode",
    "apply_json_tree_scalar",
    "build_dossier_sections",
    "build_node_sections",
    "json_value_tree",
    "parse_contract_detail",
]
