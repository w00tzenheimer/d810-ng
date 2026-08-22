"""Strict, provider-neutral schema for the analysis-phase witness.

The witness is journal authority, not an advisory cache.  This module keeps
its decoded representation immutable and makes parsing a single validation
boundary.  Callers may use the small mapping facade for compatibility with
older gateway code, but values returned by the facade are derived from the
same frozen objects held by :class:`AnalysisPhaseWitness`.
"""

from __future__ import annotations

import json
from dataclasses import dataclass

from d810.core.typing import Any

__all__ = [
    "AnalysisPhaseWitness",
    "PhaseGroup",
    "PhaseItem",
    "PhasePostcondition",
    "PhaseWitnessError",
    "PhaseXref",
    "ReverseStep",
    "parse_analysis_phase_witness",
]


class PhaseWitnessError(ValueError):
    """The phase witness is missing, malformed, or internally inconsistent."""


def _int(value: object, field: str) -> int:
    if not isinstance(value, int) or isinstance(value, bool):
        raise PhaseWitnessError(f"{field} must be an integer")
    if value < 0:
        raise PhaseWitnessError(f"{field} must be non-negative")
    return value


def _str(value: object, field: str) -> str:
    if not isinstance(value, str) or not value:
        raise PhaseWitnessError(f"{field} must be a non-empty string")
    return value


def _keys(value: object, expected: set[str], field: str) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != expected:
        raise PhaseWitnessError(f"{field} has unexpected keys")
    return value


def _canonical_list(value: object, field: str) -> list[Any]:
    if not isinstance(value, list):
        raise PhaseWitnessError(f"{field} must be a list")
    return value


@dataclass(frozen=True, slots=True)
class PhaseItem:
    ea: int
    size: int
    state: str


@dataclass(frozen=True, slots=True)
class PhaseXref:
    source_ea: int
    target_ea: int
    xref_type: int
    user_owned: bool
    is_code: bool

    def as_payload(self) -> dict[str, object]:
        return {
            "source_ea": self.source_ea,
            "target_ea": self.target_ea,
            "xref_type": self.xref_type,
            "user_owned": self.user_owned,
            "is_code": self.is_code,
        }


@dataclass(frozen=True, slots=True)
class PhasePostcondition:
    ea: int
    state: str


def _parse_items(value: object, field: str) -> tuple[PhaseItem, ...]:
    rows = _canonical_list(value, field)
    parsed: list[PhaseItem] = []
    previous_end = -1
    for index, row in enumerate(rows):
        if not isinstance(row, list) or len(row) != 3:
            raise PhaseWitnessError(f"{field}[{index}] must be [ea, size, state]")
        ea = _int(row[0], f"{field}[{index}].ea")
        size = _int(row[1], f"{field}[{index}].size")
        if size <= 0:
            raise PhaseWitnessError(f"{field}[{index}].size must be positive")
        state = _str(row[2], f"{field}[{index}].state")
        if ea < previous_end:
            raise PhaseWitnessError(f"{field} item ranges overlap")
        previous_end = ea + size
        parsed.append(PhaseItem(ea, size, state))
    if [[item.ea, item.size, item.state] for item in parsed] != rows:
        raise PhaseWitnessError(f"{field} is not in canonical order")
    return tuple(parsed)


def _parse_xrefs(value: object, field: str) -> tuple[PhaseXref, ...]:
    rows = _canonical_list(value, field)
    parsed: list[PhaseXref] = []
    previous: tuple[int, int, int, bool, bool] | None = None
    for index, row in enumerate(rows):
        data = _keys(
            row,
            {"source_ea", "target_ea", "xref_type", "user_owned", "is_code"},
            f"{field}[{index}]",
        )
        source = _int(data["source_ea"], f"{field}[{index}].source_ea")
        target = _int(data["target_ea"], f"{field}[{index}].target_ea")
        xref_type = _int(data["xref_type"], f"{field}[{index}].xref_type")
        user_owned = data["user_owned"]
        is_code = data["is_code"]
        if not isinstance(user_owned, bool) or not isinstance(is_code, bool):
            raise PhaseWitnessError(f"{field}[{index}] flags must be booleans")
        current = (source, target, xref_type, user_owned, is_code)
        if previous is not None and current <= previous:
            raise PhaseWitnessError(f"{field} must be sorted and deduplicated")
        previous = current
        parsed.append(PhaseXref(*current))
    return tuple(parsed)


def _parse_origin(token: object) -> tuple[int, int]:
    if not isinstance(token, str) or not token.startswith(("data:v1:", "data:v2:")):
        raise PhaseWitnessError("origin_data_state must be a versioned data token")
    prefix = "data:v1:" if token.startswith("data:v1:") else "data:v2:"
    try:
        payload = json.loads(token.removeprefix(prefix))
    except (TypeError, json.JSONDecodeError) as error:
        raise PhaseWitnessError("origin_data_state is not valid JSON") from error
    if not isinstance(payload, dict):
        raise PhaseWitnessError("origin_data_state payload must be an object")
    required = {"bytes", "ea", "flags", "full_flags", "head_ea", "name", "offset", "size"}
    if prefix == "data:v2:":
        required.add("xrefs")
    if set(payload) != required:
        raise PhaseWitnessError("origin_data_state has unexpected keys")
    head = _int(payload["head_ea"], "origin_data_state.head_ea")
    size = _int(payload["size"], "origin_data_state.size")
    if size <= 0:
        raise PhaseWitnessError("origin_data_state.size must be positive")
    ea = _int(payload["ea"], "origin_data_state.ea")
    offset = _int(payload["offset"], "origin_data_state.offset")
    if offset >= size or ea != head + offset:
        raise PhaseWitnessError("origin_data_state address is outside its item")
    if not isinstance(payload["bytes"], str) or len(payload["bytes"]) != size * 2:
        raise PhaseWitnessError("origin_data_state bytes do not cover its range")
    flags = payload["full_flags"]
    if not isinstance(flags, list) or len(flags) != size:
        raise PhaseWitnessError("origin_data_state full_flags do not cover its range")
    for index, flag in enumerate(flags):
        _int(flag, f"origin_data_state.full_flags[{index}]")
    if prefix == "data:v2:":
        _parse_origin_xrefs(payload["xrefs"])
    canonical = prefix + json.dumps(payload, sort_keys=True, separators=(",", ":"))
    if canonical != token:
        raise PhaseWitnessError("origin_data_state is not canonical")
    return head, size


def _parse_origin_xrefs(value: object) -> None:
    rows = _canonical_list(value, "origin_data_state.xrefs")
    previous: tuple[int, int, int, bool, bool] | None = None
    for index, row in enumerate(rows):
        data = _keys(
            row,
            {"is_code", "user_owned", "source_ea", "target_ea", "xref_type"},
            f"origin_data_state.xrefs[{index}]",
        )
        current = (
            _int(data["source_ea"], "origin xref source_ea"),
            _int(data["target_ea"], "origin xref target_ea"),
            _int(data["xref_type"], "origin xref type"),
            data["user_owned"],
            data["is_code"],
        )
        if not isinstance(current[3], bool) or not isinstance(current[4], bool):
            raise PhaseWitnessError("origin xref flags must be booleans")
        if previous is not None and current <= previous:
            raise PhaseWitnessError("origin xrefs must be sorted and deduplicated")
        previous = current


@dataclass(frozen=True, slots=True)
class PhaseGroup:
    version: int
    origin_data_state: str
    group_targets: tuple[int, ...]
    before_items: tuple[PhaseItem, ...]
    after_items: tuple[PhaseItem, ...]
    before_xrefs: tuple[PhaseXref, ...]
    after_xrefs: tuple[PhaseXref, ...]
    reverse_before_xrefs: tuple[PhaseXref, ...]
    reverse_after_xrefs: tuple[PhaseXref, ...]
    postconditions: tuple[PhasePostcondition, ...]

    def __getitem__(self, key: str) -> object:
        return self.get(key)

    def get(self, key: str, default: object = None) -> object:
        if key == "origin_data_state":
            return self.origin_data_state
        if key == "version":
            return self.version
        if key == "group_targets":
            return list(self.group_targets)
        if key in {"before_items", "after_items"}:
            items = getattr(self, key)
            return [[item.ea, item.size, item.state] for item in items]
        if key in {"before_xrefs", "after_xrefs", "reverse_before_xrefs", "reverse_after_xrefs"}:
            return [row.as_payload() for row in getattr(self, key)]
        if key == "postconditions":
            return [{"ea": row.ea, "state": row.state} for row in self.postconditions]
        return default


def _validate_equations(group: PhaseGroup, head: int, size: int) -> None:
    before = {(row.ea, row.size, row.state) for row in group.before_items}
    after = {(row.ea, row.size, row.state) for row in group.after_items}
    if not before.issubset(after):
        raise PhaseWitnessError("after_items must contain before_items")
    targets = set(group.group_targets)
    if not targets.issubset({row.ea for row in group.before_items}):
        raise PhaseWitnessError("group_targets are missing from before_items")
    before_xrefs = set(group.before_xrefs)
    after_xrefs = set(group.after_xrefs)
    if not before_xrefs.issubset(after_xrefs):
        raise PhaseWitnessError("after_xrefs must contain before_xrefs")
    reverse_before = set(group.reverse_before_xrefs)
    reverse_after = set(group.reverse_after_xrefs)
    if not reverse_after.issubset(reverse_before):
        raise PhaseWitnessError("reverse_after_xrefs must be a subset of reverse_before_xrefs")
    for postcondition in group.postconditions:
        if postcondition.ea not in {row.ea for row in group.after_items}:
            raise PhaseWitnessError("postcondition does not name a phase item")


@dataclass(frozen=True, slots=True)
class ReverseStep:
    kind: str
    head_ea: int | None = None
    action_kind: str | None = None
    ea: int | None = None
    expected_after: str | None = None
    index: int | None = None

    def __getitem__(self, key: str) -> object:
        return self.get(key)

    def get(self, key: str, default: object = None) -> object:
        values = {
            "kind": self.kind,
            "head_ea": self.head_ea,
            "action_kind": self.action_kind,
            "ea": self.ea,
            "expected_after": self.expected_after,
            "index": self.index,
        }
        return values.get(key, default)


@dataclass(frozen=True, slots=True)
class AnalysisPhaseWitness:
    version: int
    groups: tuple[PhaseGroup, ...]
    reverse_schedule: tuple[ReverseStep, ...]
    token: str

    def __getitem__(self, key: str) -> object:
        return self.get(key)

    def get(self, key: str, default: object = None) -> object:
        if key == "version":
            return self.version
        if key == "groups":
            return self.groups
        if key == "reverse_schedule":
            return self.reverse_schedule
        return default


def parse_analysis_phase_witness(token: str) -> AnalysisPhaseWitness:
    if not isinstance(token, str):
        raise PhaseWitnessError("phase witness must be a string")
    prefix = next((value for value in ("analysis-phase:v1:", "analysis-phase:v4:") if token.startswith(value)), None)
    if prefix is None:
        raise PhaseWitnessError("missing or unsupported analysis phase version")
    try:
        payload = json.loads(token.removeprefix(prefix))
    except (TypeError, json.JSONDecodeError) as error:
        raise PhaseWitnessError("phase witness is not valid JSON") from error
    top = _keys(payload, {"version", "groups", "reverse_schedule"}, "phase witness")
    version = _int(top["version"], "version")
    expected_version = 1 if prefix.endswith("v1:") else 4
    if version != expected_version:
        raise PhaseWitnessError("phase witness version does not match its prefix")
    raw_groups = _canonical_list(top["groups"], "groups")
    groups: list[PhaseGroup] = []
    heads: set[int] = set()
    for index, raw in enumerate(raw_groups):
        data = _keys(
            raw,
            {
                "version",
                "origin_data_state", "group_targets", "before_items", "after_items",
                "before_xrefs", "after_xrefs", "reverse_before_xrefs",
                "reverse_after_xrefs", "postconditions",
            },
            f"groups[{index}]",
        )
        group_version = _int(data["version"], f"groups[{index}].version")
        if group_version != version:
            raise PhaseWitnessError("group version does not match phase version")
        origin = _str(data["origin_data_state"], f"groups[{index}].origin_data_state")
        head, size = _parse_origin(origin)
        if head in heads:
            raise PhaseWitnessError("duplicate phase group head")
        heads.add(head)
        raw_targets = _canonical_list(data["group_targets"], f"groups[{index}].group_targets")
        targets = tuple(_int(value, "group target") for value in raw_targets)
        if not targets or list(targets) != sorted(set(targets)):
            raise PhaseWitnessError("group_targets must be sorted and deduplicated")
        before_items = _parse_items(data["before_items"], f"groups[{index}].before_items")
        after_items = _parse_items(data["after_items"], f"groups[{index}].after_items")
        group = PhaseGroup(
            version=group_version,
            origin_data_state=origin,
            group_targets=targets,
            before_items=before_items,
            after_items=after_items,
            before_xrefs=_parse_xrefs(data["before_xrefs"], f"groups[{index}].before_xrefs"),
            after_xrefs=_parse_xrefs(data["after_xrefs"], f"groups[{index}].after_xrefs"),
            reverse_before_xrefs=_parse_xrefs(data["reverse_before_xrefs"], f"groups[{index}].reverse_before_xrefs"),
            reverse_after_xrefs=_parse_xrefs(data["reverse_after_xrefs"], f"groups[{index}].reverse_after_xrefs"),
            postconditions=tuple(
                PhasePostcondition(
                    _int(row["ea"], f"groups[{index}].postcondition.ea"),
                    _str(row["state"], f"groups[{index}].postcondition.state"),
                )
                for row in (
                    _keys(item, {"ea", "state"}, f"groups[{index}].postconditions[{post_index}]")
                    for post_index, item in enumerate(_canonical_list(data["postconditions"], f"groups[{index}].postconditions")))
            ),
        )
        _validate_equations(group, head, size)
        groups.append(group)

    raw_schedule = _canonical_list(top["reverse_schedule"], "reverse_schedule")
    schedule: list[ReverseStep] = []
    group_schedule: set[int] = set()
    action_indices: list[int] = []
    for index, raw in enumerate(raw_schedule):
        if not isinstance(raw, dict) or "kind" not in raw:
            raise PhaseWitnessError(f"reverse_schedule[{index}] is malformed")
        kind = raw["kind"]
        if kind == "group":
            data = _keys(raw, {"head_ea", "kind"}, f"reverse_schedule[{index}]")
            head = _int(data["head_ea"], f"reverse_schedule[{index}].head_ea")
            if head not in heads or head in group_schedule:
                raise PhaseWitnessError("reverse schedule has duplicate or unknown group")
            group_schedule.add(head)
            schedule.append(ReverseStep(kind="group", head_ea=head))
        elif kind == "action":
            data = _keys(raw, {"action_kind", "ea", "expected_after", "index", "kind"}, f"reverse_schedule[{index}]")
            action_index = _int(data["index"], f"reverse_schedule[{index}].index")
            action_indices.append(action_index)
            schedule.append(ReverseStep(
                kind="action",
                action_kind=_str(data["action_kind"], "action_kind"),
                ea=_int(data["ea"], "action ea"),
                expected_after=_str(data["expected_after"], "expected_after"),
                index=action_index,
            ))
        else:
            raise PhaseWitnessError("reverse schedule has unknown step kind")
    if group_schedule != heads:
        raise PhaseWitnessError("reverse schedule is incomplete for phase groups")
    if not action_indices:
        raise PhaseWitnessError("reverse schedule is incomplete for plan actions")
    if sorted(action_indices) != list(range(len(action_indices))):
        raise PhaseWitnessError("reverse schedule action indices are incomplete")
    canonical = prefix + json.dumps(payload, sort_keys=True, separators=(",", ":"))
    if canonical != token:
        raise PhaseWitnessError("phase witness is not canonical")
    return AnalysisPhaseWitness(version, tuple(groups), tuple(schedule), token)
