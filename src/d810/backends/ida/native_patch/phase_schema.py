"""Strict, provider-neutral schema for the analysis-phase witness.

The witness is journal authority, not an advisory cache.  This module keeps
its decoded representation immutable and makes parsing a single validation
boundary.  Callers may use the small mapping facade for compatibility with
older gateway code, but values returned by the facade are derived from the
same frozen objects held by :class:`AnalysisPhaseWitness`.
"""

from __future__ import annotations

import json
import hashlib
from dataclasses import dataclass, replace

from d810.core.typing import Any

__all__ = [
    "AnalysisPhaseWitness",
    "AnalysisPhaseAttestation",
    "canonical_phase_item_state",
    "materialize_analysis_phase",
    "PhaseGroup",
    "PhaseGlobalState",
    "PhaseExtent",
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
class PhaseExtent:
    low: int
    high: int

    def as_payload(self) -> list[int]:
        return [self.low, self.high]


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


@dataclass(frozen=True, slots=True)
class PhaseGlobalState:
    """Canonical complete item/xref state at one reverse cut point."""

    items: tuple[PhaseItem, ...]
    xrefs: tuple[PhaseXref, ...]
    extents: tuple[PhaseExtent, ...]

    def as_payload(self) -> dict[str, object]:
        return {
            "items": [[item.ea, item.size, item.state] for item in self.items],
            "xrefs": [row.as_payload() for row in self.xrefs],
            "extents": [extent.as_payload() for extent in self.extents],
        }


def canonical_phase_item_state(state: str, *, head_ea: int) -> str:
    """Canonicalize a global item snapshot independently of query anchor.

    A data snapshot can be captured by querying any byte in its item.  The
    query ``ea``/``offset`` are action-local witnesses, not identity of the
    global item partition, so phase-state authority always anchors them at
    the item head.  Other payload fields (including bytes, flags and xrefs)
    remain unchanged.
    """
    if not isinstance(state, str) or not state:
        raise PhaseWitnessError("item state must be a non-empty string")
    if not state.startswith("data:v2:"):
        return state
    if not isinstance(head_ea, int) or isinstance(head_ea, bool) or head_ea < 0:
        raise PhaseWitnessError("item head must be a non-negative integer")
    try:
        payload = json.loads(state.removeprefix("data:v2:"))
    except (TypeError, ValueError) as error:
        raise PhaseWitnessError("data:v2 item state is not valid JSON") from error
    if not isinstance(payload, dict):
        raise PhaseWitnessError("data:v2 item state must be an object")
    payload_head = payload.get("head_ea")
    if payload_head != head_ea:
        raise PhaseWitnessError(
            f"data:v2 item head {payload_head!r} does not match {head_ea:#x}"
        )
    payload["ea"] = head_ea
    payload["offset"] = 0
    return "data:v2:" + json.dumps(payload, sort_keys=True, separators=(",", ":"))


def _parse_items(value: object, field: str) -> tuple[PhaseItem, ...]:
    rows = _canonical_list(value, field)
    parsed: list[PhaseItem] = []
    previous_end = -1
    previous_item: PhaseItem | None = None
    for index, row in enumerate(rows):
        if not isinstance(row, list) or len(row) != 3:
            raise PhaseWitnessError(f"{field}[{index}] must be [ea, size, state]")
        ea = _int(row[0], f"{field}[{index}].ea")
        size = _int(row[1], f"{field}[{index}].size")
        if size <= 0:
            raise PhaseWitnessError(f"{field}[{index}].size must be positive")
        state = canonical_phase_item_state(
            _str(row[2], f"{field}[{index}].state"), head_ea=ea
        )
        _validate_phase_item_state(ea, size, state, f"{field}[{index}].state")
        if ea < previous_end:
            raise PhaseWitnessError(
                f"{field} item ranges overlap at {ea:#x} with "
                f"{previous_item.ea:#x}+{previous_item.size:#x} "
                f"({previous_item.state!r} vs {state!r})"
            )
        previous_end = ea + size
        previous_item = PhaseItem(ea, size, state)
        parsed.append(previous_item)
    if [item.ea for item in parsed] != [row[0] for row in rows] or [
        item.size for item in parsed
    ] != [row[1] for row in rows]:
        raise PhaseWitnessError(f"{field} is not in canonical order")
    return tuple(parsed)


def _validate_phase_item_state(ea: int, size: int, state: str, field: str) -> None:
    if state == "unknown":
        return
    if state.startswith("code:"):
        try:
            code_size = int(state.removeprefix("code:"))
        except ValueError as error:
            raise PhaseWitnessError(f"{field} has malformed code state") from error
        if code_size <= 0 or code_size != size or state != f"code:{code_size}":
            raise PhaseWitnessError(f"{field} code size does not match item size")
        return
    if state.startswith("data:v2:"):
        head, data_size = _parse_origin(state)
        if head != ea or data_size != size:
            raise PhaseWitnessError(f"{field} data extent does not match item extent")
        return
    raise PhaseWitnessError(f"{field} has unsupported item state")


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


def _parse_extent(value: object, field: str) -> PhaseExtent:
    if not isinstance(value, list) or len(value) != 2:
        raise PhaseWitnessError(f"{field} must be [low, high]")
    low = _int(value[0], f"{field}.low")
    high = _int(value[1], f"{field}.high")
    if high <= low:
        raise PhaseWitnessError(f"{field} must be non-empty")
    if value != [low, high]:
        raise PhaseWitnessError(f"{field} is not canonical")
    return PhaseExtent(low, high)


def _parse_global_state(value: object, field: str) -> PhaseGlobalState:
    data = _keys(value, {"items", "xrefs", "extents"}, field)
    raw_extents = _canonical_list(data["extents"], f"{field}.extents")
    extents: list[PhaseExtent] = []
    previous: tuple[int, int] | None = None
    for index, raw in enumerate(raw_extents):
        if not isinstance(raw, list) or len(raw) != 2:
            raise PhaseWitnessError(f"{field}.extents[{index}] must be [low, high]")
        low = _int(raw[0], f"{field}.extents[{index}].low")
        high = _int(raw[1], f"{field}.extents[{index}].high")
        current = (low, high)
        if high <= low or (previous is not None and current <= previous):
            raise PhaseWitnessError(f"{field}.extents are empty or not canonical")
        extents.append(PhaseExtent(low, high))
        previous = current
    if not extents:
        raise PhaseWitnessError(f"{field}.extents must not be empty")
    items = _parse_items(data["items"], f"{field}.items")
    for extent in extents:
        cursor = extent.low
        for item in items:
            item_end = item.ea + item.size
            if item_end <= extent.low:
                continue
            if item.ea >= extent.high:
                break
            start = max(item.ea, extent.low)
            end = min(item_end, extent.high)
            if start > cursor:
                raise PhaseWitnessError(f"{field}.items do not cover extents")
            cursor = max(cursor, end)
            if cursor == extent.high:
                break
        if cursor != extent.high:
            raise PhaseWitnessError(f"{field}.items do not cover extents")
    for item in items:
        cursor = item.ea
        item_end = item.ea + item.size
        for extent in extents:
            if extent.high <= cursor:
                continue
            if extent.low > cursor:
                break
            cursor = max(cursor, extent.high)
            if cursor >= item_end:
                break
        if cursor < item_end:
            raise PhaseWitnessError(
                f"{field}.item is outside extents: {item.ea:#x}+{item.size:#x}"
            )
    xrefs = _parse_xrefs(data["xrefs"], f"{field}.xrefs")
    for row in xrefs:
        touches_extent = any(
            extent.low <= endpoint < extent.high
            for extent in extents
            for endpoint in (row.source_ea, row.target_ea)
        )
        if not touches_extent:
            raise PhaseWitnessError(
                f"{field}.xref does not touch a declared extent"
            )
    return PhaseGlobalState(
        items=items,
        xrefs=xrefs,
        extents=tuple(extents),
    )


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
    origin_extent: PhaseExtent | None = None
    destruction_extent: PhaseExtent | None = None

    def __getitem__(self, key: str) -> object:
        return self.get(key)

    def get(self, key: str, default: object = None) -> object:
        if key == "origin_data_state":
            return self.origin_data_state
        if key == "version":
            return self.version
        if key in {"origin_extent", "destruction_extent"}:
            extent = getattr(self, key)
            return None if extent is None else extent.as_payload()
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


def _validate_equations(
    group: PhaseGroup, head: int, size: int, *, require_complete: bool = False
) -> None:
    before = {(row.ea, row.size, row.state) for row in group.before_items}
    after = {(row.ea, row.size, row.state) for row in group.after_items}
    # Reanalysis may refine an UNKNOWN gap into one or more decoded code
    # items.  Concrete before-items must survive unchanged; unknown rows are
    # allowed to split as long as both partitions cover the full carrier.
    before_concrete = {row for row in before if row[2] != "unknown"}
    if not before_concrete.issubset(after):
        raise PhaseWitnessError("after_items lost a concrete before item")
    if require_complete:
        if group.origin_extent is None or group.destruction_extent is None:
            raise PhaseWitnessError("phase v4 group extents are missing")
        if (
            group.origin_extent.low != head
            or group.origin_extent.high != head + size
            or group.destruction_extent.low != head
            or group.destruction_extent.high < group.origin_extent.high
        ):
            raise PhaseWitnessError("phase group extents are inconsistent")
        coverage_high = max(
            group.destruction_extent.high,
            *(row.ea + row.size for row in group.before_items),
            *(row.ea + row.size for row in group.after_items),
        )
        for label, rows in (("before_items", group.before_items), ("after_items", group.after_items)):
            cursor = head
            for row in rows:
                if row.ea != cursor or row.ea + row.size > coverage_high:
                    raise PhaseWitnessError(f"{label} does not cover the carrier extent")
                cursor = row.ea + row.size
            if cursor != coverage_high:
                raise PhaseWitnessError(f"{label} does not cover the carrier extent")
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
    before_state: str | None = None
    after_state: str | None = None
    before_items: tuple[PhaseItem, ...] = ()
    after_items: tuple[PhaseItem, ...] = ()
    before_xrefs: tuple[PhaseXref, ...] = ()
    after_xrefs: tuple[PhaseXref, ...] = ()
    global_before: PhaseGlobalState | None = None
    global_after: PhaseGlobalState | None = None
    cleared_state: PhaseGlobalState | None = None
    origin_extent: PhaseExtent | None = None
    destruction_extent: PhaseExtent | None = None
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
            "before_state": self.before_state,
            "after_state": self.after_state,
            "before_items": [[item.ea, item.size, item.state] for item in self.before_items],
            "after_items": [[item.ea, item.size, item.state] for item in self.after_items],
            "before_xrefs": [row.as_payload() for row in self.before_xrefs],
            "after_xrefs": [row.as_payload() for row in self.after_xrefs],
            "global_before": (
                None if self.global_before is None else self.global_before.as_payload()
            ),
            "global_after": (
                None if self.global_after is None else self.global_after.as_payload()
            ),
            "cleared_state": (
                None if self.cleared_state is None else self.cleared_state.as_payload()
            ),
            "origin_extent": (
                None if self.origin_extent is None else self.origin_extent.as_payload()
            ),
            "destruction_extent": (
                None
                if self.destruction_extent is None
                else self.destruction_extent.as_payload()
            ),
            "expected_after": self.expected_after,
            "index": self.index,
        }
        return values.get(key, default)


def materialize_analysis_phase(
    phase: AnalysisPhaseWitness, observed: PhaseGlobalState
) -> AnalysisPhaseWitness:
    """Derive exact sequential reverse cuts from concrete post-analysis P."""
    if phase.version < 4 or not phase.reverse_schedule:
        return phase

    same_as_authorized_seal = phase.sealed_state == observed

    def state(
        items: set[PhaseItem],
        xrefs: set[PhaseXref],
        extents: tuple[PhaseExtent, ...],
    ) -> PhaseGlobalState:
        return PhaseGlobalState(
            tuple(sorted(items, key=lambda row: (row.ea, row.size, row.state))),
            tuple(sorted(
                xrefs,
                key=lambda row: (
                    row.source_ea, row.target_ea, row.xref_type,
                    row.user_owned, row.is_code,
                ),
            )),
            extents,
        )

    current = observed
    materialized: list[ReverseStep] = []
    groups_by_head = {
        _parse_origin(group.origin_data_state)[0]: group for group in phase.groups
    }
    for step in phase.reverse_schedule:
        if step.global_before is None or step.global_after is None:
            raise PhaseWitnessError("phase reverse schedule lacks global states")
        current_items = set(current.items)
        current_xrefs = set(current.xrefs)
        removed_xrefs = set(step.global_before.xrefs) - set(step.global_after.xrefs)
        next_xrefs = current_xrefs - removed_xrefs
        cleared_state = None
        if step.kind == "group":
            extent = step.destruction_extent
            if extent is None:
                raise PhaseWitnessError("phase group destruction extent is missing")
            low, high = extent.low, extent.high
            outside = {
                item for item in current_items
                if item.ea + item.size <= low or item.ea >= high
            }
            restored_inside = {
                item for item in step.global_after.items
                if item.ea >= low and item.ea + item.size <= high
            }
            group = groups_by_head.get(step.head_ea)
            if group is not None and group.origin_data_state.startswith("data:v2:"):
                origin_payload = json.loads(
                    group.origin_data_state.removeprefix("data:v2:")
                )
                origin_payload["xrefs"] = [
                    row.as_payload() for row in group.reverse_after_xrefs
                ]
                inverse_origin = "data:v2:" + json.dumps(
                    origin_payload, sort_keys=True, separators=(",", ":")
                )
                restored_inside = {
                    (
                        PhaseItem(
                            item.ea,
                            item.size,
                            canonical_phase_item_state(inverse_origin, head_ea=item.ea),
                        )
                        if item.ea == _parse_origin(group.origin_data_state)[0]
                        else item
                    )
                    for item in restored_inside
                }
            next_items = outside | restored_inside
            # IDA's lossless data recreation inverse deletes the carrier
            # extent but preserves incoming non-code data references owned by
            # surrounding metadata.  Only references sourced by the deleted
            # extent, or control references into it, are part of the cleared
            # state.  Binding this distinction keeps an interrupted real
            # del_items cut exactly observable without broad xref subtraction.
            cleared_xrefs = {
                row
                for row in next_xrefs
                if not (
                    low <= row.source_ea < high
                    or (low <= row.target_ea < high and row.is_code)
                )
            }
            cleared_state = state(
                outside | {PhaseItem(low, high - low, "unknown")},
                cleared_xrefs,
                current.extents,
            )
            if (
                same_as_authorized_seal
                and step.cleared_state is not None
                and step.cleared_state != cleared_state
            ):
                raise PhaseWitnessError(
                    "phase reverse schedule cleared state does not match materialization"
                )
        else:
            next_items = current_items
        next_state = state(next_items, next_xrefs, current.extents)
        materialized.append(replace(
            step,
            global_before=current,
            global_after=next_state,
            cleared_state=cleared_state,
        ))
        current = next_state
    return replace(
        phase,
        sealed_state=observed,
        reverse_schedule=tuple(materialized),
    )


@dataclass(frozen=True, slots=True)
class AnalysisPhaseWitness:
    version: int
    groups: tuple[PhaseGroup, ...]
    reverse_schedule: tuple[ReverseStep, ...]
    token: str
    sealed_state: PhaseGlobalState | None = None
    origin_state: PhaseGlobalState | None = None

    def __getitem__(self, key: str) -> object:
        return self.get(key)

    def get(self, key: str, default: object = None) -> object:
        if key == "version":
            return self.version
        if key == "groups":
            return self.groups
        if key == "reverse_schedule":
            return self.reverse_schedule
        if key == "sealed_state":
            return self.sealed_state
        if key == "origin_state":
            return self.origin_state
        return default


@dataclass(frozen=True, slots=True)
class AnalysisPhaseAttestation:
    """Exact post-analysis authority separate from v4 authorization."""

    version: int
    transaction_id: str
    authorization_hash: str
    observed_state: PhaseGlobalState
    reverse_schedule: tuple[ReverseStep, ...]
    lifecycle_cut: str
    phase_witness: AnalysisPhaseWitness
    token: str


def _reverse_step_payload(
    step: ReverseStep, *, include_phase_state: bool = True
) -> dict[str, object]:
    payload: dict[str, object] = {"kind": step.kind}
    for key in (
        "head_ea", "action_kind", "ea", "before_state", "after_state",
        "expected_after", "index",
    ):
        value = step.get(key)
        if value is not None:
            payload[key] = value
    if include_phase_state:
        for key in ("before_items", "after_items", "before_xrefs", "after_xrefs"):
            value = step.get(key)
            if value:
                payload[key] = value
        for key in ("global_before", "global_after", "cleared_state"):
            value = step.get(key)
            if value is not None:
                payload[key] = value
        for key in ("origin_extent", "destruction_extent"):
            value = step.get(key)
            if value is not None:
                payload[key] = value
    return payload


def make_analysis_phase_attestation(
    authorization_token: str,
    phase_witness: AnalysisPhaseWitness,
    observed_state: PhaseGlobalState,
    transaction_id: str,
    *,
    lifecycle_cut: str = "analysis_reconciled",
) -> str:
    """Serialize an exact observed-P attestation with canonical authority."""
    authorization_hash = hashlib.sha256(authorization_token.encode()).hexdigest()
    if not isinstance(transaction_id, str) or not transaction_id:
        raise PhaseWitnessError("analysis attestation transaction_id is required")
    materialized = materialize_analysis_phase(phase_witness, observed_state)

    payload = {
        "version": 1,
        "transaction_id": transaction_id,
        "authorization_hash": authorization_hash,
        "observed_state": observed_state.as_payload(),
        "reverse_schedule": [
            _reverse_step_payload(
                step, include_phase_state=materialized.version >= 4
            )
            for step in materialized.reverse_schedule
        ],
        "lifecycle_cut": lifecycle_cut,
        "phase_witness": phase_witness.token,
    }
    return "analysis-attestation:v1:" + json.dumps(
        payload, sort_keys=True, separators=(",", ":")
    )


def parse_analysis_phase_attestation(token: str) -> AnalysisPhaseAttestation:
    if not isinstance(token, str) or not token.startswith("analysis-attestation:v1:"):
        raise PhaseWitnessError("missing or unsupported analysis attestation version")
    try:
        payload = json.loads(token.removeprefix("analysis-attestation:v1:"))
    except (TypeError, json.JSONDecodeError) as error:
        raise PhaseWitnessError("analysis attestation is not valid JSON") from error
    data = _keys(
        payload,
        {
            "version", "transaction_id", "authorization_hash", "observed_state",
            "reverse_schedule", "lifecycle_cut", "phase_witness",
        },
        "analysis attestation",
    )
    if _int(data["version"], "analysis attestation.version") != 1:
        raise PhaseWitnessError("analysis attestation version is unsupported")
    authorization_hash = _str(data["authorization_hash"], "authorization_hash")
    if len(authorization_hash) != 64 or any(char not in "0123456789abcdef" for char in authorization_hash):
        raise PhaseWitnessError("authorization_hash is not canonical")
    lifecycle_cut = _str(data["lifecycle_cut"], "lifecycle_cut")
    if lifecycle_cut != "analysis_reconciled":
        raise PhaseWitnessError("analysis attestation lifecycle_cut is unsupported")
    nested = _str(data["phase_witness"], "phase_witness")
    transaction_id = _str(data["transaction_id"], "transaction_id")
    if hashlib.sha256(nested.encode()).hexdigest() != authorization_hash:
        raise PhaseWitnessError("analysis attestation authorization hash mismatch")
    phase = parse_analysis_phase_witness(nested)
    raw_schedule = _canonical_list(data["reverse_schedule"], "reverse_schedule")
    observed_state = _parse_global_state(data["observed_state"], "observed_state")
    materialized = materialize_analysis_phase(phase, observed_state)
    expected_schedule = [
        _reverse_step_payload(step, include_phase_state=materialized.version >= 4)
        for step in materialized.reverse_schedule
    ]
    if raw_schedule != expected_schedule:
        raise PhaseWitnessError(
            "analysis attestation reverse schedule does not match phase witness"
        )
    if phase.version >= 4:
        if phase.sealed_state is None:
            raise PhaseWitnessError("phase v4 authorization state is missing")
        if observed_state.extents != phase.sealed_state.extents:
            raise PhaseWitnessError(
                "observed state extents are outside phase authorization"
            )
        authorized_code = {
            (item.ea, item.size, item.state)
            for item in phase.sealed_state.items
            if item.state.startswith("code:")
        }
        observed_code = {
            (item.ea, item.size, item.state)
            for item in observed_state.items
            if item.state.startswith("code:")
        }
        if observed_code - authorized_code or not authorized_code.issubset(observed_code):
            raise PhaseWitnessError(
                "observed code items do not match phase authorization"
            )
        if observed_state.xrefs != phase.sealed_state.xrefs:
            raise PhaseWitnessError(
                "observed xrefs do not match phase authorization"
            )
    canonical = "analysis-attestation:v1:" + json.dumps(
        payload, sort_keys=True, separators=(",", ":")
    )
    if canonical != token:
        raise PhaseWitnessError("analysis attestation is not canonical")
    return AnalysisPhaseAttestation(
        1,
        transaction_id,
        authorization_hash,
        observed_state,
        materialized.reverse_schedule,
        lifecycle_cut,
        phase,
        token,
    )


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
    top_keys = {"version", "groups", "reverse_schedule"}
    if prefix.endswith("v4:"):
        top_keys |= {"sealed_state", "origin_state"}
    top = _keys(payload, top_keys, "phase witness")
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
                *({"origin_extent", "destruction_extent"} if prefix.endswith("v4:") else set()),
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
            origin_extent=(
                _parse_extent(data["origin_extent"], f"groups[{index}].origin_extent")
                if version >= 4 else None
            ),
            destruction_extent=(
                _parse_extent(
                    data["destruction_extent"],
                    f"groups[{index}].destruction_extent",
                )
                if version >= 4 else None
            ),
        )
        _validate_equations(group, head, size, require_complete=version >= 4)
        groups.append(group)

    sealed_state = (
        _parse_global_state(top["sealed_state"], "sealed_state")
        if version >= 4 else None
    )
    origin_state = (
        _parse_global_state(top["origin_state"], "origin_state")
        if version >= 4 else None
    )
    raw_schedule = _canonical_list(top["reverse_schedule"], "reverse_schedule")
    schedule: list[ReverseStep] = []
    group_schedule: set[int] = set()
    action_indices: list[int] = []
    for index, raw in enumerate(raw_schedule):
        if not isinstance(raw, dict) or "kind" not in raw:
            raise PhaseWitnessError(f"reverse_schedule[{index}] is malformed")
        kind = raw["kind"]
        if kind == "group":
            expected = {"head_ea", "kind"}
            if version >= 4:
                expected |= {
                    "before_items", "after_items", "before_xrefs", "after_xrefs",
                    "global_before", "global_after", "cleared_state",
                    "origin_extent", "destruction_extent",
                }
            data = _keys(raw, expected, f"reverse_schedule[{index}]")
            head = _int(data["head_ea"], f"reverse_schedule[{index}].head_ea")
            if head not in heads or head in group_schedule:
                raise PhaseWitnessError("reverse schedule has duplicate or unknown group")
            group_schedule.add(head)
            group = next(group for group in groups if _parse_origin(group.origin_data_state)[0] == head)
            if version >= 4:
                if _parse_items(data["before_items"], f"reverse_schedule[{index}].before_items") != group.before_items:
                    raise PhaseWitnessError("reverse group before_items do not match phase group")
                if _parse_items(data["after_items"], f"reverse_schedule[{index}].after_items") != group.after_items:
                    raise PhaseWitnessError("reverse group after_items do not match phase group")
                if _parse_xrefs(data["before_xrefs"], f"reverse_schedule[{index}].before_xrefs") != group.before_xrefs:
                    raise PhaseWitnessError("reverse group before_xrefs do not match phase group")
                if _parse_xrefs(data["after_xrefs"], f"reverse_schedule[{index}].after_xrefs") != group.after_xrefs:
                    raise PhaseWitnessError("reverse group after_xrefs do not match phase group")
                global_before = _parse_global_state(
                    data["global_before"], f"reverse_schedule[{index}].global_before"
                )
                global_after = _parse_global_state(
                    data["global_after"], f"reverse_schedule[{index}].global_after"
                )
                cleared_state = _parse_global_state(
                    data["cleared_state"], f"reverse_schedule[{index}].cleared_state"
                )
                origin_extent = _parse_extent(
                    data["origin_extent"], f"reverse_schedule[{index}].origin_extent"
                )
                destruction_extent = _parse_extent(
                    data["destruction_extent"],
                    f"reverse_schedule[{index}].destruction_extent",
                )
                if (
                    origin_extent != group.origin_extent
                    or destruction_extent != group.destruction_extent
                ):
                    raise PhaseWitnessError(
                        "reverse group extents do not match phase group"
                    )
            else:
                global_before = global_after = cleared_state = None
                origin_extent = destruction_extent = None
            schedule.append(ReverseStep(
                kind="group", head_ea=head,
                before_items=tuple(group.before_items), after_items=tuple(group.after_items),
                before_xrefs=tuple(group.before_xrefs), after_xrefs=tuple(group.after_xrefs),
                global_before=global_before, global_after=global_after,
                cleared_state=cleared_state,
                origin_extent=origin_extent,
                destruction_extent=destruction_extent,
            ))
        elif kind == "action":
            expected = {"action_kind", "ea", "expected_after", "index", "kind"}
            if version >= 4:
                expected |= {"before_state", "after_state", "global_before", "global_after"}
            data = _keys(raw, expected, f"reverse_schedule[{index}]")
            action_index = _int(data["index"], f"reverse_schedule[{index}].index")
            action_indices.append(action_index)
            if version >= 4:
                global_before = _parse_global_state(
                    data["global_before"], f"reverse_schedule[{index}].global_before"
                )
                global_after = _parse_global_state(
                    data["global_after"], f"reverse_schedule[{index}].global_after"
                )
            else:
                global_before = global_after = None
            schedule.append(ReverseStep(
                kind="action",
                action_kind=_str(data["action_kind"], "action_kind"),
                ea=_int(data["ea"], "action ea"),
                before_state=(_str(data["before_state"], "before_state") if version >= 4 else None),
                after_state=(_str(data["after_state"], "after_state") if version >= 4 else None),
                expected_after=_str(data["expected_after"], "expected_after"),
                index=action_index,
                global_before=global_before, global_after=global_after,
            ))
        else:
            raise PhaseWitnessError("reverse schedule has unknown step kind")
    if group_schedule != heads:
        raise PhaseWitnessError("reverse schedule is incomplete for phase groups")
    if not action_indices:
        raise PhaseWitnessError("reverse schedule is incomplete for plan actions")
    if len(set(action_indices)) != len(action_indices):
        raise PhaseWitnessError("reverse schedule action indices are duplicated")
    if version >= 4:
        if sealed_state is None or origin_state is None:
            raise PhaseWitnessError("phase v4 global states are missing")
        if not schedule or schedule[0].global_before != sealed_state:
            raise PhaseWitnessError("reverse schedule does not start at sealed state")
        for previous, current in zip(schedule, schedule[1:]):
            if previous.global_after != current.global_before:
                raise PhaseWitnessError("reverse schedule global states are not adjacent")
        if schedule[-1].global_after != origin_state:
            raise PhaseWitnessError("reverse schedule does not end at origin state")
    canonical = prefix + json.dumps(payload, sort_keys=True, separators=(",", ":"))
    if canonical != token:
        raise PhaseWitnessError("phase witness is not canonical")
    return AnalysisPhaseWitness(
        version, tuple(groups), tuple(schedule), token, sealed_state, origin_state
    )
