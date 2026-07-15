"""Plan fail-closed PREOPT bridges for detached interior native entries.

This module is portable and mutation-free.  The IDA-backed investigation
harness supplies observations keyed by stable native EAs and applies accepted
plans to the current MBA.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum

from d810.core.typing import Collection, Mapping


class PreoptInteriorEntryAbstentionReason(str, Enum):
    NONEMPTY_PLACEHOLDER = "nonempty_placeholder"
    NONTERMINAL_PLACEHOLDER = "nonterminal_placeholder"
    MISSING_IMPORTED_OWNER = "missing_imported_owner"
    AMBIGUOUS_IMPORTED_OWNER = "ambiguous_imported_owner"
    IMPORTED_OWNER_ALREADY_CONNECTED = "imported_owner_already_connected"


@dataclass(frozen=True, slots=True)
class PreoptImportedEntryOwner:
    serial: int
    predecessor_count: int


@dataclass(frozen=True, slots=True)
class PreoptInteriorEntryCandidate:
    native_entry_ea: int
    placeholder_serial: int
    placeholder_instruction_count: int
    placeholder_successor_count: int
    imported_owners: tuple[PreoptImportedEntryOwner, ...]


@dataclass(frozen=True, slots=True)
class PreoptInteriorEntryBridge:
    native_entry_ea: int
    placeholder_serial: int
    imported_serial: int


@dataclass(frozen=True, slots=True)
class PreoptInteriorEntryAbstention:
    native_entry_ea: int
    reason: PreoptInteriorEntryAbstentionReason


@dataclass(frozen=True, slots=True)
class PreoptInteriorEntryBridgePlan:
    bridges: tuple[PreoptInteriorEntryBridge, ...]
    abstentions: tuple[PreoptInteriorEntryAbstention, ...]


@dataclass(frozen=True, slots=True)
class PreoptImportedEntryIndex:
    owners_by_native_entry: tuple[
        tuple[int, tuple[PreoptImportedEntryOwner, ...]],
        ...,
    ]
    ambiguous_serials: tuple[int, ...]


def index_preopt_imported_entry_owners(
    *,
    native_entry_by_instruction_ea: Mapping[int, int],
    native_origins_by_imported_serial: Mapping[int, Collection[int]],
    predecessor_count_by_imported_serial: Mapping[int, int],
) -> PreoptImportedEntryIndex:
    owners_by_entry: dict[int, list[PreoptImportedEntryOwner]] = {}
    ambiguous_serials: list[int] = []
    for serial, native_origins in sorted(native_origins_by_imported_serial.items()):
        native_entries = {
            int(native_entry_by_instruction_ea[int(origin_ea)])
            for origin_ea in native_origins
            if int(origin_ea) in native_entry_by_instruction_ea
        }
        if not native_entries:
            continue
        if (
            len(native_entries) != 1
            or int(serial) not in predecessor_count_by_imported_serial
        ):
            ambiguous_serials.append(int(serial))
            continue
        native_entry_ea = next(iter(native_entries))
        owners_by_entry.setdefault(native_entry_ea, []).append(
            PreoptImportedEntryOwner(
                serial=int(serial),
                predecessor_count=int(
                    predecessor_count_by_imported_serial[int(serial)]
                ),
            )
        )
    return PreoptImportedEntryIndex(
        owners_by_native_entry=tuple(
            (native_entry_ea, tuple(owners))
            for native_entry_ea, owners in sorted(owners_by_entry.items())
        ),
        ambiguous_serials=tuple(sorted(ambiguous_serials)),
    )


def plan_preopt_interior_entry_bridges(
    candidates: tuple[PreoptInteriorEntryCandidate, ...],
) -> PreoptInteriorEntryBridgePlan:
    bridges: list[PreoptInteriorEntryBridge] = []
    abstentions: list[PreoptInteriorEntryAbstention] = []
    for candidate in candidates:
        reason: PreoptInteriorEntryAbstentionReason | None = None
        if candidate.placeholder_instruction_count != 0:
            reason = PreoptInteriorEntryAbstentionReason.NONEMPTY_PLACEHOLDER
        elif candidate.placeholder_successor_count != 0:
            reason = PreoptInteriorEntryAbstentionReason.NONTERMINAL_PLACEHOLDER
        elif not candidate.imported_owners:
            reason = PreoptInteriorEntryAbstentionReason.MISSING_IMPORTED_OWNER
        elif len(candidate.imported_owners) != 1:
            reason = PreoptInteriorEntryAbstentionReason.AMBIGUOUS_IMPORTED_OWNER
        elif candidate.imported_owners[0].predecessor_count != 0:
            reason = (
                PreoptInteriorEntryAbstentionReason.IMPORTED_OWNER_ALREADY_CONNECTED
            )

        if reason is not None:
            abstentions.append(
                PreoptInteriorEntryAbstention(
                    native_entry_ea=int(candidate.native_entry_ea),
                    reason=reason,
                )
            )
            continue

        bridges.append(
            PreoptInteriorEntryBridge(
                native_entry_ea=int(candidate.native_entry_ea),
                placeholder_serial=int(candidate.placeholder_serial),
                imported_serial=int(candidate.imported_owners[0].serial),
            )
        )

    return PreoptInteriorEntryBridgePlan(
        bridges=tuple(bridges),
        abstentions=tuple(abstentions),
    )
