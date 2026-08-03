"""Portable policy for deciding whether a global-memory read is constant."""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum


class GlobalItemKind(str, Enum):
    """Backend-neutral classification of the canonical item containing a read."""

    DATA = "data"
    CODE = "code"
    TAIL = "tail"
    UNKNOWN = "unknown"


class GlobalConstPolicy(str, Enum):
    """User-selected evidence strength for ephemeral read materialization."""

    STRICT = "strict"
    AGGRESSIVE_NO_DIRECT_WRITES = "aggressive_no_direct_writes"


class GlobalConstReason(str, Enum):
    """Stable explanation for one constness decision."""

    READONLY_DATA = "readonly_data"
    INITIALIZER_STABLE_AT_READ = "initializer_stable_at_read"
    AGGRESSIVE_NO_DIRECT_WRITES = "aggressive_no_direct_writes"
    DANGEROUS_EXECUTABLE_READONLY_OVERRIDE = (
        "dangerous_executable_readonly_override"
    )
    NOT_READABLE = "not_readable"
    WRITABLE_MEMORY = "writable_memory"
    DIRECT_WRITE_WITHOUT_STABLE_READ = "direct_write_without_stable_read"
    REACHING_WRITE = "reaching_write"
    EXECUTABLE_ITEM_REJECTED = "executable_item_rejected"
    UNSUPPORTED_ITEM_KIND = "unsupported_item_kind"
    UNSUPPORTED_WIDTH = "unsupported_width"
    READ_OUT_OF_BOUNDS = "read_out_of_bounds"
    VALUE_UNAVAILABLE = "value_unavailable"


@dataclass(frozen=True, slots=True)
class GlobalConstEvidence:
    """Facts needed to classify one concrete memory read."""

    address: int
    item_head: int
    item_end: int
    read_size: int
    readable: bool
    writable: bool
    executable: bool
    item_kind: GlobalItemKind
    has_direct_write: bool
    reaching_write: bool
    initializer_stable_at_read: bool
    value: int | None


@dataclass(frozen=True, slots=True)
class GlobalConstDecision:
    """Separate ephemeral-read and persistent-global constness decisions."""

    can_inline_read: bool
    can_persist_const: bool
    value: int | None
    reason: GlobalConstReason
    used_dangerous_override: bool = False


_SUPPORTED_WIDTHS = frozenset({1, 2, 4, 8})


def _reject(reason: GlobalConstReason) -> GlobalConstDecision:
    return GlobalConstDecision(
        can_inline_read=False,
        can_persist_const=False,
        value=None,
        reason=reason,
    )


def _inline(
    evidence: GlobalConstEvidence,
    reason: GlobalConstReason,
    *,
    persist: bool = False,
    dangerous: bool = False,
) -> GlobalConstDecision:
    return GlobalConstDecision(
        can_inline_read=True,
        can_persist_const=persist,
        value=evidence.value,
        reason=reason,
        used_dangerous_override=dangerous,
    )


def decide_global_const_read(
    evidence: GlobalConstEvidence,
    policy: GlobalConstPolicy,
    *,
    allow_executable_readonly: bool = False,
) -> GlobalConstDecision:
    """Classify one read without inferring target platform or file format.

    ``allow_executable_readonly`` is deliberately narrow: it may bypass only
    the item-kind guard for readable, non-writable executable memory. It does
    not bypass invalid reads, write evidence, or value availability, and it
    never authorizes persistent ``const``.
    """

    if evidence.read_size not in _SUPPORTED_WIDTHS:
        return _reject(GlobalConstReason.UNSUPPORTED_WIDTH)
    if not (
        evidence.item_head <= evidence.address
        and evidence.address + evidence.read_size <= evidence.item_end
    ):
        return _reject(GlobalConstReason.READ_OUT_OF_BOUNDS)
    if evidence.value is None:
        return _reject(GlobalConstReason.VALUE_UNAVAILABLE)
    if not evidence.readable:
        return _reject(GlobalConstReason.NOT_READABLE)
    if evidence.reaching_write:
        return _reject(GlobalConstReason.REACHING_WRITE)
    if evidence.initializer_stable_at_read:
        return _inline(
            evidence,
            GlobalConstReason.INITIALIZER_STABLE_AT_READ,
        )
    if evidence.has_direct_write:
        return _reject(GlobalConstReason.DIRECT_WRITE_WITHOUT_STABLE_READ)

    if evidence.writable:
        if (
            policy is GlobalConstPolicy.AGGRESSIVE_NO_DIRECT_WRITES
            and evidence.item_kind is GlobalItemKind.DATA
        ):
            return _inline(
                evidence,
                GlobalConstReason.AGGRESSIVE_NO_DIRECT_WRITES,
            )
        return _reject(GlobalConstReason.WRITABLE_MEMORY)

    if evidence.item_kind is GlobalItemKind.DATA:
        return _inline(
            evidence,
            GlobalConstReason.READONLY_DATA,
            persist=True,
        )

    if evidence.executable and allow_executable_readonly:
        return _inline(
            evidence,
            GlobalConstReason.DANGEROUS_EXECUTABLE_READONLY_OVERRIDE,
            dangerous=True,
        )

    if evidence.executable:
        return _reject(GlobalConstReason.EXECUTABLE_ITEM_REJECTED)
    return _reject(GlobalConstReason.UNSUPPORTED_ITEM_KIND)


__all__ = [
    "GlobalConstDecision",
    "GlobalConstEvidence",
    "GlobalConstPolicy",
    "GlobalConstReason",
    "GlobalItemKind",
    "decide_global_const_read",
]
