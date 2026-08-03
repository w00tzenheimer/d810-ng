"""Hex-Rays fact adapter for the portable global constness oracle."""

from __future__ import annotations

import ida_bytes
import ida_segment
import ida_xref
import idaapi

from d810.analyses.value_flow.global_constness import (
    GlobalConstDecision,
    GlobalConstEvidence,
    GlobalConstPolicy,
    GlobalItemKind,
    decide_global_const_read,
)


def _canonical_item(address: int, read_size: int) -> tuple[int, int, GlobalItemKind]:
    try:
        item_head = int(ida_bytes.get_item_head(address))
    except Exception:
        item_head = address
    if item_head == int(idaapi.BADADDR):
        item_head = address

    try:
        item_size = int(ida_bytes.get_item_size(item_head))
    except Exception:
        item_size = 0
    if item_size <= 0:
        item_size = max(int(read_size), 0)

    try:
        flags = ida_bytes.get_full_flags(item_head)
        if ida_bytes.is_code(flags):
            item_kind = GlobalItemKind.CODE
        elif ida_bytes.is_data(flags):
            item_kind = GlobalItemKind.DATA
        elif ida_bytes.is_tail(flags):
            item_kind = GlobalItemKind.TAIL
        else:
            item_kind = GlobalItemKind.UNKNOWN
    except Exception:
        item_kind = GlobalItemKind.UNKNOWN
    return item_head, item_head + item_size, item_kind


def _segment_permissions(address: int) -> tuple[bool, bool, bool]:
    try:
        segment = ida_segment.getseg(address)
        if segment is None:
            return False, False, False
        permissions = int(segment.perm)
        return (
            bool(permissions & int(ida_segment.SEGPERM_READ)),
            bool(permissions & int(ida_segment.SEGPERM_WRITE)),
            bool(permissions & int(ida_segment.SEGPERM_EXEC)),
        )
    except Exception:
        return False, False, False


def _has_direct_write(item_head: int, item_end: int) -> bool:
    for target_ea in range(item_head, item_end):
        try:
            references = ida_xref.xrefblk_t()
            found = references.first_to(target_ea, ida_xref.XREF_ALL)
            while found:
                if references.type == ida_xref.dr_W:
                    return True
                found = references.next_to()
        except Exception:
            continue
    return False


def _read_value(address: int, size: int) -> int | None:
    try:
        if size == 1:
            value = idaapi.get_byte(address)
        elif size == 2:
            value = idaapi.get_word(address)
        elif size == 4:
            value = idaapi.get_dword(address)
        elif size == 8:
            value = idaapi.get_qword(address)
        else:
            return None
        return None if value == idaapi.BADADDR else int(value)
    except Exception:
        return None


def capture_hexrays_global_const_evidence(
    address: int,
    size: int,
    *,
    reaching_write: bool = False,
    initializer_stable_at_read: bool = False,
) -> GlobalConstEvidence:
    """Capture architecture-neutral facts for one concrete IDB memory read."""

    item_head, item_end, item_kind = _canonical_item(int(address), int(size))
    readable, writable, executable = _segment_permissions(int(address))
    return GlobalConstEvidence(
        address=int(address),
        item_head=item_head,
        item_end=item_end,
        read_size=int(size),
        readable=readable,
        writable=writable,
        executable=executable,
        item_kind=item_kind,
        has_direct_write=_has_direct_write(item_head, item_end),
        reaching_write=bool(reaching_write),
        initializer_stable_at_read=bool(initializer_stable_at_read),
        value=_read_value(int(address), int(size)),
    )


def decide_hexrays_global_read(
    address: int,
    size: int,
    *,
    policy: GlobalConstPolicy = GlobalConstPolicy.STRICT,
    allow_executable_readonly: bool = False,
    reaching_write: bool = False,
    initializer_stable_at_read: bool = False,
) -> GlobalConstDecision:
    """Capture IDB facts and classify one read with the portable oracle."""

    evidence = capture_hexrays_global_const_evidence(
        address,
        size,
        reaching_write=reaching_write,
        initializer_stable_at_read=initializer_stable_at_read,
    )
    return decide_global_const_read(
        evidence,
        policy,
        allow_executable_readonly=allow_executable_readonly,
    )


__all__ = [
    "capture_hexrays_global_const_evidence",
    "decide_hexrays_global_read",
]
