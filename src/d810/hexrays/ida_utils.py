"""Low-level IDA utility helpers for cross-reference and segment queries.

These functions wrap IDA SDK calls (xrefblk_t, segment permissions, is_loaded)
and live in the ``d810.hexrays`` layer so that both ``d810.expr`` and
``d810.optimizers`` can use them without creating circular dependencies.
"""

from idaapi import (
    SEGPERM_READ,
    SEGPERM_WRITE,
    XREF_DATA,
    dr_W,
    getseg,
    is_loaded,
    segment_t,
    xrefblk_t,
)


def segment_is_read_only(addr: int) -> bool:
    """Check if address is in a read-only segment based on segment permissions.

    Returns True if segment has READ but not WRITE permission.
    This is a fast check based on IDA's segment metadata.
    """
    s: segment_t = getseg(addr)
    if s is None:
        return False
    return (s.perm & SEGPERM_READ) != 0 and (s.perm & SEGPERM_WRITE) == 0


def is_never_written_var(address: int) -> bool:
    """Check if a variable at address is never written to by any code.

    Unlike is_read_only_inited_var(), this does NOT require the segment
    to be read-only. It only checks that no code writes to this address,
    making it suitable for detecting opaque constant tables in writable
    segments (e.g., volatile globals used in OLLVM obfuscation).
    """
    if is_loaded(address):
        return False
    ref_finder = xrefblk_t()
    is_ok = ref_finder.first_to(address, XREF_DATA)
    while is_ok:
        if ref_finder.type == dr_W:
            return False
        is_ok = ref_finder.next_to()
    return True


def is_read_only_inited_var(address: int) -> bool:
    """Stricter check for truly read-only initialized variables.

    Returns True only if ALL of:
    1. Address is in a read-only segment (segment_is_read_only)
    2. Address is NOT a loaded (imported) symbol
    3. No write xrefs point to this address (static analysis)

    Use this for optimization passes where we need to be certain
    the value cannot change at runtime.
    """
    if not segment_is_read_only(address):
        return False
    if is_loaded(address):
        return False
    ref_finder = xrefblk_t()
    is_ok = ref_finder.first_to(address, XREF_DATA)
    while is_ok:
        if ref_finder.type == dr_W:
            return False
        is_ok = ref_finder.next_to()
    return True
