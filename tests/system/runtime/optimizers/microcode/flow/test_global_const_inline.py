"""System tests for GlobalConstantInliner pointer-filtering logic.

Background
----------
At ``MMAT_PREOPTIMIZED``, IDA already folds constant loads from read-only
globals into ``mop_n`` immediates for this binary (MinGW-compiled DLL with
``-O0 -g``), so ``mop_v`` references in source operand positions never appear.
Constructing fake ``minsn_t`` / ``mop_t`` objects to exercise
``_try_inline_globals`` directly would be equivalent to the mocked tests we
are replacing, without any benefit from having a live IDA session.

Instead we test ``_get_global_constant`` -- the **single decision function**
that ``_try_inline_globals`` delegates every inlining decision to -- against
real addresses inside the binary's ``.rdata`` section.  This covers the same
three logical branches that the mocked tests targeted:

+--------------------------------+------------------------+-------------------+
| Branch                         | Value                  | Expected outcome  |
+================================+========================+===================+
| Rebased-RVA pointer guard      | ``RVA_LIKE_OFFSET``    | returns ``None``  |
|                                | = 0x2000               | (skip inlining)   |
+--------------------------------+------------------------+-------------------+
| Normal constant inlining       | ``SAFE_INLINE_CONST``  | returns the value |
|                                | = 0x1122334455667788   | (do inline)       |
+--------------------------------+------------------------+-------------------+
| BADADDR all-ones sentinel      | 0xFFFFFFFFFFFFFFFF     | ``_looks_like_    |
|                                |                        | pointer`` = True  |
+--------------------------------+------------------------+-------------------+

The two constants are placed in ``.rdata`` by ``global_const_rva_guard()`` in
``samples/src/c/global_const_inline.c``.  We locate them by scanning the
``.rdata`` segment for their byte patterns rather than relying on symbol names
(which are not exported for static consts in MinGW builds).
"""

from __future__ import annotations

import os
import platform
import struct

import pytest

import ida_bytes
import ida_segment
import idaapi

from d810.optimizers.microcode.flow.constant_prop import global_const_inline as gci


# ---------------------------------------------------------------------------
# Platform helpers
# ---------------------------------------------------------------------------

def _get_default_binary() -> str:
    override = os.environ.get("D810_TEST_BINARY")
    if override:
        return override
    return "libobfuscated.dylib" if platform.system() == "Darwin" else "libobfuscated.dll"


# ---------------------------------------------------------------------------
# Search helper
# ---------------------------------------------------------------------------

def _find_in_rdata(target_value: int, size: int = 8) -> int:
    """Return the first EA in a read-only segment that holds *target_value*.

    Walks ``.rdata`` / ``.rodata`` / ``__const`` byte-by-byte with the given
    *size* alignment to locate the value.  Returns ``idaapi.BADADDR`` if not
    found.
    """
    pattern = struct.pack("<Q" if size == 8 else "<I", target_value)

    seg = ida_segment.get_first_seg()
    while seg is not None:
        seg_name = ida_segment.get_segm_name(seg)
        if seg_name in (".rdata", ".rodata", "__const", "__DATA_CONST"):
            ea = seg.start_ea
            end = seg.end_ea - size + 1
            while ea < end:
                raw = ida_bytes.get_bytes(ea, size)
                if raw and raw == pattern:
                    return ea
                ea += 1
        seg = ida_segment.get_next_seg(seg.start_ea)

    return idaapi.BADADDR


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------

class TestGlobalConstantInliner:
    """Pointer-filtering contract tests using real IDA Pro APIs.

    Each test exercises one branch of ``_get_global_constant`` -- the single
    decision function that ``_try_inline_globals`` calls for every candidate
    inlining site -- against real addresses found inside the binary's
    ``.rdata`` section.
    """

    binary_name = _get_default_binary()

    @pytest.mark.ida_required
    def test_skips_rebased_rva_pointer(self, libobfuscated_setup):
        """``_get_global_constant`` must return ``None`` for ``RVA_LIKE_OFFSET`` (0x2000).

        ``global_const_rva_guard`` stores ``RVA_LIKE_OFFSET = 0x2000`` in
        ``.rdata``.  When passed through the pointer-heuristic chain,
        ``imagebase + 0x2000`` lands inside the PE's ``.text`` section, so
        ``_looks_like_pointer`` returns ``True`` and the constant is
        rejected (returns ``None``).
        """
        rule = gci.GlobalConstantInliner()

        ea = _find_in_rdata(0x2000, size=8)
        if ea == idaapi.BADADDR:
            pytest.skip("RVA_LIKE_OFFSET (0x2000) not found in .rdata")

        result = rule._get_global_constant(ea, 8)

        assert result is None, (
            f"Expected None for RVA-like value 0x2000 at {ea:#x} "
            f"(imagebase+0x2000 = {idaapi.get_imagebase() + 0x2000:#x} is in .text); "
            f"got {result!r}"
        )

    @pytest.mark.ida_required
    def test_inlines_non_pointer_constant(self, libobfuscated_setup):
        """``_get_global_constant`` must return the value for ``SAFE_INLINE_CONST``.

        ``global_const_rva_guard`` stores ``SAFE_INLINE_CONST = 0x1122334455667788``
        in ``.rdata``.  This large random-looking value does not fall inside
        any mapped segment and triggers no ASLR heuristic, so
        ``_looks_like_pointer`` returns ``False`` and the function returns
        the constant directly.
        """
        SAFE_VALUE = 0x1122334455667788
        rule = gci.GlobalConstantInliner()

        ea = _find_in_rdata(SAFE_VALUE, size=8)
        if ea == idaapi.BADADDR:
            pytest.skip("SAFE_INLINE_CONST (0x1122334455667788) not found in .rdata")

        result = rule._get_global_constant(ea, 8)

        assert result == SAFE_VALUE, (
            f"Expected {SAFE_VALUE:#x} from {ea:#x}, got {result!r}"
        )

    @pytest.mark.ida_required
    def test_skips_badaddr_sentinel(self, libobfuscated_setup):
        """``_looks_like_pointer`` must return ``True`` for the BADADDR sentinel.

        The all-ones value ``0xFFFFFFFFFFFFFFFF`` is caught by
        ``_BadaddrSentinelHandler`` before any segment lookup.  We test
        ``_looks_like_pointer`` directly because no real binary address
        ordinarily holds the all-ones pattern.
        """
        result = gci._looks_like_pointer(int(idaapi.BADADDR), 8)

        assert result is True, (
            "Expected _looks_like_pointer to flag BADADDR (0xFFFFFFFFFFFFFFFF) "
            f"as pointer-like; got {result!r}"
        )
