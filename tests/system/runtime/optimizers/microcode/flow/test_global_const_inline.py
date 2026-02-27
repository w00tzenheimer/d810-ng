"""System tests for GlobalConstantInliner._try_inline_globals using real microcode.

These tests replace the original mocked contract tests with tests that operate on
genuine IDA Pro microcode generated from the libobfuscated binary.

``global_const_rva_guard()`` (in ``samples/src/c/global_const_inline.c``) is
purpose-built to carry exactly two constant-global loads:

* ``SAFE_INLINE_CONST = 0x1122334455667788`` -- ordinary numeric constant;
  does **not** land in any mapped segment → **must be inlined**.
* ``RVA_LIKE_OFFSET = 0x2000`` -- when added to the PE imagebase the result
  falls inside a real segment → must **not** be inlined.

Together they exercise both branches of the pointer-filtering logic
(``_looks_like_pointer`` / ``_BadaddrSentinelHandler``) with genuine
``minsn_t`` / ``mop_t`` objects instead of hand-rolled fakes.
"""

from __future__ import annotations

import os
import platform

import pytest

import ida_hexrays
import idaapi

from d810.optimizers.microcode.flow.constant_prop import global_const_inline as gci


# ---------------------------------------------------------------------------
# Platform helpers (mirror of pattern used in sibling runtime test files)
# ---------------------------------------------------------------------------

def _get_default_binary() -> str:
    """Return the default test-binary name for the current platform."""
    override = os.environ.get("D810_TEST_BINARY")
    if override:
        return override
    return "libobfuscated.dylib" if platform.system() == "Darwin" else "libobfuscated.dll"


# ---------------------------------------------------------------------------
# Microcode helpers (inlined to avoid conftest import across package boundary)
# ---------------------------------------------------------------------------

def _get_func_ea(name: str) -> int:
    """Resolve *name* to a function EA, trying with and without underscore prefix."""
    import idc

    ea = idc.get_name_ea_simple(name)
    if ea == idaapi.BADADDR:
        ea = idc.get_name_ea_simple("_" + name)
    return ea


def _gen_microcode(func_name: str):
    """Return fresh MMAT_PREOPTIMIZED microcode for *func_name*, or ``None``."""
    func_ea = _get_func_ea(func_name)
    if func_ea == idaapi.BADADDR:
        return None

    func = idaapi.get_func(func_ea)
    if func is None:
        return None

    mbr = ida_hexrays.mba_ranges_t(func)
    hf = ida_hexrays.hexrays_failure_t()
    return ida_hexrays.gen_microcode(
        mbr, hf, None, ida_hexrays.DECOMP_NO_WAIT, ida_hexrays.MMAT_PREOPTIMIZED
    )


# ---------------------------------------------------------------------------
# Search helpers
# ---------------------------------------------------------------------------

def _find_ldx_with_value(mba, target_value: int, size: int = 8):
    """Walk *mba* for an ``m_ldx`` whose ``r`` is a ``mop_v`` that reads as *target_value*.

    Returns ``(blk, ins)`` on the first match, or ``(None, None)`` if not found.
    The value is read with ``_read_constant_value`` using *size* bytes.
    """
    for i in range(mba.qty):
        blk = mba.get_mblock(i)
        ins = blk.head
        while ins is not None:
            if ins.opcode == ida_hexrays.m_ldx and ins.r.t == ida_hexrays.mop_v:
                val = gci._read_constant_value(ins.r.g, size)
                if val == target_value:
                    return blk, ins
            ins = ins.next
    return None, None


def _find_any_const_ldx(mba):
    """Return ``(blk, ins)`` for the first ``m_ldx`` that loads from a constant global."""
    for i in range(mba.qty):
        blk = mba.get_mblock(i)
        ins = blk.head
        while ins is not None:
            if ins.opcode == ida_hexrays.m_ldx and ins.r.t == ida_hexrays.mop_v:
                if gci._is_constant_global(ins.r.g):
                    return blk, ins
            ins = ins.next
    return None, None


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------

class TestTryInlineGlobals:
    """``_try_inline_globals`` contract tests using real IDA Pro microcode.

    Uses ``global_const_rva_guard()`` -- a function purpose-built for this
    scenario -- to avoid any manual mocking of IDA API functions.
    Each test method generates its own fresh ``mba_t`` so that a successful
    inlining in one test does not corrupt the microcode seen by another.
    """

    binary_name = _get_default_binary()

    @pytest.mark.ida_required
    def test_try_inline_globals_skips_rebased_rva_pointer(self, libobfuscated_setup):
        """Must return 0 for ``RVA_LIKE_OFFSET`` (value=0x2000).

        ``imagebase + 0x2000`` lands inside the loaded PE's ``.text`` section,
        so ``_looks_like_pointer`` returns ``True`` and the constant must **not**
        be rewritten to an immediate.
        """
        rule = gci.GlobalConstantInliner()
        mba = _gen_microcode("global_const_rva_guard")
        if mba is None:
            pytest.skip("global_const_rva_guard not found in binary")

        blk, ins = _find_ldx_with_value(mba, target_value=0x2000)
        if ins is None:
            pytest.skip("Could not locate RVA_LIKE_OFFSET (0x2000) load in microcode")

        result = rule._try_inline_globals(blk, ins)

        assert result == 0, (
            "Expected _try_inline_globals to skip RVA_LIKE_OFFSET=0x2000 "
            f"(imagebase+0x2000 lands in a real segment), got result={result}"
        )
        # Opcode must remain m_ldx -- no rewrite occurred.
        assert ins.opcode == ida_hexrays.m_ldx

    @pytest.mark.ida_required
    def test_try_inline_globals_inlines_non_pointer_constant(self, libobfuscated_setup):
        """Must inline ``SAFE_INLINE_CONST`` (value=0x1122334455667788).

        This large random-looking value does not fall inside any mapped segment
        and does not match any ASLR heuristic, so ``_looks_like_pointer``
        returns ``False`` and the load must be rewritten to an ``m_mov`` with
        the immediate value.
        """
        SAFE_VALUE = 0x1122334455667788

        rule = gci.GlobalConstantInliner()
        mba = _gen_microcode("global_const_rva_guard")
        if mba is None:
            pytest.skip("global_const_rva_guard not found in binary")

        blk, ins = _find_ldx_with_value(mba, target_value=SAFE_VALUE)
        if ins is None:
            pytest.skip(
                "Could not locate SAFE_INLINE_CONST (0x1122334455667788) load in microcode"
            )

        result = rule._try_inline_globals(blk, ins)

        assert result >= 1, (
            f"Expected _try_inline_globals to inline SAFE_INLINE_CONST=0x{SAFE_VALUE:X}, "
            f"got result={result}"
        )
        # The ldx should have been rewritten to m_mov carrying the immediate.
        assert ins.opcode == ida_hexrays.m_mov, (
            f"Expected opcode m_mov after inlining, got {ins.opcode}"
        )

    @pytest.mark.ida_required
    def test_try_inline_globals_skips_badaddr_sentinel(
        self, libobfuscated_setup, monkeypatch
    ):
        """Must return 0 when the global contains an all-ones BADADDR sentinel.

        Uses real microcode from ``global_const_rva_guard`` for the instruction
        object; only ``_read_constant_value`` is patched to return ``BADADDR``
        so the ``_BadaddrSentinelHandler`` path inside ``_looks_like_pointer``
        is exercised without requiring the binary to contain actual all-ones data.
        """
        rule = gci.GlobalConstantInliner()
        mba = _gen_microcode("global_const_rva_guard")
        if mba is None:
            pytest.skip("global_const_rva_guard not found in binary")

        blk, ins = _find_any_const_ldx(mba)
        if ins is None:
            pytest.skip("No constant-global ldx found in global_const_rva_guard")

        # Patch only the value-reader to simulate a BADADDR sentinel stored at
        # the address.  All IDA segment/flag APIs remain real.
        monkeypatch.setattr(
            gci, "_read_constant_value", lambda ea, sz: int(idaapi.BADADDR)
        )

        result = rule._try_inline_globals(blk, ins)

        assert result == 0, (
            "BADADDR sentinel (0xFFFFFFFFFFFFFFFF) must not be inlined; "
            f"got result={result}"
        )
        # Opcode must remain m_ldx -- no rewrite occurred.
        assert ins.opcode == ida_hexrays.m_ldx, (
            "Instruction opcode must remain m_ldx when BADADDR is encountered"
        )
