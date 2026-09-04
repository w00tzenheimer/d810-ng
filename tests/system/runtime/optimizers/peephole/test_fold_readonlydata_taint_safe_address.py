"""Runtime: ``_try_emulator_eval_address`` must not fold a tainted address.

Ticket ``d81-1jj1`` (review of ``d81-3xer`` / commit ``37fc08857``): the source
-level regression test (``tests/unit/optimizers/peephole/
test_fold_readonlydata_taint_safe_address.py``) only asserts that the raw
``interpreter.eval(`` call string is absent and that ``eval_mop_result``` /
``address_from_eval_result`` appear somewhere in the file. That is hollow --
it would still pass if the wiring called the exact-result API but ignored its
answer. This test drives the REAL rule method
(``FoldReadonlyDataRule._try_emulator_eval_address``) through the REAL
``MicroCodeInterpreter`` against hand-built microcode and asserts on its
*return value*:

* an address expression whose offset derives from an unmodeled call's
  synthetic return (``EvalResult.tainted(...)``) must fold to ``None``;
* the same expression with a proven numeric offset (``EvalResult.exact(...)``)
  must fold to the address.

The taint is produced through the real mechanism (an ``m_call`` whose callee
operand is ``mop_v`` -- unmodeled, per ``MicroCodeInterpreter._eval_call`` --
so the emulator invents a synthetic return and records it via
``_note_synthetic_result``), not by monkeypatching ``eval_mop_result``. The
only handcrafted parts are the microcode operands/instructions themselves,
following the pattern used by
``tests/system/runtime/evaluator/test_tainted_control_flow.py``.

Both cases go through the exact same code path required by the ticket: the
address operand is a ``mop_d`` wrapping ``add(&byte_TABLE, <offset>)``, which
satisfies ``_try_emulator_eval_address``'s guards (``ins.opcode == m_ldx``,
``addr_mop.t == mop_d``, ``_contains_mop_v(addr_mop)``) exactly as the real
``ldx ds, add(&byte_TABLE, xds(xdu(...)))`` shape the method's docstring
describes.
"""

from __future__ import annotations

import os
import platform

import ida_hexrays
import pytest

from d810.optimizers.microcode.instructions.peephole.fold_readonlydata import (
    FoldReadonlyDataRule,
)

from tests.system.runtime.conftest import gen_microcode_at_maturity

#: Arbitrary but plausible pointer-sized base; ``mop_a`` -> ``mop_v`` reads
#: ``mop.a.g`` directly (no live segment lookup), so this need not resolve to
#: an actual global in the sample binary.
_TABLE_EA = 0x1800296A0
_OFFSET = 0x10

#: Scratch micro-registers, well above the ABI ones the sample code uses.
_SCRATCH_DEST = ida_hexrays.mr_first + 96
_SCRATCH_LDX_DEST = ida_hexrays.mr_first + 104


def _get_default_binary() -> str:
    override = os.environ.get("D810_TEST_BINARY")
    if override:
        return override
    system = platform.system()
    if system == "Windows":
        return "libobfuscated.dll"
    if system == "Darwin":
        return "libobfuscated.dylib"
    return "libobfuscated.so"


def _gvar_address_mop(ea: int, size: int = 8) -> ida_hexrays.mop_t:
    """``&global`` -- a ``mop_a`` wrapping a ``mop_v``.

    ``mop_t.assign(mop_addr_t(...))`` does NOT set ``.t = mop_a`` -- verified
    empirically: ``mop_addr_t``'s constructor copy-constructs its ``mop_t``
    base from the wrapped operand (``mop_t(ra)`` in ``hexrays.hpp``), so the
    ``mop_addr_t`` instance's OWN ``.t`` is still ``ra.t`` (``mop_v`` here),
    and ``assign()`` copies that verbatim -- silently producing a plain
    ``mop_v`` at the SAME address instead of an address-of operand. The
    working construction is a direct attribute assignment: ``operand.t =
    mop_a; operand.a = <mop_addr_t>``.
    """
    base = ida_hexrays.mop_t()
    base.make_gvar(ea)
    address = ida_hexrays.mop_addr_t(base, size, size)
    operand = ida_hexrays.mop_t()
    operand.t = ida_hexrays.mop_a
    operand.a = address
    operand.size = size
    return operand


def _unmodeled_call_mop(ea: int, callee_ea: int, size: int = 8) -> ida_hexrays.mop_t:
    """A ``mop_d`` wrapping ``call &callee`` -- an UNMODELED callee.

    ``MicroCodeInterpreter._eval_call`` treats a ``mop_v``/``mop_b`` callee as
    unmodeled: it invents a stable synthetic return and records the site via
    ``_note_synthetic_result``, which is exactly the mechanism the P1 fix
    guards against being mistaken for a proven address.
    """
    callee = ida_hexrays.mop_t()
    callee.make_gvar(callee_ea)
    call_ins = ida_hexrays.minsn_t(ea)
    call_ins.opcode = ida_hexrays.m_call
    call_ins.l = callee
    call_ins.r = ida_hexrays.mop_t()
    call_ins.d = ida_hexrays.mop_t()
    call_ins.d.size = size
    result = ida_hexrays.mop_t()
    result._make_insn(call_ins)
    result.size = size
    return result


def _number_mop(value: int, size: int) -> ida_hexrays.mop_t:
    mop = ida_hexrays.mop_t()
    mop.make_number(value, size)
    return mop


def _add_address_expr(
    ea: int, base: ida_hexrays.mop_t, offset: ida_hexrays.mop_t, size: int = 8
) -> ida_hexrays.mop_t:
    """``add(base, offset)`` wrapped as a ``mop_d`` address expression."""
    add_ins = ida_hexrays.minsn_t(ea)
    add_ins.opcode = ida_hexrays.m_add
    add_ins.l = base
    add_ins.r = offset
    add_ins.d = ida_hexrays.mop_t()
    add_ins.d._make_reg(_SCRATCH_DEST, size)
    addr_mop = ida_hexrays.mop_t()
    addr_mop._make_insn(add_ins)
    addr_mop.size = size
    return addr_mop


def _ldx_insn(ea: int, addr_mop: ida_hexrays.mop_t) -> ida_hexrays.minsn_t:
    ins = ida_hexrays.minsn_t(ea)
    ins.opcode = ida_hexrays.m_ldx
    ins.l = ida_hexrays.mop_t()
    ins.l._make_reg(ida_hexrays.mr_first, 2)  # segment placeholder; unused by
    # _try_emulator_eval_address, which only reads ins.r for m_ldx.
    ins.r = addr_mop
    ins.d = ida_hexrays.mop_t()
    ins.d._make_reg(_SCRATCH_LDX_DEST, 1)
    return ins


@pytest.fixture(scope="class")
def real_block(libobfuscated_setup):
    """``(mba, blk)`` for any live block -- the address expression is entirely
    synthetic, so only ``blk.mba`` needs to be a real, live microcode block for
    ``MicroCodeEnvironment.set_cur_flow`` to anchor on.

    The ``mba_t`` MUST be kept alive alongside ``blk`` for the whole test: an
    ``mblock_t`` does not keep its owning ``mba_t`` alive from Python, so
    returning ``blk`` alone lets the ``mba_t`` get garbage-collected while
    ``blk`` still points at its freed memory -- a native segfault in
    ``set_cur_flow``, not a Python exception (same pattern as ``live_call`` in
    ``test_tainted_control_flow.py``).
    """
    import idautils

    for func_ea in idautils.Functions():
        mba = gen_microcode_at_maturity(func_ea, ida_hexrays.MMAT_CALLS)
        if mba is None:
            continue
        for serial in range(mba.qty):
            blk = mba.get_mblock(serial)
            if blk is not None:
                return mba, blk
    pytest.skip("no live microcode block found in the sample binary")
    raise AssertionError("unreachable")  # pragma: no cover


class TestTryEmulatorEvalAddressRejectsTaint:
    """``_try_emulator_eval_address`` must fold only an EXACT address."""

    binary_name = _get_default_binary()

    def test_a_tainted_offset_yields_no_address(self, real_block) -> None:
        _mba, blk = real_block  # keep mba ALIVE for the whole test (see fixture docstring)
        rule = object.__new__(FoldReadonlyDataRule)
        base = _gvar_address_mop(_TABLE_EA)
        offset = _unmodeled_call_mop(0x1000, 0x2000)
        addr_mop = _add_address_expr(0x1004, base, offset)
        ins = _ldx_insn(0x1008, addr_mop)

        result = rule._try_emulator_eval_address(ins, blk)

        assert result is None, (
            "a synthetic-call-derived (tainted) address must never be folded"
        )

    def test_the_corresponding_exact_offset_yields_the_address(
        self, real_block
    ) -> None:
        _mba, blk = real_block  # keep mba ALIVE for the whole test (see fixture docstring)
        rule = object.__new__(FoldReadonlyDataRule)
        base = _gvar_address_mop(_TABLE_EA)
        offset = _number_mop(_OFFSET, 8)
        addr_mop = _add_address_expr(0x1004, base, offset)
        ins = _ldx_insn(0x1008, addr_mop)

        result = rule._try_emulator_eval_address(ins, blk)

        assert result == _TABLE_EA + _OFFSET
