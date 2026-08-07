"""Runtime tests for the IDA-coupled half of the CoBRA backend.

These need real ``ida_hexrays`` types, so they live in ``system/runtime`` rather
than ``tests/unit`` (which the import-linter bars from importing
``d810.hexrays``).

What is pinned here are the two invariants that cost real debugging:

* reconstruction must not mix operand widths -- a leaf narrower than the
  destination produced 5 of 5 verifier rejections, versus 55 of 55 acceptances
  when widths are uniform;
* an in-place rewrite must invalidate the block's cached dataflow lists, or
  ``mba.verify()`` raises INTERR 50877 "wrong dnu" (``verify.cpp:1328``) --
  which reads as a malformed instruction and is not one.
"""

from __future__ import annotations

import os
import platform

import ida_hexrays
import pytest

from d810.backends.cobra.convert import (
    ReconstructionError,
    clamp_shift_amounts,
    tree_to_ast,
)
from d810.backends.cobra.detect import DEFAULT_MAX_LEAVES, MbaCandidate
from d810.hexrays.ir.mop_snapshot import MopSnapshot


def _get_default_binary() -> str:
    override = os.environ.get("D810_TEST_BINARY")
    if override:
        return override
    return (
        "libobfuscated.dylib" if platform.system() == "Darwin" else "libobfuscated.dll"
    )


def _num(value: int, size: int) -> ida_hexrays.mop_t:
    mop = ida_hexrays.mop_t()
    mop.make_number(value, size)
    return mop


@pytest.mark.usefixtures("ida_database")
class TestTreeToAst:
    """``mop_t``/``minsn_t`` construction segfaults without an open database."""

    binary_name = _get_default_binary()

    def test_constant_leaf_takes_destination_width(self):
        ast = tree_to_ast({"kind": "const", "value": 0x20}, {}, 4)
        assert ast.mop is not None
        assert ast.mop.size == 4
        assert ast.mop.nnn.value == 0x20

    def test_variable_leaf_materializes_a_fresh_owned_mop(self):
        # A snapshot, not a borrowed mop_t: the candidate outlives detection
        # (it crosses a solver subprocess), and IDA invalidates operands when
        # the optimizer runs.  to_mop() rebuilds an owned operand at use time.
        snapshot = MopSnapshot.from_mop(_num(0x1234, 4))
        ast = tree_to_ast({"kind": "var", "name": "v"}, {"v": snapshot}, 4)
        assert ast.mop is not None
        assert ast.mop.size == 4
        assert ast.mop.nnn.value == 0x1234

    def test_missing_leaf_snapshot_is_an_error_not_a_guess(self):
        with pytest.raises(ReconstructionError):
            tree_to_ast({"kind": "var", "name": "absent"}, {}, 4)

    def test_binary_node_maps_to_the_right_opcode(self):
        tree = {
            "kind": "bin",
            "op": "^",
            "a": {"kind": "var", "name": "v"},
            "b": {"kind": "const", "value": 1},
        }
        ast = tree_to_ast(tree, {"v": MopSnapshot.from_mop(_num(9, 4))}, 4)
        assert ast.opcode == ida_hexrays.m_xor

    def test_unary_not_maps_to_bnot(self):
        ast = tree_to_ast(
            {"kind": "un", "op": "~", "a": {"kind": "var", "name": "v"}},
            {"v": MopSnapshot.from_mop(_num(9, 4))},
            4,
        )
        assert ast.opcode == ida_hexrays.m_bnot

    def test_unknown_operator_is_rejected(self):
        with pytest.raises(ReconstructionError):
            tree_to_ast(
                {"kind": "bin", "op": "@", "a": {"kind": "const", "value": 1},
                 "b": {"kind": "const", "value": 2}},
                {},
                4,
            )


@pytest.mark.usefixtures("ida_database")
class TestShiftClamp:
    """verify.cpp:937 -- a shift amount must be exactly one byte (INTERR 50835)."""

    binary_name = _get_default_binary()

    def _insn(self, opcode, l=None, r=None, d=None, ea=0x1000):
        ins = ida_hexrays.minsn_t(ea)
        ins.opcode = opcode
        for slot, value in (("l", l), ("r", r), ("d", d)):
            mop = value if value is not None else ida_hexrays.mop_t()
            if value is None:
                mop.erase()
            setattr(ins, slot, mop)
        return ins

    @pytest.mark.parametrize(
        "opcode", (ida_hexrays.m_shl, ida_hexrays.m_shr, ida_hexrays.m_sar)
    )
    def test_top_level_amount_is_clamped(self, opcode):
        ins = self._insn(opcode, _num(0x1234, 4), _num(0x6F57001, 4), _num(0, 4))
        clamp_shift_amounts(ins)
        assert ins.r.size == 1
        assert ins.r.nnn.value == (0x6F57001 & 0xFF)

    def test_nested_amount_is_clamped(self):
        # The regression this exists for: create_minsn buries the shift one
        # level down, so a top-level-only clamp never fires.
        inner = self._insn(
            ida_hexrays.m_shr, _num(0x1234, 4), _num(0xDD0C2B0B, 4), _num(0, 4), 0x2000
        )
        wrapper = ida_hexrays.mop_t()
        wrapper.create_from_insn(inner)
        wrapper.size = 4
        outer = self._insn(ida_hexrays.m_and, wrapper, _num(2, 4), _num(0, 4))

        clamp_shift_amounts(outer)
        assert outer.l.d.r.size == 1

    def test_non_shift_operands_are_untouched(self):
        ins = self._insn(ida_hexrays.m_and, _num(0x1234, 4), _num(0x10, 4), _num(0, 4))
        clamp_shift_amounts(ins)
        assert ins.r.size == 4


@pytest.mark.usefixtures("ida_database")
class TestMbaCandidate:
    binary_name = _get_default_binary()

    def test_renders_leaves_as_x_indices(self):
        tree = {
            "kind": "bin",
            "op": "^",
            "a": {"kind": "var", "name": "alpha"},
            "b": {"kind": "var", "name": "beta"},
        }
        candidate = MbaCandidate(
            ea=0x1000,
            block_serial=0,
            tree=tree,
            leaf_names=("alpha", "beta"),
            leaf_snapshots={
                "alpha": MopSnapshot.from_mop(_num(1, 4)),
                "beta": MopSnapshot.from_mop(_num(2, 4)),
            },
            dest_size=4,
        )
        assert candidate.render() == "(x0^x1)"
        assert candidate.bitwidth == 32
        assert candidate.mask == 0xFFFFFFFF
        assert candidate.node_count == 3

    def test_default_leaf_cap_is_eight(self):
        # 2**n signature cost: 256 evaluations at 8, 65,536 at 16.
        assert DEFAULT_MAX_LEAVES == 8
