"""Operand-based folded-loop-guard counter/bound extraction (ticket llr-pydd).

Covers the matrix the hardening replaced the brittle TEXT regex with:

    {stack counter, reg counter}
      x {sign-bit ``m_sub`` form, direct ``m_setl`` / ``m_jl``}
      x {signed, unsigned}
      x {operand order normal, swapped}

Asserts the structured ``(counter_identity, bound, signed)`` extraction and that
a non-induction or non-const operand is rejected.  These synthetic
``_InstructionView``s are the register-path proof: the Tigress binary's counter
is stack-resident, so the register guard path is NOT exercised live yet.
"""
from __future__ import annotations

import pytest

from d810.analyses.value_flow.folded_loop_guard import (
    FoldedLoopGuardFactCollector,
    _InductionVar,
    _induction_vars,
)
from d810.analyses.value_flow.induction_carrier import (
    _InstructionView,
    _classify_induction_update,
)
from d810.ir.flowgraph import InsnKind, MopSnapshot, OperandKind


_STK = 0x1E0  # microcode stkoff of a stack-resident counter
_REG = 0x18   # mreg_t of a register-resident counter
_BOUND = 0x64  # numeric trip-count bound (100)


def _view(
    *,
    opcode_name: str,
    src_l_type: str | None = None,
    src_l_stkoff: int | None = None,
    src_l_value: int | None = None,
    src_l_reg: int | None = None,
    src_r_type: str | None = None,
    src_r_stkoff: int | None = None,
    src_r_value: int | None = None,
    src_r_reg: int | None = None,
    dest_stkoff: int | None = None,
    dest_reg: int | None = None,
    dest_size: int | None = 4,
) -> _InstructionView:
    return _InstructionView(
        block_serial=10,
        insn_index=0,
        ea=0x180010000,
        opcode_name=opcode_name,
        dest_type=None,
        dest_stkoff=dest_stkoff,
        dest_size=dest_size,
        src_l_type=src_l_type,
        src_l_stkoff=src_l_stkoff,
        src_l_value=src_l_value,
        src_r_type=src_r_type,
        src_r_stkoff=src_r_stkoff,
        src_r_value=src_r_value,
        dstr="",
        dest_reg=dest_reg,
        src_l_reg=src_l_reg,
        src_r_reg=src_r_reg,
    )


def _stack_counter() -> _InductionVar:
    return _InductionVar(size=4, stkoff=_STK)


def _reg_counter() -> _InductionVar:
    return _InductionVar(size=4, reg=_REG)


# --- induction enumeration (stack + register self-updates) -----------------


def test_enumerates_stack_self_update() -> None:
    # i = i + 1  (stack)
    add = _view(
        opcode_name="m_add",
        src_l_type="mop_S",
        src_l_stkoff=_STK,
        src_r_type="mop_n",
        src_r_value=1,
        dest_stkoff=_STK,
    )
    vars_ = _induction_vars((add,))
    assert len(vars_) == 1
    assert vars_[0].stkoff == _STK
    assert vars_[0].reg is None


def test_enumerates_register_self_update() -> None:
    # r = r + 1  (register)
    add = _view(
        opcode_name="m_add",
        src_l_type="mop_r",
        src_l_reg=_REG,
        src_r_type="mop_n",
        src_r_value=1,
        dest_reg=_REG,
    )
    update = _classify_induction_update(add)
    assert update is not None and update.step == 1
    vars_ = _induction_vars((add,))
    assert len(vars_) == 1
    assert vars_[0].reg == _REG
    assert vars_[0].stkoff is None


def test_register_self_update_sub_negative_step() -> None:
    sub = _view(
        opcode_name="m_sub",
        src_l_type="mop_r",
        src_l_reg=_REG,
        src_r_type="mop_n",
        src_r_value=1,
        dest_reg=_REG,
    )
    update = _classify_induction_update(sub)
    assert update is not None and update.step == -1


# --- guard matrix: stack counter -------------------------------------------


@pytest.mark.parametrize(
    "opcode_name, signed",
    [
        ("m_sub", True),   # sign-bit (i - N) < 0 form
        ("sub", True),     # portable InsnKind alias of m_sub
        ("m_setl", True),
        ("m_jl", True),
        ("m_setb", False),
        ("m_jb", False),
        ("m_jae", False),
        ("m_setae", False),
        ("m_jle", True),
        ("m_jg", True),
    ],
)
def test_stack_guard_normal_order(opcode_name: str, signed: bool) -> None:
    guard = _view(
        opcode_name=opcode_name,
        src_l_type="mop_S",
        src_l_stkoff=_STK,
        src_r_type="mop_n",
        src_r_value=_BOUND,
        dest_stkoff=0x200,  # writes a temp, NOT a self-update
    )
    result = FoldedLoopGuardFactCollector._guard_counter([guard], (_stack_counter(),))
    assert result is not None
    counter, bound, got_signed = result
    assert counter.stkoff == _STK
    assert bound == _BOUND
    assert got_signed is signed


@pytest.mark.parametrize("opcode_name, signed", [("m_setl", True), ("m_setb", False)])
def test_stack_guard_swapped_order(opcode_name: str, signed: bool) -> None:
    # const on the LEFT, induction var on the RIGHT
    guard = _view(
        opcode_name=opcode_name,
        src_l_type="mop_n",
        src_l_value=_BOUND,
        src_r_type="mop_S",
        src_r_stkoff=_STK,
        dest_stkoff=0x200,
    )
    result = FoldedLoopGuardFactCollector._guard_counter([guard], (_stack_counter(),))
    assert result is not None
    counter, bound, got_signed = result
    assert counter.stkoff == _STK
    assert bound == _BOUND
    assert got_signed is signed


# --- guard matrix: register counter ----------------------------------------


@pytest.mark.parametrize(
    "opcode_name, signed",
    [("m_sub", True), ("m_setl", True), ("m_jl", True), ("m_setb", False), ("m_jb", False)],
)
def test_register_guard_normal_order(opcode_name: str, signed: bool) -> None:
    guard = _view(
        opcode_name=opcode_name,
        src_l_type="mop_r",
        src_l_reg=_REG,
        src_r_type="mop_n",
        src_r_value=_BOUND,
        dest_reg=0x40,  # writes a temp reg, NOT a self-update
    )
    result = FoldedLoopGuardFactCollector._guard_counter([guard], (_reg_counter(),))
    assert result is not None
    counter, bound, got_signed = result
    assert counter.reg == _REG
    assert counter.stkoff is None
    assert bound == _BOUND
    assert got_signed is signed


@pytest.mark.parametrize("opcode_name, signed", [("m_setl", True), ("m_setb", False)])
def test_register_guard_swapped_order(opcode_name: str, signed: bool) -> None:
    guard = _view(
        opcode_name=opcode_name,
        src_l_type="mop_n",
        src_l_value=_BOUND,
        src_r_type="mop_r",
        src_r_reg=_REG,
        dest_reg=0x40,
    )
    result = FoldedLoopGuardFactCollector._guard_counter([guard], (_reg_counter(),))
    assert result is not None
    counter, bound, got_signed = result
    assert counter.reg == _REG
    assert bound == _BOUND
    assert got_signed is signed


# --- rejection cases --------------------------------------------------------


def test_rejects_non_induction_operand() -> None:
    # left operand is a DIFFERENT stack slot, not the induction counter
    guard = _view(
        opcode_name="m_setl",
        src_l_type="mop_S",
        src_l_stkoff=0x700,
        src_r_type="mop_n",
        src_r_value=_BOUND,
        dest_stkoff=0x200,
    )
    assert (
        FoldedLoopGuardFactCollector._guard_counter([guard], (_stack_counter(),))
        is None
    )


def test_rejects_non_const_other_operand() -> None:
    # both operands are stack slots; the bound is not a constant
    guard = _view(
        opcode_name="m_setl",
        src_l_type="mop_S",
        src_l_stkoff=_STK,
        src_r_type="mop_S",
        src_r_stkoff=0x300,
        dest_stkoff=0x200,
    )
    assert (
        FoldedLoopGuardFactCollector._guard_counter([guard], (_stack_counter(),))
        is None
    )


def test_rejects_non_guard_opcode() -> None:
    # m_mov is not a compare/subtract guard opcode
    guard = _view(
        opcode_name="m_mov",
        src_l_type="mop_S",
        src_l_stkoff=_STK,
        src_r_type="mop_n",
        src_r_value=_BOUND,
        dest_stkoff=0x200,
    )
    assert (
        FoldedLoopGuardFactCollector._guard_counter([guard], (_stack_counter(),))
        is None
    )


def test_rejects_non_positive_bound() -> None:
    guard = _view(
        opcode_name="m_setl",
        src_l_type="mop_S",
        src_l_stkoff=_STK,
        src_r_type="mop_n",
        src_r_value=0,
        dest_stkoff=0x200,
    )
    assert (
        FoldedLoopGuardFactCollector._guard_counter([guard], (_stack_counter(),))
        is None
    )


def test_reg_counter_not_matched_by_stack_operand() -> None:
    # a reg-keyed induction var must not bind to a stack operand of same number
    guard = _view(
        opcode_name="m_setl",
        src_l_type="mop_S",
        src_l_stkoff=_REG,  # same integer, but a STACK operand
        src_r_type="mop_n",
        src_r_value=_BOUND,
        dest_stkoff=0x200,
    )
    assert (
        FoldedLoopGuardFactCollector._guard_counter([guard], (_reg_counter(),))
        is None
    )


# --- nested operand-tree shape (the REAL live Tigress LOCOPT shape) ---------
#
# These rebuild the EXACT structured operands the lifter captures for the live
# instructions, where the ``(counter - #0x64)`` subtract is NOT a flat
# top-level operand but a sub-node buried inside an ``m_xdu`` / ``m_jge`` tree:
#
#   xdu (%var_1E0.4 - #0x64.4), rdx.8
#   jge ((bnot((%var_1D0.4 - #0x64.4)) | (%var_1D0.4 ^ #0x64.4))
#        & (xdu(%var_1D0.1) | #0xFFFFFF9B.4)), #0, @33
#
# The flat ``_InstructionView`` fields are all None for these; only the
# ``src_l_mop`` / ``src_r_mop`` MopSnapshot subtree carries the counter.


def _stk_mop(stkoff: int, size: int = 4) -> MopSnapshot:
    return MopSnapshot(size=size, stkoff=stkoff, kind=OperandKind.STACK)


def _reg_mop(reg: int, size: int = 4) -> MopSnapshot:
    return MopSnapshot(size=size, reg=reg, kind=OperandKind.REGISTER)


def _num_mop(value: int, size: int = 4) -> MopSnapshot:
    return MopSnapshot(size=size, value=value, kind=OperandKind.NUMBER)


def _subinsn_mop(kind: InsnKind, left: MopSnapshot, right: MopSnapshot, size: int = 4) -> MopSnapshot:
    """A ``mop_d`` (SUBINSN) operand wrapping a binary sub-operation."""
    return MopSnapshot(
        size=size,
        kind=OperandKind.SUBINSN,
        sub_kind=kind,
        sub_l=left,
        sub_r=right,
    )


def _tree_view(opcode_name: str, *, src_l_mop=None, src_r_mop=None) -> _InstructionView:
    """An ``_InstructionView`` whose flat operands are empty -- only the
    structured ``src_l_mop`` / ``src_r_mop`` subtree carries the predicate."""
    return _InstructionView(
        block_serial=10,
        insn_index=0,
        ea=0x180010000,
        opcode_name=opcode_name,
        dest_type=None,
        dest_stkoff=None,
        dest_size=4,
        src_l_type="mop_d",
        src_l_stkoff=None,
        src_l_value=None,
        src_r_type=None,
        src_r_stkoff=None,
        src_r_value=None,
        dstr="",
        dest_reg=None,
        src_l_reg=None,
        src_r_reg=None,
        src_l_mop=src_l_mop,
        src_r_mop=src_r_mop,
    )


def test_nested_xdu_buried_subtract_stack_counter() -> None:
    # xdu (%var_1E0.4 - #0x64.4)  -- the live LOCOPT widen shape
    sub = _subinsn_mop(InsnKind.SUB, _stk_mop(_STK), _num_mop(_BOUND))
    guard = _tree_view("m_xdu", src_l_mop=sub)
    result = FoldedLoopGuardFactCollector._guard_counter([guard], (_stack_counter(),))
    assert result is not None
    counter, bound, signed = result
    assert counter.stkoff == _STK
    assert bound == _BOUND
    assert signed is True


def test_nested_jge_deep_buried_subtract_stack_counter() -> None:
    # jge ((bnot((%var_1D0.4 - #0x64.4)) | (%var_1D0.4 ^ #0x64.4)) & (...)), #0
    # The (counter - bound) subtract is two levels deep inside an AND/OR tree.
    sub = _subinsn_mop(InsnKind.SUB, _stk_mop(_STK), _num_mop(_BOUND))
    bnot = MopSnapshot(
        size=4, kind=OperandKind.SUBINSN, sub_kind=InsnKind.UNKNOWN, sub_l=sub
    )
    xor = _subinsn_mop(InsnKind.UNKNOWN, _stk_mop(_STK), _num_mop(_BOUND))
    or_node = _subinsn_mop(InsnKind.UNKNOWN, bnot, xor)
    mask = _subinsn_mop(
        InsnKind.UNKNOWN,
        _subinsn_mop(InsnKind.XDU, _stk_mop(_STK, size=1), _num_mop(0)),
        _num_mop(0xFFFFFF9B),
    )
    and_node = _subinsn_mop(InsnKind.AND, or_node, mask)
    guard = _tree_view("m_jge", src_l_mop=and_node, src_r_mop=_num_mop(0))
    result = FoldedLoopGuardFactCollector._guard_counter([guard], (_stack_counter(),))
    assert result is not None
    counter, bound, signed = result
    assert counter.stkoff == _STK
    assert bound == _BOUND
    assert signed is True


def test_nested_buried_subtract_register_counter() -> None:
    # xds (r - #0x64)  -- the register-resident counter variant of the tree shape
    sub = _subinsn_mop(InsnKind.SUB, _reg_mop(_REG), _num_mop(_BOUND))
    guard = _tree_view("m_xds", src_l_mop=sub)
    result = FoldedLoopGuardFactCollector._guard_counter([guard], (_reg_counter(),))
    assert result is not None
    counter, bound, signed = result
    assert counter.reg == _REG
    assert bound == _BOUND
    assert signed is True


def test_nested_unsigned_tree_host_renders_unsigned() -> None:
    # an unsigned tree host (m_jb) over a buried (counter - bound) => setb
    sub = _subinsn_mop(InsnKind.SUB, _stk_mop(_STK), _num_mop(_BOUND))
    guard = _tree_view("m_jb", src_l_mop=sub, src_r_mop=_num_mop(0))
    result = FoldedLoopGuardFactCollector._guard_counter([guard], (_stack_counter(),))
    assert result is not None
    _counter, _bound, signed = result
    assert signed is False


def test_nested_rejects_non_induction_buried_subtract() -> None:
    # buried subtract over a DIFFERENT stack slot must not match the counter
    sub = _subinsn_mop(InsnKind.SUB, _stk_mop(0x700), _num_mop(_BOUND))
    guard = _tree_view("m_xdu", src_l_mop=sub)
    assert (
        FoldedLoopGuardFactCollector._guard_counter([guard], (_stack_counter(),))
        is None
    )


def test_nested_rejects_buried_non_sub_node() -> None:
    # buried node is an XOR (not a SUB), even with (counter, const) children
    xor = _subinsn_mop(InsnKind.UNKNOWN, _stk_mop(_STK), _num_mop(_BOUND))
    guard = _tree_view("m_xdu", src_l_mop=xor)
    assert (
        FoldedLoopGuardFactCollector._guard_counter([guard], (_stack_counter(),))
        is None
    )
