from __future__ import annotations

from dataclasses import dataclass

import pytest

from d810.cfg.contracts import invariants as inv


_HR = inv.ida_hexrays


class _Vec(list):
    def size(self) -> int:
        return len(self)


class _Cases:
    def __init__(self, targets: list[int]):
        self.targets = _Vec(targets)


@dataclass
class _Mop:
    t: int
    b: int | None = None
    c: object | None = None

    def is_mblock(self) -> bool:
        return self.t == int(getattr(_HR, "mop_b"))


class _Insn:
    def __init__(
        self,
        opcode: int,
        *,
        l: _Mop | None = None,
        d: _Mop | None = None,
        r: _Mop | None = None,
        ea: int = 0x401000,
        noret: bool = False,
    ):
        self.opcode = int(opcode)
        self.l = l
        self.d = d
        self.r = r
        self.ea = int(ea)
        self._noret = bool(noret)

    def is_noret_call(self, *_args) -> bool:
        return self._noret


class _Block:
    def __init__(
        self,
        serial: int,
        *,
        block_type: int,
        succs: list[int] | None = None,
        preds: list[int] | None = None,
        tail: _Insn | None = None,
        call_block: bool = False,
    ):
        self.serial = int(serial)
        self.type = int(block_type)
        self.succset = _Vec(list(succs or []))
        self.predset = _Vec(list(preds or []))
        self.tail = tail
        self.nextb: _Block | None = None
        self.prevb: _Block | None = None
        self._call_block = bool(call_block)

    def nsucc(self) -> int:
        return len(self.succset)

    def is_call_block(self) -> bool:
        return self._call_block


class _MBA:
    def __init__(self, blocks: list[_Block]):
        self._blocks = {blk.serial: blk for blk in blocks}
        self.qty = len(blocks)

    def get_mblock(self, serial: int):
        return self._blocks.get(int(serial))


def _linear_mba(qty: int, default_type: int | None = None) -> tuple[_MBA, list[_Block]]:
    block_type = int(default_type if default_type is not None else getattr(_HR, "BLT_0WAY"))
    blocks = [_Block(i, block_type=block_type) for i in range(qty)]
    for i, blk in enumerate(blocks):
        blk.prevb = blocks[i - 1] if i > 0 else None
        blk.nextb = blocks[i + 1] if i + 1 < qty else None
    return _MBA(blocks), blocks


def _codes(violations) -> set[str]:
    return {v.code for v in violations}


class _BlockAlias:
    """Proxy that mimics SWIG wrappers returning distinct Python objects."""

    def __init__(self, blk: _Block):
        self._blk = blk
        self.serial = int(blk.serial)

    @property
    def nextb(self):
        nxt = self._blk.nextb
        if nxt is None:
            return None
        return _BlockAlias(nxt)

    @property
    def prevb(self):
        prv = self._blk.prevb
        if prv is None:
            return None
        return _BlockAlias(prv)


class _AliasedMBA:
    def __init__(self, base: _MBA):
        self._base = base
        self.qty = int(base.qty)

    def get_mblock(self, serial: int):
        blk = self._base.get_mblock(serial)
        if blk is None:
            return None
        return _BlockAlias(blk)


def _build_50840():
    mba, blocks = _linear_mba(2)
    blocks[1].prevb = None
    return mba


def _build_50841():
    mba, blocks = _linear_mba(2)
    blocks[0].nextb = None
    return mba


def _build_50842():
    mba, blocks = _linear_mba(2)
    blocks[0].nextb = None
    blocks[1].prevb = blocks[0]
    return mba


def _build_50843():
    mba, blocks = _linear_mba(2)
    blocks[1].prevb = None
    blocks[0].nextb = blocks[1]
    return mba


def _build_50854():
    mba, blocks = _linear_mba(4)
    blocks[1].type = int(getattr(_HR, "BLT_1WAY"))
    blocks[1].succset = _Vec([0])
    blocks[1].tail = _Insn(int(getattr(_HR, "m_goto")), l=_Mop(int(getattr(_HR, "mop_b")), b=0))
    blocks[1]._call_block = True
    return mba


def _build_50855():
    mba, blocks = _linear_mba(3)
    blocks[1].type = int(getattr(_HR, "BLT_NWAY"))
    blocks[1].succset = _Vec([2])
    blocks[1].tail = _Insn(int(getattr(_HR, "m_goto")), l=_Mop(int(getattr(_HR, "mop_b")), b=2))
    return mba


def _build_50856():
    mba, blocks = _linear_mba(4)
    blocks[1].type = int(getattr(_HR, "BLT_2WAY"))
    blocks[1].succset = _Vec([2])
    blocks[1].tail = _Insn(int(getattr(_HR, "m_jnz")), d=_Mop(int(getattr(_HR, "mop_b")), b=3))
    return mba


def _build_50857():
    mba, blocks = _linear_mba(3)
    blocks[1].succset = _Vec([99])
    return mba


def _build_50858():
    mba, blocks = _linear_mba(3)
    blocks[1].succset = _Vec([2])
    blocks[2].predset = _Vec([])
    return mba


def _build_50859():
    mba, blocks = _linear_mba(3)
    blocks[1].type = int(getattr(_HR, "BLT_NWAY"))
    blocks[1].succset = _Vec([2])
    blocks[1].tail = _Insn(
        int(getattr(_HR, "m_jtbl")),
        r=_Mop(int(getattr(_HR, "mop_b")), b=2),
    )
    return mba


def _build_50860():
    mba, blocks = _linear_mba(3)
    blocks[1].type = int(getattr(_HR, "BLT_1WAY"))
    blocks[1].succset = _Vec([0])
    blocks[1].tail = _Insn(int(getattr(_HR, "m_goto")), l=_Mop(int(getattr(_HR, "mop_b")), b=2))
    return mba


def _build_50861():
    mba, blocks = _linear_mba(3)
    blocks[1].predset = _Vec([0])
    blocks[0].succset = _Vec([])
    return mba


def _build_50862():
    mba, blocks = _linear_mba(3)
    blocks[1].predset = _Vec([0, 0])
    return mba


def _build_51774():
    mba, blocks = _linear_mba(4)
    blocks[1].type = int(getattr(_HR, "BLT_1WAY"))
    blocks[1].succset = _Vec([2])
    blocks[1].tail = _Insn(int(getattr(_HR, "m_nop")), noret=True)
    blocks[1]._call_block = True
    return mba


def _build_51815():
    mba, blocks = _linear_mba(2)
    blocks[1].type = 999
    return mba


@pytest.mark.parametrize(
    "expected_code,builder,checker",
    (
        ("CFG_50840_BLOCK_LIST_NEXT_PREV", _build_50840, inv.block_list_consistency),
        ("CFG_50841_BLOCK_LIST_PREV_NEXT", _build_50841, inv.block_list_consistency),
        ("CFG_50842_BLOCK_LIST_END_BOUNDARY", _build_50842, inv.block_list_consistency),
        ("CFG_50843_BLOCK_LIST_BEGIN_BOUNDARY", _build_50843, inv.block_list_consistency),
        ("CFG_50854_CALL_BLOCK_FLOW_MISMATCH", _build_50854, inv.block_type_vs_tail),
        ("CFG_50855_NWAY_JTBL_MISMATCH", _build_50855, inv.block_type_vs_tail),
        ("CFG_50856_BAD_NSUCC", _build_50856, inv.block_type_vs_tail),
        ("CFG_50857_SUCC_OUT_OF_RANGE", _build_50857, inv.pred_succ_symmetry),
        ("CFG_50858_SUCC_PRED_MISMATCH", _build_50858, inv.pred_succ_symmetry),
        ("CFG_50859_JTBL_CASELIST_INVALID", _build_50859, inv.successor_set_matches_tail_semantics),
        ("CFG_50860_SUCC_MISMATCH", _build_50860, inv.successor_set_matches_tail_semantics),
        ("CFG_50861_PRED_SUCC_MISMATCH", _build_50861, inv.pred_succ_symmetry),
        ("CFG_50862_DUPLICATE_PRED", _build_50862, inv.predecessor_uniqueness),
        ("CFG_51774_NORET_CALL_BLOCK_NOT_0WAY", _build_51774, inv.block_type_vs_tail),
        ("CFG_51815_WRONG_BLOCK_TYPE", _build_51815, inv.block_type_vs_tail),
    ),
)
def test_priority_verifier_code_mappings(expected_code, builder, checker):
    mba = builder()
    violations = checker(mba, phase="post", focus_serials=None)
    assert expected_code in _codes(violations)


def test_successor_derivation_parity_for_conditional_default_and_jtbl():
    mba, blocks = _linear_mba(4)

    blocks[0].type = int(getattr(_HR, "BLT_2WAY"))
    blocks[0].succset = _Vec([1, 2])
    blocks[0].tail = _Insn(int(getattr(_HR, "m_jnz")), d=_Mop(int(getattr(_HR, "mop_b")), b=2))

    blocks[1].type = int(getattr(_HR, "BLT_1WAY"))
    blocks[1].succset = _Vec([2])
    blocks[1].tail = _Insn(int(getattr(_HR, "m_nop")))

    blocks[2].type = int(getattr(_HR, "BLT_NWAY"))
    blocks[2].succset = _Vec([0, 1])
    blocks[2].tail = _Insn(
        int(getattr(_HR, "m_jtbl")),
        r=_Mop(int(getattr(_HR, "mop_c")), c=_Cases([0, 1])),
    )

    violations = inv.successor_set_matches_tail_semantics(
        mba,
        phase="post",
        focus_serials=None,
    )

    assert "CFG_50859_JTBL_CASELIST_INVALID" not in _codes(violations)
    assert "CFG_50860_SUCC_MISMATCH" not in _codes(violations)


def test_block_list_consistency_uses_serial_equivalence_for_wrapper_aliases():
    base_mba, _ = _linear_mba(3)
    aliased_mba = _AliasedMBA(base_mba)

    violations = inv.block_list_consistency(
        aliased_mba,
        phase="post",
        focus_serials=None,
    )

    codes = _codes(violations)
    assert "CFG_50840_BLOCK_LIST_NEXT_PREV" not in codes
    assert "CFG_50841_BLOCK_LIST_PREV_NEXT" not in codes


# ---------------------------------------------------------------------------
# Helpers for new checks
# ---------------------------------------------------------------------------


class _InsnNode:
    """Minimal linked-list instruction node for head/.next chain tests."""

    def __init__(self, opcode: int, *, ea: int = 0x401000):
        self.opcode = opcode
        self.ea = ea
        self.next: _InsnNode | None = None


def _make_chain(*opcodes: int) -> _InsnNode:
    """Build a .next-linked chain of _InsnNode objects and return head."""
    nodes = [_InsnNode(op) for op in opcodes]
    for i in range(len(nodes) - 1):
        nodes[i].next = nodes[i + 1]
    return nodes[0]


class _ExtBlock(_Block):
    """Extended _Block with head/.next instruction chain, flags, start/end."""

    def __init__(
        self,
        serial: int,
        *,
        block_type: int,
        head: _InsnNode | None = None,
        tail_insn: _Insn | None = None,
        flags: int = 0,
        start: int = 0x401000,
        end: int = 0x401010,
        succs: list[int] | None = None,
        preds: list[int] | None = None,
    ):
        super().__init__(
            serial,
            block_type=block_type,
            succs=succs,
            preds=preds,
            tail=tail_insn,
        )
        self.head = head
        self.flags = flags
        self.start = start
        self.end = end


class _ExtMBA:
    """MBA with maturity, entry_ea, and mixed block types."""

    def __init__(self, blocks: list[_ExtBlock], *, maturity: int = 0, entry_ea: int = 0x401000):
        self._blocks = {blk.serial: blk for blk in blocks}
        self.qty = len(blocks)
        self.maturity = maturity
        self.entry_ea = entry_ea

    def get_mblock(self, serial: int):
        return self._blocks.get(int(serial))


# ---------------------------------------------------------------------------
# Tests for CFG_50851_SERIAL_OUT_OF_RANGE
# ---------------------------------------------------------------------------


def _build_50851_clean():
    mba, _ = _linear_mba(3)
    return mba


def _build_50851_bad():
    mba, blocks = _linear_mba(3)
    # Manually corrupt the serial of block 1 to be out of range
    blocks[1].serial = 999
    return mba


def test_50851_no_violation_clean():
    mba = _build_50851_clean()
    violations = inv.block_serial_range(mba, phase="post")
    assert "CFG_50851_SERIAL_OUT_OF_RANGE" not in _codes(violations)


def test_50851_triggers_violation():
    mba = _build_50851_bad()
    violations = inv.block_serial_range(mba, phase="post")
    assert "CFG_50851_SERIAL_OUT_OF_RANGE" in _codes(violations)


# ---------------------------------------------------------------------------
# Tests for CFG_50864_CLOSING_OPCODE_NOT_AT_TAIL
# ---------------------------------------------------------------------------


def _build_50864_clean():
    m_goto = int(getattr(_HR, "m_goto"))
    m_nop = int(getattr(_HR, "m_nop"))
    # [nop, goto] — goto is at tail (index 1 = last)
    head = _make_chain(m_nop, m_goto)
    blk = _ExtBlock(
        1,
        block_type=int(getattr(_HR, "BLT_1WAY")),
        head=head,
        tail_insn=_Insn(m_goto),
    )
    blk0 = _ExtBlock(0, block_type=int(getattr(_HR, "BLT_0WAY")))
    blk2 = _ExtBlock(2, block_type=int(getattr(_HR, "BLT_0WAY")))
    return _ExtMBA([blk0, blk, blk2])


def _build_50864_bad():
    m_goto = int(getattr(_HR, "m_goto"))
    m_nop = int(getattr(_HR, "m_nop"))
    # [goto, nop] — goto at index 0, not tail
    head = _make_chain(m_goto, m_nop)
    blk = _ExtBlock(
        1,
        block_type=int(getattr(_HR, "BLT_1WAY")),
        head=head,
        tail_insn=_Insn(m_nop),
    )
    blk0 = _ExtBlock(0, block_type=int(getattr(_HR, "BLT_0WAY")))
    blk2 = _ExtBlock(2, block_type=int(getattr(_HR, "BLT_0WAY")))
    return _ExtMBA([blk0, blk, blk2])


def test_50864_no_violation_clean():
    mba = _build_50864_clean()
    violations = inv.block_closing_opcode_at_tail(mba, phase="post")
    assert "CFG_50864_CLOSING_OPCODE_NOT_AT_TAIL" not in _codes(violations)


def test_50864_triggers_violation():
    mba = _build_50864_bad()
    violations = inv.block_closing_opcode_at_tail(mba, phase="post")
    assert "CFG_50864_CLOSING_OPCODE_NOT_AT_TAIL" in _codes(violations)


# ---------------------------------------------------------------------------
# Tests for CFG_50865_PUSH_POP_AFTER_CONVERSION
# ---------------------------------------------------------------------------


def _build_50865_clean():
    m_push = int(getattr(_HR, "m_push"))
    # push present but maturity is before MMAT_CALLS
    head = _make_chain(m_push)
    mmat_calls = int(getattr(_HR, "MMAT_CALLS", 3))
    blk = _ExtBlock(
        1,
        block_type=int(getattr(_HR, "BLT_0WAY")),
        head=head,
    )
    blk0 = _ExtBlock(0, block_type=int(getattr(_HR, "BLT_0WAY")))
    blk2 = _ExtBlock(2, block_type=int(getattr(_HR, "BLT_0WAY")))
    return _ExtMBA([blk0, blk, blk2], maturity=mmat_calls - 1)


def _build_50865_bad():
    m_push = int(getattr(_HR, "m_push"))
    mmat_calls = int(getattr(_HR, "MMAT_CALLS", 3))
    head = _make_chain(m_push)
    blk = _ExtBlock(
        1,
        block_type=int(getattr(_HR, "BLT_0WAY")),
        head=head,
    )
    blk0 = _ExtBlock(0, block_type=int(getattr(_HR, "BLT_0WAY")))
    blk2 = _ExtBlock(2, block_type=int(getattr(_HR, "BLT_0WAY")))
    return _ExtMBA([blk0, blk, blk2], maturity=mmat_calls)


def test_50865_no_violation_before_mmat_calls():
    mba = _build_50865_clean()
    violations = inv.block_closing_opcode_at_tail(mba, phase="post")
    assert "CFG_50865_PUSH_POP_AFTER_CONVERSION" not in _codes(violations)


def test_50865_triggers_violation_after_mmat_calls():
    mba = _build_50865_bad()
    violations = inv.block_closing_opcode_at_tail(mba, phase="post")
    assert "CFG_50865_PUSH_POP_AFTER_CONVERSION" in _codes(violations)


# ---------------------------------------------------------------------------
# Tests for CFG_50869_START_GE_END and CFG_50870_BLOCK_OUTSIDE_FUNC
# ---------------------------------------------------------------------------


def _build_50869_clean():
    mbl_fake = int(getattr(_HR, "MBL_FAKE", 0x10))
    # entry block (fake), normal block with valid range, exit block (fake)
    blk0 = _ExtBlock(0, block_type=int(getattr(_HR, "BLT_0WAY")), flags=mbl_fake)
    blk1 = _ExtBlock(1, block_type=int(getattr(_HR, "BLT_0WAY")), start=0x401000, end=0x401010)
    blk2 = _ExtBlock(2, block_type=int(getattr(_HR, "BLT_0WAY")), flags=mbl_fake)
    mba = _ExtMBA([blk0, blk1, blk2], entry_ea=0x401000)
    return mba


def _build_50869_bad():
    # block with start >= end (inverted range)
    blk0 = _ExtBlock(0, block_type=int(getattr(_HR, "BLT_0WAY")))
    blk1 = _ExtBlock(1, block_type=int(getattr(_HR, "BLT_0WAY")), start=0x401010, end=0x401000)
    blk2 = _ExtBlock(2, block_type=int(getattr(_HR, "BLT_0WAY")), start=0x401020, end=0x401030)
    return _ExtMBA([blk0, blk1, blk2], entry_ea=0x401000)


def test_50869_no_violation_clean():
    mba = _build_50869_clean()
    violations = inv.block_address_range(mba, phase="post")
    assert "CFG_50869_START_GE_END" not in _codes(violations)


def test_50869_triggers_violation():
    mba = _build_50869_bad()
    violations = inv.block_address_range(mba, phase="post")
    assert "CFG_50869_START_GE_END" in _codes(violations)


def _build_50870_clean():
    blk0 = _ExtBlock(0, block_type=int(getattr(_HR, "BLT_0WAY")), start=0x401000, end=0x401010)
    blk1 = _ExtBlock(1, block_type=int(getattr(_HR, "BLT_0WAY")), start=0x401010, end=0x401020)
    blk2 = _ExtBlock(2, block_type=int(getattr(_HR, "BLT_0WAY")), start=0x401020, end=0x401030)
    return _ExtMBA([blk0, blk1, blk2], entry_ea=0x401000)


def _build_50870_bad():
    # blk1 starts before entry_ea
    blk0 = _ExtBlock(0, block_type=int(getattr(_HR, "BLT_0WAY")), start=0x401000, end=0x401010)
    blk1 = _ExtBlock(1, block_type=int(getattr(_HR, "BLT_0WAY")), start=0x400000, end=0x401010)
    blk2 = _ExtBlock(2, block_type=int(getattr(_HR, "BLT_0WAY")), start=0x401010, end=0x401020)
    return _ExtMBA([blk0, blk1, blk2], entry_ea=0x401000)


def test_50870_no_violation_clean():
    mba = _build_50870_clean()
    violations = inv.block_address_range(mba, phase="post")
    assert "CFG_50870_BLOCK_OUTSIDE_FUNC" not in _codes(violations)


def test_50870_triggers_violation():
    mba = _build_50870_bad()
    violations = inv.block_address_range(mba, phase="post")
    assert "CFG_50870_BLOCK_OUTSIDE_FUNC" in _codes(violations)


# ---------------------------------------------------------------------------
# Tests for CFG_51814_SPECIAL_BLOCK_NOT_EMPTY
# ---------------------------------------------------------------------------


def _build_51814_clean():
    m_nop = int(getattr(_HR, "m_nop"))
    # entry (serial 0) and exit (serial 2) are empty; only block 1 has instructions
    head1 = _make_chain(m_nop)
    blk0 = _ExtBlock(0, block_type=int(getattr(_HR, "BLT_0WAY")), head=None)
    blk1 = _ExtBlock(1, block_type=int(getattr(_HR, "BLT_0WAY")), head=head1)
    blk2 = _ExtBlock(2, block_type=int(getattr(_HR, "BLT_0WAY")), head=None)
    return _ExtMBA([blk0, blk1, blk2])


def _build_51814_bad():
    m_nop = int(getattr(_HR, "m_nop"))
    # entry block (serial 0) has instructions — violation
    head0 = _make_chain(m_nop)
    blk0 = _ExtBlock(0, block_type=int(getattr(_HR, "BLT_0WAY")), head=head0, tail_insn=_Insn(m_nop))
    blk1 = _ExtBlock(1, block_type=int(getattr(_HR, "BLT_0WAY")), head=None)
    blk2 = _ExtBlock(2, block_type=int(getattr(_HR, "BLT_0WAY")), head=None)
    return _ExtMBA([blk0, blk1, blk2])


def test_51814_no_violation_clean():
    mba = _build_51814_clean()
    violations = inv.block_closing_opcode_at_tail(mba, phase="post")
    assert "CFG_51814_SPECIAL_BLOCK_NOT_EMPTY" not in _codes(violations)


def test_51814_triggers_violation():
    mba = _build_51814_bad()
    violations = inv.block_closing_opcode_at_tail(mba, phase="post")
    assert "CFG_51814_SPECIAL_BLOCK_NOT_EMPTY" in _codes(violations)


# ---------------------------------------------------------------------------
# Tests for CFG_50844_UNKNOWN_BLOCK_FLAGS
# ---------------------------------------------------------------------------


def _build_50844_clean():
    # flags = 0 → no unknown bits
    blk0 = _ExtBlock(0, block_type=int(getattr(_HR, "BLT_0WAY")), flags=0)
    blk1 = _ExtBlock(1, block_type=int(getattr(_HR, "BLT_0WAY")), flags=0)
    blk2 = _ExtBlock(2, block_type=int(getattr(_HR, "BLT_0WAY")), flags=0)
    return _ExtMBA([blk0, blk1, blk2])


def _build_50844_bad():
    # flags with high bits set beyond known mask
    blk0 = _ExtBlock(0, block_type=int(getattr(_HR, "BLT_0WAY")), flags=0)
    blk1 = _ExtBlock(1, block_type=int(getattr(_HR, "BLT_0WAY")), flags=0xDEAD_0000)
    blk2 = _ExtBlock(2, block_type=int(getattr(_HR, "BLT_0WAY")), flags=0)
    return _ExtMBA([blk0, blk1, blk2])


def test_50844_no_violation_clean():
    mba = _build_50844_clean()
    violations = inv.block_unknown_flags(mba, phase="post")
    assert "CFG_50844_UNKNOWN_BLOCK_FLAGS" not in _codes(violations)


def test_50844_triggers_violation():
    mba = _build_50844_bad()
    violations = inv.block_unknown_flags(mba, phase="post")
    assert "CFG_50844_UNKNOWN_BLOCK_FLAGS" in _codes(violations)
