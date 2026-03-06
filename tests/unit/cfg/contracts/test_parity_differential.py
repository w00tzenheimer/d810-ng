"""Differential parity test framework for the 22 mapped INTERR codes.

Each parametrized test:
  1. Loads the parity matrix entry for a specific code (disposition="mapped")
  2. Creates a mock MBA with a corruption that triggers the code
  3. Runs the Python contract check named in the ``owner`` field
  4. Asserts the expected violation code is emitted

Native oracle differential: when the Cython oracle is available, the corrupted
MBA is also passed to ``check_mba_native``.  All codes exercised here have
disposition="mapped" (Python-only checks), so the native oracle is NOT expected
to report them.  The oracle call acts as a smoke test — it must not raise and
must not return any false positives for these codes.  If a future Cython
implementation starts covering a mapped code, this test will surface the
overlap automatically.
"""
from __future__ import annotations

import json
import pathlib
from d810.core.typing import Any, Callable

import pytest

from d810.cfg.contracts import invariants as inv
from d810.cfg.contracts.native_oracle import check_mba_native, oracle_available

# ---------------------------------------------------------------------------
# Re-use mock primitives from test_invariants.py
# ---------------------------------------------------------------------------

_HR = inv.ida_hexrays


class _Vec(list):
    def size(self) -> int:
        return len(self)


class _Cases:
    def __init__(self, targets: list[int]):
        self.targets = _Vec(targets)


class _Mop:
    def __init__(self, t: int, b: int | None = None, c: object | None = None):
        self.t = t
        self.b = b
        self.c = c

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

    def __init__(
        self,
        blocks: list[_ExtBlock],
        *,
        maturity: int = 0,
        entry_ea: int = 0x401000,
    ):
        self._blocks = {blk.serial: blk for blk in blocks}
        self.qty = len(blocks)
        self.maturity = maturity
        self.entry_ea = entry_ea

    def get_mblock(self, serial: int):
        return self._blocks.get(int(serial))


def _linear_mba(qty: int, default_type: int | None = None) -> tuple[_MBA, list[_Block]]:
    block_type = int(default_type if default_type is not None else getattr(_HR, "BLT_0WAY"))
    blocks = [_Block(i, block_type=block_type) for i in range(qty)]
    for i, blk in enumerate(blocks):
        blk.prevb = blocks[i - 1] if i > 0 else None
        blk.nextb = blocks[i + 1] if i + 1 < qty else None
    return _MBA(blocks), blocks


def _codes(violations: Any) -> set[str]:
    return {v.code for v in violations}


# ---------------------------------------------------------------------------
# Parity matrix loader
# ---------------------------------------------------------------------------

_MATRIX_PATH = (
    pathlib.Path(__file__).resolve().parents[4]
    / "src"
    / "d810"
    / "cfg"
    / "contracts"
    / "parity_matrix.json"
)


def _load_matrix() -> list[dict]:
    with _MATRIX_PATH.open() as fh:
        return json.load(fh)["codes"]


# ---------------------------------------------------------------------------
# Corruption factories — one per mapped code
# ---------------------------------------------------------------------------

def _corrupt_50840(mba: _MBA) -> _MBA:
    """nextb->prevb mismatch: block[1].prevb set to None."""
    blk = mba.get_mblock(1)
    blk.prevb = None
    return mba


def _corrupt_50841(mba: _MBA) -> _MBA:
    """prevb->nextb mismatch: block[0].nextb set to None."""
    blk = mba.get_mblock(0)
    blk.nextb = None
    return mba


def _corrupt_50842(mba: _MBA) -> _MBA:
    """Wrong end-of-list boundary: last block has nextb != None."""
    blk0 = mba.get_mblock(0)
    blk1 = mba.get_mblock(1)
    blk0.nextb = None
    blk1.prevb = blk0
    return mba


def _corrupt_50843(mba: _MBA) -> _MBA:
    """Wrong begin-of-list boundary: first block has prevb != None."""
    blk0 = mba.get_mblock(0)
    blk1 = mba.get_mblock(1)
    blk1.prevb = None
    blk0.nextb = blk1
    return mba


def _corrupt_50844(_ignored: Any) -> _ExtMBA:
    """Unknown bits in block flags."""
    blk0 = _ExtBlock(0, block_type=int(getattr(_HR, "BLT_0WAY")), flags=0)
    blk1 = _ExtBlock(1, block_type=int(getattr(_HR, "BLT_0WAY")), flags=0xDEAD_0000)
    blk2 = _ExtBlock(2, block_type=int(getattr(_HR, "BLT_0WAY")), flags=0)
    return _ExtMBA([blk0, blk1, blk2])


def _corrupt_50851(_ignored: Any) -> _MBA:
    """Serial >= mba->qty."""
    mba, blocks = _linear_mba(3)
    blocks[1].serial = 999
    return mba


def _corrupt_50854(_ignored: Any) -> _MBA:
    """1-way call block successor != serial+1."""
    mba, blocks = _linear_mba(4)
    blocks[1].type = int(getattr(_HR, "BLT_1WAY"))
    blocks[1].succset = _Vec([0])
    blocks[1].tail = _Insn(int(getattr(_HR, "m_goto")), l=_Mop(int(getattr(_HR, "mop_b")), b=0))
    blocks[1]._call_block = True
    return mba


def _corrupt_50855(_ignored: Any) -> _MBA:
    """BLT_NWAY without jtbl tail."""
    mba, blocks = _linear_mba(3)
    blocks[1].type = int(getattr(_HR, "BLT_NWAY"))
    blocks[1].succset = _Vec([2])
    blocks[1].tail = _Insn(int(getattr(_HR, "m_goto")), l=_Mop(int(getattr(_HR, "mop_b")), b=2))
    return mba


def _corrupt_50856(_ignored: Any) -> _MBA:
    """Successor count mismatches block type (BLT_2WAY needs 2 succs)."""
    mba, blocks = _linear_mba(4)
    blocks[1].type = int(getattr(_HR, "BLT_2WAY"))
    blocks[1].succset = _Vec([2])
    blocks[1].tail = _Insn(int(getattr(_HR, "m_jnz")), d=_Mop(int(getattr(_HR, "mop_b")), b=3))
    return mba


def _corrupt_50857(_ignored: Any) -> _MBA:
    """Successor block number out of range."""
    mba, blocks = _linear_mba(3)
    blocks[1].succset = _Vec([99])
    return mba


def _corrupt_50858(_ignored: Any) -> _MBA:
    """Successor's predset missing this block."""
    mba, blocks = _linear_mba(3)
    blocks[1].succset = _Vec([2])
    blocks[2].predset = _Vec([])
    return mba


def _corrupt_50859(_ignored: Any) -> _MBA:
    """jtbl caselist invalid (no case list on m_jtbl mop_r)."""
    mba, blocks = _linear_mba(3)
    blocks[1].type = int(getattr(_HR, "BLT_NWAY"))
    blocks[1].succset = _Vec([2])
    blocks[1].tail = _Insn(
        int(getattr(_HR, "m_jtbl")),
        r=_Mop(int(getattr(_HR, "mop_b")), b=2),
    )
    return mba


def _corrupt_50860(_ignored: Any) -> _MBA:
    """Successor set doesn't match tail semantics."""
    mba, blocks = _linear_mba(3)
    blocks[1].type = int(getattr(_HR, "BLT_1WAY"))
    blocks[1].succset = _Vec([0])
    blocks[1].tail = _Insn(int(getattr(_HR, "m_goto")), l=_Mop(int(getattr(_HR, "mop_b")), b=2))
    return mba


def _corrupt_50861(_ignored: Any) -> _MBA:
    """Predecessor's succset missing this block."""
    mba, blocks = _linear_mba(3)
    blocks[1].predset = _Vec([0])
    blocks[0].succset = _Vec([])
    return mba


def _corrupt_50862(_ignored: Any) -> _MBA:
    """Duplicate predecessor entries."""
    mba, blocks = _linear_mba(3)
    blocks[1].predset = _Vec([0, 0])
    return mba


def _corrupt_50864(_ignored: Any) -> _ExtMBA:
    """Block-closing opcode not at tail."""
    m_goto = int(getattr(_HR, "m_goto"))
    m_nop = int(getattr(_HR, "m_nop"))
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


def _corrupt_50865(_ignored: Any) -> _ExtMBA:
    """push/pop after conversion phase (maturity >= MMAT_CALLS)."""
    m_push = int(getattr(_HR, "m_push"))
    mmat_calls = int(getattr(_HR, "MMAT_CALLS", 3))
    head = _make_chain(m_push)
    blk = _ExtBlock(1, block_type=int(getattr(_HR, "BLT_0WAY")), head=head)
    blk0 = _ExtBlock(0, block_type=int(getattr(_HR, "BLT_0WAY")))
    blk2 = _ExtBlock(2, block_type=int(getattr(_HR, "BLT_0WAY")))
    return _ExtMBA([blk0, blk, blk2], maturity=mmat_calls)


def _corrupt_50869(_ignored: Any) -> _ExtMBA:
    """start >= end for non-fake block."""
    blk0 = _ExtBlock(0, block_type=int(getattr(_HR, "BLT_0WAY")))
    blk1 = _ExtBlock(1, block_type=int(getattr(_HR, "BLT_0WAY")), start=0x401010, end=0x401000)
    blk2 = _ExtBlock(2, block_type=int(getattr(_HR, "BLT_0WAY")), start=0x401020, end=0x401030)
    return _ExtMBA([blk0, blk1, blk2], entry_ea=0x401000)


def _corrupt_50870(_ignored: Any) -> _ExtMBA:
    """Block outside function boundaries (starts before entry_ea)."""
    blk0 = _ExtBlock(0, block_type=int(getattr(_HR, "BLT_0WAY")), start=0x401000, end=0x401010)
    blk1 = _ExtBlock(1, block_type=int(getattr(_HR, "BLT_0WAY")), start=0x400000, end=0x401010)
    blk2 = _ExtBlock(2, block_type=int(getattr(_HR, "BLT_0WAY")), start=0x401010, end=0x401020)
    return _ExtMBA([blk0, blk1, blk2], entry_ea=0x401000)


def _corrupt_51774(_ignored: Any) -> _MBA:
    """noret call block not BLT_0WAY."""
    mba, blocks = _linear_mba(4)
    blocks[1].type = int(getattr(_HR, "BLT_1WAY"))
    blocks[1].succset = _Vec([2])
    blocks[1].tail = _Insn(int(getattr(_HR, "m_nop")), noret=True)
    blocks[1]._call_block = True
    return mba


def _corrupt_51814(_ignored: Any) -> _ExtMBA:
    """Entry/exit/extern blocks not empty (entry block has instructions)."""
    m_nop = int(getattr(_HR, "m_nop"))
    head0 = _make_chain(m_nop)
    blk0 = _ExtBlock(0, block_type=int(getattr(_HR, "BLT_0WAY")), head=head0, tail_insn=_Insn(m_nop))
    blk1 = _ExtBlock(1, block_type=int(getattr(_HR, "BLT_0WAY")), head=None)
    blk2 = _ExtBlock(2, block_type=int(getattr(_HR, "BLT_0WAY")), head=None)
    return _ExtMBA([blk0, blk1, blk2])


def _corrupt_51815(_ignored: Any) -> _MBA:
    """Invalid block type value."""
    mba, blocks = _linear_mba(2)
    blocks[1].type = 999
    return mba


# ---------------------------------------------------------------------------
# Map: code -> (violation_constant_name, checker_fn, corrupt_fn)
# ---------------------------------------------------------------------------

_OWNER_FN: dict[str, Callable] = {
    "block_list_consistency": inv.block_list_consistency,
    "block_unknown_flags": inv.block_unknown_flags,
    "block_serial_range": inv.block_serial_range,
    "block_type_vs_tail": inv.block_type_vs_tail,
    "pred_succ_symmetry": inv.pred_succ_symmetry,
    "successor_set_matches_tail_semantics": inv.successor_set_matches_tail_semantics,
    "predecessor_uniqueness": inv.predecessor_uniqueness,
    "block_closing_opcode_at_tail": inv.block_closing_opcode_at_tail,
    "block_address_range": inv.block_address_range,
}

_CODE_FIXTURES: dict[int, tuple[str, Callable]] = {
    50840: ("CFG_50840_BLOCK_LIST_NEXT_PREV", _corrupt_50840),
    50841: ("CFG_50841_BLOCK_LIST_PREV_NEXT", _corrupt_50841),
    50842: ("CFG_50842_BLOCK_LIST_END_BOUNDARY", _corrupt_50842),
    50843: ("CFG_50843_BLOCK_LIST_BEGIN_BOUNDARY", _corrupt_50843),
    50844: ("CFG_50844_UNKNOWN_BLOCK_FLAGS", _corrupt_50844),
    50851: ("CFG_50851_SERIAL_OUT_OF_RANGE", _corrupt_50851),
    50854: ("CFG_50854_CALL_BLOCK_FLOW_MISMATCH", _corrupt_50854),
    50855: ("CFG_50855_NWAY_JTBL_MISMATCH", _corrupt_50855),
    50856: ("CFG_50856_BAD_NSUCC", _corrupt_50856),
    50857: ("CFG_50857_SUCC_OUT_OF_RANGE", _corrupt_50857),
    50858: ("CFG_50858_SUCC_PRED_MISMATCH", _corrupt_50858),
    50859: ("CFG_50859_JTBL_CASELIST_INVALID", _corrupt_50859),
    50860: ("CFG_50860_SUCC_MISMATCH", _corrupt_50860),
    50861: ("CFG_50861_PRED_SUCC_MISMATCH", _corrupt_50861),
    50862: ("CFG_50862_DUPLICATE_PRED", _corrupt_50862),
    50864: ("CFG_50864_CLOSING_OPCODE_NOT_AT_TAIL", _corrupt_50864),
    50865: ("CFG_50865_PUSH_POP_AFTER_CONVERSION", _corrupt_50865),
    50869: ("CFG_50869_START_GE_END", _corrupt_50869),
    50870: ("CFG_50870_BLOCK_OUTSIDE_FUNC", _corrupt_50870),
    51774: ("CFG_51774_NORET_CALL_BLOCK_NOT_0WAY", _corrupt_51774),
    51814: ("CFG_51814_SPECIAL_BLOCK_NOT_EMPTY", _corrupt_51814),
    51815: ("CFG_51815_WRONG_BLOCK_TYPE", _corrupt_51815),
}


def _build_parametrize_args() -> list[tuple]:
    """Build parametrize list from parity matrix (mapped entries only)."""
    codes_data = _load_matrix()
    args = []
    for entry in codes_data:
        if entry.get("disposition") != "mapped":
            continue
        code = entry["code"]
        owner = entry["owner"]
        if code not in _CODE_FIXTURES:
            continue
        if owner not in _OWNER_FN:
            continue
        violation_name, corrupt_fn = _CODE_FIXTURES[code]
        checker = _OWNER_FN[owner]
        args.append(
            pytest.param(code, violation_name, checker, corrupt_fn, id=f"INTERR_{code}")
        )
    return args


_PARAMETRIZE_ARGS = _build_parametrize_args()


# ---------------------------------------------------------------------------
# Parametrized differential parity test
# ---------------------------------------------------------------------------

@pytest.mark.parametrize(
    "code,violation_name,checker,corrupt_fn",
    _PARAMETRIZE_ARGS,
)
def test_parity_mapped_code_triggers_violation(
    code: int,
    violation_name: str,
    checker: Callable,
    corrupt_fn: Callable,
) -> None:
    """For each mapped INTERR code, verify the Python contract check fires.

    Phase 3 differential assertion: when the Cython oracle is available,
    also run check_mba_native on the same corrupted MBA.  Mapped codes are
    Python-only, so the oracle must not raise and must not report the code
    (no false positives).  The oracle call is silently skipped when the
    Cython speedups extension is not compiled.
    """
    base_mba, _ = _linear_mba(3)
    mba = corrupt_fn(base_mba)

    # block_serial_range has a different call signature (no focus_serials)
    if checker is inv.block_serial_range:
        violations = checker(mba, phase="post")
    else:
        violations = checker(mba, phase="post", focus_serials=None)

    found = _codes(violations)
    assert violation_name in found, (
        f"INTERR {code}: expected {violation_name!r} in violations, got {found!r}"
    )

    # Native oracle differential: smoke-test that the Cython oracle does not
    # crash on this corrupted MBA.  Mapped-disposition codes are Python-only,
    # so the oracle is not expected to report them; assert no false positives.
    if oracle_available():
        native_results = check_mba_native(mba)
        native_codes = {r[0] for r in native_results}
        assert code not in native_codes, (
            f"INTERR {code}: native oracle unexpectedly reported this "
            f"mapped (Python-only) code. native_results={native_results!r}"
        )


# ---------------------------------------------------------------------------
# Parity dashboard test
# ---------------------------------------------------------------------------

def test_parity_dashboard() -> None:
    """Print a parity coverage summary and assert no code is unmapped."""
    codes_data = _load_matrix()

    mapped_tested: list[int] = []
    mapped_untested: list[int] = []
    planned: list[int] = []
    blocked: list[int] = []
    native_oracle: list[int] = []
    native_oracle_limited: list[int] = []
    native_oracle_deferred: list[int] = []
    unmapped: list[int] = []

    for entry in codes_data:
        code = entry["code"]
        disposition = entry.get("disposition", "")
        if disposition == "mapped":
            if code in _CODE_FIXTURES:
                mapped_tested.append(code)
            else:
                mapped_untested.append(code)
        elif disposition == "planned":
            planned.append(code)
        elif disposition == "blocked_by_api":
            blocked.append(code)
        elif disposition == "native_oracle":
            native_oracle.append(code)
        elif disposition == "native_oracle_limited":
            native_oracle_limited.append(code)
        elif disposition == "native_oracle_deferred":
            native_oracle_deferred.append(code)
        else:
            unmapped.append(code)

    total = len(codes_data)
    print("\n")
    print("=== CFG Contract Parity Dashboard ===")
    print(f"Total codes in matrix      : {total}")
    print(f"mapped + tested            : {len(mapped_tested)}")
    print(f"mapped + untested          : {len(mapped_untested)}")
    print(f"planned                    : {len(planned)}")
    print(f"blocked_by_api             : {len(blocked)}")
    print(f"native_oracle              : {len(native_oracle)}")
    print(f"native_oracle_limited      : {len(native_oracle_limited)}")
    print(f"native_oracle_deferred     : {len(native_oracle_deferred)}")
    print(f"unmapped                   : {len(unmapped)}")
    if mapped_untested:
        print(f"  untested codes          : {mapped_untested}")
    if unmapped:
        print(f"  unmapped codes          : {unmapped}")

    assert not unmapped, (
        f"The following codes have no disposition in the parity matrix: {unmapped}"
    )
