"""Unit test for the loop-bound-writer detector.

The detector consumes Hex-Rays-shaped instruction and operand objects, but it
must not import live Hex-Rays modules. These tests use hand-built ``mba``
skeletons with known opcode/mop_t values so we can verify the detector returns
a diagnostic only for the intended block.
"""
from __future__ import annotations

from d810.ir.flowgraph import InsnKind, OperandKind


class _StkOff:
    def __init__(self, off: int):
        self.off = off


class _NumValue:
    def __init__(self, value: int):
        self.value = value


class _Mop:
    """Minimal mop_t shim.  Set ``t``, plus the appropriate sub-attributes
    for the type."""

    def __init__(self, kind: OperandKind, *, s=None, nnn=None, d=None):
        self.kind = kind
        self.s = s
        self.nnn = nnn
        self.d = d


class _Insn:
    def __init__(self, kind: InsnKind, *, ea: int = 0, l=None, r=None, d=None):
        self.kind = kind
        self.ea = ea
        self.l = l
        self.r = r
        self.d = d
        self.next = None


class _Mblock:
    def __init__(self, head: _Insn | None):
        self.head = head


class _Mba:
    def __init__(self, blocks: list[_Mblock]):
        self._blocks = blocks
        self.qty = len(blocks)

    def get_mblock(self, i: int) -> _Mblock:
        return self._blocks[i]


def _chain(*insns: _Insn) -> _Insn | None:
    """Link instructions head→tail via ``next`` and return the head."""
    if not insns:
        return None
    for i in range(len(insns) - 1):
        insns[i].next = insns[i + 1]
    return insns[0]


def _build_bound_writer_block(*, bound_stkoff: int, ea: int) -> _Mblock:
    """Block whose only stkvar write is ``m_xdu (X & 0x3E), %B``."""
    var_x = _Mop(OperandKind.STACK, s=_StkOff(0x100))
    const_3e = _Mop(OperandKind.NUMBER, nnn=_NumValue(0x3E))
    inner_and = _Insn(InsnKind.AND, l=var_x, r=const_3e)
    masked = _Mop(OperandKind.SUBINSN, d=inner_and)
    dest = _Mop(OperandKind.STACK, s=_StkOff(bound_stkoff))
    writer = _Insn(InsnKind.XDU, ea=ea, l=masked, d=dest)
    return _Mblock(_chain(writer))


def _build_loop_test_block(
    *,
    bound_stkoff: int,
    counter_stkoff: int,
    delta: int,
    ea: int,
) -> _Mblock:
    """Block whose tail is ``m_jnz (counter + delta), %B, @T``."""
    counter_var = _Mop(OperandKind.STACK, s=_StkOff(counter_stkoff))
    delta_const = _Mop(OperandKind.NUMBER, nnn=_NumValue(delta))
    inner_add = _Insn(InsnKind.ADD, l=counter_var, r=delta_const)
    counter_advance = _Mop(OperandKind.SUBINSN, d=inner_add)
    bound_read = _Mop(OperandKind.STACK, s=_StkOff(bound_stkoff))
    test = _Insn(InsnKind.EQUALITY_JUMP, ea=ea, l=counter_advance, r=bound_read)
    return _Mblock(_chain(test))


def _build_unrelated_block() -> _Mblock:
    """Block with a non-matching instruction (m_add, no stkvar dest)."""
    insn = _Insn(InsnKind.ADD)
    return _Mblock(_chain(insn))


class TestDetectLoopBoundWriterRedirect:
    BOUND_STKOFF = 0x388
    COUNTER_STKOFF = 0x508
    BOUND_WRITER_EA = 0x18001606C
    LOOP_TEST_EA = 0x180013C9E

    def _build_mba(self, *, bound_stkoff: int = BOUND_STKOFF) -> _Mba:
        # Block layout:
        #   0: unrelated
        #   1: bound writer (the via_pred we want flagged)
        #   2: loop test consumer
        #   3: unrelated
        return _Mba([
            _build_unrelated_block(),
            _build_bound_writer_block(
                bound_stkoff=bound_stkoff,
                ea=self.BOUND_WRITER_EA,
            ),
            _build_loop_test_block(
                bound_stkoff=bound_stkoff,
                counter_stkoff=self.COUNTER_STKOFF,
                delta=2,
                ea=self.LOOP_TEST_EA,
            ),
            _build_unrelated_block(),
        ])

    def test_matches_bound_writer_block(self):
        from d810.transforms.loop_bound_writer_guard import (
            detect_loop_bound_writer_redirect,
        )

        mba = self._build_mba()
        diag = detect_loop_bound_writer_redirect(mba, source_block_serial=1)

        assert diag is not None
        assert diag.bound_stkoff == self.BOUND_STKOFF
        assert diag.bound_writer_ea == self.BOUND_WRITER_EA
        assert diag.loop_test_ea == self.LOOP_TEST_EA
        assert diag.counter_stkoff == self.COUNTER_STKOFF

    def test_does_not_match_unrelated_block(self):
        from d810.transforms.loop_bound_writer_guard import (
            detect_loop_bound_writer_redirect,
        )

        mba = self._build_mba()
        # Block 0 has no constant-mask writer.
        assert detect_loop_bound_writer_redirect(mba, source_block_serial=0) is None
        # Block 2 has the loop test, but no constant-mask writer.
        assert detect_loop_bound_writer_redirect(mba, source_block_serial=2) is None
        # Block 3 has no relevant instructions.
        assert detect_loop_bound_writer_redirect(mba, source_block_serial=3) is None

    def test_rejects_when_writer_uniqueness_violated(self):
        """If another block also writes the same stkvar B, the detector
        must reject -- the writer is no longer unique."""
        from d810.transforms.loop_bound_writer_guard import (
            detect_loop_bound_writer_redirect,
        )

        mba = self._build_mba()
        # Inject a second writer to bound_stkoff into block 0.
        secondary_writer = _Insn(
            InsnKind.XDU,
            ea=0x180099999,
            l=_Mop(
                OperandKind.SUBINSN,
                d=_Insn(
                    InsnKind.AND,
                    l=_Mop(OperandKind.STACK, s=_StkOff(0x200)),
                    r=_Mop(OperandKind.NUMBER, nnn=_NumValue(0x3E)),
                ),
            ),
            d=_Mop(OperandKind.STACK, s=_StkOff(self.BOUND_STKOFF)),
        )
        mba._blocks[0] = _Mblock(secondary_writer)

        diag = detect_loop_bound_writer_redirect(mba, source_block_serial=1)
        assert diag is None

    def test_rejects_when_mask_not_in_set(self):
        """Mask 0x55 is not a recognized loop-bound mask -- reject."""
        from d810.transforms.loop_bound_writer_guard import (
            detect_loop_bound_writer_redirect,
        )

        # Build a writer block with mask 0x55 instead of 0x3E.
        var_x = _Mop(OperandKind.STACK, s=_StkOff(0x100))
        const_55 = _Mop(OperandKind.NUMBER, nnn=_NumValue(0x55))
        inner_and = _Insn(InsnKind.AND, l=var_x, r=const_55)
        masked = _Mop(OperandKind.SUBINSN, d=inner_and)
        dest = _Mop(OperandKind.STACK, s=_StkOff(self.BOUND_STKOFF))
        writer = _Insn(InsnKind.XDU, ea=self.BOUND_WRITER_EA, l=masked, d=dest)

        mba = _Mba([
            _Mblock(_chain(writer)),
            _build_loop_test_block(
                bound_stkoff=self.BOUND_STKOFF,
                counter_stkoff=self.COUNTER_STKOFF,
                delta=2,
                ea=self.LOOP_TEST_EA,
            ),
        ])
        assert detect_loop_bound_writer_redirect(mba, source_block_serial=0) is None

    def test_rejects_when_counter_delta_not_small(self):
        """Delta 16 isn't in the recognized counter-advance set -- reject."""
        from d810.transforms.loop_bound_writer_guard import (
            detect_loop_bound_writer_redirect,
        )

        mba = _Mba([
            _build_bound_writer_block(
                bound_stkoff=self.BOUND_STKOFF,
                ea=self.BOUND_WRITER_EA,
            ),
            _build_loop_test_block(
                bound_stkoff=self.BOUND_STKOFF,
                counter_stkoff=self.COUNTER_STKOFF,
                delta=16,
                ea=self.LOOP_TEST_EA,
            ),
        ])
        assert detect_loop_bound_writer_redirect(mba, source_block_serial=0) is None

    def test_returns_none_when_mba_is_none(self):
        from d810.transforms.loop_bound_writer_guard import (
            detect_loop_bound_writer_redirect,
        )

        assert detect_loop_bound_writer_redirect(None, source_block_serial=1) is None


def _build_counter_advance_block(*, counter_stkoff: int, delta: int, ea: int) -> _Mblock:
    """Block with ``m_add %counter, #delta -> %temp`` (the advance)."""
    counter_var = _Mop(OperandKind.STACK, s=_StkOff(counter_stkoff))
    delta_const = _Mop(OperandKind.NUMBER, nnn=_NumValue(delta))
    temp_dest = _Mop(OperandKind.STACK, s=_StkOff(0xABC))
    advance = _Insn(InsnKind.ADD, ea=ea, l=counter_var, r=delta_const, d=temp_dest)
    return _Mblock(_chain(advance))


class TestDetectLoopCounterWritebackTail:
    COUNTER_STKOFF = 0x638
    BOUND_STKOFF = 0x388
    LOOP_TEST_EA = 0x180013C9E
    ADVANCE_EA = 0x180013C82
    WRITEBACK_EA = 0x180016098

    def _build_lvar_writeback_block(self, *, counter_stkoff: int, ea: int) -> _Mblock:
        """Block with ``m_mov %lvar -> %counter`` (writeback from a
        loop-carried lvar/temp)."""
        # mop_l source -- not constant, distinct from mop_S.
        src_lvar = _Mop(OperandKind.LVAR)
        dest = _Mop(OperandKind.STACK, s=_StkOff(counter_stkoff))
        writeback = _Insn(InsnKind.MOV, ea=ea, l=src_lvar, d=dest)
        return _Mblock(_chain(writeback))

    def _build_mba(
        self,
        *,
        counter_stkoff: int = COUNTER_STKOFF,
        bound_stkoff: int = BOUND_STKOFF,
    ) -> _Mba:
        # Block layout:
        #   0: counter advance compute
        #   1: loop test consumer (counter+#2 vs bound)
        #   2: writeback tail (m_mov temp -> counter)
        #   3: unrelated
        return _Mba([
            _build_counter_advance_block(
                counter_stkoff=counter_stkoff,
                delta=2,
                ea=self.ADVANCE_EA,
            ),
            _build_loop_test_block(
                bound_stkoff=bound_stkoff,
                counter_stkoff=counter_stkoff,
                delta=2,
                ea=self.LOOP_TEST_EA,
            ),
            self._build_lvar_writeback_block(
                counter_stkoff=counter_stkoff,
                ea=self.WRITEBACK_EA,
            ),
            _build_unrelated_block(),
        ])

    def test_matches_writeback_tail_block(self):
        from d810.transforms.loop_bound_writer_guard import (
            detect_loop_counter_writeback_tail,
        )

        mba = self._build_mba()
        diag = detect_loop_counter_writeback_tail(mba, tail_block_serial=2)

        assert diag is not None
        assert diag.tail_block_serial == 2
        assert diag.counter_stkoff == self.COUNTER_STKOFF
        assert diag.bound_stkoff == self.BOUND_STKOFF
        assert diag.loop_test_ea == self.LOOP_TEST_EA
        assert diag.advance_ea == self.ADVANCE_EA

    def test_does_not_match_non_writeback_blocks(self):
        from d810.transforms.loop_bound_writer_guard import (
            detect_loop_counter_writeback_tail,
        )

        mba = self._build_mba()
        # Block 0 has the advance compute, not a writeback to counter.
        assert detect_loop_counter_writeback_tail(mba, tail_block_serial=0) is None
        # Block 1 has the loop test, not a writeback.
        assert detect_loop_counter_writeback_tail(mba, tail_block_serial=1) is None
        # Block 3 is unrelated.
        assert detect_loop_counter_writeback_tail(mba, tail_block_serial=3) is None

    def test_rejects_when_writeback_source_is_constant(self):
        """``mov #0, %counter`` is a counter RESET, not a loop-carried
        writeback -- the detector must reject."""
        from d810.transforms.loop_bound_writer_guard import (
            detect_loop_counter_writeback_tail,
        )

        const_zero = _Mop(OperandKind.NUMBER, nnn=_NumValue(0))
        dest = _Mop(OperandKind.STACK, s=_StkOff(self.COUNTER_STKOFF))
        reset = _Insn(InsnKind.MOV, ea=self.WRITEBACK_EA, l=const_zero, d=dest)
        mba = _Mba([
            _build_counter_advance_block(
                counter_stkoff=self.COUNTER_STKOFF,
                delta=2,
                ea=self.ADVANCE_EA,
            ),
            _build_loop_test_block(
                bound_stkoff=self.BOUND_STKOFF,
                counter_stkoff=self.COUNTER_STKOFF,
                delta=2,
                ea=self.LOOP_TEST_EA,
            ),
            _Mblock(_chain(reset)),
        ])
        assert detect_loop_counter_writeback_tail(mba, tail_block_serial=2) is None

    def test_rejects_when_no_loop_test_present(self):
        """Without a ``counter+small_const`` loop test, the writeback is
        not loop-carried."""
        from d810.transforms.loop_bound_writer_guard import (
            detect_loop_counter_writeback_tail,
        )

        mba = _Mba([
            _build_counter_advance_block(
                counter_stkoff=self.COUNTER_STKOFF,
                delta=2,
                ea=self.ADVANCE_EA,
            ),
            _build_unrelated_block(),
            self._build_lvar_writeback_block(
                counter_stkoff=self.COUNTER_STKOFF,
                ea=self.WRITEBACK_EA,
            ),
        ])
        assert detect_loop_counter_writeback_tail(mba, tail_block_serial=2) is None

    def test_rejects_when_no_advance_compute(self):
        """Without an ``m_add counter+small_const`` somewhere in the
        function, the writeback isn't connected to a counter advance."""
        from d810.transforms.loop_bound_writer_guard import (
            detect_loop_counter_writeback_tail,
        )

        mba = _Mba([
            _build_unrelated_block(),
            _build_loop_test_block(
                bound_stkoff=self.BOUND_STKOFF,
                counter_stkoff=self.COUNTER_STKOFF,
                delta=2,
                ea=self.LOOP_TEST_EA,
            ),
            self._build_lvar_writeback_block(
                counter_stkoff=self.COUNTER_STKOFF,
                ea=self.WRITEBACK_EA,
            ),
        ])
        assert detect_loop_counter_writeback_tail(mba, tail_block_serial=2) is None

    def test_returns_none_when_mba_is_none(self):
        from d810.transforms.loop_bound_writer_guard import (
            detect_loop_counter_writeback_tail,
        )

        assert detect_loop_counter_writeback_tail(None, tail_block_serial=2) is None


# Extended ``_Mop`` shim with a ``dstr`` attribute so the
# ``collect_const_var_refs_in_block`` helper can extract ``%var_NNN``
# tokens from the destination operand.  The helper inspects the dest
# mop's ``dstr`` (either a callable or a string).
class _MopWithDstr(_Mop):
    def __init__(self, t: int, *, s=None, nnn=None, d=None, dstr_text: str = ""):
        super().__init__(t, s=s, nnn=nnn, d=d)
        self.dstr = dstr_text


class TestCollectConstVarRefsInBlock:
    def _build_const_writer(
        self,
        const_pairs: tuple[tuple[int, str], ...],
    ) -> _Mblock:
        """Build a block with ``m_mov #const, %var_NNN`` per pair."""
        insns: list[_Insn] = []
        for stkoff, var_token in const_pairs:
            src = _Mop(OperandKind.NUMBER, nnn=_NumValue(0xC0FFEE0000 + stkoff))
            dst = _MopWithDstr(
                OperandKind.STACK, s=_StkOff(stkoff), dstr_text=f"%var_{var_token}.8"
            )
            insns.append(_Insn(InsnKind.MOV, l=src, d=dst))
        return _Mblock(_chain(*insns))

    def test_returns_var_refs_for_const_writes(self):
        from d810.transforms.loop_bound_writer_guard import (
            collect_const_var_refs_in_block,
        )

        block = self._build_const_writer(
            (
                (0x228, "228"),
                (0x650, "650"),
                (0x658, "658"),
                (0x660, "660"),
            )
        )
        mba = _Mba([block])

        refs = collect_const_var_refs_in_block(mba, block_serial=0)

        assert refs == frozenset({"228", "650", "658", "660"})

    def test_accepts_semantic_kind_classifiers_for_live_shaped_objects(self):
        from d810.transforms.loop_bound_writer_guard import (
            collect_const_var_refs_in_block,
        )

        class LiveMop:
            def __init__(self, t, *, nnn=None, s=None, dstr_text=""):
                self.t = t
                self.nnn = nnn
                self.s = s
                self._dstr = dstr_text

            def dstr(self):
                return self._dstr

        class LiveInsn:
            def __init__(self, opcode, *, l=None, d=None):
                self.opcode = opcode
                self.l = l
                self.d = d
                self.next = None

        src = LiveMop("mop_n", nnn=_NumValue(0xC0FFEE))
        dst = LiveMop("mop_S", s=_StkOff(0x228), dstr_text="%var_228.8")
        insn = LiveInsn("m_mov", l=src, d=dst)
        mba = _Mba([_Mblock(_chain(insn))])

        refs = collect_const_var_refs_in_block(
            mba,
            block_serial=0,
            insn_kind_classifier=lambda obj: (
                InsnKind.MOV if getattr(obj, "opcode", None) == "m_mov" else None
            ),
            operand_kind_classifier=lambda obj: {
                "mop_n": OperandKind.NUMBER,
                "mop_S": OperandKind.STACK,
            }.get(getattr(obj, "t", None)),
        )

        assert refs == frozenset({"228"})

    def test_falls_back_to_instruction_text_for_const_write_dest(self):
        from d810.transforms.loop_bound_writer_guard import (
            collect_const_var_refs_in_block,
        )

        src = _Mop(OperandKind.NUMBER, nnn=_NumValue(0xC0FFEE))
        dst = _Mop(OperandKind.STACK, s=_StkOff(0x648))
        insn = _Insn(InsnKind.MOV, l=src, d=dst)
        insn.dstr = lambda: "mov    #0xC0FFEE.8, %var_648.8"
        mba = _Mba([_Mblock(_chain(insn))])

        assert collect_const_var_refs_in_block(mba, block_serial=0) == frozenset({
            "648",
        })

    def test_returns_empty_when_block_has_no_const_writes(self):
        from d810.transforms.loop_bound_writer_guard import (
            collect_const_var_refs_in_block,
        )

        # Block has only an arithmetic instruction, no m_mov #const, K.
        var_x = _Mop(OperandKind.STACK, s=_StkOff(0x100))
        var_y = _Mop(OperandKind.STACK, s=_StkOff(0x108))
        dest = _Mop(OperandKind.STACK, s=_StkOff(0x200))
        arith = _Insn(InsnKind.ADD, l=var_x, r=var_y, d=dest)
        mba = _Mba([_Mblock(_chain(arith))])

        assert collect_const_var_refs_in_block(mba, block_serial=0) == frozenset()

    def test_returns_empty_when_block_serial_out_of_range(self):
        from d810.transforms.loop_bound_writer_guard import (
            collect_const_var_refs_in_block,
        )

        block = self._build_const_writer(((0x228, "228"),))
        mba = _Mba([block])

        # Block 5 is past mba.qty == 1.
        assert collect_const_var_refs_in_block(mba, block_serial=5) == frozenset()

    def test_returns_empty_when_mba_is_none(self):
        from d810.transforms.loop_bound_writer_guard import (
            collect_const_var_refs_in_block,
        )

        assert collect_const_var_refs_in_block(None, block_serial=0) == frozenset()

    def test_skips_non_constant_movs(self):
        from d810.transforms.loop_bound_writer_guard import (
            collect_const_var_refs_in_block,
        )

        # m_mov mop_S(K1), mop_S(K2) -- not a constant, must not match.
        src_var = _Mop(OperandKind.STACK, s=_StkOff(0x100))
        dst_var = _MopWithDstr(
            OperandKind.STACK, s=_StkOff(0x200), dstr_text="%var_200.8"
        )
        insn = _Insn(InsnKind.MOV, l=src_var, d=dst_var)
        mba = _Mba([_Mblock(_chain(insn))])

        assert collect_const_var_refs_in_block(mba, block_serial=0) == frozenset()
