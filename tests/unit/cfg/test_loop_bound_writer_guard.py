"""Unit test for the loop-bound-writer detector.

The detector consumes Hex-Rays-shaped instruction and operand objects, but it
must not import live Hex-Rays modules. These tests use hand-built ``mba``
skeletons with known opcode/mop_t values so we can verify the detector returns
a diagnostic only for the intended block.
"""

from __future__ import annotations

from d810.ir.flowgraph import (
    BlockKind,
    BlockSnapshot,
    FlowGraph,
    InsnKind,
    InsnSnapshot,
    MopSnapshot,
    OperandKind,
)


class _StkOff:
    def __init__(self, off: int):
        self.off = off


class _NumValue:
    def __init__(self, value: int):
        self.value = value


def _Mop(kind: OperandKind, *, s=None, nnn=None, d=None):
    """Build a portable ``MopSnapshot`` for the detector's canonical projection.

    ``s`` carries a stack offset (``_StkOff``), ``nnn`` a constant value
    (``_NumValue``), and ``d`` a nested ``InsnSnapshot`` (a SUBINSN operand,
    projected from the wrapped ``m_add`` to ``Add(Move(StackSlot), Const)``)."""
    if kind is OperandKind.SUBINSN:
        sub = d
        return MopSnapshot(
            size=4,
            kind=OperandKind.SUBINSN,
            sub_kind=sub.kind if sub is not None else None,
            sub_l=sub.l if sub is not None else None,
            sub_r=sub.r if sub is not None else None,
        )
    if kind is OperandKind.NUMBER:
        return MopSnapshot(size=4, value=int(nnn.value), kind=OperandKind.NUMBER)
    if kind is OperandKind.STACK:
        return MopSnapshot(size=4, stkoff=int(s.off), kind=OperandKind.STACK)
    if kind is OperandKind.LVAR:
        return MopSnapshot(size=4, lvar_off=0, kind=OperandKind.LVAR)
    return MopSnapshot(size=4, kind=kind)


class _Insn:
    """Builder that exposes ``.l``/``.r``/``.d`` as portable ``MopSnapshot``s.

    For top-level block instructions it is materialized into a real
    ``InsnSnapshot`` by ``_insns_of``; as a nested SUBINSN body it is read for
    its ``kind``/``l``/``r`` operands by ``_Mop(OperandKind.SUBINSN, ...)``."""

    def __init__(self, kind: InsnKind, *, ea: int = 0, l=None, r=None, d=None):
        self.kind = kind
        self.ea = ea
        self.l = l
        self.r = r
        self.d = d
        self.next = None

    def to_snapshot(self) -> InsnSnapshot:
        operands = tuple(op for op in (self.l, self.r, self.d) if op is not None)
        return InsnSnapshot(
            opcode=-1,
            ea=int(self.ea),
            operands=operands,
            l=self.l,
            r=self.r,
            d=self.d,
            kind=self.kind,
        )


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


def _build_counter_advance_block(
    *, counter_stkoff: int, delta: int, ea: int
) -> _Mblock:
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
        return _Mba(
            [
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
            ]
        )

    def test_matches_writeback_tail_block(self):
        from d810.transforms.loop_bound_writer_guard import (
            detect_loop_counter_writeback_tail,
        )

        flow_graph = _flow_graph_from_blocks(self._build_mba()._blocks)
        diag = detect_loop_counter_writeback_tail(flow_graph, tail_block_serial=2)

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

        flow_graph = _flow_graph_from_blocks(self._build_mba()._blocks)
        # Block 0 has the advance compute, not a writeback to counter.
        assert (
            detect_loop_counter_writeback_tail(flow_graph, tail_block_serial=0) is None
        )
        # Block 1 has the loop test, not a writeback.
        assert (
            detect_loop_counter_writeback_tail(flow_graph, tail_block_serial=1) is None
        )
        # Block 3 is unrelated.
        assert (
            detect_loop_counter_writeback_tail(flow_graph, tail_block_serial=3) is None
        )

    def test_rejects_when_writeback_source_is_constant(self):
        """``mov #0, %counter`` is a counter RESET, not a loop-carried
        writeback -- the detector must reject."""
        from d810.transforms.loop_bound_writer_guard import (
            detect_loop_counter_writeback_tail,
        )

        const_zero = _Mop(OperandKind.NUMBER, nnn=_NumValue(0))
        dest = _Mop(OperandKind.STACK, s=_StkOff(self.COUNTER_STKOFF))
        reset = _Insn(InsnKind.MOV, ea=self.WRITEBACK_EA, l=const_zero, d=dest)
        flow_graph = _flow_graph_from_blocks(
            [
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
            ]
        )
        assert (
            detect_loop_counter_writeback_tail(flow_graph, tail_block_serial=2) is None
        )

    def test_rejects_when_no_loop_test_present(self):
        """Without a ``counter+small_const`` loop test, the writeback is
        not loop-carried."""
        from d810.transforms.loop_bound_writer_guard import (
            detect_loop_counter_writeback_tail,
        )

        flow_graph = _flow_graph_from_blocks(
            [
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
            ]
        )
        assert (
            detect_loop_counter_writeback_tail(flow_graph, tail_block_serial=2) is None
        )

    def test_rejects_when_no_advance_compute(self):
        """Without an ``m_add counter+small_const`` somewhere in the
        function, the writeback isn't connected to a counter advance."""
        from d810.transforms.loop_bound_writer_guard import (
            detect_loop_counter_writeback_tail,
        )

        flow_graph = _flow_graph_from_blocks(
            [
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
            ]
        )
        assert (
            detect_loop_counter_writeback_tail(flow_graph, tail_block_serial=2) is None
        )

    def test_returns_none_when_flow_graph_is_none(self):
        from d810.transforms.loop_bound_writer_guard import (
            detect_loop_counter_writeback_tail,
        )

        assert detect_loop_counter_writeback_tail(None, tail_block_serial=2) is None


# ``dstr`` is intentionally dropped: the const-writer helper reads the
# structured stack offset off the canonical projection, never rendered text.
def _MopWithDstr(t: OperandKind, *, s=None, nnn=None, d=None, dstr_text: str = ""):
    return _Mop(t, s=s, nnn=nnn, d=d)


def _insns_of(block: _Mblock) -> tuple[InsnSnapshot, ...]:
    """Flatten an ``_Mblock`` head→next chain into portable ``InsnSnapshot``s."""
    insns: list[InsnSnapshot] = []
    insn = block.head
    while insn is not None:
        insns.append(insn.to_snapshot())
        insn = insn.next
    return tuple(insns)


def _flow_graph_from_blocks(blocks: list[_Mblock]) -> FlowGraph:
    """Wrap test ``_Mblock`` fakes in a portable ``FlowGraph`` snapshot.

    ``collect_const_var_refs_in_block`` now consumes a ``FlowGraph`` and
    iterates ``BlockSnapshot.iter_insns()``; the ``_Insn`` fakes ride along
    as snapshot instructions (the helper reads ``.kind``/``.l``/``.d`` only).
    ``tail_opcode=0`` skips the ``insn_snapshots[-1].opcode`` derivation that
    the structural ``_Insn`` fakes do not provide.
    """
    snapshots = {
        serial: BlockSnapshot(
            serial=serial,
            block_type=0,
            succs=(),
            preds=(),
            flags=0,
            start_ea=0,
            insn_snapshots=_insns_of(block),
            tail_opcode=0,
            tail_kind=InsnKind.UNKNOWN,
            kind=BlockKind.ZERO_WAY,
        )
        for serial, block in enumerate(blocks)
    }
    return FlowGraph(blocks=snapshots, entry_serial=0, func_ea=0)


class TestCollectConstVarRefsInBlock:
    def _build_const_writer(
        self,
        const_pairs: tuple[tuple[int, str], ...],
    ) -> _Mblock:
        """Build a block with ``m_mov #const, stack`` per pair."""
        insns: list[_Insn] = []
        for stkoff, var_token in const_pairs:
            src = _Mop(OperandKind.NUMBER, nnn=_NumValue(0xC0FFEE0000 + stkoff))
            dst = _MopWithDstr(
                OperandKind.STACK, s=_StkOff(stkoff), dstr_text=f"%var_{var_token}.8"
            )
            insns.append(_Insn(InsnKind.MOV, l=src, d=dst))
        return _Mblock(_chain(*insns))

    def test_returns_storage_keys_for_const_writes(self):
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
        flow_graph = _flow_graph_from_blocks([block])

        refs = collect_const_var_refs_in_block(flow_graph, block_serial=0)

        assert refs == frozenset({"s552", "s1616", "s1624", "s1632"})

    def test_accepts_classifier_params_for_caller_compat(self):
        """The detector still accepts the legacy classifier parameters.

        The canonical ``Instruction`` projection carries the semantic kind, so
        the classifiers are no longer consulted; passing them must remain a
        no-op (callers in ``terminal_byte_emit_fact_guard`` /
        ``return_carrier_fact_guard`` thread them unconditionally)."""
        from d810.transforms.loop_bound_writer_guard import (
            collect_const_var_refs_in_block,
        )

        src = _Mop(OperandKind.NUMBER, nnn=_NumValue(0xC0FFEE))
        dst = _Mop(OperandKind.STACK, s=_StkOff(0x228))
        insn = _Insn(InsnKind.MOV, l=src, d=dst)
        flow_graph = _flow_graph_from_blocks([_Mblock(_chain(insn))])

        refs = collect_const_var_refs_in_block(
            flow_graph,
            block_serial=0,
            insn_kind_classifier=lambda obj: None,
            operand_kind_classifier=lambda obj: None,
        )

        assert refs == frozenset({"s552"})

    def test_ignores_instruction_text_for_const_write_dest(self):
        from d810.transforms.loop_bound_writer_guard import (
            collect_const_var_refs_in_block,
        )

        src = _Mop(OperandKind.NUMBER, nnn=_NumValue(0xC0FFEE))
        dst = _Mop(OperandKind.STACK, s=_StkOff(0x648))
        insn = _Insn(InsnKind.MOV, l=src, d=dst)
        insn.dstr = lambda: "mov    #0xC0FFEE.8, %var_DEAD.8"
        flow_graph = _flow_graph_from_blocks([_Mblock(_chain(insn))])

        assert collect_const_var_refs_in_block(flow_graph, block_serial=0) == frozenset(
            {
                "s1608",
            }
        )

    def test_returns_empty_when_block_has_no_const_writes(self):
        from d810.transforms.loop_bound_writer_guard import (
            collect_const_var_refs_in_block,
        )

        # Block has only an arithmetic instruction, no m_mov #const, K.
        var_x = _Mop(OperandKind.STACK, s=_StkOff(0x100))
        var_y = _Mop(OperandKind.STACK, s=_StkOff(0x108))
        dest = _Mop(OperandKind.STACK, s=_StkOff(0x200))
        arith = _Insn(InsnKind.ADD, l=var_x, r=var_y, d=dest)
        flow_graph = _flow_graph_from_blocks([_Mblock(_chain(arith))])

        assert (
            collect_const_var_refs_in_block(flow_graph, block_serial=0) == frozenset()
        )

    def test_returns_empty_when_block_serial_out_of_range(self):
        from d810.transforms.loop_bound_writer_guard import (
            collect_const_var_refs_in_block,
        )

        block = self._build_const_writer(((0x228, "228"),))
        flow_graph = _flow_graph_from_blocks([block])

        # Block 5 is absent from the FlowGraph (only serial 0 exists).
        assert (
            collect_const_var_refs_in_block(flow_graph, block_serial=5) == frozenset()
        )

    def test_returns_empty_when_flow_graph_is_none(self):
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
        flow_graph = _flow_graph_from_blocks([_Mblock(_chain(insn))])

        assert (
            collect_const_var_refs_in_block(flow_graph, block_serial=0) == frozenset()
        )
