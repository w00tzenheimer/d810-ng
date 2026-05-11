"""Tests for TerminalByteEmitterFactCollector."""
from __future__ import annotations

from types import SimpleNamespace

from d810.core.diag.snapshot import BlockSnapshot, InstructionSnapshot
from d810.recon.facts.collectors import TerminalByteEmitterFactCollector
from d810.recon.facts.collectors.induction_carrier import _MATURITY_VALUES


def _insn(
    *,
    index: int,
    opcode_name: str,
    dstr: str,
    ea: int | None = None,
    dest_type: str | None = None,
    dest_stkoff: int | None = None,
    dest_size: int | None = None,
    src_l_type: str | None = None,
    src_l_stkoff: int | None = None,
    src_l_value: int | None = None,
    src_r_type: str | None = None,
    src_r_stkoff: int | None = None,
    src_r_value: int | None = None,
) -> InstructionSnapshot:
    return InstructionSnapshot(
        index=index,
        ea=0x180010000 + index if ea is None else ea,
        opcode=0,
        opcode_name=opcode_name,
        dest_type=dest_type,
        dest_stkoff=dest_stkoff,
        dest_size=dest_size,
        src_l_type=src_l_type,
        src_l_stkoff=src_l_stkoff,
        src_l_value=src_l_value,
        src_r_type=src_r_type,
        src_r_stkoff=src_r_stkoff,
        src_r_value=src_r_value,
        dstr=dstr,
    )


def _target(
    *instructions: InstructionSnapshot,
    serial: int = 101,
    succs: tuple[int, ...] = (102, 241),
) -> SimpleNamespace:
    return SimpleNamespace(
        blocks={
            serial: BlockSnapshot(
                serial=serial,
                block_type=2,
                type_name="BLT_2WAY",
                start_ea=0x180014000 + serial,
                nsucc=len(succs),
                npred=1,
                succs=list(succs),
                preds=[99],
                instructions=list(instructions),
            )
        }
    )


def test_collects_terminal_byte_emit_with_explicit_byte_index() -> None:
    collector = TerminalByteEmitterFactCollector()

    facts = collector.collect(
        _target(
            _insn(
                index=0,
                opcode_name="m_jcnd",
                dstr="jcnd %var_53.8 == #2.8, @241",
            ),
            _insn(
                index=1,
                opcode_name="m_stx",
                src_l_type="mop_S",
                src_l_stkoff=0x520,
                dstr="stx v52[2], ds.1, %var_dst.8",
            ),
        ),
        func_ea=0x401000,
        maturity=_MATURITY_VALUES["MMAT_LOCOPT"],
        phase="pre_d810",
    )

    assert len(facts) == 1
    fact = facts[0]
    assert fact.kind == "TerminalByteEmitterFact"
    assert "byte_index=2" in fact.semantic_key
    assert "dest=%var_dst.8" in fact.semantic_key
    assert "counter=%var_53.8" in fact.semantic_key
    assert fact.maturity == "MMAT_LOCOPT"
    assert fact.source_block == 101
    assert fact.source_ea == 0x180010001
    assert fact.payload["byte_index"] == 2
    assert fact.payload["source_byte_expression"] == "v52[2]"
    assert fact.payload["destination_buffer_expression"] == "%var_dst.8"
    assert fact.payload["counter_carrier"] == "%var_53.8"
    assert fact.payload["guard_condition"] == "jcnd %var_53.8 == #2.8, @241"
    assert fact.payload["continuation_edge"] == 102
    assert fact.payload["return_edge"] == 241
    assert fact.payload["family_id"] == "non_terminal_byte_emitter"
    assert fact.payload["block_ea"] == 0x180014065


def test_infers_byte_index_from_guard_when_store_uses_temp() -> None:
    collector = TerminalByteEmitterFactCollector()

    facts = collector.collect(
        _target(
            _insn(
                index=0,
                opcode_name="m_jcnd",
                dstr="jnz %var_tail.8, #4.8, @return",
            ),
            _insn(
                index=1,
                opcode_name="op_1",
                src_l_type="mop_S",
                src_l_stkoff=0x688,
                dstr="stx %var_tmp.1, ds.1, %var_dst.8",
            ),
        ),
        func_ea=0x401000,
        maturity=_MATURITY_VALUES["MMAT_CALLS"],
        phase="pre_d810",
    )

    assert len(facts) == 1
    assert facts[0].payload["byte_index"] == 4
    assert facts[0].payload["source_byte_expression"] == "%var_tmp.1"
    assert facts[0].payload["counter_carrier"] == "%var_tail.8"
    assert facts[0].payload["return_edge"] is None
    assert facts[0].payload["continuation_edge"] is None


def test_infers_byte_index_from_source_byte_offset_without_guard() -> None:
    collector = TerminalByteEmitterFactCollector()

    facts = collector.collect(
        _target(
            _insn(
                index=1,
                opcode_name="op_1",
                src_l_type="mop_S",
                src_l_stkoff=0x688,
                dstr=(
                    "stx ([ds.2:%var_dst.8].8 | "
                    "(xdu.8([ds.2:(%var_src.8+#6.8)].1) <<l #8.1)), "
                    "ds.2, %var_dst.8"
                ),
            ),
            succs=(102,),
        ),
        func_ea=0x401000,
        maturity=_MATURITY_VALUES["MMAT_GLBOPT1"],
        phase="pre_d810",
    )

    assert len(facts) == 1
    assert facts[0].payload["byte_index"] == 6
    assert facts[0].payload["counter_carrier"] == "unknown-counter"
    assert facts[0].payload["return_edge"] is None


def test_semantic_key_strips_hexrays_ssa_suffixes() -> None:
    collector = TerminalByteEmitterFactCollector()

    facts = collector.collect(
        _target(
            _insn(
                index=1,
                opcode_name="op_1",
                src_l_type="mop_S",
                src_l_stkoff=0x688,
                dstr=(
                    "stx ([ds.2{403}:((%var_380.8{406} & #-8.8){405}+"
                    "%var_188.8{407}){404}].8 | "
                    "(xdu.8([ds.2:(%var_src.8+#6.8)].1) <<l #8.1)), "
                    "ds.2{403}, ((%var_380.8{406} & #-8.8){405}+"
                    "%var_188.8{407}){404}"
                ),
            ),
            succs=(102,),
        ),
        func_ea=0x401000,
        maturity=_MATURITY_VALUES["MMAT_GLBOPT1"],
        phase="pre_d810",
    )

    assert len(facts) == 1
    assert "{403}" not in facts[0].semantic_key
    assert "{406}" not in facts[0].mop_signature
    assert facts[0].payload["destination_buffer_expression"] == (
        "[ds.2:((%var_380.8 & #-8.8)+%var_188.8)]"
    )


def test_collects_guard_only_zero_edge_fact() -> None:
    collector = TerminalByteEmitterFactCollector()

    facts = collector.collect(
        SimpleNamespace(
            blocks={
                101: BlockSnapshot(
                    serial=101,
                    block_type=2,
                    type_name="BLT_2WAY",
                    start_ea=0x180014101,
                    nsucc=2,
                    npred=1,
                    succs=[102, 241],
                    preds=[99],
                    instructions=[
                        _insn(
                            index=0,
                            opcode_name="m_jcnd",
                            dstr="jnz %var_tail.8, #0.8, @return",
                        ),
                    ],
                ),
                102: BlockSnapshot(
                    serial=102,
                    block_type=2,
                    type_name="BLT_2WAY",
                    start_ea=0x180014102,
                    nsucc=2,
                    npred=1,
                    succs=[103, 241],
                    preds=[101],
                    instructions=[
                        _insn(
                            index=0,
                            opcode_name="m_jcnd",
                            dstr="jnz %var_tail.8, #1.8, @return",
                        ),
                        _insn(
                            index=1,
                            opcode_name="m_stx",
                            dstr="stx v52[1], ds.1, %var_dst.8",
                        ),
                    ],
                ),
            }
        ),
        func_ea=0x401000,
        maturity=_MATURITY_VALUES["MMAT_LOCOPT"],
        phase="pre_d810",
    )

    zero_facts = [
        fact
        for fact in facts
        if fact.payload["byte_index"] == 0
    ]
    assert len(zero_facts) == 1
    assert zero_facts[0].payload["emitter_role"] == "guard_only"
    assert zero_facts[0].payload["destination_buffer_expression"] == "guard-only"
    assert zero_facts[0].payload["return_edge"] is None
    assert zero_facts[0].payload["family_id"] == "terminal_tail"


def test_guard_only_zero_jnz_marks_fallthrough_as_return_edge() -> None:
    collector = TerminalByteEmitterFactCollector()

    facts = collector.collect(
        SimpleNamespace(
            blocks={
                206: BlockSnapshot(
                    serial=206,
                    block_type=2,
                    type_name="BLT_2WAY",
                    start_ea=0x180016448,
                    nsucc=2,
                    npred=1,
                    succs=[207, 208],
                    preds=[204],
                    instructions=[
                        _insn(
                            index=0,
                            opcode_name="m_jcnd",
                            dstr="jnz %var_198.8, #0.8, @208",
                        ),
                    ],
                ),
                208: BlockSnapshot(
                    serial=208,
                    block_type=1,
                    type_name="BLT_1WAY",
                    start_ea=0x180016465,
                    nsucc=1,
                    npred=1,
                    succs=[132],
                    preds=[206],
                    instructions=[
                        _insn(
                            index=0,
                            opcode_name="m_jcnd",
                            dstr="jnz %var_198.8, #6.8, @132",
                        ),
                        _insn(
                            index=1,
                            opcode_name="m_stx",
                            dstr="stx v52[6], ds.1, %var_dst.8",
                        ),
                    ],
                ),
            }
        ),
        func_ea=0x401000,
        maturity=_MATURITY_VALUES["MMAT_GLBOPT1"],
        phase="pre_d810",
    )

    zero_facts = [
        fact
        for fact in facts
        if fact.payload["emitter_role"] == "guard_only"
    ]
    assert len(zero_facts) == 1
    assert zero_facts[0].payload["return_edge"] == 207
    assert zero_facts[0].payload["continuation_edge"] == 208


def test_terminal_family_is_separate_from_non_terminal_byte_emitters() -> None:
    collector = TerminalByteEmitterFactCollector()

    facts = collector.collect(
        SimpleNamespace(
            blocks={
                101: BlockSnapshot(
                    serial=101,
                    block_type=2,
                    type_name="BLT_2WAY",
                    start_ea=0x180014101,
                    nsucc=2,
                    npred=1,
                    succs=[102, 241],
                    preds=[99],
                    instructions=[
                        _insn(
                            index=0,
                            opcode_name="m_jcnd",
                            dstr="jnz %var_tail.8, #0.8, @241",
                        ),
                    ],
                ),
                102: BlockSnapshot(
                    serial=102,
                    block_type=2,
                    type_name="BLT_2WAY",
                    start_ea=0x180014102,
                    nsucc=2,
                    npred=1,
                    succs=[103, 241],
                    preds=[101],
                    instructions=[
                        _insn(
                            index=0,
                            opcode_name="m_jcnd",
                            dstr="jnz %var_tail.8, #2.8, @241",
                        ),
                        _insn(
                            index=1,
                            opcode_name="m_stx",
                            dstr="stx v52[2], ds.1, %var_dst.8",
                        ),
                    ],
                ),
                201: BlockSnapshot(
                    serial=201,
                    block_type=2,
                    type_name="BLT_2WAY",
                    start_ea=0x180015201,
                    nsucc=2,
                    npred=1,
                    succs=[202, 203],
                    preds=[200],
                    instructions=[
                        _insn(
                            index=0,
                            opcode_name="m_jcnd",
                            dstr="jnz %var_loop.8, #2.8, @203",
                        ),
                        _insn(
                            index=1,
                            opcode_name="m_stx",
                            dstr="stx v52[2], ds.1, %var_dst.8",
                        ),
                    ],
                ),
            }
        ),
        func_ea=0x401000,
        maturity=_MATURITY_VALUES["MMAT_LOCOPT"],
        phase="pre_d810",
    )

    families = {
        fact.source_block: fact.payload["family_id"]
        for fact in facts
        if fact.payload["byte_index"] == 2
    }
    assert families[102] == "terminal_tail"
    assert families[201] == "non_terminal_byte_emitter"
    assert "family=terminal_tail" in next(
        fact.semantic_key for fact in facts if fact.source_block == 102
    )
    assert "family=non_terminal_byte_emitter" in next(
        fact.semantic_key for fact in facts if fact.source_block == 201
    )


def test_terminal_family_includes_byte1_continuation_on_terminal_destination() -> None:
    collector = TerminalByteEmitterFactCollector()

    facts = collector.collect(
        SimpleNamespace(
            blocks={
                101: BlockSnapshot(
                    serial=101,
                    block_type=2,
                    type_name="BLT_2WAY",
                    start_ea=0x180014101,
                    nsucc=2,
                    npred=1,
                    succs=[102, 241],
                    preds=[99],
                    instructions=[
                        _insn(
                            index=0,
                            opcode_name="m_jcnd",
                            dstr="jnz %var_tail.8, #0.8, @241",
                        ),
                    ],
                ),
                102: BlockSnapshot(
                    serial=102,
                    block_type=2,
                    type_name="BLT_2WAY",
                    start_ea=0x180014102,
                    nsucc=2,
                    npred=1,
                    succs=[103, 241],
                    preds=[101],
                    instructions=[
                        _insn(
                            index=0,
                            opcode_name="m_jcnd",
                            dstr="jnz %var_tail.8, #2.8, @241",
                        ),
                        _insn(
                            index=1,
                            opcode_name="m_stx",
                            dstr="stx v52[2], ds.1, %var_dst.8",
                        ),
                    ],
                ),
                143: BlockSnapshot(
                    serial=143,
                    block_type=2,
                    type_name="BLT_2WAY",
                    start_ea=0x180014143,
                    nsucc=2,
                    npred=1,
                    succs=[144, 145],
                    preds=[142],
                    instructions=[
                        _insn(
                            index=0,
                            opcode_name="m_jcnd",
                            dstr="jnz %var_other.8, #1.8, @145",
                        ),
                        _insn(
                            index=1,
                            opcode_name="m_stx",
                            dstr="stx #0x80.8, ds.2, %var_dst.8",
                        ),
                    ],
                ),
            }
        ),
        func_ea=0x401000,
        maturity=_MATURITY_VALUES["MMAT_CALLS"],
        phase="pre_d810",
    )

    byte1 = [
        fact
        for fact in facts
        if fact.source_block == 143 and fact.payload["byte_index"] == 1
    ]
    assert len(byte1) == 1
    assert byte1[0].payload["family_id"] == "terminal_tail"
    assert "family=terminal_tail" in byte1[0].semantic_key


def test_ignores_source_byte_load_shift_without_store() -> None:
    collector = TerminalByteEmitterFactCollector()

    facts = collector.collect(
        _target(
            _insn(
                index=0,
                opcode_name="op_22",
                dstr="shl xdu.8([ds.2:(%var_190.8+#1.8)].1), (#8.1*%var_358.1), %var_670.8",
            ),
            succs=(102,),
        ),
        func_ea=0x401000,
        maturity=_MATURITY_VALUES["MMAT_GLBOPT1"],
        phase="pre_d810",
    )

    assert facts == ()


def test_ignores_guard_only_zero_edge_without_related_store_counter() -> None:
    collector = TerminalByteEmitterFactCollector()

    facts = collector.collect(
        _target(
            _insn(
                index=0,
                opcode_name="m_jcnd",
                dstr="jnz %var_7BC.4, #0.8, @return",
            ),
        ),
        func_ea=0x401000,
        maturity=_MATURITY_VALUES["MMAT_LOCOPT"],
        phase="pre_d810",
    )

    assert facts == ()


def test_ignores_store_without_byte_index_or_guard() -> None:
    collector = TerminalByteEmitterFactCollector()

    facts = collector.collect(
        _target(
            _insn(
                index=0,
                opcode_name="m_stx",
                src_l_type="mop_S",
                src_l_stkoff=0x688,
                dstr="stx %var_tmp.1, ds.1, %var_dst.8",
            ),
            succs=(102,),
        ),
        func_ea=0x401000,
        maturity=_MATURITY_VALUES["MMAT_GLBOPT1"],
        phase="pre_d810",
    )

    assert facts == ()
