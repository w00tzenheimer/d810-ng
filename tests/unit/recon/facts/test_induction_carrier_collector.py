"""Tests for InductionVariableFactCollector."""
from __future__ import annotations

from types import SimpleNamespace

from d810.core.diag.snapshot import BlockSnapshot, InstructionSnapshot
from d810.recon.facts.collectors import InductionVariableFactCollector
from d810.recon.facts.collectors.induction_carrier import _MATURITY_VALUES


def _insn(
    *,
    index: int = 0,
    opcode_name: str = "m_add",
    dest_stkoff: int | None = 0x680,
    src_l_stkoff: int | None = 0x680,
    src_l_value: int | None = None,
    src_r_stkoff: int | None = None,
    src_r_value: int | None = 0x80,
    dstr: str = "add %var_178.8, #0x80.8, %var_178.8",
) -> InstructionSnapshot:
    return InstructionSnapshot(
        index=index,
        ea=0x180010000 + index,
        opcode=0,
        opcode_name=opcode_name,
        dest_type="mop_S" if dest_stkoff is not None else None,
        dest_stkoff=dest_stkoff,
        dest_size=8 if dest_stkoff is not None else None,
        src_l_type="mop_S" if src_l_stkoff is not None else "mop_n",
        src_l_stkoff=src_l_stkoff,
        src_l_value=src_l_value,
        src_r_type="mop_S" if src_r_stkoff is not None else "mop_n",
        src_r_stkoff=src_r_stkoff,
        src_r_value=src_r_value,
        dstr=dstr,
    )


def _target(*instructions: InstructionSnapshot) -> SimpleNamespace:
    return SimpleNamespace(
        blocks={
            10: BlockSnapshot(
                serial=10,
                block_type=1,
                type_name="BLT_1WAY",
                nsucc=1,
                npred=1,
                succs=[11],
                preds=[9],
                instructions=list(instructions),
            )
        }
    )


def _two_block_target(
    first: InstructionSnapshot,
    second: InstructionSnapshot,
) -> SimpleNamespace:
    return SimpleNamespace(
        blocks={
            10: BlockSnapshot(
                serial=10,
                block_type=1,
                type_name="BLT_1WAY",
                nsucc=1,
                npred=1,
                succs=[11],
                preds=[9],
                instructions=[first],
            ),
            11: BlockSnapshot(
                serial=11,
                block_type=1,
                type_name="BLT_1WAY",
                nsucc=1,
                npred=1,
                succs=[12],
                preds=[10],
                instructions=[second],
            ),
        }
    )


def test_collects_direct_add_induction_fact() -> None:
    collector = InductionVariableFactCollector()

    facts = collector.collect(
        _target(_insn()),
        func_ea=0x401000,
        maturity=_MATURITY_VALUES["MMAT_LOCOPT"],
        phase="pre_d810",
    )

    assert len(facts) == 1
    fact = facts[0]
    assert fact.kind == "InductionCarrierFact"
    assert fact.semantic_key == "induction:stkoff=0x680:size=8:step=128"
    assert fact.maturity == "MMAT_LOCOPT"
    assert fact.source_block == 10
    assert fact.source_ea == 0x180010000
    assert fact.payload["step"] == 0x80
    assert fact.payload["opcode"] == "m_add"
    assert fact.payload["source_side"] == "right"
    assert fact.evidence == ("add %var_178.8, #0x80.8, %var_178.8",)


def test_collects_sub_as_negative_step() -> None:
    collector = InductionVariableFactCollector()

    facts = collector.collect(
        _target(
            _insn(
                opcode_name="m_sub",
                src_r_value=1,
                dstr="sub %var_178.8, #1.8, %var_178.8",
            )
        ),
        func_ea=0x401000,
        maturity=_MATURITY_VALUES["MMAT_CALLS"],
        phase="pre_d810",
    )

    assert len(facts) == 1
    assert facts[0].semantic_key == "induction:stkoff=0x680:size=8:step=-1"
    assert facts[0].payload["step"] == -1
    assert facts[0].maturity == "MMAT_CALLS"


def test_collects_commuted_add() -> None:
    collector = InductionVariableFactCollector()

    facts = collector.collect(
        _target(
            _insn(
                src_l_stkoff=None,
                src_l_value=4,
                src_r_stkoff=0x680,
                src_r_value=None,
                dstr="add #4.8, %var_178.8, %var_178.8",
            )
        ),
        func_ea=0x401000,
        maturity=4,
        phase="pre_d810",
    )

    assert len(facts) == 1
    assert facts[0].payload["step"] == 4
    assert facts[0].payload["source_side"] == "left"


def test_collects_numeric_opcode_add_alias() -> None:
    collector = InductionVariableFactCollector()

    facts = collector.collect(
        _target(_insn(opcode_name="op_12")),
        func_ea=0x401000,
        maturity=4,
        phase="pre_d810",
    )

    assert len(facts) == 1
    assert facts[0].payload["opcode"] == "op_12"
    assert facts[0].payload["carrier_kind"] == "stack_self_update"


def test_collects_memory_store_update_carrier() -> None:
    collector = InductionVariableFactCollector()
    define = _insn(
        index=2,
        opcode_name="op_12",
        dest_stkoff=0x688,
        src_l_stkoff=None,
        src_l_value=None,
        src_r_stkoff=None,
        src_r_value=1,
        dstr="add    [ds.2:%var_178.8].8, #1.8, %var_170.8",
    )
    store = _insn(
        index=5,
        opcode_name="op_1",
        dest_stkoff=0x680,
        src_l_stkoff=0x688,
        src_l_value=None,
        src_r_stkoff=None,
        src_r_value=None,
        dstr="stx    %var_170.8, ds.2, %var_178.8",
    )

    facts = collector.collect(
        _target(define, store),
        func_ea=0x401000,
        maturity=2,
        phase="pre_d810",
    )

    assert len(facts) == 1
    fact = facts[0]
    assert fact.semantic_key == "induction:memory_base_stkoff=0x680:size=8:step=1"
    assert fact.payload["carrier_kind"] == "memory_store_update"
    assert fact.payload["base_stkoff"] == 0x680
    assert fact.payload["temp_stkoff"] == 0x688
    assert fact.payload["step"] == 1
    assert fact.evidence == (
        "add    [ds.2:%var_178.8].8, #1.8, %var_170.8",
        "stx    %var_170.8, ds.2, %var_178.8",
    )


def test_memory_store_update_does_not_pair_temp_across_blocks() -> None:
    collector = InductionVariableFactCollector()
    define = _insn(
        index=2,
        opcode_name="op_12",
        dest_stkoff=0x688,
        src_l_stkoff=None,
        src_l_value=None,
        src_r_stkoff=None,
        src_r_value=1,
        dstr="add    [ds.2:%var_178.8].8, #1.8, %var_170.8",
    )
    store = _insn(
        index=0,
        opcode_name="op_1",
        dest_stkoff=0x680,
        src_l_stkoff=0x688,
        src_l_value=None,
        src_r_stkoff=None,
        src_r_value=None,
        dstr="stx    %var_170.8, ds.2, %var_178.8",
    )

    facts = collector.collect(
        _two_block_target(define, store),
        func_ea=0x401000,
        maturity=2,
        phase="pre_d810",
    )

    assert facts == ()


def test_collects_writeback_tail_carrier() -> None:
    collector = InductionVariableFactCollector()
    move = _insn(
        index=1,
        opcode_name="op_4",
        dest_stkoff=0x638,
        src_l_stkoff=0x468,
        src_l_value=None,
        src_r_stkoff=None,
        src_r_value=None,
        dstr="mov    %var_390.8, %var_1C0.8",
    )
    address_use = _insn(
        index=3,
        opcode_name="op_9",
        dest_stkoff=0x378,
        src_l_stkoff=None,
        src_l_value=None,
        src_r_stkoff=None,
        src_r_value=None,
        dstr="xdu    [ds.2:(%var_390.8+%var_18.8)].1, %var_480.8",
    )

    facts = collector.collect(
        _target(move, address_use),
        func_ea=0x401000,
        maturity=2,
        phase="pre_d810",
    )

    assert len(facts) == 1
    fact = facts[0]
    assert fact.semantic_key == (
        "induction:writeback_tail:dest=0x638:source=0x468:size=8"
    )
    assert fact.source_block == 10
    assert fact.mop_signature == "mop_S:writeback:dest=0x638:source=0x468:8"
    assert fact.payload["carrier_kind"] == "writeback_tail"
    assert fact.payload["source_token"] == "390"
    assert fact.payload["dest_token"] == "1c0"
    assert fact.evidence == (
        "mov    %var_390.8, %var_1C0.8",
        "xdu    [ds.2:(%var_390.8+%var_18.8)].1, %var_480.8",
    )


def test_collects_writeback_tail_carrier_with_ssa_versions() -> None:
    collector = InductionVariableFactCollector()
    move = _insn(
        index=1,
        opcode_name="op_4",
        dest_stkoff=0x638,
        src_l_stkoff=0x468,
        src_l_value=None,
        src_r_stkoff=None,
        src_r_value=None,
        dstr="mov    %var_390.8{360}, %var_1C0.8{360}",
    )
    address_use = _insn(
        index=3,
        opcode_name="op_9",
        dest_stkoff=0x378,
        src_l_stkoff=None,
        src_l_value=None,
        src_r_stkoff=None,
        src_r_value=None,
        dstr="xdu    [ds.2:(%var_390.8{360}+%var_18.8{3})].1, %var_480.8",
    )

    facts = collector.collect(
        _target(move, address_use),
        func_ea=0x401000,
        maturity=4,
        phase="pre_d810",
    )

    assert len(facts) == 1
    fact = facts[0]
    assert fact.semantic_key == (
        "induction:writeback_tail:dest=0x638:source=0x468:size=8"
    )
    assert fact.payload["source_token"] == "390"
    assert fact.payload["dest_token"] == "1c0"


def test_writeback_tail_requires_same_block_address_use() -> None:
    collector = InductionVariableFactCollector()
    move = _insn(
        index=1,
        opcode_name="op_4",
        dest_stkoff=0x638,
        src_l_stkoff=0x468,
        src_l_value=None,
        src_r_stkoff=None,
        src_r_value=None,
        dstr="mov    %var_390.8, %var_1C0.8",
    )
    address_use = _insn(
        index=0,
        opcode_name="op_9",
        dest_stkoff=0x378,
        src_l_stkoff=None,
        src_l_value=None,
        src_r_stkoff=None,
        src_r_value=None,
        dstr="xdu    [ds.2:(%var_390.8+%var_18.8)].1, %var_480.8",
    )

    facts = collector.collect(
        _two_block_target(move, address_use),
        func_ea=0x401000,
        maturity=2,
        phase="pre_d810",
    )

    assert facts == ()


def test_writeback_tail_requires_source_token_inside_memory_address() -> None:
    collector = InductionVariableFactCollector()
    move = _insn(
        index=1,
        opcode_name="op_4",
        dest_stkoff=0x638,
        src_l_stkoff=0x468,
        src_l_value=None,
        src_r_stkoff=None,
        src_r_value=None,
        dstr="mov    %var_390.8{360}, %var_1C0.8{360}",
    )
    non_address_use = _insn(
        index=3,
        opcode_name="op_12",
        dest_stkoff=0x378,
        src_l_stkoff=0x468,
        src_l_value=None,
        src_r_stkoff=None,
        src_r_value=None,
        dstr="add    [ds.2:(%var_18.8{3})].8, %var_390.8{360}, %var_480.8",
    )

    facts = collector.collect(
        _target(move, non_address_use),
        func_ea=0x401000,
        maturity=4,
        phase="pre_d810",
    )

    assert facts == ()


def test_ignores_non_self_update() -> None:
    collector = InductionVariableFactCollector()

    facts = collector.collect(
        _target(_insn(src_l_stkoff=0x700)),
        func_ea=0x401000,
        maturity=2,
        phase="pre_d810",
    )

    assert facts == ()


def test_ignores_ambiguous_sub_const_minus_var() -> None:
    collector = InductionVariableFactCollector()

    facts = collector.collect(
        _target(
            _insn(
                opcode_name="m_sub",
                src_l_stkoff=None,
                src_l_value=10,
                src_r_stkoff=0x680,
                src_r_value=None,
                dstr="sub #10.8, %var_178.8, %var_178.8",
            )
        ),
        func_ea=0x401000,
        maturity=2,
        phase="pre_d810",
    )

    assert facts == ()
