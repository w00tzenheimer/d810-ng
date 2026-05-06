"""Tests for ReturnCarrierFactCollector."""
from __future__ import annotations

from types import SimpleNamespace

from d810.core.diag.snapshot import BlockSnapshot, InstructionSnapshot
from d810.recon.facts.collectors import ReturnCarrierFactCollector
from d810.recon.facts.collectors.induction_carrier import _MATURITY_VALUES


def _insn(
    *,
    index: int = 0,
    opcode_name: str = "m_mov",
    dest_type: str | None = "mop_S",
    dest_stkoff: int | None = 0x7F0,
    dest_size: int | None = 8,
    src_l_type: str | None = "mop_S",
    src_l_stkoff: int | None = 0x680,
    src_l_value: int | None = None,
    src_r_type: str | None = None,
    src_r_stkoff: int | None = None,
    src_r_value: int | None = None,
    dstr: str = "mov %var_178.8, %var_8.8",
) -> InstructionSnapshot:
    return InstructionSnapshot(
        index=index,
        ea=0x180010000 + index,
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


def test_collects_return_slot_identity_carrier() -> None:
    collector = ReturnCarrierFactCollector()

    facts = collector.collect(
        _target(
            _insn(),
            _insn(
                index=1,
                dest_type="mop_r",
                dest_stkoff=None,
                dest_size=8,
                src_l_type="mop_S",
                src_l_stkoff=0x7F0,
                dstr="mov %var_8.8, rax.8",
            ),
        ),
        func_ea=0x401000,
        maturity=_MATURITY_VALUES["MMAT_LOCOPT"],
        phase="pre_d810",
    )

    assert len(facts) == 1
    fact = facts[0]
    assert fact.kind == "ReturnCarrierFact"
    assert fact.semantic_key == (
        "return_carrier:slot=0x7f0:class=stack_identity_carrier:source=mop_S:0x680"
    )
    assert fact.maturity == "MMAT_LOCOPT"
    assert fact.source_block == 10
    assert fact.source_ea == 0x180010000
    assert fact.mop_signature == "return_slot:mop_S:0x7f0:8"
    assert fact.payload["return_slot_stkoff"] == 0x7F0
    assert fact.payload["source_signature"] == "mop_S:0x680"
    assert fact.payload["carrier_class"] == "stack_identity_carrier"
    assert fact.evidence == ("mov %var_178.8, %var_8.8",)


def test_collects_state_guard_artifact_candidate() -> None:
    collector = ReturnCarrierFactCollector()

    facts = collector.collect(
        _target(
            _insn(
                opcode_name="m_xdu",
                src_l_stkoff=0x3C,
                dstr="xdu %var_7BC.4, %var_8.8",
            ),
            _insn(
                index=1,
                dest_type="mop_r",
                dest_stkoff=None,
                src_l_stkoff=0x7F0,
                dstr="mov %var_8.8, rax.8",
            ),
        ),
        func_ea=0x401000,
        maturity=_MATURITY_VALUES["MMAT_GLBOPT1"],
        phase="post_d810",
    )

    assert len(facts) == 1
    assert facts[0].semantic_key == (
        "return_carrier:slot=0x7f0:class=state_guard_artifact_candidate:"
        "source=mop_S:0x3c"
    )
    assert facts[0].payload["source_signature"] == "mop_S:0x3c"
    assert facts[0].payload["opcode"] == "m_xdu"


def test_collects_constant_or_offset_return() -> None:
    collector = ReturnCarrierFactCollector()

    facts = collector.collect(
        _target(
            _insn(
                opcode_name="m_add",
                src_l_type="mop_n",
                src_l_stkoff=None,
                src_l_value=0xD0,
                src_r_type="mop_S",
                src_r_stkoff=0x20,
                dstr="add %arg_20.8, #0xD0.8, %var_8.8",
            ),
            _insn(
                index=1,
                dest_type="mop_r",
                dest_stkoff=None,
                src_l_stkoff=0x7F0,
                dstr="mov %var_8.8, rax.8",
            ),
        ),
        func_ea=0x401000,
        maturity=_MATURITY_VALUES["MMAT_CALLS"],
        phase="pre_d810",
    )

    assert len(facts) == 1
    assert facts[0].semantic_key == (
        "return_carrier:slot=0x7f0:class=constant_or_offset_return:source=const:0xd0"
    )
    assert facts[0].payload["source_signature"] == "const:0xd0"


def test_classifies_non_mov_stack_arithmetic_as_computed_return() -> None:
    collector = ReturnCarrierFactCollector()

    facts = collector.collect(
        _target(
            _insn(
                opcode_name="m_add",
                src_l_type="mop_S",
                src_l_stkoff=0x680,
                src_r_type="mop_S",
                src_r_stkoff=0x688,
                dstr="add %var_178.8, %var_170.8, %var_8.8",
            ),
            _insn(
                index=1,
                dest_type="mop_r",
                dest_stkoff=None,
                src_l_stkoff=0x7F0,
                dstr="mov %var_8.8, rax.8",
            ),
        ),
        func_ea=0x401000,
        maturity=_MATURITY_VALUES["MMAT_CALLS"],
        phase="pre_d810",
    )

    assert len(facts) == 1
    assert facts[0].semantic_key == (
        "return_carrier:slot=0x7f0:class=computed_return:source=mop_S:0x680"
    )
    assert facts[0].payload["carrier_class"] == "computed_return"


def test_ignores_return_slot_writes_without_return_register_read() -> None:
    collector = ReturnCarrierFactCollector()

    facts = collector.collect(
        _target(_insn()),
        func_ea=0x401000,
        maturity=_MATURITY_VALUES["MMAT_LOCOPT"],
        phase="pre_d810",
    )

    assert facts == ()


def test_ignores_non_return_slot_write() -> None:
    collector = ReturnCarrierFactCollector()

    facts = collector.collect(
        _target(
            _insn(dest_stkoff=0x680, dstr="mov %var_178.8, %var_178.8"),
            _insn(
                index=1,
                dest_type="mop_r",
                dest_stkoff=None,
                src_l_stkoff=0x7F0,
                dstr="mov %var_8.8, rax.8",
            ),
        ),
        func_ea=0x401000,
        maturity=_MATURITY_VALUES["MMAT_LOCOPT"],
        phase="pre_d810",
    )

    assert facts == ()
