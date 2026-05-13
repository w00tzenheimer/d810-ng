"""Tests for LoopCarrierFactCollector."""
from __future__ import annotations

from types import SimpleNamespace

from d810.core.diag.snapshot import BlockSnapshot, InstructionSnapshot
from d810.recon.facts.collectors import LoopCarrierFactCollector
from d810.recon.facts.collectors.induction_carrier import _MATURITY_VALUES
from d810.recon.facts.model import FactObservation, ValidatedFactView


def _insn(
    *,
    index: int,
    ea: int,
    opcode_name: str,
    dstr: str,
    dest_stkoff: int | None = None,
    dest_size: int | None = 8,
) -> InstructionSnapshot:
    return InstructionSnapshot(
        index=index,
        ea=ea,
        opcode=0,
        opcode_name=opcode_name,
        dest_type="mop_S" if dest_stkoff is not None else None,
        dest_stkoff=dest_stkoff,
        dest_size=dest_size,
        src_l_type=None,
        src_l_stkoff=None,
        src_l_value=None,
        src_r_type=None,
        src_r_stkoff=None,
        src_r_value=None,
        dstr=dstr,
    )


def _block(
    serial: int,
    *insns: InstructionSnapshot,
    succs: tuple[int, ...] = (),
) -> BlockSnapshot:
    return BlockSnapshot(
        serial=serial,
        block_type=1 if len(succs) <= 1 else 2,
        type_name="BLT_1WAY" if len(succs) <= 1 else "BLT_2WAY",
        start_ea=0x180014000 + serial,
        nsucc=len(succs),
        npred=0,
        succs=list(succs),
        preds=[],
        instructions=list(insns),
    )


def _target(*blocks: BlockSnapshot) -> SimpleNamespace:
    return SimpleNamespace(blocks={blk.serial: blk for blk in blocks})


def _collect(target: object) -> tuple[FactObservation, ...]:
    return LoopCarrierFactCollector().collect(
        target,
        func_ea=0x180012df0,
        maturity=_MATURITY_VALUES["MMAT_GLBOPT1"],
        phase="post_d810",
    )


def _sub7ffd_loop_shape(*extra_blocks: BlockSnapshot) -> SimpleNamespace:
    """Minimal graph for the v22 / %var_3A8 carrier issue.

    Predicate block 81 is in SCC {81,82}.  The carrier writers live at
    blocks 151 and 186, outside that SCC.  Predicate inputs 528/508/4F8
    are all derived from %var_3A8.
    """
    return _target(
        _block(
            52,
            _insn(
                index=0,
                ea=0x180014052,
                opcode_name="m_sub",
                dest_stkoff=0x530,
                dstr=(
                    "sub ((2*xdu(%var_3A8.1 & 0x7F)) + %var_518.8), "
                    "%var_520.8, %var_528.8"
                ),
            ),
            succs=(81,),
        ),
        _block(
            88,
            _insn(
                index=0,
                ea=0x180014088,
                opcode_name="m_bnot",
                dest_stkoff=0x530,
                dstr="bnot (%var_3A8.8 | 0x7F), %var_508.8",
            ),
            succs=(123,),
        ),
        _block(
            187,
            _insn(
                index=0,
                ea=0x180014187,
                opcode_name="m_mul",
                dest_stkoff=0x530,
                dstr="mul #7, xdu(bnot(%var_3A8.1) & 0x7F), %var_4F8.8",
            ),
            succs=(88,),
        ),
        _block(
            151,
            _insn(
                index=0,
                ea=0x180014151,
                opcode_name="m_mov",
                dest_stkoff=0x450,
                dstr="mov %var_1A0.8, %var_3A8.8",
            ),
            succs=(187,),
        ),
        _block(
            186,
            _insn(
                index=0,
                ea=0x180014186,
                opcode_name="m_mov",
                dest_stkoff=0x450,
                dstr="mov %var_4E8.8, %var_3A8.8",
            ),
            succs=(88,),
        ),
        _block(
            81,
            _insn(
                index=1,
                ea=0x180014081,
                opcode_name="m_jnz",
                dstr="jnz (%var_528.8 + %var_508.8), %var_4F8.8, @83",
            ),
            succs=(82, 83),
        ),
        _block(82, succs=(81,)),
        _block(83, succs=()),
        _block(123, succs=(52,)),
        *extra_blocks,
    )


def test_detects_carrier_writer_outside_loop_scc() -> None:
    facts = _collect(_sub7ffd_loop_shape())

    assert len(facts) == 1
    fact = facts[0]
    assert fact.kind == "LoopCarrierFact"
    assert fact.payload["classification"] == "LOOP_CARRIER_WRITER_OUTSIDE_SCC"
    assert fact.payload["predicate_block_serial"] == 81
    assert fact.payload["predicate_var_tokens"] == [
        "%var_528",
        "%var_508",
        "%var_4F8",
    ]
    assert fact.payload["carrier_var_token"] == "%var_3A8"
    assert fact.payload["carrier_stkoff"] == 0x450
    assert fact.payload["carrier_writer_blocks"] == [151, 186]
    assert fact.payload["carrier_writer_blocks_in_loop"] == []
    assert fact.payload["carrier_writer_blocks_outside_loop"] == [151, 186]
    assert fact.payload["carrier_reader_blocks"] == [52, 88, 187]
    assert fact.payload["loop_scc_blocks"] == [81, 82]


def test_classifies_carrier_writer_inside_loop_scc() -> None:
    facts = _collect(
        _sub7ffd_loop_shape(
            _block(
                82,
                _insn(
                    index=0,
                    ea=0x180014182,
                    opcode_name="m_mov",
                    dest_stkoff=0x450,
                    dstr="mov %var_1A0.8, %var_3A8.8",
                ),
                succs=(81,),
            ),
        )
    )

    assert len(facts) == 1
    fact = facts[0]
    assert fact.payload["classification"] == "LOOP_CARRIER_WRITER_IN_SCC"
    assert fact.payload["carrier_writer_blocks_in_loop"] == [82]
    assert fact.payload["carrier_writer_blocks_outside_loop"] == [151, 186]


def test_no_fact_when_predicate_block_is_not_in_loop() -> None:
    facts = _collect(
        _target(
            _block(
                52,
                _insn(
                    index=0,
                    ea=0x180014052,
                    opcode_name="m_sub",
                    dest_stkoff=0x530,
                    dstr="sub %var_3A8.8, %var_520.8, %var_528.8",
                ),
                succs=(81,),
            ),
            _block(
                88,
                _insn(
                    index=0,
                    ea=0x180014088,
                    opcode_name="m_bnot",
                    dest_stkoff=0x530,
                    dstr="bnot %var_3A8.8, %var_508.8",
                ),
                succs=(81,),
            ),
            _block(
                151,
                _insn(
                    index=0,
                    ea=0x180014151,
                    opcode_name="m_mov",
                    dest_stkoff=0x450,
                    dstr="mov %var_1A0.8, %var_3A8.8",
                ),
                succs=(81,),
            ),
            _block(
                81,
                _insn(
                    index=1,
                    ea=0x180014081,
                    opcode_name="m_jnz",
                    dstr="jnz (%var_528.8 + %var_508.8), %var_4F8.8, @83",
                ),
                succs=(83,),
            ),
            _block(83, succs=()),
        )
    )

    assert facts == ()


def test_view_accessor_returns_loop_carrier_by_predicate_block() -> None:
    facts = _collect(_sub7ffd_loop_shape())
    view = ValidatedFactView(
        maturity="MMAT_GLBOPT1",
        observations=facts,
        mappings=(),
    )

    found = view.loop_carriers_for_predicate_block(81)
    assert len(found) == 1
    assert found[0].payload["carrier_var_token"] == "%var_3A8"
    assert view.loop_carriers_for_predicate_block(999) == ()
