"""Tests for StateWriteAnchorFactCollector."""
from __future__ import annotations

from types import SimpleNamespace

from d810.core.diag.snapshot import BlockSnapshot, InstructionSnapshot
from d810.recon.facts.collectors import StateWriteAnchorFactCollector
from d810.recon.facts.collectors.induction_carrier import _MATURITY_VALUES


def _insn(
    *,
    index: int,
    opcode_name: str = "m_mov",
    dest_type: str | None = "mop_S",
    dest_stkoff: int | None = 0x3C,
    dest_size: int | None = 4,
    src_l_type: str | None = "mop_n",
    src_l_value: int | None = 0x5A21D9DB,
    src_l_stkoff: int | None = None,
    ea: int | None = None,
    dstr: str | None = None,
) -> InstructionSnapshot:
    return InstructionSnapshot(
        index=index,
        ea=0x180014100 + index if ea is None else ea,
        opcode=0,
        opcode_name=opcode_name,
        dest_type=dest_type,
        dest_stkoff=dest_stkoff,
        dest_size=dest_size,
        src_l_type=src_l_type,
        src_l_stkoff=src_l_stkoff,
        src_l_value=src_l_value,
        src_r_type=None,
        src_r_stkoff=None,
        src_r_value=None,
        dstr=dstr or "mov #0x5A21D9DB.4, %var_7BC.4",
    )


def _block(
    serial: int,
    *insns: InstructionSnapshot,
    succs: tuple[int, ...] = (),
    start_ea: int | None = None,
) -> BlockSnapshot:
    return BlockSnapshot(
        serial=serial,
        block_type=1 if len(succs) <= 1 else 2,
        type_name="BLT_1WAY" if len(succs) <= 1 else "BLT_2WAY",
        start_ea=0x180014000 + serial if start_ea is None else start_ea,
        nsucc=len(succs),
        npred=0,
        succs=list(succs),
        preds=[],
        instructions=list(insns),
    )


def _target(*blocks: BlockSnapshot) -> SimpleNamespace:
    return SimpleNamespace(blocks={blk.serial: blk for blk in blocks})


def test_collects_state_const_write_basic() -> None:
    collector = StateWriteAnchorFactCollector()
    facts = collector.collect(
        _target(
            _block(
                100,
                _insn(index=0, src_l_value=0x5A21D9DB, ea=0x180014155),
                succs=(101,),
            ),
        ),
        func_ea=0x180012cf0,
        maturity=_MATURITY_VALUES["MMAT_LOCOPT"],
        phase="pre_d810",
    )
    assert len(facts) == 1
    fact = facts[0]
    assert fact.kind == "StateWriteAnchorFact"
    assert fact.maturity == "MMAT_LOCOPT"
    assert fact.phase == "pre_d810"
    assert fact.source_block == 100
    assert fact.source_ea == 0x180014155
    assert fact.payload["state_const"] == 0x5A21D9DB
    assert fact.payload["state_const_hex"] == "0x000000005a21d9db"
    assert fact.payload["block_serial"] == 100
    assert fact.payload["instruction_index"] == 0
    assert fact.payload["instruction_ea"] == 0x180014155
    assert fact.payload["state_var_stkoff"] == 0x3C
    assert fact.payload["state_var_stkoff_hex"] == "0x3c"
    assert fact.payload["dest_var_signature"] == "%var_7BC.4"
    assert fact.payload["successor_blocks"] == [101]
    assert fact.payload["opcode"] == "m_mov"
    assert fact.semantic_key == fact.fact_id
    assert (
        fact.semantic_key
        == "state_write_anchor:blk=100:insn=0:ea=0x180014155:stkoff=0x3c"
    )
    assert fact.mop_signature == "state_write:mop_S:0x3c:4"


def test_ignores_non_const_writes() -> None:
    collector = StateWriteAnchorFactCollector()
    facts = collector.collect(
        _target(
            _block(
                100,
                # Source is a stkvar, not a const -- should be ignored
                _insn(
                    index=0,
                    src_l_type="mop_S",
                    src_l_value=None,
                    src_l_stkoff=0x40,
                    dstr="mov %var_3C.4, %var_3C.4",
                ),
            ),
        ),
        func_ea=0x180012cf0,
        maturity=_MATURITY_VALUES["MMAT_LOCOPT"],
        phase="pre_d810",
    )
    assert facts == ()


def test_ignores_non_stkvar_destination() -> None:
    collector = StateWriteAnchorFactCollector()
    facts = collector.collect(
        _target(
            _block(
                100,
                _insn(
                    index=0,
                    dest_type="mop_r",
                    dest_stkoff=None,
                    dstr="mov #0x1234.4, eax.4",
                ),
            ),
        ),
        func_ea=0x180012cf0,
        maturity=_MATURITY_VALUES["MMAT_LOCOPT"],
        phase="pre_d810",
    )
    assert facts == ()


def test_collects_multiple_writes_across_blocks() -> None:
    collector = StateWriteAnchorFactCollector()
    facts = collector.collect(
        _target(
            _block(
                54,
                _insn(
                    index=0,
                    src_l_value=0x432DC789,
                    ea=0x180012abc,
                    dstr="mov #0x432DC789.4, %var_7BC.4",
                ),
                succs=(55,),
            ),
            _block(
                100,
                _insn(
                    index=0,
                    src_l_value=0x5A21D9DB,
                    ea=0x180014155,
                ),
                succs=(101,),
            ),
            _block(
                161,
                _insn(
                    index=0,
                    src_l_value=0x149AED27,
                    ea=0x180015abc,
                    dstr="mov #0x149AED27.4, %var_7BC.4",
                ),
                succs=(162,),
            ),
        ),
        func_ea=0x180012cf0,
        maturity=_MATURITY_VALUES["MMAT_LOCOPT"],
        phase="pre_d810",
    )
    assert len(facts) == 3
    by_block = {fact.payload["block_serial"]: fact for fact in facts}
    assert by_block[54].payload["state_const"] == 0x432DC789
    assert by_block[100].payload["state_const"] == 0x5A21D9DB
    assert by_block[161].payload["state_const"] == 0x149AED27


def test_dedupe_by_block_insn_ea_stkoff() -> None:
    collector = StateWriteAnchorFactCollector()
    insn = _insn(index=0, src_l_value=0xDEAD, ea=0x180014155)
    facts = collector.collect(
        _target(_block(100, insn, succs=(101,))),
        func_ea=0x180012cf0,
        maturity=_MATURITY_VALUES["MMAT_LOCOPT"],
        phase="pre_d810",
    )
    assert len(facts) == 1


def test_synthetic_ea_fallback_when_zero() -> None:
    collector = StateWriteAnchorFactCollector()
    facts = collector.collect(
        _target(
            _block(
                42,
                _insn(index=3, ea=0, src_l_value=0x1111),
                start_ea=0x180014800,
                succs=(43,),
            ),
        ),
        func_ea=0x180012cf0,
        maturity=_MATURITY_VALUES["MMAT_LOCOPT"],
        phase="pre_d810",
    )
    assert len(facts) == 1
    fact = facts[0]
    # block start 0x180014800 + insn_index 3 = 0x180014803
    assert fact.payload["instruction_ea"] == 0x180014803
    assert fact.source_ea == 0x180014803
