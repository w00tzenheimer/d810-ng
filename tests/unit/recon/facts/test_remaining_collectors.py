"""Tests for the deferred maturity fact collectors."""
from __future__ import annotations

from types import SimpleNamespace

from d810.core.diag.snapshot import BlockSnapshot, InstructionSnapshot
from d810.recon.facts.collectors import (
    ByteEmitCorridorFactCollector,
    CallAnchorFactCollector,
    ReturnFrontierFactCollector,
    ZeroBlobFactCollector,
)
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


def _block(
    serial: int,
    *instructions: InstructionSnapshot,
    succs: tuple[int, ...] = (),
    preds: tuple[int, ...] = (),
    type_name: str = "BLT_1WAY",
    start_ea: int | None = None,
) -> BlockSnapshot:
    return BlockSnapshot(
        serial=serial,
        block_type=1 if len(succs) <= 1 else 2,
        type_name=type_name,
        start_ea=0x180014000 + serial if start_ea is None else start_ea,
        nsucc=len(succs),
        npred=len(preds),
        succs=list(succs),
        preds=list(preds),
        instructions=list(instructions),
    )


def _target(*blocks: BlockSnapshot) -> SimpleNamespace:
    return SimpleNamespace(blocks={block.serial: block for block in blocks})


def test_byte_emit_corridor_groups_terminal_byte_family() -> None:
    collector = ByteEmitCorridorFactCollector()

    facts = collector.collect(
        _target(
            _block(
                101,
                _insn(index=0, opcode_name="m_jcnd", dstr="jnz %var_tail.8, #0.8, @241"),
                succs=(102, 241),
                preds=(99,),
            ),
            _block(
                102,
                _insn(index=0, opcode_name="m_jcnd", dstr="jnz %var_tail.8, #1.8, @241"),
                _insn(index=1, opcode_name="m_stx", dstr="stx v52[1], ds.1, %var_dst.8"),
                succs=(103, 241),
                preds=(101,),
            ),
            _block(
                103,
                _insn(index=0, opcode_name="m_jcnd", dstr="jnz %var_tail.8, #2.8, @241"),
                _insn(index=1, opcode_name="m_stx", dstr="stx v52[2], ds.1, %var_dst.8"),
                succs=(104, 241),
                preds=(102,),
            ),
        ),
        func_ea=0x401000,
        maturity=_MATURITY_VALUES["MMAT_LOCOPT"],
        phase="pre_d810",
    )

    terminal = [
        fact
        for fact in facts
        if fact.payload["family_id"] == "terminal_tail"
    ]
    assert len(terminal) == 1
    assert terminal[0].kind == "ByteEmitCorridorFact"
    assert terminal[0].payload["unique_byte_indexes"] == [0, 1, 2]
    assert terminal[0].payload["source_blocks"] == [101, 102, 103]
    assert "byte_emit_corridor:family=terminal_tail" in terminal[0].semantic_key


def test_call_anchor_records_call_context() -> None:
    collector = CallAnchorFactCollector()

    facts = collector.collect(
        _target(
            _block(
                130,
                _insn(
                    index=0,
                    opcode_name="m_call",
                    dstr="call $0x180000000<fast:_QWORD #0x11.8,_QWORD #0x4A.8>",
                    ea=0x180014848,
                ),
                succs=(143,),
                preds=(129,),
            )
        ),
        func_ea=0x401000,
        maturity=_MATURITY_VALUES["MMAT_CALLS"],
        phase="pre_d810",
    )

    assert len(facts) == 1
    fact = facts[0]
    assert fact.kind == "CallAnchorFact"
    assert fact.payload["call_kind"] == "direct_call"
    assert fact.payload["call_target"] == "$0x180000000"
    assert fact.payload["successor_blocks"] == [143]
    assert fact.payload["predecessor_blocks"] == [129]
    assert fact.payload["copy_state"] == "preserved_or_original"
    assert "anchor=blk[130]" in fact.semantic_key
    assert "ea=0x180014848" in fact.semantic_key


def test_zero_blob_collector_separates_zero_store_and_blob_copy() -> None:
    collector = ZeroBlobFactCollector()

    facts = collector.collect(
        _target(
            _block(
                40,
                _insn(
                    index=0,
                    opcode_name="m_stx",
                    dstr="stx #0x0.8, ds.2, %var_dst.8",
                ),
                _insn(
                    index=1,
                    opcode_name="m_call",
                    dstr="call sub_1800164E0<fast:%var_dst.8,unk_180018E95,#0x10.8>",
                    src_r_value=0x10,
                ),
                succs=(41,),
            )
        ),
        func_ea=0x401000,
        maturity=_MATURITY_VALUES["MMAT_GLBOPT1"],
        phase="pre_d810",
    )

    kinds = {fact.payload["init_kind"] for fact in facts}
    assert kinds == {"zero_store", "blob_copy_call"}
    zero = next(fact for fact in facts if fact.payload["init_kind"] == "zero_store")
    blob = next(fact for fact in facts if fact.payload["init_kind"] == "blob_copy_call")
    assert zero.payload["destination"] == "%var_dst.8"
    assert blob.payload["size"] == 0x10
    assert "ea=0x" in zero.semantic_key
    assert "ea=0x" in blob.semantic_key


def test_return_frontier_records_nearby_return_carrier_writers() -> None:
    collector = ReturnFrontierFactCollector()

    facts = collector.collect(
        _target(
            _block(
                50,
                _insn(
                    index=0,
                    opcode_name="m_mov",
                    dest_type="mop_S",
                    dest_stkoff=0x7F0,
                    dest_size=8,
                    src_l_type="mop_S",
                    src_l_stkoff=0x680,
                    dstr="mov %var_178.8, %var_8.8",
                ),
                succs=(57,),
                preds=(49,),
            ),
            _block(
                57,
                _insn(
                    index=0,
                    opcode_name="m_mov",
                    dest_type="mop_r",
                    src_l_type="mop_S",
                    src_l_stkoff=0x7F0,
                    dstr="mov %var_8.8, rax.8",
                ),
                _insn(index=1, opcode_name="m_ret", dstr="ret"),
                succs=(),
                preds=(50,),
                type_name="BLT_STOP",
            ),
        ),
        func_ea=0x401000,
        maturity=_MATURITY_VALUES["MMAT_CALLS"],
        phase="pre_d810",
    )

    assert len(facts) == 1
    fact = facts[0]
    assert fact.kind == "ReturnFrontierFact"
    assert fact.payload["return_block"] == 57
    assert fact.payload["frontier_blocks"] == [50]
    assert fact.payload["writer_blocks"] == [50]
    assert len(fact.payload["carrier_fact_ids"]) == 1
    assert "writers=50" in fact.semantic_key
    assert "return_carrier:slot=" in fact.semantic_key
