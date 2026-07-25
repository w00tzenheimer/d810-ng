"""Tests for StateWriteAnchorFactCollector."""

from __future__ import annotations

import json
from types import SimpleNamespace

from d810.ir.expressions import ValueOpKind
from d810.ir.flowgraph import (
    BlockSnapshot as CfgBlockSnapshot,
    FlowGraph,
    InsnKind,
    InsnSnapshot,
    MopSnapshot,
    OperandKind,
)
from d810.core.diag.snapshot import BlockSnapshot, InstructionSnapshot
from d810.analyses.value_flow.state_write_anchor import StateWriteAnchorFactCollector
from d810.analyses.value_flow.induction_carrier import _MATURITY_VALUES

from tests.system.runtime.preanalysis.facts._diag_meta_builder import flat_meta

_OPCODE_ALIASES = {
    "m_mov": "move",
}

_OPERAND_TYPE_ALIASES = {
    "mop_S": "S",
    "mop_n": "c",
    "mop_r": "r",
}


def _opcode_name(value: str) -> str:
    return _OPCODE_ALIASES.get(value, value)


def _operand_type(value: str | None) -> str | None:
    if value is None:
        return None
    return _OPERAND_TYPE_ALIASES.get(value, value)


def _insn(
    *,
    index: int,
    opcode_name: str = "m_mov",
    dest_type: str | None = "mop_S",
    dest_stkoff: int | None = 0x3C,
    dest_register: int | None = None,
    dest_size: int | None = 4,
    src_l_type: str | None = "mop_n",
    src_l_value: int | None = 0x5A21D9DB,
    src_l_stkoff: int | None = None,
    ea: int | None = None,
    dstr: str | None = None,
) -> InstructionSnapshot:
    resolved_ea = 0x180014100 + index if ea is None else ea
    resolved_dstr = dstr or "mov #0x5A21D9DB.4, %var_7BC.4"
    # llr-3b41 S11: collectors lift diag rows through the canonical operand-tree
    # projection (the meta-less flat path was deleted), so attach a serializer-
    # shaped ``meta`` operand tree built from the same flat fields.
    meta = flat_meta(
        opcode_name=opcode_name,
        ea=resolved_ea,
        dstr=resolved_dstr,
        dest_type=dest_type,
        dest_stkoff=dest_stkoff,
        dest_register=dest_register,
        dest_size=dest_size,
        src_l_type=src_l_type,
        src_l_stkoff=src_l_stkoff,
        src_l_value=src_l_value,
    )
    return InstructionSnapshot(
        index=index,
        ea=resolved_ea,
        opcode=0,
        # llr-3b41 S11: the canonical lift resolves ``operation`` from the RAW
        # serializer opcode spelling (``m_mov``), so the row carries it raw; the
        # collector re-derives the normalized ``move`` payload off the canonical
        # ``Instruction``.
        opcode_name=opcode_name,
        dest_type=_operand_type(dest_type),
        dest_stkoff=dest_stkoff,
        dest_size=dest_size,
        src_l_type=_operand_type(src_l_type),
        src_l_stkoff=src_l_stkoff,
        src_l_value=src_l_value,
        src_r_type=None,
        src_r_stkoff=None,
        src_r_value=None,
        dstr=resolved_dstr,
        meta=meta,
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


def _cfg_stack(stkoff: int, *, size: int = 4) -> MopSnapshot:
    return MopSnapshot(t=5, size=size, stkoff=stkoff, kind=OperandKind.STACK)


def _cfg_number(value: int, *, size: int = 4) -> MopSnapshot:
    return MopSnapshot(t=2, size=size, value=value, kind=OperandKind.NUMBER)


def _cfg_target(*instructions: InsnSnapshot) -> FlowGraph:
    return FlowGraph(
        blocks={
            100: CfgBlockSnapshot(
                serial=100,
                block_type=0,
                succs=(101,),
                preds=(99,),
                flags=0,
                start_ea=0x180014000,
                insn_snapshots=tuple(instructions),
            )
        },
        entry_serial=100,
        func_ea=0x180012CF0,
    )


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
        func_ea=0x180012CF0,
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
    assert fact.payload["opcode"] == "move"
    assert fact.semantic_key == fact.fact_id
    assert (
        fact.semantic_key
        == "state_write_anchor:blk=100:insn=0:ea=0x180014155:stkoff=0x3c"
    )
    assert fact.mop_signature == "state_write:mop_S:0x3c:4"


def test_collects_register_state_const_write() -> None:
    collector = StateWriteAnchorFactCollector()
    facts = collector.collect(
        _target(
            _block(
                100,
                _insn(
                    index=0,
                    dest_type="mop_r",
                    dest_stkoff=None,
                    dest_register=20,
                    src_l_value=0x19A7218A,
                    dstr="mov #0x19A7218A.4, ebx.4",
                ),
                succs=(),
            ),
        ),
        func_ea=0x180012CF0,
        maturity=_MATURITY_VALUES["MMAT_LOCOPT"],
        phase="pre_d810",
    )

    assert len(facts) == 1
    assert facts[0].payload["state_var_stkoff"] is None
    assert facts[0].payload["state_var_reg"] == 20


def test_collects_state_const_write_from_canonical_move_operation() -> None:
    collector = StateWriteAnchorFactCollector()

    facts = collector.collect(
        _cfg_target(
            InsnSnapshot(
                opcode=0,
                ea=0x180014155,
                operands=(),
                kind=InsnKind.UNKNOWN,
                d=_cfg_stack(0x3C),
                l=_cfg_number(0x5A21D9DB),
                r=None,
                display_text="mov #0x5A21D9DB.4, %var_7BC.4",
                value_op_kind=ValueOpKind.MOVE,
            )
        ),
        func_ea=0x180012CF0,
        maturity=_MATURITY_VALUES["MMAT_LOCOPT"],
        phase="pre_d810",
    )

    assert len(facts) == 1
    fact = facts[0]
    assert fact.kind == "StateWriteAnchorFact"
    assert fact.source_block == 100
    assert fact.source_ea == 0x180014155
    assert fact.payload["state_const"] == 0x5A21D9DB
    assert fact.payload["state_var_stkoff"] == 0x3C
    assert fact.payload["opcode"] == "move"
    assert fact.evidence == ("mov #0x5A21D9DB.4, %var_7BC.4",)


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
        func_ea=0x180012CF0,
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
        func_ea=0x180012CF0,
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
                    ea=0x180012ABC,
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
                    ea=0x180015ABC,
                    dstr="mov #0x149AED27.4, %var_7BC.4",
                ),
                succs=(162,),
            ),
        ),
        func_ea=0x180012CF0,
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
        func_ea=0x180012CF0,
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
        func_ea=0x180012CF0,
        maturity=_MATURITY_VALUES["MMAT_LOCOPT"],
        phase="pre_d810",
    )
    assert len(facts) == 1
    fact = facts[0]
    # Synthetic-EA fallback (ea==0) = block start + the instruction's position in
    # the lifted canonical stream.  Under E opt-4 (4a) the diag source is lifted
    # via DiagSourceLifter -> from_block, so the index is the sequence position
    # (0 for this lone insn), matching the live path -- NOT the diag row's
    # recorded ``.index`` (3).  block start 0x180014800 + 0 = 0x180014800.
    assert fact.payload["instruction_ea"] == 0x180014800
    assert fact.source_ea == 0x180014800


# ---------------------------------------------------------------------------
# llr-3b41 S8: dual-currency port coverage.  The collector now consumes the
# canonical ``Instruction`` for meta-rich sources (a portable ``FlowGraph``
# block, or a diag row carrying a parseable ``meta`` operand tree) while
# meta-less rows (every test above) stay on the byte-identical legacy flat
# path.  These tests pin the canonical FlowGraph source AND the previously
# uncovered operand-tree diag-row source -- the two meta-rich currencies the
# port routes through ``project_diag_instruction`` /
# ``InstructionProjection.from_block``.
# ---------------------------------------------------------------------------


def test_collects_state_const_write_from_canonical_flowgraph_full_payload() -> None:
    """A portable ``FlowGraph`` block routes through the canonical projection;
    ``dest_stkoff`` / ``dest_size`` are read off ``Instruction.result`` and
    ``src_l_value`` off the first canonical input, so the anchor fact matches
    the legacy meta-less result byte-for-byte (full payload pinned)."""
    collector = StateWriteAnchorFactCollector()
    facts = collector.collect(
        _cfg_target(
            InsnSnapshot(
                opcode=0,
                ea=0x180014155,
                operands=(),
                kind=InsnKind.UNKNOWN,
                d=_cfg_stack(0x3C),
                l=_cfg_number(0x5A21D9DB),
                r=None,
                display_text="mov #0x5A21D9DB.4, %var_7BC.4",
                value_op_kind=ValueOpKind.MOVE,
            )
        ),
        func_ea=0x180012CF0,
        maturity=_MATURITY_VALUES["MMAT_LOCOPT"],
        phase="pre_d810",
    )
    assert len(facts) == 1
    fact = facts[0]
    assert fact.payload["state_const"] == 0x5A21D9DB
    assert fact.payload["state_var_stkoff"] == 0x3C
    assert fact.payload["dest_size"] == 4
    assert fact.payload["dest_var_signature"] == "%var_7BC.4"
    assert fact.payload["successor_blocks"] == [101]
    assert fact.payload["opcode"] == "move"
    assert fact.mop_signature == "state_write:mop_S:0x3c:4"
    assert (
        fact.semantic_key
        == "state_write_anchor:blk=100:insn=0:ea=0x180014155:stkoff=0x3c"
    )


def _meta_stack(stkoff: int, size: int = 4) -> dict:
    return {"type": "mop_S", "type_num": 5, "size": size, "dstr": "x", "stkoff": stkoff}


def _meta_const(value: int, size: int = 4) -> dict:
    return {
        "type": "mop_n",
        "type_num": 2,
        "size": size,
        "dstr": f"#{value:#x}",
        "value": value,
    }


def _meta_mov(
    *, index: int, state_const: int, ea: int, stkoff: int = 0x3C
) -> InstructionSnapshot:
    """A ``mov #const, %var`` diag row carrying a parseable ``meta`` operand
    tree -- routed through the canonical lift (``diag_row_has_operand_tree``).
    The flat ``dest_stkoff`` / ``src_l_value`` are intentionally ``None`` so a
    passing test PROVES the operands were recovered from the operand tree."""
    insn = InstructionSnapshot(
        index=index,
        ea=ea,
        opcode=0,
        opcode_name="m_mov",
        dest_type="S",
        dest_stkoff=None,
        dest_size=4,
        src_l_type="c",
        src_l_stkoff=None,
        src_l_value=None,
        src_r_type=None,
        src_r_stkoff=None,
        src_r_value=None,
        dstr=f"mov #0x{state_const:08X}.4, %var_7BC.4",
    )
    insn.meta = json.dumps({"l": _meta_const(state_const), "d": _meta_stack(stkoff)})
    return insn


def test_collects_state_const_write_from_meta_rich_diag_row() -> None:
    """A diag row whose ``meta`` carries an operand tree is lifted through the
    SAME canonical projection; ``dest_stkoff`` / ``dest_size`` / ``src_l_value``
    are recovered from the canonical record (the flat fields are ``None``),
    yielding the same anchor fact as the FlowGraph / meta-less shapes."""
    collector = StateWriteAnchorFactCollector()
    facts = collector.collect(
        _target(
            _block(
                100,
                _meta_mov(index=0, state_const=0x5A21D9DB, ea=0x180014155),
                succs=(101,),
            ),
        ),
        func_ea=0x180012CF0,
        maturity=_MATURITY_VALUES["MMAT_LOCOPT"],
        phase="pre_d810",
    )
    assert len(facts) == 1
    fact = facts[0]
    assert fact.kind == "StateWriteAnchorFact"
    assert fact.source_block == 100
    assert fact.source_ea == 0x180014155
    assert fact.payload["state_const"] == 0x5A21D9DB
    assert fact.payload["state_var_stkoff"] == 0x3C
    assert fact.payload["dest_size"] == 4
    assert fact.payload["successor_blocks"] == [101]
    assert fact.payload["opcode"] == "move"
    assert fact.mop_signature == "state_write:mop_S:0x3c:4"
