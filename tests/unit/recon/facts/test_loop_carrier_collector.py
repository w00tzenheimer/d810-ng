"""Tests for LoopPredicateValueFactCollector."""
from __future__ import annotations

from types import SimpleNamespace

from d810.core.diag.snapshot import BlockSnapshot, InstructionSnapshot
from d810.ir.flowgraph import (
    BlockSnapshot as CfgBlockSnapshot,
    FlowGraph,
    InsnKind,
    InsnSnapshot,
    MopSnapshot,
    OperandKind,
)
from d810.analyses.value_flow.loop_carrier import LoopPredicateValueFactCollector
from d810.analyses.value_flow.induction_carrier import _MATURITY_VALUES
from d810.analyses.value_flow.model import FactObservation, ValidatedFactView


def _insn(
    *,
    index: int,
    ea: int,
    opcode_name: str,
    dstr: str,
    dest_stkoff: int | None = None,
    src_l_stkoff: int | None = None,
    src_r_stkoff: int | None = None,
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
        src_l_type="mop_S" if src_l_stkoff is not None else None,
        src_l_stkoff=src_l_stkoff,
        src_l_value=None,
        src_r_type="mop_S" if src_r_stkoff is not None else None,
        src_r_stkoff=src_r_stkoff,
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
    return LoopPredicateValueFactCollector().collect(
        target,
        func_ea=0x180012df0,
        maturity=_MATURITY_VALUES["MMAT_GLBOPT1"],
        phase="post_d810",
    )


def _cfg_stack(stkoff: int, *, size: int = 8) -> MopSnapshot:
    return MopSnapshot(t=5, size=size, stkoff=stkoff, kind=OperandKind.STACK)


def _cfg_nested_refs(*stkoffs: int, size: int = 8) -> MopSnapshot:
    return MopSnapshot(
        t=4,
        size=size,
        kind=OperandKind.SUBINSN,
        sub_kind=InsnKind.UNKNOWN,
        stack_refs=tuple(stkoffs),
    )


def _cfg_insn(
    *,
    index: int,
    ea: int,
    kind: InsnKind,
    d: MopSnapshot | None = None,
    l: MopSnapshot | None = None,
    r: MopSnapshot | None = None,
    display_text: str = "",
) -> InsnSnapshot:
    return InsnSnapshot(
        opcode=index,
        ea=ea,
        operands=(),
        kind=kind,
        d=d,
        l=l,
        r=r,
        display_text=display_text,
    )


def _cfg_block(
    serial: int,
    *insns: InsnSnapshot,
    succs: tuple[int, ...] = (),
    preds: tuple[int, ...] = (),
) -> CfgBlockSnapshot:
    return CfgBlockSnapshot(
        serial=serial,
        block_type=0,
        succs=succs,
        preds=preds,
        flags=0,
        start_ea=0x180020000 + serial,
        insn_snapshots=tuple(insns),
    )


def _cfg_target(*blocks: CfgBlockSnapshot) -> FlowGraph:
    return FlowGraph(
        blocks={block.serial: block for block in blocks},
        entry_serial=blocks[0].serial,
        func_ea=0x180012DF0,
    )


def _sub7ffd_loop_shape(*extra_blocks: CfgBlockSnapshot) -> FlowGraph:
    """Minimal graph for the v22 / %var_3A8 carrier issue.

    Predicate block 81 is in SCC {81,82}.  The carrier writers live at
    blocks 151 and 186, outside that SCC.  Predicate inputs 528/508/4F8
    are all derived from %var_3A8.
    """
    return _cfg_target(
        _cfg_block(
            52,
            _cfg_insn(
                index=0,
                ea=0x180014052,
                kind=InsnKind.SUB,
                d=_cfg_stack(0x528),
                l=_cfg_stack(0x450),
                r=_cfg_stack(0x520),
                display_text=(
                    "sub ((2*xdu(%var_3A8.1 & 0x7F)) + %var_518.8), "
                    "%var_520.8, %var_528.8"
                ),
            ),
            succs=(81,),
        ),
        _cfg_block(
            88,
            _cfg_insn(
                index=0,
                ea=0x180014088,
                kind=InsnKind.MOV,
                d=_cfg_stack(0x508),
                l=_cfg_nested_refs(0x450),
                display_text="bnot (%var_3A8.8 | 0x7F), %var_508.8",
            ),
            succs=(123,),
        ),
        _cfg_block(
            187,
            _cfg_insn(
                index=0,
                ea=0x180014187,
                kind=InsnKind.MOV,
                d=_cfg_stack(0x4F8),
                l=_cfg_nested_refs(0x450),
                display_text="mul #7, xdu(bnot(%var_3A8.1) & 0x7F), %var_4F8.8",
            ),
            succs=(88,),
        ),
        _cfg_block(
            151,
            _cfg_insn(
                index=0,
                ea=0x180014151,
                kind=InsnKind.MOV,
                d=_cfg_stack(0x450),
                l=_cfg_stack(0x1A0),
                display_text="mov %var_1A0.8, %var_3A8.8",
            ),
            succs=(187,),
        ),
        _cfg_block(
            186,
            _cfg_insn(
                index=0,
                ea=0x180014186,
                kind=InsnKind.MOV,
                d=_cfg_stack(0x450),
                l=_cfg_stack(0x4E8),
                display_text="mov %var_4E8.8, %var_3A8.8",
            ),
            succs=(88,),
        ),
        _cfg_block(
            81,
            _cfg_insn(
                index=1,
                ea=0x180014081,
                kind=InsnKind.COND_JUMP,
                l=_cfg_nested_refs(0x528, 0x508),
                r=_cfg_stack(0x4F8),
                display_text="jnz (%var_528.8 + %var_508.8), %var_4F8.8, @83",
            ),
            succs=(82, 83),
        ),
        _cfg_block(82, succs=(81,)),
        _cfg_block(83, succs=()),
        _cfg_block(123, succs=(52,)),
        *extra_blocks,
    )


def test_detects_carrier_from_canonical_flowgraph_with_temp_predicate() -> None:
    facts = _collect(
        _cfg_target(
            _cfg_block(
                52,
                _cfg_insn(
                    index=0,
                    ea=0x180024052,
                    kind=InsnKind.ADD,
                    d=_cfg_stack(0x528),
                    l=_cfg_stack(0x450),
                    r=_cfg_stack(0x520),
                    display_text="add %var_450.8, %var_520.8, %var_528.8",
                ),
                succs=(81,),
            ),
            _cfg_block(
                88,
                _cfg_insn(
                    index=0,
                    ea=0x180024088,
                    kind=InsnKind.MOV,
                    d=_cfg_stack(0x508),
                    l=_cfg_nested_refs(0x450),
                    display_text="mov opaque(%var_450.8), %var_508.8",
                ),
                succs=(81,),
            ),
            _cfg_block(
                151,
                _cfg_insn(
                    index=0,
                    ea=0x180024151,
                    kind=InsnKind.MOV,
                    d=_cfg_stack(0x450),
                    l=_cfg_stack(0x1A0),
                    display_text="mov %var_1A0.8, %var_450.8",
                ),
                succs=(52,),
            ),
            _cfg_block(
                186,
                _cfg_insn(
                    index=0,
                    ea=0x180024186,
                    kind=InsnKind.MOV,
                    d=_cfg_stack(0x450),
                    l=_cfg_stack(0x4E8),
                    display_text="mov %var_4E8.8, %var_450.8",
                ),
                succs=(88,),
            ),
            _cfg_block(
                81,
                _cfg_insn(
                    index=0,
                    ea=0x180024081,
                    kind=InsnKind.COND_JUMP,
                    l=_cfg_nested_refs(0x528, 0x508),
                    display_text="jnz opaque(%var_528.8, %var_508.8), @83",
                ),
                succs=(82, 83),
            ),
            _cfg_block(82, succs=(81,)),
            _cfg_block(83, succs=()),
        )
    )

    assert len(facts) == 1
    fact = facts[0]
    assert fact.payload["predicate_storage_keys"] == ["S1320", "S1288"]
    assert fact.payload["carrier_var_token"] == "S1104"
    assert fact.payload["carrier_writer_blocks_outside_loop"] == [151, 186]
    assert fact.payload["carrier_reader_blocks"] == [52, 88]


def test_detects_carrier_writer_outside_loop_scc() -> None:
    facts = _collect(_sub7ffd_loop_shape())

    assert len(facts) == 1
    fact = facts[0]
    assert fact.kind == "LoopCarrierFact"
    assert fact.payload["classification"] == "LOOP_CARRIER_WRITER_OUTSIDE_SCC"
    assert fact.payload["predicate_block_serial"] == 81
    assert fact.payload["predicate_var_tokens"] == ["S1272", "S1320", "S1288"]
    assert fact.payload["predicate_storage_keys"] == ["S1272", "S1320", "S1288"]
    assert fact.payload["carrier_var_token"] == "S1104"
    assert fact.payload["carrier_storage_identity"] == {
        "kind": "stack",
        "prefix": "S",
        "offset": 0x450,
        "key": "S1104",
    }
    assert fact.payload["carrier_stkoff"] == 0x450
    assert fact.payload["carrier_writer_blocks"] == [151, 186]
    assert fact.payload["carrier_writer_blocks_in_loop"] == []
    assert fact.payload["carrier_writer_blocks_outside_loop"] == [151, 186]
    assert fact.payload["carrier_reader_blocks"] == [52, 88, 187]
    assert fact.payload["loop_scc_blocks"] == [81, 82]


def test_classifies_carrier_writer_inside_loop_scc() -> None:
    facts = _collect(
        _sub7ffd_loop_shape(
            _cfg_block(
                82,
                _cfg_insn(
                    index=0,
                    ea=0x180014182,
                    kind=InsnKind.MOV,
                    d=_cfg_stack(0x450),
                    l=_cfg_stack(0x1A0),
                    display_text="mov %var_1A0.8, %var_3A8.8",
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
        _cfg_target(
            _cfg_block(
                52,
                _cfg_insn(
                    index=0,
                    ea=0x180014052,
                    kind=InsnKind.SUB,
                    d=_cfg_stack(0x528),
                    l=_cfg_stack(0x450),
                    r=_cfg_stack(0x520),
                    display_text="sub %var_3A8.8, %var_520.8, %var_528.8",
                ),
                succs=(81,),
            ),
            _cfg_block(
                88,
                _cfg_insn(
                    index=0,
                    ea=0x180014088,
                    kind=InsnKind.MOV,
                    d=_cfg_stack(0x508),
                    l=_cfg_nested_refs(0x450),
                    display_text="bnot %var_3A8.8, %var_508.8",
                ),
                succs=(81,),
            ),
            _cfg_block(
                151,
                _cfg_insn(
                    index=0,
                    ea=0x180014151,
                    kind=InsnKind.MOV,
                    d=_cfg_stack(0x450),
                    l=_cfg_stack(0x1A0),
                    display_text="mov %var_1A0.8, %var_3A8.8",
                ),
                succs=(81,),
            ),
            _cfg_block(
                81,
                _cfg_insn(
                    index=1,
                    ea=0x180014081,
                    kind=InsnKind.COND_JUMP,
                    l=_cfg_nested_refs(0x528, 0x508),
                    display_text="jnz (%var_528.8 + %var_508.8), %var_4F8.8, @83",
                ),
                succs=(83,),
            ),
            _cfg_block(83, succs=()),
        )
    )

    assert facts == ()


def test_legacy_opcode_only_predicate_is_not_behavioral_proof() -> None:
    facts = _collect(_target(
        _block(
            52,
            _insn(
                index=0,
                ea=0x180014052,
                opcode_name="m_sub",
                dest_stkoff=0x528,
                src_l_stkoff=0x450,
                src_r_stkoff=0x520,
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
                dest_stkoff=0x508,
                src_l_stkoff=0x450,
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
                src_l_stkoff=0x1A0,
                dstr="mov %var_1A0.8, %var_3A8.8",
            ),
            succs=(52,),
        ),
        _block(
            186,
            _insn(
                index=0,
                ea=0x180014186,
                opcode_name="m_mov",
                dest_stkoff=0x450,
                src_l_stkoff=0x4E8,
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
                src_l_stkoff=0x528,
                src_r_stkoff=0x508,
                dstr="jnz (%var_528.8 + %var_508.8), %var_4F8.8, @83",
            ),
            succs=(82, 83),
        ),
        _block(82, succs=(81,)),
        _block(83, succs=()),
    ))

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
    assert found[0].payload["carrier_var_token"] == "S1104"
    assert view.loop_carriers_for_predicate_block(999) == ()
