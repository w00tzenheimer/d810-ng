"""Tests for InductionVariableFactCollector."""
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
from d810.analyses.value_flow.induction_carrier import InductionVariableFactCollector
from d810.analyses.value_flow.induction_carrier import _MATURITY_VALUES


def _insn(
    *,
    index: int = 0,
    opcode_name: str = "add",
    dest_stkoff: int | None = 0x680,
    src_l_stkoff: int | None = 0x680,
    src_l_value: int | None = None,
    src_r_stkoff: int | None = None,
    src_r_value: int | None = 0x80,
    dstr: str = "add %var_178.8, #0x80.8, %var_178.8",
    meta: str | None = None,
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
        meta=meta,
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


def _cfg_stack(stkoff: int, *, size: int = 8) -> MopSnapshot:
    return MopSnapshot(t=5, size=size, stkoff=stkoff, kind=OperandKind.STACK)


def _cfg_number(value: int, *, size: int = 8) -> MopSnapshot:
    return MopSnapshot(t=2, size=size, value=value, kind=OperandKind.NUMBER)


def _cfg_address(*stkoffs: int, size: int = 8) -> MopSnapshot:
    return MopSnapshot(
        t=7,
        size=size,
        stack_refs=tuple(int(stkoff) for stkoff in stkoffs),
        kind=OperandKind.ADDRESS,
    )


def _meta_address_refs(*stkoffs: int) -> str:
    return json.dumps({"address_stack_refs": [int(stkoff) for stkoff in stkoffs]})


def _cfg_insn(
    *,
    index: int = 0,
    kind: InsnKind = InsnKind.ADD,
    d: MopSnapshot | None = None,
    l: MopSnapshot | None = None,
    r: MopSnapshot | None = None,
    display_text: str = "",
    value_op_kind: ValueOpKind | None = None,
) -> InsnSnapshot:
    return InsnSnapshot(
        opcode=index,
        ea=0x180020000 + index,
        operands=(),
        kind=kind,
        d=d,
        l=l,
        r=r,
        display_text=display_text,
        value_op_kind=value_op_kind,
    )


def _cfg_target(*instructions: InsnSnapshot) -> FlowGraph:
    return FlowGraph(
        blocks={
            10: CfgBlockSnapshot(
                serial=10,
                block_type=0,
                succs=(),
                preds=(),
                flags=0,
                start_ea=0x180020000,
                insn_snapshots=tuple(instructions),
            )
        },
        entry_serial=10,
        func_ea=0x401000,
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
    assert fact.payload["opcode"] == "add"
    assert fact.payload["source_side"] == "right"
    assert fact.evidence == ("add %var_178.8, #0x80.8, %var_178.8",)


def test_collects_sub_as_negative_step() -> None:
    collector = InductionVariableFactCollector()

    facts = collector.collect(
        _target(
            _insn(
                opcode_name="sub",
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


def test_collects_direct_add_from_flowgraph_instruction_snapshot() -> None:
    collector = InductionVariableFactCollector()

    facts = collector.collect(
        _cfg_target(
            _cfg_insn(
                kind=InsnKind.ADD,
                d=_cfg_stack(0x680),
                l=_cfg_stack(0x680),
                r=_cfg_number(0x80),
                display_text="add %var_178.8, #0x80.8, %var_178.8",
            )
        ),
        func_ea=0x401000,
        maturity=_MATURITY_VALUES["MMAT_LOCOPT"],
        phase="pre_d810",
    )

    assert len(facts) == 1
    assert facts[0].semantic_key == "induction:stkoff=0x680:size=8:step=128"
    assert facts[0].payload["opcode"] == "add"
    assert facts[0].evidence == ("add %var_178.8, #0x80.8, %var_178.8",)


def test_collects_sub_from_flowgraph_instruction_snapshot() -> None:
    collector = InductionVariableFactCollector()

    facts = collector.collect(
        _cfg_target(
            _cfg_insn(
                kind=InsnKind.SUB,
                d=_cfg_stack(0x680),
                l=_cfg_stack(0x680),
                r=_cfg_number(1),
                display_text="sub %var_178.8, #1.8, %var_178.8",
            )
        ),
        func_ea=0x401000,
        maturity=_MATURITY_VALUES["MMAT_CALLS"],
        phase="pre_d810",
    )

    assert len(facts) == 1
    assert facts[0].semantic_key == "induction:stkoff=0x680:size=8:step=-1"
    assert facts[0].payload["opcode"] == "sub"


def test_flowgraph_collection_uses_canonical_value_operation() -> None:
    collector = InductionVariableFactCollector()

    facts = collector.collect(
        _cfg_target(
            _cfg_insn(
                kind=InsnKind.UNKNOWN,
                value_op_kind=ValueOpKind.ADD,
                d=_cfg_stack(0x680),
                l=_cfg_stack(0x680),
                r=_cfg_number(0x80),
                display_text="add %var_178.8, #0x80.8, %var_178.8",
            )
        ),
        func_ea=0x401000,
        maturity=_MATURITY_VALUES["MMAT_LOCOPT"],
        phase="pre_d810",
    )

    assert len(facts) == 1
    assert facts[0].semantic_key == "induction:stkoff=0x680:size=8:step=128"
    assert facts[0].payload["opcode"] == "add"


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
        meta=_meta_address_refs(0x680),
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


def test_collects_memory_store_update_from_flowgraph_instruction_snapshots() -> None:
    collector = InductionVariableFactCollector()

    facts = collector.collect(
        _cfg_target(
            _cfg_insn(
                index=2,
                kind=InsnKind.ADD,
                d=_cfg_stack(0x688),
                l=_cfg_address(0x680),
                r=_cfg_number(1),
                display_text="add    [ds.2:%var_178.8].8, #1.8, %var_170.8",
            ),
            _cfg_insn(
                index=5,
                kind=InsnKind.STORE,
                d=_cfg_stack(0x680),
                l=_cfg_stack(0x688),
                r=None,
                display_text="stx    %var_170.8, ds.2, %var_178.8",
            ),
        ),
        func_ea=0x401000,
        maturity=2,
        phase="pre_d810",
    )

    assert len(facts) == 1
    fact = facts[0]
    assert fact.semantic_key == "induction:memory_base_stkoff=0x680:size=8:step=1"
    assert fact.payload["define_opcode"] == "add"
    assert fact.payload["store_opcode"] == "store"


def test_memory_store_update_requires_structural_address_ref_not_dstr() -> None:
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

    assert facts == ()


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
        meta=_meta_address_refs(0x680),
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
        meta=_meta_address_refs(0x468, 0x18),
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
    assert fact.payload["source_token"] == "S1128"
    assert fact.payload["dest_token"] == "S1592"
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
        meta=_meta_address_refs(0x468, 0x18),
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
    assert fact.payload["source_token"] == "S1128"
    assert fact.payload["dest_token"] == "S1592"


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
        meta=_meta_address_refs(0x468, 0x18),
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
        meta=_meta_address_refs(0x18),
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
                opcode_name="sub",
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


# -- llr-3b41 S9: induction_carrier's OWN collector consumes canonical
# Instruction via a collector-local dual-currency iterator.  The FlowGraph
# (``_cfg_target``) and meta-less (``_target``/``_insn``) source currencies are
# already covered above; these tests pin the third source -- a diag row whose
# ``meta`` carries an operand tree -- which the prior suite left untested for
# this collector, plus the meta-less attrs-only zero gate.


def _meta_stack(stkoff: int, size: int = 8) -> dict:
    return {
        "type": "mop_S",
        "type_num": 5,
        "size": size,
        "dstr": "x",
        "stkoff": stkoff,
    }


def _meta_const(value: int, size: int = 8) -> dict:
    return {
        "type": "mop_n",
        "type_num": 2,
        "size": size,
        "dstr": f"#{value:#x}",
        "value": value,
    }


def _meta_self_update(
    *,
    opcode_name: str,
    step_const: int,
    stkoff: int = 0x680,
    index: int = 0,
    dstr: str,
) -> InstructionSnapshot:
    """A ``op %var, #const, %var`` self-update diag row carrying a parseable
    ``meta`` operand tree -- routed through the canonical lift
    (``diag_row_has_operand_tree``).  The flat ``dest_stkoff`` /
    ``src_l_stkoff`` / ``src_r_value`` are intentionally ``None`` so a passing
    assertion PROVES the operands were recovered from the operand tree, not the
    legacy flat fields."""
    insn = InstructionSnapshot(
        index=index,
        ea=0x180010000 + index,
        opcode=0,
        opcode_name=opcode_name,
        dest_type="S",
        dest_stkoff=None,
        dest_size=8,
        src_l_type="S",
        src_l_stkoff=None,
        src_l_value=None,
        src_r_type="c",
        src_r_stkoff=None,
        src_r_value=None,
        dstr=dstr,
    )
    insn.meta = json.dumps(
        {
            "l": _meta_stack(stkoff),
            "r": _meta_const(step_const),
            "d": _meta_stack(stkoff),
        }
    )
    return insn


def test_collects_direct_add_induction_from_operand_tree_diag_row() -> None:
    collector = InductionVariableFactCollector()

    facts = collector.collect(
        _target(
            _meta_self_update(
                opcode_name="m_add",
                step_const=0x80,
                dstr="add %var_178.8, #0x80.8, %var_178.8",
            )
        ),
        func_ea=0x401000,
        maturity=_MATURITY_VALUES["MMAT_LOCOPT"],
        phase="pre_d810",
    )

    assert len(facts) == 1
    fact = facts[0]
    # Operands recovered from the operand tree (flat fields were None).
    assert fact.semantic_key == "induction:stkoff=0x680:size=8:step=128"
    assert fact.payload["step"] == 0x80
    assert fact.payload["source_side"] == "right"
    assert fact.payload["opcode"] == "add"
    assert fact.payload["carrier_kind"] == "stack_self_update"


def test_collects_sub_induction_from_operand_tree_diag_row() -> None:
    collector = InductionVariableFactCollector()

    facts = collector.collect(
        _target(
            _meta_self_update(
                opcode_name="m_sub",
                step_const=1,
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
    assert facts[0].payload["opcode"] == "sub"


def test_meta_less_attrs_only_diag_row_yields_no_induction_fact() -> None:
    """A diag row whose ``meta`` carries only non-operand attrs (no l/r/d tree)
    stays on the byte-identical legacy flat path; with no induction-shaped flat
    operands it yields zero observations, matching the pre-S9 behaviour."""
    collector = InductionVariableFactCollector()
    insn = _insn(
        opcode_name="add",
        dest_stkoff=None,
        src_l_stkoff=None,
        src_r_value=None,
        dstr="add something unrelated",
        meta=json.dumps({"byte_index": 3}),
    )

    facts = collector.collect(
        _target(insn),
        func_ea=0x401000,
        maturity=2,
        phase="pre_d810",
    )

    assert facts == ()
