"""Tests for TerminalByteEmitterFactCollector."""

from __future__ import annotations

import json
from collections.abc import Mapping
from pathlib import Path
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
from d810.ir.semantics import ControlTransferKind, PredicateKind
from d810.analyses.value_flow.terminal_byte_emitter import (
    TerminalByteEmitterFactCollector,
)
from d810.analyses.value_flow.induction_carrier import _MATURITY_VALUES

_OPCODE_ALIASES = {
    "m_stx": "store",
    "m_mov": "move",
    "m_add": "add",
    "m_sub": "sub",
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


def _meta(**fields: object) -> str:
    return json.dumps(fields)


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
    meta: str | Mapping[str, object] | None = None,
    predicate_kind: PredicateKind | None = None,
    control_target: int | None = None,
    control_transfer: ControlTransferKind | None = None,
    branch_opcode: str | None = None,
) -> InstructionSnapshot:
    if isinstance(meta, Mapping):
        meta = json.dumps(dict(meta))
    insn = InstructionSnapshot(
        index=index,
        ea=0x180010000 + index if ea is None else ea,
        opcode=0,
        opcode_name=_opcode_name(opcode_name),
        dest_type=_operand_type(dest_type),
        dest_stkoff=dest_stkoff,
        dest_size=dest_size,
        src_l_type=_operand_type(src_l_type),
        src_l_stkoff=src_l_stkoff,
        src_l_value=src_l_value,
        src_r_type=_operand_type(src_r_type),
        src_r_stkoff=src_r_stkoff,
        src_r_value=src_r_value,
        dstr=dstr,
        meta=meta,
    )
    if predicate_kind is not None:
        insn.predicate_kind = predicate_kind
    if control_target is not None:
        insn.control_target = int(control_target)
    if control_transfer is not None:
        insn.control_transfer = control_transfer
    if branch_opcode is not None:
        payload = json.loads(meta) if isinstance(meta, str) and meta else {}
        payload.setdefault("branch_opcode", branch_opcode)
        insn.meta = json.dumps(payload)
    return insn


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


def test_collector_does_not_hardcode_hodur_destination_temp_name() -> None:
    source = Path("src/d810/analyses/value_flow/terminal_byte_emitter.py").read_text(
        encoding="utf-8"
    )

    assert "%var_188" not in source


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
                src_l_type="mop_S",
                src_l_stkoff=0x7BC,
                src_r_type="mop_n",
                src_r_value=0,
                predicate_kind=PredicateKind.NE,
                control_transfer=ControlTransferKind.CONDITIONAL_BRANCH,
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


def test_rendered_byte_store_text_does_not_authorize_byte_index() -> None:
    collector = TerminalByteEmitterFactCollector()

    facts = collector.collect(
        _target(
            _insn(
                index=0,
                opcode_name="m_stx",
                dest_type="mop_S",
                dest_stkoff=0x700,
                dstr=(
                    "stx ([ds.2:%var_dst.8].8 | "
                    "(xdu.8([ds.2:(%var_src.8+#3.8)].1) <<l #8.1)), "
                    "ds.2, %var_dst.8"
                ),
            ),
            succs=(102,),
        ),
        func_ea=0x401000,
        maturity=_MATURITY_VALUES["MMAT_GLBOPT1"],
        phase="pre_d810",
    )

    assert facts == ()


# --- llr-3b41 S10-pair: terminal_byte_emitter canonical-lift coverage ---------
#
# The pre-port tests above all use meta-less ``InstructionSnapshot`` rows (a
# ``meta`` carrying only attrs such as ``byte_index`` / ``address_const_values``
# -- no ``l`` / ``r`` / ``d`` operand tree), so ``diag_row_has_operand_tree`` is
# False and they stay on the byte-identical legacy flat path.  The S10-pair port
# routes ``_iter_block_views`` through a collector-local dual-currency iterator
# (canonical ``Instruction`` for meta-rich FlowGraph blocks and operand-tree diag
# rows; legacy flat path for meta-less rows).  These tests pin the two meta-rich
# sources.


def _cfg_stack(stkoff: int, *, size: int = 8) -> MopSnapshot:
    return MopSnapshot(kind=OperandKind.STACK, stkoff=stkoff, size=size)


def _cfg_const(value: int, *, size: int = 8) -> MopSnapshot:
    return MopSnapshot(kind=OperandKind.NUMBER, value=value, size=size)


def _cfg_insn(
    *,
    index: int,
    kind: InsnKind,
    ea: int | None = None,
    l: MopSnapshot | None = None,
    r: MopSnapshot | None = None,
    d: MopSnapshot | None = None,
    branch_predicate: PredicateKind | None = None,
    display_text: str = "",
) -> InsnSnapshot:
    return InsnSnapshot(
        opcode=-1,
        raw_opcode=0x1000 + index,
        ea=0x180014000 + index if ea is None else ea,
        operands=tuple(op for op in (l, r, d) if op is not None),
        operand_slots=tuple(
            (slot, op) for slot, op in (("l", l), ("r", r), ("d", d)) if op is not None
        ),
        display_text=display_text,
        l=l,
        r=r,
        d=d,
        kind=kind,
        branch_predicate=branch_predicate,
    )


def _cfg_block(
    serial: int,
    *instructions: InsnSnapshot,
    succs: tuple[int, ...] = (),
    preds: tuple[int, ...] = (),
    start_ea: int | None = None,
) -> CfgBlockSnapshot:
    return CfgBlockSnapshot(
        serial=serial,
        block_type=1 if len(succs) <= 1 else 2,
        succs=succs,
        preds=preds,
        flags=0,
        start_ea=0x180014000 + serial if start_ea is None else start_ea,
        insn_snapshots=tuple(instructions),
    )


def _cfg_target(*blocks: CfgBlockSnapshot) -> FlowGraph:
    return FlowGraph(
        blocks={block.serial: block for block in blocks},
        entry_serial=blocks[0].serial if blocks else 0,
        func_ea=0x401000,
    )


def _meta_stack(stkoff: int, size: int = 8) -> dict:
    return {"type": "mop_S", "type_num": 5, "size": size, "dstr": "x", "stkoff": stkoff}


def _meta_const(value: int, size: int = 8) -> dict:
    return {
        "type": "mop_n",
        "type_num": 2,
        "size": size,
        "dstr": f"#{value:#x}",
        "value": value,
    }


def test_collects_byte_emit_from_flowgraph_guard_and_store() -> None:
    # A meta-rich FlowGraph block: a conditional guard branch (``jcnd %var_54 ==
    # #2``) followed by a memory STORE.  The canonical projection recovers
    # ``control_transfer=CONDITIONAL_BRANCH`` + ``predicate_kind=EQ`` off the
    # guard's ``InsnKind.EQUALITY_JUMP`` and the STORE's stack dest/source off
    # the operand tree, so the byte index is inferred from the guard and the
    # byte-emit fact is anchored on recovered canonical semantics rather than
    # opcode-table flat fields.
    collector = TerminalByteEmitterFactCollector()

    facts = collector.collect(
        _cfg_target(
            _cfg_block(
                101,
                _cfg_insn(
                    index=0,
                    kind=InsnKind.EQUALITY_JUMP,
                    l=_cfg_stack(0x54),
                    r=_cfg_const(2),
                    branch_predicate=PredicateKind.EQ,
                    display_text="jcnd %var_54.8 == #2.8, @241",
                ),
                _cfg_insn(
                    index=1,
                    kind=InsnKind.STORE,
                    l=_cfg_stack(0x520),
                    d=_cfg_stack(0x700),
                    display_text="stx v52[2], ds.1, %var_dst.8",
                ),
                succs=(102, 241),
                preds=(99,),
            )
        ),
        func_ea=0x401000,
        maturity=_MATURITY_VALUES["MMAT_LOCOPT"],
        phase="pre_d810",
    )

    assert len(facts) == 1
    fact = facts[0]
    assert fact.kind == "TerminalByteEmitterFact"
    assert "byte_index=2" in fact.semantic_key
    assert "dest=S1792" in fact.semantic_key
    assert "counter=S84" in fact.semantic_key
    assert fact.payload["byte_index"] == 2
    assert fact.payload["counter_carrier"] == "S84"
    assert fact.payload["destination_buffer_expression"] == "S1792"
    assert fact.payload["emitter_role"] == "memory_store"
    # The FlowGraph snapshot carries no explicit jump-target operand, so the
    # guard's control_target is unresolved and there is no return edge.
    assert fact.payload["return_edge"] is None


def test_operand_tree_diag_row_yields_no_byte_emit_fact() -> None:
    # A diag row carrying a parseable ``meta`` operand tree routes through the
    # canonical projection.  ``project_diag_instruction`` rebuilds the
    # instruction from the ``l`` / ``r`` / ``d`` operand tree + opcode_name only:
    # it does NOT carry the flat ``control_transfer`` / ``predicate_kind`` guard
    # fields nor the non-operand ``byte_index`` meta key, and ``m_jcnd`` /
    # ``m_stx`` byte-step semantics are not recovered from a meta operand tree
    # yet.  So a meta-rich diag store classifies to "no byte index" -> zero
    # observations (the same result the meta-less path gives for a row lacking an
    # explicit byte index), pinning the canonical-lift route honestly.
    collector = TerminalByteEmitterFactCollector()

    facts = collector.collect(
        _target(
            _insn(
                index=0,
                opcode_name="m_jcnd",
                dstr="jcnd %var_54.8 == #2.8, @241",
                meta=_meta(l=_meta_stack(0x54), r=_meta_const(2)),
            ),
            _insn(
                index=1,
                opcode_name="m_stx",
                dstr="stx v52[2], ds.1, %var_dst.8",
                meta=_meta(
                    l=_meta_stack(0x520),
                    r=_meta_const(2),
                    d=_meta_stack(0x700),
                    byte_index=2,
                ),
            ),
        ),
        func_ea=0x401000,
        maturity=_MATURITY_VALUES["MMAT_LOCOPT"],
        phase="pre_d810",
    )

    assert facts == ()
