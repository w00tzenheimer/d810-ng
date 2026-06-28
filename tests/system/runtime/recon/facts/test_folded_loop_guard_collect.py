"""FactObservation-level coverage for ``FoldedLoopGuardFactCollector`` (llr-3b41 S6).

The pre-S6 suite (``test_folded_loop_guard_operand_match``) pinned only the
``_guard_counter`` operand extraction over synthetic ``_InstructionView``s.  The
S6 port routes the collector onto the canonical IR with a dual-currency
iterator, so these tests pin the END-TO-END ``collect()`` observation across the
THREE real sources:

* **FlowGraph** meta-rich block source -- canonical projection, byte-identical
  flat behaviour (unchanged pre/post S6).
* **operand-tree diag row** carrying a nested ``(counter - #N)`` ``sub`` --
  the EMBRACE case: pre-S6 the nested-sub guard (Shape 2) was DEAD on diag rows
  (the legacy ``_instruction_view_from_canonical`` never set ``src_l_mop`` /
  ``src_r_mop``), so this guard was UNRECOVERABLE from a diag source.  Post-S6
  the source ``MopSnapshot`` reaches ``iter_operand_exprs`` and the guard is
  detected -- a strict improvement.
* **meta-less** attrs-only diag row -- byte-identical legacy flat path; the
  nested-sub host is absent, so no guard observation (same as before).

The guard scenario every case builds is the folded counted-loop shape:

* an induction self-update ``i = i + 1`` at ``_COUNTER`` (the induction var),
* a guard block comparing ``(i - #N)`` whose live successor is the EXIT arm,
* the EXIT arm writes ``#exit_state`` to the state var and flows to a JOIN,
* an ORPHANED body block (no preds) writes ``#body_state`` and flows to the
  same JOIN (the DCE'd TRUE arm, still alive at LOCOPT).

The two state-const writes (exit + body) to the same stack slot are what
``_canonical_state_stkoff`` keys on (it requires >= 2).
"""
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
    PredicateKind,
    ValueOpKind,
)
from d810.analyses.value_flow.folded_loop_guard import FoldedLoopGuardFactCollector
from d810.analyses.value_flow.induction_carrier import _MATURITY_VALUES

_COUNTER = 0x1E0  # induction stack slot
_STATE = 0x3C  # state-variable stack slot
_BOUND = 0x64  # numeric trip-count bound (100)
_EXIT_STATE = 0xAAAA1111
_BODY_STATE = 0xBBBB2222

# block serials
_INDUCT = 10  # induction self-update block
_GUARD = 20  # folded-guard block
_EXIT = 30  # surviving FALSE/exit arm
_BODY = 40  # orphaned (DCE'd) TRUE/body arm
_JOIN = 50  # convergence point


# --------------------------------------------------------------------------- #
# FlowGraph (canonical, meta-rich) source
# --------------------------------------------------------------------------- #


def _cfg_stack(stkoff: int, size: int = 4) -> MopSnapshot:
    return MopSnapshot(kind=OperandKind.STACK, stkoff=stkoff, size=size)


def _cfg_const(value: int, size: int = 4) -> MopSnapshot:
    return MopSnapshot(kind=OperandKind.NUMBER, value=value, size=size)


def _cfg_temp_dest(size: int = 4) -> MopSnapshot:
    # an unrelated stack temp destination (NOT the counter -> not a self-update)
    return MopSnapshot(kind=OperandKind.STACK, stkoff=0x200, size=size)


def _cfg_subinsn(kind: InsnKind, left: MopSnapshot, right: MopSnapshot, size: int = 4) -> MopSnapshot:
    return MopSnapshot(
        kind=OperandKind.SUBINSN,
        sub_kind=kind,
        sub_l=left,
        sub_r=right,
        size=size,
    )


def _cfg_insn(
    *,
    ea: int,
    kind: InsnKind,
    value_op_kind: ValueOpKind | None = None,
    predicate_kind: PredicateKind | None = None,
    l: MopSnapshot | None = None,
    r: MopSnapshot | None = None,
    d: MopSnapshot | None = None,
    display_text: str = "",
) -> InsnSnapshot:
    return InsnSnapshot(
        opcode=-1,
        raw_opcode=0x1000,
        ea=ea,
        operands=tuple(op for op in (l, r, d) if op is not None),
        operand_slots=tuple(
            (slot, op)
            for slot, op in (("l", l), ("r", r), ("d", d))
            if op is not None
        ),
        display_text=display_text,
        l=l,
        r=r,
        d=d,
        kind=kind,
        value_op_kind=value_op_kind,
        predicate_kind=predicate_kind,
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


def _state_write_insn(value: int, ea: int) -> InsnSnapshot:
    return _cfg_insn(
        ea=ea,
        kind=InsnKind.MOV,
        value_op_kind=ValueOpKind.MOVE,
        l=_cfg_const(value),
        d=_cfg_stack(_STATE),
        display_text=f"mov #{value:#x}, state",
    )


def _flowgraph_scenario(guard_insn: InsnSnapshot) -> FlowGraph:
    blocks = (
        _cfg_block(
            _INDUCT,
            _cfg_insn(
                ea=0x180014001,
                kind=InsnKind.ADD,
                value_op_kind=ValueOpKind.ADD,
                l=_cfg_stack(_COUNTER),
                r=_cfg_const(1),
                d=_cfg_stack(_COUNTER),
                display_text="add i, #1 -> i",
            ),
            succs=(_GUARD,),
        ),
        _cfg_block(_GUARD, guard_insn, succs=(_EXIT,), preds=(_INDUCT,)),
        _cfg_block(
            _EXIT,
            _state_write_insn(_EXIT_STATE, 0x180014031),
            succs=(_JOIN,),
            preds=(_GUARD,),
        ),
        # body block is ORPHANED (no preds) -- the DCE'd TRUE arm
        _cfg_block(
            _BODY,
            _state_write_insn(_BODY_STATE, 0x180014041),
            succs=(_JOIN,),
        ),
        _cfg_block(_JOIN, succs=(), preds=(_EXIT, _BODY)),
    )
    return FlowGraph(
        blocks={b.serial: b for b in blocks},
        entry_serial=_INDUCT,
        func_ea=0x180014000,
    )


def _collect(target) -> tuple:
    return FoldedLoopGuardFactCollector().collect(
        target,
        func_ea=0x180014000,
        maturity=_MATURITY_VALUES["MMAT_LOCOPT"],
        phase="pre_d810",
    )


def test_flowgraph_flat_signed_guard_yields_fact() -> None:
    # setl (i - #0x64) -- flat top-level signed compare (Shape 1)
    guard = _cfg_insn(
        ea=0x180014021,
        kind=InsnKind.UNKNOWN,
        predicate_kind=PredicateKind.SLT,
        l=_cfg_stack(_COUNTER),
        r=_cfg_const(_BOUND),
        d=_cfg_temp_dest(),
        display_text="setl i, #0x64 -> tmp",
    )

    facts = _collect(_flowgraph_scenario(guard))

    assert len(facts) == 1
    fact = facts[0]
    assert fact.kind == "FoldedLoopGuardFact"
    assert fact.payload["counter_stkoff"] == _COUNTER
    assert fact.payload["bound"] == _BOUND
    assert fact.payload["signed"] is True
    assert fact.payload["exit_state"] == _EXIT_STATE & 0xFFFFFFFF
    assert fact.payload["body_state"] == _BODY_STATE & 0xFFFFFFFF


def test_flowgraph_nested_buried_subtract_guard_yields_fact() -> None:
    # xdu (i - #0x64) -- buried subtract inside a widen host (Shape 2).
    # The FlowGraph canonical projection already exposed nested structure;
    # the source MopSnapshot now reaches iter_operand_exprs -> guard detected.
    sub = _cfg_subinsn(InsnKind.SUB, _cfg_stack(_COUNTER), _cfg_const(_BOUND))
    guard = _cfg_insn(
        ea=0x180014022,
        kind=InsnKind.XDU,
        value_op_kind=ValueOpKind.ZEXT,
        l=sub,
        d=_cfg_temp_dest(size=8),
        display_text="xdu (i - #0x64) -> tmp",
    )

    facts = _collect(_flowgraph_scenario(guard))

    assert len(facts) == 1
    fact = facts[0]
    assert fact.payload["counter_stkoff"] == _COUNTER
    assert fact.payload["bound"] == _BOUND
    assert fact.payload["signed"] is True  # ZEXT host defaults signed


# --------------------------------------------------------------------------- #
# Diag-row sources (meta-rich operand tree, and meta-less attrs-only)
# --------------------------------------------------------------------------- #


def _meta_stack(stkoff: int, size: int = 4) -> dict:
    return {"type": "mop_S", "type_num": 5, "size": size, "dstr": "i", "stkoff": stkoff}


def _meta_const(value: int, size: int = 4) -> dict:
    return {
        "type": "mop_n",
        "type_num": 2,
        "size": size,
        "dstr": f"#{value:#x}",
        "value": value,
    }


def _meta_sub(left: dict, right: dict, size: int = 4) -> dict:
    # a mop_d (SUBINSN, type_num 4) wrapping an m_sub sub-instruction.
    return {
        "type": "mop_d",
        "type_num": 4,
        "size": size,
        "dstr": "(i - #0x64)",
        "sub_instruction": {"opcode_name": "m_sub", "l": left, "r": right},
    }


def _diag_insn(
    *,
    index: int,
    opcode_name: str,
    ea: int,
    dstr: str = "",
    dest_stkoff: int | None = None,
    dest_size: int | None = None,
    src_l_type: str | None = None,
    src_l_stkoff: int | None = None,
    src_l_value: int | None = None,
    src_r_type: str | None = None,
    src_r_value: int | None = None,
    meta=None,
    predicate_kind: PredicateKind | None = None,
) -> InstructionSnapshot:
    import json

    if isinstance(meta, dict):
        meta = json.dumps(meta)
    insn = InstructionSnapshot(
        index=index,
        ea=ea,
        opcode=0,
        opcode_name=opcode_name,
        dest_type="S" if dest_stkoff is not None else None,
        dest_stkoff=dest_stkoff,
        dest_size=dest_size,
        src_l_type=src_l_type,
        src_l_stkoff=src_l_stkoff,
        src_l_value=src_l_value,
        src_r_type=src_r_type,
        src_r_value=src_r_value,
        dstr=dstr,
        meta=meta,
    )
    if predicate_kind is not None:
        insn.predicate_kind = predicate_kind
    return insn


def _diag_block(
    serial: int,
    *instructions: InstructionSnapshot,
    succs: tuple[int, ...] = (),
    preds: tuple[int, ...] = (),
) -> BlockSnapshot:
    return BlockSnapshot(
        serial=serial,
        block_type=1 if len(succs) <= 1 else 2,
        type_name="BLT_1WAY",
        start_ea=0x180014000 + serial,
        nsucc=len(succs),
        npred=len(preds),
        succs=list(succs),
        preds=list(preds),
        instructions=list(instructions),
    )


def _diag_target(*blocks: BlockSnapshot) -> SimpleNamespace:
    return SimpleNamespace(blocks={b.serial: b for b in blocks})


def _diag_state_write(value: int, ea: int) -> InstructionSnapshot:
    return _diag_insn(
        index=0,
        opcode_name="m_mov",
        ea=ea,
        dstr=f"mov #{value:#x}, state",
        dest_stkoff=_STATE,
        dest_size=4,
        src_l_type="c",
        src_l_value=value,
        meta={"l": _meta_const(value), "d": _meta_stack(_STATE)},
    )


def _diag_induction() -> InstructionSnapshot:
    return _diag_insn(
        index=0,
        opcode_name="m_add",
        ea=0x180014001,
        dstr="add i, #1 -> i",
        dest_stkoff=_COUNTER,
        dest_size=4,
        src_l_type="S",
        src_l_stkoff=_COUNTER,
        src_r_type="c",
        src_r_value=1,
        meta={
            "l": _meta_stack(_COUNTER),
            "r": _meta_const(1),
            "d": _meta_stack(_COUNTER),
        },
    )


def _diag_scenario(guard_insn: InstructionSnapshot) -> SimpleNamespace:
    return _diag_target(
        _diag_block(_INDUCT, _diag_induction(), succs=(_GUARD,)),
        _diag_block(_GUARD, guard_insn, succs=(_EXIT,), preds=(_INDUCT,)),
        _diag_block(
            _EXIT,
            _diag_state_write(_EXIT_STATE, 0x180014031),
            succs=(_JOIN,),
            preds=(_GUARD,),
        ),
        _diag_block(_BODY, _diag_state_write(_BODY_STATE, 0x180014041), succs=(_JOIN,)),
        _diag_block(_JOIN, succs=(), preds=(_EXIT, _BODY)),
    )


def test_diag_operand_tree_nested_buried_subtract_guard_yields_fact_EMBRACE() -> None:
    # EMBRACE: a diag row carrying the nested ``(i - #0x64)`` sub now reaches
    # iter_operand_exprs via parse_diag_meta_operand.  Pre-S6 the operand-tree
    # diag row produced src_l_mop=None -> this guard was UNRECOVERABLE from a
    # diag source; post-S6 it is recovered.
    guard = _diag_insn(
        index=0,
        opcode_name="m_xdu",
        ea=0x180014022,
        dstr="xdu (i - #0x64) -> tmp",
        dest_stkoff=0x200,
        dest_size=8,
        meta={"l": _meta_sub(_meta_stack(_COUNTER), _meta_const(_BOUND))},
    )

    facts = _collect(_diag_scenario(guard))

    assert len(facts) == 1
    fact = facts[0]
    assert fact.kind == "FoldedLoopGuardFact"
    assert fact.payload["counter_stkoff"] == _COUNTER
    assert fact.payload["bound"] == _BOUND
    assert fact.payload["signed"] is True
    assert fact.payload["exit_state"] == _EXIT_STATE & 0xFFFFFFFF
    assert fact.payload["body_state"] == _BODY_STATE & 0xFFFFFFFF


def test_diag_meta_less_attrs_only_guard_row_yields_no_fact() -> None:
    # A meta-less attrs-only guard row (no operand tree) stays on the legacy
    # flat path.  Its flat fields are empty for the buried-sub host, so no
    # nested guard is reachable -> zero observations (byte-identical pre-S6).
    guard = _diag_insn(
        index=0,
        opcode_name="m_xdu",
        ea=0x180014022,
        dstr="xdu (i - #0x64) -> tmp",
        dest_stkoff=0x200,
        dest_size=8,
        meta={"byte_index": 1},  # attrs-only, no l/r/d operand tree
    )

    facts = _collect(_diag_scenario(guard))

    assert facts == ()
