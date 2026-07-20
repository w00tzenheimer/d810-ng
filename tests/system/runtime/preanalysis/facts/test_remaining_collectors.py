"""Tests for the deferred maturity fact collectors."""
from __future__ import annotations

import json
from collections.abc import Mapping
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
from d810.ir.semantics import CallKind, ControlTransferKind, PredicateKind
from d810.analyses.value_flow.byte_emit_corridor import ByteEmitCorridorFactCollector
from d810.analyses.value_flow.call_anchor import CallAnchorFactCollector
from d810.analyses.value_flow.return_frontier import ReturnFrontierFactCollector
from d810.analyses.value_flow.zero_blob import ZeroBlobFactCollector
from d810.analyses.value_flow.induction_carrier import _MATURITY_VALUES

from tests.system.runtime.preanalysis.facts._diag_meta_builder import flat_meta

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
    dest_reg: int | None = None,
    meta: str | Mapping[str, object] | None = None,
    predicate_kind: PredicateKind | None = None,
    control_transfer: ControlTransferKind | None = None,
    control_target: int | None = None,
) -> InstructionSnapshot:
    # llr-3b41 S11: collectors lift diag rows through the canonical operand-tree
    # projection (the meta-less flat path was deleted), so attach a serializer-
    # shaped ``meta`` operand tree (raw opcode spelling) built from the flat
    # fields.  ``dict`` ``meta`` (e.g. ``{"byte_index": N}``) is ignored -- those
    # non-operand attrs were a meta-less-only capability.
    resolved_ea = 0x180010000 + index if ea is None else ea
    if isinstance(meta, Mapping):
        # An explicit operand-tree dict (carries ``l`` / ``r`` / ``d``) is the
        # serializer operand tree the test wants -- keep it.  An attrs-only dict
        # (e.g. ``{"byte_index": 1}``) was a meta-less-only capability that the
        # canonical projection does not surface, so fall back to a flat-field
        # operand tree instead.
        if any(slot in meta for slot in ("l", "r", "d")):
            meta = json.dumps(dict(meta))
        else:
            meta = None
    if meta is None:
        meta = flat_meta(
            opcode_name=opcode_name,
            ea=resolved_ea,
            dstr=dstr,
            dest_type=dest_type,
            dest_stkoff=dest_stkoff,
            dest_size=dest_size,
            dest_register=dest_reg,
            src_l_type=src_l_type,
            src_l_stkoff=src_l_stkoff,
            src_l_value=src_l_value,
            src_l_size=dest_size or 8,
            src_r_type=src_r_type,
            src_r_stkoff=src_r_stkoff,
            src_r_value=src_r_value,
        )
    insn = InstructionSnapshot(
        index=index,
        ea=resolved_ea,
        opcode=0,
        opcode_name=opcode_name,
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
    if dest_reg is not None:
        insn.dest_reg = int(dest_reg)
    if predicate_kind is not None:
        insn.predicate_kind = predicate_kind
    if control_transfer is not None:
        insn.control_transfer = control_transfer
    if control_target is not None:
        insn.control_target = int(control_target)
    return insn


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


def _cfg_global(address: int, *, size: int = 8) -> MopSnapshot:
    return MopSnapshot(kind=OperandKind.GLOBAL, gaddr=address, size=size)


def _cfg_reg(reg: int, *, size: int = 8) -> MopSnapshot:
    return MopSnapshot(kind=OperandKind.REGISTER, reg=reg, size=size)


def _cfg_stack(stkoff: int, *, size: int = 8) -> MopSnapshot:
    return MopSnapshot(kind=OperandKind.STACK, stkoff=stkoff, size=size)


def _cfg_const(value: int, *, size: int = 8) -> MopSnapshot:
    return MopSnapshot(kind=OperandKind.NUMBER, value=value, size=size)


def _cfg_args(*args: MopSnapshot) -> MopSnapshot:
    return MopSnapshot(kind=OperandKind.ARG_LIST, args=args)


def _cfg_insn(
    *,
    index: int,
    kind: InsnKind,
    ea: int | None = None,
    l: MopSnapshot | None = None,
    r: MopSnapshot | None = None,
    d: MopSnapshot | None = None,
    call_kind: CallKind | None = None,
    display_text: str = "",
) -> InsnSnapshot:
    return InsnSnapshot(
        opcode=-1,
        raw_opcode=0x1000 + index,
        ea=0x180010000 + index if ea is None else ea,
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
        call_kind=call_kind,
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


def test_call_anchor_records_call_context() -> None:
    collector = CallAnchorFactCollector()

    facts = collector.collect(
        _cfg_target(
            _cfg_block(
                130,
                _cfg_insn(
                    index=0,
                    kind=InsnKind.CALL,
                    l=_cfg_global(0x180000000),
                    d=_cfg_reg(0),
                    call_kind=CallKind.DIRECT,
                    display_text=(
                        "call $0x180000000<fast:_QWORD #0x11.8,"
                        "_QWORD #0x4A.8>"
                    ),
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


def test_call_anchor_ignores_legacy_opcode_only_call_shape() -> None:
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

    assert facts == ()


def test_call_anchor_records_indirect_call_from_register_target() -> None:
    # An indirect call whose canonical ``control.call_kind`` is INDIRECT and
    # whose ``control.call_target`` is a register varnode -- exercises the
    # ``indirect_call`` classifier branch and the register target signature.
    collector = CallAnchorFactCollector()

    facts = collector.collect(
        _cfg_target(
            _cfg_block(
                130,
                _cfg_insn(
                    index=0,
                    kind=InsnKind.CALL,
                    l=_cfg_reg(8),
                    d=_cfg_reg(0),
                    call_kind=CallKind.INDIRECT,
                    display_text="call r8",
                    ea=0x180014860,
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
    assert fact.payload["call_kind"] == "indirect_call"
    assert fact.payload["call_target"] == "r8"
    assert fact.mop_signature == "call:indirect_call:r8"


def test_call_anchor_records_intrinsic_call() -> None:
    # An intrinsic call -> the ``intrinsic_call`` classifier branch.
    collector = CallAnchorFactCollector()

    facts = collector.collect(
        _cfg_target(
            _cfg_block(
                130,
                _cfg_insn(
                    index=0,
                    kind=InsnKind.CALL,
                    l=_cfg_global(0x180000100),
                    d=_cfg_reg(0),
                    call_kind=CallKind.INTRINSIC,
                    display_text="call !memset",
                    ea=0x180014880,
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
    assert fact.payload["call_kind"] == "intrinsic_call"
    assert fact.mop_signature == "call:intrinsic_call:$0x180000100"


def test_call_anchor_records_unknown_target_for_argless_call() -> None:
    # A call with no l/r target operand -> ``control.call_target is None`` ->
    # the "unknown-call-target" signature.
    collector = CallAnchorFactCollector()

    facts = collector.collect(
        _cfg_target(
            _cfg_block(
                130,
                _cfg_insn(
                    index=0,
                    kind=InsnKind.CALL,
                    d=_cfg_args(_cfg_const(0x10)),
                    call_kind=CallKind.DIRECT,
                    display_text="call ???",
                    ea=0x180014870,
                ),
                succs=(),
                preds=(),
            )
        ),
        func_ea=0x401000,
        maturity=_MATURITY_VALUES["MMAT_CALLS"],
        phase="pre_d810",
    )

    assert len(facts) == 1
    fact = facts[0]
    assert fact.payload["call_target"] == "unknown-call-target"
    assert fact.payload["successor_blocks"] == []
    assert fact.payload["predecessor_blocks"] == []
    assert fact.payload["has_outgoing_flow"] is False
    assert fact.payload["has_incoming_flow"] is False


# --- llr-3b41 S4: call_anchor canonical-lift coverage for the diag-row source ---
#
# Following the S3 zero_blob pattern, call_anchor's source iterator is now
# dual-currency: meta-rich FlowGraph blocks AND operand-tree diag rows route
# through the SAME canonical projection; meta-less rows stay on the byte-
# identical legacy ``_InstructionView`` flat path.  call_anchor authorizes an
# anchor on ``Instruction.control.call_kind``, which the projection only
# recovers when the InsnSnapshot carries an explicit ``call_kind`` (the live
# FlowGraph path, covered above).  The diag projection does NOT yet recover
# call semantics from a meta operand tree (``m_call`` is absent from
# ``_OPCODE_NAME_TO_INSN_KIND``; see project_diag_instruction), so an
# operand-tree diag row currently yields zero call facts -- the same result as
# the meta-less path.  These tests pin BOTH the operand-tree diag-row source
# (it routes through the canonical lift and produces zero call facts today) and
# the meta-less attrs-only row (byte-identical zero observations).


def test_call_anchor_diag_operand_tree_row_yields_no_call_fact() -> None:
    # A diag row carrying a parseable ``meta`` operand tree routes through the
    # canonical projection.  Call recovery from a meta operand tree is not yet
    # implemented (m_call is not in the opcode->kind map), so this meta-rich
    # diag row classifies to "not a call" -> zero observations.
    collector = CallAnchorFactCollector()

    facts = collector.collect(
        _target(
            _block(
                130,
                _insn(
                    index=0,
                    opcode_name="m_call",
                    dstr="call $0x180000000<fast:_QWORD #0x11.8>",
                    ea=0x180014848,
                    meta={
                        "l": {
                            "type": "mop_v",
                            "type_num": 6,
                            "size": 8,
                            "dstr": "g",
                            "global_ea": "0x180000000",
                        },
                    },
                ),
                succs=(143,),
                preds=(129,),
            )
        ),
        func_ea=0x401000,
        maturity=_MATURITY_VALUES["MMAT_CALLS"],
        phase="pre_d810",
    )

    assert facts == ()


def test_call_anchor_ignores_meta_less_attrs_only_row() -> None:
    # A meta-less row whose ``meta`` carries only attrs (no operand tree) stays
    # on the byte-identical legacy flat path: call_anchor reads only the
    # canonical call fields the flat path never populates -> zero observations.
    collector = CallAnchorFactCollector()

    facts = collector.collect(
        _target(
            _block(
                130,
                _insn(
                    index=0,
                    opcode_name="m_call",
                    dstr="call $0x180000000<fast:_QWORD #0x11.8>",
                    ea=0x180014848,
                    meta={"byte_index": 1},
                ),
                succs=(143,),
                preds=(129,),
            )
        ),
        func_ea=0x401000,
        maturity=_MATURITY_VALUES["MMAT_CALLS"],
        phase="pre_d810",
    )

    assert facts == ()


def test_zero_blob_collector_separates_zero_store_and_blob_copy() -> None:
    collector = ZeroBlobFactCollector()

    facts = collector.collect(
        _cfg_target(
            _cfg_block(
                40,
                _cfg_insn(
                    index=0,
                    kind=InsnKind.STORE,
                    l=_cfg_const(0),
                    d=_cfg_stack(0x300),
                    display_text="stx #0x0.8, ds.2, %var_dst.8",
                ),
                _cfg_insn(
                    index=1,
                    kind=InsnKind.CALL,
                    l=_cfg_global(0x1800164E0),
                    d=_cfg_args(
                        _cfg_stack(0x300),
                        _cfg_global(0x180018E95),
                        _cfg_const(0x10),
                    ),
                    call_kind=CallKind.DIRECT,
                    display_text=(
                        "call sub_1800164E0<fast:%var_dst.8,"
                        "unk_180018E95,#0x10.8>"
                    ),
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
    assert zero.payload["destination"] == "mop_S:0x300"
    assert zero.payload["source"] == "#0x0"
    assert blob.payload["destination"] == "mop_S:0x300"
    assert blob.payload["source"] == "$0x180018e95"
    assert blob.payload["size"] == 0x10
    assert "ea=0x" in zero.semantic_key
    assert "ea=0x" in blob.semantic_key


def test_zero_blob_ignores_legacy_text_only_shapes() -> None:
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

    assert facts == ()


# --- llr-3b41 S3: zero_blob canonical-lift coverage for the diag-row source ---
#
# The pre-S3 zero_blob tests covered only the FlowGraph (meta-rich, canonical)
# and the meta-less legacy ``_target`` flat source.  The S3 port also routes a
# production diag row carrying a parseable ``meta`` operand tree through the
# SAME canonical lift, so its facts become canonical-faithful.  These tests pin
# that third source (a ``core.diag.snapshot.InstructionSnapshot`` with an
# ``_instruction_operands_meta``-shaped ``meta`` JSON) AND re-confirm the
# meta-less attrs-only row stays byte-identical (zero observations).


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


def _meta_global(address: int, size: int = 8) -> dict:
    return {
        "type": "mop_v",
        "type_num": 6,
        "size": size,
        "dstr": "g",
        "global_ea": f"{address:#x}",
    }


def test_zero_blob_lifts_zero_store_from_diag_meta_operand_tree() -> None:
    # ``m_stx #0x0, ds, %var_dst`` -- serializer meta: l=value, r=segment,
    # d=target.  The canonical lift recovers operation=STORE + memory operands
    # off the operand tree, so the meta-rich diag row yields the same
    # ``zero_store`` fact the FlowGraph source does.
    collector = ZeroBlobFactCollector()

    facts = collector.collect(
        _target(
            _block(
                40,
                _insn(
                    index=0,
                    opcode_name="m_stx",
                    dstr="stx #0x0.8, ds.2, %var_dst.8",
                    ea=0x180014A00,
                    meta={
                        "l": _meta_const(0),
                        "r": _meta_const(2),
                        "d": _meta_stack(0x300),
                    },
                ),
                succs=(41,),
            )
        ),
        func_ea=0x401000,
        maturity=_MATURITY_VALUES["MMAT_GLBOPT1"],
        phase="pre_d810",
    )

    assert len(facts) == 1
    fact = facts[0]
    assert fact.kind == "ZeroBlobFact"
    assert fact.payload["init_kind"] == "zero_store"
    assert fact.payload["destination"] == "mop_S:0x300"
    assert fact.payload["source"] == "#0x0"
    assert fact.payload["source_ea"] == "0x180014a00"
    assert "ea=0x180014a00" in fact.semantic_key


def test_zero_blob_lifts_blob_store_from_diag_meta_operand_tree() -> None:
    # ``m_stx $0x180018e95, ds, %var_dst`` -- a static global blob store.
    collector = ZeroBlobFactCollector()

    facts = collector.collect(
        _target(
            _block(
                40,
                _insn(
                    index=0,
                    opcode_name="m_stx",
                    dstr="stx unk_180018E95, ds.2, %var_dst.8",
                    ea=0x180014A10,
                    meta={
                        "l": _meta_global(0x180018E95),
                        "r": _meta_const(2),
                        "d": _meta_stack(0x300),
                    },
                ),
                succs=(41,),
            )
        ),
        func_ea=0x401000,
        maturity=_MATURITY_VALUES["MMAT_GLBOPT1"],
        phase="pre_d810",
    )

    assert len(facts) == 1
    fact = facts[0]
    assert fact.payload["init_kind"] == "blob_store"
    assert fact.payload["destination"] == "mop_S:0x300"
    assert fact.payload["source"] == "$0x180018e95"
    assert fact.confidence == 0.72


def test_zero_blob_ignores_meta_less_attrs_only_row() -> None:
    # A meta-less row whose ``meta`` carries only attrs (no operand tree) stays
    # on the byte-identical legacy flat path: zero_blob reads only canonical
    # memory/call fields the flat path never populates -> zero observations.
    collector = ZeroBlobFactCollector()

    facts = collector.collect(
        _target(
            _block(
                40,
                _insn(
                    index=0,
                    opcode_name="m_stx",
                    dstr="stx v52[1], ds.1, %var_dst.8",
                    meta={"byte_index": 1},
                ),
                succs=(41,),
            )
        ),
        func_ea=0x401000,
        maturity=_MATURITY_VALUES["MMAT_GLBOPT1"],
        phase="pre_d810",
    )

    assert facts == ()


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
                    dest_reg=0,
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


def test_return_frontier_accepts_canonical_return_control() -> None:
    collector = ReturnFrontierFactCollector()

    facts = collector.collect(
        _cfg_target(
            _cfg_block(
                57,
                _cfg_insn(
                    index=0,
                    kind=InsnKind.RET,
                    display_text="ret",
                    ea=0x180014900,
                ),
                succs=(57,),
                preds=(),
            )
        ),
        func_ea=0x401000,
        maturity=_MATURITY_VALUES["MMAT_CALLS"],
        phase="pre_d810",
    )

    assert len(facts) == 1
    fact = facts[0]
    assert fact.kind == "ReturnFrontierFact"
    assert fact.payload["return_block"] == 57
    assert fact.payload["successor_blocks"] == [57]
    assert fact.payload["carrier_fact_ids"] == []
def _meta_reg(reg: int, size: int = 8) -> dict:
    return {"type": "mop_r", "type_num": 1, "size": size, "dstr": "r", "reg": reg}


def test_return_frontier_recognises_operand_tree_ret_with_successor() -> None:
    # An operand-tree ``m_ret`` row in a block that still has a successor
    # (BLT_1WAY, ``not block.succs`` is False).  Only the recovered canonical
    # ``control_transfer is RETURN`` can mark it a return block -- the meta-less
    # flat path never sets ``control_transfer`` for ``m_ret`` and yields zero
    # (see ``test_return_frontier_ignores_legacy_return_opcode_when_not_terminal``).
    # This is a provable EMBRACE recovery gain, not a regression.
    collector = ReturnFrontierFactCollector()

    facts = collector.collect(
        _target(
            _block(
                57,
                _insn(
                    index=0,
                    opcode_name="m_ret",
                    dstr="ret",
                    meta={"l": _meta_reg(0)},
                ),
                succs=(58,),
                preds=(50,),
                type_name="BLT_1WAY",
            )
        ),
        func_ea=0x401000,
        maturity=_MATURITY_VALUES["MMAT_CALLS"],
        phase="pre_d810",
    )

    assert len(facts) == 1
    fact = facts[0]
    assert fact.kind == "ReturnFrontierFact"
    assert fact.payload["return_block"] == 57
    assert fact.payload["successor_blocks"] == [58]
    assert fact.payload["carrier_fact_ids"] == []
