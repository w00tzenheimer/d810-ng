"""Tests for OLLVM profile-local raw evidence collection."""
from __future__ import annotations

import json
from types import SimpleNamespace

from d810.core.diag.snapshot import BlockSnapshot, InstructionSnapshot
from d810.ir.expressions import ValueOpKind
from d810.ir.flowgraph import (
    BlockSnapshot as CfgBlockSnapshot,
    BlockSnapshot as IRBlockSnapshot,
    FlowGraph,
    InsnKind,
    InsnSnapshot,
    MopSnapshot,
    OperandKind,
)
from d810.backends.hexrays.evidence.ollvm_carrier import (
    OllvmCarrierRawEvidenceCollector,
)
from d810.analyses.value_flow.induction_carrier import _MATURITY_VALUES

from tests.unit.recon.facts._diag_meta_builder import flat_meta


_OPCODE_CANONICAL = {
    "op_4": "m_mov",
    "op_1": "m_stx",
    "op_10": "m_call",
    "op_35": "m_xds",
    "op_56": "m_add",
}


def _insn(
    *,
    index: int = 0,
    ea: int = 0x180010000,
    opcode_name: str = "op_4",
    dstr: str,
    dest_stkoff: int | None = None,
) -> InstructionSnapshot:
    # llr-3b41 S11: the OLLVM carrier collector is text-driven (regex over
    # ``dstr``) but also reads canonical ``operation`` (STORE).  The collector
    # lifts diag rows through ``project_diag_instruction`` (the meta-less flat
    # path was deleted), so map the numeric opcode to its serializer spelling and
    # attach a ``meta`` operand tree carrying the dest stack slot.
    canonical_opcode = _OPCODE_CANONICAL.get(opcode_name, opcode_name)
    dest_type = "mop_S" if dest_stkoff is not None else None
    meta = flat_meta(
        opcode_name=canonical_opcode,
        ea=ea,
        dstr=dstr,
        dest_type=dest_type,
        dest_stkoff=dest_stkoff,
        dest_size=8,
    )
    return InstructionSnapshot(
        index=index,
        ea=ea,
        opcode=0,
        opcode_name=canonical_opcode,
        dest_type=dest_type,
        dest_stkoff=dest_stkoff,
        dest_size=8,
        src_l_type=None,
        src_l_stkoff=None,
        src_l_value=None,
        src_r_type=None,
        src_r_stkoff=None,
        src_r_value=None,
        dstr=dstr,
        meta=meta,
    )


def _block(serial: int, *insns: InstructionSnapshot) -> BlockSnapshot:
    return BlockSnapshot(
        serial=serial,
        block_type=1,
        type_name="BLT_1WAY",
        start_ea=0x180010000 + serial,
        nsucc=1,
        npred=0,
        succs=[serial + 1],
        preds=[],
        instructions=list(insns),
    )


def _target(*blocks: BlockSnapshot) -> SimpleNamespace:
    return SimpleNamespace(blocks={blk.serial: blk for blk in blocks})


def _collect(target: object):
    return OllvmCarrierRawEvidenceCollector().collect(
        target,
        func_ea=0x18000E360,
        maturity=_MATURITY_VALUES["MMAT_GLBOPT1"],
        phase="pre_d810",
    )


def test_requires_ollvm_marker() -> None:
    facts = _collect(_target(_block(1, _insn(dstr="mov rcx.8, %var_38.8"))))

    assert facts == ()


def test_records_argument_and_password_call_carriers() -> None:
    facts = _collect(_target(
        _block(
            1,
            _insn(index=0, dstr="mov    rdx.8{1}, %var_30.8{1}"),
            _insn(index=1, dstr="mov    rcx.8{2}, %var_38.8{2}"),
            _insn(
                index=2,
                opcode_name="op_10",
                dstr=(
                    "low call $0x180000000<fast:_QWORD &(%var_98{46}).8,"
                    "_QWORD &($aSecret).8,_QWORD #0x64.8> => __int64 .8, "
                    "%var_58.4{67}"
                ),
            ),
            _insn(
                index=3,
                opcode_name="op_10",
                dstr=(
                    "low call $0x180000000<...:\"const char *\" &($aS).8,"
                    "\"const char *\" &(%var_98{46}).8> => __int64 .8, "
                    "%var_54.4{64}"
                ),
            ),
        )
    ))

    by_role = {fact.payload["role"]: fact for fact in facts}
    assert by_role["ARG_INPUT_POINTER"].payload["carrier_token"] == "%var_38"
    assert by_role["ARG_OUTPUT_POINTER"].payload["carrier_token"] == "%var_30"
    assert by_role["PASSWORD_COMPARE_RESULT"].payload["carrier_token"] == "%var_58"
    assert by_role["PASSWORD_BUFFER"].payload["carrier_token"] == "%var_98"


def test_records_native_imagebase_password_compare_carriers() -> None:
    facts = _collect(_target(
        _block(
            1,
            _insn(
                index=0,
                opcode_name="op_56",
                dstr=(
                    "call   $printf <...:\"const char *const Format\" "
                    "&($aPleaseEnterPassword).8> => int .0"
                ),
            ),
            _insn(
                index=1,
                opcode_name="op_4",
                dstr=(
                    "mov    call $__ImageBase<std:\"HINSTANCE hinstDLL\" "
                    "&(%var_98{40}).8,\"DWORD fdwReason\" "
                    "low.4(&($hinstDLL@3).8),\"LPVOID lpReserved\" #0x64.8> "
                    "=> BOOL .4, %var_58.4{61}"
                ),
            ),
        )
    ))

    by_role = {fact.payload["role"]: fact for fact in facts}
    assert by_role["PASSWORD_BUFFER"].payload["carrier_token"] == "%var_98"
    assert by_role["PASSWORD_COMPARE_RESULT"].payload["carrier_token"] == "%var_58"
    assert (
        by_role["PASSWORD_COMPARE_RESULT"].payload["call_kind"]
        == "native_imagebase_strncmp_like"
    )
    assert (
        by_role["PASSWORD_COMPARE_RESULT"].payload["password_buffer_token"]
        == "%var_98"
    )


def test_distinguishes_loop_index_from_accumulator() -> None:
    facts = _collect(_target(
        _block(
            10,
            _insn(
                index=0,
                dstr="mov    &(%var_18{43}).8, %var_378.8",
            ),
            _insn(
                index=1,
                dstr="mov    %var_378.8, %var_390.8",
            ),
            _insn(
                index=2,
                opcode_name="op_35",
                dstr="setb [ds.2:%var_398.8].4, #0x64.4, %var_3A1.1",
            ),
            _insn(
                index=3,
                opcode_name="op_1",
                dstr=(
                    "stx ((#5.4*[ds.2:%var_378.8].4)+[ds.2:%var_390.8].4), "
                    "ds.2, %var_378.8"
                ),
            ),
            _insn(
                index=4,
                opcode_name="op_10",
                dstr=(
                    "low call $0x180000000<fast:_QWORD &(%var_98).8,"
                    "_QWORD &($aSecret).8,_QWORD #0x64.8> => __int64 .8, "
                    "%var_58.4"
                ),
            ),
        )
    ))

    index_facts = [
        fact for fact in facts
        if fact.payload["role"] == "LOOP_INDEX_CARRIER"
    ]
    accumulator_facts = [
        fact for fact in facts
        if fact.payload["role"] == "ACCUMULATOR_CARRIER"
    ]

    assert index_facts[0].payload["carrier_token"] == "%var_398"
    assert accumulator_facts[0].payload["carrier_token"] == "%var_378"
    assert accumulator_facts[0].payload["same_carrier_alias_proof"] is True
    assert accumulator_facts[0].payload["multiply_add_same_base_alias_tokens"] == (
        "%var_390",
    )
    assert index_facts[0].payload["carrier_token"] != accumulator_facts[0].payload["carrier_token"]


def test_multiply_add_without_same_base_alias_is_not_proven() -> None:
    facts = _collect(_target(
        _block(
            10,
            _insn(
                index=0,
                dstr="mov    &(%var_18{43}).8, %var_378.8",
            ),
            _insn(
                index=1,
                dstr="mov    &(%var_84{44}).8, %var_390.8",
            ),
            _insn(
                index=2,
                opcode_name="op_1",
                dstr=(
                    "stx ((#5.4*[ds.2:%var_378.8].4)+[ds.2:%var_390.8].4), "
                    "ds.2, %var_378.8"
                ),
            ),
            _insn(
                index=3,
                opcode_name="op_10",
                dstr=(
                    "low call $0x180000000<fast:_QWORD &(%var_98).8,"
                    "_QWORD &($aSecret).8,_QWORD #0x64.8> => __int64 .8, "
                    "%var_58.4"
                ),
            ),
        )
    ))

    accumulator_facts = [
        fact for fact in facts
        if fact.payload["role"] == "ACCUMULATOR_CARRIER"
    ]

    assert accumulator_facts[0].payload["carrier_token"] == "%var_378"
    assert accumulator_facts[0].payload["same_carrier_alias_proof"] is False


def test_records_masked_arg_output_store_candidate() -> None:
    facts = _collect(_target(
        _block(
            20,
            _insn(index=0, dstr="mov    rdx.8{1}, %var_370.8{1}"),
            _insn(
                index=1,
                opcode_name="op_1",
                dstr=(
                    "stx ((([ds.2:%var_378.8].4 ^ bnot([ds.2:%var_378.8].4)) "
                    "& #0xCD536960.4) ^ #0x259CF55E.4), ds.2, "
                    "[ds.2:%var_370.8].8"
                ),
            ),
            _insn(
                index=2,
                opcode_name="op_10",
                dstr=(
                    "low call $0x180000000<fast:_QWORD &(%var_98).8,"
                    "_QWORD &($aSecret).8,_QWORD #0x64.8> => __int64 .8, "
                    "%var_58.4"
                ),
            ),
        )
    ))

    output_facts = [
        fact for fact in facts
        if fact.payload["role"] == "ARG_OUTPUT_STORE_CANDIDATE"
    ]
    assert output_facts[0].payload["carrier_token"] == "%var_370"


def test_records_local_working_store_when_target_is_address_of_local() -> None:
    facts = _collect(_target(
        _block(
            20,
            _insn(index=0, dstr="mov    &(%var_18{43}).8, %var_370.8"),
            _insn(
                index=1,
                opcode_name="op_1",
                dstr=(
                    "stx ((([ds.2:%var_378.8].4 ^ bnot([ds.2:%var_378.8].4)) "
                    "& #0xCD536960.4) ^ #0x259CF55E.4), ds.2, "
                    "[ds.2:%var_370.8].8"
                ),
            ),
            _insn(
                index=2,
                opcode_name="op_10",
                dstr=(
                    "low call $0x180000000<fast:_QWORD &(%var_98).8,"
                    "_QWORD &($aSecret).8,_QWORD #0x64.8> => __int64 .8, "
                    "%var_58.4"
                ),
            ),
        )
    ))

    by_role = {fact.payload["role"]: fact for fact in facts}
    assert by_role["LOCAL_WORKING_POINTER"].payload["carrier_token"] == "%var_370"
    assert by_role["LOCAL_WORKING_POINTER"].payload["local_base_token"] == "%var_18"
    assert by_role["LOCAL_WORKING_STORE_CANDIDATE"].payload["carrier_token"] == "%var_370"
    assert by_role["LOCAL_WORKING_STORE_CANDIDATE"].payload["local_base_token"] == "%var_18"


# ---------------------------------------------------------------------------
# llr-3b41: dual-currency port coverage.  The collector now consumes the
# canonical ``Instruction`` for meta-rich sources (a portable ``FlowGraph``
# block, or a diag row carrying a parseable ``meta`` operand tree) while
# meta-less rows (every test above) stay on the byte-identical legacy flat
# path.  This collector is purely text-driven (carriers are matched on the
# instruction ``dstr``; the only structured read is ``operation`` vs
# ``ValueOpKind.STORE``), so the two new currencies are pinned by routing the
# SAME OLLVM carrier text through ``InstructionProjection.from_block`` and
# ``project_diag_instruction``.
# ---------------------------------------------------------------------------

_ACCUM_STORE_TEXT = (
    "stx ((#5.4*[ds.2:%var_378.8].4)+[ds.2:%var_390.8].4), ds.2, %var_378.8"
)
_PASSWORD_CALL_TEXT = (
    "low call $0x180000000<fast:_QWORD &(%var_98).8,"
    "_QWORD &($aSecret).8,_QWORD #0x64.8> => __int64 .8, %var_58.4"
)
_LOCAL_BASE_TEXT = "mov    &(%var_18{43}).8, %var_378.8"
_LOCAL_ALIAS_TEXT = "mov    %var_378.8, %var_390.8"


def _cfg_insn(
    *,
    index: int,
    display_text: str,
    kind: InsnKind = InsnKind.UNKNOWN,
    value_op_kind: ValueOpKind | None = None,
) -> InsnSnapshot:
    return InsnSnapshot(
        opcode=0,
        ea=0x180010000 + index,
        operands=(),
        display_text=display_text,
        kind=kind,
        value_op_kind=value_op_kind,
    )


def _cfg_target(*insns: InsnSnapshot) -> FlowGraph:
    return FlowGraph(
        blocks={
            10: CfgBlockSnapshot(
                serial=10,
                block_type=0,
                succs=(11,),
                preds=(9,),
                flags=0,
                start_ea=0x180010000,
                insn_snapshots=tuple(insns),
            )
        },
        entry_serial=10,
        func_ea=0x18000E360,
    )


def test_collects_accumulator_carrier_from_canonical_flowgraph() -> None:
    """A portable ``FlowGraph`` block routes through the canonical projection:
    ``dstr`` comes from ``Instruction.attrs['display_text']`` and the STORE
    check from the canonical ``operation`` (``value_op_kind=STORE``), so the
    same OLLVM carriers are recovered as on the legacy meta-less path."""
    facts = _collect(
        _cfg_target(
            _cfg_insn(index=0, display_text=_LOCAL_BASE_TEXT),
            _cfg_insn(index=1, display_text=_LOCAL_ALIAS_TEXT),
            _cfg_insn(
                index=2,
                display_text=_ACCUM_STORE_TEXT,
                kind=InsnKind.STORE,
                value_op_kind=ValueOpKind.STORE,
            ),
            _cfg_insn(index=3, display_text=_PASSWORD_CALL_TEXT),
        )
    )

    by_role = {fact.payload["role"]: fact for fact in facts}
    accum = by_role["ACCUMULATOR_CARRIER"]
    assert accum.payload["carrier_token"] == "%var_378"
    assert accum.payload["same_carrier_alias_proof"] is True
    assert accum.payload["multiply_add_same_base_alias_tokens"] == ("%var_390",)
    # The carrier anchor is the canonical block/index/dstr (text-driven match).
    assert accum.payload["source_block"] == 10
    assert accum.payload["instruction_dstr"] == _ACCUM_STORE_TEXT
    assert by_role["PASSWORD_COMPARE_RESULT"].payload["carrier_token"] == "%var_58"


def _accum_store_meta_row() -> InstructionSnapshot:
    """A STORE diag row carrying a parseable ``meta`` operand tree (so the
    ``diag_row_has_operand_tree`` gate routes it through the canonical lift).
    The flat ``dest_*`` / ``src_*`` fields are left ``None``; the carrier is
    matched purely on ``dstr``, and ``operation`` resolves via the canonical
    ``Instruction`` projected from the operand tree."""
    insn = InstructionSnapshot(
        index=2,
        ea=0x180010002,
        opcode=0,
        opcode_name="m_stx",
        dest_type=None,
        dest_stkoff=None,
        dest_size=8,
        src_l_type=None,
        src_l_stkoff=None,
        src_l_value=None,
        src_r_type=None,
        src_r_stkoff=None,
        src_r_value=None,
        dstr=_ACCUM_STORE_TEXT,
    )
    insn.meta = json.dumps(
        {
            "l": {"type": "mop_n", "type_num": 2, "size": 4, "dstr": "#5", "value": 5},
            "d": {
                "type": "mop_S",
                "type_num": 5,
                "size": 8,
                "dstr": "%var_378",
                "stkoff": 0x378,
            },
        }
    )
    return insn


def test_collects_accumulator_carrier_from_operand_tree_diag_row() -> None:
    """A diag row whose ``meta`` carries an operand tree is lifted through
    ``project_diag_instruction`` (the canonical currency), not the flat path;
    the carrier text in ``dstr`` is preserved and the STORE ``operation`` is
    recovered from the canonical ``Instruction``."""
    facts = _collect(
        _target(
            _block(
                10,
                _insn(index=0, dstr=_LOCAL_BASE_TEXT),
                _insn(index=1, dstr=_LOCAL_ALIAS_TEXT),
                # operand-tree diag row -> canonical lift (gate True)
                _accum_store_meta_row(),
                _insn(index=3, opcode_name="op_10", dstr=_PASSWORD_CALL_TEXT),
            )
        )
    )

    accumulator_facts = [
        fact for fact in facts if fact.payload["role"] == "ACCUMULATOR_CARRIER"
    ]
    assert accumulator_facts[0].payload["carrier_token"] == "%var_378"
    assert accumulator_facts[0].payload["same_carrier_alias_proof"] is True
    assert accumulator_facts[0].payload["instruction_dstr"] == _ACCUM_STORE_TEXT


# ---------------------------------------------------------------------------
# Structural ACCUMULATOR_CARRIER detection (ollvm-carrier-oracle-split port).
# These fixtures build real ``MopSnapshot`` subinsn trees so the canonical
# projection populates ``Instruction.input_exprs``, which the carrier record
# exposes as ``_OllvmCarrierInsn.src_l_expr``.  The structural self-update
# detection walks that lifted ``ExprRef`` tree (the store value = ``insn.l``)
# instead of the ``dstr`` regex.  ``display_text`` is still carried so the
# unchanged (regex-derived) ``_carrier_alias_sets`` recovers
# ``local_pointer_base`` and so the OLLVM marker gate fires; the out-of-scope
# LOOP/LOCAL roles still read it.  The payloads are asserted byte-identical to
# the rendered-text (regex-fallback) fixtures above.
# ---------------------------------------------------------------------------


def _stk(off: int, size: int = 8) -> MopSnapshot:
    return MopSnapshot(kind=OperandKind.STACK, stkoff=off, size=size)


def _num(value: int, size: int = 4) -> MopSnapshot:
    return MopSnapshot(kind=OperandKind.NUMBER, value=value, size=size)


def _addr_of_local(base_off: int) -> MopSnapshot:
    return MopSnapshot(kind=OperandKind.ADDRESS, size=8, stack_refs=(base_off,))


def _lea_local_snap(
    *, idx: int, base_off: int, dest_off: int, base_token: str, dest_token: str
) -> InsnSnapshot:
    """``mov &(local).8, carrier.8`` — lea-of-local alias seed."""
    return InsnSnapshot(
        opcode=0x4,
        ea=0x180010000 + idx,
        operands=(),
        kind=InsnKind.MOV,
        l=_addr_of_local(base_off),
        d=_stk(dest_off),
        display_text=f"mov    &({base_token}{{43}}).8, {dest_token}.8",
    )


def _var_copy_snap(
    *, idx: int, src_off: int, dest_off: int, src_token: str, dest_token: str
) -> InsnSnapshot:
    """``mov src.8, dst.8`` — var->var copy propagation."""
    return InsnSnapshot(
        opcode=0x4,
        ea=0x180010000 + idx,
        operands=(),
        kind=InsnKind.MOV,
        l=_stk(src_off),
        d=_stk(dest_off),
        display_text=f"mov    {src_token}.8, {dest_token}.8",
    )


def _accumulator_snap(
    *, idx: int, carrier_off: int, addend_off: int, carrier_token: str, addend_token: str
) -> InsnSnapshot:
    """``stx ((#5 * carrier) + addend), ds.2, carrier`` self-update store.

    The stored-value subtree (``l``) projects to
    ``Add(Mul(Const(5), Move(carrier)), Move(addend))`` so ``src_l_expr`` carries
    the full multiply-add shape; the store target (``d``) is the carrier slot.
    """
    mul = MopSnapshot(
        kind=OperandKind.SUBINSN,
        sub_kind=InsnKind.MUL,
        size=4,
        sub_l=_num(5),
        sub_r=_stk(carrier_off, size=4),
    )
    add = MopSnapshot(
        kind=OperandKind.SUBINSN,
        sub_kind=InsnKind.ADD,
        size=4,
        sub_l=mul,
        sub_r=_stk(addend_off, size=4),
    )
    return InsnSnapshot(
        opcode=0x61,
        ea=0x180010000 + idx,
        operands=(),
        kind=InsnKind.STORE,
        l=add,
        d=_stk(carrier_off),
        display_text=(
            f"stx ((#5.4*[ds.2:{carrier_token}.8].4)+"
            f"[ds.2:{addend_token}.8].4), ds.2, {carrier_token}.8"
        ),
    )


def _text_snap(*, idx: int, opcode: int, display_text: str) -> InsnSnapshot:
    return InsnSnapshot(
        opcode=opcode,
        ea=0x180010000 + idx,
        operands=(),
        kind=InsnKind.UNKNOWN,
        display_text=display_text,
    )


_LOOP_SETB_TEXT = "setb [ds.2:%var_398.8].4, #0x64.4, %var_3A1.1"
_MARKER_CALL_TEXT = (
    "low call $0x180000000<fast:_QWORD &(%var_98).8,"
    "_QWORD &($aSecret).8,_QWORD #0x64.8> => __int64 .8, %var_58.4"
)


def _ir_flowgraph(serial: int, *insns: InsnSnapshot) -> FlowGraph:
    block = IRBlockSnapshot(
        serial=serial,
        block_type=1,
        flags=0,
        succs=(),
        preds=(),
        start_ea=0x180010000 + serial,
        insn_snapshots=tuple(insns),
    )
    return FlowGraph(
        blocks={serial: block},
        entry_serial=serial,
        func_ea=0x18000E360,
    )


def test_structural_distinguishes_loop_index_from_accumulator() -> None:
    facts = _collect(_ir_flowgraph(
        10,
        _lea_local_snap(
            idx=0, base_off=0x18, dest_off=0x378,
            base_token="%var_18", dest_token="%var_378",
        ),
        _var_copy_snap(
            idx=1, src_off=0x378, dest_off=0x390,
            src_token="%var_378", dest_token="%var_390",
        ),
        _text_snap(idx=2, opcode=0x35, display_text=_LOOP_SETB_TEXT),
        _accumulator_snap(
            idx=3, carrier_off=0x378, addend_off=0x390,
            carrier_token="%var_378", addend_token="%var_390",
        ),
        _text_snap(idx=4, opcode=0x10, display_text=_MARKER_CALL_TEXT),
    ))

    index_facts = [
        fact for fact in facts if fact.payload["role"] == "LOOP_INDEX_CARRIER"
    ]
    accumulator_facts = [
        fact for fact in facts if fact.payload["role"] == "ACCUMULATOR_CARRIER"
    ]

    # Exactly one ACCUMULATOR_CARRIER hit (structural-primary, single-emit).
    assert len(accumulator_facts) == 1
    assert index_facts[0].payload["carrier_token"] == "%var_398"
    payload = accumulator_facts[0].payload
    assert payload["carrier_token"] == "%var_378"
    assert payload["store_kind"] == "self_update"
    assert payload["same_carrier_alias_proof"] is True
    assert payload["multiply_add_same_base_alias_tokens"] == ("%var_390",)
    assert payload["multiply_add_operand_tokens"] == ("%var_378", "%var_390")
    assert payload["multiply_add_base_token"] == "%var_18"


def test_structural_multiply_add_without_same_base_alias_is_not_proven() -> None:
    facts = _collect(_ir_flowgraph(
        10,
        _lea_local_snap(
            idx=0, base_off=0x18, dest_off=0x378,
            base_token="%var_18", dest_token="%var_378",
        ),
        _lea_local_snap(
            idx=1, base_off=0x84, dest_off=0x390,
            base_token="%var_84", dest_token="%var_390",
        ),
        _accumulator_snap(
            idx=2, carrier_off=0x378, addend_off=0x390,
            carrier_token="%var_378", addend_token="%var_390",
        ),
        _text_snap(idx=3, opcode=0x10, display_text=_MARKER_CALL_TEXT),
    ))

    accumulator_facts = [
        fact for fact in facts if fact.payload["role"] == "ACCUMULATOR_CARRIER"
    ]
    assert len(accumulator_facts) == 1
    payload = accumulator_facts[0].payload
    assert payload["carrier_token"] == "%var_378"
    assert payload["same_carrier_alias_proof"] is False
    assert payload["multiply_add_same_base_alias_tokens"] == ()
    assert payload["multiply_add_base_token"] == "%var_18"


def test_structural_accumulator_payload_matches_legacy_golden() -> None:
    """Byte-identical regression guard: the structural ACCUMULATOR_CARRIER
    payload equals the exact dict the regex path produces for the canonical
    ``5*x + addend`` self-update with a shared ``%var_18`` local base."""
    facts = _collect(_ir_flowgraph(
        10,
        _lea_local_snap(
            idx=0, base_off=0x18, dest_off=0x378,
            base_token="%var_18", dest_token="%var_378",
        ),
        _var_copy_snap(
            idx=1, src_off=0x378, dest_off=0x390,
            src_token="%var_378", dest_token="%var_390",
        ),
        _accumulator_snap(
            idx=2, carrier_off=0x378, addend_off=0x390,
            carrier_token="%var_378", addend_token="%var_390",
        ),
        _text_snap(idx=3, opcode=0x10, display_text=_MARKER_CALL_TEXT),
    ))
    payload = next(
        fact.payload for fact in facts
        if fact.payload["role"] == "ACCUMULATOR_CARRIER"
    )
    legacy_golden = {
        "role": "ACCUMULATOR_CARRIER",
        "carrier_token": "%var_378",
        "store_kind": "self_update",
        "multiply_add_operand_tokens": ("%var_378", "%var_390"),
        "multiply_add_base_token": "%var_18",
        "multiply_add_same_base_alias_tokens": ("%var_390",),
        "same_carrier_alias_proof": True,
    }
    assert {k: payload[k] for k in legacy_golden} == legacy_golden
