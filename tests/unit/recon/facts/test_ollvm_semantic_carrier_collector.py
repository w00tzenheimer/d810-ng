"""Tests for OllvmValueFlowEvidenceCollector."""
from __future__ import annotations

from types import SimpleNamespace

from d810.core.diag.snapshot import BlockSnapshot, InstructionSnapshot
from d810.analyses.value_flow.ollvm_semantic_carrier import OllvmValueFlowEvidenceCollector
from d810.analyses.value_flow.induction_carrier import _MATURITY_VALUES


def _insn(
    *,
    index: int = 0,
    ea: int = 0x180010000,
    opcode_name: str = "op_4",
    dstr: str,
    dest_stkoff: int | None = None,
) -> InstructionSnapshot:
    return InstructionSnapshot(
        index=index,
        ea=ea,
        opcode=0,
        opcode_name=opcode_name,
        dest_type="mop_S" if dest_stkoff is not None else None,
        dest_stkoff=dest_stkoff,
        dest_size=8,
        src_l_type=None,
        src_l_stkoff=None,
        src_l_value=None,
        src_r_type=None,
        src_r_stkoff=None,
        src_r_value=None,
        dstr=dstr,
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
    return OllvmValueFlowEvidenceCollector().collect(
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
