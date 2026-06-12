"""Pure tests for the ``test_function_ollvm_fla_bcf_sub`` oracle."""
from __future__ import annotations

import json
import sqlite3

from tests.system.e2e.ollvm.ollvm_fla_bcf_sub_oracle import (
    evaluate_ollvm_fla_bcf_sub_oracle,
    prove_alias_multiply_add_equivalence,
    prove_terminal_bcf_forms_equivalent,
    prove_xor_select_equivalence,
    render_ollvm_fla_bcf_sub_oracle_report,
)


CURRENT_STYLE_AFTER = """
__int64 __fastcall test_function_ollvm_fla_bcf_sub(__int64 a1, unsigned int **a2)
{
    __int64 result;
    unsigned int i;
    unsigned int v5;
    _DWORD v8[3];
    _QWORD v28[2];

    MEMORY[0x180000000](v8, 0, 0x64);
    printf("Please enter password:");
    MEMORY[0x180000000]("%s", (const char *)v8);
    MEMORY[0x180000000](v8, "secret", 0x64);
    **a2 = 0;
    if ((v5 & 1) == 0)
    {
        for (i = 0; i < 0x64; ++i)
            v5 += *((char *)v8 + i) * LODWORD(v28[0]);
    }
    **a2 = v5 ^ 0x173063C1;
    **a2 = (v5 ^ ~v5) & 0xCD536960 ^ ~v5 ^ 0x259CF55E;
    return result;
}
"""


def _diag_db_with_carrier_facts() -> sqlite3.Connection:
    conn = sqlite3.connect(":memory:")
    conn.execute(
        "CREATE TABLE fact_observations ("
        "snapshot_id INTEGER, kind TEXT, fact_id TEXT, func_ea_hex TEXT, payload TEXT)"
    )
    rows = [
        {"role": "ARG_INPUT_POINTER", "carrier_token": "%var_38"},
        {"role": "ARG_OUTPUT_POINTER", "carrier_token": "%var_30"},
        {"role": "PASSWORD_BUFFER", "carrier_token": "%var_98"},
        {"role": "PASSWORD_COMPARE_RESULT", "carrier_token": "%var_58"},
        {"role": "LOOP_INDEX_CARRIER", "carrier_token": "%var_398"},
        {
            "role": "ACCUMULATOR_CARRIER",
            "carrier_token": "%var_378",
            "instruction_dstr": (
                "stx ((#5.4*[ds.2:%var_378.8].4)+[ds.2:%var_390.8].4), "
                "ds.2, %var_378.8"
            ),
            "same_carrier_alias_proof": True,
        },
        {
            "role": "ACCUMULATOR_CARRIER",
            "carrier_token": "%var_378",
            "instruction_dstr": "stx ([ds.2:%var_378.8].4+#0x42.4), ds.2, %var_378.8",
        },
        {
            "role": "ACCUMULATOR_CARRIER",
            "carrier_token": "%var_378",
            "instruction_dstr": (
                "stx ((bnot(low.1([ds.2:%var_378.8].4)) & #0x42.1) | "
                "([ds.2:%var_378.8].4 & #0xFFFFFFBD.4)), ds.2, %var_378.8"
            ),
        },
        {
            "role": "ARG_OUTPUT_STORE_CANDIDATE",
            "carrier_token": "%var_30",
            "instruction_dstr": (
                "stx ((([ds.2:%var_378.8].4 ^ bnot([ds.2:%var_378.8].4)) "
                "& #0xCD536960.4) ^ #0x259CF55E.4), ds.2, [ds.2:%var_30.8].8"
            ),
        },
    ]
    for index, payload in enumerate(rows):
        conn.execute(
            "INSERT INTO fact_observations VALUES (?,?,?,?,?)",
            (
                1,
                "OllvmValueFlowEvidence",
                f"fact-{index}",
                "0x000000018000e360",
                json.dumps(payload),
            ),
        )
    return conn


def test_mba_equivalence_proofs_are_exact_for_current_constants() -> None:
    assert prove_alias_multiply_add_equivalence()
    assert prove_xor_select_equivalence()
    assert prove_terminal_bcf_forms_equivalent()


def test_oracle_accepts_current_style_after_with_fact_backing() -> None:
    conn = _diag_db_with_carrier_facts()

    result = evaluate_ollvm_fla_bcf_sub_oracle(
        CURRENT_STYLE_AFTER,
        conn=conn,
        func_ea_hex="0x000000018000e360",
    )

    assert result.passed
    assert result.fact_summary is not None
    assert result.fact_summary.role_counts["ACCUMULATOR_CARRIER"] == 3
    assert result.fact_summary.alias_multiply_add_proof_count == 1
    warning = next(
        check for check in result.checks
        if check.name == "return_result_is_presentation_artifact"
    )
    assert not warning.passed
    assert not warning.blocker


def test_oracle_accepts_counted_do_while_payload_loop() -> None:
    do_while_after = CURRENT_STYLE_AFTER.replace(
        "for (i = 0; i < 0x64; ++i)\n            v5 += *((char *)v8 + i) * LODWORD(v28[0]);",
        (
            "i = 0;\n"
            "        do\n"
            "        {\n"
            "            v5 += *((char *)v8 + i) * LODWORD(v28[0]);\n"
            "            ++i;\n"
            "        }\n"
            "        while ( i < 0x64 );"
        ),
    )

    result = evaluate_ollvm_fla_bcf_sub_oracle(
        do_while_after,
        conn=_diag_db_with_carrier_facts(),
        func_ea_hex="0x000000018000e360",
    )

    assert result.passed


def test_oracle_accepts_folded_single_xor_terminal_write() -> None:
    # The true original has a SINGLE terminal write, ``carrier ^ 0x173063C1``.
    # With fold_writable_constants on, the dead BCF second write
    # (``& 0xCD536960 ... ^ 0x259CF55E``) is correctly DCE'd.  The oracle must
    # ACCEPT this -- it must not require the obfuscation-noise constants.
    folded_after = CURRENT_STYLE_AFTER.replace(
        "\n    **a2 = (v5 ^ ~v5) & 0xCD536960 ^ ~v5 ^ 0x259CF55E;", ""
    )
    assert "0xCD536960" not in folded_after
    assert "0x259CF55E" not in folded_after

    result = evaluate_ollvm_fla_bcf_sub_oracle(
        folded_after,
        conn=_diag_db_with_carrier_facts(),
        func_ea_hex="0x000000018000e360",
    )

    assert result.passed
    terminal = next(
        check for check in result.checks
        if check.name == "terminal_bcf_forms_equivalent"
    )
    assert terminal.passed


def test_oracle_accepts_output_sink_through_a2_local_alias() -> None:
    alias_after = CURRENT_STYLE_AFTER.replace(
        "unsigned int **a2)",
        "int *a2)",
    ).replace(
        "    __int64 result;\n",
        "    __int64 result;\n    int *v25;\n",
    ).replace(
        "    MEMORY[0x180000000](v8, 0, 0x64);\n",
        "    v25 = a2;\n    MEMORY[0x180000000](v8, 0, 0x64);\n",
    ).replace(
        "    **a2 = v5 ^ 0x173063C1;",
        "    *v25 = v5 ^ 0x173063C1;",
    ).replace(
        "\n    **a2 = (v5 ^ ~v5) & 0xCD536960 ^ ~v5 ^ 0x259CF55E;",
        "",
    )

    result = evaluate_ollvm_fla_bcf_sub_oracle(
        alias_after,
        conn=_diag_db_with_carrier_facts(),
        func_ea_hex="0x000000018000e360",
    )

    assert result.passed


def test_oracle_accepts_native_global_string_compare_rendering() -> None:
    native_after = """
__int64 __fastcall test_function_ollvm_fla_bcf_sub(__int64 a1, int *a2)
{
    unsigned int v2;
    __int64 result;
    unsigned int i;
    _DWORD *v7;
    struct HINSTANCE__ v8[3];
    int *v27;
    _QWORD v29[2];

    v27 = a2;
    v7 = v29;
    _ImageBase(v8, 0, (LPVOID)0x64);
    printf("Please enter password:");
    _ImageBase((HINSTANCE)&hinstDLL, (DWORD)v8, v29);
    _ImageBase(v8, (DWORD)&hinstDLL.unused + 3, (LPVOID)0x64);
    for ( i = 0; i < 0x64; ++i )
    {
        v2 = i;
        LODWORD(v7) = (_DWORD)v7 + *((char *)&v8[0].unused + v2) * (unsigned int)v29;
    }
    *v27 = (~*v7 ^ *v7) & 0x173063C1 ^ *v7;
    return result;
}
"""

    result = evaluate_ollvm_fla_bcf_sub_oracle(
        native_after,
        conn=_diag_db_with_carrier_facts(),
        func_ea_hex="0x000000018000e360",
    )

    assert result.passed


def test_oracle_accepts_assignment_form_payload_loop_update() -> None:
    assignment_after = CURRENT_STYLE_AFTER.replace(
        "            v5 += *((char *)v8 + i) * LODWORD(v28[0]);",
        (
            "        {\n"
            "            v2 = i;\n"
            "            LODWORD(v5) = (_DWORD)v5 + *((char *)v8 + v2) * (unsigned int)v28;\n"
            "        }"
        ),
    )

    result = evaluate_ollvm_fla_bcf_sub_oracle(
        assignment_after,
        conn=_diag_db_with_carrier_facts(),
        func_ea_hex="0x000000018000e360",
    )

    assert result.passed


def test_oracle_accepts_numbered_dump_payload_loop_output_alias() -> None:
    dump_after = """
__int64 __fastcall test_function_ollvm_fla_bcf_sub(__int64 a1, int *a2)
{
    __int64 result;
    unsigned int i;
    int v2;
    _DWORD *v5;
    _BYTE v6[100];
    int *v25;
    _QWORD v27[2];

    v25 = a2;
    v5 = v27;
    MEMORY[0x180000000](v6, 0, 0x64);
    printf("Please enter password:");
    MEMORY[0x180000000]("%s", (const char *)v6);
    MEMORY[0x180000000](v6, "secret", 0x64);
    for ( i = 0; i < 0x64; ++i )
    {
        v2 = i;
        LODWORD(v5) = (_DWORD)v5 + *((char *)v6 + v2) * (unsigned int)v27;
    }
    *v25 = (~*v5 ^ *v5) & 0x173063C1 ^ *v5;
    return result;
}
""".strip("\n")
    numbered_after = "\n".join(
        f"{202300 + index}: {line}"
        for index, line in enumerate(dump_after.splitlines())
    )

    result = evaluate_ollvm_fla_bcf_sub_oracle(
        numbered_after,
        conn=_diag_db_with_carrier_facts(),
        func_ea_hex="0x000000018000e360",
    )

    assert result.passed


def test_oracle_rejects_non_counted_dispatcher_while_loop() -> None:
    residual_dispatcher_after = CURRENT_STYLE_AFTER.replace(
        "for (i = 0; i < 0x64; ++i)",
        "while ( selector != 0x62CE9A1C )",
    )

    result = evaluate_ollvm_fla_bcf_sub_oracle(
        residual_dispatcher_after,
        conn=_diag_db_with_carrier_facts(),
        func_ea_hex="0x000000018000e360",
    )

    assert not result.passed
    assert any(
        blocker.name == "dispatcher_loop_removed" for blocker in result.blockers
    )


def test_oracle_rejects_self_feeding_loop_even_with_fact_backed_carrier_split() -> None:
    bad_code = CURRENT_STYLE_AFTER.replace(
        "for (i = 0; i < 0x64; ++i)",
        "for (i = 0; i < 0x64; i += *((char *)v8 + i) * v5)",
    )

    result = evaluate_ollvm_fla_bcf_sub_oracle(
        bad_code,
        conn=_diag_db_with_carrier_facts(),
        func_ea_hex="0x000000018000e360",
    )

    assert not result.passed
    assert any(
        blocker.name == "clean_counted_loop" for blocker in result.blockers
    )


def test_oracle_rejects_current_self_feeding_do_while_loop() -> None:
    bad_code = CURRENT_STYLE_AFTER.replace(
        "for (i = 0; i < 0x64; ++i)\n            v5 += *((char *)v8 + i) * LODWORD(v28[0]);",
        (
            "LODWORD(v29[0]) = 0;\n"
            "        do\n"
            "        {\n"
            "            v2 = v29[0];\n"
            "            v3 = LODWORD(v29[0])++;\n"
            "            LODWORD(v29[0]) += *((char *)&v8[0].unused + v3) * v2;\n"
            "        }\n"
            "        while ( LODWORD(v29[0]) < 0x64 );"
        ),
    )

    result = evaluate_ollvm_fla_bcf_sub_oracle(
        bad_code,
        conn=_diag_db_with_carrier_facts(),
        func_ea_hex="0x000000018000e360",
    )

    assert not result.passed
    assert any(
        blocker.name == "clean_counted_loop" for blocker in result.blockers
    )


def test_oracle_rejects_empty_parity_do_while_loop() -> None:
    bad_code = CURRENT_STYLE_AFTER.replace(
        "for (i = 0; i < 0x64; ++i)\n            v5 += *((char *)v8 + i) * LODWORD(v28[0]);",
        "do\n            v4[3] = 0x50B4560;\n        while ( (v5 & 1) != 0 );",
    )

    result = evaluate_ollvm_fla_bcf_sub_oracle(
        bad_code,
        conn=_diag_db_with_carrier_facts(),
        func_ea_hex="0x000000018000e360",
    )

    assert not result.passed
    assert any(
        blocker.name == "dispatcher_loop_removed" for blocker in result.blockers
    )
    assert any(
        blocker.name == "clean_counted_loop" for blocker in result.blockers
    )


def test_oracle_rejects_missing_carrier_fact_roles() -> None:
    conn = sqlite3.connect(":memory:")
    conn.execute(
        "CREATE TABLE fact_observations ("
        "snapshot_id INTEGER, kind TEXT, fact_id TEXT, func_ea_hex TEXT, payload TEXT)"
    )

    result = evaluate_ollvm_fla_bcf_sub_oracle(
        CURRENT_STYLE_AFTER,
        conn=conn,
        func_ea_hex="0x000000018000e360",
    )

    assert not result.passed
    assert any(
        blocker.name == "fact_role_accumulator_carrier"
        for blocker in result.blockers
    )


def test_oracle_rejects_return_result_without_output_sink() -> None:
    bad_code = """
    __int64 __fastcall test_function_ollvm_fla_bcf_sub(__int64 a1, __int64 a2)
    {
        __int64 result;
        printf("Please enter password:");
        MEMORY[0x180000000]("%s", a1);
        MEMORY[0x180000000](a1, "secret", 0x64);
        for (i = 0; i < 0x64; ++i)
            v5 += *((char *)v8 + i) * LODWORD(v28[0]);
        v5 = v5 ^ 0x173063C1;
        v5 = (v5 ^ ~v5) & 0xCD536960 ^ ~v5 ^ 0x259CF55E;
        return result;
    }
    """

    result = evaluate_ollvm_fla_bcf_sub_oracle(
        bad_code,
        conn=_diag_db_with_carrier_facts(),
        func_ea_hex="0x000000018000e360",
    )

    assert not result.passed
    assert any(blocker.name == "sink_present" for blocker in result.blockers)
    assert any(
        blocker.name == "return_result_is_presentation_artifact"
        for blocker in result.blockers
    )


def test_oracle_requires_alias_proof_for_multiply_add() -> None:
    conn = _diag_db_with_carrier_facts()
    conn.execute(
        "UPDATE fact_observations SET payload = replace("
        "payload, '\"same_carrier_alias_proof\": true', "
        "'\"same_carrier_alias_proof\": false')"
    )

    result = evaluate_ollvm_fla_bcf_sub_oracle(
        CURRENT_STYLE_AFTER,
        conn=conn,
        func_ea_hex="0x000000018000e360",
    )

    assert not result.passed
    assert any(
        blocker.name == "fact_alias_multiply_add_same_carrier"
        for blocker in result.blockers
    )


def test_report_marks_return_artifact_as_warning() -> None:
    result = evaluate_ollvm_fla_bcf_sub_oracle(
        CURRENT_STYLE_AFTER,
        conn=_diag_db_with_carrier_facts(),
        func_ea_hex="0x000000018000e360",
    )

    report = render_ollvm_fla_bcf_sub_oracle_report(
        result,
        func_ea_hex="0x000000018000e360",
    )

    assert "Status: `pass`" in report
    assert "`return_result_is_presentation_artifact` | `warn`" in report
