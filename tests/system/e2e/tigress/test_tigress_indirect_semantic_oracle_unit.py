"""Pure tests for the ``tigress_flatten_indirect`` semantic oracle."""
from __future__ import annotations

from tests.system.e2e.tigress.tigress_indirect_semantic_oracle import (
    d810_features,
    diff_features,
    evaluate_tigress_indirect_semantic_oracle,
    format_diff_table,
    inputs_from_transfer_report,
    is_registered,
    ref_features,
    render_tigress_indirect_semantic_oracle_report,
    spec_for,
)


CURRENT_STYLE_AFTER = """
void __fastcall tigress_flatten_indirect(int *a1, _DWORD *a2)
{
    int v4;
    int v5;
    unsigned int i;
    unsigned int v7;
    int v9;
    unsigned int v10;
    int v11;
    int v14;
    _QWORD v15[38];
    char v16[112];

    MEMORY[0x180000000](v15, &off_180019F10, 0x128);
    while ( 1 )
    {
        MEMORY[0x180000000]("%s", v16);
        v4 = *a1;
        if ( (((((int)(v4 - v7) >> 0x1F) & (2 * (v4 - v7))) - (v4 - v7)) >> 0x1F)
           | ((unsigned int)MEMORY[0x180000000](v16, "secret", 0x64) != 0)
           | v5 )
        {
            *a2 = 0;
        }

        if ( v9 + (~v9 | 1) != 0xFFFFFFFF )
            break;

        v16[0] = 0;
        for ( i = 1;
              ((~(i - 0x64) | i ^ 0x64) & (i | 0xFFFFFF9B) & 0x80000000) == 0;
              i = (i ^ 0xFFFFFFFE) + ((2 * i) | 2) + 1 )
        {
            v16[i] = 0;
        }

        v5 = 0;
        MEMORY[0x180000000](&v14, 0);
        v7 = 0xD32B5931;
        v9 = (*a1 & 0x26C76F03) + (*a1 | 0x26C76F03);
        printf("Please enter password:");
    }

    v11 = (v9 & 0xFFFFFFFA) * (~(_BYTE)v9 & 5) + (v9 | 5) * (v9 & 5) + v4;
    if ( (v11 & 3) != 0 )
    {
        if ( (v11 & 3) == 1 )
            v10 = (v11 ^ 0xFFFFFFBD) + 2 * (v11 | 0x42) + 1;
        else
            v10 = v11 - 0x42;
    }
    else
    {
        v10 = (v11 | 0x42) - (v11 & 0x42);
    }

    *a2 = v10 - 2 * (v10 | 0xE8CF9C3E) - 0x173063C3;
}
"""


def _transfer(
    state: int,
    *,
    kind: str,
    next_states: tuple[int, ...] = (),
) -> dict:
    return {
        "state": state,
        "state_hex": f"0x{state:x}",
        "target_block": 100 + state,
        "target_ea": f"0x{0x180017000 + state:x}",
        "kind": kind,
        "next_states": list(next_states),
        "terminal": kind == "terminal",
        "unresolved": kind == "unresolved",
        "complete_path_count": 0 if kind == "terminal" else max(1, len(next_states)),
        "terminal_path_count": 1 if kind == "terminal" else 0,
        "unresolved_path_count": 1 if kind == "unresolved" else 0,
        "paths": [],
        "terminal_paths": [],
        "unresolved_paths": [],
    }


def _transfer_report() -> dict:
    conditional = {
        0x05: (0x0C, 0x11),
        0x1C: (0x0B, 0x20),
        0x1D: (0x04, 0x19),
        0x21: (0x02, 0x05),
        0x24: (0x08, 0x0D, 0x1E),
    }
    terminal = {0x11, 0x16, 0x17}
    transfers = []
    for state in range(1, 38):
        if state in conditional:
            transfers.append(
                _transfer(state, kind="conditional", next_states=conditional[state])
            )
        elif state in terminal:
            transfers.append(_transfer(state, kind="terminal"))
        else:
            transfers.append(
                _transfer(state, kind="direct", next_states=((state % 37) + 1,))
            )
    return {
        "snapshot": {
            "id": 1,
            "label": "maturity_MMAT_LOCOPT_pre_d810",
            "maturity": "MMAT_LOCOPT",
            "phase": "pre_d810",
            "block_count": 60,
            "dispatcher_entry_block": 16,
            "row_count": 37,
            "missing_count": 0,
        },
        "z3_bounds_proof": {
            "proved_non_negative_index": True,
            "proved_table_upper_bound": True,
            "observed_state_count": 37,
        },
        "table_invariance": {
            "proved_invariant": True,
            "explicit_overlapping_writes": [],
            "suspicious_calls": [],
            "initializer_calls": [],
        },
        "transfers": transfers,
    }


def _passing_inputs():
    return inputs_from_transfer_report(
        _transfer_report(),
        initial_state=0x22,
        repaired_handoffs={
            0x11: 0x24,
            0x16: 0x1B,
        },
        pseudocode=CURRENT_STYLE_AFTER,
    )


def test_spec_registration_accepts_original_and_flattened_names() -> None:
    assert is_registered("test_function_original")
    assert is_registered("tigress_flatten_indirect")
    assert spec_for("unknown_function") is None


def test_ref_features_capture_expected_state_handoffs() -> None:
    spec = spec_for("tigress_flatten_indirect")
    assert spec is not None
    features = {feature.feature: feature for feature in ref_features(spec)}

    assert features["state_count"].value == 37
    assert features["initial_state"].value == 0x22
    assert features["state_0x11_handoff_target"].value == 0x24
    assert features["state_0x16_handoff_target"].value == 0x1B
    assert features["terminal_states"].value == (0x17,)


def test_oracle_accepts_current_style_after_with_repaired_handoffs() -> None:
    result = evaluate_tigress_indirect_semantic_oracle(_passing_inputs())

    assert result.passed
    assert not result.blockers
    assert not result.diffs


def test_oracle_rejects_unrepaired_terminal_handoff_stubs() -> None:
    inputs = inputs_from_transfer_report(
        _transfer_report(),
        initial_state=0x22,
        pseudocode=CURRENT_STYLE_AFTER,
    )

    result = evaluate_tigress_indirect_semantic_oracle(inputs)

    assert not result.passed
    blocker_names = {blocker.name for blocker in result.blockers}
    assert "terminal_states" in blocker_names
    assert "state_0x11_handoff_target" in blocker_names
    assert "state_0x16_handoff_target" in blocker_names


def test_oracle_rejects_raw_indirect_jump_or_jumpoout() -> None:
    inputs = inputs_from_transfer_report(
        _transfer_report(),
        initial_state=0x22,
        repaired_handoffs={0x11: 0x24, 0x16: 0x1B},
        pseudocode=CURRENT_STYLE_AFTER + "\nJUMPOUT(rax);\n",
    )

    result = evaluate_tigress_indirect_semantic_oracle(inputs)

    assert not result.passed
    assert any(
        blocker.name == "no_raw_indirect_jump" for blocker in result.blockers
    )


def test_diffs_show_missing_table_proof_without_changing_ref_policy() -> None:
    report = _transfer_report()
    report["table_invariance"]["proved_invariant"] = False
    inputs = inputs_from_transfer_report(
        report,
        initial_state=0x22,
        repaired_handoffs={0x11: 0x24, 0x16: 0x1B},
        pseudocode=CURRENT_STYLE_AFTER,
    )

    result = evaluate_tigress_indirect_semantic_oracle(inputs)

    assert not result.passed
    assert any(
        blocker.name == "table_invariant_proved" for blocker in result.blockers
    )
    assert not result.diffs


def test_feature_diff_and_report_render_markdown() -> None:
    spec = spec_for("tigress_flatten_indirect")
    assert spec is not None
    bad_inputs = inputs_from_transfer_report(
        _transfer_report(),
        initial_state=0x21,
        repaired_handoffs={0x11: 0x24, 0x16: 0x1B},
        pseudocode=CURRENT_STYLE_AFTER,
    )
    diffs = diff_features(ref_features(spec), d810_features(bad_inputs))

    table = format_diff_table(diffs)
    assert "| feature | region | REF | D810 |" in table
    assert "|-|-|-|-|" in table
    assert "initial_state" in table

    result = evaluate_tigress_indirect_semantic_oracle(_passing_inputs())
    report = render_tigress_indirect_semantic_oracle_report(
        result,
        func_name="tigress_flatten_indirect",
    )
    assert "Status: `pass`" in report
    assert "`state_0x11_handoff_target` | `pass`" in report
