from __future__ import annotations

from types import SimpleNamespace

from d810.manager.function_outcome import (
    FunctionOutcomeSummary,
    build_function_outcome,
    render_function_outcome,
)


def test_unchanged_ollvm_summary_names_the_blocker() -> None:
    summary = FunctionOutcomeSummary(
        function_ea=0x401000,
        function_name="sub_401000",
        classification="ollvm_flat",
        confidence=0.80,
        evaluated=9,
        applicable=0,
        applied=0,
        blocked_by=("input_identity_recovery_disabled",),
    )

    assert render_function_outcome(summary) == (
        "[D810] sub_401000: ollvm_flat (80%) -> unchanged; "
        "evaluated=9; applicable=0; applied=0; "
        "blocked_by=input_identity_recovery_disabled"
    )


def test_builder_uses_unique_planner_strategies_and_mutation_receipts() -> None:
    report = SimpleNamespace(
        consumer_name="hodur_planner",
        provenance_dict={
            "rows": [
                {"strategy_name": "cleanup-a", "phase": "inapplicable"},
                {"strategy_name": "cleanup-b", "phase": "selected"},
                {"strategy_name": "cleanup-b", "phase": "applied"},
            ]
        },
    )
    attempts = (
        SimpleNamespace(
            reason_code=None,
            effect_refs=(SimpleNamespace(kind="mutation_receipt", ref_id="r1"),),
        ),
        SimpleNamespace(
            reason_code=None,
            effect_refs=(SimpleNamespace(kind="mutation_receipt", ref_id="r1"),),
        ),
        SimpleNamespace(
            reason_code=None,
            effect_refs=(SimpleNamespace(kind="mba_instruction_edit", ref_id="r2"),),
        ),
    )

    summary = build_function_outcome(
        function_ea=0x401000,
        function_name="sub_401000",
        classification="ollvm_flat",
        confidence=0.8,
        reports=(report,),
        attempts=attempts,
    )

    assert summary.evaluated == 2
    assert summary.applicable == 1
    assert summary.applied == 2
    assert summary.blocked_by == ()


def test_builder_normalizes_expected_blockers_without_parsing_log_text() -> None:
    attempts = (
        SimpleNamespace(
            reason_code="input identity unavailable: recovery_disabled",
            effect_refs=(),
        ),
        SimpleNamespace(
            reason_code="no_modifications",
            effect_refs=(),
        ),
    )

    summary = build_function_outcome(
        function_ea=0x401000,
        function_name="",
        classification=None,
        confidence=None,
        reports=(),
        attempts=attempts,
    )

    assert summary.function_name == "sub_401000"
    assert summary.blocked_by == ("input_identity_recovery_disabled",)
    assert render_function_outcome(summary) == (
        "[D810] sub_401000: unclassified -> unchanged; evaluated=0; "
        "applicable=0; applied=0; blocked_by=input_identity_recovery_disabled"
    )
