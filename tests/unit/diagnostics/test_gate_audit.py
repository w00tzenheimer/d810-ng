"""Tests for the gate-audit diag subcommand."""
from __future__ import annotations

import json
import textwrap
from pathlib import Path

import pytest

from d810.diagnostics.gate_audit import (
    AuditSummary,
    GateEvent,
    TRACKED_BYPASS_REASONS,
    parse_line,
    render_text_report,
    run_audit,
    scan_log_directory,
    scan_log_file,
    summary_exit_code,
    _parse_provenance_detail_gate_decisions,
)


# ---------------------------------------------------------------------------
# parse_line: per-pattern coverage
# ---------------------------------------------------------------------------


def _scan(line: str) -> AuditSummary:
    s = AuditSummary()
    parse_line(line, 1, s)
    return s


def test_gate_accounting_pattern_tracks_pass_fail_bypass() -> None:
    s = _scan("2026-05-11 ... Gate accounting: 3 passed, 1 failed, 2 bypassed")
    assert (s.passed, s.failed, s.bypassed, s.total) == (3, 1, 2, 6)
    assert s.bypass_reasons["<untracked>"] == 2
    # One event per untracked bypass.
    bypassed_events = [e for e in s.events if e.verdict == "BYPASSED"]
    assert len(bypassed_events) == 2
    assert all(e.source == "executor" for e in bypassed_events)


def test_safeguard_rejection_increments_counts_and_emits_failed_event() -> None:
    s = _scan(
        "Safeguard gate rejected stage s1: 0 passed, 1 failed, 0 bypassed"
    )
    assert (s.passed, s.failed, s.bypassed) == (0, 1, 0)
    assert s.events[0].source == "safeguard"
    assert "stage s1" in s.events[0].reason


def test_flow_context_gate_emits_failed_event_with_rule_name() -> None:
    s = _scan(
        "Skipping FixPredecessorOfConditionalJumpBlock via flow context gate:"
        " no rewritable predecessor"
    )
    assert s.failed == 1
    e = s.events[0]
    assert e.source == "flow_context"
    assert e.rule_name == "FixPredecessorOfConditionalJumpBlock"
    assert e.reason == "no rewritable predecessor"


def test_preconditioner_bypass_increments_tracked_reason() -> None:
    s = _scan("Gate bypassed [config_disabled]: MbaStatePreconditioner ...")
    assert s.bypassed == 1
    assert s.bypass_reasons["config_disabled"] == 1
    # config_disabled is tracked, so untracked count stays zero.
    assert s.untracked_bypasses == 0


def test_preconditioner_bypass_unknown_reason_is_untracked() -> None:
    s = _scan("Gate bypassed [some_new_reason]: SomeRule ...")
    assert s.bypassed == 1
    assert s.bypass_reasons["some_new_reason"] == 1
    assert s.untracked_bypasses == 1


def test_gate_skipped_is_distinct_from_bypassed() -> None:
    s = _scan(
        "Gate skipped [maturity_filter]: FixPred at maturity 16 not in scope"
    )
    assert s.skipped == 1
    assert s.bypassed == 0
    assert s.events[0].source == "gate_skip"


def test_provenance_summary_only_counts_bypassed() -> None:
    # APPLIED is intentionally NOT counted (already counted via accounting).
    s = _scan("Provenance: 1 APPLIED, 1 GATE_FAILED, 3 BYPASSED, 2 INAPPLICABLE")
    assert s.total == 3
    assert s.bypassed == 3
    assert s.bypass_reasons["pipeline_abort"] == 3
    # Bytes accounting from Provenance is "pipeline_abort", a tracked reason.
    assert s.untracked_bypasses == 0


def test_unrelated_line_is_ignored() -> None:
    s = _scan("INFO: unrelated chatter from the optimiser")
    assert s.total == 0
    assert s.events == []


# ---------------------------------------------------------------------------
# scan_log_file / scan_log_directory
# ---------------------------------------------------------------------------


_SAMPLE_LOG = textwrap.dedent(
    """\
    INFO: starting
    Gate accounting: 5 passed, 0 failed, 1 bypassed
    Skipping FooRule via flow context gate: some reason
    Gate bypassed [config_disabled]: BarRule extra notes
    Gate bypassed [mystery_reason]: BazRule
    Gate skipped [maturity_filter]: QuxRule
    Safeguard gate rejected stage stageZ: 0 passed, 1 failed, 0 bypassed
    Provenance: 1 APPLIED, 2 BYPASSED
    """
)


def _write_log(tmp_path: Path, name: str, body: str) -> Path:
    p = tmp_path / name
    p.write_text(body, encoding="utf-8")
    return p


def test_scan_log_file_aggregates_all_patterns(tmp_path: Path) -> None:
    log = _write_log(tmp_path, "d810.log", _SAMPLE_LOG)
    summary = scan_log_file(log)
    # Gate accounting (5+0+1) + flow_context (1 failed) + preconditioner bypass
    # (2 of them: config_disabled, mystery_reason) + gate_skip (1) + safeguard
    # (0+1+0) + provenance (2 bypassed).
    assert summary.passed == 5
    assert summary.failed == 1 + 1  # flow_context + safeguard
    assert summary.bypassed == 1 + 2 + 2  # accounting + preconditioner + provenance
    assert summary.skipped == 1
    assert summary.bypass_reasons["<untracked>"] == 1
    assert summary.bypass_reasons["config_disabled"] == 1
    assert summary.bypass_reasons["mystery_reason"] == 1
    assert summary.bypass_reasons["pipeline_abort"] == 2
    # Untracked = mystery_reason (1) + <untracked> (1).
    assert summary.untracked_bypasses == 2


def test_scan_log_directory_merges_multiple_files(tmp_path: Path) -> None:
    _write_log(tmp_path, "a.log", "Gate accounting: 1 passed, 0 failed, 0 bypassed\n")
    _write_log(tmp_path, "b.log", "Gate accounting: 0 passed, 2 failed, 0 bypassed\n")
    summary = scan_log_directory(tmp_path)
    assert summary.passed == 1
    assert summary.failed == 2


def test_scan_log_directory_empty_returns_empty_summary(tmp_path: Path) -> None:
    summary = scan_log_directory(tmp_path)
    assert summary.total == 0
    assert summary.events == []


# ---------------------------------------------------------------------------
# Provenance detail JSON
# ---------------------------------------------------------------------------


def test_provenance_detail_extracts_gate_decisions() -> None:
    payload = json.dumps({
        "rows": [
            {
                "strategy_name": "FixPred",
                "gate_accounting": [
                    {"verdict": "passed", "reason": "ok"},
                    {"verdict": "bypassed", "reason": "config_disabled"},
                ],
            },
            {
                "strategy_name": "BarRule",
                "gate_accounting": [
                    {"verdict": "FAILED", "reason": "predicate"},
                ],
            },
        ]
    })
    events = _parse_provenance_detail_gate_decisions(payload)
    assert len(events) == 3
    assert events[0].verdict == "PASSED"
    assert events[0].rule_name == "FixPred"
    assert events[2].verdict == "FAILED"


def test_provenance_detail_malformed_json_returns_empty() -> None:
    assert _parse_provenance_detail_gate_decisions("not json") == []
    assert _parse_provenance_detail_gate_decisions("{}") == []


# ---------------------------------------------------------------------------
# Reports + exit codes
# ---------------------------------------------------------------------------


def test_render_text_report_lists_bypass_breakdown(tmp_path: Path) -> None:
    log = _write_log(tmp_path, "d810.log", _SAMPLE_LOG)
    summary = scan_log_file(log)
    out = render_text_report(summary)
    assert "Gate Audit Summary" in out
    assert "Bypass breakdown by reason:" in out
    assert "config_disabled: 1" in out
    assert "mystery_reason: 1" in out
    assert "Untracked bypasses found -- FAIL" in out


def test_render_text_report_strict_flips_pass_fail() -> None:
    summary = AuditSummary(bypassed=2, bypass_reasons={"config_disabled": 2})
    strict_out = render_text_report(summary, strict=True)
    assert "STRICT MODE: 2 bypass(es) found -- FAIL" in strict_out
    # Non-strict treats config_disabled as tracked -> PASS.
    non_strict_out = render_text_report(summary, strict=False)
    assert "Zero untracked bypasses -- PASS" in non_strict_out


def test_summary_exit_code_default_only_untracked() -> None:
    s = AuditSummary(bypassed=3, bypass_reasons={"config_disabled": 3})
    assert summary_exit_code(s) == 0
    s.bypass_reasons["mystery"] = 1
    s.bypassed += 1
    assert summary_exit_code(s) == 1


def test_summary_exit_code_strict_any_bypass_fails() -> None:
    s = AuditSummary(bypassed=1, bypass_reasons={"config_disabled": 1})
    assert summary_exit_code(s, strict=False) == 0
    assert summary_exit_code(s, strict=True) == 1


def test_tracked_bypass_reasons_set_contains_known_codes() -> None:
    assert "config_disabled" in TRACKED_BYPASS_REASONS
    assert "pipeline_abort" in TRACKED_BYPASS_REASONS
    assert "mystery_reason" not in TRACKED_BYPASS_REASONS


# ---------------------------------------------------------------------------
# run_audit orchestrator
# ---------------------------------------------------------------------------


def test_run_audit_returns_zero_when_no_bypasses(tmp_path: Path) -> None:
    _write_log(tmp_path, "ok.log", "Gate accounting: 3 passed, 0 failed, 0 bypassed\n")
    text, rc = run_audit(tmp_path)
    assert rc == 0
    assert "Zero untracked bypasses -- PASS" in text


def test_run_audit_returns_one_on_untracked_bypass(tmp_path: Path) -> None:
    _write_log(
        tmp_path, "bad.log",
        "Gate bypassed [some_unknown_thing]: Rule\n",
    )
    text, rc = run_audit(tmp_path)
    assert rc == 1
    assert "FAIL" in text


def test_run_audit_strict_mode_fails_on_any_bypass(tmp_path: Path) -> None:
    _write_log(
        tmp_path, "strict.log",
        "Gate bypassed [config_disabled]: Rule\n",
    )
    text, rc_default = run_audit(tmp_path)
    assert rc_default == 0
    text_strict, rc_strict = run_audit(tmp_path, strict=True)
    assert rc_strict == 1
    assert "STRICT MODE" in text_strict


def test_run_audit_json_mode_emits_dict(tmp_path: Path) -> None:
    _write_log(
        tmp_path, "json.log",
        "Gate accounting: 1 passed, 0 failed, 1 bypassed\n",
    )
    text, rc = run_audit(tmp_path, as_json=True)
    payload = json.loads(text)
    assert payload["passed"] == 1
    assert payload["bypassed"] == 1
    assert payload["result"] == "FAIL"
    assert payload["strict_mode"] is False
    assert rc == 1


def test_run_audit_missing_path_returns_one_with_message(tmp_path: Path) -> None:
    missing = tmp_path / "does_not_exist"
    text, rc = run_audit(missing)
    assert rc == 1
    assert "does not exist" in text


def test_run_audit_accepts_single_log_file(tmp_path: Path) -> None:
    log = _write_log(tmp_path, "d810.log", "Gate accounting: 2 passed, 0 failed, 0 bypassed\n")
    text, rc = run_audit(log)
    assert rc == 0
    assert "Passed:                 2" in text
