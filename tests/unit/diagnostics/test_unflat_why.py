"""Unit tests for ``python -m d810.diagnostics unflat-why`` (ticket d81-k1ct).

Builds fixture diag DBs with :func:`create_diag_database` (schema v13) and
asserts the rendered causal-order report per disposition class, the retry
collapsing rule, the "not recorded" absent-evidence rule, and the graceful
degrade path for a diag DB that predates the ``unflatten_candidate_outcomes``
table (schema v12).
"""

from __future__ import annotations

import sqlite3
from pathlib import Path

import pytest

from d810.core.diag import create_diag_database
from d810.diagnostics.__main__ import main
from d810.diagnostics.unflat_why import render_session_list, render_unflat_why

FUNC_EA = 0x7FFB0EB06E50
FUNC_EA_HEX = "0x00007ffb0eb06e50"


def _make_db(tmp_path: Path, name: str = "diag.sqlite3") -> tuple[sqlite3.Connection, Path]:
    db_path = tmp_path / name
    diag_db = create_diag_database(str(db_path))
    conn = diag_db.connection()
    conn.row_factory = sqlite3.Row
    return conn, db_path


def _insert_outcome(
    conn: sqlite3.Connection,
    *,
    event_id: int,
    func_ea: int = FUNC_EA,
    func_ea_hex: str = FUNC_EA_HEX,
    session_id: str = "s1",
    maturity: str = "MMAT_GLBOPT1",
    graph_fingerprint: str = "fp-1",
    candidate_identity: str = "cand-1",
    attempt: int = 1,
    disposition: str = "not_submitted_safe_bail",
    reason: str = "no_plan_submitted",
    plan_id: str | None = None,
    handlers_recovered: int | None = None,
    handlers_total: int | None = None,
    dag_nodes: int | None = None,
    dag_edges: int | None = None,
    coverage_covered: int | None = None,
    coverage_residual: int | None = None,
    committed_batches_before: int = 0,
    unresolved_anchors_json: str = "[]",
    next_hint: str = "python -m d810.diagnostics unflat-why --db D --func 0x1",
) -> None:
    conn.execute(
        """
        INSERT INTO unflatten_candidate_outcomes
            (event_id, session_id, func_ea_hex, func_ea_i64, maturity,
             graph_fingerprint, candidate_identity, attempt, disposition,
             reason, plan_id, handlers_recovered, handlers_total, dag_nodes,
             dag_edges, coverage_covered, coverage_residual,
             committed_batches_before, unresolved_anchors_json, next_hint)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            event_id,
            session_id,
            func_ea_hex,
            func_ea,
            maturity,
            graph_fingerprint,
            candidate_identity,
            attempt,
            disposition,
            reason,
            plan_id,
            handlers_recovered,
            handlers_total,
            dag_nodes,
            dag_edges,
            coverage_covered,
            coverage_residual,
            committed_batches_before,
            unresolved_anchors_json,
            next_hint,
        ),
    )


def _insert_snapshot(
    conn: sqlite3.Connection,
    *,
    snapshot_id: int,
    label: str,
    func_ea: int = FUNC_EA,
    func_ea_hex: str = FUNC_EA_HEX,
    maturity: str = "MMAT_GLBOPT1",
    phase: str = "pre_d810",
) -> None:
    conn.execute(
        """
        INSERT INTO snapshots
            (id, label, func_ea_hex, func_ea_i64, maturity, phase, block_count, timestamp)
        VALUES (?, ?, ?, ?, ?, ?, 0, 0.0)
        """,
        (snapshot_id, label, func_ea_hex, func_ea, maturity, phase),
    )


def _insert_fact(
    conn: sqlite3.Connection,
    *,
    snapshot_id: int,
    fact_id: str,
    kind: str,
    payload: str,
    func_ea: int = FUNC_EA,
    func_ea_hex: str = FUNC_EA_HEX,
    maturity: str = "MMAT_GLBOPT1",
    phase: str = "post_pipeline",
) -> None:
    conn.execute(
        """
        INSERT INTO fact_observations
            (snapshot_id, func_ea_hex, func_ea_i64, fact_id, kind,
             semantic_key, maturity, phase, confidence, payload, evidence)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, 1.0, ?, '{}')
        """,
        (
            snapshot_id,
            func_ea_hex,
            func_ea,
            fact_id,
            kind,
            fact_id,
            maturity,
            phase,
            payload,
        ),
    )


def _insert_cfg_attempt(
    conn: sqlite3.Connection,
    *,
    plan_id: str,
    attempt_id: str,
    func_ea: int = FUNC_EA,
    func_ea_hex: str = FUNC_EA_HEX,
    session_id: str = "s1",
    current_phase: str = "committed",
    poisoned: int = 0,
    first_failure_obligation: str | None = None,
    first_failure_phase: str | None = None,
    first_failure_reason: str | None = None,
) -> None:
    conn.execute(
        """
        INSERT INTO cfg_transaction_attempts
            (plan_id, attempt_id, session_id, func_ea_hex, func_ea_i64,
             current_phase, mba_generation, evidence_generation,
             mutation_started, poisoned, first_failure_obligation,
             first_failure_phase, first_failure_reason, interr_code)
        VALUES (?, ?, ?, ?, ?, ?, 0, 0, 1, ?, ?, ?, ?, NULL)
        """,
        (
            plan_id,
            attempt_id,
            session_id,
            func_ea_hex,
            func_ea,
            current_phase,
            poisoned,
            first_failure_obligation,
            first_failure_phase,
            first_failure_reason,
        ),
    )


def _insert_recovery_search(
    conn: sqlite3.Connection,
    *,
    event_id: int,
    func_ea: int = FUNC_EA,
    func_ea_hex: str = FUNC_EA_HEX,
    session_id: str = "s1",
    provider: str = "region_seeded",
    outcome: str = "completed",
    budget: int = 50000,
    consumed: int = 9,
    reason: str = "region-seeded DFS completed",
) -> None:
    conn.execute(
        """
        INSERT INTO recovery_search_outcomes
            (event_id, session_id, func_ea_hex, func_ea_i64, provider,
             outcome, budget, consumed, target_anchors_json,
             entry_anchors_json, reason)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, '[]', '[]', ?)
        """,
        (event_id, session_id, func_ea_hex, func_ea, provider, outcome, budget, consumed, reason),
    )


# ---------------------------------------------------------------------------
# Pure render_unflat_why over a fixture DB, one per disposition class
# ---------------------------------------------------------------------------


class TestNotSubmittedSafeBail:
    def test_renders_the_terminal_outcome_and_next_step(self, tmp_path):
        conn, _ = _make_db(tmp_path)
        _insert_outcome(
            conn,
            event_id=1,
            disposition="not_submitted_safe_bail",
            reason="residual_dispatcher_corridor",
            coverage_covered=0,
            coverage_residual=158,
        )
        conn.commit()

        lines = render_unflat_why(conn, FUNC_EA)
        text = "\n".join(lines)
        assert f"unflat-why func=0x{FUNC_EA:x}" in text
        assert "disposition=not_submitted_safe_bail" in text
        assert "reason=residual_dispatcher_corridor" in text
        assert "safe bail:" in text


class TestExhausted:
    def test_renders_the_terminal_outcome_and_next_step(self, tmp_path):
        conn, _ = _make_db(tmp_path)
        _insert_outcome(
            conn,
            event_id=1,
            disposition="exhausted",
            reason="all_candidates_excluded_for_graph",
        )
        conn.commit()

        text = "\n".join(render_unflat_why(conn, FUNC_EA))
        assert "disposition=exhausted" in text
        assert "exhausted:" in text
        assert "recovery excluded this exact candidate identity" in text


class TestRejectedPreflight:
    def test_renders_the_terminal_outcome_and_next_step(self, tmp_path):
        conn, _ = _make_db(tmp_path)
        _insert_outcome(
            conn,
            event_id=1,
            disposition="rejected_preflight",
            reason="obligation_violated",
        )
        conn.commit()

        text = "\n".join(render_unflat_why(conn, FUNC_EA))
        assert "disposition=rejected_preflight" in text
        assert "rejected at preflight:" in text


class TestAppliedObserved:
    def test_renders_the_terminal_outcome_and_next_step(self, tmp_path):
        conn, _ = _make_db(tmp_path)
        _insert_outcome(
            conn,
            event_id=1,
            maturity="MMAT_GLBOPT2",
            disposition="applied_observed",
            reason="cfg_transaction_committed",
            plan_id="plan-abc",
        )
        conn.commit()

        text = "\n".join(render_unflat_why(conn, FUNC_EA))
        assert "disposition=applied_observed" in text
        assert "plan_id=plan-abc" in text
        assert "applied:" in text


class TestMaturityNoCallbacks:
    def test_renders_snapshot_list_and_flags_the_missing_marker(self, tmp_path):
        conn, _ = _make_db(tmp_path)
        _insert_outcome(
            conn,
            event_id=1,
            maturity="MMAT_GLBOPT1",
            candidate_identity="",
            graph_fingerprint="",
            attempt=0,
            disposition="maturity_no_callbacks",
            reason="hexrays_delivered_no_optblock_callback",
        )
        _insert_snapshot(
            conn,
            snapshot_id=1,
            label="maturity_MMAT_CALLS_post_d810",
            maturity="MMAT_CALLS",
            phase="post_d810",
        )
        _insert_snapshot(
            conn,
            snapshot_id=2,
            label="maturity_MMAT_GLBOPT2_pre_d810",
            maturity="MMAT_GLBOPT2",
            phase="pre_d810",
        )
        conn.commit()

        text = "\n".join(render_unflat_why(conn, FUNC_EA))
        assert "disposition=maturity_no_callbacks" in text
        assert "maturity_MMAT_CALLS_post_d810" in text
        assert "maturity_MMAT_GLBOPT2_pre_d810" in text
        assert "missing: maturity_MMAT_GLBOPT1_pre_d810" in text
        assert "d81-lbe8 class" in text

    def test_does_not_flag_the_marker_when_present(self, tmp_path):
        conn, _ = _make_db(tmp_path)
        _insert_outcome(
            conn,
            event_id=1,
            maturity="MMAT_GLBOPT1",
            disposition="maturity_no_callbacks",
            reason="hexrays_delivered_no_optblock_callback",
        )
        _insert_snapshot(
            conn,
            snapshot_id=1,
            label="maturity_MMAT_GLBOPT1_pre_d810",
            maturity="MMAT_GLBOPT1",
            phase="pre_d810",
        )
        conn.commit()

        text = "\n".join(render_unflat_why(conn, FUNC_EA))
        assert "missing: maturity_MMAT_GLBOPT1_pre_d810" not in text


class TestPoisonedRestartRequired:
    def test_renders_the_rejecting_obligation_and_committed_count(self, tmp_path):
        conn, _ = _make_db(tmp_path)
        # Two prior committed batches on other plans, then the poisoned one.
        _insert_cfg_attempt(conn, plan_id="plan-1", attempt_id="attempt-1", current_phase="committed")
        _insert_cfg_attempt(conn, plan_id="plan-2", attempt_id="attempt-2", current_phase="committed")
        _insert_cfg_attempt(
            conn,
            plan_id="plan-3",
            attempt_id="attempt-3",
            current_phase="poisoned_restart_required",
            poisoned=1,
            first_failure_obligation="runtime:post_observation_contract",
            first_failure_phase="post_observation_contract",
            first_failure_reason="observed unflatten authority rejected: reason=live_binding_failed",
        )
        _insert_outcome(
            conn,
            event_id=1,
            maturity="MMAT_GLBOPT1",
            graph_fingerprint="plan-3",
            candidate_identity="attempt-3",
            attempt=8,
            disposition="poisoned_restart_required",
            reason="observed unflatten authority rejected: reason=live_binding_failed",
            committed_batches_before=2,
        )
        conn.commit()

        text = "\n".join(render_unflat_why(conn, FUNC_EA))
        assert "disposition=poisoned_restart_required" in text
        assert "first_failure_obligation=runtime:post_observation_contract" in text
        assert "first_failure_phase=post_observation_contract" in text
        assert "committed_before=2" in text
        assert "poisoned: the rejecting obligation is named" in text
        assert "attempt=attempt-3" in text


# ---------------------------------------------------------------------------
# Retry collapsing
# ---------------------------------------------------------------------------


class TestRetryCollapsing:
    def test_collapses_identical_consecutive_attempts_and_leads_with_the_decider(
        self, tmp_path
    ):
        conn, _ = _make_db(tmp_path)
        _insert_outcome(
            conn,
            event_id=1,
            graph_fingerprint="fp-x",
            candidate_identity="cand-x",
            attempt=1,
            disposition="not_submitted_safe_bail",
            reason="no_plan_submitted",
        )
        _insert_outcome(
            conn,
            event_id=2,
            graph_fingerprint="fp-x",
            candidate_identity="cand-x",
            attempt=2,
            disposition="not_submitted_safe_bail",
            reason="no_plan_submitted",
        )
        _insert_outcome(
            conn,
            event_id=3,
            graph_fingerprint="fp-x",
            candidate_identity="cand-x",
            attempt=3,
            disposition="exhausted",
            reason="all_candidates_excluded_for_graph",
        )
        conn.commit()

        lines = render_unflat_why(conn, FUNC_EA)
        text = "\n".join(lines)
        assert "3 identical attempts" not in text
        assert "(2 identical attempts)" in text
        # The deciding (final) disposition is the FIRST reported line for the group.
        decider_idx = next(i for i, line in enumerate(lines) if "<- deciding" in line)
        earlier_idx = next(
            i for i, line in enumerate(lines) if "attempts 1-2" in line
        )
        assert "disposition=exhausted" in lines[decider_idx]
        assert earlier_idx > decider_idx


# ---------------------------------------------------------------------------
# "not recorded" -- absent evidence is always named, never silently skipped
# ---------------------------------------------------------------------------


class TestNotRecorded:
    def test_absent_facts_are_named_not_recorded(self, tmp_path):
        conn, _ = _make_db(tmp_path)
        _insert_outcome(conn, event_id=1, disposition="rejected_preflight", reason="x")
        conn.commit()

        text = "\n".join(render_unflat_why(conn, FUNC_EA))
        assert "UnflattenDispatcherRemovalPreflightProof: not recorded" in text
        assert "UnflattenDispatcherCorridorCoverageSummary: not recorded" in text
        assert "UnflattenRecoveryStatus: not recorded" in text
        assert "UnflattenDiagnosticsIncomplete: not recorded" in text
        assert "recovery_search_outcomes: not recorded" in text

    def test_present_recovery_status_is_rendered(self, tmp_path):
        conn, _ = _make_db(tmp_path)
        _insert_outcome(conn, event_id=1, disposition="not_submitted_safe_bail", reason="x")
        _insert_snapshot(conn, snapshot_id=1, label="s1")
        _insert_fact(
            conn,
            snapshot_id=1,
            fact_id="unflat-recovery:1",
            kind="UnflattenRecoveryStatus",
            payload=(
                '{"dispatch_map_present": true, "dispatcher_entry": 3, '
                '"map_rows": 59, "recovery_present": true, '
                '"state_var_reg": null, "state_var_stkoff": 4212}'
            ),
        )
        conn.commit()

        text = "\n".join(render_unflat_why(conn, FUNC_EA))
        assert "UnflattenRecoveryStatus: map_rows=59" in text
        assert "state_var=stkoff=4212" in text


# ---------------------------------------------------------------------------
# Degrade path: schema predates ticket d81-rhu6 slice 1 (no outcomes table)
# ---------------------------------------------------------------------------


class TestDegradedSchema:
    def test_missing_outcomes_table_falls_back_to_cfg_transaction_attempts(
        self, tmp_path
    ):
        conn, db_path = _make_db(tmp_path)
        conn.execute("DROP TABLE unflatten_candidate_outcomes")
        _insert_cfg_attempt(conn, plan_id="plan-1", attempt_id="attempt-1", current_phase="committed")
        _insert_cfg_attempt(
            conn,
            plan_id="plan-2",
            attempt_id="attempt-2",
            current_phase="poisoned_restart_required",
            poisoned=1,
            first_failure_obligation="runtime:post_observation_contract",
            first_failure_phase="post_observation_contract",
            first_failure_reason="observed unflatten authority rejected: reason=live_binding_failed",
        )
        conn.commit()

        lines = render_unflat_why(conn, FUNC_EA)
        text = "\n".join(lines)
        assert "unflatten_candidate_outcomes: not recorded" in text
        assert "schema predates ticket d81-rhu6 slice 1" in text
        assert "cfg_transaction_attempts:" in text
        assert "phase=poisoned_restart_required" in text
        assert "first_failure_obligation=runtime:post_observation_contract" in text
        assert "committed_before=1" in text


# ---------------------------------------------------------------------------
# CLI end to end
# ---------------------------------------------------------------------------


class TestUnflatWhyCommand:
    def test_main_renders_the_report_to_stdout(self, tmp_path, capsys):
        conn, db_path = _make_db(tmp_path)
        _insert_outcome(conn, event_id=1, disposition="applied_observed", reason="cfg_transaction_committed")
        conn.commit()

        rc = main(["unflat-why", "--db", str(db_path), "--func", hex(FUNC_EA)])
        assert rc == 0
        out = capsys.readouterr().out
        assert "disposition=applied_observed" in out

    def test_main_reports_a_missing_db(self, capsys, tmp_path):
        missing = tmp_path / "does-not-exist.sqlite3"
        rc = main(["unflat-why", "--db", str(missing), "--func", hex(FUNC_EA)])
        assert rc == 2
        err = capsys.readouterr().err
        assert "diag DB not found" in err

    def test_main_writes_to_output_file(self, tmp_path, capsys):
        conn, db_path = _make_db(tmp_path)
        _insert_outcome(conn, event_id=1, disposition="exhausted", reason="all_candidates_excluded_for_graph")
        conn.commit()

        output = tmp_path / "report.txt"
        rc = main(
            [
                "unflat-why",
                "--db",
                str(db_path),
                "--func",
                hex(FUNC_EA),
                "--output",
                str(output),
            ]
        )
        assert rc == 0
        assert capsys.readouterr().out == ""
        assert "disposition=exhausted" in output.read_text()


# ---------------------------------------------------------------------------
# State-write resolution decomposition (ticket d81-qt4v, slice 4)
# ---------------------------------------------------------------------------


def _insert_state_write(
    conn: sqlite3.Connection,
    *,
    event_id: int,
    block_serial: int = 330,
    corridor: str = "355>397",
    outcome: str = "abstain",
    cause: str = "no_def_within_hop_bound",
    reason: str = "",
    store_cells: int = 0,
    folded_value_hex: str | None = None,
    folded_value_i64: int | None = None,
    def_sites_json: str = "[]",
    contributed: int = 1,
    func_ea: int = FUNC_EA,
    func_ea_hex: str = FUNC_EA_HEX,
    maturity: str = "MMAT_GLBOPT1",
    session_id: str = "s1",
    block_ea_hex: str = "0x00007ffb0eb15239",
    block_ea_i64: int = 0x7FFB0EB15239,
) -> None:
    conn.execute(
        """
        INSERT INTO state_write_resolutions
            (event_id, session_id, func_ea_hex, func_ea_i64, maturity,
             block_serial, block_ea_hex, block_ea_i64, corridor, outcome,
             cause, reason, store_cells, folded_value_hex, folded_value_i64,
             def_sites_json, contributed_to_unresolved_transition)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            event_id,
            session_id,
            func_ea_hex,
            func_ea,
            maturity,
            block_serial,
            block_ea_hex,
            block_ea_i64,
            corridor,
            outcome,
            cause,
            reason,
            store_cells,
            folded_value_hex,
            folded_value_i64,
            def_sites_json,
            contributed,
        ),
    )


def _blk330_capture(conn: sqlite3.Connection) -> None:
    _insert_outcome(
        conn,
        event_id=1,
        disposition="not_submitted_safe_bail",
        reason="residual_dispatcher_corridor",
        coverage_covered=0,
        coverage_residual=158,
    )
    _insert_state_write(
        conn, event_id=101, corridor="329", outcome="exact_result",
        cause="resolved", folded_value_hex="0x000000004bcc8bee",
        folded_value_i64=0x4BCC8BEE, store_cells=2, contributed=0,
    )
    _insert_state_write(
        conn, event_id=102, corridor="355>398", outcome="exact_result",
        cause="resolved", folded_value_hex="0x000000001b3ee0ef",
        folded_value_i64=0x1B3EE0EF, contributed=0,
    )
    _insert_state_write(
        conn, event_id=103, corridor="355>397",
        cause="no_def_within_hop_bound", contributed=1,
    )
    _insert_state_write(
        conn, event_id=104, block_serial=236, corridor="235",
        cause="no_reaching_defs", contributed=1,
    )
    conn.commit()


def test_state_write_resolutions_decompose_by_cause(tmp_path):
    conn, _ = _make_db(tmp_path)
    _blk330_capture(conn)
    text = "\n".join(render_unflat_why(conn, FUNC_EA))

    assert "state_write_resolutions:" in text
    assert "resolved=2" in text
    assert "no_def_within_hop_bound=1" in text
    assert "no_reaching_defs=1" in text


def test_state_write_resolutions_list_top_unresolved_corridors(tmp_path):
    conn, _ = _make_db(tmp_path)
    _blk330_capture(conn)
    lines = render_unflat_why(conn, FUNC_EA)
    text = "\n".join(lines)

    assert "unresolved corridors" in text
    assert "blk236 corridor=235 cause=no_reaching_defs" in text
    assert "blk330 corridor=355>397 cause=no_def_within_hop_bound" in text
    # A resolved corridor is never listed as a contributor.
    assert "corridor=329 cause=resolved" not in text


def test_state_write_resolutions_render_the_resolved_corridors_too(tmp_path):
    conn, _ = _make_db(tmp_path)
    _blk330_capture(conn)
    text = "\n".join(render_unflat_why(conn, FUNC_EA))
    assert "blk330@0x00007ffb0eb15239 corridor=329 outcome=exact_result" in text
    assert "0x4bcc8bee" in text
    assert "corridor=355>398 outcome=exact_result cause=resolved" in text
    assert "0x1b3ee0ef" in text


def test_state_write_resolutions_absent_renders_not_recorded(tmp_path):
    conn, _ = _make_db(tmp_path)
    _insert_outcome(conn, event_id=1)
    conn.commit()
    text = "\n".join(render_unflat_why(conn, FUNC_EA))
    assert "state_write_resolutions: not recorded" in text
    assert "StateWriteResolutionFact" in text


# ---------------------------------------------------------------------------
# Emulator gap worklist (ticket d81-c6n7, slice 5)
# ---------------------------------------------------------------------------


def _insert_emulator_gap(
    conn: sqlite3.Connection,
    *,
    event_id: int,
    cause: str = "stack_slot_in_aliased_memory",
    site_ea_hex: str = "0x00007ffb0eb0cab7",
    site_ea_i64: int = 0x7FFB0EB0CAB7,
    block_serial: int = 236,
    occurrences: int = 12,
    detail: str = "",
    def_sites_json: str = "[]",
    maturity: str = "MMAT_GLBOPT1",
    attempt: int = 1,
    func_ea: int = FUNC_EA,
    func_ea_hex: str = FUNC_EA_HEX,
    session_id: str = "s1",
) -> None:
    conn.execute(
        """
        INSERT INTO emulator_gaps
            (event_id, session_id, func_ea_hex, func_ea_i64, maturity, attempt,
             cause, site_ea_hex, site_ea_i64, block_serial, occurrences,
             detail, def_sites_json)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            event_id,
            session_id,
            func_ea_hex,
            func_ea,
            maturity,
            attempt,
            cause,
            site_ea_hex,
            site_ea_i64,
            block_serial,
            occurrences,
            detail,
            def_sites_json,
        ),
    )


def _gap_capture(conn: sqlite3.Connection) -> None:
    _insert_outcome(
        conn,
        event_id=1,
        disposition="not_submitted_safe_bail",
        reason="residual_dispatcher_corridor",
        coverage_covered=0,
        coverage_residual=158,
    )
    # The two ndefs=0 stack slots of sub_7FFB0EB06E50 (plan section 6.5).
    _insert_emulator_gap(conn, event_id=201, block_serial=236, occurrences=6)
    _insert_emulator_gap(
        conn,
        event_id=202,
        block_serial=268,
        site_ea_hex="0x00007ffb0eb10db1",
        site_ea_i64=0x7FFB0EB10DB1,
        occurrences=6,
    )
    _insert_emulator_gap(
        conn,
        event_id=203,
        cause="unsupported_call_operand",
        site_ea_hex="0x00007ffb0eb0bcf7",
        site_ea_i64=0x7FFB0EB0BCF7,
        block_serial=398,
        occurrences=3,
    )
    _insert_emulator_gap(
        conn,
        event_id=204,
        cause="phi_multi_def",
        site_ea_hex="0x00007ffb0eb15239",
        site_ea_i64=0x7FFB0EB15239,
        block_serial=330,
        occurrences=1,
        def_sites_json="[[329, 140718000000000]]",
    )
    conn.commit()


def test_emulator_gaps_render_a_per_cause_count(tmp_path):
    conn, _ = _make_db(tmp_path)
    _gap_capture(conn)
    text = "\n".join(render_unflat_why(conn, FUNC_EA))

    assert "emulator_gaps:" in text
    assert "stack_slot_in_aliased_memory=12" in text
    assert "unsupported_call_operand=3" in text
    assert "phi_multi_def=1" in text


def test_emulator_gaps_list_each_site_with_its_block(tmp_path):
    conn, _ = _make_db(tmp_path)
    _gap_capture(conn)
    text = "\n".join(render_unflat_why(conn, FUNC_EA))

    assert "blk236@0x00007ffb0eb0cab7" in text
    assert "blk268@0x00007ffb0eb10db1" in text
    assert "cause=phi_multi_def" in text
    assert "x6" in text


def test_emulator_gaps_absent_renders_not_recorded(tmp_path):
    conn, _ = _make_db(tmp_path)
    _insert_outcome(conn, event_id=1)
    conn.commit()
    text = "\n".join(render_unflat_why(conn, FUNC_EA))
    assert "emulator_gaps: not recorded" in text
    assert "EmulatorGapFact" in text


# ---------------------------------------------------------------------------
# Session selection (ticket d81-y3oi): repeated decompiles of the same
# function must not merge into one indistinguishable history.
# ---------------------------------------------------------------------------


def _insert_session(
    conn: sqlite3.Connection,
    *,
    session_id: str,
    func_ea: int = FUNC_EA,
    func_ea_hex: str = FUNC_EA_HEX,
    top_level_epoch: int = 1,
    started_at: float = 0.0,
    finished_at: float | None = None,
    status: str = "finished",
) -> None:
    conn.execute(
        """
        INSERT INTO diagnostic_sessions
            (session_id, func_ea_hex, func_ea_i64, top_level_epoch,
             native_key_json, started_at, finished_at, status,
             diagnostic_error_count)
        VALUES (?, ?, ?, ?, '{}', ?, ?, ?, 0)
        """,
        (session_id, func_ea_hex, func_ea, top_level_epoch, started_at, finished_at, status),
    )


def _two_session_capture(conn: sqlite3.Connection) -> None:
    """Two decompiles of the same function: an older run and the current one.

    Mirrors the reviewer's exact repro shape: the first (older) session
    recovered 85/85 handlers and committed a batch; the second (newer,
    completed) session recovered nothing and bailed clean.
    """
    _insert_session(
        conn, session_id="s-old", top_level_epoch=1, started_at=1.0, finished_at=2.0,
        status="finished",
    )
    _insert_outcome(
        conn,
        event_id=1,
        session_id="s-old",
        disposition="applied_observed",
        reason="cfg_transaction_committed",
        handlers_recovered=85,
        handlers_total=85,
        plan_id="plan-old",
    )
    _insert_session(
        conn, session_id="s-new", top_level_epoch=2, started_at=3.0, finished_at=4.0,
        status="finished",
    )
    _insert_outcome(
        conn,
        event_id=2,
        session_id="s-new",
        disposition="not_submitted_safe_bail",
        reason="no_plan_submitted",
    )
    conn.commit()


class TestSessionSelection:
    def test_default_resolves_to_the_newest_completed_session(self, tmp_path):
        conn, _ = _make_db(tmp_path)
        _two_session_capture(conn)

        text = "\n".join(render_unflat_why(conn, FUNC_EA))
        assert "session=s-new" in text
        assert "disposition=not_submitted_safe_bail" in text
        # The older session's row must not leak into the newer session's report.
        assert "disposition=applied_observed" not in text
        assert "preplan_reachable_handlers=85/85" not in text

    def test_explicit_session_overrides_the_default(self, tmp_path):
        conn, _ = _make_db(tmp_path)
        _two_session_capture(conn)

        text = "\n".join(render_unflat_why(conn, FUNC_EA, session_id="s-old"))
        assert "session=s-old" in text
        assert "disposition=applied_observed" in text
        assert "preplan_reachable_handlers=85/85" in text
        assert "disposition=not_submitted_safe_bail" not in text

    def test_active_session_is_not_selected_as_the_default(self, tmp_path):
        """An in-progress (``active``) session never wins over a completed one."""
        conn, _ = _make_db(tmp_path)
        _two_session_capture(conn)
        _insert_session(
            conn, session_id="s-live", top_level_epoch=3, started_at=5.0,
            finished_at=None, status="active",
        )
        _insert_outcome(
            conn,
            event_id=3,
            session_id="s-live",
            disposition="not_submitted_safe_bail",
            reason="no_plan_submitted",
            handlers_recovered=1,
        )
        conn.commit()

        text = "\n".join(render_unflat_why(conn, FUNC_EA))
        assert "session=s-new" in text
        assert "preplan_reachable_handlers=1/" not in text

    def test_no_diagnostic_sessions_table_falls_back_to_merged_history(self, tmp_path):
        conn, _ = _make_db(tmp_path)
        _insert_outcome(conn, event_id=1, disposition="applied_observed", reason="x")
        conn.commit()

        text = "\n".join(render_unflat_why(conn, FUNC_EA))
        assert "session=ALL" in text
        assert "merged history" in text
        assert "disposition=applied_observed" in text

    def test_list_sessions_renders_every_session_newest_first(self, tmp_path):
        conn, _ = _make_db(tmp_path)
        _two_session_capture(conn)

        text = "\n".join(render_session_list(conn, FUNC_EA))
        s_new_idx = text.index("session_id=s-new")
        s_old_idx = text.index("session_id=s-old")
        assert s_new_idx < s_old_idx
        assert "status=finished" in text
        assert "outcome_rows=1" in text

    def test_main_list_sessions_flag(self, tmp_path, capsys):
        conn, db_path = _make_db(tmp_path)
        _two_session_capture(conn)

        rc = main(
            ["unflat-why", "--db", str(db_path), "--func", hex(FUNC_EA), "--list-sessions"]
        )
        assert rc == 0
        out = capsys.readouterr().out
        assert "session_id=s-new" in out
        assert "session_id=s-old" in out
        # --list-sessions must not also render the causal-order report.
        assert "disposition=" not in out

    def test_main_session_flag_selects_one_session(self, tmp_path, capsys):
        conn, db_path = _make_db(tmp_path)
        _two_session_capture(conn)

        rc = main(
            [
                "unflat-why", "--db", str(db_path), "--func", hex(FUNC_EA),
                "--session", "s-old",
            ]
        )
        assert rc == 0
        out = capsys.readouterr().out
        assert "session=s-old" in out
        assert "disposition=applied_observed" in out
