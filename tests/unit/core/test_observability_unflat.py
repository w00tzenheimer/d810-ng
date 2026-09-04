"""Unit tests for the terminal unflatten outcome record (ticket d81-rhu6).

The emit-decision logic is pure: it builds one authoritative record from
plain counters, so an operator never reconstructs "why no unflatten" from
log noise.  No IDA import, no diag DB.
"""

from __future__ import annotations

from types import SimpleNamespace

import pytest

from d810.core import diag as _diag_backend
from d810.core import observability
from d810.core.observability import (
    emit as _emit_diagnostic,
    get_active_diag_path,
    reset_diagnostic_bus,
    subscribe,
)
from d810.core.observability_events import (
    DiagnosticSessionObserved,
    UnflattenCandidateOutcomeObserved,
)
from d810.core.observability_unflat import (
    UNFLAT_OUTCOME_DISPOSITIONS,
    UnflattenOutcomeCounters,
    build_unflat_candidate_outcome,
    derive_bail_reason,
    format_unflat_outcome,
    has_unflat_counters,
    note_committed_batch,
    note_unflat_counters,
    note_unresolved_state_write,
    observe_unflat_candidate_outcome,
    resolve_unflat_hint_db_path,
    skipped_maturities,
    unflat_counters,
    unflat_why_hint,
)


@pytest.fixture(autouse=True)
def _fake_unflat_counters_session_store(monkeypatch):
    """Stand in for a lifecycle-owned session store (ticket d81-pqrc).

    Production counters live on ``DecompilationSessionContext.unflat_counters``
    and are reached only through the registered
    ``d810.core.observability`` provider
    (:func:`register_active_unflat_counters_provider`); this module owns no
    counters storage of its own anymore. A plain per-test dict keyed by
    func_ea stands in for "a session exists and owns these counters" without
    pulling in the manager-layer lifecycle coordinator.
    """
    store: dict[int, UnflattenOutcomeCounters] = {}

    def _provider(func_ea):
        return store.setdefault(int(func_ea), UnflattenOutcomeCounters())

    monkeypatch.setattr(observability, "_active_unflat_counters_provider", _provider)
    yield store


# ---------------------------------------------------------------------------
# Event contract
# ---------------------------------------------------------------------------


def _event(**overrides):
    kwargs = dict(
        session_id="s1",
        func_ea=0x7FFB0EB06E50,
        maturity="MMAT_GLBOPT1",
        graph_fingerprint="flowgraph-topology-epoch-v1:abc",
        candidate_identity="DispatcherCandidateIdentity(blk=1)",
        attempt=1,
        disposition="not_submitted_safe_bail",
        reason="residual_dispatcher_corridor",
    )
    kwargs.update(overrides)
    return UnflattenCandidateOutcomeObserved(**kwargs)


def test_event_rejects_unknown_disposition():
    with pytest.raises(ValueError):
        _event(disposition="made_up")


def test_event_rejects_empty_reason():
    with pytest.raises(ValueError):
        _event(reason="  ")


def test_event_rejects_negative_func_ea():
    with pytest.raises(ValueError):
        _event(func_ea=-1)


def test_event_rejects_negative_attempt():
    with pytest.raises(ValueError):
        _event(attempt=-1)


def test_event_normalises_unresolved_anchors():
    ev = _event(unresolved_anchors=[[330, 0x7FFB0EB15239], (12, 0x40)])
    assert ev.unresolved_anchors == ((12, 0x40), (330, 0x7FFB0EB15239))


def test_every_disposition_is_constructible():
    for disposition in sorted(UNFLAT_OUTCOME_DISPOSITIONS):
        assert _event(disposition=disposition).disposition == disposition


# ---------------------------------------------------------------------------
# Counters
# ---------------------------------------------------------------------------


def test_counters_accumulate_per_function():
    note_unflat_counters(0x1000, handlers_recovered=85, handlers_total=85)
    note_unflat_counters(0x1000, dag_nodes=59, dag_edges=20)
    note_unflat_counters(0x2000, dag_nodes=3)
    first = unflat_counters(0x1000)
    assert (first.handlers_recovered, first.handlers_total) == (85, 85)
    assert (first.dag_nodes, first.dag_edges) == (59, 20)
    assert unflat_counters(0x2000).dag_nodes == 3
    assert unflat_counters(0x2000).handlers_total is None


def test_counters_ignore_none_updates():
    note_unflat_counters(0x1000, dag_nodes=59)
    note_unflat_counters(0x1000, dag_nodes=None)
    assert unflat_counters(0x1000).dag_nodes == 59


def test_unresolved_state_writes_are_ordered_and_unique():
    note_unresolved_state_write(0x1000, 330, 0x7FFB0EB15239)
    note_unresolved_state_write(0x1000, 330, 0x7FFB0EB15239)
    note_unresolved_state_write(0x1000, 12, 0x40)
    assert unflat_counters(0x1000).unresolved_anchors == (
        (12, 0x40),
        (330, 0x7FFB0EB15239),
    )


def test_committed_batches_count():
    assert note_committed_batch(0x1000) == 1
    assert note_committed_batch(0x1000) == 2
    assert unflat_counters(0x1000).committed_batches == 2


def test_has_unflat_counters_is_false_without_an_active_session():
    """No provider mapping for this func_ea -> no session owns it (d81-pqrc)."""
    assert has_unflat_counters(0x9999) is False


def test_has_unflat_counters_is_false_for_an_untouched_session():
    """A session exists but nothing has been recorded into it yet."""
    assert unflat_counters(0x1000) == UnflattenOutcomeCounters()
    assert has_unflat_counters(0x1000) is False


def test_has_unflat_counters_is_true_once_a_field_is_recorded():
    note_unflat_counters(0x1000, dag_nodes=1)
    assert has_unflat_counters(0x1000) is True


def test_two_sessions_at_the_same_func_ea_never_share_a_counters_object():
    """Ticket d81-pqrc: session-owned counters, not a process-global dict.

    Reproduces the reviewer's report: an "old" session's counters must be a
    different object from a "new" session's counters at the same func_ea,
    and the new one must start blank regardless of what the old one held.
    """
    note_unflat_counters(0x1000, handlers_recovered=85, plan_id="plan-old")
    note_committed_batch(0x1000)
    old_counters = unflat_counters(0x1000)
    assert old_counters.handlers_recovered == 85
    assert old_counters.committed_batches == 1

    # A fresh session at the SAME func_ea: a new provider mapping, exactly
    # as a new DecompilationSessionContext would mint a fresh
    # UnflattenOutcomeCounters() rather than reusing the finished session's.

    def _fresh_session_provider(func_ea, _cache={}):
        return _cache.setdefault(int(func_ea), UnflattenOutcomeCounters())

    previous = observability._active_unflat_counters_provider
    observability._active_unflat_counters_provider = _fresh_session_provider
    try:
        new_counters = unflat_counters(0x1000)
        assert new_counters is not old_counters
        assert new_counters == UnflattenOutcomeCounters()
        assert new_counters.handlers_recovered is None
        assert new_counters.plan_id is None
        assert new_counters.committed_batches == 0
    finally:
        observability._active_unflat_counters_provider = previous


def test_counters_are_unreachable_once_no_session_owns_the_func_ea():
    """A finished session's counters vanish from the public API's view.

    ``unflat_counters``/``has_unflat_counters`` never expose the old
    object once the provider stops naming it -- there is no fallback global
    to read it from.
    """
    note_unflat_counters(0x1000, handlers_recovered=85)
    assert has_unflat_counters(0x1000) is True

    previous = observability._active_unflat_counters_provider
    observability._active_unflat_counters_provider = lambda func_ea: None
    try:
        assert has_unflat_counters(0x1000) is False
        assert unflat_counters(0x1000) == UnflattenOutcomeCounters()
        assert note_unflat_counters(0x1000, dag_nodes=1) is None
        assert note_committed_batch(0x1000) == 0
    finally:
        observability._active_unflat_counters_provider = previous


# ---------------------------------------------------------------------------
# Derived reason / skipped maturities
# ---------------------------------------------------------------------------


def test_bail_reason_is_residual_corridor_when_corridors_remain():
    note_unflat_counters(0x1000, coverage_covered=0, coverage_residual=158)
    assert derive_bail_reason(unflat_counters(0x1000)) == "residual_dispatcher_corridor"


def test_bail_reason_when_no_plan_was_submitted():
    assert derive_bail_reason(unflat_counters(0x1000)) == "no_plan_submitted"


def test_bail_reason_when_coverage_complete_but_no_progress():
    note_unflat_counters(0x1000, coverage_covered=12, coverage_residual=0)
    assert derive_bail_reason(unflat_counters(0x1000)) == "clean_noop_no_progress"


@pytest.mark.parametrize(
    "previous,current,expected",
    [
        # Live ``ida_hexrays`` numbering: MMAT_ZERO=0 ... MMAT_CALLS=4,
        # MMAT_GLBOPT1=5, MMAT_GLBOPT2=6.  A CALLS -> GLBOPT2 jump means
        # GLBOPT1 received no block callback at all (plan 4.4).
        (4, 6, ("MMAT_GLBOPT1",)),
        (3, 6, ("MMAT_CALLS", "MMAT_GLBOPT1")),
        (4, 5, ()),
        (None, 6, ()),
        (6, 4, ()),
    ],
)
def test_skipped_maturities(previous, current, expected):
    assert skipped_maturities(previous, current) == expected


def test_skipped_maturities_ida_numbering_is_opt_in():
    from d810.core.maturity_labels import MaturityNumbering

    assert skipped_maturities(
        3, 5, numbering=MaturityNumbering.IDA
    ) == ("MMAT_GLBOPT1",)


def test_skipped_maturities_default_matches_live_hexrays_constants():
    """Regression: the default must NOT be off by one against ida_hexrays.

    Reading a raw ``mba.maturity`` under IDA numbering named the skipped
    maturity GLBOPT2 when Hex-Rays had actually skipped GLBOPT1.
    """
    assert skipped_maturities(4, 6) == ("MMAT_GLBOPT1",)


# ---------------------------------------------------------------------------
# Record construction and rendering
# ---------------------------------------------------------------------------


def test_build_record_quotes_the_accumulated_counters():
    func_ea = 0x7FFB0EB06E50
    note_unflat_counters(
        func_ea,
        handlers_recovered=85,
        handlers_total=85,
        dag_nodes=59,
        dag_edges=20,
        coverage_covered=0,
        coverage_residual=158,
        plan_id="plan-7",
    )
    note_unresolved_state_write(func_ea, 330, 0x7FFB0EB15239)
    record = build_unflat_candidate_outcome(
        session_id="s1",
        func_ea=func_ea,
        maturity="MMAT_GLBOPT1",
        graph_fingerprint="flowgraph-topology-epoch-v1:abc",
        candidate_identity="DispatcherCandidateIdentity(blk=330)",
        attempt=1,
        disposition="not_submitted_safe_bail",
        reason=None,
        db_path="/tmp/x.diag.sqlite3",
    )
    assert record.reason == "residual_dispatcher_corridor"
    assert (record.handlers_recovered, record.handlers_total) == (85, 85)
    assert (record.dag_nodes, record.dag_edges) == (59, 20)
    assert (record.coverage_covered, record.coverage_residual) == (0, 158)
    assert record.plan_id == "plan-7"
    assert record.unresolved_anchors == ((330, 0x7FFB0EB15239),)
    assert record.next_hint == (
        "python -m d810.diagnostics unflat-why "
        "--db /tmp/x.diag.sqlite3 --func 0x7ffb0eb06e50"
    )


def test_hint_uses_a_placeholder_without_an_active_capture():
    assert unflat_why_hint(0x1000, None) == (
        "python -m d810.diagnostics unflat-why --db <diag-db> --func 0x1000"
    )


# ---------------------------------------------------------------------------
# aa-smoo: the hint must resolve to the emitted function's own capture
# ---------------------------------------------------------------------------


def test_resolve_hint_db_path_keeps_the_path_when_no_active_func_ea_is_known():
    assert (
        resolve_unflat_hint_db_path(0x7FFB0EB06E50, "/tmp/x.sqlite3", None)
        == "/tmp/x.sqlite3"
    )


def test_resolve_hint_db_path_keeps_the_path_when_it_matches_the_active_session():
    assert (
        resolve_unflat_hint_db_path(0x7FFB0EB06E50, "/tmp/x.sqlite3", 0x7FFB0EB06E50)
        == "/tmp/x.sqlite3"
    )


def test_resolve_hint_db_path_drops_the_path_for_a_different_active_function():
    # A session that never rotated (a multi-function headless batch) still
    # names the first function's DB; a record for a different function must
    # not point an operator at that misleadingly-named file.
    assert (
        resolve_unflat_hint_db_path(0x7FFB0F2726E0, "/tmp/x.sqlite3", 0x7FFB0EB06E50)
        is None
    )


def test_resolve_hint_db_path_is_a_noop_on_an_already_missing_path():
    assert resolve_unflat_hint_db_path(0x1000, None, 0x2000) is None


def test_observe_omits_the_db_path_when_the_active_session_is_a_different_function(
    monkeypatch,
):
    # ``_diag_backend`` (imported above) must load before these monkeypatches
    # run, or ``observe_unflat_candidate_outcome``'s lazy backend bootstrap
    # re-registers the real providers mid-test and overwrites them.
    monkeypatch.setattr(
        observability, "_diag_path_provider", lambda: "/tmp/first_func.diag.sqlite3"
    )
    monkeypatch.setattr(
        observability, "_diag_active_func_ea_provider", lambda: 0x7FFB0EB06E50
    )
    record = observe_unflat_candidate_outcome(
        session_id="s1",
        func_ea=0x7FFB0F2726E0,
        maturity="MMAT_GLBOPT1",
        graph_fingerprint="",
        candidate_identity="",
        attempt=0,
        disposition="maturity_no_callbacks",
        reason="hexrays_delivered_no_optblock_callback",
    )
    assert record is not None
    assert record.next_hint == (
        "python -m d810.diagnostics unflat-why --db <diag-db> --func 0x7ffb0f2726e0"
    )


def test_observe_keeps_the_db_path_when_the_active_session_matches(monkeypatch):
    monkeypatch.setattr(
        observability, "_diag_path_provider", lambda: "/tmp/own_func.diag.sqlite3"
    )
    monkeypatch.setattr(
        observability, "_diag_active_func_ea_provider", lambda: 0x7FFB0F2726E0
    )
    record = observe_unflat_candidate_outcome(
        session_id="s1",
        func_ea=0x7FFB0F2726E0,
        maturity="MMAT_GLBOPT1",
        graph_fingerprint="",
        candidate_identity="",
        attempt=0,
        disposition="maturity_no_callbacks",
        reason="hexrays_delivered_no_optblock_callback",
    )
    assert record is not None
    assert record.next_hint == (
        "python -m d810.diagnostics unflat-why "
        "--db /tmp/own_func.diag.sqlite3 --func 0x7ffb0f2726e0"
    )


# ---------------------------------------------------------------------------
# d81-y3oi(c): a multi-function batch must resolve each function's own
# capture via the disk-based fallback rather than rendering the placeholder.
# ---------------------------------------------------------------------------


def test_observe_falls_back_to_disk_lookup_when_the_live_path_is_stale(monkeypatch):
    # The live pointer still names an unrelated function's capture (a
    # multi-function batch, or a session that legitimately stays un-rotated
    # across nested callbacks) -- resolve_unflat_hint_db_path drops it.
    monkeypatch.setattr(
        observability, "_diag_path_provider", lambda: "/tmp/first_func.diag.sqlite3"
    )
    monkeypatch.setattr(
        observability, "_diag_active_func_ea_provider", lambda: 0x7FFB0EB06E50
    )
    monkeypatch.setattr(
        observability,
        "_diag_latest_path_for_func_provider",
        lambda func_ea: f"/tmp/own_capture_0x{func_ea:x}.diag.sqlite3",
    )
    record = observe_unflat_candidate_outcome(
        session_id="s1",
        func_ea=0x7FFB0F2726E0,
        maturity="MMAT_GLBOPT1",
        graph_fingerprint="",
        candidate_identity="",
        attempt=0,
        disposition="maturity_no_callbacks",
        reason="hexrays_delivered_no_optblock_callback",
    )
    assert record is not None
    assert record.next_hint == (
        "python -m d810.diagnostics unflat-why "
        "--db /tmp/own_capture_0x7ffb0f2726e0.diag.sqlite3 --func 0x7ffb0f2726e0"
    )


def test_observe_uses_the_placeholder_only_when_the_disk_lookup_also_finds_nothing(
    monkeypatch,
):
    monkeypatch.setattr(
        observability, "_diag_path_provider", lambda: "/tmp/first_func.diag.sqlite3"
    )
    monkeypatch.setattr(
        observability, "_diag_active_func_ea_provider", lambda: 0x7FFB0EB06E50
    )
    monkeypatch.setattr(
        observability, "_diag_latest_path_for_func_provider", lambda func_ea: None
    )
    record = observe_unflat_candidate_outcome(
        session_id="s1",
        func_ea=0x7FFB0F2726E0,
        maturity="MMAT_GLBOPT1",
        graph_fingerprint="",
        candidate_identity="",
        attempt=0,
        disposition="maturity_no_callbacks",
        reason="hexrays_delivered_no_optblock_callback",
    )
    assert record is not None
    assert record.next_hint == (
        "python -m d810.diagnostics unflat-why --db <diag-db> --func 0x7ffb0f2726e0"
    )


def test_multi_function_batch_resolves_each_functions_own_capture_end_to_end(
    tmp_path, monkeypatch
):
    """Real backend: func2's row lands in func1's un-rotated capture file.

    Reproduces the confirmed real-batch shape from ``resolve_unflat_hint_db_path``'s
    own docstring: a session that never rotates keeps the live pointer on the
    *first* function while later functions' rows still land in that same
    file. The disk fallback must still resolve an executable ``--db`` for
    the later function instead of the placeholder.
    """
    monkeypatch.setattr(
        _diag_backend, "get_settings", lambda: SimpleNamespace(diag_snapshots=True)
    )
    # The registered disk-fallback provider (like production) calls
    # find_latest_diag_db_path with no explicit log_dir, so it must resolve
    # to the same directory the test's session was opened in.
    monkeypatch.setattr(_diag_backend, "_resolve_log_dir", lambda _log_dir=None: tmp_path)
    func1, func2 = 0x7FFB0EB06E50, 0x7FFB0F2726E0
    # A prior test elsewhere in the suite can leak an open session (the
    # process-global ``_current_db``); without this, ``open_diag_session``'s
    # own "already open, no rotation" guard would silently no-op below and
    # this test would observe someone else's stale capture path.
    _diag_backend.close_diag_session()
    _diag_backend.open_diag_session(func1, log_dir=str(tmp_path))
    try:
        live_path = get_active_diag_path()
        assert live_path is not None
        # func2's own session (a nested/reentrant callback within the same
        # un-rotated capture) is still persisted with its OWN func_ea.
        _emit_diagnostic(
            DiagnosticSessionObserved(
                session_id="func2-session",
                func_ea=func2,
                top_level_epoch=1,
                native_key_json="{}",
                status="active",
            )
        )

        record = observe_unflat_candidate_outcome(
            session_id="func2-session",
            func_ea=func2,
            maturity="MMAT_GLBOPT1",
            graph_fingerprint="",
            candidate_identity="",
            attempt=0,
            disposition="maturity_no_callbacks",
            reason="hexrays_delivered_no_optblock_callback",
        )
        assert record is not None
        assert record.next_hint != (
            f"python -m d810.diagnostics unflat-why --db <diag-db> --func 0x{func2:x}"
        )
        assert live_path in record.next_hint
    finally:
        _diag_backend.close_diag_session()


def test_log_line_is_one_dense_anchored_line():
    record = UnflattenCandidateOutcomeObserved(
        session_id="s1",
        func_ea=0x7FFB0EB06E50,
        maturity="MMAT_GLBOPT1",
        graph_fingerprint="flowgraph-topology-epoch-v1:abc",
        candidate_identity="DispatcherCandidateIdentity(blk=330)",
        attempt=1,
        disposition="not_submitted_safe_bail",
        reason="residual_dispatcher_corridor",
        handlers_recovered=85,
        handlers_total=85,
        dag_nodes=59,
        dag_edges=20,
        coverage_covered=0,
        coverage_residual=158,
        unresolved_anchors=((330, 0x7FFB0EB15239),),
        next_hint="python -m d810.diagnostics unflat-why --db D --func 0x7ffb0eb06e50",
    )
    line = format_unflat_outcome(record)
    assert line == (
        "UNFLAT_OUTCOME func=0x7ffb0eb06e50 maturity=GLBOPT1 "
        "disposition=not_submitted_safe_bail reason=residual_dispatcher_corridor "
        "handlers=85/85 dag=59/20 coverage=0/158 "
        "unresolved=blk330@0x7FFB0EB15239 "
        'next="python -m d810.diagnostics unflat-why --db D --func 0x7ffb0eb06e50"'
    )
    assert "\n" not in line


def test_log_line_renders_unknown_counters_as_question_marks():
    record = UnflattenCandidateOutcomeObserved(
        session_id="s1",
        func_ea=0x7FFB0F2726E0,
        maturity="MMAT_GLBOPT1",
        graph_fingerprint="",
        candidate_identity="",
        attempt=0,
        disposition="maturity_no_callbacks",
        reason="hexrays_delivered_no_optblock_callback",
        next_hint="python -m d810.diagnostics unflat-why --db D --func 0x7ffb0f2726e0",
    )
    line = format_unflat_outcome(record)
    assert "handlers=?/? dag=?/? coverage=?/? unresolved=none" in line


# ---------------------------------------------------------------------------
# Emission
# ---------------------------------------------------------------------------


def test_observe_emits_on_the_bus_and_logs_once(caplog):
    reset_diagnostic_bus()
    seen = []
    subscribe(UnflattenCandidateOutcomeObserved, seen.append)
    try:
        with caplog.at_level("INFO", logger="d810.unflat.outcome"):
            record = observe_unflat_candidate_outcome(
                session_id="s1",
                func_ea=0x7FFB0F2726E0,
                maturity="MMAT_GLBOPT1",
                graph_fingerprint="",
                candidate_identity="",
                attempt=0,
                disposition="maturity_no_callbacks",
                reason="hexrays_delivered_no_optblock_callback",
            )
    finally:
        reset_diagnostic_bus()
    assert record is not None
    assert seen == [record]
    lines = [
        r.getMessage() for r in caplog.records if "UNFLAT_OUTCOME" in r.getMessage()
    ]
    assert len(lines) == 1


def test_observe_rejects_an_unknown_disposition():
    with pytest.raises(ValueError):
        observe_unflat_candidate_outcome(
            session_id="s1",
            func_ea=0x1000,
            maturity="MMAT_GLBOPT1",
            graph_fingerprint="",
            candidate_identity="",
            attempt=0,
            disposition="not_a_disposition",
            reason="x",
        )
