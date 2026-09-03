"""Baseline work counters for phase-local canonical validation sessions.

These tests freeze *how much* repeated canonical work one exact object
occurrence causes today.  They must not assert elapsed time: the counters are
deterministic integers, wall time is not.
"""

from __future__ import annotations

import io

import pytest

from d810.transforms.unflatten_authority import ids
from d810.transforms.unflatten_authority import canonical_session
from d810.transforms.unflatten_authority.canonical_session import (
    CanonicalSessionPhase,
    CanonicalValidationSession,
    CanonicalWorkMetrics,
    _WorkLedger,
    _canonical_validation_session,
    active_canonical_session,
    emit_process_work_report,
    format_work_report,
    process_work_metrics,
    reset_process_work_metrics,
)


@pytest.fixture(autouse=True)
def _isolated_process_ledger(monkeypatch):
    """Swap in a private ledger so these tests never disturb process totals."""

    monkeypatch.setattr(canonical_session, "_PROCESS_LEDGER", _WorkLedger())
    yield


def _deep_authority() -> object:
    from d810.analyses.control_flow import semantic_route_evidence as route
    from tests.unit.transforms.unflatten_authority.test_bind import (
        _compiler_corridor_unsupported_case,
    )

    authority, *_rest = _compiler_corridor_unsupported_case(
        proof_kind=route.SemanticRouteProofKind.STATE_TRANSFORM,
    )
    return authority


def test_work_metrics_are_exact_non_negative_ints() -> None:
    metrics = CanonicalWorkMetrics()
    assert metrics.tuple == (0, 0, 0, 0, 0, 0)
    assert metrics.total == 0
    assert tuple(metrics.as_payload()) == (
        "canonical_bytes_reuses",
        "content_id_reuses",
        "deep_validations",
        "inventory_validations",
        "roundtrip_decodes",
        "wire_encodes",
    )
    with pytest.raises(TypeError):
        CanonicalWorkMetrics(deep_validations=True)
    with pytest.raises(TypeError):
        CanonicalWorkMetrics(wire_encodes=1.0)
    with pytest.raises(TypeError):
        CanonicalWorkMetrics(roundtrip_decodes=-1)


def test_metrics_delta_requires_a_monotonic_earlier_snapshot() -> None:
    earlier = CanonicalWorkMetrics(deep_validations=2, wire_encodes=3)
    later = CanonicalWorkMetrics(deep_validations=5, wire_encodes=9)
    assert later.delta(earlier) == CanonicalWorkMetrics(
        deep_validations=3, wire_encodes=6,
    )
    with pytest.raises(ValueError):
        earlier.delta(later)


def test_session_is_context_local_and_rejects_foreign_nesting() -> None:
    assert active_canonical_session() is None
    with _canonical_validation_session(
        CanonicalSessionPhase.PROJECTED_PREPARATION,
    ) as session:
        assert type(session) is CanonicalValidationSession
        assert session.phase is CanonicalSessionPhase.PROJECTED_PREPARATION
        assert active_canonical_session() is session
        with pytest.raises(RuntimeError):
            with _canonical_validation_session(
                CanonicalSessionPhase.OBSERVED_REVALIDATION,
            ):
                pass
        with pytest.raises(RuntimeError):
            with _canonical_validation_session(
                CanonicalSessionPhase.PROJECTED_PREPARATION,
            ):
                pass
        with _canonical_validation_session(
            CanonicalSessionPhase.PROJECTED_PREPARATION, reuse=session,
        ) as inner:
            assert inner is session
        assert active_canonical_session() is session
        assert not session.closed
    assert active_canonical_session() is None
    assert session.closed


def test_session_token_is_reset_even_when_the_body_raises() -> None:
    with pytest.raises(ValueError):
        with _canonical_validation_session(
            CanonicalSessionPhase.OBSERVED_REVALIDATION,
        ) as session:
            raise ValueError("phase body failed")
    assert active_canonical_session() is None
    assert session.closed
    with pytest.raises(RuntimeError):
        session.record_wire_encode()


def test_session_rejects_a_foreign_reuse_handle() -> None:
    other = CanonicalValidationSession(CanonicalSessionPhase.PROJECTED_PREPARATION)
    with _canonical_validation_session(
        CanonicalSessionPhase.PROJECTED_PREPARATION,
    ) as session:
        with pytest.raises(RuntimeError):
            with _canonical_validation_session(
                CanonicalSessionPhase.PROJECTED_PREPARATION, reuse=other,
            ):
                pass
        assert active_canonical_session() is session
    with pytest.raises(RuntimeError):
        with _canonical_validation_session(
            CanonicalSessionPhase.PROJECTED_PREPARATION, reuse=other,
        ):
            pass
    with pytest.raises(TypeError):
        with _canonical_validation_session("projected-preparation"):
            pass


def test_repeated_encoding_of_the_same_occurrence_is_reused_within_one_session() -> None:
    """The same exact live object reuses its canonical bytes within one session."""

    value = (1, "two", (3, 4), frozenset({5}))
    with _canonical_validation_session(
        CanonicalSessionPhase.PROJECTED_PREPARATION,
    ) as session:
        first = ids.canonical_bytes(value)
        second = ids.canonical_bytes(value)
        metrics = session.metrics

    assert first == second
    # One occurrence, two calls: the first pays full price, the second is a
    # cache hit and must not repeat deep validation or wire encoding.
    assert metrics.deep_validations == 1
    assert metrics.wire_encodes == 1
    assert metrics.canonical_bytes_reuses == 1
    assert metrics.roundtrip_decodes == 0


def test_equal_but_distinct_occurrences_never_reuse_each_others_bytes() -> None:
    """A dataclass-equal copy is a different occurrence: it must not hit."""

    from d810.transforms.unflatten_authority import model

    first_fixture = ids.DigestFixture(
        3, model.UnflattenAuthorityPhase.PROJECTED_PREFLIGHT, ("native",),
    )
    second_fixture = ids.DigestFixture(
        3, model.UnflattenAuthorityPhase.PROJECTED_PREFLIGHT, ("native",),
    )
    assert first_fixture == second_fixture
    assert first_fixture is not second_fixture
    with _canonical_validation_session(
        CanonicalSessionPhase.PROJECTED_PREPARATION,
    ) as session:
        first_bytes = ids.canonical_bytes(first_fixture)
        second_bytes = ids.canonical_bytes(second_fixture)
        metrics = session.metrics

    # Equal content, but two distinct live occurrences: both pay full price.
    assert first_bytes == second_bytes
    assert metrics.deep_validations == 2
    assert metrics.wire_encodes == 2
    assert metrics.canonical_bytes_reuses == 0


def test_deep_authority_roundtrip_repeats_work_for_one_exact_occurrence() -> None:
    """Freeze the repeated work `validate_canonical_roundtrip` costs today."""

    authority = _deep_authority()
    with _canonical_validation_session(
        CanonicalSessionPhase.PROJECTED_PREPARATION,
    ) as session:
        decoded = ids.validate_canonical_roundtrip(authority, type(authority))
        metrics = session.metrics

    assert decoded == authority
    assert metrics.roundtrip_decodes == 1
    # The outer helper encodes once, `canonical_decode` re-encodes the decoded
    # graph, and reconstruction replays nested records' content IDs.  Two
    # encodes of the root therefore cost thirteen deep validations over the
    # same exact occurrence.  This is the frozen Task 1 baseline: it should
    # fall once phase-local reuse lands, and any change to it must be a
    # deliberate, measured one.
    assert metrics.deep_validations == 13
    assert metrics.wire_encodes == 14
    assert metrics.canonical_bytes_reuses == 0
    assert metrics.content_id_reuses == 0


def test_counters_never_change_canonical_bytes_or_identities() -> None:
    authority = _deep_authority()
    outside = ids.canonical_bytes(authority)
    with _canonical_validation_session(
        CanonicalSessionPhase.OBSERVED_REVALIDATION,
    ):
        inside = ids.canonical_bytes(authority)
    assert inside == outside
    assert ids.content_id("test-schema", authority) == ids.content_id(
        "test-schema", authority,
    )


def test_process_ledger_accumulates_without_an_active_session() -> None:
    assert process_work_metrics() == CanonicalWorkMetrics()
    ids.canonical_bytes((1, 2, 3))
    totals = process_work_metrics()
    assert totals.deep_validations == 1
    assert totals.wire_encodes == 1
    with _canonical_validation_session(
        CanonicalSessionPhase.PROJECTED_PREPARATION,
    ) as session:
        ids.canonical_bytes((4, 5, 6))
        assert session.metrics.deep_validations == 1
    assert process_work_metrics().deep_validations == 2
    reset_process_work_metrics()
    assert process_work_metrics() == CanonicalWorkMetrics()


def test_process_report_is_one_stable_json_line() -> None:
    ids.canonical_bytes(("report",))
    line = format_work_report(process_work_metrics(), pid=4242)
    assert line.startswith("d810-authority-work-counters ")
    assert line == format_work_report(process_work_metrics(), pid=4242)
    assert '"pid":4242' in line
    assert '"deep_validations":1' in line
    stream = io.StringIO()
    emit_process_work_report(stream=stream)
    assert stream.getvalue().endswith("\n")
    assert stream.getvalue().startswith("d810-authority-work-counters ")


def test_diagnostics_projects_the_process_counters_without_authority() -> None:
    from d810.transforms.unflatten_authority import diagnostics

    ids.canonical_bytes(("diagnostic",))
    counters = diagnostics.canonical_work_counters()
    assert type(counters) is CanonicalWorkMetrics
    assert counters == process_work_metrics()
    assert diagnostics.canonical_work_payload() == counters.as_payload()
    assert diagnostics.canonical_work_payload()["deep_validations"] == 1


def test_full_inventory_validation_is_counted_every_time() -> None:
    """Each `validate_semantic_graph_inventory` re-digests the whole payload."""

    from d810.transforms.unflatten_authority import model
    from tests.unit.transforms.unflatten_authority.test_inventory_model import (
        _inventory,
    )

    inventory = _inventory()
    with _canonical_validation_session(
        CanonicalSessionPhase.OBSERVED_REVALIDATION,
    ) as session:
        model.validate_semantic_graph_inventory(inventory)
        model.validate_semantic_graph_inventory(inventory)
        metrics = session.metrics

    assert metrics.inventory_validations == 2
    assert metrics.deep_validations == 2
    assert metrics.wire_encodes == 2
    assert metrics.canonical_bytes_reuses == 0
