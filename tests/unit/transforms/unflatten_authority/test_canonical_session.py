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
    assert metrics.tuple == (0,) * 14
    assert metrics.total == 0
    assert tuple(metrics.as_payload()) == (
        "bytes_lookup_hits",
        "bytes_lookup_misses",
        "canonical_bytes_reuses",
        "content_id_lookup_hits",
        "content_id_lookup_misses",
        "content_id_reuses",
        "deep_validations",
        "inventory_seal_checks",
        "inventory_seal_hits",
        "inventory_seal_mints",
        "inventory_validations",
        "occurrence_stamps",
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


def test_cache_does_not_survive_across_sessions_or_after_the_phase_ends() -> None:
    """A fresh session, or no session at all, never reuses a prior session's work."""

    value = (1, "two", (3, 4), frozenset({5}))
    with _canonical_validation_session(
        CanonicalSessionPhase.PROJECTED_PREPARATION,
    ) as first_session:
        ids.canonical_bytes(value)
        assert first_session.metrics.deep_validations == 1

    # A second, fresh session for the *same* live occurrence must fully
    # revalidate: nothing survives the first session's teardown.
    with _canonical_validation_session(
        CanonicalSessionPhase.OBSERVED_REVALIDATION,
    ) as second_session:
        ids.canonical_bytes(value)
        metrics = second_session.metrics

    assert metrics.deep_validations == 1
    assert metrics.wire_encodes == 1
    assert metrics.canonical_bytes_reuses == 0

    # Outside any session at all, the call is not tracked by either session
    # and still performs full validation (process ledger only).
    before = process_work_metrics()
    ids.canonical_bytes(value)
    after = process_work_metrics()
    assert after.deep_validations == before.deep_validations + 1
    assert after.canonical_bytes_reuses == before.canonical_bytes_reuses


def test_persistence_boundary_roundtrip_still_fully_validates_a_cached_occurrence() -> None:
    """A cached encode never shortcuts the decode/reconstruct/compare check."""

    from d810.transforms.unflatten_authority import model

    fixture = ids.DigestFixture(
        3, model.UnflattenAuthorityPhase.PROJECTED_PREFLIGHT, ("native",),
    )
    with _canonical_validation_session(
        CanonicalSessionPhase.PROJECTED_PREPARATION,
    ) as session:
        # Seed the cache: this exact occurrence is now a validated hit.
        ids.canonical_bytes(fixture)
        before = session.metrics
        decoded = ids.validate_canonical_roundtrip(fixture, ids.DigestFixture)
        after = session.metrics

    assert decoded == fixture
    # The roundtrip's own top-level encode of `fixture` reuses the seeded
    # cache entry...
    assert after.canonical_bytes_reuses == before.canonical_bytes_reuses + 1
    # ...but the persistence-boundary decode/reconstruct/compare integrity
    # check builds a brand-new object and is never skipped or served stale.
    assert after.roundtrip_decodes == before.roundtrip_decodes + 1
    assert after.deep_validations == before.deep_validations + 1
    assert after.wire_encodes == before.wire_encodes + 1


def test_an_occurrence_that_fails_validation_is_never_served_from_cache() -> None:
    """A raising validation must not populate a reusable cache entry."""

    from d810.transforms.unflatten_authority import model

    fixture = ids.DigestFixture(
        3, model.UnflattenAuthorityPhase.PROJECTED_PREFLIGHT, ("native",),
    )
    with _canonical_validation_session(
        CanonicalSessionPhase.PROJECTED_PREPARATION,
    ) as session:
        # Corrupt this exact live occurrence past a fail-closed field check.
        object.__setattr__(fixture, "ea", "not-an-int")
        with pytest.raises(TypeError):
            ids.canonical_bytes(fixture)
        after_failure = session.metrics

        # Repair it and retry the same exact occurrence: it must be fully
        # revalidated, never served a stale or partial cache entry from the
        # failed attempt.
        object.__setattr__(fixture, "ea", 3)
        data = ids.canonical_bytes(fixture)
        after_retry = session.metrics

    # The failed attempt never touched the deep-validation/wire counters and
    # certainly never recorded a reusable entry.
    assert after_failure.deep_validations == 0
    assert after_failure.wire_encodes == 0
    assert after_failure.canonical_bytes_reuses == 0
    # The retry pays full price exactly once; it is a miss, not a hit.
    assert after_retry.deep_validations == 1
    assert after_retry.wire_encodes == 1
    assert after_retry.canonical_bytes_reuses == 0
    assert data == ids.canonical_bytes(fixture)


def test_mutated_cached_occurrence_is_revalidated_before_reuse() -> None:
    """An in-session mutation cannot receive canonical bytes from before it."""

    from d810.transforms.unflatten_authority import model

    fixture = ids.DigestFixture(
        3, model.UnflattenAuthorityPhase.PROJECTED_PREFLIGHT, ("native",),
    )
    with _canonical_validation_session(
        CanonicalSessionPhase.PROJECTED_PREPARATION,
    ) as session:
        before = ids.canonical_bytes(fixture)
        object.__setattr__(fixture, "ea", 4)
        after = ids.canonical_bytes(fixture)
        metrics = session.metrics

    assert after != before
    assert ids.canonical_decode(after).ea == 4
    assert metrics.deep_validations == 2
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


def test_full_inventory_validation_is_reused_for_one_unmutated_occurrence() -> None:
    """One session seals an exact inventory after its first validation."""

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

    assert metrics.inventory_validations == 1
    assert metrics.deep_validations == 1
    assert metrics.wire_encodes == 1
    assert metrics.canonical_bytes_reuses == 0


def _stamp_partition(metrics: CanonicalWorkMetrics) -> int:
    """Sum of every path that performs exactly one stamp walk in strict mode."""

    return (
        metrics.bytes_lookup_hits + metrics.bytes_lookup_misses
        + metrics.content_id_lookup_hits + metrics.content_id_lookup_misses
        + metrics.inventory_seal_mints + metrics.inventory_seal_checks
    )


def test_occurrence_stamps_are_attributed_to_bytes_and_content_id_lookups() -> None:
    """Direct and content-ID lookups each cost one stamp walk, hit or miss."""

    from d810.transforms.unflatten_authority import model

    fixture = ids.DigestFixture(
        3, model.UnflattenAuthorityPhase.PROJECTED_PREFLIGHT, ("native",),
    )
    with _canonical_validation_session(
        CanonicalSessionPhase.PROJECTED_PREPARATION, trust_sealed=False,
    ) as session:
        ids.canonical_bytes(fixture)      # direct miss
        ids.canonical_bytes(fixture)      # direct hit
        ids.authority_id(fixture)         # content-ID hit on the shared entry
        ids.authority_id((fixture,))      # content-ID miss: fresh tuple
        metrics = session.metrics

    assert metrics.bytes_lookup_hits == 1
    assert metrics.bytes_lookup_misses == 1
    assert metrics.content_id_lookup_hits == 1
    assert metrics.content_id_lookup_misses == 1
    assert metrics.inventory_seal_mints == 0
    assert metrics.inventory_seal_checks == 0
    assert metrics.occurrence_stamps == 4
    assert metrics.occurrence_stamps == _stamp_partition(metrics)
    # The legacy reuse counter still sees both hits; the attribution splits it.
    assert metrics.canonical_bytes_reuses == 2
    assert metrics.deep_validations == 2


def test_occurrence_stamps_are_attributed_to_record_content_id_lookups() -> None:
    """The record preimage builder is a content-ID lookup, hit or miss."""

    authority = _deep_authority()
    claim = authority.proposal.claims[0]
    with _canonical_validation_session(
        CanonicalSessionPhase.PROJECTED_PREPARATION, trust_sealed=False,
    ) as session:
        first = ids.claim_id(claim)
        second = ids.claim_id(claim)
        metrics = session.metrics

    assert first == second == claim.claim_id
    assert metrics.content_id_lookup_misses == 1
    assert metrics.content_id_lookup_hits == 1
    assert metrics.content_id_reuses == 1
    assert metrics.bytes_lookup_hits == metrics.bytes_lookup_misses == 0
    assert metrics.occurrence_stamps == 2
    assert metrics.occurrence_stamps == _stamp_partition(metrics)


def test_occurrence_stamps_are_attributed_to_inventory_seals() -> None:
    """A seal mint and every seal check each cost one stamp walk."""

    from d810.transforms.unflatten_authority import model
    from tests.unit.transforms.unflatten_authority.test_inventory_model import (
        _inventory,
    )

    inventory = _inventory()
    with _canonical_validation_session(
        CanonicalSessionPhase.OBSERVED_REVALIDATION, trust_sealed=False,
    ) as session:
        model.validate_semantic_graph_inventory(inventory)
        first = session.metrics
        model.validate_semantic_graph_inventory(inventory)
        second = session.metrics.delta(first)

    # First consumption: one failed seal check, one full validation whose
    # digest costs one content-ID miss, then one seal mint.
    assert first.inventory_seal_checks == 1
    assert first.inventory_seal_hits == 0
    assert first.inventory_seal_mints == 1
    assert first.inventory_validations == 1
    assert first.content_id_lookup_misses == 1
    assert first.occurrence_stamps == 3
    assert first.occurrence_stamps == _stamp_partition(first)
    # Second consumption: exactly one seal check that hits, nothing else.
    assert second.inventory_seal_checks == 1
    assert second.inventory_seal_hits == 1
    assert second.occurrence_stamps == 1
    assert second.total == 3


def test_process_report_carries_the_attribution_counters() -> None:
    ids.canonical_bytes(("attributed",))
    line = format_work_report(process_work_metrics(), pid=7)
    for name in canonical_session._COUNTER_NAMES:
        assert f'"{name}":' in line
    # Outside a session there is no lookup and therefore no stamp walk.
    assert '"occurrence_stamps":0' in line
    assert '"bytes_lookup_misses":0' in line


# --- sealed-occurrence trust experiment (opt-in, default OFF) ---------------


def _fixture(ea: int = 3) -> object:
    from d810.transforms.unflatten_authority import model

    return ids.DigestFixture(
        ea, model.UnflattenAuthorityPhase.PROJECTED_PREFLIGHT, ("native",),
    )


def test_trust_sealed_is_off_by_default_and_explicit_per_session(monkeypatch) -> None:
    monkeypatch.delenv(canonical_session._TRUST_ENV, raising=False)
    assert canonical_session._trust_sealed_default() is False
    monkeypatch.setattr(canonical_session, "_TRUST_SEALED_DEFAULT", False)
    with _canonical_validation_session(
        CanonicalSessionPhase.PROJECTED_PREPARATION,
    ) as session:
        assert session.trust_sealed is False
    with _canonical_validation_session(
        CanonicalSessionPhase.PROJECTED_PREPARATION, trust_sealed=True,
    ) as session:
        assert session.trust_sealed is True
    monkeypatch.setattr(canonical_session, "_TRUST_SEALED_DEFAULT", True)
    with _canonical_validation_session(
        CanonicalSessionPhase.OBSERVED_REVALIDATION,
    ) as session:
        assert session.trust_sealed is True
    with _canonical_validation_session(
        CanonicalSessionPhase.OBSERVED_REVALIDATION, trust_sealed=False,
    ) as session:
        assert session.trust_sealed is False
    with pytest.raises(TypeError):
        CanonicalValidationSession(
            CanonicalSessionPhase.OBSERVED_REVALIDATION, trust_sealed=1,
        )
    monkeypatch.setenv(canonical_session._TRUST_ENV, "1")
    assert canonical_session._trust_sealed_default() is True
    monkeypatch.setenv(canonical_session._TRUST_ENV, "0")
    assert canonical_session._trust_sealed_default() is False


@pytest.mark.parametrize(
    ("value", "expected"),
    ((None, False), ("", False), ("0", False), ("1", True)),
)
def test_trust_sealed_default_selects_strict_unless_explicitly_enabled(
    monkeypatch, value: str | None, expected: bool,
) -> None:
    """Unset and empty select strict mode; only an explicit value opts in."""

    if value is None:
        monkeypatch.delenv(canonical_session._TRUST_ENV, raising=False)
    else:
        monkeypatch.setenv(canonical_session._TRUST_ENV, value)
    assert canonical_session._trust_sealed_default() is expected


def test_trusted_hit_performs_zero_recursive_walks() -> None:
    """(a) A trusted-mode hit costs no ``_occurrence_stamp`` walk at all."""

    from d810.transforms.unflatten_authority import model
    from tests.unit.transforms.unflatten_authority.test_inventory_model import (
        _inventory,
    )

    fixture = _fixture()
    nested = ("outer", fixture, frozenset({7}), {"k": [fixture]})
    authority = _deep_authority()
    claim = authority.proposal.claims[0]
    inventory = _inventory()
    with _canonical_validation_session(
        CanonicalSessionPhase.PROJECTED_PREPARATION, trust_sealed=True,
    ) as session:
        first = ids.canonical_bytes(nested)
        ids.authority_id(authority)
        ids.claim_id(claim)
        model.validate_semantic_graph_inventory(inventory)
        seeded = session.metrics
        second = ids.canonical_bytes(nested)
        ids.authority_id(authority)
        ids.claim_id(claim)
        model.validate_semantic_graph_inventory(inventory)
        hits = session.metrics.delta(seeded)

    assert first == second
    # Misses never walk a stamp either: the guard is O(direct children).
    assert seeded.occurrence_stamps == 0
    assert seeded.deep_validations >= 2
    # Every repeated lookup is a hit and none of them recursed.
    assert hits.occurrence_stamps == 0
    assert hits.bytes_lookup_hits == 1
    assert hits.content_id_lookup_hits == 2
    assert hits.inventory_seal_hits == hits.inventory_seal_checks == 1
    assert hits.bytes_lookup_misses == hits.content_id_lookup_misses == 0
    assert hits.deep_validations == hits.wire_encodes == 0
    assert hits.inventory_validations == 0


def test_trusted_mode_never_serves_a_mutated_occurrence() -> None:
    """(b) Any change to a presented occurrence's fields misses the cache."""

    fixture = _fixture()
    with _canonical_validation_session(
        CanonicalSessionPhase.PROJECTED_PREPARATION, trust_sealed=True,
    ) as session:
        before = ids.canonical_bytes(fixture)
        # A nested atom field changes: the guard sees an unequal int.
        object.__setattr__(fixture, "ea", 4)
        after_ea = ids.canonical_bytes(fixture)
        # A nested container field is replaced with different content.
        object.__setattr__(fixture, "refs", ("other",))
        after_refs = ids.canonical_bytes(fixture)
        # Same value, different exact type (True is not 1).
        object.__setattr__(fixture, "ea", True)
        with pytest.raises(TypeError):
            ids.canonical_bytes(fixture)
        metrics = session.metrics

    assert ids.canonical_decode(before).ea == 3
    assert ids.canonical_decode(after_ea).ea == 4
    assert ids.canonical_decode(after_refs).refs == ("other",)
    assert metrics.bytes_lookup_misses == 4
    assert metrics.bytes_lookup_hits == 0
    assert metrics.deep_validations == 3
    # Only the replaced ``refs`` tuple was compared by content (old vs new).
    assert metrics.occurrence_stamps == 2


def test_trusted_mode_observes_in_place_child_mutation_at_the_child() -> None:
    """(b) A descendant mutated in place misses as soon as it is presented.

    This also characterizes the experiment's trust boundary: the parent's
    guard holds the child by identity, so the parent is only re-encoded once
    a lookup observes the mutation.  When the mutated child is never presented
    on its own the parent's stale answer stands - see
    ``test_sealed_trust_boundary_is_rejected_by_descendant_mutation`` for why
    that keeps the mode opt-in.  Strict mode (the default) detects the
    mutation through the recursive stamp either way.
    """

    child = _fixture()
    parent = ("parent", child)
    for trust_sealed, parent_hits in ((False, 0), (True, 1)):
        with _canonical_validation_session(
            CanonicalSessionPhase.PROJECTED_PREPARATION, trust_sealed=trust_sealed,
        ) as session:
            ids.canonical_bytes(parent)
            ids.canonical_bytes(child)
            object.__setattr__(child, "ea", 5)
            child_bytes = ids.canonical_bytes(child)
            parent_bytes = ids.canonical_bytes(parent)
            metrics = session.metrics
            object.__setattr__(child, "ea", 3)
        assert ids.canonical_decode(child_bytes).ea == 5
        assert metrics.bytes_lookup_hits == parent_hits
        if not trust_sealed:
            assert ids.canonical_decode(parent_bytes)[1].ea == 5


def test_sealed_trust_boundary_is_rejected_by_descendant_mutation(
    monkeypatch,
) -> None:
    """Step 2 decision: REJECT.  Sealed mode can answer with stale content.

    The falsified hypothesis was "a sealed session never answers with content
    that is not the live content of the presented occurrence".  A sealed guard
    holds the presented occurrence's *direct* children by identity, so an
    in-place ``object.__setattr__`` two levels down leaves every one of those
    identities intact and the cached answer is served unchanged.  Here the
    mutated field is an inventory block's ``anchor_ea`` - the native address a
    patch is anchored to - so the masked difference is safety-relevant, not
    cosmetic.  Strict mode's recursive stamp observes the same mutation.

    No call-site proof exists that production cannot reach this shape, so the
    sealed mode stays opt-in and the default stays strict.
    """

    from tests.unit.transforms.unflatten_authority.helpers import (
        projected_site_fixture,
    )

    answers: dict[bool, tuple[bytes, bytes, bytes, CanonicalWorkMetrics]] = {}
    for trust_sealed in (False, True):
        inventory = projected_site_fixture().source_inventory
        block = inventory.blocks[0]
        assert block.anchor_ea == 0x1000
        with _canonical_validation_session(
            CanonicalSessionPhase.PROJECTED_PREPARATION, trust_sealed=trust_sealed,
        ) as session:
            cached = ids.canonical_bytes(inventory)
            seeded = session.metrics
            # Only the descendant changes, and only the parent is presented.
            object.__setattr__(block, "anchor_ea", 0x1040)
            answer = ids.canonical_bytes(inventory)
            delta = session.metrics.delta(seeded)
        answers[trust_sealed] = (cached, answer, ids.canonical_bytes(inventory), delta)

    stale, strict_answer, strict_live, strict_delta = answers[False]
    assert strict_answer == strict_live != stale
    assert strict_delta.bytes_lookup_misses == 1
    assert strict_delta.bytes_lookup_hits == 0
    assert strict_delta.occurrence_stamps == 1

    stale, sealed_answer, sealed_live, sealed_delta = answers[True]
    assert sealed_answer == stale != sealed_live
    assert sealed_delta.bytes_lookup_hits == 1
    assert sealed_delta.bytes_lookup_misses == 0
    assert sealed_delta.occurrence_stamps == 0

    # The decision, encoded: an unconfigured process still selects strict.
    monkeypatch.delenv(canonical_session._TRUST_ENV, raising=False)
    assert canonical_session._trust_sealed_default() is False


def test_trusted_mode_accepts_a_content_equal_child_replacement_once() -> None:
    """A replaced-but-equal child costs one partial check, then identity."""

    fixture = _fixture()
    holder = ("holder", fixture)
    with _canonical_validation_session(
        CanonicalSessionPhase.PROJECTED_PREPARATION, trust_sealed=True,
    ) as session:
        first = ids.canonical_bytes(fixture)
        holder_bytes = ids.canonical_bytes(holder)
        seeded = session.metrics
        # Re-normalization pattern: a field is re-set to an equal, distinct
        # object (as a re-run __post_init__ does with tuple(sorted(...))).
        replacement = tuple(["native"])   # equal, but a distinct object
        assert replacement is not fixture.refs
        object.__setattr__(fixture, "refs", replacement)
        second = ids.canonical_bytes(fixture)
        after_first_presentation = session.metrics.delta(seeded)
        third = ids.canonical_bytes(fixture)
        after_second_presentation = session.metrics.delta(seeded).delta(
            after_first_presentation,
        )
        # The holder still references the same child object: identity hit.
        assert ids.canonical_bytes(holder) == holder_bytes
        assert session.metrics.occurrence_stamps == 2

    assert first == second == third == ids.canonical_bytes(fixture)
    assert seeded.occurrence_stamps == 0
    # The first presentation after the replacement was a hit that paid two
    # stamps (old child, new child) and adopted the live guard ...
    assert after_first_presentation.bytes_lookup_hits == 1
    assert after_first_presentation.occurrence_stamps == 2
    # ... so the next presentation is an identity hit with no walk.
    assert after_second_presentation.bytes_lookup_hits == 1
    assert after_second_presentation.occurrence_stamps == 0


def test_trusted_mode_guards_mutable_and_mapping_children() -> None:
    items = [1, 2]
    mapping = {"a": items, "b": 2.5}
    with _canonical_validation_session(
        CanonicalSessionPhase.PROJECTED_PREPARATION, trust_sealed=True,
    ) as session:
        ids.canonical_bytes(items)
        items.append(3)
        grown = ids.canonical_bytes(items)
        with pytest.raises(TypeError):
            ids.canonical_bytes(mapping)  # a bare float has no encoding
        mapping["b"] = 3
        ids.canonical_bytes(mapping)
        mapping["a"] = [9]
        ids.canonical_bytes(mapping)
        metrics = session.metrics
    assert ids.canonical_decode(grown) == [1, 2, 3]
    assert metrics.bytes_lookup_hits == 0
    assert metrics.bytes_lookup_misses == 5
    # The replaced list was compared by content against the retained one.
    assert metrics.occurrence_stamps == 2


def test_trusted_mode_keeps_the_strict_boundary() -> None:
    """(c) Boundary decode and fresh sessions still deep-validate."""

    fixture = _fixture()
    with _canonical_validation_session(
        CanonicalSessionPhase.PROJECTED_PREPARATION, trust_sealed=True,
    ) as projected:
        # First sight of any occurrence is a full deep validation.
        ids.canonical_bytes(fixture)
        assert projected.metrics.deep_validations == 1
        before = projected.metrics
        decoded = ids.validate_canonical_roundtrip(fixture, ids.DigestFixture)
        after = projected.metrics
    assert decoded == fixture
    assert after.canonical_bytes_reuses == before.canonical_bytes_reuses + 1
    assert after.roundtrip_decodes == before.roundtrip_decodes + 1
    assert after.deep_validations == before.deep_validations + 1
    assert after.wire_encodes == before.wire_encodes + 1

    # The fresh observed session starts empty: nothing is trusted across it.
    with _canonical_validation_session(
        CanonicalSessionPhase.OBSERVED_REVALIDATION, trust_sealed=True,
    ) as observed:
        ids.canonical_bytes(fixture)
        metrics = observed.metrics
    assert metrics.deep_validations == 1
    assert metrics.bytes_lookup_misses == 1
    assert metrics.canonical_bytes_reuses == 0

    # A raising validation still never populates a trusted entry.
    with _canonical_validation_session(
        CanonicalSessionPhase.OBSERVED_REVALIDATION, trust_sealed=True,
    ) as failing:
        object.__setattr__(fixture, "ea", "not-an-int")
        with pytest.raises(TypeError):
            ids.canonical_bytes(fixture)
        object.__setattr__(fixture, "ea", 3)
        ids.canonical_bytes(fixture)
        metrics = failing.metrics
    assert metrics.deep_validations == 1
    assert metrics.bytes_lookup_hits == 0


_CORPUS_LABELS = (
    "digest-fixture", "nested-containers", "deep-authority", "authority-proposal",
    "claim", "inventory", "site-source-inventory", "site-projected-inventory",
    "site-source-authority", "site-claims", "site-patch-step-facts", "site-raw-fact",
)


def _corpus_value(label: str) -> object:
    from tests.unit.transforms.unflatten_authority.helpers import (
        projected_site_fixture,
    )
    from tests.unit.transforms.unflatten_authority.test_inventory_model import (
        _inventory,
    )

    if label == "digest-fixture":
        return _fixture()
    if label == "nested-containers":
        return ("x", _fixture(), frozenset({1, "s"}), {"m": [_fixture(9)]})
    if label == "inventory":
        return _inventory()
    if label.startswith("site-"):
        site = projected_site_fixture()
        return getattr(site, label[len("site-"):].replace("-", "_"))
    authority = _deep_authority()
    if label == "deep-authority":
        return authority
    if label == "authority-proposal":
        return authority.proposal
    if label == "claim":
        return authority.proposal.claims[0]
    raise KeyError(label)


@pytest.mark.parametrize("label", _CORPUS_LABELS)
def test_trusted_mode_is_byte_identical_to_strict_mode(label: str) -> None:
    """(d) Strict and trusted sessions agree byte-for-byte on the corpus."""

    value = _corpus_value(label)
    outside = ids.canonical_bytes(value)
    outside_id = ids.authority_id(value)
    results = {}
    for trust_sealed in (False, True):
        with _canonical_validation_session(
            CanonicalSessionPhase.PROJECTED_PREPARATION, trust_sealed=trust_sealed,
        ) as session:
            first = ids.canonical_bytes(value)
            first_id = ids.authority_id(value)
            second = ids.canonical_bytes(value)
            second_id = ids.authority_id(value)
            results[trust_sealed] = (first, first_id, second, second_id, session.metrics)
    strict, trusted = results[False], results[True]
    assert strict[0] == strict[2] == trusted[0] == trusted[2] == outside
    assert strict[1] == strict[3] == trusted[1] == trusted[3] == outside_id
    # Same hit/miss profile, but the trusted session walked no stamps.
    assert strict[4].bytes_lookup_hits == trusted[4].bytes_lookup_hits == 1
    assert strict[4].content_id_lookup_hits == trusted[4].content_id_lookup_hits == 2
    assert strict[4].occurrence_stamps == 4
    assert trusted[4].occurrence_stamps == 0


def test_session_report_is_one_line_per_closed_session(monkeypatch) -> None:
    stream = io.StringIO()
    with _canonical_validation_session(
        CanonicalSessionPhase.OBSERVED_REVALIDATION, trust_sealed=True,
    ) as session:
        ids.canonical_bytes(("session-report",))
    canonical_session.emit_session_work_report(session, stream=stream)
    line = stream.getvalue()
    assert line.startswith("d810-authority-work-counters-session ")
    assert line.endswith("\n")
    assert '"phase":"observed-revalidation"' in line
    assert '"trust_sealed":true' in line
    assert '"bytes_lookup_misses":1' in line
    assert '"occurrence_stamps":0' in line
    assert line.rstrip("\n") == canonical_session.format_session_work_report(
        session, pid=__import__("os").getpid(),
    )
    with pytest.raises(TypeError):
        canonical_session.format_session_work_report(object(), pid=1)

    # When reporting is enabled the context manager emits the line at close.
    captured = io.StringIO()
    monkeypatch.setattr(canonical_session, "_REPORT_ENABLED", True)
    monkeypatch.setattr(canonical_session.sys, "stderr", captured)
    with _canonical_validation_session(CanonicalSessionPhase.PROJECTED_PREPARATION):
        pass
    assert captured.getvalue().startswith("d810-authority-work-counters-session ")
    assert '"phase":"projected-preparation"' in captured.getvalue()
