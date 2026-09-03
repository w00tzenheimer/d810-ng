"""Occurrence-identity invariants for the recorded-attempt memo.

``MbaDiscoveryStore`` answers a repeated observation from an in-memory memo
instead of re-serializing and re-writing the attempt.  Every real provider
mints a fresh ``uuid4`` per attempt (``d810-cobra``'s ``cobra_solve`` and
``d810-egglog``'s optimizer both do), so the memo cannot be keyed on the
persisted row verbatim: that key would miss on every retry and the store would
be paid for in full each time.

The memo is therefore keyed on an :class:`AttemptOccurrenceKey` -- every
semantic field the store persists *except* the deliberately volatile UUID.  Two
observations that agree on all of it are the same occurrence and the second one
is a duplicate; two that differ anywhere in it are different occurrences and
the second one must be stored.  These tests vary exactly one field at a time.
"""

from __future__ import annotations

from pathlib import Path
from uuid import uuid4

import pytest

import d810.mba.discovery_store as discovery_store_module
from d810.core.function_execution_identity import (
    FunctionExecutionIdentity,
    MbaObservationContext,
)
from d810.core.plugins import PluginIdentity
from d810.mba.discovery_models import DiscoveryAttempt, ReceiptStatus
from d810.mba.discovery_store import MbaDiscoveryStore
from d810.mba.provider_outcome import (
    MatcherOutcomeMetadata,
    MatcherSelection,
    MbaProviderOutcome,
    ProviderOutcomeStatus,
)
from d810.mba.provider_routing import MbaProviderKind
from d810.mba.typed_term import TypedBvTerm, canonicalize_ac_term, term_fingerprint

_LEAF_A = TypedBvTerm(None, 32, leaf_key=("reg", "a"))
_LEAF_B = TypedBvTerm(None, 32, leaf_key=("reg", "b"))
_RAW = TypedBvTerm("add", 32, children=(_LEAF_A, _LEAF_B))
#: Same canonical term, different raw spelling: isolates the raw fingerprint.
_RAW_PERMUTED = TypedBvTerm("add", 32, children=(_LEAF_B, _LEAF_A))
#: Different canonical term.
_RAW_OTHER = TypedBvTerm("add", 32, children=(_LEAF_A, TypedBvTerm(None, 32, value=3)))


def _attempt(
    *,
    attempt_uuid: str,
    raw_term: TypedBvTerm = _RAW,
    source_provenance: tuple[str, ...] = (),
    metadata: dict[str, object] | None = None,
    matcher: MatcherOutcomeMetadata | None = None,
    status: ProviderOutcomeStatus = ProviderOutcomeStatus.UNCHANGED,
    refusal_reason: str | None = None,
    input_cost: tuple[int, int] | None = (1, 1),
    output_cost: tuple[int, int] | None = None,
    proof_verdict: bool | None = None,
    elapsed_ms: float = 1.25,
    provider: MbaProviderKind = MbaProviderKind.EGRAPH,
    instruction_ea: int = 0x401002,
    block_serial: int | None = 3,
    block_ea: int | None = 0x401000,
    function_ea: int = 0x401000,
    function_rva: int = 0x1000,
    function_fingerprint: str = "function-fp",
    decompilation_session_id: str = "12345678-1234-5678-1234-567812345679",
    top_level_epoch: int = 1,
    evidence_generation: int = 2,
    maturity: str = "ir.canonical",
    input_identity: str = "idb-local:12345678-1234-5678-1234-567812345678",
    input_identity_provenance: str = "current_idb",
    external_evidence_allowed: bool = False,
    database_uuid: str = "12345678-1234-5678-1234-567812345678",
    database_identity: str = "idb-one",
    plugin_name: str = "plugin",
    plugin_distribution: str | None = "plugin-dist",
    plugin_version: str | None = "1.0",
    plugin_origin: str = "test",
    eligible_for_mining: bool = True,
) -> DiscoveryAttempt:
    canonical = canonicalize_ac_term(raw_term)
    outcome = MbaProviderOutcome(
        provider=provider,
        status=status,
        fingerprint=term_fingerprint(canonical),
        input_cost=input_cost,
        output_cost=output_cost,
        proof_verdict=proof_verdict,
        elapsed_ms=elapsed_ms,
        refusal_reason=refusal_reason,
        source_provenance=source_provenance,
        metadata=metadata,
        matcher=matcher,
    )
    return DiscoveryAttempt(
        attempt_uuid=attempt_uuid,
        context=MbaObservationContext(
            function_identity=FunctionExecutionIdentity(
                input_identity=input_identity,
                input_identity_provenance=input_identity_provenance,
                external_evidence_allowed=external_evidence_allowed,
                database_uuid=database_uuid,
                database_identity=database_identity,
                function_ea=function_ea,
                function_rva=function_rva,
                function_fingerprint=function_fingerprint,
                decompilation_session_id=decompilation_session_id,
                top_level_epoch=top_level_epoch,
                maturity=maturity,
                evidence_generation=evidence_generation,
            ),
            plugin_identity=PluginIdentity(
                name=plugin_name,
                distribution=plugin_distribution,
                version=plugin_version,
                origin=plugin_origin,
            ),
            instruction_ea=instruction_ea,
            block_serial=block_serial,
            block_ea=block_ea,
        ),
        raw_term=raw_term,
        canonical_term=canonical,
        outcome=outcome,
        eligible_for_mining=eligible_for_mining,
    )


def _attempt_rows(store: MbaDiscoveryStore) -> int:
    return int(
        store._connection.execute("SELECT COUNT(*) FROM provider_attempts").fetchone()[
            0
        ]
    )


def _assert_conflict_not_duplicate(
    tmp_path: Path, name: str, **variation: object
) -> None:
    """One attempt UUID, two different occurrences: never a silent duplicate.

    Only ``variation`` differs between the two attempts, so a memo keyed on the
    whole occurrence must miss and let the real path speak.  The real path
    finds the stored row under the same UUID, sees different bytes, and
    refuses.  Reporting ``DUPLICATE`` here hands back the *first* attempt's
    identifiers for content that was never stored.
    """

    attempt_uuid = str(uuid4())
    store = MbaDiscoveryStore(tmp_path / f"{name}.sqlite3")
    try:
        first = store.record_attempt(_attempt(attempt_uuid=attempt_uuid))
        assert first.status is ReceiptStatus.STORED
        second = store.record_attempt(
            _attempt(attempt_uuid=attempt_uuid, **variation)  # type: ignore[arg-type]
        )
        assert (
            second.status is not ReceiptStatus.DUPLICATE
        ), f"an attempt differing only in {name} was conflated with the first"
        assert second.status is ReceiptStatus.REFUSED
        assert second.reason == "attempt_uuid_conflict"
        assert _attempt_rows(store) == 1
    finally:
        store.close()


def test_differing_source_provenance_is_not_reported_as_a_duplicate(
    tmp_path: Path,
) -> None:
    """``source_provenance`` is persisted in ``outcome_payload``."""

    _assert_conflict_not_duplicate(
        tmp_path, "source_provenance", source_provenance=("egraph", "z3")
    )


def test_differing_metadata_is_not_reported_as_a_duplicate(tmp_path: Path) -> None:
    """``metadata`` is persisted in ``outcome_payload``."""

    _assert_conflict_not_duplicate(
        tmp_path, "metadata", metadata={"rule": "sub_to_add", "rewrites": 3}
    )


def test_differing_matcher_metadata_is_not_reported_as_a_duplicate(
    tmp_path: Path,
) -> None:
    """``matcher`` is persisted in ``outcome_payload``."""

    _assert_conflict_not_duplicate(
        tmp_path,
        "matcher",
        matcher=MatcherOutcomeMetadata(
            comparisons=5,
            lazy_swaps=1,
            flattened_arity=2,
            stop_reason="matched",
            selection=MatcherSelection.RAW,
            backend="cython",
        ),
    )


def test_repeated_occurrence_with_a_fresh_uuid_is_a_memo_hit(tmp_path: Path) -> None:
    """The same occurrence under a new ``uuid4`` must hit the memo.

    This is the runtime shape: ``d810-cobra`` and ``d810-egglog`` mint a fresh
    ``uuid4`` for every attempt, so keying the memo on the persisted row -- the
    UUID included -- would make every repeat a miss and hand the whole store
    cost back to the decompile thread.
    """

    store = MbaDiscoveryStore(tmp_path / "fresh-uuid.sqlite3")
    try:
        first = store.record_attempt(_attempt(attempt_uuid=str(uuid4())))
        assert first.status is ReceiptStatus.STORED
        for _ in range(3):
            repeat = store.record_attempt(_attempt(attempt_uuid=str(uuid4())))
            assert (
                repeat.status is ReceiptStatus.DUPLICATE
            ), "a repeated occurrence with a fresh UUID missed the memo"
            assert repeat.attempt_id == first.attempt_id
            assert repeat.term_id == first.term_id
            assert repeat.raw_term_id == first.raw_term_id
        assert _attempt_rows(store) == 1
    finally:
        store.close()


_VARIATIONS: dict[str, dict[str, object]] = {
    "instruction_ea": {"instruction_ea": 0x401008},
    "block_site": {"block_serial": 4, "block_ea": 0x401004},
    "decompilation_session_id": {
        "decompilation_session_id": "12345678-1234-5678-1234-56781234567a"
    },
    "evidence_generation": {"evidence_generation": 3},
    "top_level_epoch": {"top_level_epoch": 2},
    "maturity": {"maturity": "ir.global.optimized"},
    "function_identity": {
        "function_ea": 0x402000,
        "function_rva": 0x2000,
        "function_fingerprint": "other-function-fp",
    },
    "database_identity": {"database_identity": "idb-two"},
    "plugin_identity": {"plugin_version": "2.0"},
    "source_provenance": {"source_provenance": ("egraph", "z3")},
    "metadata": {"metadata": {"rule": "sub_to_add", "rewrites": 3}},
    "matcher": {
        "matcher": MatcherOutcomeMetadata(
            comparisons=5,
            lazy_swaps=1,
            flattened_arity=2,
            stop_reason="matched",
            selection=MatcherSelection.RAW,
            backend="cython",
        )
    },
    "outcome_status_and_refusal": {
        "status": ProviderOutcomeStatus.INELIGIBLE,
        "refusal_reason": "not_mba",
    },
    "costs": {"output_cost": (2, 4)},
    "proof_verdict": {"proof_verdict": True},
    "elapsed_ms": {"elapsed_ms": 9.5},
    "provider": {"provider": MbaProviderKind.COEFFICIENT_SOLVER},
    "canonical_term_fingerprint": {"raw_term": _RAW_OTHER},
    "raw_term_fingerprint": {"raw_term": _RAW_PERMUTED},
    "eligible_for_mining": {"eligible_for_mining": False},
}


@pytest.mark.parametrize("field_name", sorted(_VARIATIONS))
def test_varying_one_semantic_field_stores_a_second_row(
    tmp_path: Path, field_name: str
) -> None:
    """A different occurrence must miss the memo and be written.

    Each case changes exactly one semantic field the store persists.  A memo
    that answered ``DUPLICATE`` here would silently drop a real observation.
    """

    store = MbaDiscoveryStore(tmp_path / f"vary-{field_name}.sqlite3")
    try:
        first = store.record_attempt(_attempt(attempt_uuid=str(uuid4())))
        assert first.status is ReceiptStatus.STORED
        second = store.record_attempt(
            _attempt(attempt_uuid=str(uuid4()), **_VARIATIONS[field_name])  # type: ignore[arg-type]
        )
        assert (
            second.status is ReceiptStatus.STORED
        ), f"an attempt differing in {field_name} was conflated with the first"
        assert second.attempt_id != first.attempt_id
        assert _attempt_rows(store) == 2
    finally:
        store.close()


@pytest.mark.parametrize("field_name", sorted(_VARIATIONS))
def test_varying_one_semantic_field_changes_the_occurrence_key(
    field_name: str,
) -> None:
    """The occurrence key itself must move for every semantic field."""

    base = _attempt(attempt_uuid=str(uuid4()))
    varied = _attempt(attempt_uuid=str(uuid4()), **_VARIATIONS[field_name])  # type: ignore[arg-type]
    assert discovery_store_module.attempt_occurrence_key(
        base
    ) != discovery_store_module.attempt_occurrence_key(varied)


def test_the_attempt_uuid_alone_does_not_change_the_occurrence_key() -> None:
    """The UUID is the row's event identity, never part of the occurrence."""

    first = _attempt(attempt_uuid=str(uuid4()))
    second = _attempt(attempt_uuid=str(uuid4()))
    assert first.attempt_uuid != second.attempt_uuid
    assert discovery_store_module.attempt_occurrence_key(
        first
    ) == discovery_store_module.attempt_occurrence_key(second)


def test_the_occurrence_key_omits_exactly_the_attempt_uuid() -> None:
    """The stored payload and the occurrence key may differ only in the UUID.

    ``outcome_payload`` is classified MEMO_KEYED, which is only true because
    the sole payload member missing from the occurrence content is the UUID
    that is itself classified VOLATILE.  A payload member added without
    extending the occurrence content would break that classification, so it is
    pinned here rather than asserted in a comment.
    """

    attempt = _attempt(
        attempt_uuid=str(uuid4()),
        metadata={"rule": "x"},
        source_provenance=("egraph",),
    )
    payload = discovery_store_module._strict_loads(
        discovery_store_module._attempt_payload_bytes(attempt)
    )
    occurrence = discovery_store_module._strict_loads(
        discovery_store_module._attempt_occurrence_bytes(attempt)
    )
    assert payload.pop("attempt_uuid") == attempt.attempt_uuid
    assert payload == occurrence


def test_attempt_identity_covers_every_persisted_attempt_column() -> None:
    """Every persisted column is classified, and classified exactly once.

    ``MEMO_KEYED`` columns are fixed by the occurrence key, ``DERIVED`` columns
    are resolved from memo-keyed content, and ``VOLATILE`` columns legitimately
    differ between two equal occurrences.  A new column that is none of those
    fails here instead of silently joining or leaving the memo key.
    """

    columns = frozenset(discovery_store_module.attempt_insert_columns())
    assert columns, "the provider_attempts INSERT column list could not be read"
    memo_keyed = discovery_store_module.MEMO_KEYED_ATTEMPT_COLUMNS
    derived = discovery_store_module.DERIVED_ATTEMPT_COLUMNS
    volatile = discovery_store_module.VOLATILE_ATTEMPT_COLUMNS
    assert not memo_keyed & derived
    assert not memo_keyed & volatile
    assert not derived & volatile
    unclassified = columns - memo_keyed - derived - volatile
    assert not unclassified, (
        f"persisted attempt columns {sorted(unclassified)} are classified "
        "neither MEMO_KEYED, DERIVED nor VOLATILE"
    )
    stale = (memo_keyed | derived | volatile) - columns
    assert (
        not stale
    ), f"the classification names columns that no longer exist: {sorted(stale)}"
    assert volatile == frozenset({"attempt_uuid", "created_at"})


def test_the_memo_reports_the_hits_and_misses_it_actually_served(
    tmp_path: Path,
) -> None:
    """The fast path must be measurable, not merely believed.

    An acceptance run cannot tell a hit from a miss by looking at the stored
    rows, so the store counts both and one INFO line at sink close reports
    them.
    """

    store = MbaDiscoveryStore(tmp_path / "memo-stats.sqlite3")
    try:
        assert store.attempt_memo_stats() == discovery_store_module.AttemptMemoStats(
            hits=0, misses=0, occurrences=0, clears=0
        )
        store.record_attempt(_attempt(attempt_uuid=str(uuid4())))
        store.record_attempt(_attempt(attempt_uuid=str(uuid4())))
        store.record_attempt(_attempt(attempt_uuid=str(uuid4())))
        store.record_attempt(
            _attempt(attempt_uuid=str(uuid4()), instruction_ea=0x401008)
        )
        stats = store.attempt_memo_stats()
        assert (stats.hits, stats.misses, stats.occurrences) == (2, 2, 2)
        assert stats.clears == 0
        # The declared policy: one row per distinct occurrence, not per attempt.
        assert _attempt_rows(store) == stats.misses == 2
    finally:
        store.close()


def test_a_repeated_occurrence_does_not_raise_the_group_observation_count(
    tmp_path: Path,
) -> None:
    """A content repeat carries no new evidence, so it adds no weight.

    ``eligible_observation_count`` is the one aggregate that escapes this
    module (as ``MbaRuleProposal.occurrence_count``).  Under the declared
    dedupe policy it counts distinct-content observations, not provider
    visits, and that is pinned here so the change is a decision rather than a
    side effect.
    """

    store = MbaDiscoveryStore(tmp_path / "observation-count.sqlite3")
    try:
        first = store.record_attempt(_attempt(attempt_uuid=str(uuid4())))
        assert first.status is ReceiptStatus.STORED
        for _ in range(4):
            store.record_attempt(_attempt(attempt_uuid=str(uuid4())))
        count = store._connection.execute(
            "SELECT eligible_observation_count FROM residual_groups WHERE group_id=?",
            (first.group_id,),
        ).fetchone()[0]
        assert count == 1
        second = store.record_attempt(
            _attempt(attempt_uuid=str(uuid4()), instruction_ea=0x401008)
        )
        assert second.status is ReceiptStatus.STORED
        count = store._connection.execute(
            "SELECT eligible_observation_count FROM residual_groups WHERE group_id=?",
            (first.group_id,),
        ).fetchone()[0]
        assert count == 2
    finally:
        store.close()
