"""Content-identity invariants for the recorded-attempt memo.

``MbaDiscoveryStore`` answers a byte-identical retry from an in-memory memo
instead of re-serializing and re-writing the attempt.  The memo key is therefore
a *content key*: two attempts that differ in any byte the store persists must
never share it.  These tests vary exactly one persisted field at a time and pin
that the store still tells the truth about the second attempt.
"""

from __future__ import annotations

import re
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


def _identity() -> FunctionExecutionIdentity:
    return FunctionExecutionIdentity(
        input_identity="idb-local:12345678-1234-5678-1234-567812345678",
        input_identity_provenance="current_idb",
        external_evidence_allowed=False,
        database_uuid="12345678-1234-5678-1234-567812345678",
        database_identity="idb-one",
        function_ea=0x401000,
        function_rva=0x1000,
        function_fingerprint="function-fp",
        decompilation_session_id="12345678-1234-5678-1234-567812345679",
        top_level_epoch=1,
        maturity="ir.canonical",
        evidence_generation=2,
    )


def _attempt(
    *,
    attempt_uuid: str,
    source_provenance: tuple[str, ...] = (),
    metadata: dict[str, object] | None = None,
    matcher: MatcherOutcomeMetadata | None = None,
) -> DiscoveryAttempt:
    raw = TypedBvTerm(None, 32, value=7)
    canonical = canonicalize_ac_term(raw)
    outcome = MbaProviderOutcome(
        provider=MbaProviderKind.EGRAPH,
        status=ProviderOutcomeStatus.UNCHANGED,
        fingerprint=term_fingerprint(canonical),
        input_cost=(1, 1),
        elapsed_ms=1.25,
        source_provenance=source_provenance,
        metadata=metadata,
        matcher=matcher,
    )
    return DiscoveryAttempt(
        attempt_uuid=attempt_uuid,
        context=MbaObservationContext(
            function_identity=_identity(),
            plugin_identity=PluginIdentity(
                name="plugin", distribution="plugin-dist", version="1.0", origin="test"
            ),
            instruction_ea=0x401002,
            block_serial=3,
            block_ea=0x401000,
        ),
        raw_term=raw,
        canonical_term=canonical,
        outcome=outcome,
        eligible_for_mining=True,
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
    """One attempt UUID, two different contents: never a silent duplicate.

    Only ``variation`` differs between the two attempts, so a memo keyed on the
    whole persisted content must miss and let the real path speak.  The real
    path finds the stored row under the same UUID, sees different bytes, and
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


def test_differing_attempt_uuid_is_stored_as_a_new_row(tmp_path: Path) -> None:
    """``attempt_uuid`` is a persisted column and its own attempt identity."""

    store = MbaDiscoveryStore(tmp_path / "attempt-uuid.sqlite3")
    try:
        first = store.record_attempt(_attempt(attempt_uuid=str(uuid4())))
        assert first.status is ReceiptStatus.STORED
        second = store.record_attempt(_attempt(attempt_uuid=str(uuid4())))
        assert (
            second.status is ReceiptStatus.STORED
        ), "a second observation with its own UUID was conflated with the first"
        assert second.attempt_id != first.attempt_id
        assert _attempt_rows(store) == 2
    finally:
        store.close()


def test_attempt_identity_embeds_the_exact_persisted_payload(tmp_path: Path) -> None:
    """The memo key must carry the stored bytes, not a hand-listed subset.

    Deriving the key from the same canonical payload the row stores is what
    keeps it from drifting away from the schema a second time.
    """

    attempt = _attempt(attempt_uuid=str(uuid4()), metadata={"rule": "x"})
    identity = MbaDiscoveryStore._attempt_identity(attempt)
    assert discovery_store_module._attempt_payload_bytes(attempt) in identity


_DERIVED_ATTEMPT_COLUMNS = frozenset(
    {
        # Surrogate keys resolved from content already covered by the payload
        # (the function identity) or by the term fingerprints.
        "function_id",
        "term_id",
        "raw_term_id",
        # Wall-clock stamp: deliberately not part of an attempt's content.
        "created_at",
    }
)
_PAYLOAD_BACKED_ATTEMPT_COLUMNS = frozenset(
    {
        "attempt_uuid",
        "session_id",
        "top_level_epoch",
        "evidence_generation",
        "maturity",
        "instruction_ea",
        "block_serial",
        "block_ea",
        "provider",
        "plugin_name",
        "plugin_distribution",
        "plugin_version",
        "plugin_origin",
        "status",
        "input_cost_ops",
        "input_cost_nodes",
        "output_cost_ops",
        "output_cost_nodes",
        "proof_verdict",
        "elapsed_ms",
        "refusal_reason",
        "outcome_payload",
    }
)


def test_attempt_identity_covers_every_persisted_attempt_column() -> None:
    """A new persisted column must be classified, never silently forgotten.

    Every column below is either derived from content the identity already
    carries or written straight out of the canonical attempt payload the
    identity embeds.  Adding a column that is neither fails here.
    """

    source = Path(discovery_store_module.__file__).read_text(encoding="utf-8")
    match = re.search(r"INSERT INTO provider_attempts\(([^)]*)\)", source)
    assert match is not None, "the provider_attempts INSERT could not be located"
    columns = frozenset(name.strip() for name in match.group(1).split(","))
    unclassified = columns - _DERIVED_ATTEMPT_COLUMNS - _PAYLOAD_BACKED_ATTEMPT_COLUMNS
    assert not unclassified, (
        f"persisted attempt columns {sorted(unclassified)} are not covered by "
        "the attempt memo identity"
    )
    stale = (_DERIVED_ATTEMPT_COLUMNS | _PAYLOAD_BACKED_ATTEMPT_COLUMNS) - columns
    assert (
        not stale
    ), f"the coverage list names columns that no longer exist: {sorted(stale)}"


@pytest.mark.parametrize(
    "field_name",
    ("source_provenance", "metadata", "matcher"),
)
def test_outcome_content_fields_change_the_attempt_identity(field_name: str) -> None:
    """Each late-added outcome field must move the memo key on its own."""

    variations: dict[str, object] = {
        "source_provenance": ("egraph",),
        "metadata": {"rule": "x"},
        "matcher": MatcherOutcomeMetadata(
            comparisons=1, lazy_swaps=0, flattened_arity=0, stop_reason="matched"
        ),
    }
    attempt_uuid = str(uuid4())
    base = _attempt(attempt_uuid=attempt_uuid)
    varied = _attempt(attempt_uuid=attempt_uuid, **{field_name: variations[field_name]})  # type: ignore[arg-type]
    assert MbaDiscoveryStore._attempt_identity(
        base
    ) != MbaDiscoveryStore._attempt_identity(varied)
