"""Cost invariants for :mod:`d810.mba.discovery_store` provider attempts.

These tests pin *how much work* one recorded attempt is allowed to do.  The
store used to re-validate the entire causal domain on every transaction and to
JSON round-trip both terms four times per attempt, which made a live decompile
quadratic in the size of a database that is never truncated.
"""

from __future__ import annotations

import sqlite3
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
from d810.mba.provider_outcome import MbaProviderOutcome, ProviderOutcomeStatus
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
    value: int = 1,
    instruction_ea: int = 0x401002,
    attempt_uuid: str | None = None,
) -> DiscoveryAttempt:
    raw = TypedBvTerm(None, 32, value=value)
    canonical = canonicalize_ac_term(raw)
    outcome = MbaProviderOutcome(
        provider=MbaProviderKind.EGRAPH,
        status=ProviderOutcomeStatus.UNCHANGED,
        fingerprint=term_fingerprint(canonical),
        input_cost=(1, 1),
        elapsed_ms=1.25,
    )
    return DiscoveryAttempt(
        attempt_uuid=attempt_uuid or str(uuid4()),
        context=MbaObservationContext(
            function_identity=_identity(),
            plugin_identity=PluginIdentity(
                name="plugin", distribution="plugin-dist", version="1.0", origin="test"
            ),
            instruction_ea=instruction_ea,
            block_serial=3,
            block_ea=0x401000,
        ),
        raw_term=raw,
        canonical_term=canonical,
        outcome=outcome,
        eligible_for_mining=True,
    )


class _Counter:
    """Count calls to a store method without changing its behaviour."""

    def __init__(self, monkeypatch: pytest.MonkeyPatch, name: str) -> None:
        self.calls = 0
        original = getattr(MbaDiscoveryStore, name)

        def wrapper(store, *args, **kwargs):
            self.calls += 1
            return original(store, *args, **kwargs)

        monkeypatch.setattr(MbaDiscoveryStore, name, wrapper)


def test_recording_attempts_does_not_revalidate_every_group_every_time(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Per-attempt work must not grow with the number of stored groups.

    The full causal-domain sweep validates *every* group in the database.
    Running it on every transaction makes attempt N cost O(N) and the whole
    decompile O(N^2).
    """

    store = MbaDiscoveryStore(tmp_path / "cost.sqlite3")
    try:
        # Seed distinct groups so a full sweep is measurably more expensive
        # than a scoped validation.
        for value in range(12):
            store.record_attempt(_attempt(value=value + 1))
        counter = _Counter(monkeypatch, "_project_group_local")
        store.record_attempt(_attempt(value=100, instruction_ea=0x401100))
        # One new group: its own lifecycle validation before and after the
        # insert is fine.  Touching all thirteen groups is not.
        assert counter.calls <= 4, (
            f"recording one attempt validated {counter.calls} groups; "
            "the causal-domain sweep is running on every transaction"
        )
    finally:
        store.close()


def test_out_of_band_mutation_still_forces_a_full_causal_sweep(
    tmp_path: Path,
) -> None:
    """Skipping the sweep must never hide tampering the store did not make."""

    path = tmp_path / "tamper.sqlite3"
    store = MbaDiscoveryStore(path)
    try:
        store.record_attempt(_attempt())
        store._connection.execute(
            "UPDATE residual_group_events SET occurred_at=?",
            ("2026-01-01T00:00:00.000000Z",),
        )
        store._connection.commit()
        with pytest.raises(ValueError):
            store.status_counts()
    finally:
        store.close()


def test_foreign_writer_mutation_still_forces_a_full_causal_sweep(
    tmp_path: Path,
) -> None:
    """A second connection's write must invalidate any validation shortcut."""

    path = tmp_path / "foreign.sqlite3"
    store = MbaDiscoveryStore(path)
    try:
        store.record_attempt(_attempt())
        store.status_counts()
        foreign = sqlite3.connect(str(path))
        try:
            foreign.execute(
                "UPDATE residual_group_events SET occurred_at=?",
                ("2026-01-01T00:00:00.000000Z",),
            )
            foreign.commit()
        finally:
            foreign.close()
        with pytest.raises(ValueError):
            store.status_counts()
    finally:
        store.close()


def test_identical_repeat_attempt_skips_serialization_entirely(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A byte-identical retry must not re-serialize either term."""

    store = MbaDiscoveryStore(tmp_path / "repeat.sqlite3")
    try:
        attempt = _attempt()
        first = store.record_attempt(attempt)
        assert first.status is ReceiptStatus.STORED

        term_bytes_calls = 0
        original = discovery_store_module._term_bytes

        def counting_term_bytes(term, *, name):
            nonlocal term_bytes_calls
            term_bytes_calls += 1
            return original(term, name=name)

        monkeypatch.setattr(
            discovery_store_module, "_term_bytes", counting_term_bytes
        )
        second = store.record_attempt(attempt)
        assert second.status is ReceiptStatus.DUPLICATE
        assert term_bytes_calls == 0, (
            "an identical retry re-serialized the terms instead of "
            "short-circuiting on the recorded-attempt memo"
        )
    finally:
        store.close()


def test_stored_attempt_serializes_each_term_exactly_once(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """One newly stored attempt must round-trip its OWN terms once each.

    Identity, not the ``name`` argument, distinguishes the attempt's terms from
    the freshly decoded copies the lifecycle validation rebuilds from stored
    bytes.  ``record_attempt`` and ``_term`` each used to serialize both.
    """

    attempt = _attempt()
    store = MbaDiscoveryStore(tmp_path / "once.sqlite3")
    try:
        calls: list[str] = []
        original = discovery_store_module._term_bytes

        def counting_term_bytes(term, *, name):
            if term is attempt.canonical_term or term is attempt.raw_term:
                calls.append(name)
            return original(term, name=name)

        monkeypatch.setattr(
            discovery_store_module, "_term_bytes", counting_term_bytes
        )
        store.record_attempt(attempt)
        assert calls == ["canonical term", "raw term"], calls
    finally:
        store.close()


def test_persisted_rows_are_byte_identical_to_the_reference_encoding(
    tmp_path: Path,
) -> None:
    """The optimization must not change a single persisted byte."""

    attempt = _attempt()
    store = MbaDiscoveryStore(tmp_path / "bytes.sqlite3")
    try:
        receipt = store.record_attempt(attempt)
        rows = store._connection.execute(
            "SELECT t.canonical_term, t.canonical_fingerprint, rt.raw_term, "
            "rt.raw_fingerprint, pa.outcome_payload "
            "FROM provider_attempts pa "
            "JOIN terms t ON t.term_id = pa.term_id "
            "JOIN raw_terms rt ON rt.raw_term_id = pa.raw_term_id "
            "WHERE pa.attempt_id=?",
            (receipt.attempt_id,),
        ).fetchone()
    finally:
        store.close()

    assert bytes(rows[0]) == discovery_store_module._term_bytes(
        attempt.canonical_term, name="canonical term"
    )
    assert rows[1] == term_fingerprint(attempt.canonical_term)
    assert bytes(rows[2]) == discovery_store_module._term_bytes(
        attempt.raw_term, name="raw term"
    )
    assert rows[3] == term_fingerprint(attempt.raw_term)
    assert bytes(rows[4]) == discovery_store_module._attempt_payload_bytes(attempt)


def test_memo_defers_to_a_foreign_writer(tmp_path: Path) -> None:
    """A foreign commit must retire the memo, not be answered from it."""

    path = tmp_path / "memo-foreign.sqlite3"
    store = MbaDiscoveryStore(path)
    try:
        attempt = _attempt()
        assert store.record_attempt(attempt).status is ReceiptStatus.STORED
        assert store.record_attempt(attempt).status is ReceiptStatus.DUPLICATE

        foreign = sqlite3.connect(str(path))
        try:
            foreign.execute("UPDATE provider_attempts SET elapsed_ms=99")
            foreign.commit()
        finally:
            foreign.close()

        # The stored row no longer matches the attempt, so the real path must
        # run and refuse instead of the memo answering "duplicate".
        assert store.record_attempt(attempt).status is ReceiptStatus.REFUSED
    finally:
        store.close()
