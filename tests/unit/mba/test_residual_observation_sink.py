from __future__ import annotations

import logging
import sqlite3
from dataclasses import FrozenInstanceError
from uuid import uuid4

import pytest

from d810.core.function_execution_identity import (
    FunctionExecutionIdentity,
    MbaObservationContext,
)
from d810.core.plugins import PluginIdentity
from d810.mba.discovery_store import MbaDiscoveryStore
from d810.mba.extension_api import MbaResidualRecord, MbaResidualReceipt
from d810.mba.provider_outcome import MbaProviderOutcome, ProviderOutcomeStatus
from d810.mba.provider_routing import MbaProviderKind
from d810.mba.residual_observation_sink import SqliteMbaResidualObservationSink
from d810.mba.semantic_canonicalization import canonicalize_mba_term
from d810.mba.typed_term import TypedBvTerm, term_cost, term_fingerprint


def _context(
    *, serial: int | None = 3, block_ea: int | None = 0x401000
) -> MbaObservationContext:
    identity = FunctionExecutionIdentity(
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
    return MbaObservationContext(
        function_identity=identity,
        plugin_identity=PluginIdentity("cobra", "d810-cobra", "1.0", "test"),
        instruction_ea=0x401002,
        block_serial=serial,
        block_ea=block_ea,
    )


def _record(
    *,
    status: ProviderOutcomeStatus = ProviderOutcomeStatus.UNCHANGED,
    provider: MbaProviderKind = MbaProviderKind.COEFFICIENT_SOLVER,
    raw: TypedBvTerm | None = None,
    canonical: TypedBvTerm | None = None,
    materialized: bool = False,
    candidate_cost: tuple[int, int] | None = None,
    replacement_cost: tuple[int, int] | None = None,
    context: MbaObservationContext | None = None,
) -> MbaResidualRecord:
    raw = raw or TypedBvTerm(
        "xor",
        32,
        children=(TypedBvTerm(None, 32, value=1), TypedBvTerm(None, 32, value=2)),
    )
    canonical = canonical or canonicalize_mba_term(raw).canonical_term
    outcome = MbaProviderOutcome(
        provider=provider,
        status=status,
        fingerprint=term_fingerprint(canonical),
        input_cost=candidate_cost or term_cost(raw),
        output_cost=replacement_cost,
        elapsed_ms=1.0,
    )
    return MbaResidualRecord(
        context=context or _context(),
        attempt_uuid=str(uuid4()),
        raw_term=raw,
        canonical_term=canonical,
        outcome=outcome,
        materialized=materialized,
        candidate_cost=candidate_cost,
        replacement_cost=replacement_cost,
    )


def test_record_rejects_applied_and_materialized_residuals() -> None:
    sink = SqliteMbaResidualObservationSink(MbaDiscoveryStore(":memory:"))
    assert (
        sink.record(_record(status=ProviderOutcomeStatus.APPLIED)).status == "rejected"
    )
    assert sink.record(_record(materialized=True)).status == "rejected"


def test_record_stores_then_reports_duplicate() -> None:
    store = MbaDiscoveryStore(":memory:")
    sink = SqliteMbaResidualObservationSink(store)
    observation = _record()
    first = sink.record(observation)
    second = sink.record(observation)
    assert first.status == "stored"
    assert second.status == "duplicate"


def test_provider_identity_policy_accepts_egglog_and_preserves_local_ineligibility() -> (
    None
):
    class CapturingStore:
        def __init__(self):
            self.attempt = None

        def record_attempt(self, attempt):
            self.attempt = attempt
            return type("Receipt", (), {"status": "stored"})()

    store = CapturingStore()
    sink = SqliteMbaResidualObservationSink(store)
    context = _context()
    context = MbaObservationContext(
        function_identity=context.function_identity,
        plugin_identity=PluginIdentity("egglog", "d810-egglog", "1.0", "test"),
        instruction_ea=context.instruction_ea,
        block_serial=context.block_serial,
        block_ea=context.block_ea,
    )
    assert (
        sink.record(_record(provider=MbaProviderKind.EGRAPH, context=context)).status
        == "stored"
    )
    assert store.attempt is not None
    assert store.attempt.eligible_for_mining is False


def test_store_refusal_maps_to_stable_rejected_receipt() -> None:
    class RefusingStore:
        def record_attempt(self, attempt):
            return type(
                "Receipt", (), {"status": "refused", "reason": "duplicate identity"}
            )()

    sink = SqliteMbaResidualObservationSink(RefusingStore())
    assert sink.record(_record()) == MbaResidualReceipt(
        "rejected", "duplicate identity"
    )


def test_record_validates_canonical_term_and_fingerprint() -> None:
    sink = SqliteMbaResidualObservationSink(MbaDiscoveryStore(":memory:"))
    raw = TypedBvTerm(
        "xor",
        32,
        children=(TypedBvTerm(None, 32, value=1), TypedBvTerm(None, 32, value=2)),
    )
    alternate = TypedBvTerm(None, 32, value=9)
    assert sink.record(_record(raw=raw, canonical=alternate)).status == "rejected"
    bad = MbaResidualRecord(
        context=_context(),
        attempt_uuid=str(uuid4()),
        raw_term=raw,
        canonical_term=canonicalize_mba_term(raw).canonical_term,
        outcome=MbaProviderOutcome(
            MbaProviderKind.COEFFICIENT_SOLVER, ProviderOutcomeStatus.UNCHANGED, "wrong"
        ),
    )
    assert sink.record(bad).status == "rejected"


def test_record_never_raises_storage_errors(caplog: pytest.LogCaptureFixture) -> None:
    class BrokenStore:
        def record_attempt(self, attempt):
            raise sqlite3.OperationalError("locked")

    sink = SqliteMbaResidualObservationSink(BrokenStore())
    with caplog.at_level(logging.ERROR):
        receipt = sink.record(_record())
    assert receipt == MbaResidualReceipt("rejected", "storage_error")
    assert "locked" in caplog.text


def test_close_is_idempotent_and_post_close_does_not_touch_store() -> None:
    class CountingStore:
        def __init__(self):
            self.calls = 0

        def record_attempt(self, attempt):
            self.calls += 1

        def close(self):
            self.calls += 100

    store = CountingStore()
    sink = SqliteMbaResidualObservationSink(store)
    sink.close()
    sink.close()
    receipt = sink.record(_record())
    assert receipt.status == "rejected"
    assert store.calls == 100
    with pytest.raises(FrozenInstanceError):
        receipt.status = "stored"
