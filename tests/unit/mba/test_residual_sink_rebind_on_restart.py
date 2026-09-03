"""Regression coverage for d81-uncr.

``state.load_project()`` restarts the manager *after* a provider rule has
already bound ``d810.mba.residual-observation.v1``.  The rule keeps its
activation-scoped view of the sink the restart closed, so before this fix
every residual observation of the whole session was rejected ``closed`` and
the discovery store stayed empty (1,044 attempts, 0 rows, headless dump of
``sub_7FFB0E398850`` on 2026-09-03).
"""

from __future__ import annotations

import logging
from types import SimpleNamespace
from uuid import uuid4

import pytest

from d810.capabilities.plugin_host import PluginHostCapabilityRegistry
from d810.core.function_execution_identity import (
    FunctionExecutionIdentity,
    MbaObservationContext,
)
from d810.core.plugins import PassImplementationCandidate, PluginIdentity
from d810.mba.extension_api import (
    D810_MBA_RESIDUAL_OBSERVATION_CAPABILITY,
    MbaResidualObservationSink,
    MbaResidualRecord,
)
from d810.mba.provider_outcome import MbaProviderOutcome, ProviderOutcomeStatus
from d810.mba.provider_routing import MbaProviderKind
from d810.mba.residual_observation_lifecycle import MbaResidualObservationLifecycle
from d810.mba.residual_observation_sink import (
    SqliteMbaResidualObservationSink,
    active_residual_sink,
)
from d810.mba.semantic_canonicalization import canonicalize_mba_term
from d810.mba.typed_term import TypedBvTerm, term_fingerprint


_IDENTITY = PluginIdentity("cobra", "d810-cobra", "1.0", "test")


class _FakeStore:
    """Minimal ``record_attempt``/``close`` store, one per sink generation."""

    def __init__(self, name: str) -> None:
        self.name = name
        self.attempts: list[object] = []
        self.closed = False

    def record_attempt(self, attempt):
        self.attempts.append(attempt)
        return SimpleNamespace(status="stored", reason=None)

    def close(self) -> None:
        self.closed = True


def _context() -> MbaObservationContext:
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
        plugin_identity=_IDENTITY,
        instruction_ea=0x401002,
        block_serial=3,
        block_ea=0x401000,
    )


def _record(left: int = 1, right: int = 2) -> MbaResidualRecord:
    raw = TypedBvTerm(
        "xor",
        32,
        children=(
            TypedBvTerm(None, 32, value=left),
            TypedBvTerm(None, 32, value=right),
        ),
    )
    canonical = canonicalize_mba_term(raw).canonical_term
    outcome = MbaProviderOutcome(
        provider=MbaProviderKind.COEFFICIENT_SOLVER,
        status=ProviderOutcomeStatus.UNCHANGED,
        fingerprint=term_fingerprint(canonical),
    )
    return MbaResidualRecord(
        attempt_uuid=str(uuid4()),
        context=_context(),
        raw_term=raw,
        canonical_term=canonical,
        outcome=outcome,
        materialized=False,
    )


_CANDIDATE = PassImplementationCandidate(
    pass_id="mba-solve",
    backend_name=_IDENTITY.name,
    backend_origin=_IDENTITY.origin,
    rule_modules=(),
    rule_name="cobra-solve",
)


def _provider_view(registry: PluginHostCapabilityRegistry):
    """Resolve the sink exactly the way an activated plugin rule does."""
    activation = registry.view_for(
        (D810_MBA_RESIDUAL_OBSERVATION_CAPABILITY,), _IDENTITY
    )
    implementation = registry.bind_implementation_view(activation, _CANDIDATE)
    return implementation.require(MbaResidualObservationSink)


@pytest.fixture
def lifecycle():
    registry = PluginHostCapabilityRegistry()
    stores: list[_FakeStore] = []

    def store_factory() -> _FakeStore:
        store = _FakeStore(f"generation-{len(stores)}")
        stores.append(store)
        return store

    subject = MbaResidualObservationLifecycle(
        store_factory=store_factory,
        registry_factory=lambda: registry,
    )
    subject.registry = registry
    subject.stores = stores
    try:
        yield subject
    finally:
        subject.stop()


def test_a_bound_provider_view_records_into_the_replacement_sink_after_restart(
    lifecycle,
) -> None:
    lifecycle.start()
    bound = _provider_view(lifecycle.registry)
    assert bound.record(_record()).status == "stored"

    lifecycle.stop()
    lifecycle.start()

    receipt = bound.record(_record(left=3, right=4))
    assert receipt.reason != "closed"
    assert receipt.status == "stored"
    assert len(lifecycle.stores) == 2
    assert len(lifecycle.stores[1].attempts) == 1


def test_the_closed_generation_receives_nothing_after_restart(lifecycle) -> None:
    lifecycle.start()
    bound = _provider_view(lifecycle.registry)
    bound.record(_record())
    first = lifecycle.stores[0]
    assert len(first.attempts) == 1

    lifecycle.stop()
    lifecycle.start()

    for offset in range(3):
        assert bound.record(_record(left=10 + offset)).status == "stored"

    assert first.closed is True
    assert len(first.attempts) == 1
    assert len(lifecycle.stores[1].attempts) == 3


def test_the_active_generation_is_the_started_sink_and_nothing_after_stop(
    lifecycle,
) -> None:
    assert active_residual_sink() is None
    lifecycle.start()
    assert active_residual_sink() is lifecycle.sink
    lifecycle.stop()
    assert active_residual_sink() is None


def test_a_closed_sink_without_a_replacement_still_fails_closed() -> None:
    """The fail-closed contract survives: no successor means no recording."""
    sink = SqliteMbaResidualObservationSink(_FakeStore("standalone"))
    facade = sink.bind_activation(_IDENTITY)
    sink.close()
    assert facade.record(_record()).reason == "closed"


def test_the_first_closed_rejection_warns_and_names_the_capability(
    caplog: pytest.LogCaptureFixture,
) -> None:
    sink = SqliteMbaResidualObservationSink(_FakeStore("standalone"))
    facade = sink.bind_activation(_IDENTITY)
    sink.close()
    with caplog.at_level(logging.WARNING):
        facade.record(_record())
        facade.record(_record(left=9))
    warnings = [
        item for item in caplog.records if item.levelno >= logging.WARNING
    ]
    assert len(warnings) == 1
    assert D810_MBA_RESIDUAL_OBSERVATION_CAPABILITY in warnings[0].getMessage()


def test_every_sink_close_in_a_load_project_flow_reports_the_traffic_it_saw(
    lifecycle, caplog: pytest.LogCaptureFixture
) -> None:
    """d81-uncr symptom: three closes in one session all reported zero traffic."""
    with caplog.at_level(logging.INFO, logger="d810.mba.residual_observation_sink"):
        lifecycle.start()
        generation_zero = lifecycle.sink
        bound = _provider_view(lifecycle.registry)
        bound.record(_record())  # generation 0 records directly
        lifecycle.stop()  # close #1
        lifecycle.start()
        for offset in range(2):
            bound.record(_record(left=20 + offset))  # forwarded by generation 0
        lifecycle.stop()  # close #2
        lifecycle.start()
        lifecycle.stop()  # close #3

    closes = [
        item.args
        for item in caplog.records
        if item.getMessage().startswith("mba residual observation sink close")
    ]
    assert len(closes) == 3
    # (stored, duplicate, rejected) per generation, reported at its own close.
    assert [item[1:] for item in closes] == [(1, 0, 0), (2, 0, 0), (0, 0, 0)]
    # Every attempt is reported exactly once, by whichever generation stored it.
    assert sum(item[1] for item in closes) == 3
    # The forwarding generation keeps its own tally: 1 direct, 2 forwarded.
    assert generation_zero.traffic() == (1, 0, 0, 2)
    rebinds = [
        item
        for item in caplog.records
        if item.getMessage().startswith("mba residual observation rebound")
    ]
    assert len(rebinds) == 1
    assert D810_MBA_RESIDUAL_OBSERVATION_CAPABILITY in rebinds[0].getMessage()
