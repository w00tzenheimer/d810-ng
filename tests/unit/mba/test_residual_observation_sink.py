from __future__ import annotations

import logging
import sqlite3
from dataclasses import FrozenInstanceError
from types import SimpleNamespace
from uuid import uuid4

import pytest

from d810.core.function_execution_identity import (
    FunctionExecutionIdentity,
    MbaObservationContext,
)
from d810.capabilities.plugin_host import PluginHostCapabilityRegistry
from d810.core.plugins import (
    BackendRegistry,
    BackendSpec,
    PassImplementationCandidate,
    PLUGIN_API_VERSION,
    PluginIdentity,
)
from d810.mba.discovery_store import MbaDiscoveryStore
from d810.mba.extension_api import (
    D810_MBA_RESIDUAL_OBSERVATION_CAPABILITY,
    MbaResidualObservationSink,
    MbaResidualRecord,
    MbaResidualReceipt,
)
from d810.mba.provider_outcome import MbaProviderOutcome, ProviderOutcomeStatus
from d810.mba.provider_routing import MbaProviderKind
from d810.mba.residual_observation_sink import SqliteMbaResidualObservationSink
import d810.mba.residual_observation_sink as sink_module
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
    outcome_input_cost: tuple[int, int] | None | object = ...,
) -> MbaResidualRecord:
    raw = raw or TypedBvTerm(
        "xor",
        32,
        children=(TypedBvTerm(None, 32, value=1), TypedBvTerm(None, 32, value=2)),
    )
    canonical = canonical or canonicalize_mba_term(raw).canonical_term
    if outcome_input_cost is ...:
        outcome_input_cost = candidate_cost or term_cost(raw)
    outcome = MbaProviderOutcome(
        provider=provider,
        status=status,
        fingerprint=term_fingerprint(canonical),
        input_cost=outcome_input_cost,
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


def _bound_sink(
    sink: SqliteMbaResidualObservationSink,
    *,
    context: MbaObservationContext | None = None,
    provider: MbaProviderKind = MbaProviderKind.COEFFICIENT_SOLVER,
):
    context = context or _context()
    if provider is MbaProviderKind.COEFFICIENT_SOLVER:
        pass_id, implementation_id = "mba-solve", "cobra-solve"
    else:
        pass_id, implementation_id = "mba-egraph", "egglog-optimizer"
    candidate = PassImplementationCandidate(
        pass_id=pass_id,
        backend_name=context.plugin_identity.name,
        backend_origin=context.plugin_identity.origin,
        rule_modules=(),
        rule_name=implementation_id,
    )
    activation = sink.bind_activation(context.plugin_identity)
    return sink.bind_implementation(activation, candidate)


def test_record_rejects_applied_and_materialized_residuals() -> None:
    sink = SqliteMbaResidualObservationSink(MbaDiscoveryStore(":memory:"))
    bound = _bound_sink(sink)
    assert (
        bound.record(_record(status=ProviderOutcomeStatus.APPLIED)).status == "rejected"
    )
    assert bound.record(_record(materialized=True)).status == "rejected"


def test_record_stores_then_reports_duplicate() -> None:
    store = MbaDiscoveryStore(":memory:")
    sink = SqliteMbaResidualObservationSink(store)
    bound = _bound_sink(sink)
    observation = _record()
    first = bound.record(observation)
    second = bound.record(observation)
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
    bound = _bound_sink(sink, context=context, provider=MbaProviderKind.EGRAPH)
    assert bound.record(
        _record(provider=MbaProviderKind.EGRAPH, context=context)
    ).status == "stored"
    assert store.attempt is not None
    assert store.attempt.eligible_for_mining is False


def test_store_refusal_maps_to_stable_rejected_receipt() -> None:
    class RefusingStore:
        def record_attempt(self, attempt):
            return type(
                "Receipt", (), {"status": "refused", "reason": "duplicate identity"}
            )()

    sink = SqliteMbaResidualObservationSink(RefusingStore())
    assert _bound_sink(sink).record(_record()) == MbaResidualReceipt(
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
    bound = _bound_sink(sink)
    assert bound.record(_record(raw=raw, canonical=alternate)).status == "rejected"
    bad = MbaResidualRecord(
        context=_context(),
        attempt_uuid=str(uuid4()),
        raw_term=raw,
        canonical_term=canonicalize_mba_term(raw).canonical_term,
        outcome=MbaProviderOutcome(
            MbaProviderKind.COEFFICIENT_SOLVER, ProviderOutcomeStatus.UNCHANGED, "wrong"
        ),
    )
    assert bound.record(bad).status == "rejected"


def test_record_never_raises_storage_errors(caplog: pytest.LogCaptureFixture) -> None:
    class BrokenStore:
        def record_attempt(self, attempt):
            raise sqlite3.OperationalError("locked")

    sink = SqliteMbaResidualObservationSink(BrokenStore())
    with caplog.at_level(logging.ERROR):
        receipt = _bound_sink(sink).record(_record())
    assert receipt == MbaResidualReceipt("rejected", "storage_error")
    assert "locked" in caplog.text
    assert "blk3@0x401000" in caplog.text


def test_malformed_context_does_not_log_a_bare_block_serial(
    caplog: pytest.LogCaptureFixture,
) -> None:
    malformed = SimpleNamespace(
        context=SimpleNamespace(
            plugin_identity=SimpleNamespace(name="hostile"),
            instruction_ea=0x401020,
            block_identity="blk3",
        )
    )

    with caplog.at_level(logging.ERROR):
        try:
            raise RuntimeError("malformed callback")
        except RuntimeError as error:
            SqliteMbaResidualObservationSink._safe_log(malformed, error)

    assert "instruction_ea=0x401020" in caplog.text
    assert "block=" not in caplog.text


@pytest.mark.parametrize(
    "error",
    (
        KeyboardInterrupt("storage interrupted"),
        SystemExit("storage exited"),
        BaseExceptionGroup("storage grouped", [RuntimeError("child")]),
    ),
)
def test_record_never_leaks_baseexception_through_callback(error) -> None:
    class BrokenStore:
        def record_attempt(self, attempt):
            raise error

    sink = SqliteMbaResidualObservationSink(BrokenStore())

    assert _bound_sink(sink).record(_record()) == MbaResidualReceipt(
        "rejected", "storage_error"
    )


def test_provider_identity_unknown_and_mismatched_are_rejected() -> None:
    sink = SqliteMbaResidualObservationSink(MbaDiscoveryStore(":memory:"))
    context = _context()
    unknown = MbaObservationContext(
        function_identity=context.function_identity,
        plugin_identity=PluginIdentity("other", "other", "1", "test"),
        instruction_ea=context.instruction_ea,
        block_serial=context.block_serial,
        block_ea=context.block_ea,
    )
    assert (
        sink.record(_record(context=unknown)).reason
        == "implementation_authority_missing"
    )
    assert (
        _bound_sink(sink, context=context)
        .record(_record(provider=MbaProviderKind.EGRAPH, context=context))
        .reason
        == "provider_plugin_mismatch"
    )


@pytest.mark.parametrize(
    ("candidate", "reason"),
    (
        (
            PassImplementationCandidate(
                pass_id="mba-solve",
                backend_name="cobra",
                backend_origin="spoofed-wheel",
                rule_modules=(),
                rule_name="cobra-solve",
            ),
            "implementation_activation_mismatch",
        ),
        (
            PassImplementationCandidate(
                pass_id="mba-solve",
                backend_name="lookalike",
                backend_origin="test",
                rule_modules=(),
                rule_name="cobra-solve",
            ),
            "implementation_activation_mismatch",
        ),
        (
            PassImplementationCandidate(
                pass_id="mba-egraph",
                backend_name="cobra",
                backend_origin="test",
                rule_modules=(),
                rule_name="cobra-solve",
            ),
            "unknown_provider_implementation",
        ),
    ),
)
def test_implementation_authority_rejects_spoofed_candidate_identity(
    candidate, reason
) -> None:
    sink = SqliteMbaResidualObservationSink(MbaDiscoveryStore(":memory:"))
    activation = sink.bind_activation(_context().plugin_identity)
    assert not hasattr(activation, "bind_implementation")

    with pytest.raises(ValueError, match=reason):
        sink.bind_implementation(activation, candidate)


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


def test_issued_activation_facade_fails_closed_after_sink_close() -> None:
    sink = SqliteMbaResidualObservationSink(MbaDiscoveryStore(":memory:"))
    identity = PluginIdentity("cobra", "cobra", "1.0", "test")
    facade = sink.bind_activation(identity)
    sink.close()

    assert facade.record(_record(context=_context())).reason == "closed"


def test_record_projects_record_only_costs_before_task5_translation() -> None:
    class CapturingStore:
        def __init__(self):
            self.attempt = None

        def record_attempt(self, attempt):
            self.attempt = attempt
            return type("Receipt", (), {"status": "stored"})()

    store = CapturingStore()
    sink = SqliteMbaResidualObservationSink(store)
    assert (
        _bound_sink(sink).record(
            _record(
                candidate_cost=(3, 4),
                replacement_cost=(5, 6),
                outcome_input_cost=None,
            )
        ).status
        == "stored"
    )
    assert store.attempt.outcome.input_cost == (3, 4)
    assert store.attempt.outcome.output_cost == (5, 6)


def test_record_catches_unexpected_validation_and_receipt_failures(
    monkeypatch: pytest.MonkeyPatch,
    caplog: pytest.LogCaptureFixture,
) -> None:
    sink = SqliteMbaResidualObservationSink(MbaDiscoveryStore(":memory:"))
    with monkeypatch.context() as patch:
        patch.setattr(
            sink_module,
            "canonicalize_mba_term",
            lambda _raw: (_ for _ in ()).throw(
                RuntimeError("validation boundary exploded")
            ),
        )
        with caplog.at_level(logging.ERROR):
            receipt = _bound_sink(sink).record(_record())
    assert receipt == MbaResidualReceipt("rejected", "storage_error")
    assert "validation boundary exploded" in caplog.text

    class BadReceiptStore:
        def record_attempt(self, _attempt):
            class BadReceipt:
                @property
                def status(self):
                    raise RuntimeError("receipt accessor exploded")

            return BadReceipt()

    sink = SqliteMbaResidualObservationSink(BadReceiptStore())
    with caplog.at_level(logging.ERROR):
        receipt = _bound_sink(sink).record(_record())
    assert receipt == MbaResidualReceipt("rejected", "storage_error")
    assert "receipt accessor exploded" in caplog.text


def test_verified_sha_eligibility_excludes_error_status() -> None:
    context = _context()
    identity = FunctionExecutionIdentity(
        input_identity="sha256:" + "a" * 64,
        input_identity_provenance="captured_from_ida",
        external_evidence_allowed=True,
        database_uuid=context.function_identity.database_uuid,
        database_identity=context.function_identity.database_identity,
        function_ea=context.function_identity.function_ea,
        function_rva=context.function_identity.function_rva,
        function_fingerprint=context.function_identity.function_fingerprint,
        decompilation_session_id=context.function_identity.decompilation_session_id,
        top_level_epoch=context.function_identity.top_level_epoch,
        maturity=context.function_identity.maturity,
        evidence_generation=context.function_identity.evidence_generation,
    )
    context = MbaObservationContext(
        function_identity=identity,
        plugin_identity=context.plugin_identity,
        instruction_ea=context.instruction_ea,
        block_serial=context.block_serial,
        block_ea=context.block_ea,
    )

    class CapturingStore:
        def __init__(self):
            self.attempts = []

        def record_attempt(self, attempt):
            self.attempts.append(attempt)
            return type("Receipt", (), {"status": "stored"})()

    store = CapturingStore()
    sink = SqliteMbaResidualObservationSink(store)
    bound = _bound_sink(sink, context=context)
    assert bound.record(_record(context=context)).status == "stored"
    assert store.attempts[-1].eligible_for_mining is True
    for status in ProviderOutcomeStatus:
        receipt = bound.record(_record(status=status, context=context))
        if status is ProviderOutcomeStatus.APPLIED:
            assert receipt.reason == "applied_not_residual"
        else:
            assert receipt.status == "stored"
            assert store.attempts[-1].eligible_for_mining is (
                status is not ProviderOutcomeStatus.ERROR
            )


def test_real_backend_activation_binds_sink_identity_and_rejects_forgery() -> None:
    store = MbaDiscoveryStore(":memory:")
    sink = SqliteMbaResidualObservationSink(store)
    host = PluginHostCapabilityRegistry()
    host.register(
        D810_MBA_RESIDUAL_OBSERVATION_CAPABILITY,
        MbaResidualObservationSink,
        sink,
        activation_binder=sink.bind_activation,
        implementation_binder=sink.bind_implementation,
    )
    seen = []

    class Plugin:
        def activate(self, context):
            seen.append(context.host.require(MbaResidualObservationSink))
            return type(
                "Activation",
                (),
                    {
                        "create_implementation": lambda self, _id: object(),
                        "capability_offers": lambda self: (),
                        "release_implementation": lambda self, _implementation: None,
                        "close": lambda self: None,
                },
            )()

    manifest = {
        "name": "cobra",
        "api_version": PLUGIN_API_VERSION,
        "provides": lambda: Plugin(),
        "requires": (D810_MBA_RESIDUAL_OBSERVATION_CAPABILITY,),
        "implements": {"mba-solve": "cobra-solve"},
    }
    registry = BackendRegistry(
        source=lambda: [
            BackendSpec(
                name="cobra",
                origin="cobra 1.0",
                load_manifest=lambda: manifest,
            )
        ],
        host=host,
        requirement_validator=host.validate,
        host_view_factory=host.view_for,
        implementation_host_view_factory=host.bind_implementation_view,
    )
    candidate = registry.require_unique_implementation(
        "mba-solve", install_hint="d810-cobra"
    )
    registry.activate_implementation(candidate)
    bound = registry.plugin_rule_services(candidate).host.require(
        MbaResidualObservationSink
    )

    assert len(seen) == 1
    assert seen[0] is not sink
    assert not hasattr(seen[0], "close")
    activated = _context()
    activated = MbaObservationContext(
        function_identity=activated.function_identity,
        plugin_identity=PluginIdentity("cobra", "cobra", "1.0", "cobra 1.0"),
        instruction_ea=activated.instruction_ea,
        block_serial=activated.block_serial,
        block_ea=activated.block_ea,
    )
    assert (
        seen[0].record(_record(context=activated)).reason
        == "implementation_authority_missing"
    )
    assert bound.record(_record(context=activated)).status == "stored"
    forged = _context()
    forged = MbaObservationContext(
        function_identity=forged.function_identity,
        plugin_identity=PluginIdentity("egglog", "d810-egglog", "1", "forged"),
        instruction_ea=forged.instruction_ea,
        block_serial=forged.block_serial,
        block_ea=forged.block_ea,
    )
    assert bound.record(_record(context=forged)).reason == "plugin_identity_mismatch"
