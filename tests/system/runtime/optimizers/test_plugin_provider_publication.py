"""IDA-runtime coverage for Task 7 provider publication boundaries."""

from __future__ import annotations

import inspect
from dataclasses import replace
from collections import defaultdict
from types import SimpleNamespace

import ida_hexrays
import pytest

from d810.errors import D810Exception
from d810.core.function_execution_identity import (
    FunctionExecutionIdentity,
    MbaObservationContext,
)
from d810.capabilities.plugin_host import PluginHostCapabilityRegistry
from d810.core.plugins import (
    PLUGIN_API_VERSION,
    BackendRegistry,
    BackendSpec,
    PluginIdentity,
    PluginRuleServices,
)
from d810.mba.extension_api import (
    MbaResidualObservationSink,
    MbaResidualRecord,
    PendingMbaProviderObservation,
    D810_MBA_RESIDUAL_OBSERVATION_CAPABILITY,
)
from d810.mba.discovery_store import MbaDiscoveryStore
from d810.mba.provider_outcome import MbaProviderOutcome, ProviderOutcomeStatus
from d810.mba.provider_routing import MbaProviderKind
from d810.mba.semantic_canonicalization import canonicalize_mba_term
from d810.mba.typed_term import TypedBvTerm, term_fingerprint
from d810.mba.residual_observation_sink import SqliteMbaResidualObservationSink
from d810.optimizers.microcode.instructions.handler import (
    InstructionOptimizationRule,
    InstructionOptimizer,
)
from d810.hexrays.hooks import optinsn_adapter
from d810.hexrays.hooks.optinsn_adapter import InstructionOptimizerManager


def _context(plugin: PluginIdentity | None = None) -> MbaObservationContext:
    identity = FunctionExecutionIdentity(
        input_identity="idb-local:12345678-1234-5678-1234-567812345678",
        input_identity_provenance="current_idb",
        external_evidence_allowed=False,
        database_uuid="12345678-1234-5678-1234-567812345678",
        database_identity="task7-runtime-idb",
        function_ea=0x401000,
        function_rva=0x1000,
        function_fingerprint="task7-function",
        decompilation_session_id="12345678-1234-5678-1234-567812345679",
        top_level_epoch=1,
        maturity="ir.canonical",
        evidence_generation=1,
    )
    return MbaObservationContext(
        function_identity=identity,
        plugin_identity=plugin
        or PluginIdentity("cobra", "d810-cobra", "1.0", "task7-runtime"),
        instruction_ea=0x401002,
        block_serial=7,
        block_ea=0x401000,
    )


def _pending(
    status: ProviderOutcomeStatus = ProviderOutcomeStatus.UNCHANGED,
    *,
    attempt_uuid: str = "12345678-1234-5678-1234-567812345670",
) -> PendingMbaProviderObservation:
    raw = TypedBvTerm(
        "xor",
        32,
        children=(TypedBvTerm(None, 32, value=1), TypedBvTerm(None, 32, value=2)),
    )
    canonical = canonicalize_mba_term(raw).canonical_term
    return PendingMbaProviderObservation(
        attempt_uuid=attempt_uuid,
        raw_term=raw,
        canonical_term=canonical,
        outcome=MbaProviderOutcome(
            provider=MbaProviderKind.COEFFICIENT_SOLVER,
            status=status,
            fingerprint=term_fingerprint(canonical),
            input_cost=(2, 3),
        ),
    )


class _RecordingSink:
    def __init__(self):
        self.records: list[MbaResidualRecord] = []

    def record(self, observation: MbaResidualRecord):
        self.records.append(observation)
        return SimpleNamespace(status="stored")


class _Host:
    def __init__(self, sink):
        self.sink = sink

    def require(self, capability):
        assert capability is MbaResidualObservationSink
        return self.sink


class _FailingSink(_RecordingSink):
    def record(self, observation):
        self.records.append(observation)
        raise RuntimeError("sink unavailable")


class _FailingHost(_Host):
    def require(self, capability):
        raise RuntimeError("host resolution failed")


class _RefusingSink(_RecordingSink):
    def record(self, observation):
        self.records.append(observation)
        return SimpleNamespace(status="refused")


class _CountingHost(_Host):
    def __init__(self, sink):
        super().__init__(sink)
        self.require_calls = 0

    def require(self, capability):
        self.require_calls += 1
        return super().require(capability)


class _ProviderRule(InstructionOptimizationRule):
    NAME = "Task7Provider"
    maturities = []

    def __init__(
        self,
        status=ProviderOutcomeStatus.UNCHANGED,
        replacement=None,
        error: BaseException | None = None,
        reject_error: BaseException | None = None,
        accept_error: BaseException | None = None,
        finalizer_error: BaseException | None = None,
        pending_error: BaseException | None = None,
        pending_factory=None,
    ):
        super().__init__()
        self.pending = _pending(status) if pending_factory is None else None
        self.replacement = replacement
        self.error = error
        self.reject_error = reject_error
        self.accept_error = accept_error
        self.finalizer_error = finalizer_error
        self.pending_error = pending_error
        self.pending_factory = pending_factory
        self.accepted = 0
        self.rejected: list[str] = []
        self.pending_calls = 0
        self.finalizer_calls = 0
        self.finalizer_reasons: list[str] = []
        self.captured_attempt_uuids: list[str] = []
        self.drained_attempt_uuids: list[str] = []

    def check_and_replace(self, _blk, _ins):
        if self.error is not None:
            raise self.error
        if self.pending_factory is not None:
            self.pending = self.pending_factory()
            self.captured_attempt_uuids.append(self.pending.attempt_uuid)
        return self.replacement

    def pending_provider_observation(self):
        self.pending_calls += 1
        pending, self.pending = self.pending, None
        if pending is not None:
            self.drained_attempt_uuids.append(pending.attempt_uuid)
        if self.pending_error is not None:
            raise self.pending_error
        return pending

    def finalize_provider_observation(self, context, *, accepted, reason):
        self.finalizer_calls += 1
        self.finalizer_reasons.append(reason)
        receipt = super().finalize_provider_observation(
            context, accepted=accepted, reason=reason
        )
        if self.finalizer_error is not None:
            raise self.finalizer_error
        return receipt

    def record_mutation_accepted(self):
        self.accepted += 1
        if self.accept_error is not None:
            raise self.accept_error

    def record_mutation_rejected(self, reason):
        self.rejected.append(reason)
        if self.reject_error is not None:
            raise self.reject_error
        if self.pending is not None:
            self.pending = replace(
                self.pending,
                outcome=replace(self.pending.outcome, refusal_reason=reason),
            )


class _PendingProviderMixin:
    def __init__(self, replacement=None):
        super().__init__()
        self.pending = _pending()
        self.replacement = replacement
        self.finalizer_calls = 0
        self.pending_calls = 0
        self.finalizer_reasons: list[str] = []

    def pending_provider_observation(self):
        self.pending_calls += 1
        pending, self.pending = self.pending, None
        return pending

    def finalize_provider_observation(self, context, *, accepted, reason):
        self.finalizer_calls += 1
        self.finalizer_reasons.append(reason)
        return super().finalize_provider_observation(
            context, accepted=accepted, reason=reason
        )


class _Optimizer(InstructionOptimizer):
    RULE_CLASSES = [object]

    def add_rule(self, rule):
        self.rules.add(rule)
        return True


def _runtime_rule(
    status=ProviderOutcomeStatus.UNCHANGED,
    replacement=None,
    *,
    error: BaseException | None = None,
    reject_error: BaseException | None = None,
    accept_error: BaseException | None = None,
    finalizer_error: BaseException | None = None,
    pending_error: BaseException | None = None,
    pending_factory=None,
):
    sink = _RecordingSink()
    rule = _ProviderRule(
        status,
        replacement,
        error,
        reject_error,
        accept_error,
        finalizer_error,
        pending_error,
        pending_factory,
    )
    rule.bind_plugin_services(
        PluginRuleServices(
            plugin=PluginIdentity("cobra", "d810-cobra", "1.0", "task7-runtime"),
            host=_Host(sink),
        )
    )
    return rule, sink


def _runtime_optimizer(rule, stats=None):
    optimizer = _Optimizer([ida_hexrays.MMAT_PREOPTIMIZED], stats=stats)
    rule.maturities = [ida_hexrays.MMAT_PREOPTIMIZED]
    optimizer.add_rule(rule)
    return (
        optimizer,
        SimpleNamespace(
            mba=SimpleNamespace(
                maturity=ida_hexrays.MMAT_PREOPTIMIZED,
                entry_ea=0x401000,
            ),
            serial=7,
        ),
        SimpleNamespace(
            opcode=ida_hexrays.m_mov,
            ea=0x401002,
            _print=lambda: "task7-ins",
        ),
    )


def _manager_for(optimizer, stats):
    manager = InstructionOptimizerManager.__new__(InstructionOptimizerManager)
    manager.current_maturity = ida_hexrays.MMAT_PREOPTIMIZED
    manager._active_optimizers = [optimizer]
    manager._last_optimizer_tried = None
    manager._rewrite_seen = defaultdict(set)
    manager._cycle_quarantined_rule_names = defaultdict(set)
    manager._scheduled_implementation_names = frozenset()
    manager._resolve_active_instruction_rule_names = lambda _blk: None
    manager._residual_admission_cache_key = None
    manager._residual_admission_cache_value = False
    manager.analyzer = SimpleNamespace(analyze=lambda _blk, _ins: None)
    manager.stats = stats
    manager.generate_z3_code = False
    manager.mba_observation_context = lambda blk, ins, identity: replace(
        _context(identity),
        instruction_ea=ins.ea,
        block_serial=blk.serial,
        block_ea=blk.mba.entry_ea,
    )
    return manager


def _manager_stats():
    events = []
    return SimpleNamespace(
        events=events,
        record_optimizer_match=lambda *_args, **_kwargs: events.append("optimizer"),
        record_rule_fired=lambda *_args, **_kwargs: events.append("rule"),
        record_cycle_detected=lambda *_args, **_kwargs: None,
        record_expression_bloat_rejected=lambda *_args, **_kwargs: None,
    )


def _context_factory(rule, _blk, _anchor):
    return _context(rule.plugin_services.plugin)


def test_terminal_outcomes_publish_exactly_once_at_outer_boundary():
    statuses = (
        ProviderOutcomeStatus.UNCHANGED,
        ProviderOutcomeStatus.INELIGIBLE,
        ProviderOutcomeStatus.UNAVAILABLE,
        ProviderOutcomeStatus.OVER_BUDGET,
        ProviderOutcomeStatus.PROOF_FAILED,
        ProviderOutcomeStatus.RECONSTRUCTION_FAILED,
        ProviderOutcomeStatus.ERROR,
    )
    for status in statuses:
        rule, sink = _runtime_rule(status)
        optimizer, blk, ins = _runtime_optimizer(rule)
        assert (
            optimizer.get_optimized_instruction(
                blk, ins, observation_context_factory=_context_factory
            )
            is None
        )
        assert len(sink.records) == 1
        assert sink.records[0].outcome.status is status
        assert rule.pending is None
        assert rule.finalizer_calls == 1
        assert rule.pending_calls == 1
        assert rule.finalizer_reasons == ["provider_terminal"]


def test_legacy_or_unbound_rule_is_a_noop_for_the_observation_sink():
    sink = _RecordingSink()
    rule = _ProviderRule()
    optimizer, blk, ins = _runtime_optimizer(rule)
    # The rule remains unbound, so even a valid pending value cannot resolve a sink.
    optimizer.get_optimized_instruction(
        blk, ins, observation_context_factory=lambda *_args: _context()
    )
    assert sink.records == []


def test_improved_attempt_waits_then_rejection_publishes_once():
    rule, sink = _runtime_rule(
        ProviderOutcomeStatus.IMPROVED,
        replacement=SimpleNamespace(
            opcode=1, ea=0x401002, _print=lambda: "task7-replacement"
        ),
    )
    optimizer, blk, ins = _runtime_optimizer(rule)
    assert (
        optimizer.get_optimized_instruction(
            blk, ins, observation_context_factory=_context_factory
        )
        is not None
    )
    assert sink.records == []
    optimizer.record_mutation_rejected("rewrite_cycle")
    assert len(sink.records) == 1
    assert rule.rejected == ["rewrite_cycle"]
    optimizer.record_mutation_rejected("rewrite_cycle")
    assert len(sink.records) == 1
    assert rule.finalizer_calls == 1
    assert rule.pending_calls == 1
    assert rule.finalizer_reasons == ["rewrite_cycle"]


def test_acceptance_drains_improved_attempt_without_residual_or_losing_hook():
    rule, sink = _runtime_rule(
        ProviderOutcomeStatus.IMPROVED,
        replacement=SimpleNamespace(
            opcode=1, ea=0x401002, _print=lambda: "task7-replacement"
        ),
    )
    optimizer, blk, ins = _runtime_optimizer(rule)
    optimizer.get_optimized_instruction(
        blk, ins, observation_context_factory=_context_factory
    )
    optimizer.record_mutation_accepted()
    assert rule.accepted == 1
    assert sink.records == []
    assert optimizer._pending_replacement_rule is None
    assert rule.finalizer_calls == 1
    assert rule.pending_calls == 1
    assert rule.finalizer_reasons == ["accepted"]
    optimizer.clear_pending_provider_observation()
    assert rule.finalizer_calls == 1
    assert rule.pending_calls == 1


def test_missing_context_and_forged_identity_clear_without_publication():
    rule, sink = _runtime_rule()
    optimizer, blk, ins = _runtime_optimizer(rule)
    assert optimizer.get_optimized_instruction(blk, ins) is None
    assert sink.records == []
    rule, sink = _runtime_rule()
    optimizer, blk, ins = _runtime_optimizer(rule)
    forged = _context(PluginIdentity("cobra", "d810-cobra", "forged", "task7"))
    assert (
        optimizer.get_optimized_instruction(
            blk,
            ins,
            observation_context_factory=lambda *_args: forged,
        )
        is None
    )
    assert sink.records == []


def test_callback_cleanup_drains_pending_state_and_is_idempotent():
    rule, sink = _runtime_rule()
    optimizer, blk, ins = _runtime_optimizer(rule)
    assert (
        optimizer.get_optimized_instruction(
            blk, ins, observation_context_factory=_context_factory
        )
        is None
    )
    optimizer.clear_pending_provider_observation()
    optimizer.clear_pending_provider_observation()
    assert rule.pending is None
    assert len(sink.records) == 1
    assert rule.finalizer_calls == 1
    assert rule.pending_calls == 1
    assert rule.finalizer_reasons == ["provider_terminal"]


def test_sibling_terminal_publication_cannot_own_later_replacement():
    sink = _RecordingSink()
    identity = PluginIdentity("cobra", "d810-cobra", "1.0", "task7-runtime")
    host = _Host(sink)
    first = _ProviderRule(ProviderOutcomeStatus.UNCHANGED)
    second = _ProviderRule(
        ProviderOutcomeStatus.IMPROVED,
        SimpleNamespace(opcode=1, ea=0x401002, _print=lambda: "replacement"),
    )
    for rule in (first, second):
        rule.bind_plugin_services(PluginRuleServices(identity, host))
    optimizer = _Optimizer([ida_hexrays.MMAT_PREOPTIMIZED], stats=None)
    for rule in (first, second):
        rule.maturities = [ida_hexrays.MMAT_PREOPTIMIZED]
        optimizer.add_rule(rule)
    blk = SimpleNamespace(
        mba=SimpleNamespace(
            maturity=ida_hexrays.MMAT_PREOPTIMIZED,
            entry_ea=0x401000,
        ),
        serial=7,
    )
    ins = SimpleNamespace(opcode=ida_hexrays.m_mov, ea=0x401002, _print=lambda: "ins")
    assert (
        optimizer.get_optimized_instruction(
            blk,
            ins,
            observation_context_factory=lambda rule, *_: _context(
                rule.plugin_services.plugin
            ),
        )
        is not None
    )
    assert [record.outcome.status for record in sink.records] == [
        ProviderOutcomeStatus.UNCHANGED
    ]
    optimizer.record_mutation_rejected("rewrite_cycle")
    assert len(sink.records) == 2
    assert sink.records[1].outcome.refusal_reason == "rewrite_cycle"


def test_callback_cleanup_drains_every_child_pending_attempt():
    optimizer = _Optimizer([ida_hexrays.MMAT_PREOPTIMIZED], stats=None)
    rules = []
    for _ in range(2):
        rule, _sink = _runtime_rule()
        rule.maturities = [ida_hexrays.MMAT_PREOPTIMIZED]
        optimizer.add_rule(rule)
        rules.append(rule)
    # Simulate two providers retaining state when an adapter exits early.
    optimizer._pending_replacement_rule = None
    optimizer.clear_pending_provider_observation()
    for rule in rules:
        assert rule.pending is None


@pytest.mark.parametrize("failure", ("sink", "host"))
def test_publication_failures_are_isolated_and_still_drain_pending(failure):
    sink = _FailingSink() if failure == "sink" else _RecordingSink()
    host = _Host(sink) if failure == "sink" else _FailingHost(sink)
    rule = _ProviderRule()
    rule.bind_plugin_services(
        PluginRuleServices(
            PluginIdentity("cobra", "d810-cobra", "1.0", "task7-runtime"), host
        )
    )
    optimizer, blk, ins = _runtime_optimizer(rule)
    assert (
        optimizer.get_optimized_instruction(
            blk, ins, observation_context_factory=_context_factory
        )
        is None
    )
    assert rule.pending is None


def test_no_candidate_does_not_resolve_the_host_sink():
    sink = _RecordingSink()
    host = _CountingHost(sink)
    rule = _ProviderRule()
    rule.pending = None
    rule.bind_plugin_services(
        PluginRuleServices(
            PluginIdentity("cobra", "d810-cobra", "1.0", "task7-runtime"), host
        )
    )
    optimizer, blk, ins = _runtime_optimizer(rule)
    assert (
        optimizer.get_optimized_instruction(
            blk, ins, observation_context_factory=_context_factory
        )
        is None
    )
    assert host.require_calls == 0
    assert sink.records == []


def test_sink_refusal_receipt_is_accepted_without_mutation_side_effect():
    sink = _RefusingSink()
    rule = _ProviderRule()
    rule.bind_plugin_services(
        PluginRuleServices(
            PluginIdentity("cobra", "d810-cobra", "1.0", "task7-runtime"),
            _Host(sink),
        )
    )
    optimizer, blk, ins = _runtime_optimizer(rule)
    assert (
        optimizer.get_optimized_instruction(
            blk, ins, observation_context_factory=_context_factory
        )
        is None
    )
    assert len(sink.records) == 1
    assert rule.pending is None


def test_finalizer_error_still_drains_and_preserves_terminal_result():
    rule, sink = _runtime_rule(finalizer_error=RuntimeError("finalizer failed"))
    optimizer, blk, ins = _runtime_optimizer(rule)
    assert (
        optimizer.get_optimized_instruction(
            blk, ins, observation_context_factory=_context_factory
        )
        is None
    )
    assert rule.pending is None
    assert len(sink.records) == 1
    assert rule.finalizer_calls == 1


def test_pending_hook_error_is_contained_after_destructive_clear():
    rule, sink = _runtime_rule(pending_error=RuntimeError("pending hook failed"))
    optimizer, blk, ins = _runtime_optimizer(rule)
    assert (
        optimizer.get_optimized_instruction(
            blk, ins, observation_context_factory=_context_factory
        )
        is None
    )
    assert rule.pending is None
    assert sink.records == []
    assert rule.pending_calls == 1


@pytest.mark.parametrize(
    "error",
    (
        KeyboardInterrupt("pending interrupted"),
        SystemExit("pending exited"),
        BaseExceptionGroup("pending grouped", [RuntimeError("child")]),
    ),
)
def test_pending_hook_baseexception_is_contained_after_destructive_clear(error):
    rule, sink = _runtime_rule(pending_error=error)
    optimizer, blk, ins = _runtime_optimizer(rule)

    assert (
        optimizer.get_optimized_instruction(
            blk, ins, observation_context_factory=_context_factory
        )
        is None
    )
    assert rule.pending is None
    assert sink.records == []
    assert rule.pending_calls == 1


@pytest.mark.parametrize(
    "error",
    (
        KeyboardInterrupt("provider interrupted"),
        SystemExit("provider exited"),
        BaseExceptionGroup("provider grouped", [RuntimeError("child")]),
    ),
)
def test_external_provider_baseexception_is_contained_and_drained(error):
    rule, sink = _runtime_rule(error=error)
    optimizer, blk, ins = _runtime_optimizer(rule)

    assert (
        optimizer.get_optimized_instruction(
            blk, ins, observation_context_factory=_context_factory
        )
        is None
    )
    assert rule.pending is None
    assert len(sink.records) == 1
    assert rule.pending_calls == 1
    assert rule.finalizer_reasons == ["provider_exception"]


@pytest.mark.parametrize(
    ("field", "error"),
    (
        ("pending_error", KeyboardInterrupt("internal pending interrupted")),
        ("finalizer_error", SystemExit("internal finalizer exited")),
    ),
)
def test_internal_rule_fatal_provider_hooks_are_not_contained(field, error):
    rule = _ProviderRule(**{field: error})
    optimizer, blk, ins = _runtime_optimizer(rule)

    with pytest.raises(type(error), match="internal"):
        optimizer.get_optimized_instruction(
            blk, ins, observation_context_factory=_context_factory
        )


def test_internal_child_fatal_cleanup_is_not_contained():
    manager = InstructionOptimizerManager.__new__(InstructionOptimizerManager)

    def fatal_cleanup():
        raise KeyboardInterrupt("internal child interrupted")

    manager.instruction_optimizers = [
        SimpleNamespace(clear_pending_provider_observation=fatal_cleanup)
    ]
    manager.analyzer = None

    with pytest.raises(KeyboardInterrupt, match="internal child"):
        manager._clear_pending_provider_state()


def test_acceptance_hook_error_preserves_mutation_and_statistics():
    stats = _manager_stats()
    rule, sink = _runtime_rule(
        ProviderOutcomeStatus.IMPROVED,
        replacement=SimpleNamespace(
            opcode=ida_hexrays.m_mov,
            ea=0x401002,
            valid=True,
            _print=lambda: "replacement",
        ),
        accept_error=RuntimeError("accepted hook failed"),
    )
    optimizer, blk, _ins = _runtime_optimizer(rule, stats=stats)
    manager = _manager_for(optimizer, stats)
    original = SimpleNamespace(
        opcode=ida_hexrays.m_mov,
        ea=0x401002,
        valid=True,
        _print=lambda: "original",
        swap=lambda _other: None,
    )
    monkeypatch = pytest.MonkeyPatch()
    try:
        monkeypatch.setattr(
            optinsn_adapter, "check_ins_mop_size_are_ok", lambda _x: True
        )
        hashes = iter((10, 20))
        monkeypatch.setattr(optinsn_adapter, "hash_minsn", lambda *_args: next(hashes))
        assert manager.optimize(blk, original) is True
    finally:
        monkeypatch.undo()
    assert rule.accepted == 1
    assert sink.records == []
    assert stats.events == ["rule", "optimizer"]


def test_real_backend_activation_uses_activation_bound_sink_for_publication():
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
    activated: list[tuple[PluginIdentity, object, object]] = []

    class Plugin:
        def activate(self, context):
            activated.append(
                (
                    context.identity,
                    context.host,
                    context.host.require(MbaResidualObservationSink),
                )
            )
            return SimpleNamespace(
                create_implementation=lambda _implementation_id: object(),
                release_implementation=lambda _implementation: None,
                capability_offers=lambda: (),
                close=lambda: None,
            )

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
                origin="cobra task7",
                load_manifest=lambda: manifest,
            )
        ],
        host=host,
        requirement_validator=host.validate,
        host_view_factory=host.view_for,
        implementation_host_view_factory=host.bind_implementation_view,
    )
    activation = registry.activate("cobra")
    assert activation is not None
    identity, activation_host, bound_sink = activated[0]
    assert bound_sink is not sink
    candidate = registry.require_unique_implementation(
        "mba-solve", install_hint="d810-cobra"
    )
    registry.activate_implementation(candidate)
    services = registry.plugin_rule_services(candidate)
    assert services.plugin == identity
    assert services.provider == candidate
    assert services.host is not activation_host

    rule = _ProviderRule()
    rule.bind_plugin_services(services)
    optimizer, blk, ins = _runtime_optimizer(rule)
    assert (
        optimizer.get_optimized_instruction(
            blk, ins, observation_context_factory=_context_factory
        )
        is None
    )
    status = store.status_counts()
    assert sum(count for _state, count in status.group_counts) == 1
    store.close()


def test_unexpected_provider_exception_drains_attempt_on_cleanup():
    rule, sink = _runtime_rule(error=ValueError("unexpected provider failure"))
    optimizer, blk, ins = _runtime_optimizer(rule)
    with pytest.raises(ValueError, match="unexpected provider failure"):
        optimizer.get_optimized_instruction(
            blk, ins, observation_context_factory=_context_factory
        )
    optimizer.clear_pending_provider_observation()
    optimizer.clear_pending_provider_observation()
    assert rule.pending is None
    assert len(sink.records) == 1
    assert rule.finalizer_calls == 1
    assert rule.pending_calls == 1
    assert rule.finalizer_reasons == ["provider_exception"]


@pytest.mark.parametrize("error_type", (RuntimeError, D810Exception))
def test_contained_provider_exception_finalizes_once(error_type):
    rule, sink = _runtime_rule(error=error_type("contained provider failure"))
    optimizer, blk, ins = _runtime_optimizer(rule)
    assert (
        optimizer.get_optimized_instruction(
            blk, ins, observation_context_factory=_context_factory
        )
        is None
    )
    assert rule.pending is None
    assert len(sink.records) == 1
    assert rule.finalizer_calls == 1
    assert rule.pending_calls == 1
    assert rule.finalizer_reasons == ["provider_exception"]


def test_pattern_and_z3_overrides_accept_publication_context_factory():
    from d810.optimizers.microcode.instructions.pattern_matching.handler import (
        PatternOptimizer,
    )
    from d810.optimizers.microcode.instructions.z3.handler import Z3Optimizer

    for optimizer_type in (PatternOptimizer, Z3Optimizer):
        parameters = inspect.signature(
            optimizer_type.get_optimized_instruction
        ).parameters
        assert "observation_context_factory" in parameters


def test_real_pattern_and_z3_optimizers_publish_terminal_and_defer_replacement(
    monkeypatch,
):
    from d810.optimizers.microcode.instructions.pattern_matching.handler import (
        PatternMatchingRule,
        PatternOptimizer,
        RulePatternInfo,
    )
    from d810.optimizers.microcode.instructions.z3.handler import Z3Optimizer, Z3Rule

    class PatternProvider(_PendingProviderMixin, PatternMatchingRule):
        PATTERN = None
        REPLACEMENT_PATTERN = None

        def __init__(self, replacement=None):
            super().__init__(replacement)

        def check_candidate(self, _candidate):
            return True

        def check_pattern_and_replace(self, _pattern, _candidate):
            return self.replacement

    class Z3Provider(_PendingProviderMixin, Z3Rule):
        PATTERN = None
        REPLACEMENT_PATTERN = None

        def __init__(self, replacement=None):
            super().__init__(replacement)

        def check_candidate(self, _candidate):
            return True

        def check_and_replace(self, _blk, _ins, *, contextual_anchor_ins=None):
            del contextual_anchor_ins
            return self.replacement

    blk = SimpleNamespace(
        mba=SimpleNamespace(
            maturity=ida_hexrays.MMAT_PREOPTIMIZED,
            entry_ea=0x401000,
        ),
        serial=7,
    )
    ins = SimpleNamespace(opcode=ida_hexrays.m_mov, ea=0x401002, _print=lambda: "ins")
    ast = SimpleNamespace()
    monkeypatch.setattr(
        "d810.optimizers.microcode.instructions.pattern_matching.handler.minsn_to_ast",
        lambda _ins: ast,
    )
    for optimizer, rule in (
        (PatternOptimizer([ida_hexrays.MMAT_PREOPTIMIZED], None), PatternProvider()),
        (Z3Optimizer([ida_hexrays.MMAT_PREOPTIMIZED], None), Z3Provider()),
    ):
        sink = _RecordingSink()
        rule.bind_plugin_services(
            PluginRuleServices(
                PluginIdentity("cobra", "d810-cobra", "1.0", "task7-runtime"),
                _Host(sink),
            )
        )
        rule.maturities = [ida_hexrays.MMAT_PREOPTIMIZED]
        if isinstance(optimizer, PatternOptimizer):
            optimizer.rules.add(rule)
            optimizer._allowed_root_opcodes.add(ins.opcode)
            optimizer._get_candidates = lambda _ast: [RulePatternInfo(rule, None)]
        else:
            optimizer.rules.add(rule)
        assert (
            optimizer.get_optimized_instruction(
                blk, ins, observation_context_factory=_context_factory
            )
            is None
        )
        assert len(sink.records) == 1
        assert rule.finalizer_calls == 1
        assert rule.finalizer_reasons == ["provider_terminal"]

        replacement = SimpleNamespace(
            opcode=ida_hexrays.m_mov, ea=ins.ea, _print=lambda: "replacement"
        )
        rule.replacement = replacement
        rule.pending = _pending(ProviderOutcomeStatus.IMPROVED)
        assert (
            optimizer.get_optimized_instruction(
                blk, ins, observation_context_factory=_context_factory
            )
            is replacement
        )
        assert len(sink.records) == 1
        optimizer.record_mutation_rejected("rewrite_cycle")
        assert len(sink.records) == 2
        assert rule.finalizer_calls == 2
        assert rule.finalizer_reasons == ["provider_terminal", "rewrite_cycle"]

        rule.pending = _pending(ProviderOutcomeStatus.IMPROVED)
        assert (
            optimizer.get_optimized_instruction(
                blk, ins, observation_context_factory=_context_factory
            )
            is replacement
        )
        optimizer.record_mutation_accepted()
        optimizer.clear_pending_provider_observation()
        assert len(sink.records) == 2
        assert rule.finalizer_calls == 3
        assert rule.finalizer_reasons[-1] == "accepted"


def test_real_pattern_runtime_exception_finalizes_once(monkeypatch):
    from d810.optimizers.microcode.instructions.pattern_matching.handler import (
        PatternMatchingRule,
        PatternOptimizer,
        RulePatternInfo,
    )

    class PatternProvider(_PendingProviderMixin, PatternMatchingRule):
        PATTERN = None
        REPLACEMENT_PATTERN = None

        def check_candidate(self, _candidate):
            return True

        def check_pattern_and_replace(self, _pattern, _candidate):
            raise RuntimeError("pattern provider failure")

    optimizer = PatternOptimizer([ida_hexrays.MMAT_PREOPTIMIZED], None)
    rule = PatternProvider()
    sink = _RecordingSink()
    rule.bind_plugin_services(
        PluginRuleServices(
            PluginIdentity("cobra", "d810-cobra", "1.0", "task7-runtime"),
            _Host(sink),
        )
    )
    rule.maturities = [ida_hexrays.MMAT_PREOPTIMIZED]
    optimizer.rules.add(rule)
    optimizer._allowed_root_opcodes.add(ida_hexrays.m_mov)
    optimizer._get_candidates = lambda _ast: [RulePatternInfo(rule, None)]
    monkeypatch.setattr(
        "d810.optimizers.microcode.instructions.pattern_matching.handler.minsn_to_ast",
        lambda _ins: SimpleNamespace(),
    )
    blk = SimpleNamespace(
        mba=SimpleNamespace(
            maturity=ida_hexrays.MMAT_PREOPTIMIZED,
            entry_ea=0x401000,
        ),
        serial=7,
    )
    ins = SimpleNamespace(opcode=ida_hexrays.m_mov, ea=0x401002, _print=lambda: "ins")
    assert (
        optimizer.get_optimized_instruction(
            blk, ins, observation_context_factory=_context_factory
        )
        is None
    )
    assert len(sink.records) == 1
    assert rule.finalizer_calls == 1
    assert rule.finalizer_reasons == ["provider_exception"]


def test_rejection_hook_error_discards_stale_improved_attempt():
    rule, sink = _runtime_rule(
        ProviderOutcomeStatus.IMPROVED,
        replacement=SimpleNamespace(
            opcode=1, ea=0x401002, _print=lambda: "task7-replacement"
        ),
        reject_error=RuntimeError("reject hook failed"),
    )
    optimizer, blk, ins = _runtime_optimizer(rule)
    assert (
        optimizer.get_optimized_instruction(
            blk, ins, observation_context_factory=_context_factory
        )
        is not None
    )
    optimizer.record_mutation_rejected("rewrite_cycle")
    assert rule.pending is None
    assert sink.records == []
    assert rule.finalizer_calls == 1
    assert rule.pending_calls == 1


@pytest.mark.parametrize(
    ("veto", "reason"),
    (
        ("invalid_operand_size", "invalid_operand_size"),
        ("expression_bloat", "expression_bloat"),
        ("rewrite_noop", "rewrite_noop"),
        ("rewrite_cycle", "rewrite_cycle"),
    ),
)
def test_real_manager_outer_veto_updates_and_publishes_provider_outcome(
    monkeypatch, veto, reason
):
    rule, sink = _runtime_rule(
        ProviderOutcomeStatus.IMPROVED,
        replacement=SimpleNamespace(
            opcode=ida_hexrays.m_mov,
            ea=0x401002,
            valid=True,
            _print=lambda: "task7-replacement",
        ),
    )
    optimizer, blk, ins = _runtime_optimizer(rule)
    optimizer.maturities = [ida_hexrays.MMAT_PREOPTIMIZED]
    stats = _manager_stats()
    manager = _manager_for(optimizer, stats)

    original = SimpleNamespace(
        opcode=ida_hexrays.m_mov,
        ea=0x401002,
        valid=True,
        _print=lambda: "task7-ins",
        swap=lambda _other: None,
    )
    blk.serial = 7
    if veto == "invalid_operand_size":
        rule.replacement.valid = False
        monkeypatch.setattr(
            optinsn_adapter,
            "check_ins_mop_size_are_ok",
            lambda candidate: candidate.valid,
        )
    elif veto == "expression_bloat":
        monkeypatch.setattr(
            optinsn_adapter,
            "check_ins_mop_size_are_ok",
            lambda _candidate: True,
        )
        monkeypatch.setattr(
            optinsn_adapter,
            "count_minsn_nodes",
            lambda candidate: 1 if candidate is original else 3,
        )
    else:
        monkeypatch.setattr(
            optinsn_adapter,
            "check_ins_mop_size_are_ok",
            lambda _candidate: True,
        )
        hashes = iter((10, 10) if veto == "rewrite_noop" else (10, 20))
        monkeypatch.setattr(optinsn_adapter, "hash_minsn", lambda *_args: next(hashes))
        monkeypatch.setattr(
            optinsn_adapter, "_rewrite_history_key", lambda *_args, **_kwargs: (1, 2, 3)
        )
        if veto == "rewrite_cycle":
            manager._rewrite_seen[(1, 2, 3)].add(20)

    # Use a real manager boundary with the same contextual owner EA.
    owner = SimpleNamespace(ea=0x401100, opcode=ida_hexrays.m_mov)
    result = manager.optimize(blk, original, contextual_anchor_ins=owner)
    assert result is False
    assert rule.rejected == [reason]
    assert len(sink.records) == 1
    assert sink.records[0].outcome.refusal_reason == reason
    assert sink.records[0].context.instruction_ea == owner.ea
    assert sink.records[0].context.block_serial == 7
    assert sink.records[0].context.block_ea == blk.mba.entry_ea


def test_real_adapter_entry_and_finally_drain_on_unexpected_exception():
    rule, _sink = _runtime_rule()
    optimizer, blk, ins = _runtime_optimizer(rule)
    manager = _manager_for(optimizer, _manager_stats())
    manager.instruction_optimizers = [optimizer]
    manager.instruction_visitor = SimpleNamespace()
    manager._decompilation_lifecycle = None
    manager._capture_callback_nop_sites = lambda _blk: set()
    manager.log_info_on_input = lambda _blk, _ins: False
    manager._report_callback_nop_delta = lambda *_args, **_kwargs: None

    def raise_unexpected(*_args, **_kwargs):
        rule.pending = _pending(ProviderOutcomeStatus.ERROR)
        optimizer._pending_replacement_rule = rule
        raise ValueError("adapter failure")

    manager.optimize = raise_unexpected
    with pytest.raises(ValueError, match="adapter failure"):
        manager.func(blk, ins)
    assert rule.pending is None
    assert optimizer._pending_replacement_rule is None
    assert optimizer._pending_replacement_context is None


@pytest.mark.parametrize(
    ("accept_error", "finalizer_error"),
    (
        (None, None),
        (RuntimeError("accepted hook failed"), None),
        (None, RuntimeError("accepted finalizer failed")),
    ),
    ids=("normal", "accepted-hook-runtime-error", "finalizer-runtime-error"),
)
def test_real_adapter_acceptance_drains_attempt_captured_inside_callback(
    monkeypatch, accept_error, finalizer_error
):
    stats = _manager_stats()
    attempt_uuid = "12345678-1234-5678-1234-567812345671"
    rule, sink = _runtime_rule(
        replacement=SimpleNamespace(
            opcode=ida_hexrays.m_mov,
            ea=0x401002,
            valid=True,
            _print=lambda: "replacement",
        ),
        accept_error=accept_error,
        finalizer_error=finalizer_error,
        pending_factory=lambda: _pending(
            ProviderOutcomeStatus.IMPROVED,
            attempt_uuid=attempt_uuid,
        ),
    )
    optimizer, blk, ins = _runtime_optimizer(rule, stats=stats)
    manager = _manager_for(optimizer, stats)
    manager.instruction_optimizers = [optimizer]
    manager._decompilation_lifecycle = None
    manager._capture_callback_nop_sites = lambda _blk: set()
    manager.log_info_on_input = lambda _blk, _ins: False
    manager._report_callback_nop_delta = lambda *_args, **_kwargs: None
    manager._bind_validated_fact_view_for_callback = lambda _blk: []
    ins.swap = lambda _other: None
    ins.optimize_solo = lambda: None
    blk.mark_lists_dirty = lambda: None
    monkeypatch.setattr(optinsn_adapter, "check_ins_mop_size_are_ok", lambda _x: True)
    monkeypatch.setattr(optinsn_adapter, "safe_verify", lambda *_args, **_kwargs: None)
    hashes = iter((10, 20))
    monkeypatch.setattr(optinsn_adapter, "hash_minsn", lambda *_args: next(hashes))

    assert rule.pending is None
    assert manager.func(blk, ins) is True
    assert sink.records == []
    assert rule.accepted == 1
    assert rule.pending is None
    assert rule.captured_attempt_uuids == [attempt_uuid]
    assert rule.drained_attempt_uuids == [attempt_uuid]
    assert rule.finalizer_reasons == ["callback_cleanup", "accepted"]
    assert rule.finalizer_calls == 2
    assert rule.pending_calls == 2
    assert stats.events == ["rule", "optimizer"]
    assert optimizer._pending_replacement_rule is None
    assert optimizer._pending_replacement_context is None


def test_real_adapter_sequential_retry_processes_each_fresh_attempt_once(monkeypatch):
    stats = _manager_stats()
    attempt_uuids = (
        "12345678-1234-5678-1234-567812345672",
        "12345678-1234-5678-1234-567812345673",
    )
    attempts = iter(
        _pending(ProviderOutcomeStatus.IMPROVED, attempt_uuid=attempt_uuid)
        for attempt_uuid in attempt_uuids
    )
    tracker_snapshots: list[frozenset[int]] = []

    def capture_attempt():
        tracker_snapshots.append(frozenset(optimizer._provider_finalized_rules))
        return next(attempts)

    rule, sink = _runtime_rule(
        replacement=SimpleNamespace(
            opcode=ida_hexrays.m_mov,
            ea=0x401002,
            valid=True,
            _print=lambda: "replacement",
        ),
        pending_factory=capture_attempt,
    )
    optimizer, blk, ins = _runtime_optimizer(rule, stats=stats)
    manager = _manager_for(optimizer, stats)
    manager.instruction_optimizers = [optimizer]
    manager._decompilation_lifecycle = None
    manager._capture_callback_nop_sites = lambda _blk: set()
    manager.log_info_on_input = lambda _blk, _ins: False
    manager._report_callback_nop_delta = lambda *_args, **_kwargs: None
    manager._bind_validated_fact_view_for_callback = lambda _blk: []
    ins.swap = lambda _other: None
    ins.optimize_solo = lambda: None
    blk.mark_lists_dirty = lambda: None
    monkeypatch.setattr(optinsn_adapter, "check_ins_mop_size_are_ok", lambda _x: True)
    monkeypatch.setattr(optinsn_adapter, "safe_verify", lambda *_args, **_kwargs: None)
    hashes = iter((10, 20, 20, 30))
    monkeypatch.setattr(optinsn_adapter, "hash_minsn", lambda *_args: next(hashes))

    assert manager.func(blk, ins) is True
    assert rule.pending is None
    assert rule.captured_attempt_uuids == [attempt_uuids[0]]
    assert rule.drained_attempt_uuids == [attempt_uuids[0]]

    assert manager.func(blk, ins) is True
    assert rule.pending is None
    assert rule.captured_attempt_uuids == list(attempt_uuids)
    assert rule.drained_attempt_uuids == list(attempt_uuids)
    assert len(set(rule.captured_attempt_uuids)) == 2
    assert tracker_snapshots == [frozenset(), frozenset()]
    assert rule.accepted == 2
    assert rule.finalizer_reasons == ["callback_cleanup", "accepted", "accepted"]
    assert rule.finalizer_calls == 3
    assert rule.pending_calls == 3
    assert sink.records == []
    assert stats.events == ["rule", "optimizer", "rule", "optimizer"]
    assert optimizer._pending_replacement_rule is None
    assert optimizer._pending_replacement_context is None


def test_reset_rules_clears_stale_tracker_before_new_rule_is_drained():
    old_rule, _old_sink = _runtime_rule()
    optimizer, blk, ins = _runtime_optimizer(old_rule)
    assert (
        optimizer.get_optimized_instruction(
            blk, ins, observation_context_factory=_context_factory
        )
        is None
    )
    assert optimizer._provider_finalized_rules == {id(old_rule)}

    new_rule, new_sink = _runtime_rule()
    optimizer._provider_finalized_rules.add(id(new_rule))
    optimizer.reset_rules()
    optimizer.add_rule(new_rule)
    optimizer.clear_pending_provider_observation()

    assert new_rule.pending is None
    assert new_rule.finalizer_reasons == ["callback_cleanup"]
    assert new_rule.finalizer_calls == 1
    assert new_rule.pending_calls == 1
    assert new_rule.drained_attempt_uuids == [
        "12345678-1234-5678-1234-567812345670"
    ]
    assert new_sink.records == []
    assert optimizer._provider_finalized_rules == {id(new_rule)}


def test_real_adapter_early_gateway_and_no_match_retry_leave_no_provider_state():
    rule, _sink = _runtime_rule()
    optimizer, blk, ins = _runtime_optimizer(rule)
    manager = _manager_for(optimizer, _manager_stats())
    manager.instruction_optimizers = [optimizer]
    manager.instruction_visitor = SimpleNamespace()
    manager._decompilation_lifecycle = None
    manager._capture_callback_nop_sites = lambda _blk: set()
    manager._report_callback_nop_delta = lambda *_args, **_kwargs: None
    manager._bind_validated_fact_view_for_callback = lambda _blk: []
    manager.log_info_on_input = lambda _blk, _ins: True
    assert manager.func(blk, ins) is True
    assert rule.pending is None

    manager.log_info_on_input = lambda _blk, _ins: False
    manager.optimize = lambda *_args, **_kwargs: False
    ins.for_all_insns = lambda _visitor: False
    assert manager.func(blk, ins) is False
    assert manager.func(blk, ins) is False
    assert rule.pending is None


def test_real_mba_context_uses_mapped_block_and_instruction_anchor(monkeypatch):
    monkeypatch.setattr(optinsn_adapter.idaapi, "is_mapped", lambda _ea: True)
    manager = InstructionOptimizerManager.__new__(InstructionOptimizerManager)
    identity = _context().function_identity
    manager._decompilation_lifecycle = SimpleNamespace(
        current_function_execution_identity=lambda _ea, _maturity: identity
    )
    blk = SimpleNamespace(
        start=0x401000,
        serial=9,
        mba=SimpleNamespace(maturity=ida_hexrays.MMAT_PREOPTIMIZED, entry_ea=0x401000),
    )
    ins = SimpleNamespace(ea=0x401020)
    plugin = PluginIdentity("cobra", "d810-cobra", "1.0", "task7-runtime")
    context = manager.mba_observation_context(blk, ins, plugin)
    assert context is not None
    assert context.instruction_ea == 0x401020
    assert context.block_serial == 9
    assert context.block_ea == 0x401020


def test_accepted_mutation_preserves_both_statistics_authorities(monkeypatch):
    stats = _manager_stats()
    rule, sink = _runtime_rule(
        ProviderOutcomeStatus.IMPROVED,
        replacement=SimpleNamespace(
            opcode=ida_hexrays.m_mov,
            ea=0x401002,
            valid=True,
            _print=lambda: "replacement",
        ),
    )
    optimizer, blk, _ins = _runtime_optimizer(rule, stats=stats)
    manager = _manager_for(optimizer, stats)
    original = SimpleNamespace(
        opcode=ida_hexrays.m_mov,
        ea=0x401002,
        valid=True,
        _print=lambda: "original",
        swap=lambda _other: None,
    )
    monkeypatch.setattr(optinsn_adapter, "check_ins_mop_size_are_ok", lambda _x: True)
    hashes = iter((10, 20))
    monkeypatch.setattr(optinsn_adapter, "hash_minsn", lambda *_args: next(hashes))
    assert manager.optimize(blk, original) is True
    assert rule.accepted == 1
    assert sink.records == []
    assert stats.events == ["rule", "optimizer"]


def test_accepted_path_does_not_retain_callback_context():
    rule, _sink = _runtime_rule(
        ProviderOutcomeStatus.IMPROVED,
        replacement=SimpleNamespace(
            opcode=1, ea=0x401002, _print=lambda: "replacement"
        ),
    )
    optimizer, blk, ins = _runtime_optimizer(rule)
    optimizer.get_optimized_instruction(
        blk, ins, observation_context_factory=_context_factory
    )
    context_id = id(optimizer._pending_replacement_context)
    optimizer.record_mutation_accepted()
    assert optimizer._pending_replacement_context is None
    assert id(optimizer._pending_replacement_context) != context_id
