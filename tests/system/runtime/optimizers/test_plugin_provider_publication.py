"""IDA-runtime coverage for Task 7 provider publication boundaries."""

from __future__ import annotations

from types import SimpleNamespace

import ida_hexrays

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
) -> PendingMbaProviderObservation:
    raw = TypedBvTerm(
        "xor",
        32,
        children=(TypedBvTerm(None, 32, value=1), TypedBvTerm(None, 32, value=2)),
    )
    canonical = canonicalize_mba_term(raw).canonical_term
    return PendingMbaProviderObservation(
        attempt_uuid="12345678-1234-5678-1234-567812345670",
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


class _ProviderRule(InstructionOptimizationRule):
    NAME = "Task7Provider"
    maturities = []

    def __init__(self, status=ProviderOutcomeStatus.UNCHANGED, replacement=None):
        super().__init__()
        self.pending = _pending(status)
        self.replacement = replacement
        self.accepted = 0
        self.rejected: list[str] = []

    def check_and_replace(self, _blk, _ins):
        return self.replacement

    def pending_provider_observation(self):
        pending, self.pending = self.pending, None
        return pending

    def record_mutation_accepted(self):
        self.accepted += 1

    def record_mutation_rejected(self, reason):
        self.rejected.append(reason)


class _Optimizer(InstructionOptimizer):
    RULE_CLASSES = [object]

    def add_rule(self, rule):
        self.rules.add(rule)
        return True


def _runtime_rule(status=ProviderOutcomeStatus.UNCHANGED, replacement=None):
    sink = _RecordingSink()
    rule = _ProviderRule(status, replacement)
    rule.bind_plugin_services(
        PluginRuleServices(
            plugin=PluginIdentity("cobra", "d810-cobra", "1.0", "task7-runtime"),
            host=_Host(sink),
        )
    )
    return rule, sink


def _runtime_optimizer(rule):
    optimizer = _Optimizer([ida_hexrays.MMAT_PREOPTIMIZED], stats=None)
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


def test_real_backend_activation_uses_activation_bound_sink_for_publication():
    store = MbaDiscoveryStore(":memory:")
    sink = SqliteMbaResidualObservationSink(store)
    host = PluginHostCapabilityRegistry()
    host.register(
        D810_MBA_RESIDUAL_OBSERVATION_CAPABILITY,
        MbaResidualObservationSink,
        sink,
        activation_binder=sink.bind_activation,
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
                capability_offers=lambda: (),
                close=lambda: None,
            )

    manifest = {
        "name": "cobra",
        "api_version": PLUGIN_API_VERSION,
        "provides": lambda: Plugin(),
        "requires": (D810_MBA_RESIDUAL_OBSERVATION_CAPABILITY,),
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
    )
    activation = registry.activate("cobra")
    assert activation is not None
    identity, activation_host, bound_sink = activated[0]
    assert bound_sink is not sink

    rule = _ProviderRule()
    rule.bind_plugin_services(
        PluginRuleServices(
            identity,
            activation_host,
        )
    )
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
