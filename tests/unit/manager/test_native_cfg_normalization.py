"""Manager-owned Stage C collector lifecycle and exact-key isolation."""

from __future__ import annotations

import pytest

from types import SimpleNamespace

from d810.core.execution_journal import (
    DecompilationSessionId,
    ExecutionAttemptId,
    ExecutionAttemptStatus,
    ExecutionEffectRef,
)
from d810.core.native_preanalysis_key import NativePreanalysisKey
from d810.ir.edge_state_contract import EdgeStateContract
from d810.ir.flowgraph import BlockSnapshot, FlowGraph, InsnKind, InsnSnapshot
from d810.ir.maturity import IRMaturity
from d810.manager.native_cfg_normalization import (
    ManagerOwnedNativeCfgNormalizer,
    NativeCfgNormalizationCollector,
)
from d810.manager.native_normalization import (
    NativeNormalizationOutcome,
    NativeNormalizationResult,
)
from d810.transforms.native_cfg_normalization import (
    NativeCfgFreezeReason,
    NativeCfgPassMutationObservation,
    NativeCfgTopologyFreezeOutcome,
    ObservedEdgeStateContract,
)
from d810.transforms.native_patch_plan import (
    NativeAddressRange,
    NativeFunctionIdentity,
)

pytestmark = pytest.mark.pure_python


def _native_key(function_rva: int = 0x1000) -> NativePreanalysisKey:
    return NativePreanalysisKey(
        input_identity="stage-c-input",
        processor="metapc",
        bitness=64,
        function_rva=function_rva,
        function_fingerprint="stage-c-function",
        profile_fingerprint="stage-c-profile",
        sdk_fingerprint="stage-c-sdk",
    )


def _block(serial: int, successors: tuple[int, ...], ea: int) -> BlockSnapshot:
    return BlockSnapshot(
        serial=serial,
        block_type=1,
        succs=successors,
        preds=(),
        flags=0,
        start_ea=ea,
        native_start_ea=ea,
        insn_snapshots=(
            InsnSnapshot(
                opcode=1,
                ea=ea,
                native_ea=ea,
                operands=(),
                kind=InsnKind.GOTO if successors else InsnKind.RET,
            ),
        ),
    )


def _graph(successor: int) -> FlowGraph:
    return FlowGraph(
        blocks={
            0: _block(0, (successor,), 0x1000),
            1: _block(1, (), 0x1010),
            2: _block(2, (), 0x1020),
        },
        entry_serial=0,
        func_ea=0x1000,
    )


def _observation() -> NativeCfgPassMutationObservation:
    contract = EdgeStateContract(
        source_stack_delta=0,
        target_stack_delta=0,
        proof_ids=("state-proof",),
    )
    return NativeCfgPassMutationObservation(
        pass_id="lower_state_machine",
        maturity=IRMaturity.CANONICAL,
        pre_graph=_graph(1),
        post_graph=_graph(2),
        plan_fingerprint="plan-a",
        receipt_ref=ExecutionEffectRef("mutation_receipt", "receipt-a"),
        edge_state_contracts=(ObservedEdgeStateContract(0, (1,), (2,), contract),),
    )


def _collector() -> NativeCfgNormalizationCollector:
    return NativeCfgNormalizationCollector(
        function_ea=0x1000,
        native_key=_native_key(),
        session_id=DecompilationSessionId.new(),
    )


def test_collector_freezes_once_and_transfers_outcome_once() -> None:
    collector = _collector()
    observation = _observation()
    collector.observe_native_cfg_mutation(observation)

    topology = collector.freeze_native_cfg_topology(
        function_ea=0x1000,
        maturity=IRMaturity.CANONICAL,
        baseline_graph=observation.pre_graph,
        final_graph=observation.post_graph,
        scheduled_pass_ids=("lower_state_machine",),
    )
    outcome = collector.take_topology_outcome()

    assert topology is outcome.topology
    assert topology is not None
    assert topology.function_ea == 0x1000
    assert collector.scheduled_pass_ids == ("lower_state_machine",)
    with pytest.raises(RuntimeError, match="already transferred"):
        collector.take_topology_outcome()
    with pytest.raises(RuntimeError, match="already frozen"):
        collector.freeze_native_cfg_topology(
            function_ea=0x1000,
            maturity=IRMaturity.CANONICAL,
            baseline_graph=observation.pre_graph,
            final_graph=observation.post_graph,
            scheduled_pass_ids=("lower_state_machine",),
        )


def test_missing_freeze_is_a_typed_abstention() -> None:
    outcome = _collector().take_topology_outcome()

    assert outcome.topology is None
    assert outcome.reason is NativeCfgFreezeReason.MISSING_PIPELINE_FREEZE


def test_function_or_key_identity_cannot_cross_collectors() -> None:
    collector = _collector()
    foreign = _observation()
    foreign_graph = FlowGraph(
        blocks=foreign.pre_graph.blocks,
        entry_serial=0,
        func_ea=0x2000,
    )
    foreign = NativeCfgPassMutationObservation(
        pass_id=foreign.pass_id,
        maturity=foreign.maturity,
        pre_graph=foreign_graph,
        post_graph=FlowGraph(
            blocks=foreign.post_graph.blocks,
            entry_serial=0,
            func_ea=0x2000,
        ),
        plan_fingerprint=foreign.plan_fingerprint,
        receipt_ref=foreign.receipt_ref,
        edge_state_contracts=foreign.edge_state_contracts,
    )

    with pytest.raises(ValueError, match="function mismatch"):
        collector.observe_native_cfg_mutation(foreign)
    assert collector.native_key == _native_key()
    assert collector.native_key != _native_key(0x2000)


def test_close_drops_observations_and_rejects_late_attachment() -> None:
    collector = _collector()
    collector.observe_native_cfg_mutation(_observation())

    collector.close()
    collector.close()

    assert collector.closed is True
    assert collector.observation_count == 0
    with pytest.raises(RuntimeError, match="closed"):
        collector.observe_native_cfg_mutation(_observation())
    with pytest.raises(RuntimeError, match="closed"):
        collector.take_topology_outcome()


class _Journal:
    def __init__(self, child_attempt_id):
        self.child_attempt_id = child_attempt_id
        self.advances = []

    def begin_attempt(self, *args, **kwargs):
        return SimpleNamespace(attempt_id=self.child_attempt_id)

    def advance(self, attempt, **kwargs):
        self.advances.append(kwargs)


class _Gateway:
    def __init__(
        self,
        *,
        restore_ok: bool = True,
        native_cfg_persist_error: Exception | None = None,
    ):
        self.restored = []
        self.restore_ok = restore_ok
        self.native_cfg_persist_error = native_cfg_persist_error
        self.native_cfg_receipts = []

    def record_diagnostic_snapshot(self, plan):
        return "diagnostic-1"

    def restore(self, transaction_id):
        self.restored.append(transaction_id)
        return SimpleNamespace(
            transaction_id=transaction_id,
            ok=self.restore_ok,
            state=SimpleNamespace(
                value="restored" if self.restore_ok else "restore_failed"
            ),
            failure_reason=None if self.restore_ok else "injected restore failure",
        )

    def record_native_cfg_postcondition_receipt(self, **kwargs):
        if self.native_cfg_persist_error is not None:
            raise self.native_cfg_persist_error
        self.native_cfg_receipts.append(kwargs)
        return "native-cfg-receipt-1", SimpleNamespace(
            observed_native_cfg_fingerprint=(kwargs["observed_native_cfg_fingerprint"])
        )


def _topology_outcome():
    collector = _collector()
    observation = _observation()
    collector.observe_native_cfg_mutation(observation)
    collector.freeze_native_cfg_topology(
        function_ea=0x1000,
        maturity=IRMaturity.CANONICAL,
        baseline_graph=observation.pre_graph,
        final_graph=observation.post_graph,
        scheduled_pass_ids=("lower_state_machine",),
    )
    return collector.take_topology_outcome()


def _normalizer(
    *,
    post_projection="projection",
    post_structure="structure",
    post_error: Exception | None = None,
    restore_ok: bool = True,
    native_cfg_persist_error: Exception | None = None,
):
    session = DecompilationSessionId("session")
    parent = ExecutionAttemptId(session, 1)
    child = ExecutionAttemptId(session, 2)
    journal = _Journal(child)
    gateway = _Gateway(
        restore_ok=restore_ok,
        native_cfg_persist_error=native_cfg_persist_error,
    )
    function_identity = NativeFunctionIdentity(
        entry_ea=0x1000,
        chunk_ranges=(NativeAddressRange(0x1000, 0x1100),),
        inherited_bytes_hash="function-hash",
    )
    plan = SimpleNamespace(
        plan_id="stage-c-plan",
        operations=(),
        target_cfg_fingerprint="target-native-cfg",
    )
    transaction_id = SimpleNamespace(value="transaction-1")
    normalization = NativeNormalizationResult(
        outcome=NativeNormalizationOutcome.APPLIED,
        apply_receipt=SimpleNamespace(transaction_id=transaction_id),
        certificate=None,
        reason=None,
    )

    def _post_apply_observer(**kwargs):
        if post_error is not None:
            raise post_error
        validated_cfunc = object()
        return (
            SimpleNamespace(fingerprint=post_projection),
            post_structure,
            SimpleNamespace(
                matches=True,
                observed=SimpleNamespace(fingerprint="target-native-cfg"),
                live_flowchart_fingerprint="live-flowchart",
            ),
            validated_cfunc,
        )

    normalizer = ManagerOwnedNativeCfgNormalizer(
        gateway=gateway,
        execution_journal=journal,
        reader=object(),
        origin_mapper=object(),
        encoder=object(),
        input_attestation=object(),
        capture_ranges=lambda cfunc, *, function_ranges: SimpleNamespace(
            fingerprint="projection"
        ),
        fingerprint_ctree=lambda cfunc: "structure",
        post_apply_observer=_post_apply_observer,
        capture_attestation=lambda **kwargs: SimpleNamespace(
            function_identity=function_identity
        ),
        bind_ranges=lambda **kwargs: SimpleNamespace(intent=object(), reason=None),
        build_plan=lambda **kwargs: SimpleNamespace(plan=plan, reason=None),
        apply_plan=lambda candidate: normalization,
    )
    return normalizer, parent, journal, gateway


def test_stage_c_success_is_terminal_and_blocks_stage_b() -> None:
    normalizer, parent, journal, gateway = _normalizer()

    result = normalizer.normalize(
        function_ea=0x1000,
        topology_outcome=_topology_outcome(),
        decompilation_result=object(),
        parent_attempt_id=parent,
    )

    assert result.normalization.outcome is NativeNormalizationOutcome.APPLIED
    assert result.allow_stage_b is False
    assert result.validated_cfunc is not None
    assert result.normalization.certificate.observed_native_cfg_fingerprint == (
        "target-native-cfg"
    )
    assert len(gateway.native_cfg_receipts) == 1
    assert gateway.restored == []
    assert journal.advances[-1]["status"] is ExecutionAttemptStatus.COMPLETED


def test_stage_c_no_changed_edges_records_abstention_and_allows_stage_b() -> None:
    normalizer, parent, journal, _gateway = _normalizer()

    result = normalizer.normalize(
        function_ea=0x1000,
        topology_outcome=NativeCfgTopologyFreezeOutcome(
            reason=NativeCfgFreezeReason.NO_CHANGED_EDGES
        ),
        decompilation_result=object(),
        parent_attempt_id=parent,
    )

    assert result.normalization is None
    assert result.allow_stage_b is True
    assert result.reason == NativeCfgFreezeReason.NO_CHANGED_EDGES.value
    assert journal.advances[-1]["status"] is ExecutionAttemptStatus.ABSTAINED


@pytest.mark.parametrize(
    ("post_projection", "post_structure", "reason"),
    (
        (
            "different-projection",
            "structure",
            "CTREE_RANGE_POSTCONDITION_MISMATCH",
        ),
        (
            "projection",
            "different-structure",
            "CTREE_STRUCTURE_POSTCONDITION_MISMATCH",
        ),
    ),
)
def test_stage_c_postcondition_failure_restores_and_stays_terminal(
    post_projection,
    post_structure,
    reason,
) -> None:
    normalizer, parent, journal, gateway = _normalizer(
        post_projection=post_projection,
        post_structure=post_structure,
    )

    result = normalizer.normalize(
        function_ea=0x1000,
        topology_outcome=_topology_outcome(),
        decompilation_result=object(),
        parent_attempt_id=parent,
    )

    assert result.reason == reason
    assert result.allow_stage_b is False
    assert len(gateway.restored) == 1
    assert journal.advances[-1]["status"] is ExecutionAttemptStatus.FAILED


def test_stage_c_postcondition_capture_exception_restores_and_stays_terminal() -> None:
    normalizer, parent, journal, gateway = _normalizer(
        post_error=RuntimeError("injected recapture failure")
    )

    result = normalizer.normalize(
        function_ea=0x1000,
        topology_outcome=_topology_outcome(),
        decompilation_result=object(),
        parent_attempt_id=parent,
    )

    assert result.reason.startswith("CTREE_POSTCONDITION_CAPTURE_FAILED")
    assert result.allow_stage_b is False
    assert len(gateway.restored) == 1
    assert journal.advances[-1]["status"] is ExecutionAttemptStatus.FAILED


def test_stage_c_postcondition_persistence_failure_restores() -> None:
    normalizer, parent, journal, gateway = _normalizer(
        native_cfg_persist_error=RuntimeError("injected receipt failure")
    )

    result = normalizer.normalize(
        function_ea=0x1000,
        topology_outcome=_topology_outcome(),
        decompilation_result=object(),
        parent_attempt_id=parent,
    )

    assert result.reason.startswith("NATIVE_CFG_POSTCONDITION_PERSIST_FAILED")
    assert result.allow_stage_b is False
    assert len(gateway.restored) == 1
    assert journal.advances[-1]["status"] is ExecutionAttemptStatus.FAILED


def test_stage_c_postcondition_reports_incomplete_emergency_restore() -> None:
    normalizer, parent, journal, gateway = _normalizer(
        post_projection="different-projection",
        restore_ok=False,
    )

    result = normalizer.normalize(
        function_ea=0x1000,
        topology_outcome=_topology_outcome(),
        decompilation_result=object(),
        parent_attempt_id=parent,
    )

    assert result.reason == (
        "CTREE_RANGE_POSTCONDITION_MISMATCH; "
        "RESTORE_INCOMPLETE: injected restore failure"
    )
    assert result.allow_stage_b is False
    assert len(gateway.restored) == 1
    assert journal.advances[-1]["status"] is ExecutionAttemptStatus.FAILED
