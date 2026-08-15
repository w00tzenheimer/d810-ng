"""Manager-owned Stage C collector lifecycle and exact-key isolation."""

from __future__ import annotations

import pytest

from d810.core.execution_journal import DecompilationSessionId, ExecutionEffectRef
from d810.core.native_preanalysis_key import NativePreanalysisKey
from d810.ir.edge_state_contract import EdgeStateContract
from d810.ir.flowgraph import BlockSnapshot, FlowGraph, InsnKind, InsnSnapshot
from d810.ir.maturity import IRMaturity
from d810.manager.native_cfg_normalization import NativeCfgNormalizationCollector
from d810.transforms.native_cfg_normalization import (
    NativeCfgFreezeReason,
    NativeCfgPassMutationObservation,
    ObservedEdgeStateContract,
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
