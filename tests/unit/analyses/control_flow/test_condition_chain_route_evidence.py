from __future__ import annotations

import pytest

from d810.analyses.control_flow.condition_chain_model import (
    ConditionChainHandlerEntry,
    ConditionChainRouteEndpoint,
    ConditionChainRouteEndpointKind,
    ConditionChainRouteEvidence,
    ConditionChainRouteProvenance,
)
from d810.analyses.control_flow.route_predicate import DecisionDag, RouteComparison
from d810.ir.block_identity import NativeEaInterval, StableBlockIdentity
from d810.core.native_preanalysis_key import NativePreanalysisKey
from d810.ir.flowgraph import BlockKind, BlockSnapshot, FlowGraph
from d810.ir.storage_identity import StorageIdentity, StorageIdentityKind
from d810.transforms.cfg_transaction import LogicalBlockRef, NativeBlockRef
from d810.transforms.minimal_unflatten_emit import _bind_condition_chain_route_evidence


def _identity(ea: int) -> StableBlockIdentity:
    return StableBlockIdentity.from_intervals(
        (NativeEaInterval(ea, ea + 1),),
        native_key=NativePreanalysisKey(
            "test-input", "metapc", 64, 0x1000, "test-function",
            "test-profile", "test-sdk",
        ),
    )


def test_condition_chain_route_evidence_keeps_extracted_interval_leaf_provenance() -> None:
    evidence = ConditionChainRouteEvidence(
        decision_dag=DecisionDag(32, {1: RouteComparison(1, "jz", 7, 2, 3)}, root=1),
        interval_rows=((0, 7, 2), (7, 8, 3)),
        default_target_serial=2,
        endpoints=(
            ConditionChainRouteEndpoint(2, ConditionChainRouteEndpointKind.NATIVE, _identity(0x1200)),
            ConditionChainRouteEndpoint(3, ConditionChainRouteEndpointKind.NATIVE, _identity(0x1300)),
        ),
        handler_entries=(
            ConditionChainHandlerEntry(2, _identity(0x1200)),
            ConditionChainHandlerEntry(3, _identity(0x1300)),
        ),
        state_identity=StorageIdentity(StorageIdentityKind.STACK, 0x34),
        provenance=ConditionChainRouteProvenance.EXTRACTED,
        source_generation=7,
    )

    assert evidence.interval_rows == ((0, 7, 2), (7, 8, 3))
    assert tuple(entry.serial for entry in evidence.handler_entries) == (2, 3)


def test_folded_condition_chain_route_evidence_rejects_interval_rows() -> None:
    with pytest.raises(ValueError, match="folded"):
        ConditionChainRouteEvidence(
            decision_dag=DecisionDag(32, {1: RouteComparison(1, "jz", 7, 2, 3)}, root=1),
            interval_rows=((0, 8, 2),),
            default_target_serial=2,
            endpoints=(ConditionChainRouteEndpoint(2, ConditionChainRouteEndpointKind.NATIVE, _identity(0x1200)),),
            handler_entries=(ConditionChainHandlerEntry(2, _identity(0x1200)),),
            state_identity=StorageIdentity(StorageIdentityKind.STACK, 0x34),
            provenance=ConditionChainRouteProvenance.FOLDED,
            source_generation=7,
        )


def test_extracted_condition_chain_rejects_interval_target_without_bound_handler() -> None:
    with pytest.raises(ValueError, match="native interval targets"):
        ConditionChainRouteEvidence(
            decision_dag=DecisionDag(32, {1: RouteComparison(1, "jz", 7, 2, 3)}, root=1),
            interval_rows=((0, 8, 2),),
            default_target_serial=None,
            endpoints=(ConditionChainRouteEndpoint(2, ConditionChainRouteEndpointKind.NATIVE, _identity(0x1200)),),
            handler_entries=(ConditionChainHandlerEntry(3, _identity(0x1300)),),
            state_identity=StorageIdentity(StorageIdentityKind.STACK, 0x34),
            provenance=ConditionChainRouteProvenance.EXTRACTED,
            source_generation=7,
        )


def test_condition_chain_route_rejects_non_generation_provenance() -> None:
    with pytest.raises(ValueError, match="generation"):
        ConditionChainRouteEvidence(
            decision_dag=DecisionDag(32, {1: RouteComparison(1, "jz", 7, 2, 3)}, root=1),
            interval_rows=((0, 8, 2),),
            default_target_serial=None,
            endpoints=(ConditionChainRouteEndpoint(2, ConditionChainRouteEndpointKind.NATIVE, _identity(0x1200)),),
            handler_entries=(ConditionChainHandlerEntry(2, _identity(0x1200)),),
            state_identity=StorageIdentity(StorageIdentityKind.STACK, 0x34),
            provenance=ConditionChainRouteProvenance.EXTRACTED,
            source_generation=-1,
        )


def test_full_partition_keeps_logical_exit_but_replays_only_native_range_leaf() -> None:
    native = _identity(0x1200)
    graph = FlowGraph(
        {
            1: BlockSnapshot(1, 0, (), (), 0, 0x1200, (), BlockKind.ZERO_WAY),
            2: BlockSnapshot(2, 0, (), (), 0, 0xFFFFFFFFFFFFFFFF, (), BlockKind.ZERO_WAY),
        },
        1,
        0x1200,
    )
    evidence = ConditionChainRouteEvidence(
        decision_dag=DecisionDag(32, {1: RouteComparison(1, "jz", 7, 1, 2)}, root=1),
        interval_rows=((0, 7, 1), (7, 8, 2)),
        default_target_serial=2,
        endpoints=(
            ConditionChainRouteEndpoint(1, ConditionChainRouteEndpointKind.NATIVE, native),
            ConditionChainRouteEndpoint(
                2, ConditionChainRouteEndpointKind.FUNCTION_EXIT,
                logical_session_id="test", logical_proxy_token="exit", logical_version=0,
            ),
        ),
        handler_entries=(ConditionChainHandlerEntry(1, native),),
        state_identity=StorageIdentity(StorageIdentityKind.STACK, 0x34),
        provenance=ConditionChainRouteProvenance.EXTRACTED,
        source_generation=7,
    )

    bound = _bind_condition_chain_route_evidence(
        graph,
        evidence,
        block_refs_by_serial={
            1: NativeBlockRef(native),
            2: LogicalBlockRef("test", "exit", 0),
        },
        source_generation=7,
        native_key=native.native_key,
        expected_state_identity=StorageIdentity(StorageIdentityKind.STACK, 0x34),
    )

    assert bound is not None
    _dag, _replay_dispatcher, catalogue = bound
    assert catalogue is not None
    assert tuple(binding.serial for binding in catalogue.bindings) == (1,)


@pytest.mark.parametrize(
    "foreign_state_identity",
    (
        StorageIdentity(StorageIdentityKind.STACK, 0x38),
        StorageIdentity(StorageIdentityKind.REGISTER, 0x34),
    ),
)
def test_condition_chain_route_evidence_rejects_foreign_state_namespace(
    foreign_state_identity: StorageIdentity,
) -> None:
    native = _identity(0x1200)
    graph = FlowGraph(
        {1: BlockSnapshot(1, 0, (), (), 0, 0x1200, (), BlockKind.ZERO_WAY)},
        1,
        0x1200,
    )
    evidence = ConditionChainRouteEvidence(
        decision_dag=DecisionDag(32, {1: RouteComparison(1, "jz", 7, 1, 1)}, root=1),
        interval_rows=((0, 1, 1),),
        default_target_serial=1,
        endpoints=(ConditionChainRouteEndpoint(1, ConditionChainRouteEndpointKind.NATIVE, native),),
        handler_entries=(ConditionChainHandlerEntry(1, native),),
        state_identity=foreign_state_identity,
        provenance=ConditionChainRouteProvenance.EXTRACTED,
        source_generation=7,
    )

    assert _bind_condition_chain_route_evidence(
        graph,
        evidence,
        block_refs_by_serial={1: NativeBlockRef(native)},
        source_generation=7,
        native_key=native.native_key,
        expected_state_identity=StorageIdentity(StorageIdentityKind.STACK, 0x34),
    ) is None
