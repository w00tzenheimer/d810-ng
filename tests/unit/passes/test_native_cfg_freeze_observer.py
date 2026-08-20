"""Config-v2 observation boundary for Stage C native CFG persistence."""

from __future__ import annotations

from dataclasses import dataclass
from types import SimpleNamespace

import pytest

from d810.capabilities.native_cfg_normalization import NativeCfgFreezeObserver
from d810.capabilities.resolver import CapabilitySet
from d810.core.execution_journal import (
    DecompilationSessionId,
    ExecutionAttemptStatus,
    ExecutionDomain,
)
from d810.core.execution_journal_store import ExecutionJournalStore
from d810.ir.edge_state_contract import EdgeStateContract
from d810.ir.flowgraph import BlockSnapshot, FlowGraph, InsnKind, InsnSnapshot
from d810.ir.maturity import IRMaturity
from d810.ir.block_identity import NativeEaInterval, StableBlockIdentity
from d810.core.native_preanalysis_key import NativePreanalysisKey
from d810.ir.semantic_edge import SemanticEdgeRole
from d810.passes.driver import run_pipeline
from d810.passes.pass_pipeline import (
    BackendRoute,
    PassResult,
    PassSpec,
    default,
    no_caps,
)
from d810.transforms.cfg_transaction import LogicalBlockRef
from d810.transforms.fragment_plan import (
    FragmentBlock,
    FragmentBlockMaterialization,
    FragmentBlockRole,
    FragmentEdge,
    FragmentOperation,
    FragmentPlan,
    FragmentPublicationPurpose,
    FragmentWorkItemScope,
)
from d810.transforms.native_cfg_normalization import (
    NativeCfgPassMutationObservation,
    ObservedEdgeStateContract,
)
from d810.transforms.plan import PatchNopInstructions, PatchPlan

pytestmark = pytest.mark.pure_python


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


_BASELINE = FlowGraph(
    blocks={
        0: _block(0, (1,), 0x1000),
        1: _block(1, (), 0x1010),
        2: _block(2, (), 0x1020),
    },
    entry_serial=0,
    func_ea=0x1000,
)
_FINAL = FlowGraph(
    blocks={
        0: _block(0, (2,), 0x1000),
        1: _block(1, (), 0x1010),
        2: _block(2, (), 0x1020),
    },
    entry_serial=0,
    func_ea=0x1000,
)


@dataclass
class _Source:
    flow_graph: FlowGraph = _BASELINE
    func_ea: int = 0x1000
    live_source: object = "LIVE"


class _Facts:
    def view(self):
        return self

    def invalidate_to(self, graph, preserved) -> None:
        del graph, preserved


class _Backend:
    def __init__(self) -> None:
        self.last_mutation_receipt = None

    def capabilities(self):
        return ()

    def apply(self, plan, live_source, safety_policy):
        del plan, live_source, safety_policy
        self.last_mutation_receipt = SimpleNamespace(
            mutation_batch_id="receipt-17",
            operation_count=1,
        )
        return _FINAL


def _plan() -> PatchPlan:
    block_ref = LogicalBlockRef("stage-c", "block:0", 0)
    return PatchPlan(
        plan_id="stage-c-plan",
        snapshot_id="stage-c-snapshot",
        steps=(PatchNopInstructions(block_ref, (0x1000,)),),
        source_coordinates=((block_ref, 0),),
    )


def _fragment_plan() -> FragmentPlan:
    native_key = NativePreanalysisKey(
        input_identity="stage-c-fragment",
        processor="metapc",
        bitness=64,
        function_rva=0x1000,
        function_fingerprint="stage-c-fragment",
        profile_fingerprint="stage-c-fragment-profile",
        sdk_fingerprint="stage-c-fragment-sdk",
    )

    def identity(ea: int) -> StableBlockIdentity:
        return StableBlockIdentity.from_intervals(
            (NativeEaInterval(ea, ea + 1),),
            native_key=native_key,
            exact_instruction_eas=(ea,),
        )

    original = identity(0x1000)
    target = identity(0x1020)
    return FragmentPlan(
        plan_id="stage-c-fragment-plan",
        atomic_group_id="stage-c-fragment@0x1000",
        publication_purpose=FragmentPublicationPurpose.FRONTEND_NORMALIZATION,
        native_key=native_key,
        blocks=(
            FragmentBlock(
                block_id="original",
                role=FragmentBlockRole.ORIGINAL,
                materialization=FragmentBlockMaterialization.REUSE_PUBLISHED,
                semantic_anchor_ea=0x1000,
                stable_identity=original,
            ),
            FragmentBlock(
                block_id="replacement",
                role=FragmentBlockRole.REPLACEMENT,
                materialization=FragmentBlockMaterialization.CLONE_PUBLISHED,
                semantic_anchor_ea=0x1000,
                stable_identity=original,
                replaces_block_id="original",
            ),
            FragmentBlock(
                block_id="target",
                role=FragmentBlockRole.EXTERNAL,
                materialization=FragmentBlockMaterialization.REUSE_PUBLISHED,
                semantic_anchor_ea=0x1020,
                stable_identity=target,
            ),
        ),
        roots=("replacement",),
        owned_originals=("original",),
        prohibited_dispatcher_blocks=(),
        operations=(
            FragmentOperation(
                operation_id="stage-c-fragment-edge",
                source_block_id="replacement",
                edges=(
                    FragmentEdge(
                        role=SemanticEdgeRole.DIRECT,
                        target_block_id="target",
                    ),
                ),
            ),
        ),
        work_item_scope=FragmentWorkItemScope(
            work_item_id="stage-c-fragment:complete",
            selected_obligation_ids=("stage-c-fragment-edge",),
            remaining_obligation_ids=(),
            unreachable_obligation_ids=(),
        ),
    )


def _edge_contract() -> ObservedEdgeStateContract:
    return ObservedEdgeStateContract(
        source_block=0,
        inherited_successors=(1,),
        final_successors=(2,),
        contract=EdgeStateContract(
            source_stack_delta=0,
            target_stack_delta=0,
            proof_ids=("pass-owned-state-proof",),
        ),
    )


class _Pass:
    def run(self, ctx) -> PassResult:
        del ctx
        return PassResult(
            rewrite_plan=_plan(),
            native_cfg_edge_contracts=(_edge_contract(),),
        )


class _NoContractPass:
    def run(self, ctx) -> PassResult:
        del ctx
        return PassResult(rewrite_plan=_plan())


class _FragmentPass:
    def run(self, ctx) -> PassResult:
        del ctx
        return PassResult(
            fragment_plan=_fragment_plan(),
            native_cfg_edge_contracts=(_edge_contract(),),
        )


class _NeverDetect:
    name = "never-detect"

    def detect(self, graph, capabilities, context=None):
        raise AssertionError("config-v2 must not perform family detection")

    def pipeline_for(self, match, context):
        raise AssertionError("config-v2 must use supplied specs")


class _LegacyFamily:
    name = "legacy"

    def __init__(self, spec: PassSpec) -> None:
        self.spec = spec

    def detect(self, graph, capabilities, context=None):
        return object()

    def pipeline_for(self, match, context):
        return (self.spec,)


class _Observer:
    def __init__(self, *, fail_observe: bool = False) -> None:
        self.fail_observe = fail_observe
        self.observations: list[NativeCfgPassMutationObservation] = []
        self.freezes: list[dict[str, object]] = []

    def observe_native_cfg_mutation(
        self, observation: NativeCfgPassMutationObservation
    ) -> None:
        if self.fail_observe:
            raise RuntimeError("observer failed")
        self.observations.append(observation)

    def freeze_native_cfg_topology(self, **kwargs):
        self.freezes.append(kwargs)
        return None


def _run(
    spec: PassSpec,
    observer: _Observer,
    *,
    journal: ExecutionJournalStore | None = None,
    session_id: DecompilationSessionId | None = None,
    config_v2: bool = True,
) -> FlowGraph:
    capabilities = CapabilitySet({NativeCfgFreezeObserver: observer})
    return run_pipeline(
        source=_Source(),
        family=_NeverDetect() if config_v2 else _LegacyFamily(spec),
        backend=_Backend(),
        facts=_Facts(),
        project_config={},
        maturity=IRMaturity.CANONICAL,
        capabilities=capabilities,
        pipeline_v2_specs=(spec,) if config_v2 else None,
        journal=journal,
        session_id=session_id,
    )


def test_config_v2_opt_in_observes_completed_mutation_and_freezes_once() -> None:
    observer = _Observer()
    spec = PassSpec(
        "stage-c-pass",
        _Pass,
        no_caps,
        default,
        options={"native_cfg_persistence": True},
    )

    assert _run(spec, observer) == _FINAL

    assert len(observer.observations) == 1
    observation = observer.observations[0]
    assert observation.pre_graph == _BASELINE
    assert observation.post_graph == _FINAL
    assert observation.plan_fingerprint == "stage-c-plan"
    assert observation.receipt_ref.kind == "mutation_receipt"
    assert observation.receipt_ref.ref_id == "receipt-17"
    assert observer.freezes == [
        {
            "function_ea": 0x1000,
            "maturity": IRMaturity.CANONICAL,
            "baseline_graph": _BASELINE,
            "final_graph": _FINAL,
            "scheduled_pass_ids": ("stage-c-pass",),
        }
    ]


def test_config_v2_opt_in_observes_completed_fragment_mutation() -> None:
    observer = _Observer()
    spec = PassSpec(
        "stage-c-fragment-pass",
        _FragmentPass,
        no_caps,
        default,
        options={"native_cfg_persistence": True},
        backend_route=BackendRoute.FRAGMENT_PUBLICATION,
    )

    assert _run(spec, observer) == _FINAL

    assert len(observer.observations) == 1
    observation = observer.observations[0]
    assert observation.pre_graph == _BASELINE
    assert observation.post_graph == _FINAL
    assert observation.plan_fingerprint == "stage-c-fragment-plan"
    assert observation.receipt_ref.ref_id == "receipt-17"


@pytest.mark.parametrize(
    ("options", "pass_factory"),
    (
        ({}, _Pass),
        ({"native_cfg_persistence": 1}, _Pass),
        ({"native_cfg_persistence": True}, _NoContractPass),
    ),
)
def test_non_authoritative_results_are_not_observed(
    options: dict[str, object], pass_factory: type
) -> None:
    observer = _Observer()
    spec = PassSpec("stage-c-pass", pass_factory, no_caps, default, options=options)

    assert _run(spec, observer) == _FINAL

    assert observer.observations == []
    assert len(observer.freezes) == 1


def test_legacy_pipeline_never_calls_stage_c_observer() -> None:
    observer = _Observer()
    spec = PassSpec(
        "stage-c-pass",
        _Pass,
        no_caps,
        default,
        options={"native_cfg_persistence": True},
    )

    assert _run(spec, observer, config_v2=False) == _FINAL
    assert observer.observations == []
    assert observer.freezes == []


def test_observer_failure_is_journaled_and_disables_final_freeze(tmp_path) -> None:
    observer = _Observer(fail_observe=True)
    spec = PassSpec(
        "stage-c-pass",
        _Pass,
        no_caps,
        default,
        options={"native_cfg_persistence": True},
    )
    session_id = DecompilationSessionId.new()

    with ExecutionJournalStore(tmp_path / "execution.sqlite") as journal:
        assert _run(spec, observer, journal=journal, session_id=session_id) == _FINAL

        attempt = journal.only_attempt(
            session_id, stage_id="native-cfg-observer:stage-c-pass"
        )
        assert attempt.domain is ExecutionDomain.NATIVE_NORMALIZATION
        assert attempt.status is ExecutionAttemptStatus.FAILED
        assert attempt.reason_code == "RuntimeError: observer failed"
        assert observer.freezes == []
