"""Receipt-gated manager orchestration for early frontend normalization."""

from __future__ import annotations

from types import SimpleNamespace

import pytest

from d810.analyses.control_flow.frontend_normalization import (
    FrontendNormalizationEvidence,
    NativeIndirectTransferProof,
    NativeTransferEndpoint,
    NativeTransferShape,
)
from d810.analyses.control_flow.native_preanalysis_session import (
    NativePreanalysisSessionState,
)
from d810.capabilities.frontend_normalization import (
    FrontendNormalizationEvidenceCapability,
)
from d810.ir.block_identity import NativeEaInterval, StableBlockIdentity
from d810.ir.flowgraph import BlockSnapshot, FlowGraph, InsnKind, InsnSnapshot
from d810.ir.semantic_edge import SemanticEdgeRole
from d810.manager.frontend_normalization import (
    FrontendNormalizationPublicationError,
    run_frontend_normalization_pipeline,
)
from tests.native_preanalysis import make_native_key


NATIVE_KEY = make_native_key(function_rva=0x1000)
GENERATION = 7


def _identity(ea: int) -> StableBlockIdentity:
    return StableBlockIdentity.from_intervals(
        (NativeEaInterval(ea, ea + 0x10),),
        native_key=NATIVE_KEY,
        exact_instruction_eas=(ea,),
    )


def _block(
    serial: int,
    ea: int,
    *,
    succs: tuple[int, ...],
    preds: tuple[int, ...],
    kind: InsnKind,
) -> BlockSnapshot:
    return BlockSnapshot(
        serial=serial,
        block_type=len(succs),
        succs=succs,
        preds=preds,
        flags=0,
        start_ea=ea,
        insn_snapshots=(
            InsnSnapshot(
                opcode=max(1, ea & 0xFF),
                ea=ea,
                operands=(),
                kind=kind,
                is_unconditional_jump=kind is InsnKind.GOTO,
            ),
        ),
    )


def _graph(*, normalized: bool) -> FlowGraph:
    source_target = 3 if normalized else 2
    return FlowGraph(
        blocks={
            0: _block(
                0,
                0x1000,
                succs=(1,),
                preds=(),
                kind=InsnKind.GOTO,
            ),
            1: _block(
                1,
                0x1100,
                succs=(source_target,),
                preds=(0,),
                kind=InsnKind.INDIRECT_JUMP,
            ),
            2: _block(
                2,
                0x1200,
                succs=(),
                preds=() if normalized else (1,),
                kind=InsnKind.RET,
            ),
            3: _block(
                3,
                0x1300,
                succs=(),
                preds=(1,) if normalized else (),
                kind=InsnKind.RET,
            ),
        },
        entry_serial=0,
        func_ea=0x1000,
    )


def _evidence() -> FrontendNormalizationEvidence:
    atomic_group_id = f"frontend-normalization:g{GENERATION}"
    return FrontendNormalizationEvidence(
        native_key=NATIVE_KEY,
        generation=GENERATION,
        atomic_group_id=atomic_group_id,
        transfer_proofs=(
            NativeIndirectTransferProof(
                proof_id="direct@0x1100",
                atomic_group_id=atomic_group_id,
                shape=NativeTransferShape.DIRECT,
                source_identity=_identity(0x1100),
                source_anchor_ea=0x1100,
                source_transfer_ea=0x1100,
                endpoints=(
                    NativeTransferEndpoint(
                        role=SemanticEdgeRole.DIRECT,
                        identity=_identity(0x1300),
                        anchor_ea=0x1300,
                    ),
                ),
            ),
        ),
    )


class _Provider:
    def __init__(
        self,
        evidence: FrontendNormalizationEvidence | None,
    ) -> None:
        self.evidence = evidence

    def evidence_for(
        self,
        function_ea: int,
    ) -> FrontendNormalizationEvidence | None:
        return self.evidence if int(function_ea) == 0x1000 else None


class _Backend:
    def __init__(
        self,
        state: NativePreanalysisSessionState,
        *,
        publish_receipt: bool,
        partial_work_item: bool = False,
    ) -> None:
        self.state = state
        self.publish_receipt = publish_receipt
        self.partial_work_item = partial_work_item
        self.plans: list[object] = []

    def capabilities(self) -> frozenset[str]:
        return frozenset()

    def apply(self, plan, live_source, safety_policy):
        raise AssertionError("frontend normalization must use fragment publication")

    def publish_fragment(self, plan, live_source, safety_policy) -> FlowGraph:
        self.plans.append(plan)
        if self.publish_receipt:
            # Gateway/lifecycle tests prove the receipt checks themselves. This
            # backend models only their successful observable state transition.
            self.state._fragment_publication_mark_normalization_staged()
            self.state._fragment_publication_mark_normalization_validated()
            if self.partial_work_item:
                self.state._fragment_publication_commit_normalization_work_item(
                    work_item_id="frontend-normalization:g7:root@0x1100",
                    selected_obligation_ids=("direct@0x1100",),
                    remaining_obligation_ids=("direct@0x1400",),
                    unreachable_obligation_ids=(),
                )
            else:
                self.state._fragment_publication_mark_normalization_published_and_postvalidated()
        return _graph(normalized=True)


def _source(graph: FlowGraph):
    return SimpleNamespace(
        flow_graph=graph,
        func_ea=graph.func_ea,
        live_source=object(),
    )


def _state() -> NativePreanalysisSessionState:
    return NativePreanalysisSessionState(evidence_generation=GENERATION)


def test_pipeline_reports_modification_only_after_current_receipt_generation() -> None:
    state = _state()
    backend = _Backend(state, publish_receipt=True)

    result = run_frontend_normalization_pipeline(
        source=_source(_graph(normalized=False)),
        backend=backend,
        evidence_provider=_Provider(_evidence()),
        lifecycle_state=state,
        native_key=NATIVE_KEY,
    )

    assert isinstance(_Provider(_evidence()), FrontendNormalizationEvidenceCapability)
    assert result.microcode_modified is True
    assert result.published_generation == GENERATION
    assert result.graph == _graph(normalized=True)
    assert len(backend.plans) == 1


def test_pipeline_rejects_changed_graph_without_current_receipt_generation() -> None:
    state = _state()
    backend = _Backend(state, publish_receipt=False)

    with pytest.raises(
        FrontendNormalizationPublicationError,
        match="without a current receipt-backed normalization publication",
    ):
        run_frontend_normalization_pipeline(
            source=_source(_graph(normalized=False)),
            backend=backend,
            evidence_provider=_Provider(_evidence()),
            lifecycle_state=state,
            native_key=NATIVE_KEY,
        )

    assert state.normalization_published_postvalidated_generation is None
    assert len(backend.plans) == 1


def test_pipeline_accepts_receipted_partial_work_item_without_generation_advance() -> (
    None
):
    state = _state()
    backend = _Backend(
        state,
        publish_receipt=True,
        partial_work_item=True,
    )

    result = run_frontend_normalization_pipeline(
        source=_source(_graph(normalized=False)),
        backend=backend,
        evidence_provider=_Provider(_evidence()),
        lifecycle_state=state,
        native_key=NATIVE_KEY,
    )

    assert result.microcode_modified is True
    assert result.published_generation is None
    assert (
        result.published_work_item_id
        == "frontend-normalization:g7:root@0x1100"
    )
    assert result.remaining_obligation_count == 1
    assert state.normalization_published_postvalidated_generation is None
    assert len(backend.plans) == 1


def test_pipeline_does_not_republish_a_generation_already_authoritative() -> None:
    state = _state()
    state._fragment_publication_mark_normalization_staged()
    state._fragment_publication_mark_normalization_validated()
    state._fragment_publication_mark_normalization_published_and_postvalidated()
    backend = _Backend(state, publish_receipt=True)
    graph = _graph(normalized=True)

    result = run_frontend_normalization_pipeline(
        source=_source(graph),
        backend=backend,
        evidence_provider=_Provider(_evidence()),
        lifecycle_state=state,
        native_key=NATIVE_KEY,
    )

    assert result.graph is graph
    assert result.microcode_modified is False
    assert result.published_generation == GENERATION
    assert backend.plans == []


def test_pipeline_without_portable_evidence_is_a_noop() -> None:
    state = _state()
    backend = _Backend(state, publish_receipt=True)
    graph = _graph(normalized=False)

    result = run_frontend_normalization_pipeline(
        source=_source(graph),
        backend=backend,
        evidence_provider=_Provider(None),
        lifecycle_state=state,
        native_key=NATIVE_KEY,
    )

    assert result.graph is graph
    assert result.microcode_modified is False
    assert result.published_generation is None
    assert backend.plans == []
