from __future__ import annotations

from types import SimpleNamespace

import pytest

from d810.core.execution_scope import (
    ExecutionAdjustment,
    ExecutionAdjustmentAction,
    ExecutionScopeService,
    ExecutionStageIdentity,
    ExecutionTargetKind,
    ExpandedExecutionStage,
    FunctionExecutionMetadata,
)
from d810.core.maturity_labels import IDA_MMAT_CALLS, IDA_MMAT_GLBOPT1, IDA_MMAT_GLBOPT2
from d810.passes.execution_stages import ExecutionPipeline, ExecutionStageDescriptor
from d810.passes.pass_pipeline import FunctionTarget


def _stage(
    pass_id: str,
    stage_id: str,
    *,
    target: FunctionTarget = FunctionTarget(),
    maturities: frozenset[int] = frozenset({3}),
) -> ExpandedExecutionStage:
    return ExpandedExecutionStage(
        descriptor=ExecutionStageDescriptor(
            pass_id,
            stage_id,
            ExecutionPipeline.FLOW,
            f"_{stage_id}",
        ),
        implementation=object(),
        target=target,
        maturities=maturities,
    )


def test_execution_and_diagnostics_share_one_evaluator() -> None:
    service = ExecutionScopeService()
    service.configure(
        (
            _stage(
                "targeted",
                "included",
                target=FunctionTarget(
                    include_eas=frozenset({0x401000}),
                    tags_all=frozenset({"cff"}),
                ),
            ),
            _stage(
                "excluded-pass",
                "excluded",
                target=FunctionTarget(exclude_eas=frozenset({0x401000})),
            ),
            _stage(
                "tagged-pass",
                "tagged",
                target=FunctionTarget(tags_any=frozenset({"ollvm", "tigress"})),
            ),
        )
    )
    service.set_metadata_provider(
        lambda _ea: FunctionExecutionMetadata(frozenset({"cff", "ollvm"}))
    )

    active = service.active_stages(
        project_name="proj",
        idb_key="idb",
        func_ea=0x401000,
        pipeline=ExecutionPipeline.FLOW,
        maturity=3,
    )
    report = service.explain(
        project_name="proj",
        idb_key="idb",
        func_ea=0x401000,
        maturity=3,
    )

    assert (
        {stage.stage_id for stage in active}
        == {decision.stage_id for decision in report.decisions if decision.active}
        == {"included", "tagged"}
    )
    assert (
        next(item for item in report.decisions if item.stage_id == "excluded").reason
        == "ea-excluded"
    )


def test_wrong_maturity_and_hint_suppression_use_stable_stage_ids() -> None:
    service = ExecutionScopeService()
    service.configure((_stage("jump-fixer", "jump-fixer"),))
    service.register_inference(
        "flattening",
        lambda _hints: [
            ExecutionAdjustment(
                ExecutionTargetKind.STAGE,
                "jump-fixer",
                ExecutionAdjustmentAction.SUPPRESS,
            )
        ],
    )
    result = service.apply_hints(
        SimpleNamespace(
            func_ea=0x401000,
            recommended_inferences=("flattening",),
            suppress_stages=(),
        )
    )

    assert result.inferences_applied == ("flattening",)
    report = service.explain(
        project_name="proj", idb_key="idb", func_ea=0x401000, maturity=3
    )
    assert report.decisions[0].reason == "inference-suppressed"

    wrong = service.explain(
        project_name="proj", idb_key="idb", func_ea=0x402000, maturity=4
    )
    assert wrong.decisions[0].reason == "wrong-maturity"


def test_legacy_flattening_forward_suppression_is_retired() -> None:
    service = ExecutionScopeService()
    service.configure(
        (
            _stage(
                "constant-simplification",
                "forward-constants",
                maturities=frozenset(
                    {IDA_MMAT_CALLS, IDA_MMAT_GLBOPT1, IDA_MMAT_GLBOPT2}
                ),
            ),
        )
    )
    service.apply_hints(
        SimpleNamespace(
            func_ea=0x401000,
            obfuscation_type="ollvm_flat",
            recommended_inferences=("unflattening",),
            suppress_stages=("forward-constants",),
        )
    )

    post = service.explain(
        project_name="proj",
        idb_key="idb",
        func_ea=0x401000,
        maturity=IDA_MMAT_GLBOPT2,
    )
    assert post.decisions[0].reason == "active"


def test_unknown_stable_targets_are_reported() -> None:
    service = ExecutionScopeService()
    service.configure((_stage("jump-fixer", "jump-fixer"),))
    service.apply_hints(
        SimpleNamespace(
            func_ea=0x401000,
            recommended_inferences=(),
            suppress_stages=("stale-stage",),
        )
    )

    report = service.explain(
        project_name="proj", idb_key="idb", func_ea=0x401000, maturity=3
    )
    assert report.unknown_targets == ("stale-stage",)


def test_scheduled_stage_round_trip_uses_public_identity() -> None:
    service = ExecutionScopeService()
    stage = _stage("constant-simplification", "forward-constants")
    service.configure((stage,))

    identity = service.identity_for_implementation(
        stage.implementation,
        pipeline=ExecutionPipeline.FLOW,
    )
    assert identity == ExecutionStageIdentity(
        pass_id="constant-simplification",
        stage_id="forward-constants",
    )
    assert service.scheduled_stages(
        identities=(identity,),
        func_ea=0x401000,
        pipeline=ExecutionPipeline.FLOW,
    ) == (stage,)


@pytest.mark.parametrize(
    "adjustment",
    (
        lambda: ExecutionAdjustment(
            ExecutionTargetKind.STAGE,
            "",
            ExecutionAdjustmentAction.SUPPRESS,
        ),
        lambda: ExecutionAdjustment(
            ExecutionTargetKind.STAGE,
            "x",
            ExecutionAdjustmentAction.SUPPRESS,
            {"bad": True},
        ),
    ),
)
def test_execution_adjustments_fail_closed(adjustment) -> None:
    with pytest.raises(ValueError):
        adjustment()


@pytest.mark.parametrize(
    "adjustment",
    (
        lambda: ExecutionAdjustment(  # type: ignore[arg-type]
            "stage", "x", ExecutionAdjustmentAction.SUPPRESS
        ),
        lambda: ExecutionAdjustment(  # type: ignore[arg-type]
            ExecutionTargetKind.STAGE, "x", "suppress"
        ),
    ),
)
def test_execution_adjustments_reject_untyped_compatibility_values(adjustment) -> None:
    with pytest.raises(TypeError):
        adjustment()
