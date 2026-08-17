from __future__ import annotations

from d810.manager.workbench_models import (
    EffectiveMaturitySchedule,
    EffectiveMaturityScheduleRow,
    EffectiveScheduleStage,
)
from d810.ui.workbench_pipeline_schedule import project_pipeline_schedule_rows


def test_matrix_rows_show_actual_maturity_and_configured_position() -> None:
    stage = EffectiveScheduleStage(
        configured_index=0,
        runtime_order=4,
        pass_id="recover_dispatcher",
        stage_id="recover-dispatcher",
        pipeline="flow",
        implementation_name="StateMachineCffUnflattener",
        requirements=(),
        provider_maturities=("MMAT_CALLS", "MMAT_GLBOPT1"),
        maturity_source="pass-contract",
    )
    schedule = EffectiveMaturitySchedule(
        rows=(
            EffectiveMaturityScheduleRow(
                ordinal=4,
                ir_maturity="ir.call.modeled",
                provider_maturity="MMAT_CALLS",
                stages=(stage,),
            ),
        ),
        stages=(stage,),
    )

    rows = project_pipeline_schedule_rows(schedule)

    assert rows[0].maturity == "MMAT_CALLS"
    assert rows[0].stage_labels == ("recover_dispatcher (configured 1)",)
    assert "runtime callback order 4" in rows[0].detail


def test_unknown_rule_defined_coverage_is_not_filled_into_every_maturity() -> None:
    stage = EffectiveScheduleStage(
        configured_index=1,
        runtime_order=1,
        pass_id="mba-simplify",
        stage_id="mba-simplify",
        pipeline="instruction",
        implementation_name="PatternOptimizer",
        requirements=(),
        provider_maturities=(),
        maturity_source="rule-defined-unknown",
    )
    schedule = EffectiveMaturitySchedule(rows=(), stages=(stage,))

    rows = project_pipeline_schedule_rows(schedule)

    assert rows == ()
