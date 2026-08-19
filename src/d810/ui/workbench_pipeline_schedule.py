"""Qt-free projection of the manager-owned effective maturity schedule."""

from __future__ import annotations

import dataclasses

from d810.manager.workbench_models import EffectiveMaturitySchedule


@dataclasses.dataclass(frozen=True, slots=True)
class PipelineScheduleRowView:
    ordinal: int
    maturity: str
    ir_maturity: str
    pipeline_groups: tuple[tuple[str, tuple[str, ...]], ...]
    detail: str


def project_pipeline_schedule_rows(
    schedule: EffectiveMaturitySchedule,
) -> tuple[PipelineScheduleRowView, ...]:
    rows: list[PipelineScheduleRowView] = []
    for row in schedule.rows:
        if not row.pipeline_stages:
            continue
        groups = tuple(
            (
                pipeline,
                tuple(
                    f"{stage.pass_id} (configured {stage.configured_index + 1})"
                    for stage in stages
                ),
            )
            for pipeline, stages in row.pipeline_stages
        )
        details: list[str] = []
        for pipeline, stages in row.pipeline_stages:
            details.append(f"{pipeline} pipeline:")
            for stage in stages:
                callback_order = (
                    f"runtime order {stage.runtime_order}"
                    if stage.runtime_order >= 0
                    else "runtime order unavailable"
                )
                details.append(
                    f"  {stage.pass_id}/{stage.stage_id}: {callback_order}; "
                    f"maturity authority {stage.maturity_source}; "
                    f"requires {', '.join(stage.requirements) or 'none'}"
                )
        detail = "\n".join(details)
        rows.append(
            PipelineScheduleRowView(
                ordinal=row.ordinal,
                maturity=row.provider_maturity,
                ir_maturity=row.ir_maturity,
                pipeline_groups=groups,
                detail=detail,
            )
        )
    return tuple(rows)


__all__ = ["PipelineScheduleRowView", "project_pipeline_schedule_rows"]
