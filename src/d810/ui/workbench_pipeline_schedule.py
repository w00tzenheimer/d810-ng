"""Qt-free projection of the manager-owned effective maturity schedule."""

from __future__ import annotations

import dataclasses

from d810.manager.workbench_models import EffectiveMaturitySchedule


@dataclasses.dataclass(frozen=True, slots=True)
class PipelineScheduleRowView:
    ordinal: int
    maturity: str
    ir_maturity: str
    stage_labels: tuple[str, ...]
    detail: str


def project_pipeline_schedule_rows(
    schedule: EffectiveMaturitySchedule,
) -> tuple[PipelineScheduleRowView, ...]:
    rows: list[PipelineScheduleRowView] = []
    for row in schedule.rows:
        if not row.stages:
            continue
        labels = tuple(
            f"{stage.pass_id} (configured {stage.configured_index + 1})"
            for stage in row.stages
        )
        details: list[str] = []
        for stage in row.stages:
            callback_order = (
                f"runtime callback order {stage.runtime_order}"
                if stage.runtime_order >= 0
                else "runtime callback order unavailable"
            )
            details.append(
                f"{stage.pipeline} {stage.pass_id}/{stage.stage_id}: "
                f"{callback_order}; maturity authority {stage.maturity_source}; "
                f"requires {', '.join(stage.requirements) or 'none'}"
            )
        detail = "\n".join(details)
        rows.append(
            PipelineScheduleRowView(
                ordinal=row.ordinal,
                maturity=row.provider_maturity,
                ir_maturity=row.ir_maturity,
                stage_labels=labels,
                detail=detail,
            )
        )
    return tuple(rows)


__all__ = ["PipelineScheduleRowView", "project_pipeline_schedule_rows"]
