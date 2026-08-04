"""Pure projection of legal canvas additions into searchable palette rows."""

from __future__ import annotations

import dataclasses

from d810.manager.workbench_recipe_models import (
    PassCatalogEntry,
    PipelineRecipeDraft,
)
from d810.ui.workbench_recipe_logic import (
    canvas_add_candidates,
    workflow_stage_label,
)


@dataclasses.dataclass(frozen=True, slots=True)
class CanvasPaletteRow:
    pass_id: str
    title: str
    subtitle: str
    detail: str


@dataclasses.dataclass(slots=True)
class CanvasPaletteSelection:
    """One-shot selection gate for a single visible palette presentation."""

    _committed: bool = False

    def reset(self) -> None:
        self._committed = False

    def take(
        self,
        rows: tuple[CanvasPaletteRow, ...],
        row_index: int,
    ) -> str | None:
        """Return one visible pass identity, or nothing after it was committed."""
        if self._committed or not 0 <= row_index < len(rows):
            return None
        self._committed = True
        return rows[row_index].pass_id


def _palette_row(entry: PassCatalogEntry) -> CanvasPaletteRow:
    return CanvasPaletteRow(
        pass_id=entry.pass_id,
        title=entry.display_name,
        subtitle=(
            f"{workflow_stage_label(entry.workflow_stage)}; maturity: {entry.maturity}"
        ),
        detail=entry.contract_json,
    )


def _searchable_text(row: CanvasPaletteRow) -> str:
    return "\n".join((row.pass_id, row.title, row.subtitle, row.detail))


def project_canvas_add_palette(
    catalog: tuple[PassCatalogEntry, ...],
    stage_id: str,
    draft: PipelineRecipeDraft,
    query: str = "",
) -> tuple[CanvasPaletteRow, ...]:
    """Project the existing legal-addition policy into a filtered palette."""
    candidates = canvas_add_candidates(catalog, stage_id, draft)
    normalized = str(query).strip().casefold()
    rows = tuple(_palette_row(entry) for entry in candidates)
    return tuple(
        row
        for row in rows
        if not normalized or normalized in _searchable_text(row).casefold()
    )


__all__ = [
    "CanvasPaletteRow",
    "CanvasPaletteSelection",
    "project_canvas_add_palette",
]
