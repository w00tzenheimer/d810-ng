from __future__ import annotations

from pathlib import Path


ROOT = Path(__file__).resolve().parents[3]
POPUP = ROOT / "src" / "d810" / "ui" / "workbench_canvas_palette.py"


def test_canvas_picker_popup_keeps_filtered_rows_inside_the_popup() -> None:
    source = POPUP.read_text(encoding="utf-8")

    assert "class CanvasPassPickerPopup" in source
    assert "project_canvas_add_palette" in source
    assert "self._visible_rows" in source
    assert "QLineEdit" in source
    assert "QTableWidget" in source
    assert "mapToGlobal" in source
    assert "QMenu" not in source


def test_canvas_picker_popup_selects_by_visible_row_identity() -> None:
    source = POPUP.read_text(encoding="utf-8")

    assert "self._visible_rows[row].pass_id" in source
    assert "self._on_pass_selected(self._stage_id, pass_id)" in source
    assert "IDA_AVAILABLE and QT_GRAPHICS_AVAILABLE" in source
