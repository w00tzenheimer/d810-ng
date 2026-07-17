from __future__ import annotations

from pathlib import Path


POPUP = Path(__file__).resolve().parents[3] / "src/d810/ui/project_picker_popup.py"


def test_picker_popup_filters_entries_and_keeps_selection_in_the_popup() -> None:
    assert POPUP.is_file()
    source = POPUP.read_text(encoding="utf-8")

    assert "class ProjectPickerPopup" in source
    assert "filter_project_picker_entries" in source
    assert "project_index" in source
    assert "mapToGlobal" in source
    assert "Qt.Popup" in source
    assert "QDialog" not in source
