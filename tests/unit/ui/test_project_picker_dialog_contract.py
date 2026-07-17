from __future__ import annotations

from pathlib import Path


DIALOG = Path(__file__).resolve().parents[3] / "src/d810/ui/project_picker_dialog.py"


def test_picker_dialog_filters_pure_entries_and_returns_original_index() -> None:
    assert DIALOG.is_file()
    source = DIALOG.read_text(encoding="utf-8")

    assert "filter_project_picker_entries" in source
    assert "project_index" in source
    assert "Load selected" in source
    assert "Filter filename, description, or runtime..." in source
    assert "selected_project_index" in source
