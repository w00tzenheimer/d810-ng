from __future__ import annotations

from pathlib import Path


ROOT = Path(__file__).resolve().parents[3]
WIDGET = ROOT / "src" / "d810" / "ui" / "workbench_preparation_panel.py"
PANEL = ROOT / "src" / "d810" / "ui" / "workbench_panel.py"


def test_preparation_widget_renders_scripts_transactions_and_owned_actions() -> None:
    source = WIDGET.read_text(encoding="utf-8")

    assert "class PreparationWorkbenchWidget" in source
    assert "script_tree" in source
    assert "transaction_tree" in source
    assert "Preview" in source
    assert "Prepare only" in source
    assert "Prepare & Decompile" in source
    assert "Restore" in source
    assert "ida_bytes" not in source
    assert "sqlite3" not in source


def test_existing_workbench_embeds_preparation_widget() -> None:
    source = PANEL.read_text(encoding="utf-8")

    assert "PreparationWorkbenchWidget" in source
    assert "self.preparation_widget" in source
    assert "layout.addWidget(self.preparation_widget)" in source
