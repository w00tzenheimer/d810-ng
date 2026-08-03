from __future__ import annotations

from d810.ui.diagnostics_capture_logic import diagnostics_capture_presentation


def test_disabled_capture_presentation_offers_enable_action() -> None:
    view = diagnostics_capture_presentation(False)

    assert view.icon_name == "diagnostics-capture-disabled"
    assert view.action_label == "Enable capture"
    assert "disabled" in view.tooltip.lower()


def test_enabled_capture_presentation_explains_the_next_decompilation() -> None:
    view = diagnostics_capture_presentation(True)

    assert view.icon_name == "diagnostics-capture-enabled"
    assert view.action_label is None
    assert "next decompilation" in view.tooltip.lower()
