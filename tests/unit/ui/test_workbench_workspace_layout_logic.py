from __future__ import annotations

from d810.ui.workbench_workspace_layout_logic import (
    COLLAPSED_RAIL_WIDTH,
    default_workspace_rail_state,
    expand_rail,
    splitter_sizes,
    collapse_rail,
)


def test_collapsed_rail_retains_its_restorable_expanded_width() -> None:
    initial = default_workspace_rail_state()

    collapsed = collapse_rail(initial, "left", current_width=246)
    restored = expand_rail(collapsed, "left")

    assert collapsed.left_expanded is False
    assert collapsed.left_width == 246
    assert splitter_sizes(collapsed, center_width=800)[0] == COLLAPSED_RAIL_WIDTH
    assert restored.left_expanded is True
    assert splitter_sizes(restored, center_width=800)[0] == 246


def test_both_rails_can_collapse_without_shrinking_the_center_canvas() -> None:
    state = default_workspace_rail_state()
    collapsed = collapse_rail(collapse_rail(state, "left"), "right")

    left, center, right = splitter_sizes(collapsed, center_width=800)

    assert (left, center, right) == (COLLAPSED_RAIL_WIDTH, 800, COLLAPSED_RAIL_WIDTH)
