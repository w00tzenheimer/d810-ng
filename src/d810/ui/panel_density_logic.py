"""Pure height-adaptive density policy for the configuration panel.

The configuration panel is docked in geometries that differ by an order of
magnitude in height: a wide short strip along an edge, and a tall right-hand
dock. Rather than tune for one, the panel sheds optional chrome as height runs
out, and this module owns that decision so it can be tested without Qt.
"""

from __future__ import annotations

import dataclasses


MIN_TREE_ROWS = 6
"""Rows of pass tree the panel refuses to shrink below before shedding chrome."""

CHOICE_LIST_ROW_HEIGHT = 24
"""Approximate row height used by dense choice-backed option lists."""

CHOICE_LIST_MIN_HEIGHT = 48
"""Minimum height that keeps a choice-backed list discoverable."""

CHOICE_LIST_MAX_HEIGHT = 224
"""Maximum height before a choice-backed list must scroll internally."""

FIELD_SECTION_ROW_HEIGHT = 36
"""Approximate vertical footprint of one scalar option row."""

FIELD_SECTION_CHOICE_CHROME_HEIGHT = 28
"""Label and spacing above one choice-backed option list."""

FIELD_SECTION_CHROME_HEIGHT = 48
"""Group title, optional description, margins, and terminal spacing."""

FIELD_SECTION_MIN_HEIGHT = 96
"""Smallest useful primary option-section viewport."""

FIELD_SECTION_MAX_HEIGHT = 420
"""Largest primary option-section viewport before it scrolls internally."""


@dataclasses.dataclass(frozen=True, slots=True)
class PanelDensityPlan:
    """What optional chrome the panel may show at its current height."""

    show_filter: bool
    show_details: bool
    details_locked: bool


def choice_list_height(
    visible_row_count: int,
    *,
    row_px: int = CHOICE_LIST_ROW_HEIGHT,
    minimum_px: int = CHOICE_LIST_MIN_HEIGHT,
    maximum_px: int = CHOICE_LIST_MAX_HEIGHT,
) -> int:
    """Return a bounded height for a choice-backed option list.

    The calculation is intentionally independent of screen geometry.  A list
    with no visible rows still receives a small stable footprint, while longer
    lists use their own vertical scrollbar after reaching the declared cap.
    """

    if maximum_px < minimum_px:
        raise ValueError("maximum_px must not be less than minimum_px")
    rows = max(0, int(visible_row_count))
    row_height = max(1, int(row_px))
    preferred = rows * row_height
    return min(max(preferred, int(minimum_px)), int(maximum_px))


def primary_field_section_height(
    *,
    scalar_rows: int,
    choice_row_counts: tuple[int, ...],
) -> int:
    """Return a content-derived, bounded height for a primary field section.

    Sparse pass editors must not claim the entire dock simply because their
    section is primary. Dense editors still receive a useful workspace, then
    rely on the section scroll area and each bounded choice list for overflow.
    """

    scalar_count = max(0, int(scalar_rows))
    choice_heights = sum(
        FIELD_SECTION_CHOICE_CHROME_HEIGHT + choice_list_height(row_count)
        for row_count in choice_row_counts
    )
    preferred = (
        FIELD_SECTION_CHROME_HEIGHT
        + scalar_count * FIELD_SECTION_ROW_HEIGHT
        + choice_heights
    )
    return min(
        max(preferred, FIELD_SECTION_MIN_HEIGHT),
        FIELD_SECTION_MAX_HEIGHT,
    )


def plan_panel_density(
    *,
    available_px: int,
    row_px: int,
    filter_has_text: bool,
    details_requested: bool,
    identity_is_divergent: bool,
) -> PanelDensityPlan:
    """Decide which optional rows survive at the panel's current height.

    Args:
        available_px: Height left for the tree once fixed chrome is subtracted.
        row_px: Height of a single tree row; non-positive means not yet measured.
        filter_has_text: Whether the filter field currently holds a query.
        details_requested: Whether the user has expanded the details disclosure.
        identity_is_divergent: Whether source and runtime projects differ.

    Returns:
        The chrome the panel may render.

    A divergent identity always wins: it expands the disclosure and locks it, at
    any height. Collapse may therefore only ever hide the case where source and
    runtime agree, which is what keeps the panel from ever showing a single
    ambiguous project label.

    >>> plan = plan_panel_density(
    ...     available_px=40,
    ...     row_px=20,
    ...     filter_has_text=False,
    ...     details_requested=True,
    ...     identity_is_divergent=False,
    ... )
    >>> plan.show_details, plan.show_filter
    (False, False)
    >>> plan_panel_density(
    ...     available_px=40,
    ...     row_px=20,
    ...     filter_has_text=False,
    ...     details_requested=False,
    ...     identity_is_divergent=True,
    ... ).show_details
    True
    """
    roomy = row_px <= 0 or available_px >= MIN_TREE_ROWS * row_px
    if roomy:
        return PanelDensityPlan(
            show_filter=True,
            show_details=bool(details_requested or identity_is_divergent),
            details_locked=bool(identity_is_divergent),
        )
    return PanelDensityPlan(
        show_filter=bool(filter_has_text),
        show_details=bool(identity_is_divergent),
        details_locked=bool(identity_is_divergent),
    )


__all__ = [
    "CHOICE_LIST_MAX_HEIGHT",
    "CHOICE_LIST_MIN_HEIGHT",
    "CHOICE_LIST_ROW_HEIGHT",
    "FIELD_SECTION_CHOICE_CHROME_HEIGHT",
    "FIELD_SECTION_CHROME_HEIGHT",
    "FIELD_SECTION_MAX_HEIGHT",
    "FIELD_SECTION_MIN_HEIGHT",
    "FIELD_SECTION_ROW_HEIGHT",
    "MIN_TREE_ROWS",
    "PanelDensityPlan",
    "choice_list_height",
    "plan_panel_density",
    "primary_field_section_height",
]
