"""Qt-free rail state for the detachable Build workspace."""

from __future__ import annotations

import dataclasses


COLLAPSED_RAIL_WIDTH = 28
DEFAULT_LEFT_RAIL_WIDTH = 220
DEFAULT_RIGHT_RAIL_WIDTH = 280


@dataclasses.dataclass(frozen=True, slots=True)
class WorkspaceRailState:
    """Per-user workspace presentation state; never recipe or IDB state."""

    left_expanded: bool
    right_expanded: bool
    left_width: int
    right_width: int


def default_workspace_rail_state() -> WorkspaceRailState:
    return WorkspaceRailState(
        left_expanded=True,
        right_expanded=True,
        left_width=DEFAULT_LEFT_RAIL_WIDTH,
        right_width=DEFAULT_RIGHT_RAIL_WIDTH,
    )


def _validated_side(side: str) -> str:
    if side not in {"left", "right"}:
        raise ValueError(f"unknown workspace rail: {side!r}")
    return side


def collapse_rail(
    state: WorkspaceRailState,
    side: str,
    *,
    current_width: int | None = None,
) -> WorkspaceRailState:
    """Collapse one rail while retaining the last useful expanded width."""

    side = _validated_side(side)
    width = max(
        COLLAPSED_RAIL_WIDTH + 1,
        current_width
        if current_width is not None
        else (state.left_width if side == "left" else state.right_width),
    )
    if side == "left":
        return dataclasses.replace(state, left_expanded=False, left_width=width)
    return dataclasses.replace(state, right_expanded=False, right_width=width)


def expand_rail(state: WorkspaceRailState, side: str) -> WorkspaceRailState:
    """Restore one rail to its prior expanded width."""

    side = _validated_side(side)
    if side == "left":
        return dataclasses.replace(state, left_expanded=True)
    return dataclasses.replace(state, right_expanded=True)


def splitter_sizes(
    state: WorkspaceRailState,
    *,
    center_width: int,
) -> tuple[int, int, int]:
    """Return splitter sizes with the timeline protected from rail collapse."""

    return (
        state.left_width if state.left_expanded else COLLAPSED_RAIL_WIDTH,
        max(1, center_width),
        state.right_width if state.right_expanded else COLLAPSED_RAIL_WIDTH,
    )


__all__ = [
    "COLLAPSED_RAIL_WIDTH",
    "WorkspaceRailState",
    "collapse_rail",
    "default_workspace_rail_state",
    "expand_rail",
    "splitter_sizes",
]
