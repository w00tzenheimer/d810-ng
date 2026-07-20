"""Session-scoped evidence capture helpers for Rhad investigation probes."""

from __future__ import annotations


def capture_preopt_union_preparation(
    state: object,
    captured: list[object],
) -> None:
    """Capture live PREOPT preparation before lifecycle cleanup."""
    preparation = getattr(state, "preopt_union_preparation", None)
    if preparation is not None:
        captured[:] = [preparation]


def latest_preopt_union_preparation(
    state: object | None,
    captured: list[object],
) -> object | None:
    """Return PREOPT preparation visible to a completed probe."""
    live = getattr(state, "preopt_union_preparation", None)
    if live is not None:
        return live
    return captured[-1] if captured else None
