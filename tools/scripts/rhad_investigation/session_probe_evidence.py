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


def native_preanalysis_boundary_port_count(state: object | None) -> int:
    """Count canonical portable boundary facts without a live preparation."""
    native_preanalysis = getattr(state, "native_preanalysis", None)
    facts = getattr(native_preanalysis, "facts", None)
    ports = getattr(facts, "boundary_ports", None)
    if ports is None:
        return 0
    return len(getattr(ports, "direct", ())) + len(
        getattr(ports, "conditional", ())
    )
