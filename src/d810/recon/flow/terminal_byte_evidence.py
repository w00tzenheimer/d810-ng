"""Terminal-byte evidence helpers derived from validated fact observations."""
from __future__ import annotations

__all__ = ["collect_terminal_tail_byte_source_eas"]


def _parse_ea(value: object) -> int | None:
    if value is None or isinstance(value, bool):
        return None
    if isinstance(value, int):
        return int(value)
    if isinstance(value, str):
        text = value.strip()
        if not text:
            return None
        try:
            return int(text, 16) if text.lower().startswith("0x") else int(text)
        except (TypeError, ValueError):
            return None
    return None


def collect_terminal_tail_byte_source_eas(snapshot: object) -> frozenset[int]:
    """Return source EAs for terminal-tail ``TerminalByteEmitterFact`` rows.

    The helper is intentionally structural: callers may pass an analysis
    snapshot, fake test object, or any object exposing ``diagnostic_fact_view``
    or ``validated_fact_view`` with ``active_observations``. No Hex-Rays
    objects are inspected here.
    """
    fact_view = (
        getattr(snapshot, "diagnostic_fact_view", None)
        or getattr(snapshot, "validated_fact_view", None)
    )
    if fact_view is None:
        return frozenset()

    out: set[int] = set()
    for obs in getattr(fact_view, "active_observations", ()) or ():
        if getattr(obs, "kind", None) != "TerminalByteEmitterFact":
            continue
        payload = getattr(obs, "payload", None) or {}
        if payload.get("corridor_role") != "terminal_tail":
            continue
        for candidate in (
            payload.get("source_ea"),
            payload.get("source_ea_hex"),
            getattr(obs, "source_ea", None),
            getattr(obs, "source_ea_hex", None),
            getattr(obs, "source_ea_i64", None),
        ):
            parsed = _parse_ea(candidate)
            if parsed is not None:
                out.add(parsed)
    return frozenset(out)
