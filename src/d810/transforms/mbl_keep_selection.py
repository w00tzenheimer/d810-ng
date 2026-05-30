"""Pure selectors for blocks that should be tagged with ``MBL_KEEP``."""
from __future__ import annotations

from dataclasses import dataclass

from d810.core.typing import Any


@dataclass(frozen=True, slots=True)
class TerminalByteKeepTarget:
    """One terminal-byte fact location that should survive IDA's CFG sweep."""

    fact_id: str
    byte_index: int | None
    block_serial: int | None
    block_ea: int | None
    source_ea: int | None
    emitter_role: str


def _int_or_none(value: Any) -> int | None:
    if value is None:
        return None
    try:
        return int(value, 0) if isinstance(value, str) else int(value)
    except (TypeError, ValueError):
        return None


def select_terminal_byte_keep_targets(
    fact_view: Any,
) -> tuple[TerminalByteKeepTarget, ...]:
    """Return terminal-byte emitter facts that should become keep roots.

    The selector is intentionally IDA-free.  Mutation code can match these
    targets against live ``mblock_t`` instances by exact block EA, by source EA
    containment, or by serial as a last-resort fallback when no EA was recorded.
    """

    active = getattr(fact_view, "active_observations", ()) or ()
    targets: list[TerminalByteKeepTarget] = []
    seen: set[tuple[str, int | None, int | None, int | None]] = set()
    for obs in active:
        if getattr(obs, "kind", None) != "TerminalByteEmitterFact":
            continue
        payload = getattr(obs, "payload", None) or {}
        if payload.get("corridor_role") != "terminal_tail":
            continue

        block_serial = _int_or_none(
            payload.get("block_serial")
            if payload.get("block_serial") is not None
            else payload.get("destination_block")
        )
        block_ea = _int_or_none(
            payload.get("block_ea")
            if payload.get("block_ea") is not None
            else payload.get("start_ea")
        )
        source_ea = _int_or_none(getattr(obs, "source_ea", None))
        byte_index = _int_or_none(payload.get("byte_index"))
        fact_id = str(getattr(obs, "fact_id", "") or "")
        key = (fact_id, block_serial, block_ea, source_ea)
        if key in seen:
            continue
        seen.add(key)
        targets.append(
            TerminalByteKeepTarget(
                fact_id=fact_id,
                byte_index=byte_index,
                block_serial=block_serial,
                block_ea=block_ea,
                source_ea=source_ea,
                emitter_role=str(payload.get("emitter_role") or ""),
            )
        )
    return tuple(targets)


__all__ = [
    "TerminalByteKeepTarget",
    "select_terminal_byte_keep_targets",
]
