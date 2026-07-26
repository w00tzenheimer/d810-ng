"""Shared fictitious-EA provenance for committed semantic fragments."""

from __future__ import annotations

from d810.core.typing import Mapping


IMPORTED_INSTRUCTION_ORIGINS: dict[tuple[int, int], int] = {}
LAST_IMPORTED_INSTRUCTION_ORIGINS: dict[
    int,
    tuple[tuple[int, int], ...],
] = {}


def stable_mba_identity(mba: object) -> int:
    """Return the underlying mba_t address across SWIG proxy wrappers."""
    try:
        return int(mba.this)
    except (AttributeError, TypeError, ValueError):
        return id(mba)


def _live_instruction_eas(mba: object) -> set[int]:
    live_eas: set[int] = set()
    for serial in range(int(mba.qty)):
        block = mba.get_mblock(serial)
        instruction = block.head
        while instruction is not None:
            live_eas.add(int(instruction.ea))
            if instruction is block.tail:
                break
            instruction = instruction.next
    return live_eas


def publish_semantic_fragment_instruction_origins(
    mba: object,
    *,
    function_ea: int,
    origins: Mapping[int, int],
) -> None:
    """Publish committed fict-EA provenance for later maturity observers."""
    identity = stable_mba_identity(mba)
    live_eas = _live_instruction_eas(mba)
    published: dict[tuple[int, int], int] = {}
    for imported_ea, native_ea in origins.items():
        imported_ea = int(imported_ea)
        native_ea = int(native_ea)
        if imported_ea not in live_eas:
            raise ValueError(
                "committed semantic-fragment instruction origin is not live"
            )
        key = (int(identity), imported_ea)
        previous = IMPORTED_INSTRUCTION_ORIGINS.get(key)
        if previous is not None and int(previous) != native_ea:
            raise ValueError(
                "committed semantic-fragment instruction origin conflicts"
            )
        published[key] = native_ea
    IMPORTED_INSTRUCTION_ORIGINS.update(published)
    LAST_IMPORTED_INSTRUCTION_ORIGINS[int(function_ea)] = tuple(
        sorted(
            (imported_ea, native_ea)
            for (_identity, imported_ea), native_ea in published.items()
        )
    )


__all__ = [
    "IMPORTED_INSTRUCTION_ORIGINS",
    "LAST_IMPORTED_INSTRUCTION_ORIGINS",
    "publish_semantic_fragment_instruction_origins",
    "stable_mba_identity",
]
