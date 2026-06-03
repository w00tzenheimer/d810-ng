"""Structured-control-flow region tree (angr ``GraphRegion`` / Phoenix AST analog).

A **goto-free** structured representation of a recovered CFG: the target a
structuring analysis (angr-style ``RegionIdentifier`` + ``Structurer``, Phoenix /
DREAM "No More Gotos") produces and the pseudocode renderer consumes. Instead of
emitting raw ``goto STATE_x`` chains over basic blocks, control flow is nested
``Sequence`` / ``Condition`` / ``Loop`` / ``Switch`` regions over leaf blocks,
with ``Break`` / ``Continue`` / ``Return`` terminators.

Pure model layer: backend-neutral, no IDA. Leaf ``BlockRegion`` bodies carry
already-rendered statement lines (the backend lift fills them); the structure
itself is what the structurer recovers. :func:`render_region` is the canonical
goto-free serializer (no ``goto`` node exists, so the output cannot contain one).
"""
from __future__ import annotations

from dataclasses import dataclass, field

from d810.core.typing import Optional, Union

__all__ = [
    "BlockRegion",
    "BreakRegion",
    "ConditionRegion",
    "ContinueRegion",
    "LoopRegion",
    "Region",
    "ReturnRegion",
    "SequenceRegion",
    "SwitchRegion",
    "render_region",
]


@dataclass(frozen=True, slots=True)
class BlockRegion:
    """A leaf basic block: its serial plus rendered statement lines."""

    serial: int
    body: tuple[str, ...] = ()


@dataclass(frozen=True, slots=True)
class SequenceRegion:
    """Straight-line composition: render children in order."""

    regions: tuple["Region", ...] = ()


@dataclass(frozen=True, slots=True)
class ConditionRegion:
    """``if (condition) then_region [else else_region]``."""

    condition: str
    then_region: Optional["Region"]
    else_region: Optional["Region"] = None


@dataclass(frozen=True, slots=True)
class LoopRegion:
    """A natural loop. ``kind`` is ``"while"`` or ``"do_while"``."""

    body: "Region"
    kind: str = "while"
    condition: str = "1"


@dataclass(frozen=True, slots=True)
class SwitchRegion:
    """``switch (discriminant)`` with cases; empty ``values`` is ``default``."""

    discriminant: str
    cases: tuple[tuple[tuple[int, ...], "Region"], ...] = ()


@dataclass(frozen=True, slots=True)
class BreakRegion:
    """Loop/switch ``break``."""


@dataclass(frozen=True, slots=True)
class ContinueRegion:
    """Loop ``continue``."""


@dataclass(frozen=True, slots=True)
class ReturnRegion:
    """``return [value]``."""

    value: Optional[str] = None


Region = Union[
    BlockRegion,
    SequenceRegion,
    ConditionRegion,
    LoopRegion,
    SwitchRegion,
    BreakRegion,
    ContinueRegion,
    ReturnRegion,
]


def _indent(level: int) -> str:
    return "    " * level


def _render(region: "Region", level: int, out: list[str]) -> None:
    pad = _indent(level)
    if isinstance(region, BlockRegion):
        for line in region.body:
            out.append(f"{pad}{line}")
    elif isinstance(region, SequenceRegion):
        for child in region.regions:
            _render(child, level, out)
    elif isinstance(region, ConditionRegion):
        out.append(f"{pad}if ( {region.condition} )")
        out.append(f"{pad}{{")
        if region.then_region is not None:
            _render(region.then_region, level + 1, out)
        out.append(f"{pad}}}")
        if region.else_region is not None:
            out.append(f"{pad}else")
            out.append(f"{pad}{{")
            _render(region.else_region, level + 1, out)
            out.append(f"{pad}}}")
    elif isinstance(region, LoopRegion):
        if region.kind == "do_while":
            out.append(f"{pad}do")
            out.append(f"{pad}{{")
            _render(region.body, level + 1, out)
            out.append(f"{pad}}} while ( {region.condition} );")
        else:
            out.append(f"{pad}while ( {region.condition} )")
            out.append(f"{pad}{{")
            _render(region.body, level + 1, out)
            out.append(f"{pad}}}")
    elif isinstance(region, SwitchRegion):
        out.append(f"{pad}switch ( {region.discriminant} )")
        out.append(f"{pad}{{")
        for values, body in region.cases:
            if values:
                for value in values:
                    out.append(f"{pad}case {value}:")
            else:
                out.append(f"{pad}default:")
            _render(body, level + 1, out)
        out.append(f"{pad}}}")
    elif isinstance(region, BreakRegion):
        out.append(f"{pad}break;")
    elif isinstance(region, ContinueRegion):
        out.append(f"{pad}continue;")
    elif isinstance(region, ReturnRegion):
        out.append(f"{pad}return;" if region.value is None else f"{pad}return {region.value};")
    else:  # pragma: no cover - exhaustive over the Region union
        raise TypeError(f"render_region: unknown region type {type(region)!r}")


def render_region(region: "Region", *, level: int = 0) -> str:
    """Serialize a region tree to goto-free C-like pseudocode text."""
    out: list[str] = []
    _render(region, level, out)
    return "\n".join(out)
