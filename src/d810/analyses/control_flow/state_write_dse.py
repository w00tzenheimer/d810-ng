"""Dead-store elimination for dispatcher state-variable writes (render-level).

After unflattening, the dispatcher state variable (e.g. ``var_64``) is dead: no
handler reads it, the recovered control flow drives execution directly. Its
writes -- both the bare state-constant assignments the obfuscator emits
(``var_64 = 0x139F2922``) and the computed next-state expressions -- are dead
stores. This module removes them from already-rendered statement lines so the
structured program shows only live handler logic (and so cosmetic leaked-state
constants like ``0x298372CC`` stop appearing as dead writes).

Pure string logic -- portable and unit-testable; no IDA dependency. The rendered
state-variable name is not derivable from the stack offset (IDA names slots by
frame position, not offset), so it is *inferred* from the assignment lines whose
right-hand side is a known dispatcher state constant.
"""
from __future__ import annotations

import re

from d810.core.typing import Iterable, Optional

__all__ = ["infer_state_var_name", "prune_dead_state_writes"]

# ``[/* assert */ ] <lhs> = <rhs>``  (leading indentation tolerated)
_ASSIGN_RE = re.compile(
    r"^\s*(?:/\*\s*assert\s*\*/\s*)?(?P<lhs>[A-Za-z_]\w*)\s*=\s*(?P<rhs>.+?)\s*$"
)
_BARE_CONST_RE = re.compile(r"^0x[0-9A-Fa-f]+$")


def _const_value(rhs: str) -> Optional[int]:
    if not _BARE_CONST_RE.match(rhs):
        return None
    try:
        return int(rhs, 16) & 0xFFFFFFFF
    except ValueError:
        return None


def infer_state_var_name(
    block_payload: "Iterable[Iterable[str]] | dict", state_consts: Iterable[int]
) -> Optional[str]:
    """Infer the rendered state-variable name from state-constant assignments.

    The state variable is the one assigned bare dispatcher state constants. The
    name with the most such assignments wins. ``block_payload`` may be a dict of
    serial -> lines or any iterable of line-iterables.
    """
    consts = {int(c) & 0xFFFFFFFF for c in state_consts}
    if not consts:
        return None
    if isinstance(block_payload, dict):
        line_groups = block_payload.values()
    else:
        line_groups = block_payload
    counts: dict[str, int] = {}
    for lines in line_groups:
        for line in lines:
            m = _ASSIGN_RE.match(line)
            if m is None:
                continue
            value = _const_value(m.group("rhs"))
            if value is not None and value in consts:
                counts[m.group("lhs")] = counts.get(m.group("lhs"), 0) + 1
    if not counts:
        return None
    return max(counts, key=lambda name: counts[name])


def prune_dead_state_writes(
    lines: Iterable[str],
    state_var_name: Optional[str],
    state_consts: Iterable[int],
) -> tuple[str, ...]:
    """Drop dead dispatcher-state writes from rendered statement ``lines``.

    A line is dropped when it assigns the (dead) state variable -- any
    ``state_var_name = ...`` -- or, as a fallback that works even when the name
    could not be inferred, when it assigns a *bare dispatcher state constant*
    (``<anyvar> = 0x<state_const>``). Non-assignment lines and live computation
    are preserved verbatim.
    """
    consts = {int(c) & 0xFFFFFFFF for c in state_consts}
    out: list[str] = []
    for line in lines:
        m = _ASSIGN_RE.match(line)
        if m is not None:
            lhs = m.group("lhs")
            if state_var_name is not None and lhs == state_var_name:
                continue
            value = _const_value(m.group("rhs"))
            if value is not None and value in consts:
                continue
        out.append(line)
    return tuple(out)
