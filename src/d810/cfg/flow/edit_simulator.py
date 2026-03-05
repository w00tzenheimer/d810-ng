"""Simulate CFG edits on an adjacency list without mutating the MBA."""
from __future__ import annotations

import copy
from dataclasses import dataclass


@dataclass(frozen=True)
class SimulatedEdit:
    """Abstract edit operation on adjacency list.

    Attributes:
        kind: Type of edit - "goto_redirect", "conditional_redirect", or "convert_to_goto".
        source: Block serial of the source block.
        old_target: Block serial of the original target being replaced.
        new_target: Block serial of the new target.
    """

    kind: str  # "goto_redirect", "conditional_redirect", "convert_to_goto"
    source: int
    old_target: int
    new_target: int


def simulate_edits(
    adj: dict[int, list[int]],
    edits: list[SimulatedEdit],
) -> dict[int, list[int]]:
    """Apply edits to a COPY of adj, return new adjacency. No MBA mutation.

    Operations:
    - ``goto_redirect``: replace first occurrence of old_target with new_target
      in source's successors.
    - ``conditional_redirect``: same as goto_redirect (edge replacement).
    - ``convert_to_goto``: replace ALL successors of source with [new_target].

    Args:
        adj: Original adjacency list (block serial -> successor serials).
        edits: Ordered list of edits to apply sequentially.

    Returns:
        A new adjacency dict with all edits applied. The original is not modified.
    """
    result: dict[int, list[int]] = copy.deepcopy(adj)

    for edit in edits:
        succs = result.get(edit.source, [])

        if edit.kind in ("goto_redirect", "conditional_redirect"):
            # Replace first occurrence of old_target with new_target
            new_succs = list(succs)
            try:
                idx = new_succs.index(edit.old_target)
                new_succs[idx] = edit.new_target
            except ValueError:
                # old_target not found — append new_target as fallback
                new_succs.append(edit.new_target)
            result[edit.source] = new_succs

        elif edit.kind == "convert_to_goto":
            # Replace ALL successors with single new_target
            result[edit.source] = [edit.new_target]

    return result
