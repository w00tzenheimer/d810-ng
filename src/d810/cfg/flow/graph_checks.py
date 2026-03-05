"""Semantic correctness checks for post-linearization CFG."""
from __future__ import annotations

from dataclasses import dataclass, field


@dataclass(frozen=True)
class TerminalCycle:
    """A terminal block that unexpectedly re-enters the handler/dispatcher region."""

    terminal_block: int
    reentry_target: int
    path: list[int] = field(default_factory=list)


@dataclass
class SemanticCheckResult:
    """Result of a semantic verification check."""

    passed: bool
    cycles: list[TerminalCycle] = field(default_factory=list)
    diagnostics: dict[str, object] = field(default_factory=dict)


def detect_terminal_cycles(
    adj: dict[int, list[int]],
    terminal_exits: set[int],
    handler_entries: set[int],
    dispatcher: int,
) -> SemanticCheckResult:
    """Check that terminal exit blocks do not re-enter dispatcher or handler region.

    Args:
        adj: Adjacency list (block serial -> successor serials).
        terminal_exits: Blocks identified as terminal handler exits.
        handler_entries: All handler entry block serials.
        dispatcher: Dispatcher block serial.

    Returns:
        SemanticCheckResult with passed=True if no cycles found.
    """
    forbidden = handler_entries | {dispatcher}
    cycles: list[TerminalCycle] = []

    for term_blk in terminal_exits:
        succs = adj.get(term_blk, [])
        if not succs:
            continue  # true terminal (0 successors) — safe

        # BFS from terminal block; if we hit forbidden, it's a cycle
        visited: set[int] = set()
        queue: list[tuple[int, list[int]]] = [(term_blk, [term_blk])]
        found = False
        while queue and not found:
            node, path = queue.pop(0)
            for succ in adj.get(node, []):
                if succ in forbidden:
                    cycles.append(TerminalCycle(
                        terminal_block=term_blk,
                        reentry_target=succ,
                        path=path + [succ],
                    ))
                    found = True
                    break
                if succ not in visited:
                    visited.add(succ)
                    queue.append((succ, path + [succ]))

    return SemanticCheckResult(passed=len(cycles) == 0, cycles=cycles)
