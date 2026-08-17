"""Pure reachability helpers for the exact unflattening safety oracle."""

from __future__ import annotations

from collections import deque
from collections.abc import Iterable, Mapping


def reachable_call_eas(
    block_successors: Mapping[int, Iterable[int]],
    call_eas_by_block: Mapping[int, Iterable[int]],
    *,
    entry_serial: int = 0,
) -> frozenset[int]:
    """Return exact native call EAs in the entry-reachable post-D810 CFG.

    The graph and call map are already persisted snapshot facts.  Unknown
    successor serials are malformed evidence, not an unreachable-call
    fallback, so this helper fails closed with ``ValueError``.
    """
    graph = {
        int(serial): tuple(int(target) for target in successors)
        for serial, successors in block_successors.items()
    }
    entry = int(entry_serial)
    if entry not in graph:
        raise ValueError(f"post-D810 snapshot has no entry block {entry}")
    if any(
        int(target) not in graph
        for successors in graph.values()
        for target in successors
    ):
        raise ValueError("post-D810 snapshot contains an unknown successor")

    reachable: set[int] = set()
    pending = deque((entry,))
    while pending:
        serial = int(pending.popleft())
        if serial in reachable:
            continue
        reachable.add(serial)
        pending.extend(graph[serial])

    return frozenset(
        int(ea)
        for serial, eas in call_eas_by_block.items()
        if int(serial) in reachable
        for ea in eas
    )
