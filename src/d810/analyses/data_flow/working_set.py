"""Worklist data structure for fixpoint iteration."""
from __future__ import annotations

from collections import deque

from d810.core.typing import Iterable, Iterator, Optional

from d810.analyses.data_flow.domain import NodeId


class WorkingSet:
    """Insertion-ordered set of pending nodes for a worklist solver.

    Combines a FIFO queue with set membership so a node is never queued
    twice while it is already pending (the classic worklist invariant).
    Deterministic iteration order (insertion order) keeps fixpoint runs
    reproducible.  The concrete solver in
    ``d810.evaluator.hexrays_microcode.forward_dataflow`` is migrated onto
    this type in a later slice (Landing Sequence step 5).
    """

    def __init__(self, initial: Optional[Iterable[NodeId]] = None) -> None:
        self._queue: deque[NodeId] = deque()
        self._pending: set[NodeId] = set()
        if initial is not None:
            for node in initial:
                self.add(node)

    def add(self, node: NodeId) -> None:
        """Enqueue ``node`` unless it is already pending."""
        if node not in self._pending:
            self._pending.add(node)
            self._queue.append(node)

    def pop(self) -> NodeId:
        """Remove and return the next pending node (FIFO).

        Raises:
            KeyError: if the working set is empty.
        """
        if not self._queue:
            raise KeyError("pop from an empty WorkingSet")
        node = self._queue.popleft()
        self._pending.discard(node)
        return node

    def __bool__(self) -> bool:
        return bool(self._queue)

    def __len__(self) -> int:
        return len(self._queue)

    def __contains__(self, node: object) -> bool:
        return node in self._pending

    def __iter__(self) -> Iterator[NodeId]:
        return iter(self._queue)
