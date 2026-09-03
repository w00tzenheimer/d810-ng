"""Pure decisions for resolving a multi-def (phi-like) operand read.

IDA-free by construction: every helper takes plain ``(block_serial, ins_ea)``
definition keys and plain integers, so the *decision* a concrete-mode emulator
makes at a merge point is testable without a live ``mba_t`` (ticket ``d81-yrkv``).

Two sound ways out of the historical "multiple reaching defs -> give up":

* **path-sensitive** (:func:`select_def_index_for_predecessor`) -- the consumer
  knows which incoming edge it is evaluating (the reduced-product concrete leg
  consults the emulator once per immediate predecessor), so the single definition
  that reaches along THAT edge is the one to evaluate.
* **path-insensitive** (:func:`agreed_value`) -- every reaching definition
  evaluates to the SAME concrete value, so the merge value is that value on
  every path.

Neither fabricates a merge value: when the incoming edge is unknown and the
definitions disagree (or any one of them is unresolved), the caller must abstain.
"""

from __future__ import annotations

from d810.core.typing import Collection, Optional, Sequence, Union

__all__ = ["DefKey", "agreed_value", "select_def_index_for_predecessor"]

#: ``(block_serial, ins_ea)`` identity of one definition site.
DefKey = tuple[int, int]

#: One incoming edge, or a whole incoming PATH (nearest block to the use first).
PredecessorPath = Union[int, Sequence[int]]


def _as_path(pred_serial: PredecessorPath) -> tuple[int, ...]:
    """Normalize a single serial or a path (nearest first) to a tuple."""
    if isinstance(pred_serial, int):
        return (pred_serial,)
    return tuple(int(serial) for serial in pred_serial)


def select_def_index_for_predecessor(
    def_keys: Sequence[DefKey],
    pred_serial: PredecessorPath,
    pred_reaching_keys: Collection[DefKey],
) -> Optional[int]:
    """Index into *def_keys* of the definition arriving along *pred_serial*.

    ``def_keys`` are the definitions reaching the merge block, in scan order
    (definitions inside one block appear in instruction order) -- they are
    already exact, so the only question is WHICH of them the incoming edge
    carries.  ``pred_serial`` is the immediate predecessor, or the whole path
    the consumer arrived along with the block NEAREST the use first.
    ``pred_reaching_keys`` are the definitions that reach the nearest block by
    its own UD chain (advisory: those chains are use-driven, so a block that
    never READS the operand reports none).

    Resolution, in order, all sound:

    1. **Path membership** -- walk the path from the use outwards and take the
       first block that defines the operand; inside that block instructions
       execute in order, so the LAST definition there is the live one.  A def on
       a nearer block shadows one further up the same path.
    2. **Through-flow** -- no block on the path redefines it and exactly one of
       the merge's definitions reaches the nearest block: that one flows through.

    Anything else returns ``None`` -- the caller must not guess.

    >>> select_def_index_for_predecessor([(329, 0x1000), (398, 0x2000)], 329, set())
    0
    >>> select_def_index_for_predecessor(
    ...     [(329, 0x1000), (398, 0x2000)], (355, 398), set()
    ... )
    1
    >>> select_def_index_for_predecessor(
    ...     [(329, 0x1000), (415, 0x2000)], 398, {(415, 0x2000)}
    ... )
    1
    >>> select_def_index_for_predecessor([(329, 0x1000), (415, 0x2000)], 398, set())
    """
    path = _as_path(pred_serial)
    for serial in path:
        own = [i for i, (blk, _) in enumerate(def_keys) if blk == serial]
        if own:
            return own[-1]
    if not path:
        return None
    reaching = set(pred_reaching_keys)
    candidates = [i for i, key in enumerate(def_keys) if key in reaching]
    if not candidates:
        return None
    if len({def_keys[i] for i in candidates}) != 1:
        return None
    return candidates[0]


def agreed_value(values: Sequence[Optional[int]]) -> Optional[int]:
    """The single value every definition evaluates to, else ``None``.

    ``None`` entries are *unresolved* definitions, not misses to ignore: an
    unknown definition could carry a different value, so the merge abstains.

    >>> agreed_value([7, 7, 7])
    7
    >>> agreed_value([7, 8])
    >>> agreed_value([7, None])
    >>> agreed_value([])
    """
    if not values:
        return None
    first = values[0]
    if first is None:
        return None
    for value in values[1:]:
        if value is None or value != first:
            return None
    return int(first)
