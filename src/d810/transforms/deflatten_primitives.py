"""De-flatten transform primitives — the clean LLVM-shaped layer over d810's mods.

The ``hexrays_structuring_lab`` terminal-tail finding (README "Established Finding:
Return Preservation") proved that preserving N returns requires two textbook compiler
transforms applied to the flattened shape:

* **Tail Duplication** (:func:`plan_tail_duplicate`) — *de-converge*: duplicate the shared
  guard / convergence block into each predecessor so every terminal owns its own
  guard->return path instead of routing through one fan-in block. (LLVM ``TailDup`` /
  jump-threading.)
* **Dead Store Elimination** (:func:`plan_dead_store_eliminate`) — *de-stage*: remove the now
  dead ``state = K`` staging writes that Hex-Rays otherwise reads as loop induction.

Each primitive is pure ``fact -> [GraphModification]`` (no IDA): it takes structural facts
and composes the existing low-level ops the backend already applies.

API deficiencies this layer documents (the lab's "which d810 rule/invariant should change"):

* **Fragmentation, not absence.** d810 has ~28 overlapping mod types
  (``DuplicateBlock``, ``PrivateTerminalSuffix``, ``PrivateTerminalSuffixGroup``,
  ``DuplicateReplayAndRedirect``, ``CloneConditionalAsGoto``, ...) — N bespoke spellings of
  *tail duplication* — instead of one clean ``TailDuplicate``. This module is the missing
  semantic seam; the long-term fix is to fold those specifics behind it.
* **No true dead-def removal.** ``NopInstructions`` leaves an ``m_nop`` (still a block
  element) and ``ZeroStateWrite`` keeps the store with a ``#0`` source. Neither *deletes* the
  instruction, so a block that held only the staging write does not collapse — a real DSE
  removal primitive is missing. We default to ``NopInstructions`` and flag the gap.
"""
from __future__ import annotations

from d810.core.typing import Iterable

from d810.transforms.graph_modification import DuplicateBlock, NopInstructions

__all__ = ["plan_tail_duplicate", "plan_dead_store_eliminate"]


def plan_tail_duplicate(
    *,
    convergence_block: int,
    predecessors: Iterable[int],
    return_target: int,
) -> list[DuplicateBlock]:
    """De-converge a shared block by tail-duplicating it into each predecessor.

    Emits one :class:`DuplicateBlock` per predecessor: each clone keeps the convergence
    block's instructions and is wired ``predecessor -> clone -> return_target``, breaking the
    fan-in that Hex-Rays turns into a loop nest. The result is the ``ref_cascade`` shape — each
    terminal owns a private guard->return path.

    Args:
        convergence_block: The shared guard / fan-in block to duplicate.
        predecessors: The terminal blocks currently routing through it (one clone each).
        return_target: The successor the clones wire to (the real return/STOP block).
    """
    return [
        DuplicateBlock(
            source_block=int(convergence_block),
            target_block=int(return_target),
            pred_serial=int(pred),
        )
        for pred in predecessors
    ]


def plan_dead_store_eliminate(
    write_sites: Iterable[tuple[int, int]],
) -> list[NopInstructions]:
    """Eliminate dead state-variable stores (the ``stage = K`` staging writes).

    Groups the ``(block_serial, insn_ea)`` write sites by block and emits one
    :class:`NopInstructions` per block (the op is per-block, multi-EA). NOPing — not deleting —
    is the available primitive; see the module docstring for the missing true-removal gap.

    Args:
        write_sites: ``(block_serial, insn_ea)`` of each dead state-var store.
    """
    by_block: dict[int, list[int]] = {}
    for block, insn_ea in write_sites:
        by_block.setdefault(int(block), []).append(int(insn_ea))
    return [
        NopInstructions(block_serial=block, insn_eas=tuple(sorted(eas)))
        for block, eas in sorted(by_block.items())
    ]
