"""De-flatten transform primitives — the clean LLVM-shaped layer (TailDuplicate + DSE).

These are the two textbook compiler transforms the hexrays_structuring_lab terminal-tail
finding showed are required to preserve returns: de-converge a shared guard (Tail Duplication)
and strip the staging writes (Dead Store Elimination). d810 currently has ~28 fragmented,
overlapping low-level mods (``DuplicateBlock``, ``PrivateTerminalSuffix``,
``DuplicateReplayAndRedirect``, ``NopInstructions``, ``ZeroStateWrite``, ...) instead of these
two clean transforms; this module is the missing semantic layer that composes them.

Pure fact->plan logic, no IDA: a primitive takes structural facts and returns a list of
existing ``graph_modification`` ops.
"""
from __future__ import annotations

from d810.transforms.deflatten_primitives import (
    plan_dead_store_eliminate,
    plan_tail_duplicate,
)
from d810.transforms.graph_modification import DuplicateBlock, NopInstructions


class TestTailDuplicate:
    """De-converge: duplicate the shared convergence block into each predecessor."""

    def test_one_clone_per_predecessor(self) -> None:
        mods = plan_tail_duplicate(
            convergence_block=5, predecessors=[1, 2, 3], return_target=9
        )
        assert all(isinstance(m, DuplicateBlock) for m in mods)
        assert [m.pred_serial for m in mods] == [1, 2, 3]
        assert all(m.source_block == 5 and m.target_block == 9 for m in mods)

    def test_empty_predecessors_yields_empty_plan(self) -> None:
        assert plan_tail_duplicate(
            convergence_block=5, predecessors=[], return_target=9
        ) == []

    def test_deconverges_shared_guard(self) -> None:
        # The lab's shared_convergence: N byte-emits -> 1 shared_guard -> return.
        # Tail-dup gives each byte its own private guard copy -> return (the cascade).
        mods = plan_tail_duplicate(
            convergence_block=53, predecessors=[10, 20, 30, 40], return_target=99
        )
        assert len(mods) == 4
        assert {m.pred_serial for m in mods} == {10, 20, 30, 40}


class TestDeadStoreEliminate:
    """De-stage: NOP the dead state-variable stores (the `stage = K` writes)."""

    def test_nops_each_write_site(self) -> None:
        mods = plan_dead_store_eliminate([(10, 0x1000), (11, 0x2000)])
        assert all(isinstance(m, NopInstructions) for m in mods)
        assert {m.block_serial for m in mods} == {10, 11}

    def test_groups_sites_by_block(self) -> None:
        # Multiple staging writes in one block collapse to a single per-block NOP op.
        mods = plan_dead_store_eliminate([(10, 0x1000), (10, 0x1004), (11, 0x2000)])
        by_block = {m.block_serial: m.insn_eas for m in mods}
        assert by_block[10] == (0x1000, 0x1004)
        assert by_block[11] == (0x2000,)

    def test_empty_sites_yields_empty_plan(self) -> None:
        assert plan_dead_store_eliminate([]) == []
