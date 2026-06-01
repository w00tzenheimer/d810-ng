"""Unit tests for FixPredecessorBranchArmStrategy.

The strategy is the cleanup-family engine entry point for known predecessor-arm
FixPredecessor shapes (d81-4zm8).  These tests pin the planner-driven gating:
arm=1 and arm=0 fixes flow through as ``CloneConditionalAsGotoFromBranchArm``
primitives, while multi-pred-target and side-effect-bearing candidates are
dropped so they remain in legacy fallback.

Synthetic ``FlowGraph`` metadata is used to seed candidate fixes
because the live mba collector is intentionally a stub today (see
:func:`collect_live_fix_predecessor_branch_arm_fixes` docstring).
"""
from __future__ import annotations

from types import SimpleNamespace

import pytest

from d810.transforms.fix_predecessor_planning import FixPredecessorOutcome
from d810.ir.flowgraph import BlockSnapshot, FlowGraph, InsnSnapshot
from d810.transforms.graph_modification import CloneConditionalAsGotoFromBranchArm
from d810.passes.fix_predecessor_branch_arm import (
    FIX_PREDECESSOR_BRANCH_ARM_FIXES_METADATA_KEY,
    FixPredecessorBranchArmFix,
    FixPredecessorBranchArmStrategy,
    build_fix_predecessor_branch_arm_modifications,
    collect_live_fix_predecessor_branch_arm_fixes,
    extract_fix_predecessor_branch_arm_fixes,
    serialize_fix_predecessor_branch_arm_fixes,
)


class _BlockRef:
    def __init__(self, block_num: int) -> None:
        self.block_num = block_num


def _block(
    serial: int,
    succs: tuple[int, ...],
    preds: tuple[int, ...],
    *,
    branch_target: int | None = None,
) -> BlockSnapshot:
    insns: tuple[InsnSnapshot, ...] = ()
    if branch_target is not None:
        ref = _BlockRef(branch_target)
        insns = (
            InsnSnapshot(
                opcode=0x70,
                ea=0x9000 + serial,
                operands=(ref,),
                operand_slots=(("d", ref),),
            ),
        )
    return BlockSnapshot(
        serial=serial,
        block_type=2 if len(succs) == 2 else (1 if succs else 0),
        succs=succs,
        preds=preds,
        flags=0,
        start_ea=0x9000 + serial,
        insn_snapshots=insns,
    )


def _arm_one_admittable_cfg(metadata: dict | None = None) -> FlowGraph:
    """Standard arm=1 admittable shape: pred 7 -> cond 10 -> target 12.

    pred 7 is 2-way (explicit branch -> 10 = cond, fallthrough -> 20).
    cond 10 is 2-way (fallthrough -> 11, explicit branch -> 12).
    target 12 has only cond 10 as a predecessor.
    """
    blocks = {
        7: _block(7, (20, 10), (), branch_target=10),
        8: _block(8, (10,), ()),
        10: _block(10, (11, 12), (7, 8), branch_target=12),
        11: _block(11, (), (10,)),
        12: _block(12, (), (10,)),
        20: _block(20, (), (7,)),
    }
    return FlowGraph(
        blocks=blocks,
        entry_serial=7,
        func_ea=0x401000,
        metadata=metadata or {},
    )


def _arm_zero_cfg(metadata: dict | None = None) -> FlowGraph:
    """arm=0 shape (cond is pred's fallthrough arm)."""
    blocks = {
        7: _block(7, (10, 20), (), branch_target=20),
        8: _block(8, (10,), ()),
        10: _block(10, (11, 12), (7, 8), branch_target=12),
        11: _block(11, (), (10,)),
        12: _block(12, (), (10,)),
        20: _block(20, (), (7,)),
    }
    return FlowGraph(
        blocks=blocks,
        entry_serial=7,
        func_ea=0x401000,
        metadata=metadata or {},
    )


def _snapshot_for(flow_graph: FlowGraph) -> SimpleNamespace:
    """Lightweight stand-in for AnalysisSnapshot used by the strategy."""
    return SimpleNamespace(flow_graph=flow_graph)


def test_strategy_is_inert_without_metadata() -> None:
    snapshot = _snapshot_for(_arm_one_admittable_cfg())
    strategy = FixPredecessorBranchArmStrategy()

    assert strategy.name == "fix_predecessor_branch_arm"
    assert strategy.is_applicable(snapshot) is False
    assert strategy.plan(snapshot) is None


def test_strategy_admits_arm_one_candidate_into_typed_primitive() -> None:
    arm_one_fix = FixPredecessorBranchArmFix(
        cond_block=10,
        pred_block=7,
        target=12,
        pred_arm=1,
        outcome=FixPredecessorOutcome.ALWAYS_TAKEN,
        description="pred 7 arm=1 always takes jump in block 10",
    )
    flow_graph = _arm_one_admittable_cfg(
        metadata={
            FIX_PREDECESSOR_BRANCH_ARM_FIXES_METADATA_KEY: (arm_one_fix,),
        }
    )
    strategy = FixPredecessorBranchArmStrategy()

    snapshot = _snapshot_for(flow_graph)
    assert strategy.is_applicable(snapshot) is True

    fragment = strategy.plan(snapshot)
    assert fragment is not None
    assert fragment.strategy_name == "fix_predecessor_branch_arm"
    assert fragment.expected_benefit.blocks_freed == 1
    assert fragment.modifications == [
        CloneConditionalAsGotoFromBranchArm(
            source_block=10,
            pred_serial=7,
            pred_arm=1,
            goto_target=12,
            reason=(
                "pred 7 arm=1 always takes jump in block 10"
            ),
        )
    ]
    # Ownership scope binds the source block + the pred->source edge.
    assert 10 in fragment.ownership.blocks
    assert (7, 10) in fragment.ownership.edges
    assert fragment.metadata[
        FIX_PREDECESSOR_BRANCH_ARM_FIXES_METADATA_KEY
    ] == (arm_one_fix,)


def test_strategy_admits_arm_zero_candidate_into_typed_primitive() -> None:
    arm_zero_fix = FixPredecessorBranchArmFix(
        cond_block=10,
        pred_block=7,
        target=11,
        pred_arm=0,
        outcome=FixPredecessorOutcome.NEVER_TAKEN,
        description="pred 7 arm=0 never takes jump in block 10",
    )
    flow_graph = _arm_zero_cfg(
        metadata={
            FIX_PREDECESSOR_BRANCH_ARM_FIXES_METADATA_KEY: (arm_zero_fix,),
        }
    )
    snapshot = _snapshot_for(flow_graph)
    strategy = FixPredecessorBranchArmStrategy()

    assert strategy.is_applicable(snapshot) is True
    fragment = strategy.plan(snapshot)
    assert fragment is not None
    assert fragment.modifications == [
        CloneConditionalAsGotoFromBranchArm(
            source_block=10,
            pred_serial=7,
            pred_arm=0,
            goto_target=11,
            reason="pred 7 arm=0 never takes jump in block 10",
        )
    ]


def test_strategy_drops_multi_pred_target_candidate() -> None:
    """Selected target with >1 predecessor must stay in legacy fallback."""
    flow_graph = FlowGraph(
        blocks={
            7: _block(7, (20, 10), (), branch_target=10),
            8: _block(8, (10,), ()),
            10: _block(10, (11, 12), (7, 8), branch_target=12),
            11: _block(11, (), (10,)),
            # target 12 has multiple preds (10, 30, 31)
            12: _block(12, (), (10, 30, 31)),
            20: _block(20, (), (7,)),
            30: _block(30, (12,), ()),
            31: _block(31, (12,), ()),
        },
        entry_serial=7,
        func_ea=0x401000,
        metadata={
            FIX_PREDECESSOR_BRANCH_ARM_FIXES_METADATA_KEY: (
                FixPredecessorBranchArmFix(
                    cond_block=10,
                    pred_block=7,
                    target=12,
                    pred_arm=1,
                    outcome=FixPredecessorOutcome.ALWAYS_TAKEN,
                ),
            ),
        },
    )
    snapshot = _snapshot_for(flow_graph)
    fragment = FixPredecessorBranchArmStrategy().plan(snapshot)
    assert fragment is None


def test_strategy_drops_side_effect_candidate() -> None:
    """Conditional with body side effects must stay in legacy fallback."""
    flow_graph = _arm_one_admittable_cfg(
        metadata={
            FIX_PREDECESSOR_BRANCH_ARM_FIXES_METADATA_KEY: (
                FixPredecessorBranchArmFix(
                    cond_block=10,
                    pred_block=7,
                    target=12,
                    pred_arm=1,
                    outcome=FixPredecessorOutcome.ALWAYS_TAKEN,
                    has_body_side_effects=True,
                ),
            ),
        }
    )
    snapshot = _snapshot_for(flow_graph)
    fragment = FixPredecessorBranchArmStrategy().plan(snapshot)
    assert fragment is None


def test_strategy_partitions_mixed_candidate_batch() -> None:
    """Only admittable candidates appear in the plan fragment."""
    flow_graph = _arm_one_admittable_cfg(
        metadata={
            FIX_PREDECESSOR_BRANCH_ARM_FIXES_METADATA_KEY: (
                FixPredecessorBranchArmFix(
                    cond_block=10,
                    pred_block=7,
                    target=12,
                    pred_arm=1,
                    outcome=FixPredecessorOutcome.ALWAYS_TAKEN,
                ),
                # Same shape but arm=0 against a fabricated (arm=0) topology
                # in the same CFG would not be admitted; we use a target
                # mismatch here to drive the planner reject path.
                FixPredecessorBranchArmFix(
                    cond_block=10,
                    pred_block=7,
                    target=11,  # arm mismatch for ALWAYS_TAKEN
                    pred_arm=1,
                    outcome=FixPredecessorOutcome.ALWAYS_TAKEN,
                ),
            ),
        }
    )
    snapshot = _snapshot_for(flow_graph)
    fragment = FixPredecessorBranchArmStrategy().plan(snapshot)
    assert fragment is not None
    assert len(fragment.modifications) == 1
    assert fragment.modifications[0].goto_target == 12


def test_collect_live_fix_predecessor_branch_arm_fixes_is_stub() -> None:
    """Live collector intentionally returns no candidates today (d81-4zm8 follow-up)."""
    mba = SimpleNamespace(maturity=8, entry_ea=0x401000, qty=0)
    assert collect_live_fix_predecessor_branch_arm_fixes(mba) == ()
    assert (
        collect_live_fix_predecessor_branch_arm_fixes(
            mba, allowed_maturities=(8,)
        )
        == ()
    )
    # None mba should be ignored without raising.
    assert collect_live_fix_predecessor_branch_arm_fixes(None) == ()


def test_serialize_is_deterministically_sorted() -> None:
    a = FixPredecessorBranchArmFix(
        cond_block=20,
        pred_block=5,
        target=22,
        pred_arm=1,
        outcome=FixPredecessorOutcome.ALWAYS_TAKEN,
    )
    b = FixPredecessorBranchArmFix(
        cond_block=10,
        pred_block=7,
        target=12,
        pred_arm=1,
        outcome=FixPredecessorOutcome.ALWAYS_TAKEN,
    )
    assert serialize_fix_predecessor_branch_arm_fixes([a, b]) == (b, a)


def test_extract_returns_empty_tuple_when_metadata_absent() -> None:
    assert extract_fix_predecessor_branch_arm_fixes(
        FlowGraph(blocks={}, entry_serial=0, func_ea=0)
    ) == ()


def test_build_modifications_returns_only_admittable_primitives() -> None:
    """``build_fix_predecessor_branch_arm_modifications`` filters by planner.

    Uses an outcome/target mismatch to trigger a planner rejection — the
    planner re-derives ``pred_arm`` from the snapshot topology, so passing
    ``pred_arm=0`` in the fix is not itself enough to drive rejection;
    instead we pair ALWAYS_TAKEN with the fallthrough arm (target 11) so
    the planner returns ``OUTCOME_TARGET_MISMATCH``.
    """
    flow_graph = _arm_one_admittable_cfg()
    admittable = FixPredecessorBranchArmFix(
        cond_block=10,
        pred_block=7,
        target=12,
        pred_arm=1,
        outcome=FixPredecessorOutcome.ALWAYS_TAKEN,
    )
    rejected_outcome_mismatch = FixPredecessorBranchArmFix(
        cond_block=10,
        pred_block=7,
        target=11,  # fallthrough arm of cond — wrong for ALWAYS_TAKEN
        pred_arm=1,
        outcome=FixPredecessorOutcome.ALWAYS_TAKEN,
    )
    mods = build_fix_predecessor_branch_arm_modifications(
        [admittable, rejected_outcome_mismatch],
        flow_graph,
    )
    assert mods == [
        CloneConditionalAsGotoFromBranchArm(
            source_block=10,
            pred_serial=7,
            pred_arm=1,
            goto_target=12,
        )
    ]
