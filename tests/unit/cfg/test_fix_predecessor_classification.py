"""Bucket-by-bucket unit tests for the FixPredecessor classifier.

The classifier is diagnostic-only and built on top of
``plan_fix_predecessor_clone_as_goto`` — these tests exercise the bucket
assignment for each shape called out by the next-slice plan.
"""
from __future__ import annotations

from d810.transforms.fix_predecessor_classification import (
    FixPredecessorBucket,
    PredecessorTopology,
    classify_predecessor_modification,
    format_classification_report,
    summarize_classifications,
)
from d810.transforms.fix_predecessor_planning import (
    FixPredecessorOutcome,
    FixPredecessorRejectReason,
)
from d810.ir.flowgraph import BlockSnapshot, FlowGraph, InsnSnapshot


class _BlockRef:
    def __init__(self, block_num: int):
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
                ea=0x4000 + serial,
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
        start_ea=0x4000 + serial,
        insn_snapshots=insns,
    )


def _bucket_already_supported_cfg() -> FlowGraph:
    return FlowGraph(
        blocks={
            8: _block(8, (10,), ()),
            9: _block(9, (10,), ()),
            10: _block(10, (11, 12), (8, 9), branch_target=12),
            11: _block(11, (), (10,)),
            12: _block(12, (), (10,)),
        },
        entry_serial=8,
        func_ea=0x401000,
    )


def test_planner_accepted_yields_already_supported_one_way() -> None:
    classification = classify_predecessor_modification(
        _bucket_already_supported_cfg(),
        pred_serial=8,
        conditional_serial=10,
        selected_target_serial=12,
        outcome=FixPredecessorOutcome.ALWAYS_TAKEN,
        description="pred 8 always takes jump in block 10",
    )

    assert classification.bucket is FixPredecessorBucket.ALREADY_SUPPORTED_ONE_WAY
    assert classification.matches_clone_conditional_as_goto is True
    assert classification.planner_rejection is None
    assert classification.predecessor_topology is PredecessorTopology.ONE_WAY
    assert classification.predecessor_arm is None
    assert classification.clone_required is True  # cond.npred == 2
    assert classification.direct_redirect_equivalent is False


def test_two_way_predecessor_with_explicit_branch_target_arm_known() -> None:
    cfg = FlowGraph(
        blocks={
            # pred 7 is 2-way: explicit branch -> 10, fallthrough -> 20
            7: _block(7, (20, 10), (), branch_target=10),
            8: _block(8, (10,), ()),
            10: _block(10, (11, 12), (7, 8), branch_target=12),
            11: _block(11, (), (10,)),
            12: _block(12, (), (10,)),
            20: _block(20, (), (7,)),
        },
        entry_serial=7,
        func_ea=0x401000,
    )
    classification = classify_predecessor_modification(
        cfg,
        pred_serial=7,
        conditional_serial=10,
        selected_target_serial=12,
        outcome=FixPredecessorOutcome.ALWAYS_TAKEN,
    )

    assert classification.bucket is FixPredecessorBucket.TWO_WAY_PREDECESSOR_ARM_KNOWN
    assert classification.predecessor_topology is PredecessorTopology.TWO_WAY
    assert classification.predecessor_arm == 1  # explicit branch arm
    assert classification.matches_clone_conditional_as_goto is False
    # The branch-arm sibling planner admits this shape — that is the whole
    # point of the d81-4zm8 migration.
    assert classification.matches_clone_conditional_as_goto_from_branch_arm is True
    assert classification.planner_rejection is None


def test_two_way_predecessor_with_explicit_fallthrough_arm_known() -> None:
    cfg = FlowGraph(
        blocks={
            # pred 7 is 2-way: explicit branch -> 20, fallthrough -> 10 (cond)
            7: _block(7, (10, 20), (), branch_target=20),
            8: _block(8, (10,), ()),
            10: _block(10, (11, 12), (7, 8), branch_target=12),
            11: _block(11, (), (10,)),
            12: _block(12, (), (10,)),
            20: _block(20, (), (7,)),
        },
        entry_serial=7,
        func_ea=0x401000,
    )
    classification = classify_predecessor_modification(
        cfg,
        pred_serial=7,
        conditional_serial=10,
        selected_target_serial=12,
        outcome=FixPredecessorOutcome.ALWAYS_TAKEN,
    )

    assert classification.bucket is FixPredecessorBucket.TWO_WAY_PREDECESSOR_ARM_KNOWN
    assert classification.predecessor_arm == 0  # fallthrough arm


def test_two_way_predecessor_without_explicit_branch_target_ambiguous() -> None:
    # No tail insn snapshot -> infer_conditional_target returns None.
    cfg = FlowGraph(
        blocks={
            7: _block(7, (20, 10), ()),  # no branch_target supplied
            8: _block(8, (10,), ()),
            10: _block(10, (11, 12), (7, 8), branch_target=12),
            11: _block(11, (), (10,)),
            12: _block(12, (), (10,)),
            20: _block(20, (), (7,)),
        },
        entry_serial=7,
        func_ea=0x401000,
    )
    classification = classify_predecessor_modification(
        cfg,
        pred_serial=7,
        conditional_serial=10,
        selected_target_serial=12,
        outcome=FixPredecessorOutcome.ALWAYS_TAKEN,
    )

    assert classification.bucket is (
        FixPredecessorBucket.TWO_WAY_PREDECESSOR_ARM_AMBIGUOUS
    )
    assert classification.predecessor_topology is PredecessorTopology.TWO_WAY
    assert classification.predecessor_arm is None


def test_shared_successor_when_conditional_arms_collapse() -> None:
    # Cond 10 is 2-way but both arms point to 11 (degenerate diamond).
    cfg = FlowGraph(
        blocks={
            8: _block(8, (10,), ()),
            9: _block(9, (10,), ()),
            10: _block(10, (11, 11), (8, 9), branch_target=11),
            11: _block(11, (), (10,)),
        },
        entry_serial=8,
        func_ea=0x401000,
    )
    classification = classify_predecessor_modification(
        cfg,
        pred_serial=8,
        conditional_serial=10,
        selected_target_serial=11,
        outcome=FixPredecessorOutcome.ALWAYS_TAKEN,
    )

    assert classification.bucket is FixPredecessorBucket.SHARED_SUCCESSOR
    assert classification.matches_clone_conditional_as_goto is False
    # Planner rejects with AMBIGUOUS_FALLTHROUGH for collapsed arms.
    assert classification.planner_rejection is (
        FixPredecessorRejectReason.AMBIGUOUS_FALLTHROUGH
    )


def test_multi_pred_target_when_selected_target_has_many_predecessors() -> None:
    # Selected target 12 has multiple preds in the snapshot; pred-arm topology
    # is fine but the planner rejects because cond_block's target arm is the
    # same conditional_target (12) and we set selected_target_serial=11
    # (the fallthrough) but with ALWAYS_TAKEN outcome -> mismatch.  Use the
    # NEVER_TAKEN form so the planner admits, then break shape via target.
    #
    # Simpler shape: a one-way pred reaching a 2-way cond whose selected arm
    # is the fallthrough block 12.  Target 12 has additional preds from
    # blocks 30/40 (external).  Planner admits this shape (multi_pred_target
    # is informational), so to actually surface the bucket we must construct
    # a case the planner rejects.  We use a SELF_LOOP_TARGET rejection: the
    # planner refuses to redirect a clone back into the source block.
    cfg = FlowGraph(
        blocks={
            8: _block(8, (10,), ()),
            9: _block(9, (10,), ()),
            10: _block(10, (10, 12), (8, 9, 10), branch_target=10),
            12: _block(12, (), (10, 30, 40)),
            30: _block(30, (12,), ()),
            40: _block(40, (12,), ()),
        },
        entry_serial=8,
        func_ea=0x401000,
    )

    classification = classify_predecessor_modification(
        cfg,
        pred_serial=8,
        conditional_serial=10,
        selected_target_serial=10,
        outcome=FixPredecessorOutcome.ALWAYS_TAKEN,
    )
    # Planner rejects self-loop; bucket falls through to multi_pred_target if
    # the selected target has multi predecessors.  Here selected_target == 10
    # (the cond itself) so we instead get unsupported_shape — adjust selection
    # to target 12 with a deliberate planner mismatch.
    classification2 = classify_predecessor_modification(
        cfg,
        pred_serial=8,
        conditional_serial=10,
        selected_target_serial=12,
        outcome=FixPredecessorOutcome.NEVER_TAKEN,
    )
    # NEVER_TAKEN expects fallthrough; cond's branch_target is 10 (self),
    # so fallthrough is 12.  Planner should ADMIT -> already_supported.
    assert classification2.bucket is FixPredecessorBucket.ALREADY_SUPPORTED_ONE_WAY

    # Force a multi_pred_target bucket by triggering a one-way pred with a
    # selected target that doesn't match the outcome arm.  Build a clean
    # multi-pred-target shape:
    cfg2 = FlowGraph(
        blocks={
            8: _block(8, (10,), ()),
            9: _block(9, (10,), ()),
            10: _block(10, (11, 12), (8, 9), branch_target=12),
            11: _block(11, (), (10,)),
            # selected target 12 has many preds — informational metadata.
            12: _block(12, (), (10, 30, 40)),
            30: _block(30, (12,), ()),
            40: _block(40, (12,), ()),
        },
        entry_serial=8,
        func_ea=0x401000,
    )
    accepted = classify_predecessor_modification(
        cfg2,
        pred_serial=8,
        conditional_serial=10,
        selected_target_serial=12,
        outcome=FixPredecessorOutcome.ALWAYS_TAKEN,
    )
    # Planner still accepts this clean shape — multi_pred_target is
    # surfaced as metadata, not as the bucket.
    assert accepted.bucket is FixPredecessorBucket.ALREADY_SUPPORTED_ONE_WAY
    assert accepted.selected_target_predecessor_count == 3

    # A clear multi_pred_target rejection: one-way pred, cond is not 2-way
    # (planner rejects with SOURCE_NOT_CONDITIONAL_2WAY), but the selected
    # target still has multi preds.
    cfg3 = FlowGraph(
        blocks={
            8: _block(8, (10,), ()),
            9: _block(9, (10,), ()),
            10: _block(10, (12,), (8, 9)),  # 1-way cond
            12: _block(12, (), (10, 30, 40)),
            30: _block(30, (12,), ()),
            40: _block(40, (12,), ()),
        },
        entry_serial=8,
        func_ea=0x401000,
    )
    cls3 = classify_predecessor_modification(
        cfg3,
        pred_serial=8,
        conditional_serial=10,
        selected_target_serial=12,
        outcome=FixPredecessorOutcome.ALWAYS_TAKEN,
    )
    assert cls3.bucket is FixPredecessorBucket.MULTI_PRED_TARGET
    assert cls3.selected_target_predecessor_count == 3
    assert cls3.matches_clone_conditional_as_goto is False


def test_multi_succ_predecessor_unsupported_for_three_way_predecessor() -> None:
    cfg = FlowGraph(
        blocks={
            8: _block(8, (10, 20, 30), ()),  # 3-way pred (unusual)
            10: _block(10, (11, 12), (8,), branch_target=12),
            11: _block(11, (), (10,)),
            12: _block(12, (), (10,)),
            20: _block(20, (), (8,)),
            30: _block(30, (), (8,)),
        },
        entry_serial=8,
        func_ea=0x401000,
    )
    classification = classify_predecessor_modification(
        cfg,
        pred_serial=8,
        conditional_serial=10,
        selected_target_serial=12,
        outcome=FixPredecessorOutcome.ALWAYS_TAKEN,
    )

    assert classification.bucket is (
        FixPredecessorBucket.MULTI_SUCC_PREDECESSOR_UNSUPPORTED
    )
    assert classification.predecessor_topology is PredecessorTopology.UNKNOWN


def test_copied_side_effects_required_when_cond_has_body_side_effects() -> None:
    # Build a one-way pred shape that the planner rejects (selected target is
    # not a cond arm) so we can surface the copied_side_effects bucket.  Use
    # a self-loop target rejection by selecting cond itself.
    cfg = FlowGraph(
        blocks={
            8: _block(8, (10,), ()),
            9: _block(9, (10,), ()),
            10: _block(10, (11, 12), (8, 9), branch_target=12),
            11: _block(11, (), (10,)),
            12: _block(12, (), (10,)),
        },
        entry_serial=8,
        func_ea=0x401000,
    )
    classification = classify_predecessor_modification(
        cfg,
        pred_serial=8,
        conditional_serial=10,
        selected_target_serial=10,  # self -> planner rejects
        outcome=FixPredecessorOutcome.ALWAYS_TAKEN,
        side_effect_blocks=frozenset({10}),
    )

    assert classification.bucket is (
        FixPredecessorBucket.COPIED_SIDE_EFFECTS_REQUIRED
    )
    assert classification.conditional_has_body_side_effects is True
    assert classification.planner_rejection is (
        FixPredecessorRejectReason.SELF_LOOP_TARGET
    )


def test_unsupported_shape_when_one_way_pred_with_target_missing() -> None:
    # Selected target absent from the CFG; not a side-effect case and the
    # target has zero predecessors recorded, so no other bucket fires.
    cfg = FlowGraph(
        blocks={
            8: _block(8, (10,), ()),
            9: _block(9, (10,), ()),
            10: _block(10, (11, 12), (8, 9), branch_target=12),
            11: _block(11, (), (10,)),
            12: _block(12, (), (10,)),
        },
        entry_serial=8,
        func_ea=0x401000,
    )
    classification = classify_predecessor_modification(
        cfg,
        pred_serial=8,
        conditional_serial=10,
        selected_target_serial=99,
        outcome=FixPredecessorOutcome.ALWAYS_TAKEN,
    )

    assert classification.bucket is FixPredecessorBucket.UNSUPPORTED_SHAPE
    assert classification.planner_rejection is (
        FixPredecessorRejectReason.TARGET_BLOCK_MISSING
    )


def test_two_way_predecessor_not_targeting_cond_falls_back_to_unsupported() -> None:
    # 2-way pred whose succs do NOT include the conditional block.
    cfg = FlowGraph(
        blocks={
            7: _block(7, (20, 21), (), branch_target=21),
            8: _block(8, (10,), ()),
            10: _block(10, (11, 12), (8,), branch_target=12),
            11: _block(11, (), (10,)),
            12: _block(12, (), (10,)),
            20: _block(20, (), (7,)),
            21: _block(21, (), (7,)),
        },
        entry_serial=7,
        func_ea=0x401000,
    )
    classification = classify_predecessor_modification(
        cfg,
        pred_serial=7,
        conditional_serial=10,
        selected_target_serial=12,
        outcome=FixPredecessorOutcome.ALWAYS_TAKEN,
    )

    assert classification.bucket is FixPredecessorBucket.UNSUPPORTED_SHAPE
    assert classification.predecessor_topology is PredecessorTopology.TWO_WAY
    assert classification.predecessor_arm is None


def _build_synthetic_corpus() -> tuple:
    """Return a fixed-order tuple of classifications spanning every bucket.

    Used as a stand-in corpus for the report helper.  A real corpus
    inventory across IDA-driven e2e fixtures populates the live rule's
    ``classifications`` property; this synthetic set proves the report
    helper renders all buckets stably without requiring IDA.
    """
    accepted = classify_predecessor_modification(
        _bucket_already_supported_cfg(),
        pred_serial=8,
        conditional_serial=10,
        selected_target_serial=12,
        outcome=FixPredecessorOutcome.ALWAYS_TAKEN,
        description="accept-case",
    )

    two_way_known_cfg = FlowGraph(
        blocks={
            7: _block(7, (20, 10), (), branch_target=10),
            8: _block(8, (10,), ()),
            10: _block(10, (11, 12), (7, 8), branch_target=12),
            11: _block(11, (), (10,)),
            12: _block(12, (), (10,)),
            20: _block(20, (), (7,)),
        },
        entry_serial=7,
        func_ea=0x402000,
    )
    two_way_known = classify_predecessor_modification(
        two_way_known_cfg,
        pred_serial=7,
        conditional_serial=10,
        selected_target_serial=12,
        outcome=FixPredecessorOutcome.ALWAYS_TAKEN,
        description="two-way-known",
    )

    two_way_ambiguous_cfg = FlowGraph(
        blocks={
            7: _block(7, (20, 10), ()),
            8: _block(8, (10,), ()),
            10: _block(10, (11, 12), (7, 8), branch_target=12),
            11: _block(11, (), (10,)),
            12: _block(12, (), (10,)),
            20: _block(20, (), (7,)),
        },
        entry_serial=7,
        func_ea=0x402000,
    )
    two_way_ambiguous = classify_predecessor_modification(
        two_way_ambiguous_cfg,
        pred_serial=7,
        conditional_serial=10,
        selected_target_serial=12,
        outcome=FixPredecessorOutcome.ALWAYS_TAKEN,
        description="two-way-ambiguous",
    )

    shared_cfg = FlowGraph(
        blocks={
            8: _block(8, (10,), ()),
            9: _block(9, (10,), ()),
            10: _block(10, (11, 11), (8, 9), branch_target=11),
            11: _block(11, (), (10,)),
        },
        entry_serial=8,
        func_ea=0x402000,
    )
    shared = classify_predecessor_modification(
        shared_cfg,
        pred_serial=8,
        conditional_serial=10,
        selected_target_serial=11,
        outcome=FixPredecessorOutcome.ALWAYS_TAKEN,
        description="shared-successor",
    )

    multi_pred_cfg = FlowGraph(
        blocks={
            8: _block(8, (10,), ()),
            9: _block(9, (10,), ()),
            10: _block(10, (12,), (8, 9)),
            12: _block(12, (), (10, 30, 40)),
            30: _block(30, (12,), ()),
            40: _block(40, (12,), ()),
        },
        entry_serial=8,
        func_ea=0x402000,
    )
    multi_pred = classify_predecessor_modification(
        multi_pred_cfg,
        pred_serial=8,
        conditional_serial=10,
        selected_target_serial=12,
        outcome=FixPredecessorOutcome.ALWAYS_TAKEN,
        description="multi-pred-target",
    )

    multi_succ_cfg = FlowGraph(
        blocks={
            8: _block(8, (10, 20, 30), ()),
            10: _block(10, (11, 12), (8,), branch_target=12),
            11: _block(11, (), (10,)),
            12: _block(12, (), (10,)),
            20: _block(20, (), (8,)),
            30: _block(30, (), (8,)),
        },
        entry_serial=8,
        func_ea=0x402000,
    )
    multi_succ = classify_predecessor_modification(
        multi_succ_cfg,
        pred_serial=8,
        conditional_serial=10,
        selected_target_serial=12,
        outcome=FixPredecessorOutcome.ALWAYS_TAKEN,
        description="multi-succ-pred",
    )

    side_effects_cfg = FlowGraph(
        blocks={
            8: _block(8, (10,), ()),
            9: _block(9, (10,), ()),
            10: _block(10, (11, 12), (8, 9), branch_target=12),
            11: _block(11, (), (10,)),
            12: _block(12, (), (10,)),
        },
        entry_serial=8,
        func_ea=0x402000,
    )
    side_effects = classify_predecessor_modification(
        side_effects_cfg,
        pred_serial=8,
        conditional_serial=10,
        selected_target_serial=10,
        outcome=FixPredecessorOutcome.ALWAYS_TAKEN,
        side_effect_blocks=frozenset({10}),
        description="side-effects",
    )

    unsupported_cfg = FlowGraph(
        blocks={
            8: _block(8, (10,), ()),
            9: _block(9, (10,), ()),
            10: _block(10, (11, 12), (8, 9), branch_target=12),
            11: _block(11, (), (10,)),
            12: _block(12, (), (10,)),
        },
        entry_serial=8,
        func_ea=0x402000,
    )
    unsupported = classify_predecessor_modification(
        unsupported_cfg,
        pred_serial=8,
        conditional_serial=10,
        selected_target_serial=99,
        outcome=FixPredecessorOutcome.ALWAYS_TAKEN,
        description="unsupported",
    )

    return (
        accepted,
        two_way_known,
        two_way_ambiguous,
        shared,
        multi_pred,
        multi_succ,
        side_effects,
        unsupported,
    )


def test_summarize_classifications_covers_every_bucket() -> None:
    corpus = _build_synthetic_corpus()
    counts = summarize_classifications(corpus)

    # Every bucket appears exactly once in the synthetic corpus.
    assert set(counts.keys()) == set(FixPredecessorBucket)
    for bucket, count in counts.items():
        assert count == 1, f"bucket {bucket.value} has count {count}, expected 1"


def test_format_classification_report_lists_every_bucket_with_example() -> None:
    corpus = _build_synthetic_corpus()
    report = format_classification_report(corpus, examples_per_bucket=2)

    # Title + count line includes total records.
    assert "FixPredecessor classification report (8 record(s))" in report
    for bucket in FixPredecessorBucket:
        assert f"[{bucket.value}] count=1" in report

    # Examples include topology and planner outcome.
    assert "pred=8" in report
    assert "topology=one_way" in report
    assert "topology=two_way" in report
    assert "planner=accepted" in report
    assert "planner=pred_not_simple_oneway" in report


def test_classification_records_topology_metadata_for_admitted_case() -> None:
    classification = classify_predecessor_modification(
        _bucket_already_supported_cfg(),
        pred_serial=8,
        conditional_serial=10,
        selected_target_serial=12,
        outcome=FixPredecessorOutcome.ALWAYS_TAKEN,
        description="pred 8 always takes jump in block 10",
    )

    assert classification.source_block == 8
    assert classification.target_conditional_block == 10
    assert classification.selected_predecessor == 8
    assert classification.selected_target == 12
    assert classification.outcome is FixPredecessorOutcome.ALWAYS_TAKEN
    assert classification.conditional_target_successor_count == 2
    assert classification.conditional_target_predecessor_count == 2
    assert classification.selected_target_predecessor_count == 1
    assert classification.description == "pred 8 always takes jump in block 10"
