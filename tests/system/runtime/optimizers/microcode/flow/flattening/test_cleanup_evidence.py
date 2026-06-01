"""Pure tests for neutral cleanup evidence adapters."""
from __future__ import annotations

from types import SimpleNamespace

import pytest

from d810.ir.flowgraph import BlockSnapshot, FlowGraph, InsnSnapshot, MopSnapshot
from d810.transforms.graph_modification import (
    DuplicateReplayAndRedirect,
    DuplicateReplayEntry,
    InsertBlock,
)
from d810.transforms.materialization_payload import (
    CapturedBlockBody,
    CapturedBlockBodySummary,
)
from d810.transforms.plan import (
    PatchDuplicateReplayAndRedirect,
    PatchInsertBlock,
    compile_patch_plan,
)
from d810.transforms.cleanup_evidence import (
    BAD_WHILE_LOOP_SOURCE_RULE,
    CLEANUP_CONDITIONAL_REDIRECT_PROOF_METADATA_KEY,
    CleanupProofVerdict,
    CleanupExitShape,
    CleanupDuplicateGroupReplayCandidate,
    CleanupFollowUpResolutionBucket,
    CleanupPerPredReplay,
    CleanupProofState,
    CleanupRewriteIntent,
    CleanupSideEffectReplayCandidate,
    CleanupTrampolineIsolationCandidate,
    DispatcherCleanupCandidate,
    bad_while_loop_duplicate_candidate,
    bad_while_loop_duplicate_group_replay_candidate,
    bad_while_loop_side_effect_replay_candidate,
    bad_while_loop_trampoline_isolation_candidate,
    build_bad_while_loop_follow_up_proofs,
    build_dispatcher_cleanup_modification,
    explain_bad_while_loop_conditional_redirect,
    extract_conditional_redirect_proofs,
    extract_follow_up_reclassifications,
    serialize_conditional_redirect_proofs,
    serialize_follow_up_reclassifications,
    reclassify_bad_while_loop_follow_ups,
    validate_conditional_duplicate_cleanup_edit,
    validate_conditional_redirect_cleanup_edit,
    validate_duplicate_group_replay_candidate,
    validate_dispatcher_cleanup_candidate,
    validate_side_effect_replay_candidate,
    validate_trampoline_isolation_candidate,
)
from d810.optimizers.microcode.flow.flattening.strategies.bad_while_loop import (
    BAD_WHILE_LOOP_DUPLICATE_AND_REDIRECT,
    BAD_WHILE_LOOP_INSERT_BLOCK,
    BAD_WHILE_LOOP_UNSUPPORTED,
    BadWhileLoopConditionalDuplicate,
    BadWhileLoopConditionalRedirect,
    BadWhileLoopDuplicateRedirect,
    BadWhileLoopFollowUp,
)


def _block(
    serial: int,
    succs: tuple[int, ...],
    preds: tuple[int, ...],
    *,
    block_type: int = 1,
    tail_target: int | None = None,
) -> BlockSnapshot:
    insn_snapshots = ()
    if tail_target is not None:
        target_mop = MopSnapshot(t=7, size=4, block_ref=tail_target)
        insn_snapshots = (
            InsnSnapshot(
                opcode=0x200,
                ea=0x5000 + serial,
                operands=(target_mop,),
                operand_slots=(("d", target_mop),),
                d=target_mop,
            ),
        )
    return BlockSnapshot(
        serial=serial,
        block_type=block_type,
        succs=succs,
        preds=preds,
        flags=0,
        start_ea=serial,
        insn_snapshots=insn_snapshots,
    )


def _duplicate_cfg(
    *,
    pred_9_succs: tuple[int, ...] = (5,),
    extra_source_pred: bool = False,
) -> FlowGraph:
    source_preds = (8, 9, 10) if extra_source_pred else (8, 9)
    blocks = {
        2: _block(2, (3, 4), (5,), block_type=4),
        3: _block(3, (), (2, 5), block_type=2),
        4: _block(4, (), (2, 5), block_type=2),
        5: _block(5, (2,), source_preds),
        8: _block(8, (5,), (0,)),
        9: _block(9, pred_9_succs, (0,)),
    }
    if extra_source_pred:
        blocks[10] = _block(10, (5,), (0,))
    return FlowGraph(
        blocks=blocks,
        entry_serial=2,
        func_ea=0x1000,
    )


def _side_effect_body(
    *,
    contains_call: bool = False,
) -> CapturedBlockBody:
    instructions = (InsnSnapshot(opcode=0x77, ea=0x2000, operands=()),)
    return CapturedBlockBody(
        backend_id="hexrays.insn_snapshot",
        capture_id="test",
        summary=CapturedBlockBodySummary(
            source_blocks=(5,),
            instruction_count=len(instructions),
            source_eas=frozenset({0x2000}),
            contains_call=contains_call,
        ),
        payload=instructions,
    )


def _conditional_redirect_cfg(
    *,
    ref_tail_target: int | None = 3,
    source_succs: tuple[int, ...] = (2,),
) -> FlowGraph:
    return FlowGraph(
        blocks={
            0: _block(0, (1,), ()),
            1: _block(1, source_succs, (0,)),
            2: _block(2, (12, 99), (1,), block_type=4),
            3: _block(3, (), (12,), block_type=2),
            4: _block(4, (), (12,), block_type=2),
            12: _block(
                12,
                (4, 3),
                (2,),
                block_type=4,
                tail_target=ref_tail_target,
            ),
            99: _block(99, (), (2,), block_type=2),
        },
        entry_serial=0,
        func_ea=0x1000,
    )


def test_bad_while_loop_duplicate_adapter_builds_neutral_candidate() -> None:
    edit = BadWhileLoopDuplicateRedirect(
        dispatcher_entry=2,
        source_serial=5,
        per_pred_targets=((8, 3), (9, 4)),
    )

    candidate = bad_while_loop_duplicate_candidate(edit)

    assert candidate == DispatcherCleanupCandidate(
        source_rule=BAD_WHILE_LOOP_SOURCE_RULE,
        dispatcher_entry=2,
        source_serial=5,
        exit_shape=CleanupExitShape.SHARED_ONE_WAY_BY_PRED,
        rewrite_intent=CleanupRewriteIntent.DUPLICATE_AND_REDIRECT,
        per_pred_targets=((8, 3), (9, 4)),
    )


def test_duplicate_candidate_validates_but_requires_replay_or_corridor_proof() -> None:
    edit = BadWhileLoopDuplicateRedirect(
        dispatcher_entry=2,
        source_serial=5,
        per_pred_targets=((8, 3), (9, 4)),
    )
    candidate = bad_while_loop_duplicate_candidate(edit)
    assert candidate is not None

    assert validate_dispatcher_cleanup_candidate(_duplicate_cfg(), candidate) is True
    with pytest.raises(ValueError, match="requires replay or corridor proof"):
        build_dispatcher_cleanup_modification(candidate)


def test_side_effect_replay_candidate_validates_lowers_and_compiles_to_patch_insert() -> None:
    body = _side_effect_body()
    candidate = bad_while_loop_side_effect_replay_candidate(
        dispatcher_entry=2,
        source_serial=5,
        target_serial=3,
        captured_body=body,
        dispatcher_internal_serials=(2,),
    )
    assert candidate == CleanupSideEffectReplayCandidate(
        source_rule=BAD_WHILE_LOOP_SOURCE_RULE,
        dispatcher_entry=2,
        source_serial=5,
        target_serial=3,
        exit_shape=CleanupExitShape.ONE_WAY_DISPATCHER_PREDECESSOR,
        rewrite_intent=CleanupRewriteIntent.REPLAY_SIDE_EFFECTS_AND_REDIRECT,
        captured_body=body,
        dispatcher_internal_serials=(2,),
    )
    assert validate_side_effect_replay_candidate(_duplicate_cfg(), candidate) is True

    modification = build_dispatcher_cleanup_modification(candidate)
    assert modification == InsertBlock(
        pred_serial=5,
        succ_serial=3,
        old_target_serial=2,
        captured_body=body,
    )

    patch_plan = compile_patch_plan([modification], _duplicate_cfg())
    assert any(isinstance(step, PatchInsertBlock) for step in patch_plan.steps)
    assert not any(step.__class__.__name__ == "LegacyBlockOperation" for step in patch_plan.steps)


def test_duplicate_group_replay_candidate_validates_lowers_and_compiles_to_composite_patch() -> None:
    left_body = _side_effect_body()
    right_body = _side_effect_body()
    candidate = bad_while_loop_duplicate_group_replay_candidate(
        dispatcher_entry=2,
        source_serial=5,
        per_pred_replays=(
            CleanupPerPredReplay(pred_serial=8, target_serial=3, captured_body=left_body),
            CleanupPerPredReplay(pred_serial=9, target_serial=4, captured_body=right_body),
        ),
        dispatcher_internal_serials=(2,),
    )

    assert candidate == CleanupDuplicateGroupReplayCandidate(
        source_rule=BAD_WHILE_LOOP_SOURCE_RULE,
        dispatcher_entry=2,
        source_serial=5,
        exit_shape=CleanupExitShape.SHARED_ONE_WAY_BY_PRED_WITH_REPLAY,
        rewrite_intent=CleanupRewriteIntent.DUPLICATE_REPLAY_AND_REDIRECT,
        per_pred_replays=(
            CleanupPerPredReplay(pred_serial=8, target_serial=3, captured_body=left_body),
            CleanupPerPredReplay(pred_serial=9, target_serial=4, captured_body=right_body),
        ),
        dispatcher_internal_serials=(2,),
    )
    assert validate_duplicate_group_replay_candidate(_duplicate_cfg(), candidate) is True

    modification = build_dispatcher_cleanup_modification(candidate)
    assert modification == DuplicateReplayAndRedirect(
        source_serial=5,
        dispatcher_entry=2,
        per_pred_replays=(
            DuplicateReplayEntry(pred_serial=8, target_serial=3, captured_body=left_body),
            DuplicateReplayEntry(pred_serial=9, target_serial=4, captured_body=right_body),
        ),
    )

    patch_plan = compile_patch_plan([modification], _duplicate_cfg())
    assert isinstance(patch_plan.steps[0], PatchDuplicateReplayAndRedirect)
    assert patch_plan.legacy_block_operations == ()
    assert [spec.kind for spec in patch_plan.new_blocks] == [
        "duplicate_replay_insert",
        "duplicate_replay_insert",
        "duplicate_replay_clone",
    ]


def test_duplicate_group_replay_candidate_rejects_partial_calls_and_conditional_targets() -> None:
    valid = bad_while_loop_duplicate_group_replay_candidate(
        dispatcher_entry=2,
        source_serial=5,
        per_pred_replays=(
            CleanupPerPredReplay(pred_serial=8, target_serial=3, captured_body=_side_effect_body()),
            CleanupPerPredReplay(pred_serial=9, target_serial=4, captured_body=_side_effect_body()),
        ),
        dispatcher_internal_serials=(2,),
    )
    assert valid is not None

    partial = bad_while_loop_duplicate_group_replay_candidate(
        dispatcher_entry=2,
        source_serial=5,
        per_pred_replays=(
            CleanupPerPredReplay(pred_serial=8, target_serial=3, captured_body=_side_effect_body()),
        ),
        dispatcher_internal_serials=(2,),
    )
    assert partial is None

    with_call = bad_while_loop_duplicate_group_replay_candidate(
        dispatcher_entry=2,
        source_serial=5,
        per_pred_replays=(
            CleanupPerPredReplay(pred_serial=8, target_serial=3, captured_body=_side_effect_body()),
            CleanupPerPredReplay(
                pred_serial=9,
                target_serial=4,
                captured_body=_side_effect_body(contains_call=True),
            ),
        ),
        dispatcher_internal_serials=(2,),
    )
    assert with_call is None

    conditional_target_cfg = _duplicate_cfg()
    assert validate_duplicate_group_replay_candidate(
        FlowGraph(
            blocks={
                **conditional_target_cfg.blocks,
                4: _block(4, (6, 7), (2, 5), block_type=2),
                6: _block(6, (), (4,), block_type=0),
                7: _block(7, (), (4,), block_type=0),
            },
            entry_serial=conditional_target_cfg.entry_serial,
            func_ea=conditional_target_cfg.func_ea,
        ),
        valid,
    ) is False


def test_trampoline_isolation_candidate_validates_lowers_and_compiles() -> None:
    candidate = bad_while_loop_trampoline_isolation_candidate(
        dispatcher_entry=2,
        source_serial=1,
        target_serial=12,
        dispatcher_internal_serials=(2,),
    )

    assert candidate == CleanupTrampolineIsolationCandidate(
        source_rule=BAD_WHILE_LOOP_SOURCE_RULE,
        dispatcher_entry=2,
        source_serial=1,
        target_serial=12,
        exit_shape=CleanupExitShape.ONE_WAY_DISPATCHER_PREDECESSOR,
        rewrite_intent=CleanupRewriteIntent.TRAMPOLINE_ISOLATION,
        dispatcher_internal_serials=(2,),
    )
    assert validate_trampoline_isolation_candidate(
        _conditional_redirect_cfg(),
        candidate,
    ) is True

    modification = build_dispatcher_cleanup_modification(candidate)
    assert modification == InsertBlock(
        pred_serial=1,
        succ_serial=12,
        old_target_serial=2,
        instructions=(),
    )

    patch_plan = compile_patch_plan([modification], _conditional_redirect_cfg())
    assert any(isinstance(step, PatchInsertBlock) for step in patch_plan.steps)
    assert patch_plan.legacy_block_operations == ()


def test_trampoline_isolation_candidate_rejects_stale_or_cyclic_shape() -> None:
    candidate = bad_while_loop_trampoline_isolation_candidate(
        dispatcher_entry=2,
        source_serial=1,
        target_serial=12,
        dispatcher_internal_serials=(2,),
    )
    assert candidate is not None

    stale_source = _conditional_redirect_cfg(source_succs=(99,))
    assert validate_trampoline_isolation_candidate(stale_source, candidate) is False

    cyclic_target = FlowGraph(
        blocks={
            **_conditional_redirect_cfg().blocks,
            12: _block(12, (2, 3), (2,), block_type=4, tail_target=3),
        },
        entry_serial=0,
        func_ea=0x1000,
    )
    assert validate_trampoline_isolation_candidate(cyclic_target, candidate) is False


def test_conditional_redirect_explainer_classifies_safe_shape_and_round_trips() -> None:
    edit = BadWhileLoopConditionalRedirect(
        dispatcher_entry=2,
        source_serial=1,
        ref_block=12,
        conditional_target=3,
        fallthrough_target=4,
        dispatcher_internal_serials=(2,),
        copied_side_effects_absent=True,
    )

    proof = explain_bad_while_loop_conditional_redirect(
        edit,
        _conditional_redirect_cfg(),
        defer_reason="conditional_redirect_not_promoted",
    )

    assert proof is not None
    assert proof.verdict is CleanupProofVerdict.SAFE_SHAPE
    assert proof.reasons == ("safe_shape_preconditions_satisfied",)
    assert proof.source_shape.succs == (2,)
    assert proof.source_shape.current_old_edge == 2
    assert proof.dispatcher_shape.succs == (12, 99)
    assert proof.ref_shape.succs == (4, 3)
    assert proof.ref_shape.conditional_tail_target == 3
    assert proof.branch_polarity_proven is True
    assert proof.projected_dispatcher_cycle_free is True

    serialized = serialize_conditional_redirect_proofs((proof,))
    cfg = FlowGraph(
        blocks=_conditional_redirect_cfg().blocks,
        entry_serial=0,
        func_ea=0x1000,
        metadata={CLEANUP_CONDITIONAL_REDIRECT_PROOF_METADATA_KEY: serialized},
    )

    assert extract_conditional_redirect_proofs(cfg) == (proof,)


def test_conditional_redirect_explainer_reports_proof_gap_for_missing_tail_target() -> None:
    edit = BadWhileLoopConditionalRedirect(
        dispatcher_entry=2,
        source_serial=1,
        ref_block=12,
        conditional_target=3,
        fallthrough_target=4,
        dispatcher_internal_serials=(2,),
        copied_side_effects_absent=True,
    )

    proof = explain_bad_while_loop_conditional_redirect(
        edit,
        _conditional_redirect_cfg(ref_tail_target=None),
    )

    assert proof is not None
    assert proof.verdict is CleanupProofVerdict.PROOF_GAP
    assert "ref_conditional_tail_target_unproven" in proof.reasons
    assert proof.branch_polarity_proven is False


def test_conditional_redirect_explainer_rejects_polarity_and_cleanup_targets() -> None:
    edit = BadWhileLoopConditionalRedirect(
        dispatcher_entry=2,
        source_serial=1,
        ref_block=12,
        conditional_target=3,
        fallthrough_target=2,
        dispatcher_internal_serials=(2,),
        copied_side_effects_absent=True,
    )

    proof = explain_bad_while_loop_conditional_redirect(
        edit,
        _conditional_redirect_cfg(ref_tail_target=4),
    )

    assert proof is not None
    assert proof.verdict is CleanupProofVerdict.UNSAFE
    assert "branch_polarity_mismatch" in proof.reasons
    assert "target_inside_cleanup_or_identical" in proof.reasons


def test_conditional_cleanup_validation_accepts_only_safe_shapes() -> None:
    duplicate = BadWhileLoopConditionalDuplicate(
        dispatcher_entry=2,
        source_serial=6,
        pred_serial=8,
        conditional_target=3,
        fallthrough_target=4,
    )
    duplicate_cfg = FlowGraph(
        blocks={
            2: _block(2, (3, 4), (6,), block_type=4),
            3: _block(3, (), (2,), block_type=2),
            4: _block(4, (), (2, 6), block_type=2),
            6: _block(6, (2, 4), (8,), block_type=4),
            8: _block(8, (6,), (0,)),
        },
        entry_serial=2,
        func_ea=0x1000,
    )

    assert (
        validate_conditional_duplicate_cleanup_edit(duplicate_cfg, duplicate)
        is True
    )
    assert (
        validate_conditional_duplicate_cleanup_edit(
            FlowGraph(
                blocks={
                    **duplicate_cfg.blocks,
                    8: _block(8, (6, 99), (0,), block_type=4),
                    99: _block(99, (), (8,), block_type=2),
                },
                entry_serial=2,
                func_ea=0x1000,
            ),
            duplicate,
        )
        is False
    )

    redirect = BadWhileLoopConditionalRedirect(
        dispatcher_entry=2,
        source_serial=1,
        ref_block=12,
        conditional_target=3,
        fallthrough_target=4,
        dispatcher_internal_serials=(2,),
        copied_side_effects_absent=True,
    )
    assert validate_conditional_redirect_cleanup_edit(
        _conditional_redirect_cfg(),
        redirect,
    ) is True
    assert (
        validate_conditional_redirect_cleanup_edit(
            _conditional_redirect_cfg(ref_tail_target=4),
            redirect,
        )
        is False
    )


def test_side_effect_replay_candidate_rejects_calls_and_dispatcher_targets() -> None:
    assert (
        bad_while_loop_side_effect_replay_candidate(
            dispatcher_entry=2,
            source_serial=5,
            target_serial=3,
            captured_body=_side_effect_body(contains_call=True),
            dispatcher_internal_serials=(2,),
        )
        is None
    )
    assert (
        bad_while_loop_side_effect_replay_candidate(
            dispatcher_entry=2,
            source_serial=5,
            target_serial=2,
            captured_body=_side_effect_body(),
            dispatcher_internal_serials=(2,),
        )
        is None
    )


def test_duplicate_candidate_validation_rejects_non_one_way_predecessor() -> None:
    edit = BadWhileLoopDuplicateRedirect(
        dispatcher_entry=2,
        source_serial=5,
        per_pred_targets=((8, 3), (9, 4)),
    )
    candidate = bad_while_loop_duplicate_candidate(edit)
    assert candidate is not None

    assert (
        validate_dispatcher_cleanup_candidate(
            _duplicate_cfg(pred_9_succs=(5, 4)),
            candidate,
        )
        is False
    )


def test_duplicate_candidate_validation_rejects_unmodeled_source_predecessor() -> None:
    edit = BadWhileLoopDuplicateRedirect(
        dispatcher_entry=2,
        source_serial=5,
        per_pred_targets=((8, 3), (9, 4)),
    )
    candidate = bad_while_loop_duplicate_candidate(edit)
    assert candidate is not None

    assert (
        validate_dispatcher_cleanup_candidate(
            _duplicate_cfg(extra_source_pred=True),
            candidate,
        )
        is False
    )


def test_bad_while_loop_adapter_rejects_non_duplicate_and_self_target() -> None:
    assert (
        bad_while_loop_duplicate_candidate(
            BadWhileLoopConditionalRedirect(
                dispatcher_entry=2,
                source_serial=5,
                ref_block=12,
                conditional_target=3,
                fallthrough_target=4,
            )
        )
        is None
    )
    assert (
        bad_while_loop_duplicate_candidate(
            BadWhileLoopDuplicateRedirect(
                dispatcher_entry=2,
                source_serial=5,
                per_pred_targets=((8, 3), (9, 5)),
            )
        )
        is None
    )


def test_cleanup_candidate_lowering_is_exhaustive() -> None:
    candidate = DispatcherCleanupCandidate(
        source_rule=BAD_WHILE_LOOP_SOURCE_RULE,
        dispatcher_entry=2,
        source_serial=5,
        exit_shape="unknown",  # type: ignore[arg-type]
        rewrite_intent=CleanupRewriteIntent.DUPLICATE_AND_REDIRECT,
        per_pred_targets=((8, 3), (9, 4)),
    )

    with pytest.raises(ValueError, match="unsupported cleanup candidate"):
        build_dispatcher_cleanup_modification(candidate)


def test_bad_while_loop_follow_up_reclassifier_buckets_remaining_lanes() -> None:
    replay_body = _side_effect_body()
    replay_candidate = bad_while_loop_side_effect_replay_candidate(
        dispatcher_entry=2,
        source_serial=5,
        target_serial=3,
        captured_body=replay_body,
        dispatcher_internal_serials=(2,),
    )
    assert replay_candidate is not None
    trampoline_candidate = bad_while_loop_trampoline_isolation_candidate(
        dispatcher_entry=2,
        source_serial=1,
        target_serial=12,
        dispatcher_internal_serials=(2,),
    )
    assert trampoline_candidate is not None
    diagnostic = {
        "dispatcher_entry": 2,
        "source_serial": 6,
        "target_serial": 3,
        "reason": "copied_side_effects_not_dependency_safe",
        "final_bucket": "stack_unique_def_chain_capturable",
        "bucket_reason": "each missing stack use has one reaching definition",
    }
    rows = reclassify_bad_while_loop_follow_ups(
        (
            BadWhileLoopFollowUp(
                dispatcher_entry=2,
                from_serial=5,
                category=BAD_WHILE_LOOP_INSERT_BLOCK,
                reason="copied_side_effects",
                target_serial=3,
            ),
            BadWhileLoopFollowUp(
                dispatcher_entry=2,
                from_serial=1,
                category=BAD_WHILE_LOOP_DUPLICATE_AND_REDIRECT,
                reason="duplicate_group_requires_trampoline",
                target_serial=12,
            ),
            BadWhileLoopFollowUp(
                dispatcher_entry=2,
                from_serial=6,
                category=BAD_WHILE_LOOP_INSERT_BLOCK,
                reason="copied_side_effects_not_dependency_safe",
                target_serial=3,
            ),
            BadWhileLoopFollowUp(
                dispatcher_entry=2,
                from_serial=7,
                category=BAD_WHILE_LOOP_UNSUPPORTED,
                reason="copied_side_effects_contains_call",
                target_serial=3,
            ),
        ),
        None,
        replay_candidates=(replay_candidate,),
        trampoline_isolation_candidates=(trampoline_candidate,),
        dependency_diagnostics=(diagnostic,),
    )

    assert [row.bucket for row in rows] == [
        CleanupFollowUpResolutionBucket.NEEDS_INSERTBLOCK_REPLAY,
        CleanupFollowUpResolutionBucket.NEEDS_TRAMPOLINE_ISOLATION,
        CleanupFollowUpResolutionBucket.NEEDS_DEPENDENCY_RESCUE,
        CleanupFollowUpResolutionBucket.CALL_ANCHOR_REQUIRED,
    ]
    assert rows[0].proof_state is CleanupProofState.PROVEN
    assert rows[1].proof_state is CleanupProofState.PROVEN
    assert rows[2].proof_state is CleanupProofState.UNPROVEN
    assert rows[3].proof_state is CleanupProofState.REJECTED

    serialized = serialize_follow_up_reclassifications(rows)
    cfg = FlowGraph(
        blocks=_conditional_redirect_cfg().blocks,
        entry_serial=0,
        func_ea=0x1000,
        metadata={
            "cleanup_bad_while_loop_follow_up_reclassifications": serialized,
        },
    )
    assert extract_follow_up_reclassifications(cfg) == rows


def test_bad_while_loop_follow_up_reclassifier_uses_modern_target_evidence() -> None:
    class _DagAuthority:
        def canonical_target_for(self, src_block: int, branch_arm: int | None):
            assert (src_block, branch_arm) == (1, None)
            return 12

        def conflicts_for_source(self, src_block: int, branch_arm: int | None):
            assert (src_block, branch_arm) == (1, None)
            return ()

    follow_up = (
        BadWhileLoopFollowUp(
            dispatcher_entry=2,
            from_serial=1,
            category=BAD_WHILE_LOOP_DUPLICATE_AND_REDIRECT,
            reason="unresolved_histories",
            target_serial=12,
        ),
    )

    transition_rows = reclassify_bad_while_loop_follow_ups(
        follow_up,
        _conditional_redirect_cfg(),
        transition_report=SimpleNamespace(
            dispatcher_entry_serial=2,
            handler_state_map={0xAA: 12},
            rows=(
                SimpleNamespace(
                    handler_serial=1,
                    next_state=0xAA,
                    conditional_states=(),
                ),
            ),
        ),
        dag_authority=_DagAuthority(),
    )
    assert transition_rows[0].bucket is (
        CleanupFollowUpResolutionBucket.NOW_RESOLVABLE_REDIRECT
    )
    assert transition_rows[0].proof_sources == ("transition_report",)

    dag_rows = reclassify_bad_while_loop_follow_ups(
        follow_up,
        _conditional_redirect_cfg(),
        dag_authority=_DagAuthority(),
    )
    assert dag_rows[0].bucket is (
        CleanupFollowUpResolutionBucket.NOW_RESOLVABLE_REDIRECT
    )
    assert dag_rows[0].proof_sources == ("semantic_dag",)

    bst_rows = reclassify_bad_while_loop_follow_ups(
        follow_up,
        _conditional_redirect_cfg(),
        bst_intervals=(
            SimpleNamespace(lo=0x100, hi=0x200, target_block=12),
        ),
        state_constants_by_source={1: 0x123},
    )
    assert bst_rows[0].bucket is (
        CleanupFollowUpResolutionBucket.NOW_RESOLVABLE_REDIRECT
    )
    assert bst_rows[0].proof_sources == ("bst_interval_singleton",)


def test_bad_while_loop_follow_up_proof_builder_feeds_reclassifier() -> None:
    class _DagAuthority:
        def canonical_target_for(self, src_block: int, branch_arm: int | None):
            assert (src_block, branch_arm) == (1, None)
            return 12

        def conflicts_for_source(self, src_block: int, branch_arm: int | None):
            assert (src_block, branch_arm) == (1, None)
            return ()

    direct = BadWhileLoopFollowUp(
        dispatcher_entry=2,
        from_serial=1,
        category=BAD_WHILE_LOOP_DUPLICATE_AND_REDIRECT,
        reason="unresolved_histories",
        target_serial=12,
    )
    duplicate = BadWhileLoopFollowUp(
        dispatcher_entry=2,
        from_serial=5,
        category=BAD_WHILE_LOOP_DUPLICATE_AND_REDIRECT,
        reason="duplicate_group_unresolved",
    )

    target_proofs, _unused_per_pred = build_bad_while_loop_follow_up_proofs(
        _conditional_redirect_cfg(),
        (direct,),
        dag_authority=_DagAuthority(),
    )
    _unused_target, per_pred_proofs = build_bad_while_loop_follow_up_proofs(
        _duplicate_cfg(),
        (duplicate,),
        per_pred_targets_by_follow_up={
            (2, 5, "duplicate_group_unresolved"): ((8, 3), (9, 4)),
        },
    )

    assert len(target_proofs) == 1
    assert target_proofs[0].target_serial == 12
    assert target_proofs[0].proof_sources == ("semantic_dag",)
    assert len(per_pred_proofs) == 1
    assert per_pred_proofs[0].per_pred_targets == ((8, 3), (9, 4))

    direct_rows = reclassify_bad_while_loop_follow_ups(
        (direct,),
        _conditional_redirect_cfg(),
        target_proofs=target_proofs,
    )
    duplicate_rows = reclassify_bad_while_loop_follow_ups(
        (duplicate,),
        _duplicate_cfg(),
        per_pred_target_proofs=per_pred_proofs,
    )

    assert direct_rows[0].bucket is (
        CleanupFollowUpResolutionBucket.NOW_RESOLVABLE_REDIRECT
    )
    assert direct_rows[0].proof_sources == ("semantic_dag",)
    assert duplicate_rows[0].bucket is (
        CleanupFollowUpResolutionBucket.NOW_RESOLVABLE_DUPLICATE_AND_REDIRECT
    )
    assert duplicate_rows[0].proof_sources == ("per_pred_target_map",)
