"""Pure tests for neutral cleanup evidence adapters."""
from __future__ import annotations

import pytest

from d810.cfg.flowgraph import BlockSnapshot, FlowGraph, InsnSnapshot, MopSnapshot
from d810.cfg.graph_modification import (
    DuplicateAndRedirect,
    DuplicateReplayAndRedirect,
    DuplicateReplayEntry,
    InsertBlock,
)
from d810.cfg.materialization_payload import (
    CapturedBlockBody,
    CapturedBlockBodySummary,
)
from d810.cfg.plan import (
    PatchDuplicateReplayAndRedirect,
    PatchInsertBlock,
    compile_patch_plan,
)
from d810.optimizers.microcode.flow.flattening.cleanup_evidence import (
    BAD_WHILE_LOOP_SOURCE_RULE,
    CLEANUP_CONDITIONAL_REDIRECT_PROOF_METADATA_KEY,
    CleanupProofVerdict,
    CleanupExitShape,
    CleanupDuplicateGroupReplayCandidate,
    CleanupPerPredReplay,
    CleanupRewriteIntent,
    CleanupSideEffectReplayCandidate,
    DispatcherCleanupCandidate,
    bad_while_loop_duplicate_candidate,
    bad_while_loop_duplicate_group_replay_candidate,
    bad_while_loop_side_effect_replay_candidate,
    build_dispatcher_cleanup_modification,
    explain_bad_while_loop_conditional_redirect,
    extract_conditional_redirect_proofs,
    serialize_conditional_redirect_proofs,
    validate_conditional_duplicate_cleanup_edit,
    validate_conditional_redirect_cleanup_edit,
    validate_duplicate_group_replay_candidate,
    validate_dispatcher_cleanup_candidate,
    validate_side_effect_replay_candidate,
)
from d810.optimizers.microcode.flow.flattening.strategies.bad_while_loop import (
    BadWhileLoopConditionalDuplicate,
    BadWhileLoopConditionalRedirect,
    BadWhileLoopDuplicateRedirect,
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


def test_duplicate_candidate_validates_and_lowers_to_duplicate_and_redirect() -> None:
    edit = BadWhileLoopDuplicateRedirect(
        dispatcher_entry=2,
        source_serial=5,
        per_pred_targets=((8, 3), (9, 4)),
    )
    candidate = bad_while_loop_duplicate_candidate(edit)
    assert candidate is not None

    assert validate_dispatcher_cleanup_candidate(_duplicate_cfg(), candidate) is True
    assert build_dispatcher_cleanup_modification(candidate) == DuplicateAndRedirect(
        source_serial=5,
        per_pred_targets=((8, 3), (9, 4)),
    )


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
