"""Pure tests for neutral cleanup evidence adapters."""
from __future__ import annotations

import pytest

from d810.cfg.flowgraph import BlockSnapshot, FlowGraph, InsnSnapshot
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
    validate_duplicate_group_replay_candidate,
    validate_dispatcher_cleanup_candidate,
    validate_side_effect_replay_candidate,
)
from d810.optimizers.microcode.flow.flattening.strategies.bad_while_loop import (
    BadWhileLoopConditionalRedirect,
    BadWhileLoopDuplicateRedirect,
)


def _block(
    serial: int,
    succs: tuple[int, ...],
    preds: tuple[int, ...],
    *,
    block_type: int = 1,
) -> BlockSnapshot:
    return BlockSnapshot(
        serial=serial,
        block_type=block_type,
        succs=succs,
        preds=preds,
        flags=0,
        start_ea=serial,
        insn_snapshots=(),
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
