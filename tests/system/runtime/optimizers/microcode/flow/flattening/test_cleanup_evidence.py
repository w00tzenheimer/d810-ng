"""Pure tests for neutral cleanup evidence adapters."""
from __future__ import annotations

import pytest

from d810.cfg.flowgraph import BlockSnapshot, FlowGraph
from d810.cfg.graph_modification import DuplicateAndRedirect
from d810.optimizers.microcode.flow.flattening.cleanup_evidence import (
    BAD_WHILE_LOOP_SOURCE_RULE,
    CleanupExitShape,
    CleanupRewriteIntent,
    DispatcherCleanupCandidate,
    bad_while_loop_duplicate_candidate,
    build_dispatcher_cleanup_modification,
    validate_dispatcher_cleanup_candidate,
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
