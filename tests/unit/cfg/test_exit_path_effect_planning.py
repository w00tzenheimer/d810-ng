from __future__ import annotations

from types import SimpleNamespace

from d810.analyses.control_flow.terminal_frontier import TerminalLoweringAction
from d810.transforms.exit_path_effect_planning import (
    CarrierBucket,
    compute_suffix_group_decision,
    select_direct_terminal_lowering_anchors,
)


def _entry(
    handler_entry: int,
    carrier_kind: str,
    *,
    proof_status: str = "unresolved",
    requires_dtl: bool = False,
):
    return SimpleNamespace(
        handler_entry=handler_entry,
        carrier_source_kind=SimpleNamespace(value=carrier_kind),
        proof_status=proof_status,
        requires_dtl=requires_dtl,
    )


def _exit_path_info(*, clonable: bool = True):
    return SimpleNamespace(
        shared_entry=20,
        return_block=30,
        suffix_serials=(31, 30),
        exit_path_length=2,
        clonable=clonable,
    )


def test_suffix_group_decision_emits_for_suffix_ambiguous_group():
    decision = compute_suffix_group_decision(
        forward_entries=(
            _entry(10, "expr"),
            _entry(11, "cursor_or_ptr"),
        ),
        exit_path_info=_exit_path_info(),
        semantic_action=TerminalLoweringAction.PRIVATE_TERMINAL_SUFFIX,
    )

    assert decision.carrier_bucket == CarrierBucket.SUFFIX_AMBIGUOUS
    assert decision.should_emit is True
    assert decision.rejection_reasons == ()


def test_suffix_group_decision_marks_state_const_groups_for_dtl():
    decision = compute_suffix_group_decision(
        forward_entries=(
            _entry(10, "state_const", requires_dtl=True),
            _entry(11, "expr"),
        ),
        exit_path_info=_exit_path_info(),
        semantic_action=TerminalLoweringAction.PRIVATE_TERMINAL_SUFFIX,
    )

    assert decision.carrier_bucket == CarrierBucket.NEEDS_DIRECT_LOWERING
    assert decision.should_emit is False
    assert decision.dtl_anchor_serials == (10,)
    assert select_direct_terminal_lowering_anchors(
        decision=decision,
        anchors=(10, 11),
    ) == (10, 11)
