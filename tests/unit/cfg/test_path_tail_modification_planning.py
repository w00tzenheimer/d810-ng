from __future__ import annotations

from d810.cfg.graph_modification import (
    DuplicateAndRedirect,
    EdgeRedirectViaPredSplit,
    RedirectGoto,
)
from d810.cfg.path_tail_modification_planning import (
    PathTailEmissionKind,
    plan_path_tail_emission,
)


class TestPlanPathTailEmission:
    def test_emits_shared_goto_when_shared_handoff_matches(self):
        plan = plan_path_tail_emission(
            source_block=20,
            target_entry=30,
            old_target=6,
            npreds=2,
            shared_handoff_target=30,
            existing_exit_target=None,
            existing_1way_target=None,
            via_pred=10,
            existing_path_edge_target=None,
            via_pred_blocked=False,
            via_pred_terminal_protected=False,
            source_succs=(6,),
            via_pred_succs=(20,),
            source_is_conditional_branch=False,
            source_anchor_block=20,
            source_branch_arm=None,
            other_preds=(11,),
        )

        assert plan.accepted
        assert plan.kind == PathTailEmissionKind.SHARED_GOTO
        assert plan.modification == RedirectGoto(from_serial=20, old_target=6, new_target=30)

    def test_emits_direct_goto_for_single_pred(self):
        plan = plan_path_tail_emission(
            source_block=20,
            target_entry=30,
            old_target=6,
            npreds=1,
            shared_handoff_target=None,
            existing_exit_target=None,
            existing_1way_target=None,
            via_pred=None,
            existing_path_edge_target=None,
            via_pred_blocked=False,
            via_pred_terminal_protected=False,
            source_succs=(6,),
            via_pred_succs=(),
            source_is_conditional_branch=False,
            source_anchor_block=20,
            source_branch_arm=None,
            other_preds=(),
        )

        assert plan.accepted
        assert plan.kind == PathTailEmissionKind.DIRECT_GOTO
        assert plan.modification == RedirectGoto(from_serial=20, old_target=6, new_target=30)

    def test_emits_pred_split_when_pair_is_valid(self):
        plan = plan_path_tail_emission(
            source_block=20,
            target_entry=30,
            old_target=6,
            npreds=2,
            shared_handoff_target=None,
            existing_exit_target=None,
            existing_1way_target=None,
            via_pred=10,
            existing_path_edge_target=None,
            via_pred_blocked=False,
            via_pred_terminal_protected=False,
            source_succs=(6,),
            via_pred_succs=(20,),
            source_is_conditional_branch=False,
            source_anchor_block=20,
            source_branch_arm=None,
            other_preds=(11,),
        )

        assert plan.accepted
        assert plan.kind == PathTailEmissionKind.PRED_SPLIT
        assert plan.modification == EdgeRedirectViaPredSplit(
            src_block=20,
            old_target=6,
            new_target=30,
            via_pred=10,
            rule_priority=550,
        )

    def test_emits_duplicate_when_pred_split_is_not_valid(self):
        plan = plan_path_tail_emission(
            source_block=20,
            target_entry=30,
            old_target=6,
            npreds=2,
            shared_handoff_target=None,
            existing_exit_target=None,
            existing_1way_target=None,
            via_pred=10,
            existing_path_edge_target=None,
            via_pred_blocked=False,
            via_pred_terminal_protected=False,
            source_succs=(6,),
            via_pred_succs=(99, 20),
            source_is_conditional_branch=True,
            source_anchor_block=10,
            source_branch_arm=1,
            other_preds=(11,),
        )

        assert plan.accepted
        assert plan.kind == PathTailEmissionKind.DUPLICATE
        assert plan.modification == DuplicateAndRedirect(
            source_serial=20,
            per_pred_targets=((11, 6), (10, 30)),
        )
