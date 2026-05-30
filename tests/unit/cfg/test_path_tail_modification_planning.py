from __future__ import annotations

from d810.transforms.graph_modification import (
    EdgeRedirectViaPredSplit,
    RedirectGoto,
)
from d810.transforms.path_tail_modification_planning import (
    LoopBoundWriterDiagnostic,
    PathTailEmissionKind,
    PathTailRedirectContext,
    apply_path_tail_emission_plan,
    plan_path_tail_emission,
    plan_path_tail_redirect,
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

    def test_rejects_clone_only_tail_when_pred_split_is_not_valid(self):
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

        assert not plan.accepted
        assert plan.rejection_reason == "path_tail_clone_safety_gap"


class TestPlanPathTailRedirect:
    def test_rejects_foreign_exact_entry_owner(self):
        decision = plan_path_tail_redirect(
            PathTailRedirectContext(
                source_block=20,
                target_entry=30,
                source_handler_is_report_exit=False,
                ordered_path_head_is_report_exit=False,
                source_in_report_exit_owned=False,
                source_blocked=False,
                source_terminal_protected=False,
                foreign_exact_owner_label="0xDEADBEEF",
                backward_same_corridor=False,
                allow_semantic_handoff=False,
                target_reaches_source=False,
                source_nsucc=1,
                source_npred=1,
                source_succs=(6,),
                source_preds=(10,),
                old_target=6,
                emitted_already=False,
                shared_handoff_target=None,
                via_pred=None,
                via_pred_succs=(),
                existing_exit_target=None,
                existing_1way_target=None,
                existing_path_edge_target=None,
                via_pred_blocked=False,
                via_pred_terminal_protected=False,
                source_is_conditional_branch=False,
                source_anchor_block=20,
                source_branch_arm=None,
                other_preds=(),
            )
        )

        assert not decision.accepted
        assert decision.rejection_reason == "foreign_exact_entry_owner"

    def test_wraps_direct_goto_plan(self):
        decision = plan_path_tail_redirect(
            PathTailRedirectContext(
                source_block=20,
                target_entry=30,
                source_handler_is_report_exit=False,
                ordered_path_head_is_report_exit=False,
                source_in_report_exit_owned=False,
                source_blocked=False,
                source_terminal_protected=False,
                foreign_exact_owner_label=None,
                backward_same_corridor=False,
                allow_semantic_handoff=False,
                target_reaches_source=False,
                source_nsucc=1,
                source_npred=1,
                source_succs=(6,),
                source_preds=(10,),
                old_target=6,
                emitted_already=False,
                shared_handoff_target=None,
                via_pred=None,
                via_pred_succs=(),
                existing_exit_target=None,
                existing_1way_target=None,
                existing_path_edge_target=None,
                via_pred_blocked=False,
                via_pred_terminal_protected=False,
                source_is_conditional_branch=False,
                source_anchor_block=20,
                source_branch_arm=None,
                other_preds=(),
            )
        )

        assert decision.accepted
        assert decision.emission_plan is not None
        assert decision.emission_plan.kind == PathTailEmissionKind.DIRECT_GOTO


class TestApplyPathTailEmissionPlan:
    def test_does_not_apply_rejected_clone_only_tail(self):
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

        assert not plan.accepted
        assert plan.modification is None
        assert plan.rejection_reason == "path_tail_clone_safety_gap"


class TestLoopBoundWriterGuard:
    def test_rejects_when_diagnostic_present(self):
        decision = plan_path_tail_redirect(
            PathTailRedirectContext(
                source_block=183,
                target_entry=224,
                source_handler_is_report_exit=False,
                ordered_path_head_is_report_exit=False,
                source_in_report_exit_owned=False,
                source_blocked=False,
                source_terminal_protected=False,
                foreign_exact_owner_label=None,
                backward_same_corridor=False,
                allow_semantic_handoff=False,
                target_reaches_source=False,
                source_nsucc=1,
                source_npred=1,
                source_succs=(184,),
                source_preds=(181,),
                old_target=184,
                emitted_already=False,
                shared_handoff_target=None,
                via_pred=None,
                via_pred_succs=(),
                existing_exit_target=None,
                existing_1way_target=None,
                existing_path_edge_target=None,
                via_pred_blocked=False,
                via_pred_terminal_protected=False,
                source_is_conditional_branch=False,
                source_anchor_block=183,
                source_branch_arm=None,
                other_preds=(),
                loop_bound_writer_diag=LoopBoundWriterDiagnostic(
                    bound_stkoff=0x388,
                    bound_writer_ea=0x180015EDC,
                    loop_test_ea=0x180013B0E,
                    counter_stkoff=0x508,
                ),
            )
        )

        assert not decision.accepted
        assert decision.rejection_reason == "loop_bound_writer_guard"
        assert decision.emission_plan is None

    def test_accepts_when_diagnostic_absent(self):
        decision = plan_path_tail_redirect(
            PathTailRedirectContext(
                source_block=20,
                target_entry=30,
                source_handler_is_report_exit=False,
                ordered_path_head_is_report_exit=False,
                source_in_report_exit_owned=False,
                source_blocked=False,
                source_terminal_protected=False,
                foreign_exact_owner_label=None,
                backward_same_corridor=False,
                allow_semantic_handoff=False,
                target_reaches_source=False,
                source_nsucc=1,
                source_npred=1,
                source_succs=(6,),
                source_preds=(10,),
                old_target=6,
                emitted_already=False,
                shared_handoff_target=None,
                via_pred=None,
                via_pred_succs=(),
                existing_exit_target=None,
                existing_1way_target=None,
                existing_path_edge_target=None,
                via_pred_blocked=False,
                via_pred_terminal_protected=False,
                source_is_conditional_branch=False,
                source_anchor_block=20,
                source_branch_arm=None,
                other_preds=(),
            )
        )

        assert decision.accepted
        assert decision.rejection_reason == ""
        assert decision.emission_plan is not None
        assert decision.emission_plan.kind == PathTailEmissionKind.DIRECT_GOTO
