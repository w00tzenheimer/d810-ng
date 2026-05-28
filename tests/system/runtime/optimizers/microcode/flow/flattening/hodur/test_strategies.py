"""Unit tests for Hodur strategy classes."""
from __future__ import annotations
from types import SimpleNamespace

import ida_hexrays
import pytest

from d810.cfg.flowgraph import (
    BlockSnapshot,
    FlowGraph,
    InsnKind,
    InsnSnapshot,
    MopSnapshot,
    OperandKind,
)
from d810.cfg.graph_modification import (
    EdgeRedirectViaPredSplit,
    NopInstructions,
    PrivateTerminalSuffix,
    PrivateTerminalSuffixGroup,
    RedirectBranch,
    RedirectGoto,
)
from d810.cfg.linearized_flow_graph_fragment_planning import (
    is_original_pre_header_candidate,
)
from d810.optimizers.microcode.flow.flattening.hodur.datamodel import (
    DispatcherStateMachine,
    StateHandler,
    StateTransition,
)
from d810.cfg.modification_builder import (
    ModificationBuilder,
)
import d810.optimizers.microcode.flow.flattening.hodur.strategies.linearized_flow_graph as lfg_module
from d810.optimizers.microcode.flow.flattening.hodur.strategies.linearized_flow_graph import (
    LinearizedFlowGraphStrategy,
    SemanticStructuredRegionStrategy,
)
import d810.optimizers.microcode.flow.flattening.hodur.strategies.reconstruction as reconstruction_module
from d810.optimizers.microcode.flow.flattening.hodur.strategies.reconstruction import (
    StateWriteReconstructionStrategy,
)
from d810.optimizers.microcode.flow.flattening.engine.strategy import (
    FAMILY_CLEANUP,
    FAMILY_DIRECT,
    FAMILY_FALLBACK,
    BenefitMetrics,
    OwnershipScope,
    PlanFragment,
    UnflatteningStrategy,
)
from d810.optimizers.microcode.flow.flattening.hodur.strategies import (
    ALL_STRATEGIES,
    ConditionalForkFallbackStrategy,
    EdgeSplitConflictResolutionStrategy,
    TerminalLoopCleanupStrategy,
)
from d810.optimizers.microcode.flow.flattening.hodur.profile import (
    default_hodur_profile,
)
from d810.optimizers.microcode.flow.flattening.engine.snapshot import AnalysisSnapshot
from d810.recon.flow.linearized_state_dag import (
    LinearizedStateDag,
    LocalSegmentKind,
    SemanticEdgeKind,
    StateDagEdge,
    StateDagNode,
    StateDagNodeKey,
    StateLocalEdge,
    StateLocalSegment,
    StateNodeKind,
    StateRedirectAnchor,
    RedirectSourceKind,
)
from d810.recon.flow.reconstruction_candidate_builder import ReconstructionCandidate
from d810.recon.flow.state_machine_analysis import build_mba_view_from_flow_graph
from d810.recon.flow.state_machine_analysis import (
    find_last_state_write_site_on_path_snapshot,
    find_last_state_write_site_snapshot,
    run_snapshot_constant_fixpoint,
)


# ---------------------------------------------------------------------------
# Protocol compliance
# ---------------------------------------------------------------------------


def test_all_strategies_implement_protocol():
    """Every class in ALL_STRATEGIES must satisfy the UnflatteningStrategy Protocol."""
    for cls in ALL_STRATEGIES:
        instance = cls()
        assert isinstance(instance, UnflatteningStrategy), (
            f"{cls.__name__} does not satisfy UnflatteningStrategy protocol"
        )
        assert hasattr(instance, "name"), f"{cls.__name__} missing 'name'"
        assert hasattr(instance, "family"), f"{cls.__name__} missing 'family'"
        assert hasattr(instance, "is_applicable"), f"{cls.__name__} missing 'is_applicable'"
        assert hasattr(instance, "plan"), f"{cls.__name__} missing 'plan'"


def test_strategy_names_unique():
    """Each strategy must have a unique name string."""
    names = [cls().name for cls in ALL_STRATEGIES]
    assert len(names) == len(set(names)), f"Duplicate strategy names: {names}"


def test_strategy_count():
    """Worktree ALL_STRATEGIES uses HCC-owned reconstruction, not standalone SRW."""
    names = {cls().name for cls in ALL_STRATEGIES}
    assert "semantic_structured_region" not in names
    assert "handler_chain_composer" in names
    assert "state_write_reconstruction" not in names
    assert "dispatcher_trampoline_skip" in names
    assert "counter_hoist" in names
    assert "return_frontier_carrier_preserve" in names
    assert "state_constant_return_fixup" in names
    assert "dead_state_variable_elimination" in names
    assert "linearized_flow_graph" not in names


def test_hodur_profile_owns_default_strategy_order():
    """The Hodur profile, not strategies/__init__.py, owns live ordering."""
    profile = default_hodur_profile()
    strategy_names = [cls().name for cls in profile.strategy_classes]
    entrypoint_names = [cls().name for cls in profile.entrypoint_strategy_classes]

    def _before(names: list[str], first: str, second: str) -> bool:
        return names.index(first) < names.index(second)

    assert ALL_STRATEGIES == list(profile.strategy_classes)
    assert "handler_chain_composer" in strategy_names
    assert "state_constant_return_fixup" in strategy_names
    assert "dead_state_variable_elimination" in strategy_names
    assert _before(strategy_names, "handler_chain_composer", "state_constant_return_fixup")
    assert _before(strategy_names, "state_constant_return_fixup", "dead_state_variable_elimination")
    assert "spurious_backedge_redirect" in entrypoint_names
    assert "spurious_backedge_redirect" not in strategy_names
    assert profile.detector == "hodur_state_machine"
    assert profile.executor_safeguard_profile == "hodur"
    assert profile.uses_evidence_adapter("transition_report_store")
    assert profile.uses_evidence_adapter("return_frontier_audit_store")
    assert profile.uses_evidence_adapter("terminal_return_audit_store")
    assert profile.uses_evidence_adapter("induction_fact_view")
    assert profile.enables_audit_hook("return_frontier_pre_plan")
    assert profile.enables_audit_hook("return_frontier_post_plan")
    assert profile.enables_audit_hook("return_frontier_post_apply")
    assert profile.enables_audit_hook("return_frontier_post_pipeline")
    assert profile.enables_audit_hook("terminal_return_persistence")
    assert profile.enables_post_apply_hook("bst_cleanup")
    assert profile.enables_post_apply_hook("pipeline_summary")
    assert profile.enables_post_apply_hook("post_pipeline_audit")
    assert profile.enables_post_apply_hook("post_pipeline_diagnostic_snapshot")
    assert profile.enables_post_apply_hook("bst_cleanup_reiteration_suppression")
    assert profile.enables_post_apply_hook("tag_all_mbl_keep")
    assert profile.enables_post_apply_hook("tail_shaping")


def test_semantic_structured_region_collapses_same_target_conditional_candidates():
    source_key = StateDagNodeKey(handler_serial=98, state_const=0x37B42A40)
    target_key = StateDagNodeKey(handler_serial=21, state_const=0x63D54755)
    site = SimpleNamespace(block_serial=98, state_value=0x63D54755, insn_ea=0, unsafe_trailing_insn_eas=())
    edge_taken = StateDagEdge(
        kind=SemanticEdgeKind.CONDITIONAL_TRANSITION,
        source_key=source_key,
        target_key=target_key,
        target_state=0x63D54755,
        target_entry_anchor=21,
        target_label="0x63D54755",
        source_anchor=StateRedirectAnchor(
            kind=RedirectSourceKind.CONDITIONAL_BRANCH,
            block_serial=98,
            branch_arm=1,
        ),
        ordered_path=(98, 100),
    )
    edge_fallthrough = StateDagEdge(
        kind=SemanticEdgeKind.CONDITIONAL_TRANSITION,
        source_key=source_key,
        target_key=target_key,
        target_state=0x63D54755,
        target_entry_anchor=21,
        target_label="0x63D54755",
        source_anchor=StateRedirectAnchor(
            kind=RedirectSourceKind.CONDITIONAL_BRANCH,
            block_serial=98,
            branch_arm=0,
        ),
        ordered_path=(98, 99, 100),
    )
    taken_candidate = ReconstructionCandidate(
        edge=edge_taken,
        horizon_block=98,
        site=site,
        target_entry=21,
        first_shared_block=None,
        via_pred=None,
        emission_mode="conditional_arm",
    )
    fallthrough_candidate = ReconstructionCandidate(
        edge=edge_fallthrough,
        horizon_block=98,
        site=site,
        target_entry=21,
        first_shared_block=None,
        via_pred=None,
        emission_mode="conditional_arm",
    )

    normalized, collapsed = lfg_module.canonicalize_same_target_conditional_candidates(
        [taken_candidate, fallthrough_candidate]
    )

    assert collapsed == 1
    assert len(normalized) == 1
    assert normalized[0].emission_mode == "direct"
    assert normalized[0].target_entry == 21


def test_reconstruction_collapses_same_target_conditional_candidates():
    source_key = StateDagNodeKey(handler_serial=98, state_const=0x37B42A40)
    target_key = StateDagNodeKey(handler_serial=21, state_const=0x63D54755)
    site = SimpleNamespace(
        block_serial=98,
        state_value=0x63D54755,
        insn_ea=0,
        unsafe_trailing_insn_eas=(),
    )
    edge_taken = StateDagEdge(
        kind=SemanticEdgeKind.CONDITIONAL_TRANSITION,
        source_key=source_key,
        target_key=target_key,
        target_state=0x63D54755,
        target_entry_anchor=21,
        target_label="0x63D54755",
        source_anchor=StateRedirectAnchor(
            kind=RedirectSourceKind.CONDITIONAL_BRANCH,
            block_serial=98,
            branch_arm=1,
        ),
        ordered_path=(98, 100),
    )
    edge_fallthrough = StateDagEdge(
        kind=SemanticEdgeKind.CONDITIONAL_TRANSITION,
        source_key=source_key,
        target_key=target_key,
        target_state=0x63D54755,
        target_entry_anchor=21,
        target_label="0x63D54755",
        source_anchor=StateRedirectAnchor(
            kind=RedirectSourceKind.CONDITIONAL_BRANCH,
            block_serial=98,
            branch_arm=0,
        ),
        ordered_path=(98, 99, 100),
    )

    normalized, collapsed = reconstruction_module.canonicalize_same_target_conditional_candidates(
        [
            ReconstructionCandidate(
                edge=edge_taken,
                horizon_block=98,
                site=site,
                target_entry=21,
                first_shared_block=None,
                via_pred=None,
                emission_mode="conditional_arm",
            ),
            ReconstructionCandidate(
                edge=edge_fallthrough,
                horizon_block=98,
                site=site,
                target_entry=21,
                first_shared_block=None,
                via_pred=None,
                emission_mode="conditional_arm",
            ),
        ]
    )

    assert collapsed == 1
    assert len(normalized) == 1
    assert normalized[0].emission_mode == "direct"
    assert normalized[0].target_entry == 21


def test_reconstruction_fragment_blocks_bst_cleanup_when_structured_leaks_exist():
    fragment = reconstruction_module.finalize_reconstruction_fragment(
        strategy_name="state_write_reconstruction",
        modifications=[],
        owned_blocks={16, 68},
        owned_edges={(16, 68)},
        accepted_metadata=[],
        rejected_metadata=[],
        allow_post_apply_bst_cleanup=True,
        post_apply_bst_cleanup_reason=None,
        residual_dispatcher_preds=(),
        structured_region_fidelity={
            "leaked_units": (("sub7ffd_10743c4c_branch_region:post_exit_frontier", 1),),
            "late_rewrite_entries": (
                {
                    "planner": "bridge",
                    "source_block": 69,
                    "target_block": 163,
                    "semantic_status": "structured_leakage",
                },
            ),
        },
    )

    assert fragment.metadata["allow_post_apply_bst_cleanup"] is False
    assert (
        fragment.metadata["post_apply_bst_cleanup_reason"]
        == "structured_region_leakage"
    )


# ---------------------------------------------------------------------------
# Name and family properties
# ---------------------------------------------------------------------------


class TestStrategyProperties:
    """Verify name and family for each strategy."""

    def test_edge_split_name(self):
        s = EdgeSplitConflictResolutionStrategy()
        assert s.name == "edge_split_conflict_resolution"

    def test_edge_split_family(self):
        s = EdgeSplitConflictResolutionStrategy()
        assert s.family == FAMILY_DIRECT

    def test_terminal_loop_cleanup_name(self):
        s = TerminalLoopCleanupStrategy()
        assert s.name == "terminal_loop_cleanup"

    def test_terminal_loop_cleanup_family(self):
        s = TerminalLoopCleanupStrategy()
        assert s.family == FAMILY_CLEANUP

    def test_conditional_fork_fallback_name(self):
        s = ConditionalForkFallbackStrategy()
        assert s.name == "conditional_fork_fallback"

    def test_conditional_fork_fallback_family(self):
        s = ConditionalForkFallbackStrategy()
        assert s.family == FAMILY_FALLBACK

    def test_state_write_reconstruction_name(self):
        s = StateWriteReconstructionStrategy()
        assert s.name == "state_write_reconstruction"

    def test_state_write_reconstruction_family(self):
        s = StateWriteReconstructionStrategy()
        assert s.family == FAMILY_DIRECT


# ---------------------------------------------------------------------------
# is_applicable with empty snapshot
# ---------------------------------------------------------------------------


def _empty_snapshot(**kwargs) -> AnalysisSnapshot:
    """Build an AnalysisSnapshot with all fields at their defaults."""
    return AnalysisSnapshot(
        mba=None,
        state_machine=None,
        detector=None,
        **kwargs,
    )


class TestIsApplicableEmptySnapshot:
    """All strategies should return False on a completely empty snapshot."""

    def test_edge_split_not_applicable(self):
        s = EdgeSplitConflictResolutionStrategy()
        assert not s.is_applicable(_empty_snapshot())


def test_find_last_state_write_site_snapshot_tracks_trailing_goto():
    mov = int(ida_hexrays.m_mov)
    goto = int(ida_hexrays.m_goto)
    mop_n = int(ida_hexrays.mop_n)
    mop_S = int(ida_hexrays.mop_S)
    state_var = MopSnapshot(t=mop_S, size=4, stkoff=0x3C)
    constant = MopSnapshot(t=mop_n, size=4, value=0x12345678)
    goto_target = MopSnapshot(t=int(ida_hexrays.mop_b), size=4, block_ref=2)

    block = BlockSnapshot(
        serial=10,
        block_type=int(ida_hexrays.BLT_1WAY),
        succs=(2,),
        preds=(),
        flags=0,
        start_ea=0x1000,
        insn_snapshots=(
            InsnSnapshot(opcode=mov, ea=0x1000, operands=(), l=constant, d=state_var),
            InsnSnapshot(opcode=goto, ea=0x1004, operands=(), l=goto_target),
        ),
    )
    flow_graph = FlowGraph(
        blocks={
            2: BlockSnapshot(
                serial=2,
                block_type=int(ida_hexrays.BLT_2WAY),
                succs=(3, 4),
                preds=(10,),
                flags=0,
                start_ea=0x2000,
                insn_snapshots=(),
            ),
            10: block,
        },
        entry_serial=10,
        func_ea=0x1000,
    )

    site = find_last_state_write_site_snapshot(flow_graph, 10, 0x3C)
    assert site is not None
    assert site.state_value == 0x12345678
    assert site.insn_ea == 0x1000
    assert site.trailing_insn_eas == (0x1004,)
    assert site.trailing_opcodes == (goto,)


def test_snapshot_constant_fixpoint_seeds_formula_state_write_site():
    mov = int(ida_hexrays.m_mov)
    xor = int(ida_hexrays.m_xor)
    goto = int(ida_hexrays.m_goto)
    mop_n = int(ida_hexrays.mop_n)
    mop_S = int(ida_hexrays.mop_S)
    mop_b = int(ida_hexrays.mop_b)

    flow_graph = FlowGraph(
        blocks={
            2: BlockSnapshot(
                serial=2,
                block_type=int(ida_hexrays.BLT_2WAY),
                succs=(3, 4),
                preds=(10,),
                flags=0,
                start_ea=0x2000,
                insn_snapshots=(),
            ),
            9: BlockSnapshot(
                serial=9,
                block_type=int(ida_hexrays.BLT_1WAY),
                succs=(10,),
                preds=(),
                flags=0,
                start_ea=0x0FF0,
                insn_snapshots=(
                    InsnSnapshot(
                        opcode=mov,
                        ea=0x0FF0,
                        operands=(),
                        l=MopSnapshot(t=mop_n, size=4, value=0xAAAA0000),
                        d=MopSnapshot(t=mop_S, size=4, stkoff=0x60),
                    ),
                    InsnSnapshot(
                        opcode=mov,
                        ea=0x0FF4,
                        operands=(),
                        l=MopSnapshot(t=mop_n, size=4, value=0xBBBB1111),
                        d=MopSnapshot(t=mop_S, size=4, stkoff=0x68),
                    ),
                    InsnSnapshot(
                        opcode=goto,
                        ea=0x0FF8,
                        operands=(),
                        l=MopSnapshot(t=mop_b, size=4, block_ref=10),
                    ),
                ),
            ),
            10: BlockSnapshot(
                serial=10,
                block_type=int(ida_hexrays.BLT_1WAY),
                succs=(2,),
                preds=(9,),
                flags=0,
                start_ea=0x1000,
                insn_snapshots=(
                    InsnSnapshot(
                        opcode=xor,
                        ea=0x1000,
                        operands=(),
                        l=MopSnapshot(t=mop_S, size=4, stkoff=0x68),
                        r=MopSnapshot(t=mop_S, size=4, stkoff=0x60),
                        d=MopSnapshot(t=mop_S, size=4, stkoff=0x3C),
                    ),
                    InsnSnapshot(
                        opcode=goto,
                        ea=0x1004,
                        operands=(),
                        l=MopSnapshot(t=mop_b, size=4, block_ref=2),
                    ),
                ),
            ),
        },
        entry_serial=9,
        func_ea=0x0FF0,
    )

    consts = run_snapshot_constant_fixpoint(flow_graph, 0x3C)
    assert consts.in_stk_maps[10][0x60] == 0xAAAA0000
    assert consts.in_stk_maps[10][0x68] == 0xBBBB1111

    site = find_last_state_write_site_snapshot(
        flow_graph,
        10,
        0x3C,
        initial_stk_map=consts.in_stk_maps[10],
        initial_reg_map=consts.in_reg_maps[10],
    )
    assert site is not None
    assert site.state_value == ((0xAAAA0000 ^ 0xBBBB1111) & 0xFFFFFFFF)
    assert site.insn_ea == 0x1000
    assert site.trailing_insn_eas == (0x1004,)


def test_find_last_state_write_site_snapshot_on_path_preserves_path_local_merge_constants():
    mov = int(ida_hexrays.m_mov)
    xor = int(ida_hexrays.m_xor)
    goto = int(ida_hexrays.m_goto)
    mop_n = int(ida_hexrays.mop_n)
    mop_S = int(ida_hexrays.mop_S)
    mop_b = int(ida_hexrays.mop_b)
    expected_state = (0xAAAA0000 ^ 0xBBBB1111) & 0xFFFFFFFF

    flow_graph = FlowGraph(
        blocks={
            2: BlockSnapshot(
                serial=2,
                block_type=int(ida_hexrays.BLT_2WAY),
                succs=(3, 4),
                preds=(10,),
                flags=0,
                start_ea=0x2000,
                insn_snapshots=(),
            ),
            9: BlockSnapshot(
                serial=9,
                block_type=int(ida_hexrays.BLT_1WAY),
                succs=(10,),
                preds=(),
                flags=0,
                start_ea=0x0FF0,
                insn_snapshots=(
                    InsnSnapshot(
                        opcode=mov,
                        ea=0x0FF0,
                        operands=(),
                        l=MopSnapshot(t=mop_n, size=4, value=0xAAAA0000),
                        d=MopSnapshot(t=mop_S, size=4, stkoff=0x60),
                    ),
                    InsnSnapshot(
                        opcode=mov,
                        ea=0x0FF4,
                        operands=(),
                        l=MopSnapshot(t=mop_n, size=4, value=0xBBBB1111),
                        d=MopSnapshot(t=mop_S, size=4, stkoff=0x68),
                    ),
                    InsnSnapshot(
                        opcode=goto,
                        ea=0x0FF8,
                        operands=(),
                        l=MopSnapshot(t=mop_b, size=4, block_ref=10),
                    ),
                ),
            ),
            10: BlockSnapshot(
                serial=10,
                block_type=int(ida_hexrays.BLT_1WAY),
                succs=(2,),
                preds=(9, 11),
                flags=0,
                start_ea=0x1000,
                insn_snapshots=(
                    InsnSnapshot(
                        opcode=xor,
                        ea=0x1000,
                        operands=(),
                        l=MopSnapshot(t=mop_S, size=4, stkoff=0x68),
                        r=MopSnapshot(t=mop_S, size=4, stkoff=0x60),
                        d=MopSnapshot(t=mop_S, size=4, stkoff=0x3C),
                    ),
                    InsnSnapshot(
                        opcode=goto,
                        ea=0x1004,
                        operands=(),
                        l=MopSnapshot(t=mop_b, size=4, block_ref=2),
                    ),
                ),
            ),
            11: BlockSnapshot(
                serial=11,
                block_type=int(ida_hexrays.BLT_1WAY),
                succs=(10,),
                preds=(),
                flags=0,
                start_ea=0x1010,
                insn_snapshots=(
                    InsnSnapshot(
                        opcode=goto,
                        ea=0x1010,
                        operands=(),
                        l=MopSnapshot(t=mop_b, size=4, block_ref=10),
                    ),
                ),
            ),
        },
        entry_serial=9,
        func_ea=0x0FF0,
    )

    consts = run_snapshot_constant_fixpoint(flow_graph, 0x3C)
    assert consts.in_stk_maps[10] == {}

    resolved = find_last_state_write_site_on_path_snapshot(
        flow_graph,
        (9, 10),
        0x3C,
        in_stk_maps=consts.in_stk_maps,
        in_reg_maps=consts.in_reg_maps,
    )

    assert resolved is not None
    block_serial, site = resolved
    assert block_serial == 10
    assert site.state_value == expected_state
    assert site.truncation_insn_eas == (0x1000, 0x1004)


def test_find_last_state_write_site_snapshot_on_path_stops_before_shared_tail_glue():
    mov = int(ida_hexrays.m_mov)
    xor = int(ida_hexrays.m_xor)
    goto = int(ida_hexrays.m_goto)
    mop_n = int(ida_hexrays.mop_n)
    mop_S = int(ida_hexrays.mop_S)
    mop_b = int(ida_hexrays.mop_b)
    expected_state = (0xAAAA0000 ^ 0xBBBB1111) & 0xFFFFFFFF

    flow_graph = FlowGraph(
        blocks={
            2: BlockSnapshot(
                serial=2,
                block_type=int(ida_hexrays.BLT_2WAY),
                succs=(3, 4),
                preds=(12,),
                flags=0,
                start_ea=0x2000,
                insn_snapshots=(),
            ),
            9: BlockSnapshot(
                serial=9,
                block_type=int(ida_hexrays.BLT_1WAY),
                succs=(10,),
                preds=(),
                flags=0,
                start_ea=0x0FF0,
                insn_snapshots=(
                    InsnSnapshot(
                        opcode=mov,
                        ea=0x0FF0,
                        operands=(),
                        l=MopSnapshot(t=mop_n, size=4, value=0xAAAA0000),
                        d=MopSnapshot(t=mop_S, size=4, stkoff=0x60),
                    ),
                    InsnSnapshot(
                        opcode=mov,
                        ea=0x0FF4,
                        operands=(),
                        l=MopSnapshot(t=mop_n, size=4, value=0xBBBB1111),
                        d=MopSnapshot(t=mop_S, size=4, stkoff=0x68),
                    ),
                ),
            ),
            10: BlockSnapshot(
                serial=10,
                block_type=int(ida_hexrays.BLT_1WAY),
                succs=(12,),
                preds=(9,),
                flags=0,
                start_ea=0x1000,
                insn_snapshots=(
                    InsnSnapshot(
                        opcode=xor,
                        ea=0x1000,
                        operands=(),
                        l=MopSnapshot(t=mop_S, size=4, stkoff=0x68),
                        r=MopSnapshot(t=mop_S, size=4, stkoff=0x60),
                        d=MopSnapshot(t=mop_S, size=4, stkoff=0x3C),
                    ),
                    InsnSnapshot(
                        opcode=goto,
                        ea=0x1004,
                        operands=(),
                        l=MopSnapshot(t=mop_b, size=4, block_ref=12),
                    ),
                ),
            ),
            12: BlockSnapshot(
                serial=12,
                block_type=int(ida_hexrays.BLT_1WAY),
                succs=(2,),
                preds=(10, 13),
                flags=0,
                start_ea=0x1010,
                insn_snapshots=(
                    InsnSnapshot(
                        opcode=goto,
                        ea=0x1010,
                        operands=(),
                        l=MopSnapshot(t=mop_b, size=4, block_ref=2),
                    ),
                ),
            ),
            13: BlockSnapshot(
                serial=13,
                block_type=int(ida_hexrays.BLT_1WAY),
                succs=(12,),
                preds=(),
                flags=0,
                start_ea=0x1018,
                insn_snapshots=(),
            ),
        },
        entry_serial=9,
        func_ea=0x0FF0,
    )

    consts = run_snapshot_constant_fixpoint(flow_graph, 0x3C)
    resolved = find_last_state_write_site_on_path_snapshot(
        flow_graph,
        (9, 10, 12),
        0x3C,
        in_stk_maps=consts.in_stk_maps,
        in_reg_maps=consts.in_reg_maps,
    )

    assert resolved is not None
    block_serial, site = resolved
    assert block_serial == 10
    assert site.state_value == expected_state


def test_find_last_state_write_site_snapshot_marks_unsafe_truncation_glue():
    mov = int(ida_hexrays.m_mov)
    goto = int(ida_hexrays.m_goto)
    mop_n = int(ida_hexrays.mop_n)
    mop_S = int(ida_hexrays.mop_S)
    mop_b = int(ida_hexrays.mop_b)

    flow_graph = FlowGraph(
        blocks={
            2: BlockSnapshot(
                serial=2,
                block_type=int(ida_hexrays.BLT_2WAY),
                succs=(3, 4),
                preds=(10,),
                flags=0,
                start_ea=0x2000,
                insn_snapshots=(),
            ),
            10: BlockSnapshot(
                serial=10,
                block_type=int(ida_hexrays.BLT_1WAY),
                succs=(2,),
                preds=(),
                flags=0,
                start_ea=0x1000,
                insn_snapshots=(
                    InsnSnapshot(
                        opcode=mov,
                        ea=0x1000,
                        operands=(),
                        l=MopSnapshot(t=mop_n, size=4, value=0x12345678),
                        d=MopSnapshot(t=mop_S, size=4, stkoff=0x3C),
                    ),
                    InsnSnapshot(
                        opcode=mov,
                        ea=0x1004,
                        operands=(),
                        l=MopSnapshot(t=mop_n, size=4, value=7),
                        d=MopSnapshot(t=mop_S, size=4, stkoff=0x60),
                    ),
                    InsnSnapshot(
                        opcode=goto,
                        ea=0x1008,
                        operands=(),
                        l=MopSnapshot(t=mop_b, size=4, block_ref=2),
                    ),
                ),
            ),
        },
        entry_serial=10,
        func_ea=0x1000,
    )

    resolved = find_last_state_write_site_on_path_snapshot(
        flow_graph,
        (10,),
        0x3C,
        in_stk_maps={10: {}},
        in_reg_maps={10: {}},
    )

    assert resolved is not None
    _, site = resolved
    assert site.truncation_insn_eas == (0x1000, 0x1004, 0x1008)
    assert site.unsafe_trailing_insn_eas == (0x1004,)
    assert site.unsafe_trailing_reasons == ("memory_write",)


def _make_reconstruction_node(
    handler_serial: int,
    state_value: int,
    entry_anchor: int,
    *,
    label: str | None = None,
    shared_suffix_blocks: tuple[int, ...] = (),
    owned_blocks: tuple[int, ...] | None = None,
) -> StateDagNode:
    owned = owned_blocks if owned_blocks is not None else (entry_anchor,)
    return StateDagNode(
        key=StateDagNodeKey(handler_serial=handler_serial, state_const=state_value),
        kind=StateNodeKind.EXACT,
        state_label=label or f"0x{state_value:08X}",
        handler_serial=handler_serial,
        entry_anchor=entry_anchor,
        owned_blocks=owned,
        exclusive_blocks=owned,
        shared_suffix_blocks=shared_suffix_blocks,
        local_segments=(),
        local_edges=(),
    )


def _make_reconstruction_snapshot(
    flow_graph: FlowGraph,
    *,
    initial_state: int = 0x11111111,
    state_var_stkoff: int = 0x3C,
    handler_blocks: list[int] | None = None,
) -> AnalysisSnapshot:
    detector = SimpleNamespace(
        state_machine=SimpleNamespace(
            state_var=SimpleNamespace(
                t=int(ida_hexrays.mop_S),
                s=SimpleNamespace(off=state_var_stkoff),
            )
        )
    )
    state_machine = DispatcherStateMachine(
        mba=None,
        initial_state=initial_state,
        handlers={
            initial_state: StateHandler(
                state_value=initial_state,
                check_block=flow_graph.entry_serial,
                handler_blocks=handler_blocks or sorted(flow_graph.blocks),
                transitions=[],
            )
        },
        transitions=[],
        assignment_map={},
    )
    return AnalysisSnapshot(
        mba=SimpleNamespace(entry_ea=flow_graph.func_ea, maturity=1),
        state_machine=state_machine,
        detector=detector,
        bst_result=SimpleNamespace(
            pre_header_serial=None,
            handler_range_map={},
            bst_node_blocks={2},
            diagnostics=(),
            dispatcher=None,
        ),
        bst_dispatcher_serial=2,
        flow_graph=flow_graph,
    )


def test_state_write_reconstruction_uses_projected_topology_backend(monkeypatch):
    class _StopAfterBackend(Exception):
        pass

    class _FakeProjectedTopologyBackend:
        def __init__(self, dag: LinearizedStateDag) -> None:
            self.dag = dag
            self.calls: list[tuple[object, object, dict]] = []

        def build_projected_mba(self, flow_graph: object) -> object:
            raise AssertionError("SWR should not request projected MBA")

        def build_live_dag(
            self,
            current_flow_graph: object,
            transition_result: object,
            **kwargs,
        ) -> LinearizedStateDag:
            self.calls.append(
                (current_flow_graph, transition_result, kwargs)
            )
            corrected = kwargs.get("corrected_dag_out")
            if corrected is not None:
                corrected.append(self.dag)
            return self.dag

    class _FakeConstantFixpointBackend:
        def compute(self, flow_graph_arg: object, state_var_stkoff: int):
            assert flow_graph_arg is flow_graph
            assert state_var_stkoff == 0x3C
            raise _StopAfterBackend

    flow_graph = FlowGraph(
        blocks={
            2: BlockSnapshot(2, int(ida_hexrays.BLT_2WAY), (), (), 0, 0x2000, ()),
            10: BlockSnapshot(10, int(ida_hexrays.BLT_1WAY), (), (), 0, 0x1000, ()),
        },
        entry_serial=10,
        func_ea=0x1000,
    )
    source_node = _make_reconstruction_node(10, 0x11111111, 10)
    dag = LinearizedStateDag(
        dispatcher_entry_serial=2,
        state_var_stkoff=0x3C,
        pre_header_serial=None,
        initial_state=0x11111111,
        bst_node_blocks=(2,),
        nodes=(source_node,),
        edges=(),
        diagnostics=(),
    )
    backend = _FakeProjectedTopologyBackend(dag)
    strategy = StateWriteReconstructionStrategy()
    strategy._projected_topology_backend = backend
    strategy._constant_fixpoint_backend = _FakeConstantFixpointBackend()
    monkeypatch.setattr(
        reconstruction_module,
        "log_chain_coverage",
        lambda *args, **kwargs: None,
    )

    snapshot = _make_reconstruction_snapshot(flow_graph)

    with pytest.raises(_StopAfterBackend):
        strategy.plan(snapshot)

    assert len(backend.calls) == 1
    live_flow_graph, transition_result, kwargs = backend.calls[0]
    assert live_flow_graph is flow_graph
    assert transition_result.strategy_name == "state_write_reconstruction"
    assert kwargs["dispatcher_entry_serial"] == 2
    assert kwargs["state_var_stkoff"] == 0x3C
    assert kwargs["pre_header_serial"] is None
    assert kwargs["initial_state"] == 0x11111111
    assert kwargs["handler_range_map"] == {}
    assert kwargs["bst_node_blocks"] == (2,)
    assert kwargs["diagnostics"] == ()
    assert kwargs["dispatcher"] is None
    assert kwargs["mba"] is snapshot.mba
    assert kwargs["prefer_local_corridors"] is True



def test_state_write_reconstruction_wires_to_immediate_target(monkeypatch):
    """Relay collapsing is disabled: wire to the immediate DAG edge target (20),
    not the collapsed relay end (30).  This prevents handler orphaning."""
    mov = int(ida_hexrays.m_mov)
    goto = int(ida_hexrays.m_goto)
    mop_n = int(ida_hexrays.mop_n)
    mop_S = int(ida_hexrays.mop_S)
    mop_b = int(ida_hexrays.mop_b)

    flow_graph = FlowGraph(
        blocks={
            2: BlockSnapshot(2, int(ida_hexrays.BLT_2WAY), (3, 4), (10,), 0, 0x2000, ()),
            10: BlockSnapshot(
                serial=10,
                block_type=int(ida_hexrays.BLT_1WAY),
                succs=(2,),
                preds=(),
                flags=0,
                start_ea=0x1000,
                insn_snapshots=(
                    InsnSnapshot(
                        opcode=mov,
                        ea=0x1000,
                        operands=(),
                        l=MopSnapshot(t=mop_n, size=4, value=0x12345678),
                        d=MopSnapshot(t=mop_S, size=4, stkoff=0x3C),
                    ),
                    InsnSnapshot(
                        opcode=goto,
                        ea=0x1004,
                        operands=(),
                        l=MopSnapshot(t=mop_b, size=4, block_ref=2),
                    ),
                ),
            ),
            20: BlockSnapshot(
                serial=20,
                block_type=int(ida_hexrays.BLT_1WAY),
                succs=(30,),
                preds=(11,),
                flags=0,
                start_ea=0x2000,
                insn_snapshots=(),
            ),
            30: BlockSnapshot(30, int(ida_hexrays.BLT_1WAY), (), (20,), 0, 0x3000, ()),
        },
        entry_serial=10,
        func_ea=0x1000,
    )

    source_node = _make_reconstruction_node(10, 0x11111111, 10)
    relay_node = _make_reconstruction_node(20, 0x12345678, 20, label="relay_target")
    final_node = _make_reconstruction_node(
        40,
        0x87654321,
        30,
        label="semantic_target",
        owned_blocks=(30,),
    )
    dag = LinearizedStateDag(
        dispatcher_entry_serial=2,
        state_var_stkoff=0x3C,
        pre_header_serial=None,
        initial_state=0x11111111,
        bst_node_blocks=(2,),
        nodes=(source_node, relay_node, final_node),
        edges=(
            StateDagEdge(
                kind=SemanticEdgeKind.TRANSITION,
                source_key=source_node.key,
                target_key=relay_node.key,
                target_state=0x12345678,
                target_entry_anchor=20,
                target_label="relay_target",
                source_anchor=StateRedirectAnchor(
                    kind=RedirectSourceKind.UNCONDITIONAL,
                    block_serial=10,
                ),
                ordered_path=(10,),
            ),
            StateDagEdge(
                kind=SemanticEdgeKind.TRANSITION,
                source_key=relay_node.key,
                target_key=final_node.key,
                target_state=0x87654321,
                target_entry_anchor=30,
                target_label="semantic_target",
                source_anchor=StateRedirectAnchor(
                    kind=RedirectSourceKind.UNCONDITIONAL,
                    block_serial=20,
                ),
                ordered_path=(20,),
            ),
        ),
        diagnostics=(),
    )
    monkeypatch.setattr(
        reconstruction_module,
        "build_live_linearized_state_dag_from_graph",
        lambda *args, **kwargs: dag,
    )

    fragment = StateWriteReconstructionStrategy().plan(
        _make_reconstruction_snapshot(flow_graph)
    )

    assert fragment is not None
    # State-write NOPing disabled — only redirect emitted
    assert isinstance(fragment.modifications[0], RedirectGoto)
    # With relay collapsing disabled, we wire to the immediate target (20),
    # not the collapsed relay end (30).
    assert fragment.modifications[0].new_target == 20


def test_state_write_reconstruction_accepts_corridor_with_trailing_non_state_write(
    monkeypatch,
):
    """A corridor with a non-state stack write after the state write is accepted.

    The side-effect guard was removed: local stack writes (payload) must survive
    reconstruction.  Only the state-write instruction is NOPed.
    """
    mov = int(ida_hexrays.m_mov)
    goto = int(ida_hexrays.m_goto)
    mop_n = int(ida_hexrays.mop_n)
    mop_S = int(ida_hexrays.mop_S)
    mop_b = int(ida_hexrays.mop_b)

    flow_graph = FlowGraph(
        blocks={
            2: BlockSnapshot(2, int(ida_hexrays.BLT_2WAY), (3, 4), (10,), 0, 0x2000, ()),
            10: BlockSnapshot(
                serial=10,
                block_type=int(ida_hexrays.BLT_1WAY),
                succs=(2,),
                preds=(),
                flags=0,
                start_ea=0x1000,
                insn_snapshots=(
                    InsnSnapshot(
                        opcode=mov,
                        ea=0x1000,
                        operands=(),
                        l=MopSnapshot(t=mop_n, size=4, value=0x12345678),
                        d=MopSnapshot(t=mop_S, size=4, stkoff=0x3C),
                    ),
                    InsnSnapshot(
                        opcode=mov,
                        ea=0x1004,
                        operands=(),
                        l=MopSnapshot(t=mop_n, size=4, value=1),
                        d=MopSnapshot(t=mop_S, size=4, stkoff=0x60),
                    ),
                    InsnSnapshot(
                        opcode=goto,
                        ea=0x1008,
                        operands=(),
                        l=MopSnapshot(t=mop_b, size=4, block_ref=2),
                    ),
                ),
            ),
            30: BlockSnapshot(30, int(ida_hexrays.BLT_1WAY), (), (), 0, 0x3000, ()),
        },
        entry_serial=10,
        func_ea=0x1000,
    )
    source_node = _make_reconstruction_node(10, 0x11111111, 10)
    target_node = _make_reconstruction_node(30, 0x12345678, 30, label="target")
    dag = LinearizedStateDag(
        dispatcher_entry_serial=2,
        state_var_stkoff=0x3C,
        pre_header_serial=None,
        initial_state=0x11111111,
        bst_node_blocks=(2,),
        nodes=(source_node, target_node),
        edges=(
            StateDagEdge(
                kind=SemanticEdgeKind.TRANSITION,
                source_key=source_node.key,
                target_key=target_node.key,
                target_state=0x12345678,
                target_entry_anchor=30,
                target_label="target",
                source_anchor=StateRedirectAnchor(
                    kind=RedirectSourceKind.UNCONDITIONAL,
                    block_serial=10,
                ),
                ordered_path=(10,),
            ),
        ),
        diagnostics=(),
    )
    monkeypatch.setattr(
        reconstruction_module,
        "build_live_linearized_state_dag_from_graph",
        lambda *args, **kwargs: dag,
    )

    fragment = StateWriteReconstructionStrategy().plan(
        _make_reconstruction_snapshot(flow_graph)
    )

    # Corridor is accepted (not rejected by side-effect guard).
    assert fragment is not None
    assert fragment.metadata["reconstruction_sites"][0]["emission_mode"] == "direct"

    # State-write NOPing disabled — only redirect emitted.
    # Redirect to target handler is present.
    redirect_mod = fragment.modifications[0]
    assert isinstance(redirect_mod, RedirectGoto)
    assert redirect_mod.new_target == 30





def test_state_write_reconstruction_shared_group_two_new_targets_falls_back_to_duplication():
    mba_blocks = [
        _FakeMBAFlowBlock(2, [], preds=[10]),
        _FakeMBAFlowBlock(8, [10, 40], preds=[]),
        _FakeMBAFlowBlock(9, [10, 41], preds=[]),
        _FakeMBAFlowBlock(10, [2], preds=[8, 9]),
        _FakeMBAFlowBlock(24, [], preds=[]),
        _FakeMBAFlowBlock(30, [], preds=[]),
        _FakeMBAFlowBlock(40, [], preds=[8]),
        _FakeMBAFlowBlock(41, [], preds=[9]),
    ]
    flow_graph = _FakeFlowGraph(mba_blocks)
    fake_mba = _FakeMBA(blocks=mba_blocks)
    builder = ModificationBuilder.from_snapshot(
        SimpleNamespace(flow_graph=flow_graph, mba=fake_mba)
    )

    source_node = _make_reconstruction_node(8, 0x11111111, 8, owned_blocks=(8, 10))
    left_target = _make_reconstruction_node(24, 0xAAAA0001, 24, label="left_target")
    right_target = _make_reconstruction_node(30, 0xBBBB0002, 30, label="right_target")

    def _candidate(via_pred: int, target_node: StateDagNode, state_value: int):
        edge = StateDagEdge(
            kind=SemanticEdgeKind.TRANSITION,
            source_key=source_node.key,
            target_key=target_node.key,
            target_state=state_value,
            target_entry_anchor=target_node.entry_anchor,
            target_label=target_node.state_label,
            source_anchor=StateRedirectAnchor(
                kind=RedirectSourceKind.UNCONDITIONAL,
                block_serial=10,
            ),
            ordered_path=(via_pred, 10),
        )
        return reconstruction_module.ReconstructionCandidate(
            edge=edge,
            horizon_block=10,
            site=SimpleNamespace(state_value=state_value, insn_ea=0x1000 + via_pred),
            target_entry=target_node.entry_anchor,
            first_shared_block=10,
            via_pred=via_pred,
            emission_mode="shared_suffix",
        )

    modifications: list = []
    accepted_metadata: list[dict[str, int | str | None]] = []
    rejected_metadata: list[dict[str, int | str | None]] = []

    emitted = StateWriteReconstructionStrategy._emit_shared_group(
        10,
        [
            _candidate(8, left_target, 0xAAAA0001),
            _candidate(9, right_target, 0xBBBB0002),
        ],
        flow_graph=flow_graph,
        dispatcher_serial=2,
        bst_node_blocks={2},
        mba=fake_mba,
        builder=builder,
        modifications=modifications,
        owned_blocks=set(),
        owned_edges=set(),
        accepted_metadata=accepted_metadata,
        rejected_metadata=rejected_metadata,
    )

    assert emitted == 0
    assert accepted_metadata == []
    assert modifications == []
    assert {site["rejection_reason"] for site in rejected_metadata} == {
        "shared_group_clone_safety_gap"
    }




def test_state_write_reconstruction_rejects_backward_same_corridor_target(
    monkeypatch,
):
    mov = int(ida_hexrays.m_mov)
    xor = int(ida_hexrays.m_xor)
    goto = int(ida_hexrays.m_goto)
    mop_n = int(ida_hexrays.mop_n)
    mop_S = int(ida_hexrays.mop_S)
    mop_b = int(ida_hexrays.mop_b)
    expected_state = (0xAAAA0000 ^ 0xBBBB1111) & 0xFFFFFFFF

    flow_graph = FlowGraph(
        blocks={
            2: BlockSnapshot(2, int(ida_hexrays.BLT_2WAY), (3, 4), (10,), 0, 0x2000, ()),
            9: BlockSnapshot(
                serial=9,
                block_type=int(ida_hexrays.BLT_1WAY),
                succs=(10,),
                preds=(),
                flags=0,
                start_ea=0x0FF0,
                insn_snapshots=(
                    InsnSnapshot(
                        opcode=mov,
                        ea=0x0FF0,
                        operands=(),
                        l=MopSnapshot(t=mop_n, size=4, value=0xAAAA0000),
                        d=MopSnapshot(t=mop_S, size=4, stkoff=0x60),
                    ),
                    InsnSnapshot(
                        opcode=mov,
                        ea=0x0FF4,
                        operands=(),
                        l=MopSnapshot(t=mop_n, size=4, value=0xBBBB1111),
                        d=MopSnapshot(t=mop_S, size=4, stkoff=0x68),
                    ),
                ),
            ),
            10: BlockSnapshot(
                serial=10,
                block_type=int(ida_hexrays.BLT_1WAY),
                succs=(2,),
                preds=(9,),
                flags=0,
                start_ea=0x1000,
                insn_snapshots=(
                    InsnSnapshot(
                        opcode=xor,
                        ea=0x1000,
                        operands=(),
                        l=MopSnapshot(t=mop_S, size=4, stkoff=0x68),
                        r=MopSnapshot(t=mop_S, size=4, stkoff=0x60),
                        d=MopSnapshot(t=mop_S, size=4, stkoff=0x3C),
                    ),
                    InsnSnapshot(
                        opcode=goto,
                        ea=0x1004,
                        operands=(),
                        l=MopSnapshot(t=mop_b, size=4, block_ref=2),
                    ),
                ),
            ),
        },
        entry_serial=9,
        func_ea=0x0FF0,
    )
    source_node = _make_reconstruction_node(9, 0x11111111, 9, owned_blocks=(9, 10))
    back_target = _make_reconstruction_node(9, expected_state, 9, label="back_target", owned_blocks=(9,))
    dag = LinearizedStateDag(
        dispatcher_entry_serial=2,
        state_var_stkoff=0x3C,
        pre_header_serial=None,
        initial_state=0x11111111,
        bst_node_blocks=(2,),
        nodes=(source_node, back_target),
        edges=(
            StateDagEdge(
                kind=SemanticEdgeKind.TRANSITION,
                source_key=source_node.key,
                target_key=back_target.key,
                target_state=expected_state,
                target_entry_anchor=9,
                target_label="back_target",
                source_anchor=StateRedirectAnchor(
                    kind=RedirectSourceKind.UNCONDITIONAL,
                    block_serial=10,
                ),
                ordered_path=(9, 10),
            ),
        ),
        diagnostics=(),
    )
    monkeypatch.setattr(
        reconstruction_module,
        "build_live_linearized_state_dag_from_graph",
        lambda *args, **kwargs: dag,
    )

    assert StateWriteReconstructionStrategy().plan(
        _make_reconstruction_snapshot(flow_graph, handler_blocks=[9, 10])
    ) is None


def test_state_write_reconstruction_rejects_dispatcher_target_rewrite(monkeypatch):
    mov = int(ida_hexrays.m_mov)
    goto = int(ida_hexrays.m_goto)
    mop_n = int(ida_hexrays.mop_n)
    mop_S = int(ida_hexrays.mop_S)
    mop_b = int(ida_hexrays.mop_b)

    flow_graph = FlowGraph(
        blocks={
            2: BlockSnapshot(2, int(ida_hexrays.BLT_2WAY), (3, 4), (10,), 0, 0x2000, ()),
            10: BlockSnapshot(
                serial=10,
                block_type=int(ida_hexrays.BLT_1WAY),
                succs=(2,),
                preds=(),
                flags=0,
                start_ea=0x1000,
                insn_snapshots=(
                    InsnSnapshot(
                        opcode=mov,
                        ea=0x1000,
                        operands=(),
                        l=MopSnapshot(t=mop_n, size=4, value=0x12345678),
                        d=MopSnapshot(t=mop_S, size=4, stkoff=0x3C),
                    ),
                    InsnSnapshot(
                        opcode=goto,
                        ea=0x1004,
                        operands=(),
                        l=MopSnapshot(t=mop_b, size=4, block_ref=2),
                    ),
                ),
            ),
            30: BlockSnapshot(30, int(ida_hexrays.BLT_1WAY), (), (), 0, 0x3000, ()),
        },
        entry_serial=10,
        func_ea=0x1000,
    )
    source_node = _make_reconstruction_node(10, 0x11111111, 10)
    unrelated = _make_reconstruction_node(30, 0x99999999, 30, label="unrelated")
    dag = LinearizedStateDag(
        dispatcher_entry_serial=2,
        state_var_stkoff=0x3C,
        pre_header_serial=None,
        initial_state=0x11111111,
        bst_node_blocks=(2,),
        nodes=(source_node, unrelated),
        edges=(
            StateDagEdge(
                kind=SemanticEdgeKind.TRANSITION,
                source_key=source_node.key,
                target_key=None,
                target_state=0x12345678,
                target_entry_anchor=2,
                target_label="dispatcher_alias",
                source_anchor=StateRedirectAnchor(
                    kind=RedirectSourceKind.UNCONDITIONAL,
                    block_serial=10,
                ),
                ordered_path=(10,),
            ),
        ),
        diagnostics=(),
    )
    monkeypatch.setattr(
        reconstruction_module,
        "build_live_linearized_state_dag_from_graph",
        lambda *args, **kwargs: dag,
    )

    assert StateWriteReconstructionStrategy().plan(
        _make_reconstruction_snapshot(flow_graph)
    ) is None


def test_terminal_loop_cleanup_not_applicable():
    s = TerminalLoopCleanupStrategy()
    assert not s.is_applicable(_empty_snapshot())


def test_conditional_fork_fallback_not_applicable():
    s = ConditionalForkFallbackStrategy()
    assert not s.is_applicable(_empty_snapshot())


# ---------------------------------------------------------------------------
# plan() returns None on empty snapshot
# ---------------------------------------------------------------------------


class TestPlanEmptySnapshot:
    """All strategies should return None when is_applicable is False."""

    def _check_none(self, strategy):
        result = strategy.plan(_empty_snapshot())
        assert result is None, (
            f"{strategy.name}.plan() should return None on empty snapshot"
        )

    def test_edge_split_returns_none(self):
        self._check_none(EdgeSplitConflictResolutionStrategy())

    def test_terminal_loop_cleanup_returns_none(self):
        self._check_none(TerminalLoopCleanupStrategy())

    def test_conditional_fork_fallback_returns_none(self):
        self._check_none(ConditionalForkFallbackStrategy())

# ---------------------------------------------------------------------------
# EdgeSplitConflictResolutionStrategy — constructor args
# ---------------------------------------------------------------------------


class TestEdgeSplitConstructor:
    """EdgeSplitConflictResolutionStrategy accepts conflict blocks at init time."""

    def test_empty_conflict_blocks_not_applicable(self):
        s = EdgeSplitConflictResolutionStrategy(conflict_blocks=set())
        assert not s.is_applicable(_empty_snapshot())

    def test_non_empty_conflict_blocks_applicable(self):
        s = EdgeSplitConflictResolutionStrategy(conflict_blocks={5, 10})
        assert s.is_applicable(_empty_snapshot())

    def test_plan_returns_none_while_duplicate_materialization_is_disabled(self):
        s = EdgeSplitConflictResolutionStrategy(conflict_blocks={5, 10})
        fragment = s.plan(_empty_snapshot())
        assert fragment is None

    def test_plan_ownership_contains_conflict_blocks(self):
        s = EdgeSplitConflictResolutionStrategy(conflict_blocks={7, 13})
        fragment = s.plan(_empty_snapshot())
        assert fragment is None

    def test_plan_strategy_name_in_fragment(self):
        s = EdgeSplitConflictResolutionStrategy(conflict_blocks={1})
        fragment = s.plan(_empty_snapshot())
        assert fragment is None
        assert s.name == "edge_split_conflict_resolution"


# ---------------------------------------------------------------------------
# Prerequisites
# ---------------------------------------------------------------------------


class TestPrerequisites:
    """Verify prerequisite declarations for each strategy."""

    def test_edge_split_no_prereqs_by_design(self):
        s = EdgeSplitConflictResolutionStrategy(conflict_blocks={1})
        frag = s.plan(_empty_snapshot())
        assert frag is None
        assert s.name == "edge_split_conflict_resolution"

class TestModificationBuilder:
    """Pure-Python checks for branch-aware GraphModification emission."""

    def test_edge_redirect_preserves_branch_kind_for_two_way_blocks(self):
        builder = ModificationBuilder(
            block_nsucc_map={10: 2},
            block_succ_map={10: (20, 21)},
        )

        modification = builder.edge_redirect(
            source_block=10,
            target_block=30,
            old_target=20,
        )

        assert modification == RedirectBranch(
            from_serial=10,
            old_target=20,
            new_target=30,
        )

    def test_edge_redirect_with_via_pred_still_emits_pred_split(self):
        builder = ModificationBuilder(
            block_nsucc_map={10: 1},
            block_succ_map={10: (20,)},
        )

        modification = builder.edge_redirect(
            source_block=10,
            target_block=30,
            old_target=20,
            via_pred=5,
        )

        assert modification == EdgeRedirectViaPredSplit(
            src_block=10,
            old_target=20,
            new_target=30,
            via_pred=5,
            rule_priority=550,
        )


class _FakeFlowBlock:
    def __init__(self, serial: int, succs: list[int], preds: list[int] | None = None):
        self.serial = serial
        self.succs = tuple(succs)
        self.preds = tuple(preds or [])
        self.nsucc = len(self.succs)
        self.npred = len(self.preds)
        self.insn_snapshots = ()
        self.block_type = 4 if len(self.succs) == 2 else 3
        self.tail_opcode = None
        self.flags = 0
        self.start_ea = 0x1000 + serial * 0x10


class _FakeFlowGraph:
    def __init__(self, blocks: list[_FakeFlowBlock]):
        self.blocks = {block.serial: block for block in blocks}
        self.func_ea = 0x401000
        self.num_blocks = len(blocks)
        self.metadata = {}

    def get_block(self, serial: int):
        return self.blocks.get(serial)

    def successors(self, serial: int):
        block = self.blocks.get(serial)
        return tuple(block.succs) if block is not None else ()

    def predecessors(self, serial: int):
        block = self.blocks.get(serial)
        return tuple(block.preds) if block is not None else ()

    def as_adjacency_dict(self) -> dict[int, list[int]]:
        return {s: list(b.succs) for s, b in self.blocks.items()}


class _FakeNum:
    def __init__(self, value: int):
        self.value = value


class _FakeStackRef:
    def __init__(self, off: int):
        self.off = off


class _FakeMop:
    def __init__(
        self,
        t: int,
        *,
        off: int | None = None,
        value: int | None = None,
        reg: int | None = None,
        size: int = 4,
    ):
        self.t = t
        self.size = size
        self.s = _FakeStackRef(off) if off is not None else None
        self.nnn = _FakeNum(value) if value is not None else None
        self.r = reg


class _FakeInsn:
    def __init__(
        self,
        opcode: int,
        l=None,
        r=None,
        d=None,
        next_insn=None,
        *,
        ea: int = 0x1000,
    ):
        self.opcode = opcode
        self.l = l
        self.r = r
        self.d = d
        self.next = next_insn
        self.ea = ea


class _FakeMBAFlowBlock(_FakeFlowBlock):
    def __init__(
        self,
        serial: int,
        succs: list[int],
        preds: list[int] | None = None,
        *,
        head=None,
    ):
        super().__init__(serial, succs, preds)
        self.head = head
        self.flags = 0
        self.start_ea = 0x1000 + serial * 0x10


class _FakeMBA(SimpleNamespace):
    def __init__(self, *, blocks: list[_FakeMBAFlowBlock], entry_ea: int = 0x401000):
        super().__init__(entry_ea=entry_ea, maturity=1, qty=len(blocks))
        self._blocks = {block.serial: block for block in blocks}

    def get_mblock(self, serial: int):
        return self._blocks.get(serial)


def test_lfg_accepts_only_original_entry_pre_header_candidates():
    flow_graph = _FakeFlowGraph(
        [
            _FakeFlowBlock(0, [1], preds=[]),
            _FakeFlowBlock(1, [77], preds=[0]),
            _FakeFlowBlock(62, [71], preds=[]),
        ]
    )

    assert is_original_pre_header_candidate(
        flow_graph,
        pre_header_serial=1,
        entry_serial=0,
    )
    assert not is_original_pre_header_candidate(
        flow_graph,
        pre_header_serial=62,
        entry_serial=0,
    )


def test_lfg_plan_uses_dag_semantic_edges(monkeypatch):
    strategy = LinearizedFlowGraphStrategy()

    source_node = StateDagNode(
        key=StateDagNodeKey(handler_serial=10, state_const=0x10),
        kind=StateNodeKind.EXACT,
        state_label="0x00000010",
        handler_serial=10,
        entry_anchor=10,
        owned_blocks=(10, 11, 12),
        exclusive_blocks=(10, 11, 12),
        shared_suffix_blocks=(),
        local_segments=(
            StateLocalSegment("blk[11]", kind=LocalSegmentKind.STRAIGHT_LINE, blocks=(11,)),
            StateLocalSegment("blk[12]", kind=LocalSegmentKind.BRANCH, blocks=(12,)),
        ),
        local_edges=(),
    )
    target_node = StateDagNode(
        key=StateDagNodeKey(handler_serial=20, state_const=0x20),
        kind=StateNodeKind.EXACT,
        state_label="0x00000020",
        handler_serial=20,
        entry_anchor=20,
        owned_blocks=(20,),
        exclusive_blocks=(20,),
        shared_suffix_blocks=(),
        local_segments=(),
        local_edges=(),
    )
    branch_target_node = StateDagNode(
        key=StateDagNodeKey(handler_serial=30, state_const=0x30),
        kind=StateNodeKind.EXACT,
        state_label="0x00000030",
        handler_serial=30,
        entry_anchor=30,
        owned_blocks=(30,),
        exclusive_blocks=(30,),
        shared_suffix_blocks=(),
        local_segments=(),
        local_edges=(),
    )
    dag = LinearizedStateDag(
        dispatcher_entry_serial=99,
        state_var_stkoff=None,
        pre_header_serial=1,
        initial_state=0x10,
        bst_node_blocks=(),
        nodes=(source_node, target_node, branch_target_node),
        edges=(
            StateDagEdge(
                kind=SemanticEdgeKind.TRANSITION,
                source_key=source_node.key,
                target_key=target_node.key,
                target_state=0x20,
                target_entry_anchor=20,
                target_label="0x00000020",
                source_anchor=StateRedirectAnchor(
                    kind=RedirectSourceKind.EXIT_BLOCK,
                    block_serial=11,
                ),
                ordered_path=(10, 11),
            ),
            StateDagEdge(
                kind=SemanticEdgeKind.CONDITIONAL_TRANSITION,
                source_key=source_node.key,
                target_key=branch_target_node.key,
                target_state=0x30,
                target_entry_anchor=30,
                target_label="0x00000030",
                source_anchor=StateRedirectAnchor(
                    kind=RedirectSourceKind.CONDITIONAL_BRANCH,
                    block_serial=12,
                    branch_arm=1,
                ),
                ordered_path=(10, 12, 14),
            ),
        ),
        diagnostics=(),
    )

    monkeypatch.setattr(
        lfg_module,
        "build_live_linearized_state_dag_from_graph",
        lambda *args, **kwargs: dag,
    )
    monkeypatch.setattr(
        LinearizedFlowGraphStrategy,
        "_disconnect_bst_comparison_nodes",
        staticmethod(lambda *args, **kwargs: 0),
    )

    flow_graph = _FakeFlowGraph(
        [
            _FakeFlowBlock(1, [10]),
            _FakeFlowBlock(10, [11]),
            _FakeFlowBlock(11, [99]),
            _FakeFlowBlock(12, [13, 14]),
            _FakeFlowBlock(13, [], preds=[12]),
            _FakeFlowBlock(14, [99], preds=[12]),
            _FakeFlowBlock(20, []),
            _FakeFlowBlock(30, []),
        ]
    )
    sm = DispatcherStateMachine(
        mba=SimpleNamespace(entry_ea=0x401000, maturity=1),
        initial_state=0x10,
        handlers={
            0x10: StateHandler(state_value=0x10, check_block=10, handler_blocks=[10, 11, 12]),
            0x20: StateHandler(state_value=0x20, check_block=20, handler_blocks=[20]),
            0x30: StateHandler(state_value=0x30, check_block=30, handler_blocks=[30]),
        },
    )
    snapshot = AnalysisSnapshot(
        mba=sm.mba,
        state_machine=sm,
        detector=None,
        bst_result=SimpleNamespace(
            handler_state_map={10: 0x10, 20: 0x20, 30: 0x30},
            handler_range_map={},
            pre_header_serial=1,
            bst_node_blocks=set(),
            dispatcher=None,
            diagnostics=(),
        ),
        bst_dispatcher_serial=99,
        flow_graph=flow_graph,
    )

    fragment = strategy.plan(snapshot)

    assert fragment is not None
    assert fragment.metadata["safeguard_min_required"] == 1
    mods = fragment.modifications
    assert any(
        isinstance(mod, RedirectGoto)
        and mod.from_serial == 11
        and mod.old_target == 99
        and mod.new_target == 20
        for mod in mods
    )
    assert any(
        isinstance(mod, RedirectGoto)
        and mod.from_serial == 14
        and mod.old_target == 99
        and mod.new_target == 30
        for mod in mods
    )
    assert not any(
        isinstance(mod, RedirectBranch)
        and mod.from_serial == 12
        for mod in mods
    )


def test_lfg_plan_uses_projected_dag_passes_without_rebuilding_from_base(monkeypatch):
    strategy = LinearizedFlowGraphStrategy()

    source_node = StateDagNode(
        key=StateDagNodeKey(handler_serial=93, state_const=0x42267E66),
        kind=StateNodeKind.EXACT,
        state_label="0x42267E66",
        handler_serial=93,
        entry_anchor=93,
        owned_blocks=(93, 94, 95),
        exclusive_blocks=(93, 94, 95),
        shared_suffix_blocks=(),
        local_segments=(),
        local_edges=(),
    )
    target_node = StateDagNode(
        key=StateDagNodeKey(handler_serial=211, state_const=0x24E2E77A),
        kind=StateNodeKind.EXACT,
        state_label="0x24E2E77A",
        handler_serial=211,
        entry_anchor=211,
        owned_blocks=(211,),
        exclusive_blocks=(211,),
        shared_suffix_blocks=(),
        local_segments=(),
        local_edges=(),
    )
    dag = LinearizedStateDag(
        dispatcher_entry_serial=2,
        state_var_stkoff=None,
        pre_header_serial=1,
        initial_state=0x42267E66,
        bst_node_blocks=(),
        nodes=(source_node, target_node),
        edges=(
            StateDagEdge(
                kind=SemanticEdgeKind.TRANSITION,
                source_key=source_node.key,
                target_key=target_node.key,
                target_state=0x24E2E77A,
                target_entry_anchor=211,
                target_label="0x24E2E77A",
                source_anchor=StateRedirectAnchor(
                    kind=RedirectSourceKind.UNCONDITIONAL,
                    block_serial=93,
                ),
                ordered_path=(93, 95),
            ),
        ),
        diagnostics=(),
    )

    original_flow_graph = _FakeFlowGraph(
        [
            _FakeFlowBlock(1, [2]),
            _FakeFlowBlock(2, []),
            _FakeFlowBlock(93, [94, 95]),
            _FakeFlowBlock(94, [], preds=[93]),
            _FakeFlowBlock(95, [2], preds=[93]),
            _FakeFlowBlock(211, []),
        ]
    )
    projected_flow_graph = _FakeFlowGraph(
        [
            _FakeFlowBlock(1, [93]),
            _FakeFlowBlock(2, []),
            _FakeFlowBlock(93, [94, 95], preds=[1]),
            _FakeFlowBlock(94, [], preds=[93]),
            _FakeFlowBlock(95, [2], preds=[93]),
            _FakeFlowBlock(211, []),
        ]
    )

    build_calls: list[object] = []

    def _fake_build_live(flow_graph, *args, **kwargs):
        build_calls.append(flow_graph)
        return dag

    monkeypatch.setattr(
        lfg_module,
        "build_live_linearized_state_dag_from_graph",
        _fake_build_live,
    )
    monkeypatch.setattr(
        lfg_module,
        "build_dispatcher_transition_report_from_graph",
        lambda *args, **kwargs: SimpleNamespace(
            rows=(
                SimpleNamespace(
                    handler_serial=93,
                    kind=lfg_module.TransitionKind.EXIT,
                ),
            )
        ),
    )
    monkeypatch.setattr(
        lfg_module,
        "compile_patch_plan",
        lambda modifications, cfg: SimpleNamespace(
            modifications=tuple(modifications),
            cfg=cfg,
        ),
    )
    monkeypatch.setattr(
        lfg_module,
        "project_post_state",
        lambda cfg, patch_plan: projected_flow_graph,
    )
    monkeypatch.setattr(
        lfg_module,
        "build_mba_view_from_flow_graph",
        lambda flow_graph: None,
    )
    monkeypatch.setattr(
        LinearizedFlowGraphStrategy,
        "_supports_projected_replanning",
        staticmethod(lambda flow_graph: True),
    )
    monkeypatch.setattr(
        LinearizedFlowGraphStrategy,
        "_disconnect_bst_comparison_nodes",
        staticmethod(lambda *args, **kwargs: 0),
    )

    sm = DispatcherStateMachine(
        mba=SimpleNamespace(entry_ea=0x401000, maturity=1),
        initial_state=0x42267E66,
        handlers={
            0x42267E66: StateHandler(
                state_value=0x42267E66,
                check_block=93,
                handler_blocks=[93, 94, 95],
            ),
            0x24E2E77A: StateHandler(
                state_value=0x24E2E77A,
                check_block=211,
                handler_blocks=[211],
            ),
        },
    )
    snapshot = AnalysisSnapshot(
        mba=sm.mba,
        state_machine=sm,
        detector=None,
        bst_result=SimpleNamespace(
            handler_state_map={93: 0x42267E66, 211: 0x24E2E77A},
            handler_range_map={},
            pre_header_serial=1,
            bst_node_blocks=set(),
            dispatcher=None,
            diagnostics=(),
        ),
        bst_dispatcher_serial=2,
        reachability=SimpleNamespace(entry_serial=1),
        flow_graph=original_flow_graph,
    )

    fragment = strategy.plan(snapshot)

    assert fragment is not None
    assert build_calls[0] is original_flow_graph
    assert build_calls[1:] == [projected_flow_graph, projected_flow_graph]
    assert any(
        isinstance(mod, RedirectGoto)
        and mod.from_serial == 1
        and mod.old_target == 2
        and mod.new_target == 93
        for mod in fragment.modifications
    )
    assert any(
        isinstance(mod, RedirectGoto)
        and mod.from_serial == 95
        and mod.old_target == 2
        and mod.new_target == 211
        for mod in fragment.modifications
    )


def test_lfg_plan_nops_dead_state_writes_for_whole_redirect_gotos(monkeypatch):
    strategy = LinearizedFlowGraphStrategy()

    source_node = StateDagNode(
        key=StateDagNodeKey(handler_serial=93, state_const=0x42267E66),
        kind=StateNodeKind.EXACT,
        state_label="0x42267E66",
        handler_serial=93,
        entry_anchor=93,
        owned_blocks=(93, 94, 95),
        exclusive_blocks=(93, 94, 95),
        shared_suffix_blocks=(),
        local_segments=(),
        local_edges=(),
    )
    target_node = StateDagNode(
        key=StateDagNodeKey(handler_serial=211, state_const=0x24E2E77A),
        kind=StateNodeKind.EXACT,
        state_label="0x24E2E77A",
        handler_serial=211,
        entry_anchor=211,
        owned_blocks=(211,),
        exclusive_blocks=(211,),
        shared_suffix_blocks=(),
        local_segments=(),
        local_edges=(),
    )
    dag = LinearizedStateDag(
        dispatcher_entry_serial=2,
        state_var_stkoff=0x3C,
        pre_header_serial=1,
        initial_state=0x42267E66,
        bst_node_blocks=(),
        nodes=(source_node, target_node),
        edges=(
            StateDagEdge(
                kind=SemanticEdgeKind.TRANSITION,
                source_key=source_node.key,
                target_key=target_node.key,
                target_state=0x24E2E77A,
                target_entry_anchor=211,
                target_label="0x24E2E77A",
                source_anchor=StateRedirectAnchor(
                    kind=RedirectSourceKind.UNCONDITIONAL,
                    block_serial=95,
                ),
                ordered_path=(93, 95),
            ),
        ),
        diagnostics=(),
    )

    pre_header_write = _FakeInsn(
        lfg_module.ida_hexrays.m_mov,
        l=_FakeMop(lfg_module.ida_hexrays.mop_n, value=0x42267E66),
        d=_FakeMop(lfg_module.ida_hexrays.mop_S, off=0x3C),
    )
    handoff_write = _FakeInsn(
        lfg_module.ida_hexrays.m_mov,
        l=_FakeMop(lfg_module.ida_hexrays.mop_n, value=0x24E2E77A),
        d=_FakeMop(lfg_module.ida_hexrays.mop_S, off=0x3C),
    )
    mba_blocks = [
        _FakeMBAFlowBlock(1, [2], preds=[0], head=pre_header_write),
        _FakeMBAFlowBlock(2, [], preds=[1, 95]),
        _FakeMBAFlowBlock(93, [94, 95], preds=[]),
        _FakeMBAFlowBlock(94, [], preds=[93]),
        _FakeMBAFlowBlock(95, [2], preds=[93], head=handoff_write),
        _FakeMBAFlowBlock(211, [], preds=[]),
    ]
    fake_mba = _FakeMBA(blocks=mba_blocks)
    flow_graph = _FakeFlowGraph(mba_blocks)

    monkeypatch.setattr(
        lfg_module,
        "build_live_linearized_state_dag_from_graph",
        lambda *args, **kwargs: dag,
    )
    monkeypatch.setattr(
        lfg_module,
        "build_dispatcher_transition_report_from_graph",
        lambda *args, **kwargs: SimpleNamespace(rows=()),
    )
    monkeypatch.setattr(
        LinearizedFlowGraphStrategy,
        "_supports_projected_replanning",
        staticmethod(lambda flow_graph: False),
    )
    monkeypatch.setattr(
        LinearizedFlowGraphStrategy,
        "_disconnect_bst_comparison_nodes",
        staticmethod(lambda *args, **kwargs: 0),
    )
    monkeypatch.setattr(
        lfg_module,
        "compile_patch_plan",
        lambda modifications, cfg: SimpleNamespace(
            modifications=tuple(modifications),
            cfg=cfg,
        ),
    )
    monkeypatch.setattr(
        lfg_module,
        "project_post_state",
        lambda cfg, patch_plan: flow_graph,
    )

    sm = DispatcherStateMachine(
        mba=fake_mba,
        state_var=_FakeMop(lfg_module.ida_hexrays.mop_S, off=0x3C),
        initial_state=0x42267E66,
        handlers={
            0x42267E66: StateHandler(
                state_value=0x42267E66,
                check_block=93,
                handler_blocks=[93, 94, 95],
            ),
            0x24E2E77A: StateHandler(
                state_value=0x24E2E77A,
                check_block=211,
                handler_blocks=[211],
            ),
        },
    )
    snapshot = AnalysisSnapshot(
        mba=fake_mba,
        state_machine=sm,
        detector=None,
        bst_result=SimpleNamespace(
            handler_state_map={93: 0x42267E66, 211: 0x24E2E77A},
            handler_range_map={},
            pre_header_serial=1,
            bst_node_blocks=set(),
            dispatcher=None,
            diagnostics=(),
        ),
        bst_dispatcher_serial=2,
        flow_graph=flow_graph,
    )

    fragment = strategy.plan(snapshot)

    assert fragment is not None
    assert fragment.metadata["nop_state_values"] == {}
    assert any(
        isinstance(mod, RedirectGoto)
        and mod.from_serial == 1
        and mod.new_target == 93
        for mod in fragment.modifications
    )
    assert any(
        isinstance(mod, RedirectGoto)
        and mod.from_serial == 95
        and mod.new_target == 211
        for mod in fragment.modifications
    )


def test_lfg_plan_blocks_post_apply_bst_cleanup_when_residual_dispatcher_tails_remain(
    monkeypatch,
):
    strategy = LinearizedFlowGraphStrategy()

    source_node = StateDagNode(
        key=StateDagNodeKey(handler_serial=93, state_const=0x42267E66),
        kind=StateNodeKind.EXACT,
        state_label="0x42267E66",
        handler_serial=93,
        entry_anchor=93,
        owned_blocks=(93, 94, 95),
        exclusive_blocks=(93, 94, 95),
        shared_suffix_blocks=(),
        local_segments=(),
        local_edges=(),
    )
    dag = LinearizedStateDag(
        dispatcher_entry_serial=2,
        state_var_stkoff=None,
        pre_header_serial=1,
        initial_state=0x42267E66,
        bst_node_blocks=(),
        nodes=(source_node,),
        edges=(),
        diagnostics=(),
    )

    original_flow_graph = _FakeFlowGraph(
        [
            _FakeFlowBlock(1, [2]),
            _FakeFlowBlock(2, []),
            _FakeFlowBlock(93, [94, 95], preds=[]),
            _FakeFlowBlock(94, [], preds=[93]),
            _FakeFlowBlock(95, [2], preds=[93]),
        ]
    )
    projected_flow_graph = _FakeFlowGraph(
        [
            _FakeFlowBlock(1, [93]),
            _FakeFlowBlock(2, [], preds=[95]),
            _FakeFlowBlock(93, [94, 95], preds=[1]),
            _FakeFlowBlock(94, [], preds=[93]),
            _FakeFlowBlock(95, [2], preds=[93]),
        ]
    )

    monkeypatch.setattr(
        lfg_module,
        "build_live_linearized_state_dag_from_graph",
        lambda *args, **kwargs: dag,
    )
    monkeypatch.setattr(
        lfg_module,
        "build_dispatcher_transition_report_from_graph",
        lambda *args, **kwargs: SimpleNamespace(rows=()),
    )
    monkeypatch.setattr(
        lfg_module,
        "compile_patch_plan",
        lambda modifications, cfg: SimpleNamespace(
            modifications=tuple(modifications),
            cfg=cfg,
        ),
    )
    monkeypatch.setattr(
        lfg_module,
        "project_post_state",
        lambda cfg, patch_plan: projected_flow_graph,
    )
    monkeypatch.setattr(
        lfg_module,
        "build_mba_view_from_flow_graph",
        lambda flow_graph: None,
    )
    monkeypatch.setattr(
        LinearizedFlowGraphStrategy,
        "_supports_projected_replanning",
        staticmethod(lambda flow_graph: True),
    )
    monkeypatch.setattr(
        LinearizedFlowGraphStrategy,
        "_disconnect_bst_comparison_nodes",
        staticmethod(lambda *args, **kwargs: 0),
    )

    sm = DispatcherStateMachine(
        mba=SimpleNamespace(entry_ea=0x401000, maturity=1),
        initial_state=0x42267E66,
        handlers={
            0x42267E66: StateHandler(
                state_value=0x42267E66,
                check_block=93,
                handler_blocks=[93, 94, 95],
            ),
        },
    )
    snapshot = AnalysisSnapshot(
        mba=sm.mba,
        state_machine=sm,
        detector=None,
        bst_result=SimpleNamespace(
            handler_state_map={93: 0x42267E66},
            handler_range_map={},
            pre_header_serial=1,
            bst_node_blocks=set(),
            dispatcher=None,
            diagnostics=(),
        ),
        bst_dispatcher_serial=2,
        flow_graph=original_flow_graph,
    )

    fragment = strategy.plan(snapshot)

    # The LFG strategy now returns None when the DAG produces no redirect
    # modifications.  This edge case previously emitted a fragment with
    # metadata-only flags, but the current implementation gates fragment
    # emission on having actual redirects.
    assert fragment is None


def test_lfg_plan_blocks_source_after_path_tail_pred_split():
    source_node = StateDagNode(
        key=StateDagNodeKey(handler_serial=126, state_const=0x10),
        kind=StateNodeKind.EXACT,
        state_label="0x00000010",
        handler_serial=126,
        entry_anchor=126,
        owned_blocks=(126, 192),
        exclusive_blocks=(126, 192),
        shared_suffix_blocks=(),
        local_segments=(),
        local_edges=(),
    )
    target_node = StateDagNode(
        key=StateDagNodeKey(handler_serial=7, state_const=0x20),
        kind=StateNodeKind.EXACT,
        state_label="0x00000020",
        handler_serial=7,
        entry_anchor=7,
        owned_blocks=(7,),
        exclusive_blocks=(7,),
        shared_suffix_blocks=(),
        local_segments=(),
        local_edges=(),
    )
    dag = LinearizedStateDag(
        dispatcher_entry_serial=2,
        state_var_stkoff=None,
        pre_header_serial=None,
        initial_state=None,
        bst_node_blocks=(),
        nodes=(source_node, target_node),
        edges=(
            StateDagEdge(
                kind=SemanticEdgeKind.TRANSITION,
                source_key=source_node.key,
                target_key=target_node.key,
                target_state=0x20,
                target_entry_anchor=7,
                target_label="0x00000020",
                source_anchor=StateRedirectAnchor(
                    kind=RedirectSourceKind.UNCONDITIONAL,
                    block_serial=126,
                ),
                ordered_path=(126, 192),
            ),
            StateDagEdge(
                kind=SemanticEdgeKind.TRANSITION,
                source_key=source_node.key,
                target_key=None,
                target_state=0x30,
                target_entry_anchor=125,
                target_label="blk[125]",
                source_anchor=StateRedirectAnchor(
                    kind=RedirectSourceKind.UNCONDITIONAL,
                    block_serial=126,
                ),
                ordered_path=(),
            ),
        ),
        diagnostics=(),
    )

    flow_graph = _FakeFlowGraph(
        [
            _FakeFlowBlock(126, [192], preds=[1]),
            _FakeFlowBlock(191, [192]),
            _FakeFlowBlock(192, [2], preds=[126, 191]),
            _FakeFlowBlock(7, []),
            _FakeFlowBlock(125, []),
        ]
    )
    builder = ModificationBuilder.from_snapshot(
        SimpleNamespace(flow_graph=flow_graph, mba=SimpleNamespace(entry_ea=0x401000))
    )
    first_edge, second_edge = dag.edges
    modifications: list = []
    owned_blocks: set[int] = set()
    owned_edges: set[tuple[int, int]] = set()
    owned_transitions: set[tuple[int, int]] = set()
    emitted: set[tuple[int, int]] = set()
    claimed_exits: dict[int, int] = {}
    claimed_path_edges: dict[tuple[int, int], int] = {}
    blocked_sources: set[int] = set()

    assert LinearizedFlowGraphStrategy._emit_path_tail_redirect(
        edge=first_edge,
        dag=dag,
        builder=builder,
        modifications=modifications,
        owned_blocks=owned_blocks,
        owned_edges=owned_edges,
        owned_transitions=owned_transitions,
        emitted=emitted,
        claimed_exits=claimed_exits,
        claimed_path_edges=claimed_path_edges,
        blocked_sources=blocked_sources,
        terminal_source_keys=set(),
        terminal_source_handlers=set(),
        terminal_source_owned_blocks=set(),
        terminal_protected_blocks=set(),
        report_exit_handlers=set(),
        report_exit_owned_blocks=set(),
        bst_node_blocks=set(),
        dispatcher_region=set(),
        flow_graph=flow_graph,
        state_var_stkoff=None,
        dispatcher_lookup=None,
        mba=SimpleNamespace(entry_ea=0x401000),
    )

    assert blocked_sources == {126}
    assert any(
        isinstance(mod, EdgeRedirectViaPredSplit)
        and mod.src_block == 192
        and mod.via_pred == 126
        and mod.old_target == 2
        and mod.new_target == 7
        for mod in modifications
    )

    assert not LinearizedFlowGraphStrategy._emit_dag_redirect(
        edge=second_edge,
        dag=dag,
        builder=builder,
        modifications=modifications,
        owned_blocks=owned_blocks,
        owned_edges=owned_edges,
        owned_transitions=owned_transitions,
        emitted=emitted,
        claimed_1way={},
        claimed_2way={},
        claimed_exits=claimed_exits,
        claimed_path_edges=claimed_path_edges,
        blocked_sources=blocked_sources,
        terminal_source_keys=set(),
        terminal_source_handlers=set(),
        terminal_source_owned_blocks=set(),
        terminal_protected_blocks=set(),
        report_exit_handlers=set(),
        report_exit_owned_blocks=set(),
        bst_node_blocks=set(),
        dispatcher_region=set(),
        flow_graph=flow_graph,
        state_var_stkoff=None,
        dispatcher_lookup=None,
        mba=SimpleNamespace(entry_ea=0x401000),
    )
    assert not any(
        isinstance(mod, RedirectGoto) and mod.from_serial == 126
        for mod in modifications
    )


def test_lfg_plan_rewrites_shared_dispatch_tail_when_block_proves_target():
    source_node = StateDagNode(
        key=StateDagNodeKey(handler_serial=15, state_const=0x606DC166),
        kind=StateNodeKind.EXACT,
        state_label="0x606DC166",
        handler_serial=15,
        entry_anchor=15,
        owned_blocks=(15, 16, 17),
        exclusive_blocks=(15, 16, 17),
        shared_suffix_blocks=(),
        local_segments=(),
        local_edges=(),
    )
    target_node = StateDagNode(
        key=StateDagNodeKey(handler_serial=25, state_const=0x7FDCE054),
        kind=StateNodeKind.EXACT,
        state_label="0x7FDCE054",
        handler_serial=25,
        entry_anchor=25,
        owned_blocks=(25,),
        exclusive_blocks=(25,),
        shared_suffix_blocks=(),
        local_segments=(),
        local_edges=(),
    )
    dag = LinearizedStateDag(
        dispatcher_entry_serial=2,
        state_var_stkoff=0x3C,
        pre_header_serial=None,
        initial_state=None,
        bst_node_blocks=(2,),
        nodes=(source_node, target_node),
        edges=(
            StateDagEdge(
                kind=SemanticEdgeKind.CONDITIONAL_TRANSITION,
                source_key=source_node.key,
                target_key=target_node.key,
                target_state=0x7FDCE054,
                target_entry_anchor=25,
                target_label="0x7FDCE054",
                source_anchor=StateRedirectAnchor(
                    kind=RedirectSourceKind.CONDITIONAL_BRANCH,
                    block_serial=15,
                    branch_arm=1,
                ),
                ordered_path=(15, 17),
            ),
        ),
        diagnostics=(),
    )
    state_write = _FakeInsn(
        lfg_module.ida_hexrays.m_mov,
        l=_FakeMop(lfg_module.ida_hexrays.mop_n, value=0x7FDCE054),
        d=_FakeMop(lfg_module.ida_hexrays.mop_S, off=0x3C),
    )
    mba_blocks = [
        _FakeMBAFlowBlock(15, [16, 17], preds=[], head=None),
        _FakeMBAFlowBlock(16, [17], preds=[15], head=None),
        _FakeMBAFlowBlock(17, [2], preds=[15, 62], head=state_write),
        _FakeMBAFlowBlock(25, [], preds=[]),
        _FakeMBAFlowBlock(62, [17], preds=[]),
    ]
    flow_graph = _FakeFlowGraph(mba_blocks)
    fake_mba = _FakeMBA(blocks=mba_blocks)
    builder = ModificationBuilder.from_snapshot(
        SimpleNamespace(
            flow_graph=flow_graph,
            mba=fake_mba,
        )
    )
    modifications: list = []
    owned_blocks: set[int] = set()
    owned_edges: set[tuple[int, int]] = set()
    owned_transitions: set[tuple[int, int]] = set()
    emitted: set[tuple[int, int]] = set()

    assert SemanticStructuredRegionStrategy._emit_dag_redirect(
        edge=dag.edges[0],
        dag=dag,
        builder=builder,
        modifications=modifications,
        owned_blocks=owned_blocks,
        owned_edges=owned_edges,
        owned_transitions=owned_transitions,
        emitted=emitted,
        claimed_1way={},
        claimed_2way={},
        claimed_exits={},
        claimed_path_edges={},
        blocked_sources=set(),
        terminal_source_keys=set(),
        terminal_source_handlers=set(),
        terminal_source_owned_blocks=set(),
        terminal_protected_blocks=set(),
        report_exit_handlers=set(),
        report_exit_owned_blocks=set(),
        bst_node_blocks={2},
        dispatcher_region={2},
        flow_graph=flow_graph,
        state_var_stkoff=0x3C,
        dispatcher_lookup=lambda state: 25 if state == 0x7FDCE054 else None,
        mba=fake_mba,
    )
    assert any(
        isinstance(mod, RedirectGoto)
        and mod.from_serial == 17
        and mod.old_target == 2
        and mod.new_target == 25
        for mod in modifications
    )
    assert not any(
        isinstance(mod, EdgeRedirectViaPredSplit)
        and mod.src_block == 17
        for mod in modifications
    )


def test_lfg_plan_prefers_immediate_state_write_semantic_entry():
    source_node = StateDagNode(
        key=StateDagNodeKey(handler_serial=136, state_const=0x139F2922),
        kind=StateNodeKind.EXACT,
        state_label="0x139F2922",
        handler_serial=136,
        entry_anchor=136,
        owned_blocks=(136, 137, 139, 140),
        exclusive_blocks=(136, 137, 139, 140),
        shared_suffix_blocks=(),
        local_segments=(),
        local_edges=(),
    )
    handoff_node = StateDagNode(
        key=StateDagNodeKey(handler_serial=20, state_const=0x63F502FA),
        kind=StateNodeKind.EXACT,
        state_label="0x63D54755_fallback",
        handler_serial=20,
        entry_anchor=20,
        owned_blocks=(20, 69),
        exclusive_blocks=(20, 69),
        shared_suffix_blocks=(),
        local_segments=(),
        local_edges=(),
    )
    compressed_target = StateDagNode(
        key=StateDagNodeKey(handler_serial=23, state_const=0x6465D165),
        kind=StateNodeKind.EXACT,
        state_label="0x6465D165",
        handler_serial=23,
        entry_anchor=23,
        owned_blocks=(23, 24),
        exclusive_blocks=(23, 24),
        shared_suffix_blocks=(),
        local_segments=(),
        local_edges=(),
    )
    dag = LinearizedStateDag(
        dispatcher_entry_serial=2,
        state_var_stkoff=0x3C,
        pre_header_serial=None,
        initial_state=None,
        bst_node_blocks=(2,),
        nodes=(source_node, handoff_node, compressed_target),
        edges=(
            StateDagEdge(
                kind=SemanticEdgeKind.CONDITIONAL_TRANSITION,
                source_key=source_node.key,
                target_key=compressed_target.key,
                target_state=0x6465D165,
                target_entry_anchor=23,
                target_label="0x6465D165",
                source_anchor=StateRedirectAnchor(
                    kind=RedirectSourceKind.CONDITIONAL_BRANCH,
                    block_serial=139,
                    branch_arm=0,
                ),
                ordered_path=(136, 137, 139, 140),
            ),
        ),
        diagnostics=(),
    )
    state_write = _FakeInsn(
        lfg_module.ida_hexrays.m_mov,
        l=_FakeMop(lfg_module.ida_hexrays.mop_n, value=0x63F502FA),
        d=_FakeMop(lfg_module.ida_hexrays.mop_S, off=0x3C),
    )
    mba_blocks = [
        _FakeMBAFlowBlock(139, [141, 140], preds=[], head=None),
        _FakeMBAFlowBlock(140, [2], preds=[139], head=state_write),
        _FakeMBAFlowBlock(20, [69], preds=[], head=None),
        _FakeMBAFlowBlock(23, [24], preds=[], head=None),
        _FakeMBAFlowBlock(69, [2], preds=[20], head=None),
        _FakeMBAFlowBlock(24, [], preds=[23], head=None),
        _FakeMBAFlowBlock(2, [], preds=[140, 69]),
    ]
    flow_graph = _FakeFlowGraph(mba_blocks)
    fake_mba = _FakeMBA(blocks=mba_blocks)
    builder = ModificationBuilder.from_snapshot(
        SimpleNamespace(flow_graph=flow_graph, mba=fake_mba)
    )
    modifications: list = []

    assert SemanticStructuredRegionStrategy._emit_dag_redirect(
        edge=dag.edges[0],
        dag=dag,
        builder=builder,
        modifications=modifications,
        owned_blocks=set(),
        owned_edges=set(),
        owned_transitions=set(),
        emitted=set(),
        claimed_1way={},
        claimed_2way={},
        claimed_exits={},
        claimed_path_edges={},
        blocked_sources=set(),
        terminal_source_keys=set(),
        terminal_source_handlers=set(),
        terminal_source_owned_blocks=set(),
        terminal_protected_blocks=set(),
        report_exit_handlers=set(),
        report_exit_owned_blocks=set(),
        bst_node_blocks={2},
        dispatcher_region={2},
        flow_graph=flow_graph,
        state_var_stkoff=0x3C,
        dispatcher_lookup=None,
        mba=fake_mba,
    )
    assert any(
        isinstance(mod, RedirectGoto)
        and mod.from_serial == 140
        and mod.old_target == 2
        and mod.new_target == 20
        for mod in modifications
    )




def test_lfg_plan_does_not_fallback_to_stale_raw_target_after_semantic_entry_reject():
    source_node = StateDagNode(
        key=StateDagNodeKey(handler_serial=56, state_const=0x7D9C16EC),
        kind=StateNodeKind.EXACT,
        state_label="0x7D9C16EC",
        handler_serial=56,
        entry_anchor=56,
        owned_blocks=(56,),
        exclusive_blocks=(56,),
        shared_suffix_blocks=(),
        local_segments=(),
        local_edges=(),
    )
    target_node = StateDagNode(
        key=StateDagNodeKey(handler_serial=41, state_const=0x72AFE1BC),
        kind=StateNodeKind.EXACT,
        state_label="0x72AFE1BC",
        handler_serial=41,
        entry_anchor=41,
        owned_blocks=(41, 42),
        exclusive_blocks=(42,),
        shared_suffix_blocks=(),
        local_segments=(),
        local_edges=(),
    )
    dag = LinearizedStateDag(
        dispatcher_entry_serial=2,
        state_var_stkoff=0x3C,
        pre_header_serial=None,
        initial_state=None,
        bst_node_blocks=(41,),
        nodes=(source_node, target_node),
        edges=(
            StateDagEdge(
                kind=SemanticEdgeKind.TRANSITION,
                source_key=source_node.key,
                target_key=target_node.key,
                target_state=0x72AFE1BC,
                target_entry_anchor=41,
                target_label="0x72AFE1BC",
                source_anchor=StateRedirectAnchor(
                    kind=RedirectSourceKind.UNCONDITIONAL,
                    block_serial=56,
                ),
                ordered_path=(56,),
            ),
        ),
        diagnostics=(),
    )
    state_write = _FakeInsn(
        lfg_module.ida_hexrays.m_mov,
        l=_FakeMop(lfg_module.ida_hexrays.mop_n, value=0x72AFE1BC),
        d=_FakeMop(lfg_module.ida_hexrays.mop_S, off=0x3C),
    )
    mba_blocks = [
        _FakeMBAFlowBlock(56, [2], preds=[], head=state_write),
        _FakeMBAFlowBlock(2, [], preds=[56]),
        _FakeMBAFlowBlock(41, [], preds=[]),
        _FakeMBAFlowBlock(42, [56], preds=[], head=None),
    ]
    flow_graph = _FakeFlowGraph(mba_blocks)
    fake_mba = _FakeMBA(blocks=mba_blocks)
    builder = ModificationBuilder.from_snapshot(
        SimpleNamespace(flow_graph=flow_graph, mba=fake_mba)
    )
    modifications: list = []

    assert not LinearizedFlowGraphStrategy._emit_dag_redirect(
        edge=dag.edges[0],
        dag=dag,
        builder=builder,
        modifications=modifications,
        owned_blocks=set(),
        owned_edges=set(),
        owned_transitions=set(),
        emitted=set(),
        claimed_1way={},
        claimed_2way={},
        claimed_exits={},
        claimed_path_edges={},
        blocked_sources=set(),
        terminal_source_keys=set(),
        terminal_source_handlers=set(),
        terminal_source_owned_blocks=set(),
        terminal_protected_blocks=set(),
        report_exit_handlers=set(),
        report_exit_owned_blocks=set(),
        bst_node_blocks={41},
        dispatcher_region={2, 41},
        flow_graph=flow_graph,
        state_var_stkoff=0x3C,
        dispatcher_lookup=None,
        mba=fake_mba,
    )
    assert modifications == []


def test_lfg_plan_prefers_dag_entry_over_raw_dispatcher_lookup_for_handoff_block():
    source_node = StateDagNode(
        key=StateDagNodeKey(handler_serial=26, state_const=0x64AFC49D),
        kind=StateNodeKind.EXACT,
        state_label="0x64AFC49D",
        handler_serial=26,
        entry_anchor=26,
        owned_blocks=(26, 28, 33),
        exclusive_blocks=(26, 28, 33),
        shared_suffix_blocks=(),
        local_segments=(),
        local_edges=(),
    )
    target_node = StateDagNode(
        key=StateDagNodeKey(handler_serial=34, state_const=0x27EEEA11),
        kind=StateNodeKind.EXACT,
        state_label="0x64AFC49D_fallback",
        handler_serial=34,
        entry_anchor=34,
        owned_blocks=(34, 35),
        exclusive_blocks=(34, 35),
        shared_suffix_blocks=(),
        local_segments=(),
        local_edges=(),
    )
    dag = LinearizedStateDag(
        dispatcher_entry_serial=2,
        state_var_stkoff=0x3C,
        pre_header_serial=None,
        initial_state=None,
        bst_node_blocks=(2,),
        nodes=(source_node, target_node),
        edges=(
            StateDagEdge(
                kind=SemanticEdgeKind.CONDITIONAL_TRANSITION,
                source_key=source_node.key,
                target_key=target_node.key,
                target_state=0x27EEEA11,
                target_entry_anchor=34,
                target_label="0x64AFC49D_fallback",
                source_anchor=StateRedirectAnchor(
                    kind=RedirectSourceKind.CONDITIONAL_BRANCH,
                    block_serial=28,
                    branch_arm=0,
                ),
                ordered_path=(26, 28, 33),
            ),
        ),
        diagnostics=(),
    )
    state_write = _FakeInsn(
        lfg_module.ida_hexrays.m_mov,
        l=_FakeMop(lfg_module.ida_hexrays.mop_n, value=0x27EEEA11),
        d=_FakeMop(lfg_module.ida_hexrays.mop_S, off=0x3C),
    )
    mba_blocks = [
        _FakeMBAFlowBlock(28, [29, 33], preds=[26], head=None),
        _FakeMBAFlowBlock(33, [2], preds=[28], head=state_write),
        _FakeMBAFlowBlock(34, [35], preds=[25], head=None),
        _FakeMBAFlowBlock(35, [57], preds=[34], head=None),
        _FakeMBAFlowBlock(2, [], preds=[33]),
    ]
    flow_graph = _FakeFlowGraph(mba_blocks)
    fake_mba = _FakeMBA(blocks=mba_blocks)
    builder = ModificationBuilder.from_snapshot(
        SimpleNamespace(flow_graph=flow_graph, mba=fake_mba)
    )
    modifications: list = []

    assert LinearizedFlowGraphStrategy._emit_dag_redirect(
        edge=dag.edges[0],
        dag=dag,
        builder=builder,
        modifications=modifications,
        owned_blocks=set(),
        owned_edges=set(),
        owned_transitions=set(),
        emitted=set(),
        claimed_1way={},
        claimed_2way={},
        claimed_exits={},
        claimed_path_edges={},
        blocked_sources=set(),
        terminal_source_keys=set(),
        terminal_source_handlers=set(),
        terminal_source_owned_blocks=set(),
        terminal_protected_blocks=set(),
        report_exit_handlers=set(),
        report_exit_owned_blocks=set(),
        bst_node_blocks={2},
        dispatcher_region={2},
        flow_graph=flow_graph,
        state_var_stkoff=0x3C,
        dispatcher_lookup=lambda state: 24 if state == 0x27EEEA11 else None,
        mba=fake_mba,
    )
    assert any(
        isinstance(mod, RedirectGoto)
        and mod.from_serial == 33
        and mod.old_target == 2
        and mod.new_target == 34
        for mod in modifications
    )


def test_lfg_resolve_redirect_safe_entry_prefers_unique_outgoing_path_start_over_mux_anchor():
    target_node = StateDagNode(
        key=StateDagNodeKey(handler_serial=195, state_const=0x41FB8FBB),
        kind=StateNodeKind.EXACT,
        state_label="0x41FB8FBB_fallback",
        handler_serial=195,
        entry_anchor=195,
        owned_blocks=(195,),
        exclusive_blocks=(195,),
        shared_suffix_blocks=(),
        local_segments=(),
        local_edges=(),
    )
    dag = LinearizedStateDag(
        dispatcher_entry_serial=2,
        state_var_stkoff=0x3C,
        pre_header_serial=None,
        initial_state=None,
        bst_node_blocks=(2,),
        nodes=(target_node,),
        edges=(
            StateDagEdge(
                kind=SemanticEdgeKind.TRANSITION,
                source_key=target_node.key,
                target_key=None,
                target_state=0x11CD1DA3,
                target_entry_anchor=161,
                target_label="0x11CD1DA3",
                source_anchor=StateRedirectAnchor(
                    kind=RedirectSourceKind.UNCONDITIONAL,
                    block_serial=39,
                ),
                ordered_path=(39,),
            ),
        ),
        diagnostics=(),
    )

    assert (
        LinearizedFlowGraphStrategy._resolve_redirect_safe_entry_from_node(
            target_node,
            dag=dag,
            bst_node_blocks={2},
        )
        == 39
    )


def test_lfg_normalized_alias_entry_uses_redirect_safe_fallback_path_start():
    fallback_node = StateDagNode(
        key=StateDagNodeKey(handler_serial=195, state_const=0x41FB8FBB),
        kind=StateNodeKind.EXACT,
        state_label="0x41FB8FBB_fallback",
        handler_serial=195,
        entry_anchor=195,
        owned_blocks=(195,),
        exclusive_blocks=(195,),
        shared_suffix_blocks=(),
        local_segments=(),
        local_edges=(),
    )
    dag = LinearizedStateDag(
        dispatcher_entry_serial=2,
        state_var_stkoff=0x3C,
        pre_header_serial=None,
        initial_state=None,
        bst_node_blocks=(2,),
        nodes=(fallback_node,),
        edges=(
            StateDagEdge(
                kind=SemanticEdgeKind.TRANSITION,
                source_key=fallback_node.key,
                target_key=None,
                target_state=0x11CD1DA3,
                target_entry_anchor=161,
                target_label="0x11CD1DA3",
                source_anchor=StateRedirectAnchor(
                    kind=RedirectSourceKind.UNCONDITIONAL,
                    block_serial=39,
                ),
                ordered_path=(39,),
            ),
        ),
        diagnostics=(),
    )

    assert (
        LinearizedFlowGraphStrategy._resolve_normalized_alias_entry_for_state(
            dag,
            0x41FB8FBB,
            source_block=188,
            bst_node_blocks={2},
        )
        == 39
    )


def test_lfg_plan_prefers_contextual_dag_edge_target_for_alias_handoff():
    source_node = StateDagNode(
        key=StateDagNodeKey(handler_serial=93, state_const=0x42267E66),
        kind=StateNodeKind.EXACT,
        state_label="0x42267E66",
        handler_serial=93,
        entry_anchor=93,
        owned_blocks=(93, 95),
        exclusive_blocks=(93, 95),
        shared_suffix_blocks=(),
        local_segments=(),
        local_edges=(),
    )
    exact_node = StateDagNode(
        key=StateDagNodeKey(handler_serial=93, state_const=0x24E2E77A),
        kind=StateNodeKind.EXACT,
        state_label="0x24E2E77A",
        handler_serial=93,
        entry_anchor=93,
        owned_blocks=(93,),
        exclusive_blocks=(93,),
        shared_suffix_blocks=(),
        local_segments=(),
        local_edges=(),
    )
    fallback_node = StateDagNode(
        key=StateDagNodeKey(handler_serial=211, state_const=0x2315233C),
        kind=StateNodeKind.EXACT,
        state_label="0x2315233C_fallback",
        handler_serial=211,
        entry_anchor=211,
        owned_blocks=(211,),
        exclusive_blocks=(211,),
        shared_suffix_blocks=(),
        local_segments=(),
        local_edges=(),
    )
    dag = LinearizedStateDag(
        dispatcher_entry_serial=2,
        state_var_stkoff=0x3C,
        pre_header_serial=None,
        initial_state=None,
        bst_node_blocks=(2,),
        nodes=(source_node, exact_node, fallback_node),
        edges=(
            StateDagEdge(
                kind=SemanticEdgeKind.TRANSITION,
                source_key=source_node.key,
                target_key=fallback_node.key,
                target_state=0x24E2E77A,
                target_entry_anchor=211,
                target_label="0x2315233C_fallback",
                source_anchor=StateRedirectAnchor(
                    kind=RedirectSourceKind.UNCONDITIONAL,
                    block_serial=93,
                ),
                ordered_path=(93, 95),
            ),
        ),
        diagnostics=(),
    )
    state_write = _FakeInsn(
        lfg_module.ida_hexrays.m_mov,
        l=_FakeMop(lfg_module.ida_hexrays.mop_n, value=0x24E2E77A),
        d=_FakeMop(lfg_module.ida_hexrays.mop_S, off=0x3C),
    )
    mba_blocks = [
        _FakeMBAFlowBlock(93, [95], preds=[], head=None),
        _FakeMBAFlowBlock(95, [2], preds=[93], head=state_write),
        _FakeMBAFlowBlock(211, [35], preds=[], head=None),
        _FakeMBAFlowBlock(2, [], preds=[95]),
    ]
    flow_graph = _FakeFlowGraph(mba_blocks)
    fake_mba = _FakeMBA(blocks=mba_blocks)
    builder = ModificationBuilder.from_snapshot(
        SimpleNamespace(flow_graph=flow_graph, mba=fake_mba)
    )
    modifications: list = []

    assert LinearizedFlowGraphStrategy._emit_dag_redirect(
        edge=dag.edges[0],
        dag=dag,
        builder=builder,
        modifications=modifications,
        owned_blocks=set(),
        owned_edges=set(),
        owned_transitions=set(),
        emitted=set(),
        claimed_1way={},
        claimed_2way={},
        claimed_exits={},
        claimed_path_edges={},
        blocked_sources=set(),
        terminal_source_keys=set(),
        terminal_source_handlers=set(),
        terminal_source_owned_blocks=set(),
        terminal_protected_blocks=set(),
        report_exit_handlers=set(),
        report_exit_owned_blocks=set(),
        bst_node_blocks={2},
        dispatcher_region={2},
        flow_graph=flow_graph,
        state_var_stkoff=0x3C,
        dispatcher_lookup=lambda state: 93 if state == 0x24E2E77A else None,
        mba=fake_mba,
    )
    assert any(
        isinstance(mod, RedirectGoto)
        and mod.from_serial == 95
        and mod.old_target == 2
        and mod.new_target == 211
        for mod in modifications
    )


def test_lfg_target_resolution_prefers_edge_entry_over_target_key_entry():
    exact_node = StateDagNode(
        key=StateDagNodeKey(handler_serial=93, state_const=0x24E2E77A),
        kind=StateNodeKind.EXACT,
        state_label="0x24E2E77A",
        handler_serial=93,
        entry_anchor=93,
        owned_blocks=(93,),
        exclusive_blocks=(93,),
        shared_suffix_blocks=(),
        local_segments=(),
        local_edges=(),
    )
    fallback_node = StateDagNode(
        key=StateDagNodeKey(handler_serial=211, state_const=0x2315233C),
        kind=StateNodeKind.EXACT,
        state_label="0x2315233C_fallback",
        handler_serial=211,
        entry_anchor=211,
        owned_blocks=(211,),
        exclusive_blocks=(211,),
        shared_suffix_blocks=(),
        local_segments=(),
        local_edges=(),
    )
    dag = LinearizedStateDag(
        dispatcher_entry_serial=2,
        state_var_stkoff=0x3C,
        pre_header_serial=None,
        initial_state=None,
        bst_node_blocks=(2,),
        nodes=(exact_node, fallback_node),
        edges=(
            StateDagEdge(
                kind=SemanticEdgeKind.TRANSITION,
                source_key=fallback_node.key,
                target_key=exact_node.key,
                target_state=0x24E2E77A,
                target_entry_anchor=211,
                target_label="0x2315233C_fallback",
                source_anchor=StateRedirectAnchor(
                    kind=RedirectSourceKind.UNCONDITIONAL,
                    block_serial=95,
                ),
                ordered_path=(93, 95),
            ),
        ),
        diagnostics=(),
    )

    assert (
        LinearizedFlowGraphStrategy._resolve_redirect_safe_target_entry(
            dag,
            dag.edges[0],
            bst_node_blocks={2},
        )
        == 93
    )


def test_lfg_target_resolution_uses_labeled_fallback_node_when_target_key_missing():
    fallback_node = StateDagNode(
        key=StateDagNodeKey(handler_serial=80, state_const=0x432DC789),
        kind=StateNodeKind.EXACT,
        state_label="0x432DC789_fallback",
        handler_serial=80,
        entry_anchor=80,
        owned_blocks=(80,),
        exclusive_blocks=(80,),
        shared_suffix_blocks=(),
        local_segments=(),
        local_edges=(),
    )
    dag = LinearizedStateDag(
        dispatcher_entry_serial=2,
        state_var_stkoff=0x3C,
        pre_header_serial=None,
        initial_state=None,
        bst_node_blocks=(2,),
        nodes=(fallback_node,),
        edges=(
            StateDagEdge(
                kind=SemanticEdgeKind.CONDITIONAL_TRANSITION,
                source_key=StateDagNodeKey(handler_serial=81, state_const=0x5FE86821),
                target_key=None,
                target_state=0x45B18E82,
                target_entry_anchor=63,
                target_label="0x432DC789_fallback",
                source_anchor=StateRedirectAnchor(
                    kind=RedirectSourceKind.CONDITIONAL_BRANCH,
                    block_serial=81,
                    branch_arm=0,
                ),
                ordered_path=(81, 82),
            ),
        ),
        diagnostics=(),
    )

    assert (
        LinearizedFlowGraphStrategy._resolve_redirect_safe_target_entry(
            dag,
            dag.edges[0],
            bst_node_blocks={2},
        )
        == 80
    )


def test_lfg_target_resolution_prefers_labeled_fallback_node_over_exact_alias_target():
    alias_node = StateDagNode(
        key=StateDagNodeKey(handler_serial=81, state_const=0x45B18E82),
        kind=StateNodeKind.EXACT,
        state_label="0x45B18E82",
        handler_serial=81,
        entry_anchor=81,
        owned_blocks=(81, 82),
        exclusive_blocks=(81, 82),
        shared_suffix_blocks=(),
        local_segments=(),
        local_edges=(),
    )
    fallback_node = StateDagNode(
        key=StateDagNodeKey(handler_serial=80, state_const=0x432DC789),
        kind=StateNodeKind.EXACT,
        state_label="0x432DC789_fallback",
        handler_serial=80,
        entry_anchor=80,
        owned_blocks=(80,),
        exclusive_blocks=(80,),
        shared_suffix_blocks=(),
        local_segments=(),
        local_edges=(),
    )
    dag = LinearizedStateDag(
        dispatcher_entry_serial=2,
        state_var_stkoff=0x3C,
        pre_header_serial=None,
        initial_state=None,
        bst_node_blocks=(2,),
        nodes=(alias_node, fallback_node),
        edges=(
            StateDagEdge(
                kind=SemanticEdgeKind.CONDITIONAL_TRANSITION,
                source_key=StateDagNodeKey(handler_serial=81, state_const=0x5FE86821),
                target_key=alias_node.key,
                target_state=0x45B18E82,
                target_entry_anchor=81,
                target_label="0x432DC789_fallback",
                source_anchor=StateRedirectAnchor(
                    kind=RedirectSourceKind.CONDITIONAL_BRANCH,
                    block_serial=81,
                    branch_arm=0,
                ),
                ordered_path=(81, 82),
            ),
        ),
        diagnostics=(),
    )

    assert (
        LinearizedFlowGraphStrategy._resolve_redirect_safe_target_entry(
            dag,
            dag.edges[0],
            bst_node_blocks={2},
        )
        == 80
    )


def test_lfg_immediate_handoff_prefers_dispatcher_target_over_ad_hoc_cover_fallback():
    fallback_node = StateDagNode(
        key=StateDagNodeKey(handler_serial=80, state_const=0x432DC789),
        kind=StateNodeKind.EXACT,
        state_label="0x432DC789_fallback",
        handler_serial=80,
        entry_anchor=80,
        owned_blocks=(80,),
        exclusive_blocks=(80,),
        shared_suffix_blocks=(),
        local_segments=(),
        local_edges=(),
    )
    dag = LinearizedStateDag(
        dispatcher_entry_serial=2,
        state_var_stkoff=0x3C,
        pre_header_serial=None,
        initial_state=None,
        bst_node_blocks=(2,),
        nodes=(fallback_node,),
        edges=(),
        diagnostics=(),
    )
    state_write = _FakeInsn(
        lfg_module.ida_hexrays.m_mov,
        l=_FakeMop(lfg_module.ida_hexrays.mop_n, value=0x45B18E82),
        d=_FakeMop(lfg_module.ida_hexrays.mop_S, off=0x3C),
    )
    mba_blocks = [_FakeMBAFlowBlock(82, [2], preds=[81], head=state_write)]
    fake_mba = _FakeMBA(blocks=mba_blocks)
    dispatcher = SimpleNamespace(
        _rows=(
            SimpleNamespace(lo=0x432DC789, hi=0x432DC78A, target=62),
            SimpleNamespace(lo=0x432DC78A, hi=0x474EEEBB, target=63),
        )
    )

    assert (
        LinearizedFlowGraphStrategy._resolve_immediate_handoff_target(
            dag,
            fake_mba,
            82,
            state_var_stkoff=0x3C,
            bst_node_blocks={2},
            dispatcher_lookup=lambda state: 63 if state == 0x45B18E82 else None,
            dispatcher=dispatcher,
        )
        == (0x45B18E82, 63)
    )


def test_lfg_immediate_handoff_prefers_dispatcher_target_over_raw_alias_node():
    alias_node = StateDagNode(
        key=StateDagNodeKey(handler_serial=170, state_const=0x24E2E77A),
        kind=StateNodeKind.EXACT,
        state_label="0x24E2E77A",
        handler_serial=170,
        entry_anchor=170,
        owned_blocks=(170,),
        exclusive_blocks=(170,),
        shared_suffix_blocks=(),
        local_segments=(),
        local_edges=(),
    )
    fallback_node = StateDagNode(
        key=StateDagNodeKey(handler_serial=211, state_const=0x2315233C),
        kind=StateNodeKind.EXACT,
        state_label="0x2315233C_fallback",
        handler_serial=211,
        entry_anchor=211,
        owned_blocks=(211,),
        exclusive_blocks=(211,),
        shared_suffix_blocks=(),
        local_segments=(),
        local_edges=(),
    )
    dag = LinearizedStateDag(
        dispatcher_entry_serial=2,
        state_var_stkoff=0x3C,
        pre_header_serial=None,
        initial_state=None,
        bst_node_blocks=(2,),
        nodes=(alias_node, fallback_node),
        edges=(),
        diagnostics=(),
    )
    state_write = _FakeInsn(
        lfg_module.ida_hexrays.m_mov,
        l=_FakeMop(lfg_module.ida_hexrays.mop_n, value=0x24E2E77A),
        d=_FakeMop(lfg_module.ida_hexrays.mop_S, off=0x3C),
    )
    fake_mba = _FakeMBA(blocks=[_FakeMBAFlowBlock(95, [2], preds=[93], head=state_write)])
    dispatcher = SimpleNamespace(
        _rows=(
            SimpleNamespace(lo=0x2315233C, hi=0x2315233D, target=211),
            SimpleNamespace(lo=0x2315233D, hi=0x258ED455, target=212),
        )
    )

    assert (
        LinearizedFlowGraphStrategy._resolve_immediate_handoff_target(
            dag,
            fake_mba,
            95,
            state_var_stkoff=0x3C,
            bst_node_blocks={2},
            dispatcher_lookup=lambda state: 170 if state == 0x24E2E77A else None,
            dispatcher=dispatcher,
        )
        == (0x24E2E77A, 170)
    )


def test_lfg_immediate_handoff_uses_dag_fallback_when_dispatcher_rows_are_degenerate():
    alias_node = StateDagNode(
        key=StateDagNodeKey(handler_serial=81, state_const=0x45B18E82),
        kind=StateNodeKind.EXACT,
        state_label="0x45B18E82",
        handler_serial=81,
        entry_anchor=81,
        owned_blocks=(81, 82),
        exclusive_blocks=(81, 82),
        shared_suffix_blocks=(),
        local_segments=(),
        local_edges=(),
    )
    fallback_node = StateDagNode(
        key=StateDagNodeKey(handler_serial=63, state_const=0x432DC789),
        kind=StateNodeKind.EXACT,
        state_label="0x432DC789_fallback",
        handler_serial=63,
        entry_anchor=63,
        owned_blocks=(63, 64),
        exclusive_blocks=(63, 64),
        shared_suffix_blocks=(),
        local_segments=(),
        local_edges=(),
    )
    dag = LinearizedStateDag(
        dispatcher_entry_serial=2,
        state_var_stkoff=0x3C,
        pre_header_serial=None,
        initial_state=None,
        bst_node_blocks=(2,),
        nodes=(alias_node, fallback_node),
        edges=(
            StateDagEdge(
                kind=SemanticEdgeKind.TRANSITION,
                source_key=alias_node.key,
                target_key=fallback_node.key,
                target_state=0x45B18E82,
                target_entry_anchor=63,
                target_label="0x432DC789_fallback",
                source_anchor=StateRedirectAnchor(
                    kind=RedirectSourceKind.UNCONDITIONAL,
                    block_serial=81,
                ),
                ordered_path=(81, 82),
            ),
        ),
        diagnostics=(),
    )
    state_write = _FakeInsn(
        lfg_module.ida_hexrays.m_mov,
        l=_FakeMop(lfg_module.ida_hexrays.mop_n, value=0x45B18E82),
        d=_FakeMop(lfg_module.ida_hexrays.mop_S, off=0x3C),
    )
    fake_mba = _FakeMBA(blocks=[_FakeMBAFlowBlock(82, [2], preds=[81], head=state_write)])
    dispatcher = SimpleNamespace(
        _rows=(SimpleNamespace(lo=0x0, hi=0x100000000, target=2),)
    )

    assert (
        LinearizedFlowGraphStrategy._resolve_immediate_handoff_target(
            dag,
            fake_mba,
            82,
            state_var_stkoff=0x3C,
            bst_node_blocks={2},
            dispatcher_lookup=lambda state: None,
            dispatcher=dispatcher,
        )
        == (0x45B18E82, 81)
    )


def test_lfg_immediate_handoff_uses_dag_fallback_for_raw_alias_with_degenerate_dispatcher():
    alias_node = StateDagNode(
        key=StateDagNodeKey(handler_serial=93, state_const=0x24E2E77A),
        kind=StateNodeKind.EXACT,
        state_label="0x24E2E77A",
        handler_serial=93,
        entry_anchor=93,
        owned_blocks=(93, 95),
        exclusive_blocks=(93, 95),
        shared_suffix_blocks=(),
        local_segments=(),
        local_edges=(),
    )
    fallback_node = StateDagNode(
        key=StateDagNodeKey(handler_serial=211, state_const=0x2315233C),
        kind=StateNodeKind.EXACT,
        state_label="0x2315233C_fallback",
        handler_serial=211,
        entry_anchor=211,
        owned_blocks=(211,),
        exclusive_blocks=(211,),
        shared_suffix_blocks=(),
        local_segments=(),
        local_edges=(),
    )
    dag = LinearizedStateDag(
        dispatcher_entry_serial=2,
        state_var_stkoff=0x3C,
        pre_header_serial=None,
        initial_state=None,
        bst_node_blocks=(2,),
        nodes=(alias_node, fallback_node),
        edges=(
            StateDagEdge(
                kind=SemanticEdgeKind.TRANSITION,
                source_key=alias_node.key,
                target_key=fallback_node.key,
                target_state=0x24E2E77A,
                target_entry_anchor=211,
                target_label="0x2315233C_fallback",
                source_anchor=StateRedirectAnchor(
                    kind=RedirectSourceKind.UNCONDITIONAL,
                    block_serial=93,
                ),
                ordered_path=(93, 95),
            ),
        ),
        diagnostics=(),
    )
    state_write = _FakeInsn(
        lfg_module.ida_hexrays.m_mov,
        l=_FakeMop(lfg_module.ida_hexrays.mop_n, value=0x24E2E77A),
        d=_FakeMop(lfg_module.ida_hexrays.mop_S, off=0x3C),
    )
    fake_mba = _FakeMBA(blocks=[_FakeMBAFlowBlock(95, [2], preds=[93], head=state_write)])
    dispatcher = SimpleNamespace(
        _rows=(SimpleNamespace(lo=0x0, hi=0x100000000, target=2),)
    )

    assert (
        LinearizedFlowGraphStrategy._resolve_immediate_handoff_target(
            dag,
            fake_mba,
            95,
            state_var_stkoff=0x3C,
            bst_node_blocks={2},
            dispatcher_lookup=lambda state: None,
            dispatcher=dispatcher,
        )
        == (0x24E2E77A, 93)
    )


def test_lfg_immediate_handoff_prefers_normalized_alias_edge_over_raw_alias_node():
    source_node = StateDagNode(
        key=StateDagNodeKey(handler_serial=89, state_const=0x42267E66),
        kind=StateNodeKind.EXACT,
        state_label="0x42267E66",
        handler_serial=89,
        entry_anchor=89,
        owned_blocks=(89, 90),
        exclusive_blocks=(89, 90),
        shared_suffix_blocks=(),
        local_segments=(),
        local_edges=(),
    )
    alias_node = StateDagNode(
        key=StateDagNodeKey(handler_serial=93, state_const=0x24E2E77A),
        kind=StateNodeKind.EXACT,
        state_label="0x24E2E77A",
        handler_serial=93,
        entry_anchor=93,
        owned_blocks=(93, 95),
        exclusive_blocks=(93, 95),
        shared_suffix_blocks=(),
        local_segments=(),
        local_edges=(),
    )
    fallback_node = StateDagNode(
        key=StateDagNodeKey(handler_serial=202, state_const=0x24E2E77A),
        kind=StateNodeKind.EXACT,
        state_label="0x2315233C_fallback",
        handler_serial=202,
        entry_anchor=202,
        owned_blocks=(202,),
        exclusive_blocks=(202,),
        shared_suffix_blocks=(),
        local_segments=(),
        local_edges=(),
    )
    dag = LinearizedStateDag(
        dispatcher_entry_serial=2,
        state_var_stkoff=0x3C,
        pre_header_serial=None,
        initial_state=None,
        bst_node_blocks=(2,),
        nodes=(source_node, alias_node, fallback_node),
        edges=(
            StateDagEdge(
                kind=SemanticEdgeKind.TRANSITION,
                source_key=source_node.key,
                target_key=fallback_node.key,
                target_state=0x24E2E77A,
                target_entry_anchor=202,
                target_label="0x2315233C_fallback",
                source_anchor=StateRedirectAnchor(
                    kind=RedirectSourceKind.UNCONDITIONAL,
                    block_serial=89,
                ),
                ordered_path=(89, 90),
            ),
        ),
        diagnostics=(),
    )
    state_write = _FakeInsn(
        lfg_module.ida_hexrays.m_mov,
        l=_FakeMop(lfg_module.ida_hexrays.mop_n, value=0x24E2E77A),
        d=_FakeMop(lfg_module.ida_hexrays.mop_S, off=0x3C),
    )
    fake_mba = _FakeMBA(blocks=[_FakeMBAFlowBlock(95, [2], preds=[93], head=state_write)])
    dispatcher = SimpleNamespace(
        _rows=(
            SimpleNamespace(lo=0x2315233C, hi=0x2315233D, target=211),
            SimpleNamespace(lo=0x2315233D, hi=0x258ED455, target=212),
        )
    )

    assert (
        LinearizedFlowGraphStrategy._resolve_immediate_handoff_target(
            dag,
            fake_mba,
            95,
            state_var_stkoff=0x3C,
            bst_node_blocks={2},
            dispatcher_lookup=lambda state: 93 if state == 0x24E2E77A else None,
            dispatcher=dispatcher,
        )
        == (0x24E2E77A, 93)
    )


def test_lfg_immediate_handoff_ignores_exact_self_entry_assert_block():
    current_node = StateDagNode(
        key=StateDagNodeKey(handler_serial=131, state_const=0x0ACD0BD5),
        kind=StateNodeKind.EXACT,
        state_label="0x0ACD0BD5",
        handler_serial=131,
        entry_anchor=131,
        owned_blocks=(131, 174, 176, 199),
        exclusive_blocks=(131, 174, 176),
        shared_suffix_blocks=(199,),
        local_segments=(),
        local_edges=(),
    )
    neighbor_node = StateDagNode(
        key=StateDagNodeKey(handler_serial=132, state_const=0x09EB3382),
        kind=StateNodeKind.EXACT,
        state_label="0x09EB3382",
        handler_serial=132,
        entry_anchor=132,
        owned_blocks=(132,),
        exclusive_blocks=(132,),
        shared_suffix_blocks=(),
        local_segments=(),
        local_edges=(),
    )
    dag = LinearizedStateDag(
        dispatcher_entry_serial=2,
        state_var_stkoff=0x3C,
        pre_header_serial=None,
        initial_state=None,
        bst_node_blocks=(2,),
        nodes=(current_node, neighbor_node),
        edges=(
            StateDagEdge(
                kind=SemanticEdgeKind.CONDITIONAL_TRANSITION,
                source_key=StateDagNodeKey(handler_serial=147, state_const=0x149F5A98),
                target_key=current_node.key,
                target_state=0x0ACD0BD5,
                target_entry_anchor=131,
                target_label="0x0ACD0BD5",
                source_anchor=StateRedirectAnchor(
                    kind=RedirectSourceKind.CONDITIONAL_BRANCH,
                    block_serial=147,
                    branch_arm=0,
                ),
                ordered_path=(147, 148),
            ),
        ),
        diagnostics=(),
    )
    state_write = _FakeInsn(
        lfg_module.ida_hexrays.m_mov,
        l=_FakeMop(lfg_module.ida_hexrays.mop_n, value=0x0ACD0BD5),
        d=_FakeMop(lfg_module.ida_hexrays.mop_S, off=0x3C),
    )
    fake_mba = _FakeMBA(
        blocks=[_FakeMBAFlowBlock(131, [174], preds=[129, 148], head=state_write)]
    )
    dispatcher = SimpleNamespace(
        _rows=(
            SimpleNamespace(lo=0x09EB3382, hi=0x09EB3383, target=132),
            SimpleNamespace(lo=0x09EB3383, hi=0x0ACD0BD5, target=130),
            SimpleNamespace(lo=0x0ACD0BD5, hi=0x0ACD0BD6, target=131),
            SimpleNamespace(lo=0x0ACD0BD6, hi=0x0D64F20F, target=130),
        )
    )

    assert (
        LinearizedFlowGraphStrategy._resolve_immediate_handoff_target(
            dag,
            fake_mba,
            131,
            state_var_stkoff=0x3C,
            bst_node_blocks={2},
            dispatcher_lookup=lambda state: 131 if state == 0x0ACD0BD5 else None,
            dispatcher=dispatcher,
        )
        is None
    )


def test_lfg_immediate_handoff_prefers_exact_entry_over_contextual_fallback_family():
    exact_node = StateDagNode(
        key=StateDagNodeKey(handler_serial=23, state_const=0x6465D165),
        kind=StateNodeKind.EXACT,
        state_label="0x6465D165",
        handler_serial=23,
        entry_anchor=23,
        owned_blocks=(23, 24),
        exclusive_blocks=(23, 24),
        shared_suffix_blocks=(),
        local_segments=(),
        local_edges=(),
    )
    fallback_node = StateDagNode(
        key=StateDagNodeKey(handler_serial=72, state_const=0x4E69F350),
        kind=StateNodeKind.EXACT,
        state_label="0x37B42A3F_fallback",
        handler_serial=72,
        entry_anchor=72,
        owned_blocks=(72,),
        exclusive_blocks=(72,),
        shared_suffix_blocks=(),
        local_segments=(),
        local_edges=(),
    )
    dag = LinearizedStateDag(
        dispatcher_entry_serial=2,
        state_var_stkoff=0x3C,
        pre_header_serial=None,
        initial_state=None,
        bst_node_blocks=(2,),
        nodes=(exact_node, fallback_node),
        edges=(
            StateDagEdge(
                kind=SemanticEdgeKind.TRANSITION,
                source_key=StateDagNodeKey(handler_serial=131, state_const=0x0ACD0BD5),
                target_key=fallback_node.key,
                target_state=0x6465D165,
                    target_entry_anchor=72,
                    target_label="0x37B42A3F_fallback",
                    source_anchor=StateRedirectAnchor(
                        kind=RedirectSourceKind.UNCONDITIONAL,
                        block_serial=176,
                    ),
                ordered_path=(176, 200),
            ),
        ),
        diagnostics=(),
    )
    state_write = _FakeInsn(
        lfg_module.ida_hexrays.m_mov,
        l=_FakeMop(lfg_module.ida_hexrays.mop_n, value=0x6465D165),
        d=_FakeMop(lfg_module.ida_hexrays.mop_S, off=0x3C),
    )
    fake_mba = _FakeMBA(
        blocks=[_FakeMBAFlowBlock(200, [2], preds=[176], head=state_write)]
    )
    dispatcher = SimpleNamespace(
        _rows=(
            SimpleNamespace(lo=0x6465D165, hi=0x6465D166, target=23),
        )
    )

    assert (
        LinearizedFlowGraphStrategy._resolve_immediate_handoff_target(
            dag,
            fake_mba,
            200,
            state_var_stkoff=0x3C,
            bst_node_blocks={2},
            dispatcher_lookup=lambda state: 23 if state == 0x6465D165 else None,
            dispatcher=dispatcher,
        )
        == (0x6465D165, 23)
    )


def test_lfg_effective_target_preserves_concrete_nonexact_dag_target(monkeypatch):
    source_node = StateDagNode(
        key=StateDagNodeKey(handler_serial=62, state_const=0x432DC789),
        kind=StateNodeKind.EXACT,
        state_label="0x432DC789",
        handler_serial=62,
        entry_anchor=62,
        owned_blocks=(62,),
        exclusive_blocks=(62,),
        shared_suffix_blocks=(),
        local_segments=(),
        local_edges=(),
    )
    raw_target_node = StateDagNode(
        key=StateDagNodeKey(handler_serial=205, state_const=0x298372CC),
        kind=StateNodeKind.EXACT,
        state_label="0x298372CC",
        handler_serial=205,
        entry_anchor=205,
        owned_blocks=(205, 206, 207),
        exclusive_blocks=(205, 206, 207),
        shared_suffix_blocks=(),
        local_segments=(),
        local_edges=(),
    )
    dag = LinearizedStateDag(
        dispatcher_entry_serial=2,
        state_var_stkoff=0x3C,
        pre_header_serial=None,
        initial_state=None,
        bst_node_blocks=(2,),
        nodes=(source_node, raw_target_node),
        edges=(
            StateDagEdge(
                kind=SemanticEdgeKind.TRANSITION,
                source_key=source_node.key,
                target_key=raw_target_node.key,
                target_state=0x298372CC,
                target_entry_anchor=206,
                target_label="0x298372CC",
                source_anchor=StateRedirectAnchor(
                    kind=RedirectSourceKind.UNCONDITIONAL,
                    block_serial=62,
                ),
                ordered_path=(62,),
            ),
        ),
        diagnostics=(),
    )
    edge = dag.edges[0]
    dispatcher = SimpleNamespace(
        _rows=(
            SimpleNamespace(lo=0x296F2453, hi=0x2981423A, target=206),
            SimpleNamespace(lo=0x2981423A, hi=0x2981423B, target=205),
            SimpleNamespace(lo=0x2981423B, hi=0x2A5ADB57, target=206),
        )
    )

    monkeypatch.setattr(
        LinearizedFlowGraphStrategy,
        "_resolve_immediate_handoff_target",
        classmethod(lambda cls, *args, **kwargs: (0x298372CC, 81)),
    )
    monkeypatch.setattr(
        LinearizedFlowGraphStrategy,
        "_resolve_synthesized_handoff_target",
        classmethod(lambda cls, *args, **kwargs: None),
    )

    assert (
        LinearizedFlowGraphStrategy._resolve_effective_target_entry(
            dag,
            edge,
            bst_node_blocks={2},
            state_var_stkoff=0x3C,
            dispatcher_lookup=lambda state: 206 if state == 0x298372CC else None,
            dispatcher=dispatcher,
            mba=_FakeMBA(blocks=[]),
        )
        == 205
    )


def test_lfg_immediate_handoff_uses_projected_flowgraph_mba_view_for_exact_state_write():
    exact_node = StateDagNode(
        key=StateDagNodeKey(handler_serial=23, state_const=0x6465D165),
        kind=StateNodeKind.EXACT,
        state_label="0x6465D165",
        handler_serial=23,
        entry_anchor=23,
        owned_blocks=(23, 24),
        exclusive_blocks=(23, 24),
        shared_suffix_blocks=(),
        local_segments=(),
        local_edges=(),
    )
    dag = LinearizedStateDag(
        dispatcher_entry_serial=2,
        state_var_stkoff=0x3C,
        pre_header_serial=None,
        initial_state=None,
        bst_node_blocks=(2,),
        nodes=(exact_node,),
        edges=(),
        diagnostics=(),
    )
    projected_cfg = FlowGraph(
        blocks={
            200: BlockSnapshot(
                serial=200,
                block_type=1,
                succs=(2,),
                preds=(176, 199),
                flags=0,
                start_ea=0x1800160EF,
                insn_snapshots=(
                    InsnSnapshot(
                        opcode=lfg_module.ida_hexrays.m_mov,
                        ea=0x180016137,
                        operands=(),
                        l=MopSnapshot(
                            t=lfg_module.ida_hexrays.mop_n,
                            value=0x6465D165,
                            size=4,
                        ),
                        d=MopSnapshot(
                            t=lfg_module.ida_hexrays.mop_S,
                            stkoff=0x3C,
                            size=4,
                        ),
                    ),
                    InsnSnapshot(
                        opcode=lfg_module.ida_hexrays.m_goto,
                        ea=0x18001613F,
                        operands=(),
                    ),
                ),
            ),
            2: BlockSnapshot(
                serial=2,
                block_type=2,
                succs=(3, 112),
                preds=(200,),
                flags=0,
                start_ea=0x180012BA3,
                insn_snapshots=(),
            ),
        },
        entry_serial=200,
        func_ea=0x180012B60,
    )
    projected_mba = build_mba_view_from_flow_graph(projected_cfg)
    dispatcher = SimpleNamespace(
        _rows=(
            SimpleNamespace(lo=0x6465D165, hi=0x6465D166, target=23),
        )
    )

    assert (
        LinearizedFlowGraphStrategy._resolve_immediate_handoff_target(
            dag,
            projected_mba,
            200,
            state_var_stkoff=0x3C,
            bst_node_blocks={2},
            dispatcher_lookup=lambda state: 23 if state == 0x6465D165 else None,
            dispatcher=dispatcher,
        )
        == (0x6465D165, 23)
    )


def test_lfg_projected_snapshot_handoff_resolves_exact_state_write():
    exact_node = StateDagNode(
        key=StateDagNodeKey(handler_serial=23, state_const=0x6465D165),
        kind=StateNodeKind.EXACT,
        state_label="0x6465D165",
        handler_serial=23,
        entry_anchor=23,
        owned_blocks=(23, 24),
        exclusive_blocks=(23, 24),
        shared_suffix_blocks=(),
        local_segments=(),
        local_edges=(),
    )
    dag = LinearizedStateDag(
        dispatcher_entry_serial=2,
        state_var_stkoff=0x3C,
        pre_header_serial=None,
        initial_state=None,
        bst_node_blocks=(2,),
        nodes=(exact_node,),
        edges=(),
        diagnostics=(),
    )
    projected_cfg = FlowGraph(
        blocks={
            200: BlockSnapshot(
                serial=200,
                block_type=1,
                succs=(2,),
                preds=(176, 199),
                flags=0,
                start_ea=0x1800160EF,
                insn_snapshots=(
                    InsnSnapshot(
                        opcode=lfg_module.ida_hexrays.m_mov,
                        ea=0x180016137,
                        operands=(),
                        l=MopSnapshot(
                            t=lfg_module.ida_hexrays.mop_n,
                            value=0x6465D165,
                            size=4,
                        ),
                        d=MopSnapshot(
                            t=lfg_module.ida_hexrays.mop_S,
                            stkoff=0x3C,
                            size=4,
                        ),
                    ),
                    InsnSnapshot(
                        opcode=lfg_module.ida_hexrays.m_goto,
                        ea=0x18001613F,
                        operands=(),
                    ),
                ),
            ),
            2: BlockSnapshot(
                serial=2,
                block_type=2,
                succs=(3, 112),
                preds=(200,),
                flags=0,
                start_ea=0x180012BA3,
                insn_snapshots=(),
            ),
        },
        entry_serial=200,
        func_ea=0x180012B60,
    )
    dispatcher = SimpleNamespace(
        _rows=(
            SimpleNamespace(lo=0x6465D165, hi=0x6465D166, target=23),
        )
    )

    assert (
        LinearizedFlowGraphStrategy._resolve_projected_snapshot_handoff_target(
            dag,
            projected_cfg,
            200,
            state_var_stkoff=0x3C,
            bst_node_blocks={2},
            dispatcher=dispatcher,
        )
        == (0x6465D165, 23)
    )


def test_lfg_assignment_map_handoff_resolves_exact_state_write():
    exact_node = StateDagNode(
        key=StateDagNodeKey(handler_serial=23, state_const=0x6465D165),
        kind=StateNodeKind.EXACT,
        state_label="0x6465D165",
        handler_serial=23,
        entry_anchor=23,
        owned_blocks=(23, 24),
        exclusive_blocks=(23, 24),
        shared_suffix_blocks=(),
        local_segments=(),
        local_edges=(),
    )
    dag = LinearizedStateDag(
        dispatcher_entry_serial=2,
        state_var_stkoff=0x3C,
        pre_header_serial=None,
        initial_state=None,
        bst_node_blocks=(2,),
        nodes=(exact_node,),
        edges=(),
        diagnostics=(),
    )
    state_write = _FakeInsn(
        lfg_module.ida_hexrays.m_mov,
        l=_FakeMop(lfg_module.ida_hexrays.mop_n, value=0x6465D165),
        d=_FakeMop(lfg_module.ida_hexrays.mop_S, off=0x3C),
    )
    dispatcher = SimpleNamespace(
        _rows=(
            SimpleNamespace(lo=0x6465D165, hi=0x6465D166, target=23),
        )
    )
    sm = DispatcherStateMachine(
        mba=None,
        assignment_map={200: [state_write]},
    )

    assert (
        LinearizedFlowGraphStrategy._resolve_assignment_map_handoff_target(
            dag,
            sm,
            200,
            bst_node_blocks={2},
            dispatcher=dispatcher,
        )
        == (0x6465D165, 23)
    )


def test_lfg_synthesized_handoff_prefers_exact_entry_over_contextual_fallback_family():
    exact_node = StateDagNode(
        key=StateDagNodeKey(handler_serial=44, state_const=0x6B588049),
        kind=StateNodeKind.EXACT,
        state_label="0x6B588049",
        handler_serial=44,
        entry_anchor=44,
        owned_blocks=(44,),
        exclusive_blocks=(44,),
        shared_suffix_blocks=(),
        local_segments=(),
        local_edges=(),
    )
    fallback_node = StateDagNode(
        key=StateDagNodeKey(handler_serial=72, state_const=0x4E69F350),
        kind=StateNodeKind.EXACT,
        state_label="0x37B42A3F_fallback",
        handler_serial=72,
        entry_anchor=72,
        owned_blocks=(72,),
        exclusive_blocks=(72,),
        shared_suffix_blocks=(),
        local_segments=(),
        local_edges=(),
    )
    dag = LinearizedStateDag(
        dispatcher_entry_serial=2,
        state_var_stkoff=0x3C,
        pre_header_serial=None,
        initial_state=None,
        bst_node_blocks=(2,),
        nodes=(exact_node, fallback_node),
        edges=(
            StateDagEdge(
                kind=SemanticEdgeKind.TRANSITION,
                source_key=StateDagNodeKey(handler_serial=183, state_const=0x307BF0E5),
                target_key=fallback_node.key,
                target_state=0x6B588049,
                    target_entry_anchor=72,
                    target_label="0x37B42A3F_fallback",
                    source_anchor=StateRedirectAnchor(
                        kind=RedirectSourceKind.UNCONDITIONAL,
                        block_serial=183,
                    ),
                ordered_path=(183, 184),
            ),
        ),
        diagnostics=(),
    )
    state_write = _FakeInsn(
        lfg_module.ida_hexrays.m_mov,
        l=_FakeMop(lfg_module.ida_hexrays.mop_n, value=0x6B588049),
        d=_FakeMop(lfg_module.ida_hexrays.mop_S, off=0x3C),
    )
    fake_mba = _FakeMBA(
        blocks=[_FakeMBAFlowBlock(184, [2], preds=[183], head=state_write)]
    )
    dispatcher = SimpleNamespace(
        _rows=(
            SimpleNamespace(lo=0x6B588049, hi=0x6B58804A, target=44),
        )
    )

    assert (
        LinearizedFlowGraphStrategy._resolve_synthesized_handoff_target(
            dag,
            fake_mba,
            184,
            state_var_stkoff=0x3C,
            bst_node_blocks={2},
            dispatcher=dispatcher,
        )
        == (0x6B588049, 44)
    )


def test_lfg_cover_fallback_prefers_cover_family_entry_over_unrelated_earlier_fallback():
    alias_node = StateDagNode(
        key=StateDagNodeKey(handler_serial=93, state_const=0x24E2E77A),
        kind=StateNodeKind.EXACT,
        state_label="0x24E2E77A",
        handler_serial=93,
        entry_anchor=93,
        owned_blocks=(93, 95),
        exclusive_blocks=(93, 95),
        shared_suffix_blocks=(),
        local_segments=(),
        local_edges=(),
    )
    cover_exact_node = StateDagNode(
        key=StateDagNodeKey(handler_serial=211, state_const=0x2315233C),
        kind=StateNodeKind.EXACT,
        state_label="0x2315233C",
        handler_serial=211,
        entry_anchor=211,
        owned_blocks=(211,),
        exclusive_blocks=(211,),
        shared_suffix_blocks=(),
        local_segments=(),
        local_edges=(),
    )
    unrelated_fallback_node = StateDagNode(
        key=StateDagNodeKey(handler_serial=160, state_const=0x11CD1DA3),
        kind=StateNodeKind.EXACT,
        state_label="0x11CD1DA3_fallback",
        handler_serial=160,
        entry_anchor=160,
        owned_blocks=(160,),
        exclusive_blocks=(160,),
        shared_suffix_blocks=(),
        local_segments=(),
        local_edges=(),
    )
    dag = LinearizedStateDag(
        dispatcher_entry_serial=2,
        state_var_stkoff=0x3C,
        pre_header_serial=None,
        initial_state=None,
        bst_node_blocks=(2,),
        nodes=(alias_node, cover_exact_node, unrelated_fallback_node),
        edges=(),
        diagnostics=(),
    )
    dispatcher = SimpleNamespace(
        _rows=(
            SimpleNamespace(lo=0x11CD1DA3, hi=0x11CD1DA4, target=160),
            SimpleNamespace(lo=0x11CD1DA4, hi=0x2315233C, target=160),
            SimpleNamespace(lo=0x2315233C, hi=0x2315233D, target=211),
            SimpleNamespace(lo=0x2315233D, hi=0x258ED455, target=212),
        )
    )

    assert (
        LinearizedFlowGraphStrategy._resolve_cover_fallback_entry_for_state(
            dag,
            0x24E2E77A,
            source_block=95,
            bst_node_blocks={2},
            dispatcher=dispatcher,
        )
        == 211
    )


def test_lfg_path_tail_shared_handoff_uses_semantic_entry_redirect():
    fallback_node = StateDagNode(
        key=StateDagNodeKey(handler_serial=78, state_const=0x7D9C16EC),
        kind=StateNodeKind.EXACT,
        state_label="0x7D9C16EC_fallback",
        handler_serial=78,
        entry_anchor=78,
        owned_blocks=(78,),
        exclusive_blocks=(78,),
        shared_suffix_blocks=(),
        local_segments=(),
        local_edges=(),
    )
    source_node = StateDagNode(
        key=StateDagNodeKey(handler_serial=211, state_const=0x2315233C),
        kind=StateNodeKind.EXACT,
        state_label="0x2315233C",
        handler_serial=211,
        entry_anchor=211,
        owned_blocks=(211, 35),
        exclusive_blocks=(211, 35),
        shared_suffix_blocks=(),
        local_segments=(),
        local_edges=(),
    )
    edge = StateDagEdge(
        kind=SemanticEdgeKind.TRANSITION,
        source_key=source_node.key,
        target_key=fallback_node.key,
        target_state=0x7FDCE054,
        target_entry_anchor=54,
        target_label="0x7D9C16EC_fallback",
        source_anchor=StateRedirectAnchor(
            kind=RedirectSourceKind.UNCONDITIONAL,
            block_serial=35,
        ),
        ordered_path=(211, 35),
    )
    dag = LinearizedStateDag(
        dispatcher_entry_serial=2,
        state_var_stkoff=0x3C,
        pre_header_serial=None,
        initial_state=None,
        bst_node_blocks=(2,),
        nodes=(source_node, fallback_node),
        edges=(edge,),
        diagnostics=(),
    )

    state_write = _FakeInsn(
        lfg_module.ida_hexrays.m_mov,
        l=_FakeMop(lfg_module.ida_hexrays.mop_n, value=0x7FDCE054),
        d=_FakeMop(lfg_module.ida_hexrays.mop_S, off=0x3C),
    )
    fake_mba = _FakeMBA(
        blocks=[
            _FakeMBAFlowBlock(34, [35], preds=[]),
            _FakeMBAFlowBlock(211, [35], preds=[]),
            _FakeMBAFlowBlock(35, [2], preds=[34, 211], head=state_write),
            _FakeMBAFlowBlock(78, [], preds=[]),
        ]
    )
    flow_graph = _FakeFlowGraph(
        [
            _FakeFlowBlock(34, [35]),
            _FakeFlowBlock(211, [35]),
            _FakeFlowBlock(35, [2], preds=[34, 211]),
            _FakeFlowBlock(78, []),
        ]
    )
    builder = ModificationBuilder(
        block_nsucc_map={34: 1, 211: 1, 35: 1, 78: 0},
        block_succ_map={34: (35,), 211: (35,), 35: (2,), 78: ()},
    )
    dispatcher = SimpleNamespace(
        _rows=(
            SimpleNamespace(lo=0x7D9C16EC, hi=0x7D9C16ED, target=54),
            SimpleNamespace(lo=0x7D9C16ED, hi=0xFFFFFFFF, target=55),
        )
    )
    modifications: list = []
    owned_blocks: set[int] = set()
    owned_edges: set[tuple[int, int]] = set()
    owned_transitions: set[tuple[int, int]] = set()
    emitted: set[tuple[int, int]] = set()
    claimed_1way: dict[int, int] = {}
    claimed_exits: dict[int, int] = {}
    claimed_path_edges: dict[tuple[int, int], int] = {}
    blocked_sources: set[int] = set()

    emitted_redirect = LinearizedFlowGraphStrategy._emit_path_tail_redirect(
        edge=edge,
        target_entry=78,
        dag=dag,
        builder=builder,
        modifications=modifications,
        owned_blocks=owned_blocks,
        owned_edges=owned_edges,
        owned_transitions=owned_transitions,
        emitted=emitted,
        claimed_1way=claimed_1way,
        claimed_exits=claimed_exits,
        claimed_path_edges=claimed_path_edges,
        blocked_sources=blocked_sources,
        terminal_source_keys=set(),
        terminal_source_handlers=set(),
        terminal_source_owned_blocks=set(),
        terminal_protected_blocks=set(),
        report_exit_handlers=set(),
        report_exit_owned_blocks=set(),
        bst_node_blocks={2},
        dispatcher_region={2},
        flow_graph=flow_graph,
        state_var_stkoff=0x3C,
        dispatcher_lookup=lambda state: 54 if state == 0x7FDCE054 else None,
        dispatcher=dispatcher,
        mba=fake_mba,
    )

    assert emitted_redirect is True
    assert modifications == [
        RedirectGoto(
            from_serial=35,
            old_target=2,
            new_target=78,
        )
    ]
    assert claimed_1way == {35: 78}
    assert claimed_exits == {35: 78}
    assert claimed_path_edges == {}


def test_emit_path_tail_redirect_does_not_steal_foreign_exact_entry():
    source_node = StateDagNode(
        key=StateDagNodeKey(handler_serial=23, state_const=0x6465D165),
        kind=StateNodeKind.EXACT,
        state_label="0x6465D165",
        handler_serial=23,
        entry_anchor=23,
        owned_blocks=(23, 24, 32),
        exclusive_blocks=(23, 24, 32),
        shared_suffix_blocks=(),
        local_segments=(),
        local_edges=(),
    )
    exact_owner = StateDagNode(
        key=StateDagNodeKey(handler_serial=62, state_const=0x432DC789),
        kind=StateNodeKind.EXACT,
        state_label="0x432DC789",
        handler_serial=62,
        entry_anchor=62,
        owned_blocks=(62,),
        exclusive_blocks=(62,),
        shared_suffix_blocks=(),
        local_segments=(),
        local_edges=(),
    )
    target_node = StateDagNode(
        key=StateDagNodeKey(handler_serial=205, state_const=0x298372CC),
        kind=StateNodeKind.EXACT,
        state_label="0x298372CC",
        handler_serial=205,
        entry_anchor=205,
        owned_blocks=(205,),
        exclusive_blocks=(205,),
        shared_suffix_blocks=(),
        local_segments=(),
        local_edges=(),
    )
    edge = StateDagEdge(
        kind=SemanticEdgeKind.TRANSITION,
        source_key=source_node.key,
        target_key=target_node.key,
        target_state=0x298372CC,
        target_entry_anchor=205,
        target_label="0x298372CC",
        source_anchor=StateRedirectAnchor(
            kind=RedirectSourceKind.UNCONDITIONAL,
            block_serial=23,
        ),
        ordered_path=(23, 24, 32, 61, 62),
    )
    dag = LinearizedStateDag(
        dispatcher_entry_serial=2,
        state_var_stkoff=None,
        pre_header_serial=None,
        initial_state=None,
        bst_node_blocks=(2,),
        nodes=(source_node, exact_owner, target_node),
        edges=(edge,),
        diagnostics=(),
    )
    state_write = _FakeInsn(
        lfg_module.ida_hexrays.m_mov,
        l=_FakeMop(lfg_module.ida_hexrays.mop_n, value=0x298372CC),
        d=_FakeMop(lfg_module.ida_hexrays.mop_S, off=0x3C),
    )
    fake_mba = _FakeMBA(
        blocks=[
            _FakeMBAFlowBlock(23, [24]),
            _FakeMBAFlowBlock(24, [32], preds=[23]),
            _FakeMBAFlowBlock(32, [62], preds=[24]),
            _FakeMBAFlowBlock(61, [62]),
            _FakeMBAFlowBlock(62, [2], preds=[32, 61], head=state_write),
            _FakeMBAFlowBlock(205, []),
        ]
    )
    flow_graph = _FakeFlowGraph(
        [
            _FakeFlowBlock(23, [24]),
            _FakeFlowBlock(24, [32], preds=[23]),
            _FakeFlowBlock(32, [62], preds=[24]),
            _FakeFlowBlock(61, [62]),
            _FakeFlowBlock(62, [2], preds=[32, 61]),
            _FakeFlowBlock(205, []),
        ]
    )
    builder = ModificationBuilder(
        block_nsucc_map={23: 1, 24: 1, 32: 1, 61: 1, 62: 1, 205: 0},
        block_succ_map={
            23: (24,),
            24: (32,),
            32: (62,),
            61: (62,),
            62: (2,),
            205: (),
        },
    )
    modifications: list = []

    emitted_redirect = LinearizedFlowGraphStrategy._emit_path_tail_redirect(
        edge=edge,
        target_entry=205,
        dag=dag,
        builder=builder,
        modifications=modifications,
        owned_blocks=set(),
        owned_edges=set(),
        owned_transitions=set(),
        emitted=set(),
        claimed_1way={},
        claimed_exits={},
        claimed_path_edges={},
        blocked_sources=set(),
        terminal_source_keys=set(),
        terminal_source_handlers=set(),
        terminal_source_owned_blocks=set(),
        terminal_protected_blocks=set(),
        report_exit_handlers=set(),
        report_exit_owned_blocks=set(),
        bst_node_blocks={2},
        dispatcher_region={2},
        flow_graph=flow_graph,
        state_var_stkoff=0x3C,
        dispatcher_lookup=lambda state: 205 if state == 0x298372CC else None,
        mba=fake_mba,
    )

    assert emitted_redirect is False
    assert modifications == []


def test_lfg_residual_branch_anchor_handoff_bypasses_dispatcher_tail():
    source_node = StateDagNode(
        key=StateDagNodeKey(handler_serial=143, state_const=0x149AED27),
        kind=StateNodeKind.EXACT,
        state_label="0x149AED27",
        handler_serial=143,
        entry_anchor=143,
        owned_blocks=(143, 144, 10),
        exclusive_blocks=(143, 144, 10),
        shared_suffix_blocks=(),
        local_segments=(),
        local_edges=(),
    )
    target_node = StateDagNode(
        key=StateDagNodeKey(handler_serial=136, state_const=0x2A5E29F6),
        kind=StateNodeKind.EXACT,
        state_label="0x2A5E29F6",
        handler_serial=136,
        entry_anchor=136,
        owned_blocks=(136,),
        exclusive_blocks=(136,),
        shared_suffix_blocks=(),
        local_segments=(),
        local_edges=(),
    )
    edge = StateDagEdge(
        kind=SemanticEdgeKind.CONDITIONAL_TRANSITION,
        source_key=source_node.key,
        target_key=target_node.key,
        target_state=0x2A5E29F6,
        target_entry_anchor=136,
        target_label="0x2A5E29F6",
        source_anchor=StateRedirectAnchor(
            kind=RedirectSourceKind.CONDITIONAL_BRANCH,
            block_serial=143,
            branch_arm=0,
        ),
        ordered_path=(143, 144, 10),
    )
    flow_graph = _FakeFlowGraph(
        [
            _FakeFlowBlock(143, [144, 145]),
            _FakeFlowBlock(144, [10], preds=[143]),
            _FakeFlowBlock(145, [155], preds=[143]),
            _FakeFlowBlock(10, [2], preds=[144]),
            _FakeFlowBlock(136, []),
            _FakeFlowBlock(2, [3, 112], preds=[10]),
        ]
    )
    builder = ModificationBuilder(
        block_nsucc_map={143: 2, 144: 1, 145: 1, 10: 1, 136: 0, 2: 2},
        block_succ_map={
            143: (144, 145),
            144: (10,),
            145: (155,),
            10: (2,),
            136: (),
            2: (3, 112),
        },
    )
    modifications: list = []
    owned_blocks: set[int] = set()
    owned_edges: set[tuple[int, int]] = set()
    owned_transitions: set[tuple[int, int]] = set()
    emitted: set[tuple[int, int]] = set()
    claimed_2way: dict[tuple[int, int], int] = {}

    emitted_redirect = LinearizedFlowGraphStrategy._emit_residual_branch_anchor_handoff(
        edge=edge,
        source_block=10,
        via_pred=144,
        prefix_target=136,
        projected_flow_graph=flow_graph,
        bst_node_blocks={2},
        dispatcher_serial=2,
        builder=builder,
        modifications=modifications,
        owned_blocks=owned_blocks,
        owned_edges=owned_edges,
        owned_transitions=owned_transitions,
        emitted=emitted,
        claimed_2way=claimed_2way,
        ignored_blocks={2},
        residual_ignored_blocks={2},
        mba=None,
    )

    assert emitted_redirect is True
    assert modifications == [
        RedirectBranch(from_serial=143, old_target=144, new_target=136)
    ]
    assert claimed_2way == {(143, 144): 136}
    assert emitted == {(143, 136)}
    assert owned_blocks == {143}
    assert owned_edges == {(143, 136)}
    assert owned_transitions == {(0x149AED27, 0x2A5E29F6)}


def test_lfg_residual_branch_anchor_handoff_rejects_duplicate_other_successor():
    source_node = StateDagNode(
        key=StateDagNodeKey(handler_serial=179, state_const=0x2FBA4611),
        kind=StateNodeKind.EXACT,
        state_label="0x2FBA4611",
        handler_serial=179,
        entry_anchor=179,
        owned_blocks=(179, 180, 203),
        exclusive_blocks=(179, 180, 203),
        shared_suffix_blocks=(),
        local_segments=(),
        local_edges=(),
    )
    target_node = StateDagNode(
        key=StateDagNodeKey(handler_serial=181, state_const=0x3050636B),
        kind=StateNodeKind.EXACT,
        state_label="0x3050636B",
        handler_serial=181,
        entry_anchor=181,
        owned_blocks=(181,),
        exclusive_blocks=(181,),
        shared_suffix_blocks=(),
        local_segments=(),
        local_edges=(),
    )
    edge = StateDagEdge(
        kind=SemanticEdgeKind.CONDITIONAL_TRANSITION,
        source_key=source_node.key,
        target_key=target_node.key,
        target_state=0x3050636B,
        target_entry_anchor=181,
        target_label="0x3050636B",
        source_anchor=StateRedirectAnchor(
            kind=RedirectSourceKind.CONDITIONAL_BRANCH,
            block_serial=179,
            branch_arm=0,
        ),
        ordered_path=(179, 180, 203),
    )
    flow_graph = _FakeFlowGraph(
        [
            _FakeFlowBlock(179, [180, 181]),
            _FakeFlowBlock(180, [203], preds=[179]),
            _FakeFlowBlock(181, [182], preds=[179]),
            _FakeFlowBlock(203, [2], preds=[180]),
            _FakeFlowBlock(2, [3, 112], preds=[203]),
        ]
    )
    builder = ModificationBuilder(
        block_nsucc_map={179: 2, 180: 1, 181: 1, 203: 1, 2: 2},
        block_succ_map={
            179: (180, 181),
            180: (203,),
            181: (182,),
            203: (2,),
            2: (3, 112),
        },
    )

    assert not LinearizedFlowGraphStrategy._emit_residual_branch_anchor_handoff(
        edge=edge,
        source_block=203,
        via_pred=180,
        prefix_target=181,
        projected_flow_graph=flow_graph,
        bst_node_blocks={2},
        dispatcher_serial=2,
        builder=builder,
        modifications=[],
        owned_blocks=set(),
        owned_edges=set(),
        owned_transitions=set(),
        emitted=set(),
        claimed_2way={},
        ignored_blocks={2},
        residual_ignored_blocks={2},
        mba=None,
    )


def test_lfg_synthesized_handoff_prefers_cover_fallback_over_alias_node():
    alias_node = StateDagNode(
        key=StateDagNodeKey(handler_serial=170, state_const=0x24E2E77A),
        kind=StateNodeKind.EXACT,
        state_label="0x24E2E77A",
        handler_serial=170,
        entry_anchor=170,
        owned_blocks=(170,),
        exclusive_blocks=(170,),
        shared_suffix_blocks=(),
        local_segments=(),
        local_edges=(),
    )
    fallback_node = StateDagNode(
        key=StateDagNodeKey(handler_serial=211, state_const=0x2315233C),
        kind=StateNodeKind.EXACT,
        state_label="0x2315233C_fallback",
        handler_serial=211,
        entry_anchor=211,
        owned_blocks=(211,),
        exclusive_blocks=(211,),
        shared_suffix_blocks=(),
        local_segments=(),
        local_edges=(),
    )
    dag = LinearizedStateDag(
        dispatcher_entry_serial=2,
        state_var_stkoff=0x3C,
        pre_header_serial=None,
        initial_state=None,
        bst_node_blocks=(2,),
        nodes=(alias_node, fallback_node),
        edges=(),
        diagnostics=(),
    )
    state_write = _FakeInsn(
        lfg_module.ida_hexrays.m_mov,
        l=_FakeMop(lfg_module.ida_hexrays.mop_n, value=0x24E2E77A),
        d=_FakeMop(lfg_module.ida_hexrays.mop_S, off=0x3C),
    )
    fake_mba = _FakeMBA(blocks=[_FakeMBAFlowBlock(95, [2], preds=[93], head=state_write)])
    dispatcher = SimpleNamespace(
        _rows=(
            SimpleNamespace(lo=0x2315233C, hi=0x2315233D, target=211),
            SimpleNamespace(lo=0x2315233D, hi=0x258ED455, target=212),
        )
    )

    assert (
        LinearizedFlowGraphStrategy._resolve_synthesized_handoff_target(
            dag,
            fake_mba,
            95,
            state_var_stkoff=0x3C,
            bst_node_blocks={2},
            dispatcher=dispatcher,
        )
        == (0x24E2E77A, 211)
    )


def test_lfg_synthesized_handoff_avoids_loopback_to_via_pred_exact_body():
    exact_node = StateDagNode(
        key=StateDagNodeKey(handler_serial=180, state_const=0x2FBA4611),
        kind=StateNodeKind.EXACT,
        state_label="0x2FBA4611",
        handler_serial=180,
        entry_anchor=180,
        owned_blocks=(180, 203),
        exclusive_blocks=(180, 203),
        shared_suffix_blocks=(),
        local_segments=(),
        local_edges=(),
    )
    fallback_node = StateDagNode(
        key=StateDagNodeKey(handler_serial=181, state_const=0x2FBA4611),
        kind=StateNodeKind.EXACT,
        state_label="0x2FBA4611_fallback",
        handler_serial=181,
        entry_anchor=181,
        owned_blocks=(181,),
        exclusive_blocks=(181,),
        shared_suffix_blocks=(),
        local_segments=(),
        local_edges=(),
    )
    alias_node = StateDagNode(
        key=StateDagNodeKey(handler_serial=181, state_const=0x3050636B),
        kind=StateNodeKind.EXACT,
        state_label="0x3050636B",
        handler_serial=181,
        entry_anchor=180,
        owned_blocks=(180,),
        exclusive_blocks=(180,),
        shared_suffix_blocks=(),
        local_segments=(),
        local_edges=(),
    )
    dag = LinearizedStateDag(
        dispatcher_entry_serial=2,
        state_var_stkoff=0x3C,
        pre_header_serial=None,
        initial_state=None,
        bst_node_blocks=(2,),
        nodes=(exact_node, fallback_node, alias_node),
        edges=(),
        diagnostics=(),
    )
    state_write = _FakeInsn(
        lfg_module.ida_hexrays.m_mov,
        l=_FakeMop(lfg_module.ida_hexrays.mop_n, value=0x3050636B),
        d=_FakeMop(lfg_module.ida_hexrays.mop_S, off=0x3C),
    )
    fake_mba = _FakeMBA(
        blocks=[_FakeMBAFlowBlock(203, [2], preds=[180], head=state_write)]
    )
    dispatcher = SimpleNamespace(
        _rows=(
            SimpleNamespace(lo=0x2FBA4611, hi=0x2FBA4612, target=180),
            SimpleNamespace(lo=0x2FBA4612, hi=0x307BF0E5, target=181),
        ),
        lookup=lambda state: 181 if state == 0x3050636B else None,
    )

    assert (
        LinearizedFlowGraphStrategy._resolve_synthesized_handoff_target(
            dag,
            fake_mba,
            203,
            state_var_stkoff=0x3C,
            bst_node_blocks={2},
            dispatcher=dispatcher,
            via_pred=180,
        )
        == (0x3050636B, 181)
    )


def test_lfg_synthesized_handoff_rejects_uncovered_alias_state():
    alias_node = StateDagNode(
        key=StateDagNodeKey(handler_serial=170, state_const=0x7A8B3FB),
        kind=StateNodeKind.EXACT,
        state_label="0x07A8B3FB",
        handler_serial=170,
        entry_anchor=170,
        owned_blocks=(170,),
        exclusive_blocks=(170,),
        shared_suffix_blocks=(),
        local_segments=(),
        local_edges=(),
    )
    dag = LinearizedStateDag(
        dispatcher_entry_serial=2,
        state_var_stkoff=0x3C,
        pre_header_serial=None,
        initial_state=None,
        bst_node_blocks=(2,),
        nodes=(alias_node,),
        edges=(),
        diagnostics=(),
    )
    state_write = _FakeInsn(
        lfg_module.ida_hexrays.m_mov,
        l=_FakeMop(lfg_module.ida_hexrays.mop_n, value=0x7A8B3FB),
        d=_FakeMop(lfg_module.ida_hexrays.mop_S, off=0x3C),
    )
    fake_mba = _FakeMBA(blocks=[_FakeMBAFlowBlock(95, [2], preds=[93], head=state_write)])
    dispatcher = SimpleNamespace(
        _rows=(
            SimpleNamespace(lo=0x2315233C, hi=0x2315233D, target=211),
            SimpleNamespace(lo=0x2315233D, hi=0x258ED455, target=212),
        )
    )

    assert (
        LinearizedFlowGraphStrategy._resolve_synthesized_handoff_target(
            dag,
            fake_mba,
            95,
            state_var_stkoff=0x3C,
            bst_node_blocks={2},
            dispatcher=dispatcher,
        )
        is None
    )


def test_lfg_projected_path_tail_target_preserves_explicit_fallback_label():
    source_node = StateDagNode(
        key=StateDagNodeKey(handler_serial=123, state_const=0x00C0C59F),
        kind=StateNodeKind.EXACT,
        state_label="0x00C0C59F_fallback",
        handler_serial=123,
        entry_anchor=123,
        owned_blocks=(123,),
        exclusive_blocks=(123,),
        shared_suffix_blocks=(),
        local_segments=(),
        local_edges=(),
    )
    fallback_node = StateDagNode(
        key=StateDagNodeKey(handler_serial=52, state_const=0x737189D5),
        kind=StateNodeKind.EXACT,
        state_label="0x737189D5_fallback",
        handler_serial=52,
        entry_anchor=52,
        owned_blocks=(52,),
        exclusive_blocks=(52,),
        shared_suffix_blocks=(),
        local_segments=(),
        local_edges=(),
    )
    distracting_cover = StateDagNode(
        key=StateDagNodeKey(handler_serial=132, state_const=0x09EB3382),
        kind=StateNodeKind.EXACT,
        state_label="0x09EB3382_fallback",
        handler_serial=132,
        entry_anchor=132,
        owned_blocks=(132,),
        exclusive_blocks=(132,),
        shared_suffix_blocks=(),
        local_segments=(),
        local_edges=(),
    )
    dag = LinearizedStateDag(
        dispatcher_entry_serial=2,
        state_var_stkoff=0x3C,
        pre_header_serial=123,
        initial_state=None,
        bst_node_blocks=(2,),
        nodes=(source_node, fallback_node, distracting_cover),
        edges=(
            StateDagEdge(
                kind=SemanticEdgeKind.TRANSITION,
                source_key=source_node.key,
                target_key=None,
                target_state=0x79F598F7,
                target_entry_anchor=52,
                target_label="0x737189D5_fallback",
                source_anchor=StateRedirectAnchor(
                    kind=RedirectSourceKind.UNCONDITIONAL,
                    block_serial=123,
                ),
                ordered_path=(123,),
            ),
        ),
        diagnostics=(),
    )
    dispatcher = SimpleNamespace(
        _rows=(
            SimpleNamespace(lo=0x09EB3382, hi=0x09EB3383, target=131),
            SimpleNamespace(lo=0x09EB3383, hi=0x79F598F8, target=132),
        )
    )

    assert (
        LinearizedFlowGraphStrategy._resolve_projected_path_tail_target(
            dag,
            source_block=123,
            bst_node_blocks={2},
            dispatcher=dispatcher,
        )
        == (0x79F598F7, 52)
    )


def test_lfg_projected_path_tail_target_avoids_loopback_to_exact_body():
    exact_node = StateDagNode(
        key=StateDagNodeKey(handler_serial=180, state_const=0x2FBA4611),
        kind=StateNodeKind.EXACT,
        state_label="0x2FBA4611",
        handler_serial=180,
        entry_anchor=180,
        owned_blocks=(180, 203),
        exclusive_blocks=(180, 203),
        shared_suffix_blocks=(),
        local_segments=(),
        local_edges=(),
    )
    fallback_node = StateDagNode(
        key=StateDagNodeKey(handler_serial=181, state_const=0x2FBA4611),
        kind=StateNodeKind.EXACT,
        state_label="0x2FBA4611_fallback",
        handler_serial=181,
        entry_anchor=181,
        owned_blocks=(181,),
        exclusive_blocks=(181,),
        shared_suffix_blocks=(),
        local_segments=(),
        local_edges=(),
    )
    alias_node = StateDagNode(
        key=StateDagNodeKey(handler_serial=181, state_const=0x3050636B),
        kind=StateNodeKind.EXACT,
        state_label="0x3050636B",
        handler_serial=181,
        entry_anchor=180,
        owned_blocks=(180,),
        exclusive_blocks=(180,),
        shared_suffix_blocks=(),
        local_segments=(),
        local_edges=(),
    )
    dag = LinearizedStateDag(
        dispatcher_entry_serial=2,
        state_var_stkoff=0x3C,
        pre_header_serial=None,
        initial_state=None,
        bst_node_blocks=(2,),
        nodes=(exact_node, fallback_node, alias_node),
        edges=(
            StateDagEdge(
                kind=SemanticEdgeKind.TRANSITION,
                source_key=exact_node.key,
                target_key=alias_node.key,
                target_state=0x3050636B,
                target_entry_anchor=180,
                target_label="0x3050636B",
                source_anchor=StateRedirectAnchor(
                    kind=RedirectSourceKind.UNCONDITIONAL,
                    block_serial=180,
                ),
                ordered_path=(179, 180, 203),
            ),
        ),
        diagnostics=(),
    )
    dispatcher = SimpleNamespace(
        _rows=(
            SimpleNamespace(lo=0x2FBA4611, hi=0x2FBA4612, target=180),
            SimpleNamespace(lo=0x2FBA4612, hi=0x307BF0E5, target=181),
        ),
        lookup=lambda state: 181 if state == 0x3050636B else None,
    )

    assert (
        LinearizedFlowGraphStrategy._resolve_projected_path_tail_target(
            dag,
            source_block=203,
            bst_node_blocks={2},
            dispatcher=dispatcher,
            predecessor_hints=(180,),
            require_predecessor_match=True,
        )
        == (0x3050636B, 181)
    )


def test_lfg_residual_dispatcher_handoff_lifts_to_last_semantic_predecessor():
    source_node = StateDagNode(
        key=StateDagNodeKey(handler_serial=143, state_const=0x63F502FA),
        kind=StateNodeKind.EXACT,
        state_label="0x63F502FA",
        handler_serial=143,
        entry_anchor=143,
        owned_blocks=(143, 144, 10),
        exclusive_blocks=(143, 144, 10),
        shared_suffix_blocks=(),
        local_segments=(),
        local_edges=(),
    )
    target_node = StateDagNode(
        key=StateDagNodeKey(handler_serial=136, state_const=0x2A5E29F6),
        kind=StateNodeKind.EXACT,
        state_label="0x2A5E29F6",
        handler_serial=136,
        entry_anchor=136,
        owned_blocks=(136,),
        exclusive_blocks=(136,),
        shared_suffix_blocks=(),
        local_segments=(),
        local_edges=(),
    )
    dag = LinearizedStateDag(
        dispatcher_entry_serial=2,
        state_var_stkoff=0x3C,
        pre_header_serial=143,
        initial_state=None,
        bst_node_blocks=(2,),
        nodes=(source_node, target_node),
        edges=(
            StateDagEdge(
                kind=SemanticEdgeKind.CONDITIONAL_TRANSITION,
                source_key=source_node.key,
                target_key=target_node.key,
                target_state=0x2A5E29F6,
                target_entry_anchor=136,
                target_label="0x2A5E29F6",
                source_anchor=StateRedirectAnchor(
                    kind=RedirectSourceKind.CONDITIONAL_BRANCH,
                    block_serial=143,
                    branch_arm=0,
                ),
                ordered_path=(143, 144, 10),
            ),
        ),
        diagnostics=(),
    )
    projected_flow_graph = _FakeFlowGraph(
        [
            _FakeFlowBlock(2, [3, 112], preds=[10]),
            _FakeFlowBlock(10, [2], preds=[144]),
            _FakeFlowBlock(143, [144, 145], preds=[]),
            _FakeFlowBlock(144, [10], preds=[143]),
            _FakeFlowBlock(145, [155], preds=[143]),
            _FakeFlowBlock(136, [10], preds=[]),
        ]
    )
    builder = ModificationBuilder(
        block_nsucc_map={2: 2, 10: 1, 143: 2, 144: 1, 145: 1, 136: 1},
        block_succ_map={
            2: (3, 112),
            10: (2,),
            143: (144, 145),
            144: (10,),
            145: (155,),
            136: (10,),
        },
    )
    modifications: list = []

    redirected = LinearizedFlowGraphStrategy._emit_residual_dispatcher_handoffs(
        dag=dag,
        state_machine=None,
        projected_flow_graph=projected_flow_graph,
        dispatcher_serial=2,
        bst_node_blocks={2},
        builder=builder,
        modifications=modifications,
        owned_blocks=set(),
        owned_edges=set(),
        owned_transitions=set(),
        emitted=set(),
        claimed_1way={},
        claimed_2way={},
        state_var_stkoff=None,
        dispatcher_lookup=None,
        dispatcher=None,
        mba=None,
        redirected_blocks=set(),
    )

    assert redirected == 1
    assert any(
        isinstance(mod, RedirectBranch)
        and mod.from_serial == 143
        and mod.old_target == 144
        and mod.new_target == 136
        for mod in modifications
    )


def test_lfg_residual_dispatcher_handoff_skips_shared_suffix_tail_when_branch_cut_exists():
    source_node = StateDagNode(
        key=StateDagNodeKey(handler_serial=143, state_const=0x149AED27),
        kind=StateNodeKind.EXACT,
        state_label="0x149AED27",
        handler_serial=143,
        entry_anchor=143,
        owned_blocks=(143, 144, 10),
        exclusive_blocks=(143, 144, 10),
        shared_suffix_blocks=(10,),
        local_segments=(),
        local_edges=(),
    )
    target_node = StateDagNode(
        key=StateDagNodeKey(handler_serial=136, state_const=0x2A5E29F6),
        kind=StateNodeKind.EXACT,
        state_label="0x2A5E29F6",
        handler_serial=136,
        entry_anchor=136,
        owned_blocks=(136,),
        exclusive_blocks=(136,),
        shared_suffix_blocks=(),
        local_segments=(),
        local_edges=(),
    )
    dag = LinearizedStateDag(
        dispatcher_entry_serial=2,
        state_var_stkoff=0x3C,
        pre_header_serial=None,
        initial_state=None,
        bst_node_blocks=(2,),
        nodes=(source_node, target_node),
        edges=(
            StateDagEdge(
                kind=SemanticEdgeKind.CONDITIONAL_TRANSITION,
                source_key=source_node.key,
                target_key=target_node.key,
                target_state=0x2A5E29F6,
                target_entry_anchor=136,
                target_label="0x2A5E29F6",
                source_anchor=StateRedirectAnchor(
                    kind=RedirectSourceKind.CONDITIONAL_BRANCH,
                    block_serial=143,
                    branch_arm=0,
                ),
                ordered_path=(143, 144, 10),
            ),
        ),
        diagnostics=(),
    )
    state_write = _FakeInsn(
        lfg_module.ida_hexrays.m_mov,
        l=_FakeMop(lfg_module.ida_hexrays.mop_n, value=0x2A5E29F6),
        d=_FakeMop(lfg_module.ida_hexrays.mop_S, off=0x3C),
    )
    mba_blocks = [
        _FakeMBAFlowBlock(2, [3, 112], preds=[10], head=None),
        _FakeMBAFlowBlock(10, [2], preds=[144], head=state_write),
        _FakeMBAFlowBlock(136, [10], preds=[], head=None),
        # Deliberately make the earlier branch source unavailable as a 2-way
        # rewrite site; the residual pass must still refuse to rewrite blk[10]
        # directly because it is only a shared suffix tail.
        _FakeMBAFlowBlock(143, [144], preds=[], head=None),
        _FakeMBAFlowBlock(144, [10], preds=[143], head=None),
        _FakeMBAFlowBlock(112, [], preds=[2], head=None),
    ]
    flow_graph = _FakeFlowGraph(mba_blocks)
    fake_mba = _FakeMBA(blocks=mba_blocks)
    builder = ModificationBuilder.from_snapshot(
        SimpleNamespace(flow_graph=flow_graph, mba=fake_mba)
    )
    modifications: list = []

    redirected = LinearizedFlowGraphStrategy._emit_residual_dispatcher_handoffs(
        dag=dag,
        state_machine=None,
        projected_flow_graph=flow_graph,
        dispatcher_serial=2,
        bst_node_blocks={2},
        builder=builder,
        modifications=modifications,
        owned_blocks=set(),
        owned_edges=set(),
        owned_transitions=set(),
        emitted=set(),
        claimed_1way={},
        claimed_2way={},
        state_var_stkoff=0x3C,
        dispatcher_lookup=None,
        dispatcher=None,
        mba=fake_mba,
        redirected_blocks=set(),
    )

    assert redirected == 0
    assert modifications == []


def test_lfg_residual_dispatcher_handoff_allows_family_fallback_shared_suffix_tail():
    exact_node = StateDagNode(
        key=StateDagNodeKey(handler_serial=180, state_const=0x2FBA4611),
        kind=StateNodeKind.EXACT,
        state_label="0x2FBA4611",
        handler_serial=180,
        entry_anchor=180,
        owned_blocks=(180, 203),
        exclusive_blocks=(180, 203),
        shared_suffix_blocks=(203,),
        local_segments=(),
        local_edges=(),
    )
    fallback_node = StateDagNode(
        key=StateDagNodeKey(handler_serial=181, state_const=0x2FBA4611),
        kind=StateNodeKind.EXACT,
        state_label="0x2FBA4611_fallback",
        handler_serial=181,
        entry_anchor=181,
        owned_blocks=(181,),
        exclusive_blocks=(181,),
        shared_suffix_blocks=(),
        local_segments=(),
        local_edges=(),
    )
    alias_node = StateDagNode(
        key=StateDagNodeKey(handler_serial=181, state_const=0x3050636B),
        kind=StateNodeKind.EXACT,
        state_label="0x3050636B",
        handler_serial=181,
        entry_anchor=180,
        owned_blocks=(180,),
        exclusive_blocks=(180,),
        shared_suffix_blocks=(),
        local_segments=(),
        local_edges=(),
    )
    dag = LinearizedStateDag(
        dispatcher_entry_serial=2,
        state_var_stkoff=0x3C,
        pre_header_serial=None,
        initial_state=None,
        bst_node_blocks=(2,),
        nodes=(exact_node, fallback_node, alias_node),
        edges=(
            StateDagEdge(
                kind=SemanticEdgeKind.CONDITIONAL_TRANSITION,
                source_key=exact_node.key,
                target_key=alias_node.key,
                target_state=0x3050636B,
                target_entry_anchor=180,
                target_label="0x3050636B",
                source_anchor=StateRedirectAnchor(
                    kind=RedirectSourceKind.CONDITIONAL_BRANCH,
                    block_serial=179,
                    branch_arm=0,
                ),
                ordered_path=(179, 180, 203),
            ),
        ),
        diagnostics=(),
    )
    state_write = _FakeInsn(
        lfg_module.ida_hexrays.m_mov,
        l=_FakeMop(lfg_module.ida_hexrays.mop_n, value=0x3050636B),
        d=_FakeMop(lfg_module.ida_hexrays.mop_S, off=0x3C),
    )
    mba_blocks = [
        _FakeMBAFlowBlock(2, [3, 112], preds=[203], head=None),
        _FakeMBAFlowBlock(179, [180, 181], preds=[], head=None),
        _FakeMBAFlowBlock(180, [203], preds=[179], head=None),
        _FakeMBAFlowBlock(181, [182], preds=[179], head=None),
        _FakeMBAFlowBlock(182, [], preds=[181], head=None),
        _FakeMBAFlowBlock(203, [2], preds=[180], head=state_write),
        _FakeMBAFlowBlock(112, [], preds=[2], head=None),
    ]
    flow_graph = _FakeFlowGraph(mba_blocks)
    fake_mba = _FakeMBA(blocks=mba_blocks)
    builder = ModificationBuilder.from_snapshot(
        SimpleNamespace(flow_graph=flow_graph, mba=fake_mba)
    )
    dispatcher = SimpleNamespace(
        _rows=(
            SimpleNamespace(lo=0x2FBA4611, hi=0x2FBA4612, target=180),
            SimpleNamespace(lo=0x2FBA4612, hi=0x307BF0E5, target=181),
        ),
        lookup=lambda state: 181 if state == 0x3050636B else None,
    )
    modifications: list = []

    redirected = LinearizedFlowGraphStrategy._emit_residual_dispatcher_handoffs(
        dag=dag,
        state_machine=None,
        projected_flow_graph=flow_graph,
        dispatcher_serial=2,
        bst_node_blocks={2},
        builder=builder,
        modifications=modifications,
        owned_blocks=set(),
        owned_edges=set(),
        owned_transitions=set(),
        emitted=set(),
        claimed_1way={},
        claimed_2way={},
        state_var_stkoff=0x3C,
        dispatcher_lookup=dispatcher.lookup,
        dispatcher=dispatcher,
        mba=fake_mba,
        redirected_blocks=set(),
    )

    assert redirected == 1
    assert modifications == [RedirectGoto(from_serial=203, old_target=2, new_target=180)]


def test_lfg_projected_path_tail_prefers_matching_predecessor_context():
    alias_source = StateDagNode(
        key=StateDagNodeKey(handler_serial=143, state_const=0x149AED27),
        kind=StateNodeKind.EXACT,
        state_label="0x149AED27",
        handler_serial=143,
        entry_anchor=143,
        owned_blocks=(143, 144, 145, 10),
        exclusive_blocks=(143, 144, 145, 10),
        shared_suffix_blocks=(),
        local_segments=(),
        local_edges=(),
    )
    fallback_target = StateDagNode(
        key=StateDagNodeKey(handler_serial=136, state_const=0x2A5E29F6),
        kind=StateNodeKind.EXACT,
        state_label="0x2A5E29F6",
        handler_serial=136,
        entry_anchor=136,
        owned_blocks=(136,),
        exclusive_blocks=(136,),
        shared_suffix_blocks=(),
        local_segments=(),
        local_edges=(),
    )
    distractor_target = StateDagNode(
        key=StateDagNodeKey(handler_serial=215, state_const=0x1CCE40B3),
        kind=StateNodeKind.EXACT,
        state_label="0x1CCE40B3",
        handler_serial=215,
        entry_anchor=215,
        owned_blocks=(215,),
        exclusive_blocks=(215,),
        shared_suffix_blocks=(),
        local_segments=(),
        local_edges=(),
    )
    dag = LinearizedStateDag(
        dispatcher_entry_serial=2,
        state_var_stkoff=0x3C,
        pre_header_serial=None,
        initial_state=None,
        bst_node_blocks=(2,),
        nodes=(alias_source, fallback_target, distractor_target),
        edges=(
            StateDagEdge(
                kind=SemanticEdgeKind.CONDITIONAL_TRANSITION,
                source_key=alias_source.key,
                target_key=fallback_target.key,
                target_state=0x2A5E29F6,
                target_entry_anchor=136,
                target_label="0x2A5E29F6",
                source_anchor=StateRedirectAnchor(
                    kind=RedirectSourceKind.CONDITIONAL_BRANCH,
                    block_serial=143,
                    branch_arm=0,
                ),
                ordered_path=(143, 144, 10),
            ),
            StateDagEdge(
                kind=SemanticEdgeKind.CONDITIONAL_TRANSITION,
                source_key=alias_source.key,
                target_key=None,
                target_state=0x1031EAF4,
                target_entry_anchor=155,
                target_label="0x1031EAF4",
                source_anchor=StateRedirectAnchor(
                    kind=RedirectSourceKind.CONDITIONAL_BRANCH,
                    block_serial=143,
                    branch_arm=1,
                ),
                ordered_path=(143, 145, 10),
            ),
            StateDagEdge(
                kind=SemanticEdgeKind.CONDITIONAL_TRANSITION,
                source_key=distractor_target.key,
                target_key=distractor_target.key,
                target_state=0x1CCE40B3,
                target_entry_anchor=215,
                target_label="0x1CCE40B3",
                source_anchor=StateRedirectAnchor(
                    kind=RedirectSourceKind.CONDITIONAL_BRANCH,
                    block_serial=8,
                    branch_arm=0,
                ),
                ordered_path=(8, 9, 10),
            ),
        ),
        diagnostics=(),
    )

    assert (
        LinearizedFlowGraphStrategy._resolve_projected_path_tail_target(
            dag,
            source_block=10,
            bst_node_blocks={2},
            predecessor_hints=(144,),
        )
        == (0x2A5E29F6, 136)
    )


def test_lfg_resolve_redirect_safe_target_entry_ignores_stale_same_corridor_explicit_anchor():
    target_node = StateDagNode(
        key=StateDagNodeKey(handler_serial=136, state_const=0x2A5E29F6),
        kind=StateNodeKind.EXACT,
        state_label="0x2A5E29F6",
        handler_serial=136,
        entry_anchor=136,
        owned_blocks=(136,),
        exclusive_blocks=(136,),
        shared_suffix_blocks=(),
        local_segments=(),
        local_edges=(),
    )
    source_node = StateDagNode(
        key=StateDagNodeKey(handler_serial=143, state_const=0x149AED27),
        kind=StateNodeKind.EXACT,
        state_label="0x149AED27",
        handler_serial=143,
        entry_anchor=143,
        owned_blocks=(143, 144, 10),
        exclusive_blocks=(143, 144, 10),
        shared_suffix_blocks=(10,),
        local_segments=(),
        local_edges=(),
    )
    dag = LinearizedStateDag(
        dispatcher_entry_serial=2,
        state_var_stkoff=0x3C,
        pre_header_serial=None,
        initial_state=None,
        bst_node_blocks=(2,),
        nodes=(source_node, target_node),
        edges=(),
        diagnostics=(),
    )
    edge = StateDagEdge(
        kind=SemanticEdgeKind.CONDITIONAL_TRANSITION,
        source_key=source_node.key,
        target_key=target_node.key,
        target_state=0x2A5E29F6,
        target_entry_anchor=143,
        target_label="0x2A5E29F6",
        source_anchor=StateRedirectAnchor(
            kind=RedirectSourceKind.CONDITIONAL_BRANCH,
            block_serial=143,
            branch_arm=0,
        ),
        ordered_path=(143, 144, 10),
    )

    assert (
        LinearizedFlowGraphStrategy._resolve_redirect_safe_target_entry(
            dag,
            edge,
            bst_node_blocks={2},
        )
        == 136
    )


def test_lfg_contextual_entry_prefers_nonlocal_exact_node_over_same_path_anchor():
    stale_node = StateDagNode(
        key=StateDagNodeKey(handler_serial=143, state_const=0x2A5E29F6),
        kind=StateNodeKind.EXACT,
        state_label="0x2A5E29F6",
        handler_serial=143,
        entry_anchor=143,
        owned_blocks=(143, 144, 10),
        exclusive_blocks=(143, 144, 10),
        shared_suffix_blocks=(10,),
        local_segments=(),
        local_edges=(),
    )
    target_node = StateDagNode(
        key=StateDagNodeKey(handler_serial=136, state_const=0x2A5E29F6),
        kind=StateNodeKind.EXACT,
        state_label="0x2A5E29F6",
        handler_serial=136,
        entry_anchor=136,
        owned_blocks=(136,),
        exclusive_blocks=(136,),
        shared_suffix_blocks=(),
        local_segments=(),
        local_edges=(),
    )
    source_node = StateDagNode(
        key=StateDagNodeKey(handler_serial=130, state_const=0x1031EAF4),
        kind=StateNodeKind.EXACT,
        state_label="0x1031EAF4",
        handler_serial=130,
        entry_anchor=130,
        owned_blocks=(130, 143, 144, 10),
        exclusive_blocks=(130, 143, 144, 10),
        shared_suffix_blocks=(10,),
        local_segments=(),
        local_edges=(),
    )
    dag = LinearizedStateDag(
        dispatcher_entry_serial=2,
        state_var_stkoff=0x3C,
        pre_header_serial=None,
        initial_state=None,
        bst_node_blocks=(2,),
        nodes=(source_node, stale_node, target_node),
        edges=(
            StateDagEdge(
                kind=SemanticEdgeKind.CONDITIONAL_TRANSITION,
                source_key=source_node.key,
                target_key=stale_node.key,
                target_state=0x2A5E29F6,
                target_entry_anchor=143,
                target_label="0x2A5E29F6",
                source_anchor=StateRedirectAnchor(
                    kind=RedirectSourceKind.CONDITIONAL_BRANCH,
                    block_serial=143,
                    branch_arm=0,
                ),
                ordered_path=(130, 143, 144, 10),
            ),
        ),
        diagnostics=(),
    )

    assert (
        LinearizedFlowGraphStrategy._resolve_contextual_dag_entry_for_state(
            dag,
            0x2A5E29F6,
            source_block=144,
            bst_node_blocks={2},
        )
        == 136
    )


def test_lfg_normalizes_projected_alias_handoff_for_initial_whole_redirect():
    source_node = StateDagNode(
        key=StateDagNodeKey(handler_serial=89, state_const=0x42267E66),
        kind=StateNodeKind.EXACT,
        state_label="0x42267E66",
        handler_serial=89,
        entry_anchor=89,
        owned_blocks=(89, 90, 95),
        exclusive_blocks=(89, 90, 95),
        shared_suffix_blocks=(),
        local_segments=(),
        local_edges=(),
    )
    fallback_node = StateDagNode(
        key=StateDagNodeKey(handler_serial=202, state_const=0x24E2E77A),
        kind=StateNodeKind.EXACT,
        state_label="0x2315233C_fallback",
        handler_serial=202,
        entry_anchor=202,
        owned_blocks=(202,),
        exclusive_blocks=(202,),
        shared_suffix_blocks=(),
        local_segments=(),
        local_edges=(),
    )
    dag = LinearizedStateDag(
        dispatcher_entry_serial=2,
        state_var_stkoff=0x3C,
        pre_header_serial=None,
        initial_state=None,
        bst_node_blocks=(2,),
        nodes=(source_node, fallback_node),
        edges=(
            StateDagEdge(
                kind=SemanticEdgeKind.TRANSITION,
                source_key=source_node.key,
                target_key=fallback_node.key,
                target_state=0x24E2E77A,
                target_entry_anchor=202,
                target_label="0x2315233C_fallback",
                source_anchor=StateRedirectAnchor(
                    kind=RedirectSourceKind.UNCONDITIONAL,
                    block_serial=89,
                ),
                ordered_path=(89, 90, 95),
            ),
        ),
        diagnostics=(),
    )
    projected_flow_graph = _FakeFlowGraph(
        [
            _FakeFlowBlock(2, [], preds=[]),
            _FakeFlowBlock(89, [90], preds=[]),
            _FakeFlowBlock(90, [95], preds=[89]),
            _FakeFlowBlock(95, [160], preds=[90]),
            _FakeFlowBlock(160, [], preds=[95]),
            _FakeFlowBlock(202, [], preds=[]),
        ]
    )
    builder = ModificationBuilder(
        block_nsucc_map={2: 0, 89: 1, 90: 1, 95: 1, 160: 0, 202: 0},
        block_succ_map={2: (), 89: (90,), 90: (95,), 95: (160,), 160: (), 202: ()},
    )
    modifications: list = [
        RedirectGoto(from_serial=95, old_target=2, new_target=160),
    ]
    emitted = {(95, 160)}
    claimed_1way = {95: 160}
    owned_blocks: set[int] = set()
    owned_edges: set[tuple[int, int]] = set()

    normalized = LinearizedFlowGraphStrategy._normalize_projected_alias_handoffs(
        dag=dag,
        projected_flow_graph=projected_flow_graph,
        dispatcher_serial=2,
        redirected_blocks={95},
        bst_node_blocks={2},
        builder=builder,
        modifications=modifications,
        owned_blocks=owned_blocks,
        owned_edges=owned_edges,
        emitted=emitted,
        claimed_1way=claimed_1way,
        mba=SimpleNamespace(entry_ea=0x401000),
    )

    assert normalized == 1
    assert modifications == [
        RedirectGoto(from_serial=95, old_target=2, new_target=202),
    ]
    assert claimed_1way == {95: 202}
    assert emitted == {(95, 202)}
    assert owned_edges == {(95, 202)}


def test_lfg_plan_skips_transition_edges_from_terminal_source_nodes():
    source_node = StateDagNode(
        key=StateDagNodeKey(handler_serial=93, state_const=0x42267E66),
        kind=StateNodeKind.EXACT,
        state_label="0x42267E66",
        handler_serial=93,
        entry_anchor=93,
        owned_blocks=(93, 94, 95),
        exclusive_blocks=(93, 94, 95),
        shared_suffix_blocks=(),
        local_segments=(),
        local_edges=(),
    )
    target_node = StateDagNode(
        key=StateDagNodeKey(handler_serial=211, state_const=0x24E2E77A),
        kind=StateNodeKind.EXACT,
        state_label="0x24E2E77A",
        handler_serial=211,
        entry_anchor=211,
        owned_blocks=(211,),
        exclusive_blocks=(211,),
        shared_suffix_blocks=(),
        local_segments=(),
        local_edges=(),
    )
    dag = LinearizedStateDag(
        dispatcher_entry_serial=2,
        state_var_stkoff=None,
        pre_header_serial=None,
        initial_state=None,
        bst_node_blocks=(),
        nodes=(source_node, target_node),
        edges=(
            StateDagEdge(
                kind=SemanticEdgeKind.TRANSITION,
                source_key=source_node.key,
                target_key=target_node.key,
                target_state=0x24E2E77A,
                target_entry_anchor=211,
                target_label="0x24E2E77A",
                source_anchor=StateRedirectAnchor(
                    kind=RedirectSourceKind.UNCONDITIONAL,
                    block_serial=93,
                ),
                ordered_path=(93, 95),
            ),
            StateDagEdge(
                kind=SemanticEdgeKind.CONDITIONAL_RETURN,
                source_key=source_node.key,
                target_key=None,
                target_state=None,
                target_entry_anchor=None,
                target_label="RETURN",
                source_anchor=StateRedirectAnchor(
                    kind=RedirectSourceKind.CONDITIONAL_BRANCH,
                    block_serial=93,
                    branch_arm=0,
                ),
                ordered_path=(93, 94),
            ),
        ),
        diagnostics=(),
    )
    flow_graph = _FakeFlowGraph(
        [
            _FakeFlowBlock(93, [94, 95], preds=[]),
            _FakeFlowBlock(94, [], preds=[93]),
            _FakeFlowBlock(95, [2], preds=[93]),
            _FakeFlowBlock(211, [], preds=[]),
        ]
    )
    builder = ModificationBuilder.from_snapshot(
        SimpleNamespace(flow_graph=flow_graph, mba=SimpleNamespace(entry_ea=0x401000))
    )
    modifications: list = []

    assert not LinearizedFlowGraphStrategy._emit_dag_redirect(
        edge=dag.edges[0],
        dag=dag,
        builder=builder,
        modifications=modifications,
        owned_blocks=set(),
        owned_edges=set(),
        owned_transitions=set(),
        emitted=set(),
        claimed_1way={},
        claimed_2way={},
        claimed_exits={},
        claimed_path_edges={},
        blocked_sources=set(),
        terminal_source_keys={source_node.key},
        terminal_source_handlers={93},
        terminal_source_owned_blocks={93, 94, 95},
        terminal_protected_blocks=set(),
        report_exit_handlers={93},
        report_exit_owned_blocks={93, 94, 95},
        bst_node_blocks=set(),
        dispatcher_region=set(),
        flow_graph=flow_graph,
        state_var_stkoff=None,
        dispatcher_lookup=None,
        mba=SimpleNamespace(entry_ea=0x401000),
    )
    assert modifications == []


def test_lfg_plan_keeps_nonterminal_corridor_from_mixed_terminal_handler():
    source_node = StateDagNode(
        key=StateDagNodeKey(handler_serial=93, state_const=0x42267E66),
        kind=StateNodeKind.EXACT,
        state_label="0x42267E66",
        handler_serial=93,
        entry_anchor=93,
        owned_blocks=(93, 94, 95),
        exclusive_blocks=(93, 94, 95),
        shared_suffix_blocks=(),
        local_segments=(),
        local_edges=(),
    )
    target_node = StateDagNode(
        key=StateDagNodeKey(handler_serial=211, state_const=0x24E2E77A),
        kind=StateNodeKind.EXACT,
        state_label="0x24E2E77A",
        handler_serial=211,
        entry_anchor=211,
        owned_blocks=(211,),
        exclusive_blocks=(211,),
        shared_suffix_blocks=(),
        local_segments=(),
        local_edges=(),
    )
    dag = LinearizedStateDag(
        dispatcher_entry_serial=2,
        state_var_stkoff=None,
        pre_header_serial=None,
        initial_state=None,
        bst_node_blocks=(),
        nodes=(source_node, target_node),
        edges=(
            StateDagEdge(
                kind=SemanticEdgeKind.TRANSITION,
                source_key=source_node.key,
                target_key=target_node.key,
                target_state=0x24E2E77A,
                target_entry_anchor=211,
                target_label="0x24E2E77A",
                source_anchor=StateRedirectAnchor(
                    kind=RedirectSourceKind.UNCONDITIONAL,
                    block_serial=93,
                ),
                ordered_path=(93, 95),
            ),
            StateDagEdge(
                kind=SemanticEdgeKind.CONDITIONAL_RETURN,
                source_key=source_node.key,
                target_key=None,
                target_state=None,
                target_entry_anchor=None,
                target_label="RETURN",
                source_anchor=StateRedirectAnchor(
                    kind=RedirectSourceKind.CONDITIONAL_BRANCH,
                    block_serial=93,
                    branch_arm=0,
                ),
                ordered_path=(93, 94),
            ),
        ),
        diagnostics=(),
    )
    flow_graph = _FakeFlowGraph(
        [
            _FakeFlowBlock(93, [94, 95], preds=[]),
            _FakeFlowBlock(94, [], preds=[93]),
            _FakeFlowBlock(95, [2], preds=[93]),
            _FakeFlowBlock(211, [], preds=[]),
        ]
    )
    fake_mba = SimpleNamespace(entry_ea=0x401000)
    builder = ModificationBuilder.from_snapshot(
        SimpleNamespace(flow_graph=flow_graph, mba=fake_mba)
    )
    modifications: list = []

    assert LinearizedFlowGraphStrategy._emit_dag_redirect(
        edge=dag.edges[0],
        dag=dag,
        builder=builder,
        modifications=modifications,
        owned_blocks=set(),
        owned_edges=set(),
        owned_transitions=set(),
        emitted=set(),
        claimed_1way={},
        claimed_2way={},
        claimed_exits={},
        claimed_path_edges={},
        blocked_sources=set(),
        terminal_source_keys={source_node.key},
        terminal_source_handlers={93},
        terminal_source_owned_blocks={93, 94, 95},
        terminal_protected_blocks={93, 94},
        report_exit_handlers=set(),
        report_exit_owned_blocks=set(),
        bst_node_blocks=set(),
        dispatcher_region={2},
        flow_graph=flow_graph,
        state_var_stkoff=None,
        dispatcher_lookup=None,
        mba=fake_mba,
    )
    assert any(
        isinstance(mod, RedirectGoto)
        and mod.from_serial == 95
        and mod.old_target == 2
        and mod.new_target == 211
        for mod in modifications
    )


def test_emit_dag_redirect_retargets_stale_bst_entry_to_semantic_body():
    source_node = StateDagNode(
        key=StateDagNodeKey(handler_serial=1, state_const=0x11111111),
        kind=StateNodeKind.EXACT,
        state_label="0x11111111",
        handler_serial=1,
        entry_anchor=1,
        owned_blocks=(1,),
        exclusive_blocks=(1,),
        shared_suffix_blocks=(),
        local_segments=(),
        local_edges=(),
    )
    target_node = StateDagNode(
        key=StateDagNodeKey(handler_serial=77, state_const=0x5D0AEBD3),
        kind=StateNodeKind.EXACT,
        state_label="0x5D0AEBD3",
        handler_serial=77,
        entry_anchor=77,
        owned_blocks=(77, 78),
        exclusive_blocks=(77, 78),
        shared_suffix_blocks=(),
        local_segments=(),
        local_edges=(),
    )
    dag = LinearizedStateDag(
        dispatcher_entry_serial=2,
        state_var_stkoff=None,
        pre_header_serial=1,
        initial_state=0x11111111,
        bst_node_blocks=(77,),
        nodes=(source_node, target_node),
        edges=(
            StateDagEdge(
                kind=SemanticEdgeKind.TRANSITION,
                source_key=source_node.key,
                target_key=target_node.key,
                target_state=0x5D0AEBD3,
                target_entry_anchor=77,
                target_label="0x5D0AEBD3",
                source_anchor=StateRedirectAnchor(
                    kind=RedirectSourceKind.UNCONDITIONAL,
                    block_serial=1,
                ),
                ordered_path=(1,),
            ),
        ),
        diagnostics=(),
    )
    flow_graph = _FakeFlowGraph(
        [
            _FakeFlowBlock(1, [2], preds=[]),
            _FakeFlowBlock(2, [], preds=[1]),
            _FakeFlowBlock(77, [78, 79], preds=[]),
            _FakeFlowBlock(78, [14], preds=[77]),
            _FakeFlowBlock(79, [], preds=[77]),
            _FakeFlowBlock(14, [], preds=[78]),
        ]
    )
    fake_mba = SimpleNamespace(entry_ea=0x401000)
    builder = ModificationBuilder.from_snapshot(
        SimpleNamespace(flow_graph=flow_graph, mba=fake_mba)
    )
    modifications: list = []

    assert LinearizedFlowGraphStrategy._emit_dag_redirect(
        edge=dag.edges[0],
        dag=dag,
        builder=builder,
        modifications=modifications,
        owned_blocks=set(),
        owned_edges=set(),
        owned_transitions=set(),
        emitted=set(),
        claimed_1way={},
        claimed_2way={},
        claimed_exits={},
        claimed_path_edges={},
        blocked_sources=set(),
        terminal_source_keys=set(),
        terminal_source_handlers=set(),
        terminal_source_owned_blocks=set(),
        terminal_protected_blocks=set(),
        report_exit_handlers=set(),
        report_exit_owned_blocks=set(),
        bst_node_blocks={77},
        dispatcher_region={2, 77},
        flow_graph=flow_graph,
        state_var_stkoff=None,
        dispatcher_lookup=None,
        mba=fake_mba,
    )
    assert any(
        isinstance(mod, RedirectGoto)
        and mod.from_serial == 1
        and mod.old_target == 2
        and mod.new_target == 78
        for mod in modifications
    )


def test_emit_dag_redirect_skips_live_oneway_noop():
    source_node = StateDagNode(
        key=StateDagNodeKey(handler_serial=93, state_const=0x42267E66),
        kind=StateNodeKind.EXACT,
        state_label="0x42267E66",
        handler_serial=93,
        entry_anchor=93,
        owned_blocks=(93, 95),
        exclusive_blocks=(93, 95),
        shared_suffix_blocks=(),
        local_segments=(),
        local_edges=(),
    )
    target_node = StateDagNode(
        key=StateDagNodeKey(handler_serial=211, state_const=0x2315233C),
        kind=StateNodeKind.EXACT,
        state_label="0x2315233C",
        handler_serial=211,
        entry_anchor=211,
        owned_blocks=(211,),
        exclusive_blocks=(211,),
        shared_suffix_blocks=(),
        local_segments=(),
        local_edges=(),
    )
    dag = LinearizedStateDag(
        dispatcher_entry_serial=2,
        state_var_stkoff=None,
        pre_header_serial=None,
        initial_state=None,
        bst_node_blocks=(),
        nodes=(source_node, target_node),
        edges=(
            StateDagEdge(
                kind=SemanticEdgeKind.TRANSITION,
                source_key=source_node.key,
                target_key=target_node.key,
                target_state=0x2315233C,
                target_entry_anchor=211,
                target_label="0x2315233C",
                source_anchor=StateRedirectAnchor(
                    kind=RedirectSourceKind.UNCONDITIONAL,
                    block_serial=95,
                ),
                ordered_path=(93, 95),
            ),
        ),
        diagnostics=(),
    )
    flow_graph = _FakeFlowGraph(
        [
            _FakeFlowBlock(93, [95], preds=[]),
            _FakeFlowBlock(95, [211], preds=[93]),
            _FakeFlowBlock(211, [], preds=[95]),
        ]
    )
    fake_mba = SimpleNamespace(entry_ea=0x401000)
    builder = ModificationBuilder.from_snapshot(
        SimpleNamespace(flow_graph=flow_graph, mba=fake_mba)
    )
    modifications: list = []

    assert not LinearizedFlowGraphStrategy._emit_dag_redirect(
        edge=dag.edges[0],
        dag=dag,
        builder=builder,
        modifications=modifications,
        owned_blocks=set(),
        owned_edges=set(),
        owned_transitions=set(),
        emitted=set(),
        claimed_1way={},
        claimed_2way={},
        claimed_exits={},
        claimed_path_edges={},
        blocked_sources=set(),
        terminal_source_keys=set(),
        terminal_source_handlers=set(),
        terminal_source_owned_blocks=set(),
        terminal_protected_blocks=set(),
        report_exit_handlers=set(),
        report_exit_owned_blocks=set(),
        bst_node_blocks=set(),
        dispatcher_region={2},
        flow_graph=flow_graph,
        state_var_stkoff=None,
        dispatcher_lookup=None,
        mba=fake_mba,
    )
    assert modifications == []


def test_lfg_residual_dispatcher_handoff_ignores_dispatcher_mediated_backpath():
    alias_node = StateDagNode(
        key=StateDagNodeKey(handler_serial=24, state_const=0x27EEEA11),
        kind=StateNodeKind.EXACT,
        state_label="0x258ED455_fallback",
        handler_serial=24,
        entry_anchor=24,
        owned_blocks=(24, 32),
        exclusive_blocks=(24, 32),
        shared_suffix_blocks=(),
        local_segments=(),
        local_edges=(),
    )
    dag = LinearizedStateDag(
        dispatcher_entry_serial=2,
        state_var_stkoff=0x3C,
        pre_header_serial=None,
        initial_state=None,
        bst_node_blocks=(2,),
        nodes=(alias_node,),
        edges=(),
        diagnostics=(),
    )
    state_write = _FakeInsn(
        lfg_module.ida_hexrays.m_mov,
        l=_FakeMop(lfg_module.ida_hexrays.mop_n, value=0x27EEEA11),
        d=_FakeMop(lfg_module.ida_hexrays.mop_S, off=0x3C),
    )
    mba_blocks = [
        _FakeMBAFlowBlock(2, [33, 112], preds=[32, 33], head=None),
        _FakeMBAFlowBlock(24, [32], preds=[198], head=None),
        _FakeMBAFlowBlock(32, [2], preds=[24], head=None),
        _FakeMBAFlowBlock(33, [2], preds=[2], head=state_write),
        _FakeMBAFlowBlock(112, [], preds=[2], head=None),
    ]
    flow_graph = _FakeFlowGraph(mba_blocks)
    fake_mba = _FakeMBA(blocks=mba_blocks)
    builder = ModificationBuilder.from_snapshot(
        SimpleNamespace(flow_graph=flow_graph, mba=fake_mba)
    )
    modifications: list = []
    emitted: set[tuple[int, int]] = set()
    claimed_1way: dict[int, int] = {}

    redirected = LinearizedFlowGraphStrategy._emit_residual_dispatcher_handoffs(
        dag=dag,
        state_machine=None,
        projected_flow_graph=flow_graph,
        dispatcher_serial=2,
        bst_node_blocks={2},
        builder=builder,
        modifications=modifications,
        owned_blocks=set(),
        owned_edges=set(),
        owned_transitions=set(),
        emitted=emitted,
        claimed_1way=claimed_1way,
        claimed_2way={},
        state_var_stkoff=0x3C,
        dispatcher_lookup=lambda state: 24 if state == 0x27EEEA11 else None,
        dispatcher=None,
        mba=fake_mba,
        redirected_blocks=set(),
    )

    assert redirected == 1
    assert any(
        isinstance(mod, RedirectGoto)
        and mod.from_serial == 33
        and mod.old_target == 2
        and mod.new_target == 24
        for mod in modifications
    )


def test_lfg_residual_dispatcher_handoff_splits_shared_feeder_by_predecessor():
    target_node = StateDagNode(
        key=StateDagNodeKey(handler_serial=24, state_const=0x11111111),
        kind=StateNodeKind.EXACT,
        state_label="0x11111111",
        handler_serial=24,
        entry_anchor=24,
        owned_blocks=(24,),
        exclusive_blocks=(24,),
        shared_suffix_blocks=(),
        local_segments=(),
        local_edges=(),
    )
    dag = LinearizedStateDag(
        dispatcher_entry_serial=2,
        state_var_stkoff=0x3C,
        pre_header_serial=None,
        initial_state=None,
        bst_node_blocks=(2,),
        nodes=(target_node,),
        edges=(),
        diagnostics=(),
    )
    via_pred_insn_2 = _FakeInsn(
        lfg_module.ida_hexrays.m_mov,
        l=_FakeMop(lfg_module.ida_hexrays.mop_n, value=0xBBBB1111),
        d=_FakeMop(lfg_module.ida_hexrays.mop_S, off=0x68),
    )
    via_pred_insn_1 = _FakeInsn(
        lfg_module.ida_hexrays.m_mov,
        l=_FakeMop(lfg_module.ida_hexrays.mop_n, value=0xAAAA0000),
        d=_FakeMop(lfg_module.ida_hexrays.mop_S, off=0x60),
        next_insn=via_pred_insn_2,
    )
    state_write = _FakeInsn(
        lfg_module.ida_hexrays.m_xor,
        l=_FakeMop(lfg_module.ida_hexrays.mop_S, off=0x68),
        r=_FakeMop(lfg_module.ida_hexrays.mop_S, off=0x60),
        d=_FakeMop(lfg_module.ida_hexrays.mop_S, off=0x3C),
    )
    mba_blocks = [
        _FakeMBAFlowBlock(2, [10, 112], preds=[10], head=None),
        _FakeMBAFlowBlock(9, [10], preds=[], head=via_pred_insn_1),
        _FakeMBAFlowBlock(10, [2], preds=[9, 11], head=state_write),
        _FakeMBAFlowBlock(11, [10], preds=[], head=None),
        _FakeMBAFlowBlock(24, [], preds=[], head=None),
        _FakeMBAFlowBlock(112, [], preds=[2], head=None),
    ]
    flow_graph = _FakeFlowGraph(mba_blocks)
    fake_mba = _FakeMBA(blocks=mba_blocks)
    builder = ModificationBuilder.from_snapshot(
        SimpleNamespace(flow_graph=flow_graph, mba=fake_mba)
    )
    modifications: list = []

    redirected = LinearizedFlowGraphStrategy._emit_residual_dispatcher_handoffs(
        dag=dag,
        state_machine=None,
        projected_flow_graph=flow_graph,
        dispatcher_serial=2,
        bst_node_blocks={2},
        builder=builder,
        modifications=modifications,
        owned_blocks=set(),
        owned_edges=set(),
        owned_transitions=set(),
        emitted=set(),
        claimed_1way={},
        claimed_2way={},
        state_var_stkoff=0x3C,
        dispatcher_lookup=None,
        dispatcher=None,
        mba=fake_mba,
        redirected_blocks=set(),
    )

    assert redirected == 1
    assert any(
        isinstance(mod, EdgeRedirectViaPredSplit)
        and mod.src_block == 10
        and mod.via_pred == 9
        and mod.old_target == 2
        and mod.new_target == 24
        for mod in modifications
    )


def test_lfg_residual_dispatcher_state_write_prefers_synthesized_pred_handoff(
    monkeypatch,
):
    correct_target = StateDagNode(
        key=StateDagNodeKey(handler_serial=24, state_const=0x11111111),
        kind=StateNodeKind.EXACT,
        state_label="0x11111111",
        handler_serial=24,
        entry_anchor=24,
        owned_blocks=(24,),
        exclusive_blocks=(24,),
        shared_suffix_blocks=(),
        local_segments=(),
        local_edges=(),
    )
    wrong_target = StateDagNode(
        key=StateDagNodeKey(handler_serial=130, state_const=0x22222222),
        kind=StateNodeKind.EXACT,
        state_label="0x22222222",
        handler_serial=130,
        entry_anchor=130,
        owned_blocks=(130,),
        exclusive_blocks=(130,),
        shared_suffix_blocks=(),
        local_segments=(),
        local_edges=(),
    )
    dag = LinearizedStateDag(
        dispatcher_entry_serial=2,
        state_var_stkoff=0x3C,
        pre_header_serial=None,
        initial_state=None,
        bst_node_blocks=(2,),
        nodes=(correct_target, wrong_target),
        edges=(),
        diagnostics=(),
    )
    via_pred_insn_2 = _FakeInsn(
        lfg_module.ida_hexrays.m_mov,
        l=_FakeMop(lfg_module.ida_hexrays.mop_n, value=0xBBBB1111),
        d=_FakeMop(lfg_module.ida_hexrays.mop_S, off=0x68),
    )
    via_pred_insn_1 = _FakeInsn(
        lfg_module.ida_hexrays.m_mov,
        l=_FakeMop(lfg_module.ida_hexrays.mop_n, value=0xAAAA0000),
        d=_FakeMop(lfg_module.ida_hexrays.mop_S, off=0x60),
        next_insn=via_pred_insn_2,
    )
    state_write = _FakeInsn(
        lfg_module.ida_hexrays.m_xor,
        l=_FakeMop(lfg_module.ida_hexrays.mop_S, off=0x68),
        r=_FakeMop(lfg_module.ida_hexrays.mop_S, off=0x60),
        d=_FakeMop(lfg_module.ida_hexrays.mop_S, off=0x3C),
    )
    mba_blocks = [
        _FakeMBAFlowBlock(2, [10, 112], preds=[10], head=None),
        _FakeMBAFlowBlock(9, [10], preds=[], head=via_pred_insn_1),
        _FakeMBAFlowBlock(10, [2], preds=[9, 11], head=state_write),
        _FakeMBAFlowBlock(11, [10], preds=[], head=None),
        _FakeMBAFlowBlock(24, [], preds=[], head=None),
        _FakeMBAFlowBlock(130, [], preds=[], head=None),
        _FakeMBAFlowBlock(112, [], preds=[2], head=None),
    ]
    flow_graph = _FakeFlowGraph(mba_blocks)
    fake_mba = _FakeMBA(blocks=mba_blocks)
    builder = ModificationBuilder.from_snapshot(
        SimpleNamespace(flow_graph=flow_graph, mba=fake_mba)
    )
    modifications: list = []

    def _wrong_projected_path_tail_target(
        cls,
        dag,
        *,
        source_block,
        bst_node_blocks,
        dispatcher,
        predecessor_hints=None,
        require_predecessor_match=False,
    ):
        if source_block == 10 and predecessor_hints:
            return (0x22222222, 130)
        return None

    monkeypatch.setattr(
        LinearizedFlowGraphStrategy,
        "_resolve_projected_path_tail_target",
        classmethod(_wrong_projected_path_tail_target),
    )

    redirected = LinearizedFlowGraphStrategy._emit_residual_dispatcher_handoffs(
        dag=dag,
        state_machine=None,
        projected_flow_graph=flow_graph,
        dispatcher_serial=2,
        bst_node_blocks={2},
        builder=builder,
        modifications=modifications,
        owned_blocks=set(),
        owned_edges=set(),
        owned_transitions=set(),
        emitted=set(),
        claimed_1way={},
        claimed_2way={},
        state_var_stkoff=0x3C,
        dispatcher_lookup=None,
        dispatcher=None,
        mba=fake_mba,
        redirected_blocks=set(),
    )

    assert redirected == 2
    assert any(
        isinstance(mod, EdgeRedirectViaPredSplit)
        and mod.src_block == 10
        and mod.via_pred == 9
        and mod.old_target == 2
        and mod.new_target == 24
        for mod in modifications
    )
    assert any(
        isinstance(mod, EdgeRedirectViaPredSplit)
        and mod.src_block == 10
        and mod.via_pred == 11
        and mod.old_target == 2
        and mod.new_target == 130
        for mod in modifications
    )


def test_lfg_residual_dispatcher_pred_split_uses_projected_predecessor_context():
    source_node = StateDagNode(
        key=StateDagNodeKey(handler_serial=66, state_const=0x474EEEBB),
        kind=StateNodeKind.EXACT,
        state_label="0x474EEEBB",
        handler_serial=66,
        entry_anchor=66,
        owned_blocks=(66, 68, 69),
        exclusive_blocks=(66, 68, 69),
        shared_suffix_blocks=(),
        local_segments=(),
        local_edges=(),
    )
    upper_target = StateDagNode(
        key=StateDagNodeKey(handler_serial=98, state_const=0x6CAA9521),
        kind=StateNodeKind.EXACT,
        state_label="0x6CAA9521",
        handler_serial=98,
        entry_anchor=98,
        owned_blocks=(98,),
        exclusive_blocks=(98,),
        shared_suffix_blocks=(),
        local_segments=(),
        local_edges=(),
    )
    fallback_target = StateDagNode(
        key=StateDagNodeKey(handler_serial=160, state_const=0x11CD1DA3),
        kind=StateNodeKind.EXACT,
        state_label="0x11CD1DA3_fallback",
        handler_serial=160,
        entry_anchor=160,
        owned_blocks=(160,),
        exclusive_blocks=(160,),
        shared_suffix_blocks=(),
        local_segments=(),
        local_edges=(),
    )
    dag = LinearizedStateDag(
        dispatcher_entry_serial=2,
        state_var_stkoff=0x3C,
        pre_header_serial=None,
        initial_state=None,
        bst_node_blocks=(2,),
        nodes=(source_node, upper_target, fallback_target),
        edges=(
            StateDagEdge(
                kind=SemanticEdgeKind.CONDITIONAL_TRANSITION,
                source_key=source_node.key,
                target_key=upper_target.key,
                target_state=0x6CAA9521,
                target_entry_anchor=98,
                target_label="0x6CAA9521",
                source_anchor=StateRedirectAnchor(
                    kind=RedirectSourceKind.CONDITIONAL_BRANCH,
                    block_serial=101,
                    branch_arm=0,
                ),
                ordered_path=(101, 102, 69),
            ),
            StateDagEdge(
                kind=SemanticEdgeKind.CONDITIONAL_TRANSITION,
                source_key=source_node.key,
                target_key=fallback_target.key,
                target_state=0x6E958F9A,
                target_entry_anchor=160,
                target_label="0x6D207773_fallback",
                source_anchor=StateRedirectAnchor(
                    kind=RedirectSourceKind.CONDITIONAL_BRANCH,
                    block_serial=163,
                    branch_arm=1,
                ),
                ordered_path=(161, 163, 164, 69),
            ),
        ),
        diagnostics=(),
    )
    mba_blocks = [
        _FakeMBAFlowBlock(2, [3, 112], preds=[69], head=None),
        _FakeMBAFlowBlock(69, [2], preds=[102, 164], head=None),
        _FakeMBAFlowBlock(98, [], preds=[], head=None),
        _FakeMBAFlowBlock(101, [102, 103], preds=[], head=None),
        _FakeMBAFlowBlock(102, [69], preds=[101], head=None),
        _FakeMBAFlowBlock(160, [], preds=[], head=None),
        _FakeMBAFlowBlock(163, [164, 165], preds=[], head=None),
        _FakeMBAFlowBlock(164, [69], preds=[163], head=None),
        _FakeMBAFlowBlock(112, [], preds=[2], head=None),
    ]
    flow_graph = _FakeFlowGraph(mba_blocks)
    fake_mba = _FakeMBA(blocks=mba_blocks)
    builder = ModificationBuilder.from_snapshot(
        SimpleNamespace(flow_graph=flow_graph, mba=fake_mba)
    )
    modifications: list = []

    redirected = LinearizedFlowGraphStrategy._emit_residual_dispatcher_handoffs(
        dag=dag,
        state_machine=None,
        projected_flow_graph=flow_graph,
        dispatcher_serial=2,
        bst_node_blocks={2},
        builder=builder,
        modifications=modifications,
        owned_blocks=set(),
        owned_edges=set(),
        owned_transitions=set(),
        emitted=set(),
        claimed_1way={},
        claimed_2way={},
        state_var_stkoff=None,
        dispatcher_lookup=None,
        dispatcher=None,
        mba=fake_mba,
        redirected_blocks=set(),
    )

    assert redirected == 1
    assert any(
        isinstance(mod, RedirectBranch)
        and mod.from_serial == 101
        and mod.old_target == 102
        and mod.new_target == 98
        for mod in modifications
    )
    assert not any(
        isinstance(mod, EdgeRedirectViaPredSplit)
        and mod.src_block == 69
        and mod.old_target == 2
        and mod.new_target == 98
        for mod in modifications
    )


def test_lfg_residual_pred_split_ignores_backpath_to_original_shared_feeder():
    target_node = StateDagNode(
        key=StateDagNodeKey(handler_serial=24, state_const=0x11111111),
        kind=StateNodeKind.EXACT,
        state_label="0x11111111",
        handler_serial=24,
        entry_anchor=24,
        owned_blocks=(24,),
        exclusive_blocks=(24,),
        shared_suffix_blocks=(),
        local_segments=(),
        local_edges=(),
    )
    dag = LinearizedStateDag(
        dispatcher_entry_serial=2,
        state_var_stkoff=0x3C,
        pre_header_serial=None,
        initial_state=None,
        bst_node_blocks=(2,),
        nodes=(target_node,),
        edges=(),
        diagnostics=(),
    )
    via_pred_insn_2 = _FakeInsn(
        lfg_module.ida_hexrays.m_mov,
        l=_FakeMop(lfg_module.ida_hexrays.mop_n, value=0xBBBB1111),
        d=_FakeMop(lfg_module.ida_hexrays.mop_S, off=0x68),
    )
    via_pred_insn_1 = _FakeInsn(
        lfg_module.ida_hexrays.m_mov,
        l=_FakeMop(lfg_module.ida_hexrays.mop_n, value=0xAAAA0000),
        d=_FakeMop(lfg_module.ida_hexrays.mop_S, off=0x60),
        next_insn=via_pred_insn_2,
    )
    state_write = _FakeInsn(
        lfg_module.ida_hexrays.m_xor,
        l=_FakeMop(lfg_module.ida_hexrays.mop_S, off=0x68),
        r=_FakeMop(lfg_module.ida_hexrays.mop_S, off=0x60),
        d=_FakeMop(lfg_module.ida_hexrays.mop_S, off=0x3C),
    )
    mba_blocks = [
        _FakeMBAFlowBlock(2, [10, 112], preds=[10], head=None),
        _FakeMBAFlowBlock(9, [10], preds=[], head=via_pred_insn_1),
        _FakeMBAFlowBlock(10, [2], preds=[9, 11, 24], head=state_write),
        _FakeMBAFlowBlock(11, [10], preds=[], head=None),
        _FakeMBAFlowBlock(24, [10], preds=[], head=None),
        _FakeMBAFlowBlock(112, [], preds=[2], head=None),
    ]
    flow_graph = _FakeFlowGraph(mba_blocks)
    fake_mba = _FakeMBA(blocks=mba_blocks)
    builder = ModificationBuilder.from_snapshot(
        SimpleNamespace(flow_graph=flow_graph, mba=fake_mba)
    )
    modifications: list = []

    redirected = LinearizedFlowGraphStrategy._emit_residual_dispatcher_handoffs(
        dag=dag,
        state_machine=None,
        projected_flow_graph=flow_graph,
        dispatcher_serial=2,
        bst_node_blocks={2},
        builder=builder,
        modifications=modifications,
        owned_blocks=set(),
        owned_edges=set(),
        owned_transitions=set(),
        emitted=set(),
        claimed_1way={},
        claimed_2way={},
        state_var_stkoff=0x3C,
        dispatcher_lookup=None,
        dispatcher=None,
        mba=fake_mba,
        redirected_blocks=set(),
    )

    assert redirected == 1
    assert any(
        isinstance(mod, EdgeRedirectViaPredSplit)
        and mod.src_block == 10
        and mod.via_pred == 9
        and mod.old_target == 2
        and mod.new_target == 24
        for mod in modifications
    )


def test_lfg_residual_pred_split_rejects_backpath_to_via_pred():
    target_node = StateDagNode(
        key=StateDagNodeKey(handler_serial=24, state_const=0x11111111),
        kind=StateNodeKind.EXACT,
        state_label="0x11111111",
        handler_serial=24,
        entry_anchor=24,
        owned_blocks=(24,),
        exclusive_blocks=(24,),
        shared_suffix_blocks=(),
        local_segments=(),
        local_edges=(),
    )
    dag = LinearizedStateDag(
        dispatcher_entry_serial=2,
        state_var_stkoff=0x3C,
        pre_header_serial=None,
        initial_state=None,
        bst_node_blocks=(2,),
        nodes=(target_node,),
        edges=(),
        diagnostics=(),
    )
    via_pred_insn_2 = _FakeInsn(
        lfg_module.ida_hexrays.m_mov,
        l=_FakeMop(lfg_module.ida_hexrays.mop_n, value=0xBBBB1111),
        d=_FakeMop(lfg_module.ida_hexrays.mop_S, off=0x68),
    )
    via_pred_insn_1 = _FakeInsn(
        lfg_module.ida_hexrays.m_mov,
        l=_FakeMop(lfg_module.ida_hexrays.mop_n, value=0xAAAA0000),
        d=_FakeMop(lfg_module.ida_hexrays.mop_S, off=0x60),
        next_insn=via_pred_insn_2,
    )
    state_write = _FakeInsn(
        lfg_module.ida_hexrays.m_xor,
        l=_FakeMop(lfg_module.ida_hexrays.mop_S, off=0x68),
        r=_FakeMop(lfg_module.ida_hexrays.mop_S, off=0x60),
        d=_FakeMop(lfg_module.ida_hexrays.mop_S, off=0x3C),
    )
    mba_blocks = [
        _FakeMBAFlowBlock(2, [10, 112], preds=[10], head=None),
        _FakeMBAFlowBlock(9, [10], preds=[24], head=via_pred_insn_1),
        _FakeMBAFlowBlock(10, [2], preds=[9, 11], head=state_write),
        _FakeMBAFlowBlock(11, [10], preds=[], head=None),
        _FakeMBAFlowBlock(24, [9], preds=[], head=None),
        _FakeMBAFlowBlock(112, [], preds=[2], head=None),
    ]
    flow_graph = _FakeFlowGraph(mba_blocks)
    fake_mba = _FakeMBA(blocks=mba_blocks)
    builder = ModificationBuilder.from_snapshot(
        SimpleNamespace(flow_graph=flow_graph, mba=fake_mba)
    )
    modifications: list = []

    redirected = LinearizedFlowGraphStrategy._emit_residual_dispatcher_handoffs(
        dag=dag,
        state_machine=None,
        projected_flow_graph=flow_graph,
        dispatcher_serial=2,
        bst_node_blocks={2},
        builder=builder,
        modifications=modifications,
        owned_blocks=set(),
        owned_edges=set(),
        owned_transitions=set(),
        emitted=set(),
        claimed_1way={},
        claimed_2way={},
        state_var_stkoff=0x3C,
        dispatcher_lookup=None,
        dispatcher=None,
        mba=fake_mba,
        redirected_blocks=set(),
    )

    assert redirected == 0
    assert modifications == []


def test_lfg_residual_handoff_falls_back_to_live_mba_for_normalized_alias():
    target_node = StateDagNode(
        key=StateDagNodeKey(handler_serial=78, state_const=0x604AAEA6),
        kind=StateNodeKind.RANGE_BACKED,
        state_label="0x606DC166_fallback",
        handler_serial=78,
        entry_anchor=78,
        owned_blocks=(78,),
        exclusive_blocks=(78,),
        shared_suffix_blocks=(),
        local_segments=(),
        local_edges=(),
    )
    dag = LinearizedStateDag(
        dispatcher_entry_serial=2,
        state_var_stkoff=0x3C,
        pre_header_serial=None,
        initial_state=None,
        bst_node_blocks=(2,),
        nodes=(target_node,),
        edges=(),
        diagnostics=(),
    )
    projected_blocks = [
        _FakeFlowBlock(2, [], preds=[111]),
        _FakeFlowBlock(78, [], preds=[]),
        _FakeFlowBlock(107, [111], preds=[]),
        _FakeFlowBlock(111, [2], preds=[107]),
    ]
    for block in projected_blocks:
        block.insn_snapshots = ()
    flow_graph = _FakeFlowGraph(projected_blocks)
    state_write = _FakeInsn(
        lfg_module.ida_hexrays.m_mov,
        l=_FakeMop(lfg_module.ida_hexrays.mop_n, value=0x604AAEA6),
        d=_FakeMop(lfg_module.ida_hexrays.mop_S, off=0x3C),
    )
    live_mba = _FakeMBA(
        blocks=[
            _FakeMBAFlowBlock(2, [], preds=[111], head=None),
            _FakeMBAFlowBlock(78, [], preds=[], head=None),
            _FakeMBAFlowBlock(107, [111], preds=[], head=None),
            _FakeMBAFlowBlock(111, [2], preds=[107], head=state_write),
        ]
    )
    builder = ModificationBuilder.from_snapshot(
        SimpleNamespace(flow_graph=flow_graph, mba=live_mba)
    )
    modifications: list = []

    redirected = LinearizedFlowGraphStrategy._emit_residual_dispatcher_handoffs(
        dag=dag,
        state_machine=None,
        projected_flow_graph=flow_graph,
        dispatcher_serial=2,
        bst_node_blocks={2},
        builder=builder,
        modifications=modifications,
        owned_blocks=set(),
        owned_edges=set(),
        owned_transitions=set(),
        emitted=set(),
        claimed_1way={},
        claimed_2way={},
        state_var_stkoff=0x3C,
        dispatcher_lookup=None,
        dispatcher=None,
        mba=live_mba,
        redirected_blocks=set(),
    )

    assert redirected == 1
    assert any(
        isinstance(mod, RedirectGoto)
        and mod.from_serial == 111
        and mod.old_target == 2
        and mod.new_target == 78
        for mod in modifications
    )


def test_lfg_collects_only_live_dispatcher_predecessors_from_preheader():
    flow_graph = _FakeFlowGraph(
        [
            _FakeFlowBlock(1, [93], preds=[]),
            _FakeFlowBlock(2, [], preds=[95, 131]),
            _FakeFlowBlock(93, [95], preds=[1]),
            _FakeFlowBlock(95, [2], preds=[93]),
            _FakeFlowBlock(131, [2], preds=[]),
        ]
    )

    residual = LinearizedFlowGraphStrategy._collect_residual_dispatcher_predecessors(
        flow_graph,
        2,
        bst_node_blocks=set(),
        reachable_from_serial=1,
    )

    assert residual == (95,)


def test_lfg_same_maturity_rerun_requires_residual_dispatcher_improvement():
    func_ea = 0x401000
    maturity = 7
    key = (func_ea, maturity)
    strategy = LinearizedFlowGraphStrategy()
    flow_graph = _FakeFlowGraph(
        [
            _FakeFlowBlock(1, [95, 131, 140, 152, 158, 170], preds=[]),
            _FakeFlowBlock(95, [2], preds=[1]),
            _FakeFlowBlock(131, [2], preds=[1]),
            _FakeFlowBlock(140, [2], preds=[1]),
            _FakeFlowBlock(152, [2], preds=[1]),
            _FakeFlowBlock(158, [2], preds=[1]),
            _FakeFlowBlock(170, [2], preds=[1]),
            _FakeFlowBlock(2, [], preds=[95, 131, 140, 152, 158, 170]),
        ]
    )
    fake_mba = SimpleNamespace(entry_ea=func_ea, maturity=maturity)
    snapshot = AnalysisSnapshot(
        mba=fake_mba,
        state_machine=SimpleNamespace(
            handlers={93: object()},
            initial_state=0x42267E66,
            state_var=None,
        ),
        bst_result=SimpleNamespace(handler_state_map={93: 0x42267E66}, bst_node_blocks=()),
        bst_dispatcher_serial=2,
        flow_graph=flow_graph,
    )

    old_applied = set(LinearizedFlowGraphStrategy._applied)
    old_residual_counts = dict(
        LinearizedFlowGraphStrategy._last_successful_residual_dispatcher_pred_counts
    )
    try:
        LinearizedFlowGraphStrategy._applied.add(key)
        LinearizedFlowGraphStrategy._last_successful_residual_dispatcher_pred_counts[key] = 5

        assert not strategy.is_applicable(snapshot)

        LinearizedFlowGraphStrategy._last_successful_residual_dispatcher_pred_counts[key] = 7

        assert strategy.is_applicable(snapshot)
    finally:
        LinearizedFlowGraphStrategy._applied = old_applied
        LinearizedFlowGraphStrategy._last_successful_residual_dispatcher_pred_counts = (
            old_residual_counts
        )


def test_lfg_same_maturity_rerun_allows_one_equal_count_retry_for_live_exact_handoff():
    func_ea = 0x401000
    maturity = 7
    key = (func_ea, maturity)
    strategy = LinearizedFlowGraphStrategy()
    state_write = _FakeInsn(
        lfg_module.ida_hexrays.m_mov,
        l=_FakeMop(lfg_module.ida_hexrays.mop_n, value=0x6465D165),
        d=_FakeMop(lfg_module.ida_hexrays.mop_S, off=0x3C),
    )
    flow_graph = _FakeFlowGraph(
        [
            _FakeMBAFlowBlock(1, [95], preds=[]),
            _FakeMBAFlowBlock(95, [2], preds=[1], head=state_write),
            _FakeFlowBlock(2, [], preds=[95]),
        ]
    )
    fake_mba = _FakeMBA(
        blocks=[
            _FakeMBAFlowBlock(1, [95], preds=[]),
            _FakeMBAFlowBlock(95, [2], preds=[1], head=state_write),
            _FakeMBAFlowBlock(2, [], preds=[95]),
        ],
        entry_ea=func_ea,
    )
    fake_mba.maturity = maturity
    snapshot = AnalysisSnapshot(
        mba=fake_mba,
        state_machine=SimpleNamespace(
            handlers={93: object()},
            initial_state=0x42267E66,
            state_var=SimpleNamespace(
                t=lfg_module.ida_hexrays.mop_S,
                s=SimpleNamespace(off=0x3C),
            ),
        ),
        bst_result=SimpleNamespace(
            handler_state_map={93: 0x42267E66},
            bst_node_blocks=(),
            dispatcher=SimpleNamespace(
                _rows=(SimpleNamespace(lo=0x6465D165, hi=0x6465D166, target=23),)
            ),
        ),
        bst_dispatcher_serial=2,
        flow_graph=flow_graph,
    )

    old_applied = set(LinearizedFlowGraphStrategy._applied)
    old_residual_counts = dict(
        LinearizedFlowGraphStrategy._last_successful_residual_dispatcher_pred_counts
    )
    old_equal_retry = set(LinearizedFlowGraphStrategy._same_count_exact_rerun_used)
    try:
        LinearizedFlowGraphStrategy._applied.add(key)
        LinearizedFlowGraphStrategy._last_successful_residual_dispatcher_pred_counts[key] = 1

        assert strategy.is_applicable(snapshot)
        assert key not in LinearizedFlowGraphStrategy._same_count_exact_rerun_used
        assert LinearizedFlowGraphStrategy._allow_same_maturity_rerun(
            snapshot,
            consume_retry=True,
        )
        assert key in LinearizedFlowGraphStrategy._same_count_exact_rerun_used
        assert not strategy.is_applicable(snapshot)
    finally:
        LinearizedFlowGraphStrategy._applied = old_applied
        LinearizedFlowGraphStrategy._last_successful_residual_dispatcher_pred_counts = (
            old_residual_counts
        )
        LinearizedFlowGraphStrategy._same_count_exact_rerun_used = old_equal_retry


def test_lfg_same_maturity_rerun_uses_raw_dispatcher_predecessors():
    func_ea = 0x401000
    maturity = 7
    key = (func_ea, maturity)
    strategy = LinearizedFlowGraphStrategy()
    flow_graph = _FakeFlowGraph(
        [
            _FakeFlowBlock(0, [1], preds=[]),
            _FakeFlowBlock(1, [], preds=[0]),
            _FakeFlowBlock(95, [2], preds=[]),
            _FakeFlowBlock(2, [], preds=[95]),
        ]
    )
    flow_graph.entry_serial = 0
    fake_mba = SimpleNamespace(entry_ea=func_ea, maturity=maturity)
    snapshot = AnalysisSnapshot(
        mba=fake_mba,
        state_machine=SimpleNamespace(
            handlers={93: object()},
            initial_state=0x42267E66,
            state_var=None,
        ),
        bst_result=SimpleNamespace(handler_state_map={93: 0x42267E66}, bst_node_blocks=()),
        bst_dispatcher_serial=2,
        flow_graph=flow_graph,
    )

    old_applied = set(LinearizedFlowGraphStrategy._applied)
    old_residual_counts = dict(
        LinearizedFlowGraphStrategy._last_successful_residual_dispatcher_pred_counts
    )
    old_equal_retry = set(LinearizedFlowGraphStrategy._same_count_exact_rerun_used)
    try:
        LinearizedFlowGraphStrategy._applied.add(key)
        LinearizedFlowGraphStrategy._last_successful_residual_dispatcher_pred_counts[key] = 2

        assert strategy.is_applicable(snapshot)
        assert LinearizedFlowGraphStrategy._allow_same_maturity_rerun(
            snapshot,
            consume_retry=False,
        )
    finally:
        LinearizedFlowGraphStrategy._applied = old_applied
        LinearizedFlowGraphStrategy._last_successful_residual_dispatcher_pred_counts = (
            old_residual_counts
        )
        LinearizedFlowGraphStrategy._same_count_exact_rerun_used = old_equal_retry


def test_lfg_same_maturity_rerun_allows_one_exploratory_equal_count_retry():
    func_ea = 0x401000
    maturity = 7
    key = (func_ea, maturity)
    strategy = LinearizedFlowGraphStrategy()
    flow_graph = _FakeFlowGraph(
        [
            _FakeFlowBlock(95, [2], preds=[]),
            _FakeFlowBlock(2, [], preds=[95]),
        ]
    )
    fake_mba = SimpleNamespace(entry_ea=func_ea, maturity=maturity)
    snapshot = AnalysisSnapshot(
        mba=fake_mba,
        state_machine=SimpleNamespace(
            handlers={93: object()},
            initial_state=0x42267E66,
            state_var=None,
        ),
        bst_result=SimpleNamespace(handler_state_map={93: 0x42267E66}, bst_node_blocks=()),
        bst_dispatcher_serial=2,
        flow_graph=flow_graph,
    )

    old_applied = set(LinearizedFlowGraphStrategy._applied)
    old_residual_counts = dict(
        LinearizedFlowGraphStrategy._last_successful_residual_dispatcher_pred_counts
    )
    old_equal_retry = set(LinearizedFlowGraphStrategy._same_count_exact_rerun_used)
    try:
        LinearizedFlowGraphStrategy._applied.add(key)
        LinearizedFlowGraphStrategy._last_successful_residual_dispatcher_pred_counts[key] = 1

        assert strategy.is_applicable(snapshot)
        assert LinearizedFlowGraphStrategy._allow_same_maturity_rerun(
            snapshot,
            consume_retry=True,
        )
        assert key in LinearizedFlowGraphStrategy._same_count_exact_rerun_used
        assert not strategy.is_applicable(snapshot)
    finally:
        LinearizedFlowGraphStrategy._applied = old_applied
        LinearizedFlowGraphStrategy._last_successful_residual_dispatcher_pred_counts = (
            old_residual_counts
        )
        LinearizedFlowGraphStrategy._same_count_exact_rerun_used = old_equal_retry


def test_lfg_same_maturity_rerun_skips_full_dag_edge_replanning(monkeypatch):
    func_ea = 0x401000
    maturity = 7
    key = (func_ea, maturity)
    strategy = LinearizedFlowGraphStrategy()
    flow_graph = _FakeFlowGraph(
        [
            _FakeFlowBlock(1, [95], preds=[]),
            _FakeFlowBlock(95, [2], preds=[1]),
            _FakeFlowBlock(2, [], preds=[95]),
        ]
    )
    fake_mba = SimpleNamespace(entry_ea=func_ea, maturity=maturity)
    sm = DispatcherStateMachine(
        mba=fake_mba,
        initial_state=0x42267E66,
        handlers={
            0x42267E66: StateHandler(
                state_value=0x42267E66,
                check_block=95,
                handler_blocks=[95],
            ),
        },
    )
    snapshot = AnalysisSnapshot(
        mba=fake_mba,
        state_machine=sm,
        bst_result=SimpleNamespace(
            handler_state_map={95: 0x42267E66},
            handler_range_map={},
            pre_header_serial=None,
            bst_node_blocks=set(),
            dispatcher=None,
            diagnostics=(),
        ),
        bst_dispatcher_serial=2,
        flow_graph=flow_graph,
    )
    empty_dag = LinearizedStateDag(
        dispatcher_entry_serial=2,
        state_var_stkoff=None,
        pre_header_serial=None,
        initial_state=0x42267E66,
        bst_node_blocks=(),
        nodes=(),
        edges=(),
        diagnostics=(),
    )

    monkeypatch.setattr(
        lfg_module,
        "build_live_linearized_state_dag_from_graph",
        lambda *args, **kwargs: empty_dag,
    )
    monkeypatch.setattr(
        lfg_module,
        "build_dispatcher_transition_report_from_graph",
        lambda *args, **kwargs: SimpleNamespace(rows=()),
    )
    monkeypatch.setattr(
        LinearizedFlowGraphStrategy,
        "_emit_dag_redirect",
        classmethod(
            lambda cls, *args, **kwargs: (_ for _ in ()).throw(
                AssertionError("same-maturity rerun should not replay full DAG edges")
            )
        ),
    )
    monkeypatch.setattr(
        LinearizedFlowGraphStrategy,
        "_emit_residual_dispatcher_handoffs",
        classmethod(lambda cls, **kwargs: 0),
    )

    old_applied = set(LinearizedFlowGraphStrategy._applied)
    old_residual_counts = dict(
        LinearizedFlowGraphStrategy._last_successful_residual_dispatcher_pred_counts
    )
    old_equal_retry = set(LinearizedFlowGraphStrategy._same_count_exact_rerun_used)
    try:
        LinearizedFlowGraphStrategy._applied.add(key)
        LinearizedFlowGraphStrategy._last_successful_residual_dispatcher_pred_counts[key] = 1
        assert strategy.plan(snapshot) is None
    finally:
        LinearizedFlowGraphStrategy._applied = old_applied
        LinearizedFlowGraphStrategy._last_successful_residual_dispatcher_pred_counts = (
            old_residual_counts
        )
        LinearizedFlowGraphStrategy._same_count_exact_rerun_used = old_equal_retry


def test_lfg_resolves_projected_snapshot_state_write_without_live_mop_fields():
    projected_flow = FlowGraph(
        blocks={
            10: BlockSnapshot(
                serial=10,
                block_type=1,
                succs=(2,),
                preds=(),
                flags=0,
                start_ea=0x401000,
                insn_snapshots=(
                    InsnSnapshot(
                        opcode=lfg_module.ida_hexrays.m_mov,
                        ea=0x401001,
                        operands=(),
                        l=MopSnapshot(t=lfg_module.ida_hexrays.mop_n, value=0xAAAA0000, size=4),
                        d=MopSnapshot(t=lfg_module.ida_hexrays.mop_S, stkoff=0x60, size=4),
                    ),
                    InsnSnapshot(
                        opcode=lfg_module.ida_hexrays.m_mov,
                        ea=0x401002,
                        operands=(),
                        l=MopSnapshot(t=lfg_module.ida_hexrays.mop_n, value=0xBBBB1111, size=4),
                        d=MopSnapshot(t=lfg_module.ida_hexrays.mop_S, stkoff=0x68, size=4),
                    ),
                    InsnSnapshot(
                        opcode=lfg_module.ida_hexrays.m_xor,
                        ea=0x401003,
                        operands=(),
                        l=MopSnapshot(t=lfg_module.ida_hexrays.mop_S, stkoff=0x68, size=4),
                        r=MopSnapshot(t=lfg_module.ida_hexrays.mop_S, stkoff=0x60, size=4),
                        d=MopSnapshot(t=lfg_module.ida_hexrays.mop_S, stkoff=0x3C, size=4),
                    ),
                ),
            )
        },
        entry_serial=10,
        func_ea=0x401000,
    )
    projected_mba = build_mba_view_from_flow_graph(projected_flow)

    assert LinearizedFlowGraphStrategy._resolve_singleton_state_write_value(
        projected_mba,
        10,
        state_var_stkoff=0x3C,
    ) == (0xAAAA0000 ^ 0xBBBB1111) & 0xFFFFFFFF


def test_lfg_collects_dead_block_cleanup_for_unreachable_original_blocks_only():
    flow_graph = FlowGraph(
        blocks={
            0: BlockSnapshot(
                serial=0,
                block_type=3,
                succs=(1,),
                preds=(),
                flags=0,
                start_ea=0x1000,
                insn_snapshots=(),
            ),
            1: BlockSnapshot(
                serial=1,
                block_type=3,
                succs=(),
                preds=(0,),
                flags=0,
                start_ea=0x1010,
                insn_snapshots=(),
            ),
            5: BlockSnapshot(
                serial=5,
                block_type=3,
                succs=(1,),
                preds=(),
                flags=0,
                start_ea=0x1050,
                insn_snapshots=(
                    InsnSnapshot(opcode=0x01, ea=0x1050, operands=()),
                    InsnSnapshot(opcode=0x02, ea=0x1054, operands=()),
                ),
            ),
            6: BlockSnapshot(
                serial=6,
                block_type=4,
                succs=(7, 8),
                preds=(),
                flags=0,
                start_ea=0x1060,
                insn_snapshots=(
                    InsnSnapshot(opcode=0x03, ea=0x1060, operands=()),
                ),
            ),
            9: BlockSnapshot(
                serial=9,
                block_type=3,
                succs=(),
                preds=(),
                flags=0,
                start_ea=0x1090,
                insn_snapshots=(
                    InsnSnapshot(opcode=0x03, ea=0x1090, operands=()),
                ),
            ),
            10: BlockSnapshot(
                serial=10,
                block_type=3,
                succs=(),
                preds=(),
                flags=0,
                start_ea=0x10A0,
                insn_snapshots=(),
            ),
        },
        entry_serial=0,
        func_ea=0x401000,
    )

    mods = LinearizedFlowGraphStrategy._collect_dead_dispatcher_root_cleanup_modifications(
        flow_graph,
        dispatcher_serial=1,
        original_stop_serial=10,
        original_blocks={0, 1, 5, 6},
    )

    assert mods == [
        RedirectGoto(from_serial=5, old_target=1, new_target=10),
    ]


def test_lfg_plan_skips_backward_same_corridor_target():
    source_node = StateDagNode(
        key=StateDagNodeKey(handler_serial=138, state_const=0x139F2922),
        kind=StateNodeKind.EXACT,
        state_label="0x139F2922",
        handler_serial=138,
        entry_anchor=138,
        owned_blocks=(138, 139, 140),
        exclusive_blocks=(138, 139, 140),
        shared_suffix_blocks=(),
        local_segments=(),
        local_edges=(),
    )
    dag = LinearizedStateDag(
        dispatcher_entry_serial=2,
        state_var_stkoff=None,
        pre_header_serial=None,
        initial_state=None,
        bst_node_blocks=(),
        nodes=(source_node,),
        edges=(
            StateDagEdge(
                kind=SemanticEdgeKind.TRANSITION,
                source_key=source_node.key,
                target_key=source_node.key,
                target_state=0x139F2922,
                target_entry_anchor=138,
                target_label="0x139F2922",
                source_anchor=StateRedirectAnchor(
                    kind=RedirectSourceKind.UNCONDITIONAL,
                    block_serial=139,
                ),
                ordered_path=(138, 139),
            ),
        ),
        diagnostics=(),
    )
    flow_graph = _FakeFlowGraph(
        [
            _FakeFlowBlock(138, [139, 140], preds=[]),
            _FakeFlowBlock(139, [165], preds=[138]),
            _FakeFlowBlock(140, [192], preds=[138]),
            _FakeFlowBlock(165, [138], preds=[139]),
            _FakeFlowBlock(192, [], preds=[140]),
        ]
    )
    fake_mba = SimpleNamespace(entry_ea=0x401000)
    builder = ModificationBuilder.from_snapshot(
        SimpleNamespace(flow_graph=flow_graph, mba=fake_mba)
    )
    modifications: list = []

    assert not LinearizedFlowGraphStrategy._emit_dag_redirect(
        edge=dag.edges[0],
        dag=dag,
        builder=builder,
        modifications=modifications,
        owned_blocks=set(),
        owned_edges=set(),
        owned_transitions=set(),
        emitted=set(),
        claimed_1way={},
        claimed_2way={},
        claimed_exits={},
        claimed_path_edges={},
        blocked_sources=set(),
        terminal_source_keys=set(),
        terminal_source_handlers=set(),
        terminal_source_owned_blocks=set(),
        terminal_protected_blocks=set(),
        report_exit_handlers=set(),
        report_exit_owned_blocks=set(),
        bst_node_blocks=set(),
        dispatcher_region={2},
        flow_graph=flow_graph,
        state_var_stkoff=None,
        dispatcher_lookup=None,
        mba=fake_mba,
    )
    assert modifications == []


# ---------------------------------------------------------------------------
# Conditional arm reconstruction (C2)
# ---------------------------------------------------------------------------


def test_state_write_reconstruction_conditional_arm_basic(monkeypatch):
    """CONDITIONAL_TRANSITION edge where horizon == source_anchor, 2-way block.

    Expect: candidate accepted with emission_mode='conditional_arm', NOP for
    state-write, RedirectBranch for the transition arm.
    """
    mov = int(ida_hexrays.m_mov)
    jnz = int(ida_hexrays.m_jnz)
    mop_n = int(ida_hexrays.mop_n)
    mop_S = int(ida_hexrays.mop_S)
    mop_b = int(ida_hexrays.mop_b)

    # Block 10: 2-way branch block. Arm 0 -> handler body (20), Arm 1 -> dispatcher (2).
    # The state-write instruction writes 0xDEAD0001 to state var at stkoff=0x3C.
    flow_graph = FlowGraph(
        blocks={
            2: BlockSnapshot(2, int(ida_hexrays.BLT_2WAY), (3, 4), (10,), 0, 0x2000, ()),
            10: BlockSnapshot(
                serial=10,
                block_type=int(ida_hexrays.BLT_2WAY),
                succs=(20, 2),
                preds=(),
                flags=0,
                start_ea=0x1000,
                insn_snapshots=(
                    InsnSnapshot(
                        opcode=mov,
                        ea=0x1000,
                        operands=(),
                        l=MopSnapshot(t=mop_n, size=4, value=0xDEAD0001),
                        d=MopSnapshot(t=mop_S, size=4, stkoff=0x3C),
                    ),
                    InsnSnapshot(
                        opcode=jnz,
                        ea=0x1004,
                        operands=(),
                        l=MopSnapshot(t=mop_n, size=4, value=1),
                        d=MopSnapshot(t=mop_b, size=4, block_ref=2),
                    ),
                ),
            ),
            20: BlockSnapshot(20, int(ida_hexrays.BLT_1WAY), (), (10,), 0, 0x1020, ()),
            30: BlockSnapshot(30, int(ida_hexrays.BLT_1WAY), (), (), 0, 0x3000, ()),
        },
        entry_serial=10,
        func_ea=0x1000,
    )

    source_node = _make_reconstruction_node(10, 0x11111111, 10)
    target_node = _make_reconstruction_node(30, 0xDEAD0001, 30, label="cond_target")
    dag = LinearizedStateDag(
        dispatcher_entry_serial=2,
        state_var_stkoff=0x3C,
        pre_header_serial=None,
        initial_state=0x11111111,
        bst_node_blocks=(2,),
        nodes=(source_node, target_node),
        edges=(
            StateDagEdge(
                kind=SemanticEdgeKind.CONDITIONAL_TRANSITION,
                source_key=source_node.key,
                target_key=target_node.key,
                target_state=0xDEAD0001,
                target_entry_anchor=30,
                target_label="cond_target",
                source_anchor=StateRedirectAnchor(
                    kind=RedirectSourceKind.CONDITIONAL_BRANCH,
                    block_serial=10,
                    branch_arm=1,
                ),
                ordered_path=(10,),
            ),
        ),
        diagnostics=(),
    )
    monkeypatch.setattr(
        reconstruction_module,
        "build_live_linearized_state_dag_from_graph",
        lambda *args, **kwargs: dag,
    )

    fragment = StateWriteReconstructionStrategy().plan(
        _make_reconstruction_snapshot(flow_graph)
    )

    assert fragment is not None
    mods = fragment.modifications
    # State-write NOPing disabled — only RedirectBranch for arm=1
    nops = [m for m in mods if isinstance(m, NopInstructions)]
    redirects = [m for m in mods if isinstance(m, RedirectBranch)]
    assert len(nops) == 0
    assert len(redirects) == 1
    assert redirects[0] == RedirectBranch(from_serial=10, old_target=2, new_target=30)
    # Verify metadata records conditional_arm mode
    accepted = fragment.metadata.get("reconstruction_sites", ())
    assert any(site.get("emission_mode") == "conditional_arm" for site in accepted)


def test_state_write_reconstruction_conditional_arm_dual_dispatcher(monkeypatch):
    """Both succs of 2-way block point to dispatcher, branch_arm=1.

    When both arms target the dispatcher, edge_redirect would match both by
    old_target. Only the transition arm (arm=1) should be redirected via
    RedirectBranch. The passthrough arm (arm=0) is left as residual because
    RedirectBranch only modifies arm=1.
    """
    mov = int(ida_hexrays.m_mov)
    jnz = int(ida_hexrays.m_jnz)
    mop_n = int(ida_hexrays.mop_n)
    mop_S = int(ida_hexrays.mop_S)
    mop_b = int(ida_hexrays.mop_b)

    # Block 10: 2-way, BOTH succs -> dispatcher (2).
    flow_graph = FlowGraph(
        blocks={
            2: BlockSnapshot(2, int(ida_hexrays.BLT_2WAY), (3, 4), (10,), 0, 0x2000, ()),
            10: BlockSnapshot(
                serial=10,
                block_type=int(ida_hexrays.BLT_2WAY),
                succs=(2, 2),
                preds=(),
                flags=0,
                start_ea=0x1000,
                insn_snapshots=(
                    InsnSnapshot(
                        opcode=mov,
                        ea=0x1000,
                        operands=(),
                        l=MopSnapshot(t=mop_n, size=4, value=0xBEEF0002),
                        d=MopSnapshot(t=mop_S, size=4, stkoff=0x3C),
                    ),
                    InsnSnapshot(
                        opcode=jnz,
                        ea=0x1004,
                        operands=(),
                        l=MopSnapshot(t=mop_n, size=4, value=1),
                        d=MopSnapshot(t=mop_b, size=4, block_ref=2),
                    ),
                ),
            ),
            40: BlockSnapshot(40, int(ida_hexrays.BLT_1WAY), (), (), 0, 0x4000, ()),
        },
        entry_serial=10,
        func_ea=0x1000,
    )

    source_node = _make_reconstruction_node(10, 0x11111111, 10)
    target_node = _make_reconstruction_node(40, 0xBEEF0002, 40, label="dual_target")
    dag = LinearizedStateDag(
        dispatcher_entry_serial=2,
        state_var_stkoff=0x3C,
        pre_header_serial=None,
        initial_state=0x11111111,
        bst_node_blocks=(2,),
        nodes=(source_node, target_node),
        edges=(
            StateDagEdge(
                kind=SemanticEdgeKind.CONDITIONAL_TRANSITION,
                source_key=source_node.key,
                target_key=target_node.key,
                target_state=0xBEEF0002,
                target_entry_anchor=40,
                target_label="dual_target",
                source_anchor=StateRedirectAnchor(
                    kind=RedirectSourceKind.CONDITIONAL_BRANCH,
                    block_serial=10,
                    branch_arm=1,
                ),
                ordered_path=(10,),
            ),
        ),
        diagnostics=(),
    )
    monkeypatch.setattr(
        reconstruction_module,
        "build_live_linearized_state_dag_from_graph",
        lambda *args, **kwargs: dag,
    )

    fragment = StateWriteReconstructionStrategy().plan(
        _make_reconstruction_snapshot(flow_graph)
    )

    assert fragment is not None
    mods = fragment.modifications
    # State-write NOPing disabled — only redirects emitted
    nops = [m for m in mods if isinstance(m, NopInstructions)]
    redirects = [m for m in mods if isinstance(m, RedirectBranch)]
    assert len(nops) == 0
    # Only ONE redirect for the transition arm (arm=1). NOT both.
    assert len(redirects) == 1
    assert redirects[0] == RedirectBranch(from_serial=10, old_target=2, new_target=40)


# ---------------------------------------------------------------------------
# C2b: Passthrough block resolution for accepted corridors
# ---------------------------------------------------------------------------




# ---------------------------------------------------------------------------
# Return-slot artifact classification
# ---------------------------------------------------------------------------


class TestClassifyArtifactReturnBlocks:
    """Unit tests for _classify_artifact_return_blocks static method."""

    def test_xdu_artifact_detected(self):
        """Block with m_xdu state_var -> other stkvar is classified as artifact."""
        m_xdu = int(ida_hexrays.m_xdu)
        mop_S = int(ida_hexrays.mop_S)
        state_stkoff = 0x3C
        return_stkoff = 0x7F0

        fg = FlowGraph(
            blocks={
                0: BlockSnapshot(0, 0, (41,), (), 0, 0x1000, ()),
                41: BlockSnapshot(
                    serial=41,
                    block_type=int(ida_hexrays.BLT_1WAY),
                    succs=(217,),
                    preds=(0,),
                    flags=0,
                    start_ea=0x4100,
                    insn_snapshots=(
                        InsnSnapshot(
                            opcode=m_xdu,
                            ea=0x4100,
                            operands=(),
                            l=MopSnapshot(
                                t=mop_S,
                                size=4,
                                stkoff=state_stkoff,
                                kind=OperandKind.STACK,
                            ),
                            d=MopSnapshot(
                                t=mop_S,
                                size=8,
                                stkoff=return_stkoff,
                                kind=OperandKind.STACK,
                            ),
                            kind=InsnKind.XDU,
                        ),
                    ),
                ),
                217: BlockSnapshot(217, int(ida_hexrays.BLT_1WAY), (), (41,), 0, 0xD900, ()),
            },
            entry_serial=0,
            func_ea=0x1000,
        )
        result = StateWriteReconstructionStrategy._classify_artifact_return_blocks(
            fg, state_stkoff, {0xDEAD0001},
        )
        assert 41 in result
        assert 0 not in result
        assert 217 not in result

    def test_mov_const_artifact_detected(self):
        """Block with m_mov #state_const -> other stkvar is classified as artifact."""
        m_mov = int(ida_hexrays.m_mov)
        mop_n = int(ida_hexrays.mop_n)
        mop_S = int(ida_hexrays.mop_S)
        state_stkoff = 0x3C
        return_stkoff = 0x7F0
        state_const = 0x41FB8FBB

        fg = FlowGraph(
            blocks={
                0: BlockSnapshot(0, 0, (27,), (), 0, 0x1000, ()),
                27: BlockSnapshot(
                    serial=27,
                    block_type=int(ida_hexrays.BLT_1WAY),
                    succs=(217,),
                    preds=(0,),
                    flags=0,
                    start_ea=0x1B00,
                    insn_snapshots=(
                        InsnSnapshot(
                            opcode=m_mov,
                            ea=0x1B00,
                            operands=(),
                            l=MopSnapshot(
                                t=mop_n,
                                size=4,
                                value=state_const,
                                kind=OperandKind.NUMBER,
                            ),
                            d=MopSnapshot(
                                t=mop_S,
                                size=8,
                                stkoff=return_stkoff,
                                kind=OperandKind.STACK,
                            ),
                            kind=InsnKind.MOV,
                        ),
                    ),
                ),
                217: BlockSnapshot(217, int(ida_hexrays.BLT_1WAY), (), (27,), 0, 0xD900, ()),
            },
            entry_serial=0,
            func_ea=0x1000,
        )
        result = StateWriteReconstructionStrategy._classify_artifact_return_blocks(
            fg, state_stkoff, {state_const},
        )
        assert 27 in result

    def test_real_setter_not_classified(self):
        """Block with m_mov from non-state-const to stkvar is NOT artifact."""
        m_mov = int(ida_hexrays.m_mov)
        mop_n = int(ida_hexrays.mop_n)
        mop_S = int(ida_hexrays.mop_S)
        state_stkoff = 0x3C
        return_stkoff = 0x7F0

        fg = FlowGraph(
            blocks={
                0: BlockSnapshot(0, 0, (94,), (), 0, 0x1000, ()),
                94: BlockSnapshot(
                    serial=94,
                    block_type=int(ida_hexrays.BLT_1WAY),
                    succs=(217,),
                    preds=(0,),
                    flags=0,
                    start_ea=0x5E00,
                    insn_snapshots=(
                        InsnSnapshot(
                            opcode=m_mov,
                            ea=0x5E00,
                            operands=(),
                            l=MopSnapshot(
                                t=mop_n,
                                size=4,
                                value=0x00000042,
                                kind=OperandKind.NUMBER,
                            ),
                            d=MopSnapshot(
                                t=mop_S,
                                size=8,
                                stkoff=return_stkoff,
                                kind=OperandKind.STACK,
                            ),
                            kind=InsnKind.MOV,
                        ),
                    ),
                ),
                217: BlockSnapshot(217, int(ida_hexrays.BLT_1WAY), (), (94,), 0, 0xD900, ()),
            },
            entry_serial=0,
            func_ea=0x1000,
        )
        result = StateWriteReconstructionStrategy._classify_artifact_return_blocks(
            fg, state_stkoff, {0xDEAD0001, 0x41FB8FBB},
        )
        assert 94 not in result

    def test_xdu_self_write_not_classified(self):
        """m_xdu where both src and dest are state_var stkoff is NOT artifact."""
        m_xdu = int(ida_hexrays.m_xdu)
        mop_S = int(ida_hexrays.mop_S)
        state_stkoff = 0x3C

        fg = FlowGraph(
            blocks={
                0: BlockSnapshot(0, 0, (50,), (), 0, 0x1000, ()),
                50: BlockSnapshot(
                    serial=50,
                    block_type=int(ida_hexrays.BLT_1WAY),
                    succs=(60,),
                    preds=(0,),
                    flags=0,
                    start_ea=0x3200,
                    insn_snapshots=(
                        InsnSnapshot(
                            opcode=m_xdu,
                            ea=0x3200,
                            operands=(),
                            l=MopSnapshot(
                                t=mop_S,
                                size=4,
                                stkoff=state_stkoff,
                                kind=OperandKind.STACK,
                            ),
                            d=MopSnapshot(
                                t=mop_S,
                                size=8,
                                stkoff=state_stkoff,
                                kind=OperandKind.STACK,
                            ),
                            kind=InsnKind.XDU,
                        ),
                    ),
                ),
                60: BlockSnapshot(60, int(ida_hexrays.BLT_1WAY), (), (50,), 0, 0x3C00, ()),
            },
            entry_serial=0,
            func_ea=0x1000,
        )
        result = StateWriteReconstructionStrategy._classify_artifact_return_blocks(
            fg, state_stkoff, {0xDEAD0001},
        )
        assert 50 not in result

    def test_empty_flow_graph(self):
        """Empty flow graph returns empty set."""
        fg = FlowGraph(
            blocks={
                0: BlockSnapshot(0, 0, (), (), 0, 0x1000, ()),
            },
            entry_serial=0,
            func_ea=0x1000,
        )
        result = StateWriteReconstructionStrategy._classify_artifact_return_blocks(
            fg, 0x3C, {0xDEAD0001},
        )
        assert result == set()


# ---------------------------------------------------------------------------
# Empty ordered_path and UNKNOWN edge fallback
# ---------------------------------------------------------------------------


def test_state_write_reconstruction_empty_path_bridge_fallback(monkeypatch):
    """Edges with empty ordered_path are wired via the Bridge Builder fallback
    using source_anchor.block_serial when the source feeds the dispatcher."""
    mov = int(ida_hexrays.m_mov)
    goto = int(ida_hexrays.m_goto)
    mop_n = int(ida_hexrays.mop_n)
    mop_S = int(ida_hexrays.mop_S)
    mop_b = int(ida_hexrays.mop_b)

    # blk[10] is a 1-way block that feeds dispatcher (blk[2])
    flow_graph = FlowGraph(
        blocks={
            2: BlockSnapshot(2, int(ida_hexrays.BLT_2WAY), (3, 4), (10,), 0, 0x2000, ()),
            10: BlockSnapshot(
                serial=10,
                block_type=int(ida_hexrays.BLT_1WAY),
                succs=(2,),
                preds=(),
                flags=0,
                start_ea=0x1000,
                insn_snapshots=(
                    InsnSnapshot(
                        opcode=mov,
                        ea=0x1000,
                        operands=(),
                        l=MopSnapshot(t=mop_n, size=4, value=0x12345678),
                        d=MopSnapshot(t=mop_S, size=4, stkoff=0x3C),
                    ),
                    InsnSnapshot(
                        opcode=goto,
                        ea=0x1004,
                        operands=(),
                        l=MopSnapshot(t=mop_b, size=4, block_ref=2),
                    ),
                ),
            ),
            30: BlockSnapshot(30, int(ida_hexrays.BLT_1WAY), (), (), 0, 0x3000, ()),
        },
        entry_serial=10,
        func_ea=0x1000,
    )

    source_node = _make_reconstruction_node(10, 0x11111111, 10)
    target_node = _make_reconstruction_node(30, 0x12345678, 30, label="target")
    dag = LinearizedStateDag(
        dispatcher_entry_serial=2,
        state_var_stkoff=0x3C,
        pre_header_serial=None,
        initial_state=0x11111111,
        bst_node_blocks=(2,),
        nodes=(source_node, target_node),
        edges=(
            StateDagEdge(
                kind=SemanticEdgeKind.TRANSITION,
                source_key=source_node.key,
                target_key=target_node.key,
                target_state=0x12345678,
                target_entry_anchor=30,
                target_label="target",
                source_anchor=StateRedirectAnchor(
                    kind=RedirectSourceKind.UNCONDITIONAL,
                    block_serial=10,
                ),
                ordered_path=(),  # empty path
            ),
        ),
        diagnostics=(),
    )
    monkeypatch.setattr(
        reconstruction_module,
        "build_live_linearized_state_dag_from_graph",
        lambda *args, **kwargs: dag,
    )

    fragment = StateWriteReconstructionStrategy().plan(
        _make_reconstruction_snapshot(flow_graph)
    )

    # The strict corridor emitter rejects this edge (missing_ordered_path),
    # but the Bridge Builder fallback should wire it using source_anchor.
    assert fragment is not None
    redirects = [m for m in fragment.modifications if isinstance(m, RedirectGoto)]
    assert any(r.from_serial == 10 and r.new_target == 30 for r in redirects), (
        f"Expected bridge fallback redirect blk[10] -> blk[30], got: {redirects}"
    )


def test_state_write_reconstruction_unknown_edge_feeder_redirect(monkeypatch):
    """UNKNOWN edges with valid target_entry_anchor are wired via the Feeder
    redirect instead of being silently skipped."""
    mov = int(ida_hexrays.m_mov)
    goto = int(ida_hexrays.m_goto)
    mop_n = int(ida_hexrays.mop_n)
    mop_S = int(ida_hexrays.mop_S)
    mop_b = int(ida_hexrays.mop_b)

    # blk[10]: 1-way block feeding dispatcher (blk[2])
    # blk[15]: TRANSITION edge from blk[15] -> blk[30] (provides at least
    #          one corridor candidate so the plan is not None)
    # blk[20]: UNKNOWN edge from blk[20] -> blk[40]
    flow_graph = FlowGraph(
        blocks={
            2: BlockSnapshot(2, int(ida_hexrays.BLT_2WAY), (3, 4), (10, 15, 20), 0, 0x2000, ()),
            10: BlockSnapshot(
                serial=10,
                block_type=int(ida_hexrays.BLT_1WAY),
                succs=(15,),
                preds=(),
                flags=0,
                start_ea=0x1000,
                insn_snapshots=(),
            ),
            15: BlockSnapshot(
                serial=15,
                block_type=int(ida_hexrays.BLT_1WAY),
                succs=(2,),
                preds=(10,),
                flags=0,
                start_ea=0x1500,
                insn_snapshots=(
                    InsnSnapshot(
                        opcode=mov,
                        ea=0x1500,
                        operands=(),
                        l=MopSnapshot(t=mop_n, size=4, value=0xAAAA0001),
                        d=MopSnapshot(t=mop_S, size=4, stkoff=0x3C),
                    ),
                    InsnSnapshot(
                        opcode=goto,
                        ea=0x1504,
                        operands=(),
                        l=MopSnapshot(t=mop_b, size=4, block_ref=2),
                    ),
                ),
            ),
            20: BlockSnapshot(
                serial=20,
                block_type=int(ida_hexrays.BLT_1WAY),
                succs=(2,),
                preds=(),
                flags=0,
                start_ea=0x2000,
                insn_snapshots=(
                    InsnSnapshot(
                        opcode=goto,
                        ea=0x2004,
                        operands=(),
                        l=MopSnapshot(t=mop_b, size=4, block_ref=2),
                    ),
                ),
            ),
            30: BlockSnapshot(30, int(ida_hexrays.BLT_1WAY), (), (), 0, 0x3000, ()),
            40: BlockSnapshot(40, int(ida_hexrays.BLT_1WAY), (), (), 0, 0x4000, ()),
        },
        entry_serial=10,
        func_ea=0x1000,
    )

    source_node_a = _make_reconstruction_node(15, 0x11111111, 15)
    source_node_b = _make_reconstruction_node(20, 0x22222222, 20)
    target_node_a = _make_reconstruction_node(30, 0xAAAA0001, 30, label="target_a")
    target_node_b = _make_reconstruction_node(40, 0xBBBB0002, 40, label="target_b")
    dag = LinearizedStateDag(
        dispatcher_entry_serial=2,
        state_var_stkoff=0x3C,
        pre_header_serial=None,
        initial_state=0x11111111,
        bst_node_blocks=(2,),
        nodes=(source_node_a, source_node_b, target_node_a, target_node_b),
        edges=(
            # Normal TRANSITION edge that will be accepted by corridor emitter
            StateDagEdge(
                kind=SemanticEdgeKind.TRANSITION,
                source_key=source_node_a.key,
                target_key=target_node_a.key,
                target_state=0xAAAA0001,
                target_entry_anchor=30,
                target_label="target_a",
                source_anchor=StateRedirectAnchor(
                    kind=RedirectSourceKind.UNCONDITIONAL,
                    block_serial=15,
                ),
                ordered_path=(15,),
            ),
            # UNKNOWN edge: valid source/target but no state writes found
            StateDagEdge(
                kind=SemanticEdgeKind.UNKNOWN,
                source_key=source_node_b.key,
                target_key=target_node_b.key,
                target_state=0xBBBB0002,
                target_entry_anchor=40,
                target_label="target_b",
                source_anchor=StateRedirectAnchor(
                    kind=RedirectSourceKind.UNCONDITIONAL,
                    block_serial=20,
                ),
                ordered_path=(20,),
            ),
        ),
        diagnostics=(),
    )
    monkeypatch.setattr(
        reconstruction_module,
        "build_live_linearized_state_dag_from_graph",
        lambda *args, **kwargs: dag,
    )

    fragment = StateWriteReconstructionStrategy().plan(
        _make_reconstruction_snapshot(flow_graph)
    )

    assert fragment is not None
    # The UNKNOWN edge should be wired via feeder redirect
    redirects = [m for m in fragment.modifications if isinstance(m, RedirectGoto)]
    assert any(r.from_serial == 20 and r.new_target == 40 for r in redirects), (
        f"Expected UNKNOWN feeder redirect blk[20] -> blk[40], got: {redirects}"
    )


def test_state_write_reconstruction_lifts_reachable_handoff_to_island_entry(
    monkeypatch,
):
    """Projected rescue should attach to the upstream semantic island entry,
    not directly to the deeper unreachable target, and should use the deepest
    reachable frontier block in the live chain."""
    flow_graph = FlowGraph(
        blocks={
            2: BlockSnapshot(2, int(ida_hexrays.BLT_1WAY), (), (), 0, 0x2000, ()),
            10: BlockSnapshot(10, int(ida_hexrays.BLT_1WAY), (20,), (), 0, 0x1000, ()),
            20: BlockSnapshot(20, int(ida_hexrays.BLT_1WAY), (30,), (10,), 0, 0x1010, ()),
            30: BlockSnapshot(30, int(ida_hexrays.BLT_1WAY), (35,), (20,), 0, 0x1020, ()),
            35: BlockSnapshot(35, int(ida_hexrays.BLT_1WAY), (), (30,), 0, 0x1030, ()),
            50: BlockSnapshot(50, int(ida_hexrays.BLT_1WAY), (60,), (), 0, 0x2000, ()),
            60: BlockSnapshot(60, int(ida_hexrays.BLT_1WAY), (), (50,), 0, 0x2010, ()),
        },
        entry_serial=10,
        func_ea=0x1000,
    )

    frontier_node = _make_reconstruction_node(
        20,
        0x11111111,
        20,
        owned_blocks=(20, 30),
    )
    island_entry = _make_reconstruction_node(50, 0x22222222, 50)
    target_node = _make_reconstruction_node(60, 0x33333333, 60, label="deep_target")
    dag = LinearizedStateDag(
        dispatcher_entry_serial=2,
        state_var_stkoff=0x3C,
        pre_header_serial=None,
        initial_state=0x11111111,
        bst_node_blocks=(2,),
        nodes=(frontier_node, island_entry, target_node),
        edges=(
            StateDagEdge(
                kind=SemanticEdgeKind.TRANSITION,
                source_key=frontier_node.key,
                target_key=target_node.key,
                target_state=0x33333333,
                target_entry_anchor=60,
                target_label="deep_target",
                source_anchor=StateRedirectAnchor(
                    kind=RedirectSourceKind.UNCONDITIONAL,
                    block_serial=20,
                ),
                ordered_path=(20,),
            ),
            StateDagEdge(
                kind=SemanticEdgeKind.TRANSITION,
                source_key=frontier_node.key,
                target_key=target_node.key,
                target_state=0x33333333,
                target_entry_anchor=60,
                target_label="deep_target",
                source_anchor=StateRedirectAnchor(
                    kind=RedirectSourceKind.UNCONDITIONAL,
                    block_serial=30,
                ),
                ordered_path=(20, 30),
            ),
            StateDagEdge(
                kind=SemanticEdgeKind.TRANSITION,
                source_key=island_entry.key,
                target_key=target_node.key,
                target_state=0x33333333,
                target_entry_anchor=60,
                target_label="deep_target",
                source_anchor=StateRedirectAnchor(
                    kind=RedirectSourceKind.UNCONDITIONAL,
                    block_serial=50,
                ),
                ordered_path=(50,),
            ),
        ),
        diagnostics=(),
    )
    monkeypatch.setattr(
        reconstruction_module,
        "build_live_linearized_state_dag_from_graph",
        lambda *args, **kwargs: dag,
    )

    fragment = StateWriteReconstructionStrategy().plan(
        _make_reconstruction_snapshot(flow_graph)
    )

    assert fragment is not None
    redirects = [m for m in fragment.modifications if isinstance(m, RedirectGoto)]
    assert any(
        r.from_serial == 30 and r.old_target == 35 and r.new_target == 50
        for r in redirects
    ), f"Expected lifted island-entry redirect blk[30] -> blk[50], got: {redirects}"
    assert not any(
        r.from_serial == 20 and r.new_target == 50 for r in redirects
    ), f"Entry-island rescue should pick deepest frontier, got: {redirects}"
    assert not any(
        r.from_serial == 30 and r.new_target == 60 for r in redirects
    ), f"Entry-island rescue should lift target blk[60] to island entry blk[50], got: {redirects}"


def test_state_write_reconstruction_prefers_non_regressing_split_frontier(
    monkeypatch,
):
    """When a deeper direct rescue would steal a live chain, prefer a split on
    an upstream reachable frontier that preserves reachability."""
    flow_graph = FlowGraph(
        blocks={
            2: BlockSnapshot(2, int(ida_hexrays.BLT_1WAY), (), (), 0, 0x2000, ()),
            10: BlockSnapshot(10, int(ida_hexrays.BLT_2WAY), (68, 102), (), 0, 0x1000, ()),
            68: BlockSnapshot(68, int(ida_hexrays.BLT_1WAY), (69,), (10,), 0, 0x1068, ()),
            102: BlockSnapshot(102, int(ida_hexrays.BLT_1WAY), (69,), (10,), 0, 0x1102, ()),
            69: BlockSnapshot(69, int(ida_hexrays.BLT_1WAY), (122,), (68, 102), 0, 0x1069, ()),
            122: BlockSnapshot(122, int(ida_hexrays.BLT_1WAY), (222,), (69,), 0, 0x1122, ()),
            222: BlockSnapshot(222, int(ida_hexrays.BLT_1WAY), (223,), (122,), 0, 0x1222, ()),
            223: BlockSnapshot(223, int(ida_hexrays.BLT_0WAY), (), (222,), 0, 0x1223, ()),
            39: BlockSnapshot(39, int(ida_hexrays.BLT_1WAY), (161,), (), 0, 0x2039, ()),
            161: BlockSnapshot(161, int(ida_hexrays.BLT_0WAY), (), (39,), 0, 0x2161, ()),
        },
        entry_serial=10,
        func_ea=0x1000,
    )

    frontier_69 = _make_reconstruction_node(69, 0x11111111, 69, owned_blocks=(69,))
    frontier_122 = _make_reconstruction_node(122, 0x22222222, 122, owned_blocks=(122,))
    island_entry = _make_reconstruction_node(39, 0x33333333, 39)
    target_node = _make_reconstruction_node(161, 0x44444444, 161, label="target_161")
    dag = LinearizedStateDag(
        dispatcher_entry_serial=2,
        state_var_stkoff=0x3C,
        pre_header_serial=None,
        initial_state=0x11111111,
        bst_node_blocks=(2,),
        nodes=(frontier_69, frontier_122, island_entry, target_node),
        edges=(
            StateDagEdge(
                kind=SemanticEdgeKind.TRANSITION,
                source_key=frontier_69.key,
                target_key=target_node.key,
                target_state=0x44444444,
                target_entry_anchor=161,
                target_label="target_161",
                source_anchor=StateRedirectAnchor(
                    kind=RedirectSourceKind.UNCONDITIONAL,
                    block_serial=69,
                ),
                ordered_path=(69,),
            ),
            StateDagEdge(
                kind=SemanticEdgeKind.TRANSITION,
                source_key=frontier_122.key,
                target_key=target_node.key,
                target_state=0x44444444,
                target_entry_anchor=161,
                target_label="target_161",
                source_anchor=StateRedirectAnchor(
                    kind=RedirectSourceKind.UNCONDITIONAL,
                    block_serial=122,
                ),
                ordered_path=(69, 122),
            ),
            StateDagEdge(
                kind=SemanticEdgeKind.TRANSITION,
                source_key=island_entry.key,
                target_key=target_node.key,
                target_state=0x44444444,
                target_entry_anchor=161,
                target_label="target_161",
                source_anchor=StateRedirectAnchor(
                    kind=RedirectSourceKind.UNCONDITIONAL,
                    block_serial=39,
                ),
                ordered_path=(39,),
            ),
        ),
        diagnostics=(),
    )
    monkeypatch.setattr(
        reconstruction_module,
        "build_live_linearized_state_dag_from_graph",
        lambda *args, **kwargs: dag,
    )

    fragment = StateWriteReconstructionStrategy().plan(
        _make_reconstruction_snapshot(flow_graph)
    )

    assert fragment is not None
    split_redirects = [
        m for m in fragment.modifications if isinstance(m, EdgeRedirectViaPredSplit)
    ]
    assert any(
        m.src_block == 69
        and m.old_target == 122
        and m.new_target == 39
        and m.via_pred in {68, 102}
        for m in split_redirects
    ), f"Expected non-regressing split rescue on blk[69] -> blk[39], got: {fragment.modifications}"

    direct_redirects = [m for m in fragment.modifications if isinstance(m, RedirectGoto)]
    assert not any(
        m.from_serial in {69, 122} and m.new_target == 39
        for m in direct_redirects
    ), f"Entry-island rescue should avoid regressing live chain with direct redirect, got: {fragment.modifications}"


def test_state_write_reconstruction_rescues_island_after_bridge_projection(
    monkeypatch,
):
    """A bridge redirect can expose a previously dispatcher-reachable island.
    The late rescue pass should then split the live frontier to keep the old
    chain while reattaching the island entry."""
    flow_graph = FlowGraph(
        blocks={
            2: BlockSnapshot(2, int(ida_hexrays.BLT_1WAY), (39,), (122,), 0, 0x2000, ()),
            10: BlockSnapshot(10, int(ida_hexrays.BLT_2WAY), (68, 102), (), 0, 0x1000, ()),
            68: BlockSnapshot(68, int(ida_hexrays.BLT_1WAY), (69,), (10,), 0, 0x1068, ()),
            102: BlockSnapshot(102, int(ida_hexrays.BLT_1WAY), (69,), (10,), 0, 0x1102, ()),
            69: BlockSnapshot(69, int(ida_hexrays.BLT_1WAY), (122,), (68, 102), 0, 0x1069, ()),
            122: BlockSnapshot(122, int(ida_hexrays.BLT_1WAY), (2,), (69,), 0, 0x1122, ()),
            39: BlockSnapshot(39, int(ida_hexrays.BLT_1WAY), (161,), (2,), 0, 0x2039, ()),
            161: BlockSnapshot(161, int(ida_hexrays.BLT_0WAY), (), (39,), 0, 0x2161, ()),
            222: BlockSnapshot(222, int(ida_hexrays.BLT_1WAY), (223,), (), 0, 0x2222, ()),
            223: BlockSnapshot(223, int(ida_hexrays.BLT_0WAY), (), (222,), 0, 0x2223, ()),
        },
        entry_serial=10,
        func_ea=0x1000,
    )

    frontier_69 = _make_reconstruction_node(69, 0x11111111, 69, owned_blocks=(69,))
    frontier_122 = _make_reconstruction_node(122, 0x22222222, 122, owned_blocks=(122,))
    island_entry = _make_reconstruction_node(39, 0x33333333, 39)
    target_161 = _make_reconstruction_node(161, 0x44444444, 161, label="target_161")
    target_222 = _make_reconstruction_node(222, 0x55555555, 222, label="target_222")
    dag = LinearizedStateDag(
        dispatcher_entry_serial=2,
        state_var_stkoff=0x3C,
        pre_header_serial=None,
        initial_state=0x11111111,
        bst_node_blocks=(2,),
        nodes=(frontier_69, frontier_122, island_entry, target_161, target_222),
        edges=(
            StateDagEdge(
                kind=SemanticEdgeKind.UNKNOWN,
                source_key=frontier_122.key,
                target_key=target_222.key,
                target_state=0x55555555,
                target_entry_anchor=222,
                target_label="target_222",
                source_anchor=StateRedirectAnchor(
                    kind=RedirectSourceKind.UNCONDITIONAL,
                    block_serial=122,
                ),
                ordered_path=(122,),
            ),
            StateDagEdge(
                kind=SemanticEdgeKind.UNKNOWN,
                source_key=frontier_69.key,
                target_key=target_161.key,
                target_state=0x44444444,
                target_entry_anchor=161,
                target_label="target_161",
                source_anchor=StateRedirectAnchor(
                    kind=RedirectSourceKind.UNCONDITIONAL,
                    block_serial=69,
                ),
                ordered_path=(69,),
            ),
            StateDagEdge(
                kind=SemanticEdgeKind.UNKNOWN,
                source_key=island_entry.key,
                target_key=target_161.key,
                target_state=0x44444444,
                target_entry_anchor=161,
                target_label="target_161",
                source_anchor=StateRedirectAnchor(
                    kind=RedirectSourceKind.UNCONDITIONAL,
                    block_serial=39,
                ),
                ordered_path=(39,),
            ),
        ),
        diagnostics=(),
    )
    monkeypatch.setattr(
        reconstruction_module,
        "build_live_linearized_state_dag_from_graph",
        lambda *args, **kwargs: dag,
    )

    fragment = StateWriteReconstructionStrategy().plan(
        _make_reconstruction_snapshot(flow_graph)
    )

    assert fragment is not None
    redirects = [m for m in fragment.modifications if isinstance(m, RedirectGoto)]
    assert any(
        m.from_serial == 122 and m.old_target == 2 and m.new_target == 222
        for m in redirects
    ), f"Expected bridge redirect blk[122] -> blk[222], got: {fragment.modifications}"

    split_redirects = [
        m for m in fragment.modifications if isinstance(m, EdgeRedirectViaPredSplit)
    ]
    assert any(
        m.src_block == 69
        and m.old_target == 122
        and m.new_target == 39
        and m.via_pred in {68, 102}
        for m in split_redirects
    ), f"Expected late split rescue blk[69] -> blk[39], got: {fragment.modifications}"

    assert not any(
        m.from_serial in {69, 122} and m.new_target == 39
        for m in redirects
    ), f"Late rescue should preserve blk[122] -> blk[222] with a split, got: {fragment.modifications}"


def test_state_write_reconstruction_does_not_chase_closed_upstream_prefix_family(
    monkeypatch,
):
    """Late rescue should stop at the externally rooted island entry.

    A closed upstream exact-state family that only feeds that rescued island
    should remain detached until it has its own external semantic roots."""
    flow_graph = FlowGraph(
        blocks={
            2: BlockSnapshot(2, int(ida_hexrays.BLT_1WAY), (39,), (122,), 0, 0x2000, ()),
            10: BlockSnapshot(10, int(ida_hexrays.BLT_2WAY), (68, 102), (), 0, 0x1000, ()),
            68: BlockSnapshot(68, int(ida_hexrays.BLT_1WAY), (69,), (10,), 0, 0x1068, ()),
            102: BlockSnapshot(102, int(ida_hexrays.BLT_1WAY), (69,), (10,), 0, 0x1102, ()),
            69: BlockSnapshot(69, int(ida_hexrays.BLT_1WAY), (122,), (68, 102), 0, 0x1069, ()),
            122: BlockSnapshot(122, int(ida_hexrays.BLT_1WAY), (2,), (69,), 0, 0x1122, ()),
            39: BlockSnapshot(39, int(ida_hexrays.BLT_1WAY), (161,), (2, 229), 0, 0x2039, ()),
            42: BlockSnapshot(42, int(ida_hexrays.BLT_1WAY), (51,), (56,), 0, 0x2042, ()),
            51: BlockSnapshot(51, int(ida_hexrays.BLT_1WAY), (229,), (42,), 0, 0x2051, ()),
            56: BlockSnapshot(56, int(ida_hexrays.BLT_1WAY), (42,), (), 0, 0x2056, ()),
            161: BlockSnapshot(161, int(ida_hexrays.BLT_0WAY), (), (39,), 0, 0x2161, ()),
            222: BlockSnapshot(222, int(ida_hexrays.BLT_1WAY), (223,), (), 0, 0x2222, ()),
            223: BlockSnapshot(223, int(ida_hexrays.BLT_0WAY), (), (222,), 0, 0x2223, ()),
            229: BlockSnapshot(229, int(ida_hexrays.BLT_1WAY), (39,), (51,), 0, 0x2229, ()),
        },
        entry_serial=10,
        func_ea=0x1000,
    )

    frontier_69 = _make_reconstruction_node(69, 0x11111111, 69, owned_blocks=(69,))
    frontier_122 = _make_reconstruction_node(122, 0x22222222, 122, owned_blocks=(122,))
    upstream_56 = _make_reconstruction_node(56, 0x33333333, 56)
    upstream_42 = _make_reconstruction_node(42, 0x44444444, 42)
    upstream_51 = _make_reconstruction_node(51, 0x55555555, 51)
    island_entry = _make_reconstruction_node(39, 0x66666666, 39)
    target_161 = _make_reconstruction_node(161, 0x77777777, 161, label="target_161")
    target_222 = _make_reconstruction_node(222, 0x88888888, 222, label="target_222")
    dag = LinearizedStateDag(
        dispatcher_entry_serial=2,
        state_var_stkoff=0x3C,
        pre_header_serial=None,
        initial_state=0x11111111,
        bst_node_blocks=(2,),
        nodes=(
            frontier_69,
            frontier_122,
            upstream_56,
            upstream_42,
            upstream_51,
            island_entry,
            target_161,
            target_222,
        ),
        edges=(
            StateDagEdge(
                kind=SemanticEdgeKind.UNKNOWN,
                source_key=frontier_122.key,
                target_key=target_222.key,
                target_state=0x88888888,
                target_entry_anchor=222,
                target_label="target_222",
                source_anchor=StateRedirectAnchor(
                    kind=RedirectSourceKind.UNCONDITIONAL,
                    block_serial=122,
                ),
                ordered_path=(122,),
            ),
            StateDagEdge(
                kind=SemanticEdgeKind.UNKNOWN,
                source_key=frontier_69.key,
                target_key=target_161.key,
                target_state=0x77777777,
                target_entry_anchor=161,
                target_label="target_161",
                source_anchor=StateRedirectAnchor(
                    kind=RedirectSourceKind.UNCONDITIONAL,
                    block_serial=69,
                ),
                ordered_path=(69,),
            ),
            StateDagEdge(
                kind=SemanticEdgeKind.TRANSITION,
                source_key=upstream_56.key,
                target_key=upstream_42.key,
                target_state=0x44444444,
                target_entry_anchor=42,
                target_label="state_42",
                source_anchor=StateRedirectAnchor(
                    kind=RedirectSourceKind.UNCONDITIONAL,
                    block_serial=56,
                ),
                ordered_path=(56,),
            ),
            StateDagEdge(
                kind=SemanticEdgeKind.TRANSITION,
                source_key=upstream_42.key,
                target_key=upstream_51.key,
                target_state=0x55555555,
                target_entry_anchor=51,
                target_label="state_51",
                source_anchor=StateRedirectAnchor(
                    kind=RedirectSourceKind.UNCONDITIONAL,
                    block_serial=42,
                ),
                ordered_path=(42,),
            ),
            StateDagEdge(
                kind=SemanticEdgeKind.TRANSITION,
                source_key=upstream_51.key,
                target_key=island_entry.key,
                target_state=0x66666666,
                target_entry_anchor=39,
                target_label="state_39",
                source_anchor=StateRedirectAnchor(
                    kind=RedirectSourceKind.UNCONDITIONAL,
                    block_serial=229,
                ),
                ordered_path=(51, 229),
            ),
            StateDagEdge(
                kind=SemanticEdgeKind.TRANSITION,
                source_key=island_entry.key,
                target_key=target_161.key,
                target_state=0x77777777,
                target_entry_anchor=161,
                target_label="target_161",
                source_anchor=StateRedirectAnchor(
                    kind=RedirectSourceKind.UNCONDITIONAL,
                    block_serial=39,
                ),
                ordered_path=(39,),
            ),
        ),
        diagnostics=(),
    )
    monkeypatch.setattr(
        reconstruction_module,
        "build_live_linearized_state_dag_from_graph",
        lambda *args, **kwargs: dag,
    )

    fragment = StateWriteReconstructionStrategy().plan(
        _make_reconstruction_snapshot(flow_graph)
    )

    assert fragment is not None
    redirects = [m for m in fragment.modifications if isinstance(m, RedirectGoto)]
    split_redirects = [
        m for m in fragment.modifications if isinstance(m, EdgeRedirectViaPredSplit)
    ]

    assert any(
        m.from_serial == 122 and m.old_target == 2 and m.new_target == 222
        for m in redirects
    ), f"Expected bridge redirect blk[122] -> blk[222], got: {fragment.modifications}"
    assert any(
        m.src_block == 69
        and m.old_target == 122
        and m.new_target == 39
        and m.via_pred in {68, 102}
        for m in split_redirects
    ), f"Expected late rescue to stop at blk[39], got: {fragment.modifications}"
    assert not any(
        getattr(m, "new_target", None) in {42, 51, 56}
        for m in fragment.modifications
    ), (
        "Closed upstream family should remain detached without external roots, "
        f"got: {fragment.modifications}"
    )

def test_state_write_reconstruction_does_not_split_equivalent_terminal_families(
    monkeypatch,
):
    mov = int(ida_hexrays.m_mov)
    goto = int(ida_hexrays.m_goto)
    mop_b = int(ida_hexrays.mop_b)
    mop_n = int(ida_hexrays.mop_n)
    mop_S = int(ida_hexrays.mop_S)
    mop_r = int(ida_hexrays.mop_r)

    flow_graph = FlowGraph(
        blocks={
            1: BlockSnapshot(1, int(ida_hexrays.BLT_2WAY), (10, 20), (), 0, 0x1000, ()),
            10: BlockSnapshot(10, int(ida_hexrays.BLT_2WAY), (11, 12), (1,), 0, 0x1010, ()),
            11: BlockSnapshot(
                11,
                int(ida_hexrays.BLT_1WAY),
                (50,),
                (10,),
                0,
                0x1110,
                (
                    InsnSnapshot(
                        opcode=mov,
                        ea=0x1110,
                        operands=(),
                        l=MopSnapshot(t=mop_n, size=8, value=1),
                        d=MopSnapshot(t=mop_S, size=8, stkoff=0x80),
                    ),
                    InsnSnapshot(
                        opcode=goto,
                        ea=0x1114,
                        operands=(),
                        l=MopSnapshot(t=mop_b, size=4, block_ref=50),
                    ),
                ),
            ),
            12: BlockSnapshot(12, int(ida_hexrays.BLT_0WAY), (), (10,), 0, 0x1120, ()),
            20: BlockSnapshot(20, int(ida_hexrays.BLT_2WAY), (21, 22), (1,), 0, 0x2010, ()),
            21: BlockSnapshot(
                21,
                int(ida_hexrays.BLT_1WAY),
                (50,),
                (20,),
                0,
                0x2110,
                (
                    InsnSnapshot(
                        opcode=mov,
                        ea=0x2110,
                        operands=(),
                        l=MopSnapshot(t=mop_n, size=8, value=1),
                        d=MopSnapshot(t=mop_S, size=8, stkoff=0x80),
                    ),
                    InsnSnapshot(
                        opcode=goto,
                        ea=0x2114,
                        operands=(),
                        l=MopSnapshot(t=mop_b, size=4, block_ref=50),
                    ),
                ),
            ),
            22: BlockSnapshot(22, int(ida_hexrays.BLT_0WAY), (), (20,), 0, 0x2120, ()),
            50: BlockSnapshot(
                50,
                int(ida_hexrays.BLT_1WAY),
                (60,),
                (11, 21),
                0,
                0x3000,
                (
                    InsnSnapshot(
                        opcode=mov,
                        ea=0x3000,
                        operands=(),
                        l=MopSnapshot(t=mop_S, size=8, stkoff=0x80),
                        d=MopSnapshot(t=mop_r, size=8, reg=0),
                    ),
                    InsnSnapshot(
                        opcode=goto,
                        ea=0x3004,
                        operands=(),
                        l=MopSnapshot(t=mop_b, size=4, block_ref=60),
                    ),
                ),
            ),
            60: BlockSnapshot(60, int(ida_hexrays.BLT_0WAY), (), (50,), 0, 0x3010, ()),
        },
        entry_serial=1,
        func_ea=0x1000,
    )

    family_a = _make_reconstruction_node(10, 0x11111111, 10, owned_blocks=(10, 11))
    family_b = _make_reconstruction_node(20, 0x22222222, 20, owned_blocks=(20, 21))
    dag = LinearizedStateDag(
        dispatcher_entry_serial=2,
        state_var_stkoff=0x3C,
        pre_header_serial=None,
        initial_state=0xAAAAAAAA,
        bst_node_blocks=(2,),
        nodes=(family_a, family_b),
        edges=(
            StateDagEdge(
                kind=SemanticEdgeKind.CONDITIONAL_RETURN,
                source_key=family_a.key,
                target_key=None,
                target_state=None,
                target_entry_anchor=None,
                target_label="RETURN",
                source_anchor=StateRedirectAnchor(
                    kind=RedirectSourceKind.CONDITIONAL_BRANCH,
                    block_serial=10,
                    branch_arm=0,
                ),
                ordered_path=(10, 11, 50, 60),
            ),
            StateDagEdge(
                kind=SemanticEdgeKind.CONDITIONAL_RETURN,
                source_key=family_b.key,
                target_key=None,
                target_state=None,
                target_entry_anchor=None,
                target_label="RETURN",
                source_anchor=StateRedirectAnchor(
                    kind=RedirectSourceKind.CONDITIONAL_BRANCH,
                    block_serial=20,
                    branch_arm=0,
                ),
                ordered_path=(20, 21, 50, 60),
            ),
        ),
        diagnostics=(),
    )
    monkeypatch.setattr(
        reconstruction_module,
        "build_live_linearized_state_dag_from_graph",
        lambda *args, **kwargs: dag,
    )

    fragment = StateWriteReconstructionStrategy().plan(
        _make_reconstruction_snapshot(flow_graph, initial_state=0xAAAAAAAA)
    )

    assert fragment is None


def test_state_write_reconstruction_logs_terminal_seed_rejections(
    monkeypatch,
):
    mov = int(ida_hexrays.m_mov)
    goto = int(ida_hexrays.m_goto)
    mop_b = int(ida_hexrays.mop_b)
    mop_n = int(ida_hexrays.mop_n)
    mop_S = int(ida_hexrays.mop_S)

    flow_graph = FlowGraph(
        blocks={
            1: BlockSnapshot(1, int(ida_hexrays.BLT_1WAY), (10,), (), 0, 0x1000, ()),
            10: BlockSnapshot(10, int(ida_hexrays.BLT_2WAY), (11, 20), (1,), 0, 0x1010, ()),
            11: BlockSnapshot(11, int(ida_hexrays.BLT_2WAY), (12, 13), (10,), 0, 0x1110, ()),
            12: BlockSnapshot(12, int(ida_hexrays.BLT_0WAY), (), (11,), 0, 0x1210, ()),
            13: BlockSnapshot(13, int(ida_hexrays.BLT_0WAY), (), (11,), 0, 0x1310, ()),
            20: BlockSnapshot(
                20,
                int(ida_hexrays.BLT_1WAY),
                (21,),
                (10,),
                0,
                0x2010,
                (
                    InsnSnapshot(
                        opcode=mov,
                        ea=0x2010,
                        operands=(),
                        l=MopSnapshot(t=mop_n, size=8, value=2),
                        d=MopSnapshot(t=mop_S, size=8, stkoff=0x80),
                    ),
                    InsnSnapshot(
                        opcode=goto,
                        ea=0x2014,
                        operands=(),
                        l=MopSnapshot(t=mop_b, size=4, block_ref=21),
                    ),
                ),
            ),
            21: BlockSnapshot(21, int(ida_hexrays.BLT_0WAY), (), (20,), 0, 0x2110, ()),
        },
        entry_serial=1,
        func_ea=0x1000,
    )

    family_a = _make_reconstruction_node(10, 0x11111111, 10, owned_blocks=(10, 20))
    dag = LinearizedStateDag(
        dispatcher_entry_serial=2,
        state_var_stkoff=0x3C,
        pre_header_serial=None,
        initial_state=0x11111111,
        bst_node_blocks=(2,),
        nodes=(family_a,),
        edges=(
            StateDagEdge(
                kind=SemanticEdgeKind.CONDITIONAL_RETURN,
                source_key=family_a.key,
                target_key=None,
                target_state=None,
                target_entry_anchor=None,
                target_label="RETURN",
                source_anchor=StateRedirectAnchor(
                    kind=RedirectSourceKind.CONDITIONAL_BRANCH,
                    block_serial=10,
                    branch_arm=1,
                ),
                ordered_path=(10, 20, 21),
            ),
        ),
        diagnostics=(),
    )
    monkeypatch.setattr(
        reconstruction_module,
        "build_live_linearized_state_dag_from_graph",
        lambda *args, **kwargs: dag,
    )
    captured_messages: list[str] = []
    original_info = reconstruction_module.logger.info

    def _recording_info(message, *args, **kwargs):
        rendered = message % args if args else str(message)
        captured_messages.append(rendered)
        return original_info(message, *args, **kwargs)

    monkeypatch.setattr(reconstruction_module.logger, "info", _recording_info)

    StateWriteReconstructionStrategy().plan(
        _make_reconstruction_snapshot(flow_graph)
    )

    assert any(
        "RECON RETURN: terminal-family seed src=blk[10]@?.arm0" in message
        and "rejection=terminal_path_non_linear" in message
        for message in captured_messages
    ), "Expected seed-stage logging for the non-linear terminal arm"
    assert any(
        "RECON RETURN: terminal-family seed src=blk[10]@?.arm1" in message
        and "origins=['dag_edge', 'projected_cfg']" in message
        for message in captured_messages
    ), "Expected seed-stage logging to preserve the dag-edge source origin"


def test_state_write_reconstruction_logs_unreachable_terminal_seed_sources(
    monkeypatch,
):
    flow_graph = FlowGraph(
        blocks={
            1: BlockSnapshot(1, int(ida_hexrays.BLT_1WAY), (20,), (), 0, 0x1000, ()),
            10: BlockSnapshot(10, int(ida_hexrays.BLT_2WAY), (11, 12), (), 0, 0x1010, ()),
            11: BlockSnapshot(11, int(ida_hexrays.BLT_0WAY), (), (10,), 0, 0x1110, ()),
            12: BlockSnapshot(12, int(ida_hexrays.BLT_0WAY), (), (10,), 0, 0x1210, ()),
            20: BlockSnapshot(20, int(ida_hexrays.BLT_1WAY), (21,), (1,), 0, 0x2010, ()),
            21: BlockSnapshot(21, int(ida_hexrays.BLT_0WAY), (), (20,), 0, 0x2110, ()),
        },
        entry_serial=1,
        func_ea=0x1000,
    )

    family_a = _make_reconstruction_node(10, 0x11111111, 10, owned_blocks=(10, 11))
    dag = LinearizedStateDag(
        dispatcher_entry_serial=2,
        state_var_stkoff=0x3C,
        pre_header_serial=None,
        initial_state=0x11111111,
        bst_node_blocks=(2,),
        nodes=(family_a,),
        edges=(
            StateDagEdge(
                kind=SemanticEdgeKind.CONDITIONAL_RETURN,
                source_key=family_a.key,
                target_key=None,
                target_state=None,
                target_entry_anchor=None,
                target_label="RETURN",
                source_anchor=StateRedirectAnchor(
                    kind=RedirectSourceKind.CONDITIONAL_BRANCH,
                    block_serial=10,
                    branch_arm=0,
                ),
                ordered_path=(10, 11),
            ),
        ),
        diagnostics=(),
    )
    monkeypatch.setattr(
        reconstruction_module,
        "build_live_linearized_state_dag_from_graph",
        lambda *args, **kwargs: dag,
    )
    captured_messages: list[str] = []
    original_info = reconstruction_module.logger.info

    def _recording_info(message, *args, **kwargs):
        rendered = message % args if args else str(message)
        captured_messages.append(rendered)
        return original_info(message, *args, **kwargs)

    monkeypatch.setattr(reconstruction_module.logger, "info", _recording_info)

    StateWriteReconstructionStrategy().plan(
        _make_reconstruction_snapshot(flow_graph)
    )

    assert any(
        "RECON RETURN: terminal-family seed src=blk[10]@?.arm0" in message
        and "rejection=source_unreachable" in message
        for message in captured_messages
    ), "Expected seed-stage logging for an unreachable terminal source"


# ---------------------------------------------------------------------------
# ALL_STRATEGIES list integrity
# ---------------------------------------------------------------------------


class TestAllStrategiesList:
    """Sanity checks on the ALL_STRATEGIES module-level list."""

    def test_all_strategies_is_list(self):
        assert isinstance(ALL_STRATEGIES, list)

    def test_all_strategies_are_classes(self):
        for item in ALL_STRATEGIES:
            assert isinstance(item, type), f"{item} is not a class"

    def test_all_strategies_instantiable(self):
        for cls in ALL_STRATEGIES:
            instance = cls()
            assert instance is not None

    def test_families_coverage(self):
        """Experimental pipeline currently spans direct reconstruction plus cleanup."""
        families = {cls().family for cls in ALL_STRATEGIES}
        assert FAMILY_DIRECT in families
        assert families <= {FAMILY_DIRECT, FAMILY_CLEANUP}
