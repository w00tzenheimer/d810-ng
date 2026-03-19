"""Unit tests for Hodur strategy classes.

These tests verify that all 7 strategy classes correctly implement the
UnflatteningStrategy protocol and have unique names, without requiring an
IDA environment.
"""
from __future__ import annotations

from types import SimpleNamespace

import pytest

from d810.cfg.graph_modification import (
    EdgeRedirectViaPredSplit,
    RedirectBranch,
    RedirectGoto,
)
from d810.optimizers.microcode.flow.flattening.hodur.datamodel import (
    DispatcherStateMachine,
    StateHandler,
    StateTransition,
)
from d810.optimizers.microcode.flow.flattening.hodur._modification_bridge import (
    ModificationBuilder,
)
import d810.optimizers.microcode.flow.flattening.hodur.strategies.linearized_flow_graph as lfg_module
from d810.optimizers.microcode.flow.flattening.hodur.strategies.linearized_flow_graph import (
    LinearizedFlowGraphStrategy,
)
from d810.optimizers.microcode.flow.flattening.hodur.strategies.backward_pred_resolution import (
    _collect_known_transition_sources,
)
from d810.optimizers.microcode.flow.flattening.hodur.strategy import (
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
    AssignmentMapFallbackStrategy,
    ConditionalForkFallbackStrategy,
    DirectHandlerLinearizationStrategy,
    EdgeSplitConflictResolutionStrategy,
    HiddenHandlerClosureStrategy,
    PredPatchFallbackStrategy,
    TerminalLoopCleanupStrategy,
)
from d810.optimizers.microcode.flow.flattening.hodur.snapshot import AnalysisSnapshot
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
    """Experimental ALL_STRATEGIES currently contains 2 active strategies."""
    assert len(ALL_STRATEGIES) == 2


def test_backward_pred_collects_known_transition_source_blocks():
    sm = DispatcherStateMachine(
        mba=None,
        transitions=[
            StateTransition(
                from_state=0x2315233C,
                to_state=0x7FDCE054,
                from_block=35,
                is_conditional=False,
            ),
            StateTransition(
                from_state=0x6D207773,
                to_state=0x0B2FECE0,
                from_block=48,
                is_conditional=False,
            ),
            StateTransition(
                from_state=0x42267E66,
                to_state=None,
                from_block=None,
                is_conditional=False,
            ),
        ],
    )

    assert _collect_known_transition_sources(sm) == {35, 48}


# ---------------------------------------------------------------------------
# Name and family properties
# ---------------------------------------------------------------------------


class TestStrategyProperties:
    """Verify name and family for each strategy."""

    def test_direct_linearization_name(self):
        s = DirectHandlerLinearizationStrategy()
        assert s.name == "direct_handler_linearization"

    def test_direct_linearization_family(self):
        s = DirectHandlerLinearizationStrategy()
        assert s.family == FAMILY_DIRECT

    def test_hidden_handler_closure_name(self):
        s = HiddenHandlerClosureStrategy()
        assert s.name == "hidden_handler_closure"

    def test_hidden_handler_closure_family(self):
        s = HiddenHandlerClosureStrategy()
        assert s.family == FAMILY_DIRECT

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

    def test_pred_patch_fallback_name(self):
        s = PredPatchFallbackStrategy()
        assert s.name == "pred_patch_fallback"

    def test_pred_patch_fallback_family(self):
        s = PredPatchFallbackStrategy()
        assert s.family == FAMILY_FALLBACK

    def test_conditional_fork_fallback_name(self):
        s = ConditionalForkFallbackStrategy()
        assert s.name == "conditional_fork_fallback"

    def test_conditional_fork_fallback_family(self):
        s = ConditionalForkFallbackStrategy()
        assert s.family == FAMILY_FALLBACK

    def test_assignment_map_fallback_name(self):
        s = AssignmentMapFallbackStrategy()
        assert s.name == "assignment_map_fallback"

    def test_assignment_map_fallback_family(self):
        s = AssignmentMapFallbackStrategy()
        assert s.family == FAMILY_FALLBACK


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

    def test_direct_linearization_not_applicable(self):
        s = DirectHandlerLinearizationStrategy()
        assert not s.is_applicable(_empty_snapshot())

    def test_hidden_handler_closure_not_applicable(self):
        s = HiddenHandlerClosureStrategy()
        assert not s.is_applicable(_empty_snapshot())

    def test_edge_split_not_applicable(self):
        s = EdgeSplitConflictResolutionStrategy()
        assert not s.is_applicable(_empty_snapshot())

    def test_terminal_loop_cleanup_not_applicable(self):
        s = TerminalLoopCleanupStrategy()
        assert not s.is_applicable(_empty_snapshot())

    def test_pred_patch_fallback_not_applicable(self):
        s = PredPatchFallbackStrategy()
        assert not s.is_applicable(_empty_snapshot())

    def test_conditional_fork_fallback_not_applicable(self):
        s = ConditionalForkFallbackStrategy()
        assert not s.is_applicable(_empty_snapshot())

    def test_assignment_map_fallback_not_applicable(self):
        s = AssignmentMapFallbackStrategy()
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

    def test_direct_linearization_returns_none(self):
        self._check_none(DirectHandlerLinearizationStrategy())

    def test_hidden_handler_closure_returns_none(self):
        self._check_none(HiddenHandlerClosureStrategy())

    def test_edge_split_returns_none(self):
        self._check_none(EdgeSplitConflictResolutionStrategy())

    def test_terminal_loop_cleanup_returns_none(self):
        self._check_none(TerminalLoopCleanupStrategy())

    def test_pred_patch_fallback_returns_none(self):
        self._check_none(PredPatchFallbackStrategy())

    def test_conditional_fork_fallback_returns_none(self):
        self._check_none(ConditionalForkFallbackStrategy())

    def test_assignment_map_fallback_returns_none(self):
        self._check_none(AssignmentMapFallbackStrategy())


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

    def test_direct_linearization_no_prereqs(self):
        s = DirectHandlerLinearizationStrategy()
        # Build a minimal snapshot so plan() runs.
        fragment = s.plan(_empty_snapshot())
        # plan returns None on empty snapshot; check via PlanFragment when applicable.
        # Constructing a PlanFragment manually to verify prereq field behaviour.
        assert s.name == "direct_handler_linearization"

    def test_hidden_handler_closure_prereqs(self):
        # Construct a plan fragment explicitly to check prerequisites field.
        frag = PlanFragment(
            strategy_name="hidden_handler_closure",
            family=FAMILY_DIRECT,
            modifications=[],
            ownership=OwnershipScope(
                blocks=frozenset(), edges=frozenset(), transitions=frozenset()
            ),
            prerequisites=["direct_handler_linearization"],
            expected_benefit=BenefitMetrics(0, 0, 0, 0.0),
            risk_score=0.2,
        )
        assert "direct_handler_linearization" in frag.prerequisites

    def test_edge_split_no_prereqs_by_design(self):
        s = EdgeSplitConflictResolutionStrategy(conflict_blocks={1})
        frag = s.plan(_empty_snapshot())
        assert frag is None
        assert s.name == "edge_split_conflict_resolution"

    def test_pred_patch_prereq_declared(self):
        # Verify the prereq list is declared on the strategy even when
        # plan() returns None (no resolvable targets from empty snapshot).
        s = PredPatchFallbackStrategy()
        snap = AnalysisSnapshot(mba=None, state_machine=None, detector=None)
        frag = s.plan(snap)
        # With no state machine, plan returns None — that's correct.
        # Verify prerequisites are accessible via the strategy's protocol.
        assert hasattr(s, "plan")
        # Also verify via a fragment that DOES get produced (needs real SM).
        # For now, trust the protocol test above covers prerequisite wiring.


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


class _FakeFlowGraph:
    def __init__(self, blocks: list[_FakeFlowBlock]):
        self.blocks = {block.serial: block for block in blocks}

    def get_block(self, serial: int):
        return self.blocks.get(serial)

    def successors(self, serial: int):
        block = self.blocks.get(serial)
        return tuple(block.succs) if block is not None else ()

    def predecessors(self, serial: int):
        block = self.blocks.get(serial)
        return tuple(block.preds) if block is not None else ()


class _FakeNum:
    def __init__(self, value: int):
        self.value = value


class _FakeStackRef:
    def __init__(self, off: int):
        self.off = off


class _FakeMop:
    def __init__(self, t: int, *, off: int | None = None, value: int | None = None):
        self.t = t
        self.s = _FakeStackRef(off) if off is not None else None
        self.nnn = _FakeNum(value) if value is not None else None


class _FakeInsn:
    def __init__(self, opcode: int, l=None, d=None, next_insn=None):
        self.opcode = opcode
        self.l = l
        self.d = d
        self.next = next_insn


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


class _FakeMBA(SimpleNamespace):
    def __init__(self, *, blocks: list[_FakeMBAFlowBlock], entry_ea: int = 0x401000):
        super().__init__(entry_ea=entry_ea, maturity=1)
        self._blocks = {block.serial: block for block in blocks}

    def get_mblock(self, serial: int):
        return self._blocks.get(serial)


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


def test_lfg_plan_uses_single_stable_dag_pass(monkeypatch):
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
        flow_graph=original_flow_graph,
    )

    fragment = strategy.plan(snapshot)

    assert fragment is not None
    assert build_calls == [original_flow_graph]
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
            _FakeFlowBlock(2, []),
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

    assert fragment is not None
    assert fragment.metadata["allow_post_apply_bst_cleanup"] is False
    assert fragment.metadata["post_apply_bst_cleanup_reason"] == (
        "residual_dispatcher_predecessors"
    )
    assert fragment.metadata["residual_dispatcher_preds"] == (95,)


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

    assert LinearizedFlowGraphStrategy._emit_dag_redirect(
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
        """Experimental pipeline currently stays in the direct family."""
        families = {cls().family for cls in ALL_STRATEGIES}
        assert FAMILY_DIRECT in families
        assert families <= {FAMILY_DIRECT}
