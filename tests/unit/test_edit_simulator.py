"""Unit tests for edit simulator (no IDA dependency)."""

from dataclasses import fields as dataclass_fields, replace
import pytest

from d810.transforms.contract import CfgContract
from d810.transforms.edit_simulator import (
    SimulatedEdit,
    SimulationResult,
    graph_modifications_to_simulated_edits,
    patch_plan_to_simulated_edits,
    project_cumulative_state,
    project_patch_plan,
    project_post_state,
    simulate_edits,
)
from d810.analyses.control_flow.graph_checks import prove_terminal_sink
from d810.ir.flowgraph import (
    BlockKind,
    BlockSnapshot,
    FlowGraph,
    InsnKind,
    InsnSnapshot,
    MopSnapshot,
    OperandKind,
    PredicateKind,
)
from d810.ir.semantics import ControlTransferKind
from d810.ir.expressions import ValueOpKind
from d810.transforms.graph_modification import (
    ConvertToGoto,
    CreateConditionalRedirect,
    ExitPathLoweringGroup,
    ExitPathLoweringKind,
    ExitPathLoweringSite,
    DuplicateBlock,
    EdgeRedirectViaPredSplit,
    InsertBlock,
    LowerConditionalStateTransition,
    PrivateTerminalSuffixGroup,
    RedirectGoto,
    RemoveEdge,
    ScalarizeLocalAliasAccess,
)
from d810.transforms.cfg_transaction import PlanBlockRef
from d810.transforms.graph_modification import PreserveLivePredicateCondition
from d810.transforms.plan import PatchPlan
from d810.transforms.plan import PatchLowerConditionalStateTransition
from d810.transforms.graph_modification import (
    SyntheticCounterBoundCondition,
    SyntheticStackValueEqualsCondition,
)
from tests.typed_patch_authority import compile_patch_plan


def _projected_plan_serial(
    cfg: FlowGraph,
    plan: PatchPlan,
    ref: PlanBlockRef,
) -> int:
    assert isinstance(ref, PlanBlockRef)
    assert ref.plan_id == plan.plan_id
    return max(cfg.blocks) + tuple(spec.block_id for spec in plan.new_blocks).index(ref)


def _expected_synthetic_goto(*, ea: int, target: int) -> InsnSnapshot:
    """Build the complete portable record required for a synthetic GOTO."""
    return InsnSnapshot(
        opcode=-1,
        ea=ea,
        operands=(),
        operand_slots=(),
        display_text="",
        l=None,
        r=None,
        d=MopSnapshot(kind=OperandKind.BLOCK, block_ref=target),
        kind=InsnKind.GOTO,
        raw_opcode=None,
        value_op_kind=None,
        control_transfer_kind=ControlTransferKind.GOTO,
        call_kind=None,
        predicate_kind=None,
        opcode_attrs={},
        branch_predicate=None,
        compare_width=None,
        is_conditional_jump=False,
        is_unconditional_jump=True,
        is_call=False,
        native_ea=None,
    )


def _assert_reciprocal_topology(graph: FlowGraph) -> None:
    for block in graph.blocks.values():
        for successor in block.succs:
            assert block.serial in graph.blocks[successor].preds
        for predecessor in block.preds:
            assert block.serial in graph.blocks[predecessor].succs


@pytest.mark.parametrize("explicit_goto", [False, True])
def test_corridor_clone_preserves_final_constant_setup(explicit_goto: bool) -> None:
    """Projection must copy fallthrough payload just as the native clone does."""
    setup = InsnSnapshot(
        opcode=4, ea=0x1204, operands=(), kind=InsnKind.MOV,
        value_op_kind=ValueOpKind.MOVE,
        l=MopSnapshot(kind=OperandKind.NUMBER, size=8, value=0x0D915A190F589E30),
        d=MopSnapshot(kind=OperandKind.REGISTER, size=8, reg=104),
    )
    body = (setup,)
    if explicit_goto:
        body += (_expected_synthetic_goto(ea=0x1208, target=2),)

    def block(serial, succs, preds, instructions=()):
        return BlockSnapshot(
            serial=serial, block_type=1 if succs else 0, succs=succs,
            preds=preds, flags=0, start_ea=0x1100 + serial * 0x100,
            insn_snapshots=instructions,
            kind=BlockKind.ONE_WAY if succs else BlockKind.ZERO_WAY,
            tail_kind=instructions[-1].kind if instructions else InsnKind.NOP,
        )

    graph = FlowGraph(
        blocks={
            0: block(0, (1,), ()),
            1: block(1, (2,), (0,), body),
            2: block(2, (4,), (1,)),
            3: block(3, (4,), ()),
            4: block(4, (), (2, 3)),
        },
        entry_serial=0, func_ea=0x1100,
    )
    plan = compile_patch_plan([
        EdgeRedirectViaPredSplit(
            src_block=1, old_target=2, new_target=3, via_pred=0, clone_until=1,
        ),
    ], graph)
    projected = project_post_state(graph, plan)
    clone_serial = _projected_plan_serial(graph, plan, plan.new_blocks[0].block_id)
    clone = projected.blocks[clone_serial]
    assert len(clone.insn_snapshots) == 2
    assert clone.insn_snapshots[0] == setup
    assert clone.insn_snapshots[1].control_transfer_kind is ControlTransferKind.GOTO
    assert clone.insn_snapshots[1].d.block_ref == 3
    assert projected.blocks[1].insn_snapshots == body
    assert projected.blocks[0].succs == (clone_serial,)
    _assert_reciprocal_topology(projected)


def test_project_post_state_forecasts_exact_local_alias_scalarization() -> None:
    source = FlowGraph(
        blocks={
            0: BlockSnapshot(
                serial=0, block_type=0, succs=(), preds=(), flags=0,
                start_ea=0x1000,
                insn_snapshots=(InsnSnapshot(
                    opcode=23, raw_opcode=23, ea=0x1000, native_ea=0x1010,
                    operands=(), kind=InsnKind.STORE,
                    display_text="%alias = %base",
                    value_op_kind=ValueOpKind.STORE,
                    l=MopSnapshot(kind=OperandKind.LVAR, size=4),
                ),),
                tail_opcode=23, tail_kind=InsnKind.STORE, raw_tail_opcode=23,
                kind=BlockKind.ZERO_WAY,
            ),
        },
        entry_serial=0, func_ea=0x1000,
    )
    plan = compile_patch_plan((ScalarizeLocalAliasAccess(
        block_serial=0, host_ea=0x1000, host_opcode=23,
        alias_token="%alias", base_token="%base", value_size=4,
    ),), source)

    projected = project_post_state(source, plan)

    host = projected.blocks[0].insn_snapshots[0]
    assert host.kind is InsnKind.MOV
    assert host.value_op_kind is ValueOpKind.MOVE
    assert host.display_text == "%alias = %base"
    assert host.ea == 0x1000
    assert host.native_ea == 0x1010
    assert host.opcode == host.raw_opcode == 23
    assert projected.blocks[0].tail_kind is InsnKind.MOV


def test_project_post_state_forecasts_local_alias_load_scalarization() -> None:
    source = FlowGraph(
        blocks={
            0: BlockSnapshot(
                serial=0, block_type=0, succs=(), preds=(), flags=0,
                start_ea=0x1000,
                insn_snapshots=(InsnSnapshot(
                    opcode=22, raw_opcode=22, ea=0x1000, native_ea=0x1010,
                    operands=(), kind=InsnKind.LOAD,
                    display_text="%result = *%alias",
                    value_op_kind=ValueOpKind.LOAD,
                    r=MopSnapshot(kind=OperandKind.LVAR, size=8),
                    d=MopSnapshot(kind=OperandKind.LVAR, size=4),
                ),),
                tail_opcode=22, tail_kind=InsnKind.LOAD, raw_tail_opcode=22,
                kind=BlockKind.ZERO_WAY,
            ),
        },
        entry_serial=0, func_ea=0x1000,
    )
    plan = compile_patch_plan((ScalarizeLocalAliasAccess(
        block_serial=0, host_ea=0x1000, host_opcode=22,
        alias_token="%alias", base_token="%base", value_size=4,
    ),), source)

    projected = project_post_state(source, plan)

    host = projected.blocks[0].insn_snapshots[0]
    assert host.kind is InsnKind.MOV
    assert host.value_op_kind is ValueOpKind.MOVE
    assert host.ea == 0x1000
    assert host.native_ea == 0x1010


def test_project_post_state_rejects_stale_local_alias_scalarization_host() -> None:
    source = FlowGraph(
        blocks={
            0: BlockSnapshot(
                serial=0, block_type=0, succs=(), preds=(), flags=0,
                start_ea=0x1000,
                insn_snapshots=(InsnSnapshot(
                    opcode=23, raw_opcode=23, ea=0x1000, native_ea=0x1000,
                    operands=(), kind=InsnKind.STORE,
                    display_text="%alias = %base",
                    value_op_kind=ValueOpKind.STORE,
                    l=MopSnapshot(kind=OperandKind.LVAR, size=4),
                ),),
                tail_opcode=23, tail_kind=InsnKind.STORE, raw_tail_opcode=23,
                kind=BlockKind.ZERO_WAY,
            ),
        },
        entry_serial=0, func_ea=0x1000,
    )
    plan = compile_patch_plan((ScalarizeLocalAliasAccess(
        block_serial=0, host_ea=0x1001, host_opcode=23,
        alias_token="%alias", base_token="%base", value_size=4,
    ),), source)

    with pytest.raises(ValueError, match="one exact source STORE"):
        project_post_state(source, plan)


def _block(
    serial: int, succs: tuple[int, ...], preds: tuple[int, ...]
) -> BlockSnapshot:
    return BlockSnapshot(
        serial=serial,
        block_type=1 if succs else 0,
        succs=succs,
        preds=preds,
        flags=0,
        start_ea=0,
        insn_snapshots=(),
    )


def _conditional_lowering_plan(
    cfg: FlowGraph, *modifications: object
) -> PatchPlan:
    return compile_patch_plan(list(modifications), cfg)


def _conditional_lowering_step() -> LowerConditionalStateTransition:
    return LowerConditionalStateTransition(
        source_serial=0,
        old_dispatcher_serial=1,
        rewrite_from_ea=0x1005,
        condition_operand=PreserveLivePredicateCondition(
            predicate_ea=0x1005,
            true_is_taken=True,
        ),
        false_target_serial=2,
        true_target_serial=3,
    )


def _conditional_cfg() -> FlowGraph:
    return FlowGraph(
        blocks={
            0: _block(0, (1,), ()),
            1: _block(1, (), (0,)),
            2: _block(2, (), ()),
            3: _block(3, (), ()),
            4: _block(4, (), ()),
        },
        entry_serial=0,
        func_ea=0x1000,
    )


def _live_predicate_cfg() -> FlowGraph:
    predicate_ea = 0x1005
    return FlowGraph(
        blocks={
            0: BlockSnapshot(
                serial=0,
                block_type=2,
                succs=(4, 1),
                preds=(),
                flags=0,
                start_ea=0x1000,
                insn_snapshots=(
                    InsnSnapshot(
                        opcode=7,
                        ea=predicate_ea,
                        operands=(),
                        d=MopSnapshot(kind=OperandKind.BLOCK, block_ref=1),
                        kind=InsnKind.COND_JUMP,
                        is_conditional_jump=True,
                    ),
                ),
                kind=BlockKind.TWO_WAY,
                tail_kind=InsnKind.COND_JUMP,
            ),
            1: _block(1, (), (0,)),
            2: _block(2, (), ()),
            3: _block(3, (), ()),
            4: _block(4, (), (0,)),
        },
        entry_serial=0,
        func_ea=0x1000,
    )


@pytest.mark.parametrize(
    ("true_is_taken", "expected_succs", "expected_taken"),
    (
        (True, (2, 3), 3),
        (False, (3, 2), 2),
    ),
)
def test_preserved_live_predicate_projection_uses_marker_polarity(
    true_is_taken: bool,
    expected_succs: tuple[int, int],
    expected_taken: int,
) -> None:
    cfg = _live_predicate_cfg()
    plan = _conditional_lowering_plan(
        cfg,
        LowerConditionalStateTransition(
            source_serial=0,
            old_dispatcher_serial=1,
            rewrite_from_ea=0x1005,
            condition_operand=PreserveLivePredicateCondition(
                predicate_ea=0x1005,
                true_is_taken=true_is_taken,
            ),
            false_target_serial=2,
            true_target_serial=3,
        ),
    )

    projected = project_post_state(cfg, plan)

    assert projected.blocks[0].succs == expected_succs
    assert projected.blocks[0].tail is not None
    assert projected.blocks[0].tail.d is not None
    assert projected.blocks[0].tail.d.block_ref == expected_taken


def test_preserved_live_predicate_projection_rejects_mismatched_predicate_ea() -> None:
    cfg = _live_predicate_cfg()
    plan = _conditional_lowering_plan(
        cfg,
        LowerConditionalStateTransition(
            source_serial=0,
            old_dispatcher_serial=1,
            rewrite_from_ea=0x1005,
            condition_operand=PreserveLivePredicateCondition(
                predicate_ea=0x1006,
                true_is_taken=True,
            ),
            false_target_serial=2,
            true_target_serial=3,
        ),
    )

    with pytest.raises(ValueError, match="predicate EA must match rewrite EA"):
        project_post_state(cfg, plan)


def test_preserved_live_predicate_projection_rejects_nonconditional_tail() -> None:
    cfg = _live_predicate_cfg()
    source = cfg.blocks[0]
    nonconditional_tail = replace(
        source.tail,
        kind=InsnKind.GOTO,
        is_conditional_jump=False,
        is_unconditional_jump=True,
    )
    assert nonconditional_tail is not None
    cfg = FlowGraph(
        {
            **cfg.blocks,
            0: replace(
                source,
                insn_snapshots=(nonconditional_tail,),
                tail_kind=InsnKind.GOTO,
            ),
        },
        entry_serial=cfg.entry_serial,
        func_ea=cfg.func_ea,
    )
    plan = _conditional_lowering_plan(cfg, _conditional_lowering_step())

    with pytest.raises(ValueError, match="two-way conditional tail"):
        project_post_state(cfg, plan)


def test_preserved_live_predicate_projection_rejects_non_two_way_source() -> None:
    cfg = _live_predicate_cfg()
    source = cfg.blocks[0]
    cfg = FlowGraph(
        {
            **cfg.blocks,
            0: replace(source, block_type=1, succs=(1,), kind=BlockKind.ONE_WAY),
            4: replace(cfg.blocks[4], preds=()),
        },
        entry_serial=cfg.entry_serial,
        func_ea=cfg.func_ea,
    )
    plan = _conditional_lowering_plan(cfg, _conditional_lowering_step())

    with pytest.raises(ValueError, match="exactly two source successors"):
        project_post_state(cfg, plan)


def test_patch_plan_lowering_is_a_typed_simulated_edit() -> None:
    cfg = _conditional_cfg()
    plan = _conditional_lowering_plan(cfg, _conditional_lowering_step())

    edits = patch_plan_to_simulated_edits(plan)
    assert [edit.kind for edit in edits] == [
        "lower_conditional_state_transition",
    ]
    assert edits[0].fallthrough_target == 2
    assert edits[0].new_target == 3
    simulated = simulate_edits(cfg.as_adjacency_dict(), edits)
    assert simulated.adj[0] == [2, 3]

    with pytest.raises(ValueError, match="unsupported lower-conditional"):
        project_post_state(cfg, plan)


def test_conditional_redirect_projection_keeps_clone_conditional_and_helper_goto() -> None:
    """The helper is a one-way synthetic GOTO, never a copied conditional body."""
    cfg = FlowGraph(
        blocks={
            0: BlockSnapshot(0, 0, (1,), (), 0, 0x1000, (), kind=BlockKind.ONE_WAY),
            1: BlockSnapshot(
                1, 1, (3, 2), (0,), 0, 0x2000,
                (InsnSnapshot(0, 0x2000, (), kind=InsnKind.NOP), InsnSnapshot(
                    0, 0x2001, (), kind=InsnKind.COND_JUMP,
                    l=MopSnapshot(kind=OperandKind.STACK, size=4, stkoff=4, stack_refs=(4,)),
                    r=MopSnapshot(kind=OperandKind.NUMBER, size=4, value=7),
                    d=MopSnapshot(kind=OperandKind.BLOCK, block_ref=2),
                    branch_predicate=PredicateKind.EQ,
                    predicate_kind=PredicateKind.EQ,
                    compare_width=4,
                    is_conditional_jump=True,
                )),
                    kind=BlockKind.TWO_WAY, tail_kind=InsnKind.COND_JUMP,
                    tail_opcode=0, raw_tail_opcode=None,
                ),
            2: BlockSnapshot(2, 0, (), (1,), 0, 0x3000, (), kind=BlockKind.ZERO_WAY),
            3: BlockSnapshot(3, 0, (), (1,), 0, 0x4000, (), kind=BlockKind.ZERO_WAY),
            5: BlockSnapshot(5, 0, (), (), 0, 0x5000, (), kind=BlockKind.ZERO_WAY),
        },
        entry_serial=0,
        func_ea=0x1000,
    )
    plan = compile_patch_plan([
        CreateConditionalRedirect(
            source_block=0, ref_block=1, conditional_target=5,
            fallthrough_target=3,
        ),
    ], cfg)

    projected = project_post_state(cfg, plan)
    assert cfg.get_block(1).tail is not None
    assert cfg.get_block(1).tail.d is not None
    assert cfg.get_block(1).tail.d.block_ref == 2
    clone_serial = _projected_plan_serial(cfg, plan, plan.new_blocks[0].block_id)
    helper_serial = _projected_plan_serial(cfg, plan, plan.new_blocks[1].block_id)
    assert projected.get_block(0).succs == (clone_serial,)
    assert projected.get_block(clone_serial).succs == (helper_serial, 7)
    assert projected.get_block(helper_serial).succs == (3,)
    assert projected.get_block(clone_serial).tail_kind is InsnKind.COND_JUMP
    assert projected.get_block(clone_serial).tail is not None
    assert projected.get_block(clone_serial).tail.d is not None
    assert projected.get_block(clone_serial).tail.d.block_ref == 7
    assert projected.get_block(helper_serial).tail_kind is InsnKind.GOTO
    assert all(
        instruction.kind is not InsnKind.COND_JUMP
        for instruction in projected.get_block(helper_serial).insn_snapshots
    )


def test_conditional_redirect_projection_requires_exact_source_old_edge() -> None:
    cfg = FlowGraph(
        blocks={
            0: BlockSnapshot(0, 0, (2,), (), 0, 0x1000, (), kind=BlockKind.ONE_WAY),
            1: BlockSnapshot(1, 1, (2, 3), (), 0, 0x2000, (), kind=BlockKind.TWO_WAY),
            2: BlockSnapshot(2, 0, (), (0, 1), 0, 0x3000, (), kind=BlockKind.ZERO_WAY),
            3: BlockSnapshot(3, 0, (), (1,), 0, 0x4000, (), kind=BlockKind.ZERO_WAY),
            9: BlockSnapshot(9, 0, (), (), 0, 0x9000, (), kind=BlockKind.ZERO_WAY),
        },
        entry_serial=0,
        func_ea=0x1000,
    )
    plan = compile_patch_plan([
        CreateConditionalRedirect(
            source_block=0, ref_block=1, conditional_target=2,
            fallthrough_target=3,
        ),
    ], cfg)
    with pytest.raises(ValueError, match="source.*old target|source adjacency"):
        project_post_state(cfg, plan)


def test_conditional_redirect_projection_rejects_nonconditional_template() -> None:
    cfg = FlowGraph(
        blocks={
            0: BlockSnapshot(0, 0, (1,), (), 0, 0x1000, (), kind=BlockKind.ONE_WAY),
            1: BlockSnapshot(
                1, 1, (2,), (0,), 0, 0x2000,
                (InsnSnapshot(0, 0x2000, (), kind=InsnKind.GOTO),),
                kind=BlockKind.ONE_WAY,
            ),
            2: BlockSnapshot(2, 0, (), (1,), 0, 0x3000, (), kind=BlockKind.ZERO_WAY),
            3: BlockSnapshot(3, 0, (), (), 0, 0x4000, (), kind=BlockKind.ZERO_WAY),
        },
        entry_serial=0,
        func_ea=0x1000,
    )
    plan = compile_patch_plan([
        CreateConditionalRedirect(
            source_block=0, ref_block=1, conditional_target=2,
            fallthrough_target=3,
        ),
    ], cfg)
    with pytest.raises(ValueError, match="coherent conditional template|two-way template"):
        project_post_state(cfg, plan)


def test_patch_plan_lowering_rejects_live_order_conflict() -> None:
    cfg = _conditional_cfg()
    plan = _conditional_lowering_plan(
        cfg,
        _conditional_lowering_step(),
        RedirectGoto(from_serial=0, old_target=2, new_target=4),
    )

    edits = patch_plan_to_simulated_edits(plan)
    assert [edit.kind for edit in edits] == [
        "goto_redirect",
        "lower_conditional_state_transition",
    ]
    with pytest.raises(ValueError, match="does not retain dispatcher"):
        simulate_edits(cfg.as_adjacency_dict(), edits)
    with pytest.raises(ValueError, match="does not retain dispatcher"):
        project_post_state(cfg, plan)


def test_project_post_state_rejects_preserve_live_lowering_at_closed_boundary() -> None:
    cfg = _conditional_cfg()
    plan = _conditional_lowering_plan(cfg, _conditional_lowering_step())
    with pytest.raises(ValueError, match="unsupported lower-conditional condition"):
        project_post_state(cfg, plan)


def test_patch_plan_insert_precedes_live_goto_change() -> None:
    cfg = _conditional_cfg()
    plan = compile_patch_plan(
        [
            InsertBlock(pred_serial=0, succ_serial=1),
            RedirectGoto(from_serial=0, old_target=1, new_target=2),
        ],
        cfg,
    )

    edits = patch_plan_to_simulated_edits(plan)
    assert [edit.kind for edit in edits] == ["insert_block", "goto_redirect"]
    simulated = simulate_edits(cfg.as_adjacency_dict(), edits)
    assert simulated.adj[0] == [2]


class TestSimulateEdits:
    def test_goto_redirect(self):
        """Single edge replacement via goto_redirect."""
        adj = {0: [1], 1: [2], 2: []}
        edits = [
            SimulatedEdit(kind="goto_redirect", source=0, old_target=1, new_target=2)
        ]
        sim = simulate_edits(adj, edits)
        assert isinstance(sim, SimulationResult)
        assert sim.adj[0] == [2]
        assert sim.adj[1] == [2]  # unchanged

    def test_conditional_redirect(self):
        """One of two edges replaced via conditional_redirect."""
        adj = {0: [1, 2], 1: [], 2: []}
        edits = [
            SimulatedEdit(
                kind="conditional_redirect", source=0, old_target=2, new_target=3
            )
        ]
        sim = simulate_edits(adj, edits)
        assert sim.adj[0] == [1, 3]

    def test_convert_to_goto(self):
        """Both edges become single target via convert_to_goto."""
        adj = {0: [1, 2], 1: [], 2: []}
        edits = [
            SimulatedEdit(kind="convert_to_goto", source=0, old_target=1, new_target=3)
        ]
        sim = simulate_edits(adj, edits)
        assert sim.adj[0] == [3]

    def test_no_mutation(self):
        """Original adj unchanged after simulate."""
        adj = {0: [1], 1: [2], 2: []}
        original_copy = {0: [1], 1: [2], 2: []}
        edits = [
            SimulatedEdit(kind="goto_redirect", source=0, old_target=1, new_target=2)
        ]
        simulate_edits(adj, edits)
        assert adj == original_copy

    def test_chained_edits(self):
        """Two edits applied sequentially."""
        adj = {0: [1], 1: [2], 2: [3], 3: []}
        edits = [
            SimulatedEdit(kind="goto_redirect", source=0, old_target=1, new_target=2),
            SimulatedEdit(kind="goto_redirect", source=1, old_target=2, new_target=3),
        ]
        sim = simulate_edits(adj, edits)
        assert sim.adj[0] == [2]
        assert sim.adj[1] == [3]

    def test_edge_split_redirect_no_via_pred(self):
        """edge_split_redirect without via_pred uses conservative fallback (append)."""
        adj = {0: [1, 2], 1: [], 2: []}
        edits = [
            SimulatedEdit(
                kind="edge_split_redirect", source=0, old_target=1, new_target=3
            )
        ]
        sim = simulate_edits(adj, edits)
        assert 3 in sim.adj[0]
        # Original successors preserved, new_target appended
        assert 1 in sim.adj[0]
        assert len(sim.created_clones) == 0

    def test_edge_split_redirect_no_via_pred_dedup(self):
        """edge_split_redirect fallback does not duplicate existing target."""
        adj = {0: [1, 3], 1: [], 3: []}
        edits = [
            SimulatedEdit(
                kind="edge_split_redirect", source=0, old_target=1, new_target=3
            )
        ]
        sim = simulate_edits(adj, edits)
        assert sim.adj[0].count(3) == 1  # no duplicate

    def test_edge_split_with_clone(self):
        """Edge split creates virtual clone node."""
        # Original: 0->1->2, via_pred=0
        adj = {0: [1], 1: [2], 2: []}
        edits = [
            SimulatedEdit(
                kind="edge_split_redirect",
                source=1,
                old_target=2,
                new_target=5,
                via_pred=0,
            )
        ]
        sim = simulate_edits(adj, edits)
        # Clone node created (serial 3 = max(2)+1)
        clone = max(sim.adj.keys())
        assert clone > 2  # new node
        assert sim.adj[clone] == [5]  # clone -> new_target
        assert clone in sim.adj[0]  # via_pred rewired to clone
        assert sim.adj[1] == [2]  # original source unchanged
        assert clone in sim.created_clones

    def test_edge_split_clone_via_pred_partial_rewire(self):
        """Edge split only rewires the source edge in via_pred, not others."""
        # via_pred 0 has two successors: [1, 3]
        adj = {0: [1, 3], 1: [2], 2: [], 3: []}
        edits = [
            SimulatedEdit(
                kind="edge_split_redirect",
                source=1,
                old_target=2,
                new_target=5,
                via_pred=0,
            )
        ]
        sim = simulate_edits(adj, edits)
        clone = max(sim.adj.keys())
        # via_pred[0] should have [clone, 3] — only source=1 replaced
        assert clone in sim.adj[0]
        assert 3 in sim.adj[0]
        assert 1 not in sim.adj[0]

    def test_edge_split_clone_cycle_detection(self):
        """Edge split clone that creates cycle is detectable."""
        # 0(disp)->1(handler)->2(exit)->3(stop, nsucc=0)
        # Edge split: src=2, via_pred=1, old=3, new=1 (back to handler!)
        adj = {0: [1], 1: [2], 2: [3], 3: []}
        edits = [
            SimulatedEdit(
                kind="edge_split_redirect",
                source=2,
                old_target=3,
                new_target=1,
                via_pred=1,
            )
        ]
        sim = simulate_edits(adj, edits)
        clone = next(iter(sim.created_clones))
        # Clone -> 1 (handler), creating cycle
        assert sim.adj[clone] == [1]
        # detect_terminal_cycles should find this
        from d810.analyses.control_flow.graph_checks import detect_terminal_cycles

        cycle_result = detect_terminal_cycles(
            sim.adj, terminal_exits={clone}, handler_entries={1}, dispatcher=0
        )
        assert not cycle_result.passed

    def test_edge_split_clone_detected_as_cycle_seed(self):
        """Clone node from edge-split must be a cycle seed for detect_terminal_cycles.

        Repro of blk[219]->blk[180] bug:
        - blk[219] is terminal (nsucc=0)
        - Edge split on blk[45] via_pred=122 creates clone (e.g. 220)
        - Clone 220 -> 180 (handler entry)
        - detect_terminal_cycles from {219} misses it
        - detect_terminal_cycles from {219, 220} catches it
        """
        adj = {
            0: [45],  # dispatcher
            45: [2],  # source block
            122: [45],  # via_pred -> source
            2: [219],  # path to terminal
            219: [],  # terminal (nsucc=0)
            180: [181],  # handler entry
            181: [],  # handler body
        }
        edits = [
            SimulatedEdit(
                kind="edge_split_redirect",
                source=45,
                old_target=2,
                new_target=180,
                via_pred=122,
            )
        ]
        sim_result = simulate_edits(adj, edits)

        # Clone was created
        assert len(sim_result.created_clones) == 1
        clone = next(iter(sim_result.created_clones))

        # Clone -> 180 (handler entry)
        assert sim_result.adj[clone] == [180]

        # Without clone as seed: MISS
        from d810.analyses.control_flow.graph_checks import detect_terminal_cycles

        miss = detect_terminal_cycles(sim_result.adj, {219}, {180}, dispatcher=0)
        assert miss.passed  # wrongly passes - 219 has no succs

        # With clone as seed: CATCH
        catch = detect_terminal_cycles(
            sim_result.adj, {219, clone}, {180}, dispatcher=0
        )
        assert not catch.passed
        assert any(c.reentry_target == 180 for c in catch.cycles)

    def test_create_conditional_redirect_creates_virtual_conditional_clone(self):
        adj = {0: [1], 1: [2], 2: []}
        edits = [
            SimulatedEdit(
                kind="create_conditional_redirect",
                source=0,
                old_target=1,
                new_target=10,
                fallthrough_target=11,
            )
        ]
        sim = simulate_edits(adj, edits)
        assert len(sim.created_clones) == 2
        clone = min(sim.created_clones)
        nop_blk = max(sim.created_clones)
        assert sim.adj[0] == [clone]
        assert sim.adj[clone] == [nop_blk, 10]
        assert sim.adj[nop_blk] == [11]

    def test_duplicate_block_creates_clone_and_redirects_predecessor(self):
        cfg = FlowGraph(
            blocks={
                9: _block(9, (10,), ()),
                10: _block(10, (11,), (9,)),
                11: _block(11, (), (10,)),
            },
            entry_serial=9,
            func_ea=0,
        )

        patch_plan = compile_patch_plan(
            [
                DuplicateBlock(
                    source_block=10,
                    target_block=11,
                    pred_serial=9,
                )
            ],
            cfg,
        )

        sim = simulate_edits(
            cfg.as_adjacency_dict(),
            patch_plan_to_simulated_edits(patch_plan),
        )

        assert sim.adj[9] == [11]
        assert sim.adj[10] == [12]
        assert sim.adj[11] == [12]
        assert sim.adj[12] == []

    def test_duplicate_block_private_target_split_redirects_1way_predecessor(self):
        cfg = FlowGraph(
            blocks={
                9: _block(9, (10,), ()),
                10: _block(10, (11,), (9,)),
                11: _block(11, (), (10,)),
            },
            entry_serial=9,
            func_ea=0,
        )

        patch_plan = compile_patch_plan(
            [
                DuplicateBlock(
                    source_block=10,
                    target_block=None,
                    pred_serial=9,
                )
            ],
            cfg,
        )

        sim = simulate_edits(
            cfg.as_adjacency_dict(),
            patch_plan_to_simulated_edits(patch_plan),
        )

        assert sim.adj[9] == [11]
        assert sim.adj[10] == [12]
        assert sim.adj[11] == [12]
        assert sim.adj[12] == []

    def test_duplicate_block_preserves_conditional_shape(self):
        edits = [
            SimulatedEdit(
                kind="duplicate_block",
                source=10,
                old_target=-1,
                new_target=None,
                via_pred=9,
                source_successors=(12, 11),
                conditional_target=12,
                fallthrough_target=11,
                created_serial=14,
                secondary_created_serial=15,
                stop_serial_before=14,
                stop_serial_after=16,
            )
        ]

        sim = simulate_edits(
            {9: [10], 10: [11, 12], 11: [], 12: [], 14: []},
            edits,
        )

        assert sim.adj[9] == [14]
        assert sim.adj[10] == [11, 12]
        assert sim.adj[14] == [15, 12]
        assert sim.adj[15] == [11]
        assert sim.adj[16] == []


class TestProjectPostState:
    @staticmethod
    def _convert_to_goto_cfg() -> FlowGraph:
        state = MopSnapshot(
            kind=OperandKind.STACK, size=8, stkoff=0x20,
            stack_refs=(0x20,),
        )
        first_store = InsnSnapshot(
            opcode=30, raw_opcode=30, ea=0x1000,
            operands=(),
            kind=InsnKind.STORE, value_op_kind=ValueOpKind.STORE,
            l=MopSnapshot(kind=OperandKind.NUMBER, size=8, value=1),
            d=state,
        )
        second_store = replace(
            first_store, opcode=31, raw_opcode=31, ea=0x1004,
            l=MopSnapshot(kind=OperandKind.NUMBER, size=8, value=2),
        )
        branch = InsnSnapshot(
            opcode=44, raw_opcode=44, ea=0x1008,
            operands=(),
            kind=InsnKind.EQUALITY_JUMP,
            l=state,
            r=MopSnapshot(kind=OperandKind.NUMBER, size=8, value=2),
            d=MopSnapshot(kind=OperandKind.BLOCK, block_ref=2),
            predicate_kind=PredicateKind.EQ,
            branch_predicate=PredicateKind.EQ,
            compare_width=8,
            control_transfer_kind=ControlTransferKind.CONDITIONAL_BRANCH,
            is_conditional_jump=True,
        )
        return FlowGraph(
            {
                0: BlockSnapshot(
                    0, 0, (1, 2), (), 0, 0x1000,
                    (first_store, second_store, branch), branch.opcode,
                    BlockKind.TWO_WAY, branch.kind, None, branch.raw_opcode,
                ),
                1: BlockSnapshot(
                    1, 0, (), (0,), 0, 0x2000, (), None,
                    BlockKind.STOP, None, None,
                ),
                2: BlockSnapshot(
                    2, 0, (), (0,), 0, 0x3000, (), None,
                    BlockKind.STOP, None, None,
                ),
            },
            0,
            0x1000,
        )

    def test_convert_to_goto_preserves_store_prefix_and_normalizes_tail(self) -> None:
        from d810.transforms.unflatten_authority import producer_api

        source = self._convert_to_goto_cfg()
        plan = compile_patch_plan([ConvertToGoto(0, 2)], source)

        projected = project_post_state(source, plan)
        feeder = projected.blocks[0]

        assert feeder.succs == (2,)
        assert feeder.insn_snapshots[:-1] == source.blocks[0].insn_snapshots[:-1]
        assert feeder.insn_snapshots[-1] == _expected_synthetic_goto(
            ea=0x1008, target=2,
        )
        assert feeder.tail_opcode == -1
        assert feeder.raw_tail_opcode is None
        assert feeder.tail_kind is InsnKind.GOTO
        observed = producer_api.observe_inventory_block(
            feeder, owner_ref=None, owner_anchor_ea=feeder.start_ea,
        )
        assert tuple(
            item.instruction_kind for item in observed.instruction_observations
        ) == (InsnKind.STORE, InsnKind.STORE, InsnKind.GOTO)

    @pytest.mark.parametrize(
        "mutation", ("nonconditional", "missing_tail", "target", "reciprocal"),
    )
    def test_convert_to_goto_rejects_nonconditional_or_inexact_source(
        self, mutation: str,
    ) -> None:
        source = self._convert_to_goto_cfg()
        blocks = dict(source.blocks)
        target = 2
        if mutation == "nonconditional":
            tail = replace(
                blocks[0].insn_snapshots[-1],
                kind=InsnKind.GOTO,
                control_transfer_kind=ControlTransferKind.GOTO,
                is_conditional_jump=False,
                is_unconditional_jump=True,
                predicate_kind=None,
                branch_predicate=None,
                compare_width=None,
            )
            blocks[0] = replace(
                blocks[0], insn_snapshots=(*blocks[0].insn_snapshots[:-1], tail),
                tail_kind=InsnKind.GOTO,
            )
        elif mutation == "missing_tail":
            blocks[0] = replace(
                blocks[0], insn_snapshots=blocks[0].insn_snapshots[:-1],
                tail_opcode=31, raw_tail_opcode=31,
                tail_kind=InsnKind.STORE,
            )
        elif mutation == "reciprocal":
            blocks[2] = replace(blocks[2], preds=())
        else:
            target = 3
        source = FlowGraph(blocks, source.entry_serial, source.func_ea)
        plan = compile_patch_plan([ConvertToGoto(0, target)], source)

        with pytest.raises(ValueError, match="convert-to-goto"):
            project_post_state(source, plan)

    def test_counter_bound_lowering_projects_exact_typed_predicate(self) -> None:
        from tests.unit.transforms.unflatten_authority.helpers import exact_fixture

        cfg, _proposal, _exclusion, _refs = exact_fixture()
        plan = compile_patch_plan(
            [
                LowerConditionalStateTransition(
                    source_serial=0,
                    old_dispatcher_serial=1,
                    rewrite_from_ea=0x1001,
                    condition_operand=SyntheticCounterBoundCondition(
                        counter_size=4,
                        bound=100,
                        counter_stkoff=0x38,
                        signed=True,
                    ),
                    false_target_serial=3,
                    true_target_serial=2,
                ),
            ],
            cfg,
        )

        feeder = project_post_state(cfg, plan).blocks[0]
        assert feeder.succs == (3, 2)
        assert feeder.tail is not None
        assert feeder.tail.predicate_kind is PredicateKind.SLT
        assert feeder.tail.l is not None
        assert feeder.tail.l.kind is OperandKind.STACK
        assert feeder.tail.l.stkoff == 0x38
        assert feeder.tail.r is not None and feeder.tail.r.value == 100

    def test_exact_stack_lowering_replaces_feeder_goto_with_coherent_conditional(self) -> None:
        from tests.unit.transforms.unflatten_authority.helpers import exact_fixture

        cfg, _proposal, _exclusion, _refs = exact_fixture()
        source_before = cfg
        plan = compile_patch_plan(
            [
                LowerConditionalStateTransition(
                    source_serial=0,
                    old_dispatcher_serial=1,
                    rewrite_from_ea=0x1001,
                    condition_operand=SyntheticStackValueEqualsCondition(
                        stack_stkoff=4, stack_size=4, value=7,
                    ),
                    false_target_serial=3,
                    true_target_serial=2,
                ),
            ],
            cfg,
        )

        projected = project_post_state(cfg, plan)
        assert cfg == source_before
        feeder = projected.blocks[0]
        assert feeder.succs == (3, 2)
        assert feeder.kind is BlockKind.TWO_WAY
        assert feeder.tail_kind is InsnKind.COND_JUMP
        assert feeder.tail is not None
        assert feeder.tail.ea == 0x1001
        assert feeder.tail.kind is InsnKind.COND_JUMP
        # Conditional instructions retain backend opcode/raw-opcode metadata.
        # The -1/None pair is reserved by InventoryInstructionObservation for
        # normalized synthetic GOTOs, not conditional jumps.
        assert feeder.tail_opcode == feeder.tail.opcode == 0
        assert feeder.raw_tail_opcode == 0
        assert feeder.tail.raw_opcode == 0
        feeder.__post_init__()
        assert feeder.raw_tail_opcode == 0
        assert feeder.tail.control_transfer_kind is not None
        assert feeder.tail.d is not None
        assert feeder.tail.d.block_ref == 2
        assert feeder.tail.l is not None and feeder.tail.l.stkoff == 4
        assert feeder.tail.r is not None and feeder.tail.r.value == 7

    def test_exact_stack_lowering_rejects_missing_rewrite_boundary(self) -> None:
        from tests.unit.transforms.unflatten_authority.helpers import exact_fixture

        cfg, _proposal, _exclusion, _refs = exact_fixture()
        plan = compile_patch_plan(
            [
                LowerConditionalStateTransition(
                    source_serial=0,
                    old_dispatcher_serial=1,
                    rewrite_from_ea=0xDEAD,
                    condition_operand=SyntheticStackValueEqualsCondition(
                        stack_stkoff=4, stack_size=4, value=7,
                    ),
                    false_target_serial=3,
                    true_target_serial=2,
                ),
            ],
            cfg,
        )

        with pytest.raises(ValueError, match="rewrite"):
            project_post_state(cfg, plan)

    def test_project_post_state_preserves_unchanged_stop_terminal_shape(self):
        cfg = FlowGraph(
            blocks={
                0: _block(0, (1, 2), ()),
                1: _block(1, (2,), (0,)),
                2: BlockSnapshot(
                    serial=2,
                    block_type=0,
                    succs=(),
                    preds=(0, 1),
                    flags=0,
                    start_ea=0x1020,
                    insn_snapshots=(),
                    kind=BlockKind.STOP,
                ),
                3: _block(3, (), ()),
            },
            entry_serial=0,
            func_ea=0x1000,
        )
        plan = compile_patch_plan(
            [RedirectGoto(from_serial=1, old_target=2, new_target=3)],
            cfg,
        )

        projected = project_post_state(cfg, plan)

        assert projected.blocks[2].kind is BlockKind.STOP
        assert projected.blocks[2].succs == ()

    def test_project_post_state_normalizes_one_way_redirect_tail_to_goto(self):
        cfg = FlowGraph(
            blocks={
                1: BlockSnapshot(
                    serial=1,
                    block_type=3,
                    succs=(2,),
                    preds=(0,),
                    flags=0,
                    start_ea=0x1010,
                    insn_snapshots=(),
                    tail_opcode=4,
                ),
                2: BlockSnapshot(
                    serial=2,
                    block_type=2,
                    succs=(),
                    preds=(1,),
                    flags=0,
                    start_ea=0x1020,
                    insn_snapshots=(),
                    tail_opcode=0,
                ),
            },
            entry_serial=1,
            func_ea=0x1000,
        )

        patch_plan = compile_patch_plan(
            [RedirectGoto(from_serial=1, old_target=2, new_target=9)],
            cfg,
        )

        projected = project_post_state(cfg, patch_plan)

        assert projected.blocks[1].succs == (9,)
        assert projected.blocks[1].tail_kind == InsnKind.GOTO

    def test_project_post_state_rebuilds_created_block_preds(self):
        cfg = FlowGraph(
            blocks={
                0: BlockSnapshot(
                    serial=0,
                    block_type=3,
                    succs=(1,),
                    preds=(),
                    flags=0,
                    start_ea=0x1000,
                    insn_snapshots=(),
                    tail_opcode=2,
                ),
                1: BlockSnapshot(
                    serial=1,
                    block_type=3,
                    succs=(2,),
                    preds=(0,),
                    flags=0,
                    start_ea=0x1010,
                    insn_snapshots=(),
                    tail_opcode=2,
                ),
                2: BlockSnapshot(
                    serial=2,
                    block_type=2,
                    succs=(),
                    preds=(1,),
                    flags=0,
                    start_ea=0x1020,
                    insn_snapshots=(),
                    tail_opcode=0,
                ),
            },
            entry_serial=0,
            func_ea=0x1000,
        )

        patch_plan = compile_patch_plan(
            [
                InsertBlock(
                    pred_serial=1,
                    succ_serial=2,
                    instructions=(),
                )
            ],
            cfg,
        )

        projected = project_post_state(cfg, patch_plan)

        assert projected.blocks[1].succs == (2,)
        assert projected.blocks[2].preds == (1,)
        assert projected.blocks[2].succs == (3,)
        assert projected.blocks[3].preds == (2,)

    def test_project_post_state_recomputes_existing_semantics_after_remove_edge(self):
        cfg = FlowGraph(
            blocks={
                10: BlockSnapshot(
                    serial=10,
                    block_type=4,
                    succs=(11, 12),
                    preds=(),
                    flags=0,
                    start_ea=0x1010,
                    insn_snapshots=(),
                    tail_opcode=7,
                    kind=BlockKind.TWO_WAY,
                    tail_kind=InsnKind.COND_JUMP,
                ),
                11: BlockSnapshot(
                    serial=11,
                    block_type=2,
                    succs=(),
                    preds=(10,),
                    flags=0,
                    start_ea=0x1020,
                    insn_snapshots=(),
                ),
                12: BlockSnapshot(
                    serial=12,
                    block_type=2,
                    succs=(),
                    preds=(10,),
                    flags=0,
                    start_ea=0x1030,
                    insn_snapshots=(),
                ),
            },
            entry_serial=10,
            func_ea=0x1000,
        )

        patch_plan = compile_patch_plan([RemoveEdge(from_serial=10, to_serial=12)], cfg)

        projected = project_post_state(cfg, patch_plan)

        assert projected.blocks[10].succs == (11,)
        assert projected.blocks[10].kind == BlockKind.ONE_WAY
        assert projected.blocks[10].tail_kind == InsnKind.GOTO
        assert (
            CfgContract().check_projection(
                project_patch_plan(cfg, patch_plan, snapshot_id=patch_plan.snapshot_id)
            )
            == []
        )


class TestModificationProjection:
    def test_graph_modifications_to_simulated_edits(self):
        mods = [
            RedirectGoto(from_serial=1, old_target=2, new_target=3),
            ConvertToGoto(block_serial=4, goto_target=5),
            EdgeRedirectViaPredSplit(
                src_block=6, old_target=7, new_target=8, via_pred=9
            ),
            InsertBlock(
                pred_serial=14,
                succ_serial=15,
                instructions=(InsnSnapshot(opcode=0x90, ea=0x1000, operands=()),),
            ),
            RemoveEdge(from_serial=16, to_serial=17),
            CreateConditionalRedirect(
                source_block=10,
                ref_block=11,
                conditional_target=12,
                fallthrough_target=13,
            ),
        ]
        edits = graph_modifications_to_simulated_edits(mods)
        assert [e.kind for e in edits] == [
            "goto_redirect",
            "convert_to_goto",
            "edge_split_redirect",
            "insert_block",
            "remove_edge",
            "create_conditional_redirect",
        ]

    def test_patch_plan_edge_split_relocates_stop(self):
        cfg = FlowGraph(
            blocks={
                122: _block(122, (45,), ()),
                45: _block(45, (2,), (122,)),
                2: _block(2, (219,), (45,)),
                180: _block(180, (), ()),
                219: _block(219, (), (2,)),
            },
            entry_serial=122,
            func_ea=0,
        )

        patch_plan = compile_patch_plan(
            [
                EdgeRedirectViaPredSplit(
                    src_block=45,
                    old_target=2,
                    new_target=180,
                    via_pred=122,
                    rule_priority=550,
                )
            ],
            cfg,
        )

        sim = simulate_edits(
            cfg.as_adjacency_dict(), patch_plan_to_simulated_edits(patch_plan)
        )

        assert sim.adj[122] == [219]
        assert sim.adj[45] == [2]
        assert sim.adj[2] == [220]
        assert sim.adj[219] == [180]
        assert sim.adj[220] == []

    def test_edge_split_and_insert_block_can_share_source(self):
        def semantic_block(
            serial: int,
            succs: tuple[int, ...],
            preds: tuple[int, ...],
        ) -> BlockSnapshot:
            return BlockSnapshot(
                serial=serial,
                block_type=1 if succs else 0,
                succs=succs,
                preds=preds,
                flags=0,
                start_ea=0,
                insn_snapshots=(),
                kind=(
                    BlockKind.TWO_WAY
                    if len(succs) == 2
                    else BlockKind.ONE_WAY
                    if len(succs) == 1
                    else BlockKind.ZERO_WAY
                ),
                tail_kind=(
                    InsnKind.COND_JUMP
                    if len(succs) == 2
                    else InsnKind.GOTO
                    if len(succs) == 1
                    else InsnKind.NOP
                ),
            )

        cfg = FlowGraph(
            blocks={
                54: semantic_block(54, (), (98,)),
                98: semantic_block(98, (54, 100), ()),
                99: semantic_block(99, (100,), ()),
                100: semantic_block(100, (2,), (98, 99)),
                2: semantic_block(2, (), (100,)),
                75: semantic_block(75, (), ()),
                180: semantic_block(180, (), ()),
                219: semantic_block(219, (), ()),
            },
            entry_serial=98,
            func_ea=0,
        )

        patch_plan = compile_patch_plan(
            [
                EdgeRedirectViaPredSplit(
                    src_block=100,
                    old_target=2,
                    new_target=180,
                    via_pred=98,
                    rule_priority=550,
                ),
                InsertBlock(
                    pred_serial=100,
                    succ_serial=75,
                    instructions=(InsnSnapshot(opcode=0x90, ea=0x1000, operands=()),),
                    old_target_serial=2,
                ),
            ],
            cfg,
        )

        projected = project_post_state(cfg, patch_plan)
        edge_split_serial = _projected_plan_serial(
            cfg,
            patch_plan,
            patch_plan.steps[0].block_id,
        )
        insert_serial = _projected_plan_serial(
            cfg,
            patch_plan,
            patch_plan.steps[1].block_id,
        )

        assert projected.blocks[98].succs == (54, edge_split_serial)
        assert projected.blocks[100].succs == (insert_serial,)
        assert projected.blocks[edge_split_serial].succs == (180,)
        assert projected.blocks[insert_serial].succs == (75,)
        assert (
            CfgContract().check_projection(
                project_patch_plan(cfg, patch_plan, snapshot_id=patch_plan.snapshot_id)
            )
            == []
        )

    def test_direct_terminal_lowering_and_private_suffix_can_share_return_family(self):
        def semantic_block(
            serial: int,
            succs: tuple[int, ...],
            preds: tuple[int, ...],
        ) -> BlockSnapshot:
            return BlockSnapshot(
                serial=serial,
                block_type=1 if succs else 0,
                succs=succs,
                preds=preds,
                flags=0,
                start_ea=0,
                insn_snapshots=(),
                kind=(BlockKind.ONE_WAY if len(succs) == 1 else BlockKind.ZERO_WAY),
                tail_kind=(InsnKind.GOTO if len(succs) == 1 else InsnKind.NOP),
            )

        cfg = FlowGraph(
            blocks={
                26: semantic_block(26, (27,), ()),
                27: semantic_block(27, (218,), (26,)),
                206: semantic_block(206, (207,), ()),
                207: semantic_block(207, (218,), (206,)),
                218: semantic_block(218, (219,), (27, 207)),
                219: semantic_block(219, (), (218,)),
            },
            entry_serial=26,
            func_ea=0,
        )

        patch_plan = compile_patch_plan(
            [
                ExitPathLoweringGroup(
                    shared_entry_serial=218,
                    return_block_serial=219,
                    suffix_serials=(218, 219),
                    sites=(
                        ExitPathLoweringSite(
                            anchor_serial=207,
                            kind=ExitPathLoweringKind.CLONE_MATERIALIZER,
                            materializer_serials=(27, 218),
                        ),
                    ),
                ),
                PrivateTerminalSuffixGroup(
                    anchors=(27,),
                    shared_entry_serial=218,
                    return_block_serial=219,
                    suffix_serials=(218, 219),
                ),
            ],
            cfg,
        )

        projected = project_post_state(cfg, patch_plan)
        dtl_step = patch_plan.steps[0]
        pts_step = patch_plan.steps[1]
        dtl_clones = tuple(
            _projected_plan_serial(cfg, patch_plan, ref)
            for anchor, refs in dtl_step.per_site_clone_block_ids
            if anchor == dtl_step.sites[0].anchor_serial
            for ref in refs
        )
        pts_clones = tuple(
            _projected_plan_serial(cfg, patch_plan, ref)
            for ref in pts_step.per_anchor_clone_block_ids[0]
        )

        assert projected.blocks[207].succs == (dtl_clones[0],)
        assert projected.blocks[dtl_clones[0]].succs == (dtl_clones[1],)
        assert projected.blocks[dtl_clones[1]].succs == ()
        assert projected.blocks[27].succs == (pts_clones[0],)
        assert (
            CfgContract().check_projection(
                project_patch_plan(cfg, patch_plan, snapshot_id=patch_plan.snapshot_id)
            )
            == []
        )

    def test_return_const_direct_terminal_lowering_rewrites_anchor_without_clone(self):
        def semantic_block(
            serial: int,
            succs: tuple[int, ...],
            preds: tuple[int, ...],
        ) -> BlockSnapshot:
            return BlockSnapshot(
                serial=serial,
                block_type=1 if succs else 0,
                succs=succs,
                preds=preds,
                flags=0,
                start_ea=0,
                insn_snapshots=(),
                kind=(BlockKind.ONE_WAY if len(succs) == 1 else BlockKind.ZERO_WAY),
                tail_kind=(InsnKind.GOTO if len(succs) == 1 else InsnKind.NOP),
            )

        cfg = FlowGraph(
            blocks={
                26: semantic_block(26, (27,), ()),
                27: semantic_block(27, (218,), (26,)),
                218: semantic_block(218, (219,), (27,)),
                219: semantic_block(219, (), (218,)),
            },
            entry_serial=26,
            func_ea=0,
        )

        patch_plan = compile_patch_plan(
            [
                ExitPathLoweringGroup(
                    shared_entry_serial=218,
                    return_block_serial=219,
                    suffix_serials=(218, 219),
                    sites=(
                        ExitPathLoweringSite(
                            anchor_serial=27,
                            kind=ExitPathLoweringKind.RETURN_CONST,
                            const_value=0x5644FD01B1049C4B,
                        ),
                    ),
                ),
            ],
            cfg,
        )

        projected = project_post_state(cfg, patch_plan)
        dtl_step = patch_plan.steps[0]

        assert (
            dict(dtl_step.per_site_clone_block_ids)[dtl_step.sites[0].anchor_serial]
            == ()
        )
        assert projected.blocks[27].succs == (219,)
        assert len(projected.blocks) == len(cfg.blocks)
        assert (
            CfgContract().check_projection(
                project_patch_plan(cfg, patch_plan, snapshot_id=patch_plan.snapshot_id)
            )
            == []
        )

    def test_patch_plan_insert_block_updates_sink_reasoning(self):
        cfg = FlowGraph(
            blocks={
                1: _block(1, (2,), ()),
                2: _block(2, (), (1,)),
            },
            entry_serial=1,
            func_ea=0,
        )

        patch_plan = compile_patch_plan(
            [
                InsertBlock(
                    pred_serial=1,
                    succ_serial=2,
                    instructions=(InsnSnapshot(opcode=0x90, ea=0x1000, operands=()),),
                )
            ],
            cfg,
        )

        sim = simulate_edits(
            cfg.as_adjacency_dict(), patch_plan_to_simulated_edits(patch_plan)
        )

        assert sim.adj[1] == [2]
        assert sim.adj[2] == [3]
        assert sim.adj[3] == []
        assert prove_terminal_sink(2, sim.adj, exits={3}, forbidden=set()).ok

    def test_patch_plan_insert_block_replaces_explicit_old_target(self):
        cfg = FlowGraph(
            blocks={
                1: _block(1, (2,), ()),
                2: _block(2, (), (1,)),
                4: _block(4, (), ()),
            },
            entry_serial=1,
            func_ea=0,
        )

        patch_plan = compile_patch_plan(
            [
                InsertBlock(
                    pred_serial=1,
                    succ_serial=4,
                    instructions=(InsnSnapshot(opcode=0x90, ea=0x1000, operands=()),),
                    old_target_serial=2,
                )
            ],
            cfg,
        )

        sim = simulate_edits(
            cfg.as_adjacency_dict(), patch_plan_to_simulated_edits(patch_plan)
        )

        assert sim.adj[1] == [4]
        assert sim.adj[2] == []
        assert sim.adj[4] == [5]
        assert sim.adj[5] == []

    def test_patch_plan_conditional_redirect_relocates_stop(self):
        cfg = FlowGraph(
            blocks={
                0: _block(0, (1,), ()),
                1: _block(1, (2, 5), (0,)),
                2: _block(2, (), (1,)),
                5: _block(5, (), (1,)),
            },
            entry_serial=0,
            func_ea=0,
        )

        patch_plan = compile_patch_plan(
            [
                CreateConditionalRedirect(
                    source_block=0,
                    ref_block=1,
                    conditional_target=5,
                    fallthrough_target=2,
                )
            ],
            cfg,
        )

        sim = simulate_edits(
            cfg.as_adjacency_dict(), patch_plan_to_simulated_edits(patch_plan)
        )

        assert sim.adj[0] == [5]
        assert sim.adj[5] == [6, 7]
        assert sim.adj[6] == [2]
        assert sim.adj[7] == []

    def test_remove_edge_is_simulated(self):
        sim = simulate_edits(
            {1: [2, 3], 2: [], 3: []},
            graph_modifications_to_simulated_edits(
                [RemoveEdge(from_serial=1, to_serial=3)]
            ),
        )

        assert sim.adj[1] == [2]


class TestProjectCumulativeState:
    """Tests for project_cumulative_state -- cumulative CFG projection."""

    def _make_cfg(self, adj: dict[int, list[int]], entry: int = 0) -> FlowGraph:
        """Build a FlowGraph from an adjacency dict."""
        blocks: dict[int, BlockSnapshot] = {}
        preds_map: dict[int, list[int]] = {s: [] for s in adj}
        for s, succs in adj.items():
            for succ in succs:
                if succ in preds_map:
                    preds_map[succ].append(s)
        for serial, succs in adj.items():
            blocks[serial] = BlockSnapshot(
                serial=serial,
                block_type=3 if len(succs) == 1 else (4 if len(succs) == 2 else 0),
                succs=tuple(succs),
                preds=tuple(preds_map.get(serial, ())),
                flags=0,
                start_ea=0,
                insn_snapshots=(),
                tail_opcode=2 if succs else 0,
            )
        return FlowGraph(blocks=blocks, entry_serial=entry, func_ea=0)

    def test_cumulative_is_same_as_project_post_state(self):
        """project_cumulative_state produces the same result as project_post_state
        when called with the same inputs."""
        cfg = self._make_cfg({0: [1], 1: [2], 2: []})
        modifications = [RedirectGoto(from_serial=0, old_target=1, new_target=2)]
        plan = compile_patch_plan(modifications, cfg)

        result_standard = project_post_state(cfg, plan)
        result_cumulative = project_cumulative_state(cfg, plan)

        assert (
            result_standard.as_adjacency_dict() == result_cumulative.as_adjacency_dict()
        )
        assert result_standard.entry_serial == result_cumulative.entry_serial

    def test_cumulative_chaining_two_plans(self):
        """Two sequential plans applied cumulatively produce correct topology."""
        cfg = self._make_cfg({0: [1], 1: [2], 2: [3], 3: []})

        plan1 = compile_patch_plan(
            [RedirectGoto(from_serial=0, old_target=1, new_target=2)],
            cfg,
        )
        cumulative1 = project_cumulative_state(cfg, plan1)

        adj1 = cumulative1.as_adjacency_dict()
        assert adj1[0] == [2]
        assert adj1[1] == [2]

        plan2 = compile_patch_plan(
            [RedirectGoto(from_serial=1, old_target=2, new_target=3)],
            cumulative1,
        )
        cumulative2 = project_cumulative_state(cumulative1, plan2)

        adj2 = cumulative2.as_adjacency_dict()
        assert adj2[0] == [2]
        assert adj2[1] == [3]
        assert adj2[2] == [3]

    def test_cumulative_preserves_metadata(self):
        """Cumulative projection preserves base CFG metadata."""
        cfg = self._make_cfg({0: [1], 1: []})
        cfg = FlowGraph(
            blocks=cfg.blocks,
            entry_serial=cfg.entry_serial,
            func_ea=cfg.func_ea,
            metadata={"custom_key": "value"},
        )
        plan = compile_patch_plan([], cfg)
        result = project_cumulative_state(cfg, plan)
        assert result.metadata.get("custom_key") == "value"
        assert result.metadata.get("projected_from_patch_plan") is True
def test_3b3_direct_and_helper_branch_projection_slots() -> None:
    from tests.unit.transforms.unflatten_authority.helpers import exact_fixture
    from d810.transforms.graph_modification import RedirectBranch
    cfg, *_ = exact_fixture()
    plan = compile_patch_plan([RedirectBranch(1, 2, 4)], cfg)
    projected = project_post_state(cfg, plan)
    assert cfg.blocks[1].succs == (3, 2)
    assert projected.blocks[1].succs == (3, 4)
    assert projected.blocks[1].tail is not None
    assert projected.blocks[1].tail.d is not None
    assert projected.blocks[1].tail.d.block_ref == 4
    source_tail = cfg.blocks[1].tail
    projected_tail = projected.blocks[1].tail
    assert source_tail is not None and projected_tail is not None
    # The branch feeder is source-bound except for its projected destination;
    # spell out every semantic slot so a stale transfer/predicate cannot hide
    # behind dataclass equality.
    assert projected_tail.kind is source_tail.kind is InsnKind.COND_JUMP
    assert projected_tail.ea == source_tail.ea
    assert projected_tail.opcode == source_tail.opcode
    assert projected_tail.raw_opcode == source_tail.raw_opcode
    assert projected_tail.operands == source_tail.operands
    assert projected_tail.control_transfer_kind == source_tail.control_transfer_kind
    assert projected_tail.call_kind == source_tail.call_kind
    assert projected_tail.is_call == source_tail.is_call
    assert projected_tail.branch_predicate == source_tail.branch_predicate
    assert projected_tail.predicate_kind == source_tail.predicate_kind
    assert projected_tail.compare_width == source_tail.compare_width
    assert projected_tail.is_conditional_jump is source_tail.is_conditional_jump is True
    assert projected_tail.is_unconditional_jump is source_tail.is_unconditional_jump is False
    for field in dataclass_fields(InsnSnapshot):
        if field.name != "d":
            assert getattr(projected_tail, field.name) == getattr(source_tail, field.name)
    assert projected.blocks[2].preds == ()
    assert projected.blocks[4].preds == (1,)
    _assert_reciprocal_topology(projected)

    # Reversing the SOURCE arm order makes the same real compiler emit the
    # helper-bearing branch family.
    feeder = cfg.blocks[1]
    tail = feeder.insn_snapshots[-1]
    helper_cfg = FlowGraph(
        {
            **cfg.blocks,
            1: replace(
                feeder, succs=(2, 3),
                insn_snapshots=(
                    *feeder.insn_snapshots[:-1],
                    replace(tail, d=replace(tail.d, block_ref=3)),
                ),
            ),
        }, cfg.entry_serial, cfg.func_ea,
    )
    helper_plan = compile_patch_plan([RedirectBranch(1, 2, 4)], helper_cfg)
    helper_projected = project_post_state(helper_cfg, helper_plan)
    helper_ref = helper_plan.steps[0].fallthrough_helper_block_id
    assert helper_ref is not None
    helper_serial = _projected_plan_serial(helper_cfg, helper_plan, helper_ref)
    assert helper_projected.blocks[1].succs == (helper_serial, 3)
    helper_block = helper_projected.blocks[helper_serial]
    semantic_target = max(helper_projected.blocks)
    assert helper_block.succs == (semantic_target,)
    assert len(helper_block.insn_snapshots) == 1
    helper_tail = helper_block.insn_snapshots[0]
    assert helper_tail.kind is InsnKind.GOTO
    assert helper_tail.opcode == -1
    assert helper_tail.raw_opcode is None
    assert helper_tail.operands == ()
    assert helper_tail.display_text == ""
    assert helper_tail.control_transfer_kind is ControlTransferKind.GOTO
    assert helper_tail.call_kind is None
    assert helper_tail.is_call is False
    assert helper_tail.branch_predicate is None
    assert helper_tail.predicate_kind is None
    assert helper_tail.is_conditional_jump is False
    assert helper_tail.is_unconditional_jump is True
    assert helper_tail.d is not None and helper_tail.d.block_ref == semantic_target
    helper_source_tail = helper_cfg.blocks[1].tail
    projected_feeder_tail = helper_projected.blocks[1].tail
    assert helper_source_tail is not None and projected_feeder_tail is not None
    assert helper_tail == _expected_synthetic_goto(
        ea=helper_cfg.blocks[1].start_ea, target=semantic_target,
    )
    for field in dataclass_fields(InsnSnapshot):
        if field.name != "d":
            assert getattr(projected_feeder_tail, field.name) == getattr(helper_source_tail, field.name)
    assert projected_feeder_tail.d is not None
    assert projected_feeder_tail.d.block_ref == helper_projected.blocks[1].succs[1]
    _assert_reciprocal_topology(helper_projected)


def test_3b3_trampoline_projection_normalizes_empty_body() -> None:
    from tests.unit.transforms.unflatten_authority.helpers import exact_fixture
    cfg, *_ = exact_fixture()
    plan = compile_patch_plan([EdgeRedirectViaPredSplit(1, 2, 4, 0)], cfg)
    projected = project_post_state(cfg, plan)
    trampoline = _projected_plan_serial(cfg, plan, plan.steps[0].block_id)
    assert projected.blocks[0].succs == (4,)
    assert projected.blocks[1].succs == (3, 2)
    assert projected.blocks[trampoline].succs == (max(cfg.blocks) + 1,)
    assert projected.blocks[trampoline].tail_kind is InsnKind.GOTO
    assert len(projected.blocks[trampoline].insn_snapshots) == 1
    assert projected.blocks[trampoline].tail is not None
    assert projected.blocks[trampoline].tail.d is not None
    trampoline_tail = projected.blocks[trampoline].tail
    assert trampoline_tail.kind is InsnKind.GOTO
    assert trampoline_tail.opcode == -1
    assert trampoline_tail.raw_opcode is None
    assert trampoline_tail.control_transfer_kind is ControlTransferKind.GOTO
    assert trampoline_tail.call_kind is None
    assert trampoline_tail.is_call is False
    assert trampoline_tail.branch_predicate is None
    assert trampoline_tail.predicate_kind is None
    assert trampoline_tail.is_conditional_jump is False
    assert trampoline_tail.is_unconditional_jump is True
    # The semantic target is relocated after insertion; the projected GOTO
    # must name that relocated target rather than the source serial.
    assert projected.blocks[trampoline].tail.d.block_ref == max(cfg.blocks) + 1
    assert trampoline_tail == _expected_synthetic_goto(
        ea=cfg.blocks[1].start_ea, target=max(cfg.blocks) + 1,
    )
    _assert_reciprocal_topology(projected)


def test_3b3_corridor_projection_clones_exact_prefixes() -> None:
    from tests.unit.transforms.unflatten_authority.helpers import exact_fixture
    cfg, *_ = exact_fixture()
    blocks = dict(cfg.blocks)
    def body(serial: int, target: int) -> tuple[InsnSnapshot, ...]:
        return (
            InsnSnapshot(
                0, serial * 0x1000, (), kind=InsnKind.MOV,
                l=MopSnapshot(kind=OperandKind.NUMBER, size=4, value=serial),
                d=MopSnapshot(kind=OperandKind.STACK, size=4, stkoff=4),
            ),
            InsnSnapshot(
                1, serial * 0x1000 + 1, (), kind=InsnKind.GOTO,
                d=MopSnapshot(kind=OperandKind.BLOCK, block_ref=target),
                control_transfer_kind=None, is_unconditional_jump=True,
            ),
        )
    blocks[1] = replace(
        blocks[1], succs=(2,), preds=(0,), kind=BlockKind.ONE_WAY,
        tail_kind=InsnKind.GOTO, insn_snapshots=body(2, 2),
    )
    blocks[2] = replace(
        blocks[2], succs=(3,), preds=(1,), kind=BlockKind.ONE_WAY,
        tail_kind=InsnKind.GOTO, insn_snapshots=body(3, 3),
    )
    blocks[3] = replace(
        blocks[3], succs=(4,), preds=(2,), kind=BlockKind.ONE_WAY,
        tail_kind=InsnKind.GOTO,
        insn_snapshots=(InsnSnapshot(0, 0x4000, (), kind=InsnKind.GOTO,
            d=MopSnapshot(kind=OperandKind.BLOCK, block_ref=4),
            control_transfer_kind=None, is_unconditional_jump=True),),
    )
    blocks[4] = replace(blocks[4], preds=(3,))
    cfg = FlowGraph(blocks, cfg.entry_serial, cfg.func_ea)
    for clone_until in (2, 3):
        plan = compile_patch_plan([EdgeRedirectViaPredSplit(
            2, 3, 4, 1, clone_until=clone_until,
        )], cfg)
        projected = project_post_state(cfg, plan)
        repeated = project_post_state(cfg, plan)
        assert projected == repeated
        clones = tuple(_projected_plan_serial(cfg, plan, spec.block_id) for spec in plan.new_blocks)
        assert len(clones) == clone_until - 1
        assert projected.blocks[1].succs == (clones[0],)
        for index, clone in enumerate(clones):
            source_serial = index + 2
            source_body = cfg.blocks[source_serial].insn_snapshots
            clone_body = projected.blocks[clone].insn_snapshots
            assert clone_body[:-1] == source_body[:-1]
            assert clone_body[-1].kind is InsnKind.GOTO
            assert clone_body[-1].d is not None
            assert clone_body[-1].d.kind is OperandKind.BLOCK
            assert clone_body[-1].d.block_ref == (
                clones[index + 1] if index + 1 < len(clones) else max(cfg.blocks) + len(clones)
            )
            assert clone_body[-1] == _expected_synthetic_goto(
                ea=source_body[-1].ea,
                target=clone_body[-1].d.block_ref,
            )
            assert clone_body[-1].d.block_ref != source_body[-1].d.block_ref
            assert projected.blocks[clone].tail_opcode == -1
            assert projected.blocks[clone].raw_tail_opcode is None
            assert projected.blocks[clone].tail_kind is InsnKind.GOTO
            assert projected.blocks[clone].succs == (clone_body[-1].d.block_ref,)
            assert projected.blocks[clone].preds == (
                (1,) if index == 0 else (clones[index - 1],)
            )
        _assert_reciprocal_topology(projected)
