"""Regression coverage for post-plan dispatcher corridor diagnostics."""

from __future__ import annotations

from dataclasses import replace
from types import SimpleNamespace

import pytest

from d810.analyses.control_flow.interval_map import IntervalDispatcher, IntervalRow
from d810.analyses.control_flow.minimal_state_recovery import (
    StateWriteTransition,
    TransitionProof,
)
from d810.analyses.control_flow.route_predicate import DecisionDag, RouteComparison
from d810.ir.expressions import ValueOpKind
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
from d810.transforms import dispatcher_corridor_coverage as corridor_module
from d810.transforms import minimal_unflatten_emit as emit_module
from d810.transforms.dispatcher_corridor_coverage import (
    DispatcherCorridorCoverage,
    analyze_dispatcher_corridor_coverage,
    build_detached_dead_handler_component_analysis,
    build_dispatcher_removal_forecast,
)
from d810.transforms.unflatten_authority.legacy_keys import LEGACY_UNFLATTEN_KEYS
from d810.transforms.graph_modification import (
    ConvertToGoto,
    EdgeRedirectViaPredSplit,
    LowerConditionalStateTransition,
    NopInstructions,
    PreserveLivePredicateCondition,
    RedirectGoto,
    RedirectBranch,
    SyntheticRegisterNonzeroCondition,
    ZeroStateWrite,
)
from d810.ir.storage_identity import StorageIdentity, StorageIdentityKind
from d810.transforms.use_def_redirect_filter import (
    UseDefSeveranceAudit,
    audit_use_def_severances,
)
from tests.typed_patch_authority import (
    compile_patch_plan,
    emit_minimal_unflatten,
    graph_modifications,
)


def _block(
    serial: int,
    succs: tuple[int, ...],
    preds: tuple[int, ...],
    ea: int,
    *,
    kind: BlockKind = BlockKind.UNKNOWN,
    insns: tuple[InsnSnapshot, ...] = (),
    tail_kind: InsnKind | None = None,
) -> BlockSnapshot:
    return BlockSnapshot(
        serial=serial,
        block_type=1,
        succs=succs,
        preds=preds,
        flags=0,
        start_ea=ea,
        insn_snapshots=insns,
        kind=kind,
        tail_kind=tail_kind,
    )


def test_transaction_replay_validator_seams_are_not_exported() -> None:
    """The corridor module exposes producer proofs, not a second authority."""

    removed = (
        "validate_dispatcher_corridor_coverage_metadata",
        "validate_dispatcher_removal_preflight_proof",
        "validated_exact_effect_exclusion_serials",
        "has_unreachable_cyclic_switch_dispatcher_residue",
    )
    assert all(name not in vars(corridor_module) for name in removed)


def test_pure_subexpression_stack_refs_keep_their_exact_width() -> None:
    stack = MopSnapshot(kind=OperandKind.STACK, size=4, stkoff=4, stack_refs=(4,))
    pure_xor = MopSnapshot(
        kind=OperandKind.SUBINSN,
        size=4,
        stack_refs=(4,),
        sub_kind=InsnKind.VALUE,
        sub_value_op_kind=ValueOpKind.XOR,
        sub_l=stack,
        sub_r=MopSnapshot(kind=OperandKind.NUMBER, size=4, value=0x42),
    )
    assert emit_module._storage_bytes(pure_xor, include_stack_refs=True) == {
        ("stk", 4), ("stk", 5), ("stk", 6), ("stk", 7),
    }

    hidden_load = replace(pure_xor, sub_value_op_kind=ValueOpKind.LOAD)
    assert ("stk", emit_module._STORAGE_UNKNOWN_BYTE) in emit_module._storage_bytes(
        hidden_load, include_stack_refs=True,
    )
    hidden_ref = replace(pure_xor, stack_refs=(4, 100))
    assert ("stk", emit_module._STORAGE_UNKNOWN_BYTE) in emit_module._storage_bytes(
        hidden_ref, include_stack_refs=True,
    )


def test_unknown_downstream_stack_read_does_not_revive_overwritten_state() -> None:
    """A definite handler write kills its prior value, even before a call."""
    state_write = InsnSnapshot(
        4, 0x1200, (), kind=InsnKind.MOV,
        l=MopSnapshot(kind=OperandKind.NUMBER, size=4, value=7),
        d=MopSnapshot(kind=OperandKind.STACK, size=4, stkoff=100),
    )
    other_write = replace(
        state_write,
        ea=0x1100,
        d=MopSnapshot(kind=OperandKind.STACK, size=4, stkoff=200),
    )
    call = InsnSnapshot(0x28, 0x1300, (), kind=InsnKind.CALL)
    graph = FlowGraph({
        1: _block(1, (2,), (), 0x1100, insns=(other_write,)),
        2: _block(2, (3,), (1,), 0x1200, insns=(state_write,)),
        3: _block(3, (), (2,), 0x1300, insns=(call,)),
    }, entry_serial=1, func_ea=0x1000)

    live = emit_module._storage_live_in_bytes(graph)
    state_bytes = {("stk", offset) for offset in range(100, 104)}
    assert emit_module._storage_bytes_overlap(state_bytes, live[3])
    assert not emit_module._storage_bytes_overlap(state_bytes, live[2])
    assert {("stk", offset) for offset in range(200, 204)} <= live[2]
    before_write = FlowGraph({
        **graph.blocks,
        2: _block(2, (3,), (1,), 0x1200, insns=(replace(call, ea=0x1200), state_write)),
    }, entry_serial=1, func_ea=0x1000)
    assert emit_module._storage_bytes_overlap(
        state_bytes, emit_module._storage_live_in_bytes(before_write)[2]
    )


def test_assertion_does_not_kill_state_live_before_a_real_read() -> None:
    state = MopSnapshot(kind=OperandKind.STACK, size=4, stkoff=100)
    asserted = InsnSnapshot(
        4, 0x1200, (), kind=InsnKind.MOV, is_assert=True,
        l=MopSnapshot(kind=OperandKind.NUMBER, size=4, value=7), d=state,
    )
    read = InsnSnapshot(
        4, 0x1204, (), kind=InsnKind.MOV, l=state,
        d=MopSnapshot(kind=OperandKind.REGISTER, size=4, reg=20),
    )
    graph = FlowGraph({
        1: _block(1, (2,), (), 0x1100),
        2: _block(2, (), (1,), 0x1200, insns=(asserted, read)),
    }, entry_serial=1, func_ea=0x1000)
    assert {("stk", byte) for byte in range(100, 104)} <= (
        emit_module._storage_live_in_bytes(graph)[2]
    )


def test_conditional_constant_stack_carrier_can_skip_dead_feeder_copy() -> None:
    """Only the proven branch arm bypasses the shared pure state feeder."""
    carrier = MopSnapshot(kind=OperandKind.STACK, size=4, stkoff=200)
    state = MopSnapshot(kind=OperandKind.STACK, size=4, stkoff=100)
    source_write = InsnSnapshot(
        4, 0x1100, (), kind=InsnKind.MOV,
        l=MopSnapshot(kind=OperandKind.NUMBER, size=4, value=7), d=carrier,
    )
    feeder_copy = InsnSnapshot(
        4, 0x1300, (), kind=InsnKind.MOV, l=carrier, d=state,
    )
    leaf_overwrite = replace(
        source_write, ea=0x1500,
        l=MopSnapshot(kind=OperandKind.NUMBER, size=4, value=8), d=state,
    )
    graph = FlowGraph({
        1: _block(1, (2, 3), (), 0x1100, kind=BlockKind.TWO_WAY,
                  insns=(source_write,)),
        2: _block(2, (3,), (1,), 0x1200),
        3: _block(3, (4,), (1, 2), 0x1300, kind=BlockKind.ONE_WAY,
                  insns=(feeder_copy,)),
        4: _block(4, (5, 6), (3,), 0x1400, kind=BlockKind.TWO_WAY),
        5: _block(5, (8,), (4,), 0x1500, insns=(leaf_overwrite,)),
        6: _block(6, (), (4,), 0x1600),
        8: _block(8, (), (5,), 0x1800,
                  insns=(InsnSnapshot(0x28, 0x1800, (), kind=InsnKind.CALL),)),
    }, entry_serial=1, func_ea=0x1000)
    dag = DecisionDag(32, {4: RouteComparison(4, "jz", 7, 5, 6)}, root=4)
    dispatcher = IntervalDispatcher([
        IntervalRow(7, 8, 5), IntervalRow(8, 9, 6),
    ], compute_default=False)
    transition = StateWriteTransition(
        1, 7, 5, False, None, via_block=3,
        proof=TransitionProof("test", "partitioned_literal", True),
    )
    redirect = RedirectBranch(1, 3, 5)
    assert emit_module._source_bound_dead_state_write_leaf_delivery(
        graph, dispatcher, dag, redirect, (transition,),
        state_identity=StorageIdentity(StorageIdentityKind.STACK, 100),
        state_var_stkoff=100, state_var_reg=None,
        live_in_by_serial=None, storage_live_in_by_serial=None,
    )
    changed_source = FlowGraph({
        **graph.blocks,
        1: _block(1, (2, 3), (), 0x1100, kind=BlockKind.TWO_WAY,
                  insns=(replace(source_write, l=MopSnapshot(
                      kind=OperandKind.NUMBER, size=4, value=9,
                  )),)),
    }, entry_serial=1, func_ea=0x1000)
    assert not emit_module._source_bound_dead_state_write_leaf_delivery(
        changed_source, dispatcher, dag, redirect, (transition,),
        state_identity=StorageIdentity(StorageIdentityKind.STACK, 100),
        state_var_stkoff=100, state_var_reg=None,
        live_in_by_serial=None, storage_live_in_by_serial=None,
    )


def test_exact_literal_xor_can_skip_only_a_dead_state_feeder() -> None:
    """A proven XOR is dead only when the routed leaf overwrites state first."""

    left = MopSnapshot(kind=OperandKind.REGISTER, size=4, reg=8)
    right = MopSnapshot(kind=OperandKind.REGISTER, size=4, reg=12)
    state = MopSnapshot(kind=OperandKind.STACK, size=4, stkoff=100)
    left_value = 0x61EAE7DF
    right_value = 0x30601CAA
    routed_state = left_value ^ right_value
    left_move = InsnSnapshot(
        4, 0x1100, (), kind=InsnKind.MOV,
        l=MopSnapshot(kind=OperandKind.NUMBER, size=4, value=left_value), d=left,
    )
    right_move = InsnSnapshot(
        4, 0x1104, (), kind=InsnKind.MOV,
        l=MopSnapshot(kind=OperandKind.NUMBER, size=4, value=right_value), d=right,
    )
    xor_write = InsnSnapshot(
        4, 0x1200, (), kind=InsnKind.VALUE, value_op_kind=ValueOpKind.XOR,
        l=left, r=right, d=state,
    )
    leaf_overwrite = InsnSnapshot(
        4, 0x1400, (), kind=InsnKind.MOV,
        l=MopSnapshot(kind=OperandKind.NUMBER, size=4, value=9), d=state,
    )
    blocks = {
        1: _block(1, (2,), (), 0x1100, insns=(left_move, right_move)),
        2: _block(2, (3,), (1,), 0x1200, insns=(xor_write,)),
        3: _block(3, (4, 5), (2,), 0x1300, kind=BlockKind.TWO_WAY),
        4: _block(4, (), (3,), 0x1400, insns=(leaf_overwrite,)),
        5: _block(5, (), (3,), 0x1500),
    }
    dag = DecisionDag(
        32, {3: RouteComparison(3, "jz", routed_state, 4, 5)}, root=3,
    )
    dispatcher = IntervalDispatcher([
        IntervalRow(routed_state, routed_state + 1, 4),
    ], compute_default=False)
    transition = StateWriteTransition(
        1, routed_state, 4, False, None, via_block=2,
        proof=TransitionProof("test", "exact_literal_xor", True),
    )

    def accepted(candidate_blocks: dict[int, BlockSnapshot]) -> bool:
        return emit_module._source_bound_dead_state_write_leaf_delivery(
            FlowGraph(candidate_blocks, entry_serial=1, func_ea=0x1000),
            dispatcher, dag, RedirectGoto(1, 2, 4), (transition,),
            state_identity=StorageIdentity(StorageIdentityKind.STACK, 100),
            state_var_stkoff=100, state_var_reg=None,
            live_in_by_serial=None, storage_live_in_by_serial=None,
        )

    assert accepted(blocks)
    assert not accepted({
        **blocks,
        1: replace(blocks[1], insn_snapshots=(
            left_move,
            replace(right_move, l=MopSnapshot(
                kind=OperandKind.NUMBER, size=4, value=right_value ^ 1,
            )),
        )),
    })
    assert not accepted({
        **blocks,
        2: replace(blocks[2], insn_snapshots=(
            replace(xor_write, value_op_kind=ValueOpKind.ADD),
        )),
    })
    assert not accepted({
        **blocks,
        2: replace(blocks[2], insn_snapshots=(
            xor_write, InsnSnapshot(0x28, 0x1204, (), kind=InsnKind.CALL),
        )),
    })
    assert not accepted({
        **blocks,
        4: replace(blocks[4], insn_snapshots=(
            InsnSnapshot(4, 0x13FF, (), kind=InsnKind.MOV, l=state, d=left),
            leaf_overwrite,
        )),
    })


def test_live_xor_feeder_clones_across_exact_selected_prefix() -> None:
    """Preserve the state write when a pure prefix precedes the selected DAG."""

    state_value = 0x309054FA
    left_value = 0x4530861A
    right_value = 0x75A0D2E0
    assert left_value ^ right_value == state_value
    left = MopSnapshot(kind=OperandKind.REGISTER, size=4, reg=72)
    right = MopSnapshot(kind=OperandKind.REGISTER, size=4, reg=24)
    state = MopSnapshot(kind=OperandKind.STACK, size=4, stkoff=4)
    source = (
        InsnSnapshot(4, 0x1100, (), kind=InsnKind.MOV,
                     l=MopSnapshot(kind=OperandKind.NUMBER, size=4, value=left_value),
                     d=left),
        InsnSnapshot(4, 0x1104, (), kind=InsnKind.MOV,
                     l=MopSnapshot(kind=OperandKind.NUMBER, size=4, value=right_value),
                     d=right),
    )
    feeder_write = InsnSnapshot(
        21, 0x1200, (), kind=InsnKind.VALUE, value_op_kind=ValueOpKind.XOR,
        l=left, r=right, d=state,
    )
    prefix_branch = InsnSnapshot(
        49, 0x1300, (), kind=InsnKind.COND_JUMP,
        l=state,
        r=MopSnapshot(kind=OperandKind.NUMBER, size=4, value=0x40D9BA32),
        d=MopSnapshot(kind=OperandKind.BLOCK, size=0, block_ref=8),
        branch_predicate=PredicateKind.SGT, is_conditional_jump=True,
    )
    root_branch = InsnSnapshot(
        47, 0x1400, (), kind=InsnKind.EQUALITY_JUMP,
        l=state,
        r=MopSnapshot(kind=OperandKind.NUMBER, size=4, value=state_value),
        d=MopSnapshot(kind=OperandKind.BLOCK, size=0, block_ref=6),
        branch_predicate=PredicateKind.EQ, is_conditional_jump=True,
    )
    blocks = {
        1: _block(1, (2,), (), 0x1100, insns=source),
        2: _block(2, (3,), (1,), 0x1200, insns=(feeder_write,)),
        3: _block(3, (4, 8), (2,), 0x1300,
                  kind=BlockKind.TWO_WAY, insns=(prefix_branch,)),
        4: _block(4, (6, 7), (3,), 0x1400,
                  kind=BlockKind.TWO_WAY, insns=(root_branch,)),
        6: _block(6, (), (4,), 0x1600,
                  insns=(InsnSnapshot(0x28, 0x1600, (), kind=InsnKind.CALL),)),
        7: _block(7, (), (4,), 0x1700),
        8: _block(8, (), (3,), 0x1800),
    }
    dag = DecisionDag(
        32, {4: RouteComparison(4, "jz", state_value, 6, 7)}, root=4,
    )
    transition = StateWriteTransition(
        1, state_value, 6, False, None, via_block=2,
        proof=TransitionProof("test", "source_exact_xor", True),
    )

    def accepted(candidate_blocks: dict[int, BlockSnapshot]) -> bool:
        graph = FlowGraph(candidate_blocks, entry_serial=1, func_ea=0x1000)
        (promoted,) = emit_module._preserve_live_state_carrier_feeders(
            graph, dag, (transition,), state_var_stkoff=4, state_var_reg=None,
        )
        split = EdgeRedirectViaPredSplit(2, 3, 6, 1, clone_until=2)
        return bool(
            promoted.preserve_via_block
            and emit_module._corridor_pred_split_preserves_handler_inputs(
                graph, dag, split, (split,), (promoted,),
                state_identity=StorageIdentity(StorageIdentityKind.STACK, 4),
                state_var_stkoff=4, state_var_reg=None,
                live_in_by_serial=None,
                storage_live_in_by_serial=emit_module._storage_live_in_bytes(graph),
            )
        )

    assert accepted(blocks)
    assert not accepted({
        **blocks,
        1: replace(blocks[1], insn_snapshots=(
            source[0],
            replace(source[1], l=MopSnapshot(
                kind=OperandKind.NUMBER, size=4, value=right_value ^ 1,
            )),
        )),
    })
    assert not accepted({
        **blocks,
        3: replace(blocks[3], insn_snapshots=(
            replace(prefix_branch, r=MopSnapshot(
                kind=OperandKind.NUMBER, size=4, value=0x20000000,
            )),
        )),
    })
    assert not accepted({
        **blocks,
        3: replace(blocks[3], insn_snapshots=(
            InsnSnapshot(0x28, 0x12FF, (), kind=InsnKind.CALL), prefix_branch,
        )),
    })


def test_trusted_source_route_can_skip_only_a_dead_state_cell_move() -> None:
    source = InsnSnapshot(
        opcode=4, ea=0x1100, operands=(), kind=InsnKind.MOV,
        l=MopSnapshot(kind=OperandKind.NUMBER, size=4, value=7),
        d=MopSnapshot(kind=OperandKind.REGISTER, size=4, reg=8),
    )
    state_move = InsnSnapshot(
        opcode=4, ea=0x1700, operands=(), kind=InsnKind.MOV,
        l=MopSnapshot(kind=OperandKind.REGISTER, size=4, reg=8),
        d=MopSnapshot(kind=OperandKind.STACK, size=4, stkoff=100),
    )
    blocks = {
        1: _block(1, (7,), (), 0x1100, insns=(source,)),
        7: _block(7, (2,), (1,), 0x1700, insns=(state_move,)),
        2: _block(2, (3, 4), (7,), 0x1200),
        3: _block(3, (), (2,), 0x1300),
        4: _block(4, (), (2,), 0x1400),
    }
    graph = FlowGraph(blocks, entry_serial=1, func_ea=0x1000)
    dag = DecisionDag(32, {2: RouteComparison(2, "jz", 7, 3, 4)}, root=2)
    dispatcher = IntervalDispatcher([IntervalRow(7, 8, 3)], compute_default=False)
    transition = StateWriteTransition(
        write_block=1, next_state=7, target_handler=3, is_return=False,
        branch_arm=None, via_block=7,
        proof=TransitionProof("source-bound", "predecessor_partitioned", True),
    )

    def accepted(
        candidate_graph: FlowGraph,
        candidate: StateWriteTransition,
        modification: RedirectGoto | RedirectBranch = RedirectGoto(1, 7, 3),
    ) -> bool:
        return emit_module._source_bound_dead_state_write_leaf_delivery(
            candidate_graph, dispatcher, dag, modification,
            (candidate,), state_identity=StorageIdentity(StorageIdentityKind.STACK, 100),
            state_var_stkoff=100, state_var_reg=None,
            live_in_by_serial=None, storage_live_in_by_serial=None,
        )

    assert accepted(graph, transition)
    asserted_source = FlowGraph(
        {**blocks, 1: _block(
            1, (7,), (), 0x1100, insns=(replace(source, is_assert=True),),
        )},
        entry_serial=1, func_ea=0x1000,
    )
    assert not accepted(asserted_source, transition)
    asserted_feeder = FlowGraph(
        {**blocks, 7: _block(
            7, (2,), (1,), 0x1700, insns=(replace(state_move, is_assert=True),),
        )},
        entry_serial=1, func_ea=0x1000,
    )
    assert not accepted(asserted_feeder, transition)
    wrong_carrier = FlowGraph(
        {
            **blocks,
            1: _block(
                1, (7,), (), 0x1100,
                insns=(replace(source, l=MopSnapshot(
                    kind=OperandKind.NUMBER, size=4, value=9,
                )),),
            ),
        },
        entry_serial=1, func_ea=0x1000,
    )
    assert not accepted(wrong_carrier, transition)
    wide_source = replace(
        source,
        l=MopSnapshot(kind=OperandKind.NUMBER, size=8, value=0x100000007),
        d=MopSnapshot(kind=OperandKind.REGISTER, size=8, reg=8),
    )
    wide_carrier = FlowGraph(
        {
            **blocks,
            1: _block(1, (7,), (), 0x1100, insns=(wide_source,)),
        },
        entry_serial=1, func_ea=0x1000,
    )
    assert accepted(wide_carrier, transition)
    wrong_wide_carrier = FlowGraph(
        {
            **blocks,
            1: _block(1, (7,), (), 0x1100, insns=(replace(
                wide_source,
                l=MopSnapshot(kind=OperandKind.NUMBER, size=8, value=0x100000009),
            ),)),
        },
        entry_serial=1, func_ea=0x1000,
    )
    assert not accepted(wrong_wide_carrier, transition)
    clobbered_carrier = FlowGraph(
        {
            **blocks,
            1: _block(
                1, (7,), (), 0x1100,
                insns=(source, replace(source, ea=0x1101, l=MopSnapshot(
                    kind=OperandKind.NUMBER, size=4, value=9,
                ))),
            ),
        },
        entry_serial=1, func_ea=0x1000,
    )
    assert not accepted(clobbered_carrier, transition)
    nested_call = InsnSnapshot(
        4, 0x1104, (), kind=InsnKind.MOV,
        l=MopSnapshot(kind=OperandKind.SUBINSN, size=4, sub_kind=InsnKind.CALL),
        d=MopSnapshot(kind=OperandKind.REGISTER, size=4, reg=20),
    )
    nested_call_graph = FlowGraph({
        **blocks,
        1: _block(1, (7,), (), 0x1100, insns=(source, nested_call)),
    }, entry_serial=1, func_ea=0x1000)
    assert not accepted(nested_call_graph, transition)
    assert not accepted(graph, replace(transition, proof=None))
    branch_graph = FlowGraph(
        {
            **blocks,
            1: _block(1, (4, 7), (), 0x1100, kind=BlockKind.TWO_WAY, insns=(source,)),
            4: _block(4, (), (1, 2), 0x1400),
        },
        entry_serial=1, func_ea=0x1000,
    )
    assert accepted(branch_graph, transition, RedirectBranch(1, 7, 3))
    leaf_read = InsnSnapshot(
        opcode=4, ea=0x1300, operands=(), kind=InsnKind.MOV,
        l=MopSnapshot(kind=OperandKind.STACK, size=4, stkoff=100),
        d=MopSnapshot(kind=OperandKind.REGISTER, size=4, reg=20),
    )
    reading_graph = FlowGraph(
        {**blocks, 3: _block(3, (), (2,), 0x1300, insns=(leaf_read,))},
        entry_serial=1, func_ea=0x1000,
    )
    assert not accepted(reading_graph, transition)
    pointer_read = InsnSnapshot(
        opcode=0x28, ea=0x1300, operands=(), kind=InsnKind.CALL,
    )
    calling_graph = FlowGraph(
        {**blocks, 3: _block(3, (), (2,), 0x1300, insns=(pointer_read,))},
        entry_serial=1, func_ea=0x1000,
    )
    assert not accepted(calling_graph, transition)


def test_fresh_load_leaf_accepts_one_converged_literal_before_goto_source() -> None:
    """A no-op source can inherit an unconditional exact write at its sole pred."""

    state = MopSnapshot(kind=OperandKind.STACK, size=4, stkoff=100)
    write = InsnSnapshot(
        4, 0x1000, (), kind=InsnKind.MOV,
        l=MopSnapshot(kind=OperandKind.NUMBER, size=4, value=7), d=state,
    )
    goto = InsnSnapshot(
        2, 0x1100, (), kind=InsnKind.GOTO,
        l=MopSnapshot(kind=OperandKind.BLOCK, block_ref=2),
    )
    blocks = {
        0: _block(0, (1,), (), 0x1000, insns=(write,)),
        1: _block(1, (2,), (0,), 0x1100, insns=(goto,)),
        2: _block(2, (3, 4), (1,), 0x1200, kind=BlockKind.TWO_WAY),
        3: _block(3, (), (2,), 0x1300),
        4: _block(4, (), (2,), 0x1400),
    }
    dag = DecisionDag(32, {2: RouteComparison(2, "jz", 7, 3, 4)}, root=2)
    dispatcher = IntervalDispatcher([IntervalRow(7, 8, 3)], compute_default=False)
    transition = StateWriteTransition(
        1, 7, 3, False, None,
        proof=TransitionProof("source-bound", "exact_predecessor_literal", True),
    )

    def accepted(graph: FlowGraph) -> bool:
        return emit_module._fresh_load_leaf_modifications_have_direct_delivery(
            graph, (RedirectGoto(1, 2, 3),), (transition,),
            dispatcher=dispatcher, leaf_serials=frozenset({3}), root_serial=2,
            state_identity=StorageIdentity(StorageIdentityKind.STACK, 100),
            reference_dag=dag, state_var_stkoff=100,
        )

    assert accepted(FlowGraph(blocks, entry_serial=0, func_ea=0x1000))
    asserted_write = FlowGraph({
        **blocks,
        0: _block(0, (1,), (), 0x1000, insns=(replace(write, is_assert=True),)),
    }, entry_serial=0, func_ea=0x1000)
    assert not accepted(asserted_write)
    bad_write = FlowGraph({
        **blocks,
        0: _block(0, (1,), (), 0x1000, insns=(replace(
            write, l=MopSnapshot(kind=OperandKind.NUMBER, size=4, value=9),
        ),)),
    }, entry_serial=0, func_ea=0x1000)
    assert not accepted(bad_write)
    effectful_source = FlowGraph({
        **blocks,
        1: _block(1, (2,), (0,), 0x1100, insns=(
            InsnSnapshot(0x28, 0x1100, (), kind=InsnKind.CALL), goto,
        )),
    }, entry_serial=0, func_ea=0x1000)
    assert not accepted(effectful_source)


def test_coverage_projects_predecessor_scoped_feeder_clone() -> None:
    """A pred-split clone cuts only its exact original dispatcher corridor."""

    graph = FlowGraph(
        blocks={
            1: _block(1, (10,), (), 0x1000, kind=BlockKind.ONE_WAY),
            10: _block(10, (20,), (1,), 0x1010, kind=BlockKind.ONE_WAY),
            20: _block(20, (30,), (10,), 0x1020, kind=BlockKind.ONE_WAY),
            30: _block(30, (40,), (20,), 0x1030, kind=BlockKind.ONE_WAY),
            40: _block(40, (), (30,), 0x1040, kind=BlockKind.ZERO_WAY),
        },
        entry_serial=1,
        func_ea=0x1000,
    )

    coverage = analyze_dispatcher_corridor_coverage(
        graph,
        modifications=(
            EdgeRedirectViaPredSplit(
                src_block=20,
                old_target=30,
                new_target=40,
                via_pred=10,
                clone_until=20,
            ),
        ),
        dispatcher_entry_serial=30,
    )

    assert tuple(corridor.label for corridor in coverage.covered_corridors) == (
        "blk1@0x1000 -> blk10@0x1010 -> blk20@0x1020 -> blk30@0x1030",
    )
    assert coverage.residual_corridors == ()


@pytest.mark.parametrize("route", ("direct", "via", "entry", "branch", "convert", "replay"))
def test_final_load_leaf_redirect_requires_exact_direct_delivery(route: str) -> None:
    """Check the final emitted edge, including post-reconciliation entry routes."""

    write = InsnSnapshot(
        opcode=4,
        ea=0x1100,
        operands=(),
        kind=InsnKind.MOV,
        l=MopSnapshot(kind=OperandKind.NUMBER, size=4, value=7),
        d=MopSnapshot(kind=OperandKind.STACK, size=4, stkoff=100),
    )
    source_target = 5 if route == "via" else 2
    blocks = {
        1: _block(1, (source_target,), (), 0x1100, insns=(write,)),
        2: _block(2, (3,), (1, 6) if route == "entry" else (5,) if route == "via" else (1,), 0x1200),
        3: _block(3, (), (2,), 0x1300),
    }
    if route == "via":
        blocks[5] = _block(5, (2,), (1,), 0x1500)
    if route == "entry":
        blocks[6] = _block(6, (2,), (), 0x1600)
    graph = FlowGraph(blocks, entry_serial=1, func_ea=0x1000)
    transition = StateWriteTransition(
        write_block=1,
        next_state=7,
        target_handler=3,
        is_return=False,
        branch_arm=None,
        via_block=5 if route == "via" else None,
    )
    modification = (
        EdgeRedirectViaPredSplit(5, 2, 3, 1)
        if route == "via"
        else RedirectBranch(1, 2, 3)
        if route == "branch"
        else ConvertToGoto(1, 3)
        if route == "convert"
        else SimpleNamespace(per_pred_replays=(SimpleNamespace(target_serial=3),))
        if route == "replay"
        else RedirectGoto(6 if route == "entry" else 1, 2, 3)
    )

    assert emit_module._fresh_load_leaf_modifications_have_direct_delivery(
        graph,
        (modification,),
        (transition,),
        leaf_serials=frozenset({3}),
        root_serial=2,
        state_identity=StorageIdentity(StorageIdentityKind.STACK, 100),
    ) is (route == "direct")
    if route == "direct":
        assert emit_module._fresh_load_leaf_modifications_have_direct_delivery(
            graph,
            (modification,),
            (),
            leaf_serials=frozenset({3}),
            root_serial=2,
            state_identity=StorageIdentity(StorageIdentityKind.STACK, 100),
            entry_state=7,
            entry_target=3,
        )


def test_reference_dag_semantic_branch_leaf_needs_final_delivery_guard() -> None:
    """A shortcut cannot skip a pre-root write read by a semantic branch."""

    source_write = InsnSnapshot(
        opcode=4,
        ea=0x1100,
        operands=(),
        kind=InsnKind.MOV,
        l=MopSnapshot(kind=OperandKind.NUMBER, size=4, value=7),
        d=MopSnapshot(kind=OperandKind.STACK, size=4, stkoff=100),
    )
    alias_write = InsnSnapshot(
        opcode=4,
        ea=0x1700,
        operands=(),
        kind=InsnKind.MOV,
        l=MopSnapshot(kind=OperandKind.NUMBER, size=4, value=1),
        d=MopSnapshot(kind=OperandKind.STACK, size=4, stkoff=200),
    )
    graph = FlowGraph(
        {
            1: _block(1, (7,), (), 0x1100, insns=(source_write,)),
            7: _block(7, (2,), (1,), 0x1700, insns=(alias_write,)),
            2: _block(2, (3, 4), (7,), 0x1200),
            3: _block(
                3,
                (5, 6),
                (2,),
                0x1300,
                kind=BlockKind.TWO_WAY,
                insns=(InsnSnapshot(
                    opcode=4,
                    ea=0x1300,
                    operands=(),
                    kind=InsnKind.MOV,
                    l=MopSnapshot(kind=OperandKind.STACK, size=4, stkoff=200),
                    d=MopSnapshot(kind=OperandKind.REGISTER, size=4, reg=0),
                ),),
            ),
            4: _block(4, (), (2,), 0x1400),
            5: _block(5, (), (3,), 0x1500),
            6: _block(6, (), (3,), 0x1600),
        },
        entry_serial=1,
        func_ea=0x1000,
    )
    reference = DecisionDag(
        32,
        {2: RouteComparison(2, "jz", 7, 3, 4)},
        root=2,
    )

    leaves = emit_module._semantic_branch_leaf_serials(graph, reference)
    assert leaves == frozenset({3})
    assert not emit_module._fresh_load_leaf_modifications_have_direct_delivery(
        graph,
        (RedirectGoto(1, 7, 3),),
        (StateWriteTransition(1, 7, 3, False, None),),
        leaf_serials=leaves,
        root_serial=2,
        state_identity=StorageIdentity(StorageIdentityKind.STACK, 100),
    )


def test_pre_root_leaf_route_requires_current_source_write_and_proof() -> None:
    graph = FlowGraph({
        1: _block(1, (7,), (), 0x1100),
        7: _block(7, (2,), (1,), 0x1700),
        2: _block(2, (3, 4), (7,), 0x1200),
        3: _block(3, (), (2,), 0x1300),
        4: _block(4, (), (2,), 0x1400),
    }, entry_serial=1, func_ea=0x1000)
    reference = DecisionDag(32, {2: RouteComparison(2, "jz", 7, 3, 4)}, root=2)
    dispatcher = IntervalDispatcher([IntervalRow(7, 8, 3)], compute_default=False)
    for state in (7, 9):
        assert not emit_module._fresh_load_leaf_modifications_have_direct_delivery(
            graph, (RedirectGoto(1, 7, 3),),
            (StateWriteTransition(1, state, 3, False, None, via_block=7),),
            dispatcher=dispatcher, leaf_serials=frozenset({3}), root_serial=2,
            state_identity=StorageIdentity(StorageIdentityKind.STACK, 100),
            reference_dag=reference, state_var_stkoff=100,
        )
    source_write = InsnSnapshot(
        4, 0x1100, (), kind=InsnKind.MOV,
        l=MopSnapshot(kind=OperandKind.NUMBER, size=4, value=7),
        d=MopSnapshot(kind=OperandKind.STACK, size=4, stkoff=100),
    )
    proved_graph = FlowGraph({
        **graph.blocks,
        1: _block(1, (7,), (), 0x1100, insns=(source_write,)),
    }, entry_serial=1, func_ea=0x1000)
    assert emit_module._fresh_load_leaf_modifications_have_direct_delivery(
        proved_graph, (RedirectGoto(1, 7, 3),),
        (StateWriteTransition(
            1, 7, 3, False, None, via_block=7,
            proof=TransitionProof("test", "exact_literal", True),
        ),),
        dispatcher=dispatcher, leaf_serials=frozenset({3}), root_serial=2,
        state_identity=StorageIdentity(StorageIdentityKind.STACK, 100),
        reference_dag=reference, state_var_stkoff=100,
    )


def test_direct_root_leaf_rejects_untrusted_or_misrouted_state() -> None:
    write = InsnSnapshot(
        4, 0x1100, (), kind=InsnKind.MOV,
        l=MopSnapshot(kind=OperandKind.NUMBER, size=4, value=9),
        d=MopSnapshot(kind=OperandKind.STACK, size=4, stkoff=100),
    )
    graph = FlowGraph({
        1: _block(1, (2,), (), 0x1100, insns=(write,)),
        2: _block(2, (3, 4), (1,), 0x1200),
        3: _block(3, (), (2,), 0x1300),
        4: _block(4, (), (2,), 0x1400),
    }, entry_serial=1, func_ea=0x1000)
    dag = DecisionDag(32, {2: RouteComparison(2, "jz", 7, 3, 4)}, root=2)
    dispatcher = IntervalDispatcher([
        IntervalRow(7, 8, 3), IntervalRow(9, 10, 4),
    ], compute_default=False)
    for proof in (None, TransitionProof("test", "literal", True)):
        assert not emit_module._fresh_load_leaf_modifications_have_direct_delivery(
            graph, (RedirectGoto(1, 2, 3),),
            (StateWriteTransition(1, 9, 3, False, None, proof=proof),),
            dispatcher=dispatcher, leaf_serials=frozenset({3}), root_serial=2,
            state_identity=StorageIdentity(StorageIdentityKind.STACK, 100),
            reference_dag=dag, state_var_stkoff=100,
        )
    assert not emit_module._fresh_load_leaf_modifications_have_direct_delivery(
        graph, (RedirectGoto(1, 2, 4),),
        (StateWriteTransition(1, 9, 4, False, None),),
        dispatcher=dispatcher, leaf_serials=frozenset({4}), root_serial=2,
        state_identity=StorageIdentity(StorageIdentityKind.STACK, 100),
        reference_dag=dag, state_var_stkoff=100,
    )
    assert emit_module._fresh_load_leaf_modifications_have_direct_delivery(
        graph, (RedirectGoto(1, 2, 4),),
        (StateWriteTransition(
            1, 9, 4, False, None,
            proof=TransitionProof("test", "literal", True),
        ),),
        dispatcher=dispatcher, leaf_serials=frozenset({4}), root_serial=2,
        state_identity=StorageIdentity(StorageIdentityKind.STACK, 100),
        reference_dag=dag, state_var_stkoff=100,
    )


def test_direct_root_leaf_accepts_missing_adapter_row_only_with_exact_proof() -> None:
    write = InsnSnapshot(
        4, 0x1100, (), kind=InsnKind.MOV,
        l=MopSnapshot(kind=OperandKind.NUMBER, size=4, value=7),
        d=MopSnapshot(kind=OperandKind.STACK, size=4, stkoff=100),
    )
    graph = FlowGraph({
        1: _block(1, (2,), (), 0x1100, insns=(write,)),
        2: _block(2, (3, 4), (1,), 0x1200),
        3: _block(3, (), (2,), 0x1300),
        4: _block(4, (), (2,), 0x1400),
    }, entry_serial=1, func_ea=0x1000)
    dag = DecisionDag(32, {2: RouteComparison(2, "jz", 7, 3, 4)}, root=2)
    missing = SimpleNamespace(resolve_target=lambda _state: None)

    def accepted(proof: TransitionProof | None, dispatcher: object = missing) -> bool:
        return emit_module._fresh_load_leaf_modifications_have_direct_delivery(
            graph, (RedirectGoto(1, 2, 3),),
            (StateWriteTransition(1, 7, 3, False, None, proof=proof),),
            dispatcher=dispatcher, leaf_serials=frozenset({3}), root_serial=2,
            state_identity=StorageIdentity(StorageIdentityKind.STACK, 100),
            reference_dag=dag, state_var_stkoff=100,
        )

    assert accepted(TransitionProof("test", "exact_literal", True))
    assert accepted(
        TransitionProof("test", "exact_literal", True),
        IntervalDispatcher([], compute_default=False),
    )
    assert not accepted(
        TransitionProof("test", "exact_literal", True),
        IntervalDispatcher([], default_target=4, compute_default=False),
    )
    assert not accepted(None)
    assert not accepted(
        TransitionProof("test", "exact_literal", True),
        SimpleNamespace(resolve_target=lambda _state: 4),
    )
    assert not accepted(
        TransitionProof("test", "exact_literal", True),
        SimpleNamespace(
            resolve_target=lambda _state: None,
            lookup_row=lambda _state: IntervalRow(7, 8, 4),
        ),
    )


def test_skipped_prefix_preserves_one_way_handler_live_ins() -> None:
    """A one-way DAG leaf may feed a later branch that reads a skipped write."""

    alias_write = InsnSnapshot(
        opcode=4,
        ea=0x1700,
        operands=(),
        kind=InsnKind.MOV,
        l=MopSnapshot(kind=OperandKind.NUMBER, size=4, value=1),
        d=MopSnapshot(kind=OperandKind.REGISTER, size=4, reg=12),
    )
    branch = InsnSnapshot(
        opcode=0x71,
        ea=0x1500,
        operands=(),
        kind=InsnKind.COND_JUMP,
        l=MopSnapshot(kind=OperandKind.REGISTER, size=4, reg=12),
        r=MopSnapshot(kind=OperandKind.NUMBER, size=4, value=0),
        branch_predicate=PredicateKind.NE,
    )
    graph = FlowGraph(
        {
            1: _block(1, (7,), (), 0x1100),
            7: _block(7, (2,), (1,), 0x1700, insns=(alias_write,)),
            2: _block(2, (3, 4), (7,), 0x1200),
            3: _block(3, (5,), (2,), 0x1300),
            4: _block(4, (), (2,), 0x1400),
            5: _block(5, (6, 8), (3,), 0x1500, kind=BlockKind.TWO_WAY, insns=(branch,)),
            6: _block(6, (), (5,), 0x1600),
            8: _block(8, (), (5,), 0x1800),
        },
        entry_serial=1,
        func_ea=0x1000,
    )
    reference = DecisionDag(
        32,
        {2: RouteComparison(2, "jz", 7, 3, 4)},
        root=2,
    )

    assert not emit_module._skipped_prefix_preserves_handler_live_ins(
        graph, reference, old_target=7, leaf_serial=3, state_var_stkoff=100,
    )
    safe_alias = replace(
        alias_write,
        d=MopSnapshot(kind=OperandKind.REGISTER, size=4, reg=20),
    )
    safe_graph = FlowGraph(
        {**graph.blocks, 7: _block(7, (2,), (1,), 0x1700, insns=(safe_alias,))},
        entry_serial=1,
        func_ea=0x1000,
    )
    assert emit_module._skipped_prefix_preserves_handler_live_ins(
        safe_graph, reference, old_target=7, leaf_serial=3, state_var_stkoff=100,
    )

    partial_alias = replace(
        alias_write,
        d=MopSnapshot(kind=OperandKind.REGISTER, size=1, reg=13),
    )
    wide_branch = replace(
        branch,
        l=MopSnapshot(kind=OperandKind.REGISTER, size=8, reg=12),
    )
    partial_graph = FlowGraph(
        {
            **graph.blocks,
            7: _block(7, (2,), (1,), 0x1700, insns=(partial_alias,)),
            5: _block(5, (6, 8), (3,), 0x1500, kind=BlockKind.TWO_WAY, insns=(wide_branch,)),
        },
        entry_serial=1,
        func_ea=0x1000,
    )
    assert not emit_module._skipped_prefix_preserves_handler_live_ins(
        partial_graph, reference, old_target=7, leaf_serial=3, state_var_stkoff=100,
        state_var_reg=13,
    )

    unknown_width_branch = replace(
        branch,
        l=MopSnapshot(kind=OperandKind.REGISTER, size=0, reg=12),
    )
    unknown_width_graph = FlowGraph(
        {
            **graph.blocks,
            5: _block(
                5, (6, 8), (3,), 0x1500,
                kind=BlockKind.TWO_WAY, insns=(unknown_width_branch,),
            ),
        },
        entry_serial=1,
        func_ea=0x1000,
    )
    assert not emit_module._skipped_prefix_preserves_handler_live_ins(
        unknown_width_graph, reference,
        old_target=7, leaf_serial=3, state_var_stkoff=100,
    )

    unknown_width_write = replace(
        alias_write,
        d=MopSnapshot(kind=OperandKind.REGISTER, size=0, reg=12),
    )
    unknown_write_graph = FlowGraph(
        {
            **graph.blocks,
            7: _block(7, (2,), (1,), 0x1700, insns=(unknown_width_write,)),
        },
        entry_serial=1,
        func_ea=0x1000,
    )
    assert not emit_module._skipped_prefix_preserves_handler_live_ins(
        unknown_write_graph, reference,
        old_target=7, leaf_serial=3, state_var_stkoff=100,
    )

    nested_call = replace(
        safe_alias,
        l=MopSnapshot(kind=OperandKind.SUBINSN, size=4, sub_kind=InsnKind.CALL),
    )
    nested_call_graph = FlowGraph(
        {**graph.blocks, 7: _block(7, (2,), (1,), 0x1700, insns=(nested_call,))},
        entry_serial=1,
        func_ea=0x1000,
    )
    assert not emit_module._skipped_prefix_preserves_handler_live_ins(
        nested_call_graph, reference, old_target=7, leaf_serial=3, state_var_stkoff=100,
    )

    partial_stack_write = replace(
        alias_write,
        d=MopSnapshot(kind=OperandKind.STACK, size=1, stkoff=104),
    )
    wide_stack_branch = replace(
        branch,
        l=MopSnapshot(kind=OperandKind.STACK, size=8, stkoff=100),
    )
    partial_stack_graph = FlowGraph(
        {
            **graph.blocks,
            7: _block(7, (2,), (1,), 0x1700, insns=(partial_stack_write,)),
            5: _block(5, (6, 8), (3,), 0x1500, kind=BlockKind.TWO_WAY, insns=(wide_stack_branch,)),
        },
        entry_serial=1,
        func_ea=0x1000,
    )
    assert not emit_module._skipped_prefix_preserves_handler_live_ins(
        partial_stack_graph, reference, old_target=7, leaf_serial=3, state_var_stkoff=100,
    )

    leaf_store = InsnSnapshot(
        opcode=0x27,
        ea=0x1500,
        operands=(),
        kind=InsnKind.STORE,
        l=MopSnapshot(kind=OperandKind.NUMBER, size=4, value=1),
        d=MopSnapshot(kind=OperandKind.REGISTER, size=8, reg=12),
    )
    store_graph = FlowGraph(
        {
            **graph.blocks,
            5: _block(5, (6, 8), (3,), 0x1500, kind=BlockKind.TWO_WAY, insns=(leaf_store,)),
        },
        entry_serial=1,
        func_ea=0x1000,
    )
    assert not emit_module._skipped_prefix_preserves_handler_live_ins(
        store_graph, reference, old_target=7, leaf_serial=3, state_var_stkoff=100,
    )

    leaf_call = InsnSnapshot(
        opcode=0x28,
        ea=0x1500,
        operands=(),
        kind=InsnKind.CALL,
        d=MopSnapshot(
            kind=OperandKind.ARG_LIST,
            args=(MopSnapshot(kind=OperandKind.REGISTER, size=8, reg=12),),
        ),
    )
    call_graph = FlowGraph(
        {
            **graph.blocks,
            5: _block(5, (6, 8), (3,), 0x1500, kind=BlockKind.TWO_WAY, insns=(leaf_call,)),
        },
        entry_serial=1,
        func_ea=0x1000,
    )
    assert not emit_module._skipped_prefix_preserves_handler_live_ins(
        call_graph, reference, old_target=7, leaf_serial=3, state_var_stkoff=100,
    )

    state_overwrite = replace(
        alias_write,
        d=MopSnapshot(kind=OperandKind.STACK, size=4, stkoff=100),
    )
    state_overwrite_graph = FlowGraph(
        {**graph.blocks, 7: _block(7, (2,), (1,), 0x1700, insns=(state_overwrite,))},
        entry_serial=1,
        func_ea=0x1000,
    )
    assert not emit_module._skipped_prefix_preserves_handler_live_ins(
        state_overwrite_graph, reference, old_target=7, leaf_serial=3,
        state_var_stkoff=100,
    )


def test_final_guard_admits_only_source_bound_corridor_pred_split() -> None:
    """The cloned feeder executes; an empty pred-split trampoline does not."""

    write = InsnSnapshot(
        opcode=4,
        ea=0x1100,
        operands=(),
        kind=InsnKind.MOV,
        l=MopSnapshot(kind=OperandKind.NUMBER, size=4, value=7),
        d=MopSnapshot(kind=OperandKind.STACK, size=4, stkoff=100),
    )
    feeder = InsnSnapshot(
        opcode=4,
        ea=0x1500,
        operands=(),
        kind=InsnKind.MOV,
        l=MopSnapshot(kind=OperandKind.NUMBER, size=4, value=1),
        d=MopSnapshot(kind=OperandKind.REGISTER, size=4, reg=20),
    )
    graph = FlowGraph(
        {
            1: _block(1, (5,), (), 0x1100, insns=(write,)),
            5: _block(5, (2,), (1,), 0x1500, insns=(feeder,)),
            2: _block(2, (3, 4), (5,), 0x1200),
            3: _block(3, (), (2,), 0x1300),
            4: _block(4, (), (2,), 0x1400),
        },
        entry_serial=1,
        func_ea=0x1000,
    )
    reference = DecisionDag(32, {2: RouteComparison(2, "jz", 7, 3, 4)}, root=2)
    transition = StateWriteTransition(
        write_block=1,
        next_state=7,
        target_handler=3,
        is_return=False,
        branch_arm=None,
        via_block=5,
        preserve_via_block=True,
        preserve_via_until=5,
        proof=TransitionProof("test", "predecessor_partitioned", True),
    )
    kwargs = dict(
        leaf_serials=frozenset({3}),
        root_serial=2,
        state_identity=StorageIdentity(StorageIdentityKind.STACK, 100),
        reference_dag=reference,
        state_var_stkoff=100,
    )
    corridor = EdgeRedirectViaPredSplit(5, 2, 3, 1, clone_until=5)
    assert emit_module._all_reference_leaf_pred_splits_preserve_handler_inputs(
        graph, reference, (corridor,), (transition,),
        state_identity=kwargs["state_identity"],
        state_var_stkoff=100, state_var_reg=None,
        live_in_by_serial=None, storage_live_in_by_serial=None,
    )
    assert not emit_module._all_reference_leaf_pred_splits_preserve_handler_inputs(
        graph, reference, (ZeroStateWrite(5, 0x1500), corridor),
        (transition,), state_identity=kwargs["state_identity"],
        state_var_stkoff=100, state_var_reg=None,
        live_in_by_serial=None, storage_live_in_by_serial=None,
    )
    assert emit_module._fresh_load_leaf_modifications_have_direct_delivery(
        graph, (corridor,), (transition,), **kwargs,
    )
    assert not emit_module._fresh_load_leaf_modifications_have_direct_delivery(
        graph, (replace(corridor, clone_until=None),), (transition,), **kwargs,
    )
    assert not emit_module._fresh_load_leaf_modifications_have_direct_delivery(
        graph, (corridor,), (replace(transition, next_state=8),), **kwargs,
    )
    # A one-block clone copies the same instructions even if another proven
    # route retargets the original shared feeder's outgoing edge.
    assert emit_module._fresh_load_leaf_modifications_have_direct_delivery(
        graph, (RedirectGoto(5, 2, 4), corridor), (transition,), **kwargs,
    )
    assert not emit_module._fresh_load_leaf_modifications_have_direct_delivery(
        graph, (RedirectGoto(1, 5, 4), corridor), (transition,), **kwargs,
    )
    assert not emit_module._fresh_load_leaf_modifications_have_direct_delivery(
        graph, (ZeroStateWrite(5, 0x1500), corridor), (transition,), **kwargs,
    )
    assert not emit_module._fresh_load_leaf_modifications_have_direct_delivery(
        graph, (NopInstructions(5, (0x1500,)), corridor), (transition,), **kwargs,
    )
    shared_graph = FlowGraph(
        {
            **graph.blocks,
            5: _block(5, (2,), (1, 6), 0x1500, insns=(feeder,)),
            6: _block(6, (5,), (), 0x1600),
        },
        entry_serial=1, func_ea=0x1000,
    )
    independent_clone = EdgeRedirectViaPredSplit(5, 2, 4, 6, clone_until=5)
    assert emit_module._corridor_pred_split_preserves_handler_inputs(
        shared_graph, reference, corridor, (corridor, independent_clone),
        (transition,), state_identity=kwargs["state_identity"],
        state_var_stkoff=100, state_var_reg=None,
        live_in_by_serial=None, storage_live_in_by_serial=None,
    )
    asserted_predecessor = FlowGraph({
        **shared_graph.blocks,
        1: _block(1, (5,), (), 0x1100, insns=(replace(write, is_assert=True),)),
    }, entry_serial=1, func_ea=0x1000)
    assert not emit_module._corridor_pred_split_preserves_handler_inputs(
        asserted_predecessor, reference, corridor, (corridor, independent_clone),
        (transition,), state_identity=kwargs["state_identity"],
        state_var_stkoff=100, state_var_reg=None,
        live_in_by_serial=None, storage_live_in_by_serial=None,
    )
    assert not emit_module._corridor_pred_split_preserves_handler_inputs(
        shared_graph, reference, corridor,
        (corridor, replace(independent_clone, source_new_target=4)),
        (transition,), state_identity=kwargs["state_identity"],
        state_var_stkoff=100, state_var_reg=None,
        live_in_by_serial=None, storage_live_in_by_serial=None,
    )
    effectful_feeder = replace(
        feeder,
        l=MopSnapshot(kind=OperandKind.SUBINSN, size=4, sub_kind=InsnKind.CALL),
    )
    effectful_graph = FlowGraph(
        {**graph.blocks, 5: _block(5, (2,), (1,), 0x1500, insns=(effectful_feeder,))},
        entry_serial=1,
        func_ea=0x1000,
    )
    assert not emit_module._fresh_load_leaf_modifications_have_direct_delivery(
        effectful_graph, (corridor,), (transition,), **kwargs,
    )






def test_source_carrier_bypasses_only_a_dead_exact_normalizer_chain() -> None:
    """An exact second selector epoch may precede the final semantic leaf."""
    from d810.analyses.control_flow.minimal_state_recovery import (
        _exact_state_normalizer_step,
    )
    source_write = InsnSnapshot(
        4, 0x1100, (), kind=InsnKind.MOV,
        l=MopSnapshot(kind=OperandKind.NUMBER, size=4, value=7),
        d=MopSnapshot(kind=OperandKind.REGISTER, size=4, reg=8),
        value_op_kind=ValueOpKind.MOVE,
    )
    normalizer_write = replace(
        source_write, ea=0x1200,
        l=MopSnapshot(kind=OperandKind.NUMBER, size=4, value=8),
    )
    feeder_write = InsnSnapshot(
        4, 0x1300, (), kind=InsnKind.MOV,
        l=MopSnapshot(kind=OperandKind.REGISTER, size=4, reg=8),
        d=MopSnapshot(kind=OperandKind.STACK, size=4, stkoff=100),
        value_op_kind=ValueOpKind.MOVE,
    )
    blocks = {
        1: _block(1, (3,), (), 0x1100, insns=(source_write,)),
        2: _block(2, (3,), (4,), 0x1200, insns=(normalizer_write,)),
        3: _block(3, (4,), (1, 2), 0x1300, insns=(feeder_write,)),
        4: _block(4, (2, 5), (3,), 0x1400),
        5: _block(5, (17, 18), (4,), 0x1500),
        17: _block(17, (), (5,), 0x1700),
        18: _block(18, (), (5,), 0x1800),
    }
    graph = FlowGraph(blocks, entry_serial=1, func_ea=0x1000)
    dag = DecisionDag(32, {
        4: RouteComparison(4, "jz", 7, 2, 5),
        5: RouteComparison(5, "jz", 8, 17, 18),
    }, root=4)
    dispatcher = IntervalDispatcher([
        IntervalRow(7, 8, 2), IntervalRow(8, 9, 17),
    ], compute_default=False)
    transition = StateWriteTransition(
        1, 7, 17, False, None, via_block=3,
        proof=TransitionProof("test", "source_carrier_decision_dag_reconciled", True),
    )
    modification = RedirectGoto(1, 3, 17)

    step = _exact_state_normalizer_step(
        graph, dag, 2,
        expected_state_identities=frozenset({
            StorageIdentity(StorageIdentityKind.STACK, 100),
        }),
    )
    assert step.valid and step.state == 8 and step.feeder_serial == 3

    def accepted(candidate: FlowGraph) -> bool:
        return emit_module._source_bound_carrier_leaf_delivery(
            candidate, dispatcher, dag, modification, (transition,),
            state_identity=StorageIdentity(StorageIdentityKind.STACK, 100),
            entry_state=None, entry_target=None,
            state_var_stkoff=100, state_var_reg=None,
            live_in_by_serial=None,
            storage_live_in_by_serial=emit_module._storage_live_in_bytes(candidate),
        )

    assert dag.route(7) == 2
    assert emit_module._exact_dead_normalizer_handoff(
        graph, dispatcher, dag, first_leaf=2, final_leaf=17,
        feeder_serial=3, state_var_stkoff=100, state_var_reg=None,
        live_in_by_serial=None, storage_live_in_by_serial=None,
    )
    from d810.analyses.control_flow.state_carrier import prove_exact_u32_carrier_state_write
    witness = prove_exact_u32_carrier_state_write(
        graph, 1, 3, state_var_stkoff=100, state_var_reg=None,
        required_comparison_serials=frozenset({4}),
    )
    assert witness is not None and not witness.requires_feeder_clone
    assert (
        witness.state, witness.source_serial, witness.feeder_serial,
        witness.comparison_entry_serial, witness.state_identity,
    ) == (
        7, 1, 3, 4, StorageIdentity(StorageIdentityKind.STACK, 100),
    )
    assert emit_module._skipped_prefix_preserves_handler_live_ins(
        graph, dag, old_target=4, leaf_serial=17,
        state_var_stkoff=100, state_var_reg=None,
    )
    assert accepted(graph)
    assertion_then_read = FlowGraph({
        **blocks,
        17: _block(17, (), (5,), 0x1700, insns=(
            InsnSnapshot(
                4, 0x1700, (), kind=InsnKind.MOV, is_assert=True,
                l=MopSnapshot(kind=OperandKind.NUMBER, size=4, value=8),
                d=MopSnapshot(kind=OperandKind.STACK, size=4, stkoff=100),
            ),
            InsnSnapshot(
                4, 0x1704, (), kind=InsnKind.MOV,
                l=MopSnapshot(kind=OperandKind.STACK, size=4, stkoff=100),
                d=MopSnapshot(kind=OperandKind.REGISTER, size=4, reg=20),
            ),
        )),
    }, entry_serial=1, func_ea=0x1000)
    assert not accepted(assertion_then_read)
    leaf_read = InsnSnapshot(
        4, 0x1700, (), kind=InsnKind.MOV,
        l=MopSnapshot(kind=OperandKind.REGISTER, size=4, reg=8),
        d=MopSnapshot(kind=OperandKind.REGISTER, size=4, reg=20),
    )
    assert not accepted(FlowGraph(
        {**blocks, 17: _block(17, (), (5,), 0x1700, insns=(leaf_read,))},
        entry_serial=1, func_ea=0x1000,
    ))
    leaf_call = InsnSnapshot(0x28, 0x1700, (), kind=InsnKind.CALL)
    unknown_stack_graph = FlowGraph(
        {**blocks, 17: _block(17, (), (5,), 0x1700, insns=(leaf_call,))},
        entry_serial=1, func_ea=0x1000,
    )
    assert not accepted(unknown_stack_graph)
    (promoted,) = emit_module._preserve_live_state_carrier_feeders(
        unknown_stack_graph, dag, (transition,),
        state_var_stkoff=100, state_var_reg=None,
    )
    assert not promoted.preserve_via_block
    # Even a stale or incorrectly promoted transition cannot bypass the
    # final delivery gate when the second state write remains observable.
    forced = replace(transition, preserve_via_block=True)
    split = EdgeRedirectViaPredSplit(3, 4, 17, 1, clone_until=3)
    assert not emit_module._corridor_pred_split_preserves_handler_inputs(
        unknown_stack_graph, dag, split, (split,), (forced,),
        state_identity=StorageIdentity(StorageIdentityKind.STACK, 100),
        state_var_stkoff=100, state_var_reg=None,
        live_in_by_serial=None,
        storage_live_in_by_serial=emit_module._storage_live_in_bytes(
            unknown_stack_graph,
        ),
    )
    state_read = InsnSnapshot(
        4, 0x1700, (), kind=InsnKind.MOV,
        l=MopSnapshot(kind=OperandKind.STACK, size=4, stkoff=100),
        d=MopSnapshot(kind=OperandKind.REGISTER, size=4, reg=20),
    )
    state_read_graph = FlowGraph(
        {**blocks, 17: _block(17, (), (5,), 0x1700, insns=(state_read,))},
        entry_serial=1, func_ea=0x1000,
    )
    assert not emit_module._corridor_pred_split_preserves_handler_inputs(
        state_read_graph, dag, split, (split,), (forced,),
        state_identity=StorageIdentity(StorageIdentityKind.STACK, 100),
        state_var_stkoff=100, state_var_reg=None,
        live_in_by_serial=None,
        storage_live_in_by_serial=emit_module._storage_live_in_bytes(
            state_read_graph,
        ),
    )


def test_live_second_selector_write_stops_normalizer_chaining() -> None:
    source_write = InsnSnapshot(
        4, 0x1100, (), kind=InsnKind.MOV,
        l=MopSnapshot(kind=OperandKind.NUMBER, size=4, value=7),
        d=MopSnapshot(kind=OperandKind.REGISTER, size=4, reg=8),
        value_op_kind=ValueOpKind.MOVE,
    )
    normalizer_write = replace(
        source_write, ea=0x1200,
        l=MopSnapshot(kind=OperandKind.NUMBER, size=4, value=8),
    )
    feeder_write = InsnSnapshot(
        4, 0x1300, (), kind=InsnKind.MOV,
        l=MopSnapshot(kind=OperandKind.REGISTER, size=4, reg=8),
        d=MopSnapshot(kind=OperandKind.STACK, size=4, stkoff=100),
        value_op_kind=ValueOpKind.MOVE,
    )
    blocks = {
        1: _block(1, (3,), (), 0x1100, insns=(source_write,)),
        2: _block(2, (3,), (4,), 0x1200, insns=(normalizer_write,)),
        3: _block(3, (4,), (1, 2), 0x1300, insns=(feeder_write,)),
        4: _block(4, (2, 5), (3,), 0x1400),
        5: _block(5, (17, 18), (4,), 0x1500),
        17: _block(17, (), (5,), 0x1700),
        18: _block(18, (), (5,), 0x1800),
    }
    dag = DecisionDag(32, {
        4: RouteComparison(4, "jz", 7, 2, 5),
        5: RouteComparison(5, "jz", 8, 17, 18),
    }, root=4)
    first = StateWriteTransition(1, 7, 2, False, None, via_block=3)
    second = StateWriteTransition(2, 8, 17, False, None, via_block=3)
    dead_graph = FlowGraph(blocks, entry_serial=1, func_ea=0x1000)
    call_graph = FlowGraph({
        **blocks,
        17: _block(17, (), (5,), 0x1700, insns=(
            InsnSnapshot(0x28, 0x1700, (), kind=InsnKind.CALL),
        )),
    }, entry_serial=1, func_ea=0x1000)

    def live_sources(
        graph: FlowGraph, transitions: tuple[StateWriteTransition, ...],
    ) -> frozenset[int]:
        return emit_module._live_state_normalizer_sources(
            graph, dag, transitions,
            state_var_stkoff=100, state_var_reg=None,
        )

    assert live_sources(dead_graph, (first, second)) == frozenset()
    assert live_sources(call_graph, (first, second)) == frozenset({2})
    # Region recovery may see the normalizer's carrier write before it has
    # recovered the feeder's state value. The exact current graph still
    # establishes that this is a second selector epoch.
    unresolved_second = replace(second, next_state=None, target_handler=None)
    assert live_sources(call_graph, (first, unresolved_second)) == frozenset({2})
    assert live_sources(call_graph, (first, replace(unresolved_second, via_block=None))) == frozenset()
    assert live_sources(call_graph, (first, replace(second, next_state=9))) == frozenset()
    weak_first = replace(
        first, next_state=6, target_handler=1, via_block=None,
        proof=TransitionProof(
            "region_partitioned_fixpoint", "region_seeded", True,
            route_source_kinds=("interval",),
        ),
    )
    assert emit_module._is_weak_region_seeded_interval_state(
        weak_first, call_graph, state_var_stkoff=100, state_var_reg=None,
    )
    from d810.analyses.control_flow.state_carrier import prove_exact_u32_carrier_state_write
    assert prove_exact_u32_carrier_state_write(
        call_graph, 1, 3, state_var_stkoff=100, state_var_reg=None,
        required_comparison_serials=frozenset({4}),
    ) is not None
    assert live_sources(call_graph, (weak_first, unresolved_second, second)) == frozenset({2})
    strong_conflict = replace(
        weak_first,
        proof=TransitionProof("native_bound_transition_route", "exact", True),
    )
    assert live_sources(call_graph, (strong_conflict, second)) == frozenset()
    assert live_sources(call_graph, (first,)) == frozenset()


def test_entry_carrier_clone_preserves_state_for_unknown_handler_read() -> None:
    """The initial edge can clone its exact state MOVE instead of dropping it."""
    source_write = InsnSnapshot(
        4, 0x1100, (), kind=InsnKind.MOV,
        l=MopSnapshot(kind=OperandKind.NUMBER, size=4, value=7),
        d=MopSnapshot(kind=OperandKind.REGISTER, size=4, reg=8),
        value_op_kind=ValueOpKind.MOVE,
    )
    feeder_write = InsnSnapshot(
        4, 0x1300, (), kind=InsnKind.MOV,
        l=MopSnapshot(kind=OperandKind.REGISTER, size=4, reg=8),
        d=MopSnapshot(kind=OperandKind.STACK, size=4, stkoff=100),
        value_op_kind=ValueOpKind.MOVE,
    )
    graph = FlowGraph({
        1: _block(1, (3,), (), 0x1100, insns=(source_write,)),
        3: _block(3, (4,), (1,), 0x1300, insns=(feeder_write,)),
        4: _block(4, (10, 11), (3,), 0x1400),
        10: _block(10, (), (4,), 0x1A00, insns=(
            InsnSnapshot(0x28, 0x1A00, (), kind=InsnKind.CALL),
        )),
        11: _block(11, (), (4,), 0x1B00),
    }, entry_serial=1, func_ea=0x1000)
    dag = DecisionDag(32, {
        4: RouteComparison(4, "jz", 7, 10, 11),
    }, root=4)
    split = EdgeRedirectViaPredSplit(3, 4, 10, 1, clone_until=3)
    kwargs = dict(
        state_identity=StorageIdentity(StorageIdentityKind.STACK, 100),
        state_var_stkoff=100, state_var_reg=None,
        live_in_by_serial=None,
        storage_live_in_by_serial=emit_module._storage_live_in_bytes(graph),
    )
    assert emit_module._corridor_pred_split_preserves_handler_inputs(
        graph, dag, split, (split,), (), entry_state=7, entry_target=10,
        **kwargs,
    )
    assert emit_module._clone_live_entry_state_carrier_feeder(
        graph, [RedirectGoto(1, 3, 10)], (), dag,
        dispatcher_entry_serial=3, entry_state=7,
        state_var_stkoff=100, state_var_reg=None,
    ) == [split]
    assert not emit_module._corridor_pred_split_preserves_handler_inputs(
        graph, dag, split, (split,), (), entry_state=8, entry_target=10,
        **kwargs,
    )
    assert not emit_module._corridor_pred_split_preserves_handler_inputs(
        graph, dag, split, (split,), (), entry_state=7, entry_target=11,
        **kwargs,
    )


@pytest.mark.parametrize("source_width", [4, 8])
def test_cloned_constant_carrier_feeder_preserves_state_read_by_handler(
    source_width: int,
) -> None:
    """A source-local clone must execute the exact state MOVE before the leaf."""

    source_write = InsnSnapshot(
        opcode=4, ea=0x1100, operands=(), kind=InsnKind.MOV,
        l=MopSnapshot(kind=OperandKind.NUMBER, size=source_width, value=7),
        d=MopSnapshot(kind=OperandKind.REGISTER, size=source_width, reg=8),
    )
    feeder_write = InsnSnapshot(
        opcode=4, ea=0x1500, operands=(), kind=InsnKind.MOV,
        l=MopSnapshot(kind=OperandKind.REGISTER, size=4, reg=8),
        d=MopSnapshot(kind=OperandKind.STACK, size=4, stkoff=100),
    )
    handler_read = InsnSnapshot(
        opcode=4, ea=0x1300, operands=(), kind=InsnKind.MOV,
        l=MopSnapshot(kind=OperandKind.STACK, size=4, stkoff=100),
        d=MopSnapshot(kind=OperandKind.REGISTER, size=4, reg=40),
    )
    graph = FlowGraph(
        {
            1: _block(1, (5,), (), 0x1100, insns=(source_write,)),
            5: _block(5, (2,), (1,), 0x1500, insns=(feeder_write,)),
            2: _block(2, (3, 4), (5,), 0x1200),
            3: _block(3, (), (2,), 0x1300, insns=(handler_read,)),
            4: _block(4, (), (2,), 0x1400),
        },
        entry_serial=1, func_ea=0x1000,
    )
    reference = DecisionDag(32, {2: RouteComparison(2, "jz", 7, 3, 4)}, root=2)
    transition = StateWriteTransition(
        1, 7, 3, False, None, via_block=5,
        proof=TransitionProof("test", "source_carrier_decision_dag_reconciled", True),
    )
    (transition,) = emit_module._preserve_live_state_carrier_feeders(
        graph, reference, (transition,), state_var_stkoff=100, state_var_reg=None,
    )
    assert transition.preserve_via_block is True
    kwargs = dict(
        leaf_serials=frozenset({3}), root_serial=2,
        state_identity=StorageIdentity(StorageIdentityKind.STACK, 100),
        reference_dag=reference, state_var_stkoff=100,
    )
    assert not emit_module._fresh_load_leaf_modifications_have_direct_delivery(
        graph, (RedirectGoto(1, 5, 3),), (transition,), **kwargs,
    )
    split = EdgeRedirectViaPredSplit(5, 2, 3, 1, clone_until=5)
    assert emit_module._fresh_load_leaf_modifications_have_direct_delivery(
        graph, (split,), (transition,), **kwargs,
    )
    changed_feeder = replace(
        feeder_write, l=MopSnapshot(kind=OperandKind.NUMBER, size=4, value=8),
    )
    changed_graph = FlowGraph(
        {**graph.blocks, 5: _block(
            5, (2,), (1,), 0x1500, insns=(changed_feeder,),
        )},
        entry_serial=1, func_ea=0x1000,
    )
    assert not emit_module._fresh_load_leaf_modifications_have_direct_delivery(
        changed_graph,
        (split,), (transition,), **kwargs,
    )
    unpromoted = replace(transition, preserve_via_block=False)
    assert emit_module._preserve_live_state_carrier_feeders(
        changed_graph, reference, (unpromoted,),
        state_var_stkoff=100, state_var_reg=None,
    ) == (unpromoted,)
    state_dead_graph = FlowGraph(
        {**graph.blocks, 3: _block(3, (), (2,), 0x1300, insns=(
            replace(handler_read, l=MopSnapshot(
                kind=OperandKind.STACK, size=4, stkoff=200,
                stack_refs=(200,),
            )),
        ))},
        entry_serial=1, func_ea=0x1000,
    )
    assert emit_module._preserve_live_state_carrier_feeders(
        state_dead_graph, reference, (unpromoted,),
        state_var_stkoff=100, state_var_reg=None,
    ) == (unpromoted,)

    hidden_read = InsnSnapshot(
        opcode=7, ea=0x1300, operands=(), kind=InsnKind.LOAD,
        l=MopSnapshot(kind=OperandKind.ADDRESS, size=8, stack_refs=(100,)),
        d=MopSnapshot(kind=OperandKind.REGISTER, size=4, reg=40),
    )
    hidden_read_graph = FlowGraph(
        {**graph.blocks, 3: _block(3, (), (2,), 0x1300, insns=(hidden_read,))},
        entry_serial=1, func_ea=0x1000,
    )
    (hidden_promoted,) = emit_module._preserve_live_state_carrier_feeders(
        hidden_read_graph, reference, (unpromoted,),
        state_var_stkoff=100, state_var_reg=None,
    )
    assert hidden_promoted.preserve_via_block is True

    # A generic pointer LOAD may alias a stack state slot even when its
    # portable address tree has no explicit frame reference.
    unknown_address = replace(hidden_read, l=MopSnapshot(
        kind=OperandKind.ADDRESS, size=8,
    ))
    unknown_read_graph = FlowGraph(
        {**graph.blocks, 3: _block(3, (), (2,), 0x1300, insns=(unknown_address,))},
        entry_serial=1, func_ea=0x1000,
    )
    (unknown_promoted,) = emit_module._preserve_live_state_carrier_feeders(
        unknown_read_graph, reference, (unpromoted,),
        state_var_stkoff=100, state_var_reg=None,
    )
    assert unknown_promoted.preserve_via_block is True

    call_leaf = replace(unknown_address, kind=InsnKind.CALL, is_call=True)
    call_graph = FlowGraph(
        {**graph.blocks, 3: _block(3, (), (2,), 0x1300, insns=(call_leaf,))},
        entry_serial=1, func_ea=0x1000,
    )
    (call_promoted,) = emit_module._preserve_live_state_carrier_feeders(
        call_graph, reference, (unpromoted,),
        state_var_stkoff=100, state_var_reg=None,
    )
    assert call_promoted.preserve_via_block is True

    nested_call = replace(
        call_leaf, kind=InsnKind.MOV, value_op_kind=ValueOpKind.MOVE,
        is_call=False,
        l=MopSnapshot(kind=OperandKind.SUBINSN, size=8, sub_kind=InsnKind.CALL),
    )
    nested_call_graph = FlowGraph(
        {**graph.blocks, 3: _block(3, (), (2,), 0x1300, insns=(nested_call,))},
        entry_serial=1, func_ea=0x1000,
    )
    (nested_call_promoted,) = emit_module._preserve_live_state_carrier_feeders(
        nested_call_graph, reference, (unpromoted,),
        state_var_stkoff=100, state_var_reg=None,
    )
    assert nested_call_promoted.preserve_via_block is True


@pytest.mark.parametrize(
    ("operation", "second_value", "leaf_reads_state"),
    (
        (ValueOpKind.SUB, 10, True),
        (ValueOpKind.XOR, 4, True),
        (ValueOpKind.XOR, 4, False),
    ),
)
def test_cloned_state_transform_feeder_preserves_state_read_by_handler(
    operation: ValueOpKind, second_value: int, leaf_reads_state: bool,
) -> None:
    """A proven arithmetic state feeder is retained even if the leaf kills state."""

    source = (
        InsnSnapshot(
            opcode=4, ea=0x1100, operands=(), kind=InsnKind.MOV,
            l=MopSnapshot(kind=OperandKind.NUMBER, size=4, value=3),
            d=MopSnapshot(kind=OperandKind.REGISTER, size=4, reg=8),
        ),
        InsnSnapshot(
            opcode=4, ea=0x1104, operands=(), kind=InsnKind.MOV,
            l=MopSnapshot(kind=OperandKind.NUMBER, size=4, value=second_value),
            d=MopSnapshot(kind=OperandKind.REGISTER, size=4, reg=12),
        ),
    )
    feeder = InsnSnapshot(
        opcode=0x40, ea=0x1500, operands=(),
        kind=InsnKind.SUB if operation is ValueOpKind.SUB else InsnKind.VALUE,
        value_op_kind=operation,
        l=MopSnapshot(kind=OperandKind.REGISTER, size=4, reg=12),
        r=MopSnapshot(kind=OperandKind.REGISTER, size=4, reg=8),
        d=MopSnapshot(kind=OperandKind.STACK, size=4, stkoff=100),
    )
    read = InsnSnapshot(
        opcode=4, ea=0x1300, operands=(), kind=InsnKind.MOV,
        l=MopSnapshot(kind=OperandKind.STACK, size=4, stkoff=100),
        d=MopSnapshot(kind=OperandKind.REGISTER, size=4, reg=40),
    )
    graph = FlowGraph(
        {
            1: _block(1, (5,), (), 0x1100, insns=source),
            5: _block(5, (2,), (1,), 0x1500, insns=(feeder,)),
            2: _block(2, (3, 4), (5,), 0x1200),
            3: _block(3, (), (2,), 0x1300, insns=(read,) if leaf_reads_state else ()),
            4: _block(4, (), (2,), 0x1400),
        },
        entry_serial=1, func_ea=0x1000,
    )
    reference = DecisionDag(32, {2: RouteComparison(2, "jz", 7, 3, 4)}, root=2)
    transform_witness = emit_module.prove_exact_u32_state_transform_feeder(
        graph, 1, 5, state_var_stkoff=100, state_var_reg=None,
        required_comparison_serials=frozenset({2}), expected_state=7,
    )
    assert transform_witness is not None
    transform_fact = emit_module.SemanticRouteFact(
        kind=emit_module.SemanticRouteFactKind.STATE_TRANSFORM,
        owner_serial=1, source_serial=1, source_instruction_ea=transform_witness.source_ea,
        state_constant=7, target_serial=3,
        owner_anchor_ea=0x1100, target_anchor_ea=0x1300,
        path_serials=(1,), path_edges=(), transform_witness=transform_witness,
    )
    unpromoted = StateWriteTransition(
        1, 7, 3, False, None, via_block=5,
        proof=TransitionProof("test", "state_transform_feeder_decision_dag_reconciled", True),
        semantic_route_fact=transform_fact,
    )
    (promoted,) = emit_module._preserve_live_state_carrier_feeders(
        graph, reference, (unpromoted,), state_var_stkoff=100, state_var_reg=None,
    )
    assert promoted.preserve_via_block is True
    assert emit_module._fresh_load_leaf_modifications_have_direct_delivery(
        graph,
        (EdgeRedirectViaPredSplit(5, 2, 3, 1, clone_until=5),),
        (promoted,),
        leaf_serials=frozenset({3}), root_serial=2,
        state_identity=StorageIdentity(StorageIdentityKind.STACK, 100),
        reference_dag=reference, state_var_stkoff=100,
    )


def _conditional_observation_fixture(
    *,
    true_is_taken: bool = True,
    stateful: bool = False,
    condition_operand: object | None = None,
    predicate_ea: int = 0x1005,
) -> tuple[FlowGraph, FlowGraph, SimpleNamespace]:
    """Build one shifted live lowering with its physical helper topology."""
    if condition_operand is None:
        condition_operand = SyntheticRegisterNonzeroCondition(
            predicate_reg=9,
            predicate_size=4,
        )
    predicate = InsnSnapshot(
        opcode=0x71,
        ea=0xF0001005,
        native_ea=predicate_ea,
        operands=(),
        l=MopSnapshot(kind=OperandKind.REGISTER, reg=9, size=4),
        r=MopSnapshot(kind=OperandKind.NUMBER, value=0, size=4),
        kind=InsnKind.COND_JUMP,
        predicate_kind=PredicateKind.NE,
        branch_predicate=PredicateKind.NE,
    )
    preserve_live = isinstance(condition_operand, PreserveLivePredicateCondition)
    pre_source_succs = (20, 30) if preserve_live else (20,)
    pre_graph = FlowGraph(
        blocks={
            10: _block(
                10,
                pre_source_succs,
                (),
                0x1000,
                kind=BlockKind.TWO_WAY if preserve_live else BlockKind.ONE_WAY,
                insns=(predicate,) if preserve_live else (),
                tail_kind=(InsnKind.COND_JUMP if preserve_live else InsnKind.GOTO),
            ),
            20: _block(20, (), (10,), 0x1100, kind=BlockKind.ZERO_WAY),
            30: _block(
                30,
                (),
                (10,) if preserve_live else (),
                0x1200,
                kind=BlockKind.ZERO_WAY,
            ),
            40: _block(40, (), (), 0x1300, kind=BlockKind.ZERO_WAY),
        },
        entry_serial=10,
        func_ea=0x1000,
    )

    fallthrough_observed = 31 if true_is_taken else 41
    taken_observed = 41 if true_is_taken else 31
    successors: dict[int, tuple[int, ...]] = {
        10: (11, 12) if stateful else (11, taken_observed),
        11: (fallthrough_observed,),
        21: (),
        31: (),
        41: (),
    }
    if stateful:
        successors[12] = (taken_observed,)

    observed_blocks = {
        10: _block(
            10,
            successors[10],
            (),
            0x1000,
            kind=BlockKind.TWO_WAY,
            insns=(predicate,),
            tail_kind=InsnKind.COND_JUMP,
        ),
        11: _block(
            11,
            successors[11],
            (),
            0x2000,
            kind=BlockKind.ONE_WAY,
            tail_kind=InsnKind.GOTO,
        ),
        21: _block(21, (), (), 0x1100, kind=BlockKind.ZERO_WAY),
        31: _block(31, (), (), 0x1200, kind=BlockKind.ZERO_WAY),
        41: _block(41, (), (), 0x1300, kind=BlockKind.ZERO_WAY),
    }
    if stateful:
        fallthrough_state = 0x11 if true_is_taken else 0x22
        taken_state = 0x22 if true_is_taken else 0x11

        def state_write(value: int, target: int) -> tuple[InsnSnapshot, ...]:
            return (
                InsnSnapshot(
                    opcode=0x01,
                    ea=predicate_ea,
                    native_ea=predicate_ea,
                    operands=(),
                    l=MopSnapshot(kind=OperandKind.NUMBER, value=value, size=4),
                    d=MopSnapshot(kind=OperandKind.REGISTER, reg=7, size=4),
                    kind=InsnKind.MOV,
                ),
                InsnSnapshot(
                    opcode=0x02,
                    ea=predicate_ea,
                    native_ea=predicate_ea,
                    operands=(),
                    l=MopSnapshot(kind=OperandKind.BLOCK, block_ref=target),
                    kind=InsnKind.GOTO,
                ),
            )

        observed_blocks[11] = replace(
            observed_blocks[11],
            insn_snapshots=state_write(fallthrough_state, fallthrough_observed),
        )
        observed_blocks[12] = _block(
            12,
            successors[12],
            (),
            0x2001,
            kind=BlockKind.ONE_WAY,
            insns=state_write(taken_state, taken_observed),
            tail_kind=InsnKind.GOTO,
        )
    predecessor_map: dict[int, list[int]] = {serial: [] for serial in observed_blocks}
    for source, targets in successors.items():
        for target in targets:
            predecessor_map[target].append(source)
    observed_graph = FlowGraph(
        blocks={
            serial: replace(
                block,
                preds=tuple(sorted(set(predecessor_map[serial]))),
            )
            for serial, block in observed_blocks.items()
        },
        entry_serial=10,
        func_ea=0x1000,
    )
    plan = compile_patch_plan(
        [
            LowerConditionalStateTransition(
                source_serial=10,
                old_dispatcher_serial=20,
                rewrite_from_ea=predicate_ea,
                condition_operand=condition_operand,
                false_target_serial=30,
                true_target_serial=40,
                state_register=7 if stateful else None,
                state_size=4 if stateful else None,
                false_state=0x11 if stateful else None,
                true_state=0x22 if stateful else None,
            ),
        ],
        pre_graph,
    )
    return pre_graph, observed_graph, plan


def _replace_observed_edges(
    graph: FlowGraph,
    successors: dict[int, tuple[int, ...]],
    *,
    overrides: dict[int, dict[str, object]] | None = None,
) -> FlowGraph:
    """Rebuild raw observed predecessors for topology-specific negatives."""
    overrides = overrides or {}
    predecessor_map: dict[int, list[int]] = {serial: [] for serial in graph.blocks}
    for source, targets in successors.items():
        for target in targets:
            predecessor_map[target].append(source)
    blocks = {}
    for serial, block in graph.blocks.items():
        block = replace(
            block,
            succs=successors.get(serial, block.succs),
            preds=tuple(sorted(set(predecessor_map[serial]))),
        )
        if serial in overrides:
            block = replace(block, **overrides[serial])
        blocks[serial] = block
    return FlowGraph(
        blocks=blocks,
        entry_serial=graph.entry_serial,
        func_ea=graph.func_ea,
        metadata=graph.metadata,
    )


def _nested_merge_corridor_graph() -> FlowGraph:
    """The two real MMORPG residual corridors, in portable CFG form."""
    return FlowGraph(
        blocks={
            0: _block(0, (45, 122), (), 0x7FF859C06F60),
            45: _block(45, (123,), (0,), 0x7FF859C07656),
            122: _block(122, (123,), (0,), 0x7FF859C08BFE),
            123: _block(123, (3,), (45, 122), 0x7FF859C08D35),
            3: _block(3, (4,), (123,), 0x7FF859C070C0),
            4: _block(4, (121, 34), (3,), 0x7FF859C070C4),
            121: _block(121, (), (4,), 0x7FF859C08B37),
            34: _block(34, (), (4,), 0x7FF859C0747A),
        },
        entry_serial=0,
        func_ea=0x7FF859C06F60,
    )


@pytest.mark.parametrize("redirect_count", [358, 360])
def test_high_fan_in_feeder_accounts_for_every_immediate_corridor(redirect_count):
    inputs = tuple(range(1, 361))
    graph = FlowGraph(blocks={
        0: _block(0, inputs, (), 0x1000),
        **{serial: _block(serial, (1000,), (0,), 0x1000 + serial * 16)
           for serial in inputs},
        1000: _block(1000, (1001,), inputs, 0x6000),
        1001: _block(1001, (1002,), (1000,), 0x6010),
        1002: _block(1002, (), (1001,), 0x6020, kind=BlockKind.STOP),
    }, entry_serial=0, func_ea=0x1000)
    report = analyze_dispatcher_corridor_coverage(
        graph,
        modifications=tuple(
            RedirectGoto(from_serial=serial, old_target=1000, new_target=1002)
            for serial in inputs[:redirect_count]
        ),
        dispatcher_entry_serial=1001,
    )
    assert report.enumeration_complete
    assert len(report.covered_corridors) == redirect_count
    assert tuple(
        tuple(anchor.serial for anchor in corridor.path)
        for corridor in report.residual_corridors
    ) == (() if redirect_count == 360 else ((359, 1000, 1001), (360, 1000, 1001)))


def test_high_fan_in_floor_does_not_unbound_upstream_merge_expansion():
    inputs = tuple(range(1, 361))
    successors = {
        **{serial: (1000,) for serial in inputs},
        1000: (1001,), 1001: (), 2000: (1,), 2001: (1,),
    }
    paths, complete = corridor_module._upstream_corridor_paths(
        successors, feeder_serial=1000, dispatcher_serial=1001,
    )
    assert not complete
    assert len(paths) == 360
    assert (2000, 1, 1000, 1001) in paths
    assert (2001, 1, 1000, 1001) in paths


@pytest.mark.parametrize("extra_successor", [False, True])
def test_direct_dispatcher_self_edge_is_one_explicit_corridor(extra_successor):
    successors = {0: (2,), 2: (2, 3) if extra_successor else (2,), 3: ()}
    paths, complete = corridor_module._upstream_corridor_paths(
        successors, feeder_serial=2, dispatcher_serial=2,
    )
    assert complete
    assert paths == ((2, 2),)


@pytest.mark.parametrize("redirect_entry", [False, True])
def test_direct_dispatcher_self_edge_coverage_tracks_reachability(redirect_entry):
    graph = FlowGraph(blocks={
        0: _block(0, (2,), (), 0x1000),
        2: _block(2, (2,), (0, 2), 0x1020),
        3: _block(3, (), (), 0x1030, kind=BlockKind.STOP),
    }, entry_serial=0, func_ea=0x1000)
    report = analyze_dispatcher_corridor_coverage(
        graph, dispatcher_entry_serial=2,
        modifications=(RedirectGoto(from_serial=0, old_target=2, new_target=3),)
        if redirect_entry else (),
    )
    assert report.enumeration_complete
    paths = report.covered_corridors if redirect_entry else report.residual_corridors
    assert {tuple(a.serial for a in path.path) for path in paths} == {(0, 2), (2, 2)}
    assert not (report.residual_corridors if redirect_entry else report.covered_corridors)


def _dispatcher_self_reentry_corridor_graph(
    *,
    reverse_cycle: bool = False,
    merge_reverse_cycle: bool = False,
) -> FlowGraph:
    """Small C-shaped dispatcher graph with optional unrelated reverse cycles."""
    if merge_reverse_cycle:
        return FlowGraph(
            blocks={
                0: _block(0, (1, 8), (), 0x1000),
                1: _block(1, (3,), (0,), 0x1010),
                8: _block(8, (4,), (0,), 0x1080),
                3: _block(3, (4,), (1, 2, 4), 0x1030),
                4: _block(4, (5, 10, 3), (8, 3), 0x1040),
                5: _block(5, (6,), (4,), 0x1050),
                6: _block(6, (2,), (5,), 0x1060),
                2: _block(2, (3,), (6,), 0x1020),
                10: _block(10, (), (4,), 0x10A0, kind=BlockKind.STOP),
                9: _block(9, (), (), 0x1090, kind=BlockKind.STOP),
            },
            entry_serial=0,
            func_ea=0x1000,
        )
    blocks = {
        0: _block(0, (1, 8), (), 0x1000),
        1: _block(1, (3,), (0,), 0x1010),
        8: _block(8, (0 if reverse_cycle else 4,), (0,), 0x1080),
        3: _block(3, (4,), (1, 2), 0x1030),
        4: _block(4, (5, 10), (8, 3), 0x1040),
        5: _block(5, (6,), (4,), 0x1050),
        6: _block(6, (2,), (5,), 0x1060),
        2: _block(2, (3,), (6,), 0x1020),
        10: _block(10, (), (4,), 0x10A0, kind=BlockKind.STOP),
        9: _block(9, (), (), 0x1090, kind=BlockKind.STOP),
    }
    if reverse_cycle:
        blocks[0] = _block(0, (1, 8), (8,), 0x1000)
        blocks[8] = _block(8, (0,), (0,), 0x1080)
    return FlowGraph(blocks=blocks, entry_serial=0, func_ea=0x1000)



def test_dispatcher_self_reentry_corridor_is_enumerated_completely() -> None:
    graph = _dispatcher_self_reentry_corridor_graph()
    report = analyze_dispatcher_corridor_coverage(
        graph,
        modifications=(
            RedirectGoto(from_serial=1, old_target=3, new_target=9),
            RedirectGoto(from_serial=2, old_target=3, new_target=9),
        ),
        dispatcher_entry_serial=3,
    )

    assert report.enumeration_complete
    assert not report.residual_corridors
    assert report.covered_corridors
    assert all(
        len({(anchor.serial, anchor.ea) for anchor in corridor.path})
        == len(corridor.path)
        for corridor in report.covered_corridors
    ), tuple(tuple(anchor.serial for anchor in corridor.path) for corridor in report.covered_corridors)
    for corridor in report.covered_corridors:
        assert corridor.label == " -> ".join(
            f"blk{anchor.serial}@0x{anchor.ea:x}" for anchor in corridor.path
        )


def test_single_block_handler_loop_before_feeder_is_finite_corridor() -> None:
    """A retained handler self-loop does not create a second feeder exit.

    The 69814 loader has blk223@0x7FFF9918A4D0 looping to itself before
    exiting through blk224@0x7FFF9918AC92 to the dispatcher. Redirecting
    the feeder exit leaves the loop executable; enumerating loop iterations
    is unnecessary for corridor coverage.
    """

    graph = FlowGraph(
        blocks={
            0: _block(0, (1,), (), 0x1000),
            1: _block(1, (2, 9), (0, 4), 0x1010),
            2: _block(2, (2, 4), (1, 2), 0x1020),
            4: _block(4, (1,), (2,), 0x1040),
            9: _block(9, (), (1,), 0x1090, kind=BlockKind.STOP),
        },
        entry_serial=0,
        func_ea=0x1000,
    )
    report = analyze_dispatcher_corridor_coverage(
        graph,
        modifications=(RedirectGoto(from_serial=4, old_target=1, new_target=9),),
        dispatcher_entry_serial=1,
    )

    assert report.enumeration_complete
    assert tuple(tuple(anchor.serial for anchor in row.path) for row in report.residual_corridors) == (
        (0, 1),
    )
    assert tuple(tuple(anchor.serial for anchor in row.path) for row in report.covered_corridors) == (
        (2, 4, 1),
    )


def test_handler_loop_with_another_exit_remains_incomplete() -> None:
    graph = FlowGraph(
        blocks={
            0: _block(0, (1,), (), 0x1000),
            1: _block(1, (2, 9), (0, 4), 0x1010),
            2: _block(2, (2, 4, 9), (1, 2), 0x1020),
            4: _block(4, (1,), (2,), 0x1040),
            9: _block(9, (), (1, 2), 0x1090, kind=BlockKind.STOP),
        },
        entry_serial=0,
        func_ea=0x1000,
    )
    report = analyze_dispatcher_corridor_coverage(
        graph,
        modifications=(RedirectGoto(from_serial=4, old_target=1, new_target=9),),
        dispatcher_entry_serial=1,
    )
    assert not report.enumeration_complete

def test_unrelated_reverse_cycle_keeps_corridor_enumeration_incomplete() -> None:
    graph = _dispatcher_self_reentry_corridor_graph(reverse_cycle=True)
    report = analyze_dispatcher_corridor_coverage(
        graph,
        modifications=(
            RedirectGoto(from_serial=1, old_target=3, new_target=9),
            RedirectGoto(from_serial=2, old_target=3, new_target=9),
        ),
        dispatcher_entry_serial=3,
    )

    assert not report.enumeration_complete


@pytest.mark.parametrize("redirect", (False, True))
def test_payload_self_loop_has_finite_exit_corridor_without_retiring_loop(redirect) -> None:
    """69814: blk391 loops locally before blk392 returns to the dispatcher."""
    graph = FlowGraph({
        0: _block(0, (1,), (), 0x1000),
        1: _block(1, (1, 2), (0, 1, 3), 0x1010),
        2: _block(2, (3,), (1,), 0x1020),
        3: _block(3, (1,), (2,), 0x1030),
        4: _block(4, (), (), 0x1040),
    }, entry_serial=0, func_ea=0x1000)
    edits = (RedirectGoto(from_serial=2, old_target=3, new_target=4),) if redirect else ()
    report = analyze_dispatcher_corridor_coverage(graph, modifications=edits, dispatcher_entry_serial=3)
    assert report.enumeration_complete
    assert bool(report.residual_corridors) is not redirect
    corridors = (*report.covered_corridors, *report.residual_corridors)
    assert any(tuple(point.serial for point in row.path) == (1, 2, 3) for row in corridors)
    assert all(len({point.serial for point in row.path}) == len(row.path) for row in corridors)
    assert all(row.state_merge_anchor is None for row in corridors)
    # Only the exit is redirected; the payload's self-loop is still executable.
    assert corridor_module._rewired_successors(graph, edits)[1] == (1, 2)


def test_payload_self_loop_replacement_return_remains_residual() -> None:
    graph = FlowGraph({
        0: _block(0, (1,), (), 0x1000),
        1: _block(1, (1, 2), (0, 1, 3), 0x1010),
        2: _block(2, (3,), (1,), 0x1020),
        3: _block(3, (1,), (2, 4), 0x1030),
        4: _block(4, (3,), (), 0x1040),
    }, entry_serial=0, func_ea=0x1000)
    report = analyze_dispatcher_corridor_coverage(
        graph, modifications=(RedirectGoto(from_serial=2, old_target=3, new_target=4),),
        dispatcher_entry_serial=3,
    )
    assert report.enumeration_complete
    assert report.residual_corridors
    assert not report.full_unflattening_claim


def test_payload_self_loop_with_additional_exit_is_not_this_bounded_shape() -> None:
    paths, complete = corridor_module._upstream_corridor_paths(
        {0: (1,), 1: (1, 2, 4), 2: (3,), 3: (1,), 4: ()},
        feeder_serial=2, dispatcher_serial=3,
    )
    assert not complete


def test_repeated_merge_node_keeps_corridor_enumeration_incomplete() -> None:
    graph = _dispatcher_self_reentry_corridor_graph(merge_reverse_cycle=True)
    report = analyze_dispatcher_corridor_coverage(
        graph,
        modifications=(
            RedirectGoto(from_serial=1, old_target=3, new_target=9),
            RedirectGoto(from_serial=2, old_target=3, new_target=9),
        ),
        dispatcher_entry_serial=3,
    )

    assert not report.enumeration_complete


def test_corridor_scope_does_not_promote_unrelated_reverse_cycle() -> None:
    """A foreign cycle is diagnostic context, not covered dispatcher scope."""

    graph = _dispatcher_self_reentry_corridor_graph(reverse_cycle=True)
    report = analyze_dispatcher_corridor_coverage(
        graph,
        modifications=(
            RedirectGoto(from_serial=1, old_target=3, new_target=9),
            RedirectGoto(from_serial=2, old_target=3, new_target=9),
        ),
        dispatcher_entry_serial=3,
    )

    assert report.covered_corridors
    covered_identities = {
        (anchor.serial, anchor.ea)
        for corridor in report.covered_corridors
        for anchor in corridor.path
    }
    assert not report.enumeration_complete
    assert {(0, 0x1000), (8, 0x1080)}.isdisjoint(covered_identities)
    for corridor in report.covered_corridors:
        assert corridor.label == " -> ".join(
            f"blk{anchor.serial}@0x{anchor.ea:x}" for anchor in corridor.path
        )


@pytest.mark.parametrize(
    ("cap_name", "cap_value"),
    (("_MAX_CORRIDOR_DEPTH", 2), ("_MAX_CORRIDORS", 1)),
)
def test_dispatcher_self_reentry_respects_corridor_caps(
    monkeypatch,
    cap_name: str,
    cap_value: int,
) -> None:
    monkeypatch.setattr(corridor_module, cap_name, cap_value)
    graph = _dispatcher_self_reentry_corridor_graph()
    report = analyze_dispatcher_corridor_coverage(
        graph,
        modifications=(
            RedirectGoto(from_serial=1, old_target=3, new_target=9),
            RedirectGoto(from_serial=2, old_target=3, new_target=9),
        ),
        dispatcher_entry_serial=3,
    )

    assert not report.enumeration_complete
    assert not report.residual_corridors



def _nested_merge_behind_shared_feeder_graph() -> FlowGraph:
    """Target shape when other handlers also re-enter the same feeder."""
    graph = _nested_merge_corridor_graph()
    return FlowGraph(
        blocks={
            **graph.blocks,
            0: _block(0, (2, 26, 45, 122), (), 0x7FF859C06F60),
            2: _block(2, (3,), (0,), 0x7FF859C06FE3),
            26: _block(26, (3,), (0,), 0x7FF859C0731C),
            3: _block(3, (4,), (2, 26, 123), 0x7FF859C070C0),
        },
        entry_serial=0,
        func_ea=0x7FF859C06F60,
    )


def _target_shape_corridor_graph() -> FlowGraph:
    """Portable 43-corridor router shape used by the safety regression."""
    dispatcher = 0
    entry = 1
    feeders = tuple(range(2, 45))
    terminal = 45
    blocks = {
        dispatcher: _block(dispatcher, (terminal,), feeders, 0x700000),
        entry: _block(entry, feeders, (), 0x700100),
        terminal: _block(terminal, (), (dispatcher,), 0x700200),
    }
    blocks.update(
        {
            feeder: _block(feeder, (dispatcher,), (entry,), 0x700000 + feeder)
            for feeder in feeders
        }
    )
    return FlowGraph(blocks=blocks, entry_serial=entry, func_ea=0x700000)


def test_use_def_audit_keeps_block_start_separate_from_instruction_ea() -> None:
    class _PortableCfg:
        def get_block(self, serial: int) -> object:
            return SimpleNamespace(
                start_ea={1: 0x700100, 2: 0x700180, 45: 0x700200}[serial]
            )

    class _UseDefSafety:
        @staticmethod
        def redirect_use_def_violations(*_args: object) -> tuple[object, ...]:
            return (
                SimpleNamespace(
                    var_stkoff=0x70,
                    var_size=4,
                    use_block=45,
                    use_ea=0x7002AA,
                ),
            )

    audit = audit_use_def_severances(
        (RedirectGoto(from_serial=1, old_target=2, new_target=45),),
        use_def_safety=_UseDefSafety(),
        live_function=object(),
        pre_cfg=_PortableCfg(),
        state_var_stkoff=0x64,
    )

    evidence = audit.violations[0]
    assert evidence.use.serial == 45
    assert evidence.use.ea == 0x700200
    assert evidence.use.label == "blk45@0x700200"
    assert evidence.use_instruction_ea == 0x7002AA
    assert (
        audit.to_metadata(function_ea=0x700000)["violations"][0]["use_instruction_ea"]
        == 0x7002AA
    )


def test_target_shape_advisory_and_explicit_veto_preserve_exact_counts(
    monkeypatch,
) -> None:
    """43 corridors, 25 candidates, and 3 findings stay deterministic."""
    graph = _target_shape_corridor_graph()
    candidate_redirects = tuple(
        RedirectGoto(from_serial=feeder, old_target=0, new_target=45)
        for feeder in range(2, 27)
    )
    recovered = analyze_dispatcher_corridor_coverage(
        graph,
        modifications=(),
        dispatcher_entry_serial=0,
    )
    planned = analyze_dispatcher_corridor_coverage(
        graph,
        modifications=candidate_redirects,
        dispatcher_entry_serial=0,
    )
    assert len(candidate_redirects) == 25
    assert len(recovered.covered_corridors) + len(recovered.residual_corridors) == 43
    assert len(planned.covered_corridors) == 25
    assert len(planned.residual_corridors) == 18

    class _TargetUseDefSafety:
        def __init__(self) -> None:
            self.calls = 0

        def redirect_use_def_violations(self, *_args: object) -> tuple[object, ...]:
            index = self.calls
            self.calls += 1
            if index < 3:
                return (
                    SimpleNamespace(
                        var_stkoff=0x70,
                        var_size=4,
                        use_block=45,
                        use_ea=0x7002AA,
                    ),
                )
            return ()

    monkeypatch.setattr(
        emit_module,
        "recover_state_write_transitions_via_partitioned_fixpoint",
        lambda *_args, **_kwargs: (),
    )
    monkeypatch.setattr(
        emit_module,
        "_dispatcher_entry_preds",
        lambda *_args, **_kwargs: [],
    )
    monkeypatch.setattr(
        emit_module,
        "build_state_write_redirects",
        lambda *_args, **_kwargs: list(candidate_redirects),
    )

    dispatcher = IntervalDispatcher(
        [
            IntervalRow(lo=0, hi=1, target=2),
            IntervalRow(lo=1, hi=0x100000000, target=45),
        ]
    )

    monkeypatch.setenv("D810_USE_DEF_VETO", "0")
    monkeypatch.delenv("D810_S1A_SEVERANCE_BAIL", raising=False)
    advisory_plan = emit_minimal_unflatten(
        graph,
        dispatcher,
        state_var_stkoff=0x64,
        dispatcher_entry_serial=0,
        use_def_safety=_TargetUseDefSafety(),
        live_function=object(),
    )
    assert len(graph_modifications(advisory_plan)) == 25
    assert not set(advisory_plan.metadata_dict()).intersection(LEGACY_UNFLATTEN_KEYS)

    monkeypatch.setenv("D810_USE_DEF_VETO", "1")
    enforced_plan = emit_minimal_unflatten(
        graph,
        dispatcher,
        state_var_stkoff=0x64,
        dispatcher_entry_serial=0,
        use_def_safety=_TargetUseDefSafety(),
        live_function=object(),
    )
    assert graph_modifications(enforced_plan) == []
    assert not set(enforced_plan.metadata_dict()).intersection(LEGACY_UNFLATTEN_KEYS)


def test_coverage_descends_one_shared_merge_behind_a_shared_feeder() -> None:
    """The known blk45/blk122 merge must not collapse into source blk123."""
    report = analyze_dispatcher_corridor_coverage(
        _nested_merge_behind_shared_feeder_graph(),
        modifications=(),
        dispatcher_entry_serial=4,
    )

    paths = {
        tuple(anchor.serial for anchor in corridor.path)
        for corridor in report.residual_corridors
    }
    assert (45, 123, 3, 4) in paths
    assert (122, 123, 3, 4) in paths
    assert (123, 3, 4) not in paths
    assert {
        corridor.state_merge.serial
        for corridor in report.residual_corridors
        if corridor.source.serial in {45, 122} and corridor.state_merge is not None
    } == {123}




def test_coverage_reports_each_reachable_nested_dispatcher_corridor() -> None:
    report = analyze_dispatcher_corridor_coverage(
        _nested_merge_corridor_graph(),
        modifications=(),
        dispatcher_entry_serial=4,
    )

    assert report.completion_status == "pending_patch_application"
    assert report.planned_completion_status == "planned_partial_residual_dispatcher"
    assert report.full_unflattening_claim is False
    assert {
        tuple(anchor.serial for anchor in corridor.path)
        for corridor in report.residual_corridors
    } == {
        (45, 123, 3, 4),
        (122, 123, 3, 4),
    }
    assert {
        tuple(anchor.ea for anchor in corridor.path)
        for corridor in report.residual_corridors
    } == {
        (0x7FF859C07656, 0x7FF859C08D35, 0x7FF859C070C0, 0x7FF859C070C4),
        (0x7FF859C08BFE, 0x7FF859C08D35, 0x7FF859C070C0, 0x7FF859C070C4),
    }

def test_coverage_marks_both_nested_corridors_covered_only_after_bypass() -> None:
    report = analyze_dispatcher_corridor_coverage(
        _nested_merge_corridor_graph(),
        modifications=(
            RedirectGoto(from_serial=45, old_target=123, new_target=121),
            RedirectGoto(from_serial=122, old_target=123, new_target=34),
        ),
        dispatcher_entry_serial=4,
    )

    assert report.completion_status == "pending_patch_application"
    assert report.planned_completion_status == "planned_dispatcher_corridors_covered"
    assert report.full_unflattening_claim is False
    assert report.whole_function_proof_status == "not_claimed"
    assert not report.residual_corridors
    assert {
        tuple(anchor.serial for anchor in corridor.path)
        for corridor in report.covered_corridors
    } == {
        (45, 123, 3, 4),
        (122, 123, 3, 4),
    }

def test_dispatcher_removal_forecast_contains_only_typed_infrastructure_loss() -> None:
    graph = _nested_merge_corridor_graph()
    coverage = analyze_dispatcher_corridor_coverage(
        graph,
        modifications=(
            RedirectGoto(from_serial=45, old_target=123, new_target=121),
            RedirectGoto(from_serial=122, old_target=123, new_target=34),
        ),
        dispatcher_entry_serial=4,
    )
    post_graph = FlowGraph(
        blocks={
            **graph.blocks,
            0: _block(0, (45, 122), (), 0x7FF859C06F60),
            45: _block(45, (121,), (0,), 0x7FF859C07656),
            122: _block(122, (34,), (0,), 0x7FF859C08BFE),
            123: _block(123, (3,), (), 0x7FF859C08D35),
            3: _block(3, (4,), (123,), 0x7FF859C070C0),
        },
        entry_serial=0,
        func_ea=0x7FF859C06F60,
    )
    forecast = corridor_module.build_dispatcher_removal_forecast(
        graph,
        coverage=coverage,
        dispatcher_entry_serial=4,
    )
    assert {
        (item.role, item.anchor.serial) for item in forecast.retirement_candidates
    } == {
        ("comparison_dispatcher", 4),
        ("dispatcher_feeder", 3),
        ("state_merge", 123),
    }
    assert not hasattr(forecast, "passed")
    assert not hasattr(forecast, "reason")


def test_incomplete_removal_forecast_abstains_without_verdict() -> None:
    graph = _nested_merge_corridor_graph()
    coverage = analyze_dispatcher_corridor_coverage(
        graph,
        modifications=(),
        dispatcher_entry_serial=4,
    )
    forecast = corridor_module.build_dispatcher_removal_forecast(
        graph,
        coverage=coverage,
        dispatcher_entry_serial=4,
    )
    assert forecast.residual_corridors
    assert forecast.dispatcher == coverage.dispatcher
    assert not hasattr(forecast, "passed")
    assert not hasattr(forecast, "reason")


def test_detached_component_analysis_proposes_only_dead_handler_island() -> None:
    state = MopSnapshot(kind=OperandKind.STACK, stkoff=40, size=4)
    branch = InsnSnapshot(
        opcode=42,
        ea=0x1200,
        operands=(),
        l=state,
        r=MopSnapshot(kind=OperandKind.NUMBER, value=7, size=4),
        d=MopSnapshot(kind=OperandKind.BLOCK, block_ref=21),
        kind=InsnKind.COND_JUMP,
        predicate_kind=PredicateKind.EQ,
    )
    pre_graph = FlowGraph(
        blocks={
            0: _block(0, (4,), (), 0x1000, kind=BlockKind.ONE_WAY),
            4: _block(4, (20, 21), (0, 21), 0x1200, kind=BlockKind.TWO_WAY, insns=(branch,)),
            20: _block(20, (), (4,), 0x1300, kind=BlockKind.STOP),
            21: _block(21, (4,), (4,), 0x1310, kind=BlockKind.ONE_WAY),
        },
        entry_serial=0,
        func_ea=0x1000,
    )
    post_graph = _replace_observed_edges(
        pre_graph,
        {0: (20,), 4: (20, 21), 20: (), 21: (4,)},
    )
    coverage = analyze_dispatcher_corridor_coverage(
        pre_graph,
        modifications=(RedirectGoto(from_serial=0, old_target=4, new_target=20),),
        dispatcher_entry_serial=4,
    )
    assert coverage.enumeration_complete
    assert {
        tuple(anchor.serial for anchor in corridor.path)
        for corridor in coverage.covered_corridors
    } == {(0, 4), (21, 4)}
    assert all(
        len({(anchor.serial, anchor.ea) for anchor in corridor.path})
        == len(corridor.path)
        for corridor in coverage.covered_corridors
    )

    analysis = build_detached_dead_handler_component_analysis(
        pre_graph,
        post_graph=post_graph,
        coverage=coverage,
        authoritative_handler_serials=frozenset({20, 21}),
    )

    assert analysis is not None
    assert {anchor.serial for anchor in analysis.dead_handlers} == {21}
    assert {anchor.serial for anchor in analysis.retained_handlers} == {20}
    assert {anchor.serial for anchor in analysis.component} == {21}


def _detached_dead_handler_component_fixture() -> tuple[FlowGraph, FlowGraph, object]:
    """One candidate with a retained handler and a dead handler island."""
    state = MopSnapshot(kind=OperandKind.STACK, stkoff=40, size=4)
    branch = InsnSnapshot(
        opcode=42,
        ea=0x1200,
        operands=(),
        l=state,
        r=MopSnapshot(kind=OperandKind.NUMBER, value=7, size=4),
        d=MopSnapshot(kind=OperandKind.BLOCK, block_ref=21),
        kind=InsnKind.COND_JUMP,
        predicate_kind=PredicateKind.EQ,
    )
    dead_local_write = InsnSnapshot(
        opcode=1,
        ea=0x1310,
        operands=(),
        l=MopSnapshot(kind=OperandKind.NUMBER, value=1, size=4),
        d=MopSnapshot(kind=OperandKind.REGISTER, reg=8, size=4),
        kind=InsnKind.MOV,
        value_op_kind=ValueOpKind.MOVE,
    )
    move_state = InsnSnapshot(
        opcode=2,
        ea=0x1320,
        operands=(),
        l=MopSnapshot(kind=OperandKind.NUMBER, value=9, size=4),
        d=state,
        kind=InsnKind.MOV,
        value_op_kind=ValueOpKind.MOVE,
    )
    pre_graph = FlowGraph(
        blocks={
            0: _block(0, (10, 12), (), 0x1000, kind=BlockKind.N_WAY),
            10: _block(10, (123,), (0,), 0x1010, kind=BlockKind.ONE_WAY),
            12: _block(12, (112,), (0,), 0x1020, kind=BlockKind.ONE_WAY),
            123: _block(123, (3,), (10,), 0x1100, kind=BlockKind.ONE_WAY),
            3: _block(3, (4,), (123,), 0x1110, kind=BlockKind.ONE_WAY),
            112: _block(112, (4,), (12,), 0x1120, kind=BlockKind.ONE_WAY),
            4: _block(
                4,
                (20, 21),
                (3, 112, 113),
                0x1200,
                kind=BlockKind.TWO_WAY,
                insns=(branch,),
            ),
            20: _block(20, (), (4,), 0x1300, kind=BlockKind.STOP),
            21: _block(
                21,
                (113,),
                (4,),
                0x1310,
                kind=BlockKind.ONE_WAY,
                insns=(dead_local_write,),
            ),
            113: _block(
                113,
                (4,),
                (21,),
                0x1320,
                kind=BlockKind.ONE_WAY,
                insns=(move_state,),
            ),
        },
        entry_serial=0,
        func_ea=0x1000,
    )
    coverage = analyze_dispatcher_corridor_coverage(
        pre_graph,
        modifications=(
            RedirectGoto(from_serial=10, old_target=123, new_target=20),
            RedirectGoto(from_serial=12, old_target=112, new_target=20),
            RedirectGoto(from_serial=21, old_target=113, new_target=20),
        ),
        dispatcher_entry_serial=4,
    )
    assert coverage.enumeration_complete
    assert {
        tuple(anchor.serial for anchor in corridor.path)
        for corridor in coverage.covered_corridors
    } == {(0, 10, 123, 3, 4), (0, 12, 112, 4), (21, 113, 4)}
    assert all(
        len({(anchor.serial, anchor.ea) for anchor in corridor.path})
        == len(corridor.path)
        for corridor in coverage.covered_corridors
    )
    post_graph = _replace_observed_edges(
        pre_graph,
        {
            **{
                serial: tuple(block.succs)
                for serial, block in pre_graph.blocks.items()
            },
            0: (10, 12),
            10: (20,),
            12: (20,),
            21: (20,),
        },
    )
    return pre_graph, post_graph, coverage


def test_detached_component_analysis_uses_state_aware_decision_forest(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    pre_graph, post_graph, coverage = _detached_dead_handler_component_fixture()
    monkeypatch.setattr(
        corridor_module,
        "_independent_comparison_dispatcher_region",
        lambda *_args, **_kwargs: frozenset(),
    )

    analysis = build_detached_dead_handler_component_analysis(
        pre_graph,
        post_graph=post_graph,
        coverage=coverage,
        authoritative_handler_serials=frozenset({20, 21}),
    )

    assert analysis is not None
    assert {item.serial for item in analysis.dead_handlers} == {21}
    assert {item.serial for item in analysis.component} == {21, 113}


def test_detached_component_analysis_uses_bounded_pure_control_fallback(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    pre_graph, post_graph, coverage = _detached_dead_handler_component_fixture()
    monkeypatch.setattr(
        corridor_module,
        "_independent_comparison_dispatcher_region",
        lambda *_args, **_kwargs: frozenset(),
    )
    monkeypatch.setattr(
        corridor_module,
        "build_current_u32_decision_forest",
        lambda *_args, **_kwargs: None,
        raising=False,
    )

    analysis = build_detached_dead_handler_component_analysis(
        pre_graph,
        post_graph=post_graph,
        coverage=coverage,
        authoritative_handler_serials=frozenset({20, 21}),
    )

    assert analysis is not None
    assert {item.serial for item in analysis.component} == {21, 113}
