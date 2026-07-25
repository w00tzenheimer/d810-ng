"""unflatten pass #1: portable equality-chain dispatcher detection over a FlowGraph.

Hand-port of HodurStateMachineDetector — verifies state_const -> handler routing (EQ -> jump
target, NE -> fall-through), dominant-state-variable selection, and the StateDispatcherMap the
downstream passes consume.
"""

from __future__ import annotations

from d810.ir.flowgraph import (
    BlockSnapshot,
    FlowGraph,
    InsnKind,
    InsnSnapshot,
    MopSnapshot,
    OperandKind,
)
from d810.ir.semantics import PredicateKind
from d810.analyses.control_flow.dispatcher_recovery import (
    _augment_residual_equality_rows,
    _recover_computed_goto_loop_header,
    build_state_dispatcher_map_from_flow_graph,
    recover_dispatcher,
    recover_entry_dominated_initial_state,
)
from d810.analyses.control_flow.dispatcher_resolution import (
    StateDispatcherMap,
    StateDispatcherRow,
)
from d810.analyses.control_flow.materialized_indirect_transfer import (
    MaterializedIndirectTransfer,
)
from d810.capabilities.dispatcher import RouterKind

C1 = 0x10000001
C2 = 0x10000002
STATE_OFF = 0x3C
INIT_STATE = 0xF6A1F  # the true prologue initial state (approov-shaped)


def _ne_check(const: int, target: int) -> InsnSnapshot:
    """jnz state, const, target  (NE: jump when state != const)."""
    l = MopSnapshot(kind=OperandKind.STACK, stkoff=STATE_OFF, size=4)
    r = MopSnapshot(kind=OperandKind.NUMBER, value=const, size=4)
    d = MopSnapshot(kind=OperandKind.BLOCK, block_ref=target)
    return InsnSnapshot(
        opcode=1,
        ea=0x1000,
        operands=(l, r, d),
        l=l,
        r=r,
        d=d,
        kind=InsnKind.EQUALITY_JUMP,
        branch_predicate=PredicateKind.NE,
        is_conditional_jump=True,
    )


def _blk(serial, succs, preds, tail=None) -> BlockSnapshot:
    return BlockSnapshot(
        serial=serial,
        block_type=1,
        succs=succs,
        preds=preds,
        flags=0,
        start_ea=0x1000 + serial,
        insn_snapshots=(tail,) if tail is not None else (),
        tail_opcode=tail.opcode if tail is not None else None,
    )


def _chain_graph() -> FlowGraph:
    # 0: jnz state,C1,2  (state==C1 -> fallthrough 1=handler; else -> 2)
    # 2: jnz state,C2,4  (state==C2 -> fallthrough 3=handler; else -> 4=exit)
    # 1,3 handlers ; 4 exit
    return FlowGraph(
        blocks={
            0: _blk(0, (1, 2), (), _ne_check(C1, 2)),
            1: _blk(1, (), (0,)),
            2: _blk(2, (3, 4), (0,), _ne_check(C2, 4)),
            3: _blk(3, (), (2,)),
            4: _blk(4, (), (2,)),
        },
        entry_serial=0,
        func_ea=0x1000,
    )


def test_detects_equality_chain_and_routes_states_to_handlers():
    dmap = build_state_dispatcher_map_from_flow_graph(_chain_graph())
    assert dmap is not None
    assert dmap.resolve_target(C1) == 1  # NE: state==C1 -> fall-through handler
    assert dmap.resolve_target(C2) == 3
    assert dmap.resolve_target(0xDEAD) is None
    assert dmap.state_var_stkoff == STATE_OFF
    assert dmap.state_to_handler() == {C1: 1, C2: 3}


def test_recovery_adds_unique_live_residual_equality_row_without_overriding_rows():
    graph = _chain_graph()
    residual = MaterializedIndirectTransfer(
        source_jmp_ea=0xDEAD,
        source_block_ea=0xBEEF,
        materialized_anchor_eas=(0xBEEF,),
        target_eas=(0x1003, 0x1004),
        condition_code=4,
        true_target_ea=0x1003,
        false_target_ea=0x1004,
        selector_state_constant=0x10000003,
        resolver_kind="residual_microcode",
    )

    recovery = recover_dispatcher(
        graph, None, materialized_indirect_transfers=(residual,)
    )

    assert recovery.dispatch_map is not None
    assert recovery.dispatch_map.resolve_target(0x10000003) == 3
    assert recovery.dispatch_map.resolve_target(C1) == 1


def test_recovery_restores_missing_condition_chain_handler_from_live_evidence():
    graph = _chain_graph()
    blocks = dict(graph.blocks)
    # Remove the C2 equality comparator while retaining its handler block at a
    # stable native EA, mirroring a CALLS redo that folded one BST leaf.
    blocks[2] = _blk(2, (4,), (0,))
    reduced = FlowGraph(blocks=blocks, entry_serial=0, func_ea=0x1000)
    evidence = MaterializedIndirectTransfer(
        source_jmp_ea=0x1002,
        source_block_ea=0x1002,
        materialized_anchor_eas=(),
        target_eas=(blocks[3].start_ea,),
        selector_state_constant=C2,
        resolver_kind="condition_chain_handler_evidence",
    )

    recovery = recover_dispatcher(
        reduced, None, materialized_indirect_transfers=(evidence,)
    )

    assert recovery.dispatch_map is not None
    assert recovery.dispatch_map.resolve_target(C1) == 1
    assert recovery.dispatch_map.resolve_target(C2) == 3


def test_recovery_promotes_exact_static_equality_route_into_dispatch_map():
    graph = _chain_graph()
    exit_state = 0xEC71CA67
    exact_route = MaterializedIndirectTransfer(
        source_jmp_ea=0x5000,
        source_block_ea=0x4FF0,
        materialized_anchor_eas=(0x5000,),
        target_eas=(graph.blocks[4].start_ea,),
        selector_state_constant=exit_state,
        resolver_kind="static_equality_route",
    )

    recovery = recover_dispatcher(
        graph, None, materialized_indirect_transfers=(exact_route,)
    )

    assert recovery.dispatch_map is not None
    assert recovery.dispatch_map.resolve_target(exit_state) == 4


def test_resolver_augmentation_recomputes_equality_only_bst_region():
    graph = FlowGraph(
        blocks={
            0: _blk(0, (8,), (1, 2, 40)),
            8: _blk(8, (20, 30), (0,)),
            20: _blk(20, (1, 30), (8,), _ne_check(C1, 30)),
            30: _blk(30, (2, 40), (8, 20), _ne_check(C2, 40)),
            1: _blk(1, (0,), (20,)),
            2: _blk(2, (0,), (30,)),
            40: _blk(40, (0,), (30,)),
        },
        entry_serial=0,
        func_ea=0x1000,
    )
    dmap = StateDispatcherMap(
        rows=(
            StateDispatcherRow(
                C1,
                1,
                20,
                20,
                "ne",
                RouterKind.CONDITION_CHAIN,
            ),
            StateDispatcherRow(
                C2,
                2,
                30,
                30,
                "ne",
                RouterKind.CONDITION_CHAIN,
            ),
        ),
        dispatcher_entry_block=0,
        dispatcher_blocks=frozenset({20, 30}),
        state_var_stkoff=STATE_OFF,
        state_var_lvar_idx=None,
        router_kind=RouterKind.CONDITION_CHAIN,
    )
    evidence = MaterializedIndirectTransfer(
        source_jmp_ea=0x5000,
        source_block_ea=0x4FF0,
        materialized_anchor_eas=(),
        target_eas=(graph.blocks[40].start_ea,),
        selector_state_constant=C2 + 1,
        resolver_kind="static_equality_route",
    )

    augmented = _augment_residual_equality_rows(graph, dmap, (evidence,))

    assert augmented.resolve_target(C2 + 1) == 40
    assert augmented.dispatcher_blocks == frozenset({0, 8, 20, 30})


def test_resolver_evidence_recomputes_region_when_rows_are_already_complete():
    graph = FlowGraph(
        blocks={
            0: _blk(0, (8,), (1, 2)),
            8: _blk(8, (20, 30), (0,)),
            20: _blk(20, (1, 30), (8,), _ne_check(C1, 30)),
            30: _blk(30, (2,), (8, 20), _ne_check(C2, 2)),
            1: _blk(1, (0,), (20,)),
            2: _blk(2, (0,), (30,)),
        },
        entry_serial=0,
        func_ea=0x1000,
    )
    dmap = StateDispatcherMap(
        rows=(
            StateDispatcherRow(
                C1,
                1,
                20,
                20,
                "ne",
                RouterKind.CONDITION_CHAIN,
            ),
            StateDispatcherRow(
                C2,
                2,
                30,
                30,
                "ne",
                RouterKind.CONDITION_CHAIN,
            ),
        ),
        dispatcher_entry_block=0,
        dispatcher_blocks=frozenset({20, 30}),
        state_var_stkoff=STATE_OFF,
        state_var_lvar_idx=None,
        router_kind=RouterKind.CONDITION_CHAIN,
    )
    evidence = MaterializedIndirectTransfer(
        source_jmp_ea=0x5000,
        source_block_ea=0x4FF0,
        materialized_anchor_eas=(),
        target_eas=(graph.blocks[2].start_ea,),
        selector_state_constant=C2,
        resolver_kind="static_equality_route",
    )

    confirmed = _augment_residual_equality_rows(graph, dmap, (evidence,))

    assert confirmed.rows == dmap.rows
    assert confirmed.dispatcher_blocks == frozenset({0, 8, 20, 30})


def test_small_constants_are_not_state_checks():
    # a conditional jump against a tiny constant must not be treated as a dispatcher row
    blk0 = _blk(0, (1, 2), (), _ne_check(3, 2))  # const 3 << MIN_STATE_CONSTANT
    g = FlowGraph(
        blocks={0: blk0, 1: _blk(1, (), (0,)), 2: _blk(2, (), (0,))},
        entry_serial=0,
        func_ea=0x1000,
    )
    assert build_state_dispatcher_map_from_flow_graph(g) is None


def _chain_with_loop_head_graph() -> FlowGraph:
    # Mirror the live OLLVM shape: a dispatcher LOOP HEAD (blk 10) the handler tails back-edge to,
    # followed by the equality-comparator chain (11 -> 12). The comparators each have in-degree 1
    # (reached only from the previous link); blk 10 has the high fan-in (entry + every handler).
    #   0 entry -> 10
    #   10 loop head -> 11               preds = {0, 1, 3}   (handlers loop back here)
    #   11 jnz state,C1,12  -> (1, 12)   handler 1 / next comparator 12
    #   12 jnz state,C2,13  -> (3, 13)   handler 3 / exit 13
    #   1,3 handlers -> 10               (back-edge to the loop head)
    #   13 exit
    return FlowGraph(
        blocks={
            0: _blk(0, (10,), ()),
            10: _blk(10, (11,), (0, 1, 3)),
            11: _blk(11, (1, 12), (10,), _ne_check(C1, 12)),
            12: _blk(12, (3, 13), (11,), _ne_check(C2, 13)),
            1: _blk(1, (10,), (11,)),
            3: _blk(3, (10,), (12,)),
            13: _blk(13, (), (12,)),
        },
        entry_serial=0,
        func_ea=0x1000,
    )


def test_dispatcher_entry_is_loop_head_not_midchain_comparator():
    # Regression: the entry must be the loop head the handlers converge on (blk 10, in-degree 3),
    # NOT an arbitrary low-in-degree mid-chain comparator (11/12). Ranking only ``chain_blocks`` by
    # in-degree picks a comparator; the dominator-walk from the function entry recovers the true head.
    dmap = build_state_dispatcher_map_from_flow_graph(_chain_with_loop_head_graph())
    assert dmap is not None
    assert dmap.resolve_target(C1) == 1
    assert dmap.resolve_target(C2) == 3
    assert dmap.dispatcher_entry_block == 10
    assert (
        10 not in dmap.dispatcher_blocks
    )  # the head is not itself a state-comparison block


def test_computed_goto_loop_header_accepts_direct_two_way_redispatch_hub():
    # A staged entry bridge can make the equality leaves return directly to the
    # native two-way BST root.  The common successor is then already the loop
    # header; following one of its two range-navigation arms would be wrong.
    graph = FlowGraph(
        blocks={
            1: _blk(1, (11, 10), (), _ne_check(C1, 10)),
            2: _blk(2, (12, 10), (), _ne_check(C2, 10)),
            3: _blk(3, (13, 10), (), _ne_check(C2 + 1, 10)),
            10: _blk(10, (20, 30), (1, 2, 3)),
            11: _blk(11, (), (1,)),
            12: _blk(12, (), (2,)),
            13: _blk(13, (), (3,)),
            20: _blk(20, (), (10,)),
            30: _blk(30, (), (10,)),
        },
        entry_serial=1,
        func_ea=0x1000,
    )

    assert (
        _recover_computed_goto_loop_header(graph, frozenset({1, 2, 3}), fallback=1)
        == 10
    )


def test_computed_goto_loop_header_prefers_state_write_successor_of_two_way_funnel():
    """A busy BST funnel is not the handler-tail transition hub."""
    state_write = InsnSnapshot(
        opcode=2,
        ea=0x2200,
        operands=(
            MopSnapshot(kind=OperandKind.NUMBER, value=C1, size=4),
            MopSnapshot(kind=OperandKind.REGISTER, reg=REG_SV, size=4),
        ),
        l=MopSnapshot(kind=OperandKind.NUMBER, value=C1, size=4),
        d=MopSnapshot(kind=OperandKind.REGISTER, reg=REG_SV, size=4),
        kind=InsnKind.MOV,
    )
    graph = FlowGraph(
        blocks={
            1: _blk(1, (11, 10), (), _reg_ne_check(C1, 10)),
            2: _blk(2, (12, 10), (), _reg_ne_check(C2, 10)),
            3: _blk(3, (13, 10), (), _reg_ne_check(C2 + 1, 10)),
            10: _blk(10, (20, 30), (1, 2, 3)),
            11: _blk(11, (), (1,)),
            12: _blk(12, (), (2,)),
            13: _blk(13, (), (3,)),
            20: _blk(20, (), (10,)),
            30: _blk(30, (20,), (10, 41, 42)),
            41: _blk(41, (30,), (), state_write),
            42: _blk(42, (30,), (), state_write),
        },
        entry_serial=1,
        func_ea=0x1000,
    )

    assert (
        _recover_computed_goto_loop_header(
            graph,
            frozenset({1, 2, 3}),
            fallback=1,
            state_identity=("reg", REG_SV),
        )
        == 30
    )


def test_computed_goto_loop_header_keeps_two_way_root_when_both_arms_have_state_writers():
    """Both state-fed arms are BST subtrees, so their parent remains the root."""

    def state_write(ea: int) -> InsnSnapshot:
        return InsnSnapshot(
            opcode=2,
            ea=ea,
            operands=(
                MopSnapshot(kind=OperandKind.NUMBER, value=C1, size=4),
                MopSnapshot(kind=OperandKind.REGISTER, reg=REG_SV, size=4),
            ),
            l=MopSnapshot(kind=OperandKind.NUMBER, value=C1, size=4),
            d=MopSnapshot(kind=OperandKind.REGISTER, reg=REG_SV, size=4),
            kind=InsnKind.MOV,
        )

    graph = FlowGraph(
        blocks={
            1: _blk(1, (11, 10), (), _reg_ne_check(C1, 10)),
            2: _blk(2, (12, 10), (), _reg_ne_check(C2, 10)),
            3: _blk(3, (13, 10), (), _reg_ne_check(C2 + 1, 10)),
            10: _blk(10, (20, 30), (1, 2, 3)),
            11: _blk(11, (), (1,)),
            12: _blk(12, (), (2,)),
            13: _blk(13, (), (3,)),
            20: _blk(20, (), (10, 41, 42)),
            30: _blk(30, (), (10, 43)),
            41: _blk(41, (20,), (), state_write(0x4100)),
            42: _blk(42, (20,), (), state_write(0x4200)),
            43: _blk(43, (30,), (), state_write(0x4300)),
        },
        entry_serial=1,
        func_ea=0x1000,
    )

    assert (
        _recover_computed_goto_loop_header(
            graph,
            frozenset({1, 2, 3}),
            fallback=1,
            state_identity=("reg", REG_SV),
        )
        == 10
    )


def test_dispatcher_entry_prefers_majority_redispatch_hub_over_busy_subtree_root():
    """A high-indegree range subtree is not the whole BST's loop header."""
    graph = FlowGraph(
        blocks={
            0: _blk(0, (134,), ()),
            8: _blk(8, (134, 40), (20, 30, 40)),
            134: _blk(134, (20, 30), (0, 1, 2, 3, 8)),
            20: _blk(20, (1, 8), (134,), _ne_check(C1, 8)),
            30: _blk(30, (2, 8), (134,), _ne_check(C2, 8)),
            40: _blk(40, (3, 8), (8,), _ne_check(C2 + 1, 8)),
            1: _blk(1, (134,), (20,)),
            2: _blk(2, (134,), (30,)),
            3: _blk(3, (134,), (40,)),
        },
        entry_serial=0,
        func_ea=0x1000,
    )

    dmap = build_state_dispatcher_map_from_flow_graph(graph)

    assert dmap is not None
    assert dmap.dispatcher_entry_block == 8
    assert dmap.dispatcher_blocks == frozenset({8, 20, 30, 40, 134})


def test_resolver_handler_augmentation_prunes_handler_body_from_bst_region():
    graph = FlowGraph(
        blocks={
            0: _blk(0, (134,), ()),
            8: _blk(8, (134, 50), (20, 30, 40)),
            134: _blk(134, (20, 30), (0, 1, 2, 3, 8)),
            20: _blk(20, (1, 8), (134,), _ne_check(C1, 8)),
            30: _blk(30, (2, 8), (134,), _ne_check(C2, 8)),
            40: _blk(40, (3, 8), (50,), _ne_check(C2 + 1, 8)),
            50: _blk(50, (40,), (8,)),
            1: _blk(1, (134,), (20,)),
            2: _blk(2, (134,), (30,)),
            3: _blk(3, (134,), (40,)),
        },
        entry_serial=0,
        func_ea=0x1000,
    )
    evidence = MaterializedIndirectTransfer(
        source_jmp_ea=0x5000,
        source_block_ea=0x4FF0,
        materialized_anchor_eas=(),
        target_eas=(graph.blocks[50].start_ea,),
        selector_state_constant=C2 + 2,
        resolver_kind="condition_chain_handler_evidence",
    )

    recovery = recover_dispatcher(
        graph, None, materialized_indirect_transfers=(evidence,)
    )

    assert recovery.dispatch_map is not None
    assert recovery.dispatch_map.resolve_target(C2 + 2) == 50
    assert 50 not in recovery.dispatch_map.dispatcher_blocks


def test_computed_goto_loop_header_follows_one_way_funnel_to_header():
    # Before the staged bridge, the leaves can converge on a one-way funnel
    # whose sole non-chain successor is the actual dispatcher loop header.
    graph = FlowGraph(
        blocks={
            1: _blk(1, (11, 10), (), _ne_check(C1, 10)),
            2: _blk(2, (12, 10), (), _ne_check(C2, 10)),
            3: _blk(3, (13, 10), (), _ne_check(C2 + 1, 10)),
            10: _blk(10, (20,), (1, 2, 3)),
            20: _blk(20, (30, 40), (10,)),
            11: _blk(11, (), (1,)),
            12: _blk(12, (), (2,)),
            13: _blk(13, (), (3,)),
            30: _blk(30, (), (20,)),
            40: _blk(40, (), (20,)),
        },
        entry_serial=1,
        func_ea=0x1000,
    )

    assert (
        _recover_computed_goto_loop_header(graph, frozenset({1, 2, 3}), fallback=1)
        == 20
    )


def test_recover_dispatcher_surfaces_map_and_state_var():
    result = recover_dispatcher(_chain_graph(), facts=None)
    assert result.dispatch_map is not None
    assert result.state_var_stkoff == STATE_OFF
    assert result.dispatch_map.resolve_target(C1) == 1
    # reachability still computed alongside
    assert {0, 1, 2, 3, 4} == set(result.reachable_block_serials)


def _state_init_mov(const: int) -> InsnSnapshot:
    """mov #const -> state_var (the prologue's initial-state write)."""
    l = MopSnapshot(kind=OperandKind.NUMBER, value=const, size=4)
    d = MopSnapshot(kind=OperandKind.STACK, stkoff=STATE_OFF, size=4)
    return InsnSnapshot(
        opcode=2,
        ea=0x2000,
        operands=(l, d),
        l=l,
        d=d,
        kind=InsnKind.MOV,
    )


def _prologue_loop_head_graph() -> FlowGraph:
    # Approov-shaped: a dispatcher LOOP HEAD (blk 10) with TWO predecessors --
    # the entry-reachable PROLOGUE (blk 5, writes the TRUE initial state) and a
    # back-edge handler (blk 1, writes a DECOY next-state const). Entry-dominance
    # must pick the prologue's INIT_STATE, never the back-edge's decoy.
    #   0 entry -> 5
    #   5 prologue (mov #INIT -> state) -> 10
    #   10 loop head -> 11               preds = {5, 1, 3}
    #   11 jnz state,C1,12  -> (1, 12)
    #   12 jnz state,C2,13  -> (3, 13)
    #   1 handler (mov #DECOY -> state) -> 10   (back-edge)
    #   3 handler -> 10                          (back-edge)
    #   13 exit
    decoy = _state_init_mov(0x10000099)
    return FlowGraph(
        blocks={
            0: _blk(0, (5,), ()),
            5: _blk(5, (10,), (0,), _state_init_mov(INIT_STATE)),
            10: _blk(10, (11,), (5, 1, 3)),
            11: _blk(11, (1, 12), (10,), _ne_check(C1, 12)),
            12: _blk(12, (3, 13), (11,), _ne_check(C2, 13)),
            1: _blk(1, (10,), (11,), decoy),
            3: _blk(3, (10,), (12,)),
            13: _blk(13, (), (12,)),
        },
        entry_serial=0,
        func_ea=0x1000,
    )


def test_entry_dominance_recovers_prologue_initial_state_not_back_edge():
    g = _prologue_loop_head_graph()
    dmap = build_state_dispatcher_map_from_flow_graph(g)
    assert dmap is not None
    assert dmap.dispatcher_entry_block == 10
    # The entry-dominated pre-header is the prologue (blk 5), reachable WITHOUT
    # traversing the dispatcher; the back-edge handlers (1, 3) are excluded.
    assert recover_entry_dominated_initial_state(g, dmap) == INIT_STATE


def test_recover_dispatcher_threads_entry_dominated_initial_state():
    result = recover_dispatcher(_prologue_loop_head_graph(), facts=None)
    assert result.dispatch_map is not None
    # recover_dispatcher threads the corrected initial state onto the map so the
    # §1a entry bridge prefers it over the spurious condition-chain mid-chain value.
    assert result.dispatch_map.initial_state == INIT_STATE


def test_entry_dominance_bails_when_ambiguous():
    # Two entry-reachable predecessors of the dispatcher entry -> ambiguous (>1
    # candidate) -> fall back to the existing behaviour (None), no correction.
    g = _prologue_loop_head_graph()
    blocks = dict(g.blocks)
    # Make blk 3 an entry-reachable second pre-header (also a direct succ of entry).
    blocks[0] = _blk(0, (5, 3), ())
    blocks[3] = _blk(3, (10,), (12, 0))
    g2 = FlowGraph(blocks=blocks, entry_serial=0, func_ea=0x1000)
    dmap = build_state_dispatcher_map_from_flow_graph(g2)
    assert dmap is not None
    assert recover_entry_dominated_initial_state(g2, dmap) is None


# --- Register-resident state variable (d81-3rja) ----------------------------
# The Rhadamanthys x86 loader (sub_40A560) keeps its CFF state in a REGISTER
# (ebx / mreg 20) that is never spilled to the stack. The equality chain compares
# the register (``jz ebx, #state_const``) and handlers write it (``mov #next, ebx``).
# Recovery must thread the register identity as ``state_var_reg`` so the disjoint
# register-lowering path (gated on ``state_var_reg is not None and
# state_var_stkoff is None``) can rewire it -- while the stack goldens, whose
# ``state_var_stkoff`` resolves to an int, keep ``state_var_reg is None``.

REG_SV = 20  # mreg of ebx in the real loader; arbitrary here (portable)


def _reg_ne_check(const: int, target: int) -> InsnSnapshot:
    """jnz reg, const, target  (NE against a REGISTER-resident state var)."""
    l = MopSnapshot(kind=OperandKind.REGISTER, reg=REG_SV, size=4)
    r = MopSnapshot(kind=OperandKind.NUMBER, value=const, size=4)
    d = MopSnapshot(kind=OperandKind.BLOCK, block_ref=target)
    return InsnSnapshot(
        opcode=1,
        ea=0x1000,
        operands=(l, r, d),
        l=l,
        r=r,
        d=d,
        kind=InsnKind.EQUALITY_JUMP,
        branch_predicate=PredicateKind.NE,
        is_conditional_jump=True,
    )


def _load_stack_state_into_reg(stkoff: int, ea: int) -> InsnSnapshot:
    source = MopSnapshot(kind=OperandKind.STACK, stkoff=stkoff, size=4)
    destination = MopSnapshot(kind=OperandKind.REGISTER, reg=REG_SV, size=4)
    return InsnSnapshot(
        opcode=2,
        ea=ea,
        operands=(source, destination),
        l=source,
        d=destination,
        kind=InsnKind.MOV,
    )


def _reg_chain_graph() -> FlowGraph:
    # Same shape as _chain_graph() but the comparisons key on a REGISTER with no
    # stack home anywhere -> _resolve_state_identity_to_stkoff returns None.
    return FlowGraph(
        blocks={
            0: _blk(0, (1, 2), (), _reg_ne_check(C1, 2)),
            1: _blk(1, (), (0,)),
            2: _blk(2, (3, 4), (0,), _reg_ne_check(C2, 4)),
            3: _blk(3, (), (2,)),
            4: _blk(4, (), (2,)),
        },
        entry_serial=0,
        func_ea=0x1000,
    )


def test_register_state_var_threads_state_var_reg():
    dmap = build_state_dispatcher_map_from_flow_graph(_reg_chain_graph())
    assert dmap is not None
    # Rows are recovered exactly as for the stack chain...
    assert dmap.resolve_target(C1) == 1
    assert dmap.resolve_target(C2) == 3
    assert dmap.state_to_handler() == {C1: 1, C2: 3}
    # ...but the state var is a register with no stack home:
    assert dmap.state_var_stkoff is None
    assert dmap.state_var_reg == REG_SV


def test_register_state_var_is_not_assigned_an_ambiguous_stack_home():
    """One-off loads from precomputed state slots do not make any slot the home.

    Rhadamanthys precomputes several conditional next states on the stack, then
    loads each choice into the long-lived state register from a different
    handler.  Every source has the same frequency, so choosing the first source
    by insertion order misclassifies the register dispatcher as stack-resident.
    """
    graph = FlowGraph(
        blocks={
            0: _blk(0, (1, 2), (), _reg_ne_check(C1, 2)),
            1: _blk(1, (), (0,), _load_stack_state_into_reg(0x40, 0x1100)),
            2: _blk(2, (3, 4), (0,), _reg_ne_check(C2, 4)),
            3: _blk(3, (), (2,), _load_stack_state_into_reg(0x44, 0x1200)),
            4: _blk(4, (), (2,)),
        },
        entry_serial=0,
        func_ea=0x1000,
    )

    dmap = build_state_dispatcher_map_from_flow_graph(graph)

    assert dmap is not None
    assert dmap.state_var_stkoff is None
    assert dmap.state_var_reg == REG_SV


def test_register_state_var_keeps_a_unique_dominant_stack_home():
    graph = FlowGraph(
        blocks={
            0: _blk(0, (1, 2), (), _reg_ne_check(C1, 2)),
            1: _blk(1, (), (0,), _load_stack_state_into_reg(0x40, 0x1100)),
            2: _blk(2, (3, 4), (0,), _reg_ne_check(C2, 4)),
            3: _blk(3, (), (2,), _load_stack_state_into_reg(0x40, 0x1200)),
            4: _blk(4, (), (2,)),
        },
        entry_serial=0,
        func_ea=0x1000,
    )

    dmap = build_state_dispatcher_map_from_flow_graph(graph)

    assert dmap is not None
    assert dmap.state_var_stkoff == 0x40
    assert dmap.state_var_reg is None


def test_recover_dispatcher_surfaces_state_var_reg():
    result = recover_dispatcher(_reg_chain_graph(), facts=None)
    assert result.dispatch_map is not None
    assert result.state_var_stkoff is None
    assert result.state_var_reg == REG_SV


def test_stack_state_var_leaves_state_var_reg_none():
    # Regression guard: the stack chain must keep state_var_reg None so the
    # disjoint register-lowering gate never fires for the proven stack goldens.
    dmap = build_state_dispatcher_map_from_flow_graph(_chain_graph())
    assert dmap is not None
    assert dmap.state_var_stkoff == STATE_OFF
    assert dmap.state_var_reg is None
    result = recover_dispatcher(_chain_graph(), facts=None)
    assert result.state_var_reg is None
