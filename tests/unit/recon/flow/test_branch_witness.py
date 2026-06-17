"""Unit tests for branch witness model and static validation."""
from __future__ import annotations

import pytest

from d810.analyses.control_flow.branch_witness import (
    BranchWitnessAbstain,
    BranchWitnessConflict,
    BranchWitnessMap,
    BranchWitnessProofKind,
    BranchWitnessRow,
    ExactBranchWitness,
    static_witness_for_state,
    resolve_exact_branch_witness,
)
from d810.analyses.control_flow.branch_witness_provider import (
    build_static_equality_chain_witness_map,
)
from d810.analyses.control_flow.dispatcher_resolution import (
    StateDispatcherMap,
    StateDispatcherRow,
)
from d810.capabilities.dispatcher import RouterKind
from d810.ir.flowgraph import (
    BlockSnapshot,
    FlowGraph,
    InsnKind,
    InsnSnapshot,
    MopSnapshot,
    OperandKind,
    PredicateKind,
)
from d810.analyses.control_flow.interval_map import IntervalDispatcher, IntervalRow

_OP_MOV = 4
_OP_JZ = 100
_OP_JNZ = 101
_T_NUM, _T_STK = 2, 4
_STATE = 0x64


def _mov_state(ea, const):
    return InsnSnapshot(
        opcode=_OP_MOV, ea=ea, operands=(),
        l=MopSnapshot(t=_T_NUM, size=4, value=const, kind=OperandKind.NUMBER),
        d=MopSnapshot(t=_T_STK, size=4, stkoff=_STATE, kind=OperandKind.STACK),
        kind=InsnKind.MOV,
    )


def _jz_block(serial, const, taken, fallthrough, preds=(), insns=()):
    """An equality-chain compare block: ``jz [state], const -> taken; fallthrough``."""
    tail = InsnSnapshot(
        opcode=_OP_JZ, ea=0x1000 + serial * 0x40, operands=(),
        l=MopSnapshot(t=_T_STK, size=4, stkoff=_STATE, kind=OperandKind.STACK),
        r=MopSnapshot(t=_T_NUM, size=4, value=const, kind=OperandKind.NUMBER),
        d=MopSnapshot(t=0, size=0, block_ref=taken, kind=OperandKind.BLOCK),
        kind=InsnKind.COND_JUMP,
        branch_predicate=PredicateKind.EQ,
        is_conditional_jump=True,
    )
    return BlockSnapshot(
        serial=serial, block_type=4, succs=(fallthrough, taken),
        preds=tuple(preds), flags=0, start_ea=0x1000 + serial * 0x40,
        insn_snapshots=(*insns, tail),
    )


def _jnz_block(serial, const, taken, fallthrough, preds=(), insns=()):
    """An equality-chain compare block with ``jnz`` semantics.

    The fallthrough is the handler (reached when equal); the jump target is the
    next comparator.
    """
    tail = InsnSnapshot(
        opcode=_OP_JNZ, ea=0x1000 + serial * 0x40, operands=(),
        l=MopSnapshot(t=_T_STK, size=4, stkoff=_STATE, kind=OperandKind.STACK),
        r=MopSnapshot(t=_T_NUM, size=4, value=const, kind=OperandKind.NUMBER),
        d=MopSnapshot(t=0, size=0, block_ref=taken, kind=OperandKind.BLOCK),
        kind=InsnKind.COND_JUMP,
        branch_predicate=PredicateKind.NE,
        is_conditional_jump=True,
    )
    return BlockSnapshot(
        serial=serial, block_type=4, succs=(fallthrough, taken),
        preds=tuple(preds), flags=0, start_ea=0x1000 + serial * 0x40,
        insn_snapshots=(*insns, tail),
    )


def _b(serial, succs, preds=(), insns=()):
    return BlockSnapshot(
        serial=serial, block_type=0, succs=tuple(succs), preds=tuple(preds),
        flags=0, start_ea=0x1000 + serial * 0x40, insn_snapshots=tuple(insns),
    )


class TestStaticWitnessForState:
    def test_eq_witness_records_selected_and_rejected(self):
        """Static EQ witness records selected (taken) and rejected (fallthrough)."""
        # blk2: jz state == 0x10 -> blk10 (handler), fallthrough -> blk3 (next cmp)
        fg = FlowGraph(blocks={
            2: _jz_block(2, 0x10, taken=10, fallthrough=3),
            3: _jz_block(3, 0x20, taken=20, fallthrough=99),
            10: _b(10, (99,), (2,)),
            20: _b(20, (99,), (3,)),
            99: _b(99, (), (10, 20)),
        }, entry_serial=2, func_ea=0x1000)

        row = BranchWitnessRow(
            state=0x10, compare_block=2, predicate="eq", compare_const=0x10,
            selected_successor=10, rejected_successors=(3,),
        )
        witness = static_witness_for_state(fg, row, 0x10, _STATE)
        assert isinstance(witness, ExactBranchWitness)
        assert witness.compare_block == 2
        assert witness.predicate == "eq"
        assert witness.selected_successor == 10  # handler (taken)
        assert witness.rejected_successors == (3,)  # fallthrough
        assert witness.target_block == 10
        assert witness.proof_kind == BranchWitnessProofKind.STATIC_EQUALITY_CHAIN

    def test_eq_witness_not_equal_selects_fallthrough(self):
        """When state != const on EQ row, selected=fallthrough (next comparator)."""
        fg = FlowGraph(blocks={
            2: _jz_block(2, 0x10, taken=10, fallthrough=3),
            3: _jz_block(3, 0x10, taken=10, fallthrough=99),
            10: _b(10, (99,), (2, 3)),
            99: _b(99, (), (10,)),
        }, entry_serial=2, func_ea=0x1000)

        row = BranchWitnessRow(
            state=0x20, compare_block=2, predicate="eq", compare_const=0x10,
            selected_successor=3, rejected_successors=(10,),
        )
        # State 0x20 != 0x10 => selected = fallthrough = 3
        witness = static_witness_for_state(fg, row, 0x20, _STATE)
        assert isinstance(witness, ExactBranchWitness)
        assert witness.selected_successor == 3
        assert witness.target_block == 3

    def test_ne_witness_records_selected_and_rejected(self):
        """Static NE witness records the taken successor when state != const."""
        # blk2: jnz state != 0x10 -> blk3 (next cmp), fallthrough -> blk10 (handler)
        fg = FlowGraph(blocks={
            2: _jnz_block(2, 0x10, taken=3, fallthrough=10),
            3: _jnz_block(3, 0x20, taken=99, fallthrough=20),
            10: _b(10, (99,), (2,)),
            20: _b(20, (99,), (3,)),
            99: _b(99, (), (10, 20)),
        }, entry_serial=2, func_ea=0x1000)

        row = BranchWitnessRow(
            state=0x20, compare_block=2, predicate="ne", compare_const=0x10,
            selected_successor=3, rejected_successors=(10,),
        )
        # 0x20 != 0x10, so the NE branch is taken to the next comparator.
        witness = static_witness_for_state(fg, row, 0x20, _STATE)
        assert isinstance(witness, ExactBranchWitness)
        assert witness.selected_successor == 3
        assert witness.rejected_successors == (10,)
        assert witness.target_block == 3
        assert witness.predicate == "ne"

    def test_stale_row_target_not_successor_returns_abstain(self):
        """Row whose target_block is no longer a block successor returns abstain."""
        fg = FlowGraph(blocks={
            2: _jz_block(2, 0x10, taken=10, fallthrough=3),
            3: _jz_block(3, 0x20, taken=20, fallthrough=99),
            10: _b(10, (99,), ()),
            20: _b(20, (99,), (3,)),
            99: _b(99, (), (10, 20)),
        }, entry_serial=2, func_ea=0x1000)

        # Claim target=100, but blk2's successors are only 10 and 3.
        row = BranchWitnessRow(
            state=0x10, compare_block=2, predicate="eq", compare_const=0x10,
            selected_successor=100, rejected_successors=(3,),
        )
        witness = static_witness_for_state(fg, row, 0x10, _STATE)
        assert isinstance(witness, BranchWitnessAbstain)
        assert "selected_successor_not_a_successor" in witness.reason

    def test_unknown_predicate_returns_abstain(self):
        """Unrecognized branch_kind returns abstain."""
        fg = FlowGraph(blocks={
            2: _jz_block(2, 0x10, taken=10, fallthrough=3),
            10: _b(10, (99,), (2,)),
            99: _b(99, (), (10,)),
            3: _b(3, (99,), (2,)),
        }, entry_serial=2, func_ea=0x1000)

        row = BranchWitnessRow(
            state=0x10, compare_block=2, predicate="lt", compare_const=0x10,
            selected_successor=10, rejected_successors=(3,),
        )
        witness = static_witness_for_state(fg, row, 0x10, _STATE)
        assert isinstance(witness, BranchWitnessAbstain)
        assert "unknown_predicate" in witness.reason

    def test_wrong_state_constant_returns_abstain(self):
        """Row state_const != block comparison constant returns abstain."""
        fg = FlowGraph(blocks={
            2: _jz_block(2, 0x10, taken=10, fallthrough=3),
            10: _b(10, (99,), (2,)),
            3: _b(3, (99,), (2,)),
            99: _b(99, (), (10, 3)),
        }, entry_serial=2, func_ea=0x1000)

        row = BranchWitnessRow(
            state=0x10, compare_block=2, predicate="eq", compare_const=0x99,
            selected_successor=10, rejected_successors=(3,),
        )
        witness = static_witness_for_state(fg, row, 0x10, _STATE)
        assert isinstance(witness, BranchWitnessAbstain)
        assert "state_constant_mismatch" in witness.reason


class TestResolveExactBranchWitness:
    def test_chain_path_resolves_with_intermediate_compare(self):
        """Two-step chain: blk2 (mismatch) -> blk4 (match) -> handler.

        state=0x20: blk2 checks 0x10 (not match, selected=fallthrough=blk4),
        blk4 checks 0x20 (match, selected=taken=blk20). Target handler = blk20.
        """
        fg = FlowGraph(blocks={
            0: _b(0, (2,), ()),
            2: _jz_block(2, 0x10, taken=10, fallthrough=4, preds=(0,), insns=(_mov_state(0x800, 0x20),)),
            4: _jz_block(4, 0x20, taken=20, fallthrough=6, preds=(2,)),
            10: _b(10, (99,), (2,)),
            20: _b(20, (99,), (4,)),
            6: _b(6, (4,), ()),
            99: _b(99, (), (10, 20)),
        }, entry_serial=0, func_ea=0x1000)

        rows = (
            BranchWitnessRow(
                state=0x20, compare_block=2, predicate="eq", compare_const=0x10,
                selected_successor=4, rejected_successors=(10,),
            ),
            BranchWitnessRow(
                state=0x20, compare_block=4, predicate="eq", compare_const=0x20,
                selected_successor=20, rejected_successors=(6,),
            ),
        )
        dispatcher = IntervalDispatcher([
            IntervalRow(lo=0x10, hi=0x11, target=10),
            IntervalRow(lo=0x20, hi=0x21, target=20),
        ])
        branch_witness_map = BranchWitnessMap(
            rows=rows,
            dispatcher_entry_block=2,
            dispatcher_blocks=frozenset((2, 4)),
            state_var_stkoff=_STATE,
            router_kind=RouterKind.CONDITION_CHAIN,
        )
        # Dispatch map: blk2 and blk4 are dispatcher blocks.
        result = resolve_exact_branch_witness(
            fg, dispatcher, 0x20, _STATE,
            branch_witness_map=branch_witness_map,
        )
        assert isinstance(result, tuple)
        assert len(result) == 2
        # First witness: blk2, state 0x20 != 0x10 -> selected=fallthrough=4
        w0 = result[0]
        assert w0.compare_block == 2
        assert w0.selected_successor == 4  # fallthrough (next comparator)
        assert w0.rejected_successors == (10,)  # taken (handler row, not selected)
        assert w0.target_block == 20  # normalized to the endpoint handler
        # Second witness: blk4, state 0x20 == 0x20 -> selected=taken=20
        w1 = result[1]
        assert w1.compare_block == 4
        assert w1.selected_successor == 20  # handler
        assert w1.rejected_successors == (6,)
        assert w1.target_block == 20

    def test_abstains_when_branch_witness_map_missing(self):
        """Without branch-witness rows, static witness abstains."""
        fg = FlowGraph(blocks={
            2: _jz_block(2, 0x10, taken=10, fallthrough=3),
            3: _b(3, (99,), (2,)),
            10: _b(10, (99,), (2,)),
            99: _b(99, (), (3, 10)),
        }, entry_serial=2, func_ea=0x1000)

        dispatcher = IntervalDispatcher([IntervalRow(lo=0x10, hi=0x11, target=10)])
        result = resolve_exact_branch_witness(fg, dispatcher, 0x10, _STATE)
        assert isinstance(result, BranchWitnessAbstain)
        assert "branch_witness_map_required" in result.reason

    def test_abstains_when_state_not_covered(self):
        """State not in IntervalDispatcher -> abstain."""
        fg = FlowGraph(blocks={
            2: _jz_block(2, 0x10, taken=10, fallthrough=3),
            3: _b(3, (99,), (2,)),
            10: _b(10, (99,), (2,)),
            99: _b(99, (), (3, 10)),
        }, entry_serial=2, func_ea=0x1000)

        rows = (
            BranchWitnessRow(
                state=0x10, compare_block=2, predicate="eq", compare_const=0x10,
                selected_successor=10, rejected_successors=(3,),
            ),
        )
        # Empty dispatcher (no rows) -> no lookup.
        dispatcher = IntervalDispatcher([])
        branch_witness_map = BranchWitnessMap(
            rows=rows, dispatcher_entry_block=2, dispatcher_blocks=frozenset((2,)),
            state_var_stkoff=_STATE,
            router_kind=RouterKind.CONDITION_CHAIN,
        )
        result = resolve_exact_branch_witness(
            fg, dispatcher, 0x10, _STATE,
            branch_witness_map=branch_witness_map,
        )
        assert isinstance(result, BranchWitnessAbstain)

    def test_adapter_ignores_stale_endpoint_target_block(self):
        """StateDispatcherMap endpoint rows are not branch proof rows."""
        fg = FlowGraph(blocks={
            2: _jz_block(2, 0x10, taken=10, fallthrough=3),
            3: _b(3, (99,), (2,)),
            10: _b(10, (99,), (2,)),
            99: _b(99, (), (3, 10)),
        }, entry_serial=2, func_ea=0x1000)

        dispatch_map = StateDispatcherMap(
            rows=(
                StateDispatcherRow(
                    state_const=0x10,
                    target_block=777,  # stale endpoint row; not branch proof
                    dispatcher_block=2,
                    compare_block=2,
                    branch_kind="eq",
                    router_kind=RouterKind.CONDITION_CHAIN,
                ),
            ),
            dispatcher_entry_block=2,
            dispatcher_blocks=frozenset((2,)),
            state_var_stkoff=_STATE,
            state_var_lvar_idx=None,
            router_kind=RouterKind.CONDITION_CHAIN,
        )
        branch_witness_map = build_static_equality_chain_witness_map(
            fg, dispatch_map, states=(0x10,)
        )
        assert isinstance(branch_witness_map, BranchWitnessMap)
        assert branch_witness_map.rows[0].selected_successor == 10

        dispatcher = IntervalDispatcher([IntervalRow(lo=0x10, hi=0x11, target=10)])
        result = resolve_exact_branch_witness(
            fg, dispatcher, 0x10, _STATE,
            branch_witness_map=branch_witness_map,
        )
        assert isinstance(result, tuple)
        assert result[0].selected_successor == 10
        assert result[0].target_block == 10

    def test_adapter_abstains_for_non_conditional_chain_maps(self):
        """Switch/indirect/condition-chain maps must not become equality-chain witnesses."""
        fg = FlowGraph(blocks={
            2: _jz_block(2, 0x10, taken=10, fallthrough=3),
            3: _b(3, (99,), (2,)),
            10: _b(10, (99,), (2,)),
            99: _b(99, (), (3, 10)),
        }, entry_serial=2, func_ea=0x1000)
        dispatch_map = StateDispatcherMap(
            rows=(
                StateDispatcherRow(
                    state_const=0x10,
                    target_block=10,
                    dispatcher_block=2,
                    compare_block=None,
                    branch_kind="indirect_jump_table",
                    router_kind=RouterKind.INDIRECT_TABLE,
                ),
            ),
            dispatcher_entry_block=2,
            dispatcher_blocks=frozenset((2,)),
            state_var_stkoff=_STATE,
            state_var_lvar_idx=None,
            router_kind=RouterKind.INDIRECT_TABLE,
        )

        assert build_static_equality_chain_witness_map(fg, dispatch_map) is None

    def test_emulation_without_branch_witness_map_abstains(self):
        """Emulation fallback still needs branch-witness compare-block context."""
        fg = FlowGraph(blocks={
            2: _jz_block(2, 0x10, taken=10, fallthrough=3),
            3: _b(3, (99,), (2,)),
            10: _b(10, (99,), (2,)),
            99: _b(99, (), (3, 10)),
        }, entry_serial=2, func_ea=0x1000)

        dispatcher = IntervalDispatcher([IntervalRow(lo=0x10, hi=0x11, target=10)])

        class _Emu:
            def exact_branch_witness(self, *_args):
                pytest.fail("dispatch-map-free emulation should not be invoked")

        result = resolve_exact_branch_witness(
            fg, dispatcher, 0x10, _STATE, branch_witness_map=None, emu=_Emu()
        )
        assert isinstance(result, BranchWitnessAbstain)
        assert "branch_witness_map_required" in result.reason

    def test_conflicts_when_emulation_disagrees_with_static(self):
        """Exact proof sources that select different successors conflict."""
        fg = FlowGraph(blocks={
            2: _jz_block(2, 0x10, taken=10, fallthrough=3),
            3: _b(3, (99,), (2,)),
            10: _b(10, (99,), (2,)),
            99: _b(99, (), (3, 10)),
        }, entry_serial=2, func_ea=0x1000)

        rows = (
            BranchWitnessRow(
                state=0x10, compare_block=2, predicate="eq", compare_const=0x10,
                selected_successor=10, rejected_successors=(3,),
            ),
        )
        dispatcher = IntervalDispatcher([IntervalRow(lo=0x10, hi=0x11, target=10)])
        branch_witness_map = BranchWitnessMap(
            rows=rows,
            dispatcher_entry_block=2,
            dispatcher_blocks=frozenset((2,)),
            state_var_stkoff=_STATE,
            router_kind=RouterKind.CONDITION_CHAIN,
        )

        class _DisagreeingEmu:
            def exact_branch_witness(self, _fg, compare_block, state, _stkoff):
                return ExactBranchWitness(
                    state=int(state) & 0xFFFFFFFF,
                    compare_block=int(compare_block),
                    predicate="eq",
                    selected_successor=3,
                    rejected_successors=(10,),
                    target_block=3,
                    proof_kind=BranchWitnessProofKind.EMULATION_EXACT,
                    evidence="test_disagreement",
                )

        result = resolve_exact_branch_witness(
            fg, dispatcher, 0x10, _STATE, branch_witness_map=branch_witness_map,
            emu=_DisagreeingEmu(),
        )
        assert isinstance(result, BranchWitnessConflict)
        assert any("selected_successor" in reason for reason in result.reasons)
