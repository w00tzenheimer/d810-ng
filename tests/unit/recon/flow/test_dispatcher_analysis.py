from __future__ import annotations

from d810.cfg.flowgraph import (
    BranchPredicate,
    BlockSnapshot,
    FlowGraph,
    InsnKind,
    InsnSnapshot,
    MopSnapshot,
    OperandKind,
)
from d810.analyses.control_flow.dispatcher_analysis import analyze_dispatcher
from d810.analyses.control_flow.dispatcher_facts import DispatcherStrategy
from d810.analyses.control_flow.dispatcher_kind import DispatcherType


def _mop(
    kind: OperandKind,
    *,
    value: int | None = None,
    stkoff: int | None = None,
    reg: int | None = None,
    size: int = 4,
) -> MopSnapshot:
    t_by_kind = {
        OperandKind.NUMBER: 2,
        OperandKind.SUBINSN: 4,
        OperandKind.STACK: 5,
        OperandKind.REGISTER: 1,
    }
    return MopSnapshot(
        t=t_by_kind.get(kind, -1),
        size=size,
        value=value,
        stkoff=stkoff,
        reg=reg,
        kind=kind,
    )


def _number(value: int) -> MopSnapshot:
    return _mop(OperandKind.NUMBER, value=value)


def _stack(offset: int = 0x20) -> MopSnapshot:
    return _mop(OperandKind.STACK, stkoff=offset)


def _insn(
    kind: InsnKind,
    *,
    l: MopSnapshot | None = None,
    r: MopSnapshot | None = None,
    branch_predicate: BranchPredicate | None = None,
) -> InsnSnapshot:
    return InsnSnapshot(
        opcode=0,
        ea=0x401000,
        operands=(),
        l=l,
        r=r,
        kind=kind,
        branch_predicate=branch_predicate,
    )


def _block(
    serial: int,
    *,
    succs: tuple[int, ...] = (),
    preds: tuple[int, ...] = (),
    insns: tuple[InsnSnapshot, ...] = (),
    tail_kind: InsnKind | None = None,
) -> BlockSnapshot:
    return BlockSnapshot(
        serial=serial,
        block_type=0,
        succs=succs,
        preds=preds,
        flags=0,
        start_ea=0x401000 + serial,
        insn_snapshots=insns,
        tail_kind=tail_kind,
    )


def _flow(blocks: list[BlockSnapshot]) -> FlowGraph:
    return FlowGraph(
        blocks={block.serial: block for block in blocks},
        entry_serial=blocks[0].serial,
        func_ea=0x401000,
        metadata={"maturity": 42, "maturity_name": "MMAT_TEST"},
    )


def _comparison_block(serial: int, constant: int) -> BlockSnapshot:
    tail = _insn(
        InsnKind.EQUALITY_JUMP,
        l=_stack(),
        r=_number(constant),
        branch_predicate=BranchPredicate.EQUAL,
    )
    return _block(serial, insns=(tail,))


def test_table_jump_short_circuits_to_switch_table() -> None:
    flow_graph = _flow(
        [_block(0, insns=(_insn(InsnKind.TABLE_JUMP),), tail_kind=InsnKind.TABLE_JUMP)]
    )

    analysis = analyze_dispatcher(flow_graph)

    assert analysis.maturity == 42
    assert analysis.dispatcher_type == DispatcherType.SWITCH_TABLE
    assert analysis.is_switch_table
    assert analysis.blocks == {}
    assert analysis.dispatchers == []


def test_high_fan_in_and_uniform_predecessors_are_ported() -> None:
    pred_blocks = [
        _block(i, succs=(5,), insns=(_insn(InsnKind.GOTO),)) for i in range(5)
    ]
    target = _block(5, preds=tuple(range(5)))
    flow_graph = _flow([*pred_blocks, target])

    analysis = analyze_dispatcher(flow_graph)

    block = analysis.blocks[5]
    assert DispatcherStrategy.HIGH_FAN_IN in block.strategies
    assert DispatcherStrategy.PREDECESSOR_UNIFORM in block.strategies
    assert DispatcherStrategy.SMALL_BLOCK in block.strategies
    assert block.predecessor_count == 5
    assert block.unconditional_pred_count == 5


def test_state_comparisons_pick_most_common_portable_operand() -> None:
    flow_graph = _flow([
        _comparison_block(serial, 0x200 + serial) for serial in range(6)
    ])

    analysis = analyze_dispatcher(flow_graph)

    assert analysis.dispatcher_type == DispatcherType.CONDITIONAL_CHAIN
    assert analysis.state_variable is not None
    assert analysis.state_variable.mop.kind is OperandKind.STACK
    assert analysis.state_variable.mop_offset == 0x20
    assert analysis.state_variable.comparison_count == 6
    assert analysis.state_variable.comparison_blocks == [0, 1, 2, 3, 4, 5]
    assert analysis.state_constants == {
        0x200,
        0x201,
        0x202,
        0x203,
        0x204,
        0x205,
    }
    for serial in range(6):
        block = analysis.blocks[serial]
        assert DispatcherStrategy.STATE_COMPARISON in block.strategies
        assert DispatcherStrategy.CONSTANT_FREQUENCY in block.strategies


def test_initial_state_is_found_from_early_state_assignment() -> None:
    assignment = _insn(InsnKind.MOV, l=_number(0x202), r=_stack())
    blocks = [
        _block(0, insns=(assignment,)),
        *[_comparison_block(serial, 0x200 + serial) for serial in range(1, 7)],
    ]
    flow_graph = _flow(blocks)

    analysis = analyze_dispatcher(flow_graph)

    assert analysis.initial_state == 0x202
    assert analysis.state_variable is not None
    assert analysis.state_variable.init_value == 0x202
    assert 0x202 in analysis.blocks[0].state_constants


def test_nested_loops_classify_conditional_chain_without_constants() -> None:
    flow_graph = _flow([
        _block(0, succs=(0,)),
        _block(1, succs=(0,)),
        _block(2, succs=(1,)),
        _block(3, succs=(2,)),
    ])

    analysis = analyze_dispatcher(flow_graph)

    assert analysis.dispatcher_type == DispatcherType.CONDITIONAL_CHAIN
    assert analysis.nested_loop_depth >= 2
    for serial in (0, 1, 2):
        assert DispatcherStrategy.NESTED_LOOP in analysis.blocks[serial].strategies


def test_previous_conditional_chain_and_persisted_state_are_explicit_inputs() -> None:
    flow_graph = _flow([_block(0)])

    analysis = analyze_dispatcher(
        flow_graph,
        previous_dispatcher_type=DispatcherType.CONDITIONAL_CHAIN,
        persisted_initial_state=0xBEEF,
    )

    assert analysis.dispatcher_type == DispatcherType.CONDITIONAL_CHAIN
    assert analysis.initial_state == 0xBEEF


def test_truthy_conditional_jump_is_not_treated_as_state_comparison() -> None:
    tail = _insn(
        InsnKind.COND_JUMP,
        l=_stack(),
        r=_number(0x200),
        branch_predicate=BranchPredicate.TRUTHY,
    )
    flow_graph = _flow([_block(0, insns=(tail,))])

    analysis = analyze_dispatcher(flow_graph)

    assert analysis.state_variable is None
    assert analysis.state_constants == set()
    assert analysis.dispatcher_type == DispatcherType.UNKNOWN


def test_computed_goto_marks_switch_jump_without_classifying_switch_table() -> None:
    tail = _insn(
        InsnKind.GOTO,
        l=_mop(OperandKind.SUBINSN),
    )
    flow_graph = _flow([_block(0, insns=(tail,))])

    analysis = analyze_dispatcher(flow_graph)

    assert analysis.dispatcher_type == DispatcherType.UNKNOWN
    assert analysis.dispatchers == [0]
    assert DispatcherStrategy.SWITCH_JUMP in analysis.blocks[0].strategies
