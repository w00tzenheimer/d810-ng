"""Runtime tests for local constant-select loop cleanup."""
from __future__ import annotations

from dataclasses import replace

from d810.ir.flowgraph import (
    PredicateKind,
    BlockSnapshot,
    FlowGraph,
    InsnKind,
    InsnSnapshot,
    MopSnapshot,
    OperandKind,
)
from d810.transforms.graph_modification import ConvertToGoto, RedirectBranch, RedirectGoto
from d810.optimizers.microcode.flow.flattening.engine.snapshot import (
    AnalysisSnapshot,
)
from d810.transforms.plan_fragment import FAMILY_CLEANUP
from d810.optimizers.microcode.flow.flattening.strategies.local_select_loop import (
    LocalSelectLoopStrategy,
)
from d810.analyses.control_flow.local_select_loop import (
    LOCAL_SELECT_LOOP_FIXES_METADATA_KEY,
    LocalSelectConvergenceLoopFix,
    LocalSelectDirectExitLoopFix,
    LocalSelectLoopFix,
    LocalSelectTerminalLoopFix,
    collect_local_select_loop_fixes,
    extract_local_select_loop_fixes,
    serialize_local_select_loop_fixes,
)


INIT = 0x1BD0B1A
SELECT = 0xCF87A00D
DONE = 0xBCF37D88


def _reg(reg: int, size: int = 4) -> MopSnapshot:
    return MopSnapshot(t=1, size=size, reg=reg, kind=OperandKind.REGISTER)


def _stack(stkoff: int, size: int = 4) -> MopSnapshot:
    return MopSnapshot(t=5, size=size, stkoff=stkoff, kind=OperandKind.STACK)


def _num(value: int) -> MopSnapshot:
    return MopSnapshot(t=2, size=4, value=value, kind=OperandKind.NUMBER)


def _blk(serial: int) -> MopSnapshot:
    return MopSnapshot(t=7, size=-1, block_ref=serial, kind=OperandKind.BLOCK)


def _mov(src: MopSnapshot, dst: MopSnapshot) -> InsnSnapshot:
    return InsnSnapshot(
        opcode=4,
        ea=0x1000,
        operands=(),
        operand_slots=(("l", src), ("d", dst)),
        l=src,
        d=dst,
        kind=InsnKind.MOV,
    )


def _xdu(src: MopSnapshot, dst: MopSnapshot) -> InsnSnapshot:
    return InsnSnapshot(
        opcode=9,
        ea=0x1000,
        operands=(),
        operand_slots=(("l", src), ("d", dst)),
        l=src,
        d=dst,
        kind=InsnKind.XDU,
    )


def _jz(left: MopSnapshot, right: MopSnapshot, target: int) -> InsnSnapshot:
    return InsnSnapshot(
        opcode=44,
        ea=0x1000,
        operands=(),
        operand_slots=(("l", left), ("r", right), ("d", _blk(target))),
        l=left,
        r=right,
        d=_blk(target),
        kind=InsnKind.EQUALITY_JUMP,
        branch_predicate=PredicateKind.EQ,
    )


def _jnz(left: MopSnapshot, right: MopSnapshot, target: int) -> InsnSnapshot:
    return InsnSnapshot(
        opcode=43,
        ea=0x1000,
        operands=(),
        operand_slots=(("l", left), ("r", right), ("d", _blk(target))),
        l=left,
        r=right,
        d=_blk(target),
        kind=InsnKind.COND_JUMP,
        branch_predicate=PredicateKind.NE,
    )


def _jg(left: MopSnapshot, right: MopSnapshot, target: int) -> InsnSnapshot:
    return InsnSnapshot(
        opcode=49,
        ea=0x1000,
        operands=(),
        operand_slots=(("l", left), ("r", right), ("d", _blk(target))),
        l=left,
        r=right,
        d=_blk(target),
        kind=InsnKind.COND_JUMP,
        branch_predicate=PredicateKind.SGT,
    )


def _call() -> InsnSnapshot:
    return InsnSnapshot(
        opcode=56,
        ea=0x1000,
        operands=(),
        kind=InsnKind.CALL,
        is_call=True,
    )


def _block(
    serial: int,
    succs: tuple[int, ...],
    preds: tuple[int, ...],
    *insns: InsnSnapshot,
) -> BlockSnapshot:
    return BlockSnapshot(
        serial=serial,
        block_type=4 if len(succs) == 2 else 1 if len(succs) == 1 else 2,
        succs=succs,
        preds=preds,
        flags=0,
        start_ea=0x1000 + serial,
        insn_snapshots=tuple(insns),
    )


def _select_loop_cfg(*, widened_previous: bool = False) -> FlowGraph:
    selector = _reg(34)
    state = _reg(36)
    previous = _reg(37, size=8 if widened_previous else 4)
    previous_cmp = _reg(37)
    default_value = _reg(29, 8)
    selected_value = _reg(30, 8)
    output = _reg(35, 8)
    blocks = {
        17: _block(
            17,
            (20,),
            (15, 16),
            _mov(default_value, output),
            _mov(_num(INIT), state),
        ),
        18: _block(18, (19, 20), (20,), _jnz(selector, _num(SELECT), 20)),
        19: _block(
            19,
            (20,),
            (18,),
            _mov(selected_value, output),
            _mov(_num(DONE), state),
        ),
        20: _block(
            20,
            (21, 18),
            (17, 18, 19),
            _xdu(state, previous) if widened_previous else _mov(state, previous),
            _mov(selector, state),
            _jz(previous_cmp, _num(INIT), 18),
        ),
        21: _block(21, (), (20,)),
    }
    return FlowGraph(blocks=blocks, entry_serial=17, func_ea=0x1000)


def _value_select_loop_cfg() -> FlowGraph:
    selector = _reg(34)
    state = _reg(36)
    previous = _reg(37)
    default_value = _reg(29, 8)
    selected_value = _reg(30, 8)
    output = _reg(35, 8)
    blocks = {
        15: _block(15, (16, 17), (), _jnz(_reg(1), _num(1), 17)),
        16: _block(16, (17,), (15,), _mov(_num(SELECT), selector)),
        17: _block(
            17,
            (20,),
            (15, 16),
            _mov(default_value, output),
            _mov(_num(INIT), state),
        ),
        18: _block(18, (19, 20), (20,), _jnz(selector, _num(SELECT), 20)),
        19: _block(
            19,
            (20,),
            (18,),
            _mov(_num(SELECT), selector),
            _mov(selected_value, output),
            _mov(_num(DONE), state),
        ),
        20: _block(
            20,
            (21, 18),
            (17, 18, 19),
            _mov(state, previous),
            _mov(selector, state),
            _jz(previous, _num(INIT), 18),
        ),
        21: _block(21, (), (20,)),
    }
    return FlowGraph(blocks=blocks, entry_serial=15, func_ea=0x1000)


def _convergence_loop_cfg(
    *,
    previous_used_after_exit: bool = False,
    previous_is_stack: bool = False,
    selector_rewritten_in_loop: bool = False,
) -> FlowGraph:
    selector = _reg(33)
    state = _reg(34)
    previous = _stack(0x40) if previous_is_stack else _reg(35)
    sink = _reg(40)
    exit_insns = (_mov(previous, sink),) if previous_used_after_exit else ()
    loop_assignment_insns = (
        (_mov(_num(SELECT), selector), _mov(_num(DONE), state))
        if selector_rewritten_in_loop
        else (_mov(_num(DONE), state),)
    )
    blocks = {
        18: _block(
            18,
            (21,),
            (16, 17),
            _mov(_num(INIT), state),
        ),
        19: _block(
            19,
            (20, 21),
            (21,),
            _jnz(selector, _num(SELECT), 21),
        ),
        20: _block(
            20,
            (21,),
            (19,),
            *loop_assignment_insns,
        ),
        21: _block(
            21,
            (22, 19),
            (18, 19, 20),
            _mov(state, previous),
            _mov(selector, state),
            _jz(previous, _num(INIT), 19),
        ),
        22: _block(22, (), (21,), *exit_insns),
    }
    return FlowGraph(blocks=blocks, entry_serial=18, func_ea=0x1000)


def _terminal_loop_cfg(
    *,
    explicit_exit: bool = False,
    external_exit: bool = False,
    external_continuation: bool = False,
    terminal_frontier: bool = False,
) -> FlowGraph:
    state = _reg(41)
    previous = _reg(42)
    choice_one = _reg(43)
    choice_two = _reg(44)
    header_successors = (38, 41) if explicit_exit else (38, 40)
    blocks = {
        36: _block(
            36,
            (37,),
            (31,) if external_exit or terminal_frontier else (),
            _mov(_num(0xE5BEDBCA), state),
        ),
        37: _block(
            37,
            header_successors,
            (36, 38, 39, 40),
            _mov(state, previous),
            _jg(state, _num(0xF33ADD73), header_successors[1]),
        ),
        38: _block(
            38,
            (39, 37),
            (37,),
            _mov(choice_one, state),
            _jz(previous, _num(0x9B9BBB1B), 37),
        ),
        39: _block(
            39,
            (40, 37),
            (38,),
            _mov(previous, state),
            _jnz(previous, _num(0xE5BEDBCA), 37),
        ),
        40: _block(40, (37,), (37, 39), _mov(choice_two, state)),
    }
    if explicit_exit:
        blocks[41] = _block(41, (), (37,))
    elif external_exit:
        blocks[31] = _block(31, (36, 41), (), _jg(_reg(1), _num(1), 41))
        if external_continuation:
            blocks[41] = _block(41, (42,), (31,))
            blocks[42] = _block(42, (), (41,))
        else:
            blocks[41] = _block(41, (), (31,))
    elif terminal_frontier:
        blocks[31] = _block(31, (36, 50), (), _jg(_reg(1), _num(1), 50))
        blocks[35] = _block(35, (), (), _call())
        blocks[50] = _block(50, (51,), (31,))
        blocks[51] = _block(51, (90,), (50,))
        blocks[90] = _block(90, (), (51,), _call())
    return FlowGraph(blocks=blocks, entry_serial=36, func_ea=0x1000)


def _direct_exit_loop_cfg(*, success_check: bool = False) -> FlowGraph:
    state = _reg(41)
    previous = _reg(42)
    choice_one = _reg(43)
    choice_two = _reg(44)
    header_successors = (38, 41)
    blocks = {
        36: _block(36, (37,), (), _mov(_num(0xE5BEDBCA), state)),
        37: _block(
            37,
            header_successors,
            (36, 38, 39, 40, 42) if success_check else (36, 38, 39, 40),
            _mov(state, previous),
            _jg(state, _num(0xF33ADD73), header_successors[1]),
        ),
        38: _block(
            38,
            (39, 37),
            (37,),
            _mov(choice_one, state),
            _jz(previous, _num(0x9B9BBB1B), 37),
        ),
        39: _block(
            39,
            (40, 37),
            (38,),
            _mov(previous, state),
            _jnz(previous, _num(0xE5BEDBCA), 37),
        ),
        40: _block(40, (37,), (37, 39), _mov(choice_two, state)),
    }
    if success_check:
        blocks[41] = _block(
            41,
            (42, 43),
            (37,),
            _jg(state, _num(0x139CD0CC), 43),
        )
        blocks[42] = _block(42, (37,), (41,), _mov(_num(0x2D02E08C), state))
        blocks[43] = _block(43, (), (41,))
    else:
        blocks[41] = _block(41, (42,), (37,))
        blocks[42] = _block(42, (), (41,))
    return FlowGraph(blocks=blocks, entry_serial=36, func_ea=0x1000)


def test_collect_local_select_loop_fixes_proves_one_iteration_shell() -> None:
    assert collect_local_select_loop_fixes(_select_loop_cfg()) == (
        LocalSelectLoopFix(
            init_block=17,
            init_old_target=20,
            test_block=18,
            test_old_target=20,
            assignment_block=19,
            assignment_old_target=20,
            exit_target=21,
        ),
    )


def test_collect_local_select_loop_fixes_accepts_widened_previous_copy() -> None:
    assert collect_local_select_loop_fixes(
        _select_loop_cfg(widened_previous=True)
    ) == (
        LocalSelectLoopFix(
            init_block=17,
            init_old_target=20,
            test_block=18,
            test_old_target=20,
            assignment_block=19,
            assignment_old_target=20,
            exit_target=21,
        ),
    )


def test_collect_local_select_loop_fixes_proves_dispatch_only_convergence_loop() -> None:
    assert collect_local_select_loop_fixes(_convergence_loop_cfg()) == (
        LocalSelectConvergenceLoopFix(
            init_block=18,
            header_block=21,
            loop_entry_target=19,
            exit_target=22,
        ),
    )


def test_collect_local_select_loop_ignores_selector_bookkeeping_as_payload() -> None:
    assert collect_local_select_loop_fixes(
        _convergence_loop_cfg(selector_rewritten_in_loop=True)
    ) == (
        LocalSelectConvergenceLoopFix(
            init_block=18,
            header_block=21,
            loop_entry_target=19,
            exit_target=22,
        ),
    )


def test_collect_local_select_loop_fixes_rejects_live_previous_temp() -> None:
    assert (
        collect_local_select_loop_fixes(
            _convergence_loop_cfg(
                previous_used_after_exit=True,
                previous_is_stack=True,
            )
        )
        == ()
    )


def test_collect_local_select_loop_allows_physical_register_reuse_after_exit() -> None:
    assert collect_local_select_loop_fixes(
        _convergence_loop_cfg(previous_used_after_exit=True)
    ) == (
        LocalSelectConvergenceLoopFix(
            init_block=18,
            header_block=21,
            loop_entry_target=19,
            exit_target=22,
        ),
    )


def test_local_select_loop_strategy_plans_redirects() -> None:
    cfg = _select_loop_cfg()
    fixes = collect_local_select_loop_fixes(cfg)
    cfg = replace(
        cfg,
        metadata={
            LOCAL_SELECT_LOOP_FIXES_METADATA_KEY: serialize_local_select_loop_fixes(
                fixes
            )
        },
    )

    fragment = LocalSelectLoopStrategy().plan(
        AnalysisSnapshot(mba=object(), flow_graph=cfg),
    )

    assert fragment is not None
    assert fragment.strategy_name == "local_select_loop"
    assert fragment.family == FAMILY_CLEANUP
    assert fragment.ownership.blocks == frozenset({17, 18, 19, 20})
    assert fragment.ownership.edges == frozenset({(17, 20), (18, 20), (19, 20)})
    assert fragment.modifications == [
        RedirectBranch(from_serial=18, old_target=20, new_target=21),
        RedirectGoto(from_serial=19, old_target=20, new_target=21),
        RedirectGoto(from_serial=17, old_target=20, new_target=18),
        ConvertToGoto(block_serial=20, goto_target=21),
    ]


def test_local_select_loop_strategy_materializes_value_select_arms_directly() -> None:
    cfg = _value_select_loop_cfg()
    fixes = collect_local_select_loop_fixes(cfg)
    cfg = replace(
        cfg,
        metadata={
            LOCAL_SELECT_LOOP_FIXES_METADATA_KEY: serialize_local_select_loop_fixes(
                fixes
            )
        },
    )

    fragment = LocalSelectLoopStrategy().plan(
        AnalysisSnapshot(mba=object(), flow_graph=cfg),
    )

    assert fragment is not None
    assert fragment.modifications == [
        RedirectGoto(from_serial=16, old_target=17, new_target=19),
        RedirectGoto(from_serial=17, old_target=20, new_target=21),
        RedirectGoto(from_serial=19, old_target=20, new_target=21),
        ConvertToGoto(block_serial=20, goto_target=21),
        ConvertToGoto(block_serial=18, goto_target=21),
    ]


def test_local_select_loop_strategy_plans_convergence_convert() -> None:
    cfg = _convergence_loop_cfg()
    fixes = collect_local_select_loop_fixes(cfg)
    cfg = replace(
        cfg,
        metadata={
            LOCAL_SELECT_LOOP_FIXES_METADATA_KEY: serialize_local_select_loop_fixes(
                fixes
            )
        },
    )

    fragment = LocalSelectLoopStrategy().plan(
        AnalysisSnapshot(mba=object(), flow_graph=cfg),
    )

    assert fragment is not None
    assert fragment.strategy_name == "local_select_loop"
    assert fragment.family == FAMILY_CLEANUP
    assert fragment.ownership.blocks == frozenset({21})
    assert fragment.ownership.edges == frozenset()
    assert fragment.modifications == [
        ConvertToGoto(block_serial=21, goto_target=22),
    ]


def test_collect_local_select_loop_fixes_proves_closed_terminal_loop() -> None:
    assert collect_local_select_loop_fixes(_terminal_loop_cfg()) == (
        LocalSelectTerminalLoopFix(
            init_block=36,
            init_old_target=37,
            sink_block=40,
            sink_old_target=37,
        ),
    )


def test_local_select_loop_strategy_rejects_unproven_terminal_self_sink() -> None:
    cfg = _terminal_loop_cfg()
    fixes = collect_local_select_loop_fixes(cfg)
    cfg = replace(
        cfg,
        metadata={
            LOCAL_SELECT_LOOP_FIXES_METADATA_KEY: serialize_local_select_loop_fixes(
                fixes
            )
        },
    )

    fragment = LocalSelectLoopStrategy().plan(
        AnalysisSnapshot(mba=object(), flow_graph=cfg),
    )

    assert fragment is None


def test_collect_local_select_loop_fixes_proves_closed_loop_external_exit() -> None:
    assert collect_local_select_loop_fixes(_terminal_loop_cfg(external_exit=True)) == (
        LocalSelectTerminalLoopFix(
            init_block=36,
            init_old_target=37,
            sink_block=40,
            sink_old_target=37,
            exit_target=41,
        ),
    )


def test_local_select_loop_strategy_plans_closed_loop_external_exit() -> None:
    cfg = _terminal_loop_cfg(external_exit=True)
    fixes = collect_local_select_loop_fixes(cfg)
    cfg = replace(
        cfg,
        metadata={
            LOCAL_SELECT_LOOP_FIXES_METADATA_KEY: serialize_local_select_loop_fixes(
                fixes
            )
        },
    )

    fragment = LocalSelectLoopStrategy().plan(
        AnalysisSnapshot(mba=object(), flow_graph=cfg),
    )

    assert fragment is not None
    assert fragment.modifications == [
        RedirectGoto(from_serial=36, old_target=37, new_target=41),
    ]


def test_collect_local_select_loop_rejects_live_external_continuation() -> None:
    assert collect_local_select_loop_fixes(
        _terminal_loop_cfg(external_exit=True, external_continuation=True)
    ) == (
        LocalSelectTerminalLoopFix(
            init_block=36,
            init_old_target=37,
            sink_block=40,
            sink_old_target=37,
        ),
    )


def test_collect_local_select_loop_fixes_proves_reachable_terminal_frontier() -> None:
    assert collect_local_select_loop_fixes(
        _terminal_loop_cfg(terminal_frontier=True)
    ) == (
        LocalSelectTerminalLoopFix(
            init_block=36,
            init_old_target=37,
            sink_block=40,
            sink_old_target=37,
            exit_target=90,
        ),
    )


def test_local_select_loop_strategy_ignores_unreachable_nearby_terminal() -> None:
    cfg = _terminal_loop_cfg(terminal_frontier=True)
    fixes = collect_local_select_loop_fixes(cfg)
    cfg = replace(
        cfg,
        metadata={
            LOCAL_SELECT_LOOP_FIXES_METADATA_KEY: serialize_local_select_loop_fixes(
                fixes
            )
        },
    )

    fragment = LocalSelectLoopStrategy().plan(
        AnalysisSnapshot(mba=object(), flow_graph=cfg),
    )

    assert fragment is not None
    assert fragment.modifications == [
        RedirectGoto(from_serial=36, old_target=37, new_target=90),
    ]


def test_collect_local_select_loop_fixes_proves_terminal_exit_loop() -> None:
    assert collect_local_select_loop_fixes(_terminal_loop_cfg(explicit_exit=True)) == (
        LocalSelectTerminalLoopFix(
            init_block=36,
            init_old_target=37,
            sink_block=40,
            sink_old_target=37,
            exit_target=41,
        ),
    )


def test_local_select_loop_strategy_plans_terminal_exit_loop_redirect() -> None:
    cfg = _terminal_loop_cfg(explicit_exit=True)
    fixes = collect_local_select_loop_fixes(cfg)
    cfg = replace(
        cfg,
        metadata={
            LOCAL_SELECT_LOOP_FIXES_METADATA_KEY: serialize_local_select_loop_fixes(
                fixes
            )
        },
    )

    fragment = LocalSelectLoopStrategy().plan(
        AnalysisSnapshot(mba=object(), flow_graph=cfg),
    )

    assert fragment is not None
    assert fragment.modifications == [
        RedirectGoto(from_serial=36, old_target=37, new_target=41),
    ]


def test_collect_local_select_loop_fixes_proves_direct_exit_loop() -> None:
    assert collect_local_select_loop_fixes(_direct_exit_loop_cfg()) == (
        LocalSelectDirectExitLoopFix(
            init_block=36,
            init_old_target=37,
            header_block=37,
            loop_entry_target=38,
            exit_target=41,
        ),
    )


def test_collect_local_select_loop_fixes_proves_success_check_exit_loop() -> None:
    assert collect_local_select_loop_fixes(
        _direct_exit_loop_cfg(success_check=True)
    ) == (
        LocalSelectDirectExitLoopFix(
            init_block=36,
            init_old_target=37,
            header_block=37,
            loop_entry_target=38,
            exit_target=43,
        ),
    )


def test_local_select_loop_strategy_plans_direct_exit_redirect() -> None:
    cfg = _direct_exit_loop_cfg(success_check=True)
    fixes = collect_local_select_loop_fixes(cfg)
    cfg = replace(
        cfg,
        metadata={
            LOCAL_SELECT_LOOP_FIXES_METADATA_KEY: serialize_local_select_loop_fixes(
                fixes
            )
        },
    )

    fragment = LocalSelectLoopStrategy().plan(
        AnalysisSnapshot(mba=object(), flow_graph=cfg),
    )

    assert fragment is not None
    assert fragment.modifications == [
        RedirectGoto(from_serial=36, old_target=37, new_target=43),
    ]


def test_extract_local_select_loop_fixes_rejects_stale_metadata() -> None:
    cfg = _select_loop_cfg()
    cfg = replace(
        cfg,
        metadata={
            LOCAL_SELECT_LOOP_FIXES_METADATA_KEY: (
                {
                    "init_block": 17,
                    "init_old_target": 99,
                    "test_block": 18,
                    "test_old_target": 20,
                    "assignment_block": 19,
                    "assignment_old_target": 20,
                    "exit_target": 21,
                },
            )
        },
    )

    assert extract_local_select_loop_fixes(cfg) == ()


def test_extract_local_select_loop_fixes_rejects_well_formed_wrong_exit() -> None:
    cfg = _select_loop_cfg()
    cfg = replace(
        cfg,
        metadata={
            LOCAL_SELECT_LOOP_FIXES_METADATA_KEY: (
                {
                    "init_block": 17,
                    "init_old_target": 20,
                    "test_block": 18,
                    "test_old_target": 20,
                    "assignment_block": 19,
                    "assignment_old_target": 20,
                    "exit_target": 18,
                },
            )
        },
    )

    assert extract_local_select_loop_fixes(cfg) == ()
