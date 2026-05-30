"""Runtime tests for guarded local state-machine cleanup."""
from __future__ import annotations

from dataclasses import replace

from d810.cfg.flowgraph import (
    BlockSnapshot,
    FlowGraph,
    InsnKind,
    InsnSnapshot,
    MopSnapshot,
    OperandKind,
)
from d810.cfg.graph_modification import RedirectBranch, RedirectGoto
from d810.optimizers.microcode.flow.flattening.engine.snapshot import (
    AnalysisSnapshot,
)
from d810.optimizers.microcode.flow.flattening.engine.strategy import (
    FAMILY_CLEANUP,
)
from d810.optimizers.microcode.flow.flattening.strategies.guarded_state_machine import (
    GuardedStateMachineStrategy,
)
from d810.cfg.guarded_state_machine_planning import (
    build_guarded_state_machine_modifications,
)
from d810.analyses.control_flow.guarded_state_machine import (
    GUARDED_STATE_MACHINE_FIXES_METADATA_KEY,
    GuardedStateMachineFix,
    collect_guarded_state_machine_fixes,
    extract_guarded_state_machine_fixes,
    serialize_guarded_state_machine_fixes,
)


INIT = 0xE5BEDBCA
CHOICE_ONE_OK = 0xF33ADD74
CHOICE_TWO_OK = 0x9B9BBB1B
OK = 0x139CD0CD
SUCCESS = 0x2D02E08C
FAIL = 0x0472A0F40
DEFAULT = 0x0AE16598


def _reg(reg: int) -> MopSnapshot:
    return MopSnapshot(t=1, size=4, reg=reg, kind=OperandKind.REGISTER)


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


def _eq(left: MopSnapshot, right: MopSnapshot, target: int) -> InsnSnapshot:
    return InsnSnapshot(
        opcode=44,
        ea=0x1000,
        operands=(),
        operand_slots=(("l", left), ("r", right), ("d", _blk(target))),
        l=left,
        r=right,
        d=_blk(target),
        kind=InsnKind.EQUALITY_JUMP,
    )


def _cond(left: MopSnapshot, right: MopSnapshot, target: int) -> InsnSnapshot:
    return InsnSnapshot(
        opcode=45,
        ea=0x1000,
        operands=(),
        operand_slots=(("l", left), ("r", right), ("d", _blk(target))),
        l=left,
        r=right,
        d=_blk(target),
        kind=InsnKind.COND_JUMP,
    )


def _unknown() -> InsnSnapshot:
    return InsnSnapshot(opcode=99, ea=0x1000, operands=())


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


def _guarded_cfg(
    *,
    extra_inner_guard_pred: bool = False,
    extra_init_pred: bool = False,
) -> FlowGraph:
    range_value = _reg(1)
    state = _reg(20)
    choice_one = _reg(10)
    choice_two = _reg(11)
    copied_state = _reg(31)
    blocks = {
        67: _block(67, (68,), ()),
        68: _block(
            68,
            (69, 70),
            (67,),
            _mov(_num(DEFAULT), choice_one),
            _cond(range_value, _num(0xAAAA), 70),
        ),
        69: _block(69, (70,), (68,), _mov(_num(CHOICE_ONE_OK), choice_one)),
        70: _block(
            70,
            (71, 72),
            (68, 69) + ((99,) if extra_inner_guard_pred else ()),
            _mov(_num(DEFAULT), choice_two),
            _cond(range_value, _num(0xBBBB), 72),
        ),
        71: _block(71, (72,), (70,), _mov(_num(CHOICE_TWO_OK), choice_two)),
        72: _block(
            72,
            (74,),
            (70, 71) + ((98,) if extra_init_pred else ()),
            _mov(_num(INIT), state),
        ),
        73: _block(73, (74,), (76,), _mov(_num(OK), state)),
        74: _block(74, (75, 78), (72, 73, 77, 78, 79, 80, 82)),
        75: _block(75, (76, 81), (74,)),
        76: _block(
            76,
            (77, 73),
            (75,),
            _eq(state, _num(CHOICE_ONE_OK), 73),
        ),
        77: _block(77, (74,), (76,), _mov(_num(FAIL), state)),
        78: _block(
            78,
            (79, 74),
            (74,),
            _mov(choice_one, state),
            _eq(copied_state, _num(CHOICE_TWO_OK), 74),
        ),
        79: _block(
            79,
            (80, 74),
            (78,),
            _mov(copied_state, state),
            _eq(copied_state, _num(INIT), 74),
        ),
        80: _block(80, (74,), (79,), _mov(choice_two, state)),
        81: _block(81, (82, 83), (75,), _eq(state, _num(OK), 83)),
        82: _block(82, (74,), (81,), _mov(_num(SUCCESS), state)),
        83: _block(83, (84, 86), (81,), _eq(state, _num(SUCCESS), 86)),
        84: _block(84, (), (83,), _unknown()),
        86: _block(86, (87,), (83,)),
        87: _block(87, (), (86,)),
    }
    if extra_inner_guard_pred:
        blocks[99] = _block(99, (70,), ())
    if extra_init_pred:
        blocks[98] = _block(98, (72,), ())
    return FlowGraph(blocks=blocks, entry_serial=67, func_ea=0x1000)


def _inline_choice_guarded_cfg() -> FlowGraph:
    range_value = _reg(1)
    state = _reg(20)
    choice_one = _reg(10)
    choice_two = _reg(11)
    copied_state = _reg(31)
    blocks = {
        97: _block(97, (98,), ()),
        98: _block(
            98,
            (99, 100),
            (97,),
            _mov(_num(CHOICE_ONE_OK), choice_one),
            _cond(range_value, _num(0xAAAA), 100),
        ),
        99: _block(99, (100,), (98,), _mov(_num(DEFAULT), choice_one)),
        100: _block(
            100,
            (101, 102),
            (98, 99),
            _mov(_num(DEFAULT), choice_two),
            _cond(range_value, _num(0xBBBB), 102),
        ),
        101: _block(101, (102,), (100,), _mov(_num(CHOICE_TWO_OK), choice_two)),
        102: _block(
            102,
            (104,),
            (100, 101),
            _mov(_num(INIT), state),
        ),
        103: _block(103, (104,), (106,), _mov(_num(OK), state)),
        104: _block(104, (105, 108), (102, 103, 107, 108, 109, 110, 112)),
        105: _block(105, (106, 111), (104,)),
        106: _block(
            106,
            (107, 103),
            (105,),
            _eq(state, _num(CHOICE_ONE_OK), 103),
        ),
        107: _block(107, (104,), (106,), _mov(_num(FAIL), state)),
        108: _block(
            108,
            (109, 104),
            (104,),
            _mov(choice_one, state),
            _eq(copied_state, _num(CHOICE_TWO_OK), 104),
        ),
        109: _block(
            109,
            (110, 104),
            (108,),
            _mov(copied_state, state),
            _eq(copied_state, _num(INIT), 104),
        ),
        110: _block(110, (104,), (109,), _mov(choice_two, state)),
        111: _block(111, (112, 113), (105,), _eq(state, _num(OK), 113)),
        112: _block(112, (104,), (111,), _mov(_num(SUCCESS), state)),
        113: _block(113, (114, 116), (111,), _eq(state, _num(SUCCESS), 116)),
        114: _block(114, (), (113,), _unknown()),
        116: _block(116, (117,), (113,)),
        117: _block(117, (), (116,)),
    }
    return FlowGraph(blocks=blocks, entry_serial=97, func_ea=0x1000)


def test_guarded_state_machine_strategy_has_expected_identity() -> None:
    strategy = GuardedStateMachineStrategy()

    assert strategy.name == "guarded_state_machine"
    assert strategy.family == FAMILY_CLEANUP


def test_collect_guarded_state_machine_fixes_proves_local_shell() -> None:
    cfg = _guarded_cfg()

    assert collect_guarded_state_machine_fixes(cfg) == (
        GuardedStateMachineFix(
            outer_guard_block=68,
            outer_guard_old_target=70,
            inner_guard_block=70,
            inner_guard_old_target=72,
            inner_override_block=71,
            inner_override_old_target=72,
            invalid_target=84,
            success_target=86,
        ),
    )


def test_guarded_state_machine_strategy_plans_redirects() -> None:
    cfg = _guarded_cfg()
    fixes = collect_guarded_state_machine_fixes(cfg)
    cfg = replace(
        cfg,
        metadata={
            GUARDED_STATE_MACHINE_FIXES_METADATA_KEY: (
                serialize_guarded_state_machine_fixes(fixes)
            )
        },
    )

    fragment = GuardedStateMachineStrategy().plan(
        AnalysisSnapshot(mba=object(), flow_graph=cfg),
    )

    assert fragment is not None
    assert fragment.metadata[GUARDED_STATE_MACHINE_FIXES_METADATA_KEY] == (
        serialize_guarded_state_machine_fixes(fixes)
    )
    assert fragment.metadata["safeguard_min_required"] == 1
    assert fragment.ownership.blocks == frozenset({68, 70, 71})
    assert fragment.ownership.edges == frozenset({(68, 70), (70, 72), (71, 72)})
    assert fragment.modifications == [
        RedirectBranch(from_serial=70, old_target=72, new_target=84),
        RedirectGoto(from_serial=71, old_target=72, new_target=86),
        RedirectBranch(from_serial=68, old_target=70, new_target=84),
    ]


def test_collect_guarded_state_machine_fixes_proves_inline_choice_shell() -> None:
    cfg = _inline_choice_guarded_cfg()

    assert collect_guarded_state_machine_fixes(cfg) == (
        GuardedStateMachineFix(
            outer_guard_block=98,
            outer_guard_old_target=99,
            inner_guard_block=100,
            inner_guard_old_target=102,
            inner_override_block=101,
            inner_override_old_target=102,
            invalid_target=114,
            success_target=116,
        ),
    )


def test_guarded_state_machine_strategy_plans_inline_choice_redirects() -> None:
    cfg = _inline_choice_guarded_cfg()
    fixes = collect_guarded_state_machine_fixes(cfg)
    cfg = replace(
        cfg,
        metadata={
            GUARDED_STATE_MACHINE_FIXES_METADATA_KEY: (
                serialize_guarded_state_machine_fixes(fixes)
            )
        },
    )

    fragment = GuardedStateMachineStrategy().plan(
        AnalysisSnapshot(mba=object(), flow_graph=cfg),
    )

    assert fragment is not None
    assert fragment.ownership.blocks == frozenset({98, 100, 101})
    assert fragment.ownership.edges == frozenset({(98, 99), (100, 102), (101, 102)})
    assert fragment.modifications == [
        RedirectBranch(from_serial=100, old_target=102, new_target=114),
        RedirectGoto(from_serial=101, old_target=102, new_target=116),
        RedirectBranch(from_serial=98, old_target=99, new_target=114),
    ]


def test_guarded_state_machine_strategy_drops_invalid_metadata() -> None:
    cfg = _guarded_cfg()
    cfg = replace(
        cfg,
        metadata={
            GUARDED_STATE_MACHINE_FIXES_METADATA_KEY: (
                {
                    "outer_guard_block": 68,
                    "outer_guard_old_target": 999,
                    "inner_guard_block": 70,
                    "inner_guard_old_target": 72,
                    "inner_override_block": 71,
                    "inner_override_old_target": 72,
                    "invalid_target": 84,
                    "success_target": 86,
                },
            )
        },
    )

    assert extract_guarded_state_machine_fixes(cfg) == ()
    assert GuardedStateMachineStrategy().plan(
        AnalysisSnapshot(mba=object(), flow_graph=cfg),
    ) is None


def test_guarded_state_machine_strategy_drops_stale_but_well_formed_metadata() -> None:
    cfg = _guarded_cfg()
    cfg = replace(
        cfg,
        metadata={
            GUARDED_STATE_MACHINE_FIXES_METADATA_KEY: (
                {
                    "outer_guard_block": 68,
                    "outer_guard_old_target": 69,
                    "inner_guard_block": 70,
                    "inner_guard_old_target": 72,
                    "inner_override_block": 71,
                    "inner_override_old_target": 72,
                    "invalid_target": 84,
                    "success_target": 87,
                },
            )
        },
    )

    assert extract_guarded_state_machine_fixes(cfg) == ()
    assert GuardedStateMachineStrategy().plan(
        AnalysisSnapshot(mba=object(), flow_graph=cfg),
    ) is None


def test_collect_guarded_state_machine_rejects_extra_predecessors() -> None:
    assert collect_guarded_state_machine_fixes(
        _guarded_cfg(extra_inner_guard_pred=True)
    ) == ()
    assert collect_guarded_state_machine_fixes(
        _guarded_cfg(extra_init_pred=True)
    ) == ()


def test_build_guarded_state_machine_modifications_emits_deferred_shape() -> None:
    modifications = build_guarded_state_machine_modifications(
        (
            GuardedStateMachineFix(
                outer_guard_block=68,
                outer_guard_old_target=70,
                inner_guard_block=70,
                inner_guard_old_target=72,
                inner_override_block=71,
                inner_override_old_target=72,
                invalid_target=84,
                success_target=86,
            ),
        )
    )

    assert modifications == [
        RedirectBranch(from_serial=70, old_target=72, new_target=84),
        RedirectGoto(from_serial=71, old_target=72, new_target=86),
        RedirectBranch(from_serial=68, old_target=70, new_target=84),
    ]
