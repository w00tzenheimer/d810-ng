from __future__ import annotations

from contextlib import contextmanager
from types import SimpleNamespace

from d810.ir.flowgraph import MopSnapshot, OperandKind
from d810.optimizers.microcode.flow.flattening.hodur.datamodel import (
    DispatcherStateMachine,
    StateHandler,
    StateTransition,
)
from d810.transforms.snapshot import AnalysisSnapshot
from d810.optimizers.microcode.flow.flattening.hodur.recon import (
    conditional_chain_resolution as resolution,
)


class _DummyFlowGraph:
    def __init__(self, blocks: dict[int, object]):
        self._blocks = blocks
        self.block_count = len(blocks)

    def get_block(self, serial: int):
        return self._blocks.get(int(serial))


def _block(
    serial: int,
    *,
    npred: int = 0,
    preds: tuple[int, ...] = (),
    nsucc: int = 0,
    succs: tuple[int, ...] = (),
    tail_opcode: int | None = None,
    tail: object | None = None,
):
    return SimpleNamespace(
        serial=serial,
        npred=npred,
        preds=preds,
        nsucc=nsucc,
        succs=succs,
        tail_opcode=tail_opcode,
        tail=tail,
    )


def _numeric_check_tail(*, opcode: int, check_value: int, jump_target: int):
    return SimpleNamespace(
        opcode=opcode,
        l=SimpleNamespace(t=0),
        r=MopSnapshot(kind=OperandKind.NUMBER, value=check_value, size=4),
        d=MopSnapshot(kind=OperandKind.BLOCK, block_ref=jump_target),
    )


@contextmanager
def _replaced_attr(obj: object, name: str, value: object):
    original = getattr(obj, name)
    setattr(obj, name, value)
    try:
        yield
    finally:
        setattr(obj, name, original)


def _snapshot(*, flow_graph: object, transitions: list[StateTransition], handlers: dict[int, StateHandler]):
    sm = DispatcherStateMachine(
        mba=SimpleNamespace(entry_ea=0x401000, maturity=1),
        state_var=SimpleNamespace(name="state"),
        handlers=handlers,
        transitions=transitions,
    )
    return AnalysisSnapshot(
        mba=sm.mba,
        state_machine=sm,
        detector=None,
        flow_graph=flow_graph,
    )


def test_collect_conditional_fork_resolution_candidates_static_chain():
    fg = _DummyFlowGraph(
        {
            10: _block(10, npred=1, preds=(5,)),
            5: _block(
                5,
                nsucc=2,
                succs=(20, 21),
                tail_opcode=0x99,
                tail=_numeric_check_tail(opcode=0x99, check_value=1, jump_target=20),
            ),
            20: _block(20),
            21: _block(21),
        }
    )
    snapshot = _snapshot(
        flow_graph=fg,
        transitions=[
            StateTransition(from_state=0x10, to_state=1, from_block=10, is_conditional=True),
            StateTransition(from_state=0x10, to_state=2, from_block=10, is_conditional=True),
        ],
        handlers={
            1: StateHandler(state_value=1, check_block=20, handler_blocks=[20]),
            2: StateHandler(state_value=2, check_block=21, handler_blocks=[21]),
        },
    )

    candidates = resolution.collect_conditional_fork_resolution_candidates(
        snapshot,
        conditional_opcodes=(0x99,),
        normalize_reversed_jump_opcode=lambda opcode: opcode,
        is_jump_taken_for_state=lambda check_opcode, state_value, check_const, check_size: state_value == 1,
    )

    assert len(candidates) == 1
    assert candidates[0].from_block == 10
    assert candidates[0].cond_block == 5
    assert candidates[0].taken_target == 20
    assert candidates[0].fallthrough_target == 21
    assert candidates[0].states == (1, 2)
    assert candidates[0].owned_transitions == ((0x10, 1), (0x10, 2))


def test_collect_conditional_fork_resolution_candidates_uses_emulation_fallback():
    fg = _DummyFlowGraph(
        {
            10: _block(10, npred=1, preds=(5,), nsucc=1, succs=(77,)),
            5: _block(
                5,
                nsucc=2,
                succs=(30, 31),
                tail_opcode=0x99,
                tail=_numeric_check_tail(opcode=0x99, check_value=1, jump_target=30),
            ),
            30: _block(30),
            31: _block(31),
            77: _block(77),
        }
    )
    snapshot = _snapshot(
        flow_graph=fg,
        transitions=[
            StateTransition(from_state=0x10, to_state=1, from_block=10, is_conditional=True),
            StateTransition(from_state=0x10, to_state=2, from_block=10, is_conditional=True),
        ],
        handlers={
            1: StateHandler(state_value=1, check_block=30, handler_blocks=[30]),
            2: StateHandler(state_value=2, check_block=31, handler_blocks=[31]),
        },
    )

    def _fake_emulate(
        mba,
        entry_block_serial,
        state_value,
        state_var,
        dispatcher_set,
        use_before_def,
        from_block_serial,
        *,
        max_instructions=5000,
    ):
        return 200 if int(state_value) == 1 else 201

    with (
        _replaced_attr(resolution, "resolve_conditional_chain_target", lambda *args, **kwargs: None),
        _replaced_attr(resolution, "_collect_ladder_use_before_def", lambda *args, **kwargs: ["seed"]),
        _replaced_attr(resolution, "get_successor_into_dispatcher", lambda *args, **kwargs: 77),
        _replaced_attr(resolution, "_emulate_chain_exit", _fake_emulate),
    ):
        candidates = resolution.collect_conditional_fork_resolution_candidates(
            snapshot,
            conditional_opcodes=(0x99,),
            normalize_reversed_jump_opcode=lambda opcode: opcode,
            is_jump_taken_for_state=lambda check_opcode, state_value, check_const, check_size: state_value == 1,
        )

    assert len(candidates) == 1
    assert candidates[0].from_block == 10
    assert candidates[0].cond_block == 5
    assert candidates[0].taken_target == 200
    assert candidates[0].fallthrough_target == 201
