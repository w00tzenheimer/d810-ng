"""Runtime tests for the live switch-case transition adapter."""
from __future__ import annotations

from types import SimpleNamespace

import ida_hexrays

from d810.optimizers.microcode.flow.dispatcher.switch_case_transitions import (
    collect_switch_case_transition_facts_from_mba,
)
from d810.recon.flow.branch_ownership import BranchOwnershipProofKind
from d810.recon.flow.dispatcher_kind import DispatcherType
from d810.recon.flow.dispatcher_map import StateDispatcherMap, StateDispatcherRow
from d810.recon.flow.switch_case_transition_analysis import SwitchCaseTransitionKind


def _dispatch_map(states: tuple[int, ...]) -> StateDispatcherMap:
    return StateDispatcherMap(
        rows=tuple(
            StateDispatcherRow(
                state_const=state,
                target_block=100 + state,
                dispatcher_block=50,
                compare_block=50,
                branch_kind="switch_case",
                source=DispatcherType.SWITCH_TABLE,
                confidence=1.0,
            )
            for state in states
        ),
        dispatcher_entry_block=50,
        dispatcher_blocks=frozenset({50}),
        state_var_stkoff=0x20,
        state_var_lvar_idx=None,
        source=DispatcherType.SWITCH_TABLE,
    )


def test_collects_live_mba_case_writes_and_return_frontiers(monkeypatch) -> None:
    dispatch_map = _dispatch_map(states=(4, 9, 13))

    class _Block:
        def __init__(self, serial: int, succs: tuple[int, ...] = (), head=None):
            self.serial = serial
            self._succs = succs
            self.head = head

        def nsucc(self) -> int:
            return len(self._succs)

        def succ(self, index: int) -> int:
            return self._succs[index]

    ret_insn = SimpleNamespace(
        opcode=ida_hexrays.m_ret,
        l=SimpleNamespace(t=ida_hexrays.mop_n, nnn=SimpleNamespace(value=1)),
        r=None,
        d=None,
        next=None,
    )
    blocks = {
        104: _Block(104, (109, 113)),
        109: _Block(109, (), ret_insn),
        113: _Block(113, (50,)),
    }
    mba = SimpleNamespace(
        qty=200,
        get_mblock=lambda serial: blocks.get(serial, _Block(serial)),
    )

    def _evaluate(_mba, *, entry_serial, **_kwargs):
        if entry_serial == 104:
            return (
                SimpleNamespace(final_state=9, exit_block=104, ordered_path=(104,)),
                SimpleNamespace(final_state=13, exit_block=104, ordered_path=(104,)),
            )
        if entry_serial == 109:
            return (SimpleNamespace(final_state=None, exit_block=109, ordered_path=(109,)),)
        return (SimpleNamespace(final_state=4, exit_block=113, ordered_path=(113,)),)

    monkeypatch.setattr(
        "d810.recon.flow.state_machine_analysis.evaluate_handler_paths",
        _evaluate,
    )

    facts = collect_switch_case_transition_facts_from_mba(
        mba=mba,
        dispatch_map=dispatch_map,
    )

    conditional = next(fact for fact in facts if fact.source_state == 4)
    assert conditional.transition_kind == SwitchCaseTransitionKind.CONDITIONAL
    assert conditional.next_states == (9, 13)
    assert conditional.exit_block == 104
    assert conditional.ordered_path == (104,)
    assert conditional.proof is not None
    assert conditional.proof.proof_kind == BranchOwnershipProofKind.REAL_DATA_DEPENDENT

    ret = next(fact for fact in facts if fact.source_state == 9)
    assert ret.transition_kind == SwitchCaseTransitionKind.RETURN_FRONTIER
    assert ret.return_value == 1
    assert ret.exit_block == 109
