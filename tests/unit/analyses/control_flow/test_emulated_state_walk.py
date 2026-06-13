"""Unit tests for the shape-agnostic emulated state-machine walk (ticket llr-a93i, Slice 5).

These tests model ``abc_xor_dispatch`` exactly -- a ``switch((state ^ 0xDEADBEEF) & 0xFF)``
dispatcher with full-width ``state ^= magic`` transitions -- with PURE callables, proving the
walk recovers the real-state -> handler table that the static equality-chain / switch-table
resolvers structurally cannot (the case labels are sub-threshold byte projections of the
state, and the real states are never compared directly).

IDA-free: the walk core is portable; only the live oracles (seed + MicroCodeInterpreter) are
IDA-bound, and those are covered by system tests.
"""
from __future__ import annotations

from d810.analyses.control_flow.emulated_state_walk import (
    DEFAULT_MAX_STATES,
    EmulatedWalkRow,
    walk_emulated_state_machine,
)

# --- abc_xor_dispatch model (mirrors samples/src/c/abc_xor_dispatch.c) -----------------
_KEY = 0xDEADBEEF
_MASK = 0xFF
_INITIAL = 0x123456EF

# Synthetic handler block serials, one per switch case label (selector value).
_H_ENTRY, _H_ADD, _H_MUL, _H_COND, _H_EXIT_A, _H_EXIT_B = 10, 11, 12, 13, 14, 15
_HANDLER_BY_SELECTOR = {
    0x00: _H_ENTRY,   # result = input;        state ^= 0x11111111
    0x11: _H_ADD,     # result += 42;          state ^= 0x22222222
    0x33: _H_MUL,     # result *= 2;           state ^= 0x44444444
    0x77: _H_COND,    # if result>100: ^0x88888888 else ^0x99999999
    0xFF: _H_EXIT_A,  # return result
    0xEE: _H_EXIT_B,  # return -result
}
_LINEAR_MAGIC = {_H_ENTRY: 0x11111111, _H_ADD: 0x22222222, _H_MUL: 0x44444444}
_COND_MAGICS = (0x88888888, 0x99999999)  # the two arms of the 0x77 handler
_TERMINALS = {_H_EXIT_A, _H_EXIT_B}


def _resolve_handler(state: int) -> int | None:
    """Evaluate the XOR-masked selector projection and route -- exactly the dispatcher."""
    return _HANDLER_BY_SELECTOR.get((state ^ _KEY) & _MASK)


def _advance_states(state: int, handler: int) -> tuple[int, ...]:
    if handler in _LINEAR_MAGIC:
        return (state ^ _LINEAR_MAGIC[handler],)
    if handler == _H_COND:
        return tuple(state ^ m for m in _COND_MAGICS)
    return ()


def _is_terminal(handler: int) -> bool:
    return handler in _TERMINALS


def _walk_abc_xor():
    return walk_emulated_state_machine(
        _INITIAL, _resolve_handler, _advance_states, _is_terminal
    )


class TestAbcXorRecovery:
    """The XOR-masked machine recovers fully by emulation."""

    def test_recovers_all_six_real_state_rows(self):
        result = _walk_abc_xor()
        # The recovered rows are keyed by the REAL full-width states, NOT the byte labels.
        expected = {
            0x123456EF: _H_ENTRY,
            0x032547FE: _H_ADD,
            0x210765DC: _H_MUL,
            0x65432198: _H_COND,
            0xEDCBA910: _H_EXIT_A,
            0xFCDAB801: _H_EXIT_B,
        }
        assert result.state_to_handler == expected

    def test_real_states_are_not_the_case_labels(self):
        # Guards the whole premise: every recovered key is a full-width state, none is a
        # bare switch label -- so a static label-keyed detector would have produced a
        # different (wrong) table.
        recovered = set(result_keys := _walk_abc_xor().state_to_handler)
        assert recovered.isdisjoint(set(_HANDLER_BY_SELECTOR))
        assert all(k > _MASK for k in result_keys)

    def test_terminal_states_are_the_two_exits(self):
        result = _walk_abc_xor()
        assert set(result.terminal_states) == {0xEDCBA910, 0xFCDAB801}

    def test_conditional_arm_forks_two_next_states(self):
        # The 0x77 handler (cond) must enqueue BOTH exit states -- the Slice-4 arm fork.
        result = _walk_abc_xor()
        assert 0xEDCBA910 in result.visited_states  # >100 arm
        assert 0xFCDAB801 in result.visited_states  # <=100 arm

    def test_no_unresolved_no_truncation(self):
        result = _walk_abc_xor()
        assert result.unresolved_states == ()
        assert result.truncated is False


class TestWalkInvariants:
    """Soundness/termination invariants independent of the abc_xor shape."""

    def test_abstain_is_recorded_not_guessed(self):
        # A state whose handler cannot be proven is dropped (no row), never fabricated.
        result = walk_emulated_state_machine(
            0x5,
            resolve_handler=lambda s: None,
            advance_states=lambda s, h: (),
            is_terminal_handler=lambda h: False,
        )
        assert result.rows == ()
        assert result.unresolved_states == (0x5,)

    def test_self_loop_terminates(self):
        # A handler that re-derives the SAME state must not spin (visited-once guard).
        result = walk_emulated_state_machine(
            0x100,
            resolve_handler=lambda s: 1,
            advance_states=lambda s, h: (s,),  # next state == current state
            is_terminal_handler=lambda h: False,
        )
        assert result.visited_states == (0x100,)
        assert result.rows == (EmulatedWalkRow(0x100, 1),)
        assert result.truncated is False

    def test_max_states_caps_runaway(self):
        # An ever-incrementing pseudo-machine is truncated at the budget, never unbounded.
        result = walk_emulated_state_machine(
            0,
            resolve_handler=lambda s: 1,
            advance_states=lambda s, h: (s + 1,),
            is_terminal_handler=lambda h: False,
            max_states=8,
        )
        assert result.truncated is True
        assert len(result.visited_states) == 8

    def test_rows_are_deduped(self):
        # Two states reaching the same handler are distinct rows; the SAME (state,handler)
        # is recorded once even if re-encountered.
        result = walk_emulated_state_machine(
            0xA,
            resolve_handler=lambda s: 1 if s == 0xA else 2,
            advance_states=lambda s, h: (0xB,) if s == 0xA else (0xA,),
            is_terminal_handler=lambda h: False,
        )
        # 0xA -> h1 -> 0xB -> h2 -> 0xA(seen) ; exactly two rows, no dupes.
        assert result.rows == (EmulatedWalkRow(0xA, 1), EmulatedWalkRow(0xB, 2))

    def test_u64_wraparound_on_state(self):
        # States are masked to 64 bits so a transition that overflows stays canonical.
        result = walk_emulated_state_machine(
            (1 << 64) - 1,
            resolve_handler=lambda s: 1,
            advance_states=lambda s, h: (),
            is_terminal_handler=lambda h: True,
        )
        assert result.state_to_handler == {(1 << 64) - 1: 1}

    def test_default_budget_is_generous(self):
        assert DEFAULT_MAX_STATES >= 256
