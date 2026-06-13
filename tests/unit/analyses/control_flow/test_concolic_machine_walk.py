"""Unit tests for the portable forking-walk wrapper (P2, ticket llr-8wq9).

These mirror ``test_emulated_state_walk`` (the same ``abc_xor_dispatch`` model) but
assert the NEW thing P2 adds on top of the core walk: the recorded forking edges
(``WalkTransition``) with ``via_block`` / ``op`` / ``const`` provenance. The core
walk already fans both arms of a conditional out into the visited set; this wrapper
records the structural edge ``state -> {next_a, next_b}`` the P4 reduced-product
orchestrator consumes (design §4).

IDA-free: the oracles are pure callables; the live Hex-Rays oracles live in the
backend engine and are covered by system tests (``portable-core-no-ida``).
"""
from __future__ import annotations

from d810.analyses.control_flow.concolic_machine_walk import (
    ForkOutcome,
    WalkTransition,
    walk_forking_state_machine,
)

# --- abc_xor_dispatch model (mirrors test_emulated_state_walk) -------------------------
_KEY = 0xDEADBEEF
_MASK = 0xFF
_INITIAL = 0x123456EF

_H_ENTRY, _H_ADD, _H_MUL, _H_COND, _H_EXIT_A, _H_EXIT_B = 10, 11, 12, 13, 14, 15
_HANDLER_BY_SELECTOR = {
    0x00: _H_ENTRY,
    0x11: _H_ADD,
    0x33: _H_MUL,
    0x77: _H_COND,
    0xFF: _H_EXIT_A,
    0xEE: _H_EXIT_B,
}
_LINEAR_MAGIC = {_H_ENTRY: 0x11111111, _H_ADD: 0x22222222, _H_MUL: 0x44444444}
_COND_MAGICS = (0x88888888, 0x99999999)
_TERMINALS = {_H_EXIT_A, _H_EXIT_B}


def _resolve_handler(state: int) -> int | None:
    return _HANDLER_BY_SELECTOR.get((state ^ _KEY) & _MASK)


def _advance(state: int, handler: int) -> ForkOutcome:
    if handler in _LINEAR_MAGIC:
        magic = _LINEAR_MAGIC[handler]
        return ForkOutcome(
            next_states=(state ^ magic,), via_block=handler, op="^", const=magic
        )
    if handler == _H_COND:
        return ForkOutcome(
            next_states=tuple(state ^ m for m in _COND_MAGICS),
            via_block=handler,
            op="^",
            const=None,  # two distinct consts -> not a single-const linear arm
        )
    return ForkOutcome(())  # terminal: no transition


def _is_terminal(handler: int) -> bool:
    return handler in _TERMINALS


def _walk():
    return walk_forking_state_machine(
        _INITIAL, _resolve_handler, _advance, _is_terminal
    )


class TestForkingWalkParity:
    """The wrapper recovers the SAME rows as the bare core walk (no behavior drift)."""

    def test_recovers_all_six_real_state_rows(self):
        res = _walk()
        expected = {
            0x123456EF: _H_ENTRY,
            0x032547FE: _H_ADD,
            0x210765DC: _H_MUL,
            0x65432198: _H_COND,
            0xEDCBA910: _H_EXIT_A,
            0xFCDAB801: _H_EXIT_B,
        }
        assert res.walk.state_to_handler == expected

    def test_no_unresolved_no_truncation(self):
        res = _walk()
        assert res.walk.unresolved_states == ()
        assert res.walk.truncated is False

    def test_terminal_states_record_no_transition(self):
        res = _walk()
        # No transition's via_block is a terminal handler; terminals end the branch.
        via_blocks = {t.via_block for t in res.transitions}
        assert via_blocks.isdisjoint(_TERMINALS)


class TestForkProvenance:
    """The wrapper records the forking edges + provenance the core threw away."""

    def test_linear_handler_records_single_next_state_with_op_const(self):
        res = _walk()
        # The entry handler (linear, ^0x11111111) -> exactly one next state.
        entry_tr = [t for t in res.transitions if t.via_block == _H_ENTRY]
        assert len(entry_tr) == 1
        tr = entry_tr[0]
        assert tr.src_state == _INITIAL
        assert tr.next_states == (_INITIAL ^ 0x11111111,)
        assert tr.op == "^"
        assert tr.const == 0x11111111

    def test_conditional_handler_records_two_arm_fork(self):
        res = _walk()
        # The 0x77 (cond) handler -> a SINGLE transition with TWO next states: the
        # first-class fork (design §4), not two separate edges.
        cond_tr = [t for t in res.transitions if t.via_block == _H_COND]
        assert len(cond_tr) == 1
        tr = cond_tr[0]
        assert tr.src_state == 0x65432198
        assert len(tr.next_states) == 2
        assert set(tr.next_states) == {0x65432198 ^ m for m in _COND_MAGICS}
        assert tr.next_states == (0xEDCBA910, 0xFCDAB801)

    def test_every_nonterminal_state_has_exactly_one_transition(self):
        res = _walk()
        # 4 non-terminal handlers visited (entry, add, mul, cond) -> 4 edges.
        assert len(res.transitions) == 4
        # Each transition's src_state is a distinct visited state.
        srcs = [t.src_state for t in res.transitions]
        assert len(srcs) == len(set(srcs))

    def test_transitions_are_walktransition_instances(self):
        res = _walk()
        assert all(isinstance(t, WalkTransition) for t in res.transitions)


class TestWrapperInvariants:
    """Soundness/recording invariants independent of the abc_xor shape."""

    def test_empty_fan_out_records_no_transition(self):
        # A handler that produces no next state (terminal/dead) records nothing.
        res = walk_forking_state_machine(
            0x5,
            resolve_handler=lambda s: 1,
            advance_states=lambda s, h: ForkOutcome(()),
            is_terminal_handler=lambda h: False,
        )
        assert res.transitions == ()
        assert res.walk.rows  # the row is still recorded by the core

    def test_abstain_records_neither_row_nor_transition(self):
        res = walk_forking_state_machine(
            0x5,
            resolve_handler=lambda s: None,
            advance_states=lambda s, h: ForkOutcome((0x6,), via_block=9),
            is_terminal_handler=lambda h: False,
        )
        assert res.walk.rows == ()
        assert res.walk.unresolved_states == (0x5,)
        assert res.transitions == ()

    def test_edge_deduped_by_src_and_via_block(self):
        # A state that loops back to itself through the same handler records the
        # edge once (matches the core's row dedup), never spins.
        res = walk_forking_state_machine(
            0x100,
            resolve_handler=lambda s: 1,
            advance_states=lambda s, h: ForkOutcome((s,), via_block=1),
            is_terminal_handler=lambda h: False,
        )
        assert res.walk.visited_states == (0x100,)
        assert len(res.transitions) == 1
        assert res.transitions[0].next_states == (0x100,)

    def test_two_arm_fork_enqueues_both_arms(self):
        # Both arms of a fork must reach the visited set (the core fans them out);
        # the wrapper records the single 2-arm edge.
        res = walk_forking_state_machine(
            0x1,
            resolve_handler=lambda s: {0x1: 5, 0xA: 6, 0xB: 6}.get(s),
            advance_states=lambda s, h: (
                ForkOutcome((0xA, 0xB), via_block=5) if s == 0x1 else ForkOutcome(())
            ),
            is_terminal_handler=lambda h: h == 6,
        )
        assert 0xA in res.walk.visited_states
        assert 0xB in res.walk.visited_states
        fork = [t for t in res.transitions if t.via_block == 5]
        assert len(fork) == 1
        assert fork[0].next_states == (0xA, 0xB)

    def test_partial_arm_set_is_caller_obligation_not_recorded_specially(self):
        # The wrapper records WHATEVER the oracle returns; completeness (abstain on
        # an un-enumerable arm) is the engine's obligation (§7). A 1-tuple here is a
        # linear arm, faithfully recorded as length-1.
        res = walk_forking_state_machine(
            0x1,
            resolve_handler=lambda s: {0x1: 5, 0x2: 6}.get(s),
            advance_states=lambda s, h: (
                ForkOutcome((0x2,), via_block=5, op="+", const=1)
                if s == 0x1
                else ForkOutcome(())
            ),
            is_terminal_handler=lambda h: h == 6,
        )
        tr = [t for t in res.transitions if t.via_block == 5]
        assert len(tr) == 1
        assert tr[0].next_states == (0x2,)
        assert tr[0].op == "+"
        assert tr[0].const == 1
