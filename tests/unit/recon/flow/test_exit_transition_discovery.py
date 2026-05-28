from __future__ import annotations

import inspect
from types import SimpleNamespace

import d810.recon.flow.exit_transition_discovery as exit_transition_discovery
from d810.recon.flow.exit_transition_discovery import (
    collect_bst_default_transition_candidates,
    collect_exit_transition_candidates,
    collect_valrange_exit_transition_candidates,
)

_MOVE_OPCODE = 4
_NUMBER_OPERAND = 2
_STACK_OPERAND = 5


class _DummyInsn:
    def __init__(self, *, value: int, ea: int = 0x1000):
        self.opcode = _MOVE_OPCODE
        self.d = SimpleNamespace(t=_STACK_OPERAND, s=SimpleNamespace(off=0x30))
        self.l = SimpleNamespace(t=_NUMBER_OPERAND, nnn=SimpleNamespace(value=value))
        self.ea = ea
        self.next = None


class _DummyBlock:
    def __init__(self, *, head: object | None, succs: tuple[int, ...] = ()):
        self.head = head
        self._succs = succs

    def nsucc(self):
        return len(self._succs)

    def succ(self, idx: int):
        return self._succs[idx]


class _DummyMba:
    def __init__(self, blocks: dict[int, _DummyBlock]):
        self._blocks = blocks

    def get_mblock(self, serial: int):
        return self._blocks.get(int(serial))


class TestCollectExitTransitionCandidates:
    def test_collects_bfs_write_candidates(self) -> None:
        snapshot = SimpleNamespace(
            mba=_DummyMba({24: _DummyBlock(head=_DummyInsn(value=0x22))}),
            detector=None,
            bst_dispatcher_serial=6,
        )
        sm = SimpleNamespace(
            state_var=SimpleNamespace(t=_STACK_OPERAND, s=SimpleNamespace(off=0x30)),
            transitions=(),
            handlers={
                0x11: SimpleNamespace(handler_blocks=(24,), check_block=24),
            },
        )
        bst_result = SimpleNamespace(
            dispatcher=None,
            handler_state_map={88: 0x22},
            handler_range_map={},
            default_block_serial=None,
        )

        candidates = collect_exit_transition_candidates(
            snapshot,
            sm=sm,
            bst_result=bst_result,
            handler_state_map={24: 0x11},
            bst_node_blocks={2, 6},
        )

        assert len(candidates) == 1
        assert candidates[0].from_block == 24
        assert candidates[0].target_entry == 88
        assert candidates[0].exit_state_value == 0x22
        assert candidates[0].discovery_kind == "write"

    def test_collects_bst_walk_fallback_candidates(self, monkeypatch) -> None:
        snapshot = SimpleNamespace(
            mba=_DummyMba({24: _DummyBlock(head=None)}),
            detector=None,
            bst_dispatcher_serial=6,
        )
        sm = SimpleNamespace(
            state_var=SimpleNamespace(t=_STACK_OPERAND, s=SimpleNamespace(off=0x30)),
            transitions=(),
            handlers={
                0x11: SimpleNamespace(handler_blocks=(24,), check_block=24),
            },
        )
        bst_result = SimpleNamespace(
            dispatcher=None,
            handler_state_map={},
            handler_range_map={},
            default_block_serial=None,
        )

        monkeypatch.setattr(
            "d810.recon.flow.exit_transition_discovery.resolve_via_bst_walk",
            lambda mba, dispatcher_serial, state_val, bst_nodes: 88,
        )

        candidates = collect_exit_transition_candidates(
            snapshot,
            sm=sm,
            bst_result=bst_result,
            handler_state_map={},
            bst_node_blocks={2, 6},
        )

        assert len(candidates) == 1
        assert candidates[0].from_block == 24
        assert candidates[0].target_entry == 88
        assert candidates[0].exit_state_value is None
        assert candidates[0].discovery_kind == "bst_walk"


class TestCollectBstDefaultTransitionCandidates:
    def test_collects_path_eval_candidates(self, monkeypatch) -> None:
        snapshot = SimpleNamespace(
            mba=_DummyMba({}),
            detector=None,
        )
        sm = SimpleNamespace(
            state_var=SimpleNamespace(t=_STACK_OPERAND, s=SimpleNamespace(off=0x30)),
        )
        bst_result = SimpleNamespace()

        seen_calls: list[tuple[int, int, frozenset[int]]] = []

        def fake_evaluate_handler_paths(
            *,
            mba,
            entry_serial,
            incoming_state,
            bst_node_blocks,
            state_var_stkoff,
            handler_entry_blocks,
        ):
            assert mba is snapshot.mba
            assert state_var_stkoff == 0x30
            seen_calls.append(
                (
                    int(entry_serial),
                    int(incoming_state),
                    frozenset(int(v) for v in handler_entry_blocks),
                )
            )
            return [
                SimpleNamespace(exit_block=24, final_state=0x22),
                SimpleNamespace(exit_block=30, final_state=None),
            ]

        monkeypatch.setattr(
            "d810.recon.flow.exit_transition_discovery.evaluate_handler_paths",
            fake_evaluate_handler_paths,
        )
        monkeypatch.setattr(
            "d810.recon.flow.exit_transition_discovery.resolve_target_via_bst",
            lambda bst, state: 88 if state == 0x22 else None,
        )

        candidates = collect_bst_default_transition_candidates(
            snapshot,
            sm=sm,
            bst_result=bst_result,
            handler_state_map={24: 0x11},
            bst_node_blocks={2, 6},
        )

        assert seen_calls == [(0x11, 24, frozenset({0x11}))]
        assert len(candidates) == 1
        assert candidates[0].handler_state == 24
        assert candidates[0].handler_entry == 0x11
        assert candidates[0].from_block == 24
        assert candidates[0].target_entry == 88
        assert candidates[0].final_state == 0x22

    def test_exit_transition_discovery_does_not_import_live_hexrays(self) -> None:
        assert "import ida_hexrays" not in inspect.getsource(
            exit_transition_discovery
        )


class _DummyTailBlock:
    def __init__(self, tail: object | None):
        self.tail = tail


class TestCollectValrangeExitTransitionCandidates:
    def test_collects_unresolved_exit_candidates(self, monkeypatch) -> None:
        tail = object()
        snapshot = SimpleNamespace(
            mba=_DummyMba({24: _DummyTailBlock(tail)}),
            resolved_transitions=frozenset(),
        )
        transition = SimpleNamespace(from_state=0x11, to_state=0x22, from_block=24)
        sm = SimpleNamespace(
            state_var=SimpleNamespace(name="state"),
            handlers={0x11: SimpleNamespace(transitions=(transition,))},
        )
        bst_result = SimpleNamespace()

        monkeypatch.setattr(
            "d810.recon.flow.exit_transition_discovery.resolve_target_via_bst",
            lambda bst, state: 88 if state == 0x33 else None,
        )

        discovery = collect_valrange_exit_transition_candidates(
            snapshot,
            sm=sm,
            bst_result=bst_result,
            resolve_state_via_valranges=lambda blk, state_var, insn: 0x33,
        )

        assert discovery.total_unresolved == 1
        assert len(discovery.candidates) == 1
        assert discovery.candidates[0].from_state == 0x11
        assert discovery.candidates[0].to_state == 0x22
        assert discovery.candidates[0].from_block == 24
        assert discovery.candidates[0].target_entry == 88
        assert discovery.candidates[0].resolved_state_value == 0x33

    def test_skips_already_resolved_transitions(self) -> None:
        tail = object()
        snapshot = SimpleNamespace(
            mba=_DummyMba({24: _DummyTailBlock(tail)}),
            resolved_transitions=frozenset({(0x11, 0x22)}),
        )
        transition = SimpleNamespace(from_state=0x11, to_state=0x22, from_block=24)
        sm = SimpleNamespace(
            state_var=SimpleNamespace(name="state"),
            handlers={0x11: SimpleNamespace(transitions=(transition,))},
        )

        discovery = collect_valrange_exit_transition_candidates(
            snapshot,
            sm=sm,
            bst_result=SimpleNamespace(),
            resolve_state_via_valranges=lambda blk, state_var, insn: 0x33,
        )

        assert discovery.total_unresolved == 0
        assert discovery.candidates == ()
