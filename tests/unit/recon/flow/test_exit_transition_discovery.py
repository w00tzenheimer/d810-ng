from __future__ import annotations

from types import SimpleNamespace

import ida_hexrays

from d810.recon.flow.exit_transition_discovery import (
    collect_exit_transition_candidates,
)


class _DummyInsn:
    def __init__(self, *, value: int, ea: int = 0x1000):
        self.opcode = ida_hexrays.m_mov
        self.d = SimpleNamespace(t=ida_hexrays.mop_S, s=SimpleNamespace(off=0x30))
        self.l = SimpleNamespace(t=ida_hexrays.mop_n, nnn=SimpleNamespace(value=value))
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
            state_var=SimpleNamespace(t=ida_hexrays.mop_S, s=SimpleNamespace(off=0x30)),
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
            state_var=SimpleNamespace(t=ida_hexrays.mop_S, s=SimpleNamespace(off=0x30)),
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
