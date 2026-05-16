from __future__ import annotations

from types import SimpleNamespace

from d810.recon.flow import state_machine_analysis as sma


def _mop_s(off: int):
    return SimpleNamespace(t=3, size=4, stkoff=off)


def _mop_n(value: int):
    return SimpleNamespace(t=2, size=4, nnn_value=value)


class _SnapshotBlock:
    def __init__(
        self,
        serial: int,
        succs: tuple[int, ...],
        *,
        opcode: int | None = None,
        cmp_value: int | None = None,
        insn_count: int = 1,
    ):
        self.serial = serial
        self.succs = succs
        if opcode is None:
            self.insn_snapshots = ()
            self.tail = None
            self.tail_opcode = None
        else:
            insn = SimpleNamespace(
                opcode=opcode,
                l=_mop_s(0x364),
                r=_mop_n(cmp_value or 0),
            )
            self.insn_snapshots = (insn,) * insn_count
            self.tail = insn
            self.tail_opcode = opcode

    @property
    def nsucc(self) -> int:
        return len(self.succs)


class _SnapshotFlowGraph:
    def __init__(self, blocks: dict[int, _SnapshotBlock]):
        self._blocks = blocks

    def get_block(self, serial: int):
        return self._blocks.get(int(serial))


class _FakeBlock:
    def __init__(self, succs: tuple[int, ...]):
        self.head = None
        self._succs = succs

    def nsucc(self) -> int:
        return len(self._succs)

    def succ(self, index: int) -> int:
        return self._succs[index]


class _FakeMBA:
    def __init__(self, blocks: dict[int, _FakeBlock]):
        self._blocks = blocks
        self.qty = max(blocks) + 1 if blocks else 0

    def get_mblock(self, serial: int) -> _FakeBlock | None:
        return self._blocks.get(serial)


def test_evaluate_handler_paths_uses_snapshot_state_for_bst_exit(monkeypatch):
    mba = _FakeMBA(
        {
            1: _FakeBlock((2,)),
            2: _FakeBlock((0,)),
        }
    )

    calls = []

    def fake_snapshot_state(flow_graph, ordered_path, state_var_stkoff):
        calls.append((flow_graph, tuple(ordered_path), state_var_stkoff))
        return (
            2,
            SimpleNamespace(
                state_value=0xA3130002,
                insn_ea=0x1800,
            ),
        )

    monkeypatch.setattr(
        sma,
        "find_last_state_write_site_on_path_snapshot",
        fake_snapshot_state,
    )

    flow_graph = object()
    results = sma.evaluate_handler_paths(
        mba,
        entry_serial=1,
        incoming_state=0x741CA546,
        bst_node_blocks={0},
        state_var_stkoff=0x364,
        flow_graph=flow_graph,
        known_handler_states={0xA3130002},
        bst_root_serial=0,
        state_machine_blocks={0, 1, 2},
    )

    assert calls == [(flow_graph, (1, 2), 0x364)]
    assert len(results) == 1
    assert results[0].final_state == 0xA3130002
    assert results[0].state_writes == [(2, 0x1800)]
    assert results[0].ordered_path == [1, 2]


def test_evaluate_handler_paths_uses_snapshot_state_for_handler_handoff(
    monkeypatch,
):
    mba = _FakeMBA(
        {
            1: _FakeBlock((2,)),
            2: _FakeBlock((3,)),
            3: _FakeBlock(()),
        }
    )

    def fake_snapshot_state(_flow_graph, ordered_path, _state_var_stkoff):
        assert tuple(ordered_path) == (1, 2)
        return (
            2,
            SimpleNamespace(
                state_value=0xE01F6CFA,
                insn_ea=0x1810,
            ),
        )

    monkeypatch.setattr(
        sma,
        "find_last_state_write_site_on_path_snapshot",
        fake_snapshot_state,
    )

    results = sma.evaluate_handler_paths(
        mba,
        entry_serial=1,
        incoming_state=0x741CA546,
        bst_node_blocks={0},
        state_var_stkoff=0x364,
        handler_entry_blocks={1, 3},
        flow_graph=object(),
    )

    assert len(results) == 1
    assert results[0].final_state == 0xE01F6CFA
    assert results[0].state_writes == [(2, 0x1810)]
    assert results[0].ordered_path == [1, 2]


def test_resolve_exit_via_bst_default_snapshot_skips_trivial_connectors():
    flow_graph = _SnapshotFlowGraph(
        {
            6: _SnapshotBlock(
                6,
                (7, 20),
                opcode=sma.ida_hexrays.m_jnz,
                cmp_value=0x1000,
            ),
            20: _SnapshotBlock(20, (22,)),
            22: _SnapshotBlock(
                22,
                (122, 23),
                opcode=sma.ida_hexrays.m_jnz,
                cmp_value=0x790A1FEB,
            ),
            122: _SnapshotBlock(
                122,
                (2,),
                opcode=sma.ida_hexrays.m_mov,
                cmp_value=0xE581B47B,
                insn_count=2,
            ),
        }
    )

    assert (
        sma.resolve_exit_via_bst_default_snapshot(
            flow_graph,
            6,
            0x790A1FEB,
        )
        == 122
    )


def test_resolve_exit_via_bst_default_snapshot_keeps_empty_handler_anchor():
    flow_graph = _SnapshotFlowGraph(
        {
            6: _SnapshotBlock(
                6,
                (20, 122),
                opcode=sma.ida_hexrays.m_jnz,
                cmp_value=0x1000,
            ),
            20: _SnapshotBlock(20, (8,)),
            8: _SnapshotBlock(8, ()),
            122: _SnapshotBlock(
                122,
                (2,),
                opcode=sma.ida_hexrays.m_mov,
                cmp_value=0xE581B47B,
                insn_count=2,
            ),
        }
    )

    assert (
        sma.resolve_exit_via_bst_default_snapshot(
            flow_graph,
            6,
            0x1000,
        )
        == 20
    )
