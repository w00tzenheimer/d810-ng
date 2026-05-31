from __future__ import annotations

from d810.analyses.control_flow.bst_model import is_terminal_handler
from d810.ir.flowgraph import BlockSnapshot, FlowGraph


def _fg(blocks: dict[int, tuple[int, ...]], entry: int = 1) -> FlowGraph:
    """Build a topology-only FlowGraph from ``{serial: succs}`` specs."""
    snapshots = {
        serial: BlockSnapshot(
            serial=serial,
            block_type=0,
            succs=tuple(succs),
            preds=(),
            flags=0,
            start_ea=0,
            insn_snapshots=(),
        )
        for serial, succs in blocks.items()
    }
    return FlowGraph(blocks=snapshots, entry_serial=entry, func_ea=0)


def test_terminal_handler_accepts_all_no_successor_paths() -> None:
    fg = _fg({1: (2, 3), 2: (), 3: ()})

    assert is_terminal_handler(fg, 1, dispatcher_serial=9, bst_blocks=set())


def test_terminal_handler_rejects_path_to_dispatcher() -> None:
    fg = _fg({1: (2, 9), 2: (), 9: ()})

    assert not is_terminal_handler(fg, 1, dispatcher_serial=9, bst_blocks=set())


def test_terminal_handler_rejects_path_to_bst_block() -> None:
    fg = _fg({1: (2, 4), 2: (), 4: ()})

    assert not is_terminal_handler(fg, 1, dispatcher_serial=9, bst_blocks={4})
