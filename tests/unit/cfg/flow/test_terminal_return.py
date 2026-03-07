"""Unit tests for terminal return CFG frontier helpers."""
from __future__ import annotations

from d810.cfg.flow.terminal_return import (
    TerminalLoweringAction,
    TerminalSemanticLoweringFrontier,
    compute_terminal_cfg_suffix_frontier,
)


def test_compute_terminal_cfg_suffix_frontier_shared_stop_only() -> None:
    preds = {
        64: (9, 16, 17),
        9: (),
        16: (),
        17: (),
    }
    frontier = compute_terminal_cfg_suffix_frontier(
        64,
        predecessors_of=lambda serial: preds.get(serial, ()),
    )
    assert frontier.shared_entry_serial == 64
    assert frontier.return_block_serial == 64
    assert frontier.suffix_serials == (64,)
    assert frontier.unique_anchor_serials == (9, 16, 17)


def test_compute_terminal_cfg_suffix_frontier_shared_suffix() -> None:
    preds = {
        64: (63,),
        63: (9, 16, 17),
        9: (),
        16: (),
        17: (),
    }
    frontier = compute_terminal_cfg_suffix_frontier(
        64,
        predecessors_of=lambda serial: preds.get(serial, ()),
    )
    assert frontier.shared_entry_serial == 63
    assert frontier.return_block_serial == 64
    assert frontier.suffix_serials == (63, 64)
    assert frontier.unique_anchor_serials == (9, 16, 17)


def test_semantic_frontier_summary() -> None:
    frontier = TerminalSemanticLoweringFrontier(
        action=TerminalLoweringAction.PRIVATE_TERMINAL_SUFFIX,
        lowering_start_serial=63,
        unique_anchor_serials=(9, 16, 17),
        notes="shared materialization happens before the stop",
    )
    assert frontier.summary() == (
        "action=private_terminal_suffix start=blk[63] "
        "anchors=[9,16,17] notes=shared materialization happens before the stop"
    )
