from __future__ import annotations

from d810.recon.flow.transition_report import (
    TransitionKind,
    build_dispatcher_transition_report,
)


class _DummyMBA:
    pass


def test_build_dispatcher_transition_report_classifies_rows(monkeypatch):
    def fake_detect(_mba, _entry, diag=False):
        if diag:
            return (0x20, None), ["detect ok"]
        return 0x20, None

    def fake_pre_header(_mba, _entry, _stkoff, diag_lines=None, state_var_lvar_idx=None):
        if diag_lines is not None:
            diag_lines.append("preheader ok")
        return 7, 0x11111111

    def fake_dump(
        _mba,
        _entry,
        indent,
        visited,
        lines,
        depth,
        max_depth,
        value_lo,
        value_hi,
        handler_state_map,
        handler_serials,
        handler_range_map,
        bst_node_blocks,
    ):
        handler_serials.update({10, 11, 12, 13})
        handler_state_map[10] = 1
        handler_state_map[11] = 2
        handler_state_map[12] = 3
        handler_range_map[13] = (0x30, 0x3F)
        bst_node_blocks.update({2, 4})

    walks = {
        10: {"next_state": 0xAA, "back_edge": True, "exit": False, "chain": [10, 20]},
        11: {"next_state": None, "back_edge": True, "exit": False, "chain": [11, 21], "conditional_states": {0xBB, 0xCC}},
        12: {"next_state": None, "back_edge": False, "exit": True, "chain": [12, 22]},
        13: {"next_state": None, "back_edge": True, "exit": False, "chain": [13, 23]},
    }

    def fake_walk(
        _mba,
        handler_start_serial,
        dispatcher_entry_serial,
        state_var_stkoff,
        chain_visited=None,
        max_chain_depth=64,
        diag_lines=None,
        state_var_lvar_idx=None,
    ):
        if diag_lines is not None:
            diag_lines.append(f"walk {handler_start_serial}")
        return walks[handler_start_serial]

    monkeypatch.setattr(
        "d810.recon.flow.transition_report._detect_state_var_stkoff", fake_detect
    )
    monkeypatch.setattr(
        "d810.recon.flow.transition_report._find_pre_header_state", fake_pre_header
    )
    monkeypatch.setattr(
        "d810.recon.flow.transition_report._dump_dispatcher_node", fake_dump
    )
    monkeypatch.setattr(
        "d810.recon.flow.transition_report._walk_handler_chain", fake_walk
    )

    report = build_dispatcher_transition_report(
        mba=_DummyMBA(),
        dispatcher_entry_serial=5,
        capture_diagnostics=True,
        max_diag_handlers=2,
    )

    assert report.pre_header_serial == 7
    assert report.initial_state == 0x11111111
    assert report.summary.handlers_total == 4
    assert report.summary.known_count == 1
    assert report.summary.conditional_count == 1
    assert report.summary.exit_count == 1
    assert report.summary.unknown_count == 1
    assert report.bst_node_blocks == (2, 4)

    by_handler = {row.handler_serial: row for row in report.rows}
    assert by_handler[10].kind == TransitionKind.TRANSITION
    assert by_handler[11].kind == TransitionKind.CONDITIONAL
    assert by_handler[12].kind == TransitionKind.EXIT
    assert by_handler[13].kind == TransitionKind.UNKNOWN
    assert by_handler[13].state_label == "State range [0x30..0x3f]"
    assert by_handler[10].chain_preview == (10, 20)
    assert "walk 10" in "\n".join(report.diagnostics)


def test_transition_hint_fills_missing_next_state(monkeypatch):
    monkeypatch.setattr(
        "d810.recon.flow.transition_report._detect_state_var_stkoff",
        lambda _mba, _entry, diag=False: ((0x20, None), []) if diag else (0x20, None),
    )
    monkeypatch.setattr(
        "d810.recon.flow.transition_report._find_pre_header_state",
        lambda *_args, **_kwargs: (None, None),
    )

    def fake_dump(
        _mba,
        _entry,
        indent,
        visited,
        lines,
        depth,
        max_depth,
        value_lo,
        value_hi,
        handler_state_map,
        handler_serials,
        handler_range_map,
        bst_node_blocks,
    ):
        handler_serials.add(50)
        handler_state_map[50] = 0x1234

    monkeypatch.setattr(
        "d810.recon.flow.transition_report._dump_dispatcher_node", fake_dump
    )
    monkeypatch.setattr(
        "d810.recon.flow.transition_report._walk_handler_chain",
        lambda *_args, **_kwargs: {
            "next_state": None,
            "back_edge": True,
            "exit": False,
            "chain": [50, 60, 70],
        },
    )

    report = build_dispatcher_transition_report(
        mba=_DummyMBA(),
        dispatcher_entry_serial=5,
        transitions_hint_by_handler={50: 0xCAFEBABE},
        chain_preview_len=2,
    )

    row = report.rows[0]
    assert row.kind == TransitionKind.TRANSITION
    assert row.next_state == 0xCAFEBABE
    assert row.transition_label == "next=0xcafebabe (back-edge)"
    assert row.chain_preview == (50, 60)
