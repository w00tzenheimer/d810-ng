"""C1 shadow-diff: fixpoint-sourced back-edge emission + per-edge diff (ticket llr-1szn).

recover_state_write_transitions_via_fixpoint reuses the production emission shell but reads
the next state from the fixpoint's out_states; diff_back_edge_transitions buckets the result
against the production fold (MATCH / case2_opaque residual / mismatch).
"""
from __future__ import annotations

from d810.analyses.control_flow.minimal_state_recovery import (
    StateWriteTransition,
    diff_back_edge_transitions,
    recover_state_write_transitions_via_fixpoint,
)
from d810.analyses.control_flow.state_transition_domain import StateValue


class _Blk:
    def __init__(self, serial, preds=(), succs=(), kind=None):
        self.serial = serial
        self.preds = list(preds)
        self.succs = list(succs)
        self.kind = kind


class _FG:
    def __init__(self, blocks):
        self._b = {b.serial: b for b in blocks}

    def get_block(self, serial):
        return self._b.get(int(serial))


class _Disp:
    def __init__(self, routes, default=None):
        self._r = dict(routes)
        self.default_target = default

    def lookup(self, state):
        r = self._r.get(int(state))
        return None if r is None else int(r)


def test_via_fixpoint_routes_singleton_and_returns_on_top() -> None:
    fg = _FG([
        _Blk(1, preds=[2, 3, 4]),   # dispatcher entry
        _Blk(2, succs=[1]),         # 1-way back-edge -> arm None
        _Blk(3, succs=[5, 1]),      # 2-way back-edge -> arm index of 1 == 1
        _Blk(4, succs=[1]),         # unresolved (fixpoint state ⊤)
        _Blk(50), _Blk(60),         # handler targets (kind None -> not STOP)
    ])
    disp = _Disp({0x100: 50, 0x200: 60})
    out_states = {2: StateValue.of(0x100), 3: StateValue.of(0x200), 4: StateValue.top()}

    res = {
        t.write_block: t
        for t in recover_state_write_transitions_via_fixpoint(
            fg, disp, dispatcher_entry_serial=1, out_states=out_states
        )
    }
    assert res[2].next_state == 0x100 and res[2].target_handler == 50
    assert res[2].is_return is False and res[2].branch_arm is None
    assert res[3].target_handler == 60 and res[3].branch_arm == 1
    assert res[4].next_state is None and res[4].is_return is True  # ⊤ -> return


def test_diff_buckets_match_case2_residual_and_mismatch() -> None:
    swt = StateWriteTransition
    production = (
        swt(2, 0x100, 50, False, None),               # fixpoint agrees -> matched
        swt(5, 0x500, 80, False, None),               # fixpoint unresolved -> mismatch
        swt(9, 0x300, 70, False, None, via_block=8),  # Case-2 opaque split -> residual
    )
    fixpoint = (
        swt(2, 0x100, 50, False, None),
        swt(5, None, None, True, None),
    )
    d = diff_back_edge_transitions(production, fixpoint)
    assert d["prod_edges"] == 3 and d["fixpoint_edges"] == 2
    assert d["matched"] == 1
    assert d["case2_opaque"] == 1            # the via_block split, expected residual
    assert len(d["mismatch"]) == 1
    assert d["mismatch"][0][0] == 5          # write_block 5 is the mismatch
