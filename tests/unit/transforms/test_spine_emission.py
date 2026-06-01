"""Portable spine redirect emission shared by the legacy LFG path and §1a #4.

``emit_spine_modifications`` walks the DAG's transition edges and emits one neutral
``GraphModification`` per redirected edge using the canonical nsucc-aware emission planner. These
tests lock the redirect-kind selection, old_target resolution, dispatcher self-loop skip, and the
2-way transition rejection that prevents the deferred backend from aborting on a "not 1-way" mismatch.
"""
from __future__ import annotations

from types import SimpleNamespace

from d810.analyses.control_flow.linearized_state_dag import (
    RedirectSourceKind,
    SemanticEdgeKind,
)
from d810.transforms.graph_modification import RedirectBranch, RedirectGoto
from d810.transforms.spine_emission import emit_spine_modifications


_SPINE = frozenset(
    {SemanticEdgeKind.TRANSITION, SemanticEdgeKind.CONDITIONAL_TRANSITION}
)


def _edge(kind, source_block, target_entry, *, branch=False, arm=None, ordered_path=()):
    branch_arm = arm if arm is not None else (0 if branch else None)
    anchor = SimpleNamespace(
        block_serial=source_block,
        branch_arm=branch_arm,
        kind=(
            RedirectSourceKind.CONDITIONAL_BRANCH
            if branch
            else RedirectSourceKind.UNCONDITIONAL
        ),
    )
    return SimpleNamespace(
        kind=kind,
        target_entry_anchor=target_entry,
        source_anchor=anchor,
        ordered_path=tuple(ordered_path),
    )


def _emit(edges, *, nsucc, succ, dispatcher=5):
    dag = SimpleNamespace(edges=tuple(edges))
    return emit_spine_modifications(
        dag=dag,
        spine_edge_kinds=_SPINE,
        dispatcher_entry_serial=dispatcher,
        block_nsucc_map=nsucc,
        block_succ_map=succ,
    )


def test_one_way_source_emits_goto_off_live_successor():
    mods = _emit(
        [_edge(SemanticEdgeKind.TRANSITION, 10, 20)],
        nsucc={10: 1},
        succ={10: (5,)},
    )
    assert mods == [RedirectGoto(from_serial=10, old_target=5, new_target=20)]


def test_two_way_conditional_arm_emits_branch_off_arm_successor():
    mods = _emit(
        [_edge(SemanticEdgeKind.CONDITIONAL_TRANSITION, 9, 44, branch=True, arm=1)],
        nsucc={9: 2},
        succ={9: (16, 17)},
    )
    assert mods == [RedirectBranch(from_serial=9, old_target=17, new_target=44)]


def test_two_way_transition_source_rejected_no_abort():
    # A 2-way TRANSITION source must NOT become a goto change; the planner rejects it.
    mods = _emit(
        [_edge(SemanticEdgeKind.TRANSITION, 15, 44)],
        nsucc={15: 2},
        succ={15: (16, 17)},
    )
    assert mods == []


def test_dispatcher_selfloop_and_non_spine_edges_skipped():
    mods = _emit(
        [
            _edge(SemanticEdgeKind.EXIT_ROUTINE, 10, 20),  # not a spine kind
            _edge(SemanticEdgeKind.TRANSITION, 10, 5),      # routes back to dispatcher (5)
            _edge(SemanticEdgeKind.TRANSITION, 11, None),   # no resolved target
        ],
        nsucc={10: 1, 11: 1},
        succ={10: (5,), 11: (5,)},
    )
    assert mods == []


def test_duplicate_edge_emitted_once():
    mods = _emit(
        [
            _edge(SemanticEdgeKind.TRANSITION, 10, 20),
            _edge(SemanticEdgeKind.TRANSITION, 10, 20),
        ],
        nsucc={10: 1},
        succ={10: (5,)},
    )
    assert mods == [RedirectGoto(from_serial=10, old_target=5, new_target=20)]
