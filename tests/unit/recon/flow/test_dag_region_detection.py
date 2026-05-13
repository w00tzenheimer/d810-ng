from __future__ import annotations

from d810.recon.flow.dag_region_detection import detect_linear_transition_regions
from d810.recon.flow.linearized_state_dag import (
    LinearizedStateDag,
    RedirectSourceKind,
    SemanticEdgeKind,
    StateDagEdge,
    StateDagNode,
    StateDagNodeKey,
    StateNodeKind,
    StateRedirectAnchor,
)


def _node(entry: int, state: int | None = None) -> StateDagNode:
    state_value = entry if state is None else state
    return StateDagNode(
        key=StateDagNodeKey(handler_serial=entry, state_const=state_value),
        kind=StateNodeKind.EXACT,
        state_label=f"STATE_{state_value:08X}",
        handler_serial=entry,
        entry_anchor=entry,
        owned_blocks=(entry,),
        exclusive_blocks=(entry,),
        shared_suffix_blocks=(),
        local_segments=(),
        local_edges=(),
    )


def _edge(
    source: StateDagNode,
    target: StateDagNode | None,
    *,
    kind: SemanticEdgeKind = SemanticEdgeKind.TRANSITION,
) -> StateDagEdge:
    return StateDagEdge(
        kind=kind,
        source_key=source.key,
        target_key=target.key if target is not None else None,
        target_state=target.key.state_const if target is not None else None,
        target_entry_anchor=target.entry_anchor if target is not None else None,
        target_label=target.state_label if target is not None else "<return>",
        source_anchor=StateRedirectAnchor(
            kind=RedirectSourceKind.EXIT_BLOCK,
            block_serial=source.entry_anchor,
            branch_arm=None,
        ),
        ordered_path=(
            (source.entry_anchor, target.entry_anchor)
            if target is not None
            else (source.entry_anchor,)
        ),
        last_write_site=None,
    )


def _dag(
    nodes: tuple[StateDagNode, ...],
    edges: tuple[StateDagEdge, ...],
) -> LinearizedStateDag:
    return LinearizedStateDag(
        dispatcher_entry_serial=2,
        state_var_stkoff=0x3C,
        pre_header_serial=None,
        initial_state=None,
        bst_node_blocks=(),
        nodes=nodes,
        edges=edges,
        diagnostics=(),
    )


def _entries(regions: tuple[tuple[StateDagNode, ...], ...]) -> tuple[tuple[int, ...], ...]:
    return tuple(tuple(node.entry_anchor for node in region) for region in regions)


def test_detects_one_maximal_linear_transition_region():
    a, b, c = _node(10), _node(20), _node(30)
    dag = _dag((c, a, b), (_edge(a, b), _edge(b, c)))

    assert _entries(detect_linear_transition_regions(dag)) == ((10, 20, 30),)


def test_join_target_starts_its_own_region():
    a, b, c, d = _node(10), _node(20), _node(30), _node(40)
    dag = _dag(
        (d, b, a, c),
        (
            _edge(a, b),
            _edge(b, d),
            _edge(c, d),
        ),
    )

    assert _entries(detect_linear_transition_regions(dag)) == (
        (10, 20),
        (30,),
        (40,),
    )


def test_non_transition_edges_do_not_extend_regions():
    a, b, c = _node(10), _node(20), _node(30)
    dag = _dag(
        (a, b, c),
        (
            _edge(a, b),
            _edge(b, c, kind=SemanticEdgeKind.CONDITIONAL_RETURN),
        ),
    )

    assert _entries(detect_linear_transition_regions(dag)) == ((10, 20), (30,))


def test_pure_cycle_has_no_region_start():
    a, b = _node(10), _node(20)
    dag = _dag((a, b), (_edge(a, b), _edge(b, a)))

    assert detect_linear_transition_regions(dag) == ()
