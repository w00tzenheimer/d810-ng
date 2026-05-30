from __future__ import annotations

from dataclasses import dataclass

from d810.cfg.semantic_region_entry import (
    EntryEligibility,
    resolve_semantic_entry_candidate,
)
from d810.analyses.control_flow.linearized_state_dag import (
    LinearizedStateDag,
    RedirectSourceKind,
    SemanticEdgeKind,
    StateDagEdge,
    StateDagNode,
    StateDagNodeKey,
    StateNodeKind,
    StateRedirectAnchor,
)


@dataclass(frozen=True)
class _FakeBlockView:
    succs_by_serial: dict[int, tuple[int | None, ...]]
    unreadable_nsucc: frozenset[int] = frozenset()

    def block_exists(self, serial: int) -> bool:
        return serial in self.succs_by_serial

    def nsucc(self, serial: int) -> int | None:
        if serial in self.unreadable_nsucc:
            return None
        succs = self.succs_by_serial.get(serial)
        return None if succs is None else len(succs)

    def succ(self, serial: int, index: int = 0) -> int | None:
        succs = self.succs_by_serial.get(serial)
        if succs is None or index >= len(succs):
            return None
        return succs[index]


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
    target: StateDagNode,
    *,
    kind: SemanticEdgeKind = SemanticEdgeKind.TRANSITION,
    source_block: int | None = None,
) -> StateDagEdge:
    block_serial = source.entry_anchor if source_block is None else source_block
    return StateDagEdge(
        kind=kind,
        source_key=source.key,
        target_key=target.key,
        target_state=target.key.state_const,
        target_entry_anchor=target.entry_anchor,
        target_label=target.state_label,
        source_anchor=StateRedirectAnchor(
            kind=RedirectSourceKind.EXIT_BLOCK,
            block_serial=block_serial,
            branch_arm=None,
        ),
        ordered_path=(block_serial, target.entry_anchor),
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


def _resolve(
    dag: LinearizedStateDag,
    head: StateDagNode,
    *,
    region_anchors: frozenset[int] | None = None,
    block_view: _FakeBlockView | None = None,
):
    return resolve_semantic_entry_candidate(
        dag=dag,
        region_head_node=head,
        region_anchors=region_anchors or frozenset({head.entry_anchor}),
        block_view=block_view or _FakeBlockView({}),
        transition_kind=SemanticEdgeKind.TRANSITION,
    )


def test_no_transition_incoming():
    source, head = _node(10), _node(20)
    dag = _dag((source, head), ())

    candidate = _resolve(dag, head)

    assert candidate.eligibility is EntryEligibility.NO_TRANSITION_INCOMING
    assert candidate.transition_source_blocks == ()


def test_multiple_transition_source_blocks():
    a, b, head = _node(10), _node(20), _node(30)
    dag = _dag(
        (a, b, head),
        (_edge(a, head), _edge(b, head)),
    )

    candidate = _resolve(dag, head)

    assert candidate.eligibility is EntryEligibility.MULTIPLE_DISTINCT_SPLICE_SOURCES
    assert candidate.transition_source_blocks == (10, 20)


def test_source_block_dead():
    source, head = _node(10), _node(20)
    dag = _dag((source, head), (_edge(source, head),))

    candidate = _resolve(dag, head)

    assert candidate.eligibility is EntryEligibility.SOURCE_DEAD
    assert candidate.splice_source_block == 10


def test_source_inside_region():
    source, head = _node(10), _node(20)
    dag = _dag((source, head), (_edge(source, head),))

    candidate = _resolve(
        dag,
        head,
        region_anchors=frozenset({10, 20}),
        block_view=_FakeBlockView({10: (99,)}),
    )

    assert candidate.eligibility is EntryEligibility.SOURCE_INSIDE_REGION
    assert candidate.splice_source_block == 10


def test_source_has_nsucc_not_one():
    source, head = _node(10), _node(20)
    dag = _dag((source, head), (_edge(source, head),))

    candidate = _resolve(dag, head, block_view=_FakeBlockView({10: (11, 12)}))

    assert candidate.eligibility is EntryEligibility.SOURCE_NOT_1WAY
    assert candidate.splice_old_target is None


def test_source_successor_unreadable():
    source, head = _node(10), _node(20)
    dag = _dag((source, head), (_edge(source, head),))

    candidate = _resolve(dag, head, block_view=_FakeBlockView({10: (None,)}))

    assert candidate.eligibility is EntryEligibility.SOURCE_OLD_TARGET_UNREADABLE
    assert candidate.splice_old_target is None


def test_valid_one_way_source():
    source, head = _node(10), _node(20)
    dag = _dag((source, head), (_edge(source, head),))

    candidate = _resolve(dag, head, block_view=_FakeBlockView({10: (99,)}))

    assert candidate.eligibility is EntryEligibility.UNCONDITIONAL_1WAY
    assert candidate.splice_source_block == 10
    assert candidate.splice_old_target == 99


def test_non_transition_incoming_is_reported_but_does_not_block_valid_transition():
    transition_source, conditional_source, head = _node(10), _node(20), _node(30)
    dag = _dag(
        (transition_source, conditional_source, head),
        (
            _edge(transition_source, head),
            _edge(
                conditional_source,
                head,
                kind=SemanticEdgeKind.CONDITIONAL_RETURN,
            ),
        ),
    )

    candidate = _resolve(dag, head, block_view=_FakeBlockView({10: (99,)}))

    assert candidate.eligibility is EntryEligibility.UNCONDITIONAL_1WAY
    assert candidate.transition_source_blocks == (10,)
    assert candidate.nontransition_source_blocks == (20,)
