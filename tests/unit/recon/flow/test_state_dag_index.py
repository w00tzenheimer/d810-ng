from __future__ import annotations

from types import SimpleNamespace

from d810.ir.state_dag_key import StateDagNodeKey
from d810.analyses.control_flow.state_dag_index import StateDagIndex


def _edge(
    *,
    source_block: int,
    branch_arm: int | None,
    source_state: int,
    target_state: int | None,
    target_entry: int,
    source_key: object | None = None,
    target_key: object | None = None,
    proof_source: str | None = None,
    last_write_site: tuple[int, int] | None = None,
):
    if source_key is None:
        source_key = StateDagNodeKey(
            handler_serial=source_block,
            state_const=source_state,
        )
    if target_key is None:
        target_key = StateDagNodeKey(
            handler_serial=target_entry,
            state_const=target_state,
        )
    return SimpleNamespace(
        source_anchor=SimpleNamespace(
            block_serial=source_block,
            branch_arm=branch_arm,
        ),
        source_key=source_key,
        target_key=target_key,
        target_state=target_state,
        target_entry_anchor=target_entry,
        ordered_path=(source_block, target_entry),
        proof_source=proof_source,
        last_write_site=last_write_site,
        kind=SimpleNamespace(name="TRANSITION"),
    )


def test_state_dag_index_returns_plural_parent_edges() -> None:
    dag = SimpleNamespace(
        edges=(
            _edge(
                source_block=10,
                branch_arm=0,
                source_state=0x1000,
                target_state=0x2000,
                target_entry=20,
            ),
            _edge(
                source_block=11,
                branch_arm=None,
                source_state=0x1001,
                target_state=0x2000,
                target_entry=20,
            ),
        )
    )

    index = StateDagIndex.from_dag(dag)

    parents = index.incoming_for_state(0x2000)
    assert len(parents) == 2
    assert {edge.source_block for edge in parents} == {10, 11}
    assert index.incoming_to_entry(20) == parents


def test_state_dag_index_unique_anchor_query_abstains_on_ambiguity() -> None:
    dag = SimpleNamespace(
        edges=(
            _edge(
                source_block=10,
                branch_arm=0,
                source_state=0x1000,
                target_state=0x2000,
                target_entry=20,
            ),
            _edge(
                source_block=10,
                branch_arm=0,
                source_state=0x1000,
                target_state=0x3000,
                target_entry=30,
            ),
        )
    )

    index = StateDagIndex.from_dag(dag)

    assert len(index.edges_from_anchor(10, 0)) == 2
    assert index.edge_from_anchor(10, 0) is None


def test_parents_of_uses_full_dag_node_identity_not_state_value() -> None:
    first_key = StateDagNodeKey(handler_serial=20, state_const=0x2000)
    second_key = StateDagNodeKey(handler_serial=21, state_const=0x2000)
    dag = SimpleNamespace(
        edges=(
            _edge(
                source_block=10,
                branch_arm=None,
                source_state=0x1000,
                target_state=0x2000,
                target_entry=20,
                target_key=first_key,
            ),
            _edge(
                source_block=11,
                branch_arm=None,
                source_state=0x1001,
                target_state=0x2000,
                target_entry=21,
                target_key=second_key,
            ),
        )
    )

    index = StateDagIndex.from_dag(dag)

    assert tuple(edge.source_block for edge in index.parents_of(first_key)) == (10,)
    assert tuple(edge.source_block for edge in index.parents_of(second_key)) == (11,)
    assert {edge.source_block for edge in index.incoming_for_state(0x2000)} == {10, 11}


def test_parents_of_supports_range_only_node_keys() -> None:
    range_key = StateDagNodeKey(
        handler_serial=30,
        range_lo=0x2000,
        range_hi=0x3000,
    )
    dag = SimpleNamespace(
        edges=(
            _edge(
                source_block=10,
                branch_arm=1,
                source_state=0x1000,
                target_state=None,
                target_entry=30,
                target_key=range_key,
            ),
        )
    )

    index = StateDagIndex.from_dag(dag)

    parents = index.parents_of(range_key)
    assert len(parents) == 1
    assert parents[0].source_block == 10
    assert index.incoming_for_state(0x2000) == ()


def test_state_dag_index_preserves_loop_recovery_edge_metadata() -> None:
    dag = SimpleNamespace(
        edges=(
            _edge(
                source_block=10,
                branch_arm=1,
                source_state=0x1000,
                target_state=0x2000,
                target_entry=20,
                proof_source="state_dispatcher_map",
                last_write_site=(12, 0x401234),
            ),
        )
    )

    edge = StateDagIndex.from_dag(dag).incoming_to_entry(20)[0]

    assert edge.semantic_kind == "TRANSITION"
    assert edge.proof_source == "state_dispatcher_map"
    assert edge.last_write_site == (12, 0x401234)
