from __future__ import annotations

from types import SimpleNamespace

from d810.analyses.control_flow.linearized_state_dag import (
    RedirectSourceKind,
    SemanticEdgeKind,
    StateDagEdge,
    StateDagNode,
    StateDagNodeKey,
    StateNodeKind,
    StateRedirectAnchor,
)
from d810.analyses.control_flow.shared_suffix_discovery import (
    can_rewrite_shared_suffix_family_fallback,
    has_prior_branch_cut_for_state,
    is_shared_suffix_conditional_tail,
    pred_split_target_reaches_via_pred,
)


def _node(
    *,
    entry: int,
    handler: int,
    state: int,
    label: str | None = None,
    owned: tuple[int, ...] = (),
    exclusive: tuple[int, ...] = (),
    shared_suffix: tuple[int, ...] = (),
) -> StateDagNode:
    return StateDagNode(
        key=StateDagNodeKey(handler_serial=handler, state_const=state),
        kind=StateNodeKind.EXACT,
        state_label=label or hex(state),
        handler_serial=handler,
        entry_anchor=entry,
        owned_blocks=owned,
        exclusive_blocks=exclusive,
        shared_suffix_blocks=shared_suffix,
        local_segments=(),
        local_edges=(),
    )


def _edge(
    *,
    source_handler: int,
    target_key: StateDagNodeKey | None,
    target_state: int | None,
    target_entry: int | None = None,
    source_block: int = 40,
    ordered_path: tuple[int, ...] = (),
) -> StateDagEdge:
    return StateDagEdge(
        kind=SemanticEdgeKind.CONDITIONAL_TRANSITION,
        source_key=StateDagNodeKey(handler_serial=source_handler, state_const=source_handler),
        target_key=target_key,
        target_state=target_state,
        target_entry_anchor=target_entry,
        target_label=hex(target_state) if target_state is not None else "unknown",
        source_anchor=StateRedirectAnchor(
            kind=RedirectSourceKind.CONDITIONAL_BRANCH,
            block_serial=source_block,
            branch_arm=0,
        ),
        ordered_path=ordered_path,
        last_write_site=None,
    )


class _DummyBlock:
    def __init__(self, *, succs: tuple[int, ...] = (), preds: tuple[int, ...] = ()):
        self.succs = succs
        self.preds = preds


class _DummyFlowGraph:
    def __init__(self, mapping: dict[int, _DummyBlock]):
        self._mapping = {int(k): v for k, v in mapping.items()}

    def get_block(self, serial: int):
        return self._mapping.get(int(serial))

    def successors(self, serial: int):
        block = self.get_block(serial)
        return () if block is None else block.succs


class TestSharedSuffixDiscovery:
    def test_has_prior_branch_cut_for_state_detects_earlier_conditional_anchor(self) -> None:
        target_node = _node(entry=24, handler=24, state=0x11)
        dag = SimpleNamespace(
            nodes=(target_node,),
            edges=(
                _edge(
                    source_handler=40,
                    target_key=target_node.key,
                    target_state=0x11,
                    target_entry=24,
                    source_block=40,
                    ordered_path=(50, 60),
                ),
            ),
        )

        assert has_prior_branch_cut_for_state(
            dag,
            source_block=60,
            state_value=0x11,
            bst_node_blocks={2, 6},
        )

    def test_has_prior_branch_cut_for_state_allows_immediate_conditional_leaf_tail(self) -> None:
        target_node = _node(entry=24, handler=24, state=0x11)
        dag = SimpleNamespace(
            nodes=(target_node,),
            edges=(
                _edge(
                    source_handler=40,
                    target_key=target_node.key,
                    target_state=0x11,
                    target_entry=24,
                    source_block=40,
                    ordered_path=(40, 60),
                ),
            ),
        )

        assert not has_prior_branch_cut_for_state(
            dag,
            source_block=60,
            state_value=0x11,
            bst_node_blocks={2, 6},
        )

    def test_is_shared_suffix_conditional_tail_requires_suffix_membership(self) -> None:
        source_node = _node(entry=10, handler=10, state=0x22, shared_suffix=(60,))
        dag = SimpleNamespace(
            nodes=(source_node,),
            edges=(
                _edge(
                    source_handler=10,
                    target_key=source_node.key,
                    target_state=0x22,
                    source_block=40,
                    ordered_path=(50, 60),
                ),
            ),
        )

        assert is_shared_suffix_conditional_tail(dag, source_block=60)
        assert not is_shared_suffix_conditional_tail(dag, source_block=50)

    def test_is_shared_suffix_conditional_tail_allows_immediate_conditional_leaf_tail(self) -> None:
        source_node = _node(entry=10, handler=10, state=0x22, shared_suffix=(60,))
        dag = SimpleNamespace(
            nodes=(source_node,),
            edges=(
                _edge(
                    source_handler=10,
                    target_key=source_node.key,
                    target_state=0x22,
                    source_block=40,
                    ordered_path=(40, 60),
                ),
            ),
        )

        assert not is_shared_suffix_conditional_tail(dag, source_block=60)

    def test_can_rewrite_shared_suffix_family_fallback_matches_owner_fallback(self) -> None:
        owner = _node(entry=20, handler=20, state=0x11, owned=(12,))
        fallback = _node(
            entry=30,
            handler=30,
            state=0x11,
            label="0x00000011_fallback",
        )
        dag = SimpleNamespace(nodes=(owner, fallback), edges=())

        assert can_rewrite_shared_suffix_family_fallback(
            dag,
            source_block=40,
            target_entry=30,
            current_preds=(12,),
            bst_node_blocks={2, 6},
        )

    def test_can_rewrite_shared_suffix_family_fallback_allows_pruned_oneway_tail(self) -> None:
        dag = SimpleNamespace(nodes=(), edges=())
        flow_graph = _DummyFlowGraph(
            {
                12: _DummyBlock(succs=(40,), preds=(8,)),
                40: _DummyBlock(succs=(2,), preds=(12,)),
            }
        )

        assert can_rewrite_shared_suffix_family_fallback(
            dag,
            source_block=40,
            target_entry=30,
            current_preds=(12,),
            bst_node_blocks={2, 6},
            flow_graph=flow_graph,
        )

    def test_can_rewrite_shared_suffix_family_fallback_allows_multi_pred_funnel_tail(self) -> None:
        dag = SimpleNamespace(nodes=(), edges=())
        flow_graph = _DummyFlowGraph(
            {
                12: _DummyBlock(succs=(40,), preds=(8,)),
                13: _DummyBlock(succs=(40,), preds=(9,)),
                40: _DummyBlock(succs=(2,), preds=(12, 13)),
            }
        )

        assert can_rewrite_shared_suffix_family_fallback(
            dag,
            source_block=40,
            target_entry=30,
            current_preds=(12, 13),
            bst_node_blocks={2, 6},
            flow_graph=flow_graph,
        )

    def test_pred_split_target_reaches_via_pred_ignores_source_block(self) -> None:
        flow_graph = _DummyFlowGraph(
            {
                30: _DummyBlock(succs=(50,)),
                50: _DummyBlock(succs=(20,)),
                20: _DummyBlock(succs=()),
            }
        )

        assert pred_split_target_reaches_via_pred(
            flow_graph,
            target_entry=30,
            via_pred=20,
            source_block=10,
            ignored_blocks=set(),
        )
