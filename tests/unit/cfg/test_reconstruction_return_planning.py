from __future__ import annotations

from dataclasses import dataclass

from d810.transforms.graph_modification import RedirectBranch, RedirectGoto
from d810.transforms.reconstruction_return_planning import (
    plan_reconstruction_return_modifications,
)


class _DummyBuilder:
    @staticmethod
    def goto_redirect(*, source_block: int, target_block: int, old_target: int):
        return RedirectGoto(
            from_serial=source_block,
            old_target=old_target,
            new_target=target_block,
        )

    @staticmethod
    def edge_redirect(*, source_block: int, target_block: int, old_target: int):
        return RedirectBranch(
            from_serial=source_block,
            old_target=old_target,
            new_target=target_block,
        )


class _DummyBlock:
    def __init__(self, preds: tuple[int, ...], succs: tuple[int, ...]):
        self.preds = preds
        self.succs = succs
        self.npred = len(preds)
        self.nsucc = len(succs)


class _DummyFlowGraph:
    def __init__(self, mapping: dict[int, tuple[tuple[int, ...], tuple[int, ...]]]):
        self._mapping = {
            int(k): _DummyBlock(
                tuple(int(v) for v in preds),
                tuple(int(v) for v in succs),
            )
            for k, (preds, succs) in mapping.items()
        }

    def get_block(self, serial: int):
        return self._mapping.get(int(serial))


@dataclass(frozen=True)
class _DummyAnchor:
    block_serial: int
    branch_arm: int | None = None


@dataclass(frozen=True)
class _DummySourceKey:
    state_const: int | None = None


@dataclass(frozen=True)
class _DummyNode:
    shared_suffix_blocks: tuple[int, ...]


@dataclass(frozen=True)
class _DummyEdge:
    kind_name: str
    ordered_path: tuple[int, ...]
    source_anchor: _DummyAnchor
    source_key: _DummySourceKey

    @property
    def kind(self):
        return type("_Kind", (), {"name": self.kind_name})()


@dataclass(frozen=True)
class _DummyDag:
    edges: tuple[_DummyEdge, ...]


class TestPlanReconstructionReturnModifications:
    def test_wires_oneway_anchor_to_common_corridor_entry(self):
        flow_graph = _DummyFlowGraph({
            10: ((4,), (6,)),
        })
        dag = _DummyDag(
            edges=(
                _DummyEdge(
                    kind_name="CONDITIONAL_RETURN",
                    ordered_path=(10, 20, 30),
                    source_anchor=_DummyAnchor(block_serial=10),
                    source_key=_DummySourceKey(),
                ),
            )
        )

        result = plan_reconstruction_return_modifications(
            dag=dag,
            flow_graph=flow_graph,
            builder=_DummyBuilder(),
            claimed_sources=set(),
            dispatcher_serial=6,
            condition_chain_blocks={6},
            common_return_corridor={20, 30},
            artifact_return_blocks=set(),
            node_by_key={},
        )

        assert result.modifications == (
            RedirectGoto(from_serial=10, old_target=6, new_target=20),
        )
        assert [entry.tag for entry in result.log_entries] == ["wire_1way"]
        assert result.skipped_entries == ()

    def test_fallback_wires_intermediate_oneway_hop(self):
        flow_graph = _DummyFlowGraph({
            10: ((4,), (99,)),
            20: ((10,), (30,)),
        })
        dag = _DummyDag(
            edges=(
                _DummyEdge(
                    kind_name="CONDITIONAL_RETURN",
                    ordered_path=(10, 20, 30),
                    source_anchor=_DummyAnchor(block_serial=10),
                    source_key=_DummySourceKey(),
                ),
            )
        )

        result = plan_reconstruction_return_modifications(
            dag=dag,
            flow_graph=flow_graph,
            builder=_DummyBuilder(),
            claimed_sources=set(),
            dispatcher_serial=6,
            condition_chain_blocks={6},
            common_return_corridor=set(),
            artifact_return_blocks=set(),
            node_by_key={},
        )

        assert result.modifications == (
            RedirectGoto(from_serial=10, old_target=99, new_target=20),
        )
        assert [entry.tag for entry in result.log_entries] == ["fallback_1way"]
        assert result.skipped_entries == ()

    def test_redirects_artifact_arm0_writer_instead_of_anchor(self):
        flow_graph = _DummyFlowGraph({
            10: ((4,), (40, 6)),
            40: ((10,), (6,)),
        })
        dag = _DummyDag(
            edges=(
                _DummyEdge(
                    kind_name="CONDITIONAL_RETURN",
                    ordered_path=(10, 40, 45, 50),
                    source_anchor=_DummyAnchor(block_serial=10, branch_arm=0),
                    source_key=_DummySourceKey(),
                ),
            )
        )

        result = plan_reconstruction_return_modifications(
            dag=dag,
            flow_graph=flow_graph,
            builder=_DummyBuilder(),
            claimed_sources=set(),
            dispatcher_serial=6,
            condition_chain_blocks={6},
            common_return_corridor={45, 50},
            artifact_return_blocks={40},
            node_by_key={},
        )

        assert result.modifications == (
            RedirectGoto(from_serial=40, old_target=6, new_target=45),
        )
        assert [entry.tag for entry in result.log_entries] == ["redirect_artifact"]
        assert result.skipped_entries == ()

    def test_does_not_redirect_artifact_to_global_corridor_off_path(self):
        flow_graph = _DummyFlowGraph({
            10: ((4,), (40, 6)),
            40: ((10,), (50,)),
        })
        dag = _DummyDag(
            edges=(
                _DummyEdge(
                    kind_name="CONDITIONAL_RETURN",
                    ordered_path=(10, 40, 50),
                    source_anchor=_DummyAnchor(block_serial=10, branch_arm=0),
                    source_key=_DummySourceKey(),
                ),
            )
        )

        result = plan_reconstruction_return_modifications(
            dag=dag,
            flow_graph=flow_graph,
            builder=_DummyBuilder(),
            claimed_sources=set(),
            dispatcher_serial=6,
            condition_chain_blocks={6},
            common_return_corridor={20, 50},
            artifact_return_blocks={40},
            node_by_key={},
        )

        assert result.modifications == ()
        assert result.log_entries == ()
        assert [(entry.source_block, entry.reason) for entry in result.skipped_entries] == [
            (40, "artifact_suffix_not_forward"),
        ]

    def test_preserves_oneway_terminal_stop_instead_of_common_corridor(self):
        flow_graph = _DummyFlowGraph({
            10: ((4,), (126,)),
            126: ((10,), ()),
        })
        dag = _DummyDag(
            edges=(
                _DummyEdge(
                    kind_name="CONDITIONAL_RETURN",
                    ordered_path=(10, 20, 126),
                    source_anchor=_DummyAnchor(block_serial=10),
                    source_key=_DummySourceKey(),
                ),
            )
        )

        result = plan_reconstruction_return_modifications(
            dag=dag,
            flow_graph=flow_graph,
            builder=_DummyBuilder(),
            claimed_sources=set(),
            dispatcher_serial=6,
            condition_chain_blocks={6},
            common_return_corridor={20, 126},
            artifact_return_blocks=set(),
            node_by_key={},
        )

        assert result.modifications == ()
        assert [
            (entry.source_block, entry.branch_arm, entry.target_block, entry.tag)
            for entry in result.log_entries
        ] == [(10, None, 126, "terminal_stop_preserved")]
        assert result.skipped_entries == ()

    def test_preserves_terminal_stop_arm_before_arm0_artifact_redirect(self):
        flow_graph = _DummyFlowGraph({
            24: ((18,), (34, 126)),
            34: ((24,), (2,)),
            126: ((24,), ()),
        })
        dag = _DummyDag(
            edges=(
                _DummyEdge(
                    kind_name="CONDITIONAL_RETURN",
                    ordered_path=(24, 20, 126),
                    source_anchor=_DummyAnchor(block_serial=24),
                    source_key=_DummySourceKey(),
                ),
            )
        )

        result = plan_reconstruction_return_modifications(
            dag=dag,
            flow_graph=flow_graph,
            builder=_DummyBuilder(),
            claimed_sources=set(),
            dispatcher_serial=2,
            condition_chain_blocks={2},
            common_return_corridor={20, 126},
            artifact_return_blocks={34},
            node_by_key={},
        )

        assert result.modifications == ()
        assert [
            (entry.source_block, entry.branch_arm, entry.target_block, entry.tag)
            for entry in result.log_entries
        ] == [(24, 1, 126, "terminal_stop_preserved")]
        assert result.skipped_entries == ()

    def test_does_not_redirect_deep_artifact_back_to_earlier_suffix_entry(self):
        flow_graph = _DummyFlowGraph({
            33: ((31,), (34, 35)),
            34: ((33,), (2,)),
        })
        dag = _DummyDag(
            edges=(
                _DummyEdge(
                    kind_name="CONDITIONAL_RETURN",
                    ordered_path=(20, 23, 26, 30, 34, 37, 40),
                    source_anchor=_DummyAnchor(block_serial=33),
                    source_key=_DummySourceKey(),
                ),
            )
        )

        result = plan_reconstruction_return_modifications(
            dag=dag,
            flow_graph=flow_graph,
            builder=_DummyBuilder(),
            claimed_sources=set(),
            dispatcher_serial=2,
            condition_chain_blocks={2},
            common_return_corridor={20, 23, 26},
            artifact_return_blocks={34},
            node_by_key={},
        )

        assert result.modifications == ()
        assert result.log_entries == ()
        assert [(entry.source_block, entry.reason) for entry in result.skipped_entries] == [
            (34, "artifact_suffix_not_forward"),
        ]

    def test_skips_claimed_anchor(self):
        flow_graph = _DummyFlowGraph({
            10: ((4,), (6,)),
        })
        dag = _DummyDag(
            edges=(
                _DummyEdge(
                    kind_name="CONDITIONAL_RETURN",
                    ordered_path=(10, 20, 30),
                    source_anchor=_DummyAnchor(block_serial=10),
                    source_key=_DummySourceKey(),
                ),
            )
        )

        result = plan_reconstruction_return_modifications(
            dag=dag,
            flow_graph=flow_graph,
            builder=_DummyBuilder(),
            claimed_sources={10},
            dispatcher_serial=6,
            condition_chain_blocks={6},
            common_return_corridor={20, 30},
            artifact_return_blocks=set(),
            node_by_key={},
        )

        assert result.modifications == ()
        assert result.log_entries == ()
        assert [(entry.source_block, entry.reason) for entry in result.skipped_entries] == [
            (10, "anchor_claimed"),
        ]
