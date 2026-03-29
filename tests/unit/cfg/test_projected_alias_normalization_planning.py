from __future__ import annotations

from types import SimpleNamespace

from d810.cfg.graph_modification import RedirectGoto
from d810.cfg.projected_alias_normalization_planning import (
    ProjectedAliasNormalizationAction,
    collect_projected_alias_normalization_actions,
)


class _FakeBlock:
    def __init__(self, succs: tuple[int, ...]):
        self.succs = succs


class _FakeFlowGraph:
    def __init__(self, blocks: dict[int, _FakeBlock]):
        self._blocks = blocks

    def get_block(self, serial: int):
        return self._blocks.get(int(serial))


def test_collect_projected_alias_normalization_actions_adds_new_redirect() -> None:
    actions = collect_projected_alias_normalization_actions(
        dag=SimpleNamespace(),
        projected_flow_graph=_FakeFlowGraph({95: _FakeBlock((160,)), 202: _FakeBlock(())}),
        dispatcher_serial=2,
        redirected_blocks={95},
        bst_node_blocks={2},
        modifications=[],
        emitted=set(),
        resolve_projected_path_tail_target=lambda dag, *, source_block, bst_node_blocks: (0x24E2E77A, 202),
    )

    assert actions == (
        ProjectedAliasNormalizationAction(
            source_block=95,
            current_target=160,
            target_entry=202,
            modification=RedirectGoto(from_serial=95, old_target=160, new_target=202),
            replace_index=None,
            replaced_target=None,
        ),
    )


def test_collect_projected_alias_normalization_actions_replaces_existing_redirect() -> None:
    actions = collect_projected_alias_normalization_actions(
        dag=SimpleNamespace(),
        projected_flow_graph=_FakeFlowGraph({95: _FakeBlock((160,)), 202: _FakeBlock(())}),
        dispatcher_serial=2,
        redirected_blocks={95},
        bst_node_blocks={2},
        modifications=[RedirectGoto(from_serial=95, old_target=2, new_target=160)],
        emitted={(95, 160)},
        resolve_projected_path_tail_target=lambda dag, *, source_block, bst_node_blocks: (0x24E2E77A, 202),
    )

    assert actions == (
        ProjectedAliasNormalizationAction(
            source_block=95,
            current_target=160,
            target_entry=202,
            modification=RedirectGoto(from_serial=95, old_target=2, new_target=202),
            replace_index=0,
            replaced_target=160,
        ),
    )
