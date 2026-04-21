from __future__ import annotations

from types import SimpleNamespace

import ida_hexrays

from d810.cfg.flowgraph import BlockSnapshot, FlowGraph
from d810.cfg.graph_modification import RedirectGoto
from d810.cfg.modification_builder import ModificationBuilder
from d810.optimizers.microcode.flow.flattening.hodur.prototypes.exact_conditional_bridge import (
    ExactConditionalBridgeNodeLoweringStrategy,
    collect_exact_conditional_bridge_sites,
)


def _make_bridge_fixture():
    flow_graph = FlowGraph(
        blocks={
            2: BlockSnapshot(2, 0, (), (69,), 0, 0, ()),
            69: BlockSnapshot(69, 0, (2,), (164,), 0, 0, ()),
            160: BlockSnapshot(160, 0, (), (), 0, 0, ()),
            161: BlockSnapshot(161, 0, (163,), (), 0, 0, ()),
            163: BlockSnapshot(163, 0, (164, 165), (161,), 0, 0, ()),
            164: BlockSnapshot(164, 0, (69,), (163,), 0, 0, ()),
            165: BlockSnapshot(165, 0, (), (163,), 0, 0, ()),
        },
        entry_serial=161,
        func_ea=0x180012B60,
    )
    bridge_edge = SimpleNamespace(
        kind=SimpleNamespace(name="CONDITIONAL_TRANSITION"),
        source_key=SimpleNamespace(state_const=0x11111111),
        source_anchor=SimpleNamespace(block_serial=163, branch_arm=1),
        target_state=0x22222222,
        target_entry_anchor=160,
        ordered_path=(161, 163, 164, 69),
    )
    sibling_edge = SimpleNamespace(
        kind=SimpleNamespace(name="CONDITIONAL_TRANSITION"),
        source_key=SimpleNamespace(state_const=0x11111111),
        source_anchor=SimpleNamespace(block_serial=163, branch_arm=0),
        target_state=0x33333333,
        target_entry_anchor=72,
        ordered_path=(161, 163, 165),
    )
    round_summary = SimpleNamespace(
        dag=SimpleNamespace(edges=(bridge_edge, sibling_edge)),
        plannable_edges=(
            SimpleNamespace(edge=bridge_edge),
            SimpleNamespace(edge=sibling_edge),
        ),
    )
    return flow_graph, bridge_edge, round_summary


def test_collect_exact_conditional_bridge_sites_selects_blk163_bridge_case():
    flow_graph, _edge, round_summary = _make_bridge_fixture()

    sites = collect_exact_conditional_bridge_sites(round_summary, flow_graph)

    assert len(sites) == 1
    site = sites[0]
    assert site.source_block == 163
    assert site.bridge_tail == 164
    assert site.exit_block == 69
    assert site.terminal_tail == 165
    assert site.target_entry == 160


def test_exact_conditional_bridge_strategy_plans_bridge_redirect_for_blk163(monkeypatch):
    flow_graph, edge, round_summary = _make_bridge_fixture()
    builder = ModificationBuilder.from_snapshot(
        SimpleNamespace(flow_graph=flow_graph, mba=SimpleNamespace())
    )
    setup = SimpleNamespace(
        builder=builder,
        bst_node_blocks=(2,),
        dispatcher_region=(2,),
    )
    monkeypatch.setattr(
        "d810.optimizers.microcode.flow.flattening.hodur.prototypes.exact_conditional_bridge.build_semantic_exact_round_summary",
        lambda _snapshot: (setup, round_summary),
    )

    snapshot = SimpleNamespace(
        mba=SimpleNamespace(entry_ea=0x180012B60, maturity=ida_hexrays.MMAT_GLBOPT1),
        state_machine=SimpleNamespace(transitions=()),
        bst_result=SimpleNamespace(pre_header_serial=None),
        flow_graph=flow_graph,
        bst_dispatcher_serial=2,
    )

    fragment = ExactConditionalBridgeNodeLoweringStrategy().plan(snapshot)

    assert fragment is not None
    redirects = [mod for mod in fragment.modifications if isinstance(mod, RedirectGoto)]
    assert any(
        mod.from_serial == 69 and mod.old_target == 2 and mod.new_target == 160
        for mod in redirects
    )
    assert fragment.metadata["bridge_case"] is True
