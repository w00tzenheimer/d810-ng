from __future__ import annotations

from types import SimpleNamespace

import ida_hexrays

from d810.cfg.flow.conditional_alias import (
    analyze_duplicate_alias_conditional_sites,
)
from d810.cfg.flowgraph import BlockSnapshot, FlowGraph, InsnSnapshot, MopSnapshot
from d810.cfg.graph_modification import DuplicateAndRedirect, NopInstructions
from d810.cfg.modification_builder import ModificationBuilder
from d810.optimizers.microcode.flow.flattening.hodur.strategies.exact_conditional_alias import (
    ExactConditionalAliasNodeLoweringStrategy,
)
from d810.optimizers.microcode.flow.flattening.hodur.strategies import (
    exact_conditional_alias as exact_conditional_alias_module,
)
from d810.optimizers.microcode.flow.flattening.hodur.strategies.exact_conditional_fork import (
    ExactConditionalForkNodeLoweringStrategy,
    analyze_exact_conditional_fork_sites,
)
from d810.optimizers.microcode.flow.flattening.hodur.strategies import (
    exact_conditional_fork as exact_conditional_fork_module,
)
from d810.optimizers.microcode.flow.flattening.hodur.strategies.exact_conditional_node import (
    analyze_exact_conditional_sites,
)


def _make_alias_fixture():
    flow_graph = FlowGraph(
        blocks={
            2: BlockSnapshot(2, 0, (33,), (), 0, 0, ()),
            28: BlockSnapshot(28, 0, (29, 33), (98, 136), 0, 0, ()),
            29: BlockSnapshot(29, 0, (33,), (28,), 0, 0, ()),
            33: BlockSnapshot(33, 0, (2,), (28, 29, 136), 0, 0, ()),
            34: BlockSnapshot(34, 0, (28,), (), 0, 0, ()),
            98: BlockSnapshot(98, 0, (28,), (), 0, 0, ()),
            136: BlockSnapshot(136, 0, (28, 33), (), 0, 0, ()),
        },
        entry_serial=28,
        func_ea=0x180012B60,
    )
    edge_a = SimpleNamespace(
        kind=SimpleNamespace(name="CONDITIONAL_TRANSITION"),
        source_key=SimpleNamespace(state_const=0x11111111),
        source_anchor=SimpleNamespace(block_serial=28, branch_arm=0),
        target_state=0x27EF1411,
        target_entry_anchor=34,
        ordered_path=(28, 29, 33),
    )
    edge_b = SimpleNamespace(
        kind=SimpleNamespace(name="CONDITIONAL_TRANSITION"),
        source_key=SimpleNamespace(state_const=0x11111111),
        source_anchor=SimpleNamespace(block_serial=28, branch_arm=1),
        target_state=0x27EF1411,
        target_entry_anchor=34,
        ordered_path=(28, 33),
    )
    round_summary = SimpleNamespace(
        dag=SimpleNamespace(edges=(edge_a, edge_b)),
        plannable_edges=(
            SimpleNamespace(edge=edge_a),
            SimpleNamespace(edge=edge_b),
        ),
    )
    return flow_graph, round_summary


def _make_semantic_fork_fixture():
    flow_graph = FlowGraph(
        blocks={
            15: BlockSnapshot(15, 0, (16, 17), (), 0, 0, ()),
            16: BlockSnapshot(16, 0, (71,), (15,), 0, 0, ()),
            17: BlockSnapshot(17, 0, (202,), (15,), 0, 0, ()),
            14: BlockSnapshot(14, 0, (136,), (), 0, 0, ()),
            71: BlockSnapshot(71, 0, (2,), (16,), 0, 0, ()),
            72: BlockSnapshot(72, 0, (177,), (), 0, 0, ()),
            202: BlockSnapshot(202, 0, (203,), (), 0, 0, ()),
        },
        entry_serial=15,
        func_ea=0x180012B60,
    )
    fallback_key = SimpleNamespace(handler_serial=14, state_const=0x474EEEBB)
    fallback_node = SimpleNamespace(
        key=fallback_key,
        entry_anchor=14,
        state_label="0x474EEEBB_fallback",
        exclusive_blocks=(),
        owned_blocks=(14,),
        shared_suffix_blocks=(),
    )
    edge_a = SimpleNamespace(
        kind=SimpleNamespace(name="CONDITIONAL_TRANSITION"),
        source_key=SimpleNamespace(state_const=0x6107F8EC),
        source_anchor=SimpleNamespace(block_serial=15, branch_arm=0),
        target_state=0x296F2452,
        target_entry_anchor=202,
        target_key=SimpleNamespace(handler_serial=202, state_const=0x296F2452),
        ordered_path=(15, 17),
    )
    edge_b = SimpleNamespace(
        kind=SimpleNamespace(name="CONDITIONAL_TRANSITION"),
        source_key=SimpleNamespace(state_const=0x6107F8EC),
        source_anchor=SimpleNamespace(block_serial=15, branch_arm=1),
        target_state=0x4C77464F,
        target_entry_anchor=72,
        target_key=fallback_key,
        ordered_path=(15, 16),
    )
    dag = SimpleNamespace(edges=(edge_a, edge_b), nodes=(fallback_node,))
    round_summary = SimpleNamespace(
        dag=dag,
        plannable_edges=(),
    )
    return flow_graph, round_summary


def _make_prefixed_path_semantic_fork_fixture():
    flow_graph = FlowGraph(
        blocks={
            15: BlockSnapshot(15, 0, (16, 17), (), 0, 0, ()),
            16: BlockSnapshot(16, 0, (71,), (15,), 0, 0, ()),
            17: BlockSnapshot(17, 0, (202,), (15,), 0, 0, ()),
            14: BlockSnapshot(14, 0, (136,), (), 0, 0, ()),
            71: BlockSnapshot(71, 0, (2,), (16,), 0, 0, ()),
            202: BlockSnapshot(202, 0, (203,), (17,), 0, 0, ()),
        },
        entry_serial=15,
        func_ea=0x180012B60,
    )
    fallback_key = SimpleNamespace(handler_serial=14, state_const=0x474EEEBB)
    fallback_node = SimpleNamespace(
        key=fallback_key,
        entry_anchor=14,
        state_label="0x474EEEBB_fallback",
        exclusive_blocks=(),
        owned_blocks=(14,),
        shared_suffix_blocks=(),
    )
    edge_a = SimpleNamespace(
        kind=SimpleNamespace(name="CONDITIONAL_TRANSITION"),
        source_key=SimpleNamespace(state_const=0x6107F8EC),
        source_anchor=SimpleNamespace(block_serial=15, branch_arm=0),
        target_state=0x296F2452,
        target_entry_anchor=202,
        target_key=SimpleNamespace(handler_serial=202, state_const=0x296F2452),
        ordered_path=(99, 15, 17),
    )
    edge_b = SimpleNamespace(
        kind=SimpleNamespace(name="CONDITIONAL_TRANSITION"),
        source_key=SimpleNamespace(state_const=0x6107F8EC),
        source_anchor=SimpleNamespace(block_serial=15, branch_arm=1),
        target_state=0x4C77464F,
        target_entry_anchor=72,
        target_key=fallback_key,
        ordered_path=(98, 15, 16),
    )
    dag = SimpleNamespace(edges=(edge_a, edge_b), nodes=(fallback_node,))
    round_summary = SimpleNamespace(
        dag=dag,
        plannable_edges=(),
    )
    return flow_graph, round_summary


def _make_prefixed_path_semantic_fork_fixture_with_state_writes():
    mov = int(ida_hexrays.m_mov)
    goto = int(ida_hexrays.m_goto)
    mop_n = int(ida_hexrays.mop_n)
    mop_S = int(ida_hexrays.mop_S)
    mop_b = int(ida_hexrays.mop_b)
    state_var = lambda: MopSnapshot(t=mop_S, size=4, stkoff=0x7BC)
    flow_graph = FlowGraph(
        blocks={
            15: BlockSnapshot(15, 0, (16, 17), (), 0, 0, ()),
            16: BlockSnapshot(
                16,
                0,
                (71,),
                (15,),
                0,
                0,
                (
                    InsnSnapshot(
                        opcode=mov,
                        ea=0x180012EE2,
                        operands=(),
                        l=MopSnapshot(t=mop_n, size=4, value=0x4C77464F),
                        d=state_var(),
                    ),
                    InsnSnapshot(
                        opcode=goto,
                        ea=0x180012EEA,
                        operands=(),
                        l=MopSnapshot(t=mop_b, size=4, block_ref=71),
                    ),
                ),
            ),
            17: BlockSnapshot(
                17,
                0,
                (202,),
                (15,),
                0,
                0,
                (
                    InsnSnapshot(
                        opcode=mov,
                        ea=0x180012EEC,
                        operands=(),
                        l=MopSnapshot(t=mop_n, size=4, value=0x296F2452),
                        d=state_var(),
                    ),
                    InsnSnapshot(
                        opcode=goto,
                        ea=0x180012EF8,
                        operands=(),
                        l=MopSnapshot(t=mop_b, size=4, block_ref=202),
                    ),
                ),
            ),
            14: BlockSnapshot(14, 0, (136,), (), 0, 0, ()),
            71: BlockSnapshot(71, 0, (2,), (16,), 0, 0, ()),
            202: BlockSnapshot(202, 0, (203,), (17,), 0, 0, ()),
        },
        entry_serial=15,
        func_ea=0x180012B60,
    )
    fallback_key = SimpleNamespace(handler_serial=14, state_const=0x474EEEBB)
    fallback_node = SimpleNamespace(
        key=fallback_key,
        entry_anchor=14,
        state_label="0x474EEEBB_fallback",
        exclusive_blocks=(),
        owned_blocks=(14,),
        shared_suffix_blocks=(),
    )
    edge_a = SimpleNamespace(
        kind=SimpleNamespace(name="CONDITIONAL_TRANSITION"),
        source_key=SimpleNamespace(state_const=0x6107F8EC),
        source_anchor=SimpleNamespace(block_serial=15, branch_arm=0),
        target_state=0x296F2452,
        target_entry_anchor=202,
        target_key=SimpleNamespace(handler_serial=202, state_const=0x296F2452),
        ordered_path=(99, 15, 17),
    )
    edge_b = SimpleNamespace(
        kind=SimpleNamespace(name="CONDITIONAL_TRANSITION"),
        source_key=SimpleNamespace(state_const=0x6107F8EC),
        source_anchor=SimpleNamespace(block_serial=15, branch_arm=1),
        target_state=0x4C77464F,
        target_entry_anchor=72,
        target_key=fallback_key,
        ordered_path=(98, 15, 16),
    )
    dag = SimpleNamespace(edges=(edge_a, edge_b), nodes=(fallback_node,))
    round_summary = SimpleNamespace(
        dag=dag,
        plannable_edges=(),
    )
    return flow_graph, round_summary


def _make_raw_alias_semantic_fork_fixture():
    flow_graph = FlowGraph(
        blocks={
            15: BlockSnapshot(15, 0, (16, 17), (), 0, 0, ()),
            16: BlockSnapshot(16, 0, (71,), (15,), 0, 0, ()),
            17: BlockSnapshot(17, 0, (202,), (15,), 0, 0, ()),
            14: BlockSnapshot(14, 0, (136,), (), 0, 0, ()),
            71: BlockSnapshot(71, 0, (2,), (16,), 0, 0, ()),
            72: BlockSnapshot(72, 0, (177,), (), 0, 0, ()),
            99: BlockSnapshot(99, 0, (16,), (), 0, 0, ()),
            202: BlockSnapshot(202, 0, (203,), (), 0, 0, ()),
        },
        entry_serial=15,
        func_ea=0x180012B60,
    )
    fallback_node = SimpleNamespace(
        key=SimpleNamespace(handler_serial=14, state_const=0x474EEEBB),
        entry_anchor=14,
        state_label="0x474EEEBB_fallback",
        exclusive_blocks=(),
        owned_blocks=(14,),
        shared_suffix_blocks=(),
    )
    edge_a = SimpleNamespace(
        kind=SimpleNamespace(name="CONDITIONAL_TRANSITION"),
        source_key=SimpleNamespace(state_const=0x6107F8EC),
        source_anchor=SimpleNamespace(block_serial=15, branch_arm=0),
        target_state=0x296F2452,
        target_entry_anchor=202,
        target_key=SimpleNamespace(handler_serial=202, state_const=0x296F2452),
        target_label="0x296F2452",
        ordered_path=(15, 17),
    )
    edge_b = SimpleNamespace(
        kind=SimpleNamespace(name="CONDITIONAL_TRANSITION"),
        source_key=SimpleNamespace(state_const=0x6107F8EC),
        source_anchor=SimpleNamespace(block_serial=15, branch_arm=1),
        target_state=0x4C77464F,
        target_entry_anchor=72,
        target_key=None,
        target_label="0x4C77464F",
        ordered_path=(15, 16),
    )
    alias_edge = SimpleNamespace(
        kind=SimpleNamespace(name="CONDITIONAL_TRANSITION"),
        source_key=SimpleNamespace(state_const=0x10743C4C),
        source_anchor=SimpleNamespace(block_serial=99, branch_arm=0),
        target_state=0x4C77464F,
        target_entry_anchor=14,
        target_key=None,
        target_label="0x474EEEBB_fallback",
        ordered_path=(99, 16),
    )
    dag = SimpleNamespace(edges=(edge_a, edge_b, alias_edge), nodes=(fallback_node,))
    round_summary = SimpleNamespace(
        dag=dag,
        plannable_edges=(),
    )
    return flow_graph, round_summary


def _make_semantic_reference_alias_fork_fixture():
    flow_graph = FlowGraph(
        blocks={
            15: BlockSnapshot(15, 0, (16, 17), (), 0, 0, ()),
            16: BlockSnapshot(16, 0, (71,), (15,), 0, 0, ()),
            17: BlockSnapshot(17, 0, (202,), (15,), 0, 0, ()),
            202: BlockSnapshot(202, 0, (203,), (), 0, 0, ()),
        },
        entry_serial=15,
        func_ea=0x180012B60,
    )
    fallback_node = SimpleNamespace(
        key=SimpleNamespace(handler_serial=14, state_const=0x474EEEBB),
        entry_anchor=14,
        state_label="0x474EEEBB_fallback",
        exclusive_blocks=(14,),
        owned_blocks=(14,),
        shared_suffix_blocks=(),
    )
    edge_a = SimpleNamespace(
        kind=SimpleNamespace(name="CONDITIONAL_TRANSITION"),
        source_key=SimpleNamespace(state_const=0x6107F8EC),
        source_anchor=SimpleNamespace(block_serial=15, branch_arm=0),
        target_state=0x296F2452,
        target_entry_anchor=202,
        target_key=SimpleNamespace(handler_serial=202, state_const=0x296F2452),
        target_label="0x296F2452",
        ordered_path=(15, 17),
    )
    edge_b = SimpleNamespace(
        kind=SimpleNamespace(name="CONDITIONAL_TRANSITION"),
        source_key=SimpleNamespace(state_const=0x6107F8EC),
        source_anchor=SimpleNamespace(block_serial=15, branch_arm=1),
        target_state=0x4C77464F,
        target_entry_anchor=72,
        target_key=None,
        target_label="0x4C77464F",
        ordered_path=(15, 16),
    )
    semantic_reference_program = SimpleNamespace(
        nodes=(
            SimpleNamespace(
                label_text="STATE_6107F8EC",
                entry_anchor=15,
                line_start=1,
                line_end=3,
            ),
            SimpleNamespace(
                label_text="STATE_296F2452",
                entry_anchor=202,
                line_start=4,
                line_end=4,
            ),
            SimpleNamespace(
                label_text="STATE_474EEEBB_fallback",
                entry_anchor=14,
                line_start=5,
                line_end=5,
            ),
        ),
        lines=(
            SimpleNamespace(line_no=1, target_label=None),
            SimpleNamespace(line_no=2, target_label="STATE_296F2452"),
            SimpleNamespace(line_no=3, target_label="STATE_474EEEBB_fallback"),
            SimpleNamespace(line_no=4, target_label=None),
            SimpleNamespace(line_no=5, target_label=None),
        ),
    )
    round_summary = SimpleNamespace(
        dag=SimpleNamespace(edges=(edge_a, edge_b), nodes=(fallback_node,)),
        plannable_edges=(),
        semantic_reference_program=semantic_reference_program,
    )
    return flow_graph, round_summary


def _make_semantic_reference_alias_fork_with_path_lead_fixture():
    flow_graph = FlowGraph(
        blocks={
            15: BlockSnapshot(15, 0, (16, 17), (), 0, 0, ()),
            16: BlockSnapshot(16, 0, (71,), (15,), 0, 0, ()),
            17: BlockSnapshot(17, 0, (202,), (15,), 0, 0, ()),
            72: BlockSnapshot(72, 0, (2,), (), 0, 0, ()),
            202: BlockSnapshot(202, 0, (203,), (), 0, 0, ()),
        },
        entry_serial=15,
        func_ea=0x180012B60,
    )
    fallback_key = SimpleNamespace(handler_serial=14, state_const=0x474EEEBB)
    fallback_node = SimpleNamespace(
        key=fallback_key,
        entry_anchor=72,
        state_label="0x474EEEBB_fallback",
        exclusive_blocks=(72,),
        owned_blocks=(72,),
        shared_suffix_blocks=(),
    )
    edge_a = SimpleNamespace(
        kind=SimpleNamespace(name="CONDITIONAL_TRANSITION"),
        source_key=SimpleNamespace(state_const=0x6107F8EC),
        source_anchor=SimpleNamespace(block_serial=15, branch_arm=0),
        target_state=0x296F2452,
        target_entry_anchor=202,
        target_key=SimpleNamespace(handler_serial=202, state_const=0x296F2452),
        target_label="0x296F2452",
        ordered_path=(15, 17),
    )
    edge_b = SimpleNamespace(
        kind=SimpleNamespace(name="CONDITIONAL_TRANSITION"),
        source_key=SimpleNamespace(state_const=0x6107F8EC),
        source_anchor=SimpleNamespace(block_serial=15, branch_arm=1),
        target_state=0x4C77464F,
        target_entry_anchor=72,
        target_key=None,
        target_label="0x4C77464F",
        ordered_path=(15, 16),
    )
    fallback_out_edge = SimpleNamespace(
        kind=SimpleNamespace(name="TRANSITION"),
        source_key=fallback_key,
        source_anchor=SimpleNamespace(block_serial=72, branch_arm=None),
        target_state=0x57BE6FD0,
        target_entry_anchor=75,
        target_key=None,
        target_label="0x57BE6FD0",
        ordered_path=(72,),
    )
    semantic_reference_program = SimpleNamespace(
        nodes=(
            SimpleNamespace(
                label_text="STATE_6107F8EC",
                entry_anchor=15,
                line_start=1,
                line_end=3,
            ),
            SimpleNamespace(
                label_text="STATE_296F2452",
                entry_anchor=202,
                line_start=4,
                line_end=4,
            ),
            SimpleNamespace(
                label_text="STATE_474EEEBB_fallback",
                entry_anchor=14,
                line_start=5,
                line_end=5,
            ),
        ),
        lines=(
            SimpleNamespace(line_no=1, target_label=None),
            SimpleNamespace(line_no=2, target_label="STATE_296F2452"),
            SimpleNamespace(line_no=3, target_label="STATE_474EEEBB_fallback"),
            SimpleNamespace(line_no=4, target_label=None),
            SimpleNamespace(line_no=5, target_label=None),
        ),
    )
    round_summary = SimpleNamespace(
        dag=SimpleNamespace(edges=(edge_a, edge_b, fallback_out_edge), nodes=(fallback_node,)),
        plannable_edges=(),
        semantic_reference_program=semantic_reference_program,
    )
    return flow_graph, round_summary


def _make_semantic_reference_direct_state_fork_fixture():
    flow_graph = FlowGraph(
        blocks={
            15: BlockSnapshot(15, 0, (16, 17), (), 0, 0, ()),
            16: BlockSnapshot(16, 0, (71,), (15,), 0, 0, ()),
            17: BlockSnapshot(17, 0, (202,), (15,), 0, 0, ()),
            66: BlockSnapshot(66, 0, (69,), (), 0, 0, ()),
            71: BlockSnapshot(71, 0, (2,), (), 0, 0, ()),
            202: BlockSnapshot(202, 0, (203,), (), 0, 0, ()),
        },
        entry_serial=15,
        func_ea=0x180012B60,
    )
    exact_node = SimpleNamespace(
        key=SimpleNamespace(handler_serial=66, state_const=0x4C77464F),
        entry_anchor=66,
        state_label="0x4C77464F",
        exclusive_blocks=(66,),
        owned_blocks=(66,),
        shared_suffix_blocks=(),
    )
    edge_a = SimpleNamespace(
        kind=SimpleNamespace(name="CONDITIONAL_TRANSITION"),
        source_key=SimpleNamespace(state_const=0x6107F8EC),
        source_anchor=SimpleNamespace(block_serial=15, branch_arm=0),
        target_state=0x296F2452,
        target_entry_anchor=202,
        target_key=SimpleNamespace(handler_serial=202, state_const=0x296F2452),
        target_label="0x296F2452",
        ordered_path=(15, 17),
    )
    edge_b = SimpleNamespace(
        kind=SimpleNamespace(name="CONDITIONAL_TRANSITION"),
        source_key=SimpleNamespace(state_const=0x6107F8EC),
        source_anchor=SimpleNamespace(block_serial=15, branch_arm=1),
        target_state=0x4C77464F,
        target_entry_anchor=71,
        target_key=None,
        target_label="0x4C77464F",
        ordered_path=(15, 16),
    )
    semantic_reference_program = SimpleNamespace(
        nodes=(
            SimpleNamespace(
                label_text="STATE_6107F8EC",
                entry_anchor=15,
                line_start=1,
                line_end=3,
            ),
            SimpleNamespace(
                label_text="STATE_296F2452",
                entry_anchor=202,
                line_start=4,
                line_end=4,
            ),
            SimpleNamespace(
                label_text="STATE_4C77464F",
                entry_anchor=66,
                line_start=5,
                line_end=5,
            ),
        ),
        lines=(
            SimpleNamespace(line_no=1, target_label=None),
            SimpleNamespace(line_no=2, target_label="STATE_296F2452"),
            SimpleNamespace(line_no=3, target_label="STATE_4C77464F"),
            SimpleNamespace(line_no=4, target_label=None),
            SimpleNamespace(line_no=5, target_label=None),
        ),
    )
    round_summary = SimpleNamespace(
        dag=SimpleNamespace(edges=(edge_a, edge_b), nodes=(exact_node,)),
        plannable_edges=(),
        semantic_reference_program=semantic_reference_program,
    )
    return flow_graph, round_summary


def _make_supplemental_selected_fork_fixture():
    flow_graph = FlowGraph(
        blocks={
            15: BlockSnapshot(15, 0, (16, 17), (), 0, 0, ()),
            16: BlockSnapshot(16, 0, (71,), (15,), 0, 0, ()),
            17: BlockSnapshot(17, 0, (202,), (15,), 0, 0, ()),
            14: BlockSnapshot(14, 0, (136,), (), 0, 0, ()),
            66: BlockSnapshot(66, 0, (69,), (), 0, 0, ()),
            202: BlockSnapshot(202, 0, (203,), (), 0, 0, ()),
        },
        entry_serial=15,
        func_ea=0x180012B60,
    )
    fallback_node = SimpleNamespace(
        key=SimpleNamespace(handler_serial=14, state_const=0x474EEEBB),
        entry_anchor=14,
        state_label="0x474EEEBB_fallback",
        exclusive_blocks=(14,),
        owned_blocks=(14,),
        shared_suffix_blocks=(),
    )
    raw_exact_node = SimpleNamespace(
        key=SimpleNamespace(handler_serial=66, state_const=0x4C77464F),
        entry_anchor=66,
        state_label="0x4C77464F",
        exclusive_blocks=(66,),
        owned_blocks=(66,),
        shared_suffix_blocks=(),
    )
    edge_a = SimpleNamespace(
        kind=SimpleNamespace(name="CONDITIONAL_TRANSITION"),
        source_key=SimpleNamespace(state_const=0x6107F8EC),
        source_anchor=SimpleNamespace(block_serial=15, branch_arm=0),
        target_state=0x296F2452,
        target_entry_anchor=202,
        target_key=SimpleNamespace(handler_serial=202, state_const=0x296F2452),
        target_label="0x296F2452",
        ordered_path=(15, 17),
    )
    edge_b = SimpleNamespace(
        kind=SimpleNamespace(name="CONDITIONAL_TRANSITION"),
        source_key=SimpleNamespace(state_const=0x6107F8EC),
        source_anchor=SimpleNamespace(block_serial=15, branch_arm=1),
        target_state=0x4C77464F,
        target_entry_anchor=66,
        target_key=SimpleNamespace(handler_serial=66, state_const=0x4C77464F),
        target_label="0x4C77464F",
        ordered_path=(15, 16),
    )
    round_summary = SimpleNamespace(
        dag=SimpleNamespace(
            edges=(edge_a, edge_b),
            nodes=(fallback_node, raw_exact_node),
            supplemental_selected_entries=((0x4C77464F, 14),),
        ),
        plannable_edges=(),
        semantic_reference_program=None,
    )
    return flow_graph, round_summary


def test_analyze_duplicate_alias_conditional_sites_selects_duplicate_arm_source():
    flow_graph, round_summary = _make_alias_fixture()

    sites = analyze_duplicate_alias_conditional_sites(round_summary, flow_graph)

    assert len(sites) == 1
    site = sites[0]
    assert site.source_block == 28
    assert site.common_tail == 33
    assert site.canonical_target_entry == 34
    assert site.alias_count == 2


def test_alias_sites_are_removed_from_hammock_missing_return_and_fork_incomplete():
    flow_graph, round_summary = _make_alias_fixture()

    _sites, cond_inventory = analyze_exact_conditional_sites(round_summary, flow_graph)
    _fork_sites, fork_inventory = analyze_exact_conditional_fork_sites(round_summary, flow_graph)

    assert 28 in cond_inventory.alias_handled_blocks
    assert 28 not in cond_inventory.missing_return_blocks
    assert 28 in fork_inventory.alias_handled_blocks
    assert 28 not in fork_inventory.plannable_incomplete_blocks


def test_exact_conditional_alias_strategy_uses_duplicate_and_redirect_when_tail_is_shared(monkeypatch):
    flow_graph, round_summary = _make_alias_fixture()
    builder = ModificationBuilder.from_snapshot(
        SimpleNamespace(flow_graph=flow_graph, mba=SimpleNamespace())
    )
    setup = SimpleNamespace(
        builder=builder,
        bst_node_blocks=(2,),
        dispatcher_region=(2,),
    )
    monkeypatch.setattr(
        exact_conditional_alias_module,
        "build_semantic_exact_round_summary",
        lambda _snapshot: (setup, round_summary),
    )

    snapshot = SimpleNamespace(
        mba=SimpleNamespace(entry_ea=0x180012B60, maturity=ida_hexrays.MMAT_GLBOPT1),
        state_machine=SimpleNamespace(transitions=()),
        bst_result=SimpleNamespace(bst_node_blocks={2}),
        flow_graph=flow_graph,
        bst_dispatcher_serial=2,
    )

    fragment = ExactConditionalAliasNodeLoweringStrategy().plan(snapshot)

    assert fragment is not None
    assert any(isinstance(mod, DuplicateAndRedirect) for mod in fragment.modifications)


def test_exact_conditional_fork_uses_semantic_target_entry_from_target_key():
    flow_graph, round_summary = _make_semantic_fork_fixture()

    sites, inventory = analyze_exact_conditional_fork_sites(round_summary, flow_graph)

    assert inventory.selected_count == 1
    assert len(sites) == 1
    site = sites[0]
    assert site.source_block == 15
    entries = {arm.first_hop: arm.target_entry for arm in site.arms}
    assert entries[16] == 14
    assert entries[17] == 202


def test_exact_conditional_fork_normalizes_raw_alias_state_to_fallback_entry():
    flow_graph, round_summary = _make_raw_alias_semantic_fork_fixture()

    sites, inventory = analyze_exact_conditional_fork_sites(round_summary, flow_graph)

    assert inventory.selected_count == 1
    assert len(sites) == 1
    site = sites[0]
    assert site.source_block == 15
    entries = {arm.first_hop: arm.target_entry for arm in site.arms}
    assert entries[16] == 14
    assert entries[17] == 202


def test_exact_conditional_fork_normalizes_raw_alias_using_semantic_reference_program():
    flow_graph, round_summary = _make_semantic_reference_alias_fork_fixture()

    sites, inventory = analyze_exact_conditional_fork_sites(round_summary, flow_graph)

    assert inventory.selected_count == 1
    assert len(sites) == 1
    site = sites[0]
    assert site.source_block == 15
    entries = {arm.first_hop: arm.target_entry for arm in site.arms}
    states = {arm.first_hop: arm.target_state for arm in site.arms}
    assert entries[16] == 14
    assert states[16] == 0x474EEEBB
    assert entries[17] == 202


def test_exact_conditional_fork_prefers_fallback_family_entry_over_path_lead():
    flow_graph, round_summary = _make_semantic_reference_alias_fork_with_path_lead_fixture()

    sites, inventory = analyze_exact_conditional_fork_sites(round_summary, flow_graph)

    assert inventory.selected_count == 1
    assert len(sites) == 1
    site = sites[0]
    entries = {arm.first_hop: arm.target_entry for arm in site.arms}
    states = {arm.first_hop: arm.target_state for arm in site.arms}
    assert entries[16] == 14
    assert states[16] == 0x474EEEBB


def test_exact_conditional_fork_prefers_direct_semantic_state_entry():
    flow_graph, round_summary = _make_semantic_reference_direct_state_fork_fixture()

    sites, inventory = analyze_exact_conditional_fork_sites(round_summary, flow_graph)

    assert inventory.selected_count == 1
    assert len(sites) == 1
    site = sites[0]
    entries = {arm.first_hop: arm.target_entry for arm in site.arms}
    states = {arm.first_hop: arm.target_state for arm in site.arms}
    assert entries[16] == 66
    assert states[16] == 0x4C77464F


def test_exact_conditional_fork_prefers_supplemental_selected_entry_over_raw_exact_row():
    flow_graph, round_summary = _make_supplemental_selected_fork_fixture()

    sites, inventory = analyze_exact_conditional_fork_sites(round_summary, flow_graph)

    assert inventory.selected_count == 1
    assert len(sites) == 1
    site = sites[0]
    entries = {arm.first_hop: arm.target_entry for arm in site.arms}
    assert entries[16] == 14
    assert entries[17] == 202


def test_exact_conditional_fork_defers_structured_region_owned_source_state():
    flow_graph, round_summary = _make_semantic_reference_alias_fork_fixture()
    round_summary = SimpleNamespace(
        **{
            **round_summary.__dict__,
            "structured_regions": (
                SimpleNamespace(
                    region_name="sub7ffd_10743c4c_branch_region",
                    entry_state=0x10743C4C,
                    state_values=(0x10743C4C, 0x6107F8EC, 0x4C77464F),
                    state_labels=(
                        "STATE_10743C4C",
                        "STATE_6107F8EC",
                        "STATE_4C77464F",
                    ),
                    internal_state_edges=(
                        (0x10743C4C, 0x6107F8EC),
                        (0x6107F8EC, 0x4C77464F),
                    ),
                    exit_state_values=(0x296F2452, 0x12ACFB20, 0x32FCD904),
                ),
            ),
        }
    )

    sites, inventory = analyze_exact_conditional_fork_sites(round_summary, flow_graph)

    assert sites == ()
    assert inventory.selected_count == 0


def test_exact_conditional_fork_uses_first_hop_relative_to_source_block():
    flow_graph, round_summary = _make_prefixed_path_semantic_fork_fixture()

    sites, inventory = analyze_exact_conditional_fork_sites(round_summary, flow_graph)

    assert inventory.selected_count == 1
    assert len(sites) == 1
    site = sites[0]
    assert site.source_block == 15
    entries = {arm.first_hop: arm.target_entry for arm in site.arms}
    assert entries[16] == 14
    assert entries[17] == 202


def test_exact_conditional_fork_accepts_clean_two_pred_join_shape():
    flow_graph = FlowGraph(
        blocks={
            10: BlockSnapshot(10, 0, (11, 12), (), 0, 0, ()),
            11: BlockSnapshot(11, 0, (13,), (10,), 0, 0, ()),
            12: BlockSnapshot(12, 0, (13,), (10,), 0, 0, ()),
            13: BlockSnapshot(13, 0, (60,), (11, 12), 0, 0, ()),
            40: BlockSnapshot(40, 0, (), (), 0, 0, ()),
            50: BlockSnapshot(50, 0, (), (), 0, 0, ()),
            60: BlockSnapshot(60, 0, (), (13,), 0, 0, ()),
        },
        entry_serial=10,
        func_ea=0x180012B60,
    )
    edge_a = SimpleNamespace(
        kind=SimpleNamespace(name="CONDITIONAL_TRANSITION"),
        source_key=SimpleNamespace(state_const=0x11111111),
        source_anchor=SimpleNamespace(block_serial=10, branch_arm=0),
        target_state=0x22222222,
        target_entry_anchor=40,
        target_key=None,
        ordered_path=(10, 11, 13),
    )
    edge_b = SimpleNamespace(
        kind=SimpleNamespace(name="CONDITIONAL_TRANSITION"),
        source_key=SimpleNamespace(state_const=0x11111111),
        source_anchor=SimpleNamespace(block_serial=10, branch_arm=1),
        target_state=0x33333333,
        target_entry_anchor=50,
        target_key=None,
        ordered_path=(10, 12, 13),
    )
    round_summary = SimpleNamespace(
        dag=SimpleNamespace(edges=(edge_a, edge_b), nodes=()),
        plannable_edges=(),
    )

    sites, inventory = analyze_exact_conditional_fork_sites(round_summary, flow_graph)

    assert inventory.selected_count == 1
    assert inventory.clean_fork_blocks == (10,)
    assert inventory.boundary_preservation_blocks == ()
    site = sites[0]
    assert {arm.first_hop: arm.tail for arm in site.arms} == {11: 11, 12: 12}
    assert {arm.first_hop: arm.target_entry for arm in site.arms} == {
        11: 40,
        12: 50,
    }


def test_exact_conditional_fork_rejects_shared_tail_boundary_shape():
    flow_graph = FlowGraph(
        blocks={
            10: BlockSnapshot(10, 0, (11, 12), (), 0, 0, ()),
            11: BlockSnapshot(11, 0, (13,), (10,), 0, 0, ()),
            12: BlockSnapshot(12, 0, (13,), (10,), 0, 0, ()),
            13: BlockSnapshot(13, 0, (2,), (11, 12), 0, 0, ()),
            2: BlockSnapshot(2, 0, (), (13,), 0, 0, ()),
            40: BlockSnapshot(40, 0, (), (), 0, 0, ()),
            50: BlockSnapshot(50, 0, (), (), 0, 0, ()),
        },
        entry_serial=10,
        func_ea=0x180012B60,
    )
    edge_a = SimpleNamespace(
        kind=SimpleNamespace(name="CONDITIONAL_TRANSITION"),
        source_key=SimpleNamespace(state_const=0x11111111),
        source_anchor=SimpleNamespace(block_serial=10, branch_arm=0),
        target_state=0x22222222,
        target_entry_anchor=40,
        target_key=None,
        ordered_path=(10, 11, 13),
    )
    edge_b = SimpleNamespace(
        kind=SimpleNamespace(name="CONDITIONAL_TRANSITION"),
        source_key=SimpleNamespace(state_const=0x11111111),
        source_anchor=SimpleNamespace(block_serial=10, branch_arm=1),
        target_state=0x33333333,
        target_entry_anchor=50,
        target_key=None,
        ordered_path=(10, 12, 13),
    )
    round_summary = SimpleNamespace(
        dag=SimpleNamespace(edges=(edge_a, edge_b), nodes=()),
        plannable_edges=(),
    )

    sites, inventory = analyze_exact_conditional_fork_sites(
        round_summary,
        flow_graph,
        bst_node_blocks={2},
    )

    assert sites == ()
    assert inventory.selected_count == 0
    assert inventory.clean_fork_blocks == ()
    assert inventory.boundary_preservation_blocks == (10,)
    assert 10 in inventory.shape_rejected_blocks


def test_exact_conditional_fork_rejects_join_to_dispatcher_outside_bst():
    flow_graph = FlowGraph(
        blocks={
            10: BlockSnapshot(10, 0, (11, 12), (), 0, 0, ()),
            11: BlockSnapshot(11, 0, (13,), (10,), 0, 0, ()),
            12: BlockSnapshot(12, 0, (13,), (10,), 0, 0, ()),
            13: BlockSnapshot(13, 0, (99,), (11, 12), 0, 0, ()),
            40: BlockSnapshot(40, 0, (), (), 0, 0, ()),
            50: BlockSnapshot(50, 0, (), (), 0, 0, ()),
            99: BlockSnapshot(99, 0, (), (13,), 0, 0, ()),
        },
        entry_serial=10,
        func_ea=0x180012B60,
    )
    edge_a = SimpleNamespace(
        kind=SimpleNamespace(name="CONDITIONAL_TRANSITION"),
        source_key=SimpleNamespace(state_const=0x11111111),
        source_anchor=SimpleNamespace(block_serial=10, branch_arm=0),
        target_state=0x22222222,
        target_entry_anchor=40,
        target_key=None,
        ordered_path=(10, 11, 13),
    )
    edge_b = SimpleNamespace(
        kind=SimpleNamespace(name="CONDITIONAL_TRANSITION"),
        source_key=SimpleNamespace(state_const=0x11111111),
        source_anchor=SimpleNamespace(block_serial=10, branch_arm=1),
        target_state=0x33333333,
        target_entry_anchor=50,
        target_key=None,
        ordered_path=(10, 12, 13),
    )
    round_summary = SimpleNamespace(
        dag=SimpleNamespace(edges=(edge_a, edge_b), nodes=()),
        plannable_edges=(),
    )

    sites, inventory = analyze_exact_conditional_fork_sites(
        round_summary,
        flow_graph,
        bst_node_blocks=set(),
        dispatcher_region={99},
    )

    assert sites == ()
    assert inventory.selected_count == 0
    assert inventory.clean_fork_blocks == ()
    assert inventory.boundary_preservation_blocks == (10,)
    assert 10 in inventory.shape_rejected_blocks


def test_exact_conditional_fork_rejects_empty_two_succ_branch_shell_join():
    flow_graph = FlowGraph(
        blocks={
            10: BlockSnapshot(10, 0, (11, 12), (), 0, 0, ()),
            11: BlockSnapshot(11, 0, (13,), (10,), 0, 0, ()),
            12: BlockSnapshot(12, 0, (13,), (10,), 0, 0, ()),
            13: BlockSnapshot(13, 0, (60, 61), (11, 12), 0, 0, ()),
            40: BlockSnapshot(40, 0, (), (), 0, 0, ()),
            50: BlockSnapshot(50, 0, (), (), 0, 0, ()),
            60: BlockSnapshot(60, 0, (), (13,), 0, 0, ()),
            61: BlockSnapshot(61, 0, (), (13,), 0, 0, ()),
        },
        entry_serial=10,
        func_ea=0x180012B60,
    )
    edge_a = SimpleNamespace(
        kind=SimpleNamespace(name="CONDITIONAL_TRANSITION"),
        source_key=SimpleNamespace(state_const=0x11111111),
        source_anchor=SimpleNamespace(block_serial=10, branch_arm=0),
        target_state=0x22222222,
        target_entry_anchor=40,
        target_key=None,
        ordered_path=(10, 11, 13),
    )
    edge_b = SimpleNamespace(
        kind=SimpleNamespace(name="CONDITIONAL_TRANSITION"),
        source_key=SimpleNamespace(state_const=0x11111111),
        source_anchor=SimpleNamespace(block_serial=10, branch_arm=1),
        target_state=0x33333333,
        target_entry_anchor=50,
        target_key=None,
        ordered_path=(10, 12, 13),
    )
    round_summary = SimpleNamespace(
        dag=SimpleNamespace(edges=(edge_a, edge_b), nodes=()),
        plannable_edges=(),
    )

    sites, inventory = analyze_exact_conditional_fork_sites(round_summary, flow_graph)

    assert sites == ()
    assert inventory.selected_count == 0
    assert inventory.clean_fork_blocks == ()
    assert inventory.boundary_preservation_blocks == (10,)
    assert 10 in inventory.shape_rejected_blocks


def test_exact_conditional_fork_plan_zeroes_safe_tail_state_writes(monkeypatch):
    flow_graph, round_summary = _make_prefixed_path_semantic_fork_fixture()
    builder = ModificationBuilder.from_snapshot(
        SimpleNamespace(flow_graph=flow_graph, mba=SimpleNamespace())
    )

    class _FakeConstantFixpointBackend:
        def compute(self, flow_graph_arg: object, state_var_stkoff: int):
            assert flow_graph_arg is flow_graph
            assert state_var_stkoff == 0x7BC
            return SimpleNamespace(in_stk_maps={}, in_reg_maps={})

    setup = SimpleNamespace(
        builder=builder,
        bst_node_blocks=(2,),
        dispatcher_region=(2,),
        state_var_stkoff=0x7BC,
        dispatcher=None,
    )
    monkeypatch.setattr(
        exact_conditional_fork_module,
        "build_semantic_exact_round_summary",
        lambda _snapshot: (setup, round_summary),
    )
    monkeypatch.setattr(
        exact_conditional_fork_module,
        "collect_residual_dispatcher_predecessors",
        lambda *args, **kwargs: (),
    )

    def _fake_path_horizon(edge, **kwargs):
        state_value = int(getattr(edge, "target_state", 0))
        block_map = {
            0x4C77464F: 16,
            0x296F2452: 17,
        }
        block_serial = block_map.get(state_value)
        if block_serial is None:
            return None
        return (
            block_serial,
            SimpleNamespace(
                state_value=state_value,
                insn_ea=0x180000000 + block_serial,
            ),
        )

    monkeypatch.setattr(
        exact_conditional_fork_module,
        "resolve_transition_path_horizon",
        _fake_path_horizon,
    )

    snapshot = SimpleNamespace(
        mba=SimpleNamespace(entry_ea=0x180012B60, maturity=ida_hexrays.MMAT_GLBOPT1),
        state_machine=SimpleNamespace(transitions=()),
        bst_result=SimpleNamespace(bst_node_blocks={2}),
        flow_graph=flow_graph,
        bst_dispatcher_serial=2,
        reachability=SimpleNamespace(entry_serial=15),
    )

    strategy = ExactConditionalForkNodeLoweringStrategy()
    strategy._constant_fixpoint_backend = _FakeConstantFixpointBackend()
    fragment = strategy.plan(snapshot)

    assert fragment is not None
    zeroes = [mod for mod in fragment.modifications if mod.__class__.__name__ == "ZeroStateWrite"]
    assert len(zeroes) == 2


def test_exact_conditional_fork_plan_nops_trivial_direct_tail_state_writes(monkeypatch):
    flow_graph, round_summary = _make_prefixed_path_semantic_fork_fixture_with_state_writes()
    builder = ModificationBuilder.from_snapshot(
        SimpleNamespace(flow_graph=flow_graph, mba=SimpleNamespace())
    )

    class _FakeConstantFixpointBackend:
        def compute(self, flow_graph_arg: object, state_var_stkoff: int):
            assert flow_graph_arg is flow_graph
            assert state_var_stkoff == 0x7BC
            return SimpleNamespace(in_stk_maps={}, in_reg_maps={})

    setup = SimpleNamespace(
        builder=builder,
        bst_node_blocks=(2,),
        dispatcher_region=(2,),
        state_var_stkoff=0x7BC,
        dispatcher=None,
    )
    monkeypatch.setattr(
        exact_conditional_fork_module,
        "build_semantic_exact_round_summary",
        lambda _snapshot: (setup, round_summary),
    )
    monkeypatch.setattr(
        exact_conditional_fork_module,
        "collect_residual_dispatcher_predecessors",
        lambda *args, **kwargs: (),
    )
    monkeypatch.setattr(
        exact_conditional_fork_module,
        "resolve_transition_path_horizon",
        lambda *args, **kwargs: None,
    )

    snapshot = SimpleNamespace(
        mba=SimpleNamespace(entry_ea=0x180012B60, maturity=ida_hexrays.MMAT_GLBOPT1),
        state_machine=SimpleNamespace(transitions=()),
        bst_result=SimpleNamespace(bst_node_blocks={2}),
        flow_graph=flow_graph,
        bst_dispatcher_serial=2,
        reachability=SimpleNamespace(entry_serial=15),
    )

    strategy = ExactConditionalForkNodeLoweringStrategy()
    strategy._constant_fixpoint_backend = _FakeConstantFixpointBackend()
    fragment = strategy.plan(snapshot)

    assert fragment is not None
    nops = [mod for mod in fragment.modifications if isinstance(mod, NopInstructions)]
    assert {(mod.block_serial, mod.insn_eas) for mod in nops} == {
        (16, (0x180012EE2,)),
        (17, (0x180012EEC,)),
    }
