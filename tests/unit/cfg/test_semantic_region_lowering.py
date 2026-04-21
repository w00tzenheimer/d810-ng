from __future__ import annotations

from dataclasses import dataclass
from types import SimpleNamespace

from d810.cfg.semantic_region_lowering import (
    _collect_semantic_entry_by_label,
    _collect_semantic_successors_by_state,
    _merge_region_contract_semantic_successors_by_state,
    _synthesize_missing_conditional_exit_sites,
    build_region_contract_fallback_lowering,
    build_region_preferred_direct_lowering,
    build_region_preferred_conditional_lowering,
    collect_admissible_region_lowering_sites,
    override_exit_sites_with_child_region_entries,
)
from d810.recon.flow.linearized_state_dag import StateNodeKind


@dataclass(frozen=True)
class _Key:
    state_const: int


def _edge(
    *,
    source_state: int,
    target_state: int,
    source_block: int,
    target_entry: int | None,
    target_key=None,
):
    source_key = _Key(source_state)
    return SimpleNamespace(
        source_key=source_key,
        target_key=target_key,
        target_state=target_state,
        source_anchor=SimpleNamespace(block_serial=source_block),
        target_entry_anchor=target_entry,
        ordered_path=(source_block,),
    )


def test_collect_admissible_region_lowering_sites_accepts_true_semantic_entry():
    region = SimpleNamespace(
        region_name="region",
        state_values=(0x11111111, 0x22222222),
        internal_state_edges=((0x11111111, 0x22222222),),
        exit_state_values=(),
    )
    edge = _edge(
        source_state=0x11111111,
        target_state=0x22222222,
        source_block=78,
        target_entry=14,
    )
    dag = SimpleNamespace(edges=(edge,))
    node_by_key = {
        edge.source_key: SimpleNamespace(entry_anchor=78),
    }

    sites = collect_admissible_region_lowering_sites(
        region=region,
        dag=dag,
        node_by_key=node_by_key,
        dispatcher_region={20},
    )

    assert len(sites) == 1
    assert sites[0].site_kind == "internal"
    assert sites[0].source_entry_anchor == 78
    assert sites[0].target_entry_anchor == 14


def test_collect_admissible_region_lowering_sites_accepts_region_exit_transition():
    region = SimpleNamespace(
        region_name="region",
        state_values=(0x11111111, 0x22222222),
        internal_state_edges=((0x11111111, 0x22222222),),
        exit_state_values=(0x33333333,),
    )
    edge = _edge(
        source_state=0x22222222,
        target_state=0x33333333,
        source_block=14,
        target_entry=35,
    )
    dag = SimpleNamespace(edges=(edge,))
    node_by_key = {
        edge.source_key: SimpleNamespace(entry_anchor=14),
    }

    sites = collect_admissible_region_lowering_sites(
        region=region,
        dag=dag,
        node_by_key=node_by_key,
        dispatcher_region={20},
    )

    assert len(sites) == 1
    assert sites[0].site_kind == "exit"
    assert sites[0].source_state == 0x22222222
    assert sites[0].target_state == 0x33333333
    assert sites[0].target_entry_anchor == 35


def test_collect_admissible_region_lowering_sites_keeps_exact_target_entry():
    region = SimpleNamespace(
        region_name="region",
        state_values=(0x6107F8EC,),
        internal_state_edges=(),
        exit_state_values=(0x4C77464F,),
    )
    target_key = _Key(0x4C77464F)
    edge = _edge(
        source_state=0x6107F8EC,
        target_state=0x4C77464F,
        source_block=15,
        target_entry=71,
        target_key=target_key,
    )
    dag = SimpleNamespace(
        edges=(edge,),
        supplemental_selected_entries=((0x4C77464F, 61),),
        nodes=(
            SimpleNamespace(
                key=target_key,
                kind=SimpleNamespace(name="EXACT"),
                state_label="0x4C77464F",
                handler_serial=66,
                entry_anchor=66,
                exclusive_blocks=(66,),
                owned_blocks=(),
                shared_suffix_blocks=(),
                local_segments=(),
            ),
        ),
    )
    node_by_key = {
        edge.source_key: SimpleNamespace(entry_anchor=15),
        target_key: dag.nodes[0],
    }
    semantic_reference_program = SimpleNamespace(
        nodes=(
            SimpleNamespace(
                label_text="STATE_6107F8EC",
                entry_anchor=15,
                line_start=1,
                line_end=2,
            ),
            SimpleNamespace(
                label_text="STATE_4C77464F",
                entry_anchor=66,
                line_start=3,
        line_end=4,
            ),
        ),
        lines=(
            SimpleNamespace(line_no=1, target_label=None),
            SimpleNamespace(line_no=2, target_label="STATE_4C77464F"),
            SimpleNamespace(line_no=3, target_label=None),
            SimpleNamespace(line_no=4, target_label=None),
        ),
    )

    sites = collect_admissible_region_lowering_sites(
        region=region,
        dag=dag,
        node_by_key=node_by_key,
        dispatcher_region={71},
        semantic_reference_program=semantic_reference_program,
    )

    assert len(sites) == 1
    assert sites[0].site_kind == "exit"
    assert sites[0].target_entry_anchor == 66
    assert sites[0].successor_state_value == 0x4C77464F


def test_collect_admissible_region_lowering_sites_normalizes_raw_nonexact_exit_target():
    region = SimpleNamespace(
        region_name="region",
        state_values=(0x6107F8EC,),
        internal_state_edges=(),
        exit_state_values=(0x4C77464F,),
    )
    target_key = _Key(0x4C77464F)
    edge = SimpleNamespace(
        source_key=_Key(0x6107F8EC),
        target_key=target_key,
        target_state=0x4C77464F,
        source_anchor=SimpleNamespace(block_serial=15),
        target_entry_anchor=71,
        target_label="0x4C77464F",
        ordered_path=(15, 16),
    )
    dag = SimpleNamespace(
        edges=(edge,),
        supplemental_selected_entries=((0x4C77464F, 61),),
        nodes=(
            SimpleNamespace(
                key=target_key,
                kind=SimpleNamespace(name="EXACT"),
                state_label="0x4C77464F",
                handler_serial=66,
                entry_anchor=66,
                exclusive_blocks=(66,),
                owned_blocks=(),
                shared_suffix_blocks=(),
                local_segments=(),
            ),
        ),
    )
    node_by_key = {
        edge.source_key: SimpleNamespace(entry_anchor=15),
        target_key: dag.nodes[0],
    }
    semantic_reference_program = SimpleNamespace(
        nodes=(
            SimpleNamespace(
                label_text="STATE_6107F8EC",
                entry_anchor=15,
                line_start=1,
                line_end=2,
            ),
        ),
        lines=(
            SimpleNamespace(line_no=1, target_label=None),
            SimpleNamespace(line_no=2, target_label="STATE_4C77464F"),
        ),
    )
    dispatcher = SimpleNamespace(lookup=lambda state: 71)

    sites = collect_admissible_region_lowering_sites(
        region=region,
        dag=dag,
        node_by_key=node_by_key,
        dispatcher_region={61, 71},
        semantic_reference_program=semantic_reference_program,
        dispatcher=dispatcher,
    )

    assert len(sites) == 1
    assert sites[0].target_entry_anchor == 66


def test_collect_admissible_region_lowering_sites_prefers_nondispatcher_supplemental_head_for_raw_alias_exit():
    region = SimpleNamespace(
        region_name="region",
        state_values=(0x6107F8EC,),
        internal_state_edges=(),
        exit_state_values=(0x4C77464F,),
    )
    target_key = _Key(0x4C77464F)
    edge = SimpleNamespace(
        source_key=_Key(0x6107F8EC),
        target_key=target_key,
        target_state=0x4C77464F,
        source_anchor=SimpleNamespace(block_serial=15),
        target_entry_anchor=71,
        target_label="0x4C77464F",
        ordered_path=(15, 16),
    )
    dag = SimpleNamespace(
        edges=(edge,),
        supplemental_selected_entries=((0x4C77464F, 61),),
        nodes=(
            SimpleNamespace(
                key=_Key(0x474EEEBB),
                kind=StateNodeKind.EXACT,
                state_label="STATE_474EEEBB_fallback",
                handler_serial=63,
                entry_anchor=63,
                exclusive_blocks=(63,),
                owned_blocks=(61, 64, 65, 66),
                shared_suffix_blocks=(),
                local_segments=(SimpleNamespace(blocks=(64, 65, 66)),),
            ),
            SimpleNamespace(
                key=target_key,
                kind=SimpleNamespace(name="EXACT"),
                state_label="0x4C77464F",
                handler_serial=66,
                entry_anchor=66,
                exclusive_blocks=(66,),
                owned_blocks=(),
                shared_suffix_blocks=(),
                local_segments=(),
            ),
        ),
    )
    node_by_key = {
        edge.source_key: SimpleNamespace(entry_anchor=15),
        target_key: dag.nodes[0],
    }
    semantic_reference_program = SimpleNamespace(
        nodes=(
            SimpleNamespace(
                label_text="STATE_6107F8EC",
                entry_anchor=15,
                line_start=1,
                line_end=2,
            ),
        ),
        lines=(
            SimpleNamespace(line_no=1, target_label=None),
            SimpleNamespace(line_no=2, target_label="STATE_4C77464F"),
        ),
    )
    dispatcher = SimpleNamespace(lookup=lambda state: 71)

    sites = collect_admissible_region_lowering_sites(
        region=region,
        dag=dag,
        node_by_key=node_by_key,
        dispatcher_region={71},
        semantic_reference_program=semantic_reference_program,
        dispatcher=dispatcher,
    )

    assert len(sites) == 1
    assert sites[0].target_entry_anchor == 63


def test_collect_admissible_region_lowering_sites_keeps_direct_and_alias_branch_exits():
    region = SimpleNamespace(
        region_name="branch_region",
        state_values=(0x10743C4C, 0x6107F8EC),
        internal_state_edges=((0x10743C4C, 0x6107F8EC),),
        exit_state_values=(0x474EEEBB, 0x296F2452),
    )
    edge_to_alias = SimpleNamespace(
        source_key=_Key(0x6107F8EC),
        target_key=_Key(0x4C77464F),
        target_state=0x4C77464F,
        source_anchor=SimpleNamespace(block_serial=15, branch_arm=0),
        target_entry_anchor=68,
        target_label="0x4C77464F",
        ordered_path=(15, 16),
    )
    edge_to_direct = SimpleNamespace(
        source_key=_Key(0x6107F8EC),
        target_key=_Key(0x296F2452),
        target_state=0x296F2452,
        source_anchor=SimpleNamespace(block_serial=15, branch_arm=1),
        target_entry_anchor=202,
        target_label="STATE_296F2452",
        ordered_path=(15, 17),
    )
    dag = SimpleNamespace(
        edges=(edge_to_alias, edge_to_direct),
        supplemental_selected_entries=((0x4C77464F, 68),),
        nodes=(
            SimpleNamespace(
                key=_Key(0x6107F8EC),
                kind=StateNodeKind.EXACT,
                state_label="STATE_6107F8EC",
                handler_serial=15,
                entry_anchor=15,
                exclusive_blocks=(15,),
                owned_blocks=(15, 16, 17),
                shared_suffix_blocks=(),
                local_segments=(SimpleNamespace(blocks=(15, 16, 17)),),
            ),
            SimpleNamespace(
                key=_Key(0x4C77464F),
                kind=StateNodeKind.EXACT,
                state_label="0x4C77464F",
                handler_serial=66,
                entry_anchor=66,
                exclusive_blocks=(66,),
                owned_blocks=(66, 67, 68, 69),
                shared_suffix_blocks=(),
                local_segments=(SimpleNamespace(blocks=(66, 67, 68, 69)),),
            ),
            SimpleNamespace(
                key=_Key(0x474EEEBB),
                kind=StateNodeKind.EXACT,
                state_label="STATE_474EEEBB",
                handler_serial=63,
                entry_anchor=63,
                exclusive_blocks=(63,),
                owned_blocks=(63, 64, 65, 66, 68, 69),
                shared_suffix_blocks=(),
                local_segments=(SimpleNamespace(blocks=(63, 64, 65, 66, 68, 69)),),
            ),
            SimpleNamespace(
                key=_Key(0x296F2452),
                kind=StateNodeKind.EXACT,
                state_label="STATE_296F2452",
                handler_serial=202,
                entry_anchor=202,
                exclusive_blocks=(202,),
                owned_blocks=(202,),
                shared_suffix_blocks=(),
                local_segments=(SimpleNamespace(blocks=(202,)),),
            ),
        ),
    )
    node_by_key = {
        edge_to_alias.source_key: dag.nodes[0],
        edge_to_alias.target_key: dag.nodes[1],
        edge_to_direct.target_key: dag.nodes[3],
    }
    semantic_reference_program = SimpleNamespace(
        nodes=(
            SimpleNamespace(
                label_text="STATE_6107F8EC",
                entry_anchor=15,
                line_start=1,
                line_end=2,
            ),
            SimpleNamespace(
                label_text="STATE_474EEEBB",
                entry_anchor=63,
                line_start=3,
                line_end=4,
            ),
            SimpleNamespace(
                label_text="STATE_296F2452",
                entry_anchor=202,
                line_start=5,
                line_end=5,
            ),
        ),
        lines=(
            SimpleNamespace(line_no=1, target_label=None),
            SimpleNamespace(line_no=2, target_label="STATE_474EEEBB"),
            SimpleNamespace(line_no=2, target_label="STATE_296F2452"),
            SimpleNamespace(line_no=3, target_label=None),
            SimpleNamespace(line_no=4, target_label=None),
            SimpleNamespace(line_no=5, target_label=None),
        ),
    )

    sites = collect_admissible_region_lowering_sites(
        region=region,
        dag=dag,
        node_by_key=node_by_key,
        dispatcher_region={71},
        semantic_reference_program=semantic_reference_program,
    )

    assert len(sites) == 2
    by_successor = {site.successor_state_value: site for site in sites}
    assert 0x474EEEBB in by_successor
    assert 0x296F2452 in by_successor
    assert by_successor[0x474EEEBB].site_kind == "exit"


def test_collect_admissible_region_lowering_sites_maps_alias_branch_exits_by_branch_arm():
    region = SimpleNamespace(
        region_name="branch_region",
        state_values=(0x6107F8EC,),
        internal_state_edges=(),
        exit_state_values=(0x474EEEBB, 0x296F2452),
    )
    edge_fallthrough = SimpleNamespace(
        source_key=_Key(0x6107F8EC),
        target_key=None,
        target_state=0x12ACFB20,
        source_anchor=SimpleNamespace(block_serial=15, branch_arm=0),
        target_entry_anchor=230,
        target_label="0x12ACFB20",
        ordered_path=(15, 16, 68, 230),
    )
    edge_taken = SimpleNamespace(
        source_key=_Key(0x6107F8EC),
        target_key=None,
        target_state=0x2981423A,
        source_anchor=SimpleNamespace(block_serial=15, branch_arm=1),
        target_entry_anchor=149,
        target_label="0x2981423A",
        ordered_path=(15, 17, 202, 224, 147, 149),
    )
    dag = SimpleNamespace(
        edges=(edge_fallthrough, edge_taken),
        nodes=(),
    )
    node_by_key = {
        edge_fallthrough.source_key: SimpleNamespace(entry_anchor=15),
    }
    semantic_reference_program = SimpleNamespace(
        nodes=(
            SimpleNamespace(
                label_text="STATE_6107F8EC",
                entry_anchor=15,
                line_start=1,
                line_end=3,
            ),
            SimpleNamespace(
                label_text="STATE_474EEEBB",
                entry_anchor=63,
                line_start=4,
                line_end=4,
            ),
            SimpleNamespace(
                label_text="STATE_296F2452",
                entry_anchor=202,
                line_start=5,
                line_end=5,
            ),
        ),
        lines=(
            SimpleNamespace(line_no=1, target_label=None),
            SimpleNamespace(line_no=2, target_label="STATE_296F2452"),
            SimpleNamespace(line_no=3, target_label="STATE_474EEEBB"),
            SimpleNamespace(line_no=4, target_label=None),
            SimpleNamespace(line_no=5, target_label=None),
        ),
    )

    sites = collect_admissible_region_lowering_sites(
        region=region,
        dag=dag,
        node_by_key=node_by_key,
        dispatcher_region={},
        semantic_reference_program=semantic_reference_program,
    )

    assert len(sites) == 2
    by_branch_arm = {
        int(getattr(getattr(site.edge, "source_anchor", None), "branch_arm", -1)): site
        for site in sites
    }
    assert by_branch_arm[0].successor_state_value == 0x474EEEBB
    assert by_branch_arm[0].target_entry_anchor == 63
    assert by_branch_arm[1].successor_state_value == 0x296F2452
    assert by_branch_arm[1].target_entry_anchor == 202


def test_collect_admissible_region_lowering_sites_accepts_dispatcher_overridden_exact_target():
    region = SimpleNamespace(
        region_name="region",
        state_values=(0x11111111, 0x22222222),
        internal_state_edges=((0x11111111, 0x22222222),),
        exit_state_values=(),
    )
    target_key = _Key(0x22222222)
    edge = _edge(
        source_state=0x11111111,
        target_state=0x22222222,
        source_block=78,
        target_entry=20,
        target_key=target_key,
    )
    dag = SimpleNamespace(edges=(edge,))
    node_by_key = {
        edge.source_key: SimpleNamespace(entry_anchor=78),
        target_key: SimpleNamespace(
            entry_anchor=20,
            exclusive_blocks=(143,),
            owned_blocks=(20, 143),
            shared_suffix_blocks=(),
        ),
    }

    sites = collect_admissible_region_lowering_sites(
        region=region,
        dag=dag,
        node_by_key=node_by_key,
        dispatcher_region={20},
    )

    assert len(sites) == 1
    assert sites[0].site_kind == "internal"
    assert sites[0].target_entry_anchor == 143


def test_collect_admissible_region_lowering_sites_accepts_dispatcher_backed_exact_source_entry():
    region = SimpleNamespace(
        region_name="region",
        state_values=(0x4E69F350, 0x2A5ADB57),
        internal_state_edges=((0x4E69F350, 0x2A5ADB57),),
        exit_state_values=(),
    )
    source_key = _Key(0x4E69F350)
    target_key = _Key(0x2A5ADB57)
    edge = _edge(
        source_state=0x4E69F350,
        target_state=0x2A5ADB57,
        source_block=72,
        target_entry=177,
        target_key=target_key,
    )
    dag = SimpleNamespace(
        edges=(edge,),
        nodes=(
            SimpleNamespace(
                key=source_key,
                kind=SimpleNamespace(name="EXACT"),
                entry_anchor=72,
                exclusive_blocks=(72,),
                owned_blocks=(),
                shared_suffix_blocks=(),
            ),
            SimpleNamespace(
                key=target_key,
                kind=SimpleNamespace(name="EXACT"),
                entry_anchor=177,
                exclusive_blocks=(177,),
                owned_blocks=(),
                shared_suffix_blocks=(),
            ),
        ),
    )
    node_by_key = {
        source_key: dag.nodes[0],
        target_key: dag.nodes[1],
    }

    sites = collect_admissible_region_lowering_sites(
        region=region,
        dag=dag,
        node_by_key=node_by_key,
        dispatcher_region={72},
    )

    assert len(sites) == 1
    assert sites[0].source_entry_anchor == 72
    assert sites[0].target_entry_anchor == 177
    assert sites[0].site_kind == "internal"


def test_collect_admissible_region_lowering_sites_reanchors_dispatcher_backed_source_to_exact_head():
    region = SimpleNamespace(
        region_name="region",
        state_values=(0x4E69F350, 0x2A5ADB57),
        internal_state_edges=((0x4E69F350, 0x2A5ADB57),),
        exit_state_values=(),
    )
    source_key = _Key(0x4E69F350)
    target_key = _Key(0x2A5ADB57)
    edge = _edge(
        source_state=0x4E69F350,
        target_state=0x2A5ADB57,
        source_block=72,
        target_entry=177,
        target_key=target_key,
    )
    dag = SimpleNamespace(
        edges=(edge,),
        nodes=(
            SimpleNamespace(
                key=source_key,
                kind=SimpleNamespace(name="EXACT"),
                entry_anchor=72,
                exclusive_blocks=(72,),
                owned_blocks=(),
                shared_suffix_blocks=(),
                local_segments=(),
            ),
            SimpleNamespace(
                key=source_key,
                kind=SimpleNamespace(name="EXACT"),
                entry_anchor=68,
                exclusive_blocks=(68,),
                owned_blocks=(72,),
                shared_suffix_blocks=(),
                local_segments=(),
            ),
            SimpleNamespace(
                key=target_key,
                kind=SimpleNamespace(name="EXACT"),
                entry_anchor=177,
                exclusive_blocks=(177,),
                owned_blocks=(),
                shared_suffix_blocks=(),
                local_segments=(),
            ),
        ),
    )
    node_by_key = {
        source_key: dag.nodes[0],
        target_key: dag.nodes[2],
    }

    sites = collect_admissible_region_lowering_sites(
        region=region,
        dag=dag,
        node_by_key=node_by_key,
        dispatcher_region={72},
    )

    assert len(sites) == 1
    assert sites[0].source_entry_anchor == 68
    assert sites[0].source_anchor_block == 72
    assert sites[0].target_entry_anchor == 177
    assert sites[0].site_kind == "internal"


def test_build_region_preferred_direct_lowering_accepts_single_block_exact_handoff():
    source_key = _Key(0x4E69F350)
    site = SimpleNamespace(
        region_name="region",
        site_kind="internal",
        source_state=0x4E69F350,
        target_state=0x2A5ADB57,
        source_entry_anchor=72,
        source_anchor_block=72,
        target_entry_anchor=177,
        ordered_path=(72,),
        edge=SimpleNamespace(
            source_key=source_key,
            source_anchor=SimpleNamespace(block_serial=72, branch_arm=None),
        ),
    )

    lowering = build_region_preferred_direct_lowering(site=site)

    assert lowering is not None
    assert lowering.emission_mode == "direct"
    assert lowering.horizon_block == 72
    assert lowering.target_entry_anchor == 177


def test_collect_admissible_region_lowering_sites_rejects_feeder_row_source():
    region = SimpleNamespace(
        region_name="region",
        state_values=(0x11111111, 0x22222222),
        internal_state_edges=((0x11111111, 0x22222222),),
        exit_state_values=(),
    )
    edge = _edge(
        source_state=0x11111111,
        target_state=0x22222222,
        source_block=14,
        target_entry=136,
    )
    dag = SimpleNamespace(edges=(edge,))
    node_by_key = {
        edge.source_key: SimpleNamespace(entry_anchor=78),
    }

    sites = collect_admissible_region_lowering_sites(
        region=region,
        dag=dag,
        node_by_key=node_by_key,
        dispatcher_region={20},
    )

    assert sites == ()


def test_collect_admissible_region_lowering_sites_rejects_self_target_site():
    region = SimpleNamespace(
        region_name="region",
        state_values=(0x4E69F350,),
        internal_state_edges=((0x4E69F350, 0x4E69F350),),
        exit_state_values=(),
    )
    source_key = _Key(0x4E69F350)
    edge = SimpleNamespace(
        source_key=source_key,
        target_key=None,
        target_state=0x4E69F350,
        source_anchor=SimpleNamespace(block_serial=163),
        target_entry_anchor=161,
        ordered_path=(161, 163, 165),
    )
    dag = SimpleNamespace(
        edges=(edge,),
        nodes=(),
    )
    node_by_key = {
        source_key: SimpleNamespace(
            entry_anchor=161,
            exclusive_blocks=(161, 163, 165),
            owned_blocks=(),
            shared_suffix_blocks=(),
        ),
    }

    sites = collect_admissible_region_lowering_sites(
        region=region,
        dag=dag,
        node_by_key=node_by_key,
        dispatcher_region={2},
    )

    assert sites == ()


def test_collect_admissible_region_lowering_sites_ignores_nested_semantic_target_override():
    region = SimpleNamespace(
        region_name="region",
        state_values=(0x11CD1DA3,),
        internal_state_edges=(),
        exit_state_values=(0x4E69F350,),
    )
    source_key = _Key(0x11CD1DA3)
    target_key = _Key(0x4E69F350)
    edge = SimpleNamespace(
        source_key=source_key,
        target_key=target_key,
        target_state=0x4E69F350,
        source_anchor=SimpleNamespace(block_serial=163),
        target_entry_anchor=72,
        ordered_path=(161, 163, 165),
    )
    dag = SimpleNamespace(
        edges=(edge,),
        nodes=(
            SimpleNamespace(
                key=source_key,
                kind=SimpleNamespace(name="EXACT"),
                entry_anchor=161,
                exclusive_blocks=(161, 163, 165),
                owned_blocks=(),
                shared_suffix_blocks=(),
            ),
            SimpleNamespace(
                key=target_key,
                kind=SimpleNamespace(name="EXACT"),
                entry_anchor=72,
                exclusive_blocks=(72,),
                owned_blocks=(),
                shared_suffix_blocks=(),
            ),
        ),
    )
    node_by_key = {
        source_key: dag.nodes[0],
        target_key: dag.nodes[1],
    }
    semantic_reference_program = SimpleNamespace(
        nodes=(
            SimpleNamespace(
                label_text="STATE_11CD1DA3",
                entry_anchor=161,
                line_start=1,
                line_end=2,
            ),
            SimpleNamespace(
                label_text="STATE_4E69F350",
                entry_anchor=161,
                line_start=3,
                line_end=4,
            ),
        ),
        lines=(
            SimpleNamespace(line_no=1, target_label=None),
            SimpleNamespace(line_no=2, target_label="STATE_4E69F350"),
            SimpleNamespace(line_no=3, target_label=None),
            SimpleNamespace(line_no=4, target_label=None),
        ),
    )

    sites = collect_admissible_region_lowering_sites(
        region=region,
        dag=dag,
        node_by_key=node_by_key,
        dispatcher_region={2},
        semantic_reference_program=semantic_reference_program,
    )

    assert len(sites) == 1
    assert sites[0].target_entry_anchor == 72


def test_collect_admissible_region_lowering_sites_prefers_direct_semantic_successor_head_over_source_corridor_entry():
    region = SimpleNamespace(
        region_name="region",
        state_values=(0x11CD1DA3,),
        internal_state_edges=(),
        exit_state_values=(0x4E69F350,),
    )
    source_key = _Key(0x11CD1DA3)
    target_key = _Key(0x4E69F350)
    edge = SimpleNamespace(
        source_key=source_key,
        target_key=target_key,
        target_state=0x4E69F350,
        source_anchor=SimpleNamespace(block_serial=163, branch_arm=1),
        target_entry_anchor=161,
        ordered_path=(161, 163, 165),
    )
    target_node = SimpleNamespace(
        key=target_key,
        kind=SimpleNamespace(name="EXACT"),
        entry_anchor=72,
        exclusive_blocks=(72,),
        owned_blocks=(),
        shared_suffix_blocks=(),
    )
    dag = SimpleNamespace(
        edges=(edge,),
        nodes=(
            SimpleNamespace(
                key=source_key,
                kind=SimpleNamespace(name="EXACT"),
                entry_anchor=161,
                exclusive_blocks=(161, 163, 165),
                owned_blocks=(),
                shared_suffix_blocks=(),
            ),
            target_node,
        ),
    )
    node_by_key = {
        source_key: dag.nodes[0],
        target_key: target_node,
    }
    semantic_reference_program = SimpleNamespace(
        nodes=(
            SimpleNamespace(
                label_text="STATE_11CD1DA3",
                entry_anchor=161,
                line_start=1,
                line_end=2,
            ),
            SimpleNamespace(
                label_text="STATE_4E69F350",
                entry_anchor=72,
                line_start=3,
                line_end=4,
            ),
        ),
        lines=(
            SimpleNamespace(line_no=1, target_label=None),
            SimpleNamespace(line_no=2, target_label="STATE_4E69F350"),
            SimpleNamespace(line_no=3, target_label=None),
            SimpleNamespace(line_no=4, target_label=None),
        ),
    )

    sites = collect_admissible_region_lowering_sites(
        region=region,
        dag=dag,
        node_by_key=node_by_key,
        dispatcher_region={2},
        semantic_reference_program=semantic_reference_program,
    )

    assert len(sites) == 1
    assert sites[0].target_entry_anchor == 72
    assert sites[0].semantic_target_label == "STATE_4E69F350"


def test_override_exit_sites_with_child_region_entries_prefers_child_region_entry():
    source_key = _Key(0x11CD1DA3)
    target_key = _Key(0x4E69F350)
    site = SimpleNamespace(
        region_name="parent",
        site_kind="exit",
        source_state=0x11CD1DA3,
        target_state=0x4E69F350,
        source_entry_anchor=161,
        source_anchor_block=163,
        target_entry_anchor=161,
        ordered_path=(161, 163, 165),
        edge=SimpleNamespace(source_key=source_key, target_key=target_key, target_state=0x4E69F350),
        semantic_target_label=None,
        successor_state_value=0x4E69F350,
    )
    dag = SimpleNamespace(
        nodes=(
            SimpleNamespace(
                key=target_key,
                kind=SimpleNamespace(name="EXACT"),
                state_label="STATE_4E69F350",
                entry_anchor=72,
                exclusive_blocks=(72,),
                owned_blocks=(),
                local_segments=(),
                shared_suffix_blocks=(),
            ),
        ),
        edges=(),
    )
    structured_regions = (
        SimpleNamespace(region_name="parent", entry_state=0x11CD1DA3),
        SimpleNamespace(region_name="child", entry_state=0x4E69F350),
    )

    overridden = override_exit_sites_with_child_region_entries(
        (site,),
        current_region_name="parent",
        structured_regions=structured_regions,
        dag=dag,
        dispatcher_region={2},
    )

    assert len(overridden) == 1
    assert overridden[0].target_entry_anchor == 72


def test_override_exit_sites_with_child_region_entries_prefers_alias_normalized_child_entry():
    source_key = _Key(0x11CD1DA3)
    target_key = _Key(0x4E69F350)
    site = SimpleNamespace(
        region_name="parent",
        site_kind="exit",
        source_state=0x11CD1DA3,
        target_state=0x4E69F350,
        source_entry_anchor=161,
        source_anchor_block=163,
        target_entry_anchor=161,
        ordered_path=(161, 163, 165),
        edge=SimpleNamespace(
            source_key=source_key,
            target_key=target_key,
            target_state=0x4E69F350,
        ),
        semantic_target_label="STATE_4E69F350",
        successor_state_value=0x4E69F350,
    )
    dag = SimpleNamespace(
        nodes=(
            SimpleNamespace(
                key=target_key,
                kind=SimpleNamespace(name="EXACT"),
                state_label="STATE_4E69F350",
                entry_anchor=68,
                exclusive_blocks=(68,),
                owned_blocks=(),
                local_segments=(),
                shared_suffix_blocks=(),
            ),
            SimpleNamespace(
                key=target_key,
                kind=SimpleNamespace(name="EXACT"),
                state_label="STATE_4E69F350",
                entry_anchor=161,
                exclusive_blocks=(161, 163, 165),
                owned_blocks=(),
                local_segments=(),
                shared_suffix_blocks=(),
            ),
        ),
        edges=(),
    )
    structured_regions = (
        SimpleNamespace(region_name="parent", entry_state=0x11CD1DA3),
        SimpleNamespace(region_name="child", entry_state=0x4E69F350),
    )
    semantic_reference_program = SimpleNamespace(
        nodes=(
            SimpleNamespace(
                label_text="STATE_4E69F350",
                entry_anchor=161,
                line_start=1,
                line_end=1,
            ),
        ),
        lines=(SimpleNamespace(line_no=1, target_label=None),),
    )
    dispatcher = SimpleNamespace(
        _rows=(SimpleNamespace(lo=0x4E69F350, hi=0x4E69F351, target=72),)
    )

    overridden = override_exit_sites_with_child_region_entries(
        (site,),
        current_region_name="parent",
        structured_regions=structured_regions,
        dag=dag,
        dispatcher_region={66, 71, 72},
        semantic_reference_program=semantic_reference_program,
        dispatcher=dispatcher,
    )

    assert len(overridden) == 1
    assert overridden[0].target_entry_anchor == 68


def test_override_exit_sites_with_child_region_entries_promotes_raw_alias_child_to_owner_head():
    source_key = _Key(0x6107F8EC)
    target_key = _Key(0x4C77464F)
    site = SimpleNamespace(
        region_name="parent",
        site_kind="exit",
        source_state=0x6107F8EC,
        target_state=0x4C77464F,
        source_entry_anchor=15,
        source_anchor_block=16,
        target_entry_anchor=66,
        ordered_path=(15, 16),
        edge=SimpleNamespace(
            source_key=source_key,
            target_key=target_key,
            target_state=0x4C77464F,
        ),
        semantic_target_label="STATE_4C77464F",
        successor_state_value=0x4C77464F,
    )
    dag = SimpleNamespace(
        supplemental_selected_entries=((0x4C77464F, 61),),
        nodes=(
            SimpleNamespace(
                key=_Key(0x474EEEBB),
                kind=StateNodeKind.EXACT,
                state_label="STATE_474EEEBB_fallback",
                entry_anchor=63,
                exclusive_blocks=(63,),
                owned_blocks=(61, 64, 65, 66),
                local_segments=(SimpleNamespace(blocks=(64, 65, 66)),),
                shared_suffix_blocks=(),
            ),
            SimpleNamespace(
                key=target_key,
                kind=SimpleNamespace(name="EXACT"),
                state_label="0x4C77464F",
                entry_anchor=66,
                exclusive_blocks=(66,),
                owned_blocks=(),
                local_segments=(),
                shared_suffix_blocks=(),
            ),
        ),
        edges=(),
    )
    structured_regions = (
        SimpleNamespace(region_name="parent", entry_state=0x6107F8EC),
        SimpleNamespace(region_name="child", entry_state=0x4C77464F),
    )
    semantic_reference_program = SimpleNamespace(
        nodes=(
            SimpleNamespace(
                label_text="STATE_4C77464F",
                entry_anchor=66,
                line_start=1,
                line_end=1,
            ),
        ),
        lines=(SimpleNamespace(line_no=1, target_label=None),),
    )

    overridden = override_exit_sites_with_child_region_entries(
        (site,),
        current_region_name="parent",
        structured_regions=structured_regions,
        dag=dag,
        dispatcher_region={71},
        semantic_reference_program=semantic_reference_program,
    )

    assert len(overridden) == 1
    assert overridden[0].target_entry_anchor == 63


def test_override_exit_sites_with_child_region_entries_uses_successor_state_value_for_child_matching():
    source_key = _Key(0x6107F8EC)
    target_key = _Key(0x4C77464F)
    site = SimpleNamespace(
        region_name="parent",
        site_kind="exit",
        source_state=0x6107F8EC,
        target_state=0x4C77464F,
        source_entry_anchor=15,
        source_anchor_block=16,
        target_entry_anchor=68,
        ordered_path=(15, 16),
        edge=SimpleNamespace(
            source_key=source_key,
            target_key=target_key,
            target_state=0x4C77464F,
        ),
        semantic_target_label="STATE_474EEEBB_fallback",
        successor_state_value=0x474EEEBB,
    )
    dag = SimpleNamespace(
        supplemental_selected_entries=((0x474EEEBB, 61),),
        nodes=(
            SimpleNamespace(
                key=_Key(0x474EEEBB),
                kind=StateNodeKind.EXACT,
                state_label="STATE_474EEEBB_fallback",
                entry_anchor=63,
                exclusive_blocks=(63,),
                owned_blocks=(61, 64, 65, 66),
                local_segments=(SimpleNamespace(blocks=(64, 65, 66)),),
                shared_suffix_blocks=(),
            ),
        ),
        edges=(),
    )
    structured_regions = (
        SimpleNamespace(region_name="parent", entry_state=0x6107F8EC),
        SimpleNamespace(region_name="child474", entry_state=0x474EEEBB),
    )
    semantic_reference_program = SimpleNamespace(
        nodes=(
            SimpleNamespace(
                label_text="STATE_474EEEBB_fallback",
                entry_anchor=63,
                line_start=1,
                line_end=1,
            ),
        ),
        lines=(SimpleNamespace(line_no=1, target_label=None),),
    )

    overridden = override_exit_sites_with_child_region_entries(
        (site,),
        current_region_name="parent",
        structured_regions=structured_regions,
        dag=dag,
        dispatcher_region={71},
        semantic_reference_program=semantic_reference_program,
    )

    assert len(overridden) == 1
    assert overridden[0].target_entry_anchor == 63


def test_override_exit_sites_with_child_region_entries_prefers_semantic_child_head_over_generic_owner():
    source_key = _Key(0x149F5A97)
    target_key = _Key(0x610BB4D8)
    site = SimpleNamespace(
        region_name="parent",
        site_kind="exit",
        source_state=0x149F5A97,
        target_state=0x610BB4D8,
        source_entry_anchor=143,
        source_anchor_block=145,
        target_entry_anchor=15,
        ordered_path=(143, 145, 15),
        edge=SimpleNamespace(
            source_key=source_key,
            target_key=target_key,
            target_state=0x610BB4D8,
        ),
        semantic_target_label="STATE_610BB4D8",
        successor_state_value=0x610BB4D8,
    )
    dag = SimpleNamespace(
        nodes=(
            SimpleNamespace(
                key=target_key,
                kind=StateNodeKind.EXACT,
                state_label="STATE_610BB4D8",
                entry_anchor=15,
                exclusive_blocks=(15,),
                owned_blocks=(),
                local_segments=(),
                shared_suffix_blocks=(),
            ),
            SimpleNamespace(
                key=target_key,
                kind=StateNodeKind.EXACT,
                state_label="STATE_610BB4D8",
                entry_anchor=14,
                exclusive_blocks=(14,),
                owned_blocks=(15,),
                local_segments=(),
                shared_suffix_blocks=(),
            ),
        ),
        edges=(),
    )
    structured_regions = (
        SimpleNamespace(region_name="parent", entry_state=0x149F5A97),
        SimpleNamespace(region_name="child610", entry_state=0x610BB4D8),
    )
    semantic_reference_program = SimpleNamespace(
        nodes=(
            SimpleNamespace(
                label_text="STATE_610BB4D8",
                entry_anchor=15,
                line_start=1,
                line_end=1,
            ),
        ),
        lines=(SimpleNamespace(line_no=1, target_label=None),),
    )

    overridden = override_exit_sites_with_child_region_entries(
        (site,),
        current_region_name="parent",
        structured_regions=structured_regions,
        dag=dag,
        dispatcher_region={2},
        semantic_reference_program=semantic_reference_program,
    )

    assert len(overridden) == 1
    assert overridden[0].target_entry_anchor == 15


def test_override_exit_sites_with_child_region_entries_prunes_descendant_child_paths():
    source_key = _Key(0x149F5A97)
    child_key = _Key(0x610BB4D8)
    raw_key = _Key(0x4C77464F)
    direct_child_site = SimpleNamespace(
        region_name="parent",
        site_kind="exit",
        source_state=0x149F5A97,
        target_state=0x610BB4D8,
        source_entry_anchor=143,
        source_anchor_block=145,
        target_entry_anchor=15,
        ordered_path=(143, 145, 15),
        edge=SimpleNamespace(
            source_key=source_key,
            target_key=child_key,
            target_state=0x610BB4D8,
        ),
        semantic_target_label="STATE_610BB4D8",
        successor_state_value=0x610BB4D8,
    )
    descendant_site = SimpleNamespace(
        region_name="parent",
        site_kind="exit",
        source_state=0x149F5A97,
        target_state=0x4C77464F,
        source_entry_anchor=143,
        source_anchor_block=145,
        target_entry_anchor=68,
        ordered_path=(143, 145, 15, 16, 68, 163),
        edge=SimpleNamespace(
            source_key=source_key,
            target_key=raw_key,
            target_state=0x4C77464F,
        ),
        semantic_target_label="STATE_474EEEBB_fallback",
        successor_state_value=0x474EEEBB,
    )
    dag = SimpleNamespace(
        nodes=(
            SimpleNamespace(
                key=child_key,
                kind=StateNodeKind.EXACT,
                state_label="STATE_610BB4D8",
                entry_anchor=15,
                exclusive_blocks=(15,),
                owned_blocks=(),
                local_segments=(),
                shared_suffix_blocks=(),
            ),
            SimpleNamespace(
                key=raw_key,
                kind=StateNodeKind.EXACT,
                state_label="0x4C77464F",
                entry_anchor=68,
                exclusive_blocks=(68,),
                owned_blocks=(),
                local_segments=(),
                shared_suffix_blocks=(),
            ),
        ),
        edges=(),
    )
    structured_regions = (
        SimpleNamespace(region_name="parent", entry_state=0x149F5A97),
        SimpleNamespace(region_name="child610", entry_state=0x610BB4D8),
        SimpleNamespace(region_name="child474", entry_state=0x474EEEBB),
    )
    semantic_reference_program = SimpleNamespace(
        nodes=(
            SimpleNamespace(
                label_text="STATE_610BB4D8",
                entry_anchor=15,
                line_start=1,
                line_end=1,
            ),
            SimpleNamespace(
                label_text="STATE_474EEEBB_fallback",
                entry_anchor=68,
                line_start=2,
                line_end=2,
            ),
        ),
        lines=(
            SimpleNamespace(line_no=1, target_label=None),
            SimpleNamespace(line_no=2, target_label=None),
        ),
    )

    overridden = override_exit_sites_with_child_region_entries(
        (direct_child_site, descendant_site),
        current_region_name="parent",
        structured_regions=structured_regions,
        dag=dag,
        dispatcher_region={71},
        semantic_reference_program=semantic_reference_program,
    )

    assert len(overridden) == 1
    assert overridden[0].successor_state_value == 0x610BB4D8
    assert overridden[0].target_entry_anchor == 15


def test_override_exit_sites_with_child_region_entries_prefers_raw_target_when_it_is_child_entry():
    source_key = _Key(0x139F2922)
    target_key = _Key(0x2315233C)
    site = SimpleNamespace(
        region_name="parent",
        site_kind="exit",
        source_state=0x139F2922,
        target_state=0x2315233C,
        source_entry_anchor=136,
        source_anchor_block=141,
        target_entry_anchor=211,
        ordered_path=(136, 137, 139, 141),
        edge=SimpleNamespace(
            source_key=source_key,
            target_key=target_key,
            target_state=0x2315233C,
        ),
        semantic_target_label="STATE_2315233C",
        successor_state_value=0x7FDCE054,
    )
    dag = SimpleNamespace(
        supplemental_selected_entries=(),
        nodes=(
            SimpleNamespace(
                key=_Key(0x2315233C),
                kind=StateNodeKind.EXACT,
                state_label="STATE_2315233C",
                entry_anchor=210,
                exclusive_blocks=(210,),
                owned_blocks=(210,),
                local_segments=(),
                shared_suffix_blocks=(),
            ),
        ),
        edges=(),
    )
    structured_regions = (
        SimpleNamespace(region_name="parent", entry_state=0x139F2922),
        SimpleNamespace(region_name="child231", entry_state=0x2315233C),
    )
    semantic_reference_program = SimpleNamespace(
        nodes=(
            SimpleNamespace(
                label_text="STATE_2315233C",
                entry_anchor=210,
                line_start=1,
                line_end=1,
            ),
        ),
        lines=(SimpleNamespace(line_no=1, target_label=None),),
    )

    overridden = override_exit_sites_with_child_region_entries(
        (site,),
        current_region_name="parent",
        structured_regions=structured_regions,
        dag=dag,
        dispatcher_region={211},
        semantic_reference_program=semantic_reference_program,
    )

    assert len(overridden) == 1
    assert overridden[0].target_entry_anchor == 210
    assert overridden[0].successor_state_value == 0x2315233C


def test_override_exit_sites_with_child_region_entries_normalizes_successor_even_when_entry_is_already_correct():
    source_key = _Key(0x6465D165)
    target_key = _Key(0x474EEEBA)
    site = SimpleNamespace(
        region_name="parent",
        site_kind="exit",
        source_state=0x6465D165,
        target_state=0x474EEEBA,
        source_entry_anchor=23,
        source_anchor_block=32,
        target_entry_anchor=62,
        ordered_path=(23, 24, 32),
        edge=SimpleNamespace(
            source_key=source_key,
            target_key=target_key,
            target_state=0x474EEEBA,
        ),
        semantic_target_label="STATE_432DC789",
        successor_state_value=0x474EEEBA,
    )
    dag = SimpleNamespace(
        supplemental_selected_entries=(),
        nodes=(
            SimpleNamespace(
                key=_Key(0x432DC789),
                kind=StateNodeKind.EXACT,
                state_label="STATE_432DC789",
                entry_anchor=62,
                exclusive_blocks=(62,),
                owned_blocks=(62,),
                local_segments=(),
                shared_suffix_blocks=(),
            ),
        ),
        edges=(),
    )
    structured_regions = (
        SimpleNamespace(region_name="parent", entry_state=0x6465D165),
        SimpleNamespace(region_name="child432", entry_state=0x432DC789),
    )
    semantic_reference_program = SimpleNamespace(
        nodes=(
            SimpleNamespace(
                label_text="STATE_432DC789",
                entry_anchor=62,
                line_start=1,
                line_end=1,
            ),
        ),
        lines=(SimpleNamespace(line_no=1, target_label=None),),
    )

    overridden = override_exit_sites_with_child_region_entries(
        (site,),
        current_region_name="parent",
        structured_regions=structured_regions,
        dag=dag,
        dispatcher_region={62},
        semantic_reference_program=semantic_reference_program,
    )

    assert len(overridden) == 1
    assert overridden[0].target_entry_anchor == 62
    assert overridden[0].semantic_target_label == "STATE_432DC789"
    assert overridden[0].successor_state_value == 0x432DC789


def test_override_exit_alias_sites_with_child_region_entries_uses_semantic_alias_successor():
    source_key = _Key(0x6107F8EC)
    target_key = _Key(0x4C77464F)
    site = SimpleNamespace(
        region_name="parent",
        site_kind="exit_alias_candidate",
        source_state=0x6107F8EC,
        target_state=0x4C77464F,
        source_entry_anchor=15,
        source_anchor_block=16,
        target_entry_anchor=68,
        ordered_path=(15, 16),
        edge=SimpleNamespace(
            source_key=source_key,
            target_key=target_key,
            target_state=0x4C77464F,
        ),
        semantic_target_label="STATE_474EEEBB_fallback",
        successor_state_value=0x474EEEBB,
    )
    dag = SimpleNamespace(
        supplemental_selected_entries=((0x474EEEBB, 61),),
        nodes=(
            SimpleNamespace(
                key=_Key(0x474EEEBB),
                kind=StateNodeKind.EXACT,
                state_label="STATE_474EEEBB_fallback",
                entry_anchor=63,
                exclusive_blocks=(63,),
                owned_blocks=(61, 64, 65, 66),
                local_segments=(SimpleNamespace(blocks=(64, 65, 66)),),
                shared_suffix_blocks=(),
            ),
        ),
        edges=(),
    )
    structured_regions = (
        SimpleNamespace(region_name="parent", entry_state=0x6107F8EC),
        SimpleNamespace(region_name="child474", entry_state=0x474EEEBB),
    )
    semantic_reference_program = SimpleNamespace(
        nodes=(
            SimpleNamespace(
                label_text="STATE_474EEEBB_fallback",
                entry_anchor=63,
                line_start=1,
                line_end=1,
            ),
        ),
        lines=(SimpleNamespace(line_no=1, target_label=None),),
    )

    overridden = override_exit_sites_with_child_region_entries(
        (site,),
        current_region_name="parent",
        structured_regions=structured_regions,
        dag=dag,
        dispatcher_region={71},
        semantic_reference_program=semantic_reference_program,
    )

    assert len(overridden) == 1
    assert overridden[0].target_entry_anchor == 63


def test_override_exit_sites_with_child_region_entries_uses_first_post_branch_block_for_child_head_resolution():
    source_key = _Key(0x6107F8EC)
    target_key = _Key(0x474EEEBB)
    site = SimpleNamespace(
        region_name="parent",
        site_kind="exit",
        source_state=0x6107F8EC,
        target_state=0x474EEEBB,
        source_entry_anchor=15,
        source_anchor_block=15,
        target_entry_anchor=66,
        ordered_path=(15, 16, 68),
        edge=SimpleNamespace(
            source_key=source_key,
            target_key=target_key,
            target_state=0x474EEEBB,
            source_anchor=SimpleNamespace(block_serial=15, branch_arm=0),
        ),
        semantic_target_label="STATE_474EEEBB",
        successor_state_value=0x474EEEBB,
    )
    dag = SimpleNamespace(
        supplemental_selected_entries=((0x474EEEBB, 61),),
        nodes=(
            SimpleNamespace(
                key=target_key,
                kind=StateNodeKind.EXACT,
                state_label="STATE_474EEEBB",
                entry_anchor=63,
                exclusive_blocks=(63,),
                owned_blocks=(61, 64, 65, 66),
                local_segments=(SimpleNamespace(blocks=(64, 65, 66)),),
                shared_suffix_blocks=(),
            ),
        ),
        edges=(),
    )
    structured_regions = (
        SimpleNamespace(region_name="parent", entry_state=0x6107F8EC),
        SimpleNamespace(region_name="child474", entry_state=0x474EEEBB),
    )
    semantic_reference_program = SimpleNamespace(
        nodes=(
            SimpleNamespace(
                label_text="STATE_474EEEBB",
                entry_anchor=66,
                line_start=1,
                line_end=1,
            ),
        ),
        lines=(SimpleNamespace(line_no=1, target_label=None),),
    )

    overridden = override_exit_sites_with_child_region_entries(
        (site,),
        current_region_name="parent",
        structured_regions=structured_regions,
        dag=dag,
        dispatcher_region={71},
        semantic_reference_program=semantic_reference_program,
    )

    assert len(overridden) == 1
    assert overridden[0].target_entry_anchor == 63
    assert overridden[0].ordered_path == (15, 63)
    assert overridden[0].edge.target_entry_anchor == 63


def test_collect_admissible_region_lowering_sites_canonicalizes_exit_alias_to_exact_head():
    region = SimpleNamespace(
        region_name="branch_region",
        state_values=(0x10743C4C, 0x6107F8EC),
        internal_state_edges=((0x10743C4C, 0x6107F8EC),),
        exit_state_values=(0x474EEEBB, 0x296F2452),
    )
    edge_to_alias = SimpleNamespace(
        source_key=_Key(0x6107F8EC),
        target_key=_Key(0x4C77464F),
        target_state=0x4C77464F,
        source_anchor=SimpleNamespace(block_serial=15, branch_arm=0),
        target_entry_anchor=68,
        target_label="0x4C77464F",
        ordered_path=(15, 16),
    )
    dag = SimpleNamespace(
        edges=(edge_to_alias,),
        supplemental_selected_entries=((0x4C77464F, 68),),
        nodes=(
            SimpleNamespace(
                key=_Key(0x6107F8EC),
                kind=StateNodeKind.EXACT,
                state_label="STATE_6107F8EC",
                handler_serial=15,
                entry_anchor=15,
                exclusive_blocks=(15,),
                owned_blocks=(15, 16),
                shared_suffix_blocks=(),
                local_segments=(SimpleNamespace(blocks=(15, 16)),),
            ),
            SimpleNamespace(
                key=_Key(0x4C77464F),
                kind=StateNodeKind.EXACT,
                state_label="0x4C77464F",
                handler_serial=66,
                entry_anchor=66,
                exclusive_blocks=(66,),
                owned_blocks=(66, 67, 68, 69),
                shared_suffix_blocks=(),
                local_segments=(SimpleNamespace(blocks=(66, 67, 68, 69)),),
            ),
        ),
    )
    node_by_key = {
        edge_to_alias.source_key: dag.nodes[0],
        edge_to_alias.target_key: dag.nodes[1],
    }

    sites = collect_admissible_region_lowering_sites(
        region=region,
        dag=dag,
        node_by_key=node_by_key,
        dispatcher_region={71},
        semantic_reference_program=None,
    )

    assert len(sites) == 1
    assert sites[0].target_entry_anchor == 66


def test_override_exit_sites_with_child_region_entries_prefers_dispatcher_exact_head_when_normalized_child_self_loops():
    source_key = _Key(0x11CD1DA3)
    target_key = _Key(0x4E69F350)
    site = SimpleNamespace(
        region_name="parent",
        site_kind="exit",
        source_state=0x11CD1DA3,
        target_state=0x4E69F350,
        source_entry_anchor=161,
        source_anchor_block=163,
        target_entry_anchor=72,
        ordered_path=(161, 163, 165),
        edge=SimpleNamespace(
            source_key=source_key,
            target_key=target_key,
            target_state=0x4E69F350,
        ),
        semantic_target_label="STATE_4E69F350",
        successor_state_value=0x4E69F350,
    )
    dag = SimpleNamespace(
        nodes=(
            SimpleNamespace(
                key=target_key,
                kind=SimpleNamespace(name="EXACT"),
                state_label="STATE_4E69F350",
                entry_anchor=161,
                exclusive_blocks=(161, 163, 165),
                owned_blocks=(),
                local_segments=(),
                shared_suffix_blocks=(),
            ),
        ),
        edges=(),
    )
    structured_regions = (
        SimpleNamespace(region_name="parent", entry_state=0x12ACFB20),
        SimpleNamespace(region_name="child", entry_state=0x4E69F350),
    )
    semantic_reference_program = SimpleNamespace(
        nodes=(
            SimpleNamespace(
                label_text="STATE_4E69F350",
                entry_anchor=161,
                line_start=1,
                line_end=1,
            ),
        ),
        lines=(SimpleNamespace(line_no=1, target_label=None),),
    )
    dispatcher = SimpleNamespace(
        _rows=(SimpleNamespace(lo=0x4E69F350, hi=0x4E69F351, target=72),)
    )

    overridden = override_exit_sites_with_child_region_entries(
        (site,),
        current_region_name="parent",
        structured_regions=structured_regions,
        dag=dag,
        dispatcher_region={66, 71, 72},
        semantic_reference_program=semantic_reference_program,
        dispatcher=dispatcher,
    )

    assert len(overridden) == 1
    assert overridden[0].target_entry_anchor == 72


def test_override_exit_sites_with_child_region_entries_rewrites_site_and_edge_to_normalized_child_target():
    source_key = _Key(0x6107F8EC)
    site = SimpleNamespace(
        region_name="parent",
        site_kind="exit",
        source_state=0x6107F8EC,
        target_state=0x12ACFB20,
        source_entry_anchor=15,
        source_anchor_block=15,
        target_entry_anchor=202,
        ordered_path=(15, 16, 68, 230),
        edge=SimpleNamespace(
            source_key=source_key,
            target_state=0x12ACFB20,
            target_entry_anchor=202,
            target_label="STATE_296F2452",
            source_anchor=SimpleNamespace(block_serial=15, branch_arm=0),
            ordered_path=(15, 16, 68, 230),
        ),
        semantic_target_label="STATE_474EEEBB",
        successor_state_value=0x474EEEBB,
    )
    dag = SimpleNamespace(
        nodes=(
            SimpleNamespace(
                key=_Key(0x474EEEBB),
                kind=StateNodeKind.EXACT,
                state_label="STATE_474EEEBB",
                entry_anchor=66,
                exclusive_blocks=(66,),
                owned_blocks=(66, 67, 68, 69),
                local_segments=(SimpleNamespace(blocks=(66, 67, 68, 69)),),
                shared_suffix_blocks=(),
            ),
        ),
        edges=(),
        supplemental_selected_entries=(),
    )
    structured_regions = (
        SimpleNamespace(region_name="parent", entry_state=0x10743C4C),
        SimpleNamespace(region_name="child474", entry_state=0x474EEEBB),
    )
    semantic_reference_program = SimpleNamespace(
        nodes=(
            SimpleNamespace(
                label_text="STATE_474EEEBB",
                entry_anchor=66,
                line_start=1,
                line_end=1,
            ),
        ),
        lines=(SimpleNamespace(line_no=1, target_label=None),),
    )

    overridden = override_exit_sites_with_child_region_entries(
        (site,),
        current_region_name="parent",
        structured_regions=structured_regions,
        dag=dag,
        dispatcher_region={71},
        semantic_reference_program=semantic_reference_program,
    )

    assert len(overridden) == 1
    assert overridden[0].target_state == 0x474EEEBB
    assert overridden[0].target_entry_anchor == 66
    assert overridden[0].successor_state_value == 0x474EEEBB
    assert overridden[0].edge.target_state == 0x474EEEBB
    assert overridden[0].edge.observed_target_state == 0x12ACFB20
    assert overridden[0].edge.target_entry_anchor == 66
    assert overridden[0].edge.target_label == "STATE_474EEEBB"


def test_override_exit_sites_with_child_region_entries_recanonicalizes_stale_semantic_label_for_normalized_child_state():
    source_key = _Key(0x6107F8EC)
    site = SimpleNamespace(
        region_name="parent",
        site_kind="exit",
        source_state=0x6107F8EC,
        target_state=0x474EEEBB,
        source_entry_anchor=15,
        source_anchor_block=15,
        target_entry_anchor=202,
        ordered_path=(15, 66, 163),
        edge=SimpleNamespace(
            source_key=source_key,
            target_state=0x474EEEBB,
            target_entry_anchor=202,
            target_label="STATE_296F2452",
            source_anchor=SimpleNamespace(block_serial=15),
            ordered_path=(15, 66, 163),
        ),
        semantic_target_label="STATE_296F2452",
        successor_state_value=0x296F2452,
    )
    dag = SimpleNamespace(
        nodes=(
            SimpleNamespace(
                key=_Key(0x296F2452),
                kind=StateNodeKind.EXACT,
                state_label="STATE_296F2452",
                entry_anchor=202,
                exclusive_blocks=(202,),
                owned_blocks=(202,),
                local_segments=(),
                shared_suffix_blocks=(),
            ),
            SimpleNamespace(
                key=_Key(0x474EEEBB),
                kind=StateNodeKind.EXACT,
                state_label="STATE_474EEEBB",
                entry_anchor=66,
                exclusive_blocks=(66,),
                owned_blocks=(66, 67, 68, 69),
                local_segments=(SimpleNamespace(blocks=(66, 67, 68, 69)),),
                shared_suffix_blocks=(),
            ),
        ),
        edges=(),
        supplemental_selected_entries=(),
    )
    structured_regions = (
        SimpleNamespace(region_name="parent", entry_state=0x10743C4C),
        SimpleNamespace(region_name="child296", entry_state=0x296F2452),
        SimpleNamespace(region_name="child474", entry_state=0x474EEEBB),
    )
    semantic_reference_program = SimpleNamespace(
        nodes=(
            SimpleNamespace(
                label_text="STATE_296F2452",
                entry_anchor=202,
                line_start=1,
                line_end=1,
            ),
            SimpleNamespace(
                label_text="STATE_474EEEBB",
                entry_anchor=66,
                line_start=2,
                line_end=2,
            ),
        ),
        lines=(
            SimpleNamespace(line_no=1, target_label=None),
            SimpleNamespace(line_no=2, target_label=None),
        ),
    )

    overridden = override_exit_sites_with_child_region_entries(
        (site,),
        current_region_name="parent",
        structured_regions=structured_regions,
        dag=dag,
        dispatcher_region={71},
        semantic_reference_program=semantic_reference_program,
    )

    assert len(overridden) == 1
    assert overridden[0].target_state == 0x474EEEBB
    assert overridden[0].target_entry_anchor == 66
    assert overridden[0].semantic_target_label == "STATE_474EEEBB"
    assert overridden[0].successor_state_value == 0x474EEEBB
    assert overridden[0].ordered_path == (15, 66)
    assert overridden[0].edge.target_state == 0x474EEEBB
    assert overridden[0].edge.target_entry_anchor == 66
    assert overridden[0].edge.target_label == "STATE_474EEEBB"
    assert overridden[0].edge.ordered_path == (15, 66)


def test_override_exit_sites_with_child_region_entries_rebuilds_branch_child_path_from_source_anchor():
    source_key = _Key(0x6107F8EC)
    site = SimpleNamespace(
        region_name="parent",
        site_kind="exit",
        source_state=0x6107F8EC,
        target_state=0x474EEEBB,
        source_entry_anchor=14,
        source_anchor_block=15,
        target_entry_anchor=202,
        ordered_path=(14, 136, 137, 139, 143, 145, 15, 16, 68, 230),
        edge=SimpleNamespace(
            source_key=source_key,
            target_state=0x474EEEBB,
            target_entry_anchor=202,
            target_label="STATE_296F2452",
            source_anchor=SimpleNamespace(block_serial=15, branch_arm=0),
            ordered_path=(14, 136, 137, 139, 143, 145, 15, 16, 68, 230),
        ),
        semantic_target_label="STATE_296F2452",
        successor_state_value=0x296F2452,
    )
    dag = SimpleNamespace(
        nodes=(
            SimpleNamespace(
                key=_Key(0x296F2452),
                kind=StateNodeKind.EXACT,
                state_label="STATE_296F2452",
                entry_anchor=202,
                exclusive_blocks=(202,),
                owned_blocks=(202,),
                local_segments=(),
                shared_suffix_blocks=(),
            ),
            SimpleNamespace(
                key=_Key(0x474EEEBB),
                kind=StateNodeKind.EXACT,
                state_label="STATE_474EEEBB",
                entry_anchor=66,
                exclusive_blocks=(66,),
                owned_blocks=(66, 67, 68, 69),
                local_segments=(SimpleNamespace(blocks=(66, 67, 68, 69)),),
                shared_suffix_blocks=(),
            ),
        ),
        edges=(),
        supplemental_selected_entries=(),
    )
    structured_regions = (
        SimpleNamespace(region_name="parent", entry_state=0x10743C4C),
        SimpleNamespace(region_name="child296", entry_state=0x296F2452),
        SimpleNamespace(region_name="child474", entry_state=0x474EEEBB),
    )
    semantic_reference_program = SimpleNamespace(
        nodes=(
            SimpleNamespace(
                label_text="STATE_296F2452",
                entry_anchor=202,
                line_start=1,
                line_end=1,
            ),
            SimpleNamespace(
                label_text="STATE_474EEEBB",
                entry_anchor=66,
                line_start=2,
                line_end=2,
            ),
        ),
        lines=(
            SimpleNamespace(line_no=1, target_label=None),
            SimpleNamespace(line_no=2, target_label=None),
        ),
    )

    overridden = override_exit_sites_with_child_region_entries(
        (site,),
        current_region_name="parent",
        structured_regions=structured_regions,
        dag=dag,
        dispatcher_region={71},
        semantic_reference_program=semantic_reference_program,
    )

    assert len(overridden) == 1
    assert overridden[0].target_state == 0x474EEEBB
    assert overridden[0].target_entry_anchor == 66
    assert overridden[0].semantic_target_label == "STATE_474EEEBB"
    assert overridden[0].successor_state_value == 0x474EEEBB
    assert overridden[0].ordered_path == (15, 66)
    assert overridden[0].edge.target_state == 0x474EEEBB
    assert overridden[0].edge.target_entry_anchor == 66
    assert overridden[0].edge.target_label == "STATE_474EEEBB"
    assert overridden[0].edge.ordered_path == (15, 66)


def test_collect_admissible_region_lowering_sites_prefers_exact_head_even_when_child_head_is_dispatcher_row():
    region = SimpleNamespace(
        region_name="region",
        state_values=(0x11CD1DA3,),
        internal_state_edges=(),
        exit_state_values=(0x4E69F350,),
    )
    source_key = _Key(0x11CD1DA3)
    target_key = _Key(0x4E69F350)
    edge = SimpleNamespace(
        source_key=source_key,
        target_key=target_key,
        target_state=0x4E69F350,
        source_anchor=SimpleNamespace(block_serial=163, branch_arm=1),
        target_entry_anchor=161,
        ordered_path=(161, 163, 165),
    )
    target_node = SimpleNamespace(
        key=target_key,
        kind=SimpleNamespace(name="EXACT"),
        entry_anchor=72,
        exclusive_blocks=(72,),
        owned_blocks=(),
        shared_suffix_blocks=(),
    )
    dag = SimpleNamespace(
        edges=(edge,),
        nodes=(
            SimpleNamespace(
                key=source_key,
                kind=SimpleNamespace(name="EXACT"),
                entry_anchor=161,
                exclusive_blocks=(161, 163, 165),
                owned_blocks=(),
                shared_suffix_blocks=(),
            ),
            target_node,
        ),
    )
    node_by_key = {
        source_key: dag.nodes[0],
        target_key: target_node,
    }
    semantic_reference_program = SimpleNamespace(
        nodes=(
            SimpleNamespace(
                label_text="STATE_11CD1DA3__blk_163",
                entry_anchor=163,
                line_start=1,
                line_end=2,
            ),
            SimpleNamespace(
                label_text="STATE_4E69F350",
                entry_anchor=72,
                line_start=3,
                line_end=4,
            ),
        ),
        lines=(
            SimpleNamespace(line_no=1, target_label=None),
            SimpleNamespace(line_no=2, target_label="STATE_4E69F350"),
            SimpleNamespace(line_no=3, target_label=None),
            SimpleNamespace(line_no=4, target_label=None),
        ),
    )

    sites = collect_admissible_region_lowering_sites(
        region=region,
        dag=dag,
        node_by_key=node_by_key,
        dispatcher_region={66, 71, 72},
        semantic_reference_program=semantic_reference_program,
    )

    assert len(sites) == 1
    assert sites[0].target_entry_anchor == 72


def test_collect_admissible_region_lowering_sites_prefers_exact_head_over_exit_path_lead():
    region = SimpleNamespace(
        region_name="region",
        state_values=(0x11CD1DA3,),
        internal_state_edges=(),
        exit_state_values=(0x4E69F350,),
    )
    source_key = _Key(0x11CD1DA3)
    target_key = _Key(0x4E69F350)
    edge = SimpleNamespace(
        source_key=source_key,
        target_key=target_key,
        target_state=0x4E69F350,
        source_anchor=SimpleNamespace(block_serial=163, branch_arm=1),
        target_entry_anchor=161,
        ordered_path=(161, 163, 165),
    )
    target_node = SimpleNamespace(
        key=target_key,
        kind=SimpleNamespace(name="EXACT"),
        entry_anchor=72,
        exclusive_blocks=(72,),
        owned_blocks=(),
        shared_suffix_blocks=(),
    )
    dag = SimpleNamespace(
        edges=(edge,),
        nodes=(
            SimpleNamespace(
                key=source_key,
                kind=SimpleNamespace(name="EXACT"),
                entry_anchor=161,
                exclusive_blocks=(161, 163, 165),
                owned_blocks=(),
                shared_suffix_blocks=(),
            ),
            target_node,
        ),
    )
    node_by_key = {
        source_key: dag.nodes[0],
        target_key: target_node,
    }
    semantic_reference_program = SimpleNamespace(
        nodes=(
            SimpleNamespace(
                label_text="STATE_11CD1DA3",
                entry_anchor=161,
                line_start=1,
                line_end=1,
            ),
            SimpleNamespace(
                label_text="STATE_4E69F350",
                entry_anchor=72,
                line_start=2,
                line_end=2,
            ),
        ),
        lines=(),
    )

    sites = collect_admissible_region_lowering_sites(
        region=region,
        dag=dag,
        node_by_key=node_by_key,
        dispatcher_region={66, 71, 72},
        semantic_reference_program=semantic_reference_program,
    )

    assert len(sites) == 1
    assert sites[0].target_entry_anchor == 72


def test_override_exit_sites_with_child_region_entries_prefers_exact_head_even_when_child_head_is_dispatcher_row():
    source_key = _Key(0x11CD1DA3)
    target_key = _Key(0x4E69F350)
    site = SimpleNamespace(
        region_name="parent",
        site_kind="exit",
        source_state=0x11CD1DA3,
        target_state=0x4E69F350,
        source_entry_anchor=161,
        source_anchor_block=163,
        target_entry_anchor=161,
        ordered_path=(161, 163, 165),
        edge=SimpleNamespace(source_key=source_key, target_key=target_key, target_state=0x4E69F350),
        semantic_target_label="STATE_4E69F350",
        successor_state_value=0x4E69F350,
    )
    dag = SimpleNamespace(
        nodes=(
            SimpleNamespace(
                key=target_key,
                kind=SimpleNamespace(name="EXACT"),
                state_label="STATE_4E69F350",
                entry_anchor=72,
                exclusive_blocks=(72,),
                owned_blocks=(),
                local_segments=(),
                shared_suffix_blocks=(),
            ),
        ),
        edges=(),
    )
    structured_regions = (
        SimpleNamespace(region_name="parent", entry_state=0x11CD1DA3),
        SimpleNamespace(region_name="child", entry_state=0x4E69F350),
    )

    overridden = override_exit_sites_with_child_region_entries(
        (site,),
        current_region_name="parent",
        structured_regions=structured_regions,
        dag=dag,
        dispatcher_region={66, 71, 72},
    )

    assert len(overridden) == 1
    assert overridden[0].target_entry_anchor == 72


def test_override_exit_sites_with_child_region_entries_keeps_normalized_child_entry_when_no_distinct_child_head_exists():
    source_key = _Key(0x11CD1DA3)
    target_key = _Key(0x4E69F350)
    site = SimpleNamespace(
        region_name="parent",
        site_kind="exit",
        source_state=0x11CD1DA3,
        target_state=0x4E69F350,
        source_entry_anchor=161,
        source_anchor_block=163,
        target_entry_anchor=161,
        ordered_path=(161, 163, 165),
        edge=SimpleNamespace(
            source_key=source_key,
            target_key=target_key,
            target_state=0x4E69F350,
        ),
        semantic_target_label="STATE_4E69F350",
        successor_state_value=0x4E69F350,
    )
    dag = SimpleNamespace(
        nodes=(
            SimpleNamespace(
                key=target_key,
                kind=SimpleNamespace(name="EXACT"),
                state_label="STATE_4E69F350",
                entry_anchor=161,
                exclusive_blocks=(161, 163, 165),
                owned_blocks=(),
                local_segments=(),
                shared_suffix_blocks=(),
            ),
        ),
        edges=(),
    )
    structured_regions = (
        SimpleNamespace(region_name="parent", entry_state=0x11CD1DA3),
        SimpleNamespace(region_name="child", entry_state=0x4E69F350),
    )
    semantic_reference_program = SimpleNamespace(
        nodes=(
            SimpleNamespace(
                label_text="STATE_11CD1DA3",
                entry_anchor=161,
                line_start=1,
                line_end=1,
            ),
            SimpleNamespace(
                label_text="STATE_4E69F350",
                entry_anchor=72,
                line_start=2,
                line_end=2,
            ),
        ),
        lines=(
            SimpleNamespace(line_no=1, target_label="STATE_4E69F350"),
            SimpleNamespace(line_no=2, target_label=None),
        ),
    )

    overridden = override_exit_sites_with_child_region_entries(
        (site,),
        current_region_name="parent",
        structured_regions=structured_regions,
        dag=dag,
        dispatcher_region={66, 71, 72},
        semantic_reference_program=semantic_reference_program,
    )

    assert len(overridden) == 1
    assert overridden[0].target_entry_anchor == 161


def test_override_exit_sites_with_child_region_entries_prefers_dispatcher_exact_head_over_semantic_self_loop():
    source_key = _Key(0x11CD1DA3)
    target_key = _Key(0x4E69F350)
    site = SimpleNamespace(
        region_name="parent",
        site_kind="exit",
        source_state=0x11CD1DA3,
        target_state=0x4E69F350,
        source_entry_anchor=161,
        source_anchor_block=163,
        target_entry_anchor=161,
        ordered_path=(161, 163, 165),
        edge=SimpleNamespace(
            source_key=source_key,
            target_key=target_key,
            target_state=0x4E69F350,
        ),
        semantic_target_label="STATE_4E69F350",
        successor_state_value=0x4E69F350,
    )
    dag = SimpleNamespace(
        nodes=(
            SimpleNamespace(
                key=target_key,
                kind=SimpleNamespace(name="EXACT"),
                state_label="STATE_4E69F350",
                entry_anchor=161,
                exclusive_blocks=(161, 163, 165),
                owned_blocks=(),
                local_segments=(),
                shared_suffix_blocks=(),
            ),
        ),
        edges=(),
    )
    structured_regions = (
        SimpleNamespace(region_name="parent", entry_state=0x11CD1DA3),
        SimpleNamespace(region_name="child", entry_state=0x4E69F350),
    )
    semantic_reference_program = SimpleNamespace(
        nodes=(
            SimpleNamespace(
                label_text="STATE_4E69F350",
                entry_anchor=161,
                line_start=1,
                line_end=1,
            ),
        ),
        lines=(SimpleNamespace(line_no=1, target_label=None),),
    )
    dispatcher = SimpleNamespace(
        _rows=(
            SimpleNamespace(lo=0x4E69F350, hi=0x4E69F351, target=72),
        )
    )

    overridden = override_exit_sites_with_child_region_entries(
        (site,),
        current_region_name="parent",
        structured_regions=structured_regions,
        dag=dag,
        dispatcher_region={66, 71, 72},
        semantic_reference_program=semantic_reference_program,
        dispatcher=dispatcher,
    )

    assert len(overridden) == 1
    assert overridden[0].target_entry_anchor == 72


def test_synthesize_missing_conditional_exit_sites_populates_last_write_site_attribute():
    source_key = _Key(0x6107F8EC)
    template_edge = SimpleNamespace(
        source_key=source_key,
        target_key=_Key(0x296F2452),
        target_state=0x296F2452,
        kind="conditional_transition",
        last_write_site=None,
        source_anchor=SimpleNamespace(block_serial=15, branch_arm=1),
        target_entry_anchor=202,
        target_label="STATE_296F2452",
        ordered_path=(15, 17),
    )
    template_site = SimpleNamespace(
        region_name="branch_region",
        site_kind="exit",
        source_state=0x6107F8EC,
        target_state=0x296F2452,
        source_entry_anchor=15,
        source_anchor_block=15,
        target_entry_anchor=202,
        ordered_path=(15, 17),
        edge=template_edge,
        semantic_target_label="STATE_296F2452",
        successor_state_value=0x296F2452,
    )

    synthesized = _synthesize_missing_conditional_exit_sites(
        [template_site],
        region_states={0x10743C4C, 0x6107F8EC},
        semantic_successors_by_state={
            0x6107F8EC: ("STATE_474EEEBB", "STATE_296F2452"),
        },
        semantic_entry_by_label={
            "STATE_474EEEBB": 66,
            "STATE_296F2452": 202,
        },
    )

    assert len(synthesized) == 2
    synthesized_site = next(
        site for site in synthesized if site.semantic_target_label == "STATE_474EEEBB"
    )
    assert synthesized_site.edge.last_write_site is None
    assert hasattr(synthesized_site.edge.source_anchor, "kind")
    assert synthesized_site.edge.source_anchor.branch_arm == 0
    assert synthesized_site.edge.source_anchor.block_serial == 15
    assert synthesized_site.edge.source_key.state_const == 0x6107F8EC
    assert synthesized_site.target_entry_anchor == 66


def test_synthesize_missing_conditional_exit_sites_ignores_descendant_nonconditional_observation_for_missing_arm():
    source_key = _Key(0x6107F8EC)
    conditional_edge = SimpleNamespace(
        source_key=source_key,
        target_key=_Key(0x296F2452),
        target_state=0x296F2452,
        kind="conditional_transition",
        last_write_site=None,
        source_anchor=SimpleNamespace(block_serial=15, branch_arm=1),
        target_entry_anchor=202,
        target_label="STATE_296F2452",
        ordered_path=(15, 17),
    )
    descendant_edge = SimpleNamespace(
        source_key=source_key,
        target_key=_Key(0x474EEEBB),
        target_state=0x474EEEBB,
        kind="path_tail_redirect",
        last_write_site=None,
        source_anchor=SimpleNamespace(block_serial=15),
        target_entry_anchor=66,
        target_label="STATE_474EEEBB",
        ordered_path=(15, 66, 163),
    )
    sites = [
        SimpleNamespace(
            region_name="branch_region",
            site_kind="exit",
            source_state=0x6107F8EC,
            target_state=0x296F2452,
            source_entry_anchor=15,
            source_anchor_block=15,
            target_entry_anchor=202,
            ordered_path=(15, 17),
            edge=conditional_edge,
            semantic_target_label="STATE_296F2452",
            successor_state_value=0x296F2452,
        ),
        SimpleNamespace(
            region_name="branch_region",
            site_kind="exit",
            source_state=0x6107F8EC,
            target_state=0x474EEEBB,
            source_entry_anchor=15,
            source_anchor_block=15,
            target_entry_anchor=66,
            ordered_path=(15, 66, 163),
            edge=descendant_edge,
            semantic_target_label="STATE_474EEEBB",
            successor_state_value=0x474EEEBB,
        ),
    ]

    synthesized = _synthesize_missing_conditional_exit_sites(
        sites,
        region_states={0x10743C4C, 0x6107F8EC},
        semantic_successors_by_state={
            0x6107F8EC: ("STATE_474EEEBB", "STATE_296F2452"),
        },
        semantic_entry_by_label={
            "STATE_474EEEBB": 66,
            "STATE_296F2452": 202,
        },
    )

    branch_zero_sites = [
        site
        for site in synthesized
        if getattr(getattr(site.edge, "source_anchor", None), "branch_arm", None) == 0
        and site.semantic_target_label == "STATE_474EEEBB"
    ]
    assert len(branch_zero_sites) == 1
    assert branch_zero_sites[0].ordered_path == (15,)
    assert branch_zero_sites[0].target_entry_anchor == 66
    assert branch_zero_sites[0].edge.source_key.state_const == 0x6107F8EC
    assert branch_zero_sites[0].edge.source_anchor.block_serial == 15


def test_synthesize_missing_conditional_exit_sites_uses_observed_dag_branch_context_for_missing_source_sites():
    base_edge = _edge(
        source_state=0x10743C4C,
        target_state=0x6107F8EC,
        source_block=158,
        target_entry=136,
    )
    base_edge.target_label = "STATE_6107F8EC"
    base_site = SimpleNamespace(
        region_name="sub7ffd_10743c4c_branch_region",
        site_kind="internal",
        source_state=0x10743C4C,
        target_state=0x6107F8EC,
        source_entry_anchor=158,
        source_anchor_block=158,
        target_entry_anchor=136,
        ordered_path=(158,),
        edge=base_edge,
        semantic_target_label="STATE_6107F8EC",
        successor_state_value=0x6107F8EC,
    )
    fallthrough_edge = _edge(
        source_state=0x6107F8EC,
        target_state=0x4C77464F,
        source_block=15,
        target_entry=68,
    )
    fallthrough_edge.source_anchor.branch_arm = 0
    fallthrough_edge.target_label = "0x4C77464F"
    fallthrough_edge.ordered_path = (15, 16, 68, 230)
    taken_edge = _edge(
        source_state=0x6107F8EC,
        target_state=0x296F2452,
        source_block=15,
        target_entry=202,
    )
    taken_edge.source_anchor.branch_arm = 1
    taken_edge.target_label = "STATE_296F2452"
    taken_edge.ordered_path = (15, 17, 202, 224)

    synthesized = _synthesize_missing_conditional_exit_sites(
        [base_site],
        region_name="sub7ffd_10743c4c_branch_region",
        region_states={0x10743C4C, 0x6107F8EC},
        semantic_successors_by_state={
            0x6107F8EC: ("STATE_296F2452", "STATE_474EEEBB"),
        },
        semantic_entry_by_label={
            "STATE_474EEEBB": 66,
            "STATE_296F2452": 202,
        },
        semantic_reference_program=SimpleNamespace(
            nodes=(
                SimpleNamespace(
                    label_text="STATE_6107F8EC",
                    entry_anchor=136,
                    line_start=1,
                    line_end=3,
                ),
            ),
            lines=(),
        ),
        dag=SimpleNamespace(edges=(fallthrough_edge, taken_edge)),
        dispatcher_blocks={71},
    )

    by_branch_arm = {
        int(getattr(getattr(site.edge, "source_anchor", None), "branch_arm", -1)): site
        for site in synthesized
    }
    assert by_branch_arm[1].source_entry_anchor == 15
    assert by_branch_arm[1].source_anchor_block == 15
    assert by_branch_arm[1].ordered_path == (15, 17)
    assert by_branch_arm[1].target_entry_anchor == 202
    assert by_branch_arm[0].source_entry_anchor == 15
    assert by_branch_arm[0].source_anchor_block == 15
    assert by_branch_arm[0].ordered_path == (15, 16)
    assert by_branch_arm[0].target_entry_anchor == 66
    assert by_branch_arm[0].semantic_target_label == "STATE_474EEEBB"
    assert by_branch_arm[0].successor_state_value == 0x474EEEBB


def test_collect_admissible_region_lowering_sites_accepts_owned_interior_source_block():
    region = SimpleNamespace(
        region_name="region",
        state_values=(0x11111111, 0x22222222),
        internal_state_edges=((0x11111111, 0x22222222),),
        exit_state_values=(),
    )
    edge = _edge(
        source_state=0x11111111,
        target_state=0x22222222,
        source_block=140,
        target_entry=143,
    )
    dag = SimpleNamespace(edges=(edge,))
    node_by_key = {
        edge.source_key: SimpleNamespace(
            entry_anchor=136,
            exclusive_blocks=(136, 140, 141, 142),
        ),
    }

    sites = collect_admissible_region_lowering_sites(
        region=region,
        dag=dag,
        node_by_key=node_by_key,
        dispatcher_region={20},
    )

    assert len(sites) == 1
    assert sites[0].source_entry_anchor == 136
    assert sites[0].target_entry_anchor == 143


def test_collect_admissible_region_lowering_sites_rejects_dispatcher_owned_target():
    region = SimpleNamespace(
        region_name="region",
        state_values=(0x11111111, 0x22222222),
        internal_state_edges=((0x11111111, 0x22222222),),
        exit_state_values=(),
    )
    edge = _edge(
        source_state=0x11111111,
        target_state=0x22222222,
        source_block=78,
        target_entry=20,
    )
    dag = SimpleNamespace(edges=(edge,))
    node_by_key = {
        edge.source_key: SimpleNamespace(entry_anchor=78),
    }

    sites = collect_admissible_region_lowering_sites(
        region=region,
        dag=dag,
        node_by_key=node_by_key,
        dispatcher_region={20},
    )

    assert sites == ()


def test_collect_admissible_region_lowering_sites_normalizes_unmatched_alias_exit_to_semantic_fallback():
    region = SimpleNamespace(
        region_name="region",
        state_values=(0x6107F8EC,),
        internal_state_edges=(),
        exit_state_values=(0x296F2452, 0x474EEEBB),
    )
    matched_edge = _edge(
        source_state=0x6107F8EC,
        target_state=0x296F2452,
        source_block=13,
        target_entry=15,
    )
    alias_edge = _edge(
        source_state=0x6107F8EC,
        target_state=0x4C77464F,
        source_block=13,
        target_entry=20,
    )
    dag = SimpleNamespace(edges=(matched_edge, alias_edge))
    node_by_key = {
        matched_edge.source_key: SimpleNamespace(entry_anchor=13),
    }
    semantic_reference_program = SimpleNamespace(
        nodes=(
            SimpleNamespace(
                label_text="STATE_6107F8EC",
                entry_anchor=13,
                line_start=1,
                line_end=3,
            ),
            SimpleNamespace(
                label_text="STATE_296F2452",
                entry_anchor=15,
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

    sites = collect_admissible_region_lowering_sites(
        region=region,
        dag=dag,
        node_by_key=node_by_key,
        dispatcher_region={20},
        semantic_reference_program=semantic_reference_program,
    )

    assert len(sites) == 2
    matched = next(site for site in sites if site.target_state == 0x296F2452)
    alias = next(site for site in sites if site.target_state == 0x474EEEBB)
    assert matched.target_entry_anchor == 15
    assert matched.successor_state_value == 0x296F2452
    assert alias.target_entry_anchor == 14
    assert alias.semantic_target_label == "STATE_474EEEBB_fallback"
    assert alias.successor_state_value == 0x474EEEBB
    assert alias.edge.target_state == 0x474EEEBB
    assert alias.edge.target_entry_anchor == 14
    assert alias.edge.target_label == "STATE_474EEEBB_fallback"


def test_collect_admissible_region_lowering_sites_normalizes_raw_exit_value_when_semantic_successor_differs():
    region = SimpleNamespace(
        region_name="region",
        state_values=(0x6107F8EC,),
        internal_state_edges=(),
        exit_state_values=(0x296F2452, 0x474EEEBB),
    )
    matched_edge = _edge(
        source_state=0x6107F8EC,
        target_state=0x296F2452,
        source_block=13,
        target_entry=15,
    )
    alias_edge = _edge(
        source_state=0x6107F8EC,
        target_state=0x4C77464F,
        source_block=13,
        target_entry=66,
    )
    dag = SimpleNamespace(edges=(matched_edge, alias_edge))
    node_by_key = {
        matched_edge.source_key: SimpleNamespace(entry_anchor=13),
    }
    semantic_reference_program = SimpleNamespace(
        nodes=(
            SimpleNamespace(
                label_text="STATE_6107F8EC",
                entry_anchor=13,
                line_start=1,
                line_end=3,
            ),
            SimpleNamespace(
                label_text="STATE_296F2452",
                entry_anchor=15,
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

    sites = collect_admissible_region_lowering_sites(
        region=region,
        dag=dag,
        node_by_key=node_by_key,
        dispatcher_region={66},
        semantic_reference_program=semantic_reference_program,
    )

    assert len(sites) == 2
    matched = next(site for site in sites if site.target_state == 0x296F2452)
    alias = next(site for site in sites if site.target_state == 0x474EEEBB)
    assert matched.target_entry_anchor == 15
    assert matched.successor_state_value == 0x296F2452
    assert alias.target_entry_anchor == 14
    assert alias.semantic_target_label == "STATE_474EEEBB_fallback"
    assert alias.successor_state_value == 0x474EEEBB
    assert alias.edge.target_state == 0x474EEEBB
    assert alias.edge.target_entry_anchor == 14
    assert alias.edge.target_label == "STATE_474EEEBB_fallback"


def test_collect_admissible_region_lowering_sites_normalizes_multiple_alias_exits_to_single_semantic_successor():
    region = SimpleNamespace(
        region_name="region",
        state_values=(0x11CD1DA3,),
        internal_state_edges=(),
        exit_state_values=(0x4E69F350,),
    )
    alias_edge_a = _edge(
        source_state=0x11CD1DA3,
        target_state=0x6E958F99,
        source_block=163,
        target_entry=47,
    )
    alias_edge_b = _edge(
        source_state=0x11CD1DA3,
        target_state=0x6E958F99,
        source_block=164,
        target_entry=47,
    )
    dag = SimpleNamespace(edges=(alias_edge_a, alias_edge_b))
    node_by_key = {
        alias_edge_a.source_key: SimpleNamespace(
            entry_anchor=161,
            owned_blocks=(163, 164),
        ),
    }
    semantic_reference_program = SimpleNamespace(
        nodes=(
            SimpleNamespace(
                label_text="STATE_11CD1DA3",
                entry_anchor=161,
                line_start=1,
                line_end=4,
            ),
            SimpleNamespace(
                label_text="STATE_4E69F350",
                entry_anchor=72,
                line_start=5,
                line_end=5,
            ),
        ),
        lines=(
            SimpleNamespace(line_no=1, target_label=None),
            SimpleNamespace(line_no=2, target_label=None),
            SimpleNamespace(line_no=3, target_label="STATE_4E69F350"),
            SimpleNamespace(line_no=4, target_label=None),
            SimpleNamespace(line_no=5, target_label=None),
        ),
    )

    sites = collect_admissible_region_lowering_sites(
        region=region,
        dag=dag,
        node_by_key=node_by_key,
        dispatcher_region={47},
        semantic_reference_program=semantic_reference_program,
    )

    assert len(sites) == 2
    assert {site.target_entry_anchor for site in sites} == {72}
    assert {site.semantic_target_label for site in sites} == {"STATE_4E69F350"}
    assert {site.successor_state_value for site in sites} == {0x4E69F350}


def test_collect_admissible_region_lowering_sites_accepts_alias_exit_from_local_segment_block():
    region = SimpleNamespace(
        region_name="region",
        state_values=(0x11CD1DA3,),
        internal_state_edges=(),
        exit_state_values=(0x4E69F350,),
    )
    alias_edge = _edge(
        source_state=0x11CD1DA3,
        target_state=0x6E958F99,
        source_block=163,
        target_entry=47,
    )
    dag = SimpleNamespace(edges=(alias_edge,))
    node_by_key = {
        alias_edge.source_key: SimpleNamespace(
            entry_anchor=161,
            local_segments=(SimpleNamespace(blocks=(163, 164)),),
        ),
    }
    semantic_reference_program = SimpleNamespace(
        nodes=(
            SimpleNamespace(
                label_text="STATE_11CD1DA3",
                entry_anchor=161,
                line_start=1,
                line_end=3,
            ),
            SimpleNamespace(
                label_text="STATE_4E69F350",
                entry_anchor=72,
                line_start=4,
                line_end=4,
            ),
        ),
        lines=(
            SimpleNamespace(line_no=1, target_label=None),
            SimpleNamespace(line_no=2, target_label="STATE_4E69F350"),
            SimpleNamespace(line_no=3, target_label=None),
            SimpleNamespace(line_no=4, target_label=None),
        ),
    )

    sites = collect_admissible_region_lowering_sites(
        region=region,
        dag=dag,
        node_by_key=node_by_key,
        dispatcher_region={47},
        semantic_reference_program=semantic_reference_program,
    )

    assert len(sites) == 1
    assert sites[0].target_entry_anchor == 72
    assert sites[0].semantic_target_label == "STATE_4E69F350"
    assert sites[0].successor_state_value == 0x4E69F350


def test_collect_admissible_region_lowering_sites_synthesizes_missing_conditional_exit_sibling():
    region = SimpleNamespace(
        region_name="region",
        state_values=(0x6107F8EC,),
        internal_state_edges=(),
        exit_state_values=(0x296F2452, 0x474EEEBB),
    )
    direct_edge = _edge(
        source_state=0x6107F8EC,
        target_state=0x296F2452,
        source_block=15,
        target_entry=202,
    )
    direct_edge.source_anchor.branch_arm = 1
    direct_edge.ordered_path = (15, 17)
    dag = SimpleNamespace(edges=(direct_edge,))
    node_by_key = {
        direct_edge.source_key: SimpleNamespace(
            entry_anchor=15,
            exclusive_blocks=(15,),
            owned_blocks=(15, 16, 17),
        ),
    }
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
                label_text="STATE_474EEEBB",
                entry_anchor=66,
                line_start=5,
                line_end=5,
            ),
        ),
        lines=(
            SimpleNamespace(line_no=1, target_label=None),
            SimpleNamespace(line_no=2, target_label="STATE_296F2452"),
            SimpleNamespace(line_no=3, target_label="STATE_474EEEBB"),
            SimpleNamespace(line_no=4, target_label=None),
            SimpleNamespace(line_no=5, target_label=None),
        ),
    )

    sites = collect_admissible_region_lowering_sites(
        region=region,
        dag=dag,
        node_by_key=node_by_key,
        dispatcher_region={71},
        semantic_reference_program=semantic_reference_program,
    )

    assert len(sites) == 2
    by_successor = {
        int(site.successor_state_value): site
        for site in sites
        if site.successor_state_value is not None
    }
    assert by_successor[0x296F2452].target_entry_anchor == 202
    assert by_successor[0x474EEEBB].target_entry_anchor == 66
    assert by_successor[0x474EEEBB].semantic_target_label == "STATE_474EEEBB"
    assert int(by_successor[0x474EEEBB].edge.source_anchor.branch_arm) == 0


def test_merge_region_contract_semantic_successors_prefers_immediate_region_contract():
    region = SimpleNamespace(
        region_name="sub7ffd_10743c4c_branch_region",
        state_values=(0x10743C4C, 0x6107F8EC),
        internal_state_edges=((0x10743C4C, 0x6107F8EC),),
        exit_state_values=(0x474EEEBB, 0x296F2452),
    )
    merged = _merge_region_contract_semantic_successors_by_state(
        region=region,
        semantic_successors_by_state={
            0x10743C4C: ("STATE_6107F8EC", "STATE_606DC166"),
            0x6107F8EC: ("STATE_296F2452", "STATE_474EEEBB", "STATE_139F2922"),
        },
        semantic_entry_by_label={
            "STATE_6107F8EC": 15,
            "STATE_296F2452": 202,
            "STATE_474EEEBB": 66,
            "STATE_606DC166": 14,
            "STATE_139F2922": 220,
        },
    )

    assert merged[0x10743C4C] == ("STATE_6107F8EC",)
    assert merged[0x6107F8EC] == ("STATE_296F2452", "STATE_474EEEBB")


def test_merge_region_contract_semantic_successors_does_not_widen_local_semantic_successors_with_descendant_exit_states():
    region = SimpleNamespace(
        region_name="sub7ffd_10743c4c_branch_region",
        state_values=(0x6107F8EC,),
        internal_state_edges=(),
        exit_state_values=(0x474EEEBB, 0x296F2452, 0x0ACD0BD5, 0x139F2922),
    )
    merged = _merge_region_contract_semantic_successors_by_state(
        region=region,
        semantic_successors_by_state={
            0x6107F8EC: ("STATE_296F2452", "STATE_474EEEBB"),
        },
        semantic_entry_by_label={
            "STATE_296F2452": 202,
            "STATE_474EEEBB": 66,
            "STATE_0ACD0BD5": 131,
            "STATE_139F2922": 220,
        },
    )

    assert merged[0x6107F8EC] == ("STATE_296F2452", "STATE_474EEEBB")


def test_merge_region_contract_semantic_successors_preserves_leaf_rendered_branch_targets_when_region_contract_is_lossy():
    region = SimpleNamespace(
        region_name="sub7ffd_10743c4c_branch_region",
        state_values=(0x6107F8EC,),
        internal_state_edges=(),
        exit_state_values=(0x296F2452,),
    )
    merged = _merge_region_contract_semantic_successors_by_state(
        region=region,
        semantic_successors_by_state={
            0x6107F8EC: ("STATE_296F2452", "STATE_474EEEBB"),
        },
        semantic_entry_by_label={
            "STATE_296F2452": 202,
            "STATE_474EEEBB": 66,
        },
    )

    assert merged[0x6107F8EC] == ("STATE_296F2452", "STATE_474EEEBB")


def test_collect_admissible_region_lowering_sites_uses_region_contract_when_projected_source_semantics_are_missing():
    region = SimpleNamespace(
        region_name="branch_region",
        state_values=(0x4E69F350, 0x10743C4C, 0x6107F8EC),
        internal_state_edges=(
            (0x4E69F350, 0x10743C4C),
            (0x10743C4C, 0x6107F8EC),
        ),
        exit_state_values=(0x296F2452, 0x474EEEBB),
    )
    matched_edge = _edge(
        source_state=0x6107F8EC,
        target_state=0x296F2452,
        source_block=15,
        target_entry=202,
    )
    matched_edge.source_anchor.branch_arm = 1
    matched_edge.ordered_path = (15, 17)
    alias_edge = _edge(
        source_state=0x6107F8EC,
        target_state=0x4C77464F,
        source_block=15,
        target_entry=66,
    )
    alias_edge.source_anchor.branch_arm = 0
    alias_edge.target_label = "0x4C77464F"
    alias_edge.ordered_path = (15, 16)
    dag = SimpleNamespace(edges=(matched_edge, alias_edge))
    node_by_key = {
        matched_edge.source_key: SimpleNamespace(
            entry_anchor=15,
            exclusive_blocks=(15,),
            owned_blocks=(15, 16, 17),
        ),
    }
    semantic_reference_program = SimpleNamespace(
        nodes=(
            SimpleNamespace(
                label_text="STATE_296F2452",
                entry_anchor=202,
                line_start=1,
                line_end=1,
            ),
            SimpleNamespace(
                label_text="STATE_474EEEBB",
                entry_anchor=66,
                line_start=2,
                line_end=2,
            ),
        ),
        lines=(
            SimpleNamespace(line_no=1, target_label=None),
            SimpleNamespace(line_no=2, target_label=None),
        ),
    )

    sites = collect_admissible_region_lowering_sites(
        region=region,
        dag=dag,
        node_by_key=node_by_key,
        dispatcher_region={71},
        semantic_reference_program=semantic_reference_program,
    )

    assert len(sites) == 2
    by_successor = {
        int(site.successor_state_value): site
        for site in sites
        if site.successor_state_value is not None
    }
    assert by_successor[0x296F2452].target_entry_anchor == 202
    assert by_successor[0x474EEEBB].target_entry_anchor == 66
    assert by_successor[0x474EEEBB].semantic_target_label == "STATE_474EEEBB"


def test_collect_admissible_region_lowering_sites_uses_region_contract_when_semantic_node_span_contains_descendants():
    region = SimpleNamespace(
        region_name="sub7ffd_10743c4c_branch_region",
        state_values=(0x10743C4C, 0x6107F8EC),
        internal_state_edges=((0x10743C4C, 0x6107F8EC),),
        exit_state_values=(0x296F2452, 0x474EEEBB),
    )
    matched_edge = _edge(
        source_state=0x6107F8EC,
        target_state=0x296F2452,
        source_block=15,
        target_entry=202,
    )
    matched_edge.source_anchor.branch_arm = 1
    matched_edge.ordered_path = (15, 17)
    alias_edge = _edge(
        source_state=0x6107F8EC,
        target_state=0x4C77464F,
        source_block=15,
        target_entry=66,
    )
    alias_edge.source_anchor.branch_arm = 0
    alias_edge.target_label = "0x4C77464F"
    alias_edge.ordered_path = (15, 16, 68)
    dag = SimpleNamespace(edges=(matched_edge, alias_edge))
    node_by_key = {
        matched_edge.source_key: SimpleNamespace(
            entry_anchor=15,
            exclusive_blocks=(15,),
            owned_blocks=(15, 16, 17),
        ),
    }
    semantic_reference_program = SimpleNamespace(
        nodes=(
            SimpleNamespace(
                label_text="STATE_10743C4C",
                entry_anchor=158,
                line_start=1,
                line_end=1,
            ),
            SimpleNamespace(
                label_text="STATE_6107F8EC",
                entry_anchor=15,
                line_start=2,
                line_end=6,
            ),
            SimpleNamespace(
                label_text="STATE_296F2452",
                entry_anchor=202,
                line_start=7,
                line_end=7,
            ),
            SimpleNamespace(
                label_text="STATE_474EEEBB",
                entry_anchor=66,
                line_start=8,
                line_end=8,
            ),
            SimpleNamespace(
                label_text="STATE_139F2922",
                entry_anchor=220,
                line_start=9,
                line_end=9,
            ),
        ),
        lines=(
            SimpleNamespace(line_no=1, target_label="STATE_6107F8EC"),
            SimpleNamespace(line_no=2, target_label=None),
            SimpleNamespace(line_no=3, target_label="STATE_296F2452"),
            SimpleNamespace(line_no=4, target_label="STATE_474EEEBB"),
            SimpleNamespace(line_no=5, target_label="STATE_139F2922"),
            SimpleNamespace(line_no=6, target_label="STATE_139F2922"),
            SimpleNamespace(line_no=7, target_label=None),
            SimpleNamespace(line_no=8, target_label=None),
            SimpleNamespace(line_no=9, target_label=None),
        ),
    )

    sites = collect_admissible_region_lowering_sites(
        region=region,
        dag=dag,
        node_by_key=node_by_key,
        dispatcher_region={71},
        semantic_reference_program=semantic_reference_program,
    )

    by_successor = {
        int(site.successor_state_value): site
        for site in sites
        if site.source_state == 0x6107F8EC
        and site.successor_state_value is not None
    }
    assert by_successor[0x296F2452].target_entry_anchor == 202
    assert by_successor[0x296F2452].semantic_target_label == "STATE_296F2452"
    assert by_successor[0x474EEEBB].target_entry_anchor == 66


def test_collect_admissible_region_lowering_sites_defers_descendant_internal_sites_outside_region_contract():
    region = SimpleNamespace(
        region_name="sub7ffd_10743c4c_branch_region",
        state_values=(
            0x4E69F350,
            0x2A5ADB57,
            0x1AB9946F,
            0x7C2C0220,
            0x10743C4C,
            0x6107F8EC,
        ),
        internal_state_edges=(
            (0x10743C4C, 0x6107F8EC),
            (0x4E69F350, 0x2A5ADB57),
            (0x2A5ADB57, 0x1AB9946F),
            (0x1AB9946F, 0x7C2C0220),
        ),
        exit_state_values=(0x296F2452, 0x474EEEBB),
    )
    root_edge = _edge(
        source_state=0x10743C4C,
        target_state=0x6107F8EC,
        source_block=158,
        target_entry=136,
    )
    descendant_edges = (
        _edge(
            source_state=0x4E69F350,
            target_state=0x2A5ADB57,
            source_block=72,
            target_entry=177,
        ),
        _edge(
            source_state=0x2A5ADB57,
            target_state=0x1AB9946F,
            source_block=177,
            target_entry=214,
        ),
        _edge(
            source_state=0x1AB9946F,
            target_state=0x7C2C0220,
            source_block=214,
            target_entry=54,
        ),
    )
    dag = SimpleNamespace(edges=(root_edge, *descendant_edges))
    node_by_key = {
        root_edge.source_key: SimpleNamespace(entry_anchor=158, exclusive_blocks=(158,)),
        descendant_edges[0].source_key: SimpleNamespace(entry_anchor=72, exclusive_blocks=(72,)),
        descendant_edges[1].source_key: SimpleNamespace(entry_anchor=177, exclusive_blocks=(177,)),
        descendant_edges[2].source_key: SimpleNamespace(entry_anchor=214, exclusive_blocks=(214,)),
    }
    semantic_reference_program = SimpleNamespace(
        nodes=(
            SimpleNamespace(
                label_text="STATE_10743C4C",
                entry_anchor=158,
                line_start=1,
                line_end=1,
            ),
            SimpleNamespace(
                label_text="STATE_6107F8EC",
                entry_anchor=136,
                line_start=2,
                line_end=4,
            ),
            SimpleNamespace(
                label_text="STATE_296F2452",
                entry_anchor=202,
                line_start=5,
                line_end=5,
            ),
            SimpleNamespace(
                label_text="STATE_474EEEBB",
                entry_anchor=66,
                line_start=6,
                line_end=6,
            ),
        ),
        lines=(
            SimpleNamespace(line_no=1, target_label="STATE_6107F8EC"),
            SimpleNamespace(line_no=2, target_label=None),
            SimpleNamespace(line_no=3, target_label="STATE_296F2452"),
            SimpleNamespace(line_no=4, target_label="STATE_474EEEBB"),
            SimpleNamespace(line_no=5, target_label=None),
            SimpleNamespace(line_no=6, target_label=None),
        ),
    )

    sites = collect_admissible_region_lowering_sites(
        region=region,
        dag=dag,
        node_by_key=node_by_key,
        dispatcher_region={71},
        semantic_reference_program=semantic_reference_program,
    )

    assert {
        (site.source_state, site.target_state)
        for site in sites
        if site.site_kind == "internal"
    } == {
        (0x10743C4C, 0x6107F8EC),
    }


def test_collect_admissible_region_lowering_sites_prefers_observed_branch_arm_mapping_over_label_order():
    region = SimpleNamespace(
        region_name="sub7ffd_10743c4c_branch_region",
        state_values=(0x6107F8EC,),
        internal_state_edges=(),
        exit_state_values=(0x474EEEBB, 0x296F2452),
    )
    matched_edge = _edge(
        source_state=0x6107F8EC,
        target_state=0x296F2452,
        source_block=15,
        target_entry=202,
    )
    matched_edge.source_anchor.branch_arm = 1
    matched_edge.ordered_path = (15, 17)
    alias_edge = _edge(
        source_state=0x6107F8EC,
        target_state=0x4C77464F,
        source_block=15,
        target_entry=66,
    )
    alias_edge.source_anchor.branch_arm = 0
    alias_edge.target_label = "0x4C77464F"
    alias_edge.ordered_path = (15, 16, 68)
    dag = SimpleNamespace(edges=(matched_edge, alias_edge))
    node_by_key = {
        matched_edge.source_key: SimpleNamespace(
            entry_anchor=15,
            exclusive_blocks=(15,),
            owned_blocks=(15, 16, 17),
        ),
    }
    semantic_reference_program = SimpleNamespace(
        nodes=(
            SimpleNamespace(
                label_text="STATE_6107F8EC",
                entry_anchor=15,
                line_start=1,
                line_end=4,
            ),
            SimpleNamespace(
                label_text="STATE_474EEEBB",
                entry_anchor=66,
                line_start=5,
                line_end=5,
            ),
            SimpleNamespace(
                label_text="STATE_296F2452",
                entry_anchor=202,
                line_start=6,
                line_end=6,
            ),
        ),
        lines=(
            SimpleNamespace(line_no=1, target_label=None),
            # Reversed order in the rendered node should not defeat branch-arm truth.
            SimpleNamespace(line_no=2, target_label="STATE_474EEEBB"),
            SimpleNamespace(line_no=3, target_label="STATE_296F2452"),
            SimpleNamespace(line_no=4, target_label="STATE_139F2922"),
            SimpleNamespace(line_no=5, target_label=None),
            SimpleNamespace(line_no=6, target_label=None),
        ),
    )

    sites = collect_admissible_region_lowering_sites(
        region=region,
        dag=dag,
        node_by_key=node_by_key,
        dispatcher_region={71},
        semantic_reference_program=semantic_reference_program,
    )

    by_successor = {
        int(site.successor_state_value): site
        for site in sites
        if site.successor_state_value is not None
    }
    assert by_successor[0x296F2452].target_entry_anchor == 202
    assert by_successor[0x296F2452].semantic_target_label == "STATE_296F2452"
    assert int(by_successor[0x296F2452].edge.source_anchor.branch_arm) == 1
    assert by_successor[0x474EEEBB].target_entry_anchor == 66
    assert by_successor[0x474EEEBB].semantic_target_label == "STATE_474EEEBB"
    assert int(by_successor[0x474EEEBB].edge.source_anchor.branch_arm) == 0


def test_collect_admissible_region_lowering_sites_discards_duplicate_observed_branch_labels_from_descendants():
    region = SimpleNamespace(
        region_name="sub7ffd_10743c4c_branch_region",
        state_values=(0x6107F8EC,),
        internal_state_edges=(),
        exit_state_values=(0x474EEEBB, 0x296F2452),
    )
    polluted_fallthrough = _edge(
        source_state=0x6107F8EC,
        target_state=0x12ACFB20,
        source_block=15,
        target_entry=202,
    )
    polluted_fallthrough.source_anchor.branch_arm = 0
    polluted_fallthrough.target_label = "STATE_296F2452"
    polluted_fallthrough.ordered_path = (15, 16, 68, 230)
    polluted_taken = _edge(
        source_state=0x6107F8EC,
        target_state=0x2981423A,
        source_block=15,
        target_entry=202,
    )
    polluted_taken.source_anchor.branch_arm = 1
    polluted_taken.target_label = "STATE_296F2452"
    polluted_taken.ordered_path = (15, 17, 202, 224, 149)
    dag = SimpleNamespace(edges=(polluted_fallthrough, polluted_taken))
    node_by_key = {
        polluted_fallthrough.source_key: SimpleNamespace(
            entry_anchor=15,
            exclusive_blocks=(15,),
            owned_blocks=(15, 16, 17),
        ),
    }
    semantic_reference_program = SimpleNamespace(
        nodes=(
            SimpleNamespace(
                label_text="STATE_6107F8EC",
                entry_anchor=15,
                line_start=1,
                line_end=4,
            ),
            SimpleNamespace(
                label_text="STATE_296F2452",
                entry_anchor=202,
                line_start=5,
                line_end=5,
            ),
            SimpleNamespace(
                label_text="STATE_474EEEBB",
                entry_anchor=66,
                line_start=6,
                line_end=6,
            ),
        ),
        lines=(
            SimpleNamespace(line_no=1, target_label=None),
            SimpleNamespace(line_no=2, target_label="STATE_296F2452"),
            SimpleNamespace(line_no=3, target_label="STATE_474EEEBB"),
            SimpleNamespace(line_no=4, target_label="STATE_139F2922"),
            SimpleNamespace(line_no=5, target_label=None),
            SimpleNamespace(line_no=6, target_label=None),
        ),
    )

    sites = collect_admissible_region_lowering_sites(
        region=region,
        dag=dag,
        node_by_key=node_by_key,
        dispatcher_region={71},
        semantic_reference_program=semantic_reference_program,
    )

    by_branch_arm = {
        int(getattr(getattr(site.edge, "source_anchor", None), "branch_arm", -1)): site
        for site in sites
        if site.successor_state_value is not None
    }
    assert by_branch_arm[1].successor_state_value == 0x296F2452
    assert by_branch_arm[1].target_entry_anchor == 202
    assert by_branch_arm[0].successor_state_value == 0x474EEEBB
    assert by_branch_arm[0].target_entry_anchor == 66


def test_collect_admissible_region_lowering_sites_uses_exit_alias_contract_when_local_semantic_span_loses_child_label():
    region = SimpleNamespace(
        region_name="sub7ffd_10743c4c_branch_region",
        state_values=(0x6107F8EC,),
        internal_state_edges=(),
        exit_state_values=(0x4C77464F, 0x296F2452),
    )
    polluted_fallthrough = _edge(
        source_state=0x6107F8EC,
        target_state=0x12ACFB20,
        source_block=15,
        target_entry=202,
    )
    polluted_fallthrough.source_anchor.branch_arm = 0
    polluted_fallthrough.target_label = "STATE_296F2452"
    polluted_fallthrough.ordered_path = (15, 16, 68, 230)
    polluted_taken = _edge(
        source_state=0x6107F8EC,
        target_state=0x2981423A,
        source_block=15,
        target_entry=202,
    )
    polluted_taken.source_anchor.branch_arm = 1
    polluted_taken.target_label = "STATE_296F2452"
    polluted_taken.ordered_path = (15, 17, 202, 224, 149)
    dag = SimpleNamespace(
        edges=(polluted_fallthrough, polluted_taken),
        nodes=(
            SimpleNamespace(
                key=_Key(0x474EEEBB),
                kind=StateNodeKind.EXACT,
                state_label="STATE_474EEEBB",
                entry_anchor=66,
                exclusive_blocks=(68,),
                owned_blocks=(66, 67, 68, 69),
                local_segments=(),
                shared_suffix_blocks=(),
            ),
            SimpleNamespace(
                key=_Key(0x296F2452),
                kind=StateNodeKind.EXACT,
                state_label="STATE_296F2452",
                entry_anchor=202,
                exclusive_blocks=(202,),
                owned_blocks=(202,),
                local_segments=(),
                shared_suffix_blocks=(),
            ),
        ),
        supplemental_selected_entries=((0x4C77464F, 68),),
    )
    node_by_key = {
        polluted_fallthrough.source_key: SimpleNamespace(
            entry_anchor=15,
            exclusive_blocks=(15,),
            owned_blocks=(15, 16, 17),
        ),
    }
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
                label_text="STATE_474EEEBB",
                entry_anchor=66,
                line_start=5,
                line_end=5,
            ),
        ),
        lines=(
            SimpleNamespace(line_no=1, target_label=None),
            SimpleNamespace(line_no=2, target_label="STATE_296F2452"),
            SimpleNamespace(line_no=3, target_label="STATE_139F2922"),
            SimpleNamespace(line_no=4, target_label=None),
            SimpleNamespace(line_no=5, target_label=None),
        ),
    )

    sites = collect_admissible_region_lowering_sites(
        region=region,
        dag=dag,
        node_by_key=node_by_key,
        dispatcher_region={71},
        semantic_reference_program=semantic_reference_program,
    )

    by_branch_arm = {
        int(getattr(getattr(site.edge, "source_anchor", None), "branch_arm", -1)): site
        for site in sites
        if site.successor_state_value is not None
    }
    assert by_branch_arm[1].successor_state_value == 0x296F2452
    assert by_branch_arm[1].target_entry_anchor == 202
    assert by_branch_arm[0].successor_state_value == 0x474EEEBB
    assert by_branch_arm[0].target_entry_anchor == 66
    assert by_branch_arm[0].semantic_target_label == "STATE_474EEEBB"
    assert by_branch_arm[0].edge.target_state == 0x474EEEBB
    assert by_branch_arm[0].edge.target_entry_anchor == 66
    assert by_branch_arm[0].edge.target_label == "STATE_474EEEBB"


def test_collect_admissible_region_lowering_sites_synthesizes_missing_branch_arm_from_multiple_same_arm_descendants():
    region = SimpleNamespace(
        region_name="sub7ffd_10743c4c_branch_region",
        state_values=(0x6107F8EC,),
        internal_state_edges=(),
        exit_state_values=(0x296F2452, 0x474EEEBB),
    )
    taken_a = _edge(
        source_state=0x6107F8EC,
        target_state=0x41B585C8,
        source_block=15,
        target_entry=202,
    )
    taken_a.source_anchor.branch_arm = 1
    taken_a.target_label = "STATE_296F2452"
    taken_a.ordered_path = (15, 17, 202, 224, 147, 149)
    taken_b = _edge(
        source_state=0x6107F8EC,
        target_state=0x7FDCE054,
        source_block=15,
        target_entry=202,
    )
    taken_b.source_anchor.branch_arm = 1
    taken_b.target_label = "STATE_296F2452"
    taken_b.ordered_path = (15, 17, 202, 35)
    dag = SimpleNamespace(edges=(taken_a, taken_b))
    node_by_key = {
        taken_a.source_key: SimpleNamespace(
            entry_anchor=15,
            exclusive_blocks=(15,),
            owned_blocks=(15, 16, 17),
        ),
    }
    semantic_reference_program = SimpleNamespace(
        nodes=(
            SimpleNamespace(
                label_text="STATE_6107F8EC",
                entry_anchor=15,
                line_start=1,
                line_end=4,
            ),
            SimpleNamespace(
                label_text="STATE_296F2452",
                entry_anchor=202,
                line_start=5,
                line_end=5,
            ),
            SimpleNamespace(
                label_text="STATE_474EEEBB",
                entry_anchor=66,
                line_start=6,
                line_end=6,
            ),
        ),
        lines=(
            SimpleNamespace(line_no=1, target_label=None),
            SimpleNamespace(line_no=2, target_label="STATE_296F2452"),
            SimpleNamespace(line_no=3, target_label="STATE_474EEEBB"),
            SimpleNamespace(line_no=4, target_label="STATE_139F2922"),
            SimpleNamespace(line_no=5, target_label=None),
            SimpleNamespace(line_no=6, target_label=None),
        ),
    )

    sites = collect_admissible_region_lowering_sites(
        region=region,
        dag=dag,
        node_by_key=node_by_key,
        dispatcher_region={71},
        semantic_reference_program=semantic_reference_program,
    )

    by_branch_arm = {
        int(getattr(getattr(site.edge, "source_anchor", None), "branch_arm", -1)): site
        for site in sites
        if site.successor_state_value is not None
    }
    assert by_branch_arm[1].successor_state_value == 0x296F2452
    assert by_branch_arm[1].semantic_target_label == "STATE_296F2452"
    assert by_branch_arm[0].successor_state_value == 0x474EEEBB
    assert by_branch_arm[0].semantic_target_label == "STATE_474EEEBB"
    assert by_branch_arm[0].target_entry_anchor == 66
    assert by_branch_arm[0].edge.target_state == 0x474EEEBB
    assert by_branch_arm[0].edge.target_entry_anchor == 66
    assert by_branch_arm[0].edge.target_label == "STATE_474EEEBB"


def test_collect_admissible_region_lowering_sites_remaps_mislabeled_internal_sites_to_semantic_successors():
    region = SimpleNamespace(
        region_name="branch_region",
        state_values=(0x10743C4C, 0x6107F8EC),
        internal_state_edges=((0x10743C4C, 0x6107F8EC),),
        exit_state_values=(0x296F2452, 0x474EEEBB),
    )
    direct_edge = _edge(
        source_state=0x10743C4C,
        target_state=0x6107F8EC,
        source_block=158,
        target_entry=136,
    )
    direct_edge.target_label = "STATE_6107F8EC"
    alias_edge = _edge(
        source_state=0x6107F8EC,
        target_state=0x4C77464F,
        source_block=15,
        target_entry=72,
    )
    alias_edge.source_anchor.branch_arm = 0
    alias_edge.target_label = "0x4C77464F"
    alias_edge.ordered_path = (15, 16, 68, 232, 163, 165)
    dag = SimpleNamespace(
        edges=(direct_edge, alias_edge),
    )
    node_by_key = {
        direct_edge.source_key: SimpleNamespace(
            entry_anchor=158,
            exclusive_blocks=(158,),
            owned_blocks=(158,),
        ),
        alias_edge.source_key: SimpleNamespace(
            entry_anchor=15,
            exclusive_blocks=(15,),
            owned_blocks=(15, 16),
        ),
    }
    semantic_reference_program = SimpleNamespace(
        nodes=(
            SimpleNamespace(
                label_text="STATE_10743C4C",
                entry_anchor=158,
                line_start=1,
                line_end=1,
            ),
            SimpleNamespace(
                label_text="STATE_6107F8EC",
                entry_anchor=15,
                line_start=2,
                line_end=3,
            ),
            SimpleNamespace(
                label_text="STATE_296F2452",
                entry_anchor=202,
                line_start=4,
                line_end=4,
            ),
            SimpleNamespace(
                label_text="STATE_474EEEBB",
                entry_anchor=68,
                line_start=5,
                line_end=5,
            ),
        ),
        lines=(
            SimpleNamespace(line_no=1, target_label="STATE_6107F8EC"),
            SimpleNamespace(line_no=2, target_label="STATE_296F2452"),
            SimpleNamespace(line_no=3, target_label="STATE_474EEEBB"),
            SimpleNamespace(line_no=4, target_label=None),
            SimpleNamespace(line_no=5, target_label=None),
        ),
    )

    sites = collect_admissible_region_lowering_sites(
        region=region,
        dag=dag,
        node_by_key=node_by_key,
        dispatcher_region={71},
        semantic_reference_program=semantic_reference_program,
    )

    by_source = {
        int(site.source_state) & 0xFFFFFFFF: site
        for site in sites
    }
    assert by_source[0x10743C4C].semantic_target_label == "STATE_6107F8EC"
    assert by_source[0x10743C4C].successor_state_value == 0x6107F8EC
    assert by_source[0x10743C4C].target_entry_anchor == 15
    assert by_source[0x6107F8EC].semantic_target_label == "STATE_474EEEBB"
    assert by_source[0x6107F8EC].successor_state_value == 0x474EEEBB
    assert by_source[0x6107F8EC].target_entry_anchor == 68
    assert by_source[0x6107F8EC].edge.target_state == 0x474EEEBB
    assert by_source[0x6107F8EC].edge.target_entry_anchor == 68
    assert by_source[0x6107F8EC].edge.target_label == "STATE_474EEEBB"


def test_collect_admissible_region_lowering_sites_synthesizes_missing_branch_exit_sites_from_semantic_contract():
    region = SimpleNamespace(
        region_name="branch_region",
        state_values=(0x10743C4C, 0x6107F8EC),
        internal_state_edges=((0x10743C4C, 0x6107F8EC),),
        exit_state_values=(0x4C77464F, 0x296F2452),
    )
    direct_edge = _edge(
        source_state=0x10743C4C,
        target_state=0x6107F8EC,
        source_block=158,
        target_entry=15,
    )
    direct_edge.target_label = "STATE_6107F8EC"
    dag = SimpleNamespace(
        edges=(direct_edge,),
        nodes=(
            SimpleNamespace(
                key=_Key(0x4C77464F),
                kind=StateNodeKind.EXACT,
                state_label="0x4C77464F",
                entry_anchor=66,
                exclusive_blocks=(66,),
                owned_blocks=(66, 68),
                local_segments=(),
                shared_suffix_blocks=(),
            ),
            SimpleNamespace(
                key=_Key(0x474EEEBB),
                kind=StateNodeKind.EXACT,
                state_label="STATE_474EEEBB",
                entry_anchor=68,
                exclusive_blocks=(68,),
                owned_blocks=(68, 69),
                local_segments=(),
                shared_suffix_blocks=(),
            ),
            SimpleNamespace(
                key=_Key(0x6107F8EC),
                kind=StateNodeKind.EXACT,
                state_label="STATE_6107F8EC",
                entry_anchor=15,
                exclusive_blocks=(15,),
                owned_blocks=(15, 16),
                local_segments=(),
                shared_suffix_blocks=(),
            ),
        ),
    )
    node_by_key = {
        direct_edge.source_key: SimpleNamespace(
            entry_anchor=158,
            exclusive_blocks=(158,),
            owned_blocks=(158,),
        ),
    }
    semantic_reference_program = SimpleNamespace(
        nodes=(
            SimpleNamespace(
                label_text="STATE_10743C4C",
                entry_anchor=158,
                line_start=1,
                line_end=1,
            ),
            SimpleNamespace(
                label_text="STATE_6107F8EC__blk_15",
                entry_anchor=15,
                line_start=2,
                line_end=4,
            ),
            SimpleNamespace(
                label_text="STATE_296F2452__blk_202",
                entry_anchor=202,
                line_start=5,
                line_end=5,
            ),
            SimpleNamespace(
                label_text="STATE_474EEEBB__blk_68",
                entry_anchor=68,
                line_start=6,
                line_end=6,
            ),
        ),
        lines=(
            SimpleNamespace(line_no=1, target_label="STATE_6107F8EC"),
            SimpleNamespace(line_no=2, target_label=None),
            SimpleNamespace(line_no=3, target_label="STATE_296F2452"),
            SimpleNamespace(line_no=4, target_label="STATE_474EEEBB"),
            SimpleNamespace(line_no=5, target_label=None),
            SimpleNamespace(line_no=6, target_label=None),
        ),
    )

    sites = collect_admissible_region_lowering_sites(
        region=region,
        dag=dag,
        node_by_key=node_by_key,
        dispatcher_region={71},
        semantic_reference_program=semantic_reference_program,
    )

    branch_sites = {
        int(getattr(getattr(site.edge, "source_anchor", None), "branch_arm", -1)): site
        for site in sites
        if int(site.source_state) & 0xFFFFFFFF == 0x6107F8EC
    }
    assert branch_sites[1].semantic_target_label == "STATE_296F2452"
    assert branch_sites[1].successor_state_value == 0x296F2452
    assert branch_sites[1].target_entry_anchor == 202
    assert branch_sites[0].semantic_target_label == "STATE_474EEEBB"
    assert branch_sites[0].successor_state_value == 0x474EEEBB
    assert branch_sites[0].target_entry_anchor == 68


def test_collect_admissible_region_lowering_sites_preserves_observed_branch_horizon_when_semantic_head_differs():
    region = SimpleNamespace(
        region_name="sub7ffd_10743c4c_branch_region",
        state_values=(0x10743C4C, 0x6107F8EC),
        internal_state_edges=((0x10743C4C, 0x6107F8EC),),
        exit_state_values=(0x296F2452, 0x474EEEBB),
    )
    direct_edge = _edge(
        source_state=0x10743C4C,
        target_state=0x6107F8EC,
        source_block=158,
        target_entry=136,
    )
    direct_edge.target_label = "STATE_6107F8EC"
    fallthrough_edge = _edge(
        source_state=0x6107F8EC,
        target_state=0x4C77464F,
        source_block=15,
        target_entry=68,
    )
    fallthrough_edge.source_anchor.branch_arm = 0
    fallthrough_edge.target_label = "0x4C77464F"
    fallthrough_edge.ordered_path = (15, 16, 68, 230)
    taken_edge = _edge(
        source_state=0x6107F8EC,
        target_state=0x296F2452,
        source_block=15,
        target_entry=202,
    )
    taken_edge.source_anchor.branch_arm = 1
    taken_edge.target_label = "STATE_296F2452"
    taken_edge.ordered_path = (15, 17, 202, 224, 149)
    dag = SimpleNamespace(edges=(direct_edge, fallthrough_edge, taken_edge))
    node_by_key = {
        direct_edge.source_key: SimpleNamespace(
            entry_anchor=158,
            exclusive_blocks=(158,),
            owned_blocks=(158,),
        ),
    }
    semantic_reference_program = SimpleNamespace(
        nodes=(
            SimpleNamespace(
                label_text="STATE_10743C4C",
                entry_anchor=158,
                line_start=1,
                line_end=1,
            ),
            SimpleNamespace(
                label_text="STATE_6107F8EC",
                entry_anchor=136,
                line_start=2,
                line_end=4,
            ),
            SimpleNamespace(
                label_text="STATE_296F2452",
                entry_anchor=202,
                line_start=5,
                line_end=5,
            ),
            SimpleNamespace(
                label_text="STATE_474EEEBB",
                entry_anchor=66,
                line_start=6,
                line_end=6,
            ),
        ),
        lines=(
            SimpleNamespace(line_no=1, target_label="STATE_6107F8EC"),
            SimpleNamespace(line_no=2, target_label="STATE_296F2452"),
            SimpleNamespace(line_no=3, target_label="STATE_474EEEBB"),
            SimpleNamespace(line_no=4, target_label="STATE_139F2922"),
            SimpleNamespace(line_no=5, target_label=None),
            SimpleNamespace(line_no=6, target_label=None),
        ),
    )

    sites = collect_admissible_region_lowering_sites(
        region=region,
        dag=dag,
        node_by_key=node_by_key,
        dispatcher_region={71},
        semantic_reference_program=semantic_reference_program,
    )

    by_branch_arm = {
        int(getattr(getattr(site.edge, "source_anchor", None), "branch_arm", -1)): site
        for site in sites
        if int(site.source_state) & 0xFFFFFFFF == 0x6107F8EC
    }
    assert by_branch_arm[1].source_entry_anchor == 15
    assert by_branch_arm[1].source_anchor_block == 15
    assert by_branch_arm[1].ordered_path == (15, 17)
    assert by_branch_arm[1].target_entry_anchor == 202
    assert by_branch_arm[0].source_entry_anchor == 15
    assert by_branch_arm[0].source_anchor_block == 15
    assert by_branch_arm[0].ordered_path == (15, 16)
    assert by_branch_arm[0].target_entry_anchor == 66
    assert by_branch_arm[0].semantic_target_label == "STATE_474EEEBB"


def test_collect_admissible_region_lowering_sites_infers_semantic_successor_from_nonraw_target_entry():
    region = SimpleNamespace(
        region_name="region",
        state_values=(0x6107F8EC,),
        internal_state_edges=(),
        exit_state_values=(0x4C77464F,),
    )
    target_key = _Key(0x4C77464F)
    edge = _edge(
        source_state=0x6107F8EC,
        target_state=0x4C77464F,
        source_block=16,
        target_entry=68,
        target_key=target_key,
    )
    dag = SimpleNamespace(
        edges=(edge,),
        nodes=(
            SimpleNamespace(
                key=_Key(0x474EEEBB),
                kind=StateNodeKind.EXACT,
                state_label="0x474EEEBB",
                entry_anchor=66,
                exclusive_blocks=(68,),
                owned_blocks=(66, 68, 69),
                local_segments=(),
                shared_suffix_blocks=(),
            ),
        ),
    )
    node_by_key = {
        edge.source_key: SimpleNamespace(entry_anchor=15, exclusive_blocks=(15, 16)),
    }

    sites = collect_admissible_region_lowering_sites(
        region=region,
        dag=dag,
        node_by_key=node_by_key,
        dispatcher_region={71},
    )

    assert len(sites) == 1
    assert sites[0].target_entry_anchor == 68
    assert sites[0].semantic_target_label == "STATE_474EEEBB"
    assert sites[0].successor_state_value == 0x474EEEBB


def test_collect_admissible_region_lowering_sites_recanonicalizes_stale_semantic_label_after_child_target_normalization():
    region = SimpleNamespace(
        region_name="branch_region",
        state_values=(0x6107F8EC,),
        internal_state_edges=(),
        exit_state_values=(0x296F2452, 0x474EEEBB),
    )
    source_key = _Key(0x6107F8EC)
    stale_target_key = _Key(0x296F2452)
    edge = SimpleNamespace(
        source_key=source_key,
        target_key=stale_target_key,
        target_state=0x474EEEBB,
        source_anchor=SimpleNamespace(block_serial=15),
        target_entry_anchor=202,
        ordered_path=(15, 66, 163),
    )
    dag = SimpleNamespace(
        edges=(edge,),
        nodes=(
            SimpleNamespace(
                key=source_key,
                kind=StateNodeKind.EXACT,
                entry_anchor=15,
                exclusive_blocks=(15,),
                owned_blocks=(15,),
                local_segments=(),
                shared_suffix_blocks=(),
            ),
            SimpleNamespace(
                key=stale_target_key,
                kind=StateNodeKind.EXACT,
                state_label="STATE_296F2452",
                entry_anchor=202,
                exclusive_blocks=(202,),
                owned_blocks=(202,),
                local_segments=(),
                shared_suffix_blocks=(),
            ),
            SimpleNamespace(
                key=_Key(0x474EEEBB),
                kind=StateNodeKind.EXACT,
                state_label="STATE_474EEEBB",
                entry_anchor=66,
                exclusive_blocks=(66, 68, 69),
                owned_blocks=(66, 68, 69),
                local_segments=(),
                shared_suffix_blocks=(),
            ),
        ),
    )
    node_by_key = {
        source_key: dag.nodes[0],
        stale_target_key: dag.nodes[1],
    }
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
                label_text="STATE_474EEEBB",
                entry_anchor=66,
                line_start=5,
                line_end=5,
            ),
        ),
        lines=(
            SimpleNamespace(line_no=1, target_label=None),
            SimpleNamespace(line_no=2, target_label="STATE_296F2452"),
            SimpleNamespace(line_no=3, target_label="STATE_474EEEBB"),
            SimpleNamespace(line_no=4, target_label=None),
            SimpleNamespace(line_no=5, target_label=None),
        ),
    )

    sites = collect_admissible_region_lowering_sites(
        region=region,
        dag=dag,
        node_by_key=node_by_key,
        dispatcher_region={71},
        semantic_reference_program=semantic_reference_program,
    )

    assert len(sites) == 1
    assert sites[0].target_state == 0x474EEEBB
    assert sites[0].target_entry_anchor == 66
    assert sites[0].semantic_target_label == "STATE_474EEEBB"
    assert sites[0].successor_state_value == 0x474EEEBB


def test_collect_semantic_entry_by_label_indexes_raw_and_state_forms():
    semantic_reference_program = SimpleNamespace(
        nodes=(
            SimpleNamespace(label_text="0x474EEEBB_fallback", entry_anchor=14),
            SimpleNamespace(label_text="STATE_296F2452", entry_anchor=202),
        )
    )

    entries = _collect_semantic_entry_by_label(semantic_reference_program)

    assert entries["0x474EEEBB_fallback"] == 14
    assert entries["STATE_474EEEBB_fallback"] == 14
    assert entries["STATE_296F2452"] == 202
    assert entries["0x296F2452"] == 202


def test_collect_semantic_successors_by_state_accepts_raw_state_node_labels():
    semantic_reference_program = SimpleNamespace(
        nodes=(
            SimpleNamespace(
                label_text="0x6107F8EC",
                entry_anchor=15,
                line_start=1,
                line_end=3,
            ),
        ),
        lines=(
            SimpleNamespace(line_no=2, target_label="STATE_474EEEBB_fallback"),
            SimpleNamespace(line_no=3, target_label="STATE_296F2452"),
        ),
    )

    successors = _collect_semantic_successors_by_state(semantic_reference_program)

    assert successors[0x6107F8EC] == (
        "STATE_474EEEBB_fallback",
        "STATE_296F2452",
    )


def test_collect_semantic_successors_by_state_accepts_block_suffixed_state_labels():
    semantic_reference_program = SimpleNamespace(
        nodes=(
            SimpleNamespace(
                label_text="STATE_11CD1DA3__blk_163",
                entry_anchor=163,
                line_start=1,
                line_end=4,
            ),
        ),
        lines=(
            SimpleNamespace(line_no=2, target_label=None),
            SimpleNamespace(line_no=3, target_label="STATE_4E69F350"),
            SimpleNamespace(line_no=4, target_label=None),
        ),
    )

    successors = _collect_semantic_successors_by_state(semantic_reference_program)

    assert successors[0x11CD1DA3] == ("STATE_4E69F350",)


def test_collect_semantic_successors_by_state_accumulates_multiple_same_state_blocks():
    semantic_reference_program = SimpleNamespace(
        nodes=(
            SimpleNamespace(
                label_text="STATE_11CD1DA3__blk_162",
                entry_anchor=162,
                line_start=1,
                line_end=2,
            ),
            SimpleNamespace(
                label_text="STATE_11CD1DA3__blk_163",
                entry_anchor=163,
                line_start=3,
                line_end=4,
            ),
        ),
        lines=(
            SimpleNamespace(line_no=2, target_label="STATE_11CD1DA3__blk_217"),
            SimpleNamespace(line_no=4, target_label="STATE_4E69F350"),
        ),
    )

    successors = _collect_semantic_successors_by_state(semantic_reference_program)

    assert successors[0x11CD1DA3] == (
        "STATE_11CD1DA3__blk_217",
        "STATE_4E69F350",
    )


def test_collect_semantic_entry_by_label_canonicalizes_block_suffixed_state_labels():
    semantic_reference_program = SimpleNamespace(
        nodes=(
            SimpleNamespace(
                label_text="STATE_6107F8EC__blk_15",
                entry_anchor=15,
                line_start=1,
                line_end=3,
            ),
            SimpleNamespace(
                label_text="STATE_474EEEBB__blk_68",
                entry_anchor=68,
                line_start=4,
                line_end=5,
            ),
        ),
        lines=(),
    )

    entries = _collect_semantic_entry_by_label(semantic_reference_program)

    assert entries["STATE_6107F8EC"] == 15
    assert entries["STATE_474EEEBB"] == 68


def test_build_region_contract_fallback_lowering_accepts_conditional_shared_rejection():
    edge = _edge(
        source_state=0x11111111,
        target_state=0x22222222,
        source_block=78,
        target_entry=143,
    )
    edge.source_anchor.branch_arm = 1
    site = next(
        iter(
            collect_admissible_region_lowering_sites(
                region=SimpleNamespace(
                    region_name="region",
                    state_values=(0x11111111, 0x22222222),
                    internal_state_edges=((0x11111111, 0x22222222),),
                    exit_state_values=(),
                ),
                dag=SimpleNamespace(edges=(edge,)),
                node_by_key={edge.source_key: SimpleNamespace(entry_anchor=78)},
                dispatcher_region={20},
            )
        )
    )

    fallback = build_region_contract_fallback_lowering(
        site=site,
        rejection_reason="missing_via_pred",
    )

    assert fallback is not None
    assert fallback.emission_mode == "conditional_arm"
    assert fallback.horizon_block == 78
    assert fallback.target_entry_anchor == 143


def test_build_region_contract_fallback_lowering_rejects_unrelated_reason():
    edge = _edge(
        source_state=0x11111111,
        target_state=0x22222222,
        source_block=78,
        target_entry=143,
    )
    site = next(
        iter(
            collect_admissible_region_lowering_sites(
                region=SimpleNamespace(
                    region_name="region",
                    state_values=(0x11111111, 0x22222222),
                    internal_state_edges=((0x11111111, 0x22222222),),
                    exit_state_values=(),
                ),
                dag=SimpleNamespace(edges=(edge,)),
                node_by_key={edge.source_key: SimpleNamespace(entry_anchor=78)},
                dispatcher_region={20},
            )
        )
    )

    fallback = build_region_contract_fallback_lowering(
        site=site,
        rejection_reason="missing_path_horizon",
    )

    assert fallback is None


def test_build_region_preferred_conditional_lowering_prefers_source_arm_redirect():
    edge = _edge(
        source_state=0x6107F8EC,
        target_state=0x4C77464F,
        source_block=15,
        target_entry=66,
    )
    edge.source_anchor.branch_arm = 0
    edge.ordered_path = (15, 16)
    site = next(
        iter(
            collect_admissible_region_lowering_sites(
                region=SimpleNamespace(
                    region_name="region",
                    state_values=(0x6107F8EC,),
                    internal_state_edges=(),
                    exit_state_values=(0x4C77464F,),
                ),
                dag=SimpleNamespace(edges=(edge,)),
                node_by_key={edge.source_key: SimpleNamespace(entry_anchor=15)},
                dispatcher_region={71},
                semantic_reference_program=SimpleNamespace(
                    nodes=(
                        SimpleNamespace(
                            label_text="STATE_6107F8EC",
                            entry_anchor=15,
                            line_start=1,
                            line_end=2,
                        ),
                        SimpleNamespace(
                            label_text="STATE_4C77464F",
                            entry_anchor=66,
                            line_start=3,
                            line_end=4,
                        ),
                    ),
                    lines=(
                        SimpleNamespace(line_no=1, target_label=None),
                        SimpleNamespace(line_no=2, target_label="STATE_4C77464F"),
                        SimpleNamespace(line_no=3, target_label=None),
                        SimpleNamespace(line_no=4, target_label=None),
                    ),
                ),
            )
        )
    )

    preferred = build_region_preferred_conditional_lowering(site=site)

    assert preferred is not None
    assert preferred.emission_mode == "conditional_arm"
    assert preferred.horizon_block == 15
    assert preferred.target_entry_anchor == 66


def test_build_region_preferred_conditional_lowering_uses_interior_branch_block():
    edge = _edge(
        source_state=0x11CD1DA3,
        target_state=0x4E69F350,
        source_block=163,
        target_entry=72,
    )
    edge.source_anchor.branch_arm = 1
    edge.ordered_path = (161, 163, 165)
    site = next(
        iter(
            collect_admissible_region_lowering_sites(
                region=SimpleNamespace(
                    region_name="region",
                    state_values=(0x11CD1DA3, 0x4E69F350),
                    internal_state_edges=((0x11CD1DA3, 0x4E69F350),),
                    exit_state_values=(),
                ),
                dag=SimpleNamespace(edges=(edge,)),
                node_by_key={
                    edge.source_key: SimpleNamespace(
                        entry_anchor=161,
                        exclusive_blocks=(161, 162, 163, 164, 165),
                    )
                },
                dispatcher_region={20},
            )
        )
    )

    preferred = build_region_preferred_conditional_lowering(site=site)

    assert preferred is not None
    assert preferred.emission_mode == "conditional_arm"
    assert preferred.horizon_block == 163
    assert preferred.target_entry_anchor == 72


def test_build_region_preferred_conditional_lowering_accepts_path_rooted_at_source_anchor():
    edge = _edge(
        source_state=0x16F7FF74,
        target_state=0x6D207773,
        source_block=150,
        target_entry=48,
    )
    edge.source_anchor.branch_arm = 1
    edge.ordered_path = (150, 152)
    site = SimpleNamespace(
        region_name="region",
        site_kind="exit",
        source_state=0x16F7FF74,
        target_state=0x6D207773,
        source_entry_anchor=151,
        source_anchor_block=150,
        target_entry_anchor=48,
        ordered_path=(150, 152),
        edge=edge,
        semantic_target_label="STATE_6D207773",
        successor_state_value=0x6D207773,
    )

    preferred = build_region_preferred_conditional_lowering(site=site)
    fallback = build_region_contract_fallback_lowering(
        site=site,
        rejection_reason="missing_via_pred",
    )

    assert preferred is not None
    assert preferred.emission_mode == "conditional_arm"
    assert preferred.horizon_block == 150
    assert preferred.target_entry_anchor == 48
    assert fallback is not None
    assert fallback.emission_mode == "conditional_arm"
    assert fallback.horizon_block == 150


def test_build_region_preferred_conditional_lowering_rejects_non_branch_site():
    edge = _edge(
        source_state=0x11111111,
        target_state=0x22222222,
        source_block=78,
        target_entry=143,
    )
    site = next(
        iter(
            collect_admissible_region_lowering_sites(
                region=SimpleNamespace(
                    region_name="region",
                    state_values=(0x11111111, 0x22222222),
                    internal_state_edges=((0x11111111, 0x22222222),),
                    exit_state_values=(),
                ),
                dag=SimpleNamespace(edges=(edge,)),
                node_by_key={edge.source_key: SimpleNamespace(entry_anchor=78)},
                dispatcher_region={20},
            )
        )
    )

    preferred = build_region_preferred_conditional_lowering(site=site)

    assert preferred is None


def test_build_region_contract_fallback_lowering_uses_interior_branch_block():
    edge = _edge(
        source_state=0x11CD1DA3,
        target_state=0x4E69F350,
        source_block=163,
        target_entry=72,
    )
    edge.source_anchor.branch_arm = 1
    edge.ordered_path = (161, 163, 165)
    site = next(
        iter(
            collect_admissible_region_lowering_sites(
                region=SimpleNamespace(
                    region_name="region",
                    state_values=(0x11CD1DA3, 0x4E69F350),
                    internal_state_edges=((0x11CD1DA3, 0x4E69F350),),
                    exit_state_values=(),
                ),
                dag=SimpleNamespace(edges=(edge,)),
                node_by_key={
                    edge.source_key: SimpleNamespace(
                        entry_anchor=161,
                        exclusive_blocks=(161, 162, 163, 164, 165),
                    )
                },
                dispatcher_region={20},
            )
        )
    )

    fallback = build_region_contract_fallback_lowering(
        site=site,
        rejection_reason="missing_keep_pred",
    )

    assert fallback is not None
    assert fallback.emission_mode == "conditional_arm"
    assert fallback.horizon_block == 163
    assert fallback.target_entry_anchor == 72
