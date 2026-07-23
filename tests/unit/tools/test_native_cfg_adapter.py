from tools.scripts.rhad_investigation.native_cfg_adapter import (
    NativeFlowBlockFact,
    build_native_cfg_from_flow_facts,
    can_decode_proven_native_successor,
    has_native_semantic_boundary,
    is_native_direct_control_operand,
    needs_native_flow_decode,
    select_visited_native_flow_facts,
)
from tools.scripts.rhad_investigation.native_semantic_closure import (
    NativeEdgeKind,
    NativeTerminalKind,
)


def test_builds_conditional_and_fallthrough_edges() -> None:
    cfg = build_native_cfg_from_flow_facts(
        (
            NativeFlowBlockFact(
                start_ea=0x1000,
                end_ea=0x1010,
                successor_eas=(0x1010, 0x1020),
                direct_branch_target_ea=0x1020,
            ),
            NativeFlowBlockFact(
                start_ea=0x1010,
                end_ea=0x1020,
                successor_eas=(0x1030,),
            ),
            NativeFlowBlockFact(0x1020, 0x1030),
            NativeFlowBlockFact(0x1030, 0x1040),
        )
    )

    first = cfg.blocks_by_ea[0x1000]
    assert {(edge.kind, edge.target_ea) for edge in first.outgoing_edges} == {
        (NativeEdgeKind.CONDITIONAL_TRUE, 0x1020),
        (NativeEdgeKind.CONDITIONAL_FALSE, 0x1010),
    }
    assert cfg.blocks_by_ea[0x1010].outgoing_edges[0].kind is (
        NativeEdgeKind.FALLTHROUGH
    )


def test_marks_return_indirect_and_resolver_cut_blocks_terminal() -> None:
    cfg = build_native_cfg_from_flow_facts(
        (
            NativeFlowBlockFact(
                0x2000,
                0x2010,
                is_return_tail=True,
            ),
            NativeFlowBlockFact(
                0x2010,
                0x2020,
                is_indirect_jump_tail=True,
                terminal_instruction_ea=0x201E,
            ),
            NativeFlowBlockFact(
                0x2020,
                0x2030,
                successor_eas=(0x2030,),
                force_stop=True,
            ),
            NativeFlowBlockFact(0x2030, 0x2040),
        )
    )

    assert cfg.blocks_by_ea[0x2000].terminal is NativeTerminalKind.RETURN
    assert cfg.blocks_by_ea[0x2010].terminal is NativeTerminalKind.STOP
    assert cfg.blocks_by_ea[0x2020].terminal is NativeTerminalKind.STOP
    assert cfg.blocks_by_ea[0x2020].outgoing_edges == ()


def test_retains_resolver_proven_edge_at_force_stop() -> None:
    from tools.scripts.rhad_investigation.native_semantic_closure import (
        NativeEdge,
    )

    resolver_ea = 0x210E
    target_ea = 0x9000
    cfg = build_native_cfg_from_flow_facts(
        (
            NativeFlowBlockFact(
                0x2100,
                0x2110,
                force_stop=True,
                cut_edges=(
                    NativeEdge(
                        NativeEdgeKind.INDIRECT,
                        target_ea,
                        resolver_proven=True,
                        provenance="static_fixpoint",
                        source_instruction_ea=resolver_ea,
                    ),
                ),
            ),
        )
    )

    block = cfg.blocks_by_ea[0x2100]
    assert block.terminal is NativeTerminalKind.STOP
    assert len(block.outgoing_edges) == 1
    edge = block.outgoing_edges[0]
    assert edge.kind is NativeEdgeKind.INDIRECT
    assert edge.target_ea == target_ea
    assert edge.resolver_proven
    assert edge.source_instruction_ea == resolver_ea


def test_retains_unproven_indirect_cut_for_closure_abstention() -> None:
    from tools.scripts.rhad_investigation.native_semantic_closure import (
        NativeEdge,
    )

    cfg = build_native_cfg_from_flow_facts(
        (
            NativeFlowBlockFact(
                0x2200,
                0x2210,
                force_stop=True,
                cut_edges=(
                    NativeEdge(
                        NativeEdgeKind.INDIRECT,
                        source_instruction_ea=0x220E,
                        provenance="ambiguous_resolver_transfer",
                    ),
                ),
            ),
        )
    )

    edge = cfg.blocks_by_ea[0x2200].outgoing_edges[0]
    assert edge.kind is NativeEdgeKind.INDIRECT
    assert edge.target_ea is None
    assert not edge.resolver_proven


def test_synthesizes_unproven_cut_for_native_indirect_without_resolver() -> None:
    terminal_ea = 0x230E
    cfg = build_native_cfg_from_flow_facts(
        (
            NativeFlowBlockFact(
                0x2300,
                0x2310,
                is_indirect_jump_tail=True,
                terminal_instruction_ea=terminal_ea,
            ),
        )
    )

    edge = cfg.blocks_by_ea[0x2300].outgoing_edges[0]
    assert edge.kind is NativeEdgeKind.INDIRECT
    assert edge.target_ea is None
    assert edge.source_instruction_ea == terminal_ea
    assert not edge.resolver_proven


def test_excludes_live_entries_except_explicit_missing_seeds() -> None:
    cfg = build_native_cfg_from_flow_facts(
        (
            NativeFlowBlockFact(0x3000, 0x3010),
            NativeFlowBlockFact(0x3010, 0x3020),
            NativeFlowBlockFact(0x3020, 0x3030),
        ),
        excluded_entry_eas=frozenset({0x3000, 0x3010}),
        retained_entry_eas=frozenset({0x3010}),
    )

    assert tuple(cfg.blocks_by_ea) == (0x3010, 0x3020)


def test_ignores_zero_length_flowchart_sentinels() -> None:
    cfg = build_native_cfg_from_flow_facts(
        (
            NativeFlowBlockFact(0x4000, 0x4000),
            NativeFlowBlockFact(0x4010, 0x4020),
        )
    )

    assert tuple(cfg.blocks_by_ea) == (0x4010,)


def test_zero_length_flowchart_sentinel_requires_native_decode() -> None:
    assert needs_native_flow_decode(None)
    assert needs_native_flow_decode(NativeFlowBlockFact(0x5000, 0x5000))
    assert not needs_native_flow_decode(NativeFlowBlockFact(0x5000, 0x5010))


def test_malformed_conditional_flow_fact_requires_native_decode() -> None:
    assert needs_native_flow_decode(
        NativeFlowBlockFact(
            0x5100,
            0x5110,
            successor_eas=(0x5200, 0x5300),
        )
    )


def test_resolver_cut_fact_does_not_require_conditional_redecode() -> None:
    assert not needs_native_flow_decode(
        NativeFlowBlockFact(
            0x5200,
            0x5210,
            successor_eas=(0x5300, 0x5400),
            force_stop=True,
        )
    )


def test_proven_successor_admits_unowned_code_but_not_foreign_functions() -> None:
    assert can_decode_proven_native_successor(
        is_code=True,
        owner_func_ea=None,
        requested_func_ea=0x6000,
    )
    assert can_decode_proven_native_successor(
        is_code=True,
        owner_func_ea=0x6000,
        requested_func_ea=0x6000,
    )
    assert not can_decode_proven_native_successor(
        is_code=True,
        owner_func_ea=0x7000,
        requested_func_ea=0x6000,
    )
    assert not can_decode_proven_native_successor(
        is_code=False,
        owner_func_ea=None,
        requested_func_ea=0x6000,
    )


def test_semantic_boundary_ignores_partition_only_block_end() -> None:
    assert not has_native_semantic_boundary(
        resolver_cut=False,
        is_return=False,
        is_indirect_jump=False,
        is_call=False,
        direct_branch_target_ea=None,
        has_stop_feature=False,
    )


def test_semantic_boundary_splits_calls_into_explicit_fallthrough_blocks() -> None:
    assert has_native_semantic_boundary(
        resolver_cut=False,
        is_return=False,
        is_indirect_jump=False,
        is_call=True,
        direct_branch_target_ea=0x7100,
        has_stop_feature=False,
    )


def test_semantic_boundary_accepts_only_proven_control_transfers() -> None:
    common = {
        "resolver_cut": False,
        "is_return": False,
        "is_indirect_jump": False,
        "is_call": False,
        "direct_branch_target_ea": None,
        "has_stop_feature": False,
    }
    for override in (
        {"resolver_cut": True},
        {"is_return": True},
        {"is_indirect_jump": True},
        {"direct_branch_target_ea": 0x7200},
        {"has_stop_feature": True},
    ):
        assert has_native_semantic_boundary(**(common | override))


def test_direct_control_operand_requires_jump_or_call_semantics() -> None:
    assert not is_native_direct_control_operand(
        operand_is_near=True,
        is_call=False,
        is_basic_block_end=False,
        has_stop_feature=False,
    )
    assert is_native_direct_control_operand(
        operand_is_near=True,
        is_call=True,
        is_basic_block_end=False,
        has_stop_feature=False,
    )
    assert is_native_direct_control_operand(
        operand_is_near=True,
        is_call=False,
        is_basic_block_end=True,
        has_stop_feature=False,
    )
    assert is_native_direct_control_operand(
        operand_is_near=True,
        is_call=False,
        is_basic_block_end=False,
        has_stop_feature=True,
    )
    assert not is_native_direct_control_operand(
        operand_is_near=False,
        is_call=True,
        is_basic_block_end=True,
        has_stop_feature=True,
    )


def test_selects_only_flow_facts_visited_from_closure_seeds() -> None:
    selected = select_visited_native_flow_facts(
        {
            0x8000: NativeFlowBlockFact(0x8000, 0x8010),
            0x9000: NativeFlowBlockFact(
                0x9000,
                0x9010,
                successor_eas=(0xA000, 0xB000),
            ),
        },
        visited_entry_eas=(0x8000,),
    )

    assert selected == (NativeFlowBlockFact(0x8000, 0x8010),)
