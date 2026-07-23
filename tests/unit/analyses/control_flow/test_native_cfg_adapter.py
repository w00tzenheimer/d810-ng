from d810.analyses.control_flow.native_cfg_adapter import (
    NativeFlowBlockFact,
    build_native_cfg_from_flow_facts,
    can_decode_native_call_continuation,
    can_decode_proven_native_successor,
    has_native_semantic_boundary,
    is_native_direct_control_operand,
    needs_native_flow_decode,
    select_visited_native_flow_facts,
)
from d810.analyses.control_flow.native_semantic_closure import (
    NativeEdge,
    NativeEdgeKind,
    NativeTerminalKind,
)


def test_builds_conditional_direct_and_fallthrough_edges() -> None:
    cfg = build_native_cfg_from_flow_facts(
        (
            NativeFlowBlockFact(
                start_ea=0x1000,
                end_ea=0x1010,
                successor_eas=(0x1010, 0x1020),
                direct_branch_target_ea=0x1020,
                terminal_instruction_ea=0x100E,
            ),
            NativeFlowBlockFact(
                start_ea=0x1010,
                end_ea=0x1020,
                successor_eas=(0x1030,),
                direct_branch_target_ea=0x1030,
                terminal_instruction_ea=0x101E,
            ),
            NativeFlowBlockFact(0x1020, 0x1030),
            NativeFlowBlockFact(0x1030, 0x1040),
        )
    )

    first = cfg.blocks_by_ea[0x1000]
    assert {
        (edge.kind, edge.target_ea, edge.source_instruction_ea)
        for edge in first.outgoing_edges
    } == {
        (NativeEdgeKind.CONDITIONAL_TRUE, 0x1020, 0x100E),
        (NativeEdgeKind.CONDITIONAL_FALSE, 0x1010, 0x100E),
    }
    assert cfg.blocks_by_ea[0x1010].outgoing_edges == (
        NativeEdge(
            NativeEdgeKind.DIRECT_JUMP,
            0x1030,
            source_instruction_ea=0x101E,
        ),
    )


def test_call_tail_excludes_direct_callee_from_traversable_successors() -> None:
    callee_ea = 0x5000
    continuation_ea = 0x4205
    cfg = build_native_cfg_from_flow_facts(
        (
            NativeFlowBlockFact(
                0x4200,
                continuation_ea,
                successor_eas=(callee_ea, continuation_ea),
                direct_branch_target_ea=callee_ea,
                is_call_tail=True,
            ),
            NativeFlowBlockFact(continuation_ea, 0x4210),
            NativeFlowBlockFact(callee_ea, 0x5010),
        )
    )

    assert cfg.blocks_by_ea[0x4200].outgoing_edges == (
        NativeEdge(NativeEdgeKind.CALL_FALLTHROUGH, continuation_ea),
    )


def test_retains_proven_and_unknown_indirect_cut_evidence() -> None:
    proven_source_ea = 0x200E
    unknown_source_ea = 0x201E
    cfg = build_native_cfg_from_flow_facts(
        (
            NativeFlowBlockFact(
                0x2000,
                0x2010,
                force_stop=True,
                cut_edges=(
                    NativeEdge(
                        NativeEdgeKind.INDIRECT,
                        0x9000,
                        resolver_proven=True,
                        provenance="resolver",
                        source_instruction_ea=proven_source_ea,
                    ),
                ),
            ),
            NativeFlowBlockFact(
                0x2010,
                0x2020,
                is_indirect_jump_tail=True,
                terminal_instruction_ea=unknown_source_ea,
            ),
        )
    )

    proven = cfg.blocks_by_ea[0x2000]
    assert proven.terminal is NativeTerminalKind.STOP
    assert proven.outgoing_edges == (
        NativeEdge(
            NativeEdgeKind.INDIRECT,
            0x9000,
            resolver_proven=True,
            provenance="resolver",
            source_instruction_ea=proven_source_ea,
        ),
    )
    unknown = cfg.blocks_by_ea[0x2010].outgoing_edges[0]
    assert unknown.kind is NativeEdgeKind.INDIRECT
    assert unknown.target_ea is None
    assert unknown.source_instruction_ea == unknown_source_ea
    assert not unknown.resolver_proven


def test_excludes_live_entries_but_retains_requested_seeds() -> None:
    cfg = build_native_cfg_from_flow_facts(
        (
            NativeFlowBlockFact(0x3000, 0x3010),
            NativeFlowBlockFact(0x3010, 0x3020),
            NativeFlowBlockFact(0x3020, 0x3030),
        ),
        excluded_entry_eas=(0x3000, 0x3010),
        retained_entry_eas=(0x3010,),
    )

    assert tuple(cfg.blocks_by_ea) == (0x3010, 0x3020)


def test_rejects_empty_placeholder_facts_and_requests_native_redecode() -> None:
    placeholder = NativeFlowBlockFact(0x4000, 0x4000)
    cfg = build_native_cfg_from_flow_facts(
        (placeholder, NativeFlowBlockFact(0x4010, 0x4020))
    )

    assert tuple(cfg.blocks_by_ea) == (0x4010,)
    assert needs_native_flow_decode(None)
    assert needs_native_flow_decode(placeholder)


def test_interior_resolver_cut_requests_native_redecode() -> None:
    fact = NativeFlowBlockFact(
        0x4100,
        0x4110,
        terminal_instruction_ea=0x410C,
        force_stop=True,
        cut_edges=(
            NativeEdge(
                NativeEdgeKind.INDIRECT,
                0x9000,
                resolver_proven=True,
                source_instruction_ea=0x4108,
            ),
        ),
    )

    assert needs_native_flow_decode(fact)


def test_incomplete_conditional_flowchart_row_requests_native_redecode() -> None:
    incomplete = NativeFlowBlockFact(
        0x4200,
        0x4210,
        successor_eas=(0x4300,),
        direct_branch_target_ea=0x4300,
        is_conditional_jump_tail=True,
        terminal_instruction_ea=0x420E,
    )

    assert needs_native_flow_decode(incomplete)


def test_noncontiguous_fallthrough_flowchart_row_requests_native_redecode() -> None:
    stale = NativeFlowBlockFact(
        0x4400,
        0x4410,
        successor_eas=(0x4500,),
        terminal_instruction_ea=0x440C,
    )

    assert needs_native_flow_decode(stale)


def test_native_decode_guards_are_semantic_and_function_bounded() -> None:
    assert can_decode_proven_native_successor(
        is_code=True,
        owner_func_ea=None,
        requested_func_ea=0x5000,
    )
    assert not can_decode_proven_native_successor(
        is_code=True,
        owner_func_ea=0x6000,
        requested_func_ea=0x5000,
    )
    assert can_decode_proven_native_successor(
        is_code=False,
        owner_func_ea=0x5000,
        requested_func_ea=0x5000,
        resolver_proven_unmarked=True,
    )
    assert not can_decode_proven_native_successor(
        is_code=False,
        owner_func_ea=0x6000,
        requested_func_ea=0x5000,
        resolver_proven_unmarked=True,
    )
    assert has_native_semantic_boundary(
        resolver_cut=False,
        is_return=False,
        is_indirect_jump=False,
        is_call=True,
        direct_branch_target_ea=0x7000,
        has_stop_feature=False,
    )
    assert is_native_direct_control_operand(
        operand_is_near=True,
        is_call=False,
        is_basic_block_end=True,
        has_stop_feature=False,
    )


def test_call_continuation_accepts_ownerless_resolver_scoped_ida_flow() -> None:
    assert can_decode_native_call_continuation(
        function_contains=False,
        ida_marks_flow=True,
        is_direct_call=False,
        is_code=True,
        owner_func_ea=None,
        requested_func_ea=0x5000,
    )
    assert can_decode_native_call_continuation(
        function_contains=True,
        ida_marks_flow=False,
        is_direct_call=False,
        is_code=True,
        owner_func_ea=0x5000,
        requested_func_ea=0x5000,
    )
    assert not can_decode_native_call_continuation(
        function_contains=True,
        ida_marks_flow=False,
        is_direct_call=True,
        is_code=True,
        owner_func_ea=0x5000,
        requested_func_ea=0x5000,
    )
    assert not can_decode_native_call_continuation(
        function_contains=False,
        ida_marks_flow=True,
        is_direct_call=False,
        is_code=True,
        owner_func_ea=0x6000,
        requested_func_ea=0x5000,
    )


def test_selects_only_facts_visited_from_resolver_seeds() -> None:
    selected = select_visited_native_flow_facts(
        {
            0x8000: NativeFlowBlockFact(0x8000, 0x8010),
            0x9000: NativeFlowBlockFact(0x9000, 0x9010),
        },
        visited_entry_eas=(0x8000,),
    )

    assert selected == (NativeFlowBlockFact(0x8000, 0x8010),)
