from __future__ import annotations

from types import SimpleNamespace

import ida_bytes
import ida_funcs
import ida_gdl
import ida_idp
import ida_segment
import ida_ua
import idaapi
import idautils

from d810.analyses.control_flow.native_semantic_closure import (
    ClosureAbstentionReason,
    NativeEdge,
    NativeEdgeKind,
    NativeTerminalKind,
    ResolverProvenHandlerEntry,
    plan_native_semantic_closure,
)
from d810.analyses.control_flow.native_cfg_adapter import NativeFlowBlockFact
from d810.backends.hexrays.evidence.native_semantic_closure import (
    NativeCfgDecodeAbstentionReason,
    build_native_semantic_cfg,
)
from d810.backends.hexrays.evidence import native_semantic_closure as native_backend
from tests.system.runtime.conftest import get_func_ea


def _function(name: str) -> ida_funcs.func_t:
    entry_ea = int(get_func_ea(name))
    assert entry_ea != int(idaapi.BADADDR)
    function = ida_funcs.get_func(entry_ea)
    assert function is not None
    return function


def _decoded_instruction(ea: int) -> ida_ua.insn_t:
    instruction = ida_ua.insn_t()
    assert int(ida_ua.decode_insn(instruction, int(ea))) > 0
    return instruction


def _find_indirect_jump_ea(function: ida_funcs.func_t) -> int:
    for ea in idautils.Heads(int(function.start_ea), int(function.end_ea)):
        instruction = _decoded_instruction(int(ea))
        if ida_idp.is_indirect_jump_insn(instruction):
            return int(ea)
    raise AssertionError("fixture function has no native indirect jump")


def _find_function_with_call() -> tuple[ida_funcs.func_t, int]:
    for function_ea in idautils.Functions():
        function = ida_funcs.get_func(int(function_ea))
        if function is None:
            continue
        for ea in idautils.Heads(int(function.start_ea), int(function.end_ea)):
            instruction = _decoded_instruction(int(ea))
            if ida_idp.is_call_insn(instruction):
                return function, int(ea)
    raise AssertionError("fixture database has no native call instruction")


def _find_non_code_ea() -> int:
    for segment_ea in idautils.Segments():
        segment = ida_segment.getseg(int(segment_ea))
        assert segment is not None
        for ea in idautils.Heads(int(segment.start_ea), int(segment.end_ea)):
            if not ida_bytes.is_code(ida_bytes.get_full_flags(int(ea))):
                return int(ea)
    raise AssertionError("fixture database has no non-code address")


def _find_flowchart_with_interior_cut(
    function: ida_funcs.func_t,
) -> tuple[int, int, int, int]:
    for flow_block in ida_gdl.FlowChart(function):
        start_ea = int(flow_block.start_ea)
        end_ea = int(flow_block.end_ea)
        instruction_eas = tuple(
            int(ea)
            for ea in idautils.Heads(start_ea, end_ea)
            if ida_bytes.is_code(ida_bytes.get_full_flags(int(ea)))
        )
        if len(instruction_eas) >= 3:
            return start_ea, end_ea, instruction_eas[-2], instruction_eas[-1]
    raise AssertionError("fixture function has no interior FlowChart instruction")


class TestNativeSemanticCfgAdapter:
    binary_name = "restructuring_lab.dll"

    def test_traverses_direct_and_conditional_native_flow(self, ida_database) -> None:
        function = _function("lab_if_diamond")

        result = build_native_semantic_cfg(
            function,
            live_native_eas=(),
            seed_eas=(int(function.start_ea),),
            resolver_target_eas_by_source={},
        )

        edge_kinds = {
            edge.kind
            for block in result.cfg.blocks_by_ea.values()
            for edge in block.outgoing_edges
        }
        assert NativeEdgeKind.DIRECT_JUMP in edge_kinds
        assert NativeEdgeKind.CONDITIONAL_TRUE in edge_kinds
        assert NativeEdgeKind.CONDITIONAL_FALSE in edge_kinds
        closure = plan_native_semantic_closure(
            result.cfg,
            (
                ResolverProvenHandlerEntry(
                    int(function.start_ea),
                    "runtime_fixture",
                ),
            ),
        )
        assert set(closure.included_block_eas) == set(result.cfg.blocks_by_ea)
        assert not result.abstentions

    def test_retains_calls_inside_native_ranges_without_traversing_them(
        self,
        ida_database,
    ) -> None:
        function, call_ea = _find_function_with_call()

        result = build_native_semantic_cfg(
            function,
            live_native_eas=(),
            seed_eas=(int(function.start_ea),),
            resolver_target_eas_by_source={},
        )

        containing_blocks = tuple(
            block
            for block in result.cfg.blocks_by_ea.values()
            if block.start_ea <= call_ea < block.end_ea
        )
        assert len(containing_blocks) == 1
        assert any(
            edge.kind is NativeEdgeKind.CALL_FALLTHROUGH
            for edge in containing_blocks[0].outgoing_edges
        )
        assert all(
            edge.kind is not NativeEdgeKind.CALL
            for block in result.cfg.blocks_by_ea.values()
            for edge in block.outgoing_edges
        )

    def test_lifts_resolver_proven_indirect_boundary(self, ida_database) -> None:
        function = _function("lab_rhad_indirect")
        source_instruction_ea = _find_indirect_jump_ea(function)
        resolver_target_ea = int(function.start_ea)

        result = build_native_semantic_cfg(
            function,
            live_native_eas=(),
            seed_eas=(int(function.start_ea),),
            resolver_target_eas_by_source={
                source_instruction_ea: (resolver_target_ea,),
            },
        )

        source_blocks = tuple(
            block
            for block in result.cfg.blocks_by_ea.values()
            if block.start_ea <= source_instruction_ea < block.end_ea
        )
        assert len(source_blocks) == 1
        source_block = source_blocks[0]
        assert source_block.terminal is NativeTerminalKind.STOP
        assert len(source_block.outgoing_edges) == 1
        edge = source_block.outgoing_edges[0]
        assert edge.kind is NativeEdgeKind.INDIRECT
        assert edge.target_ea == resolver_target_ea
        assert edge.resolver_proven
        assert edge.source_instruction_ea == source_instruction_ea

    def test_resolver_proven_unmarked_entry_has_one_native_block_owner(
        self,
        ida_database,
    ) -> None:
        function = _function("lab_rhad_indirect")
        source_instruction_ea = _find_indirect_jump_ea(function)
        source_instruction = _decoded_instruction(source_instruction_ea)
        filler_ea = source_instruction_ea + int(source_instruction.size)
        filler_instruction = _decoded_instruction(filler_ea)
        resolver_target_ea = filler_ea + int(filler_instruction.size)
        assert ida_bytes.get_byte(filler_ea) == 0xCC

        result = build_native_semantic_cfg(
            function,
            live_native_eas=(),
            seed_eas=(int(function.start_ea), resolver_target_ea),
            resolver_target_eas_by_source={
                source_instruction_ea: (resolver_target_ea,),
            },
            resolver_proven_unmarked_entry_eas=(resolver_target_ea,),
        )

        owners = tuple(
            block
            for block in result.cfg.blocks_by_ea.values()
            if block.start_ea <= resolver_target_ea < block.end_ea
        )
        assert len(owners) == 1
        assert owners[0].start_ea == resolver_target_ea

    def test_explicit_cut_without_target_evidence_stays_unproven(self) -> None:
        source_instruction_ea = 0x401010

        edges = native_backend._cut_edges_for_range(
            0x401000,
            0x401020,
            (source_instruction_ea,),
            {},
        )

        assert len(edges) == 1
        edge = edges[0]
        assert edge.kind is NativeEdgeKind.INDIRECT
        assert edge.target_ea is None
        assert not edge.resolver_proven
        assert edge.source_instruction_ea == source_instruction_ea

    def test_interior_resolver_cut_ends_at_exact_decoded_boundary(
        self,
        ida_database,
    ) -> None:
        function = _function("lab_if_diamond")
        block_start_ea, flowchart_end_ea, source_instruction_ea, later_cut_ea = (
            _find_flowchart_with_interior_cut(function)
        )
        source_instruction = _decoded_instruction(source_instruction_ea)
        expected_end_ea = source_instruction_ea + int(source_instruction.size)

        result = build_native_semantic_cfg(
            function,
            live_native_eas=(),
            seed_eas=(block_start_ea,),
            resolver_target_eas_by_source={
                source_instruction_ea: (int(function.start_ea),),
                later_cut_ea: (block_start_ea,),
            },
        )

        source_block = result.cfg.blocks_by_ea[block_start_ea]
        assert expected_end_ea <= later_cut_ea < flowchart_end_ea
        assert source_block.end_ea == expected_end_ea
        assert len(source_block.outgoing_edges) == 1
        edge = source_block.outgoing_edges[0]
        assert edge.kind is NativeEdgeKind.INDIRECT
        assert edge.target_ea == int(function.start_ea)
        assert edge.source_instruction_ea == source_instruction_ea

    def test_unknown_indirect_is_ea_anchored_planner_abstention(
        self,
        ida_database,
    ) -> None:
        function = _function("lab_rhad_indirect")
        source_instruction_ea = _find_indirect_jump_ea(function)

        result = build_native_semantic_cfg(
            function,
            live_native_eas=(),
            seed_eas=(int(function.start_ea),),
            resolver_target_eas_by_source={},
        )
        closure = plan_native_semantic_closure(
            result.cfg,
            (
                ResolverProvenHandlerEntry(
                    int(function.start_ea),
                    "runtime_fixture",
                ),
            ),
        )

        assert len(closure.abstentions) == 1
        abstention = closure.abstentions[0]
        assert abstention.reason is ClosureAbstentionReason.UNPROVEN_INDIRECT_TARGET
        assert abstention.source_block_ea is not None
        source_block = result.cfg.blocks_by_ea[abstention.source_block_ea]
        edge = source_block.outgoing_edges[0]
        assert edge.source_instruction_ea == source_instruction_ea

    def test_resolver_proven_target_set_emits_each_exact_edge(self) -> None:
        source_instruction_ea = 0x401010
        target_eas = (0x402000, 0x403000)

        edges = native_backend._cut_edges_for_range(
            0x401000,
            0x401020,
            (source_instruction_ea,),
            {source_instruction_ea: target_eas},
        )

        assert tuple(edge.target_ea for edge in edges) == target_eas
        assert all(edge.kind is NativeEdgeKind.INDIRECT for edge in edges)
        assert all(edge.resolver_proven for edge in edges)
        assert all(
            edge.source_instruction_ea == source_instruction_ea for edge in edges
        )

    def test_resolver_cut_targets_are_visited_as_native_cfg_entries(
        self,
        monkeypatch,
    ) -> None:
        source_ea = 0x401000
        cut_ea = 0x401010
        target_eas = (0x402000, 0x403000)
        facts = {
            source_ea: NativeFlowBlockFact(
                start_ea=source_ea,
                end_ea=cut_ea + 2,
                force_stop=True,
                terminal_instruction_ea=cut_ea,
                cut_edges=tuple(
                    NativeEdge(
                        NativeEdgeKind.INDIRECT,
                        target_ea,
                        resolver_proven=True,
                        provenance="runtime_test",
                        source_instruction_ea=cut_ea,
                    )
                    for target_ea in target_eas
                ),
            ),
            **{
                target_ea: NativeFlowBlockFact(
                    start_ea=target_ea,
                    end_ea=target_ea + 1,
                    is_return_tail=True,
                    terminal_instruction_ea=target_ea,
                )
                for target_ea in target_eas
            },
        }
        monkeypatch.setattr(
            native_backend,
            "_flowchart_facts",
            lambda *_args, **_kwargs: facts,
        )

        result = build_native_semantic_cfg(
            SimpleNamespace(start_ea=source_ea),
            live_native_eas=(),
            seed_eas=(source_ea,),
            resolver_cut_eas=(cut_ea,),
            resolver_target_eas_by_source={cut_ea: target_eas},
        )

        assert set(result.cfg.blocks_by_ea) == {source_ea, *target_eas}
        assert not result.abstentions

    def test_resolver_proven_entry_splits_stale_flowchart_owner(
        self,
        monkeypatch,
    ) -> None:
        function_ea = 0x401000
        stale_entry_ea = 0x401010
        resolver_entry_ea = 0x401011
        stale_end_ea = 0x401030
        facts = {
            function_ea: NativeFlowBlockFact(
                start_ea=function_ea,
                end_ea=stale_entry_ea,
                successor_eas=(stale_entry_ea,),
            ),
            stale_entry_ea: NativeFlowBlockFact(
                start_ea=stale_entry_ea,
                end_ea=stale_end_ea,
                is_return_tail=True,
                terminal_instruction_ea=stale_end_ea - 1,
            ),
        }
        decoded = {
            stale_entry_ea: NativeFlowBlockFact(
                start_ea=stale_entry_ea,
                end_ea=resolver_entry_ea,
                force_stop=True,
                terminal_instruction_ea=stale_entry_ea,
            ),
            resolver_entry_ea: NativeFlowBlockFact(
                start_ea=resolver_entry_ea,
                end_ea=stale_end_ea,
                is_return_tail=True,
                terminal_instruction_ea=stale_end_ea - 1,
            ),
        }
        monkeypatch.setattr(
            native_backend,
            "_flowchart_facts",
            lambda *_args, **_kwargs: facts,
        )
        monkeypatch.setattr(
            native_backend,
            "_decode_missing_flow_block",
            lambda *_args, start_ea, **_kwargs: decoded[int(start_ea)],
        )

        result = build_native_semantic_cfg(
            SimpleNamespace(start_ea=function_ea),
            live_native_eas=(),
            seed_eas=(function_ea, resolver_entry_ea),
            resolver_target_eas_by_source={},
            resolver_proven_unmarked_entry_eas=(resolver_entry_ea,),
        )

        owners = tuple(
            block
            for block in result.cfg.blocks_by_ea.values()
            if block.start_ea <= resolver_entry_ea < block.end_ea
        )
        assert tuple(
            (block.start_ea, block.end_ea) for block in owners
        ) == ((resolver_entry_ea, stale_end_ea),)

    def test_discovered_successor_splits_stale_flowchart_owner(
        self,
        monkeypatch,
    ) -> None:
        function_ea = 0x401000
        stale_entry_ea = 0x401010
        discovered_entry_ea = 0x401020
        stale_end_ea = 0x401030
        facts = {
            function_ea: NativeFlowBlockFact(
                start_ea=function_ea,
                end_ea=function_ea,
            ),
            stale_entry_ea: NativeFlowBlockFact(
                start_ea=stale_entry_ea,
                end_ea=stale_end_ea,
                is_return_tail=True,
                terminal_instruction_ea=stale_end_ea - 1,
            ),
        }
        decoded = {
            function_ea: NativeFlowBlockFact(
                start_ea=function_ea,
                end_ea=stale_entry_ea,
                successor_eas=(discovered_entry_ea,),
                direct_branch_target_ea=discovered_entry_ea,
            ),
            stale_entry_ea: NativeFlowBlockFact(
                start_ea=stale_entry_ea,
                end_ea=discovered_entry_ea,
                successor_eas=(discovered_entry_ea,),
            ),
            discovered_entry_ea: NativeFlowBlockFact(
                start_ea=discovered_entry_ea,
                end_ea=stale_end_ea,
                is_return_tail=True,
                terminal_instruction_ea=stale_end_ea - 1,
            ),
        }
        monkeypatch.setattr(
            native_backend,
            "_flowchart_facts",
            lambda *_args, **_kwargs: facts,
        )
        monkeypatch.setattr(
            native_backend,
            "_decode_missing_flow_block",
            lambda *_args, start_ea, **_kwargs: decoded[int(start_ea)],
        )

        result = build_native_semantic_cfg(
            SimpleNamespace(start_ea=function_ea),
            live_native_eas=(),
            seed_eas=(function_ea, stale_entry_ea),
            resolver_target_eas_by_source={},
        )

        owners = tuple(
            block
            for block in result.cfg.blocks_by_ea.values()
            if block.start_ea <= discovered_entry_ea < block.end_ea
        )
        assert tuple(
            (block.start_ea, block.end_ea) for block in owners
        ) == ((discovered_entry_ea, stale_end_ea),)

    def test_non_code_seed_abstains_with_exact_native_ea(
        self,
        ida_database,
    ) -> None:
        function = _function("lab_asm_branch")
        non_code_ea = _find_non_code_ea()

        result = build_native_semantic_cfg(
            function,
            live_native_eas=(non_code_ea,),
            seed_eas=(non_code_ea,),
            resolver_target_eas_by_source={},
        )

        assert non_code_ea not in result.cfg.blocks_by_ea
        assert len(result.abstentions) == 1
        abstention = result.abstentions[0]
        assert abstention.reason is (
            NativeCfgDecodeAbstentionReason.NON_CODE_OR_FOREIGN_FUNCTION
        )
        assert abstention.entry_ea == non_code_ea
        assert abstention.cursor_ea == non_code_ea

    def test_resolver_proven_unmarked_entry_decodes_native_bytes(
        self,
        ida_database,
        monkeypatch,
    ) -> None:
        function = _function("lab_if_diamond")
        seed_ea = int(function.start_ea)
        original_is_code = native_backend._is_code
        monkeypatch.setattr(
            native_backend,
            "_is_code",
            lambda ea: False if int(ea) == seed_ea else original_is_code(ea),
        )

        result = build_native_semantic_cfg(
            function,
            live_native_eas=(),
            seed_eas=(seed_ea,),
            resolver_target_eas_by_source={},
            resolver_proven_unmarked_entry_eas=(seed_ea,),
        )

        assert seed_ea in result.cfg.blocks_by_ea
        assert not result.abstentions
