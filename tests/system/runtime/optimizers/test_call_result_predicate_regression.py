"""Native Hex-Rays acceptance coverage for call-result predicate retention."""

from __future__ import annotations

import os

import ida_hexrays
import idaapi
import ida_bytes
import idc

from d810.analyses.value_flow import CALL_RETURN_VALUE_FACT_TYPE
from d810.analyses.value_flow.model import FactStatus, FactMapping, ValidatedFactView
from d810.analyses.value_flow.observation import FactObservation
from d810.evaluator.hexrays_microcode import def_search
from d810.hexrays.utils.hexrays_formatters import format_minsn_t
from d810.hexrays.ir.minsn_utils import minsn_to_ast
from tests.system.runtime.conftest import gen_microcode_at_maturity


class TestCallResultPredicateRegression:
    binary_name = os.getenv("D810_TEST_BINARY", "libobfuscated_fixturetest.dll")

    @staticmethod
    def _project_index(state):
        return next(
            index
            for index, project in enumerate(state.project_manager.projects())
            if project.path.name == "eidolon_v3_const_solve.json"
        )

    def test_native_fixture_exposes_required_chain(self, libobfuscated_setup):
        function_ea = idc.get_name_ea_simple("call_result_predicate_fixture")
        assert function_ea != idaapi.BADADDR
        helper_ea = idc.get_name_ea_simple("call_result_predicate_helper")
        assert helper_ea != idaapi.BADADDR
        mba = gen_microcode_at_maturity(function_ea, ida_hexrays.MMAT_CALLS)
        assert mba is not None
        lines = []
        assignments = []
        for serial in range(mba.qty):
            block = mba.get_mblock(serial)
            instruction = None if block is None else block.head
            while instruction is not None:
                lines.append(f"blk{serial}: {format_minsn_t(instruction)}")
                if def_search._call_result_assignment(instruction) is not None:
                    assignments.append((block, instruction))
                instruction = instruction.next
        print("\n" + "\n".join(lines))
        assert assignments, "native MBA did not expose assigned call result"
        block, assignment = assignments[0]
        nested_call, destination = def_search._call_result_assignment(assignment)
        assert destination.t == ida_hexrays.mop_r
        assert destination.size == 8
        assert nested_call.opcode == ida_hexrays.m_call
        assert nested_call.d.t == ida_hexrays.mop_f
        assert def_search._call_result_callee_ea(assignment) == helper_ea
        assert any("0xA" in line and "0x6" not in line for line in lines)
        # Hex-Rays canonicalizes ``(eax >> 6) & 1`` to the equivalent 0x40
        # mask at MMAT_CALLS; the decoy ECX shift remains visible as 0xA.
        assert any("0x40" in line for line in lines)
        assert any("xdu" in line and "dword_" in line for line in lines)
        later_writes = [
            instruction
            for serial in range(mba.qty)
            for instruction in self._instructions(mba, serial)
            if instruction.ea > assignment.ea
            and getattr(instruction, "d", None) is not None
            and instruction.d.t == ida_hexrays.mop_r
            and instruction.d.r == destination.r
        ]
        assert later_writes, "native fixture did not expose a later EAX write"
        assert any(
            "dword_" in format_minsn_t(instruction) for instruction in later_writes
        )
        function = idaapi.get_func(function_ea)
        disassembly = []
        address = function.start_ea
        while address < function.end_ea:
            disassembly.append(
                f"{idc.print_insn_mnem(address)} "
                f"{idc.print_operand(address, 0)}, {idc.print_operand(address, 1)}"
            )
            address = ida_bytes.next_head(address, function.end_ea)
        normalized = {line.replace(" ", "").lower() for line in disassembly}
        assert "shr ecx,0ah".replace(" ", "") in normalized
        assert "shr eax,6".replace(" ", "") in normalized
        assert "and eax,1".replace(" ", "") in normalized

    def test_native_no_fact_production_route_retains_branch_and_later_load(
        self, libobfuscated_setup, d810_state, pseudocode_to_string
    ):
        with d810_state() as state:
            state.load_project(self._project_index(state))
            state.start_d810()
            function_ea = idc.get_name_ea_simple("call_result_predicate_fixture")
            cfunc = idaapi.decompile(function_ea, flags=idaapi.DECOMP_NO_CACHE)
            assert cfunc is not None
            code = pseudocode_to_string(cfunc.get_pseudocode())
            print(code)
            assert "0x12345678" in code
            assert "if" in code

    def test_native_resolver_returns_call_definition_not_later_eax_write(
        self, libobfuscated_setup
    ):
        function_ea = idc.get_name_ea_simple("call_result_predicate_fixture")
        mba = gen_microcode_at_maturity(function_ea, ida_hexrays.MMAT_CALLS)
        assert mba is not None
        branch = None
        block = None
        for serial in range(mba.qty):
            candidate_block = mba.get_mblock(serial)
            for instruction in self._instructions(mba, serial):
                if instruction.opcode == ida_hexrays.m_jnz:
                    branch = instruction
                    block = candidate_block
                    break
            if branch is not None:
                break
        assert branch is not None and block is not None
        # The branch itself is a control-flow opcode; its xdu condition is the
        # native expression-bearing minsn accepted by the AST adapter.
        condition = branch.l.d if branch.l.t == ida_hexrays.mop_d else branch
        ast = minsn_to_ast(condition)
        assert ast is not None
        resolved = def_search.recursively_resolve_ast(ast, block, branch)

        leaves = []
        stack = [resolved]
        while stack:
            node = stack.pop()
            if node is None:
                continue
            if def_search.is_call_result_leaf(node):
                leaves.append(node)
            for attribute in ("left", "right", "dst"):
                child = getattr(node, attribute, None)
                if child is not None:
                    stack.append(child)
        assert leaves, "resolver did not retain the assigned call-result leaf"
        nested_call, _destination = def_search._call_result_assignment(
            next(
                instruction
                for serial in range(mba.qty)
                for instruction in self._instructions(mba, serial)
                if def_search._call_result_assignment(instruction) is not None
            )
        )
        assert all(leaf.value_ref.def_site == nested_call.ea for leaf in leaves)
        assert not any("12345678" in str(leaf.name) for leaf in leaves)

    def test_native_fact_view_uses_production_manager_route(
        self, libobfuscated_setup, d810_state, pseudocode_to_string
    ):
        function_ea = idc.get_name_ea_simple("call_result_predicate_fixture")
        mba = gen_microcode_at_maturity(function_ea, ida_hexrays.MMAT_CALLS)
        assert mba is not None
        assignment = next(
            instruction
            for serial in range(mba.qty)
            for instruction in self._instructions(mba, serial)
            if def_search._call_result_assignment(instruction) is not None
        )
        nested_call, _destination = def_search._call_result_assignment(assignment)
        call_ea = int(nested_call.ea)
        helper_ea = idc.get_name_ea_simple("call_result_predicate_helper")

        with d810_state() as state:
            state.load_project(self._project_index(state))
            state.start_d810()
            manager = state.manager.instruction_optimizer
            previous = manager._validated_fact_view_provider
            provider_calls = []
            try:
                for kind in (
                    "none",
                    "zero",
                    "one",
                    "stale",
                    "malformed",
                    "conflicting",
                    "carrier",
                ):

                    def provider(_function_ea, _maturity, *, _kind=kind):
                        provider_calls.append(_kind)
                        return self._fact_view(
                            _kind, call_ea=call_ea, callee_ea=helper_ea
                        )

                    manager.configure_validated_fact_view_provider(provider)
                    cfunc = idaapi.decompile(function_ea, flags=idaapi.DECOMP_NO_CACHE)
                    assert cfunc is not None
                    code = pseudocode_to_string(cfunc.get_pseudocode())
                    print(f"{kind}:\n{code}")
                    if kind in {"none", "stale", "malformed", "conflicting", "carrier"}:
                        assert "if" in code and "0x12345678" in code
                    else:
                        assert "if" in code or "return 0;" in code
            finally:
                manager.configure_validated_fact_view_provider(previous)
            assert set(provider_calls) == {
                "none",
                "zero",
                "one",
                "stale",
                "malformed",
                "conflicting",
                "carrier",
            }

    @staticmethod
    def _fact_view(kind, *, call_ea, callee_ea):
        if kind == "none":
            return ValidatedFactView(maturity="MMAT_CALLS")

        def observation(fact_id, evidence):
            return FactObservation(
                fact_id=fact_id,
                kind=CALL_RETURN_VALUE_FACT_TYPE,
                semantic_key=f"call:{call_ea:x}",
                maturity="MMAT_CALLS",
                phase="value-flow",
                confidence=1.0,
                source_ea=call_ea,
                payload={
                    "lifecycle_status": "production_proven",
                    "source_identity": {"call_ea": call_ea},
                    "call_return_value": {
                        "schema_version": 1,
                        "call_ea": call_ea,
                        "callee_ea": callee_ea,
                        "result_width_bits": 64,
                        "argument_fingerprint": None,
                        "evidence": evidence,
                    },
                },
            )

        if kind == "zero":
            observations = (
                observation(
                    "known-zero",
                    {"kind": "known_bits", "known_zero": 0x40, "known_one": 0},
                ),
            )
        elif kind == "one":
            observations = (
                observation(
                    "known-one",
                    {"kind": "known_bits", "known_zero": 0, "known_one": 0x40},
                ),
            )
        elif kind == "stale":
            observations = (
                observation(
                    "stale", {"kind": "known_bits", "known_zero": 0, "known_one": 0x40}
                ),
            )
            return ValidatedFactView(
                maturity="MMAT_CALLS",
                observations=observations,
                mappings=(
                    FactMapping(
                        "stale",
                        "MMAT_PREOPTIMIZED",
                        "MMAT_CALLS",
                        FactStatus.STALE,
                        1.0,
                    ),
                ),
            )
        elif kind == "malformed":
            observations = (
                observation(
                    "malformed",
                    {"kind": "known_bits", "known_zero": 0x40, "known_one": 0x40},
                ),
            )
        elif kind == "conflicting":
            observations = (
                observation("conflict-zero", {"kind": "exact", "value": 0}),
                observation("conflict-one", {"kind": "exact", "value": 1}),
            )
        elif kind == "carrier":
            observations = (
                FactObservation(
                    fact_id="legacy-carrier",
                    kind=CALL_RETURN_VALUE_FACT_TYPE,
                    semantic_key="carrier",
                    maturity="MMAT_CALLS",
                    phase="value-flow",
                    confidence=1.0,
                    source_ea=call_ea,
                    payload={
                        "lifecycle_status": "production_proven",
                        "source_identity": {"call_ea": call_ea},
                        "details": {"carrier_class": "PASSWORD_COMPARE_RESULT"},
                    },
                ),
            )
        else:
            raise AssertionError(kind)
        return ValidatedFactView(maturity="MMAT_CALLS", observations=observations)

    @staticmethod
    def _instructions(mba, serial):
        block = mba.get_mblock(serial)
        instruction = None if block is None else block.head
        while instruction is not None:
            yield instruction
            instruction = instruction.next
