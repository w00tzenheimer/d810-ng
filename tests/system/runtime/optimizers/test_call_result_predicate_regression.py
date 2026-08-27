"""Native Hex-Rays acceptance coverage for call-result predicate retention."""

from __future__ import annotations

import os
from functools import partial

import ida_hexrays
import idaapi
import ida_bytes
import idc

from d810.analyses.value_flow import CALL_RETURN_VALUE_FACT_TYPE
from d810.analyses.value_flow.model import FactStatus, FactMapping, ValidatedFactView
from d810.analyses.value_flow.observation import FactObservation
from d810.analyses.value_flow.call_return_value import refine_call_result
from d810.backends.ast import z3 as z3_backend
from d810.core.observability import reset_diagnostic_bus, subscribe, unsubscribe
from d810.core.observability_events import Z3PredicateProofObserved
from d810.core.z3_proof import Z3ProofStatus
from d810.evaluator.hexrays_microcode import def_search
from d810.evaluator.hexrays_microcode.abstract_ast import decide_zero_status
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
            if project.path.name == "default_instruction_only.json"
        )

    def test_native_fixture_exposes_required_chain(self, libobfuscated_setup):
        fixture_path = libobfuscated_setup.get(
            "binary_path", idaapi.get_root_filename()
        )
        print(
            "fixture_binary={} backend={}".format(
                fixture_path, def_search.get_recursive_resolver_backend()
            )
        )
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
        assert "cmp eax,0".replace(" ", "") in normalized

    def test_native_no_fact_production_route_retains_branch_and_later_load(
        self, libobfuscated_setup
    ):
        function_ea = idc.get_name_ea_simple("call_result_predicate_fixture")
        mba = gen_microcode_at_maturity(function_ea, ida_hexrays.MMAT_CALLS)
        assert mba is not None
        branch = next(
            instruction
            for serial in range(mba.qty)
            for instruction in self._instructions(mba, serial)
            if instruction.opcode == ida_hexrays.m_jnz
        )
        block = next(
            mba.get_mblock(serial)
            for serial in range(mba.qty)
            if any(
                instruction.ea == branch.ea and instruction.opcode == ida_hexrays.m_jnz
                for instruction in self._instructions(mba, serial)
            )
        )
        condition = branch.l.d if branch.l.t == ida_hexrays.mop_d else branch
        ast = minsn_to_ast(condition)
        assert ast is not None
        resolved = def_search.recursively_resolve_ast(ast, block, branch)
        assert resolved is not None
        assert "0x40" in str(resolved)
        assert any(
            def_search.is_call_result_leaf(node) for node in resolved.get_leaf_list()
        )
        assert any(
            "dword_" in format_minsn_t(instruction)
            for serial in range(mba.qty)
            for instruction in self._instructions(mba, serial)
            if instruction.opcode == ida_hexrays.m_xdu
        )
        print(f"no-fact-native-ast={resolved}")

    def test_native_resolver_terminal_guard_has_native_mutation_witness(
        self, libobfuscated_setup, monkeypatch
    ):
        function_ea = idc.get_name_ea_simple("call_result_predicate_fixture")
        mba = gen_microcode_at_maturity(function_ea, ida_hexrays.MMAT_CALLS)
        assert mba is not None
        branch = None
        block = None
        later_write = None
        later_block = None
        post_load = None
        for serial in range(mba.qty):
            candidate_block = mba.get_mblock(serial)
            for instruction in self._instructions(mba, serial):
                if instruction.opcode == ida_hexrays.m_jnz:
                    branch = instruction
                    block = candidate_block
                if (
                    instruction.opcode == ida_hexrays.m_xdu
                    and getattr(instruction, "d", None) is not None
                    and instruction.d.t == ida_hexrays.mop_r
                    and "dword_" in format_minsn_t(instruction)
                ):
                    later_write = instruction
                    later_block = candidate_block
                    post_load = instruction.next
            if branch is not None and later_write is not None:
                break
        assert branch is not None and block is not None
        assert (
            later_write is not None
            and later_block is not None
            and post_load is not None
        )
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

        # Re-run the production resolver on a native-owned call leaf while the
        # search anchor is after the materializable later EAX load.  The
        # terminal guard must preserve the call-site identity in both the
        # selected backend and the explicit Python implementation.
        call_leaf = leaves[0]
        guarded = def_search.recursively_resolve_ast(
            call_leaf.clone(), later_block, post_load
        )
        python_guarded = def_search._py_slow_recursively_resolve_ast(
            call_leaf.clone(), later_block, post_load
        )
        assert def_search.is_call_result_leaf(guarded)
        assert def_search.is_call_result_leaf(python_guarded)
        assert guarded.value_ref.def_site == nested_call.ea
        assert python_guarded.value_ref.def_site == nested_call.ea

        # Disable only terminal recognition.  The same native anchor must now
        # follow the later physical EAX definition and materialize its global
        # load, proving that the guard is load-bearing.
        original_is_call_result_leaf = def_search.is_call_result_leaf
        monkeypatch.setattr(def_search, "is_call_result_leaf", lambda _node: False)
        mutated = def_search.recursively_resolve_ast(
            call_leaf.clone(), later_block, post_load, cache={}
        )
        mutated_python = def_search._py_slow_recursively_resolve_ast(
            call_leaf.clone(), later_block, post_load, cache={}
        )
        assert mutated is not None and mutated_python is not None
        assert getattr(mutated, "ea", None) == later_write.ea
        assert getattr(mutated_python, "ea", None) == later_write.ea
        assert getattr(mutated, "opcode", None) == later_write.opcode
        assert getattr(mutated_python, "opcode", None) == later_write.opcode
        assert "dword_" in format_minsn_t(later_write)
        assert not original_is_call_result_leaf(mutated)
        assert not original_is_call_result_leaf(mutated_python)

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
        native_branch_instruction = next(
            instruction
            for serial in range(mba.qty)
            for instruction in self._instructions(mba, serial)
            if instruction.opcode == ida_hexrays.m_jnz
        )
        native_branch_block = next(
            mba.get_mblock(serial)
            for serial in range(mba.qty)
            if any(
                instruction.ea == native_branch_instruction.ea
                and instruction.opcode == ida_hexrays.m_jnz
                for instruction in self._instructions(mba, serial)
            )
        )
        native_branch_mop = native_branch_instruction.l
        native_condition = (
            native_branch_mop.d
            if native_branch_mop.t == ida_hexrays.mop_d
            else native_branch_instruction
        )
        assert native_branch_block is not None and native_condition is not None

        with d810_state() as state:
            state.load_project(self._project_index(state))
            state.start_d810()
            manager = state.manager.instruction_optimizer
            previous = manager._validated_fact_view_provider
            provider_calls = []
            proof_events = []
            reset_diagnostic_bus()
            subscribe(Z3PredicateProofObserved, proof_events.append)
            solver_calls = 0
            original_new_query_solver = z3_backend._new_query_solver

            def recording_new_query_solver(*args, **kwargs):
                nonlocal solver_calls
                solver_calls += 1
                return original_new_query_solver(*args, **kwargs)

            z3_backend._new_query_solver = recording_new_query_solver

            codes = {}
            direct_results = {}
            direct_solver_deltas = {}
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
                    native_kind_view = self._fact_view(
                        kind, call_ea=call_ea, callee_ea=helper_ea
                    )
                    native_ast = minsn_to_ast(native_condition)
                    assert native_ast is not None
                    native_resolved = def_search.recursively_resolve_ast(
                        native_ast,
                        native_branch_block,
                        native_branch_instruction,
                        cache={},
                        call_result_refiner=partial(
                            refine_call_result, view=native_kind_view
                        ),
                    )
                    solver_count_before_direct = solver_calls
                    direct_prover = z3_backend.Z3MopProver(
                        blk=native_branch_block,
                        ins=native_branch_instruction,
                        call_result_refiner=partial(
                            refine_call_result, view=native_kind_view
                        ),
                    )
                    direct_zero = direct_prover.prove_always_zero(native_branch_mop)
                    direct_nonzero = direct_prover.prove_always_nonzero(
                        native_branch_mop
                    )
                    direct_results[kind] = (direct_zero, direct_nonzero)
                    direct_solver_deltas[kind] = (
                        solver_calls - solver_count_before_direct
                    )
                    print(
                        "native_abstract="
                        + repr(
                            {
                                "kind": kind,
                                "status": decide_zero_status(native_resolved).value,
                                "ast": str(native_resolved),
                                "prove_zero": direct_zero.status.name,
                                "prove_nonzero": direct_nonzero.status.name,
                                "solver_delta": direct_solver_deltas[kind],
                            }
                        )
                    )
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
                    codes[kind] = code
                    print(
                        "oracle="
                        + repr(
                            {
                                "kind": kind,
                                "has_if": "if" in code,
                                "has_zero_arm": "0x12345678" in code,
                                "has_one_arm": "0xCAFEBABE" in code,
                            }
                        )
                    )
                manager.configure_validated_fact_view_provider(
                    lambda _function_ea, _maturity: ValidatedFactView(
                        maturity="MMAT_CALLS"
                    )
                )
                empty_view = manager._validated_fact_view_provider(
                    function_ea, "MMAT_CALLS"
                )
                empty_ast = minsn_to_ast(native_condition)
                assert empty_ast is not None
                empty_resolved = def_search.recursively_resolve_ast(
                    empty_ast,
                    native_branch_block,
                    native_branch_instruction,
                    cache={},
                    call_result_refiner=partial(refine_call_result, view=empty_view),
                )
                empty_prover = z3_backend.Z3MopProver(
                    blk=native_branch_block,
                    ins=native_branch_instruction,
                    call_result_refiner=partial(refine_call_result, view=empty_view),
                )
                empty_zero = empty_prover.prove_always_zero(native_branch_mop)
                empty_nonzero = empty_prover.prove_always_nonzero(native_branch_mop)
                print(
                    "always-empty-abstract="
                    + repr(
                        {
                            "status": decide_zero_status(empty_resolved).value,
                            "prove_zero": empty_zero.status.name,
                            "prove_nonzero": empty_nonzero.status.name,
                        }
                    )
                )
                assert empty_zero.status is Z3ProofStatus.DISPROVED
                assert empty_nonzero.status is Z3ProofStatus.DISPROVED
                assert (empty_zero, empty_nonzero) != direct_results["zero"]
                assert (empty_zero, empty_nonzero) != direct_results["one"]
                empty_cfunc = idaapi.decompile(
                    function_ea, flags=idaapi.DECOMP_NO_CACHE
                )
                assert empty_cfunc is not None
                empty_code = pseudocode_to_string(empty_cfunc.get_pseudocode())
                print(f"always-empty-provider:\n{empty_code}")
                codes["empty"] = empty_code
            finally:
                manager.configure_validated_fact_view_provider(previous)
                z3_backend._new_query_solver = original_new_query_solver
                unsubscribe(Z3PredicateProofObserved, proof_events.append)
            assert set(provider_calls) == {
                "none",
                "zero",
                "one",
                "stale",
                "malformed",
                "conflicting",
                "carrier",
            }
            print(
                "codes_differ="
                + repr(
                    {
                        "zero_vs_none": codes["zero"] != codes["none"],
                        "one_vs_none": codes["one"] != codes["none"],
                    }
                )
            )
            print(
                "proof_events="
                + repr([(event.operation, event.status.name) for event in proof_events])
            )
            assert direct_results["none"][0].status is Z3ProofStatus.DISPROVED
            assert direct_results["none"][1].status is Z3ProofStatus.DISPROVED
            assert direct_results["zero"][0].status is Z3ProofStatus.PROVED
            assert direct_results["zero"][1].status is Z3ProofStatus.DISPROVED
            assert direct_results["one"][0].status is Z3ProofStatus.DISPROVED
            assert direct_results["one"][1].status is Z3ProofStatus.PROVED
            assert direct_solver_deltas["zero"] == 0
            assert direct_solver_deltas["one"] == 0
            for kind in ("stale", "malformed", "conflicting", "carrier"):
                assert direct_results[kind][0].status is Z3ProofStatus.DISPROVED
                assert direct_results[kind][1].status is Z3ProofStatus.DISPROVED
            assert direct_results["zero"] != direct_results["none"]
            assert direct_results["one"] != direct_results["none"]

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
