"""Native Hex-Rays acceptance coverage for call-result predicate retention."""

from __future__ import annotations

from pathlib import Path

import ida_hexrays
import idaapi
import ida_bytes
import idc

from d810.analyses.value_flow import CALL_RETURN_VALUE_FACT_TYPE
from d810.analyses.value_flow.model import FactStatus, FactMapping, ValidatedFactView
from d810.analyses.value_flow.observation import FactObservation
from d810.backends.ast import z3 as z3_backend
from d810.core.observability import reset_diagnostic_bus, subscribe, unsubscribe
from d810.core.observability_events import Z3PredicateProofObserved
from d810.evaluator.hexrays_microcode import def_search
from d810.optimizers.microcode.instructions.z3 import handler as z3_handler
from d810.hexrays.utils.hexrays_formatters import format_minsn_t
from d810.hexrays.ir.minsn_utils import minsn_to_ast
from tests.system.runtime.conftest import gen_microcode_at_maturity


class TestCallResultPredicateRegression:
    # Fixture acceptance is authoritative only against the shared corpus.
    binary_name = "libobfuscated.dll"

    @staticmethod
    def _project_index(state):
        for index, project in enumerate(state.project_manager.projects()):
            if project.path.name == "call_result_predicate_acceptance.json":
                return index
        from d810.core.config import ProjectConfiguration

        config_path = (
            Path(__file__).resolve().parents[4]
            / "src/d810/conf/call_result_predicate_acceptance.json"
        )
        project = ProjectConfiguration.from_file(config_path)
        state.project_manager.update("default_instruction_only.json", project)
        return state.project_manager.index(config_path.name)

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
        normalized = {
            line.replace(" ", "").replace(",", "").lower() for line in disassembly
        }
        assert "shr ecx,0ah".replace(" ", "").replace(",", "") in normalized
        assert "shr eax,6".replace(" ", "").replace(",", "") in normalized
        assert "and eax,1".replace(" ", "").replace(",", "") in normalized
        assert "cmp eax,0".replace(" ", "").replace(",", "") in normalized
        assert "setnz dl".replace(" ", "").replace(",", "") in normalized
        assert "movzx edx,dl".replace(" ", "").replace(",", "") in normalized

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
        condition = self._branch_condition(block, branch)
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
        condition = self._branch_condition(block, branch)
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
        self, libobfuscated_setup, d810_state
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
        # Build one untouched native MBA/candidate per fact case.  Each callback
        # must own its candidate so a decisive rewrite cannot affect the next
        # fact's production result.
        case_mbas = {
            kind: gen_microcode_at_maturity(function_ea, ida_hexrays.MMAT_CALLS)
            for kind in (
                "none",
                "zero",
                "one",
                "stale",
                "malformed",
                "conflicting",
                "carrier",
                "empty",
            )
        }
        assert all(case_mbas.values())
        with d810_state() as state:
            state.load_project(self._project_index(state))
            state.start_d810()
            manager = state.manager.instruction_optimizer
            previous = manager._validated_fact_view_provider
            provider_calls = []
            proof_events = []
            production_refiner_calls = []
            production_decisions = []
            current_case = {"value": None}
            z3_construction_counts = {}
            real_refine_call_result = z3_handler.refine_call_result
            real_decide_zero_status = z3_backend.decide_zero_status
            real_make_z3_mop_prover = z3_handler.Z3Rule.make_z3_mop_prover
            real_create_z3_vars = z3_backend.create_z3_vars
            real_ast_node_z3_visitor = z3_backend.AstNodeZ3Visitor
            real_new_query_solver = z3_backend._new_query_solver
            production_rule_views = []

            def recording_refine_call_result(query, view):
                result = real_refine_call_result(query, view)
                production_refiner_calls.append(
                    {
                        "case": current_case["value"],
                        "call_ea": int(query.call_ea),
                        "width": int(query.result_width_bits),
                        "fact_ids": tuple(
                            sorted(
                                str(observation.fact_id)
                                for observation in getattr(
                                    view, "active_observations", ()
                                )
                            )
                        ),
                        "status": result.status.value,
                    }
                )
                return result

            def recording_decide_zero_status(root):
                decision = real_decide_zero_status(root)
                production_decisions.append(
                    {
                        "case": current_case["value"],
                        "ast": str(root),
                        "status": decision.value,
                    }
                )
                return decision

            def recording_make_z3_mop_prover(rule, **kwargs):
                production_rule_views.append(
                    {
                        "case": current_case["value"],
                        "rule": type(rule).__name__,
                        "view": type(rule.validated_fact_view).__name__
                        if rule.validated_fact_view is not None
                        else None,
                        "fact_ids": tuple(
                            sorted(
                                str(observation.fact_id)
                                for observation in getattr(
                                    rule.validated_fact_view,
                                    "active_observations",
                                    (),
                                )
                            )
                        ),
                    }
                )
                return real_make_z3_mop_prover(rule, **kwargs)

            def recording_create_z3_vars(*args, **kwargs):
                z3_construction_counts[current_case["value"]]["create_z3_vars"] += 1
                return real_create_z3_vars(*args, **kwargs)

            class RecordingAstNodeZ3Visitor(real_ast_node_z3_visitor):
                def __init__(self, *args, **kwargs):
                    z3_construction_counts[current_case["value"]][
                        "AstNodeZ3Visitor"
                    ] += 1
                    super().__init__(*args, **kwargs)

            def recording_new_query_solver(*args, **kwargs):
                z3_construction_counts[current_case["value"]][
                    "_new_query_solver"
                ] += 1
                return real_new_query_solver(*args, **kwargs)

            z3_handler.refine_call_result = recording_refine_call_result
            z3_backend.decide_zero_status = recording_decide_zero_status
            z3_handler.Z3Rule.make_z3_mop_prover = recording_make_z3_mop_prover
            z3_backend.create_z3_vars = recording_create_z3_vars
            z3_backend.AstNodeZ3Visitor = RecordingAstNodeZ3Visitor
            z3_backend._new_query_solver = recording_new_query_solver
            reset_diagnostic_bus()
            subscribe(Z3PredicateProofObserved, proof_events.append)
            production_rule_outcomes = {}
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
                    current_case["value"] = kind

                    def provider(_function_ea, _maturity, *, _kind=kind):
                        provider_calls.append(_kind)
                        return self._fact_view(
                            _kind, call_ea=call_ea, callee_ea=helper_ea
                        )

                    manager.configure_validated_fact_view_provider(provider)
                    case_mba = case_mbas[kind]
                    setnz_block, setnz_instruction = self._find_nested_opcode(
                        case_mba, ida_hexrays.m_setnz
                    )
                    assert setnz_block is not None and setnz_instruction is not None
                    z3_construction_counts[kind] = {
                        "create_z3_vars": 0,
                        "AstNodeZ3Visitor": 0,
                        "_new_query_solver": 0,
                    }
                    before_opcode = setnz_instruction.opcode
                    before_text = format_minsn_t(setnz_instruction)
                    callback_result = manager.func(setnz_block, setnz_instruction)
                    production_rule_outcomes[kind] = callback_result
                    after_text = format_minsn_t(setnz_instruction)
                    if kind in ("zero", "one"):
                        assert callback_result is True
                        assert setnz_instruction.opcode == ida_hexrays.m_mov
                        assert setnz_instruction.l.t == ida_hexrays.mop_n
                        assert setnz_instruction.l.nnn.value == (0 if kind == "zero" else 1)
                    else:
                        assert callback_result is False
                        assert setnz_instruction.opcode == before_opcode
                        assert after_text == before_text

                manager.configure_validated_fact_view_provider(
                    lambda _function_ea, _maturity: ValidatedFactView(
                        maturity="MMAT_CALLS"
                    )
                )
                current_case["value"] = "empty"
                empty_mba = case_mbas["empty"]
                empty_setnz_block, empty_setnz_instruction = self._find_nested_opcode(
                    empty_mba, ida_hexrays.m_setnz
                )
                assert (
                    empty_setnz_block is not None
                    and empty_setnz_instruction is not None
                )
                z3_construction_counts["empty"] = {
                    "create_z3_vars": 0,
                    "AstNodeZ3Visitor": 0,
                    "_new_query_solver": 0,
                }
                empty_before_opcode = empty_setnz_instruction.opcode
                empty_before_text = format_minsn_t(empty_setnz_instruction)
                production_rule_outcomes["empty"] = manager.func(
                    empty_setnz_block, empty_setnz_instruction
                )
                assert production_rule_outcomes["empty"] is False
                assert empty_setnz_instruction.opcode == empty_before_opcode
                assert format_minsn_t(empty_setnz_instruction) == empty_before_text
            finally:
                manager.configure_validated_fact_view_provider(previous)
                z3_handler.refine_call_result = real_refine_call_result
                z3_backend.decide_zero_status = real_decide_zero_status
                z3_handler.Z3Rule.make_z3_mop_prover = real_make_z3_mop_prover
                z3_backend.create_z3_vars = real_create_z3_vars
                z3_backend.AstNodeZ3Visitor = real_ast_node_z3_visitor
                z3_backend._new_query_solver = real_new_query_solver
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
                "proof_events="
                + repr([(event.operation, event.status.name) for event in proof_events])
            )
            print("production_refiner_calls=" + repr(production_refiner_calls))
            print(
                "production_rule_views="
                + repr(
                    sorted(
                        set(tuple(record.items()) for record in production_rule_views)
                    )
                )
            )
            print(
                "production_decisions="
                + repr(
                    {
                        case: sorted(
                            {
                                record["status"]
                                for record in production_decisions
                                if record["case"] == case and "0x40" in record["ast"]
                            }
                        )
                        for case in ("none", "zero", "one", "empty")
                    }
                )
            )
            print("production_rule_outcomes=" + repr(production_rule_outcomes))
            print("z3_construction_counts=" + repr(z3_construction_counts))
            assert production_rule_outcomes["none"] is False
            assert production_rule_outcomes["zero"] is True
            assert production_rule_outcomes["one"] is True
            for kind in ("stale", "malformed", "conflicting", "carrier", "empty"):
                assert production_rule_outcomes[kind] is False
            relevant_refiners = [
                record
                for record in production_refiner_calls
                if record["case"] in ("none", "zero", "one", "empty")
                and record["call_ea"] == call_ea
            ]
            assert relevant_refiners
            assert any(
                record["case"] == "zero"
                and record["status"] == "refined"
                and record["fact_ids"] == ("known-zero",)
                for record in relevant_refiners
            )
            assert any(
                record["case"] == "one"
                and record["status"] == "refined"
                and record["fact_ids"] == ("known-one",)
                for record in relevant_refiners
            )
            assert not any(
                record["case"] == "empty" and record["status"] == "refined"
                for record in relevant_refiners
            )
            zero_decisions = {
                record["status"]
                for record in production_decisions
                if record["case"] == "zero" and "0x40" in record["ast"]
            }
            one_decisions = {
                record["status"]
                for record in production_decisions
                if record["case"] == "one" and "0x40" in record["ast"]
            }
            empty_decisions = {
                record["status"]
                for record in production_decisions
                if record["case"] == "empty" and "0x40" in record["ast"]
            }
            assert "always_zero" in zero_decisions
            assert "always_nonzero" in one_decisions
            assert empty_decisions == {"unknown"}
            assert z3_construction_counts["zero"] == {
                "create_z3_vars": 0,
                "AstNodeZ3Visitor": 0,
                "_new_query_solver": 0,
            }
            assert z3_construction_counts["one"] == {
                "create_z3_vars": 0,
                "AstNodeZ3Visitor": 0,
                "_new_query_solver": 0,
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

    @staticmethod
    def _find_nested_opcode(mba, opcode):
        """Find an opcode in native instructions and nested minsn operands."""
        for serial in range(mba.qty):
            block = mba.get_mblock(serial)
            instruction = None if block is None else block.head
            seen = set()
            while instruction is not None:
                stack = [instruction]
                while stack:
                    candidate = stack.pop()
                    if candidate is None or id(candidate) in seen:
                        continue
                    seen.add(id(candidate))
                    if candidate.opcode == opcode:
                        return block, candidate
                    for mop in (
                        getattr(candidate, "l", None),
                        getattr(candidate, "r", None),
                        getattr(candidate, "d", None),
                    ):
                        nested = getattr(mop, "d", None)
                        if nested is not None:
                            stack.append(nested)
                instruction = instruction.next
        return None, None

    @staticmethod
    def _branch_condition(block, branch):
        """Return the expression minsn that materializes a native JNZ value."""
        if branch.l.t == ida_hexrays.mop_d:
            return branch.l.d
        target = getattr(branch.l, "r", None)
        candidate = block.head
        last = None
        while candidate is not None and candidate != branch:
            destination = getattr(candidate, "d", None)
            if (
                destination is not None
                and getattr(destination, "t", None) == ida_hexrays.mop_r
                and getattr(destination, "r", None) == target
            ):
                last = candidate
            candidate = candidate.next
        return last if last is not None else branch
