"""Unit tests for Z3MopProver API surface."""

from types import SimpleNamespace

import pytest

try:
    import z3

    Z3_AVAILABLE = True
except ImportError:
    Z3_AVAILABLE = False

try:
    import ida_hexrays

    IDA_AVAILABLE = True
except ImportError:
    IDA_AVAILABLE = False


@pytest.mark.skipif(not Z3_AVAILABLE, reason="z3 not installed")
@pytest.mark.skipif(not IDA_AVAILABLE, reason="IDA not available")
class TestZ3MopProverAPI:
    """Verify the Z3MopProver class exists and has the expected methods."""

    @staticmethod
    def _register_leaf(*, name, register=1, size=4, valnum=0):
        from d810.hexrays.expr.ast import AstLeaf
        from d810.hexrays.ir.mop_snapshot import MopSnapshot

        leaf = AstLeaf(name)
        leaf.mop = MopSnapshot(
            t=ida_hexrays.mop_r,
            size=size,
            valnum=valnum,
            reg=register,
        )
        leaf.dest_size = size
        return leaf

    def test_z3_vars_coalesce_independently_rebuilt_same_version_snapshots(self):
        """Independent AST rebuilds of one version share one symbolic input."""
        from d810.backends.ast.z3 import create_z3_vars

        left = self._register_leaf(name="left", register=3, valnum=17)
        right = self._register_leaf(name="right", register=3, valnum=17)

        variables = create_z3_vars([left, right])

        assert len(variables) == 1
        assert left.z3_var is right.z3_var

    def test_z3_vars_keep_distinct_register_versions_separate(self):
        """A new SSA version is not silently identified with its predecessor."""
        from d810.backends.ast.z3 import create_z3_vars

        first = self._register_leaf(name="first", register=3, valnum=17)
        second = self._register_leaf(name="second", register=3, valnum=18)

        variables = create_z3_vars([first, second])

        assert len(variables) == 2
        assert first.z3_var is not second.z3_var

    def test_z3_vars_keep_widths_separate_without_an_explicit_conversion(self):
        """The same register/version at different widths cannot share a BV."""
        from d810.backends.ast.z3 import create_z3_vars

        byte = self._register_leaf(name="byte", register=3, size=1, valnum=17)
        dword = self._register_leaf(name="dword", register=3, size=4, valnum=17)

        variables = create_z3_vars([byte, dword])

        assert len(variables) == 2
        assert byte.z3_var.size() == 8
        assert dword.z3_var.size() == 32
        assert byte.z3_var is not dword.z3_var

    def test_z3_vars_coalesce_only_explicit_proof_origins_for_unversioned_leaves(self):
        """Valnum-zero leaves need resolver-attested provenance to coalesce."""
        from d810.backends.ast.z3 import create_z3_vars

        left = self._register_leaf(name="left", register=3, valnum=0)
        right = self._register_leaf(name="right", register=3, valnum=0)
        left.proof_origin = ("scope", "entry", "r3", 4)
        right.proof_origin = ("scope", "entry", "r3", 4)

        variables = create_z3_vars([left, right])

        assert len(variables) == 1
        assert left.z3_var is right.z3_var

    def test_z3_vars_keep_unversioned_leaves_without_proof_origin_opaque(self):
        """Display/storage equality alone must not invent an unresolved alias."""
        from d810.backends.ast.z3 import create_z3_vars

        left = self._register_leaf(name="left", register=3, valnum=0)
        right = self._register_leaf(name="right", register=3, valnum=0)

        variables = create_z3_vars([left, right])

        assert len(variables) == 2

    def test_z3_vars_keep_shared_unversioned_snapshot_leaves_distinct(self):
        """A shared snapshot object is still not proof of a shared value."""
        from d810.backends.ast.z3 import create_z3_vars
        from d810.hexrays.expr.ast import AstLeaf
        from d810.hexrays.ir.mop_snapshot import MopSnapshot

        shared_snapshot = MopSnapshot(
            t=ida_hexrays.mop_r,
            size=4,
            valnum=0,
            reg=3,
        )
        left = AstLeaf("left")
        right = AstLeaf("right")
        left.mop = shared_snapshot
        right.mop = shared_snapshot
        left.dest_size = right.dest_size = 4

        variables = create_z3_vars([left, right])

        assert len(variables) == 2
        assert left.z3_var is not right.z3_var

    def test_z3_vars_coalesce_rebuilt_call_leaves_by_value_ref_at_valnum_zero(self):
        from d810.backends.ast.z3 import create_z3_vars
        from d810.analyses.data_flow.concolic.refs import LocationRef, ValueRef
        from d810.evaluator.hexrays_microcode.def_search import CallResultAstLeaf
        from d810.analyses.data_flow.concolic.values import ConcolicValue
        from d810.hexrays.ir.mop_snapshot import MopSnapshot

        value_ref = ValueRef(LocationRef.reg(3, 4), def_site=0x401000)
        left = CallResultAstLeaf("left", value_ref, ConcolicValue.top(32))
        right = CallResultAstLeaf(
            "right", ValueRef(LocationRef.reg(3, 4), def_site=0x401000), ConcolicValue.top(32)
        )
        left.mop = MopSnapshot(t=ida_hexrays.mop_r, size=4, reg=3, valnum=0)
        right.mop = MopSnapshot(t=ida_hexrays.mop_r, size=4, reg=3, valnum=0)
        left.dest_size = right.dest_size = 4

        variables = create_z3_vars([left, right])

        assert len(variables) == 1
        assert left.z3_var is right.z3_var

    def test_z3_vars_split_call_leaves_by_value_ref_def_site_despite_same_valnum(self):
        from d810.backends.ast.z3 import create_z3_vars
        from d810.analyses.data_flow.concolic.refs import LocationRef, ValueRef
        from d810.evaluator.hexrays_microcode.def_search import CallResultAstLeaf
        from d810.analyses.data_flow.concolic.values import ConcolicValue
        from d810.hexrays.ir.mop_snapshot import MopSnapshot

        def leaf(name, def_site):
            result = CallResultAstLeaf(
                name,
                ValueRef(LocationRef.reg(3, 4), def_site=def_site),
                ConcolicValue.top(32),
            )
            result.mop = MopSnapshot(t=ida_hexrays.mop_r, size=4, reg=3, valnum=9)
            result.dest_size = 4
            return result

        first = leaf("first", 0x401000)
        second = leaf("second", 0x402000)

        variables = create_z3_vars([first, second])

        assert len(variables) == 2
        assert first.z3_var is not second.z3_var

    def test_z3_vars_keep_complex_operands_opaque(self):
        """Complex mops do not acquire identity from a partial snapshot."""
        from d810.backends.ast.z3 import create_z3_vars
        from d810.hexrays.expr.ast import AstLeaf
        from d810.hexrays.ir.mop_snapshot import MopSnapshot

        left = AstLeaf("left")
        right = AstLeaf("right")
        left.mop = MopSnapshot(t=ida_hexrays.mop_d, size=4, valnum=0)
        right.mop = MopSnapshot(t=ida_hexrays.mop_d, size=4, valnum=0)
        left.dest_size = right.dest_size = 4

        variables = create_z3_vars([left, right])

        assert len(variables) == 2

    def test_prover_instantiation_no_context(self):
        from d810.backends.ast.z3 import Z3MopProver

        prover = Z3MopProver()
        assert prover is not None

    def test_prover_instantiation_with_context(self):
        from d810.backends.ast.z3 import Z3MopProver

        prover = Z3MopProver(blk=None, ins=None)
        assert prover is not None

    def test_prover_accepts_callback_local_call_result_refiner(self):
        from d810.backends.ast.z3 import Z3MopProver

        def refiner(query):
            return query
        prover = Z3MopProver(call_result_refiner=refiner)

        assert prover._call_result_refiner is refiner

    def test_no_fact_view_keeps_call_result_unconstrained(self):
        from d810.backends.ast.z3 import Z3MopProver

        prover = Z3MopProver(call_result_refiner=None)

        assert prover._call_result_refiner is None

    def test_assigned_call_leaf_without_view_is_top(self, monkeypatch):
        from d810.backends.ast import z3 as z3_backend
        from d810.evaluator.hexrays_microcode import def_search
        from d810.hexrays.expr.ast import AstLeaf
        from tests.system.runtime.evaluator.test_def_search_mop_snapshot import (
            _call_result_test_parts,
        )

        assignment, _call, _destination, block, use = _call_result_test_parts()
        monkeypatch.setattr(def_search, "find_def_in_block", lambda *_args: assignment)
        monkeypatch.setattr(
            def_search, "_materialize_mop_for_tracking", lambda mop, *_a, **_k: mop
        )
        monkeypatch.setattr(
            z3_backend, "mop_to_ast", lambda *_args, **_kwargs: AstLeaf("operand")
        )

        prepared = z3_backend.Z3MopProver()._prepare_single_ast(
            use,
            blk=block,
            ins=SimpleNamespace(ea=0x401100),
            operation="prove_always_zero",
        )

        assert prepared is not None
        _mop, leaf, _budget, _visitor_needs_budget = prepared
        assert def_search.is_call_result_leaf(leaf)
        assert leaf.concolic_value.status.name == "TOP"

    @staticmethod
    def _prepared_abstract_ast(value, *, mask=1, shift=6, width=32):
        from d810.evaluator.hexrays_microcode.def_search import CallResultAstLeaf
        from d810.analyses.data_flow.concolic.refs import LocationRef, ValueRef
        from d810.hexrays.ir.mop_snapshot import MopSnapshot
        from d810.hexrays.expr.ast import AstConstant, AstNode

        call_leaf = CallResultAstLeaf(
            "call-result",
            ValueRef(LocationRef.reg(0, width // 8), def_site=0x401000),
            value,
        )
        call_leaf.mop = MopSnapshot(
            t=ida_hexrays.mop_r, size=width // 8, reg=0
        )
        constant = AstConstant("mask", expected_value=mask, expected_size=width // 8)
        constant.mop = MopSnapshot(
            t=ida_hexrays.mop_n, size=width // 8, value=mask
        )
        shifted = AstNode(ida_hexrays.m_shr, call_leaf, AstConstant("shift", expected_value=shift, expected_size=width // 8))
        shifted.right.mop = MopSnapshot(t=ida_hexrays.mop_n, size=width // 8, value=shift)
        shifted.dest_size = width // 8
        root = AstNode(ida_hexrays.m_and, shifted, constant)
        root.dest_size = width // 8
        return root

    def test_known_call_bit_decides_predicate_without_z3_construction(self, monkeypatch):
        from d810.analyses.data_flow.concolic.abstract_evidence import AbstractEvidence
        from d810.analyses.data_flow.concolic.values import ConcolicValue, PrecisionStatus, reduce
        from d810.analyses.abstract_domains.known_bits import KnownBits
        from d810.analyses.abstract_domains.wrapped_interval import WrappedInterval
        from d810.backends.ast import z3 as z3_backend
        from d810.backends.ast.z3 import Z3MopProver
        from d810.backends.ast.z3_proof_policy import Z3ProofStatus

        width = 32
        value = reduce(ConcolicValue(
            None, None,
            AbstractEvidence(
                width,
                KnownBits(width, zero=((1 << width) - 1) ^ 0x40, one=0x40),
                WrappedInterval.top(width),
            ),
            width,
            PrecisionStatus.ABSTRACT,
        ))
        ast = self._prepared_abstract_ast(value, mask=1, shift=6)
        mop = SimpleNamespace(t=ida_hexrays.mop_r, size=4)
        monkeypatch.setattr(z3_backend.Z3MopProver, "_prepare_single_ast", lambda *_a, **_k: (mop, ast, None, False))
        counters = {"vars": 0, "visitor": 0, "solver": 0}
        monkeypatch.setattr(z3_backend, "create_z3_vars", lambda *_a, **_k: counters.__setitem__("vars", counters["vars"] + 1))
        monkeypatch.setattr(z3_backend, "AstNodeZ3Visitor", lambda *_a, **_k: counters.__setitem__("visitor", counters["visitor"] + 1))
        monkeypatch.setattr(z3_backend, "_new_query_solver", lambda *_a, **_k: counters.__setitem__("solver", counters["solver"] + 1))

        result = Z3MopProver().prove_always_nonzero(mop)
        opposite = Z3MopProver().prove_always_zero(mop)

        assert result.status is Z3ProofStatus.PROVED
        assert opposite.status is Z3ProofStatus.DISPROVED
        assert counters == {"vars": 0, "visitor": 0, "solver": 0}

    def test_exact_call_value_decides_predicate_without_z3_construction(self, monkeypatch):
        from d810.analyses.data_flow.concolic.values import ConcolicValue
        from d810.backends.ast import z3 as z3_backend
        from d810.backends.ast.z3 import Z3MopProver
        from d810.backends.ast.z3_proof_policy import Z3ProofStatus

        top_ast = self._prepared_abstract_ast(ConcolicValue.top(32), mask=1, shift=6)
        exact_ast = self._prepared_abstract_ast(ConcolicValue.of(0, 32), mask=1, shift=6)
        mop = SimpleNamespace(t=ida_hexrays.mop_r, size=4)
        current_ast = [top_ast]
        monkeypatch.setattr(z3_backend.Z3MopProver, "_prepare_single_ast", lambda *_a, **_k: (mop, current_ast[0], None, False))
        counters = {"vars": 0, "visitor": 0, "solver": 0}
        monkeypatch.setattr(z3_backend, "create_z3_vars", lambda *_a, **_k: counters.__setitem__("vars", counters["vars"] + 1))
        monkeypatch.setattr(z3_backend, "AstNodeZ3Visitor", lambda *_a, **_k: counters.__setitem__("visitor", counters["visitor"] + 1) or SimpleNamespace(visit=lambda _ast: z3_backend.z3.BitVec("call", 32)))
        monkeypatch.setattr(z3_backend, "_new_query_solver", lambda *_a, **_k: counters.__setitem__("solver", counters["solver"] + 1) or z3_backend.z3.Solver())

        prover = Z3MopProver(call_result_refiner=lambda _query: None)
        fallback = prover.prove_always_zero(mop)
        current_ast[0] = exact_ast
        result = prover.prove_always_zero(mop)

        assert result.status is Z3ProofStatus.PROVED
        assert fallback.status is Z3ProofStatus.DISPROVED
        assert counters == {"vars": 1, "visitor": 1, "solver": 1}

    def test_known_call_zero_bit_decides_predicate_without_z3_construction(self, monkeypatch):
        from d810.analyses.abstract_domains.known_bits import KnownBits
        from d810.analyses.abstract_domains.wrapped_interval import WrappedInterval
        from d810.analyses.data_flow.concolic.abstract_evidence import AbstractEvidence
        from d810.analyses.data_flow.concolic.values import ConcolicValue, PrecisionStatus, reduce
        from d810.backends.ast import z3 as z3_backend
        from d810.backends.ast.z3 import Z3MopProver
        from d810.backends.ast.z3_proof_policy import Z3ProofStatus

        value = reduce(ConcolicValue(
            None,
            None,
            AbstractEvidence(
                32,
                KnownBits(32, zero=0x40, one=0),
                WrappedInterval.top(32),
            ),
            32,
            PrecisionStatus.ABSTRACT,
        ))
        ast = self._prepared_abstract_ast(value, mask=1, shift=6)
        mop = SimpleNamespace(t=ida_hexrays.mop_r, size=4)
        monkeypatch.setattr(z3_backend.Z3MopProver, "_prepare_single_ast", lambda *_a, **_k: (mop, ast, None, False))
        counters = {"vars": 0, "visitor": 0, "solver": 0}
        monkeypatch.setattr(z3_backend, "create_z3_vars", lambda *_a, **_k: counters.__setitem__("vars", counters["vars"] + 1))
        monkeypatch.setattr(z3_backend, "AstNodeZ3Visitor", lambda *_a, **_k: counters.__setitem__("visitor", counters["visitor"] + 1))
        monkeypatch.setattr(z3_backend, "_new_query_solver", lambda *_a, **_k: counters.__setitem__("solver", counters["solver"] + 1))

        result = Z3MopProver().prove_always_zero(mop)
        opposite = Z3MopProver().prove_always_nonzero(mop)

        assert result.status is Z3ProofStatus.PROVED
        assert opposite.status is Z3ProofStatus.DISPROVED
        assert counters == {"vars": 0, "visitor": 0, "solver": 0}

    def test_indecisive_call_fact_falls_through_to_one_existing_z3_query(self, monkeypatch):
        from d810.analyses.abstract_domains.known_bits import KnownBits
        from d810.analyses.abstract_domains.wrapped_interval import WrappedInterval
        from d810.analyses.data_flow.concolic.abstract_evidence import AbstractEvidence
        from d810.analyses.data_flow.concolic.values import ConcolicValue, PrecisionStatus, reduce
        from d810.backends.ast import z3 as z3_backend
        from d810.backends.ast.z3 import Z3MopProver
        from d810.backends.ast.z3_proof_policy import Z3ProofStatus

        value = reduce(ConcolicValue(
            None,
            None,
            AbstractEvidence(32, KnownBits(32, zero=0x20), WrappedInterval.top(32)),
            32,
            PrecisionStatus.ABSTRACT,
        ))
        ast = self._prepared_abstract_ast(value, mask=1, shift=6)
        mop = SimpleNamespace(t=ida_hexrays.mop_r, size=4)
        monkeypatch.setattr(z3_backend.Z3MopProver, "_prepare_single_ast", lambda *_a, **_k: (mop, ast, None, False))
        counters = {"vars": 0, "visitor": 0, "solver": 0}
        monkeypatch.setattr(z3_backend, "create_z3_vars", lambda *_a, **_k: counters.__setitem__("vars", counters["vars"] + 1))
        monkeypatch.setattr(z3_backend, "AstNodeZ3Visitor", lambda *_a, **_k: counters.__setitem__("visitor", counters["visitor"] + 1) or SimpleNamespace(visit=lambda _ast: z3_backend.z3.BitVecVal(1, 32)))
        solvers = []
        class _RecordingSolver(z3_backend.z3.Solver):
            def __init__(self):
                super().__init__()
                self.added = []

            def add(self, *constraints):
                self.added.extend(constraints)
                return super().add(*constraints)

        def _new_solver(*_args, **_kwargs):
            counters["solver"] += 1
            solver = _RecordingSolver()
            solvers.append(solver)
            return solver
        monkeypatch.setattr(z3_backend, "_new_query_solver", _new_solver)

        result = Z3MopProver().prove_always_nonzero(mop)

        assert result.status is Z3ProofStatus.PROVED
        assert counters == {"vars": 1, "visitor": 1, "solver": 1}
        assert len(solvers) == 1
        assert len(solvers[0].added) == 1

    def test_top_call_result_falls_through_as_one_unconstrained_bitvector(self, monkeypatch):
        from d810.analyses.data_flow.concolic.values import ConcolicValue
        from d810.backends.ast import z3 as z3_backend
        from d810.backends.ast.z3 import Z3MopProver
        from d810.backends.ast.z3_proof_policy import Z3ProofStatus

        ast = self._prepared_abstract_ast(ConcolicValue.top(32), mask=1, shift=6)
        mop = SimpleNamespace(t=ida_hexrays.mop_r, size=4)
        monkeypatch.setattr(z3_backend.Z3MopProver, "_prepare_single_ast", lambda *_a, **_k: (mop, ast, None, False))
        counters = {"vars": 0, "visitor": 0, "solver": 0}
        monkeypatch.setattr(z3_backend, "create_z3_vars", lambda *_a, **_k: counters.__setitem__("vars", counters["vars"] + 1))
        monkeypatch.setattr(z3_backend, "AstNodeZ3Visitor", lambda *_a, **_k: counters.__setitem__("visitor", counters["visitor"] + 1) or SimpleNamespace(visit=lambda _ast: z3_backend.z3.BitVecVal(1, 32)))
        monkeypatch.setattr(z3_backend, "_new_query_solver", lambda *_a, **_k: counters.__setitem__("solver", counters["solver"] + 1) or z3_backend.z3.Solver())

        result = Z3MopProver().prove_always_nonzero(mop)

        assert result.status is Z3ProofStatus.PROVED
        assert counters == {"vars": 1, "visitor": 1, "solver": 1}

    def test_conflicting_facts_cannot_create_abstract_proof(self, monkeypatch):
        from d810.analyses.data_flow.concolic.values import ConcolicValue
        from d810.backends.ast import z3 as z3_backend
        from d810.backends.ast.z3 import Z3MopProver
        from d810.backends.ast.z3_proof_policy import Z3ProofStatus

        ast = self._prepared_abstract_ast(ConcolicValue.bottom(32), mask=1, shift=6)
        mop = SimpleNamespace(t=ida_hexrays.mop_r, size=4)
        monkeypatch.setattr(z3_backend.Z3MopProver, "_prepare_single_ast", lambda *_a, **_k: (mop, ast, None, False))
        counters = {"vars": 0, "visitor": 0, "solver": 0}
        monkeypatch.setattr(z3_backend, "create_z3_vars", lambda *_a, **_k: counters.__setitem__("vars", counters["vars"] + 1))
        monkeypatch.setattr(z3_backend, "AstNodeZ3Visitor", lambda *_a, **_k: counters.__setitem__("visitor", counters["visitor"] + 1) or SimpleNamespace(visit=lambda _ast: z3_backend.z3.BitVecVal(1, 32)))
        monkeypatch.setattr(z3_backend, "_new_query_solver", lambda *_a, **_k: counters.__setitem__("solver", counters["solver"] + 1) or z3_backend.z3.Solver())

        result = Z3MopProver().prove_always_nonzero(mop)

        assert result.status is Z3ProofStatus.PROVED
        assert counters == {"vars": 1, "visitor": 1, "solver": 1}

    def test_call_result_refiner_disables_context_free_zero_cache(self, monkeypatch):
        from d810.analyses.data_flow.concolic.values import ConcolicValue
        from d810.backends.ast import z3 as z3_backend
        from d810.backends.ast.z3 import Z3MopProver
        from d810.backends.ast.z3_proof_policy import Z3ProofStatus

        mop = SimpleNamespace(t=ida_hexrays.mop_r, size=4)
        ast = self._prepared_abstract_ast(ConcolicValue.of(0, 32), mask=1, shift=6)
        prepared = []

        def _prepare(*_args, **_kwargs):
            prepared.append(True)
            return mop, ast, None, False

        monkeypatch.setattr(z3_backend.Z3MopProver, "_prepare_single_ast", _prepare)
        prover = Z3MopProver(call_result_refiner=lambda _query: None)

        first = prover.prove_always_zero(mop)
        second = prover.prove_always_zero(mop)

        assert first.status is Z3ProofStatus.PROVED
        assert second.status is Z3ProofStatus.PROVED
        assert len(prepared) == 2

    def test_assigned_call_leaf_with_carrier_only_view_is_top(self, monkeypatch):
        from functools import partial

        from d810.analyses.value_flow import CALL_RETURN_VALUE_FACT_TYPE
        import d810.analyses.value_flow.call_return_value as call_results
        from d810.analyses.value_flow.model import FactObservation, ValidatedFactView
        from d810.backends.ast import z3 as z3_backend
        from d810.evaluator.hexrays_microcode import def_search
        from d810.hexrays.expr.ast import AstLeaf
        from tests.system.runtime.evaluator.test_def_search_mop_snapshot import (
            _call_result_test_parts,
        )

        assignment, _call, _destination, block, use = _call_result_test_parts()
        monkeypatch.setattr(def_search, "find_def_in_block", lambda *_args: assignment)
        monkeypatch.setattr(
            def_search, "_materialize_mop_for_tracking", lambda mop, *_a, **_k: mop
        )
        monkeypatch.setattr(
            z3_backend, "mop_to_ast", lambda *_args, **_kwargs: AstLeaf("operand")
        )

        carrier = FactObservation(
            fact_id="legacy-carrier",
            kind=CALL_RETURN_VALUE_FACT_TYPE,
            semantic_key="carrier",
            maturity="MMAT_PREOPTIMIZED",
            phase="value-flow",
            confidence=1.0,
            source_ea=0x401000,
            payload={
                "storage_kind": "register",
                "source_ea": 0x401000,
                "lifecycle_status": "production_proven",
                "source_identity": {"call_ea": 0x401000},
                "details": {"carrier_class": "PASSWORD_COMPARE_RESULT"},
            },
        )
        carrier_view = ValidatedFactView(
            maturity="MMAT_PREOPTIMIZED", observations=(carrier,)
        )
        seen = []
        original_refine_call_result = call_results.refine_call_result

        def recording_refiner(query, view):
            result = original_refine_call_result(query, view)
            seen.append((query, view, result))
            return result

        monkeypatch.setattr(call_results, "refine_call_result", recording_refiner)
        refiner = partial(call_results.refine_call_result, view=carrier_view)
        prepared = z3_backend.Z3MopProver(
            call_result_refiner=refiner
        )._prepare_single_ast(
            use,
            blk=block,
            ins=SimpleNamespace(ea=0x401100),
            operation="prove_always_zero",
        )

        assert prepared is not None
        _mop, leaf, _budget, _visitor_needs_budget = prepared
        assert carrier_view.active_observations == (carrier,)
        assert def_search.is_call_result_leaf(leaf)
        assert leaf.concolic_value.status.name == "TOP"
        assert len(seen) == 1
        assert seen[0][1] is carrier_view
        assert seen[0][2].status.name == "INVALID_EVIDENCE"

    def test_prover_has_are_equal(self):
        from d810.backends.ast.z3 import Z3MopProver

        prover = Z3MopProver()
        assert callable(getattr(prover, "are_equal", None))

    def test_prover_has_are_unequal(self):
        from d810.backends.ast.z3 import Z3MopProver

        prover = Z3MopProver()
        assert callable(getattr(prover, "are_unequal", None))

    def test_prover_has_prove_comparison(self):
        from d810.backends.ast.z3 import Z3MopProver

        prover = Z3MopProver()
        assert callable(getattr(prover, "prove_comparison", None))

    @pytest.mark.parametrize(
        ("comparison", "left", "right", "expected"),
        (
            ("eq", 7, 7, True),
            ("ne", 7, 7, False),
            ("ult", 0xFFFFFFFF, 0, False),
            ("ule", 0, 0, True),
            ("ugt", 0xFFFFFFFF, 0, True),
            ("uge", 0, 0, True),
            ("slt", 0xFFFFFFFF, 0, True),
            ("sle", 0, 0, True),
            ("sgt", 0xFFFFFFFF, 0, False),
            ("sge", 0, 0, True),
        ),
    )
    def test_prove_comparison_discharge_covers_signed_and_unsigned_relations(
        self,
        monkeypatch,
        comparison,
        left,
        right,
        expected,
    ):
        import d810.backends.ast.z3 as z3mod
        from d810.backends.ast.z3 import Z3MopProver

        class _StubMop:
            t = ida_hexrays.mop_n
            size = 4

            def __init__(self, value):
                self.value = value

            def dstr(self):
                return hex(self.value)

        monkeypatch.setattr(
            z3mod,
            "mop_list_to_z3_expression_list",
            lambda mops: [z3.BitVecVal(mop.value, 32) for mop in mops],
        )

        result = Z3MopProver().prove_comparison(
            _StubMop(left),
            _StubMop(right),
            comparison,
        )

        assert result is expected

    def test_prove_comparison_returns_none_when_relation_is_not_constant(
        self, monkeypatch
    ):
        import d810.backends.ast.z3 as z3mod
        from d810.backends.ast.z3 import Z3MopProver

        class _StubMop:
            t = ida_hexrays.mop_r
            size = 4

            def __init__(self, name):
                self.name = name

            def dstr(self):
                return self.name

        monkeypatch.setattr(
            z3mod,
            "mop_list_to_z3_expression_list",
            lambda mops: [z3.BitVec(mop.name, 32) for mop in mops],
        )

        assert (
            Z3MopProver().prove_comparison(_StubMop("x"), _StubMop("y"), "ult") is None
        )

    def test_prove_comparison_abstains_when_64_bit_operands_were_truncated(
        self, monkeypatch
    ):
        """A low-32-bit model must not authorize a 64-bit native predicate."""
        import d810.backends.ast.z3 as z3mod
        from d810.backends.ast.z3 import Z3MopProver

        class _StubMop:
            t = ida_hexrays.mop_r
            size = 8

            def __init__(self, name):
                self.name = name

            def dstr(self):
                return self.name

        # This is the unsound model the production translator currently builds
        # for both ``x`` and ``x & 0xffffffff`` when their real mop size is 8.
        truncated_x = z3.BitVec("x_low32", 32)
        monkeypatch.setattr(
            z3mod,
            "mop_list_to_z3_expression_list",
            lambda _mops: [truncated_x, truncated_x & 0xFFFFFFFF],
        )

        assert (
            Z3MopProver().prove_comparison(
                _StubMop("x"),
                _StubMop("x & 0xffffffff"),
                "eq",
            )
            is None
        )

    @pytest.mark.parametrize(
        ("left_size", "right_size"),
        ((1, 1), (2, 2), (8, 8), (4, 8), (8, 4)),
    )
    def test_prove_comparison_accepts_equal_width_native_operands(
        self, monkeypatch, left_size, right_size
    ):
        import d810.backends.ast.z3 as z3mod
        from d810.backends.ast.z3 import Z3MopProver

        if left_size != right_size:
            monkeypatch.setattr(
                z3mod,
                "mop_list_to_z3_expression_list",
                lambda _mops: pytest.fail("mixed-width operands reached the translator"),
            )
            left = SimpleNamespace(t=ida_hexrays.mop_r, size=left_size)
            right = SimpleNamespace(t=ida_hexrays.mop_r, size=right_size)
            assert Z3MopProver().prove_comparison(left, right, "eq") is None
            return

        bit_width = left_size * 8
        monkeypatch.setattr(
            z3mod,
            "mop_list_to_z3_expression_list",
            lambda _mops: [z3.BitVecVal(7, bit_width), z3.BitVecVal(7, bit_width)],
        )
        left = SimpleNamespace(t=ida_hexrays.mop_r, size=left_size)
        right = SimpleNamespace(t=ida_hexrays.mop_r, size=right_size)

        assert Z3MopProver().prove_comparison(left, right, "eq") is True

    @pytest.mark.parametrize("comparison", ["unsupported", ""])
    def test_prove_comparison_fails_closed_for_unknown_relation(self, comparison):
        from d810.backends.ast.z3 import Z3MopProver

        assert Z3MopProver().prove_comparison(object(), object(), comparison) is None

    def test_prove_comparison_fails_closed_when_operand_conversion_is_incomplete(
        self, monkeypatch
    ):
        import d810.backends.ast.z3 as z3mod
        from d810.backends.ast.z3 import Z3MopProver

        mop = SimpleNamespace(t=ida_hexrays.mop_r, size=4)
        monkeypatch.setattr(
            z3mod,
            "mop_list_to_z3_expression_list",
            lambda _mops: [z3.BitVec("only_one", 32)],
        )

        assert Z3MopProver().prove_comparison(mop, mop, "eq") is None

    def test_prover_has_is_always_zero(self):
        from d810.backends.ast.z3 import Z3MopProver

        prover = Z3MopProver()
        assert callable(getattr(prover, "is_always_zero", None))

    def test_prover_has_is_always_nonzero(self):
        from d810.backends.ast.z3 import Z3MopProver

        prover = Z3MopProver()
        assert callable(getattr(prover, "is_always_nonzero", None))

    def test_prover_has_prove_equivalence(self):
        from d810.backends.ast.z3 import Z3MopProver

        prover = Z3MopProver()
        assert callable(getattr(prover, "prove_equivalence", None))

    def test_prover_has_clear_caches(self):
        from d810.backends.ast.z3 import Z3MopProver

        prover = Z3MopProver()
        assert callable(getattr(prover, "clear_caches", None))

    def test_prover_none_mops_are_equal_returns_false(self):
        from d810.backends.ast.z3 import Z3MopProver

        prover = Z3MopProver()
        assert prover.are_equal(None, None) is False

    def test_prover_none_mops_are_unequal_abstains(self):
        from d810.backends.ast.z3 import Z3MopProver

        prover = Z3MopProver()
        assert prover.are_unequal(None, None) is False

    @pytest.mark.parametrize("method_name", ["are_equal", "are_unequal"])
    def test_equality_provers_reject_mixed_native_widths_before_translation(
        self, monkeypatch, method_name
    ):
        import d810.backends.ast.z3 as z3mod
        from d810.backends.ast.z3 import Z3MopProver

        monkeypatch.setattr(
            z3mod,
            "mop_list_to_z3_expression_list",
            lambda _mops: pytest.fail("mixed-width operands reached the translator"),
        )
        left = SimpleNamespace(t=ida_hexrays.mop_r, size=1)
        right = SimpleNamespace(t=ida_hexrays.mop_r, size=4)

        assert getattr(Z3MopProver(), method_name)(left, right) is False

    @pytest.mark.parametrize("method_name", ["are_equal", "are_unequal"])
    def test_equality_provers_abstain_when_translation_returns_wrong_sorts(
        self, monkeypatch, method_name
    ):
        import d810.backends.ast.z3 as z3mod
        from d810.backends.ast.z3 import Z3MopProver

        monkeypatch.setattr(
            z3mod,
            "mop_list_to_z3_expression_list",
            lambda _mops: [z3.BitVec("byte_value", 8), z3.BitVec("dword_value", 32)],
        )
        left = SimpleNamespace(t=ida_hexrays.mop_r, size=1)
        right = SimpleNamespace(t=ida_hexrays.mop_r, size=1)

        assert getattr(Z3MopProver(), method_name)(left, right) is False

    @pytest.mark.parametrize(
        ("method_name", "expected"),
        [("are_equal", False), ("are_unequal", False), ("prove_comparison", None)],
    )
    def test_provers_abstain_when_z3_translation_raises(
        self, monkeypatch, method_name, expected
    ):
        import d810.backends.ast.z3 as z3mod
        from d810.backends.ast.z3 import Z3MopProver
        from d810.errors import D810Z3Exception

        def _raise(_mops):
            raise D810Z3Exception("unsupported AST opcode")

        monkeypatch.setattr(z3mod, "mop_list_to_z3_expression_list", _raise)
        left = SimpleNamespace(t=ida_hexrays.mop_r, size=4)
        right = SimpleNamespace(t=ida_hexrays.mop_r, size=4)
        method = getattr(Z3MopProver(), method_name)

        if method_name == "prove_comparison":
            assert method(left, right, "eq") is expected
        else:
            assert method(left, right) is expected

    def test_prover_none_mop_is_always_zero_returns_false(self):
        from d810.backends.ast.z3 import Z3MopProver

        prover = Z3MopProver()
        assert prover.is_always_zero(None) is False

    @pytest.mark.parametrize("method_name", ["is_always_zero", "is_always_nonzero"])
    def test_stack_snapshot_materializes_against_context_mba(
        self,
        monkeypatch,
        method_name,
    ):
        import d810.backends.ast.z3 as z3mod
        from d810.backends.ast.z3 import Z3MopProver

        destination_mba = object()
        materialized_with = []

        class _FakeSnapshot:
            def to_mop(self, mba=None):
                materialized_with.append(mba)
                return SimpleNamespace(t=ida_hexrays.mop_S, size=4)

        monkeypatch.setattr(z3mod, "MopSnapshot", _FakeSnapshot)
        monkeypatch.setattr(z3mod, "structural_mop_hash", lambda _mop, _depth: 1)
        monkeypatch.setattr(z3mod, "mop_to_ast", lambda _mop: None)
        monkeypatch.setattr(z3mod, "_resolve_mop_to_ast", lambda *_args: None)

        prover = Z3MopProver(
            blk=SimpleNamespace(mba=destination_mba),
            ins=object(),
        )
        assert getattr(prover, method_name)(_FakeSnapshot()) is False
        assert materialized_with == [destination_mba]

    def test_are_unequal_abstains_when_operand_fails_ast_conversion(self, monkeypatch):
        """``are_unequal`` MUST abstain (return ``False``) when an operand cannot be
        converted to a Z3 expression (ticket llr-mra1).

        Proving inequality requires an actual Z3 proof. When an operand fails AST
        conversion -- e.g. a memory load ``[ds:p].1`` (``m_ldx`` is an unsupported
        root opcode for the AST builder), modelling Approov's ``cmpb (%rax)``
        (``*v6``) -- the conversion yields fewer than two expressions and the
        prover has NO information.  Returning ``True`` here was the unsound default
        that let ``Z3setzRuleGeneric`` fold ``setz(*v6, 0) -> 0`` (claiming
        ``*v6 != 0`` always), deleting the real runtime two-way loop-exit and
        collapsing ``approov_real_pattern`` to an infinite loop.  An unconvertible
        operand is unknown, never provably-unequal -- mirroring ``are_equal``'s
        symmetric abstention.

        Driving the failure through ``mop_list_to_z3_expression_list`` (the exact
        site that drops the unconvertible load) with lightweight operand stubs
        keeps the test free of fragile raw ``m_ldx`` microcode synthesis (which
        segfaults when a ``mop_t`` is built outside a live ``mba``).
        """
        import d810.backends.ast.z3 as z3mod
        from d810.backends.ast.z3 import Z3MopProver

        class _StubMop:
            """Minimal operand: satisfies the SWIG-validity guards (``t``/``size``)
            without being a real SWIG ``mop_t``."""

            def __init__(self, ident):
                self.t = ida_hexrays.mop_d  # memory-load-shaped operand type
                self.size = 1
                self._ident = ident

            def dstr(self):
                return f"<stub {self._ident}>"

        a = _StubMop("load")  # the unconvertible *v6 dereference
        b = _StubMop("zero")  # the #0 constant compared against

        # Keep cache keys stable + cheap for the stubs (avoid SWIG hashing).
        monkeypatch.setattr(z3mod, "structural_mop_hash", lambda m, _d: hash(m._ident))
        # Simulate one operand failing AST conversion (the load) -> single expr,
        # exactly as ``ldx`` does ("unsupported root opcode" -> 1 of 2 converted).
        monkeypatch.setattr(
            z3mod, "mop_list_to_z3_expression_list", lambda _mops: [object()]
        )

        prover = Z3MopProver()
        prover.clear_caches()
        assert prover.are_unequal(a, b) is False
        # are_equal already abstains soundly on the same conversion failure.
        assert prover.are_equal(a, b) is False

    def test_bounded_result_and_boolean_wrapper_are_fail_closed(self, monkeypatch):
        import d810.backends.ast.z3 as z3mod
        from d810.backends.ast.z3 import Z3MopProver
        from d810.backends.ast.z3_proof_policy import (
            Z3ProofPolicy,
            Z3ProofStatus,
        )

        class _StubMop:
            t = ida_hexrays.mop_r
            size = 4

            def __init__(self, name):
                self.name = name

            def dstr(self):
                return self.name

        monkeypatch.setattr(
            z3mod,
            "structural_mop_hash",
            lambda mop, _depth: hash(mop.name),
        )
        monkeypatch.setattr(
            z3mod,
            "mop_list_to_z3_expression_list",
            lambda _mops, **_kwargs: [
                z3.BitVecVal(7, 32),
                z3.BitVecVal(7, 32),
            ],
        )
        policy = Z3ProofPolicy(max_expression_nodes=8, proof_timeout_ms=100)
        prover = Z3MopProver(policy=policy)
        left = _StubMop("left")
        right = _StubMop("right")

        result = prover.prove_equal(left, right)

        assert result.status is Z3ProofStatus.PROVED
        assert result.reason is None
        assert prover.are_equal(left, right) is True

    def test_bounded_sat_is_disproved_and_never_a_positive_boolean(self, monkeypatch):
        import d810.backends.ast.z3 as z3mod
        from d810.backends.ast.z3 import Z3MopProver
        from d810.backends.ast.z3_proof_policy import (
            Z3ProofPolicy,
            Z3ProofStatus,
        )

        left = SimpleNamespace(t=ida_hexrays.mop_r, size=4, name="left")
        right = SimpleNamespace(t=ida_hexrays.mop_r, size=4, name="right")
        monkeypatch.setattr(
            z3mod,
            "structural_mop_hash",
            lambda mop, _depth: hash(mop.name),
        )
        monkeypatch.setattr(
            z3mod,
            "mop_list_to_z3_expression_list",
            lambda _mops, **_kwargs: [
                z3.BitVec("left", 32),
                z3.BitVec("right", 32),
            ],
        )

        result = Z3MopProver(
            policy=Z3ProofPolicy(max_expression_nodes=8, proof_timeout_ms=100)
        ).prove_equal(left, right)

        assert result.status is Z3ProofStatus.DISPROVED
        assert result.reason is None
        assert result.status is not Z3ProofStatus.PROVED

    def test_bounded_unknown_maps_timeout_and_does_not_touch_global_solver(
        self, monkeypatch
    ):
        import d810.backends.ast.z3 as z3mod
        from d810.backends.ast.z3 import Z3MopProver
        from d810.backends.ast.z3_proof_policy import (
            Z3ProofAbstentionReason,
            Z3ProofPolicy,
            Z3ProofStatus,
        )

        class _StubMop:
            t = ida_hexrays.mop_r
            size = 4
            name = "stub"

            def dstr(self):
                return self.name

        class _UnknownSolver:
            def set(self, **_kwargs):
                return None

            def push(self):
                return None

            def pop(self):
                return None

            def add(self, _query):
                return None

            def check(self):
                return z3.unknown

            def reason_unknown(self):
                return "timeout"

        global_solver = z3.Solver()
        global_solver.set(timeout=777)
        global_solver_before = global_solver.sexpr()
        global_solver_calls = []
        monkeypatch.setattr(
            z3mod,
            "get_solver",
            lambda: global_solver_calls.append(True) or global_solver,
        )
        monkeypatch.setattr(z3mod.z3, "Solver", _UnknownSolver)
        monkeypatch.setattr(
            z3mod,
            "mop_list_to_z3_expression_list",
            lambda _mops, **_kwargs: [
                z3.BitVecVal(7, 32),
                z3.BitVecVal(7, 32),
            ],
        )

        result = Z3MopProver(
            policy=Z3ProofPolicy(max_expression_nodes=8, proof_timeout_ms=1)
        ).prove_equal(_StubMop(), _StubMop())

        assert result.status is Z3ProofStatus.ABSTAINED
        assert result.reason is Z3ProofAbstentionReason.TIMEOUT
        assert global_solver_calls == []
        assert global_solver.sexpr() == global_solver_before

    def test_abstentions_are_not_cached_and_can_be_retried(self, monkeypatch):
        import d810.backends.ast.z3 as z3mod
        from d810.backends.ast.z3 import Z3MopProver
        from d810.backends.ast.z3_proof_policy import (
            Z3ProofAbstentionReason,
            Z3ProofPolicy,
            Z3ProofStatus,
        )
        from d810.errors import D810Z3Exception

        class _StubMop:
            t = ida_hexrays.mop_r
            size = 4
            name = "retry"

            def dstr(self):
                return self.name

        attempts = []

        def _flaky_translation(_mops, **_kwargs):
            attempts.append(True)
            if len(attempts) == 1:
                raise D810Z3Exception("unsupported AST opcode")
            return [z3.BitVecVal(7, 32), z3.BitVecVal(7, 32)]

        monkeypatch.setattr(
            z3mod,
            "mop_list_to_z3_expression_list",
            _flaky_translation,
        )
        prover = Z3MopProver(
            policy=Z3ProofPolicy(max_expression_nodes=8, proof_timeout_ms=100)
        )
        first = prover.prove_equal(_StubMop(), _StubMop())
        second = prover.prove_equal(_StubMop(), _StubMop())

        assert first.status is Z3ProofStatus.ABSTAINED
        assert first.reason is Z3ProofAbstentionReason.UNSUPPORTED_EXPRESSION
        assert second.status is Z3ProofStatus.PROVED
        assert attempts == [True, True]

    def test_comparison_abstention_is_not_cached_and_can_be_retried(
        self, monkeypatch
    ):
        import d810.backends.ast.z3 as z3mod
        from d810.backends.ast.z3 import Z3MopProver
        from d810.backends.ast.z3_proof_policy import Z3ProofPolicy
        from d810.errors import D810Z3Exception

        left = SimpleNamespace(t=ida_hexrays.mop_r, size=4, name="comparison-left")
        right = SimpleNamespace(t=ida_hexrays.mop_r, size=4, name="comparison-right")
        monkeypatch.setattr(
            z3mod,
            "structural_mop_hash",
            lambda mop, _depth: hash(mop.name),
        )
        attempts = []

        def _flaky_translation(_mops, **_kwargs):
            attempts.append(True)
            if len(attempts) == 1:
                raise D810Z3Exception("unsupported AST opcode")
            return [z3.BitVecVal(7, 32), z3.BitVecVal(7, 32)]

        monkeypatch.setattr(
            z3mod,
            "mop_list_to_z3_expression_list",
            _flaky_translation,
        )
        prover = Z3MopProver(
            policy=Z3ProofPolicy(max_expression_nodes=8, proof_timeout_ms=100)
        )

        assert prover.prove_comparison(left, right, "eq") is None
        assert prover.prove_comparison(left, right, "eq") is True
        assert attempts == [True, True]

    def test_policy_isolation_keeps_node_limit_and_conclusive_cache_separate(
        self, monkeypatch
    ):
        import d810.backends.ast.z3 as z3mod
        from d810.backends.ast.z3 import Z3MopProver
        from d810.backends.ast.z3_proof_policy import (
            Z3ProofAbstentionReason,
            Z3ProofPolicy,
            Z3ProofStatus,
        )

        class _StubMop:
            t = ida_hexrays.mop_r
            size = 4
            name = "isolated"

            def dstr(self):
                return self.name

        def _two_occurrence_translation(_mops, *, node_budget):
            node_budget.consume()
            node_budget.consume()
            return [z3.BitVecVal(7, 32), z3.BitVecVal(7, 32)]

        monkeypatch.setattr(
            z3mod,
            "mop_list_to_z3_expression_list",
            _two_occurrence_translation,
        )
        left = _StubMop()
        right = _StubMop()
        low = Z3MopProver(
            policy=Z3ProofPolicy(max_expression_nodes=1, proof_timeout_ms=100)
        )
        high = Z3MopProver(
            policy=Z3ProofPolicy(max_expression_nodes=2, proof_timeout_ms=100)
        )

        low_result = low.prove_equal(left, right)
        high_result = high.prove_equal(left, right)

        assert low_result.status is Z3ProofStatus.ABSTAINED
        assert low_result.reason is Z3ProofAbstentionReason.NODE_LIMIT
        assert high_result.status is Z3ProofStatus.PROVED

    def test_builder_budget_is_consumed_at_translation_seam_before_second_occurrence(
        self, monkeypatch
    ):
        import d810.backends.ast.z3 as z3mod
        from d810.backends.ast.z3 import Z3MopProver
        from d810.backends.ast.z3_proof_policy import (
            Z3ProofAbstentionReason,
            Z3ProofPolicy,
            Z3ProofStatus,
        )

        class _StubMop:
            t = ida_hexrays.mop_r
            size = 4
            name = "builder-shape"

            def dstr(self):
                return self.name

        builder_budgets = []

        def _builder(_mop, *, node_budget):
            builder_budgets.append(node_budget)
            node_budget.consume()
            return None

        monkeypatch.setattr(z3mod, "mop_to_ast", _builder)
        monkeypatch.setattr(
            z3mod,
            "structural_mop_hash",
            lambda _mop, _depth: 1,
        )

        one_node_too_small = Z3MopProver(
            policy=Z3ProofPolicy(max_expression_nodes=1, proof_timeout_ms=100)
        ).prove_equal(_StubMop(), _StubMop())

        assert one_node_too_small.status is Z3ProofStatus.ABSTAINED
        assert one_node_too_small.reason is Z3ProofAbstentionReason.NODE_LIMIT
        assert one_node_too_small.observed_expression_nodes == 1
        assert len(builder_budgets) == 2
        assert builder_budgets[0] is builder_budgets[1]

    def test_context_resolved_zero_cache_is_bypassed_and_receipt_is_live(
        self, monkeypatch
    ):
        import d810.backends.ast.z3 as z3mod
        from d810.backends.ast.z3 import Z3MopProver
        from d810.backends.ast.z3_proof_policy import Z3ProofPolicy, Z3ProofStatus

        class _FakeAst:
            def __init__(self, value):
                self.value = value

            def is_leaf(self):
                return True

            def get_leaf_list(self):
                return []

        class _FakeVisitor:
            def __init__(self, node_budget=None):
                self.node_budget = node_budget

            def visit(self, ast):
                if self.node_budget is not None:
                    self.node_budget.consume()
                return z3.BitVecVal(ast.value, 32)

        mop = SimpleNamespace(t=ida_hexrays.mop_r, size=4, name="same-register")
        blk_a = SimpleNamespace(mba=SimpleNamespace(owner="mba-a"))
        blk_b = SimpleNamespace(mba=SimpleNamespace(owner="mba-b"))
        ins_a = SimpleNamespace(label="ins-a")
        ins_b = SimpleNamespace(label="ins-b")

        monkeypatch.setattr(z3mod, "structural_mop_hash", lambda _mop, _depth: 17)
        monkeypatch.setattr(z3mod, "AstNodeZ3Visitor", _FakeVisitor)
        monkeypatch.setattr(
            z3mod,
            "mop_to_ast",
            lambda _mop, *, node_budget: node_budget.consume() or _FakeAst(99),
        )
        monkeypatch.setattr(
            z3mod,
            "_resolve_mop_to_ast",
            lambda _mop, _blk, ins, *, node_budget=None: _FakeAst(
                0 if ins.label == "ins-a" else 1
            ),
        )
        monkeypatch.setattr(
            z3mod,
            "_recursively_resolve_ast",
            lambda ast, _blk, _ins, **_kwargs: ast,
        )

        prover = Z3MopProver(
            policy=Z3ProofPolicy(max_expression_nodes=2, proof_timeout_ms=100)
        )
        first = prover.prove_always_zero(mop, blk=blk_a, ins=ins_a)
        second = prover.prove_always_zero(mop, blk=blk_b, ins=ins_b)

        assert first.status is Z3ProofStatus.PROVED
        assert first.observed_expression_nodes == 2
        assert second.status is Z3ProofStatus.DISPROVED
        assert second.observed_expression_nodes == 2

    @pytest.mark.parametrize(
        ("method_name", "first_expected", "second_expected"),
        (
            ("prove_equal", "proved", "disproved"),
            ("prove_unequal", "disproved", "proved"),
            ("prove_comparison", True, False),
        ),
    )
    def test_context_bypasses_pair_and_comparison_caches(
        self, monkeypatch, method_name, first_expected, second_expected
    ):
        import d810.backends.ast.z3 as z3mod
        from d810.backends.ast.z3 import Z3MopProver
        from d810.backends.ast.z3_proof_policy import Z3ProofPolicy

        left = SimpleNamespace(t=ida_hexrays.mop_r, size=4, name="context-left")
        right = SimpleNamespace(t=ida_hexrays.mop_r, size=4, name="context-right")
        blk_a = SimpleNamespace(mba=SimpleNamespace(owner="pair-mba-a"))
        blk_b = SimpleNamespace(mba=SimpleNamespace(owner="pair-mba-b"))
        ins_a = SimpleNamespace(label="pair-ins-a")
        ins_b = SimpleNamespace(label="pair-ins-b")
        attempts = []

        monkeypatch.setattr(z3mod, "structural_mop_hash", lambda _mop, _depth: 23)

        def _translate(_mops, **_kwargs):
            attempts.append(True)
            value = 7 if len(attempts) == 1 else 8
            return [z3.BitVecVal(7, 32), z3.BitVecVal(value, 32)]

        monkeypatch.setattr(z3mod, "mop_list_to_z3_expression_list", _translate)
        prover = Z3MopProver(
            policy=Z3ProofPolicy(max_expression_nodes=8, proof_timeout_ms=100)
        )

        def _invoke(blk, ins):
            method = getattr(prover, method_name)
            if method_name == "prove_comparison":
                return method(left, right, "eq", blk=blk, ins=ins)
            return method(left, right, blk=blk, ins=ins)

        first = _invoke(blk_a, ins_a)
        second = _invoke(blk_b, ins_b)

        if method_name == "prove_comparison":
            assert first is first_expected
            assert second is second_expected
        else:
            assert first.status.value == first_expected
            assert second.status.value == second_expected
        assert attempts == [True, True]

    def test_bounded_proof_copies_caller_assertions_without_mutating_global_solver(
        self, monkeypatch
    ):
        import d810.backends.ast.z3 as z3mod
        from d810.backends.ast.z3 import Z3MopProver
        from d810.backends.ast.z3_proof_policy import Z3ProofPolicy, Z3ProofStatus

        left = SimpleNamespace(t=ida_hexrays.mop_r, size=4, name="assert-left")
        right = SimpleNamespace(t=ida_hexrays.mop_r, size=4, name="assert-right")
        x = z3.BitVec("assert_x", 32)
        y = z3.BitVec("assert_y", 32)
        caller_solver = z3.Solver()
        caller_solver.add(x == y)
        global_solver = z3mod.get_solver()
        global_before = global_solver.sexpr()

        monkeypatch.setattr(
            z3mod,
            "structural_mop_hash",
            lambda mop, _depth: hash(mop.name),
        )
        monkeypatch.setattr(
            z3mod,
            "mop_list_to_z3_expression_list",
            lambda _mops, **_kwargs: [x, y],
        )

        result = Z3MopProver(
            policy=Z3ProofPolicy(max_expression_nodes=8, proof_timeout_ms=100)
        ).prove_equal(left, right, solver=caller_solver)

        assert result.status is Z3ProofStatus.PROVED
        assert global_solver.sexpr() == global_before

    def test_context_resolved_zero_node_limit_receipt_uses_live_budget(
        self, monkeypatch
    ):
        import d810.backends.ast.z3 as z3mod
        from d810.backends.ast.z3 import Z3MopProver
        from d810.backends.ast.z3_proof_policy import (
            Z3ProofAbstentionReason,
            Z3ProofPolicy,
            Z3ProofStatus,
        )

        class _FakeAst:
            def is_leaf(self):
                return True

            def get_leaf_list(self):
                return []

        class _FakeVisitor:
            def __init__(self, node_budget=None):
                self.node_budget = node_budget

            def visit(self, _ast):
                self.node_budget.consume()
                self.node_budget.consume()
                return z3.BitVecVal(0, 32)

        mop = SimpleNamespace(t=ida_hexrays.mop_r, size=4, name="limited-register")
        blk = SimpleNamespace(mba=SimpleNamespace(owner="limited-mba"))
        ins = SimpleNamespace(label="limited-ins")
        monkeypatch.setattr(z3mod, "structural_mop_hash", lambda _mop, _depth: 19)
        monkeypatch.setattr(z3mod, "AstNodeZ3Visitor", _FakeVisitor)
        monkeypatch.setattr(
            z3mod,
            "mop_to_ast",
            lambda _mop, *, node_budget: node_budget.consume() or _FakeAst(),
        )
        monkeypatch.setattr(
            z3mod,
            "_resolve_mop_to_ast",
            lambda *_args, node_budget=None: _FakeAst(),
        )
        monkeypatch.setattr(
            z3mod,
            "_recursively_resolve_ast",
            lambda ast, _blk, _ins, **_kwargs: ast,
        )

        result = Z3MopProver(
            policy=Z3ProofPolicy(max_expression_nodes=1, proof_timeout_ms=100)
        ).prove_always_zero(mop, blk=blk, ins=ins)

        assert result.status is Z3ProofStatus.ABSTAINED
        assert result.reason is Z3ProofAbstentionReason.NODE_LIMIT
        assert result.observed_expression_nodes == 1

    def test_m_ldc_budget_charges_wrapper_and_nested_constant(self, monkeypatch):
        from d810.backends.ast.z3 import AstNodeZ3Visitor
        import d810.hexrays.ir.mop_utils as mop_utils
        from d810.backends.ast.z3_proof_policy import (
            Z3ExpressionNodeBudget,
            Z3NodeLimitExceeded,
            Z3ProofPolicy,
        )

        class _DetachedMop:
            pass

        wrapper = _DetachedMop()
        wrapper.t = ida_hexrays.mop_d
        wrapper.size = 4
        wrapper.d = SimpleNamespace(
            opcode=ida_hexrays.m_ldc,
            ea=0,
            size=4,
            l=SimpleNamespace(
                t=ida_hexrays.mop_n,
                size=4,
                nnn=SimpleNamespace(value=7),
            ),
            d=None,
        )
        monkeypatch.setattr(mop_utils, "get_mop_key", lambda _mop: ("ldc",))

        def _fake_safe_make_number(mop, value, size):
            mop.t = ida_hexrays.mop_n
            mop.size = size
            mop.nnn = SimpleNamespace(value=value)

        monkeypatch.setattr(mop_utils, "safe_make_number", _fake_safe_make_number)
        monkeypatch.setattr(mop_utils.ida_hexrays, "mop_t", _DetachedMop)

        one_node_budget = Z3ExpressionNodeBudget(
            Z3ProofPolicy(max_expression_nodes=1, proof_timeout_ms=100)
        )
        with pytest.raises(Z3NodeLimitExceeded):
            mop_utils.mop_to_ast_internal(
                wrapper,
                mop_utils.AstBuilderContext(),
                node_budget=one_node_budget,
            )
        assert one_node_budget.observed_nodes == 1

        two_node_budget = Z3ExpressionNodeBudget(
            Z3ProofPolicy(max_expression_nodes=2, proof_timeout_ms=100)
        )
        ast = mop_utils.mop_to_ast_internal(
            wrapper,
            mop_utils.AstBuilderContext(),
            node_budget=two_node_budget,
        )
        assert ast is not None
        assert ast.is_constant()
        assert ast.expected_value == 7
        assert two_node_budget.observed_nodes == 2

        # The real visitor shares the builder budget.  The nested constant was
        # already charged at construction, so translating it must not consume
        # a third occurrence.
        AstNodeZ3Visitor(node_budget=two_node_budget).visit(ast)
        assert two_node_budget.observed_nodes == 2

    def test_repeated_cached_m_ldc_charges_nested_source_occurrences(
        self, monkeypatch
    ):
        import d810.hexrays.ir.mop_utils as mop_utils
        from d810.backends.ast.z3 import AstNodeZ3Visitor
        from d810.backends.ast.z3_proof_policy import (
            Z3ExpressionNodeBudget,
            Z3NodeLimitExceeded,
            Z3ProofPolicy,
        )

        class _DetachedMop:
            pass

        def _fake_safe_make_number(mop, value, size):
            mop.t = ida_hexrays.mop_n
            mop.size = size
            mop.nnn = SimpleNamespace(value=value)

        def _ldc_wrapper(name):
            wrapper = _DetachedMop()
            wrapper.t = ida_hexrays.mop_d
            wrapper.size = 4
            wrapper.name = name
            wrapper.d = SimpleNamespace(
                opcode=ida_hexrays.m_ldc,
                ea=0,
                size=4,
                l=SimpleNamespace(
                    t=ida_hexrays.mop_n,
                    size=4,
                    nnn=SimpleNamespace(value=7),
                ),
                d=None,
            )
            return wrapper

        left = _ldc_wrapper("shared-ldc")
        root = _DetachedMop()
        root.t = ida_hexrays.mop_d
        root.size = 4
        root.name = "root-ldc-add"
        root.d = SimpleNamespace(
            opcode=ida_hexrays.m_add,
            ea=0,
            l=left,
            r=left,
            d=None,
        )
        monkeypatch.setattr(
            mop_utils, "get_mop_key", lambda mop: (getattr(mop, "name", ""),)
        )
        monkeypatch.setattr(mop_utils, "safe_make_number", _fake_safe_make_number)
        monkeypatch.setattr(mop_utils.ida_hexrays, "mop_t", _DetachedMop)

        class _FakeSnapshot:
            @classmethod
            def from_mop(cls, mop):
                return SimpleNamespace(t=mop.t)

        monkeypatch.setattr(
            mop_utils,
            "MopSnapshot",
            _FakeSnapshot,
        )

        low_budget = Z3ExpressionNodeBudget(
            Z3ProofPolicy(max_expression_nodes=4, proof_timeout_ms=100)
        )
        with pytest.raises(Z3NodeLimitExceeded):
            mop_utils.mop_to_ast_internal(
                root,
                mop_utils.AstBuilderContext(),
                node_budget=low_budget,
            )
        assert low_budget.observed_nodes == 4

        in_budget = Z3ExpressionNodeBudget(
            Z3ProofPolicy(max_expression_nodes=5, proof_timeout_ms=100)
        )
        ast = mop_utils.mop_to_ast_internal(
            root,
            mop_utils.AstBuilderContext(),
            node_budget=in_budget,
        )
        assert ast is not None
        assert in_budget.observed_nodes == 5
        AstNodeZ3Visitor(node_budget=in_budget).visit(ast)
        assert in_budget.observed_nodes == 5

    def test_contextual_replacement_budget_aborts_before_construction(
        self, monkeypatch
    ):
        import d810.backends.ast.z3 as z3mod
        from d810.backends.ast.z3 import Z3MopProver
        from d810.backends.ast.z3_proof_policy import (
            Z3ProofAbstentionReason,
            Z3ProofPolicy,
            Z3ProofStatus,
        )

        class _FakeAst:
            def __init__(self):
                self.left = None
                self.right = None

            def is_leaf(self):
                return False

            def get_leaf_list(self):
                return []

        constructed = []

        def _resolver(_ast, _blk, _ins, *, node_budget=None):
            def _make_node():
                if node_budget is not None:
                    node_budget.consume()
                node = _FakeAst()
                if node_budget is not None:
                    node_budget.mark_charged(node)
                constructed.append(node)
                return node

            replacement = _make_node()
            replacement.left = _make_node()
            return replacement

        class _FakeVisitor:
            def __init__(self, node_budget=None):
                self.node_budget = node_budget

            def visit(self, _ast):
                return z3.BitVecVal(0, 32)

        mop = SimpleNamespace(
            t=ida_hexrays.mop_d,
            size=4,
            name="preconstruction-context",
            d=SimpleNamespace(opcode=ida_hexrays.m_add),
        )
        blk = SimpleNamespace(mba=SimpleNamespace(owner="preconstruction-mba"))
        ins = SimpleNamespace(label="preconstruction-ins")
        monkeypatch.setattr(z3mod, "structural_mop_hash", lambda _mop, _depth: 31)
        monkeypatch.setattr(z3mod, "AstNodeZ3Visitor", _FakeVisitor)
        monkeypatch.setattr(
            z3mod,
            "mop_to_ast",
            lambda _mop, *, node_budget: node_budget.consume() or _FakeAst(),
        )
        monkeypatch.setattr(z3mod, "_resolve_mop_to_ast", lambda *_args: None)
        monkeypatch.setattr(z3mod, "_recursively_resolve_ast", _resolver)

        result = Z3MopProver(
            policy=Z3ProofPolicy(max_expression_nodes=1, proof_timeout_ms=100)
        ).prove_always_zero(mop, blk=blk, ins=ins)

        assert result.status is Z3ProofStatus.ABSTAINED
        assert result.reason is Z3ProofAbstentionReason.NODE_LIMIT
        assert result.observed_expression_nodes == 1
        assert constructed == []

    def test_contextual_root_expansion_starts_at_reaching_definition(
        self, monkeypatch
    ):
        """Do not resolve a reaching definition's inputs from the later use site.

        A root such as ``rcx = call_result & mask`` is first recovered while
        proving a later ``setz rcx, 0``.  Its children must be expanded from
        the defining ``and`` instruction.  Expanding them from ``setz`` can
        select later redefinitions of a source register and turn an unknown
        call result into an unrelated constant.
        """
        import d810.backends.ast.z3 as z3mod
        from d810.backends.ast.z3 import Z3MopProver

        class _FakeAst:
            def __init__(self, *, leaf, ins=None):
                self._leaf = leaf
                self.ins = ins

            def is_leaf(self):
                return self._leaf

        use_ins = object()
        definition_ins = object()
        blk = SimpleNamespace(mba=object())
        mop = SimpleNamespace(t=ida_hexrays.mop_r, size=8)
        initial_leaf = _FakeAst(leaf=True)
        reaching_root = _FakeAst(leaf=False, ins=definition_ins)
        recursive_anchors = []

        monkeypatch.setattr(z3mod, "mop_to_ast", lambda _mop: initial_leaf)
        monkeypatch.setattr(
            z3mod,
            "_resolve_mop_to_ast",
            lambda _mop, _blk, _ins: reaching_root,
        )
        monkeypatch.setattr(
            z3mod,
            "_recursively_resolve_ast",
            lambda ast, _blk, ins, *, node_budget=None: (
                recursive_anchors.append(ins) or ast
            ),
        )

        prepared = Z3MopProver()._prepare_single_ast(
            mop,
            blk=blk,
            ins=use_ins,
            operation="prove_always_zero",
        )

        assert prepared is not None
        assert prepared[1] is reaching_root
        assert recursive_anchors == [definition_ins]

    def test_bounded_minsn_gateway_routes_to_python_builder(self, monkeypatch):
        import d810.hexrays.ir.minsn_utils as minsn_utils
        from d810.backends.ast.z3_proof_policy import (
            Z3ExpressionNodeBudget,
            Z3ProofPolicy,
        )

        compiled_calls = []
        python_calls = []
        compiled_result = SimpleNamespace(ea=0x401000)
        python_result = SimpleNamespace(ea=0x401000)

        monkeypatch.setattr(
            minsn_utils,
            "_minsn_to_ast_impl",
            lambda _ins: compiled_calls.append(True) or compiled_result,
        )
        monkeypatch.setattr(
            minsn_utils,
            "_py_slow_minsn_to_ast",
            lambda _ins, *, node_budget=None: python_calls.append(node_budget)
            or python_result,
        )

        instruction = SimpleNamespace(ea=0x401000)
        budget = Z3ExpressionNodeBudget(
            Z3ProofPolicy(max_expression_nodes=4, proof_timeout_ms=100)
        )

        assert minsn_utils.minsn_to_ast(instruction) is compiled_result
        assert minsn_utils.minsn_to_ast(instruction, node_budget=budget) is python_result
        assert compiled_calls == [True]
        assert python_calls == [budget]

    def test_bounded_minsn_builder_propagates_node_limit(self, monkeypatch):
        import d810.hexrays.ir.minsn_utils as minsn_utils
        from d810.backends.ast.z3_proof_policy import (
            Z3ExpressionNodeBudget,
            Z3NodeLimitExceeded,
            Z3ProofPolicy,
        )

        class _FakeMop:
            def create_from_insn(self, _instruction):
                return None

        monkeypatch.setattr(minsn_utils.ida_hexrays, "mop_t", _FakeMop)

        def _bounded_builder(_mop, *, node_budget):
            node_budget.consume()
            return None

        monkeypatch.setattr(minsn_utils, "mop_to_ast", _bounded_builder)
        instruction = SimpleNamespace(
            opcode=ida_hexrays.m_add,
            ea=0x1000,
            dstr=lambda: "add",
        )
        budget = Z3ExpressionNodeBudget(
            Z3ProofPolicy(max_expression_nodes=1, proof_timeout_ms=100)
        )
        budget.consume()

        with pytest.raises(Z3NodeLimitExceeded):
            minsn_utils._py_slow_minsn_to_ast(instruction, node_budget=budget)
        assert budget.observed_nodes == 1

    def test_direct_contextual_resolution_keeps_one_cumulative_budget(
        self, monkeypatch
    ):
        import d810.backends.ast.z3 as z3mod
        from d810.backends.ast.z3 import Z3MopProver
        from d810.backends.ast.z3_proof_policy import Z3ProofPolicy, Z3ProofStatus

        class _FakeAst:
            def __init__(self, *, leaf):
                self.left = None
                self.right = None
                self._leaf = leaf

            def is_leaf(self):
                return self._leaf

            def get_leaf_list(self):
                return []

        class _FakeVisitor:
            def __init__(self, node_budget=None):
                self.node_budget = node_budget

            def visit(self, ast):
                self.node_budget.consume_ast(ast)
                return z3.BitVecVal(0, 32)

        initial = _FakeAst(leaf=True)
        definition = _FakeAst(leaf=False)
        definition.left = _FakeAst(leaf=True)

        def _initial_builder(_mop, *, node_budget):
            node_budget.consume()
            node_budget.mark_charged(initial)
            return initial

        def _definition_resolver(_mop, _blk, _ins, *, node_budget):
            for occurrence in (definition, definition.left):
                node_budget.consume()
                node_budget.mark_charged(occurrence)
            return definition

        monkeypatch.setattr(z3mod, "mop_to_ast", _initial_builder)
        monkeypatch.setattr(z3mod, "_resolve_mop_to_ast", _definition_resolver)
        monkeypatch.setattr(
            z3mod,
            "_recursively_resolve_ast",
            lambda ast, _blk, _ins, **_kwargs: ast,
        )
        monkeypatch.setattr(z3mod, "AstNodeZ3Visitor", _FakeVisitor)
        monkeypatch.setattr(z3mod, "structural_mop_hash", lambda _mop, _depth: 37)

        result = Z3MopProver(
            policy=Z3ProofPolicy(max_expression_nodes=3, proof_timeout_ms=100)
        ).prove_always_zero(
            SimpleNamespace(t=ida_hexrays.mop_r, size=4, name="cumulative"),
            blk=SimpleNamespace(mba=SimpleNamespace(owner="cumulative-mba")),
            ins=SimpleNamespace(label="cumulative-ins"),
        )

        assert result.status is Z3ProofStatus.PROVED
        assert result.observed_expression_nodes == 3

    @pytest.mark.parametrize("seam", ("native", "fallback", "memory_store"))
    @pytest.mark.parametrize("max_expression_nodes", (2, 3))
    def test_contextual_definition_builder_shares_policy_budget(
        self, monkeypatch, seam, max_expression_nodes
    ):
        """Definition trees built by every resolver seam are policy-bounded."""
        import d810.evaluator.hexrays_microcode.def_search as def_search
        import d810.hexrays.ir.minsn_utils as minsn_utils
        import d810.hexrays.ir.mop_utils as mop_utils
        from d810.backends.ast.z3_proof_policy import (
            Z3ExpressionNodeBudget,
            Z3NodeLimitExceeded,
            Z3ProofPolicy,
        )

        class _FakeSnapshot:
            @classmethod
            def from_mop(cls, mop):
                return SimpleNamespace(t=mop.t)

        class _FakeMop:
            pass

        class _InstructionMop(_FakeMop):
            def create_from_insn(self, instruction):
                self.__dict__.update(vars(instruction.source))

        def _number(name, value):
            mop = _FakeMop()
            mop.t = ida_hexrays.mop_n
            mop.size = 4
            mop.name = name
            mop.nnn = SimpleNamespace(value=value)
            mop.dstr = lambda: name
            return mop

        left = _number("left", 1)
        right = _number("right", 2)
        source = _FakeMop()
        source.t = ida_hexrays.mop_d
        source.size = 4
        source.name = "definition"
        source.d = SimpleNamespace(
            opcode=ida_hexrays.m_add,
            ea=0x1000,
            l=left,
            r=right,
            d=None,
        )
        source.dstr = lambda: "definition"
        definition = SimpleNamespace(
            opcode=ida_hexrays.m_add,
            d=SimpleNamespace(t=ida_hexrays.mop_r, r=7),
            ea=0x1000,
            source=source,
        )

        monkeypatch.setattr(mop_utils, "MopSnapshot", _FakeSnapshot)
        monkeypatch.setattr(minsn_utils.ida_hexrays, "mop_t", _InstructionMop)
        monkeypatch.setattr(
            mop_utils,
            "get_mop_key",
            lambda mop: (getattr(mop, "name", "anonymous"),),
        )
        monkeypatch.setattr(mop_utils, "format_mop_t", lambda mop: mop.name)
        monkeypatch.setattr(mop_utils, "sanitize_ea", lambda ea: ea)
        monkeypatch.setattr(
            mop_utils,
            "get_constant_mop",
            lambda value, size: SimpleNamespace(
                t=ida_hexrays.mop_n,
                size=size,
                nnn=SimpleNamespace(value=value),
            ),
        )

        def _build_definition(instruction, *, node_budget=None):
            return minsn_utils.minsn_to_ast(instruction, node_budget=node_budget)

        monkeypatch.setattr(def_search, "minsn_to_ast", _build_definition)

        mop = SimpleNamespace(t=ida_hexrays.mop_r, size=4, r=7)
        block = SimpleNamespace(mba=None, serial=1)
        instruction = SimpleNamespace(ea=0x2000, prev=None)

        if seam == "native":
            monkeypatch.setattr(
                def_search,
                "find_def_in_block",
                lambda _mop, _blk, _before: definition,
            )
            monkeypatch.setattr(def_search, "_USE_NATIVE_DEF_SEARCH", True)
            resolver_mop = mop
        elif seam == "fallback":
            class _Tracker:
                @staticmethod
                def reset():
                    return None

                def __init__(self, _mops, **_kwargs):
                    pass

                def search_backward(self, _blk, _ins):
                    return [SimpleNamespace(history=[SimpleNamespace(ins_list=[definition])])]

            monkeypatch.setattr(def_search, "_USE_NATIVE_DEF_SEARCH", False)
            monkeypatch.setitem(
                def_search.sys.modules,
                "d810.evaluator.hexrays_microcode.tracker",
                SimpleNamespace(MopTracker=_Tracker),
            )
            resolver_mop = mop
        else:
            address = SimpleNamespace(name="address")
            store = SimpleNamespace(
                opcode=ida_hexrays.m_stx,
                l=source,
                r=address,
                ea=0x1001,
                prev=None,
            )
            instruction.prev = store
            block.tail = store
            monkeypatch.setattr(def_search, "equal_mops_ignore_size", lambda *_args: True)
            monkeypatch.setattr(
                def_search,
                "mop_to_ast",
                lambda stored, *, node_budget=None: mop_utils.mop_to_ast(
                    stored,
                    node_budget=node_budget,
                ),
            )
            resolver_mop = SimpleNamespace(
                t=ida_hexrays.mop_d,
                d=SimpleNamespace(
                    opcode=ida_hexrays.m_ldx,
                    d=SimpleNamespace(t=ida_hexrays.mop_n),
                    r=address,
                ),
            )

        budget = Z3ExpressionNodeBudget(
            Z3ProofPolicy(
                max_expression_nodes=max_expression_nodes,
                proof_timeout_ms=100,
            )
        )
        if max_expression_nodes == 2:
            with pytest.raises(Z3NodeLimitExceeded):
                def_search.resolve_mop_to_ast(
                    resolver_mop,
                    block,
                    instruction,
                    node_budget=budget,
                )
            assert budget.observed_nodes == 2
        else:
            ast = def_search.resolve_mop_to_ast(
                resolver_mop,
                block,
                instruction,
                node_budget=budget,
            )
            assert ast is not None
            assert budget.observed_nodes == 3

    def test_compiled_recursive_resolver_receives_policy_budget(
        self, monkeypatch
    ):
        import d810.evaluator.hexrays_microcode.def_search as def_search
        from d810.backends.ast.z3_proof_policy import (
            Z3ExpressionNodeBudget,
            Z3NodeLimitExceeded,
            Z3ProofPolicy,
        )

        class _FakeAst:
            def is_leaf(self):
                return False

        ast = _FakeAst()
        budget = Z3ExpressionNodeBudget(
            Z3ProofPolicy(max_expression_nodes=1, proof_timeout_ms=100)
        )
        budget.consume()
        constructed = []
        received = []

        def _compiled(*args):
            policy_budget = args[-1]
            received.append(policy_budget)
            policy_budget.consume()
            constructed.append(object())
            return ast

        monkeypatch.setattr(def_search, "_compiled_recursively_resolve_ast", _compiled)
        with pytest.raises(Z3NodeLimitExceeded):
            def_search.recursively_resolve_ast(
                ast,
                SimpleNamespace(),
                SimpleNamespace(),
                node_budget=budget,
            )

        assert received == [budget]
        assert constructed == []

    def test_repeated_cached_subtree_charges_all_descendant_occurrences(
        self, monkeypatch
    ):
        import d810.hexrays.ir.mop_utils as mop_utils
        from d810.backends.ast.z3_proof_policy import (
            Z3ExpressionNodeBudget,
            Z3NodeLimitExceeded,
            Z3ProofPolicy,
        )

        class _Mop:
            pass

        def _leaf(name):
            mop = _Mop()
            mop.t = ida_hexrays.mop_r
            mop.size = 4
            mop.r = 1
            mop.valnum = 0
            mop.name = name
            mop.dstr = lambda: name
            return mop

        shared_leaf_left = _leaf("shared-left")
        shared_leaf_right = _leaf("shared-right")
        shared_subtree = _Mop()
        shared_subtree.t = ida_hexrays.mop_d
        shared_subtree.size = 4
        shared_subtree.name = "shared-subtree"
        shared_subtree.d = SimpleNamespace(
            opcode=ida_hexrays.m_add,
            ea=0,
            l=shared_leaf_left,
            r=shared_leaf_right,
            d=None,
        )
        root = _Mop()
        root.t = ida_hexrays.mop_d
        root.size = 4
        root.name = "root"
        root.d = SimpleNamespace(
            opcode=ida_hexrays.m_add,
            ea=0,
            l=shared_subtree,
            r=shared_subtree,
            d=None,
        )

        monkeypatch.setattr(mop_utils, "get_mop_key", lambda mop: (mop.name,))
        monkeypatch.setattr(mop_utils, "format_mop_t", lambda mop: mop.name)
        monkeypatch.setattr(mop_utils, "sanitize_ea", lambda ea: ea)

        class _FakeSnapshot:
            @classmethod
            def from_mop(cls, mop):
                return SimpleNamespace(t=mop.t)

        monkeypatch.setattr(
            mop_utils,
            "MopSnapshot",
            _FakeSnapshot,
        )

        low_budget = Z3ExpressionNodeBudget(
            Z3ProofPolicy(max_expression_nodes=5, proof_timeout_ms=100)
        )
        with pytest.raises(Z3NodeLimitExceeded):
            mop_utils.mop_to_ast_internal(
                root,
                mop_utils.AstBuilderContext(),
                node_budget=low_budget,
            )
        assert low_budget.observed_nodes == 5

        in_budget = Z3ExpressionNodeBudget(
            Z3ProofPolicy(max_expression_nodes=7, proof_timeout_ms=100)
        )
        ast = mop_utils.mop_to_ast_internal(
            root,
            mop_utils.AstBuilderContext(),
            node_budget=in_budget,
        )
        assert ast is not None
        assert in_budget.observed_nodes == 7

    @pytest.mark.parametrize(
        ("max_expression_nodes", "expected_status", "expected_observed"),
        (
            (1, "abstained", 1),
            (2, "proved", 2),
        ),
    )
    def test_contextual_nonleaf_replacement_shares_policy_budget(
        self, monkeypatch, max_expression_nodes, expected_status, expected_observed
    ):
        import d810.backends.ast.z3 as z3mod
        from d810.backends.ast.z3 import Z3MopProver
        from d810.backends.ast.z3_proof_policy import Z3ProofPolicy

        class _FakeAst:
            def is_leaf(self):
                return False

            def get_leaf_list(self):
                return []

        class _FakeVisitor:
            def __init__(self, node_budget=None):
                self.node_budget = node_budget

            def visit(self, ast):
                if self.node_budget is not None:
                    self.node_budget.consume_ast(ast)
                return z3.BitVecVal(0, 32)

        mop = SimpleNamespace(
            t=ida_hexrays.mop_d,
            size=4,
            name="contextual-nonleaf",
            d=SimpleNamespace(opcode=ida_hexrays.m_add),
        )
        blk = SimpleNamespace(mba=SimpleNamespace(owner="recursive-mba"))
        ins = SimpleNamespace(label="recursive-ins")
        monkeypatch.setattr(z3mod, "structural_mop_hash", lambda _mop, _depth: 29)
        monkeypatch.setattr(z3mod, "AstNodeZ3Visitor", _FakeVisitor)
        monkeypatch.setattr(
            z3mod,
            "mop_to_ast",
            lambda _mop, *, node_budget: node_budget.consume() or _FakeAst(),
        )
        monkeypatch.setattr(z3mod, "_resolve_mop_to_ast", lambda *_args: None)

        def _replace(_ast, _blk, _ins, *, node_budget=None):
            if node_budget is not None:
                node_budget.consume()
            replacement = _FakeAst()
            if node_budget is not None:
                node_budget.mark_charged(replacement)
            return replacement

        monkeypatch.setattr(z3mod, "_recursively_resolve_ast", _replace)

        result = Z3MopProver(
            policy=Z3ProofPolicy(
                max_expression_nodes=max_expression_nodes,
                proof_timeout_ms=100,
            )
        ).prove_always_zero(mop, blk=blk, ins=ins)

        assert result.status.value == expected_status
        assert result.observed_expression_nodes == expected_observed
