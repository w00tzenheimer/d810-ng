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

    def test_prover_instantiation_no_context(self):
        from d810.backends.ast.z3 import Z3MopProver

        prover = Z3MopProver()
        assert prover is not None

    def test_prover_instantiation_with_context(self):
        from d810.backends.ast.z3 import Z3MopProver

        prover = Z3MopProver(blk=None, ins=None)
        assert prover is not None

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
            lambda _mop, _blk, ins: _FakeAst(0 if ins.label == "ins-a" else 1),
        )
        monkeypatch.setattr(
            z3mod, "_recursively_resolve_ast", lambda ast, _blk, _ins: ast
        )

        prover = Z3MopProver(
            policy=Z3ProofPolicy(max_expression_nodes=1, proof_timeout_ms=100)
        )
        first = prover.prove_always_zero(mop, blk=blk_a, ins=ins_a)
        second = prover.prove_always_zero(mop, blk=blk_b, ins=ins_b)

        assert first.status is Z3ProofStatus.PROVED
        assert first.observed_expression_nodes == 1
        assert second.status is Z3ProofStatus.DISPROVED
        assert second.observed_expression_nodes == 1

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
        monkeypatch.setattr(z3mod, "_resolve_mop_to_ast", lambda *_args: _FakeAst())
        monkeypatch.setattr(
            z3mod, "_recursively_resolve_ast", lambda ast, _blk, _ins: ast
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

            def visit(self, _ast):
                if self.node_budget is not None:
                    self.node_budget.consume()
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
        monkeypatch.setattr(
            z3mod, "_recursively_resolve_ast", lambda _ast, _blk, _ins: _FakeAst()
        )

        result = Z3MopProver(
            policy=Z3ProofPolicy(
                max_expression_nodes=max_expression_nodes,
                proof_timeout_ms=100,
            )
        ).prove_always_zero(mop, blk=blk, ins=ins)

        assert result.status.value == expected_status
        assert result.observed_expression_nodes == expected_observed
