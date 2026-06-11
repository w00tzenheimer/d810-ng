"""Unit tests for Z3MopProver API surface."""
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
        assert callable(getattr(prover, 'are_equal', None))

    def test_prover_has_are_unequal(self):
        from d810.backends.ast.z3 import Z3MopProver
        prover = Z3MopProver()
        assert callable(getattr(prover, 'are_unequal', None))

    def test_prover_has_is_always_zero(self):
        from d810.backends.ast.z3 import Z3MopProver
        prover = Z3MopProver()
        assert callable(getattr(prover, 'is_always_zero', None))

    def test_prover_has_is_always_nonzero(self):
        from d810.backends.ast.z3 import Z3MopProver
        prover = Z3MopProver()
        assert callable(getattr(prover, 'is_always_nonzero', None))

    def test_prover_has_prove_equivalence(self):
        from d810.backends.ast.z3 import Z3MopProver
        prover = Z3MopProver()
        assert callable(getattr(prover, 'prove_equivalence', None))

    def test_prover_has_clear_caches(self):
        from d810.backends.ast.z3 import Z3MopProver
        prover = Z3MopProver()
        assert callable(getattr(prover, 'clear_caches', None))

    def test_prover_none_mops_are_equal_returns_false(self):
        from d810.backends.ast.z3 import Z3MopProver
        prover = Z3MopProver()
        assert prover.are_equal(None, None) is False

    def test_prover_none_mop_is_always_zero_returns_false(self):
        from d810.backends.ast.z3 import Z3MopProver
        prover = Z3MopProver()
        assert prover.is_always_zero(None) is False

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
        monkeypatch.setattr(
            z3mod, "structural_mop_hash", lambda m, _d: hash(m._ident)
        )
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
