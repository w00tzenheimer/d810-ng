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
