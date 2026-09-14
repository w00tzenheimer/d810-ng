from __future__ import annotations

import pytest
import threading

from d810.backends.ast import z3 as backend
from d810.backends.ast.z3_proof_policy import Z3ProofPolicy


pytestmark = pytest.mark.skipif(
    not backend.Z3_INSTALLED,
    reason="runtime Z3 backend is unavailable",
)


class _Assertion:
    def __init__(self, text: str) -> None:
        self._text = text

    def sexpr(self) -> str:
        return self._text


class _Solver:
    def __init__(self, assertions: tuple[str, ...], result) -> None:
        self._assertions = tuple(_Assertion(text) for text in assertions)
        self._result = result
        self.checks = 0

    def assertions(self):
        return self._assertions

    def sexpr(self) -> str:
        return "\n".join(f"(assert {item.sexpr()})" for item in self._assertions)

    def check(self):
        self.checks += 1
        return self._result


class _BlockingSolver(_Solver):
    def __init__(
        self,
        assertions: tuple[str, ...],
        result,
        *,
        started: threading.Event,
        release: threading.Event,
    ) -> None:
        super().__init__(assertions, result)
        self._started = started
        self._release = release

    def check(self):
        self.checks += 1
        self._started.set()
        if not self._release.wait(timeout=5):
            raise TimeoutError("test did not release the blocking solver")
        return self._result


@pytest.fixture(autouse=True)
def _clean_query_cache():
    backend._clear_bounded_query_result_cache()
    yield
    backend._clear_bounded_query_result_cache()


def _check(solver, policy, *, cache_allowed=True):
    return backend._check_bounded_query(
        solver,
        policy=policy,
        cache_allowed=cache_allowed,
    )


def test_identical_complete_query_reuses_one_conclusive_result() -> None:
    policy = Z3ProofPolicy(max_expression_nodes=50, proof_timeout_ms=25)
    first = _Solver(("(= x #x00)",), backend.z3.unsat)
    second = _Solver(("(= x #x00)",), backend.z3.sat)

    assert _check(first, policy) == backend.z3.unsat
    assert _check(second, policy) == backend.z3.unsat
    assert first.checks == 1
    assert second.checks == 0
    stats = backend.bounded_query_result_cache_stats()
    assert (stats.hits, stats.misses, stats.size, stats.insertions) == (1, 1, 1, 1)


def test_complete_assertions_and_policy_are_part_of_equality() -> None:
    low = Z3ProofPolicy(max_expression_nodes=50, proof_timeout_ms=25)
    high = Z3ProofPolicy(max_expression_nodes=50, proof_timeout_ms=50)
    first = _Solver(("(= x #x00)",), backend.z3.unsat)
    different_assertion = _Solver(("(= x #x01)",), backend.z3.sat)
    different_policy = _Solver(("(= x #x00)",), backend.z3.sat)

    assert _check(first, low) == backend.z3.unsat
    assert _check(different_assertion, low) == backend.z3.sat
    assert _check(different_policy, high) == backend.z3.sat
    assert (first.checks, different_assertion.checks, different_policy.checks) == (
        1,
        1,
        1,
    )


def test_same_assertion_text_with_different_declarations_does_not_collide() -> None:
    policy = Z3ProofPolicy(max_expression_nodes=50, proof_timeout_ms=25)
    one_bit = backend.z3.Solver()
    one_bit_values = backend.z3.BitVecs("x y z", 1)
    one_bit.add(backend.z3.Distinct(*one_bit_values))
    two_bit = backend.z3.Solver()
    two_bit_values = backend.z3.BitVecs("x y z", 2)
    two_bit.add(backend.z3.Distinct(*two_bit_values))

    assert one_bit.assertions()[0].sexpr() == two_bit.assertions()[0].sexpr()
    assert _check(one_bit, policy) == backend.z3.unsat
    assert _check(two_bit, policy) == backend.z3.sat


def test_unknown_and_explicitly_ineligible_checks_are_never_reused() -> None:
    policy = Z3ProofPolicy(max_expression_nodes=50, proof_timeout_ms=25)
    unknown_first = _Solver(("hard",), backend.z3.unknown)
    unknown_second = _Solver(("hard",), backend.z3.unsat)
    disabled_first = _Solver(("easy",), backend.z3.unsat)
    disabled_second = _Solver(("easy",), backend.z3.sat)

    assert _check(unknown_first, policy) == backend.z3.unknown
    assert _check(unknown_second, policy) == backend.z3.unsat
    assert _check(disabled_first, policy, cache_allowed=False) == backend.z3.unsat
    assert _check(disabled_second, policy, cache_allowed=False) == backend.z3.sat
    assert (
        unknown_first.checks,
        unknown_second.checks,
        disabled_first.checks,
        disabled_second.checks,
    ) == (1, 1, 1, 1)


def test_decompilation_reset_clears_shared_query_results() -> None:
    policy = Z3ProofPolicy(max_expression_nodes=50, proof_timeout_ms=25)
    first = _Solver(("(= x #x00)",), backend.z3.unsat)
    after_reset = _Solver(("(= x #x00)",), backend.z3.sat)

    assert _check(first, policy) == backend.z3.unsat
    backend.Z3MopProver().clear_caches()
    assert _check(after_reset, policy) == backend.z3.sat
    assert after_reset.checks == 1


def test_old_session_solve_cannot_publish_after_generation_reset() -> None:
    policy = Z3ProofPolicy(max_expression_nodes=50, proof_timeout_ms=25)
    started = threading.Event()
    release = threading.Event()
    old_solver = _BlockingSolver(
        ("(= x #x00)",),
        backend.z3.unsat,
        started=started,
        release=release,
    )
    result = []
    worker = threading.Thread(target=lambda: result.append(_check(old_solver, policy)))
    worker.start()
    assert started.wait(timeout=5)

    backend._clear_bounded_query_result_cache()
    release.set()
    worker.join(timeout=5)
    assert not worker.is_alive()
    assert result == [backend.z3.unsat]

    new_solver = _Solver(("(= x #x00)",), backend.z3.sat)
    assert _check(new_solver, policy) == backend.z3.sat
    assert new_solver.checks == 1
    stats = backend.bounded_query_result_cache_stats()
    assert (stats.hits, stats.misses, stats.size, stats.insertions) == (0, 1, 1, 1)
