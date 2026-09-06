"""Pure contracts for generalized finite-zero-set predicate recovery."""

from __future__ import annotations

import dataclasses
import importlib
import importlib.util

import pytest


_MODULE = "d810.optimizers.microcode.instructions.peephole.predicate_root_recovery"

# Derivation of the deterministic Z3 budget used below in place of
# production's 100 ms wall-clock `timeout_ms` (see
# z3_proves_finite_zero_set_predicate's `rlimit` kwarg,
# predicate_root_recovery.py:415-433). Z3's rlimit counts internal solver
# ticks, which do not vary with host CPU contention, so this converts the
# production wall-clock budget into its tick-equivalent instead of fitting
# a value to this test's own observed proof cost.
#
# Measured 2026-09-06 on an Apple M5 Pro (Darwin 25.5.0, arm64), z3 4.13.0:
# five fresh `z3.Solver()` proofs of this exact predicate, each run with
# `rlimit=0` (unbounded) and timed, gave a ticks-per-ms throughput of
# 7,318.8-9,108.1 (`solver.statistics().get_key_value("rlimit count")`
# per call, divided by that call's wall time -- the counter is cumulative
# across `Solver()` instances in one process, so per-call ticks must be
# differenced, not read as-is). Scaled to the production 100 ms deadline,
# that is a 731,876-910,805 tick-equivalent budget on this host. This
# constant is 2x that measured upper bound, rounded up: it enforces a
# budget derived from what production actually funds, not from this
# proof's own ~46,800-93,200-tick cost.
_PRODUCTION_BUDGET_EQUIVALENT_RLIMIT = 2_000_000


def _api():
    assert importlib.util.find_spec(_MODULE) is not None, "predicate-root recovery module is missing"
    module = importlib.import_module(_MODULE)
    return (
        module.Binary,
        module.Constant,
        module.Predicate,
        module.Unary,
        module.Variable,
        module.recover_finite_zero_set_predicate,
    )


def _mul(value: int, expression):
    Binary, Constant, _, _, _, _ = _api()
    return Binary("mul", 32, Constant(value, 32), expression)


def _and(expression, value: int):
    Binary, Constant, _, _, _, _ = _api()
    return Binary("and", expression.width, expression, Constant(value, expression.width))


def _partitioned_affine_predicate(variable, *, byte_term=True, byte_input=False):
    """A member of the family; the values are intentionally not its identity."""

    Binary, Constant, Predicate, Unary, _, _ = _api()
    inverted = Unary("bnot", 32, variable)
    masked_inverted = _and(inverted, 0xFFFFFF8F)
    low_mask = _and(inverted, 0x70)
    byte_inverted = Unary("bnot", 8, Unary("low8", 8, variable))
    byte_low_mask = Binary("zext", 32, _and(byte_inverted, 0x70), None)
    byte_input_mask = Binary("zext", 32, _and(Unary("low8", 8, variable), 0x70), None)
    expression = Binary(
        "sub",
        32,
        Binary(
            "sub",
            32,
            Binary(
                "sub",
                32,
                Binary(
                    "sub",
                    32,
                    _mul(0xB, inverted),
                    _mul(7, Binary("or", 32, inverted, Constant(0x70, 32))),
                ),
                _mul(6, byte_input_mask if byte_input else _and(variable, 0x70)),
            ),
            _mul(0x12, masked_inverted),
        ),
        _mul(0x12, byte_low_mask if byte_term else low_mask),
    )
    return Predicate("ne", expression, Constant(0, 32), 1)


def test_recovers_a_bounded_partitioned_affine_predicate_after_typed_normalization() -> None:
    _, _, _, _, Variable, recover = _api()
    variable = Variable("input", 32)

    for predicate in (
        _partitioned_affine_predicate(variable),
        _partitioned_affine_predicate(variable, byte_term=False),
        _partitioned_affine_predicate(variable, byte_input=True),
    ):
        recovered = recover(predicate)

        assert recovered is not None
        assert recovered.variable == variable
        assert recovered.mask == 0x70
        assert recovered.excluded_values == (0x124924AF, 0x924924AF)


def test_rejects_non_predicate_roots_and_more_than_one_symbol() -> None:
    Binary, Constant, Predicate, _, Variable, recover = _api()
    variable = Variable("input", 32)
    other = Variable("other", 32)

    root = _partitioned_affine_predicate(variable)
    wrong_root = Predicate("eq", root.left, Constant(0, 32), 1)
    two_leaf = Predicate(
        "ne",
        Binary("add", 32, root.left, other),
        Constant(0, 32),
        1,
    )
    assert recover(wrong_root) is None
    assert recover(two_leaf) is None


def test_complete_masked_affine_solver_is_parameterized_not_fixture_specific() -> None:
    module = importlib.import_module(_MODULE)

    values = module.solve_masked_affine_zeroes(
        width=8,
        mask=0x03,
        outside_coefficient=1,
        masked_coefficient=1,
        constant=0,
        max_mask_bits=2,
    )

    # q + a == 0 has only ~input == 0, independently of the PEB-shaped input.
    assert values == (0xFF,)
    assert (
        module.solve_masked_affine_zeroes(
            width=32,
            mask=0x70,
            outside_coefficient=-14,
            masked_coefficient=-1,
            constant=-0x5B0,
            max_mask_bits=2,
        )
        is None
    )


def test_z3_independently_proves_the_recovered_predicate() -> None:
    """Regression guard for a RESOURCE-class flake (seen at host load ~36).

    The production path bounds this proof with a 100 ms wall-clock
    ``timeout_ms``, which exists to keep a live decompile responsive but
    makes the *test's* outcome depend on host CPU contention rather than on
    the property being proved.
    ``_PRODUCTION_BUDGET_EQUIVALENT_RLIMIT`` (see its derivation comment
    above) converts that same production budget into Z3's ``rlimit``
    resource-tick unit, which is unaffected by other processes competing
    for the CPU, and stays >2x within what the 100 ms deadline itself
    funds -- so this does not loosen the property being proved, it removes
    wall-clock noise from measuring it.
    """
    pytest.importorskip("z3")
    module = importlib.import_module(_MODULE)
    variable = module.Variable("input", 32)
    predicate = _partitioned_affine_predicate(variable)
    recovered = module.recover_finite_zero_set_predicate(predicate)

    assert recovered is not None
    assert module.z3_proves_finite_zero_set_predicate(
        predicate, recovered, rlimit=_PRODUCTION_BUDGET_EQUIVALENT_RLIMIT
    )


def test_production_wall_clock_exhaustion_matches_rlimit_exhaustion(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The production timeout_ms branch and the test's rlimit branch fail alike.

    ``z3_proves_finite_zero_set_predicate`` has two mutually exclusive budget
    branches (predicate_root_recovery.py:490-495): production's wall-clock
    ``timeout_ms`` (the default, taken by the sole production caller,
    ``predicate_root_recovery_native.py:229``) and this suite's ``rlimit``
    override. Both feed the same ``solver.check() == z3.unsat`` comparison
    (predicate_root_recovery.py:497), so an exhausted budget should produce
    ``z3.unknown`` either way, which compares ``False`` with no exception on
    both paths -- checked here rather than assumed.
    """
    pytest.importorskip("z3")
    module = importlib.import_module(_MODULE)
    variable = module.Variable("input", 32)
    predicate = _partitioned_affine_predicate(variable)
    recovered = module.recover_finite_zero_set_predicate(predicate)
    assert recovered is not None

    # rlimit=1: effectively zero solver ticks before Z3 gives up.
    rlimit_exhausted = module.z3_proves_finite_zero_set_predicate(
        predicate, recovered, rlimit=1
    )

    # Force the PRODUCTION (default, wall-clock) branch to a 1 ms deadline.
    # This exact proof measured 46,800-93,200 ticks and 5.78-11.82 ms wall
    # clock unbounded on this host (see the derivation comment above) --
    # comfortably longer than 1 ms -- and any additional host contention
    # only makes it slower, never faster, so forcing this branch to expire
    # is not itself host-load-flaky in the direction that matters here.
    tiny_timeout = dataclasses.replace(
        module.FiniteZeroSetPredicateRule.CONSTRAINTS[-1], timeout_ms=1
    )
    monkeypatch.setattr(
        module.FiniteZeroSetPredicateRule,
        "CONSTRAINTS",
        (*module.FiniteZeroSetPredicateRule.CONSTRAINTS[:-1], tiny_timeout),
    )
    wall_clock_exhausted = module.z3_proves_finite_zero_set_predicate(
        predicate, recovered
    )

    assert rlimit_exhausted is False
    assert wall_clock_exhausted is False
    assert rlimit_exhausted == wall_clock_exhausted
