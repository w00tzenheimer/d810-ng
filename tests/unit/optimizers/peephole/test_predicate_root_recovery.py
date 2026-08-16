"""Pure contracts for generalized finite-zero-set predicate recovery."""

from __future__ import annotations

import importlib
import importlib.util

import pytest


_MODULE = "d810.optimizers.microcode.instructions.peephole.predicate_root_recovery"


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
    pytest.importorskip("z3")
    module = importlib.import_module(_MODULE)
    variable = module.Variable("input", 32)
    predicate = _partitioned_affine_predicate(variable)
    recovered = module.recover_finite_zero_set_predicate(predicate)

    assert recovered is not None
    assert module.z3_proves_finite_zero_set_predicate(predicate, recovered)
