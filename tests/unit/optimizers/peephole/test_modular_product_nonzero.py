"""Contracts for modular-product nonzero predicate recovery."""

from __future__ import annotations

import importlib
import importlib.util

import pytest


_MODULE = "d810.optimizers.microcode.instructions.peephole.modular_product_nonzero"
_AST = "d810.optimizers.microcode.instructions.peephole.predicate_root_recovery"


def _api():
    assert importlib.util.find_spec(_MODULE) is not None, "modular-product recovery module is missing"
    module = importlib.import_module(_MODULE)
    ast = importlib.import_module(_AST)
    return ast.Binary, ast.Constant, ast.Predicate, ast.Unary, ast.Variable, module


def _mul(left, right):
    Binary, _, _, _, _, _ = _api()
    return Binary("mul", 32, left, right)


def _and(left, right):
    Binary, _, _, _, _, _ = _api()
    return Binary("and", 32, left, right)


def _product_predicate(variable):
    Binary, Constant, Predicate, Unary, _, _ = _api()
    u = Unary("bnot", 32, variable)
    low_u = Unary("bnot", 8, Unary("low8", 8, variable))
    factors = (
        Constant(11, 32),
        Constant(7, 32),
        Constant(6, 32),
        Constant(0x12, 32),
        Constant(0x12, 32),
        u,
        Binary("or", 32, u, Constant(0x70, 32)),
        _and(variable, Constant(0x70, 32)),
        _and(u, Constant(0xFFFFFF8F, 32)),
        Binary("zext", 32, Binary("and", 8, low_u, Constant(0x70, 8)), None),
    )
    product = factors[0]
    for factor in factors[1:]:
        product = _mul(product, factor)
    return Predicate("ne", product, Constant(0, 32), 1)


def test_recovers_the_generalized_masked_modular_product_budget() -> None:
    _, _, _, _, Variable, module = _api()
    predicate = _product_predicate(Variable("input", 32))

    match = module.recover_modular_product_nonzero(predicate)

    assert match is not None
    assert match.mask == 0x70
    assert match.constant_trailing_zeroes == 3
    assert match.trailing_zero_budget == 29


def test_rejects_a_product_missing_one_complementary_factor() -> None:
    Binary, Constant, Predicate, Unary, Variable, module = _api()
    variable = Variable("input", 32)
    u = Unary("bnot", 32, variable)
    product = _mul(
        _mul(Constant(6, 32), _and(variable, Constant(0x70, 32))),
        _mul(Constant(0x12, 32), _and(u, Constant(0xFFFFFF8F, 32))),
    )

    assert module.recover_modular_product_nonzero(Predicate("ne", product, Constant(0, 32), 1)) is None


def test_z3_proves_the_ctz_budget_for_the_entire_32_bit_domain() -> None:
    pytest.importorskip("z3")
    _, _, _, _, Variable, module = _api()
    predicate = _product_predicate(Variable("input", 32))
    match = module.recover_modular_product_nonzero(predicate)

    assert match is not None
    assert module.z3_proves_modular_product_nonzero(predicate, match)
