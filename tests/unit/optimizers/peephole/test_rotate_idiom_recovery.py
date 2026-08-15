"""Pure contracts for the narrow 64-bit rotate idiom matcher."""

from __future__ import annotations

import importlib
import importlib.util

import pytest

MASK64 = (1 << 64) - 1
C1 = 0x87C37B91114253D5
C2 = 0x4CF5AD432745937F
_MODULE = "d810.optimizers.microcode.instructions.peephole.rotate_idiom_recovery"


def _api():
    assert importlib.util.find_spec(_MODULE) is not None, "rotate idiom matcher module is missing"
    module = importlib.import_module(_MODULE)
    return module.Binary, module.Constant, module.Variable, module.match_rol64_idiom


def _mul(left, right):
    Binary, _, _, _ = _api()
    return Binary("mul", 64, left, right)


def _rol_idiom(constant: int, variable, rotation: int, *, swap_or: bool, swap_mul: bool):
    Binary, Constant, _, _ = _api()
    base = _mul(Constant(constant, 64), variable)
    shifted_constant = Constant((constant << rotation) & MASK64, 64)
    shifted_product = _mul(
        variable if swap_mul else shifted_constant,
        shifted_constant if swap_mul else variable,
    )
    right_shift = Binary(
        "shr",
        64,
        _mul(variable if swap_mul else Constant(constant, 64), Constant(constant, 64) if swap_mul else variable),
        Constant(64 - rotation, 8),
    )
    return Binary(
        "or",
        64,
        right_shift if swap_or else shifted_product,
        shifted_product if swap_or else right_shift,
    ), base


@pytest.mark.parametrize("constant,rotation", [(C1, 31), (C2, 33)])
@pytest.mark.parametrize("swap_or", [False, True])
@pytest.mark.parametrize("swap_mul", [False, True])
def test_matches_murmur_rotate_idiom_under_only_commuted_or_and_mul(
    constant: int, rotation: int, swap_or: bool, swap_mul: bool
) -> None:
    _, _, Variable, match_rol64_idiom = _api()
    source, expected_base = _rol_idiom(
        constant,
        Variable("input", 64),
        rotation,
        swap_or=swap_or,
        swap_mul=swap_mul,
    )

    match = match_rol64_idiom(source)

    assert match is not None
    assert match.base == expected_base
    assert match.rotation == rotation


def test_rejects_non_exact_or_mixed_width_rotate_lookalikes() -> None:
    Binary, Constant, Variable, match_rol64_idiom = _api()
    source, _ = _rol_idiom(
        C1,
        Variable("input", 64),
        31,
        swap_or=False,
        swap_mul=False,
    )

    lookalikes = (
        Binary("or", 64, _mul(Constant(0x1234, 64), Variable("input", 64)), source.right),
        Binary("or", 64, source.left, Binary("shr", 64, source.right.left, Constant(32, 8))),
        Binary(
            "or",
            64,
            source.left,
            Binary("shr", 64, _mul(Constant(C1, 64), Variable("other", 64)), source.right.right),
        ),
        Binary("or", 32, source.left, source.right),
    )

    assert all(match_rol64_idiom(lookalike) is None for lookalike in lookalikes)


def test_z3_proves_every_fixed_nonzero_64_bit_rotation() -> None:
    z3 = pytest.importorskip("z3")
    value = z3.BitVec("value", 64)
    constant = z3.BitVecVal(C1, 64)

    for rotation in range(1, 64):
        base = constant * value
        recovered = (
            (z3.BitVecVal((C1 << rotation) & MASK64, 64) * value)
            | z3.LShR(base, 64 - rotation)
        )
        rol = (base << rotation) | z3.LShR(base, 64 - rotation)
        solver = z3.Solver()
        solver.add(recovered != rol)
        assert solver.check() == z3.unsat, f"rotation {rotation} is not equivalent"
