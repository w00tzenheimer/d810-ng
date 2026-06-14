"""Division and modulo MBA simplification rules."""

from __future__ import annotations

from dataclasses import dataclass

from d810.mba.dsl import Const, High, Umod, Var, Zext
from d810.mba.rules._base import VerifiableRule

_ALL_MATURITIES = [2, 3, 4, 5]

x = Var("x_0")
magic = Var("magic")

ONE = Const("1", 1)


@dataclass(frozen=True)
class UnsignedMagicModSpec:
    """Parameters for unsigned magic-divide remainder recovery.

    Canonical identity:

        x - d * (high(zext(x) * magic) >> shift) == x %u d

    ``magic`` remains a runtime operand in the DSL pattern because Hex-Rays can
    expose it through a folded local/temporary expression before
    constant-subtree cleanup materializes the literal.
    """

    divisor: int
    magic: int
    x_bits: int = 32
    zext_bits: int = 64
    high_bits: int = 32
    shift: int = 1

    @property
    def divisor_const(self):
        return Const(str(self.divisor), self.divisor)

    @property
    def shift_const(self):
        return Const(str(self.shift), self.shift)


def make_unsigned_magic_mod_rule(spec: UnsignedMagicModSpec):
    """Create a rule for one unsigned magic-divide remainder identity."""
    divisor = spec.divisor_const
    shift = spec.shift_const
    rule_name = f"UnsignedMagicModulo{spec.divisor}Rule"
    pattern = x - (
        divisor
        * (High(Zext(x, spec.zext_bits) * magic, spec.high_bits) >> shift)
    )

    def check_candidate(self, candidate) -> bool:
        try:
            x_mop = candidate["x_0"].mop
            if hasattr(x_mop, "to_mop"):
                x_mop = x_mop.to_mop()
            magic_mop = candidate["magic"].mop
        except Exception:
            return False

        if x_mop is None or getattr(x_mop, "size", None) != spec.x_bits // 8:
            return False
        if not _candidate_widths_match(candidate, spec, x_mop, magic_mop):
            return False

        evaluator = getattr(self, "_runtime_constant_evaluator", None)
        if evaluator is None:
            return False
        magic_value = evaluator(magic_mop, bits=spec.zext_bits)
        if magic_value is None:
            return False
        mask = (1 << spec.zext_bits) - 1
        return (int(magic_value) & mask) == spec.magic

    return type(
        rule_name,
        (VerifiableRule,),
        {
            "__module__": __name__,
            "__doc__": (
                f"Recover ``x %u {spec.divisor}`` from an unsigned "
                "magic-divide remainder sequence."
            ),
            "_SPEC": spec,
            "maturities": _ALL_MATURITIES,
            "PATTERN": pattern,
            "REPLACEMENT": Umod(x, divisor),
            "GENERATE_COMMUTATIVE_PERMUTATIONS": False,
            "SKIP_VERIFICATION": True,
            "DESCRIPTION": (
                "Simplify unsigned magic divide-by-"
                f"{spec.divisor} remainder to x %u {spec.divisor}"
            ),
            "REFERENCE": "Hacker's Delight unsigned division by invariant integer",
            "check_candidate": check_candidate,
        },
    )


def _size_bytes(obj) -> int | None:
    if obj is None:
        return None
    for attr in ("size", "dest_size"):
        try:
            value = getattr(obj, attr, None)
        except Exception:
            value = None
        if value is not None and int(value) > 0:
            return int(value)
    try:
        dst_mop = getattr(obj, "dst_mop", None)
    except Exception:
        dst_mop = None
    if dst_mop is not None:
        return _size_bytes(dst_mop)
    try:
        mop = getattr(obj, "mop", None)
    except Exception:
        mop = None
    if mop is not None:
        return _size_bytes(mop)
    return None


def _constant_value(obj) -> int | None:
    if obj is None:
        return None
    for attr in ("value", "expected_value"):
        try:
            value = getattr(obj, attr, None)
        except Exception:
            value = None
        if value is not None:
            return int(value)
    try:
        mop = getattr(obj, "mop", None)
    except Exception:
        mop = None
    if mop is not None:
        return _constant_value(mop)
    try:
        nnn = getattr(obj, "nnn", None)
        if nnn is not None:
            return int(nnn.value)
    except Exception:
        return None
    return None


def _child(node, name: str):
    try:
        return getattr(node, name)
    except Exception:
        return None


def _candidate_widths_match(
    candidate,
    spec: UnsignedMagicModSpec,
    x_mop,
    magic_mop,
) -> bool:
    """Validate the matched canonical tree carries the expected widths."""
    x_size = spec.x_bits // 8
    zext_size = spec.zext_bits // 8
    high_size = spec.high_bits // 8

    # Validate the result width of the matched subtraction.  In the live IDA
    # adapter path the matched pattern node carries no ``dst_mop`` (only the
    # enclosing instruction does), so fall back to the node's own size
    # (``size``/``dest_size``) when ``dst_mop`` is absent.
    result_size = _size_bytes(getattr(candidate, "dst_mop", None))
    if result_size is None:
        result_size = _size_bytes(candidate)
    if result_size != x_size:
        return False

    divisor_mul = _child(candidate, "right")
    divisor_leaf = _child(divisor_mul, "left")
    shift_node = _child(divisor_mul, "right")
    high_node = _child(shift_node, "left")
    shift_leaf = _child(shift_node, "right")
    product_node = _child(high_node, "left")
    zext_node = _child(product_node, "left")
    magic_leaf = _child(product_node, "right")
    zext_x_leaf = _child(zext_node, "left")

    expected_sizes = (
        (divisor_mul, x_size),
        (shift_node, high_size),
        (high_node, high_size),
        (product_node, zext_size),
        (zext_node, zext_size),
        (zext_x_leaf, x_size),
        (magic_leaf, zext_size),
        (x_mop, x_size),
        (magic_mop, zext_size),
    )
    for node, size in expected_sizes:
        if _size_bytes(node) != size:
            return False

    divisor_value = _constant_value(divisor_leaf)
    if divisor_value is not None and divisor_value != spec.divisor:
        return False
    shift_value = _constant_value(shift_leaf)
    if shift_value is not None and shift_value != spec.shift:
        return False
    return True


UnsignedMagicModulo3Rule = make_unsigned_magic_mod_rule(
    UnsignedMagicModSpec(
        divisor=3,
        magic=0xAAAAAAAB,
        shift=1,
    )
)
