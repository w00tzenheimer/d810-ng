"""3-valued lattice for Forward Constant Propagation.

Values:
    BOTTOM  – identity for meet (unknown / not-yet-seen)
    Const   – a known constant (value, size)
    TOP     – absorbing for meet (conflicting definitions)

Meet rules:
    meet(BOTTOM, x)       = x
    meet(TOP,    x)       = TOP
    meet(Const(v,s), Const(v,s)) = Const(v,s)
    meet(Const(a,_), Const(b,_)) = TOP   if a != b or sizes differ
"""
from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Union


# ---------------------------------------------------------------------------
# Sentinel values: BOTTOM and TOP
# ---------------------------------------------------------------------------

class _Sentinel(Enum):
    """Lattice sentinel values."""

    BOTTOM = "BOTTOM"
    TOP = "TOP"

    def __repr__(self) -> str:
        return self.value


BOTTOM: _Sentinel = _Sentinel.BOTTOM
TOP: _Sentinel = _Sentinel.TOP


# ---------------------------------------------------------------------------
# Const
# ---------------------------------------------------------------------------

@dataclass(frozen=True, slots=True)
class Const:
    """A known constant value with its byte size.

    Args:
        value: The integer constant value.
        size:  The operand size in bytes.
    """

    value: int
    size: int

    def __repr__(self) -> str:
        return f"Const(0x{self.value:x}, {self.size})"


# ---------------------------------------------------------------------------
# Type aliases
# ---------------------------------------------------------------------------

LatticeValue = Union[_Sentinel, Const]
LatticeEnv = dict[str, LatticeValue]


# ---------------------------------------------------------------------------
# lattice_meet
# ---------------------------------------------------------------------------

def lattice_meet(a: LatticeValue, b: LatticeValue) -> LatticeValue:
    """Compute the meet of two lattice values.

    Args:
        a: First lattice value.
        b: Second lattice value.

    Returns:
        The meet of a and b.
    """
    # BOTTOM is identity
    if a is BOTTOM:
        return b
    if b is BOTTOM:
        return a

    # TOP is absorbing
    if a is TOP or b is TOP:
        return TOP

    # Both are Const
    assert isinstance(a, Const) and isinstance(b, Const)
    if a.value == b.value and a.size == b.size:
        return a
    return TOP


# ---------------------------------------------------------------------------
# env_meet
# ---------------------------------------------------------------------------

def env_meet(a: LatticeEnv, b: LatticeEnv) -> LatticeEnv:
    """Pointwise meet over the union of keys in two LatticeEnvs.

    Missing keys are treated as BOTTOM (identity for meet).

    Args:
        a: First environment.
        b: Second environment.

    Returns:
        A new LatticeEnv that is the pointwise meet of a and b.
    """
    result: LatticeEnv = {}
    all_keys = a.keys() | b.keys()
    for key in all_keys:
        va = a.get(key, BOTTOM)
        vb = b.get(key, BOTTOM)
        met = lattice_meet(va, vb)
        result[key] = met
    return result


# ---------------------------------------------------------------------------
# LatticeMeet strategy
# ---------------------------------------------------------------------------

class LatticeMeet:
    """Meet strategy that folds a list of predecessor OUT environments.

    Usage::

        strategy = LatticeMeet()
        in_env = strategy.meet(pred_out_envs)
    """

    def meet(self, pred_outs: list[LatticeEnv]) -> LatticeEnv:
        """Compute the meet over all predecessor OUT environments.

        Args:
            pred_outs: List of OUT environments from predecessor blocks.

        Returns:
            A new LatticeEnv that is the meet of all inputs.
            - Empty list  → empty dict (no information).
            - Single env  → a copy of that env.
            - Multiple    → sequential pairwise env_meet.
        """
        if not pred_outs:
            return {}
        result: LatticeEnv = dict(pred_outs[0])
        for env in pred_outs[1:]:
            result = env_meet(result, env)
        return result
