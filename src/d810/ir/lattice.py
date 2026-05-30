"""Generic lattice infrastructure and constant-propagation domain.

Provides domain-agnostic building blocks (``BOTTOM``, ``TOP``, ``env_meet``,
``LatticeMeet``) that any forward-dataflow domain can reuse, plus the
concrete constant-propagation domain (``Const``, ``lattice_meet``).

Sentinel values:
    BOTTOM  – identity for meet (unknown / not-yet-seen)
    TOP     – absorbing for meet (conflicting definitions)

Constant-propagation meet rules:
    meet(BOTTOM, x)       = x
    meet(TOP,    x)       = TOP
    meet(Const(v,s), Const(v,s)) = Const(v,s)
    meet(Const(a,_), Const(b,_)) = TOP   if a != b or sizes differ
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum

from d810.core import getLogger
from d810.core.typing import Any, Callable, Optional, Union

logger = getLogger(__name__)


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

    # Both should be Const; if either is not, treat as conflict → TOP
    if not isinstance(a, Const) or not isinstance(b, Const):
        logger.warning(
            "lattice_meet: unexpected non-Const input: a=%r (type=%s), b=%r (type=%s); returning TOP",
            a,
            type(a).__name__,
            b,
            type(b).__name__,
        )
        return TOP
    if a.value == b.value and a.size == b.size:
        return a
    return TOP


# ---------------------------------------------------------------------------
# env_meet
# ---------------------------------------------------------------------------


def env_meet(
    a: dict,
    b: dict,
    *,
    default_missing: Any = BOTTOM,
    value_meet: Optional[Callable[[Any, Any], Any]] = None,
) -> dict:
    """Pointwise meet over the union of keys in two environments.

    Works with any key type and any value type — the per-value merge is
    delegated to *value_meet*.

    Args:
        a: First environment.
        b: Second environment.
        default_missing: Value used for keys absent from one side.
            ``BOTTOM`` (default) is aggressive — missing keys are treated as
            the identity for meet, so a value present in one env survives.
            ``TOP`` is conservative — missing keys kill the value.
        value_meet: Callable ``(v1, v2) -> merged``.  Defaults to
            :func:`lattice_meet` (the constant-propagation domain).

    Returns:
        A new dict that is the pointwise meet of *a* and *b*.
    """
    if value_meet is None:
        value_meet = lattice_meet
    result: dict = {}
    all_keys = a.keys() | b.keys()
    for key in all_keys:
        va = a.get(key, default_missing)
        vb = b.get(key, default_missing)
        met = value_meet(va, vb)
        result[key] = met
    return result


# ---------------------------------------------------------------------------
# LatticeMeet strategy
# ---------------------------------------------------------------------------


class LatticeMeet:
    """Meet strategy that folds a list of predecessor OUT environments.

    Domain-agnostic: works with any key/value types.  The per-value merge
    is delegated to *value_meet* (defaults to :func:`lattice_meet` for the
    constant-propagation domain).

    Args:
        default_missing: Value used for keys absent from one predecessor.
            ``BOTTOM`` (default) is aggressive — missing keys are identity for
            meet, so values present in only one predecessor survive.
            ``TOP`` is conservative — missing keys kill the value.
        value_meet: Callable ``(v1, v2) -> merged``.  Defaults to
            :func:`lattice_meet`.

    Usage::

        # Constant-propagation (default)
        strategy = LatticeMeet()
        conservative = LatticeMeet(default_missing=TOP)

        # Custom domain
        strategy = LatticeMeet(value_meet=my_domain_meet, default_missing=MY_TOP)

        in_env = strategy.meet(pred_out_envs)
    """

    def __init__(
        self,
        *,
        default_missing: Any = BOTTOM,
        value_meet: Optional[Callable[[Any, Any], Any]] = None,
    ):
        self._default_missing = default_missing
        self._value_meet = value_meet

    def meet(self, pred_outs: list[dict]) -> dict:
        """Compute the meet over all predecessor OUT environments.

        Args:
            pred_outs: List of OUT environments from predecessor blocks.

        Returns:
            A new dict that is the meet of all inputs.
            - Empty list  → empty dict (no information).
            - Single env  → a copy of that env.
            - Multiple    → sequential pairwise :func:`env_meet`.
        """
        if not pred_outs:
            return {}
        result: dict = dict(pred_outs[0])
        for env in pred_outs[1:]:
            result = env_meet(
                result,
                env,
                default_missing=self._default_missing,
                value_meet=self._value_meet,
            )
        return result
