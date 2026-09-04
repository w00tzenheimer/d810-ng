"""Pure decisions for synthetic-return taint (ticket ``d81-0xzp``).

IDA-free by construction: the helpers take plain operand keys, so the rule the
concrete emulator applies when it models an unsupported call as a *synthetic*
return is testable without a live ``mba_t``.

Why taint has to be carried separately from the value: a synthetic return is
tagged only in its HIGH bits (``SyntheticCallReturnCache.DEFAULT_TAG`` over a
48-bit mask).  Masking that value to a 4-byte destination destroys the tag, so a
32-bit state value derived from a synthetic return is NOT recognisable by its
bits.  Provenance therefore travels as a set of tainted operand keys, and any
consumer that needs a PROVEN value (a dispatcher state write, a fake-jump path
comparison) abstains when the key it reads is in that set.

Ticket ``d81-1t9x`` makes that abstention structural rather than per-consumer:
exactness is part of the evaluator's RESULT (:class:`EvalResult`), so a consumer
that only accepts an ``int`` receives ``None`` for a tainted value and cannot
mistake an invented integer for a proven one.
"""

from __future__ import annotations

import dataclasses
import enum

from d810.core.typing import Collection, Hashable, Iterable

__all__ = [
    "EvalResult",
    "Exactness",
    "address_from_eval_result",
    "any_tainted",
    "taint_location_key",
    "taint_result",
]


class Exactness(enum.Enum):
    """How much the evaluator can claim about a value it produced.

    ``EXACT``     the value is proven by evaluation of proven operands;
    ``TAINTED``   an integer was produced, but it derives from a result the
                  emulator INVENTED (an unmodeled call) -- usable for
                  propagation, never for a decision;
    ``UNKNOWN``   no value at all.
    """

    EXACT = "exact"
    TAINTED = "tainted"
    UNKNOWN = "unknown"


@dataclasses.dataclass(frozen=True)
class EvalResult:
    """An evaluated value together with how much it may be trusted.

    ``exact_value`` is the ONLY accessor a decision may read: it is ``None``
    unless the result is exact, so a control-flow choice or a published state
    transition cannot be built out of an invented integer.

    >>> EvalResult.exact(7).exact_value
    7
    >>> EvalResult.tainted(7).exact_value is None
    True
    >>> EvalResult.tainted(7).value
    7
    >>> EvalResult.unknown().value is None
    True
    """

    value: int | None = None
    exactness: Exactness = Exactness.UNKNOWN

    @classmethod
    def exact(cls, value: int) -> "EvalResult":
        """A proven value."""
        return cls(value=int(value), exactness=Exactness.EXACT)

    @classmethod
    def tainted(cls, value: int | None) -> "EvalResult":
        """An invented (or invention-derived) value: propagate, never decide."""
        return cls(
            value=None if value is None else int(value),
            exactness=Exactness.TAINTED,
        )

    @classmethod
    def unknown(cls) -> "EvalResult":
        """No value could be produced."""
        return cls(value=None, exactness=Exactness.UNKNOWN)

    @property
    def is_exact(self) -> bool:
        """``True`` only for a proven value."""
        return self.exactness is Exactness.EXACT and self.value is not None

    @property
    def exact_value(self) -> int | None:
        """The value a DECISION may use -- ``None`` unless proven.

        >>> EvalResult(value=None, exactness=Exactness.EXACT).exact_value is None
        True
        """
        return self.value if self.is_exact else None


def taint_location_key(kind: int, ident: int) -> tuple:
    """Size-AGNOSTIC key identifying the storage location taint is tracked on.

    Taint must classify locations exactly as the VALUE store does.  The
    environment matches stored values with ``equal_mops_ignore_size`` (a
    register by its micro-register number, a stack slot by its frame offset),
    so a key that carried the operand SIZE laundered every widening/narrowing
    copy: a tainted ``rax.8`` read back as ``rax.4`` came out clean, which is
    precisely the shape a 32-bit dispatcher state variable has (d81-1t9x).

    >>> taint_location_key(1, 8) == taint_location_key(1, 8)
    True
    >>> taint_location_key(1, 8) == taint_location_key(2, 8)
    False
    """
    return (int(kind), int(ident))


def any_tainted(keys: Iterable[Hashable], tainted_keys: Collection[Hashable]) -> bool:
    """``True`` when any of *keys* is a tainted operand.

    >>> any_tainted([("r", 8, 4)], {("r", 8, 4)})
    True
    >>> any_tainted([("r", 8, 4)], set())
    False
    """
    if not tainted_keys:
        return False
    return any(key in tainted_keys for key in keys)


def taint_result(
    *,
    produces_synthetic: bool,
    source_keys: Iterable[Hashable],
    tainted_keys: Collection[Hashable],
) -> bool:
    """``True`` when an instruction's destination must be marked tainted.

    An instruction taints its destination when it MODELS a call (its result is
    invented, not computed) or when it reads any already-tainted operand.  Never
    inferred from the produced value's bits -- see the module docstring.

    >>> taint_result(produces_synthetic=True, source_keys=(), tainted_keys=set())
    True
    >>> taint_result(
    ...     produces_synthetic=False, source_keys=[("r", 8, 4)], tainted_keys=set()
    ... )
    False
    """
    if produces_synthetic:
        return True
    return any_tainted(source_keys, tainted_keys)


def address_from_eval_result(
    result: EvalResult, *, min_address: int = 0x10000
) -> int | None:
    """The address a memory-fold decision may use, or ``None``.

    Only an ``EXACT`` evaluation may become a fold address: a value derived
    from a synthetic call return (:attr:`Exactness.TAINTED`) must never be
    treated as a resolved pointer, no matter how plausible its magnitude looks
    (ticket ``d81-3xer``).  A value at or below *min_address* is also rejected
    as an implausible virtual address.

    >>> address_from_eval_result(EvalResult.exact(0x1800296A0))
    6442620576
    >>> address_from_eval_result(EvalResult.tainted(0x1800296A0)) is None
    True
    >>> address_from_eval_result(EvalResult.exact(0x100)) is None
    True
    >>> address_from_eval_result(EvalResult.unknown()) is None
    True
    """
    value = result.exact_value
    if value is None or value <= min_address:
        return None
    return value
