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
"""

from __future__ import annotations

from d810.core.typing import Collection, Hashable, Iterable

__all__ = ["any_tainted", "taint_result"]


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
