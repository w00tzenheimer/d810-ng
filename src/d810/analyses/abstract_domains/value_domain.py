"""ValueDomain — the semantic layer (eval / satisfies / assume) over a domain.

This is LiSA's ``BaseNonRelationalValueDomain`` shape: a domain that can
*evaluate* an operation on abstract operands, *decide* a comparison
(``Satisfiability`` — the guard / opaque-predicate oracle), and *assume* a
comparison to refine operands. It sits on top of an :class:`AbstractDomain`
element (``KnownBits`` / ``WrappedInterval``) and is what the state-value
resolver and guard-oracle consume.

Every implementation shares the **constant-fold fast path**: when both operands
are concrete (``to_const`` succeeds), the result is the exact modular value from
``operations.eval_const_*`` — domain approximation only kicks in for
non-constant operands. That fast path is what folds OLLVM's MBA-over-constants
next-state writes.

Portable, no IDA.
"""
from __future__ import annotations

from d810.core.typing import Generic, Optional, Protocol, TypeVar, runtime_checkable
from d810.analyses.abstract_domains.known_bits import KnownBits
from d810.analyses.abstract_domains.wrapped_interval import WrappedInterval
from d810.analyses.abstract_domains.relational import Satisfiability
from d810.analyses.abstract_domains.operations import (
    BinaryOp,
    CompareOp,
    UnaryOp,
    eval_const_binary,
    eval_const_compare,
    eval_const_unary,
)

__all__ = [
    "ValueDomain",
    "KnownBitsValueDomain",
    "WrappedIntervalValueDomain",
]

D = TypeVar("D")


@runtime_checkable
class ValueDomain(Protocol[D]):
    """Non-relational value-domain semantics over abstract element type ``D``."""

    def const(self, value: int, width: int) -> D: ...
    def top(self, width: int) -> D: ...
    def to_const(self, element: D) -> Optional[int]: ...
    def eval_binary(self, op: BinaryOp, left: D, right: D, width: int) -> D: ...
    def eval_unary(self, op: UnaryOp, operand: D, width: int) -> D: ...
    def satisfies(
        self, op: CompareOp, left: D, right: D, width: int
    ) -> Satisfiability: ...
    def assume_compare(
        self, op: CompareOp, left: D, right: D, width: int, taken: bool
    ) -> "tuple[D, D]": ...


class _BaseValueDomain(Generic[D]):
    """Shared constant-fold fast path + default assume (EQ-meet refinement)."""

    def to_const(self, element: D) -> Optional[int]:
        return element.to_const()  # type: ignore[attr-defined]

    def _fold_binary(
        self, op: BinaryOp, left: D, right: D, width: int
    ) -> Optional[D]:
        lc, rc = self.to_const(left), self.to_const(right)
        if lc is not None and rc is not None:
            return self.const(eval_const_binary(op, lc, rc, width), width)  # type: ignore[attr-defined]
        return None

    def satisfies(
        self, op: CompareOp, left: D, right: D, width: int
    ) -> Satisfiability:
        lc, rc = self.to_const(left), self.to_const(right)
        if lc is not None and rc is not None:
            return (
                Satisfiability.SATISFIED
                if eval_const_compare(op, lc, rc, width)
                else Satisfiability.NOT_SATISFIED
            )
        return self._satisfies_abstract(op, left, right, width)

    def _satisfies_abstract(
        self, op: CompareOp, left: D, right: D, width: int
    ) -> Satisfiability:
        return Satisfiability.UNKNOWN

    def assume_compare(
        self, op: CompareOp, left: D, right: D, width: int, taken: bool
    ) -> "tuple[D, D]":
        # EQ-true / NE-false => operands must be equal => meet both ways.
        eq = (op is CompareOp.EQ and taken) or (op is CompareOp.NE and not taken)
        if eq:
            m = left.meet(right)  # type: ignore[attr-defined]
            return m, m
        return left, right


class KnownBitsValueDomain(_BaseValueDomain[KnownBits]):
    """Bitwise-precise value domain — the MBA workhorse."""

    def const(self, value: int, width: int) -> KnownBits:
        return KnownBits.of(value, width)

    def top(self, width: int) -> KnownBits:
        return KnownBits.top(width)

    def eval_binary(
        self, op: BinaryOp, left: KnownBits, right: KnownBits, width: int
    ) -> KnownBits:
        folded = self._fold_binary(op, left, right, width)
        if folded is not None:
            return folded
        if op is BinaryOp.AND:
            return left.band(right)
        if op is BinaryOp.OR:
            return left.bor(right)
        if op is BinaryOp.XOR:
            return left.bxor(right)
        if op in (BinaryOp.SHL, BinaryOp.SHR_U):
            shift = right.to_const()
            if shift is not None:
                return self._shift_known(op, left, shift % width, width)
        return KnownBits.top(width)  # arithmetic on unknowns: sound ⊤

    def _shift_known(
        self, op: BinaryOp, value: KnownBits, k: int, width: int
    ) -> KnownBits:
        mask = (1 << width) - 1
        if op is BinaryOp.SHL:
            zero = ((value.zero << k) & mask) | ((1 << k) - 1)  # low k bits -> 0
            one = (value.one << k) & mask
        else:  # SHR_U
            hi = ((1 << k) - 1) << (width - k) if k else 0
            zero = (value.zero >> k) | (hi & mask)  # high k bits -> 0
            one = value.one >> k
        return KnownBits(width, zero & mask, one & mask)

    def eval_unary(self, op: UnaryOp, operand: KnownBits, width: int) -> KnownBits:
        c = operand.to_const()
        if c is not None:
            return self.const(eval_const_unary(op, c, width), width)
        if op is UnaryOp.NOT:
            return operand.bnot()
        return KnownBits.top(width)  # NEG of unknown: sound ⊤

    def _satisfies_abstract(
        self, op: CompareOp, left: KnownBits, right: KnownBits, width: int
    ) -> Satisfiability:
        # Bitwise refutation: if a bit is proven 1 on one side and 0 on the
        # other, the two can never be equal.
        differ = (left.one & right.zero) | (left.zero & right.one)
        if op is CompareOp.EQ and differ:
            return Satisfiability.NOT_SATISFIED
        if op is CompareOp.NE and differ:
            return Satisfiability.SATISFIED
        return Satisfiability.UNKNOWN


class WrappedIntervalValueDomain(_BaseValueDomain[WrappedInterval]):
    """Modular-range value domain — word-correct arithmetic ranges."""

    def const(self, value: int, width: int) -> WrappedInterval:
        return WrappedInterval.of(value, width)

    def top(self, width: int) -> WrappedInterval:
        return WrappedInterval.top(width)

    def eval_binary(
        self, op: BinaryOp, left: WrappedInterval, right: WrappedInterval, width: int
    ) -> WrappedInterval:
        folded = self._fold_binary(op, left, right, width)
        if folded is not None:
            return folded
        if op is BinaryOp.ADD:
            return left.add(right)
        if op is BinaryOp.SUB:
            return left.sub(right)
        return WrappedInterval.top(width)  # bitwise/mul on ranges: sound ⊤

    def eval_unary(
        self, op: UnaryOp, operand: WrappedInterval, width: int
    ) -> WrappedInterval:
        c = operand.to_const()
        if c is not None:
            return self.const(eval_const_unary(op, c, width), width)
        return WrappedInterval.top(width)
