"""Portable root-chain capability matching the native chain simplifiers.

This is intentionally a descriptor of the *candidate root*, not a profile
summary.  ``ChainOptimizer`` decides whether to run from the root opcode and
then flattens one of two narrow algebra families.  Aggregate profile operation
counts cannot faithfully represent either family.
"""

from __future__ import annotations

import enum
from dataclasses import dataclass

from d810.mba.typed_term import TypedBvTerm, canonicalize_ac_term, term_fingerprint


class MbaRootChainFamily(enum.StrEnum):
    """The exact flattening family supported by the native chain optimizer."""

    SAME_OPERATION = "same_operation"
    ARITHMETIC_ADDITIVE = "arithmetic_additive"


_SAME_OPERATION_ROOTS = frozenset({"and", "or", "xor"})
_ARITHMETIC_ROOTS = frozenset({"add", "sub"})


@dataclass(frozen=True)
class MbaRootChainDescriptor:
    """Immutable, profile-bound capability for structural-chain routing."""

    family: MbaRootChainFamily
    root_operation: str
    flattened_arity: int
    fingerprint: str

    def __post_init__(self) -> None:
        if not isinstance(self.family, MbaRootChainFamily):
            raise ValueError("family must be an MbaRootChainFamily")
        if self.family is MbaRootChainFamily.SAME_OPERATION:
            allowed_roots = _SAME_OPERATION_ROOTS
        else:
            allowed_roots = _ARITHMETIC_ROOTS
        if self.root_operation not in allowed_roots:
            raise ValueError(
                f"{self.family.value} does not support root {self.root_operation!r}"
            )
        if type(self.flattened_arity) is not int or self.flattened_arity < 2:
            raise ValueError("flattened_arity must be an integer of at least two")
        if type(self.fingerprint) is not str or not self.fingerprint:
            raise ValueError("fingerprint must be a non-empty string")


def _same_operation_arity(term: TypedBvTerm, operation: str) -> int:
    if term.operation != operation:
        return 1
    return sum(_same_operation_arity(child, operation) for child in term.children)


def _arithmetic_arity(term: TypedBvTerm) -> int:
    """Count operands exactly as ``ArithmeticChainSimplification.add_mop``."""

    if term.operation in {"add", "sub"}:
        return sum(_arithmetic_arity(child) for child in term.children)
    if term.operation == "neg":
        return _arithmetic_arity(term.children[0])
    return 1


def describe_root_chain(term: TypedBvTerm) -> MbaRootChainDescriptor | None:
    """Describe exactly one native structural-chain root, if it is supported.

    Same-operation chains flatten only nested instances of their root opcode;
    arbitrary child operations, including ``bnot``, remain operands.  Arithmetic
    chains flatten a combined ``add``/``sub``/``neg`` signed algebra, matching
    ``ArithmeticChainSimplification.add_mop``.  No generic AC grouping occurs.
    """

    root_operation = term.operation
    fingerprint = term_fingerprint(canonicalize_ac_term(term))
    if root_operation in _SAME_OPERATION_ROOTS:
        return MbaRootChainDescriptor(
            family=MbaRootChainFamily.SAME_OPERATION,
            root_operation=root_operation,
            flattened_arity=_same_operation_arity(term, root_operation),
            fingerprint=fingerprint,
        )
    if root_operation in _ARITHMETIC_ROOTS:
        return MbaRootChainDescriptor(
            family=MbaRootChainFamily.ARITHMETIC_ADDITIVE,
            root_operation=root_operation,
            flattened_arity=_arithmetic_arity(term),
            fingerprint=fingerprint,
        )
    return None


__all__ = [
    "MbaRootChainDescriptor",
    "MbaRootChainFamily",
    "describe_root_chain",
]
