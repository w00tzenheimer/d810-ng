"""Forward-target resolver for back-edges (Piece 5 of uee-32r3).

Given a dispatcher-aware classified back-edge ``(src, tgt)``, this
module computes the safe forward target block — the block control flow
should land on if the back-edge were rewritten — when and only when the
target is *provable*.

Three cases:

1. **Dispatcher round-trip** — ``tgt`` is the dispatcher root or a
   condition-chain cascade node. The resolver reads ``src``'s reaching definition of
   the state variable and asks a condition-chain lookup callable to map that
   constant to a handler block. Returns ``None`` if the state-var
   reaching def is missing or condition-chain lookup is ambiguous.

2. **Spurious non-dispatcher predicate edge** — ``tgt`` has a
   conditional tail. The resolver reads ``src``'s reaching def of
   ``tgt``'s predicate operand, evaluates the comparison, and returns
   the chosen successor. Returns ``None`` if the reaching def is
   missing, the predicate opcode is unrecognized, or the comparison
   semantics are ambiguous.

3. **Real-loop / unknown edges** — always returns ``None``. The
   resolver must never rewrite genuine algorithmic loops or edges where
   the predicate is unreadable.

Strictly non-behavioral. The resolver is a *prediction model*: given an
edge, it answers "where would a safe redirect go?". CFG edits live in
a future piece. Piece 5 is unit-tested in isolation and validated
against existing strategy decisions.
"""
from __future__ import annotations

from dataclasses import dataclass

from d810.analyses.control_flow.dispatcher_aware_classifier import (
    DispatcherAwareClassification,
    DispatcherAwareEdgeClass,
)
from d810.core.logging import getLogger
from d810.core.typing import Callable, Mapping

logger = getLogger(__name__)


@dataclass(frozen=True, slots=True)
class PredicateInfo:
    """Tail predicate of a target block.

    Parameters
    ----------
    opcode : str
        IDA microcode opcode name without the ``m_`` prefix
        (e.g. ``"jge"``, ``"jnz"``, ``"jcnd"``).
    read_var : str
        Variable token whose value drives the comparison
        (e.g. ``"%var_3C"``). Caller chooses namespace.
    test_const : int | None
        Constant being compared against. ``None`` for ``jcnd``-style
        predicates that test against zero implicitly.
    taken_succ : int
        Successor block taken when the predicate is true.
    fallthrough_succ : int
        Successor block taken when the predicate is false.
    """

    opcode: str
    read_var: str
    test_const: int | None
    taken_succ: int
    fallthrough_succ: int


@dataclass(frozen=True, slots=True)
class ResolvedTarget:
    """Output of the resolver when a forward target is provable."""

    src_serial: int
    old_target: int
    new_target: int
    resolution_kind: str
    reason: str


def resolve_forward_target(
    classification: DispatcherAwareClassification,
    *,
    src_reaching_const: Mapping[str, int | None],
    condition_chain_resolver: Callable[[int], int | None] | None = None,
    target_predicate: PredicateInfo | None = None,
) -> ResolvedTarget | None:
    """Compute the safe forward target block, or ``None`` if not provable.

    Parameters
    ----------
    classification : DispatcherAwareClassification
        The classified back-edge.
    src_reaching_const : Mapping[str, int | None]
        Var-token → constant value at ``src``'s tail. ``None`` value means
        the def reaches but is non-constant; missing key means no def
        reaches. Both are treated as "not provable".
    condition_chain_resolver : callable
        ``state_const -> handler_serial | None``. Required for dispatcher
        round-trip resolution; ignored otherwise.
    target_predicate : PredicateInfo | None
        Tail predicate of the target block. Required for spurious
        non-dispatcher predicate resolution; ignored otherwise.
    """
    if classification.is_real_loop:
        return None
    if classification.classification is DispatcherAwareEdgeClass.UNKNOWN:
        return None

    if classification.is_dispatcher_round_trip:
        return _resolve_dispatcher_round_trip(
            classification=classification,
            src_reaching_const=src_reaching_const,
            condition_chain_resolver=condition_chain_resolver,
        )

    # Spurious non-dispatcher edge: simulate target predicate.
    return _resolve_predicate_edge(
        classification=classification,
        src_reaching_const=src_reaching_const,
        target_predicate=target_predicate,
    )


def _resolve_dispatcher_round_trip(
    *,
    classification: DispatcherAwareClassification,
    src_reaching_const: Mapping[str, int | None],
    condition_chain_resolver: Callable[[int], int | None] | None,
) -> ResolvedTarget | None:
    if condition_chain_resolver is None:
        return None
    # Try every var that has a known constant reaching def. Typically
    # only the state-var token is relevant; the condition-chain resolver returns
    # None for non-state values so unrelated reaching consts are
    # naturally filtered.
    for var_token in sorted(src_reaching_const):
        const = src_reaching_const[var_token]
        if const is None:
            continue
        try:
            handler = condition_chain_resolver(int(const))
        except Exception:
            handler = None
        if handler is None:
            continue
        return ResolvedTarget(
            src_serial=classification.src_serial,
            old_target=classification.tgt_serial,
            new_target=int(handler),
            resolution_kind="condition_chain_const_resolved",
            reason=(
                f"state_const=0x{int(const):x} via {var_token} -> "
                f"handler blk[{int(handler)}]"
            ),
        )
    return None


def _resolve_predicate_edge(
    *,
    classification: DispatcherAwareClassification,
    src_reaching_const: Mapping[str, int | None],
    target_predicate: PredicateInfo | None,
) -> ResolvedTarget | None:
    if target_predicate is None:
        return None
    const = src_reaching_const.get(target_predicate.read_var)
    if const is None:
        return None
    taken = _evaluate_comparison(
        opcode=target_predicate.opcode,
        lhs=int(const),
        rhs=target_predicate.test_const,
    )
    if taken is None:
        return None
    new_target = (
        target_predicate.taken_succ if taken else target_predicate.fallthrough_succ
    )
    return ResolvedTarget(
        src_serial=classification.src_serial,
        old_target=classification.tgt_serial,
        new_target=int(new_target),
        resolution_kind="predicate_simulated",
        reason=(
            f"{target_predicate.read_var}=0x{int(const):x} "
            f"{target_predicate.opcode} {target_predicate.test_const} "
            f"-> {'taken' if taken else 'fallthrough'} blk[{int(new_target)}]"
        ),
    )


# Microcode comparison opcode -> Python int comparison result.
_UNSIGNED_MASK_64 = (1 << 64) - 1


def _evaluate_comparison(*, opcode: str, lhs: int, rhs: int | None) -> bool | None:
    """Evaluate a microcode comparison opcode against two integers.

    Returns ``True`` if the predicate is taken, ``False`` if the branch
    falls through, ``None`` if the opcode is unrecognized or required
    operand is missing.

    >>> _evaluate_comparison(opcode="jge", lhs=10, rhs=5)
    True
    >>> _evaluate_comparison(opcode="jl", lhs=10, rhs=5)
    False
    >>> _evaluate_comparison(opcode="jcnd", lhs=0, rhs=None)
    False
    >>> _evaluate_comparison(opcode="jcnd", lhs=42, rhs=None)
    True
    >>> _evaluate_comparison(opcode="ja", lhs=-1, rhs=0) is True
    True
    >>> _evaluate_comparison(opcode="jg", lhs=-1, rhs=0) is False
    True
    """
    op = opcode.lower()
    if op.startswith("m_"):
        op = op[2:]
    if op == "jcnd":
        return bool(lhs)
    if rhs is None:
        return None
    rhs = int(rhs)
    if op == "jnz":
        return lhs != rhs
    if op == "jz":
        return lhs == rhs
    if op in ("jae", "jb", "ja", "jbe"):
        # Unsigned 64-bit comparison.
        ulhs = lhs & _UNSIGNED_MASK_64
        urhs = rhs & _UNSIGNED_MASK_64
        if op == "jae":
            return ulhs >= urhs
        if op == "jb":
            return ulhs < urhs
        if op == "ja":
            return ulhs > urhs
        return ulhs <= urhs  # jbe
    if op in ("jge", "jl", "jg", "jle"):
        if op == "jge":
            return lhs >= rhs
        if op == "jl":
            return lhs < rhs
        if op == "jg":
            return lhs > rhs
        return lhs <= rhs  # jle
    return None


__all__ = [
    "PredicateInfo",
    "ResolvedTarget",
    "resolve_forward_target",
]
