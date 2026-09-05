"""Resolve a *computed* dispatcher state write to a proven constant set (d81-czrc).

An OLLVM comparison-tree dispatcher does not always write its next state with a
literal.  On ``sub_7FFB0E398850`` six of the seventy-five writes to the state
slot are computed from registers set in the *predecessor* blocks::

    blk36:   mov #0xA84A23E8, ecx ; mov #0xBA1637C8, eax ; goto @136
    blk135:  mov #0x5FDB1F09, ecx ; mov #0x1D431D66, eax          (falls through)
    blk136:  xor ecx, eax -> %var_438 ; goto @5      <- the computed write

Every closed-world consumer of the "set of state constants this function writes"
must therefore either *prove* what such a write can produce or *say so* — a
silent ``None`` would understate the set, and understating it is the one
direction that is unsound (a route judged exact because the second state that
shares its interval was never collected).

WHAT THIS MODULE IS.  The pure, IDA-free decision core of the T2c
*predecessor-partitioned* (LiSA disjunctive-join) fold that
:mod:`d810.evaluator.hexrays_microcode.dynamic_state_write_backend` already
performs for stack operands.  It is parameterised on an opaque
:class:`StorageKey` so the same core serves ``mop_S`` stack slots, ``mop_r``
registers and ``mop_l`` local variables, and on two injected readers so it never
imports a vendor microcode API:

``const_reader(pred_serial, storage) -> int | None``
    the constant *storage* carries on the edge from *pred_serial*, or ``None``
    when that definition is not a provable constant.
``fold(env) -> int | None``
    evaluate the write's own expression under a fully-bound environment
    ``{storage: const}``; ``None`` when the operation is not foldable.

WHY PARTITION AND NOT JOIN.  The operands are *correlated by predecessor*.
Joining the operand environments first would either collapse each operand to ⊤
(two constants) or, if paired naively, manufacture the cross product
``A₁ op B₂`` — states the program cannot reach.  Folding inside each disjunct
yields exactly one state per real data flow.  This is the same argument
:func:`d810.analyses.data_flow.abstract_value.fold_correlated_binop` makes for
the two-operand case; this core generalises it to *n* operands and to a fold
that is an arbitrary expression rather than a single binary operator.

SOUNDNESS.  All-or-nothing: unless EVERY enumerated predecessor binds EVERY
operand to a provable constant *and* the fold succeeds there, the resolution
abstains with an explicit :class:`AbstainReason` and contributes no values at
all.  A partial answer is never emitted, because a partial value set is exactly
an under-approximation.  Conversely the values that ARE proven may be a strict
over-approximation of what a path-sensitive analysis would give (an infeasible
predecessor still contributes its constant); that direction is safe for the
route-exactness consumer, where a larger written-state set can only *refuse*
routes, never invent one.

>>> import operator
>>> ecx, eax = StorageKey("r", 1), StorageKey("r", 0)
>>> table = {36: {ecx: 0xA84A23E8, eax: 0xBA1637C8},
...          135: {ecx: 0x5FDB1F09, eax: 0x1D431D66}}
>>> res = resolve_computed_write(
...     operands=(ecx, eax),
...     predecessors=(36, 135),
...     const_reader=lambda p, s: table[p].get(s),
...     fold=lambda env: (env[ecx] ^ env[eax]) & 0xFFFFFFFF,
... )
>>> res.resolved, sorted(hex(v) for v in res.values)
(True, ['0x125c1420', '0x4298026f'])
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum

from d810.core.logging import getLogger
from d810.core.typing import Callable, Iterable, Mapping, Sequence

from d810.analyses.data_flow.abstract_value import (
    TOP,
    AbstractValue,
    value_set_from_reaching_def_consts,
)

__all__ = [
    "AbstainReason",
    "ComputedWriteEvidence",
    "ComputedWriteRequest",
    "ComputedWriteResolution",
    "ComputedWriteSet",
    "StorageKey",
    "resolve_computed_write",
    "resolve_computed_writes",
]

logger = getLogger(__name__)

#: The state slot is a 32-bit selector on every dispatcher shape d810 recovers;
#: this mirrors ``fold_block_state_write``'s fold width.
_U32 = 0xFFFFFFFF

#: Enumeration caps.  Exceeding either is an *abstain*, never a truncation: a
#: truncated partition set is an under-approximation.
DEFAULT_MAX_PREDECESSORS = 64
DEFAULT_MAX_OPERANDS = 8


class AbstainReason(str, Enum):
    """Why a computed write could not be reduced to a proven constant set.

    Every value is a stable string so it can be logged, stored in a receipt and
    compared across runs without importing this module.
    """

    NO_STATE_WRITE = "no_state_write"
    NO_OPERANDS = "no_operands"
    NO_PREDECESSORS = "no_predecessors"
    UNRESOLVED_OPERAND = "unresolved_operand"
    UNFOLDABLE_OPERATION = "unfoldable_operation"
    PREDECESSOR_BUDGET_EXCEEDED = "predecessor_budget_exceeded"
    OPERAND_BUDGET_EXCEEDED = "operand_budget_exceeded"

    def __str__(self) -> str:  # pragma: no cover - trivial
        return self.value


@dataclass(frozen=True, slots=True)
class StorageKey:
    """The identity of a value-carrying location, independent of any backend.

    ``kind`` is ``"S"`` for a stack slot (``key`` = stack offset), ``"r"`` for a
    register (``key`` = register number) or ``"l"`` for a local variable
    (``key`` = lvar index) — deliberately the same three tags the evaluator's
    ``_dest_key`` already produces, so an adapter is a rename and not a mapping.
    """

    kind: str
    key: int

    def __repr__(self) -> str:  # pragma: no cover - trivial
        return f"{self.kind}:{self.key:#x}"


@dataclass(frozen=True, slots=True)
class ComputedWriteEvidence:
    """One resolved partition: what the operands were on one incoming edge.

    Attributes:
        pred_serial: the predecessor block the partition corresponds to.
        bindings: the ``(storage, const)`` pairs read on that edge, in operand
            order, so the fold is reproducible from the record alone.
        folded: the state constant the write produces under those bindings.
    """

    pred_serial: int
    bindings: tuple[tuple[StorageKey, int], ...]
    folded: int


@dataclass(frozen=True, slots=True)
class ComputedWriteResolution:
    """A proven constant set for one computed write, or an explicit abstention.

    Invariant (enforced in :meth:`__post_init__`, mirroring
    ``WrittenStateSet.complete == (not reasons)``): ``reason is None`` iff there
    is at least one value.  A reason can never ship alongside values, and a
    "resolved" resolution can never be empty — the two states a caller might
    otherwise confuse are made unrepresentable.
    """

    values: frozenset[int]
    reason: AbstainReason | None
    evidence: tuple[ComputedWriteEvidence, ...]

    def __post_init__(self) -> None:
        if self.reason is not None and self.values:
            raise ValueError(
                f"abstained resolution ({self.reason}) cannot carry values: "
                f"{sorted(self.values)!r}"
            )
        if self.reason is None and not self.values:
            raise ValueError("resolved resolution must carry at least one value")

    @property
    def resolved(self) -> bool:
        """Whether the write was reduced to a proven constant set."""
        return self.reason is None

    def to_abstract_value(self) -> AbstractValue:
        """Project onto the existing value-side seam.

        ``Const`` for a singleton, ``OneOf`` for several, ``⊤`` for an
        abstention — byte-identical to what
        :func:`~d810.analyses.data_flow.abstract_value.value_set_from_reaching_def_consts`
        would produce for the same constants, so this core drops into the
        resolve ladder without a new shape.
        """
        if not self.resolved:
            return TOP
        return value_set_from_reaching_def_consts(sorted(self.values))


def _abstain(reason: AbstainReason) -> ComputedWriteResolution:
    return ComputedWriteResolution(values=frozenset(), reason=reason, evidence=())


def resolve_computed_write(
    *,
    operands: Sequence[StorageKey],
    predecessors: Sequence[int],
    const_reader: Callable[[int, StorageKey], int | None],
    fold: Callable[[Mapping[StorageKey, int]], int | None],
    max_predecessors: int = DEFAULT_MAX_PREDECESSORS,
    max_operands: int = DEFAULT_MAX_OPERANDS,
) -> ComputedWriteResolution:
    """Fold one computed state write across its predecessor partitions.

    Args:
        operands: every storage the write reads, in operand order.  Duplicates
            are collapsed; the order fixes the evidence ordering.
        predecessors: the block serials of the incoming edges.  Duplicates are
            visited once (a ``predset`` may repeat a serial for a two-way
            branch whose arms both land here) so a partition is not counted
            twice.
        const_reader: ``(pred_serial, storage) -> const | None``.
        fold: ``env -> folded | None`` under a fully-bound environment.
        max_predecessors: abstain rather than enumerate more partitions.
        max_operands: abstain rather than bind more operands.

    Returns:
        A :class:`ComputedWriteResolution` that either carries the proven
        constant set with per-partition evidence, or names why it abstained.
    """
    unique_operands: list[StorageKey] = []
    for storage in operands:
        if storage not in unique_operands:
            unique_operands.append(storage)
    if not unique_operands:
        return _abstain(AbstainReason.NO_OPERANDS)
    if len(unique_operands) > max_operands:
        return _abstain(AbstainReason.OPERAND_BUDGET_EXCEEDED)

    unique_preds: list[int] = []
    for pred in predecessors:
        serial = int(pred)
        if serial not in unique_preds:
            unique_preds.append(serial)
    if not unique_preds:
        return _abstain(AbstainReason.NO_PREDECESSORS)
    if len(unique_preds) > max_predecessors:
        return _abstain(AbstainReason.PREDECESSOR_BUDGET_EXCEEDED)

    debug = logger.debug_on
    evidence: list[ComputedWriteEvidence] = []
    values: set[int] = set()
    for pred in unique_preds:
        env: dict[StorageKey, int] = {}
        bindings: list[tuple[StorageKey, int]] = []
        for storage in unique_operands:
            const = const_reader(pred, storage)
            if const is None:
                if debug:
                    logger.debug(
                        "COMPUTED_STATE_WRITE: abstain %s: blk%d does not bind %r",
                        AbstainReason.UNRESOLVED_OPERAND,
                        pred,
                        storage,
                    )
                return _abstain(AbstainReason.UNRESOLVED_OPERAND)
            masked = int(const) & _U32
            env[storage] = masked
            bindings.append((storage, masked))
        folded = fold(env)
        if folded is None:
            if debug:
                logger.debug(
                    "COMPUTED_STATE_WRITE: abstain %s: fold declined for blk%d",
                    AbstainReason.UNFOLDABLE_OPERATION,
                    pred,
                )
            return _abstain(AbstainReason.UNFOLDABLE_OPERATION)
        masked_result = int(folded) & _U32
        values.add(masked_result)
        evidence.append(
            ComputedWriteEvidence(
                pred_serial=pred,
                bindings=tuple(bindings),
                folded=masked_result,
            )
        )

    if debug:
        logger.debug(
            "COMPUTED_STATE_WRITE: resolved %d partition(s) -> %s",
            len(evidence),
            ", ".join(f"{v:#010x}" for v in sorted(values)),
        )
    return ComputedWriteResolution(
        values=frozenset(values), reason=None, evidence=tuple(evidence)
    )


@dataclass(frozen=True, slots=True)
class ComputedWriteRequest:
    """One computed write to resolve, tagged with the site it was seen at.

    ``site`` is opaque to this module (a block serial at the call sites, carried
    only so an abstention can name *which* write blocked completeness).
    """

    site: object
    operands: Sequence[StorageKey]
    predecessors: Sequence[int]
    const_reader: Callable[[int, StorageKey], int | None]
    fold: Callable[[Mapping[StorageKey, int]], int | None]
    max_predecessors: int = DEFAULT_MAX_PREDECESSORS
    max_operands: int = DEFAULT_MAX_OPERANDS


@dataclass(frozen=True, slots=True)
class ComputedWriteSet:
    """The aggregate verdict over every computed write in a function.

    Attributes:
        values: the union of every RESOLVED write's constants.  Kept even when
            the set is incomplete: enlarging the written-state set can only
            make the route-exactness test *refuse*, never accept, so retaining
            proven constants is the safe direction and strictly more precise
            than discarding them.
        reasons: the deduplicated, sorted abstention reasons.
        unresolved_sites: the sites that abstained, in encounter order.
        resolutions: the per-request resolutions, in request order.

    Invariant: ``complete == (not reasons)``.
    """

    values: frozenset[int]
    reasons: tuple[AbstainReason, ...]
    unresolved_sites: tuple[object, ...]
    resolutions: tuple[ComputedWriteResolution, ...]

    @property
    def complete(self) -> bool:
        """Whether every computed write was reduced to proven constants."""
        return not self.reasons


def resolve_computed_writes(
    requests: Iterable[ComputedWriteRequest],
) -> ComputedWriteSet:
    """Resolve every computed write and aggregate a completeness verdict.

    The verdict is all-or-nothing *for completeness* but additive *for values*:
    one unresolved write leaves ``complete`` False (so a closed-world consumer
    must abstain) while the constants proven for its siblings are still
    contributed.
    """
    values: set[int] = set()
    reasons: list[AbstainReason] = []
    unresolved: list[object] = []
    resolutions: list[ComputedWriteResolution] = []
    for request in requests:
        resolution = resolve_computed_write(
            operands=request.operands,
            predecessors=request.predecessors,
            const_reader=request.const_reader,
            fold=request.fold,
            max_predecessors=request.max_predecessors,
            max_operands=request.max_operands,
        )
        resolutions.append(resolution)
        if resolution.resolved:
            values |= resolution.values
        else:
            unresolved.append(request.site)
            if resolution.reason is not None and resolution.reason not in reasons:
                reasons.append(resolution.reason)
    return ComputedWriteSet(
        values=frozenset(values),
        reasons=tuple(sorted(reasons, key=lambda r: r.value)),
        unresolved_sites=tuple(unresolved),
        resolutions=tuple(resolutions),
    )
