"""The ``resolve`` ladder facade (S3 of the dispatcher-model consolidation).

``resolve(var, point, ctx) -> AbstractValue`` orchestrates the existing
value-resolution tiers behind one interface, in increasing cost / decreasing
locality.  Each tier returns an :class:`AbstractValue`; a tier that cannot prove
a value returns :data:`~d810.analyses.data_flow.abstract_value.TOP` (``⊤``) to
*escalate* to the next.  The first non-``⊤`` answer wins; if every tier yields
``⊤`` the value is genuinely unknown and ``resolve`` returns ``⊤`` (an explicit,
surfaced gap — not a silently dropped edge).

The tiers (``docs/plans/dispatcher-model-consolidation.md`` unflatten, §S3):

* **T1 — local const-fold.**  Forward constant-propagation over one block,
  folding the state-write RHS through the KnownBits value domain
  (:func:`d810.evaluator.hexrays_microcode.dynamic_state_write_backend.fold_block_state_write`,
  refactored in S3 to return ``Const | Top``).
* **T2 — cross-block value-set.**  The sound forward value-set fixpoint
  (:class:`d810.analyses.control_flow.state_transition_domain.StateTransitionDomain`
  via :func:`d810.analyses.data_flow.run_fixpoint`), projected
  ``Const | OneOf | Top`` through :meth:`StateValue.project`.
* **T3 — escalation.**  MopTracker / emulated-dispatcher backward tracing
  (a thin call that returns ``⊤`` when unavailable).
* **T4 — Z3 / MBA guard simplification.**  A seam for path-sensitive guard
  solving; a stub returning ``⊤`` for now (not needed for const next-states).

LAYERING — this facade lives in portable-core ``analyses.data_flow`` (no IDA).
T1 and T3 are IDA-coupled (the ``evaluator`` / ``backends`` layers, *above*
``analyses``), so they are *injected* as callables on :class:`ResolveContext`
rather than imported (dependency inversion: a downward import is impossible, so
the higher layer wires its tier in).  T2 is itself an ``analyses`` domain, so it
*could* be referenced directly, but is injected uniformly for testability.

STANDING RULE: :class:`ResolvePoint` carries a block serial *and* its EA, so any
serialized resolve point names ``serial@0xEA``.

This slice only DEFINES and unit-tests the facade — it is wired into no live
pass here (S4 ``explore()`` is the consumer).  The legacy recovery path is
byte-identical: ``recognize_constant_folded_state_write`` unwraps the new T1
``Const -> int`` so its external behaviour is unchanged.
"""
from __future__ import annotations

from dataclasses import dataclass, field

from d810.core.logging import getLogger
from d810.core.typing import Callable, Optional

from d810.analyses.data_flow.abstract_value import TOP, AbstractValue, Const, OneOf
from d810.analyses.data_flow.domain import NodeId

__all__ = [
    "VarRef",
    "ResolvePoint",
    "ResolveTier",
    "ResolveContext",
    "resolve",
]

logger = getLogger(__name__)

#: A variable reference the ladder resolves a value for.  Kept opaque (an
#: identity token — a stack offset, lvar index, or an ``(kind, key)`` pair) so
#: the portable facade never interprets a vendor-specific variable encoding; the
#: injected tiers know how to read it.
VarRef = object


@dataclass(frozen=True, slots=True)
class ResolvePoint:
    """The program point a value is resolved *at*: a block, optionally an insn.

    Carries the block ``serial`` and its ``ea`` (STANDING RULE: serialize the EA
    alongside the serial); ``insn_ea`` optionally pins the exact write site
    within the block.  ``__repr__`` renders ``serial@0xEA``.
    """

    serial: NodeId
    ea: int | None = None
    insn_ea: int | None = None

    def __repr__(self) -> str:
        head = (
            f"ResolvePoint({self.serial})"
            if self.ea is None
            else f"ResolvePoint({self.serial}@{self.ea:#x})"
        )
        if self.insn_ea is None:
            return head
        return f"{head[:-1]}#{self.insn_ea:#x})"


#: One rung of the ladder: ``(var, point) -> AbstractValue``.  A tier returns
#: ``⊤`` (:data:`TOP`) to decline / escalate to the next rung.  Tiers are pure
#: from the facade's view — any IDA / fixpoint state they need is captured in
#: their closure when the higher layer builds the :class:`ResolveContext`.
ResolveTier = Callable[[VarRef, ResolvePoint], AbstractValue]


@dataclass(frozen=True, slots=True)
class ResolveContext:
    """The injected tier stack the :func:`resolve` ladder walks, in order.

    Each field is an optional :data:`ResolveTier`; an absent (``None``) tier is
    skipped (treated as if it returned ``⊤``), so a caller that only has the
    local fold available wires ``t1_local_fold`` and leaves the rest ``None``.

    The IDA-coupled tiers (T1 local fold, T3 escalation) are injected here by
    the higher layer (``evaluator`` / ``backends``) because ``analyses`` cannot
    import upward.  T2 (the value-set fixpoint) is an ``analyses`` domain but is
    injected too, so the whole ladder is a pure, unit-testable function of its
    context.

    Attributes:
        t1_local_fold: local const-fold over one block (``Const | Top``).
        t2_value_set: cross-block value-set fixpoint, projected
            (``Const | OneOf | Top``).
        t3_escalation: MopTracker / emulated-dispatcher escalation (``Top`` when
            unavailable).
        t4_guard_solver: Z3 / MBA guard-simplification seam (stub: ``Top``).
    """

    t1_local_fold: Optional[ResolveTier] = None
    t2_value_set: Optional[ResolveTier] = None
    t3_escalation: Optional[ResolveTier] = None
    t4_guard_solver: Optional[ResolveTier] = field(default=None)

    def tiers(self) -> tuple[tuple[str, Optional[ResolveTier]], ...]:
        """The ordered ``(name, tier)`` ladder (cheapest / most local first)."""
        return (
            ("t1_local_fold", self.t1_local_fold),
            ("t2_value_set", self.t2_value_set),
            ("t3_escalation", self.t3_escalation),
            ("t4_guard_solver", self.t4_guard_solver),
        )


def _is_top(value: AbstractValue) -> bool:
    """Whether *value* is ``⊤`` — escalate — vs a resolved answer.

    A non-``⊤`` :class:`OneOf` that is *empty* (``⊥`` projected) carries no
    constants, so it cannot route; treat it as escalation too rather than
    declaring the ladder "resolved" with nothing to route.
    """
    if value is TOP:
        return True
    if isinstance(value, OneOf) and not value.values:
        return True
    return False


def resolve(
    var: VarRef,
    point: ResolvePoint,
    ctx: ResolveContext,
) -> AbstractValue:
    """Resolve the abstract value of *var* at *point* via the tier ladder.

    Walks ``ctx``'s tiers cheapest-first; returns the first tier's non-``⊤``
    answer.  A ``⊤`` (or empty :class:`OneOf` projection of ``⊥``) escalates to
    the next tier.  When every tier declines, returns :data:`TOP` — the explicit
    "value unknown" the router lifts to ``Unknown(reason)`` rather than dropping
    the edge silently.

    Args:
        var: the variable whose value is sought (opaque to the facade).
        point: the program point — block serial + EA (standing rule).
        ctx: the injected tier stack (T1 local fold → T2 value-set → T3
            escalation → T4 guard solver).

    Returns:
        The first resolved :class:`AbstractValue` (``Const`` / non-empty
        ``OneOf`` / ``Guarded``), else :data:`TOP`.
    """
    debug = logger.debug_on
    for name, tier in ctx.tiers():
        if tier is None:
            continue
        value = tier(var, point)
        if _is_top(value):
            if debug:
                logger.debug("resolve %r: %s escalated (⊤)", point, name)
            continue
        if debug:
            logger.debug("resolve %r: %s resolved -> %r", point, name, value)
        return value
    if debug:
        logger.debug("resolve %r: all tiers escalated -> ⊤", point)
    return TOP
