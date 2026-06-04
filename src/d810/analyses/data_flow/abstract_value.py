"""Result ADTs for the dispatcher-model consolidation seam (S0).

Two small algebraic data types sit between the lattice engine
(``analyses/abstract_domains``) and the dispatcher router:

* :class:`AbstractValue` — the *projection* of a per-variable lattice element
  into the value-side seam the router consumes.  Four shapes:
  ``Const`` / ``Guarded`` / ``OneOf`` / ``Top``.
* :class:`RouteResult` — what a ``DispatcherModel.route`` returns for an
  abstract value: ``Block`` / ``EntersDispatcher`` / ``OneOf`` / ``Unknown``.

These are *pure types* (no IDA, no wiring).  The ``Const`` variant deliberately
reuses :class:`d810.ir.lattice.Const` (value + size) rather than minting a third
``Const`` — there are already two (``ir.expressions.Const`` for IR literals and
``ir.lattice.Const`` for the constant-propagation domain).  The ``OneOf`` value
variant unifies with :class:`d810.analyses.control_flow.state_transition_domain.StateValue`
via :meth:`OneOf.from_state_value` / :meth:`OneOf.to_state_value`, so the powerset
the state fixpoint already produces is the same powerset the router fans out over.

STANDING RULE: whenever a block/serial is serialized (JSON/logs), its EA is
carried alongside.  :class:`Block` and :class:`EntersDispatcher` therefore hold
an optional ``ea`` and render ``serial@0xEA`` in ``__repr__``.
"""
from __future__ import annotations

from dataclasses import dataclass, field

from d810.core.typing import Iterable, Union

from d810.ir.lattice import Const

__all__ = [
    "Const",
    "Guarded",
    "OneOf",
    "Top",
    "AbstractValue",
    "cases",
    "value_set_from_reaching_def_consts",
    "Block",
    "EntersDispatcher",
    "RouteOneOf",
    "Unknown",
    "RouteResult",
]

_U64_MASK = 0xFFFFFFFFFFFFFFFF


# ---------------------------------------------------------------------------
# AbstractValue = Const | Guarded | OneOf | Top
# ---------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class Guarded:
    """A value refined per guard: a list of ``(guard, value)`` choices.

    The functorial ``Guarded`` shape: each branch carries a guard predicate
    (an opaque token — a comparison expr / edge id, kept abstract here) and the
    :class:`AbstractValue` that holds when the guard is true.  Produced by
    per-edge ``assume_compare`` refinement (S6); for S0 it is a pure carrier.
    """

    choices: tuple[tuple[object, "AbstractValue"], ...] = ()


@dataclass(frozen=True, slots=True)
class OneOf:
    """A finite powerset of concrete constants the value may equal.

    Unifies with the state fixpoint's powerset
    (:class:`~d810.analyses.control_flow.state_transition_domain.StateValue`):
    :meth:`from_state_value` lifts a non-⊤/⊥ ``StateValue`` to ``OneOf`` and
    :meth:`to_state_value` lowers back.  A singleton ``OneOf`` is *not*
    auto-collapsed to :class:`Const` (projection decides that), but
    :meth:`single` exposes the sole value when there is one.
    """

    values: frozenset[int] = field(default_factory=frozenset)

    @staticmethod
    def of(values: Iterable[int]) -> "OneOf":
        return OneOf(frozenset(int(v) & _U64_MASK for v in values))

    def single(self) -> int | None:
        return next(iter(self.values)) if len(self.values) == 1 else None

    @staticmethod
    def from_state_value(sv) -> "AbstractValue":
        """Lift a ``StateValue`` powerset to an :class:`AbstractValue`.

        Duck-typed on the ``StateValue`` shape (``is_top`` / ``constants``) so
        this stays a pure, dependency-light unification — the reverse direction
        (``StateValue.project``) lives on ``StateValue`` itself (added in S0).

        ``⊤`` → :data:`TOP`; ``⊥`` (empty, not ⊤) → empty :class:`OneOf`;
        a singleton → :class:`OneOf` with one element (the caller projects to
        :class:`Const` when it wants the scalar); otherwise the full powerset.
        """
        if getattr(sv, "is_top", False):
            return TOP
        return OneOf(frozenset(int(v) & _U64_MASK for v in sv.constants))


@dataclass(frozen=True, slots=True)
class _Top:
    """The unknown value ``⊤`` — singleton (use :data:`TOP`)."""

    def __repr__(self) -> str:  # pragma: no cover - trivial
        return "Top"


#: The single ``⊤`` AbstractValue (value is unknown / unresolved).
TOP: _Top = _Top()
Top = _Top  # alias so callers can ``isinstance(v, Top)``

#: The value-side seam: a projection of a per-variable lattice element.
AbstractValue = Union[Const, Guarded, OneOf, _Top]


def value_set_from_reaching_def_consts(
    consts: Iterable[int | None],
) -> "AbstractValue":
    """Project a set of reaching-def constants into an :class:`AbstractValue`.

    Pure decision core for the T2 value-set state-write resolver (no IDA): given
    the constant value of every reaching definition of a state-write source
    variable (``None`` for any def that is *not* a provable constant), decide the
    value-side seam shape:

    * any non-constant reaching def (a ``None`` in *consts*) -> :data:`TOP`
      (the value set is not fully known; escalate to the next resolve tier).
    * no reaching defs at all -> :data:`TOP` (nothing proven).
    * exactly one distinct const -> :class:`Const` (masked to 32 bits, size 4),
      so a single-valued source collapses to the scalar the router prefers.
    * two or more distinct consts -> :class:`OneOf` (the powerset the router
      fans out over, one routed edge per member).

    The 32-bit mask mirrors :func:`fold_block_state_write`'s state width.
    """
    seen: set[int] = set()
    for c in consts:
        if c is None:
            return TOP
        seen.add(int(c) & 0xFFFFFFFF)
    if not seen:
        return TOP
    if len(seen) == 1:
        return Const(next(iter(seen)), 4)
    return OneOf(frozenset(seen))


def cases(value: "AbstractValue") -> tuple[tuple[object | None, int], ...]:
    """Enumerate the ``(guard, const)`` cases an :class:`AbstractValue` routes over.

    The router fans out over this: each ``(guard, const)`` becomes one routed
    edge (``guard`` is the predicate the const is valid under, or ``None`` when
    unconditional).  Additive over the four shapes:

    * :class:`Const` -> ``((None, value),)`` — one unconditional case.
    * :class:`OneOf`  -> ``((None, v0), (None, v1), …)`` — one unconditional case
      per powerset member (deterministically sorted so edge sets are stable).
    * :class:`Guarded` -> one case per ``(guard, inner)`` choice, recursing into
      each inner :class:`AbstractValue` and carrying the guard down.  A non-const
      inner (``⊤`` / empty ``OneOf``) contributes nothing under that guard.
    * :data:`TOP` (``⊤``) -> ``()`` — no enumerable const; the router emits an
      explicit unresolved gap rather than inventing a target.

    Defined as a module function (not a method) because the ``Const`` variant IS
    the shared :class:`d810.ir.lattice.Const`, which this seam must not mutate.
    """
    if value is TOP or isinstance(value, _Top):
        return ()
    if isinstance(value, Const):
        return ((None, int(value.value) & _U64_MASK),)
    if isinstance(value, OneOf):
        return tuple((None, v) for v in sorted(value.values))
    if isinstance(value, Guarded):
        out: list[tuple[object | None, int]] = []
        for guard, inner in value.choices:
            for inner_guard, const in cases(inner):
                # Outer guard dominates; an inner guard (nested ``Guarded``) is
                # only reached when the outer one already holds, so keep the
                # outer guard as the case's predicate.
                _ = inner_guard
                out.append((guard, const))
        return tuple(out)
    return ()


# ---------------------------------------------------------------------------
# RouteResult = Block | EntersDispatcher | OneOf | Unknown
# ---------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class Block:
    """The route resolves to a single target block.

    Carries ``serial`` plus an optional ``ea`` (STANDING RULE: serialize EA
    alongside the serial).  ``__repr__`` renders ``Block(serial@0xEA)``.
    """

    serial: int
    ea: int | None = None

    def __repr__(self) -> str:
        if self.ea is None:
            return f"Block({self.serial})"
        return f"Block({self.serial}@{self.ea:#x})"


@dataclass(frozen=True, slots=True)
class EntersDispatcher:
    """The route re-enters a (possibly inner) dispatcher model.

    ``model`` is the inner :class:`DispatcherModel`; ``entry_serial`` /
    ``entry_ea`` name its entry (EA carried alongside the serial).
    """

    model: object
    entry_serial: int | None = None
    entry_ea: int | None = None

    def __repr__(self) -> str:
        if self.entry_serial is None:
            return "EntersDispatcher(?)"
        if self.entry_ea is None:
            return f"EntersDispatcher({self.entry_serial})"
        return f"EntersDispatcher({self.entry_serial}@{self.entry_ea:#x})"


@dataclass(frozen=True, slots=True)
class RouteOneOf:
    """The route fans out to several candidate blocks (one per input value).

    Named ``RouteOneOf`` to avoid colliding with the value-side :class:`OneOf`;
    ``RouteResult.OneOf`` in the plan maps to this.  Each target is a
    :class:`Block` (so each carries its EA).
    """

    targets: tuple[Block, ...] = ()


@dataclass(frozen=True, slots=True)
class Unknown:
    """The route could not be resolved — an explicit, honest gap.

    ``reason`` is the surfaced diagnostic (e.g. ``"state_not_in_dispatcher_map"``)
    rather than a silently dropped edge.
    """

    reason: str = ""


#: What a ``DispatcherModel.route`` returns for an :class:`AbstractValue`.
RouteResult = Union[Block, EntersDispatcher, RouteOneOf, Unknown]
