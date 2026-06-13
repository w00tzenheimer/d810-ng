"""DEFFAI abstract state: a multi-cell powerset store (``M# : Var -> 2^Val``).

The DEFFAI abstract state at a program point is ``M# = Var -> 2^Val`` -- a map
from storage cells to **sets of concrete values** (Baek & Lee, *Deobfuscation of
CFF Based on Abstract Interpretation*, IEEE TSE 52(3) 2026; Fig.6 ``x |-> {3,4}``).

The per-cell set element already exists: :class:`StateValue`
(``state_transition_domain.py``) is the finite powerset of constants with explicit
``top``/``bottom``.  This module is the *store* on top of it -- the multi-cell map
keyed by :class:`LocationRef`, with the lattice ops (join/meet/widen/leq) lifted
cell-wise.

Portable-core: no IDA / Hex-Rays imports.  The store is the value the DEFFAI
fixpoint carries through :func:`d810.analyses.data_flow.run_fixpoint`.

Soundness (the ``abstract_domains/protocol.py`` contract): ``join``/``meet``/
``widen`` over-approximate (never drop a feasible value); an unrepresentable cell
returns ``top`` (a visible recovery gap), never a wrong concrete value; ``widen``
guarantees termination (the per-cell powerset is finite-height -- it caps to
``top`` past :attr:`StateValue.MAX_CONSTS`).
"""
from __future__ import annotations

from dataclasses import dataclass, field

from d810.core.typing import ClassVar, Mapping

from d810.analyses.control_flow.state_transition_domain import StateValue
from d810.analyses.data_flow.concolic.refs import LocationRef

__all__ = ["PowersetStore"]


@dataclass(frozen=True, slots=True)
class PowersetStore:
    """``M# : LocationRef -> StateValue`` -- a per-cell powerset map.

    An **absent** cell concretizes to ``bottom`` (``StateValue.bottom()`` --
    unreachable / no information), so the empty store is the lattice ``bottom``.
    A cell mapped to ``StateValue.top()`` is the unresolvable case (data /
    MBA-obfuscated write, or args/returns) -- DEFFAI's ``top`` context-transition,
    surfaced rather than guessed.

    Frozen + hashable: the constructor canonicalizes ``cells`` to a sorted tuple
    of ``(LocationRef, StateValue)`` pairs (dropping ``bottom`` cells so two
    stores that differ only by explicit-vs-absent ``bottom`` compare equal), so a
    :class:`PowersetStore` can key the fixpoint's per-(block, context) state maps.

    Distinct from :class:`d810.analyses.data_flow.concolic.PartitionedState`: that
    carries a *single* ``LocationRef -> StateValue`` store per partition for the
    single-state-variable analysis; :class:`PowersetStore` is the DEFFAI
    multi-cell store (state cell + condvar cells) the set-valued transfer forks
    over.  It is built fresh here rather than reusing ``PartitionedState`` so the
    DEFFAI store can expose the cell-wise ``meet`` / ``leq`` the CCM/CTG need
    without the partition machinery.
    """

    cells: Mapping[LocationRef, StateValue] = field(default_factory=dict)

    #: Store-level cap on the number of distinct cells tracked (the second
    #: blow-up valve, alongside per-cell :attr:`StateValue.MAX_CONSTS`).  Beyond
    #: this, :meth:`set` refuses to add *new* cells and returns ``self``
    #: unchanged (a missing cell is ``bottom`` -- sound under-tracking would be
    #: unsound for a *read*, so we instead keep every existing cell and only
    #: cap growth; callers that hit this should slice harder, design risk 1).
    MAX_CELLS: ClassVar[int] = 4096

    def __post_init__(self) -> None:
        # Canonicalize: drop bottom cells, sort by (kind, key, width) so equal
        # stores hash equal and ordering is deterministic for the CCM/CTG.  Accept
        # either a mapping (``{cell: value}``) or an already-canonical iterable of
        # ``(cell, value)`` pairs (so re-wrapping a frozen store's ``cells`` is a
        # no-op and ``bottom()``'s empty tuple is handled).
        cells = self.cells
        pairs = cells.items() if isinstance(cells, Mapping) else cells
        canon: dict[LocationRef, StateValue] = {}
        for cell, value in pairs:
            if value.is_bottom:
                continue
            canon[cell] = value
        ordered = tuple(
            sorted(
                canon.items(),
                key=lambda kv: (kv[0].kind.value, kv[0].key, kv[0].width),
            )
        )
        object.__setattr__(self, "cells", ordered)

    # -- constructors -------------------------------------------------------
    @staticmethod
    def bottom() -> "PowersetStore":
        """The least element -- the empty store (every cell is ``bottom``)."""
        return PowersetStore(())

    @staticmethod
    def of(mapping: Mapping[LocationRef, StateValue]) -> "PowersetStore":
        """A store from an explicit ``cell -> StateValue`` mapping."""
        return PowersetStore(dict(mapping))

    @staticmethod
    def singleton(cell: LocationRef, value: int) -> "PowersetStore":
        """A store with one cell holding the singleton set ``{value}``."""
        return PowersetStore({cell: StateValue.of(value)})

    # -- access -------------------------------------------------------------
    def get(self, cell: LocationRef) -> StateValue:
        """The cell's value, or ``StateValue.bottom()`` when absent."""
        return dict(self.cells).get(cell, StateValue.bottom())

    def has(self, cell: LocationRef) -> bool:
        """``True`` iff ``cell`` is explicitly tracked (non-``bottom``)."""
        return cell in dict(self.cells)

    def cell_refs(self) -> frozenset[LocationRef]:
        """The set of explicitly-tracked (non-``bottom``) cells."""
        return frozenset(cell for cell, _ in self.cells)

    def is_bottom(self) -> bool:
        """``True`` iff this is the empty store (the lattice ``bottom``)."""
        return len(self.cells) == 0

    # -- functional update --------------------------------------------------
    def set(self, cell: LocationRef, value: StateValue) -> "PowersetStore":
        """Functional update: a new store with ``cell`` strong-updated to ``value``.

        Setting a cell to ``bottom`` removes it (canonicalized in
        ``__post_init__``).  Adding a *new* cell past :attr:`MAX_CELLS` is
        refused (returns ``self``); updating an existing cell always applies.
        """
        current = dict(self.cells)
        if cell not in current and len(current) >= self.MAX_CELLS:
            return self
        current[cell] = value
        return PowersetStore(current)

    def remove(self, cell: LocationRef) -> "PowersetStore":
        """A new store with ``cell`` dropped (set to ``bottom``)."""
        current = dict(self.cells)
        if cell not in current:
            return self
        del current[cell]
        return PowersetStore(current)

    # -- lattice ops --------------------------------------------------------
    def join(self, other: "PowersetStore") -> "PowersetStore":
        """Least upper bound -- per-cell :meth:`StateValue.join` (set UNION).

        Cells present in only one store keep their value (the other contributes
        ``bottom``, the join identity).  This is DEFFAI's lub at a control-flow
        merge: the dispatcher-merge of two handler exits writing ``{a}`` and
        ``{b}`` yields the first-class set ``{a, b}`` (never collapsed to ``top``).
        """
        result: dict[LocationRef, StateValue] = dict(self.cells)
        for cell, value in other.cells:
            existing = result.get(cell)
            result[cell] = value if existing is None else existing.join(value)
        return PowersetStore(result)

    def meet(self, other: "PowersetStore") -> "PowersetStore":
        """Greatest lower bound -- per-cell :meth:`StateValue.meet` (intersection).

        A cell absent from one store is ``bottom`` there, and ``bottom`` is
        absorbing under ``meet`` -- so the result keeps only cells the two stores
        share (their intersection), each refined to the cell-wise glb.  Used by
        CCM/CTG arm feasibility (a context whose condvar set is disjoint from a
        branch arm's required value meets to ``bottom`` -- the arm is infeasible).
        """
        self_cells = dict(self.cells)
        other_cells = dict(other.cells)
        result: dict[LocationRef, StateValue] = {}
        for cell in self_cells.keys() & other_cells.keys():
            result[cell] = self_cells[cell].meet(other_cells[cell])
        return PowersetStore(result)

    def widen(self, other: "PowersetStore") -> "PowersetStore":
        """Widening -- per-cell :meth:`StateValue.widen` (the finite-height join).

        The per-cell powerset caps to ``top`` past :attr:`StateValue.MAX_CONSTS`,
        so the lattice is finite-height and ``widen == join`` suffices for
        termination (mirrors :meth:`StateTransitionDomain.widen`).
        """
        result: dict[LocationRef, StateValue] = dict(self.cells)
        for cell, value in other.cells:
            existing = result.get(cell)
            result[cell] = value if existing is None else existing.widen(value)
        return PowersetStore(result)

    def leq(self, other: "PowersetStore") -> bool:
        """The lattice order ``self <= other``: ``forall cell. self[c] <= other[c]``.

        A cell absent from ``self`` is ``bottom`` (``<=`` everything), so only the
        cells present in ``self`` must be checked against ``other``.
        """
        other_cells = dict(other.cells)
        for cell, value in self.cells:
            if not value.leq(other_cells.get(cell, StateValue.bottom())):
                return False
        return True

    def __repr__(self) -> str:
        if not self.cells:
            return "PowersetStore(bottom)"
        body = ", ".join(
            f"{cell!r}={_fmt_state(value)}" for cell, value in self.cells
        )
        return f"PowersetStore({body})"


def _fmt_state(value: StateValue) -> str:
    if value.is_top:
        return "T"
    if value.is_bottom:
        return "_"
    return "{" + ",".join(hex(c) for c in sorted(value.constants)) + "}"
