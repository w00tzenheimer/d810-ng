"""The §7 completeness gate -- the soundness heart of the reduced product (P4, llr-1d8u).

The load-bearing soundness fact (Z3-PROVEN, truth
``reduced_product_cff_refinement/is_sound_iff``):

    Refining a ⊤ context-cell ``σ#(c) = V if G(c,V) else ⊤`` preserves the abstract
    spine's soundness (``∀c: C(c) ⊆ γ(σ'#(c))``) **IFF** the gate guarantees
    completeness ``G(c,V) ⟹ C(c) ⊆ V(c)``.

A *naive* ``V ⊆ C`` (observed-values-only) gate is UNSOUND: the Z3 counterexample
``C = 0b1111, V = ∅`` satisfies ``V ⊆ C`` vacuously, so the gate would accept the empty
set and silently drop every real transition.  Two SOUND gates exist:

* **(a)** ``V = image(f)`` for a deterministic per-context ``f`` over a fully-enumerated
  *sound* in-context input set -- then ``V`` is the exact reachable set.
* **(b)** ``fold_exact``: accept ``V`` only if ``V ⊇ γ(σ#_floor)`` against a SOUND coarser
  floor (``C ⊆ Floor ⊆ V``).  This is the DEFAULT.

The in-tree defect this module fixes (design §7, ticket §0.1): the existing
``minimal_state_recovery._emulate_unresolved_state`` folded against
``ConcolicValue.top(8)`` -- a ⊤ floor whose ``contains`` is always ``True`` -- so the
gate was VACUOUS (soundness rested only on the emulator's abstain discipline, not the
gate).  :meth:`CompletenessGate._gate_b` early-returns "stay ⊤" the moment the floor is
⊤, so the gate NEVER refines on the strength of a ⊤ floor.

Portable: no IDA, no z3.  The gate reuses the proven ``fold_exact`` primitive
(:func:`d810.analyses.data_flow.concolic.fold_exact`) with a NON-⊤ floor, so it now does
real per-value soundness validation.
"""
from __future__ import annotations

import enum
from dataclasses import dataclass, field, replace

from d810.core.logging import getLogger
from d810.analyses.control_flow.recovered_machine import (
    MachineTransition,
    Soundness,
    ExitPathEffectSummary,
)
from d810.analyses.data_flow.concolic import (
    AbstractEvidence,
    ConcolicValue,
    LocationRef,
    PrecisionStatus,
    fold_exact,
)
from d810.analyses.data_flow.concolic.emulation import EmulationOutcome

logger = getLogger(__name__)

__all__ = [
    "GateMode",
    "ConcolicCellValue",
    "TopCell",
    "CompletenessGate",
    "gamma_members",
]

#: Soundness cap on enumerating γ(floor).  Above this many candidate values the
#: floor is treated as not-finitely-enumerable (-> singleton-only gate), so the
#: gate never iterates an unbounded set.  CFF state domains are small (sub_7FFD has
#: ~45-66 states); a real floor enumerates far below this.
GAMMA_ENUM_CAP = 4096


class GateMode(enum.Enum):
    """Which §7 soundness gate the refinement uses."""

    #: §7 (b): accept ``V`` only when ``γ(floor) ⊆ V`` against a SOUND non-⊤ floor.
    #: The DEFAULT -- it does not trust any "I enumerated everything" flag.
    FOLD_EXACT_FLOOR = enum.auto()
    #: §7 (a): accept ``V = image(f)`` only when the concolic walk proves ``f``
    #: deterministic over a FULLY-enumerated sound input set.
    DETERMINISTIC_F = enum.auto()


@dataclass(frozen=True, slots=True)
class ConcolicCellValue:
    """One ⊤-cell's concolic evidence (the [P2] engine's value for a context).

    ``next_states`` is ``V`` (the candidate forking next-state set).
    ``per_state_value`` maps each next-state to the proven exact concrete the
    emulator asserts for that arm (replayed through ``fold_exact`` against the
    floor).  ``exact_outcome`` is the raw :class:`EmulationOutcome` ADT for the
    ``fold_exact`` replay.  ``enumerated_inputs_complete`` / ``deterministic`` are
    the gate (a) obligations the concolic engine sets ONLY for a sound, exhaustive
    walk (never from observed values); the gate refuses to refine when either is
    ``False``.
    """

    next_states: frozenset[int]
    per_state_value: dict[int, int] = field(default_factory=dict)
    exact_outcome: EmulationOutcome | None = None
    state_loc: LocationRef | None = None
    enumerated_inputs_complete: bool = False
    deterministic: bool = False
    exit_path_effect_summary: ExitPathEffectSummary | None = None


@dataclass(frozen=True, slots=True)
class TopCell:
    """A ⊤ context-cell the orchestrator asks the gate to refine.

    ``transition`` is the underlying :class:`MachineTransition` (its
    ``next_states`` are best-effort/empty while ⊤).  ``floor`` is the AI spine's
    ``σ#_in(c)`` projection for THIS cell (the §7 (b) input); ``None`` for a
    non-spine cell.  ``is_top`` records that the cell is unresolved -- the gate
    only ever touches ``is_top`` cells.
    """

    transition: MachineTransition
    floor: AbstractEvidence | None
    is_top: bool = True
    exit_path_effect_summary: ExitPathEffectSummary | None = None


def gamma_members(floor: AbstractEvidence, *, cap: int = GAMMA_ENUM_CAP) -> frozenset[int] | None:
    """A SOUND, EXACT ``{v : floor.contains(v)}`` (γ membership), or ``None``.

    Returns the exact member set when the floor's value space is finitely
    enumerable below ``cap``; ``None`` when the floor is ⊤ / too large to
    enumerate soundly (the caller then degrades to the singleton-only gate, which
    can never collapse a fork on incomplete evidence -- design §12 risk 1).

    The enumeration MUST be sound: every ``v`` the floor contains must appear, or
    the completeness check ``γ(floor) ⊆ V`` could pass while a real transition is
    dropped.  Two enumerable windows, both checked against the FULL floor's
    ``contains`` so the result is exactly ``{v : floor.contains(v)}``:

    * the interval component's enumerable arc (``cardinality() ≤ cap``), using the
      proven modular walk ``(lo + i) % 2^w`` (the same enumeration
      ``WrappedInterval.project`` uses for its ``OneOf``);
    * else the whole value space when ``2^w ≤ cap`` (small widths).

    Anything wider/unbounded -> ``None`` (never enumerate an unsound/huge set).
    """
    if floor is None or floor.is_top() or floor.is_bottom():
        return None
    interval = floor.interval
    width = floor.width
    mod = 1 << width
    # Prefer the interval arc: it is a sound over-approx of the value range, and a
    # bounded arc enumerates exactly. A value is a γ member iff the FULL reduced
    # product (bits ∩ interval) contains it, so we still filter by floor.contains.
    if not interval.is_top() and not interval.is_bottom():
        card = interval.cardinality()
        if 0 < card <= cap:
            members = frozenset(
                v for i in range(card) if floor.contains(v := (interval.lo + i) % mod)
            )
            return members if members else None
    # Fall back to the whole space for small widths (sound: tests every value).
    if mod <= cap:
        members = frozenset(v for v in range(mod) if floor.contains(v))
        return members if members else None
    return None


class CompletenessGate:
    """The §7 (a)/(b) refinement gate -- the only sanctioned ⊤-cell refine entry.

    ``refine_top_cell`` returns the cell UNCHANGED (still ⊤) unless the chosen
    gate establishes completeness (and, for (b), per-value soundness via
    ``fold_exact`` against the NON-⊤ floor).  A refined cell is returned with its
    ``next_states`` set to ``V``, ``is_top=False``, and ``Soundness.EXACT_BOUNDED``.
    """

    def __init__(self, mode: GateMode = GateMode.FOLD_EXACT_FLOOR) -> None:
        self.mode = mode

    def refine_top_cell(
        self,
        *,
        cell: TopCell,
        concolic_value: ConcolicCellValue,
        spine_floor: AbstractEvidence | None = None,
    ) -> TopCell:
        """Refine ``cell`` to the concolic ``V`` iff the gate proves completeness.

        ``spine_floor`` overrides ``cell.floor`` when given (the orchestrator
        passes the per-context σ#_in projection); otherwise ``cell.floor`` is used.
        Returns the (possibly unchanged) :class:`TopCell`.
        """
        floor = spine_floor if spine_floor is not None else cell.floor
        if self.mode is GateMode.FOLD_EXACT_FLOOR:
            return self._gate_b(cell, concolic_value, floor)
        return self._gate_a(cell, concolic_value)

    # -- gate (b): V ⊇ γ(floor), floor sound -------------------------------
    def _gate_b(
        self,
        cell: TopCell,
        cv: ConcolicCellValue,
        floor: AbstractEvidence | None,
    ) -> TopCell:
        if floor is None or floor.is_top():
            # NO non-trivial floor -> cannot establish (b) -> stay ⊤.
            # THIS IS THE §0.1 FIX: the gate never refines on a ⊤ floor.
            if logger.info_on:
                logger.info("gate(b): ⊤/None floor -> stay ⊤")
            return cell
        if floor.is_bottom():
            # ⊥ floor means the cell is unreachable; nothing to refine.
            return cell
        v = cv.next_states
        if not v:
            return cell  # empty V is the Z3 CEX's vacuous accept -> stay ⊤
        members = gamma_members(floor)
        if members is None:
            # floor not finitely enumerable -> singleton-only (cannot prove a fork
            # complete here; a singleton V is complete iff γ(floor) ⊆ {exact}).
            return self._gate_b_singleton(cell, cv, floor)
        # 1. COMPLETENESS (the §7 obligation): every floor member must be in V.
        if not members <= v:
            if logger.info_on:
                logger.info(
                    "gate(b): incomplete γ(floor)=%s ⊄ V=%s -> stay ⊤",
                    sorted(members), sorted(v),
                )
            return cell  # γ(floor) ⊄ V -> V is INCOMPLETE -> reject (drops Z3 CEX)
        # 2. SOUNDNESS-of-V: each claimed value validated by fold_exact against the
        #    NON-⊤ floor, so a backend value OUTSIDE γ(floor) is caught and dropped.
        if not self._all_values_fold_clean(cv, floor):
            return cell
        # 3. ACCEPT: refine ⊤ -> V (complete AND sound).
        return self._accept(cell, v)

    def _gate_b_singleton(
        self,
        cell: TopCell,
        cv: ConcolicCellValue,
        floor: AbstractEvidence,
    ) -> TopCell:
        """Gate (b) when γ(floor) is not enumerable: accept ONLY a singleton V.

        A singleton ``V = {x}`` is complete iff ``C(c) ⊆ {x}``.  We can prove that
        only when the floor itself collapses to ``{x}`` (``floor.to_const() == x``),
        i.e. the spine already proved the cell deterministic and equal to ``x`` --
        in which case ``γ(floor) = {x} ⊆ V``.  Any larger floor (``|γ(floor)|>1``)
        CANNOT be collapsed to one value here, so we stay ⊤ (refuse to collapse a
        real fork) -- the property design §12 risk 1 demands.
        """
        if len(cv.next_states) != 1:
            return cell  # cannot prove a fork complete against an un-enumerable floor
        (only,) = tuple(cv.next_states)
        floor_const = floor.to_const()
        if floor_const is None or (floor_const & ((1 << floor.width) - 1)) != (
            only & ((1 << floor.width) - 1)
        ):
            # floor is multi-valued (or disagrees) -> {only} may drop a real value.
            return cell
        if not self._all_values_fold_clean(cv, floor):
            return cell
        return self._accept(cell, cv.next_states)

    def _all_values_fold_clean(
        self, cv: ConcolicCellValue, floor: AbstractEvidence
    ) -> bool:
        """``True`` iff every claimed next-state folds CONCRETE against the floor.

        Replays ``fold_exact`` with the NON-⊤ floor for each ``s`` in ``V``: a
        backend value the floor does NOT contain (an unsound/over-eager emulator)
        folds back to ABSTRACT, not CONCRETE, and is rejected here -- the §7 (b)
        per-value soundness check (concrete_refiner.py:66, ``value.abstract.contains``).
        Cells with no replay evidence (``exact_outcome``/``state_loc`` absent) are
        accepted on the strength of the completeness check alone (the floor already
        bounds them); only an EXPLICIT contradicting outcome rejects.
        """
        if cv.exact_outcome is None or cv.state_loc is None:
            return True
        base = ConcolicValue(None, None, floor, floor.width, PrecisionStatus.ABSTRACT)
        for s in cv.next_states:
            expected = cv.per_state_value.get(int(s))
            if expected is None:
                continue  # no exact claim for this arm -> floor bounds it; accept
            folded = fold_exact(base, cv.exact_outcome, cv.state_loc)
            if folded.status is not PrecisionStatus.CONCRETE:
                if logger.info_on:
                    logger.info(
                        "gate(b): backend value for state=%s not in γ(floor) -> drop",
                        s,
                    )
                return False
            if int(folded.concrete) & ((1 << floor.width) - 1) != int(expected) & (
                (1 << floor.width) - 1
            ):
                # The fold resolved to a DIFFERENT value than the per-arm claim:
                # the floor disagrees with the backend -> unsound -> drop.
                if logger.info_on:
                    logger.info(
                        "gate(b): fold=%#x != claimed=%#x -> drop",
                        int(folded.concrete), int(expected),
                    )
                return False
        return True

    # -- gate (a): V = image(f) over a complete sound input set -------------
    def _gate_a(self, cell: TopCell, cv: ConcolicCellValue) -> TopCell:
        if not (cv.enumerated_inputs_complete and cv.deterministic):
            if logger.info_on:
                logger.info(
                    "gate(a): inputs_complete=%s deterministic=%s -> stay ⊤",
                    cv.enumerated_inputs_complete, cv.deterministic,
                )
            return cell  # cannot prove image(f)=C -> stay ⊤
        if not cv.next_states:
            return cell
        corridor = None
        if cv.exit_path_effect_summary is not None:
            corridor = self.accept_exit_path_effect_summary(cv.exit_path_effect_summary)
            if corridor is None:
                return cell
        # f deterministic + inputs fully enumerated => V = image(f) = C (§7 (a)).
        return self._accept(cell, cv.next_states, floor=None, exit_path_effect_summary=corridor)

    def accept_exit_path_effect_summary(
        self, corridor: ExitPathEffectSummary
    ) -> ExitPathEffectSummary | None:
        """Accept an exit-path effect summary only when it proves Gate A obligations.

        This keeps exit-path effect recovery proof-carrying: symbolic payloads
        such as a fresh external-call value are allowed in effects, but not in
        branch choices.
        """

        if not corridor.is_complete_deterministic_proof:
            if logger.info_on:
                logger.info(
                    "gate(a): exit-path effect summary rejected "
                    "(complete=%s deterministic=%s terminal=%s sym_branch=%s)",
                    corridor.enumerated_inputs_complete,
                    corridor.deterministic,
                    corridor.terminal_reachable,
                    sorted(corridor.symbolic_branch_dependencies),
                )
            return None
        return corridor

    # -- accept helper ------------------------------------------------------
    def _accept(
        self,
        cell: TopCell,
        v: frozenset[int],
        *,
        floor: AbstractEvidence | None = ...,  # type: ignore[assignment]
        exit_path_effect_summary: ExitPathEffectSummary | None = None,
    ) -> TopCell:
        """Build the refined (non-⊤) cell with ``next_states = V``.

        The underlying :class:`MachineTransition` gets ``next_states`` set to the
        sorted ``V`` and ``confidence`` carried through; the :class:`TopCell`
        wrapper flips ``is_top`` to ``False``.  The floor is preserved by default
        (gate (b)); gate (a) passes ``floor=None``.
        """
        new_tr = replace(cell.transition, next_states=tuple(sorted(int(s) for s in v)))
        new_floor = cell.floor if floor is ... else floor
        if logger.info_on:
            logger.info(
                "gate: REFINE ⊤ -> V=%s (src_state=%s)",
                sorted(v), cell.transition.src_state,
            )
        return TopCell(
            transition=new_tr,
            floor=new_floor,
            is_top=False,
            exit_path_effect_summary=exit_path_effect_summary,
        )
