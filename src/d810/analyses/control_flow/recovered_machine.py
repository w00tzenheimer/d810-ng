"""Engine-neutral recovered state machine (P1, llr-5knz).

Generalizes ``StateDispatcherMap`` (dispatcher_resolution.py) into the common
contract every recovery engine (StaticShape / AbstractInterp / Concolic) emits.
Today's ``state -> handler`` map is the degenerate ``k=1, no-fork, PATTERN`` case
(design §4): ``to_state_dispatcher_map()`` round-trips it byte-identically so the
existing emit path is unchanged. Forks (``transitions``) and contexts (k-tuples)
are first-class slots the abstract/concolic engines fill in P3/P4; StaticShape
leaves them empty.

LEAF module: imports only the pure-data row/map types + enums. It must NOT import
``dispatcher_resolver`` / ``dispatcher_recovery`` (those import the engine layer
that imports *this*), keeping the contract cycle-free under ``check-cycles``.
"""
from __future__ import annotations

from dataclasses import dataclass, field, replace
import enum

from d810.analyses.control_flow.dispatcher_kind import DispatcherType
from d810.analyses.control_flow.dispatcher_resolution import (
    StateDispatcherMap,
    StateDispatcherRow,
)

__all__ = [
    "Soundness",
    "MachineRow",
    "MachineTransition",
    "RecoveredMachine",
]


class Soundness(enum.Enum):
    """How an engine's result relates to the true reachable transition set.

    SOUND_OVERAPPROX -- ``C(c) ⊆ γ(result)`` always (abstract interpretation;
        may include spurious transitions, never drops a real one). Design §5/§7.
    EXACT_BOUNDED    -- exact within an explored/bounded region; outside it the
        result is silent (concolic; under-approximates unless completeness-gated).
    PATTERN          -- structural pattern match; correct iff the shape assumption
        holds (today's equality-chain / switch / indirect resolvers). Design §5.
    """

    SOUND_OVERAPPROX = "sound_overapprox"
    EXACT_BOUNDED = "exact_bounded"
    PATTERN = "pattern"


@dataclass(frozen=True, slots=True)
class MachineRow:
    """One ``state_const -> target_block`` row (k=1 degenerate transition).

    Field-compatible superset of ``StateDispatcherRow`` so ``to_state_dispatcher_map``
    is a 1:1 field copy. ``context`` is the k-tuple this row's state belongs to
    (``()`` == k=1 raw-state today).
    """

    state_const: int
    target_block: int
    dispatcher_block: int
    compare_block: int | None = None
    branch_kind: str = ""
    source: DispatcherType = DispatcherType.UNKNOWN
    confidence: float = 1.0
    row_kind: str = "handler"
    context: tuple[int, ...] = ()
    payload: dict[str, object] = field(default_factory=dict)

    @property
    def is_handler_row(self) -> bool:
        return self.row_kind in {"handler", "handler_alias"}


@dataclass(frozen=True, slots=True)
class MachineTransition:
    """A FORKING edge: ``(src_state, context) -> tuple[next_state, ...]``.

    First-class fork (design §4): a two-valued ``state = cond ? a : b`` is one
    transition with ``next_states=(a, b)``. ``via_block`` + ``op``/``const``
    capture provenance (which block/opcode/constant produced the fork). EMPTY for
    StaticShapeEngine in P1 (it emits no forks); filled by AbstractInterp (P3).
    """

    src_state: int
    context: tuple[int, ...]
    next_states: tuple[int, ...]
    via_block: int | None = None
    op: str | None = None
    const: int | None = None
    confidence: float = 1.0


@dataclass(frozen=True, slots=True)
class RecoveredMachine:
    """Engine-neutral recovered CFF state machine (the common contract).

    ``rows`` are the resolved ``state -> handler`` edges; ``transitions`` are the
    forking edges; ``contexts`` is the tuple of k-tuples in play (k=1 today, so a
    tuple of 1-tuples or ``()``). ``source`` + ``soundness`` + ``confidence`` +
    ``provenance`` are the policy/diagnostic envelope the P4 orchestrator ranks on.
    """

    rows: tuple[MachineRow, ...]
    transitions: tuple[MachineTransition, ...] = ()
    contexts: tuple[tuple[int, ...], ...] = ()
    initial_states: tuple[int, ...] = ()
    state_var_stkoff: int | None = None
    state_var_lvar_idx: int | None = None
    dispatcher_entry_block: int | None = None
    dispatcher_blocks: frozenset[int] = frozenset()
    source: DispatcherType = DispatcherType.UNKNOWN
    soundness: Soundness = Soundness.PATTERN
    confidence: float = 1.0
    provenance: tuple[str, ...] = ()
    # carried through verbatim so to_state_dispatcher_map round-trips byte-identically
    default_target_block: int | None = None
    default_row_kind: str | None = None

    # ---- adapters (the load-bearing P1 deliverable) ----

    @classmethod
    def from_state_dispatcher_map(
        cls,
        dmap: StateDispatcherMap,
        *,
        soundness: Soundness = Soundness.PATTERN,
        confidence: float = 1.0,
        provenance: tuple[str, ...] = (),
    ) -> "RecoveredMachine":
        """Lift a ``StateDispatcherMap`` (today's k=1 PATTERN result) into the contract.

        Pure field copy + degenerate context derivation; NO recomputation, so the
        round-trip ``from_state_dispatcher_map -> to_state_dispatcher_map`` is the
        identity on every field (proven by test, §6 step 4).
        """
        rows = tuple(
            MachineRow(
                state_const=r.state_const,
                target_block=r.target_block,
                dispatcher_block=r.dispatcher_block,
                compare_block=r.compare_block,
                branch_kind=r.branch_kind,
                source=r.source,
                confidence=r.confidence,
                row_kind=r.row_kind,
                context=(),                # k=1 raw state
                payload=dict(r.payload),
            )
            for r in dmap.rows
        )
        initial = (
            (int(dmap.initial_state),) if dmap.initial_state is not None else ()
        )
        return cls(
            rows=rows,
            transitions=(),
            contexts=(),
            initial_states=initial,
            state_var_stkoff=dmap.state_var_stkoff,
            state_var_lvar_idx=dmap.state_var_lvar_idx,
            dispatcher_entry_block=dmap.dispatcher_entry_block,
            dispatcher_blocks=dmap.dispatcher_blocks,
            source=dmap.source,
            soundness=soundness,
            confidence=confidence,
            provenance=provenance,
            default_target_block=dmap.default_target_block,
            default_row_kind=dmap.default_row_kind,
        )

    def to_state_dispatcher_map(self) -> StateDispatcherMap:
        """Project back to ``StateDispatcherMap`` so the existing emit path is unchanged.

        FIELD-BY-FIELD inverse of ``from_state_dispatcher_map``. ``transitions`` /
        ``contexts`` / ``soundness`` / ``confidence`` / ``provenance`` are dropped
        here (the emit path does not consume them); for a StaticShape result they
        are empty/PATTERN so nothing is lost. ``initial_states`` collapses to the
        single ``initial_state`` (k=1, len<=1 for StaticShape).
        """
        rows = tuple(
            StateDispatcherRow(
                state_const=r.state_const,
                target_block=r.target_block,
                dispatcher_block=r.dispatcher_block,
                compare_block=r.compare_block,
                branch_kind=r.branch_kind,
                source=r.source,
                confidence=r.confidence,
                row_kind=r.row_kind,
                payload=dict(r.payload),
            )
            for r in self.rows
        )
        initial_state = (
            int(self.initial_states[0]) if self.initial_states else None
        )
        return StateDispatcherMap(
            rows=rows,
            dispatcher_entry_block=int(self.dispatcher_entry_block)
            if self.dispatcher_entry_block is not None
            else None,
            dispatcher_blocks=self.dispatcher_blocks,
            state_var_stkoff=self.state_var_stkoff,
            state_var_lvar_idx=self.state_var_lvar_idx,
            source=self.source,
            initial_state=initial_state,
            default_target_block=self.default_target_block,
            default_row_kind=self.default_row_kind,
        )

    def with_initial_state(self, state: int) -> "RecoveredMachine":
        """Return a copy threading a single initial state (mirrors dispatcher_recovery.py:551
        ``replace(dmap, initial_state=...)``)."""
        return replace(self, initial_states=(int(state),))
