"""``recover_machine`` -- the reduced-product composition orchestrator (P4, llr-1d8u).

Composes the three recovery engines (design §6) into one sound machine:

1. **Anchor** (shared) -- reuse the production ``recover_dispatcher`` so the
   dispatcher entry + state cell + initial state never diverge from detection.
2. **Spine = AbstractInterp** (sound over-approx) -- the k-switch set-domain
   fixpoint, with k-escalation (2 -> 4 -> 6) when ⊤-density is high.
3. **Refine = Concolic** of ⊤ cells ONLY -- through the §7 completeness
   :class:`~d810.analyses.machine.refinement_gate.CompletenessGate` so a refinement
   can only NARROW soundly (the Z3-proven gate; never observed-values-only).
4. **Cross-validate** -- agreement raises confidence; disagreement keeps the sound
   AI cell + flags it.
5. **Rank** -- soundness ≻ specificity ≻ confidence (the reduced product wins over
   a bare pattern machine unless the pattern is strictly more specific and no less
   sound).

The heavy engines are INJECTABLE (``spine_engine`` / ``concolic_engine``) so the
orchestrator is unit-testable with fakes (no IDA); absent injection it composes the
sound spine over the StaticShape pattern result from the engine registry and returns
that (the heavy AI/concolic engines wire in at the backend seam).  Returns ``None``
when no engine recovers a dispatcher (the caller then takes the legacy single-engine
path).

Portable: no IDA imports.  Opt-in only: the ``RecoverDispatcher`` pass selects this
when ``project_config["recovery_engine"] == "reduced_product"``.
"""
from __future__ import annotations

from dataclasses import replace

from d810.core.logging import getLogger
from d810.core.typing import Callable, Protocol

from d810.ir.flowgraph import FlowGraph
from d810.analyses.control_flow.dispatcher_recovery import (
    MIN_STATE_CONSTANT,
    min_state_constant_from_config,
    recover_dispatcher,
)
from d810.analyses.control_flow.machine_recovery_engine import DispatcherAnchors
from d810.analyses.control_flow.recovered_machine import (
    MachineTransition,
    RecoveredMachine,
    Soundness,
)
from d810.analyses.control_flow.engine_registry import (
    default_engines,
    recover_machine_via_engines,
)
from d810.analyses.machine.refinement_gate import (
    CompletenessGate,
    ConcolicCellValue,
    GateMode,
    TopCell,
)
from d810.analyses.machine.cross_validate import cross_validate
from d810.analyses.machine.engine_rank import SOUND_RANK, rank_machines, specificity
from d810.analyses.machine.k_escalation import KBudget, should_escalate

logger = getLogger(__name__)

__all__ = [
    "recover_machine",
    "compose_reduced_product",
    "SpineEngine",
    "ConcolicEngine",
    "SpineResult",
]


class SpineResult(Protocol):
    """What a spine engine returns: a machine + the per-cell sound floors.

    ``machine`` is the ``SOUND_OVERAPPROX`` :class:`RecoveredMachine` (its forking
    ``transitions`` may include ⊤ cells -- an empty ``next_states``).  ``floor_for``
    yields the AI ``σ#_in(c)`` projection for a (src_state, context) cell (the §7 (b)
    gate input), or ``None`` for a non-spine/unavailable cell.  ``top_density`` is
    the escalation signal.
    """

    machine: RecoveredMachine
    top_density: float

    def floor_for(self, src_state: int, context: tuple[int, ...]): ...


class SpineEngine(Protocol):
    """The sound AI spine. ``recover`` returns a :class:`SpineResult` or ``None``."""

    name: str

    def recover(
        self,
        graph: FlowGraph,
        anchors: DispatcherAnchors,
        caps: object | None,
        *,
        k: int,
    ) -> SpineResult | None: ...


class ConcolicEngine(Protocol):
    """The concolic engine. ``cell_value`` yields one ⊤-cell's evidence or ``None``."""

    name: str

    def cell_value(
        self, src_state: int, context: tuple[int, ...]
    ) -> ConcolicCellValue | None: ...


# A concolic-cell resolver: (src_state, context) -> evidence or None.
ConcolicResolver = Callable[[int, tuple[int, ...]], "ConcolicCellValue | None"]


def _gate_mode_from_config(project_config) -> GateMode:
    """Read the gate mode from config; default to the (b) fold_exact-floor gate."""
    if isinstance(project_config, dict):
        raw = project_config.get("gate_mode")
        if raw == "deterministic_f":
            return GateMode.DETERMINISTIC_F
    return GateMode.FOLD_EXACT_FLOOR


def _k_from_config(project_config, default: int = 2) -> int:
    if isinstance(project_config, dict):
        try:
            return int(project_config.get("recovery_k", default))
        except (TypeError, ValueError):
            return default
    return default


def _anchors_from_recovery(recovery, graph: FlowGraph) -> DispatcherAnchors:
    """Build the shared :class:`DispatcherAnchors` from a ``DispatcherRecovery``."""
    dmap = getattr(recovery, "dispatch_map", None)
    initial = getattr(dmap, "initial_state", None) if dmap is not None else None
    initial_states = (int(initial),) if initial is not None else ()
    return DispatcherAnchors(
        dispatcher_entry_block=getattr(recovery, "dispatcher_block_serial", None),
        state_var_stkoff=getattr(recovery, "state_var_stkoff", None),
        state_var_lvar_idx=getattr(dmap, "state_var_lvar_idx", None)
        if dmap is not None
        else None,
        initial_states=initial_states,
    )


def _cap_spine_engine(engines: object) -> SpineEngine | None:
    """Best-effort ``engines.spine_engine()`` -> a SpineEngine or None."""
    fn = getattr(engines, "spine_engine", None)
    if fn is None:
        return None
    try:
        return fn()
    except Exception:  # noqa: BLE001 -- capability is best-effort -> abstain
        logger.debug("recover_machine: spine_engine() raised", exc_info=True)
        return None


def _cap_concolic_machine(
    engines: object, graph: FlowGraph, anchors: DispatcherAnchors
) -> RecoveredMachine | None:
    """Best-effort ``engines.concolic_machine(graph, anchors)`` -> machine or None."""
    fn = getattr(engines, "concolic_machine", None)
    if fn is None:
        return None
    try:
        return fn(graph, anchors)
    except Exception:  # noqa: BLE001 -- live emulation is best-effort -> abstain
        logger.debug("recover_machine: concolic_machine() raised", exc_info=True)
        return None


def _cap_concolic_resolver(
    engines: object, graph: FlowGraph, anchors: DispatcherAnchors
) -> ConcolicResolver | None:
    """Best-effort ``engines.concolic_resolver(graph, anchors)`` -> resolver or None."""
    fn = getattr(engines, "concolic_resolver", None)
    if fn is None:
        return None
    try:
        return fn(graph, anchors)
    except Exception:  # noqa: BLE001 -- capability is best-effort -> abstain
        logger.debug("recover_machine: concolic_resolver() raised", exc_info=True)
        return None


def _top_cells(machine: RecoveredMachine) -> tuple[MachineTransition, ...]:
    """The ⊤/unresolved forking transitions (empty ``next_states``)."""
    return tuple(
        t for t in getattr(machine, "transitions", ()) if not t.next_states
    )


def _replace_transition(
    machine: RecoveredMachine, old: MachineTransition, new: MachineTransition
) -> RecoveredMachine:
    """Return ``machine`` with ``old`` swapped for ``new`` in ``transitions``."""
    new_transitions = tuple(new if t is old else t for t in machine.transitions)
    return replace(machine, transitions=new_transitions)


def _select_best(candidates: list[RecoveredMachine]) -> RecoveredMachine | None:
    """Pick the RICHEST recovery, breaking ties by soundness then confidence.

    Ranks by ``(specificity, sound_rank, confidence)`` -- specificity FIRST so the
    fullest recovered table wins regardless of engine.  This differs from
    :func:`rank_machines` (soundness-first) deliberately: at the production seam the
    goal is the best UNFLATTEN, and the concolic engine is prove-exact-or-abstain
    (it rejects truncated / sub-threshold walks, concolic_emulation_engine.py:507),
    so its rows are validated.  When the concolic abstains or recovers fewer rows
    than the static §1a equality-chain lift, the static lift (more specific OR equal
    + higher soundness rank) is kept -- so the §1a floor is never regressed.  A full
    tie keeps the first candidate (the reduced product / concolic is appended before
    the static lift), preserving the EXACT_BOUNDED machine on an exact tie.
    """
    if not candidates:
        return None
    return max(
        candidates,
        key=lambda m: (
            specificity(m),
            SOUND_RANK.get(m.soundness, 0),
            float(m.confidence),
        ),
    )


def run_spine_with_escalation(
    spine_engine: SpineEngine,
    graph: FlowGraph,
    anchors: DispatcherAnchors,
    caps: object | None,
    budget: KBudget,
) -> SpineResult | None:
    """Run the AI spine at increasing k while ⊤-density stays high (design §6.2/§6.5).

    Tries each k in ``budget.schedule_from_start()``; keeps the latest non-None
    result and stops as soon as ⊤-density drops below the threshold (good enough) or
    the budget is exhausted (cost cap).  The spine is replaced by a higher-k result
    only when it actually reduces ⊤-density.
    """
    budget.reset_clock()
    best: SpineResult | None = None
    for k in budget.schedule_from_start():
        result = spine_engine.recover(graph, anchors, caps, k=k)
        if result is None:
            if budget.exhausted(k):
                break
            continue
        if best is None or result.top_density < best.top_density:
            best = result
        if not should_escalate_machine(result):
            break  # density below threshold -> stop escalating
        if budget.exhausted(k):
            break
    return best


def should_escalate_machine(spine_result: SpineResult) -> bool:
    """⊤-density of a spine result exceeds the escalation threshold."""
    return should_escalate(spine_result)


def compose_reduced_product(
    graph: FlowGraph,
    anchors: DispatcherAnchors,
    caps: object | None,
    *,
    spine_engine: SpineEngine,
    concolic_resolver: ConcolicResolver | None,
    concolic_machine: RecoveredMachine | None = None,
    gate_mode: GateMode = GateMode.FOLD_EXACT_FLOOR,
    budget: KBudget | None = None,
) -> RecoveredMachine | None:
    """The §6 reduced product over a precomputed spine + concolic resolver.

    Separated from :func:`recover_machine` so it is unit-testable with fake engines
    (no IDA): callers inject a ``spine_engine`` and a ``concolic_resolver``
    (``(src_state, context) -> ConcolicCellValue | None``).  Returns the merged,
    ranked machine or ``None`` if the spine produced nothing.
    """
    budget = budget or KBudget()
    spine = run_spine_with_escalation(spine_engine, graph, anchors, caps, budget)
    if spine is None:
        # The sound spine abstained entirely. The reduced product cannot form, but a
        # FULL concolic machine (EXACT_BOUNDED, the proven old-engine recovery behind
        # the contract) still beats no recovery, so let it compete (design §6 step 6).
        return rank_machines([concolic_machine]) if concolic_machine is not None else None

    gate = CompletenessGate(mode=gate_mode)
    refined = spine.machine
    accepted_exit_path_summaries = []
    for cell_tr in _top_cells(refined):
        cv = (
            concolic_resolver(int(cell_tr.src_state), tuple(cell_tr.context))
            if concolic_resolver is not None
            else None
        )
        if cv is None:
            continue  # stay ⊤ (incompleteness is free)
        floor = spine.floor_for(int(cell_tr.src_state), tuple(cell_tr.context))
        top_cell = TopCell(transition=cell_tr, floor=floor, is_top=True)
        new_cell = gate.refine_top_cell(
            cell=top_cell, concolic_value=cv, spine_floor=floor
        )
        if not new_cell.is_top:
            # The gate established completeness + soundness -> adopt the refined edge.
            refined = _replace_transition(refined, cell_tr, new_cell.transition)
            if new_cell.exit_path_effect_summary is not None:
                accepted_exit_path_summaries.append(new_cell.exit_path_effect_summary)
    for corridor in accepted_exit_path_summaries:
        refined = refined.with_exit_path_effect_summary(corridor)

    # Cross-validation (§6.4): agreement raises confidence; disagreement keeps AI.
    result = cross_validate(refined, concolic_machine)
    refined = result.machine

    # Ranking (§6/§7): the reduced product competes with the FULL concolic machine.
    # ``rank_machines`` is soundness ≻ specificity ≻ confidence, so the sound spine
    # wins UNLESS the concolic machine is strictly more specific at no less soundness
    # -- i.e. the spine resolved nothing usable (all ⊤) but the concolic executed the
    # dispatcher to a full table. This is the safety net that restores the cases the
    # AI spine cannot yet shape into the contract while it is being built out.
    candidates = [refined]
    if concolic_machine is not None:
        candidates.append(concolic_machine)
    return rank_machines(candidates)


def recover_machine(
    graph: FlowGraph,
    caps: object | None = None,
    *,
    project_config: dict | None = None,
    engines: object | None = None,
    spine_engine: SpineEngine | None = None,
    concolic_resolver: ConcolicResolver | None = None,
    concolic_machine: RecoveredMachine | None = None,
) -> RecoveredMachine | None:
    """Reduced-product composition of the recovery engines (design §6).

    Returns the merged machine, or ``None`` when no engine recovers a dispatcher
    (the caller then takes the legacy single-engine path).

    The heavy engines reach the orchestrator two ways: directly (``spine_engine`` /
    ``concolic_resolver`` / ``concolic_machine`` -- the unit-test injection seam) OR
    via the backend-provided ``engines`` capability
    (:class:`~d810.capabilities.machine_engines.MachineRecoveryEnginesCapability`),
    from which the orchestrator derives the spine + concolic against its OWN shared
    anchors (so anchoring never diverges).  Absent both, the orchestrator composes
    over the enriched-anchor static §1a candidate only -- byte-equivalent to the
    legacy path (no regression).
    """
    if graph is None:
        return None
    min_const = (
        min_state_constant_from_config(project_config)
        if project_config is not None
        else MIN_STATE_CONSTANT
    )
    # ── (1) SHARED ANCHORING ───────────────────────────────────────────────
    recovery = recover_dispatcher(graph, None, min_state_constant=min_const)
    has_static_dispatcher = (
        getattr(recovery, "dispatcher_block_serial", None) is not None
    )
    # The static ``recover_dispatcher`` only recognizes a dispatcher by its compare
    # SHAPE (equality-chain / switch-table). A non-identity-selector machine -- the
    # XOR-masked ``switch((state ^ KEY) & MASK)`` (abc_xor_dispatch) -- has no static
    # shape, so it returns no dispatcher; but the concolic engine SELF-ANCHORS (its
    # ``discover_anchors`` falls back to the dominant-self-update slot the legacy
    # ``EmulatedDispatcherUnflattener`` used) and can still execute it. So do NOT bail
    # here when static anchoring fails -- consult the concolic engine first with empty
    # anchors (it ignores them and self-anchors), and only return None if it too
    # abstains. ``has_static_dispatcher`` gates the static §1a lift below.
    anchors = (
        _anchors_from_recovery(recovery, graph)
        if has_static_dispatcher
        else DispatcherAnchors(dispatcher_entry_block=None)
    )

    # ── derive engines from the backend capability (if not injected directly) ──
    if engines is not None:
        if spine_engine is None:
            spine_engine = _cap_spine_engine(engines)
        if concolic_machine is None:
            concolic_machine = _cap_concolic_machine(engines, graph, anchors)
        if concolic_resolver is None:
            concolic_resolver = _cap_concolic_resolver(engines, graph, anchors)

    # No static dispatcher AND the concolic engine abstained -> nothing to recover.
    if not has_static_dispatcher and concolic_machine is None:
        return None  # caller falls back to the legacy single-engine path

    # Candidates compete via ``rank_machines`` (soundness ≻ specificity ≻ conf).
    candidates: list[RecoveredMachine] = []

    # ── reduced product when a spine engine is available ───────────────────
    if spine_engine is not None:
        gate_mode = _gate_mode_from_config(project_config)
        budget = KBudget(start=_k_from_config(project_config, default=2))
        product = compose_reduced_product(
            graph,
            anchors,
            caps,
            spine_engine=spine_engine,
            concolic_resolver=concolic_resolver,
            concolic_machine=concolic_machine,
            gate_mode=gate_mode,
            budget=budget,
        )
        if product is not None:
            candidates.append(product)
    elif concolic_machine is not None:
        # No spine, but the concolic engine recovered a FULL machine (EXACT_BOUNDED,
        # the proven old-engine recovery behind the contract). It competes directly.
        candidates.append(concolic_machine)

    # ── enriched-anchor static lift (byte-equivalent §1a; the sound floor) ──
    # The anchoring ``recovery`` is exactly what the legacy
    # ``recover_dispatcher(graph, facts)`` path produced -- it has the entry-dominance
    # ``initial_state`` threaded (dispatcher_recovery.py:548-551) that the bare
    # engine-registry / StaticShape path LOSES (it lifts the raw resolver map with
    # ``initial_state=None``). Lifting ``recovery.dispatch_map`` makes the no-spine
    # opt-in path byte-equivalent to the §1a legacy path: ``to_state_dispatcher_map()``
    # of this lift == ``recovery.dispatch_map`` field-for-field, including the
    # recovered prologue ``initial_state`` and ``state_var_stkoff`` the entry bridge
    # needs (root-cause #1: SEAM REGRESSION).
    dmap = getattr(recovery, "dispatch_map", None)
    if dmap is not None:
        candidates.append(
            RecoveredMachine.from_state_dispatcher_map(
                dmap,
                soundness=Soundness.PATTERN,
                provenance=("reduced_product_anchor",),
            )
        )
    else:
        engine_machine = recover_machine_via_engines(
            graph, default_engines(min_state_constant=min_const), anchors=anchors
        )
        if engine_machine is not None:
            candidates.append(engine_machine)

    # Rank: EXACT_BOUNDED concolic outranks the PATTERN static lift, so when the
    # concolic engine executed the dispatcher to a fuller table (the cases the static
    # equality-chain shape cannot resolve), it wins; otherwise the static §1a lift is
    # the floor. ``_select_best`` guards against an EXACT_BOUNDED machine that is
    # strictly LESS specific than the PATTERN floor (never regress the §1a recovery).
    return _select_best(candidates)
