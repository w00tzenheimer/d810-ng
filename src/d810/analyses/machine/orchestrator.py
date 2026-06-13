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
from d810.analyses.machine.engine_rank import rank_machines
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
        return None

    gate = CompletenessGate(mode=gate_mode)
    refined = spine.machine
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

    # Cross-validation (§6.4): agreement raises confidence; disagreement keeps AI.
    result = cross_validate(refined, concolic_machine)
    refined = result.machine

    # Ranking (§6/§7): the reduced product competes with a FULL StaticShape machine.
    return rank_machines([refined])


def recover_machine(
    graph: FlowGraph,
    caps: object | None = None,
    *,
    project_config: dict | None = None,
    spine_engine: SpineEngine | None = None,
    concolic_resolver: ConcolicResolver | None = None,
    concolic_machine: RecoveredMachine | None = None,
) -> RecoveredMachine | None:
    """Reduced-product composition of the recovery engines (design §6).

    Returns the merged machine, or ``None`` when no engine recovers a dispatcher
    (the caller then takes the legacy single-engine path).

    The heavy engines are injectable for testing.  When ``spine_engine`` is absent,
    the orchestrator falls back to the engine registry (StaticShape pattern result)
    so the opt-in path is always defined even before the AI/concolic engines wire in
    at the backend seam -- it returns the registry's best machine (PATTERN), which
    ``to_state_dispatcher_map`` projects to exactly today's map (no regression).
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
    if getattr(recovery, "dispatcher_block_serial", None) is None:
        return None  # no dispatcher -> caller falls back
    anchors = _anchors_from_recovery(recovery, graph)

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
            return product

    # ── fallback: engine registry (StaticShape PATTERN) ────────────────────
    # No spine available (or it abstained): return the registry's best machine so
    # the opt-in path degrades to today's pattern recovery (byte-identical map via
    # to_state_dispatcher_map). This keeps the green floor intact when the heavy
    # engines are not wired.
    engines = default_engines(min_state_constant=min_const)
    machine = recover_machine_via_engines(graph, engines, anchors=anchors)
    if machine is None:
        # Last resort: lift the anchoring recovery's own map (it found a dispatcher).
        dmap = getattr(recovery, "dispatch_map", None)
        if dmap is None:
            return None
        return RecoveredMachine.from_state_dispatcher_map(
            dmap, soundness=Soundness.PATTERN, provenance=("reduced_product_anchor",)
        )
    return machine
