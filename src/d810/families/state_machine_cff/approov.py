"""ApproovFamily — the second unflatten profile: switch/indirect CFF on the shared spine.

This is a *sibling* of :class:`HodurFamily`, not a fork: it runs the SAME portable
``run_pipeline`` driver over the SAME five passes (``RecoverDispatcher`` ->
``RecoverStateTransitions`` -> ``PlanSemanticRegions`` -> ``LowerStateMachine`` ->
``CleanupResidualDispatcher``). A *profile* only customises three things:

* ``detect`` — which table provenances it claims (switch-table / indirect-jump),
  scoped over the SHARED front-end ``build_dispatch_map_any_kind`` so the two families
  never grow parallel detectors;
* ``pipeline_for`` — per-pass capability requirements and the table-provenance
  pin, via the already-injectable ``LowerStateMachine``;
* the ``"emulation"`` capability requirement — switch/indirect next-state targets are
  folded by a concrete emulator (``EmulationCapability``; M3 backend ``llr-xauw``).

Disambiguation (the resolution of "why is Hodur attacking Approov"): each family OWNS a
``TableProvenance`` set. A table-backed function is claimed HERE; an equality-chain function by
``HodurFamily``. The shared *front-end* stays shared; only the *claim* is per-family.
Because the claims are DISJOINT (table-backed here, equality-chain for Hodur),
``select_family`` is order-independent — no priority/tiebreak needed.

Additive + inert: ApproovFamily auto-registers (via :class:`StateMachineCffFamily` /
``Registrant``) and is enumerated by :func:`d810.families.registry.select_family`, which
is NOT on the live maturity-hook path (the live entry hardcodes ``HodurFamily()``).
``HodurFamily.detect`` already claims ``CONDITION_CHAIN`` only, so the claims are disjoint
today; the remaining cutover is wiring the live entry to ``select_family`` so abc on
unflatten-portable routes here (production abc is unaffected — it runs via HCC).
"""
from __future__ import annotations

from d810.passes.pass_pipeline import (
    CapabilityPolicy,
    default,
    live_mba,
    no_caps,
)
from d810.passes.unflatten.state_machine import (
    CleanupResidualDispatcher,
    LowerStateMachine,
    PlanSemanticRegions,
    RecoverDispatcher,
    RecoverStateTransitions,
)
from d810.capabilities.dispatcher import RouterKind, TableProvenance
from d810.analyses.control_flow.dispatcher_recovery import build_dispatch_map_any_kind
from d810.families.state_machine_cff.base import StateMachineCffFamily
from d810.ir.maturity import IRMaturity
from d810.families.state_machine_cff.pipeline import (
    CLEANUP_ANALYSES,
    DISPATCHER_ANALYSES,
    LOWER_ANALYSES,
    REGION_ANALYSES,
    TRANSITION_ANALYSES,
    state_machine_pass_spec,
    standard_state_machine_passes,
)

# Hard backend requirement: indirect/computed next-state targets need a concrete
# emulator to fold. The string keys ``CapabilityPolicy.required`` (validated against
# ``backend.capabilities()``); the typed ``EmulationCapability`` is read inside the pass
# via ``ctx.capabilities.optional(...)`` (portable fallback: ``ReferenceEmulator``).
emulation = CapabilityPolicy(required=frozenset({"live_mba", "emulation"}))

# The table provenances THIS profile owns. A table-backed function is claimed here;
# equality-chain (CONDITION_CHAIN) belongs to HodurFamily.
_APPROOV_TABLE_PROVENANCES = frozenset({
    TableProvenance.SWITCH,
    TableProvenance.INDIRECT_JUMP_TABLE,
})


class ApproovFamily(StateMachineCffFamily):
    """Switch/indirect CFF (Approov) family: detection + pipeline shape. No microcode patching."""

    name = "approov"

    #: Switch-table dispatchers survive flat through global analysis (the backend keeps the
    #: jump table), so ``GLOBAL_ANALYZED`` (Hex-Rays ``MMAT_GLBOPT1``) is the recovery point
    #: — the goldens are tuned to it (ticket llr-a93i). The TABLE/indirect_jump_table case is routed to
    #: ``CALL_MODELED`` (``MMAT_CALLS``) by the rule's structural ``_is_indirect`` gate, not
    #: by this declaration.
    recovery_maturities = (IRMaturity.GLOBAL_ANALYZED,)

    def detect(self, graph, capabilities, context=None):
        """Claim ONLY switch/indirect dispatchers over a portable ``FlowGraph``.

        Reuses the shared front-end ``build_dispatch_map_any_kind`` (so detect and the
        pipeline's pass #1 never disagree on which shapes are supported), then narrows by
        ``StateDispatcherMap.router_kind`` to this profile's kind set. Returns the recovered
        map (truthy) on a match, else ``None`` so the pipeline only runs where a real
        switch/indirect dispatcher is present.
        """
        if graph is None or not hasattr(graph, "blocks"):
            return None
        dmap = build_dispatch_map_any_kind(graph)
        if (
            dmap is None
            or dmap.router_kind is not RouterKind.TABLE
            or dmap.table_provenance not in _APPROOV_TABLE_PROVENANCES
        ):
            return None
        return dmap

    def pipeline_for(self, match, context) -> "tuple[PassSpec, ...]":
        """Kind-aware pipeline.

        ``TABLE`` with switch provenance runs the standard seeded-fold spine
        (NO emulation) — proven on
        abc_or_dispatch, whose masked-OR writes fold via the partitioned fixpoint; this is
        the only live ApproovFamily kind (the chain has no indirect detector yet).

        ``TABLE/indirect_jump_table`` needs the concrete emulator to fold computed targets
        (``EmulationCapability``, M3+) and pins ``RouterKind.TABLE`` plus
        ``TableProvenance.INDIRECT_JUMP_TABLE``; structural
        until an indirect resolver + emulation backend land.
        """
        if (
            getattr(match, "router_kind", None) is RouterKind.TABLE
            and getattr(match, "table_provenance", None)
            is TableProvenance.INDIRECT_JUMP_TABLE
        ):
            return (
                state_machine_pass_spec(
                    "recover_dispatcher",
                    RecoverDispatcher,
                    live_mba,
                    default,
                    analyses=DISPATCHER_ANALYSES,
                ),
                state_machine_pass_spec(
                    "recover_state_transitions",
                    RecoverStateTransitions,
                    emulation,
                    default,
                    analyses=TRANSITION_ANALYSES,
                ),
                state_machine_pass_spec(
                    "plan_semantic_regions",
                    PlanSemanticRegions,
                    no_caps,
                    default,
                    analyses=REGION_ANALYSES,
                ),
                state_machine_pass_spec(
                    "lower_state_machine",
                    lambda: LowerStateMachine(
                        configured_kind=RouterKind.TABLE,
                        configured_table_provenance=(
                            TableProvenance.INDIRECT_JUMP_TABLE
                        ),
                    ),
                    emulation,
                    default,
                    analyses=LOWER_ANALYSES,
                ),
                state_machine_pass_spec(
                    "cleanup_residual_dispatcher",
                    CleanupResidualDispatcher,
                    no_caps,
                    default,
                    analyses=CLEANUP_ANALYSES,
                ),
            )
        return standard_state_machine_passes()
