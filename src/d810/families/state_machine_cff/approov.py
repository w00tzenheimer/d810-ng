"""ApproovFamily — the second §1a profile: switch/indirect CFF on the shared spine.

This is a *sibling* of :class:`HodurFamily`, not a fork: it runs the SAME portable
``run_pipeline`` driver over the SAME five passes (``RecoverDispatcher`` ->
``RecoverStateTransitions`` -> ``PlanSemanticRegions`` -> ``LowerStateMachine`` ->
``CleanupResidualDispatcher``). A *profile* only customises three things:

* ``detect`` — which dispatcher *kinds* it claims (here: switch-table / indirect-jump),
  scoped over the SHARED front-end ``build_dispatch_map_any_kind`` so the two families
  never grow parallel detectors;
* ``pipeline_for`` — per-pass capability requirements and the router *shape* pin
  (``RouterKind.SWITCH``), via the already-injectable ``LowerStateMachine``;
* the ``"emulation"`` capability requirement — switch/indirect next-state targets are
  folded by a concrete emulator (``EmulationCapability``; M3 backend ``llr-xauw``).

Disambiguation (the resolution of "why is Hodur attacking Approov"): each family OWNS a
``DispatcherType`` set. A switch function is claimed HERE; an equality-chain function by
``HodurFamily``. The shared *front-end* stays shared; only the *claim* is per-family.
Because the claims are DISJOINT (switch/indirect here, equality-chain for Hodur),
``select_family`` is order-independent — no priority/tiebreak needed.

Additive + inert: ApproovFamily auto-registers (via :class:`StateMachineCffFamily` /
``Registrant``) and is enumerated by :func:`d810.families.registry.select_family`, which
is NOT on the live maturity-hook path (the live entry hardcodes ``HodurFamily()``). The
symmetric tightening of ``HodurFamily.detect`` to ``CONDITIONAL_CHAIN``-only is DEFERRED
to the live cutover — doing it now would regress the abc switch case on the live §1a path.
"""
from __future__ import annotations

from d810.passes.pass_pipeline import (
    CapabilityPolicy,
    PassSpec,
    default,
    golden,
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
from d810.capabilities.dispatcher import RouterKind
from d810.analyses.control_flow.dispatcher_kind import DispatcherType
from d810.analyses.control_flow.dispatcher_recovery import build_dispatch_map_any_kind
from d810.families.state_machine_cff.base import StateMachineCffFamily

# Hard backend requirement: indirect/computed next-state targets need a concrete
# emulator to fold. The string keys ``CapabilityPolicy.required`` (validated against
# ``backend.capabilities()``); the typed ``EmulationCapability`` is read inside the pass
# via ``ctx.capabilities.optional(...)`` (portable fallback: ``ReferenceEmulator``).
emulation = CapabilityPolicy(required=frozenset({"live_mba", "emulation"}))

# The dispatcher kinds THIS profile owns. A switch/indirect function is claimed here;
# equality-chain (CONDITIONAL_CHAIN) belongs to HodurFamily.
_APPROOV_KINDS = frozenset({DispatcherType.SWITCH_TABLE, DispatcherType.INDIRECT_JUMP})


class ApproovFamily(StateMachineCffFamily):
    """Switch/indirect CFF (Approov) family: detection + pipeline shape. No microcode patching."""

    name = "approov"

    def detect(self, graph, capabilities, context=None):
        """Claim ONLY switch/indirect dispatchers over a portable ``FlowGraph``.

        Reuses the shared front-end ``build_dispatch_map_any_kind`` (so detect and the
        pipeline's pass #1 never disagree on which shapes are supported), then narrows by
        ``StateDispatcherMap.source`` to this profile's kind set. Returns the recovered
        map (truthy) on a match, else ``None`` so the pipeline only runs where a real
        switch/indirect dispatcher is present.
        """
        if graph is None or not hasattr(graph, "blocks"):
            return None
        dmap = build_dispatch_map_any_kind(graph)
        if dmap is None or dmap.source not in _APPROOV_KINDS:
            return None
        return dmap

    def pipeline_for(self, match, context) -> "tuple[PassSpec, ...]":
        """Same five passes as Hodur, but emulation-gated and switch-router-pinned.

        ``recover_state_transitions`` and ``lower_state_machine`` require ``"emulation"``
        (indirect target folding); ``lower_state_machine`` pins ``RouterKind.SWITCH`` so
        the exact ``state -> handler`` map drives the router regardless of a
        collapsed/absent comparison BST. ``INDIRECT_TABLE`` would instead inject a custom
        ``DispatcherRouterResolver`` (consuming ``EmulationCapability``); the
        ``configured_kind`` pin is the switch-table form.
        """
        return (
            PassSpec("recover_dispatcher", RecoverDispatcher, live_mba, default),
            PassSpec("recover_state_transitions", RecoverStateTransitions, emulation, default),
            PassSpec("plan_semantic_regions", PlanSemanticRegions, no_caps, default),
            PassSpec(
                "lower_state_machine",
                lambda: LowerStateMachine(configured_kind=RouterKind.SWITCH),
                emulation,
                golden,
            ),
            PassSpec("cleanup_residual_dispatcher", CleanupResidualDispatcher, no_caps, golden),
        )
