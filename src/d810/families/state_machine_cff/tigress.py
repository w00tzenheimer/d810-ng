"""TigressFamily — the third unflatten profile: switch / indirect-jump CFF on the spine.

A *sibling* of :class:`HodurFamily` / :class:`ApproovFamily`, not a fork: it runs the
SAME portable ``run_pipeline`` driver over the SAME five passes. A *profile* only
customises ``detect`` (which dispatcher *kinds* it claims) and ``pipeline_for`` (the
per-pass capability requirements + router-shape pin).

Tigress emits two CFF shapes this profile owns: a switch-table dispatcher (``SWITCH``)
and a computed indirect-jump dispatcher (``INDIRECT_TABLE``). Detection is scoped over the
SHARED front-end ``build_dispatch_map_any_kind`` so the families never grow parallel
detectors; the claim is then narrowed by ``StateDispatcherMap.router_kind`` to this kind set.

Behaviour-neutral foundation (M3 slice 1, ``llr-11du``): TigressFamily auto-registers (via
:class:`StateMachineCffFamily` / ``Registrant``) AFTER ``ApproovFamily``, so for the live
switch kind Approov is polled first and keeps the claim — Tigress is INERT in golden. There
is NO indirect detector in the front-end chain yet, so ``build_dispatch_map_any_kind`` never
returns ``INDIRECT_TABLE`` live; the indirect / jump-table analysis is slice 2 (``llr-890r``).
The ``INDIRECT_TABLE`` branch of ``pipeline_for`` is therefore structural until that lands.
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
from d810.analyses.control_flow.dispatcher_recovery import build_dispatch_map_any_kind
from d810.families.state_machine_cff.base import StateMachineCffFamily
from d810.ir.maturity import IRMaturity
from d810.families.state_machine_cff.pipeline import standard_state_machine_passes

__all__ = ["TigressFamily"]

# Hard backend requirement: indirect/computed next-state targets need a concrete
# emulator to fold. The string keys in ``CapabilityPolicy.required`` are validated
# against ``backend.capabilities()``; the typed ``EmulationCapability`` is read inside
# the pass via ``ctx.capabilities.optional(...)``.
emulation = CapabilityPolicy(required=frozenset({"live_mba", "emulation"}))

# The dispatcher kinds THIS profile owns. Tigress emits switch-table and computed
# indirect-jump CFF; equality-chain (CONDITION_CHAIN) belongs to HodurFamily.
_TIGRESS_KINDS = frozenset(
    {RouterKind.SWITCH, RouterKind.INDIRECT_TABLE}
)


class TigressFamily(StateMachineCffFamily):
    """Tigress switch / indirect-jump CFF family: detection + pipeline shape. No patching."""

    name = "tigress"

    #: The SWITCH case recovers at ``GLOBAL_ANALYZED`` (Hex-Rays ``MMAT_GLBOPT1``, the
    #: golden-tuned stage), like Approov. The INDIRECT_TABLE case is routed to
    #: ``CALL_MODELED`` (``MMAT_CALLS``) by the rule's structural ``_is_indirect`` gate (its
    #: state writes + accumulation-loop guard are DCE'd by global analysis), so it is NOT
    #: listed here (ticket llr-a93i / llr-m9r4).
    recovery_maturities = (IRMaturity.GLOBAL_ANALYZED,)

    def detect(self, graph, capabilities, context=None):
        """Claim ONLY switch / indirect dispatchers over a portable ``FlowGraph``.

        Reuses the shared front-end ``build_dispatch_map_any_kind`` (so detect and the
        pipeline's pass #1 never disagree on which shapes are supported), then narrows by
        ``StateDispatcherMap.router_kind`` to this profile's kind set. Returns the recovered
        map (truthy) on a match, else ``None``.
        """
        if graph is None or not hasattr(graph, "blocks"):
            return None
        dmap = build_dispatch_map_any_kind(graph)
        if dmap is None or dmap.router_kind not in _TIGRESS_KINDS:
            return None
        return dmap

    def pipeline_for(self, match, context) -> "tuple[PassSpec, ...]":
        """Kind-aware pipeline (mirrors :meth:`ApproovFamily.pipeline_for`).

        ``SWITCH`` runs the standard seeded-fold spine (NO emulation).

        ``INDIRECT_TABLE`` needs the concrete emulator to fold computed targets
        (``EmulationCapability``) and pins ``RouterKind.INDIRECT_TABLE``; structural
        until the indirect resolver + emulation backend land (slice 2, ``llr-890r``).
        """
        if getattr(match, "router_kind", None) == RouterKind.INDIRECT_TABLE:
            return (
                PassSpec("recover_dispatcher", RecoverDispatcher, live_mba, default),
                PassSpec(
                    "recover_state_transitions",
                    RecoverStateTransitions,
                    emulation,
                    default,
                ),
                PassSpec("plan_semantic_regions", PlanSemanticRegions, no_caps, default),
                PassSpec(
                    "lower_state_machine",
                    lambda: LowerStateMachine(configured_kind=RouterKind.INDIRECT_TABLE),
                    emulation,
                    golden,
                ),
                PassSpec(
                    "cleanup_residual_dispatcher",
                    CleanupResidualDispatcher,
                    no_caps,
                    golden,
                ),
            )
        return standard_state_machine_passes()
