"""TigressFamily — the third unflatten profile: switch / indirect-jump CFF on the spine.

A *sibling* of :class:`HodurFamily` / :class:`ApproovFamily`, not a fork: it runs the
SAME portable ``run_pipeline`` driver over the SAME five passes. A *profile* only
customises ``detect`` (which table provenances it claims) and ``pipeline_for`` (the
per-pass capability requirements + table-provenance pin).

Tigress emits two CFF shapes this profile owns: a switch-table dispatcher
and a computed indirect-jump dispatcher (``TABLE/indirect_jump_table``). Detection is scoped over the
SHARED front-end ``build_dispatch_map_any_kind`` so the families never grow parallel
detectors; the claim is then narrowed by ``StateDispatcherMap.table_provenance``.

Behaviour-neutral foundation (M3 slice 1, ``llr-11du``): TigressFamily auto-registers (via
:class:`StateMachineCffFamily` / ``Registrant``) AFTER ``ApproovFamily``, so for the live
switch kind Approov is polled first and keeps the claim — Tigress is INERT in golden. There
is NO indirect detector in the front-end chain yet, so ``build_dispatch_map_any_kind`` never
returns ``TABLE/indirect_jump_table`` live; the indirect / jump-table analysis is slice 2 (``llr-890r``).
The ``TABLE/indirect_jump_table`` branch of ``pipeline_for`` is therefore structural until that lands.
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
    standard_state_machine_passes,
)

__all__ = ["TigressFamily"]

# Hard backend requirement: indirect/computed next-state targets need a concrete
# emulator to fold. The string keys in ``CapabilityPolicy.required`` are validated
# against ``backend.capabilities()``; the typed ``EmulationCapability`` is read inside
# the pass via ``ctx.capabilities.optional(...)``.
emulation = CapabilityPolicy(required=frozenset({"live_mba", "emulation"}))

# The dispatcher kinds THIS profile owns. Tigress emits switch-table and computed
# indirect-jump CFF; equality-chain (CONDITION_CHAIN) belongs to HodurFamily.
_TIGRESS_TABLE_PROVENANCES = frozenset({
    TableProvenance.SWITCH,
    TableProvenance.INDIRECT_JUMP_TABLE,
})


class TigressFamily(StateMachineCffFamily):
    """Tigress switch / indirect-jump CFF family: detection + pipeline shape. No patching."""

    name = "tigress"

    #: The switch-table case recovers at ``GLOBAL_ANALYZED`` (Hex-Rays ``MMAT_GLBOPT1``, the
    #: golden-tuned stage), like Approov. The TABLE/indirect_jump_table case is routed to
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
        if (
            dmap is None
            or dmap.router_kind is not RouterKind.TABLE
            or dmap.table_provenance not in _TIGRESS_TABLE_PROVENANCES
        ):
            return None
        return dmap

    def pipeline_for(self, match, context) -> "tuple[PassSpec, ...]":
        """Kind-aware pipeline (mirrors :meth:`ApproovFamily.pipeline_for`).

        ``TABLE`` with switch provenance runs the standard seeded-fold spine
        (NO emulation).

        ``TABLE/indirect_jump_table`` needs the concrete emulator to fold computed targets
        (``EmulationCapability``) and pins ``RouterKind.TABLE`` plus
        ``TableProvenance.INDIRECT_JUMP_TABLE``; structural
        until the indirect resolver + emulation backend land (slice 2, ``llr-890r``).
        """
        if (
            getattr(match, "router_kind", None) is RouterKind.TABLE
            and getattr(match, "table_provenance", None)
            is TableProvenance.INDIRECT_JUMP_TABLE
        ):
            return (
                PassSpec(
                    "recover_dispatcher",
                    RecoverDispatcher,
                    live_mba,
                    default,
                    analyses=DISPATCHER_ANALYSES,
                ),
                PassSpec(
                    "recover_state_transitions",
                    RecoverStateTransitions,
                    emulation,
                    default,
                    analyses=TRANSITION_ANALYSES,
                ),
                PassSpec(
                    "plan_semantic_regions",
                    PlanSemanticRegions,
                    no_caps,
                    default,
                    analyses=REGION_ANALYSES,
                ),
                PassSpec(
                    "lower_state_machine",
                    lambda: LowerStateMachine(
                        configured_kind=RouterKind.TABLE,
                        configured_table_provenance=(
                            TableProvenance.INDIRECT_JUMP_TABLE
                        ),
                    ),
                    emulation,
                    golden,
                    analyses=LOWER_ANALYSES,
                ),
                PassSpec(
                    "cleanup_residual_dispatcher",
                    CleanupResidualDispatcher,
                    no_caps,
                    golden,
                    analyses=CLEANUP_ANALYSES,
                ),
            )
        return standard_state_machine_passes()
