"""Hodur family: the unflatten ``Family`` profile for equality-chain state-variable CFF.

:class:`HodurFamily` recognizes the equality-chain (Hodur) dispatcher shape over a
portable ``FlowGraph`` and declares the five-pass pipeline on the shared spine. It
auto-registers via :class:`StateMachineCffFamily` / ``Registrant`` so the scanner
discovers it on load. Hexrays-free (the unflatten passes/analyses are portable); no microcode
patching happens here.

(The former ``HodurUnflatteningProfile`` strategy-ordering policy was retired with the
M2 hodur-cluster sever, llr-ibpi — its only consumer was the deleted ``hodur/profile.py``.)
"""
from __future__ import annotations

from d810.ir.flowgraph import FlowGraph
from d810.passes.pass_pipeline import PassSpec
from d810.analyses.control_flow.dispatcher_kind import DispatcherType
from d810.analyses.control_flow.dispatcher_recovery import (
    build_dispatch_map_any_kind,
    build_state_dispatcher_map_from_flow_graph,
    min_state_constant_from_config,
)
from d810.families.state_machine_cff.base import StateMachineCffFamily
from d810.ir.maturity import IRMaturity
from d810.families.state_machine_cff.pipeline import standard_state_machine_passes

__all__ = ["HodurFamily"]


class HodurFamily(StateMachineCffFamily):
    """State-variable CFF (Hodur) family: detection + pipeline shape. No microcode patching."""

    name = "hodur"

    #: Recover at ``GLOBAL_ANALYZED`` (Hex-Rays ``MMAT_GLBOPT1`` — the historical stage the
    #: goldens are tuned to). Equality-chains that the backend folds into a structured loop
    #: before global analysis (abc_f6/approov_vm) read ``map_rows=0`` here, but listing the
    #: pre-fold ``CALL_MODELED`` as a co-equal stage was REVERTED (ticket llr-a93i): with
    #: per-(ea,maturity) convergence a function recoverable at BOTH stages commits at the
    #: EARLIER one, moving its tuned golden (regressed test_function_ollvm_fla_bcf_sub). The
    #: folded-chain failures are a detect/recover DIVERGENCE (prelim
    #: ``build_dispatch_map_any_kind`` finds them, ``detect``'s equality-chain-only
    #: ``build_state_dispatcher_map_from_flow_graph`` declines), not a maturity gap; the
    #: sound fix is a CALL_MODELED fallback gated on a GLOBAL_ANALYZED miss — follow-on work.
    recovery_maturities = (IRMaturity.GLOBAL_ANALYZED,)

    def detect(self, graph: FlowGraph, capabilities, context=None):
        """Recognize the equality-chain (``CONDITIONAL_CHAIN``) Hodur state machine.

        Claims ONLY the equality-chain dispatcher shape via
        ``build_state_dispatcher_map_from_flow_graph`` — DISJOINT from ``ApproovFamily``'s
        switch/indirect, so at most one profile claims any graph and ``select_family`` is
        order-independent. The match IS the recovered ``StateDispatcherMap`` (truthy), so
        the pipeline only runs where a real equality-chain dispatcher is present.

        The detector honours the project ``min_state_constant`` (threaded as ``context``);
        a project of folded sub-default equality-chains (the F6xxx family) lowers it so
        ``0xF6950``-class states are admitted (ticket llr-a93i). NOTE: routing this through
        ``build_dispatch_map_any_kind`` was tried and reverted — it shifted ollvm's
        GLBOPT1 recovery (moved its golden); the equality-chain detector + the per-project
        threshold is the minimal, golden-stable form.
        """
        if graph is None or not hasattr(graph, "blocks"):
            return None
        # Thread the project config's min_state_constant (select_family passes the rule
        # config as ``context``) so detection uses the SAME threshold as recovery -- a
        # lowered threshold admits sub-default equality-chains (approov ~0xF6A1F).
        min_state_constant = min_state_constant_from_config(context)
        dmap = build_state_dispatcher_map_from_flow_graph(
            graph, min_state_constant=min_state_constant
        )
        if dmap is not None:
            return dmap
        # Fallback (ticket llr-a93i, Slice 5): a NON-identity-selector machine -- XOR-masked
        # ``switch((state^KEY)&MASK)`` -- is invisible to the equality-chain detector (its case
        # labels are sub-threshold byte projections; the compared operand is a computed m_xor
        # tree). A backend EMULATION resolver reconstructs the exact CONDITIONAL_CHAIN table by
        # executing the machine. CONFIG-GATED on the SAME opt-in knob that registers that
        # resolver, so for every other project this method is byte-identical to the pre-Slice-5
        # behaviour -- it does not even make the extra ``build_dispatch_map_any_kind`` call (the
        # one that would otherwise re-run the indirect resolver). Consult the shared front-end
        # ONLY on an equality-chain MISS and claim ONLY its CONDITIONAL_CHAIN result
        # (SWITCH/INDIRECT remain ApproovFamily/TigressFamily's). ollvm/hodur hit the equality
        # detector above and never reach here, so their goldens are unaffected.
        if not (isinstance(context, dict) and context.get("emulation_dispatcher")):
            return None
        fallback = build_dispatch_map_any_kind(graph, min_state_constant=min_state_constant)
        if fallback is not None and fallback.source is DispatcherType.CONDITIONAL_CHAIN:
            return fallback
        return None

    def pipeline_for(self, match, context) -> "tuple[PassSpec, ...]":
        # DRY: the canonical five-pass spine lives in ``pipeline``; this family's
        # equality-chain shape runs it unchanged.
        return standard_state_machine_passes()
