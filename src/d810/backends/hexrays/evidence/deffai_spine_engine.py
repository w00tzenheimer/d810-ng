"""DEFFAI ``SpineEngine`` adapter for the reduced product (ticket llr-iy9i).

Wraps the portable DEFFAI k-switch fixpoint (``deffai.analyze_kswitch`` +
``build_ccm`` / ``build_ctg``) behind the orchestrator's ``SpineEngine`` Protocol:

    recover(graph, anchors, caps, *, k) -> SpineResult | None

A :class:`SpineResult` exposes ``.machine`` (the SOUND_OVERAPPROX
:class:`RecoveredMachine` projected from the CCM/CTG), ``.floor_for(src_state,
context)`` (the per-cell ``σ#_in`` projection -> ``AbstractEvidence``, the §7 (b)
gate input), and ``.top_density`` (the k-escalation signal).

CONSERVATIVE BY CONTRACT: the CTG→``RecoveredMachine`` projection
(``to_recovered_machine``) is the P3 wiring layer that is still being proven
(deffai/__init__.py notes it is intentionally absent), so this adapter ABSTAINS
(``recover`` returns ``None``) until that projection lands and is verified.  An
abstaining spine makes the orchestrator fall to the concolic + static §1a
candidates -- so wiring this in is always safe (no regression), and flipping it on
is a localized change here once the projection is trusted.

The live ``mba`` is bound for the block evaluator the fixpoint needs; the fixpoint
itself is portable.
"""
from __future__ import annotations

from dataclasses import dataclass

import ida_hexrays

from d810.analyses.control_flow.machine_recovery_engine import DispatcherAnchors
from d810.analyses.control_flow.dispatcher_recovery import MIN_STATE_CONSTANT
from d810.core.logging import getLogger
from d810.ir.flowgraph import FlowGraph

logger = getLogger("D810.backends.deffai_spine_engine")

__all__ = ["DeffaiSpineEngine"]


@dataclass
class DeffaiSpineEngine:
    """The DEFFAI AI spine behind the orchestrator's ``SpineEngine`` Protocol.

    ``mba`` is the live microcode (for the block evaluator); ``min_state_constant``
    threads the detection threshold.  ``name`` identifies the engine in provenance.
    """

    mba: ida_hexrays.mba_t
    min_state_constant: int = MIN_STATE_CONSTANT
    name: str = "deffai_spine"

    def recover(
        self,
        graph: FlowGraph,
        anchors: DispatcherAnchors,
        caps: object | None = None,
        *,
        k: int = 2,
    ):
        """Run the k-switch fixpoint and project to a :class:`SpineResult`.

        Returns ``None`` (abstain) while the CTG→``RecoveredMachine`` projection is
        unproven -- the orchestrator then composes over the concolic + static
        candidates, which is the byte-equivalent §1a + old-engine path.
        """
        # P3 projection (CTG -> RecoveredMachine + floor_for) pending verification.
        # Abstain so the reduced product degrades to concolic + static (no regression).
        return None
