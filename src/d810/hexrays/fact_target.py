"Hex-Rays adapters for portable fact collectors.\n\n``mba_to_fact_target`` adapts a live ``mba_t`` into the portable fact target\nthat the preanalysis fact collectors iterate.  It delegates to\n:func:`d810.hexrays.mutation.ir_translator.lift`, the SAME lifter the pre-D810\n``FLOWGRAPH_READY`` path uses, so post-D810 capture hands collectors a canonical\n:class:`~d810.ir.flowgraph.FlowGraph` whose blocks carry ``insn_snapshots``.\n\nWhy a real ``FlowGraph`` (S10, ticket llr-3b41): production fact collectors are\ncanonical-only (S11) -- they consume a meta-rich\n:class:`~d810.ir.flowgraph.BlockSnapshot` through the canonical\n``InstructionProjection.from_block`` projection, with no meta-less fallback.\nThis adapter previously returned a flat ``SimpleNamespace`` (``serial`` + flat\n``instructions`` only, NO ``insn_snapshots``), which the canonical projection\ncannot consume.  Returning ``lift(mba)`` puts post-D810 capture on the canonical\nbranch -- byte-identical to the pre-D810 path's own target shape.\n\nEMBRACE (intended, strictly-better recovery): post-D810 facts now recover the\noperand structure the flat path dropped -- ``operation`` (the canonical\n``ValueOpKind`` derived from the lifted instruction kind), full operand\n``address``/``stkoff`` provenance, and nested ``mop_d`` sub-operation structure.\nStack-offset and constant-value identity are preserved (the lifter and the flat\nadapter read the same ``mop`` fields); the canonical projection adds detail, it\nnever drops or alters those identities.\n"

from __future__ import annotations

from d810.core.typing import Any
from d810.hexrays.mutation.ir_translator import lift as _lift_mba_to_flowgraph


def mba_to_fact_target(mba: Any) -> Any:
    """Adapt a live ``mba_t`` to the canonical portable fact target.

    Returns the same :class:`~d810.ir.flowgraph.FlowGraph` the pre-D810
    ``FLOWGRAPH_READY`` path produces, so fact collectors route post-D810
    capture through their canonical ``InstructionProjection.from_block`` branch
    (meta-rich); there is no meta-less fallback.
    """
    return _lift_mba_to_flowgraph(mba)
