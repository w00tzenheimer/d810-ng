"""Hex-Rays adapters for portable fact collectors.

``mba_to_fact_target`` adapts a live ``mba_t`` into the portable fact target
that the recon fact collectors iterate.  It delegates to
:func:`d810.hexrays.mutation.ir_translator.lift`, the SAME lifter the pre-D810
``FLOWGRAPH_READY`` path uses, so post-D810 capture hands collectors a canonical
:class:`~d810.ir.flowgraph.FlowGraph` whose blocks carry ``insn_snapshots``.

Why a real ``FlowGraph`` (S10, ticket llr-3b41): every fact collector branches on
``getattr(blk, "insn_snapshots", None) is not None`` -- a meta-rich
:class:`~d810.ir.flowgraph.BlockSnapshot` routes through the canonical
``InstructionProjection.from_block`` projection; a meta-less block falls back to
the flat legacy ``_InstructionView`` path.  This adapter previously returned a
flat ``SimpleNamespace`` (``serial`` + flat ``instructions`` only, NO
``insn_snapshots``), so the post-D810 path was the LONE production source still
exercising the meta-less fallback.  Returning ``lift(mba)`` puts post-D810
capture on the canonical branch -- byte-identical to the pre-D810 path's own
target shape.

EMBRACE (intended, strictly-better recovery): post-D810 facts now recover the
operand structure the flat path dropped -- ``operation`` (the canonical
``ValueOpKind`` derived from the lifted instruction kind), full operand
``address``/``stkoff`` provenance, and nested ``mop_d`` sub-operation structure.
Stack-offset and constant-value identity are preserved (the lifter and the flat
adapter read the same ``mop`` fields); the canonical projection adds detail, it
never drops or alters those identities.
"""
from __future__ import annotations

from d810.core.typing import Any
from d810.hexrays.mutation.ir_translator import lift as _lift_mba_to_flowgraph


def mba_to_fact_target(mba: Any) -> Any:
    """Adapt a live ``mba_t`` to the canonical portable fact target.

    Returns the same :class:`~d810.ir.flowgraph.FlowGraph` the pre-D810
    ``FLOWGRAPH_READY`` path produces, so fact collectors route post-D810
    capture through their canonical ``InstructionProjection.from_block`` branch
    (meta-rich) instead of the flat meta-less ``_InstructionView`` fallback.
    """
    return _lift_mba_to_flowgraph(mba)
