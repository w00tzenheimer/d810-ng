"""Portable analysis-result dataclasses.

These are the substrate result types capability Protocols return.
They live below ``d810.capabilities`` so capability return annotations
can reference them without circularity, and they remain IDA-free /
vendor-neutral so future angr / Ghidra / MLIR backends produce the
same shapes.

Slice 9 scope: only ``ConstantFixpointResult`` is lifted here because
it is the result type ``ConstantFixpointCapability.compute()``
currently returns as ``Any``.  Other capability results (e.g. for
``UseDefSafetyCapability``) come in slice 10+ alongside their own
boundary work.
"""

from __future__ import annotations

from dataclasses import dataclass

__all__ = ["ConstantFixpointResult"]


@dataclass(frozen=True, slots=True)
class ConstantFixpointResult:
    """Conservative exact-constant facts at block boundaries.

    Lifted from ``d810.analyses.control_flow.state_machine_analysis.SnapshotConstantFixpointResult``
    so ``ConstantFixpointCapability.compute()`` can tighten its return
    annotation off ``Any``.  Field shapes are unchanged.  The legacy
    name ``SnapshotConstantFixpointResult`` is preserved at its
    original location as a back-compat alias of this class -- the 6
    existing consumer files keep working without migration.

    Attributes:
        in_stk_maps: For each block serial, a map of stack offset to
            exact constant value at the block's entry.  Empty per-
            block map means "no known constants on entry".
        in_reg_maps: For each block serial, a map of register id to
            exact constant value at the block's entry.
        out_stk_maps: Same as ``in_stk_maps`` but at the block's exit.
        out_reg_maps: Same as ``in_reg_maps`` but at the block's exit.
        iterations: Number of fixpoint iterations the analysis ran.
            ``0`` if the analysis returned trivially (e.g. empty CFG).
    """

    in_stk_maps: dict[int, dict[int, int]]
    in_reg_maps: dict[int, dict[int, int]]
    out_stk_maps: dict[int, dict[int, int]]
    out_reg_maps: dict[int, dict[int, int]]
    iterations: int
