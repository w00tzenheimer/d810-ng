"""IDA / Hex-Rays adapter for the backend-agnostic :class:`IRMaturity` (ticket llr-a93i).

Maps ``ida_hexrays.MMAT_*`` maturity constants to/from the portable
:class:`d810.ir.maturity.IRMaturity` levels, so portable profiles can declare the
maturity their pattern is recoverable at WITHOUT importing the IDA SDK, and the
IDA-bound rule resolves the declaration here.

Import this only inside an IDA Python / Hex-Rays runtime — it touches ``ida_hexrays``.
The portable enum (:mod:`d810.ir.maturity`) stays independent of the SDK.
"""
from __future__ import annotations

import ida_hexrays

from d810.ir.maturity import IRMaturity

__all__ = [
    "IDA_TO_IR_MATURITY",
    "IR_TO_IDA_MATURITY",
    "ida_maturity_to_ir",
    "ir_maturity_to_ida",
]

IDA_TO_IR_MATURITY: "dict[int, IRMaturity]" = {
    ida_hexrays.MMAT_ZERO: IRMaturity.LIFTED,
    ida_hexrays.MMAT_GENERATED: IRMaturity.LIFTED,
    ida_hexrays.MMAT_PREOPTIMIZED: IRMaturity.CANONICAL,
    ida_hexrays.MMAT_LOCOPT: IRMaturity.LOCAL_OPTIMIZED,
    ida_hexrays.MMAT_CALLS: IRMaturity.CALL_MODELED,
    ida_hexrays.MMAT_GLBOPT1: IRMaturity.GLOBAL_ANALYZED,
    ida_hexrays.MMAT_GLBOPT2: IRMaturity.GLOBAL_OPTIMIZED,
    ida_hexrays.MMAT_GLBOPT3: IRMaturity.STRUCTURED,
    ida_hexrays.MMAT_LVARS: IRMaturity.VARIABLE_RECOVERED,
}
IR_TO_IDA_MATURITY: "dict[IRMaturity, int]" = {
    v: k for k, v in IDA_TO_IR_MATURITY.items()
}


def ida_maturity_to_ir(mmat: int) -> IRMaturity:
    """Map an ``ida_hexrays.MMAT_*`` constant to its :class:`IRMaturity`."""
    try:
        return IDA_TO_IR_MATURITY[mmat]
    except KeyError as exc:
        raise ValueError(f"Unsupported Hex-Rays maturity: {mmat!r}") from exc


def ir_maturity_to_ida(maturity: IRMaturity) -> int:
    """Map an :class:`IRMaturity` to its ``ida_hexrays.MMAT_*`` constant."""
    try:
        return IR_TO_IDA_MATURITY[maturity]
    except KeyError as exc:
        raise ValueError(f"No Hex-Rays maturity for {maturity!r}") from exc
