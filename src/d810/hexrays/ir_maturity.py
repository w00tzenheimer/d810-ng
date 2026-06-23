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

import json

from d810.ir.maturity import IRMaturity, SnapshotForm, snapshot_form_for_maturity

__all__ = [
    "IDA_TO_IR_MATURITY",
    "IR_TO_IDA_MATURITY",
    "ida_maturity_to_ir",
    "hexrays_maturity_envelope",
    "hexrays_maturity_envelope_json",
    "ir_maturity_to_ida",
    "maturity_name_to_ida",
    "maturity_to_name",
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
IDA_MATURITY_NAMES: "dict[int, str]" = {
    ida_hexrays.MMAT_ZERO: "MMAT_ZERO",
    ida_hexrays.MMAT_GENERATED: "MMAT_GENERATED",
    ida_hexrays.MMAT_PREOPTIMIZED: "MMAT_PREOPTIMIZED",
    ida_hexrays.MMAT_LOCOPT: "MMAT_LOCOPT",
    ida_hexrays.MMAT_CALLS: "MMAT_CALLS",
    ida_hexrays.MMAT_GLBOPT1: "MMAT_GLBOPT1",
    ida_hexrays.MMAT_GLBOPT2: "MMAT_GLBOPT2",
    ida_hexrays.MMAT_GLBOPT3: "MMAT_GLBOPT3",
    ida_hexrays.MMAT_LVARS: "MMAT_LVARS",
}
IDA_MATURITY_BY_NAME: "dict[str, int]" = {
    name: value for value, name in IDA_MATURITY_NAMES.items()
}


def ida_maturity_to_ir(mmat: int) -> IRMaturity:
    """Map an ``ida_hexrays.MMAT_*`` constant to its :class:`IRMaturity`."""
    try:
        return IDA_TO_IR_MATURITY[mmat]
    except KeyError as exc:
        raise ValueError(f"Unsupported Hex-Rays maturity: {mmat!r}") from exc


def maturity_to_name(mmat: int) -> str:
    """Return the canonical ``MMAT_*`` name for a Hex-Rays maturity id."""

    return IDA_MATURITY_NAMES.get(int(mmat), f"MMAT_UNKNOWN_{int(mmat)}")


def maturity_name_to_ida(maturity_name: str) -> int | None:
    """Return the Hex-Rays maturity id for an ``MMAT_*`` name if known."""

    cleaned = str(maturity_name).strip().upper()
    if not cleaned:
        return None
    if not cleaned.startswith("MMAT_"):
        cleaned = f"MMAT_{cleaned}"
    return IDA_MATURITY_BY_NAME.get(cleaned)


def hexrays_maturity_envelope(maturity: int | str) -> dict[str, object | None]:
    """Return the persisted maturity envelope for a Hex-Rays stage.

    The portable fields are semantic; the provider fields are provenance and
    replay/debug context. Unknown provider maturities keep their provider label
    but leave the portable fields unset except for ``SnapshotForm.UNKNOWN``.
    """

    if isinstance(maturity, str):
        provider_id = maturity_name_to_ida(maturity)
        provider_name = (
            maturity_to_name(provider_id)
            if provider_id is not None else str(maturity)
        )
    else:
        provider_id = int(maturity)
        provider_name = maturity_to_name(provider_id)

    ir_maturity: IRMaturity | None
    if provider_id is None:
        ir_maturity = None
    else:
        try:
            ir_maturity = ida_maturity_to_ir(provider_id)
        except ValueError:
            ir_maturity = None

    snapshot_form = (
        snapshot_form_for_maturity(ir_maturity)
        if ir_maturity is not None else SnapshotForm.UNKNOWN
    )
    return {
        "ir": ir_maturity.name if ir_maturity is not None else None,
        "snapshot_form": snapshot_form.name,
        "provider": "hexrays",
        "provider_id": provider_id,
        "provider_name": provider_name,
    }


def hexrays_maturity_envelope_json(maturity: int | str) -> str:
    """Return canonical JSON for :func:`hexrays_maturity_envelope`."""

    return json.dumps(
        hexrays_maturity_envelope(maturity),
        sort_keys=True,
        separators=(",", ":"),
    )


def ir_maturity_to_ida(maturity: IRMaturity) -> int:
    """Map an :class:`IRMaturity` to its ``ida_hexrays.MMAT_*`` constant."""
    try:
        return IR_TO_IDA_MATURITY[maturity]
    except KeyError as exc:
        raise ValueError(f"No Hex-Rays maturity for {maturity!r}") from exc
