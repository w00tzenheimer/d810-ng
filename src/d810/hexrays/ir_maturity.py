"""IDA / Hex-Rays adapter for the backend-agnostic :class:`IRMaturity` (ticket llr-a93i).

Maps ``ida_hexrays.MMAT_*`` maturity constants to/from the portable
:class:`d810.ir.maturity.IRMaturity` levels, so portable profiles can declare the
maturity their pattern is recoverable at WITHOUT importing the IDA SDK, and the
IDA-bound rule resolves the declaration here.

Import this only inside an IDA Python / Hex-Rays runtime — it touches ``ida_hexrays``.
The portable enum (:mod:`d810.ir.maturity`) stays independent of the SDK.
"""
from __future__ import annotations

import json
from collections.abc import Mapping
from dataclasses import dataclass
from enum import Enum

import ida_hexrays

from d810.core.typing import Any
from d810.ir.maturity import IRMaturity, SnapshotForm, snapshot_form_for_maturity

__all__ = [
    "HexRaysMaturity",
    "HexRaysMaturityEnvelope",
    "IDA_TO_IR_MATURITY",
    "IR_TO_IDA_MATURITY",
    "ida_maturity_to_ir",
    "hexrays_maturity_envelope",
    "hexrays_maturity_envelope_json",
    "ir_maturity_to_ida",
    "maturity_name_to_ida",
    "maturity_to_name",
]


class HexRaysMaturity(Enum):
    """Native Hex-Rays maturity stages with stable ``MMAT_*`` names."""

    MMAT_ZERO = ida_hexrays.MMAT_ZERO
    MMAT_GENERATED = ida_hexrays.MMAT_GENERATED
    MMAT_PREOPTIMIZED = ida_hexrays.MMAT_PREOPTIMIZED
    MMAT_LOCOPT = ida_hexrays.MMAT_LOCOPT
    MMAT_CALLS = ida_hexrays.MMAT_CALLS
    MMAT_GLBOPT1 = ida_hexrays.MMAT_GLBOPT1
    MMAT_GLBOPT2 = ida_hexrays.MMAT_GLBOPT2
    MMAT_GLBOPT3 = ida_hexrays.MMAT_GLBOPT3
    MMAT_LVARS = ida_hexrays.MMAT_LVARS

    @classmethod
    def from_id(cls, maturity_id: int) -> "HexRaysMaturity | None":
        """Return the enum member for a native maturity id, if known."""

        try:
            return cls(int(maturity_id))
        except ValueError:
            return None

    @classmethod
    def from_name(cls, maturity_name: str) -> "HexRaysMaturity | None":
        """Return the enum member for an ``MMAT_*`` name, if known."""

        cleaned = str(maturity_name).strip().upper()
        if not cleaned:
            return None
        if not cleaned.startswith("MMAT_"):
            cleaned = f"MMAT_{cleaned}"
        return cls.__members__.get(cleaned)


HEX_RAYS_TO_IR_MATURITY: "dict[HexRaysMaturity, IRMaturity]" = {
    HexRaysMaturity.MMAT_ZERO: IRMaturity.LIFTED,
    HexRaysMaturity.MMAT_GENERATED: IRMaturity.LIFTED,
    HexRaysMaturity.MMAT_PREOPTIMIZED: IRMaturity.CANONICAL,
    HexRaysMaturity.MMAT_LOCOPT: IRMaturity.LOCAL_OPTIMIZED,
    HexRaysMaturity.MMAT_CALLS: IRMaturity.CALL_MODELED,
    HexRaysMaturity.MMAT_GLBOPT1: IRMaturity.GLOBAL_ANALYZED,
    HexRaysMaturity.MMAT_GLBOPT2: IRMaturity.GLOBAL_OPTIMIZED,
    HexRaysMaturity.MMAT_GLBOPT3: IRMaturity.STRUCTURED,
    HexRaysMaturity.MMAT_LVARS: IRMaturity.VARIABLE_RECOVERED,
}
IDA_TO_IR_MATURITY: "dict[int, IRMaturity]" = {
    maturity.value: ir_maturity
    for maturity, ir_maturity in HEX_RAYS_TO_IR_MATURITY.items()
}
IR_TO_IDA_MATURITY: "dict[IRMaturity, int]" = {
    v: k for k, v in IDA_TO_IR_MATURITY.items()
}


@dataclass(frozen=True)
class HexRaysMaturityEnvelope:
    """Portable maturity semantics plus native Hex-Rays provenance."""

    ir: IRMaturity | None
    snapshot_form: SnapshotForm
    provider_id: int | None
    provider_name: str
    provider: str = "hexrays"

    def to_dict(self) -> dict[str, object | None]:
        return {
            "ir": self.ir.name if self.ir is not None else None,
            "snapshot_form": self.snapshot_form.name,
            "provider": self.provider,
            "provider_id": self.provider_id,
            "provider_name": self.provider_name,
        }

    def to_record(self) -> dict[str, object | None]:
        return self.to_dict()

    def dump(self) -> dict[str, object | None]:
        return self.to_dict()

    def dumps(self) -> str:
        return json.dumps(
            self.to_dict(),
            sort_keys=True,
            separators=(",", ":"),
        )

    @classmethod
    def load(
        cls,
        record: Mapping[str, Any],
    ) -> "HexRaysMaturityEnvelope":
        if isinstance(record, cls):
            return record
        ir_value = record.get("ir")
        ir_maturity = (
            IRMaturity[str(ir_value)]
            if ir_value is not None else None
        )
        snapshot_form_value = record.get("snapshot_form")
        snapshot_form = (
            SnapshotForm[str(snapshot_form_value)]
            if snapshot_form_value is not None else SnapshotForm.UNKNOWN
        )
        provider_id_value = record.get("provider_id")
        provider_id = (
            int(provider_id_value)
            if provider_id_value is not None else None
        )
        provider_name_value = record.get("provider_name")
        provider_name = (
            str(provider_name_value)
            if provider_name_value is not None
            else (
                maturity_to_name(provider_id)
                if provider_id is not None else "UNKNOWN"
            )
        )
        provider_value = record.get("provider")
        provider = (
            str(provider_value) if provider_value is not None else "hexrays"
        )
        return cls(
            ir=ir_maturity,
            snapshot_form=snapshot_form,
            provider_id=provider_id,
            provider_name=provider_name,
            provider=provider,
        )

    @classmethod
    def loads(cls, payload: str | bytes) -> "HexRaysMaturityEnvelope":
        record = json.loads(payload)
        if not isinstance(record, Mapping):
            raise ValueError("Hex-Rays maturity envelope JSON must be an object")
        return cls.load(record)


def ida_maturity_to_ir(mmat: int) -> IRMaturity:
    """Map an ``ida_hexrays.MMAT_*`` constant to its :class:`IRMaturity`."""

    maturity = HexRaysMaturity.from_id(int(mmat))
    if maturity is None:
        raise ValueError(f"Unsupported Hex-Rays maturity: {mmat!r}")
    return HEX_RAYS_TO_IR_MATURITY[maturity]


def maturity_to_name(mmat: int) -> str:
    """Return the canonical ``MMAT_*`` name for a Hex-Rays maturity id."""

    maturity = HexRaysMaturity.from_id(int(mmat))
    if maturity is None:
        return f"MMAT_UNKNOWN_{int(mmat)}"
    return maturity.name


def maturity_name_to_ida(maturity_name: str) -> int | None:
    """Return the Hex-Rays maturity id for an ``MMAT_*`` name if known."""

    maturity = HexRaysMaturity.from_name(maturity_name)
    if maturity is None:
        return None
    return int(maturity.value)


def hexrays_maturity_envelope(
    maturity: int | str,
) -> HexRaysMaturityEnvelope:
    """Return the persisted maturity envelope for a Hex-Rays stage.

    The portable fields are semantic; the provider fields are provenance and
    replay/debug context. Unknown provider maturities keep their provider label
    but leave the portable fields unset except for ``SnapshotForm.UNKNOWN``.
    """

    if isinstance(maturity, str):
        provider_stage = HexRaysMaturity.from_name(maturity)
        provider_id = (
            int(provider_stage.value) if provider_stage is not None else None
        )
        provider_name = (
            provider_stage.name
            if provider_stage is not None else str(maturity)
        )
    else:
        provider_stage = HexRaysMaturity.from_id(int(maturity))
        provider_id = int(maturity)
        provider_name = (
            provider_stage.name
            if provider_stage is not None else maturity_to_name(provider_id)
        )

    ir_maturity: IRMaturity | None
    if provider_stage is None:
        ir_maturity = None
    else:
        ir_maturity = HEX_RAYS_TO_IR_MATURITY[provider_stage]

    snapshot_form = (
        snapshot_form_for_maturity(ir_maturity)
        if ir_maturity is not None else SnapshotForm.UNKNOWN
    )
    return HexRaysMaturityEnvelope(
        ir=ir_maturity,
        snapshot_form=snapshot_form,
        provider_id=provider_id,
        provider_name=provider_name,
    )


def hexrays_maturity_envelope_json(maturity: int | str) -> str:
    """Return canonical JSON for :func:`hexrays_maturity_envelope`."""

    return hexrays_maturity_envelope(maturity).dumps()


def ir_maturity_to_ida(maturity: IRMaturity) -> int:
    """Map an :class:`IRMaturity` to its ``ida_hexrays.MMAT_*`` constant."""
    try:
        return IR_TO_IDA_MATURITY[maturity]
    except KeyError as exc:
        raise ValueError(f"No Hex-Rays maturity for {maturity!r}") from exc
