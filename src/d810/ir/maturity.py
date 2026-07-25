"""Backend-agnostic IR maturity levels (ticket llr-a93i).

A *maturity* names HOW MUCH analysis the decompiler IR has had — independent of which
backend produced it. Portable analyses and unflatten profiles declare the maturity
their pattern is recoverable at in these terms, so the same declaration applies to any
IR backend; an IDA / Hex-Rays *adapter*
(:mod:`d810.hexrays.ir_maturity`) maps these to ``ida_hexrays.MMAT_*`` constants. The
mapping for each backend is recorded per member below.

Portable: pure ``enum`` — NO ``ida_*`` import (this module is portable-core; the live
mapping lives in the vendor adapter).
"""

from __future__ import annotations

import json
from collections.abc import Mapping
from dataclasses import dataclass
from enum import Enum
from types import MappingProxyType

__all__ = [
    "EARLY_FACT_COLLECTION_IR_MATURITIES",
    "IRMaturity",
    "IR_MATURITY_ORDER",
    "MaturityEnvelope",
    "SnapshotForm",
    "IR_MATURITY_TO_SNAPSHOT_FORM",
    "LOCAL_FACT_COLLECTION_IR_MATURITIES",
    "ir_maturity_rank",
    "snapshot_form_for_maturity",
]


class IRMaturity(str, Enum):
    """Backend-agnostic decompiler IR maturity levels (ordered lift → pseudocode)."""

    # Hex-Rays: MMAT_GENERATED | Ghidra: raw instruction P-code | Binary Ninja: LLIL
    # Meaning: direct lift from machine code.
    LIFTED = "ir.lifted"
    # Hex-Rays: MMAT_PREOPTIMIZED | Ghidra: early/canonicalized P-code
    # Binary Ninja: LLIL after canonical cleanup | Meaning: instruction semantics normalized.
    CANONICAL = "ir.canonical"
    # Hex-Rays: MMAT_LOCOPT | Ghidra: locally simplified decompiler P-code | Binary Ninja: MLIL
    # Meaning: local propagation, temp folding, expression cleanup.
    LOCAL_OPTIMIZED = "ir.local.optimized"
    # Hex-Rays: MMAT_CALLS | Ghidra: High P-code after call analysis
    # Binary Ninja: MLIL with call/prototype recovery
    # Meaning: calls, arguments, returns, and prototypes modeled.
    CALL_MODELED = "ir.call.modeled"
    # Hex-Rays: MMAT_GLBOPT1 | Ghidra: HighFunction after global dataflow | Binary Ninja: MLIL SSA
    # Meaning: global def-use/dataflow facts are available.
    GLOBAL_ANALYZED = "ir.global.analyzed"
    # Hex-Rays: MMAT_GLBOPT2 | Ghidra: heavily simplified HighFunction
    # Binary Ninja: MLIL SSA / early HLIL | Meaning: stronger global simplification and DCE.
    GLOBAL_OPTIMIZED = "ir.global.optimized"
    # Hex-Rays: MMAT_GLBOPT3 | Ghidra: final High P-code before C emission | Binary Ninja: HLIL
    # Meaning: structured high-level control flow.
    STRUCTURED = "ir.structured"
    # Hex-Rays: MMAT_LVARS | Ghidra: recovered local-variable model
    # Binary Ninja: HLIL with variable recovery
    # Meaning: pseudocode-ready local variable abstraction.
    VARIABLE_RECOVERED = "ir.variable.recovered"


class SnapshotForm(str, Enum):
    """Coarse, backend-neutral form of a lifted ``FlowGraph`` snapshot.

    ``IRMaturity`` is the fine-grained ordered pass-scheduling vocabulary.
    ``SnapshotForm`` is the lossy derived classification stored in snapshot
    metadata for read-only analyses that only need to ask which broad shape of
    IR they are observing.
    """

    UNKNOWN = "unknown"
    RAW_IR = "raw_ir"
    NORMALIZED_IR = "normalized_ir"
    OPTIMIZED_IR = "optimized_ir"
    LVAR_RECOVERED = "lvar_recovered"
    FINAL_PRE_RENDER = "final_pre_render"


@dataclass(frozen=True)
class MaturityEnvelope:
    """Portable maturity semantics plus provider provenance.

    ``IRMaturity`` and ``SnapshotForm`` are the portable scheduling/form
    vocabulary.  ``provider_*`` fields are boundary metadata used for replay,
    persisted diagnostics, and native adapter round-trips.
    """

    ir: IRMaturity | None
    snapshot_form: SnapshotForm = SnapshotForm.UNKNOWN
    provider: str = ""
    provider_id: int | None = None
    provider_name: str | None = None

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
    def _load_ir(cls, value: object) -> IRMaturity | None:
        if value is None or isinstance(value, IRMaturity):
            return value
        text = str(value)
        try:
            return IRMaturity[text]
        except KeyError:
            return IRMaturity(text)

    @classmethod
    def _load_snapshot_form(cls, value: object) -> SnapshotForm:
        if value is None:
            return SnapshotForm.UNKNOWN
        if isinstance(value, SnapshotForm):
            return value
        text = str(value)
        try:
            return SnapshotForm[text]
        except KeyError:
            return SnapshotForm(text)

    @classmethod
    def load(
        cls, record: Mapping[str, object] | "MaturityEnvelope"
    ) -> "MaturityEnvelope":
        if isinstance(record, cls):
            return record
        provider_id_value = record.get("provider_id")
        provider_id = int(provider_id_value) if provider_id_value is not None else None
        provider_value = record.get("provider")
        provider_name_value = record.get("provider_name")
        return cls(
            ir=cls._load_ir(record.get("ir")),
            snapshot_form=cls._load_snapshot_form(record.get("snapshot_form")),
            provider=str(provider_value) if provider_value is not None else "",
            provider_id=provider_id,
            provider_name=(
                str(provider_name_value) if provider_name_value is not None else None
            ),
        )

    @classmethod
    def loads(cls, payload: str | bytes) -> "MaturityEnvelope":
        record = json.loads(payload)
        if not isinstance(record, Mapping):
            raise ValueError("MaturityEnvelope JSON must be an object")
        return cls.load(record)


IR_MATURITY_ORDER = (
    IRMaturity.LIFTED,
    IRMaturity.CANONICAL,
    IRMaturity.LOCAL_OPTIMIZED,
    IRMaturity.CALL_MODELED,
    IRMaturity.GLOBAL_ANALYZED,
    IRMaturity.GLOBAL_OPTIMIZED,
    IRMaturity.STRUCTURED,
    IRMaturity.VARIABLE_RECOVERED,
)
EARLY_FACT_COLLECTION_IR_MATURITIES = frozenset(
    {
        IRMaturity.CANONICAL,
        IRMaturity.LOCAL_OPTIMIZED,
        IRMaturity.CALL_MODELED,
        IRMaturity.GLOBAL_ANALYZED,
    }
)
LOCAL_FACT_COLLECTION_IR_MATURITIES = frozenset(
    {
        IRMaturity.CANONICAL,
        IRMaturity.LOCAL_OPTIMIZED,
    }
)

IR_MATURITY_TO_SNAPSHOT_FORM = MappingProxyType(
    {
        IRMaturity.LIFTED: SnapshotForm.RAW_IR,
        IRMaturity.CANONICAL: SnapshotForm.NORMALIZED_IR,
        IRMaturity.LOCAL_OPTIMIZED: SnapshotForm.OPTIMIZED_IR,
        IRMaturity.CALL_MODELED: SnapshotForm.OPTIMIZED_IR,
        IRMaturity.GLOBAL_ANALYZED: SnapshotForm.OPTIMIZED_IR,
        IRMaturity.GLOBAL_OPTIMIZED: SnapshotForm.OPTIMIZED_IR,
        IRMaturity.STRUCTURED: SnapshotForm.FINAL_PRE_RENDER,
        IRMaturity.VARIABLE_RECOVERED: SnapshotForm.LVAR_RECOVERED,
    }
)


def ir_maturity_rank(maturity: IRMaturity) -> int:
    """Return the canonical ordering rank for a portable IR maturity."""

    try:
        return IR_MATURITY_ORDER.index(maturity)
    except ValueError as exc:
        raise ValueError(f"No IRMaturity rank for {maturity!r}") from exc


def snapshot_form_for_maturity(maturity: IRMaturity) -> SnapshotForm:
    """Return the coarse snapshot form for one fine-grained IR maturity."""

    try:
        return IR_MATURITY_TO_SNAPSHOT_FORM[maturity]
    except KeyError as exc:
        raise ValueError(f"No SnapshotForm mapping for {maturity!r}") from exc
