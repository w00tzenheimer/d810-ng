"""IDA-free fact-observation model for portable value-flow facts.

Relocated from ``d810.recon.facts.model`` (Landing Sequence LS7, Commit 0) so
portable ``d810.analyses`` code can depend on the fact-observation type without
an upward import into ``d810.recon`` -- e.g. value-flow fact projection, once it
moves under ``analyses``, would otherwise form an ``analyses -> recon`` edge
(UPWARD-FATAL).  ``d810.recon.facts.model`` re-exports these names for backward
compatibility; the lifecycle types that depend on ``FactStatus`` (FactMapping,
ValidatedFactView, ...) stay in that module.

Portable-core layer: no live IDA / Hex-Rays imports, no vendor mutation surfaces.
"""
from __future__ import annotations

import json
from dataclasses import dataclass, field

from d810.core.typing import Any, Mapping

JsonMapping = Mapping[str, Any]

__all__ = ["FactObservation", "JsonMapping", "canonical_json"]


def canonical_json(value: Any) -> str:
    """Serialize fact payload data deterministically."""
    return json.dumps(value, sort_keys=True, separators=(",", ":"))


def _json_mapping(value: JsonMapping | None) -> dict[str, Any]:
    return dict(value or {})


def _string_tuple(value: tuple[str, ...] | list[str] | None) -> tuple[str, ...]:
    return tuple(str(item) for item in (value or ()))


def _require_text(field_name: str, value: str) -> None:
    if not isinstance(value, str) or not value:
        raise ValueError(f"{field_name} must be a non-empty string")


def _validate_confidence(value: float) -> float:
    confidence = float(value)
    if not 0.0 <= confidence <= 1.0:
        raise ValueError("confidence must be between 0.0 and 1.0")
    return confidence


@dataclass(frozen=True)
class FactObservation:
    """One collector-observed semantic fact at one maturity."""

    fact_id: str
    kind: str
    semantic_key: str
    maturity: str
    phase: str
    confidence: float
    source_block: int | None = None
    source_ea: int | None = None
    block_fingerprint: str | None = None
    mop_signature: str | None = None
    payload: JsonMapping = field(default_factory=dict)
    evidence: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        for field_name in ("fact_id", "kind", "semantic_key", "maturity", "phase"):
            _require_text(field_name, getattr(self, field_name))
        object.__setattr__(self, "confidence", _validate_confidence(self.confidence))
        object.__setattr__(self, "payload", _json_mapping(self.payload))
        object.__setattr__(self, "evidence", _string_tuple(self.evidence))

    @property
    def payload_json(self) -> str:
        return canonical_json(self.payload)

    @property
    def evidence_json(self) -> str:
        return canonical_json(list(self.evidence))

    def to_json_dict(self) -> dict[str, Any]:
        return {
            "fact_id": self.fact_id,
            "kind": self.kind,
            "semantic_key": self.semantic_key,
            "maturity": self.maturity,
            "phase": self.phase,
            "confidence": self.confidence,
            "source_block": self.source_block,
            "source_ea": self.source_ea,
            "block_fingerprint": self.block_fingerprint,
            "mop_signature": self.mop_signature,
            "payload": dict(self.payload),
            "evidence": list(self.evidence),
        }

    @classmethod
    def from_json_dict(cls, data: JsonMapping) -> "FactObservation":
        return cls(
            fact_id=str(data["fact_id"]),
            kind=str(data["kind"]),
            semantic_key=str(data["semantic_key"]),
            maturity=str(data["maturity"]),
            phase=str(data["phase"]),
            confidence=float(data["confidence"]),
            source_block=data.get("source_block"),  # type: ignore[arg-type]
            source_ea=data.get("source_ea"),  # type: ignore[arg-type]
            block_fingerprint=data.get("block_fingerprint"),  # type: ignore[arg-type]
            mop_signature=data.get("mop_signature"),  # type: ignore[arg-type]
            payload=data.get("payload") or {},
            evidence=data.get("evidence") or (),
        )
