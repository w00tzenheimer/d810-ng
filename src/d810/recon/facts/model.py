"""IDA-free model objects for maturity-lifecycle facts."""
from __future__ import annotations

import json
from dataclasses import dataclass, field, replace
from enum import Enum

from d810.core.typing import Any, Mapping

JsonMapping = Mapping[str, Any]


class FactStatus(str, Enum):
    """Lifecycle status for a fact as it moves between maturities."""

    ACTIVE = "ACTIVE"
    REMAPPED = "REMAPPED"
    STALE = "STALE"
    CONTRADICTED = "CONTRADICTED"
    SUPERSEDED = "SUPERSEDED"
    IDENTITY_LOST = "IDENTITY_LOST"
    OPTIMIZATION_FOLDED = "OPTIMIZATION_FOLDED"
    UNKNOWN = "UNKNOWN"


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


@dataclass(frozen=True)
class FactMapping:
    """Relationship between a previously observed fact and a later maturity."""

    source_fact_id: str
    source_maturity: str
    target_maturity: str
    status: FactStatus
    confidence: float
    target_fact_id: str | None = None
    target_block: int | None = None
    target_ea: int | None = None
    target_mop_signature: str | None = None
    reason: str | None = None
    payload: JsonMapping = field(default_factory=dict)

    def __post_init__(self) -> None:
        for field_name in ("source_fact_id", "source_maturity", "target_maturity"):
            _require_text(field_name, getattr(self, field_name))
        status = self.status if isinstance(self.status, FactStatus) else FactStatus(str(self.status))
        object.__setattr__(self, "status", status)
        object.__setattr__(self, "confidence", _validate_confidence(self.confidence))
        object.__setattr__(self, "payload", _json_mapping(self.payload))

    @property
    def payload_json(self) -> str:
        return canonical_json(self.payload)

    def to_json_dict(self) -> dict[str, Any]:
        return {
            "source_fact_id": self.source_fact_id,
            "source_maturity": self.source_maturity,
            "target_maturity": self.target_maturity,
            "status": self.status.value,
            "confidence": self.confidence,
            "target_fact_id": self.target_fact_id,
            "target_block": self.target_block,
            "target_ea": self.target_ea,
            "target_mop_signature": self.target_mop_signature,
            "reason": self.reason,
            "payload": dict(self.payload),
        }

    @classmethod
    def from_json_dict(cls, data: JsonMapping) -> "FactMapping":
        return cls(
            source_fact_id=str(data["source_fact_id"]),
            source_maturity=str(data["source_maturity"]),
            target_maturity=str(data["target_maturity"]),
            status=FactStatus(str(data["status"])),
            confidence=float(data["confidence"]),
            target_fact_id=data.get("target_fact_id"),  # type: ignore[arg-type]
            target_block=data.get("target_block"),  # type: ignore[arg-type]
            target_ea=data.get("target_ea"),  # type: ignore[arg-type]
            target_mop_signature=data.get("target_mop_signature"),  # type: ignore[arg-type]
            reason=data.get("reason"),  # type: ignore[arg-type]
            payload=data.get("payload") or {},
        )


@dataclass(frozen=True)
class FactConsumerRecord:
    """Diagnostic record for a strategy decision made from facts."""

    consumer: str
    strategy: str
    fact_id: str
    maturity: str
    decision: str
    reason: str | None = None
    payload: JsonMapping = field(default_factory=dict)

    def __post_init__(self) -> None:
        for field_name in ("consumer", "strategy", "fact_id", "maturity", "decision"):
            _require_text(field_name, getattr(self, field_name))
        object.__setattr__(self, "payload", _json_mapping(self.payload))

    @property
    def payload_json(self) -> str:
        return canonical_json(self.payload)


@dataclass(frozen=True)
class FactConflict:
    """Diagnostic record for incompatible fact observations or mappings."""

    conflict_id: str
    fact_id: str
    other_fact_id: str
    maturity: str
    conflict_kind: str
    reason: str
    payload: JsonMapping = field(default_factory=dict)

    def __post_init__(self) -> None:
        for field_name in (
            "conflict_id",
            "fact_id",
            "other_fact_id",
            "maturity",
            "conflict_kind",
            "reason",
        ):
            _require_text(field_name, getattr(self, field_name))
        object.__setattr__(self, "payload", _json_mapping(self.payload))

    @property
    def payload_json(self) -> str:
        return canonical_json(self.payload)


@dataclass(frozen=True)
class ValidatedFactView:
    """Read model exposed to future consumers after lifecycle validation."""

    maturity: str
    observations: tuple[FactObservation, ...] = ()
    mappings: tuple[FactMapping, ...] = ()

    def __post_init__(self) -> None:
        _require_text("maturity", self.maturity)
        object.__setattr__(self, "observations", tuple(self.observations))
        object.__setattr__(self, "mappings", tuple(self.mappings))

    @property
    def active_observations(self) -> tuple[FactObservation, ...]:
        stale_ids = {
            mapping.source_fact_id
            for mapping in self.mappings
            if mapping.status
            in {
                FactStatus.REMAPPED,
                FactStatus.STALE,
                FactStatus.CONTRADICTED,
                FactStatus.SUPERSEDED,
                FactStatus.IDENTITY_LOST,
            }
        }
        return tuple(obs for obs in self.observations if obs.fact_id not in stale_ids)

    def return_carrier_sites_for_block(
        self,
        block_serial: int,
    ) -> tuple[FactObservation, ...]:
        """Return active ``ReturnCarrierFact`` observations whose
        ``upstream_writer_block_serial`` payload entry matches ``block_serial``.

        Only observations surfaced via :pyattr:`active_observations` are
        considered: STALE, REMAPPED, CONTRADICTED, SUPERSEDED, and
        IDENTITY_LOST mappings are excluded so consumers never act on
        invalidated facts.
        """
        try:
            target = int(block_serial)
        except (TypeError, ValueError):
            return ()
        matches: list[FactObservation] = []
        for obs in self.active_observations:
            if obs.kind != "ReturnCarrierFact":
                continue
            payload = obs.payload or {}
            raw = payload.get("upstream_writer_block_serial")
            if raw is None:
                continue
            try:
                if int(raw) != target:
                    continue
            except (TypeError, ValueError):
                continue
            matches.append(obs)
        return tuple(matches)

    def stale_return_carrier_hazards_for_block(
        self,
        block_serial: int,
    ) -> tuple[FactObservation, ...]:
        """Return historical ``ReturnCarrierFact`` hazards for ``block_serial``.

        These facts are explicitly not active. They were observed at an earlier
        maturity and later mapped to ``IDENTITY_LOST``. That status means the
        carrier surface was folded or removed, but the earlier observation can
        still be a valid negative planning constraint when its identity payload
        remains usable.

        The helper is intentionally narrow: it requires a recorded upstream
        writer block, an EA for the carrier/materialization site, and recorded
        stkvar read references. It also rejects any fact that has a
        ``CONTRADICTED`` mapping.
        """
        try:
            target = int(block_serial)
        except (TypeError, ValueError):
            return ()

        lost_blocks_by_id: dict[str, set[int]] = {}
        for mapping in self.mappings:
            if mapping.status is not FactStatus.IDENTITY_LOST:
                continue
            if mapping.target_block is not None:
                try:
                    lost_blocks_by_id.setdefault(mapping.source_fact_id, set()).add(
                        int(mapping.target_block)
                    )
                except (TypeError, ValueError):
                    pass
        lost_ids = set(lost_blocks_by_id)
        contradicted_ids = {
            mapping.source_fact_id
            for mapping in self.mappings
            if mapping.status is FactStatus.CONTRADICTED
        }
        if not lost_ids:
            return ()

        matches: list[FactObservation] = []
        for obs in self.observations:
            if obs.kind != "ReturnCarrierFact":
                continue
            if obs.fact_id not in lost_ids or obs.fact_id in contradicted_ids:
                continue
            payload = obs.payload or {}
            # Stale hazards must be associated with the current target by the
            # lifecycle mapping's exact-EA block resolution. Earlier observed
            # block serials are not stable across maturities and are therefore
            # insufficient for a late negative constraint.
            if target not in lost_blocks_by_id.get(obs.fact_id, set()):
                continue
            raw_refs = payload.get("upstream_writer_var_refs")
            if not isinstance(raw_refs, (tuple, list)) or not raw_refs:
                continue
            raw_ea = payload.get("upstream_writer_ea")
            if obs.source_ea is None and raw_ea is None:
                continue
            matches.append(obs)
        return tuple(matches)

    def with_mapping(self, mapping: FactMapping) -> "ValidatedFactView":
        return replace(self, mappings=(*self.mappings, mapping))
