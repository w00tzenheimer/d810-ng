"""IDA-free model objects for maturity-lifecycle facts."""
from __future__ import annotations

from dataclasses import dataclass, field, replace
from enum import Enum

from d810.analyses.value_flow.observation import (
    FactObservation,
    JsonMapping,
    canonical_json,
    _json_mapping,
    _require_text,
    _validate_confidence,
)
from d810.core.typing import Any


class FactStatus(str, Enum):
    """Lifecycle status for a fact as it moves between maturities."""

    ACTIVE = "ACTIVE"
    REMAPPED = "REMAPPED"
    STALE = "STALE"
    CONTRADICTED = "CONTRADICTED"
    SUPERSEDED = "SUPERSEDED"
    IDENTITY_LOST = "IDENTITY_LOST"
    OPTIMIZATION_FOLDED = "OPTIMIZATION_FOLDED"
    STATE_CONST_REWRITTEN = "STATE_CONST_REWRITTEN"
    UNKNOWN = "UNKNOWN"


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

    def state_transitions_for_source_block(
        self,
        block_serial: int,
    ) -> tuple[FactObservation, ...]:
        """Return active ``StateTransitionAnchorFact`` observations whose
        payload ``source_block_serial`` matches ``block_serial``.

        Only observations surfaced via :pyattr:`active_observations` are
        considered.  Each observation carries the source state constant,
        the chain of transit blocks, the next state constant (if found),
        and the successor kind (``direct`` / ``transit`` / ``branch`` /
        ``loop`` / ``exit`` / ``unresolved``).  Cross-link with
        :meth:`terminal_byte_emit_sites_for_block` is performed by
        callers, not embedded here, so this view stays purely block-
        local.
        """
        try:
            target = int(block_serial)
        except (TypeError, ValueError):
            return ()
        matches: list[FactObservation] = []
        for obs in self.active_observations:
            if obs.kind != "StateTransitionAnchorFact":
                continue
            payload = obs.payload or {}
            raw = payload.get("source_block_serial")
            if raw is None:
                continue
            try:
                if int(raw) != target:
                    continue
            except (TypeError, ValueError):
                continue
            matches.append(obs)
        return tuple(matches)

    def state_write_anchors_for_block(
        self,
        block_serial: int,
    ) -> tuple[FactObservation, ...]:
        """Return active ``StateWriteAnchorFact`` observations whose
        payload's ``block_serial`` matches ``block_serial``.

        Only observations surfaced via :pyattr:`active_observations` are
        considered: STALE / REMAPPED / CONTRADICTED / SUPERSEDED /
        IDENTITY_LOST mappings are excluded so consumers never act on
        invalidated facts.  STATE_CONST_REWRITTEN mappings do NOT remove
        the underlying observation from the active set: the original
        LOCOPT-pre fact remains valuable as a "what was here before
        IDA's CP rewrote it" record, and consumers can still inspect
        the mapping for the rewritten value separately.
        """
        try:
            target = int(block_serial)
        except (TypeError, ValueError):
            return ()
        matches: list[FactObservation] = []
        for obs in self.active_observations:
            if obs.kind != "StateWriteAnchorFact":
                continue
            payload = obs.payload or {}
            raw = payload.get("block_serial")
            if raw is None:
                continue
            try:
                if int(raw) != target:
                    continue
            except (TypeError, ValueError):
                continue
            matches.append(obs)
        return tuple(matches)

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

    def terminal_byte_emit_sites_for_block(
        self,
        block_serial: int,
    ) -> tuple[FactObservation, ...]:
        """Return active ``TerminalByteEmitterFact`` observations whose
        payload identifies ``block_serial`` as the byte-emit destination.

        Filtering rules:

        * ``obs.kind == "TerminalByteEmitterFact"``
        * ``obs.payload["corridor_role"] == "terminal_tail"``  (we
          deliberately ignore ``non_terminal_byte_emitter`` and
          ``guard_only`` rows -- only terminal tail emit sites are
          load-bearing for the per-byte ``v52[k]`` reads we want IDA's
          structurer to keep).
        * ``obs.payload["destination_block"] == block_serial`` OR
          ``obs.payload["block_serial"] == block_serial`` -- the
          collector populates both keys today; the helper accepts either
          for safety against schema drift.

        Only observations surfaced via :pyattr:`active_observations` are
        considered: STALE / REMAPPED / CONTRADICTED / SUPERSEDED /
        IDENTITY_LOST mappings are excluded so consumers never act on
        invalidated facts.
        """
        try:
            target = int(block_serial)
        except (TypeError, ValueError):
            return ()
        matches: list[FactObservation] = []
        for obs in self.active_observations:
            if obs.kind != "TerminalByteEmitterFact":
                continue
            payload = obs.payload or {}
            if payload.get("corridor_role") != "terminal_tail":
                continue
            if payload.get("emitter_role") == "guard_only":
                continue
            destination = payload.get("destination_block")
            block_payload = payload.get("block_serial")
            matched = False
            for raw in (destination, block_payload):
                if raw is None:
                    continue
                try:
                    if int(raw) == target:
                        matched = True
                        break
                except (TypeError, ValueError):
                    continue
            if not matched:
                continue
            matches.append(obs)
        return tuple(matches)

    def terminal_zero_guard_return_sites_for_block(
        self,
        block_serial: int,
    ) -> tuple[FactObservation, ...]:
        """Return active guard-only terminal-byte facts whose zero-residual
        return edge is ``block_serial``.

        ``TerminalByteEmitterFact`` uses ``emitter_role == "guard_only"``
        for the residual-zero guard that should return before any terminal
        byte emit.  This helper is intentionally separate from
        :meth:`terminal_byte_emit_sites_for_block`, because the latter
        protects concrete byte-emitter destinations while this protects the
        no-byte early-return edge.
        """
        try:
            target = int(block_serial)
        except (TypeError, ValueError):
            return ()
        matches: list[FactObservation] = []
        for obs in self.active_observations:
            if obs.kind != "TerminalByteEmitterFact":
                continue
            payload = obs.payload or {}
            if payload.get("corridor_role") != "terminal_tail":
                continue
            if payload.get("emitter_role") != "guard_only":
                continue
            try:
                byte_index = int(payload.get("byte_index"))
            except (TypeError, ValueError):
                continue
            if byte_index != 0:
                continue
            raw_return_edge = payload.get("return_edge")
            if raw_return_edge is None:
                continue
            try:
                if int(raw_return_edge) != target:
                    continue
            except (TypeError, ValueError):
                continue
            matches.append(obs)
        return tuple(matches)

    def loop_carriers_for_predicate_block(
        self,
        block_serial: int,
    ) -> tuple[FactObservation, ...]:
        """Return active ``LoopCarrierFact`` observations for a predicate block.

        The helper is deliberately keyed on the predicate block, not on the
        carrier writer block: the current sub_7FFD failure is precisely that
        the carrier writers sit outside the loop SCC, so consumers need to ask
        "what carrier facts constrain this predicate?" and then inspect the
        payload's ``carrier_writer_blocks_*`` fields.
        """
        try:
            target = int(block_serial)
        except (TypeError, ValueError):
            return ()
        matches: list[FactObservation] = []
        for obs in self.active_observations:
            if obs.kind != "LoopCarrierFact":
                continue
            payload = obs.payload or {}
            raw = payload.get("predicate_block_serial")
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
