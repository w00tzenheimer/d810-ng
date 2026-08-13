"""Stable portable telemetry for MBA provider attempts."""

from __future__ import annotations

import enum
import json
import math
from collections.abc import Mapping
from dataclasses import dataclass
from types import MappingProxyType

from d810.core.typing import TypeAlias
from d810.mba.provider_routing import MbaProviderKind


class ProviderOutcomeStatus(enum.StrEnum):
    """The result of one provider attempt, independent of mutation ownership."""

    APPLIED = "applied"
    IMPROVED = "improved"
    UNCHANGED = "unchanged"
    INELIGIBLE = "ineligible"
    UNAVAILABLE = "unavailable"
    OVER_BUDGET = "over_budget"
    PROOF_FAILED = "proof_failed"
    RECONSTRUCTION_FAILED = "reconstruction_failed"
    ERROR = "error"


JsonValue: TypeAlias = (
    None
    | bool
    | int
    | float
    | str
    | tuple["JsonValue", ...]
    | Mapping[str, "JsonValue"]
)


def _freeze_json_value(value: object) -> JsonValue:
    if value is None or type(value) in (bool, int, str):
        return value
    if type(value) is float:
        if not math.isfinite(value):
            raise ValueError("JSON numbers must be finite")
        return value
    if isinstance(value, Mapping):
        if any(type(key) is not str for key in value):
            raise ValueError("metadata mappings must have string keys")
        frozen_items: dict[str, JsonValue] = {}
        for key in sorted(value):
            frozen_items[key] = _freeze_json_value(value[key])
        return MappingProxyType(frozen_items)
    if isinstance(value, (list, tuple)):
        return tuple(_freeze_json_value(item) for item in value)
    raise ValueError(f"metadata value is not JSON-compatible: {type(value).__qualname__}")


def _json_ready(value: JsonValue) -> object:
    if isinstance(value, Mapping):
        return {key: _json_ready(item) for key, item in value.items()}
    if isinstance(value, tuple):
        return [_json_ready(item) for item in value]
    return value


def _normalize_cost(
    name: str,
    cost: tuple[int, int] | None,
) -> tuple[int, int] | None:
    if cost is None:
        return None
    if len(cost) != 2 or any(type(value) is not int or value < 0 for value in cost):
        raise ValueError(f"{name} cost must contain two non-negative integers")
    return tuple(cost)


@dataclass(frozen=True)
class MatcherOutcomeMetadata:
    """Matcher-specific telemetry kept separate from generic provider fields."""

    comparisons: int
    lazy_swaps: int
    flattened_arity: int
    stop_reason: str

    def __post_init__(self) -> None:
        for field_name in ("comparisons", "lazy_swaps", "flattened_arity"):
            value = getattr(self, field_name)
            if type(value) is not int or value < 0:
                raise ValueError(f"{field_name} must be a non-negative integer")
        if type(self.stop_reason) is not str or not self.stop_reason:
            raise ValueError("stop_reason must be a non-empty string")

    def to_dict(self) -> dict[str, int | str]:
        return {
            "comparisons": self.comparisons,
            "lazy_swaps": self.lazy_swaps,
            "flattened_arity": self.flattened_arity,
            "stop_reason": self.stop_reason,
        }


@dataclass(frozen=True)
class MbaProviderOutcome:
    """One serializable provider outcome for a portable fixed-width island."""

    provider: MbaProviderKind
    status: ProviderOutcomeStatus
    fingerprint: str
    input_cost: tuple[int, int] | None = None
    output_cost: tuple[int, int] | None = None
    proof_verdict: bool | None = None
    elapsed_ms: float = 0.0
    source_provenance: tuple[str, ...] = ()
    refusal_reason: str | None = None
    metadata: Mapping[str, JsonValue] | None = None
    matcher: MatcherOutcomeMetadata | None = None

    def __post_init__(self) -> None:
        if not isinstance(self.provider, MbaProviderKind):
            raise ValueError("provider must be an MbaProviderKind")
        if not isinstance(self.status, ProviderOutcomeStatus):
            raise ValueError("status must be a ProviderOutcomeStatus")
        if type(self.fingerprint) is not str or not self.fingerprint:
            raise ValueError("fingerprint must be a non-empty string")
        object.__setattr__(self, "input_cost", _normalize_cost("input", self.input_cost))
        object.__setattr__(self, "output_cost", _normalize_cost("output", self.output_cost))
        if self.proof_verdict is not None and type(self.proof_verdict) is not bool:
            raise ValueError("proof_verdict must be a boolean or None")
        if type(self.elapsed_ms) not in (int, float) or not math.isfinite(self.elapsed_ms):
            raise ValueError("elapsed_ms must be finite")
        if self.elapsed_ms < 0:
            raise ValueError("elapsed_ms must be non-negative")
        object.__setattr__(self, "elapsed_ms", float(self.elapsed_ms))
        object.__setattr__(self, "source_provenance", tuple(self.source_provenance))
        if any(type(item) is not str for item in self.source_provenance):
            raise ValueError("source_provenance must contain only strings")
        if self.refusal_reason is not None and (
            type(self.refusal_reason) is not str or not self.refusal_reason
        ):
            raise ValueError("refusal_reason must be a non-empty string or None")
        if self.metadata is None:
            object.__setattr__(self, "metadata", MappingProxyType({}))
        else:
            frozen_metadata = _freeze_json_value(self.metadata)
            if not isinstance(frozen_metadata, Mapping):
                raise ValueError("metadata must be a mapping")
            object.__setattr__(self, "metadata", frozen_metadata)
        if self.matcher is not None and not isinstance(self.matcher, MatcherOutcomeMetadata):
            raise ValueError("matcher must be MatcherOutcomeMetadata or None")

    def to_dict(self) -> dict[str, object]:
        """Return a JSON-ready dictionary with a fixed field vocabulary."""

        return {
            "provider": self.provider.value,
            "status": self.status.value,
            "fingerprint": self.fingerprint,
            "input_cost": list(self.input_cost) if self.input_cost is not None else None,
            "output_cost": list(self.output_cost) if self.output_cost is not None else None,
            "proof_verdict": self.proof_verdict,
            "elapsed_ms": self.elapsed_ms,
            "source_provenance": list(self.source_provenance),
            "refusal_reason": self.refusal_reason,
            "metadata": _json_ready(self.metadata),
            "matcher": self.matcher.to_dict() if self.matcher is not None else None,
        }

    def to_json(self) -> str:
        """Return deterministic, finite, compact JSON suitable for report files."""

        return json.dumps(
            self.to_dict(),
            allow_nan=False,
            ensure_ascii=True,
            separators=(",", ":"),
            sort_keys=True,
        )


__all__ = [
    "MatcherOutcomeMetadata",
    "MbaProviderKind",
    "MbaProviderOutcome",
    "ProviderOutcomeStatus",
]
