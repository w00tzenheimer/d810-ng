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


class MatcherSelection(enum.StrEnum):
    """The matcher route selected for one provider attempt."""

    RAW = "raw"
    CANONICAL_FALLBACK = "canonical_fallback"
    NONE = "none"


@dataclass(frozen=True)
class RawMatcherWorkReceipt:
    """Exact work performed by one raw handler attempt.

    ``comparisons`` counts candidate-pattern comparisons started by the live
    handler. ``lazy_swaps`` counts only runtime operand swaps; generated legacy
    permutations are already represented by separate comparisons. ``backend``
    is the route that performed those comparisons (``legacy_ast`` for the
    mutating AstNode path, or the normalized Python/Cython engine name).
    """

    comparisons: int
    lazy_swaps: int
    backend: str

    def __post_init__(self) -> None:
        for field_name in ("comparisons", "lazy_swaps"):
            value = getattr(self, field_name)
            if type(value) is not int or value < 0:
                raise ValueError(f"{field_name} must be a non-negative integer")
        if type(self.backend) is not str or not self.backend:
            raise ValueError("backend must be a non-empty string")

    def to_dict(self) -> dict[str, object]:
        """Return the stable JSON/POD representation."""

        return {
            "comparisons": self.comparisons,
            "lazy_swaps": self.lazy_swaps,
            "backend": self.backend,
        }


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
    cost: object,
) -> tuple[int, int] | None:
    if cost is None:
        return None
    if not isinstance(cost, tuple):
        raise ValueError(f"{name} must be a tuple")
    if len(cost) != 2 or any(type(value) is not int or value < 0 for value in cost):
        raise ValueError(f"{name} cost must contain two non-negative integers")
    return cost


@dataclass(frozen=True)
class MatcherOutcomeMetadata:
    """Matcher-specific telemetry kept separate from generic provider fields."""

    comparisons: int
    lazy_swaps: int
    flattened_arity: int
    stop_reason: str
    selection: MatcherSelection = MatcherSelection.NONE
    raw_comparisons: int = 0
    raw_lazy_swaps: int = 0
    backend: str = "unknown"
    fallback_comparisons: int = 0
    fallback_flattened_arity: int = 0
    terminal_stop_reason: str | None = None
    provenance_rejection_count: int = 0
    native_equivalence_verdict: bool | None = None
    mutation_outcome: str | None = None

    def __post_init__(self) -> None:
        for field_name in ("comparisons", "lazy_swaps", "flattened_arity"):
            value = getattr(self, field_name)
            if type(value) is not int or value < 0:
                raise ValueError(f"{field_name} must be a non-negative integer")
        for field_name in (
            "raw_comparisons",
            "raw_lazy_swaps",
            "fallback_comparisons",
            "fallback_flattened_arity",
            "provenance_rejection_count",
        ):
            value = getattr(self, field_name)
            if type(value) is not int or value < 0:
                raise ValueError(f"{field_name} must be a non-negative integer")
        if not isinstance(self.selection, MatcherSelection):
            raise ValueError("selection must be a MatcherSelection")
        if type(self.backend) is not str or not self.backend:
            raise ValueError("backend must be a non-empty string")
        if type(self.stop_reason) is not str or not self.stop_reason:
            raise ValueError("stop_reason must be a non-empty string")
        if self.terminal_stop_reason is None:
            object.__setattr__(self, "terminal_stop_reason", self.stop_reason)
        elif type(self.terminal_stop_reason) is not str or not self.terminal_stop_reason:
            raise ValueError("terminal_stop_reason must be a non-empty string or None")
        if self.native_equivalence_verdict is not None and type(
            self.native_equivalence_verdict
        ) is not bool:
            raise ValueError("native_equivalence_verdict must be a boolean or None")
        if self.mutation_outcome is not None and self.mutation_outcome not in {
            "accepted",
            "rejected",
        }:
            raise ValueError("mutation_outcome must be accepted, rejected, or None")

    def to_dict(self) -> dict[str, object]:
        return {
            "comparisons": self.comparisons,
            "lazy_swaps": self.lazy_swaps,
            "flattened_arity": self.flattened_arity,
            "stop_reason": self.stop_reason,
            "selection": self.selection.value,
            "raw_comparisons": self.raw_comparisons,
            "raw_lazy_swaps": self.raw_lazy_swaps,
            "backend": self.backend,
            "fallback_comparisons": self.fallback_comparisons,
            "fallback_flattened_arity": self.fallback_flattened_arity,
            "terminal_stop_reason": self.terminal_stop_reason,
            "provenance_rejection_count": self.provenance_rejection_count,
            "native_equivalence_verdict": self.native_equivalence_verdict,
            "mutation_outcome": self.mutation_outcome,
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
        object.__setattr__(self, "input_cost", _normalize_cost("input_cost", self.input_cost))
        object.__setattr__(self, "output_cost", _normalize_cost("output_cost", self.output_cost))
        if self.proof_verdict is not None and type(self.proof_verdict) is not bool:
            raise ValueError("proof_verdict must be a boolean or None")
        if type(self.elapsed_ms) not in (int, float) or not math.isfinite(self.elapsed_ms):
            raise ValueError("elapsed_ms must be finite")
        if self.elapsed_ms < 0:
            raise ValueError("elapsed_ms must be non-negative")
        object.__setattr__(self, "elapsed_ms", float(self.elapsed_ms))
        if not isinstance(self.source_provenance, tuple):
            raise ValueError("source_provenance must be a tuple")
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
    "MatcherSelection",
    "RawMatcherWorkReceipt",
    "MbaProviderKind",
    "MbaProviderOutcome",
    "ProviderOutcomeStatus",
]
