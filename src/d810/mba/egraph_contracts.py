"""Portable contracts for bounded e-graph MBA extraction.

The types in this module are deliberately independent from any e-graph
implementation.  A backend may attach its concrete name and version to an
extraction receipt, but option validation, skip reasons, and serialization are
owned by this backend-neutral boundary.
"""

from __future__ import annotations

import enum
import json
import math
from collections.abc import Mapping
from dataclasses import dataclass
from types import MappingProxyType

from d810.core.typing import TypeAlias
from d810.ir.maturity import IRMaturity


JsonValue: TypeAlias = (
    None
    | bool
    | int
    | float
    | str
    | tuple["JsonValue", ...]
    | Mapping[str, "JsonValue"]
)


def _json_ready(value: JsonValue) -> object:
    if isinstance(value, Mapping):
        return {key: _json_ready(item) for key, item in value.items()}
    if isinstance(value, tuple):
        return [_json_ready(item) for item in value]
    return value


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
        frozen = {
            key: _freeze_json_value(item)
            for key, item in sorted(value.items())
        }
        return MappingProxyType(frozen)
    if isinstance(value, (list, tuple)):
        return tuple(_freeze_json_value(item) for item in value)
    raise ValueError(
        f"metadata value is not JSON-compatible: {type(value).__qualname__}"
    )


def _nonnegative_int(name: str, value: object) -> int:
    if type(value) is not int or value < 0:
        raise ValueError(f"{name} must be a non-negative integer")
    return value


def _optional_nonnegative_int(name: str, value: object) -> int | None:
    if value is None:
        return None
    return _nonnegative_int(name, value)


def _positive_int(name: str, value: object) -> int:
    if type(value) is not int or value <= 0:
        raise ValueError(f"{name} must be a positive integer")
    return value


def _timing(name: str, value: object, *, optional: bool = False) -> float | None:
    if optional and value is None:
        return None
    if type(value) not in (int, float) or not math.isfinite(float(value)):
        raise ValueError(f"{name} must be finite")
    if value < 0:  # type: ignore[operator]
        raise ValueError(f"{name} must be non-negative")
    return float(value)


def _nonempty_string(name: str, value: object) -> str:
    if type(value) is not str or not value:
        raise ValueError(f"{name} must be a non-empty string")
    return value


def _optional_string(name: str, value: object) -> str | None:
    if value is None:
        return None
    return _nonempty_string(name, value)


def _string_tuple(name: str, value: object) -> tuple[str, ...]:
    if type(value) is not tuple:
        raise ValueError(f"{name} must be a tuple")
    normalized: list[str] = []
    for item in value:
        normalized.append(_nonempty_string(f"{name} entry", item))
    return tuple(normalized)


def _cost(name: str, value: object, *, json_input: bool = False) -> tuple[int, int] | None:
    if value is None:
        return None
    expected = list if json_input else tuple
    if not isinstance(value, expected):
        raise ValueError(f"{name} must be a {'list' if json_input else 'tuple'}")
    if len(value) != 2:
        raise ValueError(f"{name} cost must contain two non-negative integers")
    if any(type(item) is not int or item < 0 for item in value):
        raise ValueError(f"{name} cost must contain two non-negative integers")
    return (value[0], value[1])


def _trace(name: str, value: object) -> tuple[tuple[str, str, tuple[str, ...]], ...]:
    if type(value) is not tuple:
        raise ValueError(f"{name} must be a tuple")
    normalized: list[tuple[str, str, tuple[str, ...]]] = []
    for row in value:
        if type(row) is not tuple or len(row) != 3:
            raise ValueError(
                f"{name} entries must be (family, source, aliases) tuples"
            )
        family = _nonempty_string(f"{name} family", row[0])
        source = _nonempty_string(f"{name} source", row[1])
        aliases = _string_tuple(f"{name} aliases", row[2])
        normalized.append((family, source, aliases))
    return tuple(normalized)


def _json_tuple(name: str, value: object) -> tuple[object, ...]:
    if type(value) is not list:
        raise ValueError(f"{name} must be a JSON list")
    return tuple(value)


def _json_trace(name: str, value: object) -> tuple[tuple[str, str, tuple[str, ...]], ...]:
    rows = _json_tuple(name, value)
    parsed: list[tuple[str, str, tuple[str, ...]]] = []
    for row in rows:
        if type(row) is not list or len(row) != 3:
            raise ValueError(
                f"{name} entries must be [family, source, aliases] lists"
            )
        aliases = _json_tuple(f"{name} aliases", row[2])
        parsed.append(
            (
                row[0],
                row[1],
                tuple(aliases),
            )
        )
    return _trace(name, tuple(parsed))


class EgraphSkipReason(enum.StrEnum):
    """Stable reasons for a fail-closed e-graph extraction."""

    RUNTIME_UNAVAILABLE = "runtime_unavailable"
    NON_MBA_CANDIDATE = "non_mba_candidate"
    UNSUPPORTED_WIDTH_SEMANTICS = "unsupported_width_semantics"
    CANDIDATE_BUDGET = "candidate_budget"
    TIME_BUDGET = "time_budget"
    ECLASS_BUDGET = "eclass_budget"
    ENODE_BUDGET = "enode_budget"
    RULE_FIRING_BUDGET = "rule_firing_budget"
    LOWERING_FAILED = "lowering_failed"
    PROOF_FAILED = "proof_failed"
    INTERNAL_ERROR = "internal_error"


DEFAULT_MATURITIES = ("GLOBAL_OPTIMIZED",)
DEFAULT_FAMILIES = ("add",)
DEFAULT_LEARNED_REPLAY_ENABLED = False
DEFAULT_LEARNED_REPLAY_MAX_ENTRIES = 256
DEFAULT_LEARNED_REPLAY_MAX_BYTES = 2_097_152
MAX_LEARNED_REPLAY_ENTRIES = 4_096
MAX_LEARNED_REPLAY_BYTES = 16_777_216
EGRAPH_FAMILIES = (
    "add",
    "and",
    "bnot",
    "fixed_rotate",
    "mul",
    "neg",
    "or",
    "sub",
    "xor",
)


@dataclass(frozen=True, slots=True)
class MbaEgraphOptions:
    """Validated, backend-neutral options for one bounded extraction."""

    max_leaves: int = 2
    max_operator_nodes: int = 10
    max_degree: int = 1
    saturation_rounds: int = 2
    max_eclasses: int = 64
    max_enodes: int = 128
    max_rule_firings: int = 32
    cross_block_constant_preparation: bool = False
    cross_block_def_use_preparation: bool = False
    learned_replay_enabled: bool = DEFAULT_LEARNED_REPLAY_ENABLED
    learned_replay_max_entries: int = DEFAULT_LEARNED_REPLAY_MAX_ENTRIES
    learned_replay_max_bytes: int = DEFAULT_LEARNED_REPLAY_MAX_BYTES
    time_budget_ms: int = 3
    function_time_budget_ms: int | None = None
    residual_only: bool = False
    require_proof: bool = True
    collect_stage_timings: bool = False
    execution_mode: str = "interactive"
    native_proof_mode: str = "legacy"
    families: tuple[str, ...] = DEFAULT_FAMILIES
    maturities: tuple[str, ...] = DEFAULT_MATURITIES

    def __post_init__(self) -> None:
        if type(self.max_leaves) is not int or not 1 <= self.max_leaves <= 8:
            raise ValueError("max_leaves must be an integer from 1 to 8")
        for name in (
            "max_operator_nodes",
            "max_eclasses",
            "max_enodes",
            "max_rule_firings",
            "time_budget_ms",
        ):
            _positive_int(name, getattr(self, name))
        if type(self.max_degree) is not int or self.max_degree not in (1, 2):
            raise ValueError("max_degree must be exactly 1 or 2")
        if type(self.saturation_rounds) is not int or not 1 <= self.saturation_rounds <= 6:
            raise ValueError("saturation_rounds must be an integer from 1 to 6")
        if self.function_time_budget_ms is not None:
            if type(self.function_time_budget_ms) is not int or not 0 <= self.function_time_budget_ms <= 5_000:
                raise ValueError(
                    "function_time_budget_ms must be an integer from 0 to 5000"
                )
            if self.function_time_budget_ms == 0:
                object.__setattr__(self, "function_time_budget_ms", None)
        for name in (
            "cross_block_constant_preparation",
            "cross_block_def_use_preparation",
            "learned_replay_enabled",
            "residual_only",
            "collect_stage_timings",
        ):
            if type(getattr(self, name)) is not bool:
                raise ValueError(f"{name} must be a boolean")
        if type(self.learned_replay_max_entries) is not int or not 1 <= self.learned_replay_max_entries <= MAX_LEARNED_REPLAY_ENTRIES:
            raise ValueError("learned_replay_max_entries must be an integer from 1 to 4096")
        if type(self.learned_replay_max_bytes) is not int or not 1 <= self.learned_replay_max_bytes <= MAX_LEARNED_REPLAY_BYTES:
            raise ValueError("learned_replay_max_bytes must be an integer from 1 to 16777216")
        if self.require_proof is not True:
            raise ValueError("require_proof must remain true")
        if type(self.execution_mode) is not str or self.execution_mode not in {
            "interactive",
            "noninteractive",
        }:
            raise ValueError("execution_mode must be interactive or noninteractive")
        if type(self.native_proof_mode) is not str or self.native_proof_mode not in {
            "legacy",
            "shadow",
        }:
            raise ValueError("native_proof_mode must be legacy or shadow")
        families = _string_tuple("families", self.families)
        if not families:
            raise ValueError("families must be a nonempty tuple of names")
        if len(set(families)) != len(families):
            raise ValueError("families must be unique")
        if "fixed_rotate" in families and len(families) != 1:
            raise ValueError("families fixed_rotate must be selected alone")
        unsupported = tuple(family for family in families if family not in EGRAPH_FAMILIES)
        if unsupported:
            raise ValueError(
                "families must name supported families; got " + ", ".join(unsupported)
            )
        if "fixed_rotate" in families and (
            self.cross_block_constant_preparation or self.cross_block_def_use_preparation
        ):
            raise ValueError("families fixed_rotate cannot use cross-block preparation")
        maturities = _string_tuple("maturities", self.maturities)
        if not maturities or any(value not in {member.name for member in IRMaturity} for value in maturities):
            raise ValueError("maturities must name supported IR maturities")
        object.__setattr__(self, "families", families)
        object.__setattr__(self, "maturities", maturities)

    def to_dict(self) -> dict[str, object]:
        """Return the complete JSON-ready option vocabulary."""

        return {
            "max_leaves": self.max_leaves,
            "max_operator_nodes": self.max_operator_nodes,
            "max_degree": self.max_degree,
            "saturation_rounds": self.saturation_rounds,
            "max_eclasses": self.max_eclasses,
            "max_enodes": self.max_enodes,
            "max_rule_firings": self.max_rule_firings,
            "cross_block_constant_preparation": self.cross_block_constant_preparation,
            "cross_block_def_use_preparation": self.cross_block_def_use_preparation,
            "learned_replay_enabled": self.learned_replay_enabled,
            "learned_replay_max_entries": self.learned_replay_max_entries,
            "learned_replay_max_bytes": self.learned_replay_max_bytes,
            "time_budget_ms": self.time_budget_ms,
            "function_time_budget_ms": self.function_time_budget_ms,
            "residual_only": self.residual_only,
            "require_proof": self.require_proof,
            "collect_stage_timings": self.collect_stage_timings,
            "execution_mode": self.execution_mode,
            "native_proof_mode": self.native_proof_mode,
            "families": list(self.families),
            "maturities": list(self.maturities),
        }

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), allow_nan=False, sort_keys=True, separators=(",", ":"))

    @classmethod
    def from_dict(cls, payload: object) -> "MbaEgraphOptions":
        if type(payload) is not dict:
            raise ValueError("invalid e-graph options schema")
        allowed = {item for item in cls.__dataclass_fields__}
        unknown = set(payload) - allowed
        if unknown:
            raise ValueError(f"unknown e-graph options: {sorted(unknown, key=str)}")
        values = dict(payload)
        if "families" in values:
            values["families"] = tuple(_json_tuple("families", values["families"]))
        if "maturities" in values:
            values["maturities"] = tuple(_json_tuple("maturities", values["maturities"]))
        try:
            return cls(**values)
        except (TypeError, ValueError) as exc:
            raise ValueError(str(exc)) from exc

    @classmethod
    def from_json(cls, encoded: str) -> "MbaEgraphOptions":
        if type(encoded) is not str:
            raise ValueError("e-graph options JSON must be a string")
        try:
            payload = json.loads(encoded)
        except (TypeError, ValueError, json.JSONDecodeError) as exc:
            raise ValueError("invalid e-graph options JSON") from exc
        return cls.from_dict(payload)


@dataclass(frozen=True, slots=True)
class EgraphExtractionReceipt:
    """Immutable telemetry for one extraction or fail-closed skip."""

    input_cost: tuple[int, int] | None = None
    extracted_cost: tuple[int, int] | None = None
    degree: int | None = None
    eclass_count: int | None = None
    enode_count: int | None = None
    rule_firings: int = 0
    elapsed_ms: float = 0.0
    selected_family: str | None = None
    selected_source: str | None = None
    selected_aliases: tuple[str, ...] = ()
    derivation_trace: tuple[tuple[str, str, tuple[str, ...]], ...] = ()
    island_class: str | None = None
    island_fingerprint: str | None = None
    operator_count: int | None = None
    distinct_leaf_count: int | None = None
    nonlinear_product_count: int | None = None
    blockers: tuple[str, ...] = ()
    native_profile: Mapping[str, JsonValue] | None = None
    proof_mode: str = "legacy"
    template_source_name: str | None = None
    template_fallback_reason: str | None = None
    template_proof_verdict: bool | None = None
    legacy_proof_verdict: bool | None = None
    template_proof_elapsed_ms: float | None = None
    legacy_proof_elapsed_ms: float | None = None
    native_matcher_backend: str | None = None
    native_matcher_comparisons: int | None = None
    native_matcher_lazy_swaps: int | None = None
    native_fixed_binding_count: int | None = None
    native_matcher_elapsed_ms: float | None = None
    skip_reason: EgraphSkipReason | None = None
    canonicalizer_version: int | None = None
    canonical_input_cost: tuple[int, int] | None = None
    normalization_steps: tuple[str, ...] = ()
    execution_path: str | None = None
    cache_status: str | None = None
    cache_key: str | None = None
    replayed_trace: tuple[tuple[str, str, tuple[str, ...]], ...] = ()
    cache_lookup_elapsed_ms: float | None = None
    replay_rebuild_elapsed_ms: float | None = None
    replay_proof_elapsed_ms: float | None = None
    egraph_work_units: int = 0
    replay_fallback_reason: str | None = None
    egraph_run_count: int | None = None
    replay_saved_egraph_runs: int | None = None
    backend: str | None = None
    backend_version: str | None = None

    def __post_init__(self) -> None:
        if self.native_matcher_elapsed_ms is not None and type(self.native_matcher_elapsed_ms) is not float:
            raise ValueError("native_matcher_elapsed_ms must be a non-negative float or null")
        for name in (
            "degree",
            "eclass_count",
            "enode_count",
            "operator_count",
            "distinct_leaf_count",
            "nonlinear_product_count",
            "native_matcher_comparisons",
            "native_matcher_lazy_swaps",
            "native_fixed_binding_count",
            "egraph_run_count",
            "replay_saved_egraph_runs",
        ):
            object.__setattr__(self, name, _optional_nonnegative_int(name, getattr(self, name)))
        object.__setattr__(self, "rule_firings", _nonnegative_int("rule_firings", self.rule_firings))
        object.__setattr__(self, "egraph_work_units", _nonnegative_int("egraph_work_units", self.egraph_work_units))
        for name in (
            "elapsed_ms",
            "template_proof_elapsed_ms",
            "legacy_proof_elapsed_ms",
            "native_matcher_elapsed_ms",
            "cache_lookup_elapsed_ms",
            "replay_rebuild_elapsed_ms",
            "replay_proof_elapsed_ms",
        ):
            object.__setattr__(self, name, _timing(name, getattr(self, name), optional=name != "elapsed_ms"))
        object.__setattr__(self, "input_cost", _cost("input_cost", self.input_cost))
        object.__setattr__(self, "extracted_cost", _cost("extracted_cost", self.extracted_cost))
        object.__setattr__(self, "canonical_input_cost", _cost("canonical_input_cost", self.canonical_input_cost))
        object.__setattr__(self, "selected_aliases", _string_tuple("selected_aliases", self.selected_aliases))
        object.__setattr__(self, "normalization_steps", _string_tuple("normalization_steps", self.normalization_steps))
        object.__setattr__(self, "blockers", tuple(sorted(_string_tuple("blockers", self.blockers))))
        object.__setattr__(self, "derivation_trace", _trace("derivation_trace", self.derivation_trace))
        object.__setattr__(self, "replayed_trace", _trace("replayed_trace", self.replayed_trace))
        object.__setattr__(self, "native_profile", self._normalize_profile(self.native_profile))
        if self.skip_reason is not None and not isinstance(self.skip_reason, EgraphSkipReason):
            raise ValueError("skip_reason must be an EgraphSkipReason or None")
        if type(self.proof_mode) is not str or self.proof_mode not in {"legacy", "shadow"}:
            raise ValueError("proof_mode must be legacy or shadow")
        if self.execution_path is not None and (
            type(self.execution_path) is not str
            or self.execution_path
            not in {"telemetry_only", "direct_catalogue", "fresh_saturation", "learned_replay"}
        ):
            raise ValueError("unknown e-graph execution path")
        if self.cache_status is not None and (
            type(self.cache_status) is not str
            or self.cache_status not in {"disabled", "miss", "hit", "stale", "malformed", "evicted"}
        ):
            raise ValueError("unknown e-graph cache status")
        object.__setattr__(self, "selected_family", _optional_string("selected_family", self.selected_family))
        object.__setattr__(self, "selected_source", _optional_string("selected_source", self.selected_source))
        object.__setattr__(self, "island_class", _optional_string("island_class", self.island_class))
        object.__setattr__(self, "island_fingerprint", _optional_string("island_fingerprint", self.island_fingerprint))
        object.__setattr__(self, "template_source_name", _optional_string("template_source_name", self.template_source_name))
        object.__setattr__(self, "template_fallback_reason", _optional_string("template_fallback_reason", self.template_fallback_reason))
        object.__setattr__(self, "replay_fallback_reason", _optional_string("replay_fallback_reason", self.replay_fallback_reason))
        object.__setattr__(self, "cache_key", _optional_string("cache_key", self.cache_key))
        if self.native_matcher_backend is not None and (
            type(self.native_matcher_backend) is not str
            or self.native_matcher_backend not in {"python", "cython"}
        ):
            raise ValueError("unknown native matcher backend")
        for name in ("template_proof_verdict", "legacy_proof_verdict"):
            value = getattr(self, name)
            if value is not None and type(value) is not bool:
                raise ValueError(f"{name} must be a boolean or None")
        if self.canonicalizer_version is not None:
            _positive_int("canonicalizer_version", self.canonicalizer_version)
        object.__setattr__(self, "backend", _optional_string("backend", self.backend))
        object.__setattr__(self, "backend_version", _optional_string("backend_version", self.backend_version))
        if (self.backend is None) != (self.backend_version is None):
            raise ValueError("backend and backend_version must be provided together")

    @staticmethod
    def _normalize_profile(value: object) -> Mapping[str, JsonValue] | None:
        if value is None:
            return None
        if not isinstance(value, Mapping):
            raise ValueError("native_profile must be a mapping or None")
        frozen = _freeze_json_value(value)
        if not isinstance(frozen, Mapping):
            raise ValueError("native_profile must be a mapping")
        return frozen

    def to_dict(self) -> dict[str, object]:
        """Return the exact JSON-ready receipt vocabulary."""

        return {
            "input_cost": list(self.input_cost) if self.input_cost is not None else None,
            "extracted_cost": list(self.extracted_cost) if self.extracted_cost is not None else None,
            "degree": self.degree,
            "eclass_count": self.eclass_count,
            "enode_count": self.enode_count,
            "rule_firings": self.rule_firings,
            "elapsed_ms": self.elapsed_ms,
            "selected_family": self.selected_family,
            "selected_source": self.selected_source,
            "selected_aliases": list(self.selected_aliases),
            "derivation_trace": [[family, source, list(aliases)] for family, source, aliases in self.derivation_trace],
            "island_class": self.island_class,
            "island_fingerprint": self.island_fingerprint,
            "operator_count": self.operator_count,
            "distinct_leaf_count": self.distinct_leaf_count,
            "nonlinear_product_count": self.nonlinear_product_count,
            "blockers": list(self.blockers),
            "native_profile": None if self.native_profile is None else _json_ready(self.native_profile),
            "proof_mode": self.proof_mode,
            "template_source_name": self.template_source_name,
            "template_fallback_reason": self.template_fallback_reason,
            "template_proof_verdict": self.template_proof_verdict,
            "legacy_proof_verdict": self.legacy_proof_verdict,
            "template_proof_elapsed_ms": self.template_proof_elapsed_ms,
            "legacy_proof_elapsed_ms": self.legacy_proof_elapsed_ms,
            "native_matcher_backend": self.native_matcher_backend,
            "native_matcher_comparisons": self.native_matcher_comparisons,
            "native_matcher_lazy_swaps": self.native_matcher_lazy_swaps,
            "native_fixed_binding_count": self.native_fixed_binding_count,
            "native_matcher_elapsed_ms": self.native_matcher_elapsed_ms,
            "skip_reason": None if self.skip_reason is None else self.skip_reason.value,
            "canonicalizer_version": self.canonicalizer_version,
            "canonical_input_cost": list(self.canonical_input_cost) if self.canonical_input_cost is not None else None,
            "normalization_steps": list(self.normalization_steps),
            "execution_path": self.execution_path,
            "cache_status": self.cache_status,
            "cache_key": self.cache_key,
            "replayed_trace": [[family, source, list(aliases)] for family, source, aliases in self.replayed_trace],
            "cache_lookup_elapsed_ms": self.cache_lookup_elapsed_ms,
            "replay_rebuild_elapsed_ms": self.replay_rebuild_elapsed_ms,
            "replay_proof_elapsed_ms": self.replay_proof_elapsed_ms,
            "egraph_work_units": self.egraph_work_units,
            "replay_fallback_reason": self.replay_fallback_reason,
            "egraph_run_count": self.egraph_run_count,
            "replay_saved_egraph_runs": self.replay_saved_egraph_runs,
            "backend": self.backend,
            "backend_version": self.backend_version,
        }

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), allow_nan=False, ensure_ascii=True, sort_keys=True, separators=(",", ":"))

    @classmethod
    def from_dict(cls, payload: object) -> "EgraphExtractionReceipt":
        expected = {field.name for field in cls.__dataclass_fields__.values()}
        if type(payload) is not dict or set(payload) != expected:
            raise ValueError("invalid e-graph receipt schema")
        try:
            return cls(
                input_cost=_cost("input_cost", payload["input_cost"], json_input=True),
                extracted_cost=_cost("extracted_cost", payload["extracted_cost"], json_input=True),
                degree=payload["degree"],
                eclass_count=payload["eclass_count"],
                enode_count=payload["enode_count"],
                rule_firings=payload["rule_firings"],
                elapsed_ms=payload["elapsed_ms"],
                selected_family=payload["selected_family"],
                selected_source=payload["selected_source"],
                selected_aliases=_json_tuple("selected_aliases", payload["selected_aliases"]),
                derivation_trace=_json_trace("derivation_trace", payload["derivation_trace"]),
                island_class=payload["island_class"],
                island_fingerprint=payload["island_fingerprint"],
                operator_count=payload["operator_count"],
                distinct_leaf_count=payload["distinct_leaf_count"],
                nonlinear_product_count=payload["nonlinear_product_count"],
                blockers=_json_tuple("blockers", payload["blockers"]),
                native_profile=payload["native_profile"],
                proof_mode=payload["proof_mode"],
                template_source_name=payload["template_source_name"],
                template_fallback_reason=payload["template_fallback_reason"],
                template_proof_verdict=payload["template_proof_verdict"],
                legacy_proof_verdict=payload["legacy_proof_verdict"],
                template_proof_elapsed_ms=payload["template_proof_elapsed_ms"],
                legacy_proof_elapsed_ms=payload["legacy_proof_elapsed_ms"],
                native_matcher_backend=payload["native_matcher_backend"],
                native_matcher_comparisons=payload["native_matcher_comparisons"],
                native_matcher_lazy_swaps=payload["native_matcher_lazy_swaps"],
                native_fixed_binding_count=payload["native_fixed_binding_count"],
                native_matcher_elapsed_ms=payload["native_matcher_elapsed_ms"],
                skip_reason=(None if payload["skip_reason"] is None else EgraphSkipReason(payload["skip_reason"])),
                canonicalizer_version=payload["canonicalizer_version"],
                canonical_input_cost=_cost("canonical_input_cost", payload["canonical_input_cost"], json_input=True),
                normalization_steps=_json_tuple("normalization_steps", payload["normalization_steps"]),
                execution_path=payload["execution_path"],
                cache_status=payload["cache_status"],
                cache_key=payload["cache_key"],
                replayed_trace=_json_trace("replayed_trace", payload["replayed_trace"]),
                cache_lookup_elapsed_ms=payload["cache_lookup_elapsed_ms"],
                replay_rebuild_elapsed_ms=payload["replay_rebuild_elapsed_ms"],
                replay_proof_elapsed_ms=payload["replay_proof_elapsed_ms"],
                egraph_work_units=payload["egraph_work_units"],
                replay_fallback_reason=payload["replay_fallback_reason"],
                egraph_run_count=payload["egraph_run_count"],
                replay_saved_egraph_runs=payload["replay_saved_egraph_runs"],
                backend=payload["backend"],
                backend_version=payload["backend_version"],
            )
        except (KeyError, TypeError, ValueError, IndexError) as exc:
            raise ValueError(f"invalid e-graph receipt: {exc}") from exc

    @classmethod
    def from_json(cls, encoded: str) -> "EgraphExtractionReceipt":
        if type(encoded) is not str:
            raise ValueError("e-graph receipt JSON must be a string")
        try:
            payload = json.loads(encoded)
        except (TypeError, ValueError, json.JSONDecodeError) as exc:
            raise ValueError("invalid e-graph receipt JSON") from exc
        return cls.from_dict(payload)


__all__ = [
    "DEFAULT_FAMILIES",
    "DEFAULT_MATURITIES",
    "EGRAPH_FAMILIES",
    "EgraphExtractionReceipt",
    "EgraphSkipReason",
    "MbaEgraphOptions",
]
