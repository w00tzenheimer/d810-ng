"""Immutable, cheap-to-query views over already-certified MBA catalogues."""

from __future__ import annotations

import hashlib
import json
from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from pathlib import Path
from types import MappingProxyType
from d810.core.typing import Any, TypeAlias
from d810.mba.typed_term import TypedBvTerm


RootShape: TypeAlias = tuple[str | None, int, int]
CompiledRule: TypeAlias = Any


@dataclass(frozen=True)
class CertifiedCatalogueSnapshot:
    fingerprint: str
    rules_in_declaration_order: tuple[CompiledRule, ...]
    rule_ids_by_root_shape: Mapping[RootShape, tuple[int, ...]]

    def __post_init__(self) -> None:
        object.__setattr__(
            self,
            "rule_ids_by_root_shape",
            MappingProxyType(dict(self.rule_ids_by_root_shape)),
        )


@dataclass(frozen=True)
class StructuralMatcherParityCertificate:
    """Persisted native parity evidence for one matcher runtime and snapshot."""

    snapshot_fingerprint: str
    runtime_mode: str
    corpus_identity: str
    legacy_observation_count: int

    def authorizes(
        self, snapshot: CertifiedCatalogueSnapshot, runtime_mode: str
    ) -> bool:
        return (
            self.snapshot_fingerprint == snapshot.fingerprint
            and self.runtime_mode == runtime_mode
        )


def load_structural_matcher_parity_certificate(
    path: Path,
) -> StructuralMatcherParityCertificate:
    """Load fail-closed structural-matcher parity evidence from JSON.

    The certificate is deliberately separate from an experimental environment
    flag: the flag requests selection while this artifact binds that request to
    one certified catalogue snapshot and one active matcher runtime.
    """

    raw = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(raw, dict):
        raise ValueError("structural parity certificate must be an object")
    if raw.get("schema_version") != 1:
        raise ValueError("structural parity certificate schema_version must be 1")
    fingerprint = raw.get("snapshot_fingerprint")
    if (
        not isinstance(fingerprint, str)
        or len(fingerprint) != 64
        or any(character not in "0123456789abcdef" for character in fingerprint)
    ):
        raise ValueError(
            "structural parity certificate has invalid snapshot_fingerprint"
        )
    runtime_mode = raw.get("runtime_mode")
    if runtime_mode not in {"python", "cython"}:
        raise ValueError("structural parity certificate has invalid runtime_mode")
    corpus_identity = raw.get("corpus_identity")
    if not isinstance(corpus_identity, str) or not corpus_identity:
        raise ValueError("structural parity certificate has invalid corpus_identity")
    observation_count = raw.get("legacy_observation_count")
    if type(observation_count) is not int or observation_count <= 0:
        raise ValueError(
            "structural parity certificate needs positive legacy_observation_count"
        )
    for field in (
        "legacy_rule_mismatches",
        "legacy_binding_mismatches",
        "legacy_binding_unknown",
    ):
        if raw.get(field) != 0:
            raise ValueError(f"structural parity certificate requires {field}=0")
    return StructuralMatcherParityCertificate(
        snapshot_fingerprint=fingerprint,
        runtime_mode=runtime_mode,
        corpus_identity=corpus_identity,
        legacy_observation_count=observation_count,
    )


@dataclass
class ShadowMatcherParityLedger:
    """Configuration-scoped evidence for legacy-to-structural parity."""

    observation_count: int = 0
    legacy_match_count: int = 0
    legacy_rule_mismatches: int = 0
    legacy_binding_mismatches: int = 0
    legacy_binding_unknown: int = 0
    new_safe_coverage_pending: int = 0
    new_safe_coverage_proved: int = 0

    def record(
        self,
        *,
        legacy_match: bool,
        structural_match: bool,
        same_rule: bool,
        same_bindings: bool | None,
        structural_proven: bool = False,
    ) -> None:
        self.observation_count += 1
        if not legacy_match:
            # A structural-only hit is useful coverage evidence, but cannot
            # become a provider win during the shadow period. It remains
            # pending unless the adapter completes its proof-only native path.
            if structural_match:
                if structural_proven:
                    self.new_safe_coverage_proved += 1
                else:
                    self.new_safe_coverage_pending += 1
            return
        self.legacy_match_count += 1
        if not structural_match or not same_rule:
            self.legacy_rule_mismatches += 1
        if same_bindings is None:
            self.legacy_binding_unknown += 1
        elif not same_bindings:
            self.legacy_binding_mismatches += 1


_SNAPSHOTS: dict[str, CertifiedCatalogueSnapshot] = {}


def _rule_pattern(rule: CompiledRule) -> Any:
    value = getattr(rule, "pattern", None)
    return value() if callable(value) else value


def _rule_identity(rule: CompiledRule) -> tuple[object, ...]:
    pattern = _rule_pattern(rule)
    return (
        _rule_family(rule),
        str(
            getattr(rule, "source_name", getattr(rule, "name", type(rule).__qualname__))
        ),
        repr(pattern),
        tuple(str(item) for item in getattr(rule, "aliases", ())),
    )


def _rule_family(rule: CompiledRule) -> str:
    explicit = getattr(rule, "family", None)
    if type(explicit) is str and explicit:
        return explicit
    module = getattr(type(rule), "__module__", "")
    return module.rsplit(".", 1)[-1] if type(module) is str else ""


def _root_shape(rule: CompiledRule, width: int) -> RootShape:
    pattern = _rule_pattern(rule)
    operation = getattr(pattern, "operation", None)
    arity = sum(
        child is not None
        for child in (getattr(pattern, "left", None), getattr(pattern, "right", None))
    )
    return (operation, width, arity)


def root_shape_for_term(term: TypedBvTerm) -> RootShape:
    """Return the exact cheap bucket key for one lowered candidate root."""

    return (term.operation, term.width, len(term.children))


def build_certified_catalogue_snapshot(
    rules: Iterable[CompiledRule],
    *,
    compiler_version: str,
    widths: tuple[int, ...] = (8, 16, 32, 64),
    enabled_families: tuple[str, ...] | None = None,
) -> CertifiedCatalogueSnapshot:
    """Freeze already-admitted rules; never compile or verify inside this API."""

    if type(compiler_version) is not str or not compiler_version:
        raise ValueError("compiler_version must be non-empty")
    all_rules = tuple(rules)
    families = None if enabled_families is None else tuple(enabled_families)
    enabled = None if families is None else frozenset(families)
    frozen_rules = tuple(
        rule for rule in all_rules if enabled is None or _rule_family(rule) in enabled
    )
    payload = {
        "compiler_version": compiler_version,
        "widths": tuple(widths),
        "enabled_families": families,
        "rules": tuple(_rule_identity(rule) for rule in frozen_rules),
    }
    encoded = json.dumps(
        payload, ensure_ascii=True, separators=(",", ":"), sort_keys=True
    )
    fingerprint = hashlib.sha256(encoded.encode("ascii")).hexdigest()
    cached = _SNAPSHOTS.get(fingerprint)
    if cached is not None:
        return cached
    buckets: dict[RootShape, list[int]] = {}
    for rule_id, rule in enumerate(frozen_rules):
        for width in widths:
            buckets.setdefault(_root_shape(rule, width), []).append(rule_id)
    snapshot = CertifiedCatalogueSnapshot(
        fingerprint=fingerprint,
        rules_in_declaration_order=frozen_rules,
        rule_ids_by_root_shape={key: tuple(value) for key, value in buckets.items()},
    )
    _SNAPSHOTS[fingerprint] = snapshot
    return snapshot


__all__ = [
    "CertifiedCatalogueSnapshot",
    "CompiledRule",
    "RootShape",
    "ShadowMatcherParityLedger",
    "StructuralMatcherParityCertificate",
    "build_certified_catalogue_snapshot",
    "load_structural_matcher_parity_certificate",
    "root_shape_for_term",
]
