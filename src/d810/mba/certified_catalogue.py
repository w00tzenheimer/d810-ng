"""Immutable, cheap-to-query views over already-certified MBA catalogues."""

from __future__ import annotations

import hashlib
import json
from collections.abc import Iterable, Mapping
from dataclasses import dataclass
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


@dataclass
class ShadowMatcherParityLedger:
    """Configuration-scoped evidence for legacy-to-structural parity."""

    observation_count: int = 0
    legacy_match_count: int = 0
    legacy_rule_mismatches: int = 0
    legacy_binding_mismatches: int = 0
    legacy_binding_unknown: int = 0

    def record(
        self,
        *,
        legacy_match: bool,
        structural_match: bool,
        same_rule: bool,
        same_bindings: bool | None,
    ) -> None:
        self.observation_count += 1
        if not legacy_match:
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
    "build_certified_catalogue_snapshot",
    "root_shape_for_term",
]
