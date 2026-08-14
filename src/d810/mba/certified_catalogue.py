"""Immutable, cheap-to-query views over already-certified MBA catalogues."""

from __future__ import annotations

import hashlib
import json
from types import CodeType
from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from pathlib import Path
from types import MappingProxyType
from d810.core.typing import Any, TypeAlias
from d810.mba.typed_term import TypedBvTerm


RootShape: TypeAlias = tuple[str | None, int, int]
CompiledRule: TypeAlias = Any


_SNAPSHOT_FINGERPRINT_VERSION = 2
_PARITY_CERTIFICATE_SCHEMA_VERSION = 2
_DIGEST_LENGTH = 64


def _is_sha256_digest(value: object) -> bool:
    return (
        isinstance(value, str)
        and len(value) == _DIGEST_LENGTH
        and all(character in "0123456789abcdef" for character in value)
    )


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
class StructuralMatcherParityExpectation:
    """The exact corpus/toolchain coverage a certificate must attest to.

    This is supplied by the explicitly enabled experiment configuration, not
    inferred from a certificate.  A persisted certificate is evidence only; it
    cannot select the corpus, toolchain, or coverage it is allowed to unlock.
    """

    corpus_digest: str
    toolchain_digest: str
    legacy_observation_count: int

    def __post_init__(self) -> None:
        if not _is_sha256_digest(self.corpus_digest):
            raise ValueError("corpus_digest must be a lowercase SHA-256 digest")
        if not _is_sha256_digest(self.toolchain_digest):
            raise ValueError("toolchain_digest must be a lowercase SHA-256 digest")
        if (
            type(self.legacy_observation_count) is not int
            or self.legacy_observation_count <= 0
        ):
            raise ValueError("legacy_observation_count must be positive")


@dataclass(frozen=True)
class StructuralMatcherParityCertificate:
    """Persisted native parity evidence for one matcher runtime and snapshot."""

    snapshot_fingerprint: str
    runtime_mode: str
    corpus_digest: str
    toolchain_digest: str
    legacy_observation_count: int

    def authorizes(
        self,
        snapshot: CertifiedCatalogueSnapshot,
        runtime_mode: str,
        expectation: StructuralMatcherParityExpectation | None,
    ) -> bool:
        return (
            expectation is not None
            and self.snapshot_fingerprint == snapshot.fingerprint
            and self.runtime_mode == runtime_mode
            and self.corpus_digest == expectation.corpus_digest
            and self.toolchain_digest == expectation.toolchain_digest
            and self.legacy_observation_count == expectation.legacy_observation_count
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
    if raw.get("schema_version") != _PARITY_CERTIFICATE_SCHEMA_VERSION:
        raise ValueError("structural parity certificate schema_version must be 2")
    fingerprint = raw.get("snapshot_fingerprint")
    if not _is_sha256_digest(fingerprint):
        raise ValueError(
            "structural parity certificate has invalid snapshot_fingerprint"
        )
    runtime_mode = raw.get("runtime_mode")
    if runtime_mode not in {"python", "cython"}:
        raise ValueError("structural parity certificate has invalid runtime_mode")
    corpus_digest = raw.get("corpus_digest")
    if not _is_sha256_digest(corpus_digest):
        raise ValueError("structural parity certificate has invalid corpus_digest")
    toolchain_digest = raw.get("toolchain_digest")
    if not _is_sha256_digest(toolchain_digest):
        raise ValueError("structural parity certificate has invalid toolchain_digest")
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
    if raw.get("new_safe_coverage_pending") != 0:
        raise ValueError(
            "structural parity certificate requires new_safe_coverage_pending=0"
        )
    proven_coverage = raw.get("new_safe_coverage_proved")
    if type(proven_coverage) is not int or proven_coverage < 0:
        raise ValueError(
            "structural parity certificate has invalid new_safe_coverage_proved"
        )
    return StructuralMatcherParityCertificate(
        snapshot_fingerprint=fingerprint,
        runtime_mode=runtime_mode,
        corpus_digest=corpus_digest,
        toolchain_digest=toolchain_digest,
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


def _semantic_value(value: object) -> object:
    """Return a deterministic representation of one rule semantic input.

    Rule objects use small DSL trees plus closures for constraints and dynamic
    constants.  ``repr`` alone loses closure state and function bodies, so a
    snapshot must recursively include both.  Unknown values remain fail-closed
    by carrying their type and representation into the fingerprint.
    """

    if value is None or isinstance(value, (bool, int, float, str)):
        return value
    if isinstance(value, bytes):
        return {"bytes": value.hex()}
    if isinstance(value, CodeType):
        return {
            "code": value.co_code.hex(),
            "consts": tuple(_semantic_value(item) for item in value.co_consts),
            "names": value.co_names,
            "varnames": value.co_varnames,
        }
    if isinstance(value, property):
        return {
            "property": {
                "get": _semantic_value(value.fget),
                "set": _semantic_value(value.fset),
                "delete": _semantic_value(value.fdel),
            }
        }
    if isinstance(value, Mapping):
        return {
            "mapping": tuple(
                (str(key), _semantic_value(item))
                for key, item in sorted(value.items(), key=lambda item: str(item[0]))
            )
        }
    if isinstance(value, (tuple, list, set, frozenset)):
        items = tuple(_semantic_value(item) for item in value)
        if isinstance(value, (set, frozenset)):
            items = tuple(sorted(items, key=repr))
        return {"sequence": items}
    if callable(value):
        function = getattr(value, "__func__", value)
        code = getattr(function, "__code__", None)
        closure = getattr(function, "__closure__", None)
        return {
            "callable": f"{getattr(function, '__module__', '')}."
            f"{getattr(function, '__qualname__', type(function).__qualname__)}",
            "code": _semantic_value(code) if code is not None else None,
            "defaults": _semantic_value(getattr(function, "__defaults__", None)),
            "kwdefaults": _semantic_value(
                getattr(function, "__kwdefaults__", None)
            ),
            "closure": tuple(
                _semantic_value(cell.cell_contents) for cell in closure or ()
            ),
        }
    attributes = getattr(value, "__dict__", None)
    if isinstance(attributes, dict):
        return {
            "object": f"{type(value).__module__}.{type(value).__qualname__}",
            "attributes": _semantic_value(attributes),
        }
    return {"object": f"{type(value).__module__}.{type(value).__qualname__}", "repr": repr(value)}


def _implementation_identity(rule: CompiledRule) -> tuple[object, ...]:
    """Fingerprint runtime hooks that can change match/materialization semantics."""

    names = (
        "pattern",
        "replacement",
        "check_candidate",
        "check_runtime_constraints",
        "get_constraints",
        "get_replacement",
    )
    identities: list[object] = []
    for name in names:
        implementation = getattr(type(rule), name, None)
        identities.append((name, _semantic_value(implementation)))
    return tuple(identities)


def _rule_identity(rule: CompiledRule) -> tuple[object, ...]:
    pattern = _rule_pattern(rule)
    return (
        _rule_family(rule),
        str(
            getattr(rule, "source_name", getattr(rule, "name", type(rule).__qualname__))
        ),
        _semantic_value(pattern),
        _semantic_value(getattr(rule, "replacement", None)),
        _semantic_value(getattr(rule, "CONSTRAINTS", ())),
        _semantic_value(getattr(rule, "DYNAMIC_CONSTS", {})),
        _semantic_value(getattr(rule, "CONTEXT_VARS", {})),
        _semantic_value(getattr(rule, "UPDATE_DESTINATION", None)),
        _semantic_value(getattr(rule, "BIT_WIDTH", None)),
        _implementation_identity(rule),
        _semantic_value(getattr(rule, "aliases", ())),
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
        "snapshot_fingerprint_version": _SNAPSHOT_FINGERPRINT_VERSION,
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
    "StructuralMatcherParityExpectation",
    "build_certified_catalogue_snapshot",
    "load_structural_matcher_parity_certificate",
    "root_shape_for_term",
]
