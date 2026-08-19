"""Immutable, cheap-to-query views over already-certified MBA catalogues."""

from __future__ import annotations

import builtins
import dis
import hashlib
import json
import weakref
from collections import OrderedDict
from collections.abc import Iterable, Mapping
from dataclasses import dataclass, field
from pathlib import Path
from threading import RLock
from types import (
    BuiltinFunctionType,
    BuiltinMethodType,
    CodeType,
    MappingProxyType,
    ModuleType,
)
from d810.core.typing import Any, Protocol, TypeAlias
from d810.mba.certified_rule_compiler import CompiledMbaRule
from d810.mba.canonical_pattern import (
    CanonicalPatternMalformed,
    CanonicalPatternUnsupported,
    TRANSIENT_RULE_STATE_FIELDS,
    canonical_template_payload,
    compile_canonical_pattern,
)
from d810.mba.semantic_canonicalization import CANONICALIZER_SCHEMA_VERSION
from d810.mba.typed_term import TypedBvTerm, term_fingerprint


RootShape: TypeAlias = tuple[str | None, int, int]
class _CompiledRuleLike(Protocol):
    source_name: str
    aliases: tuple[str, ...]
    family: str
    pattern: object
    replacement: object
    proof_widths: tuple[int, ...]


CompiledRule: TypeAlias = CompiledMbaRule | _CompiledRuleLike


_SNAPSHOT_FINGERPRINT_VERSION = 5
_PARITY_CERTIFICATE_SCHEMA_VERSION = 3
_DIGEST_LENGTH = 64

# Retained only as a negative-test/compatibility sentinel. Possession of this
# importable object is deliberately not authorization.
_STRUCTURAL_RULE_ADMISSION_TOKEN = object()
_STRUCTURAL_PROOF_CACHE_CAPACITY = 256
_STRUCTURAL_PROOF_CACHE_LOCK = RLock()
_STRUCTURAL_PROOF_CACHE: OrderedDict[tuple[object, ...], bool] = OrderedDict()
_ADMITTED_STRUCTURAL_IDENTITIES: dict[
    int, tuple[weakref.ReferenceType[Any], tuple[object, ...]]
] = {}


def _is_exact_typed_term(term: object, active: set[int] | None = None) -> bool:
    if type(term) is not TypedBvTerm:
        return False
    active_ids = set() if active is None else active
    identity = id(term)
    if identity in active_ids:
        return False
    active_ids.add(identity)
    try:
        children = getattr(term, "children", None)
        return type(children) is tuple and all(
            _is_exact_typed_term(child, active_ids) for child in children
        )
    finally:
        active_ids.remove(identity)


def _fixed_rotate_identity(rule: object) -> tuple[object, ...]:
    """Validate and return the live identity of one fixed-rotate rule."""

    try:
        source_name = getattr(rule, "source_name")
        width = getattr(rule, "width")
        direction = getattr(rule, "direction")
        count = getattr(rule, "count")
        pattern = getattr(rule, "pattern")
        replacement = getattr(rule, "replacement")
        proof_verdict = getattr(rule, "proof_verdict")
        family = getattr(rule, "family")
        aliases = getattr(rule, "aliases")
        proof_widths = getattr(rule, "proof_widths")
        claimed_fingerprint = getattr(rule, "semantic_fingerprint")
    except Exception as exc:
        raise ValueError("structural rule fields are incomplete") from exc
    if type(source_name) is not str or not source_name:
        raise ValueError("structural rule source_name must be non-empty")
    if type(width) is not int or width not in {8, 16, 32, 64}:
        raise ValueError("structural rule width is unsupported")
    if type(direction) is not str or direction not in {"rol", "ror"}:
        raise ValueError("structural rule direction is unsupported")
    if type(count) is not int or not 1 <= count < width:
        raise ValueError("structural rule count is unsupported")
    if proof_verdict is not True:
        raise ValueError("structural rule proof_verdict must be true")
    if type(family) is not str or family != "fixed_rotate":
        raise ValueError("structural rule family is unsupported")
    if type(aliases) is not tuple or any(
        type(alias) is not str or not alias for alias in aliases
    ):
        raise ValueError("structural rule aliases are malformed")
    if type(proof_widths) is not tuple or proof_widths != (width,):
        raise ValueError("structural rule proof_widths are malformed")
    if not _is_exact_typed_term(pattern) or not _is_exact_typed_term(replacement):
        raise ValueError("structural rule terms must be exact TypedBvTerm values")
    if (
        type(pattern.operation) is not str
        or pattern.operation != "or"
        or pattern.width != width
        or pattern.value is not None
        or pattern.leaf_key is not None
        or pattern.shift_count is not None
        or len(pattern.children) != 2
    ):
        raise ValueError("structural rule pattern shape is unsupported")
    left, right = pattern.children
    first_operation, second_operation = (
        ("shl", "lshr") if direction == "rol" else ("lshr", "shl")
    )
    if (
        type(left.operation) is not str
        or type(right.operation) is not str
        or left.operation != first_operation
        or right.operation != second_operation
        or left.width != width
        or right.width != width
        or type(left.shift_count) is not int
        or type(right.shift_count) is not int
        or left.shift_count != count
        or right.shift_count != width - count
        or len(left.children) != 1
        or len(right.children) != 1
        or left.children[0] != right.children[0]
    ):
        raise ValueError("structural rule pattern is not complementary")
    if (
        type(replacement.operation) is not str
        or replacement.operation != direction
        or replacement.width != width
        or type(replacement.shift_count) is not int
        or replacement.shift_count != count
        or len(replacement.children) != 1
        or replacement.children[0] != left.children[0]
    ):
        raise ValueError("structural rule replacement shape is unsupported")
    try:
        from d810.mba.extension_api import structural_rule_semantic_fingerprint

        expected_fingerprint = structural_rule_semantic_fingerprint(rule)
    except Exception as exc:
        raise ValueError("structural rule fingerprint cannot be recomputed") from exc
    if type(claimed_fingerprint) is not str or claimed_fingerprint != expected_fingerprint:
        raise ValueError("structural rule semantic fingerprint is dishonest")
    return (
        family,
        source_name,
        width,
        direction,
        count,
        term_fingerprint(pattern),
        term_fingerprint(replacement),
        proof_verdict,
        proof_widths,
        aliases,
    )


def _enroll_structural_rule(
    rule: object, identity: tuple[object, ...] | None = None
) -> None:
    """Record exact live identity after a backend proof compiler admits it."""

    rule_id = id(rule)
    validated_identity = (
        _fixed_rotate_identity(rule) if identity is None else identity
    )

    def _cleanup(reference: weakref.ReferenceType[Any]) -> None:
        current = _ADMITTED_STRUCTURAL_IDENTITIES.get(rule_id)
        if current is not None and current[0] is reference:
            _ADMITTED_STRUCTURAL_IDENTITIES.pop(rule_id, None)

    try:
        reference = weakref.ref(rule, _cleanup)
    except TypeError as exc:
        raise TypeError("admitted structural rules must support weak references") from exc
    _ADMITTED_STRUCTURAL_IDENTITIES[rule_id] = (reference, validated_identity)


def _is_enrolled_structural_rule(rule: object) -> bool:
    """Return whether this exact live object was enrolled by a proof compiler."""

    rule_id = id(rule)
    record = _ADMITTED_STRUCTURAL_IDENTITIES.get(rule_id)
    if record is None or record[0]() is not rule:
        return False
    try:
        return _fixed_rotate_identity(rule) == record[1]
    except Exception:
        return False


def enroll_structural_rule(rule: object) -> None:
    """Enroll one proof-gated structural rule in the portable certificate set."""

    identity = _fixed_rotate_identity(rule)
    try:
        from d810.mba.extension_api import prove_typed_term_equivalence
    except Exception as exc:
        raise ValueError("structural rule proof authority unavailable") from exc
    cache_key = (prove_typed_term_equivalence, *identity[:7])
    with _STRUCTURAL_PROOF_CACHE_LOCK:
        cached_verdict = _STRUCTURAL_PROOF_CACHE.get(cache_key)
        if cached_verdict is not None:
            _STRUCTURAL_PROOF_CACHE.move_to_end(cache_key)
            if cached_verdict is not True:
                raise ValueError("structural rule proof failed")
            _enroll_structural_rule(rule, identity)
            return
    try:
        proof_verdict = prove_typed_term_equivalence(
            getattr(rule, "pattern"), getattr(rule, "replacement")
        )
    except Exception as exc:
        raise ValueError("structural rule proof failed") from exc
    with _STRUCTURAL_PROOF_CACHE_LOCK:
        _STRUCTURAL_PROOF_CACHE[cache_key] = proof_verdict is True
        _STRUCTURAL_PROOF_CACHE.move_to_end(cache_key)
        while len(_STRUCTURAL_PROOF_CACHE) > _STRUCTURAL_PROOF_CACHE_CAPACITY:
            _STRUCTURAL_PROOF_CACHE.popitem(last=False)
    if proof_verdict is not True:
        raise ValueError("structural rule proof failed")
    _enroll_structural_rule(rule, identity)


def is_enrolled_structural_rule(rule: object) -> bool:
    """Return whether this exact live structural rule was enrolled."""

    return _is_enrolled_structural_rule(rule)


def _is_sha256_digest(value: object) -> bool:
    return (
        isinstance(value, str)
        and len(value) == _DIGEST_LENGTH
        and all(character in "0123456789abcdef" for character in value)
    )


def _is_exact_zero(value: object) -> bool:
    """Accept only an integer zero for fail-closed evidence counters."""

    return type(value) is int and value == 0


def _is_exact_canonicalizer_schema(value: object) -> bool:
    """Accept only the exact integer canonicalizer schema version."""

    return type(value) is int and value == CANONICALIZER_SCHEMA_VERSION


@dataclass(frozen=True)
class CertifiedCatalogueSnapshot:
    fingerprint: str
    rules_in_declaration_order: tuple[CompiledRule, ...]
    rule_ids_by_root_shape: Mapping[RootShape, tuple[int, ...]]
    structural_authorizable: bool
    canonicalizer_schema_version: int = CANONICALIZER_SCHEMA_VERSION
    canonical_templates_by_rule_width: Mapping[
        tuple[int, int], Mapping[str, object]
    ] = field(default_factory=dict)
    canonical_status_by_rule_width: Mapping[tuple[int, int], str] = field(
        default_factory=dict
    )
    canonical_rule_ids_by_root_shape: Mapping[RootShape, tuple[int, ...]] = field(
        default_factory=dict
    )
    structural_rule_fingerprints: tuple[str, ...] = ()
    structural_rule_digest: str = ""
    # The backend-owned implementation boundary for the active matcher and
    # proof/emitter path. An empty value is retained for non-structural test
    # snapshots, but can never authorize a persisted structural certificate.
    runtime_semantics_digest: str = ""

    def __post_init__(self) -> None:
        object.__setattr__(
            self,
            "rule_ids_by_root_shape",
            MappingProxyType(dict(self.rule_ids_by_root_shape)),
        )
        if not _is_exact_canonicalizer_schema(self.canonicalizer_schema_version):
            raise ValueError("unsupported canonicalizer schema version")
        object.__setattr__(
            self,
            "canonical_templates_by_rule_width",
            MappingProxyType(
                {
                    key: MappingProxyType(dict(value))
                    for key, value in self.canonical_templates_by_rule_width.items()
                }
            ),
        )
        object.__setattr__(
            self,
            "canonical_status_by_rule_width",
            MappingProxyType(dict(self.canonical_status_by_rule_width)),
        )
        object.__setattr__(
            self,
            "canonical_rule_ids_by_root_shape",
            MappingProxyType(dict(self.canonical_rule_ids_by_root_shape)),
        )
        fingerprints = tuple(self.structural_rule_fingerprints)
        if any(type(item) is not str or not item for item in fingerprints):
            raise ValueError("structural_rule_fingerprints must contain strings")
        object.__setattr__(self, "structural_rule_fingerprints", fingerprints)
        if type(self.structural_rule_digest) is not str:
            raise ValueError("structural_rule_digest must be a string")
        if type(self.runtime_semantics_digest) is not str:
            raise ValueError("runtime_semantics_digest must be a string")
        if self.runtime_semantics_digest and not _is_sha256_digest(
            self.runtime_semantics_digest
        ):
            raise ValueError(
                "runtime_semantics_digest must be a lowercase SHA-256 digest"
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
    runtime_semantics_digest: str
    legacy_observation_count: int
    observation_count: int | None = None

    def __post_init__(self) -> None:
        if not _is_sha256_digest(self.corpus_digest):
            raise ValueError("corpus_digest must be a lowercase SHA-256 digest")
        if not _is_sha256_digest(self.toolchain_digest):
            raise ValueError("toolchain_digest must be a lowercase SHA-256 digest")
        if not _is_sha256_digest(self.runtime_semantics_digest):
            raise ValueError(
                "runtime_semantics_digest must be a lowercase SHA-256 digest"
            )
        if (
            type(self.legacy_observation_count) is not int
            or self.legacy_observation_count <= 0
        ):
            raise ValueError("legacy_observation_count must be positive")
        if self.observation_count is not None and (
            type(self.observation_count) is not int
            or self.observation_count <= 0
            or self.observation_count < self.legacy_observation_count
        ):
            raise ValueError(
                "observation_count must be positive and include legacy observations"
            )


@dataclass(frozen=True)
class StructuralMatcherParityCertificate:
    """Persisted native parity evidence for one matcher runtime and snapshot."""

    snapshot_fingerprint: str
    runtime_mode: str
    corpus_digest: str
    toolchain_digest: str
    runtime_semantics_digest: str
    legacy_observation_count: int
    canonicalizer_schema_version: int = CANONICALIZER_SCHEMA_VERSION
    observation_count: int | None = None
    legacy_rule_mismatches: int | None = None
    legacy_binding_mismatches: int | None = None
    legacy_binding_unknown: int | None = None
    new_safe_coverage_pending: int | None = None
    unsafe_mutations: int | None = None
    unproved_structural_replacements: int | None = None

    def authorizes(
        self,
        snapshot: CertifiedCatalogueSnapshot,
        runtime_mode: str,
        expectation: StructuralMatcherParityExpectation | None,
    ) -> bool:
        return (
            expectation is not None
            and snapshot.structural_authorizable is True
            and runtime_mode in {"python", "cython"}
            and self.snapshot_fingerprint == snapshot.fingerprint
            and self.runtime_mode == runtime_mode
            and self.corpus_digest == expectation.corpus_digest
            and self.toolchain_digest == expectation.toolchain_digest
            and _is_sha256_digest(self.runtime_semantics_digest)
            and _is_sha256_digest(snapshot.runtime_semantics_digest)
            and self.runtime_semantics_digest == expectation.runtime_semantics_digest
            and self.runtime_semantics_digest == snapshot.runtime_semantics_digest
            and type(self.legacy_observation_count) is int
            and type(expectation.legacy_observation_count) is int
            and self.legacy_observation_count == expectation.legacy_observation_count
            and expectation.observation_count is not None
            and type(expectation.observation_count) is int
            and self.observation_count == expectation.observation_count
            and type(self.observation_count) is int
            and self.observation_count >= self.legacy_observation_count
            and _is_exact_canonicalizer_schema(self.canonicalizer_schema_version)
            and _is_exact_canonicalizer_schema(
                snapshot.canonicalizer_schema_version
            )
            and self.canonicalizer_schema_version
            == snapshot.canonicalizer_schema_version
            and _is_exact_zero(self.legacy_rule_mismatches)
            and _is_exact_zero(self.legacy_binding_mismatches)
            and _is_exact_zero(self.legacy_binding_unknown)
            and _is_exact_zero(self.new_safe_coverage_pending)
            and _is_exact_zero(self.unsafe_mutations)
            and _is_exact_zero(self.unproved_structural_replacements)
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
    if (
        type(raw.get("schema_version")) is not int
        or raw.get("schema_version") != _PARITY_CERTIFICATE_SCHEMA_VERSION
    ):
        raise ValueError("structural parity certificate schema_version must be 3")
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
    runtime_semantics_digest = raw.get("runtime_semantics_digest")
    if not _is_sha256_digest(runtime_semantics_digest):
        raise ValueError(
            "structural parity certificate has invalid runtime_semantics_digest"
        )
    observation_count = raw.get("legacy_observation_count")
    if type(observation_count) is not int or observation_count <= 0:
        raise ValueError(
            "structural parity certificate needs positive legacy_observation_count"
        )
    total_observation_count = raw.get("observation_count")
    if (
        type(total_observation_count) is not int
        or total_observation_count <= 0
        or total_observation_count < observation_count
    ):
        raise ValueError(
            "structural parity certificate needs a complete positive observation_count"
        )
    for certificate_field in (
        "legacy_rule_mismatches",
        "legacy_binding_mismatches",
        "legacy_binding_unknown",
        "unsafe_mutations",
        "unproved_structural_replacements",
    ):
        if not _is_exact_zero(raw.get(certificate_field)):
            raise ValueError(
                f"structural parity certificate requires {certificate_field}=0"
            )
    if not _is_exact_zero(raw.get("new_safe_coverage_pending")):
        raise ValueError(
            "structural parity certificate requires new_safe_coverage_pending=0"
        )
    proven_coverage = raw.get("new_safe_coverage_proved")
    if type(proven_coverage) is not int or proven_coverage < 0:
        raise ValueError(
            "structural parity certificate has invalid new_safe_coverage_proved"
        )
    canonicalizer_version = raw.get("canonicalizer_schema_version")
    if not _is_exact_canonicalizer_schema(canonicalizer_version):
        raise ValueError(
            "structural parity certificate canonicalizer_schema_version must be 1"
        )
    return StructuralMatcherParityCertificate(
        snapshot_fingerprint=fingerprint,
        runtime_mode=runtime_mode,
        corpus_digest=corpus_digest,
        toolchain_digest=toolchain_digest,
        runtime_semantics_digest=runtime_semantics_digest,
        legacy_observation_count=observation_count,
        canonicalizer_schema_version=canonicalizer_version,
        observation_count=total_observation_count,
        legacy_rule_mismatches=raw["legacy_rule_mismatches"],
        legacy_binding_mismatches=raw["legacy_binding_mismatches"],
        legacy_binding_unknown=raw["legacy_binding_unknown"],
        new_safe_coverage_pending=raw["new_safe_coverage_pending"],
        unsafe_mutations=raw["unsafe_mutations"],
        unproved_structural_replacements=raw["unproved_structural_replacements"],
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
    new_safe_coverage_refused: int = 0
    unsafe_mutations: int = 0
    unproved_structural_replacements: int = 0

    def record(
        self,
        *,
        legacy_match: bool,
        structural_match: bool,
        same_rule: bool,
        same_bindings: bool | None,
        structural_proven: bool = False,
        structural_refused: bool = False,
    ) -> None:
        self.observation_count += 1
        if not legacy_match:
            # A structural-only hit is useful coverage evidence, but cannot
            # become a provider win during the shadow period. It remains
            # pending unless the adapter completes its proof-only native path.
            if structural_match:
                if structural_proven:
                    self.new_safe_coverage_proved += 1
                elif structural_refused:
                    self.new_safe_coverage_refused += 1
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


def make_structural_matcher_parity_certificate(
    *,
    snapshot: CertifiedCatalogueSnapshot,
    ledger: ShadowMatcherParityLedger,
    runtime_mode: str,
    corpus_digest: str,
    toolchain_digest: str,
    runtime_semantics_digest: str,
) -> dict[str, object]:
    """Render one reproducible certificate from completed parity evidence.

    This function deliberately refuses partial evidence.  The output is still
    data, not authorization: configuration must independently supply matching
    corpus/toolchain expectations before structural selection can activate.
    """

    if snapshot.structural_authorizable is not True:
        raise ValueError("structural parity certificate needs an authorizable snapshot")
    if runtime_mode not in {"python", "cython"}:
        raise ValueError("structural parity certificate has invalid runtime_mode")
    if not _is_sha256_digest(corpus_digest):
        raise ValueError("structural parity certificate has invalid corpus_digest")
    if not _is_sha256_digest(toolchain_digest):
        raise ValueError("structural parity certificate has invalid toolchain_digest")
    if not _is_sha256_digest(runtime_semantics_digest):
        raise ValueError(
            "structural parity certificate has invalid runtime_semantics_digest"
        )
    if snapshot.runtime_semantics_digest != runtime_semantics_digest:
        raise ValueError(
            "structural parity certificate runtime_semantics_digest does not match snapshot"
        )
    if not _is_exact_canonicalizer_schema(snapshot.canonicalizer_schema_version):
        raise ValueError(
            "structural parity certificate has invalid canonicalizer schema"
        )
    if type(ledger.legacy_match_count) is not int or ledger.legacy_match_count <= 0:
        raise ValueError(
            "structural parity certificate needs positive legacy_match_count"
        )
    if (
        type(ledger.observation_count) is not int
        or ledger.observation_count <= 0
        or type(ledger.legacy_match_count) is not int
        or ledger.observation_count < ledger.legacy_match_count
    ):
        raise ValueError(
            "structural parity certificate needs complete positive observation_count"
        )
    for ledger_field in (
        "legacy_rule_mismatches",
        "legacy_binding_mismatches",
        "legacy_binding_unknown",
        "new_safe_coverage_pending",
        "unsafe_mutations",
        "unproved_structural_replacements",
    ):
        if not _is_exact_zero(getattr(ledger, ledger_field)):
            raise ValueError(
                f"structural parity certificate requires {ledger_field}=0"
            )
    if (
        type(ledger.new_safe_coverage_proved) is not int
        or ledger.new_safe_coverage_proved < 0
    ):
        raise ValueError(
            "structural parity certificate has invalid new_safe_coverage_proved"
        )
    return {
        "schema_version": _PARITY_CERTIFICATE_SCHEMA_VERSION,
        "canonicalizer_schema_version": snapshot.canonicalizer_schema_version,
        "snapshot_fingerprint": snapshot.fingerprint,
        "runtime_mode": runtime_mode,
        "corpus_digest": corpus_digest,
        "toolchain_digest": toolchain_digest,
        "runtime_semantics_digest": runtime_semantics_digest,
        "legacy_observation_count": ledger.legacy_match_count,
        "observation_count": ledger.observation_count,
        "legacy_rule_mismatches": ledger.legacy_rule_mismatches,
        "legacy_binding_mismatches": ledger.legacy_binding_mismatches,
        "legacy_binding_unknown": ledger.legacy_binding_unknown,
        "new_safe_coverage_pending": ledger.new_safe_coverage_pending,
        "new_safe_coverage_proved": ledger.new_safe_coverage_proved,
        "unsafe_mutations": ledger.unsafe_mutations,
        "unproved_structural_replacements": ledger.unproved_structural_replacements,
    }


# Catalogue snapshots are immutable and keyed by their complete semantic
# fingerprint.  Keep only a small process-local working set: IDA sessions can
# reconfigure projects repeatedly, and retaining every historical configuration
# would make the memo itself an unbounded production-state leak.
_SNAPSHOT_MEMO_CAPACITY = 16
_SNAPSHOT_MEMO_LOCK = RLock()
_SNAPSHOTS: OrderedDict[str, CertifiedCatalogueSnapshot] = OrderedDict()


@dataclass
class _SemanticFingerprintState:
    """Carry fail-closed state through a recursive rule semantic encoding."""

    active_ids: set[int]
    structural_authorizable: bool = True

    def unavailable(self, value: object, reason: str) -> object:
        self.structural_authorizable = False
        return {
            "unavailable": {
                "reason": reason,
                "type": f"{type(value).__module__}.{type(value).__qualname__}",
            }
        }


def _rule_pattern(rule: CompiledRule) -> Any:
    value = getattr(rule, "pattern", None)
    return value() if callable(value) else value


def _code_semantic_value(value: CodeType, state: _SemanticFingerprintState) -> object:
    return {
        "code": value.co_code.hex(),
        "consts": tuple(_semantic_value(item, state) for item in value.co_consts),
        "names": value.co_names,
        "varnames": value.co_varnames,
    }


def _referenced_global_names(code: CodeType) -> tuple[str, ...] | None:
    """Return only global/builtin names actually loaded by executable code."""

    names: set[str] = set()
    pending = [code]
    while pending:
        current = pending.pop()
        try:
            for instruction in dis.get_instructions(current):
                if instruction.opname in {"LOAD_GLOBAL", "LOAD_NAME"} and isinstance(
                    instruction.argval, str
                ):
                    names.add(instruction.argval)
        except (TypeError, ValueError):
            # A malformed code object cannot be certified as an authorization
            # input. The caller marks the corresponding callable unavailable.
            return None
        pending.extend(
            constant for constant in current.co_consts if isinstance(constant, CodeType)
        )
    return tuple(sorted(names))


def _callable_global_values(
    function: object,
    code: CodeType,
    state: _SemanticFingerprintState,
) -> object:
    namespace = getattr(function, "__globals__", None)
    if not isinstance(namespace, Mapping):
        return state.unavailable(function, "callable_has_no_globals")
    builtin_namespace = namespace.get("__builtins__", builtins)
    if isinstance(builtin_namespace, ModuleType):
        builtin_namespace = vars(builtin_namespace)
    if not isinstance(builtin_namespace, Mapping):
        return state.unavailable(function, "callable_has_invalid_builtins")
    bindings: list[tuple[str, object]] = []
    names = _referenced_global_names(code)
    if names is None:
        return state.unavailable(function, "unreadable_callable_code")
    for name in names:
        if name in namespace:
            binding = namespace[name]
        elif name in builtin_namespace:
            binding = builtin_namespace[name]
        else:
            bindings.append((name, state.unavailable(function, "missing_global")))
            continue
        if _is_operational_d810_logger(binding):
            # Logging configuration carries locks, handlers, and verbosity state.
            # Rule hooks use the project logger only for diagnostics; treating that
            # mutable operational state as rewrite semantics would permanently deny
            # structural authorization to every otherwise-certified runtime rule.
            bindings.append((name, {"operational_logger": "d810"}))
            continue
        bindings.append((name, _semantic_value(binding, state)))
    return tuple(bindings)


def _is_operational_d810_logger(value: object) -> bool:
    """Recognize only D810's concrete diagnostic logger as non-semantic state."""

    logger_type = type(value)
    return (
        logger_type.__module__ == "d810.core.logging"
        and logger_type.__qualname__ == "D810Logger"
    )


def _semantic_value(
    value: object,
    state: _SemanticFingerprintState | None = None,
) -> object:
    """Return a deterministic representation of one rule semantic input.

    Rule objects use small DSL trees plus closures for constraints and dynamic
    constants.  ``repr`` alone loses closure state and function bodies, so a
    snapshot must recursively include both. Unknown values make structural
    authorization fail closed rather than contributing unstable object identity.
    """

    state = state or _SemanticFingerprintState(active_ids=set())
    if value is None or isinstance(value, (bool, int, float, str)):
        return value
    if isinstance(value, bytes):
        return {"bytes": value.hex()}
    identity = id(value)
    if identity in state.active_ids:
        return state.unavailable(value, "cyclic_semantic_input")
    state.active_ids.add(identity)
    try:
        try:
            return _semantic_value_inner(value, state)
        except Exception:
            return state.unavailable(value, "semantic_encoding_error")
    finally:
        state.active_ids.discard(identity)


def _semantic_value_inner(value: object, state: _SemanticFingerprintState) -> object:
    if isinstance(value, CodeType):
        return _code_semantic_value(value, state)
    if isinstance(value, property):
        return {
            "property": {
                "get": _semantic_value(value.fget, state),
                "set": _semantic_value(value.fset, state),
                "delete": _semantic_value(value.fdel, state),
            }
        }
    if isinstance(value, Mapping):
        entries = tuple(
            (_semantic_value(key, state), _semantic_value(item, state))
            for key, item in value.items()
            if not (type(key) is str and key in TRANSIENT_RULE_STATE_FIELDS)
        )
        return {
            "mapping": tuple(
                sorted(
                    entries,
                    key=lambda item: json.dumps(
                        item[0], ensure_ascii=True, separators=(",", ":"), sort_keys=True
                    ),
                )
            )
        }
    if isinstance(value, (tuple, list, set, frozenset)):
        items = tuple(_semantic_value(item, state) for item in value)
        if isinstance(value, (set, frozenset)):
            items = tuple(
                sorted(
                    items,
                    key=lambda item: json.dumps(
                        item, ensure_ascii=True, separators=(",", ":"), sort_keys=True
                    ),
                )
            )
        return {"sequence": items}
    if callable(value):
        function = getattr(value, "__func__", value)
        code = getattr(function, "__code__", None)
        closure = getattr(function, "__closure__", None)
        if not isinstance(code, CodeType):
            if isinstance(function, (BuiltinFunctionType, BuiltinMethodType, type)):
                return {
                    "builtin_callable": (
                        f"{getattr(function, '__module__', '')}."
                        f"{getattr(function, '__qualname__', type(function).__qualname__)}"
                    )
                }
            return state.unavailable(function, "callable_has_no_code")
        return {
            "callable": f"{getattr(function, '__module__', '')}."
            f"{getattr(function, '__qualname__', type(function).__qualname__)}",
            "code": _code_semantic_value(code, state),
            "globals": _callable_global_values(function, code, state),
            "defaults": _semantic_value(getattr(function, "__defaults__", None), state),
            "kwdefaults": _semantic_value(
                getattr(function, "__kwdefaults__", None), state
            ),
            "closure": tuple(
                _semantic_value(cell.cell_contents, state) for cell in closure or ()
            ),
        }
    attributes = getattr(value, "__dict__", None)
    if isinstance(attributes, dict):
        return {
            "object": f"{type(value).__module__}.{type(value).__qualname__}",
            "attributes": _semantic_value(attributes, state),
        }
    return state.unavailable(value, "unserializable_semantic_input")


def _implementation_identity(
    rule: CompiledRule, state: _SemanticFingerprintState
) -> tuple[object, ...]:
    """Fingerprint runtime hooks that can change match/materialization semantics."""

    implementation_owner = getattr(rule, "rule_type", type(rule))
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
        implementation = getattr(implementation_owner, name, None)
        identities.append((name, _semantic_value(implementation, state)))
    return tuple(identities)


def _rule_semantic_attribute(
    rule: CompiledRule,
    name: str,
    default: object,
) -> object:
    """Read an admitted rule field from its wrapper or rule implementation."""

    value = getattr(rule, name, None)
    if value is None and name == "constraints":
        value = getattr(rule, "CONSTRAINTS", None)
    if value is not None:
        return value
    owner = getattr(rule, "rule_type", type(rule))
    if name == "constraints":
        value = getattr(owner, "CONSTRAINTS", None)
        if value is not None:
            return value
    return getattr(owner, name, default)


def _rule_identity(
    rule: CompiledRule, state: _SemanticFingerprintState
) -> tuple[object, ...]:
    pattern = _rule_pattern(rule)
    rule_type = getattr(rule, "rule_type", type(rule))
    return (
        _rule_family(rule),
        str(
            getattr(rule, "source_name", getattr(rule, "name", type(rule).__qualname__))
        ),
        f"{getattr(rule_type, '__module__', type(rule_type).__module__)}."
        f"{getattr(rule_type, '__qualname__', type(rule_type).__qualname__)}",
        _semantic_value(_rule_semantic_attribute(rule, "proof_widths", ()), state),
        _semantic_value(pattern, state),
        _semantic_value(getattr(rule, "replacement", None), state),
        _semantic_value(_rule_semantic_attribute(rule, "constraints", ()), state),
        _semantic_value(_rule_semantic_attribute(rule, "DYNAMIC_CONSTS", {}), state),
        _semantic_value(_rule_semantic_attribute(rule, "CONTEXT_VARS", {}), state),
        _semantic_value(
            _rule_semantic_attribute(rule, "UPDATE_DESTINATION", None), state
        ),
        _semantic_value(_rule_semantic_attribute(rule, "BIT_WIDTH", None), state),
        _semantic_value(getattr(rule, "config", {}), state),
        _implementation_identity(rule, state),
        _semantic_value(getattr(rule, "aliases", ()), state),
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
    structural_rules: Iterable[object] = (),
    runtime_semantics_digest: str | None = None,
) -> CertifiedCatalogueSnapshot:
    """Freeze already-admitted rules; never compile or verify inside this API."""

    if type(compiler_version) is not str or not compiler_version:
        raise ValueError("compiler_version must be non-empty")
    if runtime_semantics_digest is not None and not _is_sha256_digest(
        runtime_semantics_digest
    ):
        raise ValueError(
            "runtime_semantics_digest must be a lowercase SHA-256 digest"
        )
    active_runtime_semantics_digest = runtime_semantics_digest or ""
    all_rules = tuple(rules)
    families = None if enabled_families is None else tuple(enabled_families)
    enabled = None if families is None else frozenset(families)
    frozen_rules = tuple(
        rule for rule in all_rules if enabled is None or _rule_family(rule) in enabled
    )
    structural_rule_list = tuple(structural_rules)
    structural_rule_payload: list[object] = []
    structural_rule_fingerprints: list[str] = []
    structural_authorizable = True
    if structural_rule_list and not _is_sha256_digest(
        active_runtime_semantics_digest
    ):
        structural_authorizable = False
    if structural_rule_list:
        for structural_rule in structural_rule_list:
            # Keep the portable catalogue independent of the backend that
            # supplies structural rules.  The production builder passes only
            # the immutable, proof-gated inventory; the structural artifact's
            # stable fields are the authorization boundary here.  Backend
            # identity/enrollment remains enforced by its own matcher before
            # a rule can be applied.
            source_name = getattr(structural_rule, "source_name", None)
            width = getattr(structural_rule, "width", None)
            direction = getattr(structural_rule, "direction", None)
            count = getattr(structural_rule, "count", None)
            proof_verdict = getattr(structural_rule, "proof_verdict", None)
            family = getattr(structural_rule, "family", None)
            semantic_fingerprint = getattr(
                structural_rule, "semantic_fingerprint", None
            )
            admitted = (
                _is_enrolled_structural_rule(structural_rule)
                and type(source_name) is str
                and bool(source_name)
                and type(width) is int
                and type(direction) is str
                and type(count) is int
                and proof_verdict is True
                and type(family) is str
                and type(semantic_fingerprint) is str
                and bool(semantic_fingerprint)
            )
            if not admitted:
                structural_authorizable = False
                structural_rule_payload.append(
                    {
                        "status": "unavailable",
                        "reason": "structural_rule_not_admitted",
                        "type": (
                            f"{type(structural_rule).__module__}."
                            f"{type(structural_rule).__qualname__}"
                        ),
                    }
                )
                continue
            structural_rule_payload.append(
                {
                    "source_name": source_name,
                    "width": width,
                    "direction": direction,
                    "count": count,
                    "proof_verdict": proof_verdict,
                    "family": family,
                    "semantic_fingerprint": semantic_fingerprint,
                }
            )
            structural_rule_fingerprints.append(semantic_fingerprint)
    structural_rule_fingerprints_tuple = tuple(structural_rule_fingerprints)
    structural_rule_digest = hashlib.sha256(
        json.dumps(
            tuple(structural_rule_payload),
            ensure_ascii=True,
            separators=(",", ":"),
            sort_keys=True,
        ).encode("ascii")
    ).hexdigest()
    semantic_state = _SemanticFingerprintState(active_ids=set())
    canonical_templates: dict[tuple[int, int], Mapping[str, object]] = {}
    canonical_statuses: dict[tuple[int, int], str] = {}
    canonical_root_buckets: dict[RootShape, list[int]] = {}
    canonical_rule_payloads: list[
        tuple[object, tuple[object, ...], tuple[Mapping[str, object], ...]]
    ] = []
    for rule_id, rule in enumerate(frozen_rules):
        width_templates: list[object] = []
        width_statuses: list[Mapping[str, object]] = []
        for width in widths:
            try:
                compiled_pattern = compile_canonical_pattern(
                    rule,
                    width=width,
                    declaration_index=rule_id,
                )
            except CanonicalPatternUnsupported:
                # Unsupported DSL operations are intentionally legacy-eligible;
                # they do not make the supported canonical snapshot opaque.
                canonical_statuses[(rule_id, width)] = "unsupported"
                width_statuses.append({"width": width, "status": "unsupported"})
                continue
            except CanonicalPatternMalformed:
                # Malformed/opaque DSL cannot authorize a structural snapshot;
                # preserve the legacy rule identity while rejecting activation.
                semantic_state.structural_authorizable = False
                canonical_statuses[(rule_id, width)] = "opaque"
                width_statuses.append({"width": width, "status": "opaque"})
                continue
            except (TypeError, ValueError):
                # A malformed or opaque rule semantic cannot authorize a
                # canonical structural snapshot.  Keep its legacy identity in
                # the payload so the resulting digest still changes.
                semantic_state.structural_authorizable = False
                canonical_statuses[(rule_id, width)] = "opaque"
                width_statuses.append({"width": width, "status": "opaque"})
                continue
            fragment = canonical_template_payload(compiled_pattern)
            canonical_templates[(rule_id, width)] = fragment
            canonical_statuses[(rule_id, width)] = "eligible"
            width_templates.append(fragment)
            width_statuses.append({"width": width, "status": "eligible"})
            canonical_root_buckets.setdefault(
                (
                    compiled_pattern.pattern_term.operation,
                    width,
                    len(compiled_pattern.pattern_term.children),
                ),
                [],
            ).append(rule_id)
        canonical_rule_payloads.append(
            (
                _rule_identity(rule, semantic_state),
                tuple(width_templates),
                tuple(width_statuses),
            )
        )
    payload = {
        "snapshot_fingerprint_version": _SNAPSHOT_FINGERPRINT_VERSION,
        "canonicalizer_schema_version": CANONICALIZER_SCHEMA_VERSION,
        "compiler_version": compiler_version,
        "widths": tuple(widths),
        "enabled_families": families,
        "rules": tuple(canonical_rule_payloads),
        "structural_authorizable": (
            semantic_state.structural_authorizable and structural_authorizable
        ),
        "structural_rules": tuple(structural_rule_payload),
        "structural_rule_digest": structural_rule_digest,
        "runtime_semantics_digest": active_runtime_semantics_digest,
    }
    encoded = json.dumps(
        payload, ensure_ascii=True, separators=(",", ":"), sort_keys=True
    )
    fingerprint = hashlib.sha256(encoded.encode("ascii")).hexdigest()
    with _SNAPSHOT_MEMO_LOCK:
        cached = _SNAPSHOTS.get(fingerprint)
        if cached is not None:
            _SNAPSHOTS.move_to_end(fingerprint)
            return cached
    buckets: dict[RootShape, list[int]] = {}
    for rule_id, rule in enumerate(frozen_rules):
        for width in widths:
            buckets.setdefault(_root_shape(rule, width), []).append(rule_id)
    snapshot = CertifiedCatalogueSnapshot(
        fingerprint=fingerprint,
        rules_in_declaration_order=frozen_rules,
        rule_ids_by_root_shape={key: tuple(value) for key, value in buckets.items()},
        structural_authorizable=(
            semantic_state.structural_authorizable and structural_authorizable
        ),
        canonicalizer_schema_version=CANONICALIZER_SCHEMA_VERSION,
        canonical_templates_by_rule_width=canonical_templates,
        canonical_status_by_rule_width=canonical_statuses,
        canonical_rule_ids_by_root_shape={
            key: tuple(value) for key, value in canonical_root_buckets.items()
        },
        structural_rule_fingerprints=structural_rule_fingerprints_tuple,
        structural_rule_digest=structural_rule_digest,
        runtime_semantics_digest=active_runtime_semantics_digest,
    )
    with _SNAPSHOT_MEMO_LOCK:
        # Another thread may have completed the same immutable snapshot while
        # this thread was compiling its canonical views.  Reuse that instance
        # so identity memoization remains stable under concurrent callers.
        cached = _SNAPSHOTS.get(fingerprint)
        if cached is not None:
            _SNAPSHOTS.move_to_end(fingerprint)
            return cached
        _SNAPSHOTS[fingerprint] = snapshot
        _SNAPSHOTS.move_to_end(fingerprint)
        while len(_SNAPSHOTS) > _SNAPSHOT_MEMO_CAPACITY:
            _SNAPSHOTS.popitem(last=False)
    return snapshot


__all__ = [
    "CertifiedCatalogueSnapshot",
    "CompiledRule",
    "RootShape",
    "ShadowMatcherParityLedger",
    "StructuralMatcherParityCertificate",
    "StructuralMatcherParityExpectation",
    "build_certified_catalogue_snapshot",
    "enroll_structural_rule",
    "is_enrolled_structural_rule",
    "load_structural_matcher_parity_certificate",
    "make_structural_matcher_parity_certificate",
    "root_shape_for_term",
]
