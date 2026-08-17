#!/usr/bin/env python3
"""Render a fail-closed certificate from persisted parity and capture evidence."""

from __future__ import annotations

import argparse
import hashlib
import json
import math
import sys
from collections.abc import Mapping, Sequence
from pathlib import Path

from d810.mba.certified_catalogue import (
    CertifiedCatalogueSnapshot,
    ShadowMatcherParityLedger,
    make_structural_matcher_parity_certificate,
)
from d810.mba.differential_report import report_from_dict
from d810.mba.provider_outcome import MbaProviderKind
from d810.mba.semantic_canonicalization import CANONICALIZER_SCHEMA_VERSION


_DIGEST_LENGTH = 64
_RUNTIME_MODES = frozenset(("python", "cython"))
_REPO_ROOT = Path(__file__).resolve().parents[2]
_MANIFEST = _REPO_ROOT / "tests/fixtures/mba_portfolio/compiler_shapes.json"
_EXPECTED_CAPTURE_SCHEMA_VERSION = 1
_EXPECTED_CASE_COUNT = 76
_EXPECTED_CORPUS_IDENTITY = "mba-compiler-shapes-native"
_EXPECTED_PROVIDERS = tuple(MbaProviderKind)


def _load_json(path: Path) -> object:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ValueError(f"{path}: cannot load JSON: {exc}") from exc


def _file_digest(path: Path) -> str:
    try:
        return hashlib.sha256(path.read_bytes()).hexdigest()
    except OSError as exc:
        raise ValueError(f"{path}: cannot read manifest: {exc}") from exc


def _canonical_toolchain_digest(path: Path) -> str:
    toolchain = _load_json(path)
    if not isinstance(toolchain, Mapping):
        raise ValueError("toolchain document must be a JSON object")
    try:
        encoded = json.dumps(
            toolchain,
            allow_nan=False,
            ensure_ascii=True,
            separators=(",", ":"),
            sort_keys=True,
        ).encode("utf-8")
    except (TypeError, ValueError) as exc:
        raise ValueError(f"{path}: invalid toolchain document: {exc}") from exc
    return hashlib.sha256(encoded).hexdigest()


def _canonical_json_digest(value: object) -> str:
    try:
        encoded = json.dumps(
            value,
            allow_nan=False,
            ensure_ascii=True,
            separators=(",", ":"),
            sort_keys=True,
        ).encode("utf-8")
    except (TypeError, ValueError) as exc:
        raise ValueError(f"cannot derive canonical JSON digest: {exc}") from exc
    return hashlib.sha256(encoded).hexdigest()


def _manifest_contract() -> tuple[dict[str, str], str]:
    manifest = _load_json(_MANIFEST)
    if not isinstance(manifest, Mapping):
        raise ValueError("compiler-shape manifest must be an object")
    cases = manifest.get("cases")
    if not isinstance(cases, Sequence) or isinstance(cases, (str, bytes)):
        raise ValueError("compiler-shape manifest cases must be a sequence")
    case_strata: dict[str, str] = {}
    for case in cases:
        if not isinstance(case, Mapping):
            raise ValueError("compiler-shape manifest cases must be objects")
        case_id = case.get("case_id")
        stratum = case.get("stratum")
        if type(case_id) is not str or not case_id:
            raise ValueError("compiler-shape manifest case_id must be non-empty")
        if type(stratum) is not str or not stratum:
            raise ValueError(f"manifest case {case_id} has invalid stratum")
        if case_id in case_strata:
            raise ValueError(f"compiler-shape manifest has duplicate case_id {case_id}")
        case_strata[case_id] = stratum
    if len(case_strata) != _EXPECTED_CASE_COUNT:
        raise ValueError(
            "compiler-shape manifest must contain exactly "
            f"{_EXPECTED_CASE_COUNT} unique cases"
        )
    return case_strata, _file_digest(_MANIFEST)


def _is_sha256_digest(value: object) -> bool:
    return (
        type(value) is str
        and len(value) == _DIGEST_LENGTH
        and all(character in "0123456789abcdef" for character in value)
    )


def _evidence_snapshot(value: object) -> CertifiedCatalogueSnapshot:
    if not isinstance(value, Mapping):
        raise ValueError("parity evidence snapshot must be an object")
    fingerprint = value.get("fingerprint")
    authorizable = value.get("structural_authorizable")
    if not _is_sha256_digest(fingerprint) or type(authorizable) is not bool:
        raise ValueError("parity evidence snapshot is incomplete")
    if "canonicalizer_schema_version" not in value:
        raise ValueError(
            "parity evidence snapshot requires canonicalizer_schema_version"
        )
    canonicalizer_version = value["canonicalizer_schema_version"]
    if (
        type(canonicalizer_version) is not int
        or canonicalizer_version != CANONICALIZER_SCHEMA_VERSION
    ):
        raise ValueError("parity evidence snapshot has invalid canonicalizer schema")
    return CertifiedCatalogueSnapshot(
        fingerprint=fingerprint,
        rules_in_declaration_order=(),
        rule_ids_by_root_shape={},
        structural_authorizable=authorizable,
        canonicalizer_schema_version=canonicalizer_version,
    )


def _evidence_ledger(value: object) -> ShadowMatcherParityLedger:
    if not isinstance(value, Mapping):
        raise ValueError("parity evidence ledger must be an object")
    unknowns_alias = value.get("legacy_binding_unknowns")
    unknown = value.get("legacy_binding_unknown")
    if "legacy_binding_unknowns" in value:
        if "legacy_binding_unknown" in value and unknowns_alias != unknown:
            raise ValueError(
                "parity evidence ledger has conflicting legacy_binding_unknowns"
            )
        if type(unknowns_alias) is not int:
            raise ValueError("legacy_binding_unknowns must be an integer")
        if unknowns_alias != 0:
            raise ValueError(
                "structural parity certificate requires legacy_binding_unknowns=0"
            )
        unknown = unknowns_alias
    fields = (
        "observation_count",
        "legacy_match_count",
        "legacy_rule_mismatches",
        "legacy_binding_mismatches",
        "legacy_binding_unknown",
        "new_safe_coverage_pending",
        "new_safe_coverage_proved",
        "unsafe_mutations",
        "unproved_structural_replacements",
    )
    normalized = dict(value)
    if unknown is not None:
        normalized["legacy_binding_unknown"] = unknown
    missing = tuple(field for field in fields if field not in normalized)
    if missing:
        raise ValueError(
            "parity evidence ledger is incomplete: missing " + ", ".join(missing)
        )
    invalid = tuple(field for field in fields if type(normalized[field]) is not int)
    if invalid:
        raise ValueError(
            "parity evidence ledger requires integer fields: " + ", ".join(invalid)
        )
    return ShadowMatcherParityLedger(**{field: normalized[field] for field in fields})


def build_certificate(
    evidence: object,
    *,
    manifest: Path,
    toolchain: Path,
) -> dict[str, object]:
    """Bind completed parity evidence to exact corpus and toolchain inputs."""

    if not isinstance(evidence, Mapping):
        raise ValueError("parity evidence must be a JSON object")
    runtime_mode = evidence.get("runtime_mode")
    if runtime_mode not in {"python", "cython"}:
        raise ValueError("parity evidence has invalid runtime_mode")
    return make_structural_matcher_parity_certificate(
        snapshot=_evidence_snapshot(evidence.get("snapshot")),
        ledger=_evidence_ledger(evidence.get("ledger")),
        runtime_mode=runtime_mode,
        corpus_digest=_file_digest(manifest),
        toolchain_digest=_canonical_toolchain_digest(toolchain),
    )


def _capture_digest_claims(value: Mapping[str, object], field: str) -> tuple[str, ...]:
    aliases = (
        field,
        "manifest_digest",
        "corpus_fingerprint",
    ) if field == "corpus_digest" else (
        field,
        "toolchain_fingerprint",
    )
    claims: list[str] = []
    locations = (
        ("top-level", value),
        ("capture", value.get("capture")),
        ("capture_metadata", value.get("capture_metadata")),
    )
    for location_name, document in locations:
        if not isinstance(document, Mapping):
            continue
        for alias in aliases:
            candidate = document.get(alias)
            if candidate is None:
                continue
            if not _is_sha256_digest(candidate):
                raise ValueError(f"capture artifact has invalid {field} at {location_name}")
            claims.append(candidate)
    if len(set(claims)) > 1:
        raise ValueError(f"capture artifact has conflicting {field} claims")
    return tuple(claims)


def _capture_runtime(value: Mapping[str, object], *, runtime_mode: str) -> str:
    claims: list[str] = []
    direct = value.get("runtime_mode")
    if direct is not None:
        claims.append(direct)
    toolchain = value.get("toolchain_identity")
    if isinstance(toolchain, Mapping):
        matcher_backend = toolchain.get("matcher_backend")
        if matcher_backend is not None:
            claims.append(matcher_backend)
    metadata = value.get("capture_metadata")
    if isinstance(metadata, Mapping) and metadata.get("runtime_mode") is not None:
        claims.append(metadata["runtime_mode"])
    if not claims:
        raise ValueError("capture artifact requires runtime_mode")
    if any(type(claim) is not str or claim not in _RUNTIME_MODES for claim in claims):
        raise ValueError("capture artifact has invalid runtime_mode")
    if len(set(claims)) != 1 or claims[0] != runtime_mode:
        raise ValueError("capture artifact runtime_mode does not match runtime")
    return claims[0]


def _capture_bindings(
    value: object, *, runtime_mode: str
) -> tuple[str, str, int, int, frozenset[str]]:
    if not isinstance(value, Mapping):
        raise ValueError("capture artifact must be an object")
    if runtime_mode not in _RUNTIME_MODES:
        raise ValueError("invalid runtime_mode")
    schema_version = value.get("schema_version")
    if type(schema_version) is not int or schema_version != _EXPECTED_CAPTURE_SCHEMA_VERSION:
        raise ValueError("capture artifact schema_version must be 1")
    _capture_runtime(value, runtime_mode=runtime_mode)
    corpus_identity = value.get("corpus_identity")
    if corpus_identity != _EXPECTED_CORPUS_IDENTITY:
        raise ValueError("capture artifact has invalid corpus_identity")
    toolchain_identity = value.get("toolchain_identity")
    if not isinstance(toolchain_identity, Mapping) or not toolchain_identity:
        raise ValueError("capture artifact requires toolchain_identity")
    if any(
        type(key) is not str
        or not key
        or type(item) is not str
        or not item
        for key, item in toolchain_identity.items()
    ):
        raise ValueError("capture artifact toolchain_identity must map non-empty strings")
    cases = value.get("cases")
    if not isinstance(cases, Sequence) or isinstance(cases, (str, bytes)):
        raise ValueError("capture artifact cases must be a sequence")
    if not cases:
        raise ValueError("capture artifact requires observed cases")
    case_strata, derived_corpus_digest = _manifest_contract()
    expected_provider_values = frozenset(provider.value for provider in _EXPECTED_PROVIDERS)
    seen_case_ids: set[str] = set()
    provider_row_count = 0
    for case in cases:
        if not isinstance(case, Mapping):
            raise ValueError("capture artifact cases must be objects")
        case_id = case.get("case_id")
        if type(case_id) is not str or not case_id:
            raise ValueError("capture artifact cases must have non-empty case_id")
        if case_id in seen_case_ids:
            raise ValueError(f"capture artifact has duplicate case_id {case_id}")
        seen_case_ids.add(case_id)
        if case_id not in case_strata:
            raise ValueError("capture artifact case IDs must match manifest case IDs")
        if case.get("stratum") != case_strata[case_id]:
            raise ValueError(f"capture artifact case {case_id} has invalid stratum")
        outcomes = case.get("outcomes")
        if not isinstance(outcomes, Sequence) or isinstance(outcomes, (str, bytes)):
            raise ValueError(f"capture artifact case {case_id} has incomplete provider matrix")
        providers: list[str] = []
        for outcome in outcomes:
            if not isinstance(outcome, Mapping):
                raise ValueError(f"capture artifact case {case_id} has incomplete provider matrix")
            provider = outcome.get("provider")
            if type(provider) is not str or provider not in expected_provider_values:
                raise ValueError(f"capture artifact case {case_id} has invalid provider matrix")
            if provider in providers:
                raise ValueError(
                    f"capture artifact case {case_id} has duplicate provider matrix rows"
                )
            providers.append(provider)
        if frozenset(providers) != expected_provider_values:
            raise ValueError(f"capture artifact case {case_id} has incomplete provider matrix")
        provider_row_count += len(outcomes)
    if set(seen_case_ids) != set(case_strata) or len(seen_case_ids) != _EXPECTED_CASE_COUNT:
        raise ValueError("capture artifact case IDs must match manifest case IDs")
    metadata = value.get("capture_metadata")
    if not isinstance(metadata, Mapping):
        raise ValueError("capture artifact requires capture_metadata")
    elapsed = metadata.get("whole_function_elapsed_ms_by_case")
    if not isinstance(elapsed, Mapping) or set(elapsed) != set(case_strata):
        raise ValueError("capture artifact capture_metadata case coverage is incomplete")
    if any(type(item) not in (int, float) or not math.isfinite(item) or item < 0 for item in elapsed.values()):
        raise ValueError("capture artifact capture_metadata has invalid case timing")
    report_from_dict(value)
    corpus_claims = _capture_digest_claims(value, "corpus_digest")
    if corpus_claims and corpus_claims[0] != derived_corpus_digest:
        raise ValueError("capture artifact corpus_digest conflicts with manifest content")
    derived_toolchain_digest = _canonical_json_digest(toolchain_identity)
    toolchain_claims = _capture_digest_claims(value, "toolchain_digest")
    if toolchain_claims and toolchain_claims[0] != derived_toolchain_digest:
        raise ValueError("capture artifact toolchain_digest conflicts with toolchain_identity")
    return (
        derived_corpus_digest,
        derived_toolchain_digest,
        len(case_strata),
        provider_row_count,
        frozenset(
            case_id for case_id, stratum in case_strata.items() if stratum == "catalogue"
        ),
    )


def build_certificate_from_artifacts(
    *,
    ledger_path: Path,
    capture_path: Path,
    runtime_mode: str,
) -> dict[str, object]:
    """Render a certificate from persisted parity and native-capture artifacts."""

    if runtime_mode not in _RUNTIME_MODES:
        raise ValueError("invalid runtime_mode")
    ledger_document = _load_json(ledger_path)
    if not isinstance(ledger_document, Mapping):
        raise ValueError("parity ledger artifact must be an object")
    if ledger_document.get("schema_version") != 1:
        raise ValueError("parity ledger artifact schema_version must be 1")
    recorded_runtime = ledger_document.get("runtime_mode")
    if recorded_runtime not in _RUNTIME_MODES:
        raise ValueError("parity ledger artifact requires runtime_mode")
    if recorded_runtime != runtime_mode:
        raise ValueError("parity ledger runtime_mode does not match runtime")
    snapshot_value = ledger_document.get("snapshot")
    ledger_value = ledger_document.get("ledger")
    if snapshot_value is None or ledger_value is None:
        raise ValueError("parity ledger artifact requires snapshot and ledger")
    capture = _load_json(capture_path)
    (
        corpus_digest,
        toolchain_digest,
        case_count,
        provider_row_count,
        catalogue_case_ids,
    ) = _capture_bindings(capture, runtime_mode=runtime_mode)
    snapshot = _evidence_snapshot(snapshot_value)
    ledger = _evidence_ledger(ledger_value)
    coverage = ledger_document.get("coverage")
    if not isinstance(coverage, Mapping):
        raise ValueError("parity ledger artifact requires coverage")
    if (
        type(coverage.get("case_count")) is not int
        or coverage["case_count"] != case_count
        or type(coverage.get("provider_row_count")) is not int
        or coverage["provider_row_count"] != provider_row_count
    ):
        raise ValueError("parity ledger coverage does not match capture coverage")
    catalogue_coverage = coverage.get("catalogue_cases")
    if not isinstance(catalogue_coverage, Mapping) or set(catalogue_coverage) != set(
        catalogue_case_ids
    ):
        raise ValueError("parity ledger coverage must include every catalogue case")
    observed_total = 0
    legacy_total = 0
    for case_id in sorted(catalogue_case_ids):
        case_coverage = catalogue_coverage[case_id]
        if not isinstance(case_coverage, Mapping):
            raise ValueError(f"parity ledger coverage is invalid for {case_id}")
        observation_count = case_coverage.get("observation_count")
        legacy_match_count = case_coverage.get("legacy_match_count")
        if (
            type(observation_count) is not int
            or observation_count < 0
            or type(legacy_match_count) is not int
            or legacy_match_count < 0
            or legacy_match_count > observation_count
        ):
            raise ValueError(f"parity ledger coverage is invalid for {case_id}")
        observed_total += observation_count
        legacy_total += legacy_match_count
    if observed_total != ledger.observation_count or legacy_total != ledger.legacy_match_count:
        raise ValueError(
            "parity ledger coverage does not match persisted observation_count/legacy_match_count"
        )
    return make_structural_matcher_parity_certificate(
        snapshot=snapshot,
        ledger=ledger,
        runtime_mode=runtime_mode,
        corpus_digest=corpus_digest,
        toolchain_digest=toolchain_digest,
    )


def _parse_args(argv: Sequence[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--ledger", required=True, type=Path)
    parser.add_argument("--capture", required=True, type=Path)
    parser.add_argument("--runtime", required=True, choices=sorted(_RUNTIME_MODES))
    parser.add_argument("--output", required=True, type=Path)
    return parser.parse_args(argv)


def main(argv: Sequence[str] | None = None) -> int:
    args = _parse_args(argv)
    try:
        certificate = build_certificate_from_artifacts(
            ledger_path=args.ledger,
            capture_path=args.capture,
            runtime_mode=args.runtime,
        )
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(
            json.dumps(certificate, allow_nan=False, ensure_ascii=True, indent=2, sort_keys=True)
            + "\n",
            encoding="utf-8",
        )
        return 0
    except ValueError as exc:
        print(f"mba_structural_matcher_certificate: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
