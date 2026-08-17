#!/usr/bin/env python3
"""Render a fail-closed certificate from persisted parity and capture evidence."""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
from collections.abc import Mapping, Sequence
from pathlib import Path

from d810.mba.certified_catalogue import (
    CertifiedCatalogueSnapshot,
    ShadowMatcherParityLedger,
    make_structural_matcher_parity_certificate,
)
from d810.mba.semantic_canonicalization import CANONICALIZER_SCHEMA_VERSION


_DIGEST_LENGTH = 64
_RUNTIME_MODES = frozenset(("python", "cython"))


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


def _capture_digest(value: Mapping[str, object], field: str) -> str:
    direct = value.get(field)
    if direct is not None:
        if not _is_sha256_digest(direct):
            raise ValueError(f"capture artifact has invalid {field}")
        return direct
    for nested_name in ("capture", "capture_metadata"):
        nested = value.get(nested_name)
        if isinstance(nested, Mapping) and field in nested:
            nested_value = nested[field]
            if not _is_sha256_digest(nested_value):
                raise ValueError(f"capture artifact has invalid {field}")
            return nested_value
    aliases = (
        ("corpus_digest", "manifest_digest", "corpus_fingerprint")
        if field == "corpus_digest"
        else ("toolchain_digest", "toolchain_fingerprint")
    )
    for alias in aliases[1:]:
        aliased = value.get(alias)
        if aliased is not None:
            if not _is_sha256_digest(aliased):
                raise ValueError(f"capture artifact has invalid {field}")
            return aliased
    if field == "corpus_digest":
        identity = value.get("corpus_identity")
        if type(identity) is str and identity:
            return hashlib.sha256(identity.encode("utf-8")).hexdigest()
    else:
        identity = value.get("toolchain_identity")
        if isinstance(identity, Mapping):
            try:
                encoded = json.dumps(
                    identity,
                    allow_nan=False,
                    ensure_ascii=True,
                    separators=(",", ":"),
                    sort_keys=True,
                ).encode("utf-8")
            except (TypeError, ValueError) as exc:
                raise ValueError(
                    "capture artifact has invalid toolchain_identity"
                ) from exc
            return hashlib.sha256(encoded).hexdigest()
    raise ValueError(f"capture artifact requires {field}")


def _capture_bindings(value: object, *, runtime_mode: str) -> tuple[str, str]:
    if not isinstance(value, Mapping):
        raise ValueError("capture artifact must be an object")
    if runtime_mode not in _RUNTIME_MODES:
        raise ValueError("invalid runtime_mode")
    schema_version = value.get("schema_version")
    if type(schema_version) is not int or schema_version <= 0:
        raise ValueError("capture artifact requires a positive schema_version")
    captured_runtime = value.get("runtime_mode")
    if captured_runtime is None:
        toolchain_identity = value.get("toolchain_identity")
        if isinstance(toolchain_identity, Mapping):
            captured_runtime = toolchain_identity.get("matcher_backend")
    if captured_runtime is not None and captured_runtime != runtime_mode:
        raise ValueError("capture artifact runtime_mode does not match runtime")
    cases = value.get("cases")
    if not isinstance(cases, Sequence) or isinstance(cases, (str, bytes)) or not cases:
        raise ValueError("capture artifact requires observed cases")
    if any(
        not isinstance(case, Mapping)
        or type(case.get("case_id")) is not str
        or not case["case_id"]
        for case in cases
    ):
        raise ValueError("capture artifact cases must have non-empty case_id")
    return (
        _capture_digest(value, "corpus_digest"),
        _capture_digest(value, "toolchain_digest"),
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
    recorded_runtime = ledger_document.get("runtime_mode")
    if recorded_runtime is not None and recorded_runtime != runtime_mode:
        raise ValueError("parity ledger runtime_mode does not match runtime")
    snapshot_value = ledger_document.get("snapshot")
    ledger_value = ledger_document.get("ledger")
    if snapshot_value is None or ledger_value is None:
        raise ValueError("parity ledger artifact requires snapshot and ledger")
    snapshot = _evidence_snapshot(snapshot_value)
    ledger = _evidence_ledger(ledger_value)
    capture = _load_json(capture_path)
    corpus_digest, toolchain_digest = _capture_bindings(
        capture, runtime_mode=runtime_mode
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
