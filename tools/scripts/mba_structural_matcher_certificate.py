#!/usr/bin/env python3
"""Render a fail-closed structural-matcher parity certificate from evidence."""

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


def _evidence_snapshot(value: object) -> CertifiedCatalogueSnapshot:
    if not isinstance(value, Mapping):
        raise ValueError("parity evidence snapshot must be an object")
    fingerprint = value.get("fingerprint")
    authorizable = value.get("structural_authorizable")
    if type(fingerprint) is not str or type(authorizable) is not bool:
        raise ValueError("parity evidence snapshot is incomplete")
    canonicalizer_version = value.get(
        "canonicalizer_schema_version", CANONICALIZER_SCHEMA_VERSION
    )
    if canonicalizer_version != CANONICALIZER_SCHEMA_VERSION:
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
    fields = (
        "observation_count",
        "legacy_match_count",
        "legacy_rule_mismatches",
        "legacy_binding_mismatches",
        "legacy_binding_unknown",
        "new_safe_coverage_pending",
        "new_safe_coverage_proved",
    )
    if any(type(value.get(field)) is not int for field in fields):
        raise ValueError("parity evidence ledger is incomplete")
    return ShadowMatcherParityLedger(**{field: value[field] for field in fields})


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


def _parse_args(argv: Sequence[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--evidence", required=True, type=Path)
    parser.add_argument("--manifest", required=True, type=Path)
    parser.add_argument("--toolchain", required=True, type=Path)
    parser.add_argument("--out", required=True, type=Path)
    return parser.parse_args(argv)


def main(argv: Sequence[str] | None = None) -> int:
    args = _parse_args(argv)
    try:
        certificate = build_certificate(
            _load_json(args.evidence),
            manifest=args.manifest,
            toolchain=args.toolchain,
        )
        args.out.parent.mkdir(parents=True, exist_ok=True)
        args.out.write_text(
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
