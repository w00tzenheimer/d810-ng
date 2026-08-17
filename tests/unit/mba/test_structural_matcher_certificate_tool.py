"""Portable contract tests for the parity-certificate generator CLI."""

from __future__ import annotations

import hashlib
from pathlib import Path

import pytest

from tools.scripts.mba_structural_matcher_certificate import build_certificate
from d810.mba.semantic_canonicalization import CANONICALIZER_SCHEMA_VERSION


def _digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _evidence(*, mismatch: int = 0) -> dict[str, object]:
    return {
        "snapshot": {
            "fingerprint": "a" * 64,
            "structural_authorizable": True,
            "canonicalizer_schema_version": CANONICALIZER_SCHEMA_VERSION,
        },
        "ledger": {
            "observation_count": 11,
            "legacy_match_count": 9,
            "legacy_rule_mismatches": mismatch,
            "legacy_binding_mismatches": 0,
            "legacy_binding_unknown": 0,
            "new_safe_coverage_pending": 0,
            "new_safe_coverage_proved": 2,
        },
        "runtime_mode": "python",
    }


def test_build_certificate_binds_exact_manifest_and_canonical_toolchain(
    tmp_path: Path,
) -> None:
    manifest = tmp_path / "manifest.json"
    toolchain = tmp_path / "toolchain.json"
    manifest.write_text('{"cases":["case_01"]}\n', encoding="utf-8")
    toolchain.write_text('{"ida":"9.4","backend":"python"}\n', encoding="utf-8")

    certificate = build_certificate(
        _evidence(), manifest=manifest, toolchain=toolchain
    )

    assert certificate["schema_version"] == 3
    assert certificate["corpus_digest"] == _digest(manifest)
    assert certificate["toolchain_digest"] == hashlib.sha256(
        b'{"backend":"python","ida":"9.4"}'
    ).hexdigest()
    assert certificate["legacy_observation_count"] == 9


def test_build_certificate_rejects_nonzero_parity_mismatch(tmp_path: Path) -> None:
    manifest = tmp_path / "manifest.json"
    toolchain = tmp_path / "toolchain.json"
    manifest.write_text("{}", encoding="utf-8")
    toolchain.write_text("{}", encoding="utf-8")

    with pytest.raises(ValueError, match="legacy_rule_mismatches=0"):
        build_certificate(_evidence(mismatch=1), manifest=manifest, toolchain=toolchain)


def test_build_certificate_rejects_missing_canonicalizer_version(tmp_path: Path) -> None:
    manifest = tmp_path / "manifest.json"
    toolchain = tmp_path / "toolchain.json"
    manifest.write_text("{}", encoding="utf-8")
    toolchain.write_text("{}", encoding="utf-8")
    evidence = _evidence()
    del evidence["snapshot"]["canonicalizer_schema_version"]

    with pytest.raises(
        ValueError,
        match="parity evidence snapshot requires canonicalizer_schema_version",
    ):
        build_certificate(evidence, manifest=manifest, toolchain=toolchain)


def test_build_certificate_rejects_non_object_toolchain(tmp_path: Path) -> None:
    manifest = tmp_path / "manifest.json"
    toolchain = tmp_path / "toolchain.json"
    manifest.write_text("{}", encoding="utf-8")
    toolchain.write_text("[]", encoding="utf-8")

    with pytest.raises(ValueError, match="toolchain document must be a JSON object"):
        build_certificate(_evidence(), manifest=manifest, toolchain=toolchain)
