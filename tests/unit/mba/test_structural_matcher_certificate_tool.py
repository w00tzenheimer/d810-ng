"""Portable contract tests for the parity-certificate generator CLI."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest

from tools.scripts import mba_structural_matcher_certificate as certificate_tool
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
            "unsafe_mutations": 0,
            "unproved_structural_replacements": 0,
        },
        "runtime_mode": "python",
    }


def _ledger_artifact(*, runtime_mode: str = "python") -> dict[str, object]:
    evidence = _evidence()
    evidence["runtime_mode"] = runtime_mode
    return evidence


def _capture_artifact() -> dict[str, object]:
    return {
        "schema_version": 1,
        "corpus_digest": "b" * 64,
        "toolchain_digest": "c" * 64,
        "cases": [{"case_id": "case_01", "status": "observed"}],
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


@pytest.mark.parametrize(
    "field",
    ("unsafe_mutations", "unproved_structural_replacements"),
)
def test_build_certificate_rejects_unsafe_or_unproved_evidence(
    tmp_path: Path, field: str
) -> None:
    manifest = tmp_path / "manifest.json"
    toolchain = tmp_path / "toolchain.json"
    manifest.write_text("{}", encoding="utf-8")
    toolchain.write_text("{}", encoding="utf-8")
    evidence = _evidence()
    evidence["ledger"][field] = 1

    with pytest.raises(ValueError, match=f"{field}=0"):
        build_certificate(evidence, manifest=manifest, toolchain=toolchain)


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


def test_build_certificate_rejects_boolean_canonicalizer_version(
    tmp_path: Path,
) -> None:
    manifest = tmp_path / "manifest.json"
    toolchain = tmp_path / "toolchain.json"
    manifest.write_text("{}", encoding="utf-8")
    toolchain.write_text("{}", encoding="utf-8")
    evidence = _evidence()
    evidence["snapshot"]["canonicalizer_schema_version"] = True

    with pytest.raises(ValueError):
        build_certificate(evidence, manifest=manifest, toolchain=toolchain)


def test_build_certificate_rejects_non_object_toolchain(tmp_path: Path) -> None:
    manifest = tmp_path / "manifest.json"
    toolchain = tmp_path / "toolchain.json"
    manifest.write_text("{}", encoding="utf-8")
    toolchain.write_text("[]", encoding="utf-8")

    with pytest.raises(ValueError, match="toolchain document must be a JSON object"):
        build_certificate(_evidence(), manifest=manifest, toolchain=toolchain)


@pytest.mark.parametrize(
    "field",
    (
        "legacy_rule_mismatches",
        "legacy_binding_mismatches",
        "legacy_binding_unknowns",
        "new_safe_coverage_pending",
        "unsafe_mutations",
        "unproved_structural_replacements",
    ),
)
def test_artifact_certificate_rejects_each_nonzero_safety_counter(
    tmp_path: Path, field: str
) -> None:
    ledger = _ledger_artifact()
    ledger_fields = ledger["ledger"]
    assert isinstance(ledger_fields, dict)
    ledger_fields[field] = 1
    ledger_path = tmp_path / "parity-ledger.json"
    capture_path = tmp_path / "native-capture.json"
    ledger_path.write_text(json.dumps(ledger), encoding="utf-8")
    capture_path.write_text(json.dumps(_capture_artifact()), encoding="utf-8")

    with pytest.raises(ValueError, match=field):
        certificate_tool.build_certificate_from_artifacts(
            ledger_path=ledger_path,
            capture_path=capture_path,
            runtime_mode="python",
        )


def test_artifact_certificate_binds_persisted_ledger_capture_and_runtime(
    tmp_path: Path,
) -> None:
    ledger_path = tmp_path / "parity-ledger.json"
    capture_path = tmp_path / "native-capture.json"
    ledger_path.write_text(json.dumps(_ledger_artifact()), encoding="utf-8")
    capture_path.write_text(json.dumps(_capture_artifact()), encoding="utf-8")

    certificate = certificate_tool.build_certificate_from_artifacts(
        ledger_path=ledger_path,
        capture_path=capture_path,
        runtime_mode="python",
    )

    assert certificate["runtime_mode"] == "python"
    assert certificate["snapshot_fingerprint"] == "a" * 64
    assert certificate["corpus_digest"] == "b" * 64
    assert certificate["toolchain_digest"] == "c" * 64
    assert certificate["observation_count"] == 11


def test_artifact_certificate_rejects_runtime_mismatch_and_empty_capture(
    tmp_path: Path,
) -> None:
    ledger_path = tmp_path / "parity-ledger.json"
    capture_path = tmp_path / "native-capture.json"
    ledger_path.write_text(json.dumps(_ledger_artifact()), encoding="utf-8")
    empty_capture = _capture_artifact()
    empty_capture["cases"] = []
    capture_path.write_text(json.dumps(empty_capture), encoding="utf-8")

    with pytest.raises(ValueError, match="capture artifact requires observed cases"):
        certificate_tool.build_certificate_from_artifacts(
            ledger_path=ledger_path,
            capture_path=capture_path,
            runtime_mode="python",
        )

    capture_path.write_text(json.dumps(_capture_artifact()), encoding="utf-8")
    ledger = _ledger_artifact(runtime_mode="cython")
    ledger_path.write_text(json.dumps(ledger), encoding="utf-8")
    with pytest.raises(ValueError, match="runtime_mode"):
        certificate_tool.build_certificate_from_artifacts(
            ledger_path=ledger_path,
            capture_path=capture_path,
            runtime_mode="python",
        )


def test_artifact_certificate_accepts_task13_capture_identity_shape(
    tmp_path: Path,
) -> None:
    ledger_path = tmp_path / "parity-ledger.json"
    capture_path = tmp_path / "native-capture.json"
    ledger_path.write_text(json.dumps(_ledger_artifact()), encoding="utf-8")
    capture_path.write_text(
        json.dumps(
            {
                "schema_version": 1,
                "corpus_identity": "mba-compiler-shapes-native",
                "toolchain_identity": {
                    "ida_sdk": "940",
                    "matcher_backend": "python",
                },
                "cases": [{"case_id": "case_01"}],
            }
        ),
        encoding="utf-8",
    )

    certificate = certificate_tool.build_certificate_from_artifacts(
        ledger_path=ledger_path,
        capture_path=capture_path,
        runtime_mode="python",
    )

    assert certificate["corpus_digest"] == hashlib.sha256(
        b"mba-compiler-shapes-native"
    ).hexdigest()
    assert certificate["toolchain_digest"] == hashlib.sha256(
        b'{"ida_sdk":"940","matcher_backend":"python"}'
    ).hexdigest()


def test_cli_requires_explicit_ledger_capture_runtime_and_output_flags(
    tmp_path: Path,
) -> None:
    ledger_path = tmp_path / "parity-ledger.json"
    capture_path = tmp_path / "native-capture.json"
    output_path = tmp_path / "certificate.json"
    ledger_path.write_text(json.dumps(_ledger_artifact()), encoding="utf-8")
    capture_path.write_text(json.dumps(_capture_artifact()), encoding="utf-8")

    assert (
        certificate_tool.main(
            [
                "--ledger",
                str(ledger_path),
                "--capture",
                str(capture_path),
                "--runtime",
                "python",
                "--output",
                str(output_path),
            ]
        )
        == 0
    )
    assert json.loads(output_path.read_text(encoding="utf-8"))["runtime_mode"] == "python"
