"""Portable contract tests for the parity-certificate generator CLI."""

from __future__ import annotations

import hashlib
import json
from copy import deepcopy
from pathlib import Path

import pytest

from tools.scripts import mba_structural_matcher_certificate as certificate_tool
from tools.scripts.mba_structural_matcher_certificate import build_certificate
from d810.mba.semantic_canonicalization import CANONICALIZER_SCHEMA_VERSION
from d810.mba.provider_outcome import MbaProviderKind


_MANIFEST = Path(__file__).resolve().parents[2] / "fixtures/mba_portfolio/compiler_shapes.json"


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
    cases = json.loads(_MANIFEST.read_text(encoding="utf-8"))["cases"]
    catalogue_case_ids = [
        case["case_id"] for case in cases if case["stratum"] == "catalogue"
    ]
    evidence["schema_version"] = 1
    evidence["coverage"] = {
        "case_count": len(cases),
        "provider_row_count": len(cases) * len(tuple(MbaProviderKind)),
        "catalogue_cases": {
            case_id: {
                "observation_count": 1 if index < 9 else 2,
                "legacy_match_count": 1 if index < 9 else 0,
            }
            for index, case_id in enumerate(catalogue_case_ids)
        },
    }
    evidence["runtime_mode"] = runtime_mode
    return evidence


def _capture_artifact(
    *, runtime_mode: str = "python", direct_digests: bool = False
) -> dict[str, object]:
    manifest = json.loads(_MANIFEST.read_text(encoding="utf-8"))
    toolchain_identity = {
        "ida_sdk": "940",
        "matcher_backend": runtime_mode,
        "profile": "portfolio-interactive",
    }
    cases = []
    for manifest_case in manifest["cases"]:
        case_id = manifest_case["case_id"]
        cases.append(
            {
                "case_id": case_id,
                "stratum": manifest_case["stratum"],
                "profile": None,
                "outcomes": [
                    {
                        "provider": provider.value,
                        "status": "unavailable",
                        "fingerprint": f"native_candidate_not_observed:{case_id}",
                        "input_cost": None,
                        "output_cost": None,
                        "proof_verdict": None,
                        "elapsed_ms": 0.0,
                        "source_provenance": [],
                        "refusal_reason": "native_candidate_not_observed",
                        "metadata": {
                            "native_capture": "native_candidate_not_observed"
                        },
                        "matcher": None,
                    }
                    for provider in MbaProviderKind
                ],
            }
        )
    capture = {
        "schema_version": 1,
        "corpus_identity": "mba-compiler-shapes-native",
        "toolchain_identity": toolchain_identity,
        "capture_metadata": {
            "whole_function_elapsed_ms_by_case": {
                case["case_id"]: 0.0 for case in cases
            }
        },
        "cases": cases,
    }
    if direct_digests:
        capture["corpus_digest"] = _digest(_MANIFEST)
        capture["toolchain_digest"] = hashlib.sha256(
            json.dumps(
                toolchain_identity,
                ensure_ascii=True,
                separators=(",", ":"),
                sort_keys=True,
            ).encode("utf-8")
        ).hexdigest()
    return capture


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
    assert certificate["corpus_digest"] == _digest(_MANIFEST)
    assert certificate["toolchain_digest"] == hashlib.sha256(
        b'{"ida_sdk":"940","matcher_backend":"python","profile":"portfolio-interactive"}'
    ).hexdigest()
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
    capture_path.write_text(json.dumps(_capture_artifact()), encoding="utf-8")

    certificate = certificate_tool.build_certificate_from_artifacts(
        ledger_path=ledger_path,
        capture_path=capture_path,
        runtime_mode="python",
    )

    assert certificate["corpus_digest"] == _digest(_MANIFEST)
    assert certificate["toolchain_digest"] == hashlib.sha256(
        b'{"ida_sdk":"940","matcher_backend":"python","profile":"portfolio-interactive"}'
    ).hexdigest()


@pytest.mark.parametrize(
    ("mutation", "message"),
    (
        ("duplicate_case", "duplicate"),
        ("unknown_case", "manifest case IDs"),
        ("missing_case", "manifest case IDs"),
        ("missing_outcome", "provider matrix"),
        ("duplicate_outcome", "provider matrix"),
        ("empty_case", "provider matrix"),
    ),
)
def test_artifact_certificate_rejects_incomplete_or_unknown_capture_rows(
    tmp_path: Path, mutation: str, message: str
) -> None:
    capture = _capture_artifact()
    if mutation == "duplicate_case":
        capture["cases"].append(deepcopy(capture["cases"][0]))
    elif mutation == "unknown_case":
        capture["cases"][0]["case_id"] = "not_a_manifest_case"
    elif mutation == "missing_case":
        capture["cases"].pop()
    elif mutation == "missing_outcome":
        capture["cases"][0]["outcomes"].pop()
    elif mutation == "duplicate_outcome":
        capture["cases"][0]["outcomes"].append(
            deepcopy(capture["cases"][0]["outcomes"][0])
        )
    elif mutation == "empty_case":
        capture["cases"][0]["outcomes"] = []
    else:  # pragma: no cover - parameterized contract
        raise AssertionError(mutation)
    ledger_path = tmp_path / "parity-ledger.json"
    capture_path = tmp_path / "native-capture.json"
    ledger_path.write_text(json.dumps(_ledger_artifact()), encoding="utf-8")
    capture_path.write_text(json.dumps(capture), encoding="utf-8")

    with pytest.raises(ValueError, match=message):
        certificate_tool.build_certificate_from_artifacts(
            ledger_path=ledger_path,
            capture_path=capture_path,
            runtime_mode="python",
        )


def test_artifact_certificate_rejects_missing_or_conflicting_runtime_bindings(
    tmp_path: Path,
) -> None:
    ledger_path = tmp_path / "parity-ledger.json"
    capture_path = tmp_path / "native-capture.json"
    ledger = _ledger_artifact()
    ledger.pop("runtime_mode")
    capture = _capture_artifact()
    capture["toolchain_identity"].pop("matcher_backend")
    ledger_path.write_text(json.dumps(ledger), encoding="utf-8")
    capture_path.write_text(json.dumps(capture), encoding="utf-8")

    with pytest.raises(ValueError, match="runtime_mode"):
        certificate_tool.build_certificate_from_artifacts(
            ledger_path=ledger_path,
            capture_path=capture_path,
            runtime_mode="python",
        )

    ledger = _ledger_artifact()
    capture = _capture_artifact()
    capture["runtime_mode"] = "cython"
    ledger_path.write_text(json.dumps(ledger), encoding="utf-8")
    capture_path.write_text(json.dumps(capture), encoding="utf-8")
    with pytest.raises(ValueError, match="runtime_mode"):
        certificate_tool.build_certificate_from_artifacts(
            ledger_path=ledger_path,
            capture_path=capture_path,
            runtime_mode="python",
        )


@pytest.mark.parametrize("field", ("corpus_digest", "toolchain_digest"))
def test_artifact_certificate_rejects_conflicting_digest_claims(
    tmp_path: Path, field: str
) -> None:
    ledger_path = tmp_path / "parity-ledger.json"
    capture_path = tmp_path / "native-capture.json"
    ledger_path.write_text(json.dumps(_ledger_artifact()), encoding="utf-8")
    capture = _capture_artifact(direct_digests=True)
    capture.setdefault("capture_metadata", {})[field] = "0" * 64
    capture_path.write_text(json.dumps(capture), encoding="utf-8")

    with pytest.raises(ValueError, match=field):
        certificate_tool.build_certificate_from_artifacts(
            ledger_path=ledger_path,
            capture_path=capture_path,
            runtime_mode="python",
        )


@pytest.mark.parametrize("field", ("corpus_digest", "toolchain_digest"))
def test_artifact_certificate_rejects_nested_conflicting_digest_claims(
    tmp_path: Path, field: str
) -> None:
    ledger_path = tmp_path / "parity-ledger.json"
    capture_path = tmp_path / "native-capture.json"
    ledger_path.write_text(json.dumps(_ledger_artifact()), encoding="utf-8")
    capture = _capture_artifact(direct_digests=True)
    capture["capture"] = {field: "0" * 64}
    capture_path.write_text(json.dumps(capture), encoding="utf-8")

    with pytest.raises(ValueError, match=field):
        certificate_tool.build_certificate_from_artifacts(
            ledger_path=ledger_path,
            capture_path=capture_path,
            runtime_mode="python",
        )


def test_artifact_certificate_rejects_boolean_capture_schema_version(
    tmp_path: Path,
) -> None:
    ledger_path = tmp_path / "parity-ledger.json"
    capture_path = tmp_path / "native-capture.json"
    ledger_path.write_text(json.dumps(_ledger_artifact()), encoding="utf-8")
    capture = _capture_artifact()
    capture["schema_version"] = True
    capture_path.write_text(json.dumps(capture), encoding="utf-8")

    with pytest.raises(ValueError, match="schema_version"):
        certificate_tool.build_certificate_from_artifacts(
            ledger_path=ledger_path,
            capture_path=capture_path,
            runtime_mode="python",
        )


def test_artifact_certificate_rejects_unbound_ledger_coverage(
    tmp_path: Path,
) -> None:
    ledger = _ledger_artifact()
    ledger["coverage"]["provider_row_count"] -= 1
    ledger_path = tmp_path / "parity-ledger.json"
    capture_path = tmp_path / "native-capture.json"
    ledger_path.write_text(json.dumps(ledger), encoding="utf-8")
    capture_path.write_text(json.dumps(_capture_artifact()), encoding="utf-8")

    with pytest.raises(ValueError, match="coverage"):
        certificate_tool.build_certificate_from_artifacts(
            ledger_path=ledger_path,
            capture_path=capture_path,
            runtime_mode="python",
        )


def test_artifact_certificate_rejects_observation_count_outside_capture_coverage(
    tmp_path: Path,
) -> None:
    ledger = _ledger_artifact()
    ledger["ledger"]["observation_count"] = ledger["coverage"]["provider_row_count"] + 1
    ledger_path = tmp_path / "parity-ledger.json"
    capture_path = tmp_path / "native-capture.json"
    ledger_path.write_text(json.dumps(ledger), encoding="utf-8")
    capture_path.write_text(json.dumps(_capture_artifact()), encoding="utf-8")

    with pytest.raises(ValueError, match="observation_count"):
        certificate_tool.build_certificate_from_artifacts(
            ledger_path=ledger_path,
            capture_path=capture_path,
            runtime_mode="python",
        )


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
