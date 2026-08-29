"""Package-layout and failure-closed contracts for structural runtime identity."""

from __future__ import annotations

import importlib
import json
from pathlib import Path
from types import SimpleNamespace

import pytest

from d810.backends.mba import native_pod_matcher
from d810.mba.certified_catalogue import (
    CertifiedCatalogueSnapshot,
    StructuralMatcherParityCertificate,
    StructuralMatcherParityExpectation,
)


def _authorization_case(digest: str):
    snapshot = CertifiedCatalogueSnapshot(
        fingerprint="a" * 64,
        rules_in_declaration_order=(),
        rule_ids_by_root_shape={},
        structural_authorizable=True,
        runtime_semantics_digest=digest,
    )
    expectation = StructuralMatcherParityExpectation(
        corpus_digest="b" * 64,
        toolchain_digest="c" * 64,
        runtime_semantics_digest=digest,
        legacy_observation_count=1,
        observation_count=1,
    )
    certificate = StructuralMatcherParityCertificate(
        snapshot_fingerprint=snapshot.fingerprint,
        runtime_mode="python",
        corpus_digest=expectation.corpus_digest,
        toolchain_digest=expectation.toolchain_digest,
        runtime_semantics_digest=digest,
        legacy_observation_count=1,
        observation_count=1,
        legacy_rule_mismatches=0,
        legacy_binding_mismatches=0,
        legacy_binding_unknown=0,
        new_safe_coverage_pending=0,
        unsafe_mutations=0,
        unproved_structural_replacements=0,
    )
    return snapshot, expectation, certificate


def test_runtime_digest_and_activation_work_from_installed_package_layout(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    site_packages = tmp_path / "site-packages"
    package_root = site_packages / "installed_d810"
    mba_root = package_root / "backends" / "mba"
    mba_root.mkdir(parents=True)
    (package_root / "__init__.py").write_text("", encoding="utf-8")
    (package_root / "backends" / "__init__.py").write_text("", encoding="utf-8")
    (mba_root / "__init__.py").write_text("", encoding="utf-8")
    manifest = {
        "schema_version": 1,
        "runtime_sources": [
            "backends/mba/native_pod_matcher.py",
            "backends/mba/runtime_semantics.py",
        ],
    }
    (package_root / "runtime_semantics_manifest.json").write_text(
        json.dumps(manifest), encoding="utf-8"
    )
    (mba_root / "native_pod_matcher.py").write_text(
        "# installed wheel matcher\n", encoding="utf-8"
    )
    (mba_root / "runtime_semantics.py").write_text(
        "# installed wheel digest helper\n", encoding="utf-8"
    )
    monkeypatch.syspath_prepend(str(site_packages))
    importlib.invalidate_caches()
    importlib.import_module("installed_d810")

    identity = native_pod_matcher.NativeMatcherRuntimeIdentity(
        pod_backend="python",
        implementation="installed_d810.backends.mba.native_pod_matcher",
        artifact_identity="python-fallback",
    )
    digest = native_pod_matcher.runtime_semantics_digest(
        identity=identity,
        package_name="installed_d810",
    )
    assert len(digest) == 64
    assert not (tmp_path / "src").exists()

    snapshot, expectation, certificate = _authorization_case(digest)
    assert certificate.authorizes(snapshot, "python", expectation) is True


def test_runtime_digest_is_independent_of_manifest_source_order(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    site_packages = tmp_path / "site-packages"
    package_root = site_packages / "installed_d810_ordered"
    mba_root = package_root / "backends" / "mba"
    mba_root.mkdir(parents=True)
    (package_root / "__init__.py").write_text("", encoding="utf-8")
    (package_root / "backends" / "__init__.py").write_text("", encoding="utf-8")
    (mba_root / "__init__.py").write_text("", encoding="utf-8")
    sources = [
        "backends/mba/runtime_semantics.py",
        "backends/mba/native_pod_matcher.py",
        "mba/canonical_pattern.py",
    ]
    for index, source_name in enumerate(sources):
        source_path = package_root.joinpath(*Path(source_name).parts)
        source_path.parent.mkdir(parents=True, exist_ok=True)
        source_path.write_text(f"# runtime source {index}\n", encoding="utf-8")
    manifest_path = package_root / "runtime_semantics_manifest.json"
    manifest_path.write_text(
        json.dumps({"schema_version": 1, "runtime_sources": list(reversed(sources))}),
        encoding="utf-8",
    )
    monkeypatch.syspath_prepend(str(site_packages))
    importlib.invalidate_caches()
    importlib.import_module("installed_d810_ordered")
    identity = native_pod_matcher.NativeMatcherRuntimeIdentity(
        pod_backend="python",
        implementation="installed_d810_ordered.backends.mba.native_pod_matcher",
        artifact_identity="python-fallback",
    )

    reversed_digest = native_pod_matcher.runtime_semantics_digest(
        identity=identity,
        package_name="installed_d810_ordered",
    )
    manifest_path.write_text(
        json.dumps({"schema_version": 1, "runtime_sources": sources}),
        encoding="utf-8",
    )
    ordered_digest = native_pod_matcher.runtime_semantics_digest(
        identity=identity,
        package_name="installed_d810_ordered",
    )

    assert reversed_digest == ordered_digest


def test_runtime_digest_tracks_matcher_and_provenance_sources(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    site_packages = tmp_path / "site-packages"
    package_root = site_packages / "installed_d810_semantics"
    package_root.mkdir(parents=True)
    (package_root / "__init__.py").write_text("", encoding="utf-8")
    sources = (
        "backends/mba/compiled_pattern_catalogue.py",
        "backends/mba/native_mba_term_view.py",
        "mba/canonical_pattern.py",
        "mba/semantic_canonicalization.py",
    )
    for index, source_name in enumerate(sources):
        source_path = package_root.joinpath(*Path(source_name).parts)
        source_path.parent.mkdir(parents=True, exist_ok=True)
        source_path.write_text(f"# executable semantics {index}\n", encoding="utf-8")
    (package_root / "runtime_semantics_manifest.json").write_text(
        json.dumps({"schema_version": 1, "runtime_sources": list(sources)}),
        encoding="utf-8",
    )
    monkeypatch.syspath_prepend(str(site_packages))
    importlib.invalidate_caches()
    importlib.import_module("installed_d810_semantics")
    identity = native_pod_matcher.NativeMatcherRuntimeIdentity(
        pod_backend="python",
        implementation="installed_d810_semantics.backends.mba.native_pod_matcher",
        artifact_identity="python-fallback",
    )

    before = native_pod_matcher.runtime_semantics_digest(
        identity=identity,
        package_name="installed_d810_semantics",
    )
    changed = package_root / "backends" / "mba" / "compiled_pattern_catalogue.py"
    changed.write_text("# changed fallback selection\n", encoding="utf-8")
    after_selection_change = native_pod_matcher.runtime_semantics_digest(
        identity=identity,
        package_name="installed_d810_semantics",
    )
    changed = package_root / "backends" / "mba" / "native_mba_term_view.py"
    changed.write_text("# changed provenance projection\n", encoding="utf-8")
    after_projection_change = native_pod_matcher.runtime_semantics_digest(
        identity=identity,
        package_name="installed_d810_semantics",
    )

    assert before != after_selection_change
    assert after_selection_change != after_projection_change


def test_runtime_digest_rejects_missing_active_artifact() -> None:
    identity = native_pod_matcher.NativeMatcherRuntimeIdentity(
        pod_backend="cython",
        implementation="d810.speedups.mba.c_native_pod_matcher",
        artifact_identity="",
    )

    with pytest.raises(OSError, match="artifact"):
        native_pod_matcher.runtime_semantics_digest(identity=identity)


def test_loaded_extension_artifact_identity_changes_when_binary_changes(
    tmp_path: Path,
) -> None:
    suffix = ".cpython-313-darwin.so"
    artifact = tmp_path / f"c_native_pod_matcher{suffix}"
    module = SimpleNamespace(
        __name__="d810.speedups.mba.c_native_pod_matcher",
        __file__=str(artifact),
    )
    artifact.write_bytes(b"first extension artifact")
    first_identity = native_pod_matcher.loaded_extension_artifact_identity(module)
    artifact.write_bytes(b"second extension artifact")
    second_identity = native_pod_matcher.loaded_extension_artifact_identity(module)

    assert first_identity != second_identity
