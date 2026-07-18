from __future__ import annotations

import importlib.util
import json
import subprocess
import sys
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[3]
SCRIPT = (
    REPO_ROOT
    / "tools"
    / "scripts"
    / "codemod_consolidate_decompilation_lifecycle.py"
)


def _load_module():
    spec = importlib.util.spec_from_file_location("codemod_lifecycle", SCRIPT)
    assert spec is not None
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def test_rewrite_text_renames_only_declared_lifecycle_symbols() -> None:
    mod = _load_module()
    source = """from d810.passes.phase import ReconPhase
from d810.passes.recon_runtime_factory import ReconRuntimeBundle
from d810.hexrays.lifecycle import DecompilationEvent

bundle = ReconRuntimeBundle(recon_phase=ReconPhase(store))
config = {"enable_recon_pipeline": True, "recon_db": "facts.sqlite"}
logger_name = "D810.recon.flowgraph_ready"
event = DecompilationEvent.STARTED
"""

    result = mod.rewrite_text(source)

    assert result.changed
    assert "from d810.passes.phase import PreanalysisPhase" in result.text
    assert (
        "from d810.passes.analysis_runtime_factory import AnalysisRuntimeBundle"
        in result.text
    )
    assert "AnalysisRuntimeBundle(preanalysis_phase=PreanalysisPhase(store))" in result.text
    assert '"enable_analysis_pipeline"' in result.text
    assert '"analysis_db"' in result.text
    assert '"D810.preanalysis.flowgraph_ready"' in result.text
    assert "DecompilationEvent.SESSION_STARTED" in result.text
    assert "ReconPhase" not in result.text
    assert "recon_phase" not in result.text


def test_scan_classifies_manual_migration_points_without_rewriting_them(
    tmp_path: Path,
) -> None:
    mod = _load_module()
    sample = tmp_path / "sample.py"
    source = """from d810.passes.phase import ReconPhase

session = ReconPhase(store)
runtime.reset_for_func(0x401000)
runtime.analyze_and_persist(0x401000)
cache = _RESOLUTIONS_BY_EA[0x401000]
"""
    sample.write_text(source, encoding="utf-8")

    candidates = mod.scan_paths([sample], root=tmp_path)

    assert {(candidate.kind, candidate.rewriteable) for candidate in candidates} >= {
        ("legacy-import", True),
        ("legacy-symbol", True),
        ("direct-runtime-call", False),
        ("resolver-global-access", False),
    }
    assert mod.rewrite_text(source).text != source
    assert sample.read_text(encoding="utf-8") == source


def test_scan_reports_json_config_keys_as_manual_migration_points(tmp_path: Path) -> None:
    mod = _load_module()
    config = tmp_path / "default.json"
    config.write_text(
        '{"additional_configuration": {"recon_fact_profile_modules": []}}\n',
        encoding="utf-8",
    )

    candidates = mod.scan_paths([config], root=tmp_path)

    assert {(candidate.kind, candidate.rewriteable) for candidate in candidates} == {
        ("manual-config-key", False),
    }


def test_default_discovery_excludes_its_own_fixture_test(tmp_path: Path) -> None:
    mod = _load_module()
    fixture = tmp_path / "tests" / mod.SELF_TEST_FILE
    fixture.parent.mkdir()
    fixture.write_text("phase = ReconPhase(store)\n", encoding="utf-8")

    assert fixture.resolve() not in mod.discover_paths(tmp_path, [])


def test_default_discovery_excludes_graphify_artifacts(tmp_path: Path) -> None:
    mod = _load_module()
    artifact = tmp_path / "src" / "graphify-out" / "cache" / "artifact.py"
    artifact.parent.mkdir(parents=True)
    artifact.write_text("phase = ReconPhase(store)\n", encoding="utf-8")

    assert artifact.resolve() not in mod.discover_paths(tmp_path, [])


def test_cli_dry_run_writes_inventory_but_does_not_rewrite_source(tmp_path: Path) -> None:
    sample = tmp_path / "sample.py"
    source = "from d810.passes.phase import ReconPhase\nphase = ReconPhase(store)\n"
    sample.write_text(source, encoding="utf-8")
    report = tmp_path / "inventory.json"

    proc = subprocess.run(
        [
            sys.executable,
            str(SCRIPT),
            "--root",
            str(tmp_path),
            "--report",
            str(report),
            str(sample),
        ],
        capture_output=True,
        text=True,
        cwd=REPO_ROOT,
        timeout=30,
    )

    assert proc.returncode == 0, proc.stderr
    assert "dry-run: candidates=" in proc.stdout
    assert "would rewrite sample.py" in proc.stdout
    assert sample.read_text(encoding="utf-8") == source
    payload = json.loads(report.read_text(encoding="utf-8"))
    assert payload["summary"]["unknown"] == 0
    assert [candidate["kind"] for candidate in payload["candidates"]] == [
        "legacy-import",
        "legacy-symbol",
    ]


def test_cli_apply_refuses_unknown_patterns_without_writing(tmp_path: Path) -> None:
    sample = tmp_path / "sample.py"
    source = """from d810.passes.phase import ReconPhase
runtime.reset_for_func(0x401000)
"""
    sample.write_text(source, encoding="utf-8")

    proc = subprocess.run(
        [
            sys.executable,
            str(SCRIPT),
            "--root",
            str(tmp_path),
            "--apply",
            str(sample),
        ],
        capture_output=True,
        text=True,
        cwd=REPO_ROOT,
        timeout=30,
    )

    assert proc.returncode == 2
    assert "refusing --apply" in proc.stderr
    assert sample.read_text(encoding="utf-8") == source


def test_cli_apply_requires_an_explicit_test_update(tmp_path: Path) -> None:
    sample = tmp_path / "sample.py"
    source = "from d810.passes.phase import ReconPhase\nphase = ReconPhase(store)\n"
    sample.write_text(source, encoding="utf-8")

    proc = subprocess.run(
        [
            sys.executable,
            str(SCRIPT),
            "--root",
            str(tmp_path),
            "--apply",
            str(sample),
        ],
        capture_output=True,
        text=True,
        cwd=REPO_ROOT,
        timeout=30,
    )

    assert proc.returncode == 2
    assert "--test-update" in proc.stderr
    assert sample.read_text(encoding="utf-8") == source


def test_cli_apply_rewrites_safe_patterns_with_explicit_test_update(
    tmp_path: Path,
) -> None:
    sample = tmp_path / "sample.py"
    test_update = tmp_path / "tests" / "test_lifecycle.py"
    source = "from d810.passes.phase import ReconPhase\nphase = ReconPhase(store)\n"
    sample.write_text(source, encoding="utf-8")
    test_update.parent.mkdir()
    test_update.write_text("def test_updated_expectation():\n    pass\n", encoding="utf-8")

    proc = subprocess.run(
        [
            sys.executable,
            str(SCRIPT),
            "--root",
            str(tmp_path),
            "--apply",
            "--test-update",
            str(test_update),
            str(sample),
        ],
        capture_output=True,
        text=True,
        cwd=REPO_ROOT,
        timeout=30,
    )

    assert proc.returncode == 0, proc.stderr
    assert "apply: rewritten=1" in proc.stdout
    assert sample.read_text(encoding="utf-8") == (
        "from d810.passes.phase import PreanalysisPhase\n"
        "phase = PreanalysisPhase(store)\n"
    )


def test_manifest_gate_allows_only_baseline_manual_residue_and_declared_bridge(
    tmp_path: Path,
) -> None:
    mod = _load_module()
    baseline = {
        "candidates": [
            {
                "path": "src/resolver.py",
                "line": 10,
                "column": 0,
                "kind": "resolver-global-access",
                "detail": "_RESOLUTIONS_BY_EA",
                "rewriteable": False,
            },
            {
                "path": "tests/test_runtime.py",
                "line": 11,
                "column": 0,
                "kind": "direct-runtime-call",
                "detail": "reset_for_func",
                "rewriteable": False,
            },
        ]
    }
    current = {
        "candidates": [
            *baseline["candidates"],
            {
                "path": "src/coordinator.py",
                "line": 20,
                "column": 0,
                "kind": "direct-runtime-call",
                "detail": "analyze_and_persist",
                "rewriteable": False,
            },
        ]
    }
    baseline_path = tmp_path / "baseline.json"
    baseline_path.write_text(json.dumps(baseline), encoding="utf-8")
    bridge_path = tmp_path / "src" / "coordinator.py"
    bridge_path.parent.mkdir()
    bridge_path.write_text("# bridge\n", encoding="utf-8")
    manifest = {
        "schema_version": 1,
        "baseline_report": "baseline.json",
        "retired_manual_kinds": [],
        "direct_runtime": {
            "checkpoint_count": 2,
            "allowed_production": [
                {
                    "path": "src/coordinator.py",
                    "detail": "analyze_and_persist",
                    "maximum": 1,
                }
            ],
        },
        "bridges": [
            {
                "path": "src/coordinator.py",
                "kind": "direct-runtime-call",
                "details": ["analyze_and_persist"],
            }
        ],
    }

    assert mod.verify_manifest(current, manifest, root=tmp_path) == []


def test_manifest_gate_rejects_adapter_direct_calls_and_forgotten_bridge(
    tmp_path: Path,
) -> None:
    mod = _load_module()
    baseline_path = tmp_path / "baseline.json"
    baseline_path.write_text('{"candidates": []}', encoding="utf-8")
    bridge_path = tmp_path / "src" / "coordinator.py"
    bridge_path.parent.mkdir()
    bridge_path.write_text("# bridge\n", encoding="utf-8")
    manifest = {
        "schema_version": 1,
        "baseline_report": "baseline.json",
        "retired_manual_kinds": [],
        "direct_runtime": {
            "checkpoint_count": 1,
            "allowed_production": [
                {
                    "path": "src/coordinator.py",
                    "detail": "reset_for_func",
                    "maximum": 1,
                }
            ],
        },
        "bridges": [
            {
                "path": "src/coordinator.py",
                "kind": "direct-runtime-call",
                "details": ["reset_for_func"],
            }
        ],
    }
    adapter_call = {
        "candidates": [
            {
                "path": "src/adapter.py",
                "line": 20,
                "column": 0,
                "kind": "direct-runtime-call",
                "detail": "reset_for_func",
                "rewriteable": False,
            }
        ]
    }

    errors = mod.verify_manifest(adapter_call, manifest, root=tmp_path)
    assert any("not manifest-allowlisted" in error for error in errors)

    forgotten_bridge = {"candidates": []}
    errors = mod.verify_manifest(forgotten_bridge, manifest, root=tmp_path)
    assert any("must be removed" in error for error in errors)
