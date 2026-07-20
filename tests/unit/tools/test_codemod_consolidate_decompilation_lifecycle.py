from __future__ import annotations

import importlib.util
import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[3]
SCRIPT = (
    REPO_ROOT / "tools" / "scripts" / "codemod_consolidate_decompilation_lifecycle.py"
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
writer_patch = "d810.passes.runtime.get_recon_writer"
message = f"ReconResult.metrics for {bundle!r}"
"""

    result = mod.rewrite_text(source)

    assert result.changed
    assert "from d810.passes.phase import PreanalysisPhase" in result.text
    assert (
        "from d810.passes.analysis_runtime_factory import AnalysisRuntimeBundle"
        in result.text
    )
    assert "AnalysisRuntimeBundle(recon_phase=PreanalysisPhase(store))" in result.text
    assert '"enable_analysis_pipeline"' in result.text
    assert '"analysis_db"' in result.text
    assert '"D810.preanalysis.flowgraph_ready"' in result.text
    assert "DecompilationEvent.SESSION_STARTED" in result.text
    assert '"d810.passes.runtime.get_preanalysis_writer"' in result.text
    assert 'f"PreanalysisResult.metrics for {bundle!r}"' in result.text
    assert "ReconPhase" not in result.text
    assert "recon_phase" in result.text


def test_bundle_phase_injection_is_manual_because_the_new_owner_is_a_runtime(
    tmp_path: Path,
) -> None:
    mod = _load_module()
    sample = tmp_path / "sample.py"
    sample.write_text(
        "bundle = ReconRuntimeBundle(recon_phase=ReconPhase(store))\n",
        encoding="utf-8",
    )

    candidates = mod.scan_paths([sample], root=tmp_path)

    assert any(
        candidate.kind == "manual-lifecycle-owner"
        and candidate.detail == "recon_phase"
        and not candidate.rewriteable
        for candidate in candidates
    )


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


def test_scan_inventories_legacy_resolver_api_calls_in_tools(tmp_path: Path) -> None:
    mod = _load_module()
    sample = tmp_path / "tools" / "probe.py"
    sample.parent.mkdir()
    sample.write_text(
        "resolver.mark_indirect_dispatcher(0x401000)\n",
        encoding="utf-8",
    )

    candidates = mod.scan_paths([sample], root=tmp_path)

    assert [
        (candidate.kind, candidate.detail, candidate.rewriteable)
        for candidate in candidates
    ] == [
        ("resolver-global-access", "mark_indirect_dispatcher", False),
    ]


def test_scan_allows_session_owned_indirect_dispatcher_marker(tmp_path: Path) -> None:
    mod = _load_module()
    sample = tmp_path / "src" / "resolver.py"
    sample.parent.mkdir()
    sample.write_text(
        "resolver.mark_indirect_dispatcher(session_state)\n",
        encoding="utf-8",
    )

    assert mod.scan_paths([sample], root=tmp_path) == []


def test_scan_reports_json_config_keys_as_rewriteable_migration_points(
    tmp_path: Path,
) -> None:
    mod = _load_module()
    config = tmp_path / "default.json"
    config.write_text(
        '{"additional_configuration": {"recon_fact_profile_modules": []}}\n',
        encoding="utf-8",
    )

    candidates = mod.scan_paths([config], root=tmp_path)

    assert {(candidate.kind, candidate.rewriteable) for candidate in candidates} == {
        ("legacy-config-key", True),
    }


def test_json_rewrite_and_inventory_only_touch_object_keys(tmp_path: Path) -> None:
    mod = _load_module()
    source = '{"recon_db": "recon_db"}\n'
    config = tmp_path / "default.json"
    config.write_text(source, encoding="utf-8")

    result = mod.rewrite_json_text(source)
    candidates = mod.scan_paths([config], root=tmp_path)

    assert result.text == '{"analysis_db": "recon_db"}\n'
    assert [(candidate.detail, candidate.rewriteable) for candidate in candidates] == [
        ("recon_db", True),
    ]


def test_default_discovery_excludes_its_own_fixture_test(tmp_path: Path) -> None:
    mod = _load_module()
    fixture = tmp_path / "tests" / mod.SELF_TEST_FILE
    fixture.parent.mkdir()
    fixture.write_text("phase = ReconPhase(store)\n", encoding="utf-8")

    assert fixture.resolve() not in mod.discover_paths(tmp_path, [])


def test_default_discovery_excludes_the_codemod_implementation() -> None:
    mod = _load_module()

    assert SCRIPT.resolve() not in mod.discover_paths(REPO_ROOT, [])


def test_default_discovery_excludes_graphify_artifacts(tmp_path: Path) -> None:
    mod = _load_module()
    artifact = tmp_path / "src" / "graphify-out" / "cache" / "artifact.py"
    artifact.parent.mkdir(parents=True)
    artifact.write_text("phase = ReconPhase(store)\n", encoding="utf-8")

    assert artifact.resolve() not in mod.discover_paths(tmp_path, [])


def test_default_discovery_includes_tools_and_cli_metadata(tmp_path: Path) -> None:
    mod = _load_module()
    tool = tmp_path / "tools" / "recon_tool.py"
    tool.parent.mkdir()
    tool.write_text("def main():\n    pass\n", encoding="utf-8")
    metadata = tmp_path / "pyproject.toml"
    metadata.write_text(
        "[project.scripts]\nd810-recon = 'd810.cli:main'\n",
        encoding="utf-8",
    )

    discovered = mod.discover_paths(tmp_path, [])

    assert tool.resolve() in discovered
    assert metadata.resolve() in discovered


def test_default_discovery_includes_product_docs_and_text_configuration(
    tmp_path: Path,
) -> None:
    mod = _load_module()
    product_readme = tmp_path / "README.md"
    headless_docs = tmp_path / "HEADLESS.md"
    nested_docs = tmp_path / "src" / "d810" / "EXTENSION_GUIDE.md"
    yaml_config = tmp_path / "src" / "d810" / "default.yml"
    cython_source = tmp_path / "src" / "d810" / "runtime.pyx"
    shell_tool = tmp_path / "tools" / "probe.sh"
    migration_plan = tmp_path / "TODO.md"
    nested_docs.parent.mkdir(parents=True)
    shell_tool.parent.mkdir(parents=True)
    for path in (
        product_readme,
        headless_docs,
        nested_docs,
        yaml_config,
        cython_source,
        shell_tool,
        migration_plan,
    ):
        path.write_text("placeholder\n", encoding="utf-8")

    discovered = mod.discover_paths(tmp_path, [])

    assert product_readme.resolve() in discovered
    assert headless_docs.resolve() in discovered
    assert nested_docs.resolve() in discovered
    assert yaml_config.resolve() in discovered
    assert cython_source.resolve() in discovered
    assert shell_tool.resolve() in discovered
    assert migration_plan.resolve() not in discovered


def test_scan_inventories_residual_terminology_in_docs_comments_logs_and_paths(
    tmp_path: Path,
) -> None:
    mod = _load_module()
    docs = tmp_path / "src" / "d810" / "guide.md"
    source = tmp_path / "src" / "d810" / "worker.py"
    legacy_path = tmp_path / "src" / "d810" / "recon_dag_index.py"
    docs.parent.mkdir(parents=True)
    docs.write_text(
        "ReconStore persists recon_fact_profiles. "
        "The recon-lifecycle label is also legacy. "
        "Reconstruction and reconciliation are unrelated words.\n",
        encoding="utf-8",
    )
    source.write_text(
        "# Recon pipeline disabled\n"
        "message = 'D810.recon.flowgraph_ready'\n"
        "label = 'recon_artifacts'\n",
        encoding="utf-8",
    )
    legacy_path.write_text("VALUE = 1\n", encoding="utf-8")

    candidates = mod.scan_paths([docs, source, legacy_path], root=tmp_path)
    triples = {
        (candidate.path, candidate.kind, candidate.detail) for candidate in candidates
    }

    assert ("src/d810/guide.md", "residual-recon-text", "ReconStore") in triples
    assert (
        "src/d810/guide.md",
        "residual-recon-text",
        "recon_fact_profiles",
    ) in triples
    assert (
        "src/d810/guide.md",
        "residual-recon-text",
        "recon-lifecycle",
    ) in triples
    assert ("src/d810/worker.py", "residual-recon-text", "Recon") in triples
    assert (
        "src/d810/worker.py",
        "legacy-log-prefix",
        "D810.recon.flowgraph_ready",
    ) in triples
    assert (
        "src/d810/worker.py",
        "residual-recon-text",
        "recon_artifacts",
    ) in triples
    assert (
        "src/d810/recon_dag_index.py",
        "residual-recon-path",
        "recon_dag_index.py",
    ) in triples
    assert not any(
        candidate.detail in {"Reconstruction", "reconciliation"}
        for candidate in candidates
    )


def test_scan_anchors_implicit_string_residue_to_the_physical_literal_line(
    tmp_path: Path,
) -> None:
    mod = _load_module()
    source = tmp_path / "sample.py"
    source.write_text(
        "message = (\n    'ordinary prefix ' \n    'recon collector gap'\n)\n",
        encoding="utf-8",
    )

    candidates = mod.scan_paths([source], root=tmp_path)

    assert any(
        candidate.line == 3
        and candidate.kind == "residual-recon-text"
        and candidate.detail == "recon"
        for candidate in candidates
    )


def test_plain_text_inventory_is_never_rewritten_as_toml(tmp_path: Path) -> None:
    mod = _load_module()
    docs = tmp_path / "README.md"
    source = "d810-recon = historical command spelling\n"
    docs.write_text(source, encoding="utf-8")

    assert mod._rewrite_candidates([docs]) == []
    assert docs.read_text(encoding="utf-8") == source


def test_toml_inventory_and_rewrite_only_touch_console_script_key(
    tmp_path: Path,
) -> None:
    mod = _load_module()
    metadata = tmp_path / "pyproject.toml"
    source = (
        "[project.scripts]\n"
        "  d810-recon = 'd810.cli:main'\n"
        "description = 'd810-recon remains in this message'\n"
    )
    metadata.write_text(source, encoding="utf-8")

    candidates = mod.scan_paths([metadata], root=tmp_path)
    result = mod.rewrite_toml_text(source)

    assert [
        (candidate.kind, candidate.detail, candidate.rewriteable)
        for candidate in candidates
    ] == [
        ("legacy-cli-name", "d810-recon", True),
    ]
    assert result.text == (
        "[project.scripts]\n"
        "  d810-preanalysis = 'd810.cli:main'\n"
        "description = 'd810-recon remains in this message'\n"
    )


def test_scan_inventories_unknown_recon_apis_and_cli_names(tmp_path: Path) -> None:
    mod = _load_module()
    sample = tmp_path / "sample.py"
    sample.write_text(
        "def recon_orphan():\n    return None\nparser.add_argument('--recon-orphan')\n",
        encoding="utf-8",
    )

    candidates = mod.scan_paths([sample], root=tmp_path)

    assert {
        (candidate.kind, candidate.detail, candidate.rewriteable)
        for candidate in candidates
    } >= {
        ("residual-recon-api", "recon_orphan", False),
        ("legacy-cli-name", "--recon-orphan", False),
    }


def test_scan_inventories_residual_recon_module_imports(tmp_path: Path) -> None:
    mod = _load_module()
    sample = tmp_path / "sample.py"
    sample.write_text(
        "from d810.analyses.control_flow.recon_dag_index import build_index\n"
        "import d810.core.observability_recon\n",
        encoding="utf-8",
    )

    candidates = mod.scan_paths([sample], root=tmp_path)

    assert {
        (candidate.kind, candidate.detail, candidate.rewriteable)
        for candidate in candidates
    } >= {
        (
            "residual-recon-api",
            "d810.analyses.control_flow.recon_dag_index",
            False,
        ),
        ("residual-recon-api", "d810.core.observability_recon", False),
    }


def test_scan_classifies_declared_cli_rename_as_rewriteable(tmp_path: Path) -> None:
    mod = _load_module()
    sample = tmp_path / "sample.py"
    sample.write_text("parser.add_argument('--recon-db')\n", encoding="utf-8")

    candidates = mod.scan_paths([sample], root=tmp_path)

    assert [
        (candidate.kind, candidate.detail, candidate.rewriteable)
        for candidate in candidates
    ] == [
        ("legacy-cli-name", "--recon-db", True),
    ]
    assert mod.rewrite_text(sample.read_text(encoding="utf-8")).text == (
        'parser.add_argument("--analysis-db")\n'
    )


def test_scan_classifies_declared_legacy_definitions_as_rewriteable(
    tmp_path: Path,
) -> None:
    mod = _load_module()
    sample = tmp_path / "sample.py"
    sample.write_text(
        "class ReconPhase:\n    pass\n\ndef recon_db_path():\n    return None\n",
        encoding="utf-8",
    )

    candidates = mod.scan_paths([sample], root=tmp_path)

    assert {
        (candidate.kind, candidate.detail, candidate.rewriteable)
        for candidate in candidates
    } >= {
        ("legacy-symbol", "ReconPhase", True),
        ("legacy-symbol", "recon_db_path", True),
    }


def test_scan_inventories_rewriteable_dotted_mock_targets(tmp_path: Path) -> None:
    mod = _load_module()
    sample = tmp_path / "sample.py"
    sample.write_text(
        'patch("d810.passes.runtime.get_recon_writer")\n',
        encoding="utf-8",
    )

    candidates = mod.scan_paths([sample], root=tmp_path)

    assert [
        (candidate.kind, candidate.detail, candidate.rewriteable)
        for candidate in candidates
    ] == [
        ("legacy-symbol", "d810.passes.runtime.get_recon_writer", True),
    ]


def test_scan_does_not_misclassify_internal_reset_helpers_as_runtime_ports(
    tmp_path: Path,
) -> None:
    mod = _load_module()
    sample = tmp_path / "sample.py"
    sample.write_text(
        "runtime.reset_for_func(0x401000)\n"
        "self._analysis_runtime.analyze_and_persist(0x401000)\n"
        "self._fact_lifecycle.reset_for_func(0x401000)\n"
        "self._outcome_log.reset_for_func(0x401000)\n",
        encoding="utf-8",
    )

    candidates = mod.scan_paths([sample], root=tmp_path)

    assert [
        candidate.detail
        for candidate in candidates
        if candidate.kind == "direct-runtime-call"
    ] == [
        "reset_for_func",
        "analyze_and_persist",
    ]


def test_cli_dry_run_writes_inventory_but_does_not_rewrite_source(
    tmp_path: Path,
) -> None:
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
    assert payload["summary"]["production"] == {
        "by_kind": {"legacy-import": 1, "legacy-symbol": 1},
        "candidates": 2,
        "rewritable": 2,
        "unknown": 0,
    }
    assert [candidate["kind"] for candidate in payload["candidates"]] == [
        "legacy-import",
        "legacy-symbol",
    ]


def test_report_breaks_inventory_down_by_owned_surface(tmp_path: Path) -> None:
    mod = _load_module()
    candidates = [
        mod.Candidate(
            "src/d810/runtime.py", 1, 0, "residual-recon-text", "Recon", False
        ),
        mod.Candidate(
            "tests/test_runtime.py", 1, 0, "residual-recon-text", "Recon", False
        ),
        mod.Candidate("tools/probe.py", 1, 0, "residual-recon-text", "Recon", False),
        mod.Candidate("README.md", 1, 0, "residual-recon-text", "Recon", False),
        mod.Candidate(
            "config/default.yml", 1, 0, "residual-recon-text", "recon_db", False
        ),
    ]

    payload = mod._report_payload(tmp_path, candidates)
    summary = payload["summary"]

    assert payload["root"] == "."
    assert summary["source"]["candidates"] == 1
    assert summary["tests"]["candidates"] == 1
    assert summary["tools"]["candidates"] == 1
    assert summary["documentation"]["candidates"] == 1
    assert summary["configuration"]["candidates"] == 1


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
    test_update.write_text(
        "def test_updated_expectation():\n    pass\n", encoding="utf-8"
    )

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


def test_apply_rewrites_preserves_executable_mode(tmp_path: Path) -> None:
    mod = _load_module()
    executable = tmp_path / "d810cli.py"
    executable.write_text(
        "from d810.passes.phase import ReconPhase\n",
        encoding="utf-8",
    )
    os.chmod(executable, 0o755)

    mod.apply_rewrites(mod._rewrite_candidates([executable]))

    assert executable.stat().st_mode & 0o777 == 0o755
    assert "PreanalysisPhase" in executable.read_text(encoding="utf-8")


def test_apply_rewrites_rolls_back_every_file_when_one_commit_fails(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    mod = _load_module()
    first = tmp_path / "first.py"
    second = tmp_path / "second.py"
    original = "from d810.passes.phase import ReconPhase\n"
    first.write_text(original, encoding="utf-8")
    second.write_text(original, encoding="utf-8")
    rewrites = mod._rewrite_candidates([first, second])
    real_replace = mod.os.replace
    failed = False

    def fail_second_commit(source: str | Path, destination: str | Path) -> None:
        nonlocal failed
        if Path(destination) == second and not failed:
            failed = True
            raise OSError("simulated commit failure")
        real_replace(source, destination)

    monkeypatch.setattr(mod.os, "replace", fail_second_commit)

    with pytest.raises(OSError, match="simulated commit failure"):
        mod.apply_rewrites(rewrites)

    assert first.read_text(encoding="utf-8") == original
    assert second.read_text(encoding="utf-8") == original


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


def test_cli_manifest_gate_cannot_overwrite_its_baseline_before_verification(
    tmp_path: Path,
) -> None:
    sample = tmp_path / "sample.py"
    sample.write_text("def recon_orphan():\n    return None\n", encoding="utf-8")
    baseline = tmp_path / "baseline.json"
    original_baseline = '{"candidates": []}\n'
    baseline.write_text(original_baseline, encoding="utf-8")
    manifest = tmp_path / "manifest.json"
    manifest.write_text(
        json.dumps(
            {
                "schema_version": 1,
                "baseline_report": "baseline.json",
                "retired_manual_kinds": [],
                "direct_runtime": {
                    "checkpoint_count": 0,
                    "allowed_production": [],
                },
                "temporary_internal_ports": [],
                "bridges": [],
            }
        ),
        encoding="utf-8",
    )

    proc = subprocess.run(
        [
            sys.executable,
            str(SCRIPT),
            "--root",
            str(tmp_path),
            "--report",
            str(baseline),
            "--manifest",
            str(manifest),
            str(sample),
        ],
        capture_output=True,
        text=True,
        cwd=REPO_ROOT,
        timeout=30,
    )

    assert proc.returncode == 2
    assert "manifest violation" in proc.stderr
    assert baseline.read_text(encoding="utf-8") == original_baseline


def test_manifest_bounds_and_self_retires_temporary_internal_port(
    tmp_path: Path,
) -> None:
    mod = _load_module()
    baseline_path = tmp_path / "baseline.json"
    baseline_path.write_text('{"candidates": []}', encoding="utf-8")
    manifest = {
        "schema_version": 1,
        "baseline_report": "baseline.json",
        "retired_manual_kinds": [],
        "direct_runtime": {
            "checkpoint_count": 0,
            "allowed_production": [],
        },
        "temporary_internal_ports": [
            {
                "detail": "temporary_probe_override",
                "locations": [
                    {
                        "path": "src/resolver.py",
                        "role": "definition",
                        "maximum": 1,
                    },
                    {
                        "path": "tools/probe.py",
                        "role": "consumer",
                        "maximum": 1,
                    },
                ],
                "removal_condition": "Remove after the PREOPT proof.",
            }
        ],
        "bridges": [],
    }
    definition = {
        "path": "src/resolver.py",
        "line": 1,
        "column": 0,
        "kind": "temporary-internal-port",
        "detail": "temporary_probe_override",
        "rewriteable": False,
    }
    consumer = {
        "path": "tools/probe.py",
        "line": 1,
        "column": 0,
        "kind": "temporary-internal-port",
        "detail": "temporary_probe_override",
        "rewriteable": False,
    }

    assert (
        mod.verify_manifest(
            {"candidates": [definition, consumer]},
            manifest,
            root=tmp_path,
        )
        == []
    )

    errors = mod.verify_manifest(
        {"candidates": [definition]},
        manifest,
        root=tmp_path,
    )
    assert any("no remaining consumers" in error for error in errors)

    errors = mod.verify_manifest(
        {"candidates": []},
        manifest,
        root=tmp_path,
    )
    assert any("manifest entry has retired" in error for error in errors)
