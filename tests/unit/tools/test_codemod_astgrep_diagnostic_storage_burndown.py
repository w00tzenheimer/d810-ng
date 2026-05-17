from __future__ import annotations

import importlib.util
import subprocess
import sys
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[3]
SCRIPT = (
    REPO_ROOT
    / "tools"
    / "scripts"
    / "codemod_astgrep_diagnostic_storage_burndown.py"
)


def _load_module():
    spec = importlib.util.spec_from_file_location("codemod_diag_burndown", SCRIPT)
    assert spec is not None
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def test_strip_ignores_preserves_rule_body() -> None:
    mod = _load_module()
    text = """id: no-example
language: python
ignores:
  # comment
  - "src/example.py"
message: |
  nope
rule:
  pattern: import sqlite3
"""

    assert mod.parse_ignores(text) == ("src/example.py",)
    stripped = mod.strip_ignores_block(text)

    assert "ignores:" not in stripped
    assert "message: |" in stripped
    assert "pattern: import sqlite3" in stripped


def test_rewrite_import_text_handles_moved_modules_and_symbols() -> None:
    mod = _load_module()
    source = "\n".join(
        [
            "from d810.recon.flow.edge_diagnostics import classify_dag_edges",
            "from d810.recon.flow.selected_alternate_edge_override import apply_selected_alternate_edge_overrides, apply_selected_alternate_edge_overrides_from_diag",
            "",
        ]
    )

    result = mod.rewrite_import_text(source, path=Path("sample.py"))

    assert result.warnings == ()
    assert (
        "from d810.diagnostics.edge_diagnostics import classify_dag_edges"
        in result.text
    )
    assert (
        "from d810.recon.flow.selected_alternate_edge_override import "
        "apply_selected_alternate_edge_overrides"
        in result.text
    )
    assert (
        "from d810.diagnostics.selected_alternate_edge_override import "
        "apply_selected_alternate_edge_overrides_from_diag"
        in result.text
    )


def test_render_report_lists_ignores_and_phase_manifest() -> None:
    mod = _load_module()
    inventory = mod.RuleInventory(
        rule_path="rules/no-example.yml",
        rule_id="no-example",
        ignores=("src/example.py",),
        no_ignore_returncode=1,
        hits=(
            mod.SgHit(
                path="src/example.py",
                line=1,
                col=1,
                severity="error",
                rule="no-example",
                message="Nope",
            ),
        ),
        raw_output="",
    )

    report = mod.render_report((inventory,))
    manifest = mod.build_manifest(Path("/repo"), (inventory,))

    assert "`no-example`" in report
    assert "`src/example.py:1:1`" in report
    assert "`phase2-optimizer-hcc-diagnostic-query`" in report
    assert manifest["rules"][0]["ignores"] == ["src/example.py"]
    assert (
        manifest["candidate_phases"][2]["automation"]
        == "completed-provider-boundary"
    )


def test_rewrite_imports_cli_dry_run_does_not_write(tmp_path: Path) -> None:
    sample = tmp_path / "sample.py"
    sample.write_text(
        "from d810.recon.flow.edge_diagnostics import classify_dag_edges\n",
        encoding="utf-8",
    )

    result = subprocess.run(
        [
            sys.executable,
            str(SCRIPT),
            "rewrite-imports",
            "--root",
            str(tmp_path),
            str(sample),
        ],
        capture_output=True,
        text=True,
        cwd=str(REPO_ROOT),
        timeout=30,
    )

    assert result.returncode == 0, result.stderr
    assert "would rewrite" in result.stdout
    assert "--- " in result.stdout
    assert "dry-run: rewritten=1 warnings=0" in result.stdout
    assert "d810.recon.flow.edge_diagnostics" in sample.read_text(encoding="utf-8")
