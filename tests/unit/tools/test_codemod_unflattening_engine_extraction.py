from __future__ import annotations

import importlib.util
import subprocess
import sys
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[3]
GUIDE_SCRIPT = (
    REPO_ROOT / "tools" / "scripts" / "codemod_unflattening_engine_extension_guide.py"
)
BOUNDARY_SCRIPT = (
    REPO_ROOT / "tools" / "scripts" / "codemod_unflattening_engine_import_boundary.py"
)
HODUR_PACKAGE = "d810.optimizers.microcode.flow.flattening.hodur"


def _load_module(script: Path, name: str):
    spec = importlib.util.spec_from_file_location(name, script)
    assert spec is not None
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def test_extension_guide_renderer_captures_engine_contract() -> None:
    mod = _load_module(GUIDE_SCRIPT, "codemod_engine_extension_guide")

    guide = mod.render_extension_guide()

    assert "detect -> snapshot -> plan -> execute -> provenance" in guide
    assert "Strategies consume a snapshot and emit `PlanFragment` objects." in guide
    assert "diagnostic SQLite" in guide
    assert "sg scan --config sgconfig.yml --report-style short" in guide


def test_extension_guide_dry_run_does_not_write(tmp_path: Path) -> None:
    result = subprocess.run(
        [
            sys.executable,
            str(GUIDE_SCRIPT),
            "--root",
            str(tmp_path),
        ],
        capture_output=True,
        text=True,
        cwd=str(REPO_ROOT),
        timeout=30,
    )

    assert result.returncode == 0, result.stderr
    assert "would write" in result.stdout
    assert "dry-run: 1 file(s)" in result.stdout
    assert not (
        tmp_path
        / "src"
        / "d810"
        / "optimizers"
        / "microcode"
        / "flow"
        / "flattening"
        / "engine"
        / "EXTENSION_GUIDE.md"
    ).exists()


def test_extension_guide_apply_writes_expected_path(tmp_path: Path) -> None:
    result = subprocess.run(
        [
            sys.executable,
            str(GUIDE_SCRIPT),
            "--root",
            str(tmp_path),
            "--apply",
        ],
        capture_output=True,
        text=True,
        cwd=str(REPO_ROOT),
        timeout=30,
    )

    assert result.returncode == 0, result.stderr
    guide_path = (
        tmp_path
        / "src"
        / "d810"
        / "optimizers"
        / "microcode"
        / "flow"
        / "flattening"
        / "engine"
        / "EXTENSION_GUIDE.md"
    )
    assert guide_path.exists()
    assert "Layer Contract" in guide_path.read_text(encoding="utf-8")


def _write_import_boundary_fixture(root: Path) -> None:
    src_dir = root / "src" / "pkg"
    tests_dir = root / "tests"
    tools_dir = root / "tools" / "scripts"
    src_dir.mkdir(parents=True)
    tests_dir.mkdir(parents=True)
    tools_dir.mkdir(parents=True)
    (src_dir / "prod.py").write_text(
        f"from {HODUR_PACKAGE}.strategy import PlanFragment\n",
        encoding="utf-8",
    )
    (tests_dir / "test_engine.py").write_text(
        f"import {HODUR_PACKAGE}.executor as executor\n",
        encoding="utf-8",
    )
    (tools_dir / "codemod_phase99_old.py").write_text(
        f"from {HODUR_PACKAGE} import snapshot\n",
        encoding="utf-8",
    )


def test_import_boundary_report_classifies_current_shim_shapes(tmp_path: Path) -> None:
    _write_import_boundary_fixture(tmp_path)
    mod = _load_module(BOUNDARY_SCRIPT, "codemod_engine_import_boundary")

    hits = mod.scan_imports(tmp_path)
    report = mod.render_report(tmp_path, hits)

    assert {hit.classification for hit in hits} == {
        "blocking-production",
        "historical-codemod",
        "test-rewrite-candidate",
    }
    assert "src/pkg/prod.py:1" in report
    assert "`blocking-production`: 1" in report
    assert "`historical-codemod`: 1" in report


def test_import_boundary_apply_writes_report(tmp_path: Path) -> None:
    _write_import_boundary_fixture(tmp_path)

    result = subprocess.run(
        [
            sys.executable,
            str(BOUNDARY_SCRIPT),
            "--root",
            str(tmp_path),
            "--apply",
        ],
        capture_output=True,
        text=True,
        cwd=str(REPO_ROOT),
        timeout=30,
    )

    assert result.returncode == 0, result.stderr
    report_path = (
        tmp_path
        / ".tmp"
        / "unflattening_engine_extraction"
        / "import_boundary_report.md"
    )
    assert report_path.exists()
    report = report_path.read_text(encoding="utf-8")
    assert "Unflattening Engine Import Boundary Report" in report
    assert "test-rewrite-candidate" in report


def test_import_boundary_fail_on_production(tmp_path: Path) -> None:
    _write_import_boundary_fixture(tmp_path)

    result = subprocess.run(
        [
            sys.executable,
            str(BOUNDARY_SCRIPT),
            "--root",
            str(tmp_path),
            "--fail-on-production",
        ],
        capture_output=True,
        text=True,
        cwd=str(REPO_ROOT),
        timeout=30,
    )

    assert result.returncode == 1
    assert "blocking production compatibility imports found" in result.stdout
