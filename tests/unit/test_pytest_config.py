"""Guards for repository-wide pytest configuration."""

from __future__ import annotations

import ast
import os
import subprocess
import sys
from pathlib import Path


_REPO_ROOT = Path(__file__).resolve().parents[2]


def _top_level_imports(path: Path) -> set[str]:
    tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    names: set[str] = set()
    for node in tree.body:
        if isinstance(node, ast.Import):
            names.update(alias.name.split(".", 1)[0] for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module:
            names.add(node.module.split(".", 1)[0])
    return names


def test_root_conftest_does_not_require_idapro_for_unit_collection() -> None:
    root_conftest = _REPO_ROOT / "tests" / "conftest.py"

    assert "idapro" not in _top_level_imports(root_conftest)


def test_system_conftest_owns_idapro_initialization() -> None:
    system_conftest = _REPO_ROOT / "tests" / "system" / "conftest.py"
    text = system_conftest.read_text(encoding="utf-8")

    assert "import idapro" in text
    assert "System tests require IDA Pro or idalib." in text


def test_condition_chain_provider_import_does_not_require_live_ida() -> None:
    code = """
import importlib
import sys

for name in ("idapro", "idaapi", "ida_hexrays"):
    sys.modules[name] = None

mod = importlib.import_module("d810.backends.hexrays.evidence.condition_chain_analysis")
mod.build_condition_chain_walker_provider()
"""
    env = dict(os.environ)
    env["PYTHONPATH"] = str(_REPO_ROOT / "src")
    result = subprocess.run(
        [sys.executable, "-c", code],
        cwd=_REPO_ROOT,
        env=env,
        text=True,
        capture_output=True,
        check=False,
    )

    assert result.returncode == 0, result.stderr


def test_codemod_tool_tests_have_libcst_in_dev_and_ci_dependencies() -> None:
    pyproject = (_REPO_ROOT / "pyproject.toml").read_text(encoding="utf-8")
    workflow = (_REPO_ROOT / ".github" / "workflows" / "python.yml").read_text(
        encoding="utf-8"
    )

    assert '"libcst>=1.0.0"' in pyproject
    assert "pytest pytest-cov import-linter vermin libcst" in workflow
    assert "pytest pytest-cov libcst" in workflow


def test_unit_ci_provisions_llvm_opt_for_real_verifier_coverage() -> None:
    workflow = (_REPO_ROOT / ".github" / "workflows" / "python.yml").read_text(
        encoding="utf-8"
    )

    assert "Install LLVM opt" in workflow
    assert "sudo apt-get install -y -qq llvm" in workflow
    assert 'echo "LLVM_OPT=$(command -v opt)" >> "$GITHUB_ENV"' in workflow
    assert workflow.count('echo "LLVM_OPT=$(command -v opt)" >> "$GITHUB_ENV"') >= 2
