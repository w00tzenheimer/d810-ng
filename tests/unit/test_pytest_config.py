"""Guards for repository-wide pytest configuration."""

from __future__ import annotations

import ast
import os
import pathlib
import subprocess
import sys
import types
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


def test_native_gui_smoke_bypasses_idapro_for_embedded_venv_only(monkeypatch) -> None:
    """The embedded IDA Python executable must not trigger idalib setup."""
    system_conftest = _REPO_ROOT / "tests" / "system" / "conftest.py"
    source = system_conftest.read_text(encoding="utf-8")
    tree = ast.parse(source, filename=str(system_conftest))
    functions = {
        node.name: node
        for node in tree.body
        if isinstance(node, ast.FunctionDef)
        and node.name in {"_is_ida", "_should_initialize_idalib"}
    }

    assert set(functions) == {"_is_ida", "_should_initialize_idalib"}
    namespace = {
        "os": os,
        "pathlib": pathlib,
        "sys": types.SimpleNamespace(executable="/app/ida/.venv/bin/python3"),
    }
    exec(
        compile(
            ast.Module(body=list(functions.values()), type_ignores=[]),
            str(system_conftest),
            "exec",
        ),
        namespace,
    )
    should_initialize = namespace["_should_initialize_idalib"]

    assert should_initialize(native_gui_smoke=True) is False
    assert should_initialize(native_gui_smoke=False) is True
    assert (
        should_initialize(native_gui_smoke=False, executable="/usr/bin/idat64") is False
    )
    monkeypatch.setenv("D810_NATIVE_GUI_SMOKE", "1")
    assert should_initialize() is False
    monkeypatch.setenv("D810_NATIVE_GUI_SMOKE", "0")
    assert should_initialize() is True

    initializer = next(
        node
        for node in tree.body
        if isinstance(node, ast.If)
        and isinstance(node.test, ast.Call)
        and isinstance(node.test.func, ast.Name)
        and node.test.func.id == "_should_initialize_idalib"
    )
    assert any(
        isinstance(node, ast.Import)
        and any(alias.name == "idapro" for alias in node.names)
        for node in ast.walk(initializer)
    )


def test_disposable_idb_keeps_idapro_import_lazy_until_fixture_use() -> None:
    """Native runtime collection must not initialize a separate idalib process."""
    disposable = (
        _REPO_ROOT / "tests" / "system" / "runtime" / "support" / "disposable_idb.py"
    )
    tree = ast.parse(disposable.read_text(encoding="utf-8"), filename=str(disposable))

    def imports_idapro(node: ast.AST) -> bool:
        if isinstance(node, ast.Import):
            return any(alias.name == "idapro" for alias in node.names)
        return isinstance(node, ast.ImportFrom) and node.module == "idapro"

    assert not any(imports_idapro(node) for node in tree.body)
    fixture = next(
        node
        for node in tree.body
        if isinstance(node, ast.FunctionDef) and node.name == "copy_of_idb"
    )
    assert sum(imports_idapro(node) for node in ast.walk(fixture)) == 1
    calls = {
        node.func.attr
        for node in ast.walk(fixture)
        if isinstance(node, ast.Call)
        and isinstance(node.func, ast.Attribute)
        and isinstance(node.func.value, ast.Name)
        and node.func.value.id == "idapro"
    }
    assert {"open_database", "close_database"} <= calls


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


def test_system_ci_allows_llvm_backed_tests_to_skip_when_opt_is_unavailable() -> None:
    workflow = (_REPO_ROOT / ".github" / "workflows" / "python.yml").read_text(
        encoding="utf-8"
    )

    assert "system-tests (idapro-9.2, pure-python)" in workflow
    assert "system-tests (idapro-9.2, speedups)" in workflow
    assert 'LLVM_OPT_PATH=\\"\\$(command -v opt' in workflow
    assert workflow.count('LLVM_OPT_PATH=\\"\\$(command -v opt') >= 2
    assert 'export LLVM_OPT=\\"\\$LLVM_OPT_PATH\\"' in workflow
    assert "LLVM opt: not found; LLVM-backed system tests will skip" in workflow
    assert "ERROR: system tests require LLVM opt for verifier coverage" not in workflow
    assert "export D810_REQUIRE_LLVM_OPT=1" not in workflow
