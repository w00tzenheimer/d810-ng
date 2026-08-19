"""Task 14 packaging boundaries for the core distribution."""

from __future__ import annotations

import os
import re
import subprocess
import sys
import tomllib
from pathlib import Path
from zipfile import ZipFile


ROOT = Path(__file__).resolve().parents[2]


def _metadata() -> dict[str, object]:
    return tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))


def _requirement_names(requirements: list[str]) -> set[str]:
    return {
        re.match(r"^[A-Za-z0-9_.-]+", requirement)
        .group(0)
        .lower()
        .replace("_", "-")
        for requirement in requirements
    }


def test_core_direct_dependencies_do_not_include_provider_runtime() -> None:
    project = _metadata()["project"]
    assert isinstance(project, dict)

    direct = list(project["dependencies"])
    extras = [
        requirement
        for requirements in project["optional-dependencies"].values()
        for requirement in requirements
    ]
    assert not _requirement_names(direct + extras) & {"egglog", "cloudpickle"}


def test_core_egraph_extra_points_only_to_the_external_provider() -> None:
    project = _metadata()["project"]
    assert project["optional-dependencies"]["egraph"] == ["d810-egglog>=0.1.0"]


def test_core_and_extension_python_floors_agree() -> None:
    core_project = _metadata()["project"]
    extension_project = tomllib.loads(
        (ROOT.parent / "d810-egglog-extension" / "pyproject.toml").read_text(
            encoding="utf-8"
        )
    )["project"]

    assert core_project["requires-python"] == ">=3.11"
    assert extension_project["requires-python"] == core_project["requires-python"]


def test_core_release_version_is_the_extension_api_floor() -> None:
    source = (ROOT / "src/d810/__init__.py").read_text(encoding="utf-8")
    assert '__version__ = "1.0.0b2"' in source


def test_core_readme_documents_the_external_egraph_install() -> None:
    readme = (ROOT / "README.md").read_text(encoding="utf-8")
    assert "d810-egglog" in readme


def test_core_readme_documents_the_supported_python_floor() -> None:
    readme = (ROOT / "README.md").read_text(encoding="utf-8")
    assert "Python 3.11 or later" in readme
    assert "Python 3.10 or later" not in readme
    assert "CPython 3.11 through" in readme
    assert "CPython 3.10 through" not in readme


def test_ci_python_matrix_matches_the_project_python_floor() -> None:
    workflow = (ROOT / ".github/workflows/python.yml").read_text(encoding="utf-8")
    project = _metadata()["project"]
    floor_match = re.fullmatch(r">=\s*(\d+\.\d+)", project["requires-python"])
    assert floor_match is not None
    floor = tuple(int(part) for part in floor_match.group(1).split("."))

    version_lists = re.findall(r"python-version:\s*\[([^\]]+)\]", workflow)
    versions = {
        tuple(int(part) for part in value.split("."))
        for values in version_lists
        for value in re.findall(r'"(\d+\.\d+)"', values)
    }

    assert floor in versions
    assert {"3.11", "3.12", "3.13"} <= {
        f"{major}.{minor}" for major, minor in versions
    }
    assert all(version >= floor for version in versions)
    assert "3.10" not in workflow


def test_task14_blocked_import_snippet_uses_exported_registry_helper() -> None:
    paths = (
        ROOT / "docs/superpowers/plans/2026-08-18-d810-egglog-extension-extraction.md",
        ROOT
        / ".superpowers/sdd/2026-08-18-d810-egglog-extension-extraction/task-14-brief.md",
    )
    for path in paths:
        text = path.read_text(encoding="utf-8")
        assert "operational_config_v2_pass_registry" in text
        assert "operational_pass_registry" not in text


def test_blocked_optional_imports_preserve_public_mba_egraph_registration() -> None:
    script = """
import builtins

real_import = builtins.__import__


def blocked(name, *args, **kwargs):
    if name == "egglog" or name == "cloudpickle" or name.startswith("d810_egglog"):
        raise ImportError(f"blocked optional dependency: {name}")
    return real_import(name, *args, **kwargs)


builtins.__import__ = blocked
import d810
from d810.passes.operational_config_v2 import operational_config_v2_pass_registry

assert "mba-egraph" in operational_config_v2_pass_registry().public_pass_ids()
print("blocked core import proof: PASS")
"""
    environment = os.environ.copy()
    environment["PYTHONPATH"] = str(ROOT / "src")
    result = subprocess.run(
        [sys.executable, "-c", script],
        cwd=ROOT,
        env=environment,
        capture_output=True,
        text=True,
        check=False,
    )
    assert result.returncode == 0, result.stdout + result.stderr
    assert "blocked core import proof: PASS" in result.stdout


def test_core_wheel_metadata_record_and_installation(tmp_path: Path) -> None:
    output_dir = tmp_path / "dist"
    output_dir.mkdir()
    environment = os.environ.copy()
    environment.pop("PYTHONPATH", None)
    result = subprocess.run(
        [
            sys.executable,
            "-m",
            "pip",
            "wheel",
            ".",
            "--no-deps",
            "--no-build-isolation",
            "--wheel-dir",
            str(output_dir),
        ],
        cwd=ROOT,
        env=environment,
        capture_output=True,
        text=True,
        check=False,
    )
    assert result.returncode == 0, result.stdout + result.stderr

    wheels = sorted(output_dir.glob("d810_ng-*.whl"))
    assert len(wheels) == 1
    with ZipFile(wheels[0]) as archive:
        names = set(archive.namelist())
        metadata_name = next(name for name in names if name.endswith(".dist-info/METADATA"))
        metadata = archive.read(metadata_name).decode("utf-8")
        assert "Version: 1.0.0b2" in metadata
        assert "Requires-Python: >=3.11" in metadata
        assert "Requires-Dist: d810-egglog>=0.1.0" in metadata
        assert "Requires-Dist: egglog" not in metadata
        assert "Requires-Dist: cloudpickle" not in metadata

        for name in names:
            if name.endswith("entry_points.txt"):
                assert "[d810.backends]" not in archive.read(name).decode("utf-8")

        record_name = next(name for name in names if name.endswith(".dist-info/RECORD"))
        record_names = {
            line.split(",", 1)[0]
            for line in archive.read(record_name).decode("utf-8").splitlines()
        }
        assert names <= record_names

    virtualenv = tmp_path / "venv"
    create = subprocess.run(
        [sys.executable, "-m", "venv", str(virtualenv)],
        cwd=ROOT,
        env=environment,
        capture_output=True,
        text=True,
        check=False,
    )
    assert create.returncode == 0, create.stdout + create.stderr
    python = virtualenv / "bin/python"
    install = subprocess.run(
        [str(python), "-m", "pip", "install", "--no-deps", str(wheels[0])],
        cwd=ROOT,
        env=environment,
        capture_output=True,
        text=True,
        check=False,
    )
    assert install.returncode == 0, install.stdout + install.stderr
    probe = subprocess.run(
        [
            str(python),
            "-c",
            (
                "from importlib.metadata import entry_points, version; "
                "import d810; "
                "assert version('d810-ng') == '1.0.0b2'; "
                "assert tuple(entry_points(group='d810.backends')) == ()"
            ),
        ],
        cwd=ROOT,
        env=environment,
        capture_output=True,
        text=True,
        check=False,
    )
    assert probe.returncode == 0, probe.stdout + probe.stderr
