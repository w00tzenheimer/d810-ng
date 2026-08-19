"""Task 14 packaging boundaries for the core distribution."""

from __future__ import annotations

import re
import tomllib
from pathlib import Path


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


def test_core_release_version_is_the_extension_api_floor() -> None:
    source = (ROOT / "src/d810/__init__.py").read_text(encoding="utf-8")
    assert '__version__ = "1.0.0b2"' in source


def test_core_readme_documents_the_external_egraph_install() -> None:
    readme = (ROOT / "README.md").read_text(encoding="utf-8")
    assert "d810-egglog" in readme
