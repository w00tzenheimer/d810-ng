"""Tests for the committed MBA research provenance audit."""

from __future__ import annotations

import importlib.util
import json
from pathlib import Path

import pytest


REPO_ROOT = Path(__file__).resolve().parents[3]
MANIFEST_PATH = REPO_ROOT / "tests/fixtures/mba_portfolio/research_sources.json"
CHECKER_PATH = REPO_ROOT / "tools/scripts/check_mba_research_sources.py"

EXPECTED_COMMITS = {
    "Simplifier": "813cdc7",
    "MSiMBA": "7a0fa6d",
    "mbased": "66a7472",
    "inspecting-compiler-opts": "daf5ef2",
    "M3": "1f9931a",
    "arybo": "89d9a42",
    "GAMBA": "96691c0",
    "SiMBA": "2281799",
    "ferret": "6c91995",
    "MBA": "4650495",
    "SiMBA-": "2681863",
}


def _load_checker():
    spec = importlib.util.spec_from_file_location("check_mba_research_sources", CHECKER_PATH)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _write_manifest(tmp_path: Path, sources: list[dict[str, object]]) -> Path:
    path = tmp_path / "research_sources.json"
    path.write_text(json.dumps(sources), encoding="utf-8")
    return path


def test_manifest_pins_all_eleven_reviewed_snapshots() -> None:
    checker = _load_checker()

    sources = checker.load_research_sources(MANIFEST_PATH)

    assert {source.name: source.reviewed_commit for source in sources} == EXPECTED_COMMITS
    assert checker.validate_research_sources(sources) == ()


def test_research_only_sources_cannot_be_copied() -> None:
    checker = _load_checker()
    sources = checker.load_research_sources(MANIFEST_PATH)

    no_license = {source.name for source in sources if source.license is None}
    gpl = {source.name for source in sources if source.license == "GPL-3.0"}

    assert no_license == {"inspecting-compiler-opts", "M3", "MBA"}
    assert gpl == {"Simplifier", "MSiMBA", "GAMBA", "SiMBA", "SiMBA-"}
    assert all(not source.copy_allowed for source in sources if source.name in no_license | gpl)


@pytest.mark.parametrize("license_name", [None, "GPL-3.0", "GPL-2.0"])
def test_validator_rejects_copying_without_a_compatible_license(
    tmp_path: Path, license_name: str | None
) -> None:
    checker = _load_checker()
    path = _write_manifest(
        tmp_path,
        [
            {
                "name": "unsafe",
                "url": "https://example.com/unsafe",
                "reviewed_commit": "abc1234",
                "license": license_name,
                "copy_allowed": True,
                "retained_ideas": ["idea"],
            }
        ],
    )

    sources = checker.load_research_sources(path)

    assert checker.validate_research_sources(sources) == (
        f"unsafe: copy_allowed=true requires a D810-compatible license; observed {license_name!r}",
    )


def test_loader_rejects_missing_and_unknown_fields_deterministically(tmp_path: Path) -> None:
    checker = _load_checker()
    path = _write_manifest(
        tmp_path,
        [
            {
                "name": "broken",
                "url": "https://example.com/broken",
                "reviewed_commit": "abc1234",
                "license": "MIT",
                "copy_allowed": False,
                "unexpected": "value",
            }
        ],
    )

    with pytest.raises(
        ValueError,
        match=r"^source\[0\]: invalid fields \(missing: retained_ideas; unknown: unexpected\)$",
    ):
        checker.load_research_sources(path)
