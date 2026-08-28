"""Fail-closed inventory checks for committed native fixture artifacts."""

from __future__ import annotations

from pathlib import Path


REPO = Path(__file__).resolve().parents[3]


def test_committed_windows_fixture_contains_every_tracked_masm_export() -> None:
    """Keep the shared MASM source corpus and committed DLL synchronized."""

    fixture = (REPO / "samples/bins/libobfuscated.dll").read_bytes()
    required_exports = tuple(
        sorted(source.stem for source in (REPO / "samples/src/masm").glob("*.asm"))
    )
    missing = [
        name for name in required_exports if name.encode("ascii") + b"\0" not in fixture
    ]

    assert missing == [], (
        "committed samples/bins/libobfuscated.dll is stale; rebuild it with "
        f"samples/scripts/build_windows.ps1 (missing exports: {missing})"
    )
