"""Fail-closed inventory checks for committed native fixture artifacts."""

from __future__ import annotations

from pathlib import Path


REPO = Path(__file__).resolve().parents[3]

#: Exports whose MASM source is checked in but which have not yet been folded
#: into the canonical ``samples/bins/libobfuscated.dll`` build.  Each one still
#: has to ship a committed DLL of its own (see the second assertion below), so
#: this list admits the transitional state without letting a missing artifact
#: through.  Drop an entry here once the next canonical Windows build
#: (``samples/scripts/build_windows.ps1``) picks the export up.
PENDING_CANONICAL_BUILD = frozenset(
    {
        # d81-jlfw: shipped as samples/bins/jlfw_folded_tail.dll, the local
        # compatibility build emitted by `d810cli fixture`.
        "sub_7FFB0E398850",
        # d81-czrc: shipped as samples/bins/computed_state_writers.dll, built
        # with samples/scripts/build_masm.sh (llvm-ml64 + lld-link, 0
        # unresolved externs).  Drop this entry once the canonical Windows
        # build folds the two computed-state-writer fixtures into
        # libobfuscated.dll -- until then their DSL cases SKIP.
        "computed_state_writers",
    }
)


def _committed_dlls() -> tuple[Path, ...]:
    return tuple(sorted((REPO / "samples/bins").glob("*.dll")))


def _tracked_masm_exports() -> tuple[str, ...]:
    return tuple(
        sorted(source.stem for source in (REPO / "samples/src/masm").glob("*.asm"))
    )


def test_committed_windows_fixture_contains_every_tracked_masm_export() -> None:
    """Keep the shared MASM source corpus and committed DLL synchronized."""

    fixture = (REPO / "samples/bins/libobfuscated.dll").read_bytes()
    required_exports = tuple(
        name for name in _tracked_masm_exports() if name not in PENDING_CANONICAL_BUILD
    )
    missing = [
        name for name in required_exports if name.encode("ascii") + b"\0" not in fixture
    ]

    assert missing == [], (
        "committed samples/bins/libobfuscated.dll is stale; rebuild it with "
        f"samples/scripts/build_windows.ps1 (missing exports: {missing})"
    )


def test_exports_pending_canonical_build_ship_a_committed_dll() -> None:
    """A pending export must still be reachable from some committed fixture DLL."""

    tracked = set(_tracked_masm_exports())
    dlls = {path: path.read_bytes() for path in _committed_dlls()}

    stale_entries = sorted(PENDING_CANONICAL_BUILD - tracked)
    assert stale_entries == [], (
        "PENDING_CANONICAL_BUILD names exports with no MASM source under "
        f"samples/src/masm; drop them: {stale_entries}"
    )

    unshipped = sorted(
        name
        for name in PENDING_CANONICAL_BUILD
        if not any(name.encode("ascii") + b"\0" in blob for blob in dlls.values())
    )
    assert unshipped == [], (
        "exports pending the canonical build must ship their own committed DLL "
        f"under samples/bins; missing binaries for: {unshipped}"
    )


def test_exports_folded_into_the_canonical_build_leave_the_pending_list() -> None:
    """Stop a pending entry from masking a rebuilt canonical fixture."""

    fixture = (REPO / "samples/bins/libobfuscated.dll").read_bytes()
    already_canonical = sorted(
        name
        for name in PENDING_CANONICAL_BUILD
        if name.encode("ascii") + b"\0" in fixture
    )

    assert already_canonical == [], (
        "these exports are now in samples/bins/libobfuscated.dll and must be "
        f"removed from PENDING_CANONICAL_BUILD: {already_canonical}"
    )
