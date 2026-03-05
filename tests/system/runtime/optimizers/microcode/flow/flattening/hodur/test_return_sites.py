"""Unit tests for HodurReturnSiteProvider.

Uses plain dataclasses as stand-ins for HandlerPathResult so no IDA
environment is required.
"""
from __future__ import annotations

import hashlib
from dataclasses import dataclass, field

import pytest

from d810.cfg.flow.return_frontier import ReturnSite
from d810.optimizers.microcode.flow.flattening.hodur.return_sites import (
    HodurReturnSiteProvider,
)


# ---------------------------------------------------------------------------
# Minimal stand-in for HandlerPathResult (no IDA dependency)
# ---------------------------------------------------------------------------


@dataclass
class _FakePath:
    """Mimics the HandlerPathResult interface used by HodurReturnSiteProvider."""

    exit_block: int
    final_state: int | None
    state_writes: list = field(default_factory=list)
    ordered_path: list = field(default_factory=list)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _provider() -> HodurReturnSiteProvider:
    return HodurReturnSiteProvider()


def _guard(entry_serial: int, path: _FakePath) -> str:
    parts = [str(entry_serial), str(path.exit_block)]
    for w in path.state_writes:
        parts.append(str(w))
    raw = "|".join(parts)
    return hashlib.sha256(raw.encode()).hexdigest()[:16]


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


class TestCollectTerminalPaths:
    def test_collect_terminal_paths(self) -> None:
        """Terminal paths (final_state=None) are turned into ReturnSites."""
        p = _FakePath(exit_block=42, final_state=None, state_writes=[(5, 0x1234)])
        handler_paths = {10: [p]}

        sites = _provider().collect_return_sites(snapshot=None, handler_paths=handler_paths)  # type: ignore[arg-type]

        assert len(sites) == 1
        site = sites[0]
        assert isinstance(site, ReturnSite)
        assert site.site_id == "hodur_ret_10_42"
        assert site.origin_block == 42
        assert site.expected_terminal_kind == "return"
        assert site.provenance == "handler_10_path_0"

    def test_multiple_terminal_paths_different_blocks(self) -> None:
        """Multiple terminal paths with distinct exit blocks → multiple sites."""
        paths = [
            _FakePath(exit_block=10, final_state=None),
            _FakePath(exit_block=20, final_state=None),
        ]
        sites = _provider().collect_return_sites(snapshot=None, handler_paths={1: paths})  # type: ignore[arg-type]

        assert len(sites) == 2
        blocks = {s.origin_block for s in sites}
        assert blocks == {10, 20}


class TestSkipNonTerminal:
    def test_skip_non_terminal(self) -> None:
        """Paths with final_state != None must be ignored."""
        paths = [
            _FakePath(exit_block=99, final_state=0xDEAD),
            _FakePath(exit_block=100, final_state=1),
        ]
        sites = _provider().collect_return_sites(snapshot=None, handler_paths={5: paths})  # type: ignore[arg-type]

        assert sites == ()

    def test_mixed_terminal_and_non_terminal(self) -> None:
        """Only the terminal path is collected, non-terminal is skipped."""
        paths = [
            _FakePath(exit_block=1, final_state=7),   # non-terminal
            _FakePath(exit_block=2, final_state=None), # terminal
        ]
        sites = _provider().collect_return_sites(snapshot=None, handler_paths={3: paths})  # type: ignore[arg-type]

        assert len(sites) == 1
        assert sites[0].origin_block == 2


class TestDedupByExitBlock:
    def test_dedup_by_exit_block(self) -> None:
        """Same exit block appearing in multiple handlers → only one ReturnSite."""
        shared_exit = 55
        handler_paths = {
            10: [_FakePath(exit_block=shared_exit, final_state=None)],
            20: [_FakePath(exit_block=shared_exit, final_state=None)],
            30: [_FakePath(exit_block=99, final_state=None)],
        }
        sites = _provider().collect_return_sites(snapshot=None, handler_paths=handler_paths)  # type: ignore[arg-type]

        assert len(sites) == 2
        blocks = {s.origin_block for s in sites}
        assert blocks == {shared_exit, 99}

    def test_dedup_within_same_handler(self) -> None:
        """Same exit block twice in one handler's path list → one ReturnSite."""
        paths = [
            _FakePath(exit_block=7, final_state=None),
            _FakePath(exit_block=7, final_state=None),
        ]
        sites = _provider().collect_return_sites(snapshot=None, handler_paths={1: paths})  # type: ignore[arg-type]

        assert len(sites) == 1


class TestGuardHashStability:
    def test_same_input_same_hash(self) -> None:
        """Identical inputs produce identical guard hashes."""
        p = _FakePath(exit_block=5, final_state=None, state_writes=[(3, 0xABC)])
        h1 = HodurReturnSiteProvider._compute_guard_hash(10, p)
        h2 = HodurReturnSiteProvider._compute_guard_hash(10, p)
        assert h1 == h2

    def test_different_entry_different_hash(self) -> None:
        """Different entry serials produce different hashes."""
        p = _FakePath(exit_block=5, final_state=None, state_writes=[])
        h1 = HodurReturnSiteProvider._compute_guard_hash(10, p)
        h2 = HodurReturnSiteProvider._compute_guard_hash(11, p)
        assert h1 != h2

    def test_different_exit_block_different_hash(self) -> None:
        """Different exit blocks produce different hashes."""
        p1 = _FakePath(exit_block=5, final_state=None, state_writes=[])
        p2 = _FakePath(exit_block=6, final_state=None, state_writes=[])
        h1 = HodurReturnSiteProvider._compute_guard_hash(1, p1)
        h2 = HodurReturnSiteProvider._compute_guard_hash(1, p2)
        assert h1 != h2

    def test_different_state_writes_different_hash(self) -> None:
        """Different state_writes lists produce different hashes."""
        p1 = _FakePath(exit_block=5, final_state=None, state_writes=[(1, 0x10)])
        p2 = _FakePath(exit_block=5, final_state=None, state_writes=[(2, 0x20)])
        h1 = HodurReturnSiteProvider._compute_guard_hash(1, p1)
        h2 = HodurReturnSiteProvider._compute_guard_hash(1, p2)
        assert h1 != h2

    def test_hash_length(self) -> None:
        """Guard hash is exactly 16 hex characters."""
        p = _FakePath(exit_block=0, final_state=None, state_writes=[])
        h = HodurReturnSiteProvider._compute_guard_hash(0, p)
        assert len(h) == 16
        assert all(c in "0123456789abcdef" for c in h)

    def test_hash_matches_expected(self) -> None:
        """Guard hash value matches independent calculation."""
        p = _FakePath(exit_block=42, final_state=None, state_writes=[(5, 0x1234)])
        expected = _guard(10, p)
        result = HodurReturnSiteProvider._compute_guard_hash(10, p)
        assert result == expected


class TestEmptyHandlers:
    def test_empty_handlers(self) -> None:
        """No handlers → empty tuple returned."""
        sites = _provider().collect_return_sites(snapshot=None, handler_paths={})  # type: ignore[arg-type]
        assert sites == ()

    def test_handler_with_no_paths(self) -> None:
        """Handler entry present but path list is empty → no sites."""
        sites = _provider().collect_return_sites(snapshot=None, handler_paths={1: []})  # type: ignore[arg-type]
        assert sites == ()

    def test_return_type_is_tuple(self) -> None:
        """Return value is always a tuple."""
        sites = _provider().collect_return_sites(snapshot=None, handler_paths={})  # type: ignore[arg-type]
        assert isinstance(sites, tuple)
