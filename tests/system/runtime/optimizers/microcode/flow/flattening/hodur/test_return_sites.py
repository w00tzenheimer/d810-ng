"""Unit tests for HodurReturnSiteProvider.

Uses plain dataclasses as stand-ins for HandlerPathResult / DispatcherTransitionReport
so no IDA environment is required.
"""
from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from typing import Optional, Tuple

import pytest

from d810.cfg.flow.return_frontier import ReturnSite
from d810.optimizers.microcode.flow.flattening.hodur.return_sites import (
    HodurReturnSiteProvider,
)
from d810.recon.flow.transition_report import (
    DispatcherTransitionReport,
    TransitionKind,
    TransitionPath,
    TransitionRow,
    TransitionSummary,
)


# ---------------------------------------------------------------------------
# Minimal stand-in for HandlerPathResult (no IDA dependency)
# ---------------------------------------------------------------------------


@dataclass
class _FakePath:
    """Mimics the HandlerPathResult interface used by the legacy provider."""

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


def _make_path(handler_serial: int, chain: tuple, reaches_exit: bool = True) -> TransitionPath:
    return TransitionPath(
        handler_serial=handler_serial,
        chain=chain,
        next_state=None,
        conditional_states=(),
        back_edge=False,
        reaches_exit_block=reaches_exit,
        classified_exit=reaches_exit,
        unresolved=not reaches_exit,
    )


def _make_row(
    handler_serial: int,
    kind: TransitionKind,
    state_const: Optional[int] = None,
    chain: tuple = (),
    chain_preview: tuple = (),
    reaches_exit: bool = True,
    state_range_lo: Optional[int] = None,
    state_range_hi: Optional[int] = None,
) -> TransitionRow:
    path = _make_path(handler_serial, chain, reaches_exit)
    return TransitionRow(
        state_const=state_const,
        state_range_lo=state_range_lo,
        state_range_hi=state_range_hi,
        handler_serial=handler_serial,
        kind=kind,
        next_state=None,
        conditional_states=(),
        state_label=f"State 0x{state_const:08x}" if state_const is not None else "State <unknown>",
        transition_label="RETURN (exit)" if kind == TransitionKind.EXIT else "unknown",
        chain_preview=chain_preview or chain[:4],
        path=path,
    )


def _make_report(rows: list[TransitionRow]) -> DispatcherTransitionReport:
    exit_count = sum(1 for r in rows if r.kind == TransitionKind.EXIT)
    unknown_count = sum(1 for r in rows if r.kind == TransitionKind.UNKNOWN)
    return DispatcherTransitionReport(
        dispatcher_entry_serial=0,
        state_var_stkoff=None,
        state_var_lvar_idx=None,
        pre_header_serial=None,
        initial_state=None,
        handler_state_map={},
        handler_range_map={},
        bst_node_blocks=(),
        rows=tuple(rows),
        summary=TransitionSummary(
            handlers_total=len(rows),
            known_count=0,
            conditional_count=0,
            exit_count=exit_count,
            unknown_count=unknown_count,
        ),
        diagnostics=(),
    )


# ---------------------------------------------------------------------------
# Tests: new collect_return_sites(report) API — strict EXIT-only mode
# ---------------------------------------------------------------------------


class TestCollectReturnSitesFromReport:
    def test_exit_rows_become_sites(self) -> None:
        """EXIT rows are turned into ReturnSites, one per handler_serial."""
        rows = [
            _make_row(10, TransitionKind.EXIT, state_const=0x1000, chain=(10, 55, 219)),
            _make_row(20, TransitionKind.EXIT, state_const=0x2000, chain=(20, 60, 219)),
        ]
        report = _make_report(rows)
        sites = _provider().collect_return_sites(report)

        assert len(sites) == 2
        serials = {s.origin_block for s in sites}
        assert serials == {10, 20}

    def test_unknown_rows_excluded_in_strict_mode(self) -> None:
        """UNKNOWN rows are excluded (strict mode: only EXIT)."""
        rows = [
            _make_row(30, TransitionKind.UNKNOWN, state_const=0x3000, chain=()),
        ]
        report = _make_report(rows)
        sites = _provider().collect_return_sites(report)

        assert sites == ()

    def test_transition_rows_excluded(self) -> None:
        """TRANSITION rows are not included in the return sites."""
        rows = [
            _make_row(10, TransitionKind.TRANSITION, state_const=0x1000),
            _make_row(20, TransitionKind.EXIT, state_const=0x2000, chain=(20, 219)),
        ]
        report = _make_report(rows)
        sites = _provider().collect_return_sites(report)

        assert len(sites) == 1
        assert sites[0].origin_block == 20

    def test_conditional_rows_excluded(self) -> None:
        """CONDITIONAL rows are not included in the return sites."""
        rows = [
            _make_row(10, TransitionKind.CONDITIONAL, state_const=0x1000),
        ]
        report = _make_report(rows)
        sites = _provider().collect_return_sites(report)

        assert sites == ()

    def test_no_dedup_by_exit_block(self) -> None:
        """Multiple handlers sharing the same exit block → multiple distinct sites (no dedup)."""
        rows = [
            _make_row(10, TransitionKind.EXIT, state_const=0x1000, chain=(10, 219)),
            _make_row(20, TransitionKind.EXIT, state_const=0x2000, chain=(20, 219)),
            _make_row(30, TransitionKind.EXIT, state_const=0x3000, chain=(30, 219)),
        ]
        report = _make_report(rows)
        sites = _provider().collect_return_sites(report)

        # All 3 handlers become distinct sites (not deduped by shared exit 219)
        assert len(sites) == 3
        serials = {s.origin_block for s in sites}
        assert serials == {10, 20, 30}

    def test_site_id_format_08x(self) -> None:
        """site_id uses hodur_handler_{serial}_state_{08x} zero-padded format."""
        rows = [
            _make_row(42, TransitionKind.EXIT, state_const=0xABCD),
        ]
        report = _make_report(rows)
        sites = _provider().collect_return_sites(report)

        assert sites[0].site_id == "hodur_handler_42_state_0000abcd"

    def test_site_id_range_format(self) -> None:
        """site_id with range state uses range_{lo:08x}_{hi:08x} format."""
        row = _make_row(
            99, TransitionKind.EXIT,
            state_const=None,
            state_range_lo=0x100,
            state_range_hi=0x1FF,
        )
        report = _make_report([row])
        sites = _provider().collect_return_sites(report)

        assert sites[0].site_id == "hodur_handler_99_state_range_00000100_000001ff"

    def test_site_id_unknown_state(self) -> None:
        """site_id with no state info uses 'unknown' label."""
        row = _make_row(77, TransitionKind.EXIT, state_const=None)
        report = _make_report([row])
        sites = _provider().collect_return_sites(report)

        assert sites[0].site_id == "hodur_handler_77_state_unknown"

    def test_origin_block_is_handler_serial(self) -> None:
        """origin_block is handler_serial (not the shared exit block)."""
        rows = [
            _make_row(55, TransitionKind.EXIT, state_const=0x5500, chain=(55, 100, 219)),
        ]
        report = _make_report(rows)
        sites = _provider().collect_return_sites(report)

        assert sites[0].origin_block == 55  # handler serial, not 219

    def test_dedup_by_site_id(self) -> None:
        """Same handler_serial + same state → same site_id → only one site."""
        rows = [
            _make_row(10, TransitionKind.EXIT, state_const=0x1000),
            _make_row(10, TransitionKind.EXIT, state_const=0x1000),
        ]
        report = _make_report(rows)
        sites = _provider().collect_return_sites(report)

        assert len(sites) == 1

    def test_metadata_keys_present(self) -> None:
        """metadata dict contains all required keys from the user predicate."""
        chain = (10, 55, 219)
        rows = [
            _make_row(10, TransitionKind.EXIT, state_const=0x1000, chain=chain),
        ]
        report = _make_report(rows)
        sites = _provider().collect_return_sites(report)

        meta = sites[0].metadata
        assert "dispatcher_entry" in meta
        assert "state_const" in meta
        assert "state_range_lo" in meta
        assert "state_range_hi" in meta
        assert "transition_kind" in meta
        assert "transition_label" in meta
        assert "path_chain" in meta
        assert "path_back_edge" in meta
        assert "path_reaches_exit_block" in meta
        assert "path_classified_exit" in meta
        assert "path_unresolved" in meta

    def test_metadata_values_correct(self) -> None:
        """metadata values are populated from the report row."""
        chain = (10, 55, 219)
        rows = [
            _make_row(10, TransitionKind.EXIT, state_const=0x1000, chain=chain),
        ]
        report = _make_report(rows)
        sites = _provider().collect_return_sites(report)

        meta = sites[0].metadata
        assert meta["dispatcher_entry"] == 0  # from _make_report dispatcher_entry_serial=0
        assert meta["state_const"] == 0x1000
        assert meta["state_range_lo"] is None
        assert meta["state_range_hi"] is None
        assert meta["transition_kind"] == "EXIT"
        assert meta["path_chain"] == list(chain)
        assert meta["path_back_edge"] is False
        assert meta["path_reaches_exit_block"] is True
        assert meta["path_classified_exit"] is True
        assert meta["path_unresolved"] is False

    def test_sort_order_by_origin_block_then_site_id(self) -> None:
        """Sites are sorted by (origin_block, site_id)."""
        rows = [
            _make_row(30, TransitionKind.EXIT, state_const=0x3000),
            _make_row(10, TransitionKind.EXIT, state_const=0x1000),
            _make_row(20, TransitionKind.EXIT, state_const=0x2000),
        ]
        report = _make_report(rows)
        sites = _provider().collect_return_sites(report)

        origins = [s.origin_block for s in sites]
        assert origins == [10, 20, 30]

    def test_expected_terminal_kind_is_return(self) -> None:
        """EXIT rows produce expected_terminal_kind='return'."""
        rows = [_make_row(10, TransitionKind.EXIT, state_const=0x1)]
        report = _make_report(rows)
        sites = _provider().collect_return_sites(report)

        assert sites[0].expected_terminal_kind == "return"

    def test_return_type_is_tuple(self) -> None:
        """collect_return_sites always returns a tuple."""
        report = _make_report([])
        sites = _provider().collect_return_sites(report)

        assert isinstance(sites, tuple)

    def test_empty_report(self) -> None:
        """Empty report → empty tuple."""
        report = _make_report([])
        sites = _provider().collect_return_sites(report)

        assert sites == ()

    def test_no_guard_hash_or_provenance_set(self) -> None:
        """Provider does not set guard_hash or provenance (uses defaults)."""
        rows = [_make_row(10, TransitionKind.EXIT, state_const=0x1000)]
        report = _make_report(rows)
        sites = _provider().collect_return_sites(report)

        assert sites[0].guard_hash == ""
        assert sites[0].provenance == ""

    def test_exit_without_reaches_exit_block_excluded(self) -> None:
        """EXIT kind but reaches_exit_block=False must be excluded (false return candidate)."""
        rows = [
            _make_row(10, TransitionKind.EXIT, state_const=0x1000, reaches_exit=False),
        ]
        report = _make_report(rows)
        sites = _provider().collect_return_sites(report)

        assert sites == ()

    def test_exit_with_path_none_raises(self) -> None:
        """EXIT kind with path=None raises AttributeError — indicates bug in transition report."""
        # Build row manually with path=None to bypass _make_row helper
        row = TransitionRow(
            state_const=0x2000,
            state_range_lo=None,
            state_range_hi=None,
            handler_serial=20,
            kind=TransitionKind.EXIT,
            next_state=None,
            conditional_states=(),
            state_label="State 0x00002000",
            transition_label="RETURN (exit)",
            chain_preview=(),
            path=None,
        )
        report = _make_report([row])
        with pytest.raises(AttributeError):
            _provider().collect_return_sites(report)

    def test_exit_with_reaches_exit_block_true_included(self) -> None:
        """EXIT kind with reaches_exit_block=True must produce exactly one site."""
        rows = [
            _make_row(15, TransitionKind.EXIT, state_const=0x1500, reaches_exit=True),
        ]
        report = _make_report(rows)
        sites = _provider().collect_return_sites(report)

        assert len(sites) == 1
        assert sites[0].origin_block == 15


# ---------------------------------------------------------------------------
# Tests: legacy collect_return_sites_legacy(snapshot, handler_paths) API
# ---------------------------------------------------------------------------


class TestCollectTerminalPaths:
    def test_collect_terminal_paths(self) -> None:
        """Terminal paths (final_state=None) are turned into ReturnSites."""
        p = _FakePath(exit_block=42, final_state=None, state_writes=[(5, 0x1234)])
        handler_paths = {10: [p]}

        sites = _provider().collect_return_sites_legacy(snapshot=None, handler_paths=handler_paths)  # type: ignore[arg-type]

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
        sites = _provider().collect_return_sites_legacy(snapshot=None, handler_paths={1: paths})  # type: ignore[arg-type]

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
        sites = _provider().collect_return_sites_legacy(snapshot=None, handler_paths={5: paths})  # type: ignore[arg-type]

        assert sites == ()

    def test_mixed_terminal_and_non_terminal(self) -> None:
        """Only the terminal path is collected, non-terminal is skipped."""
        paths = [
            _FakePath(exit_block=1, final_state=7),   # non-terminal
            _FakePath(exit_block=2, final_state=None), # terminal
        ]
        sites = _provider().collect_return_sites_legacy(snapshot=None, handler_paths={3: paths})  # type: ignore[arg-type]

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
        sites = _provider().collect_return_sites_legacy(snapshot=None, handler_paths=handler_paths)  # type: ignore[arg-type]

        assert len(sites) == 2
        blocks = {s.origin_block for s in sites}
        assert blocks == {shared_exit, 99}

    def test_dedup_within_same_handler(self) -> None:
        """Same exit block twice in one handler's path list → one ReturnSite."""
        paths = [
            _FakePath(exit_block=7, final_state=None),
            _FakePath(exit_block=7, final_state=None),
        ]
        sites = _provider().collect_return_sites_legacy(snapshot=None, handler_paths={1: paths})  # type: ignore[arg-type]

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
        sites = _provider().collect_return_sites_legacy(snapshot=None, handler_paths={})  # type: ignore[arg-type]
        assert sites == ()

    def test_handler_with_no_paths(self) -> None:
        """Handler entry present but path list is empty → no sites."""
        sites = _provider().collect_return_sites_legacy(snapshot=None, handler_paths={1: []})  # type: ignore[arg-type]
        assert sites == ()

    def test_return_type_is_tuple(self) -> None:
        """Return value is always a tuple."""
        sites = _provider().collect_return_sites_legacy(snapshot=None, handler_paths={})  # type: ignore[arg-type]
        assert isinstance(sites, tuple)
