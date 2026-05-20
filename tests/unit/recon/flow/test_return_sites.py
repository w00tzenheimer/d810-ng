from __future__ import annotations

import hashlib
from dataclasses import dataclass, field

import pytest

from d810.recon.flow.return_sites import (
    compute_legacy_return_site_guard_hash,
    legacy_handler_path_return_sites,
    transition_report_return_sites,
)
from d810.recon.flow.transition_report import (
    DispatcherTransitionReport,
    TransitionKind,
    TransitionPath,
    TransitionRow,
    TransitionSummary,
)


@dataclass
class _FakePath:
    exit_block: int
    final_state: int | None
    state_writes: list = field(default_factory=list)


def _make_path(handler_serial: int, chain: tuple[int, ...], reaches_exit: bool = True) -> TransitionPath:
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
    *,
    state_const: int | None = None,
    chain: tuple[int, ...] = (),
    reaches_exit: bool = True,
    state_range_lo: int | None = None,
    state_range_hi: int | None = None,
) -> TransitionRow:
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
        chain_preview=chain[:4],
        path=_make_path(handler_serial, chain, reaches_exit),
    )


def _make_report(rows: list[TransitionRow]) -> DispatcherTransitionReport:
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
            exit_count=sum(1 for row in rows if row.kind == TransitionKind.EXIT),
            unknown_count=sum(1 for row in rows if row.kind == TransitionKind.UNKNOWN),
        ),
        diagnostics=(),
    )


def test_transition_report_exit_rows_become_handler_origin_return_sites() -> None:
    report = _make_report([
        _make_row(20, TransitionKind.EXIT, state_const=0x2000, chain=(20, 219)),
        _make_row(10, TransitionKind.EXIT, state_const=0x1000, chain=(10, 219)),
    ])

    sites = transition_report_return_sites(report)

    assert [site.origin_block for site in sites] == [10, 20]
    assert sites[0].site_id == "return_handler_10_state_00001000"
    assert sites[0].expected_terminal_kind == "return"
    assert sites[0].metadata["path_chain"] == [10, 219]


def test_transition_report_excludes_non_exit_and_unreached_exit_rows() -> None:
    report = _make_report([
        _make_row(10, TransitionKind.TRANSITION, state_const=0x1000),
        _make_row(20, TransitionKind.EXIT, state_const=0x2000, reaches_exit=False),
    ])

    assert transition_report_return_sites(report) == ()


def test_transition_report_site_id_supports_range_and_unknown_state_tags() -> None:
    report = _make_report([
        _make_row(
            10,
            TransitionKind.EXIT,
            state_range_lo=0x100,
            state_range_hi=0x1FF,
        ),
        _make_row(20, TransitionKind.EXIT),
    ])

    sites = transition_report_return_sites(report)

    assert sites[0].site_id == "return_handler_10_state_range_00000100_000001ff"
    assert sites[1].site_id == "return_handler_20_state_unknown"


def test_transition_report_site_id_accepts_family_prefix() -> None:
    report = _make_report([
        _make_row(10, TransitionKind.EXIT, state_const=0x1000),
    ])

    sites = transition_report_return_sites(report, site_id_prefix="example")

    assert sites[0].site_id == "example_handler_10_state_00001000"


def test_transition_report_exit_with_missing_path_preserves_legacy_error() -> None:
    row = _make_row(20, TransitionKind.EXIT, state_const=0x2000)
    row = row.__class__(
        state_const=row.state_const,
        state_range_lo=row.state_range_lo,
        state_range_hi=row.state_range_hi,
        handler_serial=row.handler_serial,
        kind=row.kind,
        next_state=row.next_state,
        conditional_states=row.conditional_states,
        state_label=row.state_label,
        transition_label=row.transition_label,
        chain_preview=row.chain_preview,
        path=None,
    )

    with pytest.raises(AttributeError):
        transition_report_return_sites(_make_report([row]))


def test_legacy_handler_path_return_sites_dedup_by_exit_block() -> None:
    sites = legacy_handler_path_return_sites({
        10: [_FakePath(exit_block=55, final_state=None, state_writes=[(1, 2)])],
        20: [_FakePath(exit_block=55, final_state=None)],
        30: [_FakePath(exit_block=99, final_state=0x1234)],
    })

    assert len(sites) == 1
    assert sites[0].site_id == "return_ret_10_55"
    assert sites[0].origin_block == 55
    assert sites[0].provenance == "handler_10_path_0"


def test_legacy_handler_path_return_sites_accepts_family_prefix() -> None:
    sites = legacy_handler_path_return_sites(
        {
            10: [_FakePath(exit_block=55, final_state=None, state_writes=[(1, 2)])],
        },
        site_id_prefix="example",
    )

    assert sites[0].site_id == "example_ret_10_55"


def test_legacy_guard_hash_matches_prior_formula() -> None:
    path = _FakePath(exit_block=42, final_state=None, state_writes=[(5, 0x1234)])
    expected = hashlib.sha256("10|42|(5, 4660)".encode()).hexdigest()[:16]

    assert compute_legacy_return_site_guard_hash(10, path) == expected
