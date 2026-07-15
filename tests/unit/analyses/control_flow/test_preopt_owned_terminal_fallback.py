from __future__ import annotations

from d810.analyses.control_flow import detached_handler_island
from d810.analyses.control_flow.detached_handler_island import (
    DetachedSnippetTerminalEvidence,
    DetachedSnippetTerminalRoutePlan,
    plan_detached_snippet_terminal_routes,
)


def test_preopt_0x40c703_selects_terminal_source_when_all_predecessors_covered() -> None:
    selected = (
        detached_handler_island.select_boundary_owned_terminal_source_blocks(
            source_native_ea_by_block={77: 0x40C703},
            predecessor_blocks_by_source={77: frozenset({31, 32})},
            redirect_endpoint_blocks_by_old_successor_ea={
                0x40C703: frozenset({31, 32}),
            },
        )
    )

    assert selected == frozenset({77})


def test_preopt_0x40c703_selects_empty_predecessor_source_when_old_successor_covered() -> None:
    selected = (
        detached_handler_island.select_boundary_owned_terminal_source_blocks(
            source_native_ea_by_block={77: 0x40C703},
            predecessor_blocks_by_source={77: frozenset()},
            redirect_endpoint_blocks_by_old_successor_ea={
                0x40C703: frozenset({31}),
            },
        )
    )

    assert selected == frozenset({77})


def test_preopt_0x40c703_selects_orphan_after_covering_endpoint_was_removed() -> None:
    selected = (
        detached_handler_island.select_boundary_owned_terminal_source_blocks(
            source_native_ea_by_block={77: 0x40C703},
            predecessor_blocks_by_source={77: frozenset()},
            redirect_endpoint_blocks_by_old_successor_ea={
                0x40C703: frozenset(),
            },
        )
    )

    assert selected == frozenset({77})


def test_preopt_0x40c703_rejects_terminal_source_with_one_uncovered_predecessor() -> None:
    selected = (
        detached_handler_island.select_boundary_owned_terminal_source_blocks(
            source_native_ea_by_block={77: 0x40C703},
            predecessor_blocks_by_source={77: frozenset({31, 32})},
            redirect_endpoint_blocks_by_old_successor_ea={
                0x40C703: frozenset({31}),
            },
        )
    )

    assert selected == frozenset()


def test_preopt_0x40c703_covered_source_does_not_select_uncovered_sibling() -> None:
    selected = (
        detached_handler_island.select_boundary_owned_terminal_source_blocks(
            source_native_ea_by_block={77: 0x40C703, 78: 0x40C703},
            predecessor_blocks_by_source={
                77: frozenset({31}),
                78: frozenset({32}),
            },
            redirect_endpoint_blocks_by_old_successor_ea={
                0x40C703: frozenset({31}),
            },
        )
    )

    assert selected == frozenset({77})


def test_preopt_0x40c703_already_routed_source_keeps_uncovered_sibling_fallback() -> None:
    owned_imported_exit_ea = 0xF1C002D0
    uncovered_imported_exit_ea = 0xF1C002D8
    native_exit_ea = 0x40C703
    target_ea = 0x40AF00

    plans = plan_detached_snippet_terminal_routes(
        (
            DetachedSnippetTerminalEvidence(
                imported_exit_ea=owned_imported_exit_ea,
                native_exit_ea=native_exit_ea,
            ),
            DetachedSnippetTerminalEvidence(
                imported_exit_ea=uncovered_imported_exit_ea,
                native_exit_ea=native_exit_ea,
            ),
        ),
        resolver_targets={native_exit_ea: (target_ea,)},
        source_blocks_by_imported_ea={
            owned_imported_exit_ea: 77,
            uncovered_imported_exit_ea: 78,
        },
        target_blocks_by_ea={target_ea: 70},
        zero_way_source_blocks=frozenset({77, 78}),
        already_routed_source_blocks=frozenset({77}),
    )

    assert plans == (
        DetachedSnippetTerminalRoutePlan(
            source_block_serial=78,
            target_block_serial=70,
            native_exit_ea=native_exit_ea,
            target_ea=target_ea,
        ),
    )
