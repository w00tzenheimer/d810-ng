"""IDA-free tests for the aliased-stack reaching-definitions fallback."""

from __future__ import annotations

from d810.analyses.value_flow import aliased_stack_reaching_defs


def _run(events: dict[int, tuple[object, ...]]) -> set[object]:
    """Run a diamond CFG whose target is block 3."""
    successors = {0: (1, 2), 1: (3,), 2: (3,), 3: ()}
    return set(
        aliased_stack_reaching_defs.collect_aliased_stack_reaching_defs(
            entry_block=0,
            target_block=3,
            successors_of=lambda block: successors[block],
            events_for_block=lambda block: events.get(block, ()),
        )
    )


def test_direct_stack_definition_reaches_an_aliased_slot_through_a_join() -> None:
    definition = aliased_stack_reaching_defs.AliasedStackDefSite(1, 0x1010, 4)
    events = {
        1: (
            aliased_stack_reaching_defs.AliasedStackDefEvent(
                definition,
                replaces_cell=True,
            ),
        ),
    }

    assert _run(events) == {definition}


def test_may_clobber_keeps_prior_definition_and_records_its_own_site() -> None:
    definition = aliased_stack_reaching_defs.AliasedStackDefSite(1, 0x1010, 4)
    uncertain_store = aliased_stack_reaching_defs.AliasedStackDefSite(1, 0x1014, 1)
    events = {
        1: (
            aliased_stack_reaching_defs.AliasedStackDefEvent(
                definition, replaces_cell=True
            ),
            aliased_stack_reaching_defs.AliasedStackDefEvent(uncertain_store),
        ),
    }

    assert _run(events) == {definition, uncertain_store}


def test_partial_overlapping_stack_write_is_a_may_definition_not_a_kill() -> None:
    full_definition = aliased_stack_reaching_defs.AliasedStackDefSite(1, 0x1010, 4)
    partial_write = aliased_stack_reaching_defs.AliasedStackDefSite(1, 0x1014, 4)
    events = {
        1: (
            aliased_stack_reaching_defs.AliasedStackDefEvent(
                full_definition,
                replaces_cell=True,
            ),
            aliased_stack_reaching_defs.AliasedStackDefEvent(partial_write),
        ),
    }

    assert _run(events) == {full_definition, partial_write}
