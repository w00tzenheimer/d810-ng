"""Emulator gap worklist: cause vocabulary, dedupe keying, aggregate (d81-c6n7).

Slice 5 keeps the emulator's gap WARNINGs at WARNING level and turns them into
a worklist: every line names a stable cause token, the site, the block, the
maturity and the command to run next, deduped per ``(function, attempt, cause,
site)`` rather than once per interpreter or once per process.

These tests are IDA-free by construction -- the decision layer they exercise
lives in ``d810.core.observability_emulator`` and never touches a live ``mba``.
"""

from __future__ import annotations

import pytest

from d810.core.observability_emulator import (
    CAUSE_GLOBAL_NOT_SEEDED,
    CAUSE_HELPER_NOT_IMPLEMENTED,
    CAUSE_NO_REACHING_DEFS,
    CAUSE_NULL_DEREF,
    CAUSE_PHI_MULTI_DEF,
    CAUSE_STACK_SLOT_IN_ALIASED_MEMORY,
    CAUSE_UNSUPPORTED_CALL_OPERAND,
    EMULATOR_GAP_CAUSES,
    EmulatorGap,
    EmulatorGapScope,
    begin_emulator_gap_attempt,
    build_emulator_gap_events,
    emulator_gap_counts,
    emulator_gap_scope,
    flush_emulator_gaps,
    format_emulator_gap,
    format_emulator_gap_aggregate,
    is_stack_slot_in_aliased_memory,
    record_emulator_gap,
    reset_emulator_gaps,
)
from d810.core.observability_events import EmulatorGapObserved
from d810.core.observability_state_write import STATE_WRITE_RESOLUTION_CAUSES

FUNC = 0x7FFB0EB06E50


@pytest.fixture(autouse=True)
def _clean_scopes():
    reset_emulator_gaps()
    yield
    reset_emulator_gaps()


# -- cause vocabulary --------------------------------------------------------


class TestCauseVocabulary:
    def test_every_emitted_cause_is_in_the_enum(self):
        for cause in (
            CAUSE_UNSUPPORTED_CALL_OPERAND,
            CAUSE_HELPER_NOT_IMPLEMENTED,
            CAUSE_GLOBAL_NOT_SEEDED,
            CAUSE_NO_REACHING_DEFS,
            CAUSE_PHI_MULTI_DEF,
            CAUSE_NULL_DEREF,
            CAUSE_STACK_SLOT_IN_ALIASED_MEMORY,
        ):
            assert cause in EMULATOR_GAP_CAUSES

    def test_shared_causes_keep_the_slice_4_spelling(self):
        """A cause the state-write decomposition also uses must be ONE token."""
        shared = EMULATOR_GAP_CAUSES & STATE_WRITE_RESOLUTION_CAUSES
        assert CAUSE_PHI_MULTI_DEF in shared
        assert CAUSE_NO_REACHING_DEFS in shared
        assert CAUSE_GLOBAL_NOT_SEEDED in shared

    def test_the_aliased_stack_slot_cause_is_a_state_write_cause_too(self):
        """d81-cor5: it reaches unflat-why through the state-write channel."""
        assert CAUSE_STACK_SLOT_IN_ALIASED_MEMORY in STATE_WRITE_RESOLUTION_CAUSES


# -- the aliased-memory chain-coverage gap (d81-cor5 evidence) ---------------


class TestAliasedStackSlot:
    def test_slot_at_or_above_minstkref_has_no_hexrays_chain(self):
        # sub_7FFB0EB06E50: minstkref = 0x9A0, var_3A0 = 0xD30, var_B0 = 0x1020
        assert is_stack_slot_in_aliased_memory(0xD30, 0x9A0) is True
        assert is_stack_slot_in_aliased_memory(0x1020, 0x9A0) is True
        assert is_stack_slot_in_aliased_memory(0x9A0, 0x9A0) is True

    def test_restricted_slot_below_minstkref_is_not_the_gap(self):
        assert is_stack_slot_in_aliased_memory(0x3C, 0x9A0) is False
        assert is_stack_slot_in_aliased_memory(0x99F, 0x9A0) is False

    def test_unknown_minstkref_never_claims_the_gap(self):
        """No ``minstkref`` -> no evidence; never guess the cause."""
        assert is_stack_slot_in_aliased_memory(0xD30, 0) is False
        assert is_stack_slot_in_aliased_memory(0xD30, None) is False
        assert is_stack_slot_in_aliased_memory(0xD30, -1) is False


# -- dedupe keying -----------------------------------------------------------


class TestDedupeKeying:
    def test_a_site_warns_once_per_attempt(self):
        begin_emulator_gap_attempt(FUNC, maturity="MMAT_GLBOPT1")
        first = record_emulator_gap(
            FUNC, CAUSE_UNSUPPORTED_CALL_OPERAND, site_ea=0x1000, block_serial=330
        )
        second = record_emulator_gap(
            FUNC, CAUSE_UNSUPPORTED_CALL_OPERAND, site_ea=0x1000, block_serial=330
        )
        assert first is not None
        assert second is None

    def test_a_new_attempt_resets_the_dedupe(self):
        begin_emulator_gap_attempt(FUNC, maturity="MMAT_GLBOPT1")
        assert record_emulator_gap(FUNC, CAUSE_NULL_DEREF, site_ea=0x20) is not None
        assert record_emulator_gap(FUNC, CAUSE_NULL_DEREF, site_ea=0x20) is None
        begin_emulator_gap_attempt(FUNC, maturity="MMAT_GLBOPT1")
        assert record_emulator_gap(FUNC, CAUSE_NULL_DEREF, site_ea=0x20) is not None

    def test_the_attempt_number_increments_per_function(self):
        begin_emulator_gap_attempt(FUNC, maturity="MMAT_GLBOPT1")
        assert emulator_gap_scope(FUNC).attempt == 1
        begin_emulator_gap_attempt(FUNC, maturity="MMAT_GLBOPT1")
        assert emulator_gap_scope(FUNC).attempt == 2

    def test_a_different_function_keeps_its_own_dedupe(self):
        begin_emulator_gap_attempt(FUNC, maturity="MMAT_GLBOPT1")
        begin_emulator_gap_attempt(FUNC + 0x100, maturity="MMAT_GLBOPT1")
        assert record_emulator_gap(FUNC, CAUSE_NULL_DEREF, site_ea=0x20) is not None
        assert (
            record_emulator_gap(FUNC + 0x100, CAUSE_NULL_DEREF, site_ea=0x20)
            is not None
        )

    def test_the_dedupe_key_separates_cause_and_site(self):
        begin_emulator_gap_attempt(FUNC, maturity="MMAT_GLBOPT1")
        assert record_emulator_gap(FUNC, CAUSE_NULL_DEREF, site_ea=0x20) is not None
        assert (
            record_emulator_gap(FUNC, CAUSE_HELPER_NOT_IMPLEMENTED, site_ea=0x20)
            is not None
        )
        assert record_emulator_gap(FUNC, CAUSE_NULL_DEREF, site_ea=0x24) is not None

    def test_a_repeat_still_counts_toward_the_aggregate(self):
        begin_emulator_gap_attempt(FUNC, maturity="MMAT_GLBOPT1")
        for _ in range(5):
            record_emulator_gap(FUNC, CAUSE_NULL_DEREF, site_ea=0x20)
        assert emulator_gap_counts(FUNC) == {CAUSE_NULL_DEREF: 5}
        gaps = emulator_gap_scope(FUNC).gaps
        assert len(gaps) == 1
        assert gaps[0].occurrences == 5

    def test_a_maturity_change_rotates_the_attempt(self):
        begin_emulator_gap_attempt(FUNC, maturity="MMAT_CALLS")
        record_emulator_gap(
            FUNC, CAUSE_NULL_DEREF, site_ea=0x20, maturity="MMAT_CALLS"
        )
        record_emulator_gap(
            FUNC, CAUSE_NULL_DEREF, site_ea=0x20, maturity="MMAT_GLBOPT1"
        )
        scope = emulator_gap_scope(FUNC)
        assert scope.maturity == "MMAT_GLBOPT1"
        assert emulator_gap_counts(FUNC) == {CAUSE_NULL_DEREF: 1}

    def test_the_gap_table_is_bounded(self):
        begin_emulator_gap_attempt(FUNC, maturity="MMAT_GLBOPT1")
        for index in range(EmulatorGapScope.MAX_GAPS + 50):
            record_emulator_gap(FUNC, CAUSE_NULL_DEREF, site_ea=index)
        assert len(emulator_gap_scope(FUNC).gaps) == EmulatorGapScope.MAX_GAPS


# -- line + aggregate formatting --------------------------------------------


class TestFormatting:
    def test_a_gap_line_carries_cause_site_block_maturity_and_next(self):
        scope = begin_emulator_gap_attempt(FUNC, maturity="MMAT_GLBOPT1")
        gap = record_emulator_gap(
            FUNC,
            CAUSE_PHI_MULTI_DEF,
            site_ea=0x7FFB0EB15239,
            block_serial=330,
            def_sites=((329, 0x7FFB0EB1520A), (398, 0x7FFB0EB0BCF7)),
            detail="mov eax, ecx",
        )
        line = format_emulator_gap(scope, gap, db_path="/tmp/cap.sqlite3")
        assert "EMULATOR_GAP" in line
        assert "cause=phi_multi_def" in line
        assert f"func=0x{FUNC:x}" in line
        assert "maturity=GLBOPT1" in line
        assert "blk=330" in line
        assert "site=0x7ffb0eb15239" in line
        assert "defs=blk329@0x7ffb0eb1520a,blk398@0x7ffb0eb0bcf7" in line
        assert "attempt=1" in line
        assert (
            'next="python -m d810.diagnostics unflat-why '
            f'--db /tmp/cap.sqlite3 --func 0x{FUNC:x}"'
        ) in line

    def test_a_gap_line_without_a_capture_still_names_the_command(self):
        scope = begin_emulator_gap_attempt(FUNC, maturity="MMAT_GLBOPT1")
        gap = record_emulator_gap(FUNC, CAUSE_NULL_DEREF, site_ea=0)
        line = format_emulator_gap(scope, gap, db_path=None)
        assert "unflat-why --db <diag-db>" in line

    def test_the_aggregate_counts_every_cause_most_frequent_first(self):
        scope = begin_emulator_gap_attempt(FUNC, maturity="MMAT_GLBOPT1")
        for index in range(3):
            record_emulator_gap(
                FUNC, CAUSE_UNSUPPORTED_CALL_OPERAND, site_ea=0x100 + index
            )
        record_emulator_gap(FUNC, CAUSE_PHI_MULTI_DEF, site_ea=0x200)
        line = format_emulator_gap_aggregate(scope, unresolved_state_writes=2)
        assert line.startswith("EMULATOR_GAPS ")
        assert f"func=0x{FUNC:x}" in line
        assert "maturity=GLBOPT1" in line
        assert "attempt=1" in line
        assert "unsupported_call_operand=3 phi_multi_def=1" in line
        assert "sites=4" in line
        assert "unresolved_state_writes=2" in line

    def test_the_aggregate_is_empty_for_a_gapless_attempt(self):
        scope = begin_emulator_gap_attempt(FUNC, maturity="MMAT_GLBOPT1")
        assert format_emulator_gap_aggregate(scope) == ""


# -- facts -------------------------------------------------------------------


class TestFacts:
    def test_one_event_per_deduped_gap(self):
        scope = begin_emulator_gap_attempt(
            FUNC, maturity="MMAT_GLBOPT1", session_id="s1"
        )
        record_emulator_gap(
            FUNC, CAUSE_PHI_MULTI_DEF, site_ea=0x10, block_serial=330,
            def_sites=((329, 0x20),),
        )
        record_emulator_gap(FUNC, CAUSE_PHI_MULTI_DEF, site_ea=0x10, block_serial=330)
        record_emulator_gap(
            FUNC, CAUSE_STACK_SLOT_IN_ALIASED_MEMORY, site_ea=0x30, block_serial=236
        )
        events = build_emulator_gap_events(scope)
        assert len(events) == 2
        assert all(isinstance(event, EmulatorGapObserved) for event in events)
        first = events[0]
        assert first.func_ea == FUNC
        assert first.cause == CAUSE_PHI_MULTI_DEF
        assert first.site_ea == 0x10
        assert first.block_serial == 330
        assert first.occurrences == 2
        assert first.def_sites == ((329, 0x20),)
        assert first.maturity == "MMAT_GLBOPT1"
        assert first.attempt == 1
        assert first.session_id == "s1"
        assert events[1].cause == CAUSE_STACK_SLOT_IN_ALIASED_MEMORY

    def test_flush_publishes_logs_and_resets(self):
        published: list[object] = []
        warnings: list[str] = []

        class _Log:
            def warning(self, msg, *args):
                warnings.append(msg % args if args else msg)

        begin_emulator_gap_attempt(FUNC, maturity="MMAT_GLBOPT1")
        record_emulator_gap(FUNC, CAUSE_NULL_DEREF, site_ea=0x20)
        line = flush_emulator_gaps(
            FUNC, log=_Log(), emit_fn=published.append, unresolved_state_writes=0
        )
        assert line
        assert warnings == [line]
        assert len(published) == 1
        assert emulator_gap_counts(FUNC) == {}

    def test_flush_of_a_gapless_attempt_says_nothing(self):
        published: list[object] = []
        begin_emulator_gap_attempt(FUNC, maturity="MMAT_GLBOPT1")
        assert flush_emulator_gaps(FUNC, emit_fn=published.append) is None
        assert published == []

    def test_a_bus_failure_never_escapes(self):
        def _boom(_event):
            raise RuntimeError("bus down")

        begin_emulator_gap_attempt(FUNC, maturity="MMAT_GLBOPT1")
        record_emulator_gap(FUNC, CAUSE_NULL_DEREF, site_ea=0x20)
        assert flush_emulator_gaps(FUNC, emit_fn=_boom) is not None


class TestEmulatorGapEvent:
    def test_an_unknown_cause_is_rejected(self):
        with pytest.raises(ValueError):
            EmulatorGapObserved(func_ea=FUNC, cause="", site_ea=0)

    def test_negative_occurrences_are_rejected(self):
        with pytest.raises(ValueError):
            EmulatorGapObserved(
                func_ea=FUNC, cause=CAUSE_NULL_DEREF, site_ea=0, occurrences=-1
            )

    def test_fields_are_coerced(self):
        event = EmulatorGapObserved(
            func_ea=FUNC,
            cause=CAUSE_NULL_DEREF,
            site_ea=0x10,
            def_sites=[[329, 0x20]],
        )
        assert event.def_sites == ((329, 0x20),)


def test_a_gap_is_hashable_and_carries_its_key():
    gap = EmulatorGap(cause=CAUSE_NULL_DEREF, site_ea=0x10, block_serial=3)
    assert gap.key() == (CAUSE_NULL_DEREF, 0x10, 3)
