"""Pure state-write resolution facts (ticket d81-qt4v, slice 4).

Every emu-consult decision in state-write recovery leaves one
``StateWriteResolutionFact``; transition recovery then flags the abstentions
whose corridor left a transition unresolved, so a residual corridor count
decomposes by cause instead of being a single opaque number.

IDA-free by construction: the module under test takes plain serials, EAs and
outcome tokens.
"""

from __future__ import annotations

import pytest

from d810.core.observability_events import StateWriteResolutionObserved
from d810.core.observability_state_write import (
    AbstainCauseLog,
    CAUSE_EMULATOR_RAISED,
    CAUSE_GLOBAL_NOT_SEEDED,
    CAUSE_NO_DEF_WITHIN_HOP_BOUND,
    CAUSE_NO_LIVE_BLOCK,
    CAUSE_NO_REACHING_DEFS,
    CAUSE_PHI_MULTI_DEF,
    CAUSE_RESOLVED,
    CAUSE_STACK_SLOT_IN_ALIASED_MEMORY,
    CAUSE_SYNTHETIC_TAINT,
    CAUSE_TOP_FLOOR_STRICT,
    CAUSE_UNRESOLVED,
    STATE_WRITE_RESOLUTION_CAUSES,
    StateWriteResolutionRecorder,
    classify_state_write_cause,
    decompose_by_cause,
    dominant_cause,
    format_corridor,
    top_unresolved_corridors,
)


class TestDominantCause:
    def test_empty_is_unresolved(self):
        assert dominant_cause(()) == CAUSE_UNRESOLVED

    def test_precedence_prefers_synthetic_taint(self):
        assert (
            dominant_cause([CAUSE_PHI_MULTI_DEF, CAUSE_SYNTHETIC_TAINT])
            == CAUSE_SYNTHETIC_TAINT
        )

    def test_precedence_prefers_phi_over_single_def(self):
        assert (
            dominant_cause(["single_def_eval_failed", CAUSE_PHI_MULTI_DEF])
            == CAUSE_PHI_MULTI_DEF
        )

    def test_unknown_token_is_kept_verbatim(self):
        assert dominant_cause(["something_new"]) == "something_new"

    def test_every_named_cause_is_registered(self):
        for cause in (
            CAUSE_RESOLVED,
            CAUSE_PHI_MULTI_DEF,
            CAUSE_NO_REACHING_DEFS,
            CAUSE_SYNTHETIC_TAINT,
            CAUSE_GLOBAL_NOT_SEEDED,
            CAUSE_NO_DEF_WITHIN_HOP_BOUND,
            CAUSE_NO_LIVE_BLOCK,
            CAUSE_EMULATOR_RAISED,
            CAUSE_TOP_FLOOR_STRICT,
            CAUSE_UNRESOLVED,
        ):
            assert cause in STATE_WRITE_RESOLUTION_CAUSES


class TestClassify:
    def test_resolved_consult_is_resolved(self):
        assert (
            classify_state_write_cause(outcome_kind="ExactResult", resolved=True)
            == CAUSE_RESOLVED
        )

    def test_exact_result_dropped_by_the_floor_is_fold_rejected(self):
        assert (
            classify_state_write_cause(outcome_kind="ExactResult", resolved=False)
            == "fold_rejected"
        )

    def test_emulator_cause_wins_over_the_generic_reason(self):
        assert (
            classify_state_write_cause(
                outcome_kind="Abstain",
                resolved=False,
                reason="emulator+history could not resolve state-var write",
                emulator_cause=CAUSE_PHI_MULTI_DEF,
            )
            == CAUSE_PHI_MULTI_DEF
        )

    def test_known_abstain_reasons_map_without_an_emulator_cause(self):
        assert (
            classify_state_write_cause(
                outcome_kind="Abstain", resolved=False, reason="no live block"
            )
            == CAUSE_NO_LIVE_BLOCK
        )
        assert (
            classify_state_write_cause(
                outcome_kind="Abstain",
                resolved=False,
                reason="no state-var write in block",
            )
            == "no_state_write_in_block"
        )
        assert (
            classify_state_write_cause(
                outcome_kind="Abstain", resolved=False, reason="history eval raised"
            )
            == CAUSE_EMULATOR_RAISED
        )

    def test_corridor_exhaustion_outranks_the_per_consult_cause(self):
        assert (
            classify_state_write_cause(
                outcome_kind="Abstain",
                resolved=False,
                emulator_cause=CAUSE_PHI_MULTI_DEF,
                corridor_exhausted=True,
            )
            == CAUSE_NO_DEF_WITHIN_HOP_BOUND
        )

    def test_unknown_abstain_reason_falls_back_to_unresolved(self):
        assert (
            classify_state_write_cause(
                outcome_kind="Abstain", resolved=False, reason="mystery"
            )
            == CAUSE_UNRESOLVED
        )


class TestRecorder:
    def _recorder(self):
        return StateWriteResolutionRecorder(
            func_ea=0x7FFB0EB06E50,
            block_serial=330,
            block_ea=0x7FFB0EB15239,
            maturity="MMAT_GLBOPT1",
        )

    def test_blk330_three_corridors_decompose_by_cause(self):
        rec = self._recorder()
        rec.note(corridor=(329,), outcome_kind="ExactResult", resolved=True,
                 folded_value=0x4BCC8BEE, store_cells=2)
        rec.note(corridor=(355, 398), outcome_kind="ExactResult", resolved=True,
                 folded_value=0x1B3EE0EF, store_cells=0)
        rec.note(corridor=(355, 397), outcome_kind="Abstain", resolved=False,
                 store_cells=0, corridor_exhausted=True,
                 reason="emulator+history could not resolve state-var write")
        events = rec.build_events()
        assert [e.cause for e in events] == [
            CAUSE_RESOLVED,
            CAUSE_RESOLVED,
            CAUSE_NO_DEF_WITHIN_HOP_BOUND,
        ]
        assert decompose_by_cause(events) == {
            CAUSE_RESOLVED: 2,
            CAUSE_NO_DEF_WITHIN_HOP_BOUND: 1,
        }

    def test_mark_unresolved_transition_flags_only_abstentions(self):
        rec = self._recorder()
        rec.note(corridor=(329,), outcome_kind="ExactResult", resolved=True,
                 folded_value=1)
        rec.note(corridor=(355, 397), outcome_kind="Abstain", resolved=False,
                 corridor_exhausted=True)
        assert rec.mark_unresolved_transition() == 1
        events = rec.build_events()
        by_corridor = {e.corridor: e.contributed_to_unresolved_transition
                       for e in events}
        assert by_corridor[(329,)] is False
        assert by_corridor[(355, 397)] is True

    def test_resolved_consults_never_contribute(self):
        rec = self._recorder()
        rec.note(corridor=(329,), outcome_kind="ExactResult", resolved=True,
                 folded_value=7)
        assert rec.mark_unresolved_transition() == 0

    def test_def_sites_and_store_cells_ride_along(self):
        rec = self._recorder()
        rec.note(
            corridor=(355, 397),
            outcome_kind="Abstain",
            resolved=False,
            store_cells=4,
            emulator_cause=CAUSE_PHI_MULTI_DEF,
            def_sites=((329, 0x7FFB0EB1520A), (398, 0x7FFB0EB0BCF7)),
        )
        (event,) = rec.build_events()
        assert event.cause == CAUSE_PHI_MULTI_DEF
        assert event.store_cells == 4
        assert event.def_sites == ((329, 0x7FFB0EB1520A), (398, 0x7FFB0EB0BCF7))
        assert event.folded_value is None

    def test_duplicate_corridor_consults_collapse_to_the_last(self):
        rec = self._recorder()
        rec.note(corridor=(329,), outcome_kind="Abstain", resolved=False)
        rec.note(corridor=(329,), outcome_kind="ExactResult", resolved=True,
                 folded_value=9)
        events = rec.build_events()
        assert len(events) == 1
        assert events[0].cause == CAUSE_RESOLVED

    def test_recorder_is_bounded(self):
        rec = self._recorder()
        for serial in range(StateWriteResolutionRecorder.MAX_CONSULTS + 25):
            rec.note(corridor=(serial,), outcome_kind="Abstain", resolved=False)
        assert len(rec.build_events()) == StateWriteResolutionRecorder.MAX_CONSULTS

    def test_emit_publishes_every_event(self):
        published: list[object] = []
        rec = self._recorder()
        rec.note(corridor=(329,), outcome_kind="Abstain", resolved=False)
        rec.emit(published.append)
        assert len(published) == 1
        assert isinstance(published[0], StateWriteResolutionObserved)

    def test_emit_never_raises_for_a_diagnostic_reason(self):
        def boom(_event):
            raise RuntimeError("bus down")

        rec = self._recorder()
        rec.note(corridor=(329,), outcome_kind="Abstain", resolved=False)
        rec.emit(boom)  # must not propagate


class TestDecomposition:
    def _event(self, corridor, cause, contributed):
        return StateWriteResolutionObserved(
            func_ea=0x1000,
            block_serial=330,
            block_ea=0x2000,
            corridor=tuple(corridor),
            outcome="abstain",
            cause=cause,
            contributed_to_unresolved_transition=contributed,
        )

    def test_top_unresolved_corridors_ranks_contributors_only(self):
        events = [
            self._event((329,), CAUSE_RESOLVED, False),
            self._event((355, 397), CAUSE_NO_DEF_WITHIN_HOP_BOUND, True),
            self._event((355, 397, 178), CAUSE_NO_DEF_WITHIN_HOP_BOUND, True),
            self._event((236,), CAUSE_NO_REACHING_DEFS, True),
        ]
        top = top_unresolved_corridors(events, limit=2)
        assert len(top) == 2
        assert all(entry.contributed_to_unresolved_transition for entry in top)

    def test_decompose_counts_every_cause(self):
        events = [
            self._event((329,), CAUSE_RESOLVED, False),
            self._event((355, 397), CAUSE_NO_DEF_WITHIN_HOP_BOUND, True),
            self._event((236,), CAUSE_NO_DEF_WITHIN_HOP_BOUND, True),
        ]
        assert decompose_by_cause(events) == {
            CAUSE_RESOLVED: 1,
            CAUSE_NO_DEF_WITHIN_HOP_BOUND: 2,
        }

    def test_format_corridor_is_stable(self):
        assert format_corridor((355, 397)) == "355>397"
        assert format_corridor((329,)) == "329"
        assert format_corridor(()) == "-"


class TestEventValidation:
    def test_negative_func_ea_is_rejected(self):
        with pytest.raises(ValueError):
            StateWriteResolutionObserved(
                func_ea=-1, block_serial=1, block_ea=0, corridor=(1,),
                outcome="abstain", cause=CAUSE_UNRESOLVED,
            )

    def test_unknown_outcome_is_rejected(self):
        with pytest.raises(ValueError):
            StateWriteResolutionObserved(
                func_ea=0x10, block_serial=1, block_ea=0, corridor=(1,),
                outcome="wat", cause=CAUSE_UNRESOLVED,
            )

    def test_corridor_is_normalised_to_ints(self):
        event = StateWriteResolutionObserved(
            func_ea=0x10, block_serial=1, block_ea=0, corridor=[355, 397],
            outcome="abstain", cause=CAUSE_UNRESOLVED,
        )
        assert event.corridor == (355, 397)


class TestAbstainCauseLog:
    """The bounded channel the concrete interpreter reports its cause through."""

    def test_empty_log_names_no_cause(self):
        log = AbstainCauseLog()
        assert log.dominant() == ""
        assert log.def_sites() == ()

    def test_note_records_cause_and_def_sites(self):
        log = AbstainCauseLog()
        log.note(
            CAUSE_PHI_MULTI_DEF,
            def_sites=((329, 0x7FFB0EB1520A), (398, 0x7FFB0EB0BCF7)),
        )
        assert log.dominant() == CAUSE_PHI_MULTI_DEF
        assert log.def_sites() == ((329, 0x7FFB0EB1520A), (398, 0x7FFB0EB0BCF7))

    def test_dominant_uses_the_cause_precedence(self):
        log = AbstainCauseLog()
        log.note(CAUSE_NO_REACHING_DEFS)
        log.note(CAUSE_SYNTHETIC_TAINT)
        assert log.dominant() == CAUSE_SYNTHETIC_TAINT

    def test_def_sites_come_from_the_dominant_cause_only(self):
        log = AbstainCauseLog()
        log.note(CAUSE_PHI_MULTI_DEF, def_sites=((1, 2),))
        log.note("single_def_eval_failed", def_sites=((9, 9),))
        assert log.dominant() == CAUSE_PHI_MULTI_DEF
        assert log.def_sites() == ((1, 2),)

    def test_repeated_notes_do_not_duplicate_def_sites(self):
        log = AbstainCauseLog()
        for _ in range(5):
            log.note(CAUSE_PHI_MULTI_DEF, def_sites=((1, 2),))
        assert log.def_sites() == ((1, 2),)

    def test_log_is_bounded(self):
        log = AbstainCauseLog()
        for index in range(AbstainCauseLog.MAX_DEF_SITES + 50):
            log.note(CAUSE_PHI_MULTI_DEF, def_sites=((index, index),))
        assert len(log.def_sites()) == AbstainCauseLog.MAX_DEF_SITES

    def test_clear_resets_the_log(self):
        log = AbstainCauseLog()
        log.note(CAUSE_PHI_MULTI_DEF, def_sites=((1, 2),))
        log.clear()
        assert log.dominant() == ""
        assert log.def_sites() == ()

    def test_note_never_raises_on_a_malformed_def_site(self):
        log = AbstainCauseLog()
        log.note(CAUSE_PHI_MULTI_DEF, def_sites=[("bad", None)])
        assert log.dominant() == CAUSE_PHI_MULTI_DEF
        assert log.def_sites() == ()


class TestMarkCorridorExhausted:
    def _recorder(self):
        return StateWriteResolutionRecorder(func_ea=0x10, block_serial=330)

    def test_recauses_an_abstaining_corridor(self):
        rec = self._recorder()
        rec.note(corridor=(355, 397), outcome_kind="Abstain", resolved=False,
                 emulator_cause=CAUSE_PHI_MULTI_DEF)
        assert rec.mark_corridor_exhausted((355, 397)) is True
        (event,) = rec.build_events()
        assert event.cause == CAUSE_NO_DEF_WITHIN_HOP_BOUND

    def test_never_recauses_a_resolved_corridor(self):
        rec = self._recorder()
        rec.note(corridor=(329,), outcome_kind="ExactResult", resolved=True,
                 folded_value=1)
        assert rec.mark_corridor_exhausted((329,)) is False
        (event,) = rec.build_events()
        assert event.cause == CAUSE_RESOLVED

    def test_unknown_corridor_is_a_no_op(self):
        rec = self._recorder()
        assert rec.mark_corridor_exhausted((1, 2)) is False
        assert rec.build_events() == ()


# ---------------------------------------------------------------------------
# Per-step cause cursor (ticket d81-c6n7, slice 5)
# ---------------------------------------------------------------------------


class TestAbstainCauseLogStepCursor:
    """The emulator WARNING needs the cause of THIS instruction, not the block.

    ``dominant()`` answers "why did this whole consult abstain" and slice 4's
    ``eval_block`` reads it once per block.  A per-instruction WARNING needs a
    narrower question, so the cursor is additive: ``begin_step`` only forgets
    the *cursor*, never the accumulated causes ``dominant()`` ranks.
    """

    def test_latest_is_empty_before_anything_is_noted(self):
        log = AbstainCauseLog()
        assert log.latest() == ""
        assert log.latest_def_sites() == ()

    def test_latest_names_the_most_recent_cause(self):
        log = AbstainCauseLog()
        log.note(CAUSE_PHI_MULTI_DEF, def_sites=((329, 0x10),))
        log.note(CAUSE_NO_REACHING_DEFS)
        assert log.latest() == CAUSE_NO_REACHING_DEFS
        assert log.latest_def_sites() == ()

    def test_latest_carries_the_def_sites_of_that_cause(self):
        log = AbstainCauseLog()
        log.note(CAUSE_PHI_MULTI_DEF, def_sites=((329, 0x10), (398, 0x20)))
        assert log.latest() == CAUSE_PHI_MULTI_DEF
        assert log.latest_def_sites() == ((329, 0x10), (398, 0x20))

    def test_begin_step_clears_only_the_cursor(self):
        log = AbstainCauseLog()
        log.note(CAUSE_PHI_MULTI_DEF, def_sites=((329, 0x10),))
        log.begin_step()
        assert log.latest() == ""
        # dominant() still sees the accumulated cause: slice 4's block-level
        # consult must be byte-identical.
        assert log.dominant() == CAUSE_PHI_MULTI_DEF
        assert log.def_sites() == ((329, 0x10),)

    def test_a_repeat_note_still_moves_the_cursor(self):
        log = AbstainCauseLog()
        log.note(CAUSE_PHI_MULTI_DEF, def_sites=((329, 0x10),))
        log.note(CAUSE_NO_REACHING_DEFS)
        log.begin_step()
        log.note(CAUSE_PHI_MULTI_DEF)
        assert log.latest() == CAUSE_PHI_MULTI_DEF
        assert log.latest_def_sites() == ((329, 0x10),)

    def test_clear_resets_the_cursor_too(self):
        log = AbstainCauseLog()
        log.note(CAUSE_PHI_MULTI_DEF)
        log.clear()
        assert log.latest() == ""
        assert log.dominant() == ""

    def test_the_aliased_stack_slot_cause_outranks_no_reaching_defs(self):
        assert (
            dominant_cause(
                [CAUSE_NO_REACHING_DEFS, CAUSE_STACK_SLOT_IN_ALIASED_MEMORY]
            )
            == CAUSE_STACK_SLOT_IN_ALIASED_MEMORY
        )
