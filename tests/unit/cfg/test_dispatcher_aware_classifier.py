"""Tests for the dispatcher-aware back-edge classifier."""
from __future__ import annotations

from d810.analyses.control_flow.dispatcher_aware_classifier import (
    DispatcherAwareClassification,
    DispatcherAwareEdgeClass,
    DispatcherAwareSummary,
    DispatcherContext,
    classify_backedge_dispatcher_aware,
    classify_backedges_dispatcher_aware,
    summarize,
)


class TestClassifyBackedgeDispatcherAware:
    def test_target_in_dispatcher_region_classifies_round_trip(self) -> None:
        ctx = DispatcherContext(
            dispatcher_blocks=frozenset({2, 3, 4, 5, 6}),
            excluded_carriers=frozenset({"%var_3C"}),
        )
        # Handler X writes %state_var, gotos dispatcher.
        c = classify_backedge_dispatcher_aware(
            src_serial=42,
            tgt_serial=2,  # dispatcher root
            src_writes=frozenset({"%var_3C"}),
            tgt_predicate_reads=frozenset({"%var_3C"}),
            context=ctx,
        )
        assert c.classification is DispatcherAwareEdgeClass.DISPATCHER_ROUND_TRIP
        assert c.is_dispatcher_round_trip
        assert not c.is_real_loop
        assert not c.is_spurious
        # Round-trip classification short-circuits before computing overlap.
        assert c.overlap == frozenset()
        assert "dispatcher region" in c.reason

    def test_target_in_condition_chain_cascade_also_round_trip(self) -> None:
        ctx = DispatcherContext(
            dispatcher_blocks=frozenset({2, 3, 4, 5, 6}),
        )
        c = classify_backedge_dispatcher_aware(
            src_serial=42,
            tgt_serial=4,  # condition-chain cascade node
            src_writes=frozenset(),
            tgt_predicate_reads=frozenset(),
            context=ctx,
        )
        assert c.is_dispatcher_round_trip

    def test_real_loop_carrier_outside_state_vars(self) -> None:
        # blk[10] writes %var_178 (head-byte stride carrier), blk[4]
        # predicate reads %var_178. Not a dispatcher target.
        ctx = DispatcherContext(
            dispatcher_blocks=frozenset(),
            excluded_carriers=frozenset({"%var_3C"}),
        )
        c = classify_backedge_dispatcher_aware(
            src_serial=10,
            tgt_serial=4,
            src_writes=frozenset({"%var_178"}),
            tgt_predicate_reads=frozenset({"%var_178"}),
            context=ctx,
        )
        assert c.classification is DispatcherAwareEdgeClass.REAL_LOOP
        assert c.is_real_loop
        assert c.overlap == frozenset({"%var_178"})
        assert c.state_var_overlap == frozenset()

    def test_only_state_var_overlap_is_spurious(self) -> None:
        # Carrier is state var only — that's dispatcher mechanism, not
        # algorithmic iteration. Classify SPURIOUS.
        ctx = DispatcherContext(
            dispatcher_blocks=frozenset(),
            excluded_carriers=frozenset({"%var_3C"}),
        )
        c = classify_backedge_dispatcher_aware(
            src_serial=42,
            tgt_serial=99,
            src_writes=frozenset({"%var_3C"}),
            tgt_predicate_reads=frozenset({"%var_3C"}),
            context=ctx,
        )
        assert c.classification is DispatcherAwareEdgeClass.SPURIOUS
        assert c.is_spurious
        assert c.overlap == frozenset({"%var_3C"})
        assert c.state_var_overlap == frozenset({"%var_3C"})

    def test_real_loop_with_state_var_plus_real_carrier(self) -> None:
        # If src writes BOTH state var and a real carrier that target
        # reads, REAL_LOOP wins (the real carrier exists).
        ctx = DispatcherContext(excluded_carriers=frozenset({"%var_3C"}))
        c = classify_backedge_dispatcher_aware(
            src_serial=10,
            tgt_serial=4,
            src_writes=frozenset({"%var_3C", "%var_178"}),
            tgt_predicate_reads=frozenset({"%var_3C", "%var_178"}),
            context=ctx,
        )
        assert c.is_real_loop
        assert c.overlap == frozenset({"%var_3C", "%var_178"})
        assert c.state_var_overlap == frozenset({"%var_3C"})

    def test_disjoint_sets_classify_spurious(self) -> None:
        ctx = DispatcherContext()
        c = classify_backedge_dispatcher_aware(
            src_serial=15,
            tgt_serial=13,
            src_writes=frozenset({"%var_5B8"}),
            tgt_predicate_reads=frozenset({"%var_F0"}),
            context=ctx,
        )
        assert c.is_spurious
        assert c.overlap == frozenset()

    def test_empty_predicate_reads_classify_unknown(self) -> None:
        ctx = DispatcherContext()
        c = classify_backedge_dispatcher_aware(
            src_serial=12,
            tgt_serial=5,
            src_writes=frozenset({"%var_330"}),
            tgt_predicate_reads=frozenset(),
            context=ctx,
        )
        assert c.classification is DispatcherAwareEdgeClass.UNKNOWN
        assert "no readable tail predicate" in c.reason

    def test_dispatcher_takes_priority_over_carrier_overlap(self) -> None:
        # Even when src writes %var_3C and tgt reads %var_3C, if tgt is
        # the dispatcher we classify ROUND_TRIP (not SPURIOUS), so the
        # actionable forward-target resolver knows to condition-chain-resolve.
        ctx = DispatcherContext(
            dispatcher_blocks=frozenset({2}),
            excluded_carriers=frozenset({"%var_3C"}),
        )
        c = classify_backedge_dispatcher_aware(
            src_serial=42,
            tgt_serial=2,
            src_writes=frozenset({"%var_3C"}),
            tgt_predicate_reads=frozenset({"%var_3C"}),
            context=ctx,
        )
        assert c.is_dispatcher_round_trip


class TestLocoptShape:
    """Verify the classifier handles the LOCOPT shape: dispatcher alive,
    handler→dispatcher round-trips dominate the back-edge set."""

    def test_dispatcher_alive_loopopt_classification(self) -> None:
        # 5 handlers each tail-jump to dispatcher root blk[2].
        # Plus a real iteration loop blk[10]→blk[4] (head-byte stride).
        edges = [
            (42, 2), (43, 2), (44, 2), (45, 2), (46, 2),  # round-trips
            (10, 4),                                       # real loop
        ]
        ctx = DispatcherContext(
            dispatcher_blocks=frozenset({2, 3, 4, 5, 6, 7}),
            excluded_carriers=frozenset({"%var_3C"}),
        )
        # All handlers write %state_var. Real loop block writes carrier.
        block_writes = {
            42: frozenset({"%var_3C"}),
            43: frozenset({"%var_3C"}),
            44: frozenset({"%var_3C"}),
            45: frozenset({"%var_3C"}),
            46: frozenset({"%var_3C"}),
            10: frozenset({"%var_178"}),
        }
        block_predicate_reads = {
            2: frozenset({"%var_3C"}),
            4: frozenset({"%var_178"}),
        }
        result = classify_backedges_dispatcher_aware(
            edges,
            block_writes=block_writes,
            block_predicate_reads=block_predicate_reads,
            context=ctx,
        )
        # ALL handler→dispatcher edges classify as DISPATCHER_ROUND_TRIP
        # (target is in dispatcher region; classification short-circuits).
        # The real-loop edge (10, 4) targets blk[4] which IS in the
        # dispatcher_blocks set in this fixture — so it ALSO classifies
        # as round-trip. This test documents that behavior: the real
        # loop has to be detected outside the dispatcher region.
        for c in result[:5]:
            assert c.is_dispatcher_round_trip
        # The 6th edge demonstrates the dispatcher-region precedence.
        assert result[5].is_dispatcher_round_trip

    def test_real_loop_outside_dispatcher_region(self) -> None:
        # When the real-loop predicate block is OUTSIDE the dispatcher,
        # it correctly classifies as REAL_LOOP. This is the case at
        # GLBOPT1 post-D810 where the dispatcher has been demoted.
        ctx = DispatcherContext(
            dispatcher_blocks=frozenset({2, 3}),  # only the root cascade
            excluded_carriers=frozenset({"%var_3C"}),
        )
        edges = [(42, 2), (10, 4)]
        block_writes = {
            42: frozenset({"%var_3C"}),
            10: frozenset({"%var_178"}),
        }
        block_predicate_reads = {
            2: frozenset({"%var_3C"}),
            4: frozenset({"%var_178"}),
        }
        result = classify_backedges_dispatcher_aware(
            edges,
            block_writes=block_writes,
            block_predicate_reads=block_predicate_reads,
            context=ctx,
        )
        assert result[0].is_dispatcher_round_trip
        assert result[1].is_real_loop


class TestSummary:
    def test_empty_summary(self) -> None:
        s = summarize([])
        assert s.total == 0
        assert s == DispatcherAwareSummary()

    def test_mixed_summary(self) -> None:
        ctx = DispatcherContext(
            dispatcher_blocks=frozenset({2}),
            excluded_carriers=frozenset({"%var_3C"}),
        )
        edges = [(42, 2), (10, 4), (15, 13), (12, 5)]
        block_writes = {
            42: frozenset({"%var_3C"}),
            10: frozenset({"%var_178"}),
            15: frozenset({"%var_5B8"}),
            12: frozenset({"%var_330"}),
        }
        block_predicate_reads = {
            2: frozenset({"%var_3C"}),
            4: frozenset({"%var_178"}),
            13: frozenset({"%var_F0"}),
            5: frozenset(),
        }
        result = classify_backedges_dispatcher_aware(
            edges,
            block_writes=block_writes,
            block_predicate_reads=block_predicate_reads,
            context=ctx,
        )
        s = summarize(result)
        assert s.dispatcher_round_trip == 1
        assert s.real_loop == 1
        assert s.spurious == 1
        assert s.unknown == 1
        assert s.total == 4


class TestDataclassShortcuts:
    def _mk(self, cls: DispatcherAwareEdgeClass) -> DispatcherAwareClassification:
        return DispatcherAwareClassification(
            src_serial=0, tgt_serial=0, classification=cls,
            src_writes=frozenset(), tgt_predicate_reads=frozenset(),
            overlap=frozenset(), state_var_overlap=frozenset(),
            reason="x",
        )

    def test_round_trip_shortcut(self) -> None:
        c = self._mk(DispatcherAwareEdgeClass.DISPATCHER_ROUND_TRIP)
        assert c.is_dispatcher_round_trip
        assert not c.is_real_loop
        assert not c.is_spurious

    def test_real_loop_shortcut(self) -> None:
        c = self._mk(DispatcherAwareEdgeClass.REAL_LOOP)
        assert not c.is_dispatcher_round_trip
        assert c.is_real_loop
        assert not c.is_spurious

    def test_spurious_shortcut(self) -> None:
        c = self._mk(DispatcherAwareEdgeClass.SPURIOUS)
        assert not c.is_dispatcher_round_trip
        assert not c.is_real_loop
        assert c.is_spurious

    def test_unknown_shortcuts_all_false(self) -> None:
        c = self._mk(DispatcherAwareEdgeClass.UNKNOWN)
        assert not c.is_dispatcher_round_trip
        assert not c.is_real_loop
        assert not c.is_spurious
