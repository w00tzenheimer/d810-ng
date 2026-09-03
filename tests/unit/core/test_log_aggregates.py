"""Tests for the pure per-maturity log aggregation counters (slice 3 of
unflat-diagnostics-legibility, ticket d81-ymrt).
"""

from d810.core.log_aggregates import FakeLoopCheckAggregator, RuleMatchAggregator


class FakeInfoLogger:
    """Minimal test double satisfying the ``_InfoLogger`` protocol."""

    def __init__(self):
        self.calls: list[tuple] = []

    def info(self, msg, *args):
        self.calls.append((msg, *args))


class TestRuleMatchAggregator:
    def test_empty_by_default(self):
        agg = RuleMatchAggregator()
        assert agg.is_empty()
        assert agg.total() == 0

    def test_record_accumulates_per_rule_name(self):
        agg = RuleMatchAggregator()
        agg.record("FoldReadonlyDataRule")
        agg.record("FoldReadonlyDataRule")
        agg.record("Z3setzRuleGeneric")

        assert not agg.is_empty()
        assert agg.total() == 3
        assert agg.counts == {"FoldReadonlyDataRule": 2, "Z3setzRuleGeneric": 1}

    def test_summary_line_sorts_by_count_desc_then_name(self):
        agg = RuleMatchAggregator()
        for _ in range(11):
            agg.record("FoldReadonlyDataRule")
        for _ in range(8):
            agg.record("Z3setzRuleGeneric")

        assert (
            agg.summary_line()
            == "rule matches: 19 (FoldReadonlyDataRule=11, Z3setzRuleGeneric=8)"
        )

    def test_summary_line_ties_break_alphabetically(self):
        agg = RuleMatchAggregator()
        agg.record("BRule")
        agg.record("ARule")

        assert agg.summary_line() == "rule matches: 2 (ARule=1, BRule=1)"

    def test_reset_clears_counts(self):
        agg = RuleMatchAggregator()
        agg.record("SomeRule")
        agg.reset()

        assert agg.is_empty()
        assert agg.total() == 0
        assert agg.counts == {}

    def test_flush_emits_one_info_line_and_resets(self):
        agg = RuleMatchAggregator()
        agg.record("FoldReadonlyDataRule")
        logger = FakeInfoLogger()

        agg.flush(logger, "InstructionOptimizerManager MMAT_GLBOPT1")

        assert len(logger.calls) == 1
        msg, prefix, summary = logger.calls[0]
        assert prefix == "InstructionOptimizerManager MMAT_GLBOPT1"
        assert summary == "rule matches: 1 (FoldReadonlyDataRule=1)"
        assert agg.is_empty()

    def test_flush_is_a_noop_when_empty(self):
        agg = RuleMatchAggregator()
        logger = FakeInfoLogger()

        agg.flush(logger, "unused prefix")

        assert logger.calls == []


class TestFakeLoopCheckAggregator:
    def test_empty_by_default(self):
        agg = FakeLoopCheckAggregator()
        assert agg.is_empty()
        assert agg.checked == 0
        assert agg.confirmed == 0

    def test_record_confirmed_and_unconfirmed(self):
        agg = FakeLoopCheckAggregator()
        agg.record(confirmed=True)
        agg.record(confirmed=False)
        agg.record(confirmed=True)

        assert not agg.is_empty()
        assert agg.checked == 3
        assert agg.confirmed == 2

    def test_summary_line(self):
        agg = FakeLoopCheckAggregator()
        for _ in range(1103):
            agg.record(confirmed=False)

        assert agg.summary_line() == "fake-loop checks: 1103, confirmed: 0"

    def test_reset_clears_counts(self):
        agg = FakeLoopCheckAggregator()
        agg.record(confirmed=True)
        agg.reset()

        assert agg.is_empty()
        assert agg.checked == 0
        assert agg.confirmed == 0

    def test_flush_emits_one_info_line_and_resets(self):
        agg = FakeLoopCheckAggregator()
        agg.record(confirmed=False)
        agg.record(confirmed=True)
        logger = FakeInfoLogger()

        agg.flush(logger, "UnflattenerFakeJump MMAT_CALLS")

        assert len(logger.calls) == 1
        msg, prefix, summary = logger.calls[0]
        assert prefix == "UnflattenerFakeJump MMAT_CALLS"
        assert summary == "fake-loop checks: 2, confirmed: 1"
        assert agg.is_empty()

    def test_flush_is_a_noop_when_empty(self):
        agg = FakeLoopCheckAggregator()
        logger = FakeInfoLogger()

        agg.flush(logger, "unused prefix")

        assert logger.calls == []
