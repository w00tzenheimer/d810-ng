"""System tests for ctree optimizer manager and rule registration.

These tests import d810.hexrays and d810.optimizers, which are forbidden
in tests/unit by the import-linter contract.  They live here in tests/system.
"""

from __future__ import annotations

from types import SimpleNamespace

import ida_hexrays

from d810.analyses.control_flow.native_preanalysis_session import NativeMutationBoundary
from d810.core.execution_journal import (
    DecompilationSessionId,
    ExecutionAttemptStatus,
    ExecutionDomain,
)
from d810.core.execution_journal_store import ExecutionJournalStore
from d810.core.stats import OptimizationStatistics
from d810.hexrays.hooks.ctree_hooks import (
    CtreeOptimizerManager,
    CtreeOptimizationRule,
)


# -------------------------------------------------------------------------
# CtreeOptimizerManager tests (without IDA)
# -------------------------------------------------------------------------
class TestCtreeOptimizerManager:
    def test_manager_creation(self):
        stats = OptimizationStatistics()
        mgr = CtreeOptimizerManager(stats)
        assert mgr.ctree_rules == []
        assert mgr.stats is stats

    def test_on_maturity_skips_non_final(self):
        stats = OptimizationStatistics()
        mgr = CtreeOptimizerManager(stats)
        # When ida_hexrays is None, CMAT_FINAL comparison is skipped
        # and all rules are evaluated. With no rules, result is 0.
        assert mgr.on_maturity(None, 3) == 0

    def test_on_maturity_keeps_capture_but_skips_rules_when_quarantined(self):
        counts = {"capture": 0, "analyze": 0, "observe": 0, "rule": 0}
        lifecycle = SimpleNamespace(
            capture_ctree=lambda *_args, **_kwargs: counts.__setitem__(
                "capture", counts["capture"] + 1
            ),
            analyze_current_function=lambda **_kwargs: counts.__setitem__(
                "analyze", counts["analyze"] + 1
            ),
            observe_native_mutation_quarantine=lambda **kwargs: (
                counts.__setitem__("observe", counts["observe"] + 1)
                or kwargs["boundary"] is NativeMutationBoundary.CTREE
            ),
        )

        class CountingRule(CtreeOptimizationRule):
            NAME = "quarantined_ctree_rule"

            def optimize_ctree(self, _cfunc):
                counts["rule"] += 1
                return 1

        mgr = CtreeOptimizerManager(
            OptimizationStatistics(),
            decompilation_lifecycle=lifecycle,
        )
        mgr.add_rule(CountingRule())
        cfunc = SimpleNamespace(entry_ea=0x40A560)

        assert mgr.on_maturity(cfunc, ida_hexrays.CMAT_FINAL) == 0
        assert counts == {"capture": 1, "analyze": 1, "observe": 1, "rule": 0}


# -------------------------------------------------------------------------
# CtreeOptimizationRule registration tests
# -------------------------------------------------------------------------
class TestCtreeOptimizationRuleRegistration:
    def test_noop_counter_is_registered(self):
        """NoopCtreeCounter should auto-register when imported."""
        # Force import to trigger registration
        from d810.backends.hexrays.evidence.noop_counter import NoopCtreeCounter  # noqa: F401

        # Registry uses normalize_key(keyof(cls)) which is cls.__name__.lower()
        key = CtreeOptimizationRule.normalize_key(
            CtreeOptimizationRule.keyof(NoopCtreeCounter)
        )
        assert key in CtreeOptimizationRule.registry
        assert CtreeOptimizationRule.registry[key] is NoopCtreeCounter

    def test_noop_counter_returns_zero(self):
        from d810.backends.hexrays.evidence.noop_counter import NoopCtreeCounter

        rule = NoopCtreeCounter()
        assert rule.name == "noop_ctree_counter"
        # With None cfunc, should still return 0
        assert rule.optimize_ctree(None) == 0


# -------------------------------------------------------------------------
# CtreeOptimizerManager rule execution tests (MEDIUM issue)
# -------------------------------------------------------------------------
class TestCtreeOptimizerManagerRuleExecution:
    def test_rules_fire_and_stats_recorded(self):
        """Rules should fire and statistics should be recorded."""

        class FakeRule(CtreeOptimizationRule):
            NAME = "fake_rule"

            def optimize_ctree(self, cfunc):
                return 3  # 3 patches

        stats = OptimizationStatistics()
        mgr = CtreeOptimizerManager(stats)
        rule = FakeRule()
        mgr.add_rule(rule)

        # Without IDA, on_maturity skips CMAT_FINAL check, evaluates all rules
        total = mgr.on_maturity(None, 8)
        assert total == 3
        # Stats should have recorded the patches
        assert stats.get_cfg_rule_patch_counts("fake_rule") == [3]

    def test_exception_handling_in_rules(self):
        """Exceptions in rules should be caught and not propagate."""

        class FailingRule(CtreeOptimizationRule):
            NAME = "failing_rule"

            def optimize_ctree(self, cfunc):
                raise RuntimeError("boom")

        stats = OptimizationStatistics()
        mgr = CtreeOptimizerManager(stats)
        mgr.add_rule(FailingRule())

        # Should not raise
        total = mgr.on_maturity(None, 8)
        assert total == 0

    def test_rules_record_terminal_attempts_in_the_active_session(self, tmp_path):
        class AppliedRule(CtreeOptimizationRule):
            NAME = "ctree_applied"

            def optimize_ctree(self, cfunc):
                del cfunc
                return 2

        class NoOpRule(CtreeOptimizationRule):
            NAME = "ctree_noop"

            def optimize_ctree(self, cfunc):
                del cfunc
                return 0

        class FailingRule(CtreeOptimizationRule):
            NAME = "ctree_failing"

            def optimize_ctree(self, cfunc):
                del cfunc
                raise RuntimeError("ctree failure")

        journal = ExecutionJournalStore(
            tmp_path / "execution.sqlite", callback_detail="full"
        )
        session_id = DecompilationSessionId.new()
        parent = journal.begin_attempt(
            session_id,
            stage_id="hexrays_preanalysis",
            domain=ExecutionDomain.HOOK,
        )
        lifecycle = type(
            "Lifecycle",
            (),
            {
                "execution_journal": journal,
                "current_session": lambda self, _function_ea: type(
                    "Session",
                    (),
                    {
                        "session_id": session_id,
                        "preanalysis_attempt_id": parent.attempt_id,
                    },
                )(),
                "capture_ctree": lambda self, *args, **kwargs: None,
                "analyze_current_function": lambda self, **kwargs: None,
            },
        )()
        manager = CtreeOptimizerManager(
            OptimizationStatistics(),
            decompilation_lifecycle=lifecycle,
        )
        manager.add_rule(AppliedRule())
        manager.add_rule(NoOpRule())
        manager.add_rule(FailingRule())
        cfunc = type("Cfunc", (), {"entry_ea": 0x401000})()

        try:
            assert manager.on_maturity(cfunc, ida_hexrays.CMAT_FINAL) == 2
            applied = journal.only_attempt(
                session_id, stage_id="ctree_rule:ctree_applied"
            )
            assert applied.status is ExecutionAttemptStatus.COMPLETED
            assert applied.parent_attempt_id == parent.attempt_id
            assert applied.details == {
                "maturity": "CMAT_FINAL",
                "patch_count": 2,
            }
            mutation = journal.only_attempt(
                session_id, stage_id="ctree_mutation:ctree_applied"
            )
            assert mutation.status is ExecutionAttemptStatus.COMPLETED
            assert mutation.parent_attempt_id == applied.attempt_id
            assert mutation.details == {
                "maturity": "CMAT_FINAL",
                "patch_count": 2,
            }
            assert mutation.effect_refs[0].kind == "ctree_edit"

            noop = journal.only_attempt(session_id, stage_id="ctree_rule:ctree_noop")
            assert noop.status is ExecutionAttemptStatus.ABSTAINED
            assert noop.reason_code == "no_modifications"
            noop_mutation = journal.only_attempt(
                session_id, stage_id="ctree_mutation:ctree_noop"
            )
            assert noop_mutation.status is ExecutionAttemptStatus.ABSTAINED
            assert noop_mutation.reason_code == "no_modifications"

            failed = journal.only_attempt(
                session_id, stage_id="ctree_rule:ctree_failing"
            )
            assert failed.status is ExecutionAttemptStatus.FAILED
            assert "RuntimeError: ctree failure" == failed.reason_code
            failed_mutation = journal.only_attempt(
                session_id, stage_id="ctree_mutation:ctree_failing"
            )
            assert failed_mutation.status is ExecutionAttemptStatus.FAILED
        finally:
            journal.close()

    def test_noop_rule_is_summarized_by_default(self, tmp_path):
        class NoOpRule(CtreeOptimizationRule):
            NAME = "ctree_summary_noop"

            def optimize_ctree(self, cfunc):
                del cfunc
                return 0

        journal = ExecutionJournalStore(tmp_path / "execution.sqlite")
        session_id = DecompilationSessionId.new()
        parent = journal.begin_attempt(
            session_id,
            stage_id="hexrays_preanalysis",
            domain=ExecutionDomain.HOOK,
        )
        lifecycle = type(
            "Lifecycle",
            (),
            {
                "execution_journal": journal,
                "current_session": lambda self, _function_ea: type(
                    "Session",
                    (),
                    {
                        "session_id": session_id,
                        "preanalysis_attempt_id": parent.attempt_id,
                    },
                )(),
                "capture_ctree": lambda self, *args, **kwargs: None,
                "analyze_current_function": lambda self, **kwargs: None,
            },
        )()
        manager = CtreeOptimizerManager(
            OptimizationStatistics(),
            decompilation_lifecycle=lifecycle,
        )
        manager.add_rule(NoOpRule())
        cfunc = type("Cfunc", (), {"entry_ea": 0x401000})()

        try:
            assert manager.on_maturity(cfunc, ida_hexrays.CMAT_FINAL) == 0
            assert len(journal.attempts_for_session(session_id)) == 1
            summary = journal.flush_callback_summaries(
                session_id, parent_attempt_id=parent.attempt_id
            )
            assert summary is not None
            assert summary.details["groups"][0]["callback_kind"] == "ctree"
        finally:
            journal.close()

    def test_multiple_rules_accumulate(self):
        """Multiple rules should accumulate their patch counts."""

        class Rule1(CtreeOptimizationRule):
            NAME = "rule_one"

            def optimize_ctree(self, cfunc):
                return 2

        class Rule2(CtreeOptimizationRule):
            NAME = "rule_two"

            def optimize_ctree(self, cfunc):
                return 5

        stats = OptimizationStatistics()
        mgr = CtreeOptimizerManager(stats)
        mgr.add_rule(Rule1())
        mgr.add_rule(Rule2())

        total = mgr.on_maturity(None, 8)
        assert total == 7
