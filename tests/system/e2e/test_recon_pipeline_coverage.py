"""E2E pipeline coverage assertions — verify recon lifecycle fires completely.

These tests piggyback on the DSL test suite. They do NOT trigger new
decompilations. They open the recon DB that was populated during the
DSL test run and assert aggregate properties:

Layer 1 (this file):
- All decompiled functions produced hints
- All functions with hints have session summaries (no 93/94 gap)
- Consumer outcomes were recorded

These assertions catch pipeline plumbing regressions.
"""
import pytest

from tests.system.cases.libobfuscated_comprehensive import TOTAL_FUNCTION_COUNT


@pytest.mark.e2e
class TestReconPipelineCoverage:
    """Aggregate pipeline coverage assertions.

    Depends on DSL tests having run first in the same session.
    """

    def test_hints_produced_for_all_functions(self, recon_store_session):
        """Every decompiled function should produce deobfuscation hints."""
        if recon_store_session is None:
            pytest.skip("Recon pipeline disabled")
        count = recon_store_session.count_functions_with_hints()
        assert count >= TOTAL_FUNCTION_COUNT, (
            f"Expected >= {TOTAL_FUNCTION_COUNT} functions with hints, got {count}"
        )

    def test_session_summaries_match_hints(self, recon_store_session):
        """Every function with hints must also have a session summary.

        This is the regression test for the 93/94 gap fixed by eager
        session summary persistence in analyze_and_persist().
        """
        if recon_store_session is None:
            pytest.skip("Recon pipeline disabled")
        gap = recon_store_session.list_functions_missing_session_summary()
        assert len(gap) == 0, (
            f"Functions with hints but no session summary: "
            f"{[hex(ea) for ea in gap]}"
        )

    def test_session_summary_count(self, recon_store_session):
        """Session summary count should match hint count."""
        if recon_store_session is None:
            pytest.skip("Recon pipeline disabled")
        hints_count = recon_store_session.count_functions_with_hints()
        summary_count = recon_store_session.count_functions_with_session_summaries()
        assert summary_count == hints_count, (
            f"Hints: {hints_count}, Summaries: {summary_count} — "
            f"gap of {hints_count - summary_count}"
        )

    def test_consumer_outcomes_recorded(self, recon_store_session):
        """At least some functions should have consumer outcome records."""
        if recon_store_session is None:
            pytest.skip("Recon pipeline disabled")
        count = recon_store_session.count_functions_with_consumer_outcomes()
        assert count > 0, "No consumer outcomes recorded — pipeline wiring broken"

    def test_collectors_fired_nonzero(self, recon_store_session):
        """Every session summary should report at least 1 collector fired."""
        if recon_store_session is None:
            pytest.skip("Recon pipeline disabled")
        summaries = recon_store_session.load_all_session_summaries()
        zero_collector_funcs = [
            hex(s["func_ea"]) for s in summaries
            if s["collectors_fired"] == 0
        ]
        assert len(zero_collector_funcs) == 0, (
            f"Functions with 0 collectors fired: {zero_collector_funcs}"
        )
