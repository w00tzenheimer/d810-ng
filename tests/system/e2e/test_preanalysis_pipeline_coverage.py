"E2E pipeline coverage assertions \u2014 verify preanalysis lifecycle fires completely.\n\nThe analysis_store_session fixture triggers a minimal decompilation\n(_hodur_func) to populate the preanalysis DB, making these tests self-contained.\n\nLayer 1 (this file):\n- At least one decompiled function produced hints\n- All functions with hints have session summaries (no 93/94 gap)\n- Consumer outcomes were recorded\n\nThese assertions catch pipeline plumbing regressions.\n"
import pytest


@pytest.mark.e2e
class TestReconPipelineCoverage:
    "Aggregate pipeline coverage assertions.\n\n    The analysis_store_session fixture triggers at least one decompilation\n    (e.g., _hodur_func) to populate the preanalysis DB, making these tests\n    self-contained.\n    "

    def test_hints_produced(self, analysis_store_session):
        """At least one decompiled function should produce deobfuscation hints."""
        if analysis_store_session is None:
            pytest.skip("Preanalysis pipeline disabled")
        count = analysis_store_session.count_functions_with_hints()
        assert count >= 1, (
            f"Expected >= 1 function with hints, got {count}"
        )

    def test_session_summaries_match_hints(self, analysis_store_session):
        """Every function with hints must also have a session summary.

        This is the regression test for the 93/94 gap fixed by eager
        session summary persistence in analyze_and_persist().
        """
        if analysis_store_session is None:
            pytest.skip("Preanalysis pipeline disabled")
        gap = analysis_store_session.list_functions_missing_session_summary()
        assert len(gap) == 0, (
            f"Functions with hints but no session summary: "
            f"{[hex(ea) for ea in gap]}"
        )

    def test_session_summary_count(self, analysis_store_session):
        """Session summary count should match hint count."""
        if analysis_store_session is None:
            pytest.skip("Preanalysis pipeline disabled")
        hints_count = analysis_store_session.count_functions_with_hints()
        summary_count = analysis_store_session.count_functions_with_session_summaries()
        assert summary_count == hints_count, (
            f"Hints: {hints_count}, Summaries: {summary_count} — "
            f"gap of {hints_count - summary_count}"
        )

    def test_consumer_outcomes_recorded(self, analysis_store_session):
        """At least some functions should have consumer outcome records."""
        if analysis_store_session is None:
            pytest.skip("Preanalysis pipeline disabled")
        count = analysis_store_session.count_functions_with_consumer_outcomes()
        assert count > 0, "No consumer outcomes recorded — pipeline wiring broken"

    def test_collectors_fired_nonzero(self, analysis_store_session):
        """Every session summary should report at least 1 collector fired."""
        if analysis_store_session is None:
            pytest.skip("Preanalysis pipeline disabled")
        summaries = analysis_store_session.load_all_session_summaries()
        zero_collector_funcs = [
            hex(s["func_ea"]) for s in summaries
            if s["collectors_fired"] == 0
        ]
        assert len(zero_collector_funcs) == 0, (
            f"Functions with 0 collectors fired: {zero_collector_funcs}"
        )
