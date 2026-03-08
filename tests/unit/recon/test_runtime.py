"""Unit tests for ReconAnalysisRuntime coordinator."""
from __future__ import annotations

from types import MappingProxyType
from unittest.mock import MagicMock, call, create_autospec

from d810.recon.analysis import AnalysisPhase
from d810.recon.models import DeobfuscationHints, ReconResult
from d810.recon.phase import ReconPhase
from d810.recon.runtime import ReconAnalysisRuntime
from d810.recon.store import ReconStore

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

_FUNC_EA = 0x401000
_MATURITY = 5
_SENTINEL_TARGET = object()


def _make_recon_result(
    collector_name: str = "CFGShapeCollector",
    func_ea: int = _FUNC_EA,
    maturity: int = _MATURITY,
) -> ReconResult:
    return ReconResult(
        collector_name=collector_name,
        func_ea=func_ea,
        maturity=maturity,
        timestamp=0.0,
        metrics=MappingProxyType({"block_count": 20}),
        candidates=(),
    )


def _make_hints(
    func_ea: int = _FUNC_EA,
    obfuscation_type: str | None = "ollvm_flat",
    confidence: float = 0.85,
) -> DeobfuscationHints:
    return DeobfuscationHints(
        func_ea=func_ea,
        obfuscation_type=obfuscation_type,
        confidence=confidence,
        recommended_recipes=("unflattening_recipe",),
        candidates=(),
        suppress_rules=(),
    )


def _make_runtime() -> tuple[
    ReconAnalysisRuntime, MagicMock, MagicMock, MagicMock
]:
    """Build a runtime with mocked dependencies.

    Returns (runtime, mock_phase, mock_analysis, mock_store).
    """
    mock_phase = create_autospec(ReconPhase, instance=True)
    mock_analysis = create_autospec(AnalysisPhase, instance=True)
    mock_store = create_autospec(ReconStore, instance=True)
    rt = ReconAnalysisRuntime(mock_phase, mock_analysis, mock_store)
    return rt, mock_phase, mock_analysis, mock_store


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


def test_collect_and_analyze_persists_hints() -> None:
    """collect_and_analyze with persist_hints=True saves hints to store."""
    rt, mock_phase, mock_analysis, mock_store = _make_runtime()

    results = [_make_recon_result()]
    hints = _make_hints()

    mock_phase.run_microcode_collectors.return_value = results
    mock_analysis.interpret.return_value = hints

    returned = rt.collect_and_analyze(
        _FUNC_EA, _SENTINEL_TARGET, _MATURITY, persist_hints=True,
    )

    assert returned is hints
    mock_phase.run_microcode_collectors.assert_called_once_with(
        _SENTINEL_TARGET, func_ea=_FUNC_EA, maturity=_MATURITY,
    )
    mock_analysis.interpret.assert_called_once_with(
        func_ea=_FUNC_EA, results=results,
    )
    mock_store.save_hints.assert_called_once_with(hints)


def test_collect_and_analyze_no_persist() -> None:
    """collect_and_analyze with persist_hints=False does NOT save hints."""
    rt, mock_phase, mock_analysis, mock_store = _make_runtime()

    results = [_make_recon_result()]
    hints = _make_hints()

    mock_phase.run_microcode_collectors.return_value = results
    mock_analysis.interpret.return_value = hints

    returned = rt.collect_and_analyze(
        _FUNC_EA, _SENTINEL_TARGET, _MATURITY, persist_hints=False,
    )

    assert returned is hints
    mock_store.save_hints.assert_not_called()


def test_load_hints_delegates_to_store() -> None:
    """load_hints passes through to store and returns the result."""
    rt, _mock_phase, _mock_analysis, mock_store = _make_runtime()

    stored_hints = _make_hints()
    mock_store.load_hints.return_value = stored_hints

    returned = rt.load_hints(_FUNC_EA)

    assert returned is stored_hints
    mock_store.load_hints.assert_called_once_with(func_ea=_FUNC_EA)


def test_load_hints_returns_none_when_absent() -> None:
    """load_hints returns None when the store has no entry."""
    rt, _mock_phase, _mock_analysis, mock_store = _make_runtime()

    mock_store.load_hints.return_value = None

    returned = rt.load_hints(_FUNC_EA)

    assert returned is None
    mock_store.load_hints.assert_called_once_with(func_ea=_FUNC_EA)


def test_load_or_analyze_cache_hit() -> None:
    """load_or_analyze returns cached hints without running collectors."""
    rt, mock_phase, mock_analysis, mock_store = _make_runtime()

    cached_hints = _make_hints()
    mock_store.load_hints.return_value = cached_hints

    returned = rt.load_or_analyze(
        _FUNC_EA, _SENTINEL_TARGET, _MATURITY,
    )

    assert returned is cached_hints
    mock_store.load_hints.assert_called_once_with(func_ea=_FUNC_EA)
    mock_phase.run_microcode_collectors.assert_not_called()
    mock_analysis.interpret.assert_not_called()


def test_load_or_analyze_cache_miss() -> None:
    """load_or_analyze falls back to collect_and_analyze on cache miss."""
    rt, mock_phase, mock_analysis, mock_store = _make_runtime()

    results = [_make_recon_result()]
    fresh_hints = _make_hints(confidence=0.70)

    mock_store.load_hints.return_value = None
    mock_phase.run_microcode_collectors.return_value = results
    mock_analysis.interpret.return_value = fresh_hints

    returned = rt.load_or_analyze(
        _FUNC_EA, _SENTINEL_TARGET, _MATURITY, persist_hints=True,
    )

    assert returned is fresh_hints
    mock_store.load_hints.assert_called_once_with(func_ea=_FUNC_EA)
    mock_phase.run_microcode_collectors.assert_called_once_with(
        _SENTINEL_TARGET, func_ea=_FUNC_EA, maturity=_MATURITY,
    )
    mock_analysis.interpret.assert_called_once_with(
        func_ea=_FUNC_EA, results=results,
    )
    mock_store.save_hints.assert_called_once_with(fresh_hints)


def test_reset_for_func_clears_fired_and_store() -> None:
    """reset_for_func delegates to phase.reset and store.clear_func."""
    rt, mock_phase, _mock_analysis, mock_store = _make_runtime()

    result = rt.reset_for_func(_FUNC_EA)

    assert result is True
    mock_phase.reset.assert_called_once_with(func_ea=_FUNC_EA)
    mock_store.clear_func.assert_called_once_with(func_ea=_FUNC_EA)


def test_analyze_and_persist_with_results() -> None:
    """analyze_and_persist runs analysis and saves hints when results exist."""
    rt, _mock_phase, mock_analysis, mock_store = _make_runtime()

    results = [_make_recon_result()]
    hints = _make_hints()

    mock_store.load_all_recon_results.return_value = results
    mock_analysis.interpret.return_value = hints

    returned = rt.analyze_and_persist(_FUNC_EA)

    assert returned is hints
    mock_store.load_all_recon_results.assert_called_once_with(func_ea=_FUNC_EA)
    mock_analysis.interpret.assert_called_once_with(
        func_ea=_FUNC_EA, results=results,
    )
    mock_store.save_hints.assert_called_once_with(hints)


def test_analyze_and_persist_no_results() -> None:
    """analyze_and_persist returns None when store has no recon results."""
    rt, _mock_phase, mock_analysis, mock_store = _make_runtime()

    mock_store.load_all_recon_results.return_value = []

    returned = rt.analyze_and_persist(_FUNC_EA)

    assert returned is None
    mock_store.load_all_recon_results.assert_called_once_with(func_ea=_FUNC_EA)
    mock_analysis.interpret.assert_not_called()
    mock_store.save_hints.assert_not_called()


def test_analyze_and_persist_overwrites_previous_hints() -> None:
    """analyze_and_persist overwrites hints on re-analysis."""
    rt, _mock_phase, mock_analysis, mock_store = _make_runtime()

    results_v1 = [_make_recon_result()]
    hints_v1 = _make_hints(confidence=0.60)
    results_v2 = [_make_recon_result(), _make_recon_result("DispatchPatternCollector")]
    hints_v2 = _make_hints(confidence=0.95)

    # First call
    mock_store.load_all_recon_results.return_value = results_v1
    mock_analysis.interpret.return_value = hints_v1
    ret1 = rt.analyze_and_persist(_FUNC_EA)

    # Second call with more results
    mock_store.load_all_recon_results.return_value = results_v2
    mock_analysis.interpret.return_value = hints_v2
    ret2 = rt.analyze_and_persist(_FUNC_EA)

    assert ret1 is hints_v1
    assert ret2 is hints_v2
    assert mock_store.save_hints.call_count == 2
    mock_store.save_hints.assert_any_call(hints_v1)
    mock_store.save_hints.assert_any_call(hints_v2)


def test_collect_and_analyze_saves_recon_results() -> None:
    """Verify run_microcode_collectors is invoked (it saves results internally)."""
    rt, mock_phase, mock_analysis, mock_store = _make_runtime()

    r1 = _make_recon_result("CFGShapeCollector")
    r2 = _make_recon_result("DispatchPatternCollector")
    results = [r1, r2]
    hints = _make_hints()

    mock_phase.run_microcode_collectors.return_value = results
    mock_analysis.interpret.return_value = hints

    returned = rt.collect_and_analyze(
        _FUNC_EA, _SENTINEL_TARGET, _MATURITY,
    )

    assert returned is hints
    # The runtime delegates to phase which internally saves each ReconResult.
    # Verify the phase was called with the right arguments.
    mock_phase.run_microcode_collectors.assert_called_once_with(
        _SENTINEL_TARGET, func_ea=_FUNC_EA, maturity=_MATURITY,
    )
    # Both results are forwarded to the analysis phase.
    mock_analysis.interpret.assert_called_once_with(
        func_ea=_FUNC_EA, results=results,
    )


# ---------------------------------------------------------------------------
# Dedup: reset fires exactly once per decompilation, across managers
# ---------------------------------------------------------------------------


def test_reset_deduplicates_across_calls() -> None:
    """Calling reset_for_func(X) twice only fires phase.reset/store.clear once.

    This simulates two managers (instruction + block) both calling
    reset_for_func with the same func_ea during a single decompilation.
    The runtime's internal guard deduplicates: only the first call fires.
    """
    rt, mock_phase, _mock_analysis, mock_store = _make_runtime()

    # First call fires
    assert rt.reset_for_func(_FUNC_EA) is True
    assert mock_phase.reset.call_count == 1
    assert mock_store.clear_func.call_count == 1

    # Second call with same func_ea is a no-op
    assert rt.reset_for_func(_FUNC_EA) is False
    assert mock_phase.reset.call_count == 1  # still 1
    assert mock_store.clear_func.call_count == 1  # still 1


def test_mark_decompilation_finished_allows_re_reset() -> None:
    """After mark_decompilation_finished, same func_ea triggers reset again.

    Simulates the lifecycle: decompile func X -> FINISHED event ->
    re-decompile func X. The FINISHED event calls mark_decompilation_finished
    which resets the guard so the next decompilation fires reset.
    """
    rt, mock_phase, _mock_analysis, mock_store = _make_runtime()

    # 1st decompilation
    assert rt.reset_for_func(_FUNC_EA) is True
    assert mock_phase.reset.call_count == 1

    # Decompilation finishes
    rt.mark_decompilation_finished()

    # 2nd decompilation of SAME function: fires again
    assert rt.reset_for_func(_FUNC_EA) is True
    assert mock_phase.reset.call_count == 2
    assert mock_store.clear_func.call_count == 2
    mock_phase.reset.assert_has_calls(
        [call(func_ea=_FUNC_EA), call(func_ea=_FUNC_EA)]
    )


def test_reset_fires_on_different_func_without_mark_finished() -> None:
    """Switching to a different function fires reset without needing mark_finished.

    This covers the case where IDA decompiles func A then func B in sequence
    without an explicit FINISHED event between them.
    """
    rt, mock_phase, _mock_analysis, mock_store = _make_runtime()
    other_ea = 0x402000

    assert rt.reset_for_func(_FUNC_EA) is True
    assert rt.reset_for_func(other_ea) is True
    assert mock_phase.reset.call_count == 2
    mock_phase.reset.assert_has_calls(
        [call(func_ea=_FUNC_EA), call(func_ea=other_ea)]
    )


# ---------------------------------------------------------------------------
# Outcome recording
# ---------------------------------------------------------------------------


def test_runtime_record_outcome() -> None:
    """record_outcome delegates to outcome log."""
    rt, _mock_phase, _mock_analysis, _mock_store = _make_runtime()

    from d810.recon.outcome import RuleScopeOutcomeAdapter
    from d810.recon.runtime import ReconOutcome

    outcome = ReconOutcome(
        func_ea=_FUNC_EA,
        hints=_make_hints(),
        apply_result=None,
        source="analyzed",
    )
    adapter = RuleScopeOutcomeAdapter(outcome)
    rt.record_outcome(adapter)

    reports = rt.outcome_log.get_func_reports(_FUNC_EA)
    assert len(reports) == 1
    assert reports[0].consumer_name == "rule_scope"
    assert reports[0].func_ea == _FUNC_EA


def test_reset_clears_outcome_log() -> None:
    """reset_for_func clears outcome entries for the function."""
    rt, _mock_phase, _mock_analysis, _mock_store = _make_runtime()

    from d810.recon.outcome import RuleScopeOutcomeAdapter
    from d810.recon.runtime import ReconOutcome

    outcome = ReconOutcome(
        func_ea=_FUNC_EA,
        hints=_make_hints(),
        apply_result=None,
        source="cached",
    )
    adapter = RuleScopeOutcomeAdapter(outcome)
    rt.record_outcome(adapter)
    assert len(rt.outcome_log.get_func_reports(_FUNC_EA)) == 1

    # reset_for_func should also clear outcome log
    rt.reset_for_func(_FUNC_EA)
    assert rt.outcome_log.get_func_reports(_FUNC_EA) == []


def test_record_rule_scope_outcome() -> None:
    """record_rule_scope_outcome builds adapter internally and records."""
    rt, _mock_phase, _mock_analysis, _mock_store = _make_runtime()

    hints = _make_hints()
    rt.record_rule_scope_outcome(
        func_ea=_FUNC_EA,
        hints=hints,
        apply_result=None,
        source="analyzed",
    )

    reports = rt.outcome_log.get_func_reports(_FUNC_EA)
    assert len(reports) == 1
    assert reports[0].consumer_name == "rule_scope"
    assert reports[0].source_artifacts_available is True
    assert reports[0].summary_available is True
    assert reports[0].consumer_verdict_applied is False  # apply_result=None


def test_get_outcome_summary() -> None:
    """get_outcome_summary delegates to outcome log summary."""
    rt, _mock_phase, _mock_analysis, _mock_store = _make_runtime()

    rt.record_rule_scope_outcome(
        func_ea=_FUNC_EA,
        hints=_make_hints(),
        apply_result=None,
        source="analyzed",
    )

    summary = rt.get_outcome_summary(_FUNC_EA)
    assert summary["func_ea"] == _FUNC_EA
    assert len(summary["consumers"]) == 1
    assert summary["consumers"][0]["name"] == "rule_scope"
