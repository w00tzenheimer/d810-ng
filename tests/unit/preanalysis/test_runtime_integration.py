"""Unit tests for consumer analysis and rule-scope delivery."""
from __future__ import annotations

from types import MappingProxyType
from pathlib import Path
from unittest.mock import MagicMock, create_autospec, patch

import pytest

from d810.core import ProviderPhaseSnapshot
from d810.core.rule_scope import ApplyHintsResult, RuleScopeService
from d810.passes.analysis import AnalysisPhase
from d810.analyses.control_flow.models import DeobfuscationHints, PreanalysisResult
from d810.passes.phase import PreanalysisPhase
from d810.passes.runtime import DecompilationAnalysisRuntime, AnalysisOutcome
from d810.passes.store import PreanalysisStore

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

_FUNC_EA = 0x401000
_MATURITY = 5
_SENTINEL_TARGET = object()


def _phase(level: int = _MATURITY, friendly: str | None = None) -> ProviderPhaseSnapshot:
    return ProviderPhaseSnapshot(
        provider_name="hexrays_microcode",
        provider_level=level,
        friendly_provider_level=friendly or f"MMAT_{level}",
    )


def _make_preanalysis_result(
    collector_name: str = "CFGShapeCollector",
    func_ea: int = _FUNC_EA,
    maturity: int = _MATURITY,
) -> PreanalysisResult:
    return PreanalysisResult(
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
    recommended_inferences: tuple[str, ...] = ("unflattening",),
    suppress_rules: tuple[str, ...] = (),
) -> DeobfuscationHints:
    return DeobfuscationHints(
        func_ea=func_ea,
        obfuscation_type=obfuscation_type,
        confidence=confidence,
        recommended_inferences=recommended_inferences,
        candidates=(),
        suppress_rules=suppress_rules,
    )


def _make_apply_result(
    func_ea: int = _FUNC_EA,
    inferences_applied: tuple[str, ...] = ("unflattening",),
    inferences_not_found: tuple[str, ...] = (),
    rules_suppressed: tuple[str, ...] = (),
    cache_invalidated: bool = True,
    generation_before: int = 0,
    generation_after: int = 1,
) -> ApplyHintsResult:
    return ApplyHintsResult(
        func_ea=func_ea,
        inferences_applied=inferences_applied,
        inferences_not_found=inferences_not_found,
        rules_suppressed=rules_suppressed,
        cache_invalidated=cache_invalidated,
        generation_before=generation_before,
        generation_after=generation_after,
    )


def _make_sync_writer(mock_store: MagicMock) -> MagicMock:
    writer = MagicMock()
    writer.submit.side_effect = lambda fn: fn(mock_store)
    writer.submit_sync.side_effect = lambda fn: fn(mock_store)
    writer.flush.return_value = None
    return writer


_active_patchers: list = []


@pytest.fixture(autouse=True)
def _cleanup_writer_patchers():
    yield
    for p in _active_patchers:
        p.stop()
    _active_patchers.clear()


def _make_runtime() -> tuple[
    DecompilationAnalysisRuntime, MagicMock, MagicMock, MagicMock
]:
    """Build a runtime with mocked dependencies.

    Returns (runtime, mock_phase, mock_analysis, mock_store).
    """
    mock_phase = create_autospec(PreanalysisPhase, instance=True)
    mock_analysis = create_autospec(AnalysisPhase, instance=True)
    mock_store = create_autospec(PreanalysisStore, instance=True)
    mock_store.db_path = Path("/tmp/test_preanalysis.db")

    writer = _make_sync_writer(mock_store)
    p1 = patch("d810.passes.runtime.get_preanalysis_writer", return_value=writer)
    p2 = patch("d810.passes.phase.get_preanalysis_writer", return_value=writer)
    p1.start()
    p2.start()
    _active_patchers.extend([p1, p2])

    rt = DecompilationAnalysisRuntime(mock_analysis, mock_store)
    return rt, mock_phase, mock_analysis, mock_store


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


def test_apply_to_rule_scope_fresh_analysis() -> None:
    """No cached hints -> analyzes persisted evidence and applies it."""
    rt, mock_phase, mock_analysis, mock_store = _make_runtime()
    mock_rule_scope = create_autospec(RuleScopeService, instance=True)

    results = [_make_preanalysis_result()]
    hints = _make_hints()
    apply_result = _make_apply_result()

    mock_store.load_hints.return_value = None
    mock_store.load_all_preanalysis_results.return_value = results
    mock_analysis.interpret.return_value = hints
    mock_rule_scope.apply_hints.return_value = apply_result

    outcome = rt.apply_to_rule_scope(_FUNC_EA, mock_rule_scope)

    assert outcome.func_ea == _FUNC_EA
    assert outcome.hints is hints
    assert outcome.apply_result is apply_result
    assert outcome.source == "analyzed"

    mock_store.load_hints.assert_called_once_with(func_ea=_FUNC_EA)
    mock_phase.run_microcode_collectors.assert_not_called()
    mock_analysis.interpret.assert_called_once_with(
        func_ea=_FUNC_EA, results=results, store=mock_store,
    )
    mock_rule_scope.apply_hints.assert_called_once_with(hints)


def test_apply_to_rule_scope_cached_hints() -> None:
    """Cached hints -> skips collectors, applies directly."""
    rt, mock_phase, mock_analysis, mock_store = _make_runtime()
    mock_rule_scope = create_autospec(RuleScopeService, instance=True)

    cached_hints = _make_hints()
    apply_result = _make_apply_result()

    mock_store.load_hints.return_value = cached_hints
    mock_rule_scope.apply_hints.return_value = apply_result

    outcome = rt.apply_to_rule_scope(_FUNC_EA, mock_rule_scope)

    assert outcome.func_ea == _FUNC_EA
    assert outcome.hints is cached_hints
    assert outcome.apply_result is apply_result
    assert outcome.source == "cached"

    # Collectors must NOT have run
    mock_phase.run_microcode_collectors.assert_not_called()
    mock_analysis.interpret.assert_not_called()


def test_apply_to_rule_scope_no_hints_available() -> None:
    """No cached hints and no target -> returns unavailable outcome."""
    rt, mock_phase, mock_analysis, mock_store = _make_runtime()
    mock_rule_scope = create_autospec(RuleScopeService, instance=True)

    mock_store.load_hints.return_value = None
    mock_store.load_all_preanalysis_results.return_value = []

    outcome = rt.apply_to_rule_scope(_FUNC_EA, mock_rule_scope)

    assert outcome.func_ea == _FUNC_EA
    assert outcome.hints is None
    assert outcome.apply_result is None
    assert outcome.source == "unavailable"

    # Nothing should have run
    mock_phase.run_microcode_collectors.assert_not_called()
    mock_analysis.interpret.assert_not_called()
    mock_rule_scope.apply_hints.assert_not_called()


def test_outcome_records_source_correctly() -> None:
    """Verify source field is set correctly for each scenario."""
    rt, mock_phase, mock_analysis, mock_store = _make_runtime()
    mock_rule_scope = create_autospec(RuleScopeService, instance=True)
    hints = _make_hints()
    apply_result = _make_apply_result()

    # --- "cached" ---
    mock_store.load_hints.return_value = hints
    mock_rule_scope.apply_hints.return_value = apply_result

    cached_outcome = rt.apply_to_rule_scope(_FUNC_EA, mock_rule_scope)
    assert cached_outcome.source == "cached"

    # --- "analyzed" ---
    mock_store.load_hints.return_value = None
    mock_store.load_all_preanalysis_results.return_value = [
        _make_preanalysis_result()
    ]
    mock_analysis.interpret.return_value = hints
    mock_rule_scope.apply_hints.return_value = apply_result

    analyzed_outcome = rt.apply_to_rule_scope(_FUNC_EA, mock_rule_scope)
    assert analyzed_outcome.source == "analyzed"

    # --- "unavailable" ---
    mock_store.load_hints.return_value = None
    mock_store.load_all_preanalysis_results.return_value = []

    unavailable_outcome = rt.apply_to_rule_scope(_FUNC_EA, mock_rule_scope)
    assert unavailable_outcome.source == "unavailable"
