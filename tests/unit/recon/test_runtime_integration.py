"""Unit tests for ReconAnalysisRuntime.apply_to_rule_scope lifecycle."""
from __future__ import annotations

from types import MappingProxyType
from unittest.mock import MagicMock, create_autospec

from d810.core.rule_scope import ApplyHintsResult, RuleScopeService
from d810.recon.analysis import AnalysisPhase
from d810.recon.models import DeobfuscationHints, ReconResult
from d810.recon.phase import ReconPhase
from d810.recon.runtime import ReconAnalysisRuntime, ReconOutcome
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


def test_apply_to_rule_scope_fresh_analysis() -> None:
    """No cached hints -> runs full pipeline (collect, analyze, apply)."""
    rt, mock_phase, mock_analysis, mock_store = _make_runtime()
    mock_rule_scope = create_autospec(RuleScopeService, instance=True)

    results = [_make_recon_result()]
    hints = _make_hints()
    apply_result = _make_apply_result()

    mock_store.load_hints.return_value = None
    mock_phase.run_microcode_collectors.return_value = results
    mock_analysis.interpret.return_value = hints
    mock_rule_scope.apply_hints.return_value = apply_result

    outcome = rt.apply_to_rule_scope(
        _FUNC_EA, mock_rule_scope,
        target=_SENTINEL_TARGET, maturity=_MATURITY,
        persist_hints=True,
    )

    assert outcome.func_ea == _FUNC_EA
    assert outcome.hints is hints
    assert outcome.apply_result is apply_result
    assert outcome.source == "analyzed"

    # Verify full pipeline ran
    mock_store.load_hints.assert_called_once_with(func_ea=_FUNC_EA)
    mock_phase.run_microcode_collectors.assert_called_once_with(
        _SENTINEL_TARGET, func_ea=_FUNC_EA, maturity=_MATURITY,
    )
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

    outcome = rt.apply_to_rule_scope(
        _FUNC_EA, mock_rule_scope,
        target=_SENTINEL_TARGET, maturity=_MATURITY,
    )

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

    outcome = rt.apply_to_rule_scope(
        _FUNC_EA, mock_rule_scope,
        target=None, maturity=None,
    )

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

    cached_outcome = rt.apply_to_rule_scope(
        _FUNC_EA, mock_rule_scope, target=None, maturity=None,
    )
    assert cached_outcome.source == "cached"

    # --- "analyzed" ---
    mock_store.load_hints.return_value = None
    mock_phase.run_microcode_collectors.return_value = [_make_recon_result()]
    mock_analysis.interpret.return_value = hints
    mock_rule_scope.apply_hints.return_value = apply_result

    analyzed_outcome = rt.apply_to_rule_scope(
        _FUNC_EA, mock_rule_scope,
        target=_SENTINEL_TARGET, maturity=_MATURITY,
    )
    assert analyzed_outcome.source == "analyzed"

    # --- "unavailable" ---
    mock_store.load_hints.return_value = None

    unavailable_outcome = rt.apply_to_rule_scope(
        _FUNC_EA, mock_rule_scope, target=None, maturity=None,
    )
    assert unavailable_outcome.source == "unavailable"
