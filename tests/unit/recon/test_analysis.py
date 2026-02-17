from __future__ import annotations
import time
from types import MappingProxyType
import pytest
from d810.recon.models import CandidateFlag, DeobfuscationHints, ReconResult
from d810.recon.analysis import AnalysisPhase


def _make_result(collector: str, func_ea: int, maturity: int, metrics: dict,
                 candidates: tuple = ()) -> ReconResult:
    return ReconResult(
        collector_name=collector,
        func_ea=func_ea,
        maturity=maturity,
        timestamp=time.time(),
        metrics=MappingProxyType(metrics),
        candidates=candidates,
    )


class TestAnalysisPhaseOllvmFlat:
    """AnalysisPhase should classify OLLVM flattening when:
    - flattening_score > 0.4  (from CFGShapeCollector)
    - max_in_degree >= 4
    - nway_block_count >= 1 OR back_edge_count >= 2 (from DispatchPatternCollector)
    """
    def test_strong_flattening_signals(self):
        results = [
            _make_result("CFGShapeCollector", 0x401000, 5, {
                "block_count": 30, "edge_count": 45,
                "max_in_degree": 8, "flattening_score": 0.72,
            }, candidates=(
                CandidateFlag("high_indegree_block", 3, 0.9, "8 preds"),
            )),
            _make_result("DispatchPatternCollector", 0x401000, 3, {
                "nway_block_count": 1, "max_nway_fan_out": 6,
                "tway_chain_max_len": 0, "back_edge_count": 4,
                "indirect_jump_count": 0,
            }, candidates=(
                CandidateFlag("switch_dispatcher", 3, 0.8, "NWAY"),
            )),
        ]
        phase = AnalysisPhase()
        hints = phase.interpret(func_ea=0x401000, results=results)
        assert hints.obfuscation_type == "ollvm_flat"
        assert hints.confidence >= 0.6
        assert "unflattening_recipe" in hints.recommended_recipes

    def test_weak_signals_no_classification(self):
        results = [
            _make_result("CFGShapeCollector", 0x401000, 5, {
                "block_count": 5, "edge_count": 4,
                "max_in_degree": 1, "flattening_score": 0.0,
            }),
        ]
        phase = AnalysisPhase()
        hints = phase.interpret(func_ea=0x401000, results=results)
        assert hints.obfuscation_type is None
        assert hints.confidence < 0.3
        assert hints.recommended_recipes == ()

    def test_candidates_forwarded(self):
        flag = CandidateFlag("switch_dispatcher", 3, 0.8, "NWAY")
        results = [
            _make_result("CFGShapeCollector", 0x401000, 5, {
                "block_count": 30, "max_in_degree": 8, "flattening_score": 0.72,
                "edge_count": 45,
            }),
            _make_result("DispatchPatternCollector", 0x401000, 3, {
                "nway_block_count": 1, "max_nway_fan_out": 6,
                "tway_chain_max_len": 0, "back_edge_count": 4,
                "indirect_jump_count": 0,
            }, candidates=(flag,)),
        ]
        phase = AnalysisPhase()
        hints = phase.interpret(func_ea=0x401000, results=results)
        assert len(hints.candidates) >= 1

    def test_empty_results_returns_no_hints(self):
        phase = AnalysisPhase()
        hints = phase.interpret(func_ea=0x401000, results=[])
        assert hints.obfuscation_type is None
        assert hints.func_ea == 0x401000

    def test_suppress_rules_empty_when_no_obfuscation(self):
        phase = AnalysisPhase()
        hints = phase.interpret(func_ea=0x401000, results=[])
        assert hints.suppress_rules == ()


class TestAnalysisPhaseInterpretFromStore:
    def test_interpret_from_store(self, tmp_path):
        from d810.recon.store import ReconStore
        store = ReconStore(tmp_path / "analysis_test.db")
        r1 = _make_result("CFGShapeCollector", 0x401000, 5, {
            "block_count": 30, "edge_count": 45,
            "max_in_degree": 8, "flattening_score": 0.72,
        })
        store.save_recon_result(r1)

        phase = AnalysisPhase()
        hints = phase.interpret_from_store(func_ea=0x401000, store=store)
        assert hints.func_ea == 0x401000
        store.close()
