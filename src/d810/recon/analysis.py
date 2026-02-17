"""AnalysisPhase — interprets ReconResults into DeobfuscationHints.

Heuristics are deliberately simple in this first pass. The intent is to
cover the common OLLVM control-flow flattening case and emit recipe names
that ``RuleScopeService.apply_hints()`` can act on.

No IDA imports — fully unit-testable.
"""
from __future__ import annotations

from d810.recon.models import CandidateFlag, DeobfuscationHints, ReconResult
from d810.recon.store import ReconStore


# ---------------------------------------------------------------------------
# Signal weights — tunable without changing test expectations
# ---------------------------------------------------------------------------
_FLAT_SCORE_THRESHOLD = 0.40
_FLAT_INDEGREE_THRESHOLD = 4
_FLAT_BACK_EDGE_THRESHOLD = 2
_FLAT_NWAY_MIN = 1

_CONF_FLAT_BASE = 0.5
_CONF_FLAT_PER_SIGNAL = 0.15
_CONF_CLASSIFY_THRESHOLD = 0.45


class AnalysisPhase:
    """Classify obfuscation and produce DeobfuscationHints from ReconResults.

    Usage::

        phase = AnalysisPhase()
        hints = phase.interpret(func_ea=0x401000, results=[r1, r2, r3])
        # or load from store:
        hints = phase.interpret_from_store(func_ea=0x401000, store=store)
    """

    def interpret(
        self, *, func_ea: int, results: list[ReconResult]
    ) -> DeobfuscationHints:
        """Classify obfuscation type from a list of ReconResults."""
        if not results:
            return DeobfuscationHints(
                func_ea=func_ea,
                obfuscation_type=None,
                confidence=0.0,
                recommended_recipes=(),
                candidates=(),
                suppress_rules=(),
            )

        # Aggregate metrics by collector
        by_collector: dict[str, dict] = {}
        all_candidates: list[CandidateFlag] = []
        for r in results:
            by_collector[r.collector_name] = dict(r.metrics)
            all_candidates.extend(r.candidates)

        # --- OLLVM flattening heuristic ---
        flat_signals = 0
        cfg = by_collector.get("CFGShapeCollector", {})
        dispatch = by_collector.get("DispatchPatternCollector", {})

        if float(cfg.get("flattening_score", 0.0)) >= _FLAT_SCORE_THRESHOLD:
            flat_signals += 1
        if int(cfg.get("max_in_degree", 0)) >= _FLAT_INDEGREE_THRESHOLD:
            flat_signals += 1
        if int(dispatch.get("nway_block_count", 0)) >= _FLAT_NWAY_MIN:
            flat_signals += 1
        if int(dispatch.get("back_edge_count", 0)) >= _FLAT_BACK_EDGE_THRESHOLD:
            flat_signals += 1

        confidence = (
            _CONF_FLAT_BASE + flat_signals * _CONF_FLAT_PER_SIGNAL
            if flat_signals >= 2
            else flat_signals * _CONF_FLAT_PER_SIGNAL
        )

        if confidence >= _CONF_CLASSIFY_THRESHOLD:
            obfuscation_type: str | None = "ollvm_flat"
            recommended_recipes: tuple[str, ...] = ("unflattening_recipe",)
            suppress_rules: tuple[str, ...] = ()
        else:
            obfuscation_type = None
            recommended_recipes = ()
            suppress_rules = ()

        return DeobfuscationHints(
            func_ea=func_ea,
            obfuscation_type=obfuscation_type,
            confidence=min(1.0, confidence),
            recommended_recipes=recommended_recipes,
            candidates=tuple(all_candidates),
            suppress_rules=suppress_rules,
        )

    def interpret_from_store(
        self, *, func_ea: int, store: ReconStore
    ) -> DeobfuscationHints:
        """Load all ReconResults from the store and interpret them."""
        results = store.load_all_recon_results(func_ea=func_ea)
        return self.interpret(func_ea=func_ea, results=results)
