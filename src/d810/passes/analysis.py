"""AnalysisPhase - interprets PreanalysisResult values into hints.

Heuristics are deliberately simple in this first pass. The intent is to
cover the common OLLVM control-flow flattening case and emit inference names
that ``ExecutionScopeService.apply_hints()`` can act on.

Four supplementary collectors—``FixPredSignalsCollector``,
``CompareChainCollector``, ``FlowProfileClassifierCollector``, and
``OpcodeDistributionCollector``—provide *additive* evidence when present.
Their absence does not change the baseline scoring.

No IDA imports - fully unit-testable.
"""

from __future__ import annotations

from d810.core.logging import getLogger
from d810.core.typing import TYPE_CHECKING

from d810.analyses.control_flow.models import (
    CandidateFlag,
    DeobfuscationHints,
    PreanalysisResult,
)

if TYPE_CHECKING:
    from d810.passes.store import PreanalysisStore

logger = getLogger("d810.passes.analysis")


# ---------------------------------------------------------------------------
# Signal weights - tunable without changing test expectations
# ---------------------------------------------------------------------------
_FLAT_SCORE_THRESHOLD = 0.40
_FLAT_INDEGREE_THRESHOLD = 4
_FLAT_BACK_EDGE_THRESHOLD = 2
_FLAT_NWAY_MIN = 1

_CONF_FLAT_BASE = 0.5
_CONF_FLAT_PER_SIGNAL = 0.15
_CONF_CLASSIFY_THRESHOLD = 0.45

# Supplementary collector thresholds (additive signals)
_FIXPRED_MIN_DISPATCHER_PREDS = 3
_COMPARE_CHAIN_MIN_LENGTH = 3
_COMPARE_CHAIN_MIN_CONSTANTS = 4
_FLOW_PROFILE_MIN_CONFIDENCE = 0.4

# The executable early-maturity forward-constants gate belongs to the FCP rule
# itself. Hints stay declarative and persist no flat stage suppression, because
# a flat stage ID cannot express the safe post-unflatten ``MMAT_GLBOPT2``
# boundary.


class AnalysisPhase:
    """Classify obfuscation and produce hints from preanalysis results.

    Usage::

        phase = AnalysisPhase()
        hints = phase.interpret(func_ea=0x401000, results=[r1, r2, r3])
        # or load from store:
        hints = phase.interpret_from_store(func_ea=0x401000, store=store)
    """

    def interpret(
        self,
        *,
        func_ea: int,
        results: list[PreanalysisResult],
        store: PreanalysisStore | None = None,
    ) -> DeobfuscationHints:
        """Classify obfuscation type from a list of preanalysis results.

        When *store* is provided and a user override exists for *func_ea*,
        the override takes precedence over computed classification.
        """
        # --- User override (takes precedence over computed classification) ---
        if store is not None:
            override = store.load_user_override(func_ea)
            if override is not None:
                logger.info(
                    "interpret: func=0x%x user override classification=%s confidence=%.2f",
                    func_ea,
                    override["override_value"],
                    override["confidence"],
                )
                inferences: tuple[str, ...] = ()
                suppress: tuple[str, ...] = ()
                if override["override_value"] == "ollvm_flat":
                    inferences = ("unflattening",)
                return DeobfuscationHints(
                    func_ea=func_ea,
                    obfuscation_type=override["override_value"],
                    confidence=override["confidence"],
                    recommended_inferences=inferences,
                    candidates=(),
                    suppress_stages=suppress,
                )

        if not results:
            return DeobfuscationHints(
                func_ea=func_ea,
                obfuscation_type=None,
                confidence=0.0,
                recommended_inferences=(),
                candidates=(),
                suppress_stages=(),
            )

        # Aggregate metrics by collector
        by_collector: dict[str, dict] = {}
        all_candidates: list[CandidateFlag] = []
        for r in results:
            by_collector[r.collector_name] = dict(r.metrics)
            all_candidates.extend(r.candidates)

        # --- OLLVM flattening heuristic (core signals) ---
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

        # --- Supplementary signals (additive when collectors present) ---
        fixpred = by_collector.get("FixPredSignalsCollector", {})
        compare = by_collector.get("compare_chain", {})
        flow_profile = by_collector.get("flow_profile_classifier", {})

        if (
            fixpred
            and any(c.kind == "fixpred_high_fanin_dispatcher" for c in all_candidates)
            and int(fixpred.get("max_dispatcher_predecessors", 0))
            >= _FIXPRED_MIN_DISPATCHER_PREDS
        ):
            flat_signals += 1

        if (
            compare
            and int(compare.get("compare_chain_length", 0)) >= _COMPARE_CHAIN_MIN_LENGTH
            and int(compare.get("unique_constants", 0)) >= _COMPARE_CHAIN_MIN_CONSTANTS
        ):
            flat_signals += 1

        if (
            flow_profile
            and float(flow_profile.get("classification_confidence", 0.0))
            >= _FLOW_PROFILE_MIN_CONFIDENCE
        ):
            flat_signals += 1

        # --- OpcodeDistribution (supplementary) ---
        opcode_results = by_collector.get("OpcodeDistributionCollector", {})
        if (
            opcode_results
            and any(c.kind == "high_opcode_dominance" for c in all_candidates)
            and float(opcode_results.get("top_opcode_ratio", 0)) > 0.5
        ):
            flat_signals += 1

        # --- Confidence calculation ---
        confidence = (
            _CONF_FLAT_BASE + flat_signals * _CONF_FLAT_PER_SIGNAL
            if flat_signals >= 2
            else flat_signals * _CONF_FLAT_PER_SIGNAL
        )

        if confidence >= _CONF_CLASSIFY_THRESHOLD:
            obfuscation_type: str | None = "ollvm_flat"
            recommended_inferences: tuple[str, ...] = ("unflattening",)
            # FCP applies its own early-maturity safety gate. Keep this
            # persisted hint free of flat stage suppressions so the recovered
            # GLBOPT2 pass can still run.
            suppress_stages: tuple[str, ...] = ()
        else:
            obfuscation_type = None
            recommended_inferences = ()
            suppress_stages = ()

        return DeobfuscationHints(
            func_ea=func_ea,
            obfuscation_type=obfuscation_type,
            confidence=min(1.0, confidence),
            recommended_inferences=recommended_inferences,
            candidates=tuple(all_candidates),
            suppress_stages=suppress_stages,
        )

    def interpret_from_store(
        self, *, func_ea: int, store: PreanalysisStore
    ) -> DeobfuscationHints:
        """Load all preanalysis results from the store and interpret them."""
        results = store.load_all_preanalysis_results(func_ea=func_ea)
        return self.interpret(func_ea=func_ea, results=results, store=store)
