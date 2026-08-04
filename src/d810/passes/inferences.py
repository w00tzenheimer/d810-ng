'Built-in inference factories for the execution inference layer.\n\nAn inference factory translates ``DeobfuscationHints`` into a list of\n``ExecutionAdjustment`` objects that adjust stage behavior for the analyzed function.\n\nDesign rationale\n----------------\nThe naming choice of "inference" reflects that these adjustments are\n*derived from automated preanalysis analysis*, not hand-authored presets.  "Delta" conveys a diff from baseline behavior, not an absolute\nconfiguration.\n\nPrecedence\n----------\nInference deltas are ephemeral (applied per-decompilation).  User\n``per_function_overrides`` and ``whitelisted_functions`` in the project\nJSON config always take precedence.  When a user config overrides an\ninference delta, a WARN log is emitted so the user can understand why\nthe inferred behavior is not taking effect.\n\nSee ``docs/plans/2026-03-09-rule-inference-layer-design.md`` for the\nfull design document.\n'

from __future__ import annotations

from d810.core.execution_scope import ExecutionAdjustment
from d810.core.typing import Any


def unflattening_inference(hints: Any) -> list[ExecutionAdjustment]:
    """Infer execution adjustments for functions with detected control-flow flattening.

    Confidence-gated: suppresses the stable ``constant-folding`` stage at >= 0.7
    because early scalar folding can interfere with dispatcher-state recovery.

    Args:
        hints: ``DeobfuscationHints`` (duck-typed to avoid circular import).

    Returns:
        List of ``ExecutionAdjustment`` objects to apply for this function.
    """
    deltas: list[ExecutionAdjustment] = []
    confidence = getattr(hints, "confidence", 0.0)
    if confidence >= 0.7:
        deltas.append(ExecutionAdjustment("stage", "constant-folding", "suppress"))
    return deltas
