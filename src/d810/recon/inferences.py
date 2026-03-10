"""Built-in inference factories for the rule inference layer.

An inference factory translates ``DeobfuscationHints`` into a list of
``RuleDelta`` objects that adjust rule behavior for the analyzed function.

Design rationale
----------------
The naming choice of "inference" reflects that these adjustments are
*derived from automated recon analysis*, not hand-authored presets.  "Delta" conveys a diff from baseline behavior, not an absolute
configuration.

Precedence
----------
Inference deltas are ephemeral (applied per-decompilation).  User
``per_function_overrides`` and ``whitelisted_functions`` in the project
JSON config always take precedence.  When a user config overrides an
inference delta, a WARN log is emitted so the user can understand why
the inferred behavior is not taking effect.

See ``docs/plans/2026-03-09-rule-inference-layer-design.md`` for the
full design document.
"""
from __future__ import annotations

from d810.core.rule_scope import RuleDelta
from d810.core.typing import Any


def unflattening_inference(hints: Any) -> list[RuleDelta]:
    """Infer rule deltas for functions with detected control-flow flattening.

    Confidence-gated: only suppresses ``ConstantFolding`` at >= 0.7
    confidence because constant folding interferes with dispatcher state
    resolution during unflattening.

    Args:
        hints: ``DeobfuscationHints`` (duck-typed to avoid circular import).

    Returns:
        List of ``RuleDelta`` objects to apply for this function.
    """
    deltas: list[RuleDelta] = []
    confidence = getattr(hints, "confidence", 0.0)
    if confidence >= 0.7:
        deltas.append(RuleDelta("ConstantFolding", "suppress", {}))
    return deltas
