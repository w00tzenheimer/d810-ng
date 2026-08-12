'Built-in inference factories for the execution inference layer.\n\nAn inference factory translates ``DeobfuscationHints`` into a list of\n``ExecutionAdjustment`` objects that adjust stage behavior for the analyzed function.\n\nDesign rationale\n----------------\nThe naming choice of "inference" reflects that these adjustments are\n*derived from automated preanalysis analysis*, not hand-authored presets.  "Delta" conveys a diff from baseline behavior, not an absolute\nconfiguration.\n\nPrecedence\n----------\nInference deltas are ephemeral (applied per-decompilation).  User\n``per_function_overrides`` and ``whitelisted_functions`` in the project\nJSON config always take precedence.  When a user config overrides an\ninference delta, a WARN log is emitted so the user can understand why\nthe inferred behavior is not taking effect.\n\nSee ``docs/plans/2026-03-09-rule-inference-layer-design.md`` for the\nfull design document.\n'

from __future__ import annotations

from d810.core.execution_scope import ExecutionAdjustment
from d810.core.typing import Any


def unflattening_inference(hints: Any) -> list[ExecutionAdjustment]:
    """Retain the public inference name without duplicating FCP's safety gate.

    ``ForwardConstantPropagationRule`` owns its narrow MMAT_CALLS dispatcher
    guard. Config-v2 native state-machine projects schedule that rule only at
    MMAT_GLBOPT2. An execution-scope suppression here would therefore be a
    redundant second policy and can accidentally suppress post-unflatten FCP.

    Args:
        hints: ``DeobfuscationHints`` (duck-typed to avoid circular import).

    Returns:
        No adjustments. The name remains registered for persisted hints and
        execution diagnostics.
    """
    del hints
    return []
