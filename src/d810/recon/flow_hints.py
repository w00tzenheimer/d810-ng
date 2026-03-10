"""Flow-context hint summary types and derivation.

Consumer-specific summary consumed by :class:`FlowMaturityContext` gates.
Deliberately free of IDA imports so it can be unit-tested standalone.
"""
from __future__ import annotations

from dataclasses import dataclass

from d810.core.gate_modes import GateOperationMode
from d810.core.typing import TYPE_CHECKING

if TYPE_CHECKING:
    from d810.recon.models import DeobfuscationHints

# Obfuscation type values that signal control-flow flattening.
_FLATTENING_TYPES: frozenset[str] = frozenset({
    "ollvm_flat",
    "ollvm_flattening",
    "mixed",
})


@dataclass(frozen=True, slots=True)
class FlowContextHintSummary:
    """Minimal analyzed summary consumed by FlowMaturityContext gates.

    This is a *consumer-specific* projection of the generic
    :class:`DeobfuscationHints` — flow-context only sees what it needs.

    Attributes:
        obfuscation_type: Detected obfuscation family, or ``None``.
        confidence: Overall classification confidence in ``[0.0, 1.0]``.
        has_flattening_signal: Whether the hints indicate control-flow
            flattening is present.
        recommended_gate_mode: Suggested gate operation mode, or ``None``
            if the hints carry no recommendation.
    """

    obfuscation_type: str | None
    confidence: float
    has_flattening_signal: bool
    recommended_gate_mode: GateOperationMode | None


def derive_flow_context_summary(
    hints: DeobfuscationHints,
) -> FlowContextHintSummary:
    """Convert generic :class:`DeobfuscationHints` to a flow-context summary.

    The mapping checks ``obfuscation_type`` for flattening signals and
    derives a ``recommended_gate_mode`` accordingly:

    - Flattening detected with high confidence (>= 0.6) recommends
      ``GATE_SELECT`` (full gate + planner influence).
    - Flattening detected with low confidence recommends ``GATE_ONLY``
      (enforce gates, but don't influence planner).
    - No flattening signal: no recommendation (``None``).

    Args:
        hints: Generic deobfuscation hints from the analysis phase.

    Returns:
        A frozen flow-context-specific summary.

    Example:
        >>> from d810.recon.models import DeobfuscationHints
        >>> hints = DeobfuscationHints(
        ...     func_ea=0x401000,
        ...     obfuscation_type="ollvm_flat",
        ...     confidence=0.9,
        ...     recommended_inferences=(),
        ...     candidates=(),
        ...     suppress_rules=(),
        ... )
        >>> summary = derive_flow_context_summary(hints)
        >>> summary.has_flattening_signal
        True
        >>> summary.recommended_gate_mode
        <GateOperationMode.GATE_SELECT: 'gate_select'>
    """
    has_flattening = (
        hints.obfuscation_type is not None
        and hints.obfuscation_type in _FLATTENING_TYPES
    )

    recommended_mode: GateOperationMode | None = None
    if has_flattening:
        if hints.confidence >= 0.6:
            recommended_mode = GateOperationMode.GATE_SELECT
        else:
            recommended_mode = GateOperationMode.GATE_ONLY

    return FlowContextHintSummary(
        obfuscation_type=hints.obfuscation_type,
        confidence=hints.confidence,
        has_flattening_signal=has_flattening,
        recommended_gate_mode=recommended_mode,
    )
