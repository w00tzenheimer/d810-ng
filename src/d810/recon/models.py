"""Core data model for the reconnaissance pipeline.

Immutable value objects passed between ReconPhase, AnalysisPhase, and
RuleScopeService. All public types are frozen dataclasses or NamedTuples.
No IDA imports — this module is unit-testable without IDA.
"""
from __future__ import annotations

from dataclasses import dataclass
from types import MappingProxyType


@dataclass(frozen=True)
class CandidateFlag:
    """A flagged location for potential deeper analysis.

    Attributes:
        kind: Category of the flagged pattern, e.g. ``"flattened_switch"``,
            ``"opaque_predicate"``, ``"mba_expression"``.
        block_serial: Serial number of the flagged basic block within the MBA.
        confidence: Detection confidence in ``[0.0, 1.0]``.
        detail: Human-readable description for diagnostics.

    Example:
        >>> flag = CandidateFlag(kind="flattened_switch", block_serial=3,
        ...                      confidence=0.85, detail="12 predecessors")
        >>> flag.confidence
        0.85
    """
    kind: str
    block_serial: int
    confidence: float
    detail: str

    def __post_init__(self) -> None:
        if not (0.0 <= self.confidence <= 1.0):
            raise ValueError(
                f"CandidateFlag.confidence must be in [0.0, 1.0], got {self.confidence}"
            )


@dataclass(frozen=True)
class ReconResult:
    """Per-collector, per-maturity observation result.

    Produced by a ``ReconCollector.collect()`` call and stored in
    ``ReconStore``. All values are frozen — collectors must not modify
    results after creation.

    Attributes:
        collector_name: Name of the collector that produced this result.
        func_ea: Function effective address.
        maturity: Microcode maturity level at which observation was made.
        timestamp: Wall-clock time of observation (``time.time()``).
        metrics: Read-only mapping of metric name -> scalar value.
        candidates: Tuple of flagged locations within this function.

    Example:
        >>> from types import MappingProxyType
        >>> result = ReconResult(
        ...     collector_name="CFGShapeCollector",
        ...     func_ea=0x401000,
        ...     maturity=5,
        ...     timestamp=0.0,
        ...     metrics=MappingProxyType({"block_count": 20}),
        ...     candidates=(),
        ... )
        >>> result.metrics["block_count"]
        20
    """
    collector_name: str
    func_ea: int
    maturity: int
    timestamp: float
    metrics: MappingProxyType  # type: ignore[type-arg]
    candidates: tuple[CandidateFlag, ...]

    def __post_init__(self) -> None:
        if not isinstance(self.metrics, MappingProxyType):
            raise TypeError(
                f"ReconResult.metrics must be MappingProxyType, got {type(self.metrics)!r}"
            )


@dataclass(frozen=True)
class DeobfuscationHints:
    """Actionable output of the AnalysisPhase.

    Summarises what obfuscation was detected and what the DeobfuscationPhase
    should do about it. Consumed by ``RuleScopeService.apply_hints()``.

    Attributes:
        func_ea: Function effective address these hints apply to.
        obfuscation_type: Detected obfuscation family, or ``None`` if none.
            One of: ``"ollvm_flat"``, ``"tigress_indirect"``, ``"mixed"``,
            ``None``.
        confidence: Overall classification confidence in ``[0.0, 1.0]``.
        recommended_recipes: Tuple of ``RuleRecipeOverlay`` names to activate.
        candidates: Forwarded candidate flags from ReconResults.
        suppress_rules: Rule names to explicitly disable for this function.

    Example:
        >>> hints = DeobfuscationHints(
        ...     func_ea=0x401000,
        ...     obfuscation_type="ollvm_flat",
        ...     confidence=0.85,
        ...     recommended_recipes=("unflattening_recipe",),
        ...     candidates=(),
        ...     suppress_rules=(),
        ... )
        >>> hints.obfuscation_type
        'ollvm_flat'
    """
    func_ea: int
    obfuscation_type: str | None
    confidence: float
    recommended_recipes: tuple[str, ...]
    candidates: tuple[CandidateFlag, ...]
    suppress_rules: tuple[str, ...]
