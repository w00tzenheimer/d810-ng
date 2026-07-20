"Core data model for the reconnaissance pipeline.\n\nImmutable value objects passed between PreanalysisPhase, AnalysisPhase, and\nRuleScopeService. All public types are frozen dataclasses or NamedTuples.\nNo IDA imports - this module is unit-testable without IDA.\n"
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


@dataclass(frozen=True, init=False)
class PreanalysisResult:
    "Per-collector, per-maturity observation result.\n\n    Produced by a ``PreanalysisCollector.collect()`` call and stored in\n    ``PreanalysisStore``. All values are frozen - collectors must not modify\n    results after creation.\n\n    Attributes:\n        collector_name: Name of the collector that produced this result.\n        func_ea: Function effective address.\n        maturity: Microcode maturity level at which observation was made.\n        timestamp: Wall-clock time of observation (``time.time()``).\n        metrics: Read-only mapping of metric name -> scalar value.\n        candidates: Tuple of flagged locations within this function.\n\n    Example:\n        >>> from types import MappingProxyType\n        >>> result = PreanalysisResult(\n        ...     collector_name=\"CFGShapeCollector\",\n        ...     func_ea=0x401000,\n        ...     maturity=5,\n        ...     timestamp=0.0,\n        ...     metrics=MappingProxyType({\"block_count\": 20}),\n        ...     candidates=(),\n        ... )\n        >>> result.metrics[\"block_count\"]\n        20\n    "
    collector_name: str
    func_ea: int
    provider_level: int
    timestamp: float
    metrics: MappingProxyType  # type: ignore[type-arg]
    candidates: tuple[CandidateFlag, ...]

    def __init__(
        self,
        *,
        collector_name: str,
        func_ea: int,
        timestamp: float,
        metrics: MappingProxyType,  # type: ignore[type-arg]
        candidates: tuple[CandidateFlag, ...],
        provider_level: int | None = None,
        **legacy_fields: object,
    ) -> None:
        legacy_level = legacy_fields.pop("maturity", None)
        if legacy_fields:
            names = ", ".join(sorted(legacy_fields))
            raise TypeError(f"Unexpected PreanalysisResult field(s): {names}")
        if provider_level is None:
            if legacy_level is None:
                raise TypeError("provider_level is required")
            provider_level = int(legacy_level)
        object.__setattr__(self, "collector_name", collector_name)
        object.__setattr__(self, "func_ea", int(func_ea))
        object.__setattr__(self, "provider_level", int(provider_level))
        object.__setattr__(self, "timestamp", float(timestamp))
        object.__setattr__(self, "metrics", metrics)
        object.__setattr__(self, "candidates", candidates)
        self.__post_init__()

    def __post_init__(self) -> None:
        if not (hasattr(self.metrics, '__getitem__') and not hasattr(self.metrics, '__setitem__')):
            raise TypeError(
                f"PreanalysisResult.metrics must be a read-only mapping, got {type(self.metrics)!r}"
            )

    @property
    def maturity(self) -> int:
        return int(self.provider_level)


@dataclass(frozen=True)
class DeobfuscationHints:
    "Actionable output of the AnalysisPhase.\n\n    Summarises what obfuscation was detected and what the DeobfuscationPhase\n    should do about it. Consumed by ``RuleScopeService.apply_hints()``.\n\n    Attributes:\n        func_ea: Function effective address these hints apply to.\n        obfuscation_type: Detected obfuscation family, or ``None`` if none.\n            One of: ``\"ollvm_flat\"``, ``\"tigress_indirect\"``, ``\"mixed\"``,\n            ``None``.\n        confidence: Overall classification confidence in ``[0.0, 1.0]``.\n        recommended_inferences: Tuple of inference names to activate.\n        candidates: Forwarded candidate flags from PreanalysisResults.\n        suppress_rules: Rule names to explicitly disable for this function.\n\n    Example:\n        >>> hints = DeobfuscationHints(\n        ...     func_ea=0x401000,\n        ...     obfuscation_type=\"ollvm_flat\",\n        ...     confidence=0.85,\n        ...     recommended_inferences=(\"unflattening\",),\n        ...     candidates=(),\n        ...     suppress_rules=(),\n        ... )\n        >>> hints.obfuscation_type\n        'ollvm_flat'\n    "
    func_ea: int
    obfuscation_type: str | None
    confidence: float
    recommended_inferences: tuple[str, ...]
    candidates: tuple[CandidateFlag, ...]
    suppress_rules: tuple[str, ...]
