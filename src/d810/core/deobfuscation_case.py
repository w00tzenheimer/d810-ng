"""Portable evidence for building and validating a deobfuscation strategy.

The records in this module deliberately describe *what is known* about a
function without depending on a UI, diagnostic database implementation, or a
live Hex-Rays object.  C0 through C5 describe progress/evidence only; semantic
success requires a C6 verdict with an explicit witness.
"""
from __future__ import annotations

import dataclasses
import enum

__all__ = [
    "CaseEvidenceLevel",
    "CaseExecution",
    "CaseFinding",
    "CaseFindingKind",
    "CaseHypothesis",
    "CaseVerdict",
    "DeobfuscationCaseEvidence",
    "DeobfuscationCaseSnapshot",
    "StrategyDeficiency",
    "StrategyRecommendation",
    "StrategyWorkflowStage",
]


class CaseEvidenceLevel(str, enum.Enum):
    """The strongest evidence level currently recorded for one function."""

    C0_ENVIRONMENT = "c0_environment"
    C1_DISCOVERY = "c1_discovery"
    C2_NORMALIZATION = "c2_normalization"
    C3_CANONICAL_PLAN = "c3_canonical_plan"
    C4_STAGED_PROOF = "c4_staged_proof"
    C5_PUBLICATION = "c5_publication"
    C6_SEMANTIC_OUTPUT = "c6_semantic_output"


class CaseFindingKind(str, enum.Enum):
    """A fact's role in the observation-to-verdict lifecycle."""

    OBSERVATION = "observation"
    HYPOTHESIS = "hypothesis"
    VALIDATION = "validation"
    PORTABLE_EVIDENCE = "portable_evidence"
    PASS_DECISION = "pass_decision"
    FRAGMENT_PLAN = "fragment_plan"
    RECEIPT = "receipt"
    SEMANTIC_RESULT = "semantic_result"
    UNRESOLVED_QUESTION = "unresolved_question"
    REJECTION = "rejection"


class StrategyWorkflowStage(str, enum.Enum):
    """Registered-pipeline stage metadata; never an execution scheduler."""

    EVIDENCE_PROVIDER = "evidence_provider"
    FRONTEND_NORMALIZATION = "frontend_normalization"
    CANONICAL_ANALYSIS = "canonical_analysis"
    CANONICAL_TRANSFORM = "canonical_transform"
    BACKEND_PUBLICATION = "backend_publication"
    CANONICAL_PIPELINE = "canonical_pipeline"


class StrategyDeficiency(str, enum.Enum):
    """The smallest missing capability a strategy must address."""

    NATIVE_EVIDENCE = "native_evidence"
    CFG_FORMATION = "cfg_formation"
    FRONTEND_NORMALIZATION = "frontend_normalization"
    CANONICAL_ANALYSIS = "canonical_analysis"
    CANONICAL_TRANSFORM = "canonical_transform"
    BACKEND_PUBLICATION = "backend_publication"
    SEMANTIC_VERIFICATION = "semantic_verification"


_ANCHOR_REQUIRED_KINDS = frozenset(
    {
        CaseFindingKind.PORTABLE_EVIDENCE,
        CaseFindingKind.FRAGMENT_PLAN,
        CaseFindingKind.RECEIPT,
        CaseFindingKind.SEMANTIC_RESULT,
    }
)


def _require_text(value: str, field_name: str) -> None:
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"{field_name} must be non-empty")


def _require_unique(values: tuple[str, ...], field_name: str) -> None:
    if any(not isinstance(value, str) or not value.strip() for value in values):
        raise ValueError(f"{field_name} must contain only non-empty identifiers")
    if len(set(values)) != len(values):
        raise ValueError(f"{field_name} must not contain duplicates")


@dataclasses.dataclass(frozen=True, slots=True)
class CaseFinding:
    """One anchored or explicitly unanchored piece of case evidence."""

    finding_id: str
    kind: CaseFindingKind
    summary: str
    detail: str
    native_ea: int | None
    confidence: float | None
    provenance: tuple[str, ...]

    def __post_init__(self) -> None:
        _require_text(self.finding_id, "finding_id")
        _require_text(self.summary, "summary")
        if not isinstance(self.kind, CaseFindingKind):
            raise ValueError("kind must be a CaseFindingKind")
        if self.kind in _ANCHOR_REQUIRED_KINDS and self.native_ea is None:
            raise ValueError("native anchor is required for this finding")
        if self.native_ea is not None and self.native_ea < 0:
            raise ValueError("native_ea must be non-negative")
        if self.confidence is not None and not 0.0 <= self.confidence <= 1.0:
            raise ValueError("confidence must be between 0.0 and 1.0")
        if not self.provenance:
            raise ValueError("provenance must not be empty")
        _require_unique(self.provenance, "provenance")


@dataclasses.dataclass(frozen=True, slots=True)
class CaseHypothesis:
    """A competing explanation that evidence may validate or reject."""

    hypothesis_id: str
    summary: str
    supporting_finding_ids: tuple[str, ...]
    competing_hypothesis_ids: tuple[str, ...] = ()
    validated: bool | None = None

    def __post_init__(self) -> None:
        _require_text(self.hypothesis_id, "hypothesis_id")
        _require_text(self.summary, "summary")
        _require_unique(self.supporting_finding_ids, "supporting_finding_ids")
        _require_unique(self.competing_hypothesis_ids, "competing_hypothesis_ids")
        if self.hypothesis_id in self.competing_hypothesis_ids:
            raise ValueError("a hypothesis cannot compete with itself")


@dataclasses.dataclass(frozen=True, slots=True)
class StrategyRecommendation:
    """A capability-level recommendation grounded in named evidence."""

    deficiency: StrategyDeficiency
    summary: str
    required_finding_ids: tuple[str, ...]
    stages: tuple[StrategyWorkflowStage, ...]

    def __post_init__(self) -> None:
        if not isinstance(self.deficiency, StrategyDeficiency):
            raise ValueError("deficiency must be a StrategyDeficiency")
        _require_text(self.summary, "summary")
        _require_unique(self.required_finding_ids, "required_finding_ids")
        if not self.stages:
            raise ValueError("stages must not be empty")
        if any(not isinstance(stage, StrategyWorkflowStage) for stage in self.stages):
            raise ValueError("stages must contain only StrategyWorkflowStage values")


@dataclasses.dataclass(frozen=True, slots=True)
class CaseExecution:
    """The identity and outcome of one build or direct-run command."""

    run_identity: str
    command_id: str
    generation: int
    accepted: bool
    summary: str

    def __post_init__(self) -> None:
        _require_text(self.run_identity, "run_identity")
        _require_text(self.command_id, "command_id")
        _require_text(self.summary, "summary")
        if self.generation < 0:
            raise ValueError("generation must be non-negative")


@dataclasses.dataclass(frozen=True, slots=True)
class CaseVerdict:
    """The current result without conflating intermediate progress with success."""

    level: CaseEvidenceLevel
    summary: str
    first_blocked_obligation: str | None
    semantic_witness: str | None = None

    def __post_init__(self) -> None:
        if not isinstance(self.level, CaseEvidenceLevel):
            raise ValueError("level must be a CaseEvidenceLevel")
        _require_text(self.summary, "summary")
        if self.first_blocked_obligation is not None:
            _require_text(self.first_blocked_obligation, "first_blocked_obligation")
        if self.semantic_witness is not None:
            _require_text(self.semantic_witness, "semantic_witness")
        if (
            self.level is CaseEvidenceLevel.C6_SEMANTIC_OUTPUT
            and self.semantic_witness is None
        ):
            raise ValueError("semantic witness is required for C6")
        if (
            self.level is not CaseEvidenceLevel.C6_SEMANTIC_OUTPUT
            and self.semantic_witness is not None
        ):
            raise ValueError("semantic witness is only valid for C6")

    @property
    def semantic_verified(self) -> bool:
        return (
            self.level is CaseEvidenceLevel.C6_SEMANTIC_OUTPUT
            and self.semantic_witness is not None
        )


@dataclasses.dataclass(frozen=True, slots=True)
class DeobfuscationCaseEvidence:
    """Ordered portable evidence emitted for one function/runtime/run identity."""

    schema_version: int
    function_fingerprint: str
    runtime_identity: str
    run_identity: str
    findings: tuple[CaseFinding, ...]
    verdict: CaseVerdict

    def __post_init__(self) -> None:
        if self.schema_version < 1:
            raise ValueError("schema_version must be positive")
        _require_text(self.function_fingerprint, "function_fingerprint")
        _require_text(self.runtime_identity, "runtime_identity")
        _require_text(self.run_identity, "run_identity")
        if not isinstance(self.verdict, CaseVerdict):
            raise ValueError("verdict must be a CaseVerdict")
        if any(not isinstance(finding, CaseFinding) for finding in self.findings):
            raise ValueError("findings must contain only CaseFinding values")
        finding_ids = tuple(finding.finding_id for finding in self.findings)
        if len(set(finding_ids)) != len(finding_ids):
            raise ValueError("duplicate finding identifiers are not allowed")


@dataclasses.dataclass(frozen=True, slots=True)
class DeobfuscationCaseSnapshot:
    """The current evidence and safe execution decision for a Workbench view."""

    evidence: DeobfuscationCaseEvidence | None
    strategy: StrategyRecommendation | None
    direct_run_permitted: bool
    direct_run_reason: str

    def __post_init__(self) -> None:
        if self.evidence is not None and not isinstance(
            self.evidence, DeobfuscationCaseEvidence
        ):
            raise ValueError("evidence must be DeobfuscationCaseEvidence or None")
        if self.strategy is not None and not isinstance(
            self.strategy, StrategyRecommendation
        ):
            raise ValueError("strategy must be StrategyRecommendation or None")
        _require_text(self.direct_run_reason, "direct_run_reason")
