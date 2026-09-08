"""Stable pass-owned identities for private execution implementations."""

from __future__ import annotations

import enum
import re
from dataclasses import dataclass, field

from d810.core.execution_scope import ExecutionPipeline
from d810.ir.maturity import IRMaturity, IR_MATURITY_ORDER


class StageLifecycleDomain(str, enum.Enum):
    """Lifecycle authority that owns one compiled execution stage."""

    PRE_HEXRAYS = "pre_hexrays"
    MICROCODE = "microcode"


class ExecutionOwnership(str, enum.Enum):
    """Component that owns the execution of one public stage."""

    D810_OWNED = "d810_owned"
    HEXRAYS_HOSTED = "hexrays_hosted"


class ExecutionHost(str, enum.Enum):
    """Callback or pipeline host responsible for invoking one stage."""

    D810_PIPELINE = "d810_pipeline"
    HEXRAYS_OPTINSN = "hexrays_optinsn"
    HEXRAYS_OPTBLOCK = "hexrays_optblock"
    HEXRAYS_CTREE = "hexrays_ctree"


class IRScope(str, enum.Enum):
    """Intermediate-representation scope consumed by one execution stage."""

    EXPRESSION = "expression"
    INSTRUCTION = "instruction"
    BLOCK = "block"
    FUNCTION = "function"


_LEGACY_PROJECTION = {
    ExecutionPipeline.INSTRUCTION: (
        ExecutionOwnership.HEXRAYS_HOSTED,
        ExecutionHost.HEXRAYS_OPTINSN,
        IRScope.INSTRUCTION,
    ),
    ExecutionPipeline.FLOW: (
        ExecutionOwnership.HEXRAYS_HOSTED,
        ExecutionHost.HEXRAYS_OPTBLOCK,
        IRScope.BLOCK,
    ),
    ExecutionPipeline.CTREE: (
        ExecutionOwnership.HEXRAYS_HOSTED,
        ExecutionHost.HEXRAYS_CTREE,
        IRScope.FUNCTION,
    ),
}

# D-810-owned stages retain the old lane for compatibility while their IR
# scope is independent of the Hex-Rays callback that may provide a safe point.
# The broad mapping keeps all four IR scopes representable without assigning
# D-810-owned work to a Hex-Rays host.
_PIPELINE_FOR_HOST_SCOPE = {
    (ExecutionHost.D810_PIPELINE, IRScope.EXPRESSION): ExecutionPipeline.INSTRUCTION,
    (ExecutionHost.D810_PIPELINE, IRScope.INSTRUCTION): ExecutionPipeline.INSTRUCTION,
    (ExecutionHost.D810_PIPELINE, IRScope.BLOCK): ExecutionPipeline.FLOW,
    (ExecutionHost.D810_PIPELINE, IRScope.FUNCTION): ExecutionPipeline.FLOW,
    (ExecutionHost.HEXRAYS_OPTINSN, IRScope.INSTRUCTION): ExecutionPipeline.INSTRUCTION,
    (ExecutionHost.HEXRAYS_OPTBLOCK, IRScope.BLOCK): ExecutionPipeline.FLOW,
    (ExecutionHost.HEXRAYS_CTREE, IRScope.FUNCTION): ExecutionPipeline.CTREE,
}


@dataclass(frozen=True, slots=True)
class ExecutionStageDescriptor:
    """Bind one stable stage identity to a private implementation name."""

    pass_id: str
    stage_id: str
    pipeline: ExecutionPipeline
    implementation_name: str
    lifecycle_domain: StageLifecycleDomain = StageLifecycleDomain.MICROCODE
    supported_maturities: tuple[IRMaturity, ...] = ()
    ownership: ExecutionOwnership | None = field(default=None, kw_only=True)
    host: ExecutionHost | None = field(default=None, kw_only=True)
    scope: IRScope | None = field(default=None, kw_only=True)

    def __post_init__(self) -> None:
        for field_name in ("pass_id", "stage_id", "implementation_name"):
            value = getattr(self, field_name)
            if not isinstance(value, str) or not value.strip():
                raise ValueError(f"{field_name} must be a non-empty string")
            if value != value.strip():
                raise ValueError(f"{field_name} must not contain outer whitespace")
        if not isinstance(self.pipeline, ExecutionPipeline):
            raise TypeError("pipeline must be an ExecutionPipeline")
        if not isinstance(self.lifecycle_domain, StageLifecycleDomain):
            raise TypeError("lifecycle_domain must be a StageLifecycleDomain")
        if not isinstance(self.supported_maturities, tuple):
            raise TypeError("supported_maturities must be a tuple")
        if any(not isinstance(value, IRMaturity) for value in self.supported_maturities):
            raise TypeError("supported_maturities must contain IRMaturity values")
        if len(set(self.supported_maturities)) != len(self.supported_maturities):
            raise ValueError("supported_maturities must not contain duplicates")
        if self.supported_maturities != tuple(
            maturity
            for maturity in IR_MATURITY_ORDER
            if maturity in self.supported_maturities
        ):
            raise ValueError("supported_maturities must follow IR_MATURITY_ORDER")

        default_ownership, default_host, default_scope = _LEGACY_PROJECTION[
            self.pipeline
        ]
        ownership = self.ownership if self.ownership is not None else default_ownership
        host = self.host if self.host is not None else default_host
        scope = self.scope if self.scope is not None else default_scope
        for field_name, value, enum_type in (
            ("ownership", ownership, ExecutionOwnership),
            ("host", host, ExecutionHost),
            ("scope", scope, IRScope),
        ):
            if not isinstance(value, enum_type):
                raise TypeError(f"{field_name} must be a typed {enum_type.__name__}")

        expected_ownership = (
            ExecutionOwnership.D810_OWNED
            if host is ExecutionHost.D810_PIPELINE
            else ExecutionOwnership.HEXRAYS_HOSTED
        )
        if ownership is not expected_ownership:
            raise ValueError(
                f"{host.value} requires {expected_ownership.value} ownership"
            )
        expected_pipeline = _PIPELINE_FOR_HOST_SCOPE.get((host, scope))
        if expected_pipeline is None:
            raise ValueError(
                f"execution host {host.value} cannot consume {scope.value} scope"
            )
        if self.pipeline is not expected_pipeline:
            raise ValueError(
                f"pipeline {self.pipeline.value} is incoherent with "
                f"{host.value}/{scope.value}; expected {expected_pipeline.value}"
            )
        object.__setattr__(self, "ownership", ownership)
        object.__setattr__(self, "host", host)
        object.__setattr__(self, "scope", scope)


def canonical_transform_id(implementation_name: str) -> str:
    """Normalize a private Python implementation name to a stable public ID."""

    if not isinstance(implementation_name, str) or not implementation_name.strip():
        raise ValueError("implementation_name must be a non-empty string")
    split_acronyms = re.sub(
        r"([A-Z]+)([A-Z][a-z])",
        r"\1-\2",
        implementation_name.strip(),
    )
    split_words = re.sub(r"([a-z0-9])([A-Z])", r"\1-\2", split_acronyms)
    raw_tokens = re.findall(r"[A-Za-z]+|[0-9]+", split_words)
    tokens: list[str] = []
    for token in raw_tokens:
        normalized = token.lower()
        rule_match = re.fullmatch(r"rule([0-9]*)", normalized)
        if rule_match is not None:
            if rule_match.group(1):
                tokens.append(rule_match.group(1))
            continue
        tokens.append(normalized)
    public_id = "-".join(tokens)
    if not public_id:
        raise ValueError("implementation_name does not produce a public transform id")
    return public_id


__all__ = [
    "ExecutionHost",
    "ExecutionOwnership",
    "ExecutionPipeline",
    "ExecutionStageDescriptor",
    "IRScope",
    "StageLifecycleDomain",
    "canonical_transform_id",
]
