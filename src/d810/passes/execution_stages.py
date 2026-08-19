"""Stable pass-owned identities for private execution implementations."""

from __future__ import annotations

import re
from dataclasses import dataclass

from d810.core.execution_scope import ExecutionPipeline
from d810.ir.maturity import IRMaturity, IR_MATURITY_ORDER
from d810.passes.constant_simplification_options import StageLifecycleDomain


@dataclass(frozen=True, slots=True)
class ExecutionStageDescriptor:
    """Bind one stable stage identity to a private implementation name."""

    pass_id: str
    stage_id: str
    pipeline: ExecutionPipeline
    implementation_name: str
    lifecycle_domain: StageLifecycleDomain = StageLifecycleDomain.MICROCODE
    supported_maturities: tuple[IRMaturity, ...] = ()

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
    "ExecutionPipeline",
    "ExecutionStageDescriptor",
    "StageLifecycleDomain",
    "canonical_transform_id",
]
