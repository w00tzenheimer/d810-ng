"""Stable pass-owned identities for private execution implementations."""

from __future__ import annotations

import re
from dataclasses import dataclass

from d810.core.execution_scope import ExecutionPipeline


@dataclass(frozen=True, slots=True)
class ExecutionStageDescriptor:
    """Bind one stable stage identity to a private implementation name."""

    pass_id: str
    stage_id: str
    pipeline: ExecutionPipeline
    implementation_name: str

    def __post_init__(self) -> None:
        for field_name in ("pass_id", "stage_id", "implementation_name"):
            value = getattr(self, field_name)
            if not isinstance(value, str) or not value.strip():
                raise ValueError(f"{field_name} must be a non-empty string")
            if value != value.strip():
                raise ValueError(f"{field_name} must not contain outer whitespace")
        if not isinstance(self.pipeline, ExecutionPipeline):
            raise TypeError("pipeline must be an ExecutionPipeline")


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
    "canonical_transform_id",
]
