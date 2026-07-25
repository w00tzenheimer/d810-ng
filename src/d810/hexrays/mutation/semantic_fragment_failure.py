"""Structured failure facts for semantic-fragment publication."""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class MbaSemanticFragmentFailure:
    """One ordered failure fact from a fragment publication transaction."""

    failure_kind: str
    phase: str
    error_type: str
    error_message: str
    interr_code: int | None = None
    verification_context: str = ""

    def __post_init__(self) -> None:
        failure_kind = str(self.failure_kind)
        phase = str(self.phase)
        error_type = str(self.error_type)
        error_message = str(self.error_message)
        verification_context = str(self.verification_context)
        interr_code = None if self.interr_code is None else int(self.interr_code)
        if failure_kind not in {
            "stage",
            "publication",
            "rollback",
            "verifier",
        }:
            raise ValueError("semantic-fragment failure kind is invalid")
        if not phase or not error_type or not error_message:
            raise ValueError(
                "semantic-fragment failure requires phase, type, and message"
            )
        if interr_code is not None and interr_code <= 0:
            raise ValueError("semantic-fragment INTERR code must be positive")
        if verification_context and failure_kind != "verifier":
            raise ValueError("only verifier failures may carry verification context")
        object.__setattr__(self, "failure_kind", failure_kind)
        object.__setattr__(self, "phase", phase)
        object.__setattr__(self, "error_type", error_type)
        object.__setattr__(self, "error_message", error_message)
        object.__setattr__(self, "interr_code", interr_code)
        object.__setattr__(
            self,
            "verification_context",
            verification_context,
        )


__all__ = ["MbaSemanticFragmentFailure"]
