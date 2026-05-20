"""Return-frontier artifact evidence labels owned by recon.

These labels are not core policy and are not general return-frontier taxonomy.
They describe a narrow recon proof: a return-frontier writer is not a recoverable
return carrier, but it is still topology-sensitive and must be protected from
blind graph rewrites.
"""
from __future__ import annotations

from dataclasses import dataclass
from enum import Enum

from d810.core.typing import Any, Iterable, Sequence


class ReturnFrontierCarrierClassification(str, Enum):
    """Recon classification for return-frontier carrier facts."""

    RETURN_CARRIER = "RETURN_CARRIER"
    PROTECTED_NON_CARRIER_RETURN_WRITER = "PROTECTED_NON_CARRIER_RETURN_WRITER"


class ReturnFrontierArtifactKind(str, Enum):
    """Specific protected non-carrier writer shapes known to recon."""

    KNOWN_IMPOSSIBLE_CONSTANT_RETURN_WRITER = "KNOWN_IMPOSSIBLE_CONSTANT_RETURN_WRITER"
    STATE_VARIABLE_RETURN_WRITER = "STATE_VARIABLE_RETURN_WRITER"


@dataclass(frozen=True, slots=True)
class ReturnFrontierArtifactEdgeProof:
    """Exact edge proof for materializing a protected return-frontier artifact.

    Recon/profile code owns the layout proof. Backend runtimes must verify the
    live edge identities before applying the corresponding graph mutation.
    """

    source_block: int
    artifact_block: int
    old_target_block: int
    continuation_block: int
    proof_ids: Sequence[str] = ()


@dataclass(frozen=True, slots=True)
class ReturnFrontierArtifactPriors:
    """Function/profile priors for protected return-frontier artifacts.

    Recon does not own the set of impossible return constants. A caller that
    knows a constant cannot be a legitimate return value for a specific
    function supplies that fact here.
    """

    known_impossible_return_constants: frozenset[int] = frozenset()
    impossible_return_artifact_edges: tuple[
        ReturnFrontierArtifactEdgeProof, ...
    ] = ()

    @classmethod
    def from_known_impossible_return_constants(
        cls,
        values: Iterable[object],
    ) -> "ReturnFrontierArtifactPriors":
        return cls(
            known_impossible_return_constants=frozenset(
                _coerce_u64(value) for value in values
            )
        )

    def is_known_impossible_return_constant(self, value: int) -> bool:
        return _coerce_u64(value) in self.known_impossible_return_constants

    def with_known_impossible_return_constants(
        self,
        values: Iterable[object],
    ) -> "ReturnFrontierArtifactPriors":
        merged = set(self.known_impossible_return_constants)
        merged.update(_coerce_u64(value) for value in values)
        return ReturnFrontierArtifactPriors(
            frozenset(merged),
            self.impossible_return_artifact_edges,
        )

    def with_impossible_return_artifact_edges(
        self,
        edge_proofs: Iterable[ReturnFrontierArtifactEdgeProof],
    ) -> "ReturnFrontierArtifactPriors":
        merged = tuple(
            dict.fromkeys(
                (*self.impossible_return_artifact_edges, *tuple(edge_proofs))
            )
        )
        return ReturnFrontierArtifactPriors(
            self.known_impossible_return_constants,
            merged,
        )

    def merge(
        self,
        other: "ReturnFrontierArtifactPriors | None",
    ) -> "ReturnFrontierArtifactPriors":
        if other is None:
            return self
        return ReturnFrontierArtifactPriors(
            frozenset(
                {
                    *self.known_impossible_return_constants,
                    *other.known_impossible_return_constants,
                }
            ),
            tuple(
                dict.fromkeys(
                    (
                        *self.impossible_return_artifact_edges,
                        *other.impossible_return_artifact_edges,
                    )
                )
            ),
        )


def _coerce_u64(value: object) -> int:
    if isinstance(value, str):
        value = value.strip()
        if not value:
            raise ValueError("empty return artifact constant")
        return int(value, 0) & 0xFFFFFFFFFFFFFFFF
    return int(value) & 0xFFFFFFFFFFFFFFFF


def is_protected_non_carrier_return_writer(fact: Any) -> bool:
    return (
        getattr(fact, "classification", None)
        == ReturnFrontierCarrierClassification.PROTECTED_NON_CARRIER_RETURN_WRITER
    )


def is_known_impossible_constant_return_artifact_fact(fact: Any) -> bool:
    return (
        is_protected_non_carrier_return_writer(fact)
        and getattr(fact, "artifact_kind", None)
        == ReturnFrontierArtifactKind.KNOWN_IMPOSSIBLE_CONSTANT_RETURN_WRITER
    )


__all__ = [
    "ReturnFrontierArtifactEdgeProof",
    "ReturnFrontierArtifactKind",
    "ReturnFrontierArtifactPriors",
    "ReturnFrontierCarrierClassification",
    "is_known_impossible_constant_return_artifact_fact",
    "is_protected_non_carrier_return_writer",
]
