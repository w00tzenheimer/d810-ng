"""In-memory evidence interfaces for byte-tail mutation runtime hooks."""
from __future__ import annotations

from dataclasses import dataclass

from d810.core.typing import Any, Mapping, Protocol, Sequence


@dataclass(frozen=True, slots=True)
class TerminalTailPlannerEvidence:
    """DB-free planner inputs for terminal-tail lowering.

    ``blocks`` and ``sites`` are the same pure planner shapes consumed by
    ``TerminalTailCascadeEgressPlanner``. ``dag`` is the current in-memory
    reconstruction DAG, not a persisted diag snapshot.
    """

    blocks: Mapping[int, Any]
    sites: Sequence[Any]
    dag: Any | None = None


@dataclass(frozen=True, slots=True)
class ByteTailRuntimeEvidence:
    """Evidence bundle supplied to byte-tail mutation hooks."""

    fact_view: Any | None = None
    dag: Any | None = None
    terminal_tail_planner: TerminalTailPlannerEvidence | None = None
    terminal_tail_cascade_egress: Any | None = None
    impossible_return_artifact_edges: Sequence[Any] = ()


class ByteTailRuntimeEvidenceProvider(Protocol):
    """Provider for current-function byte-tail evidence.

    Implementations should be backed by process-local recon/runtime evidence,
    not by diagnostic SQLite rows.
    """

    def byte_tail_runtime_evidence(self, mba: Any) -> ByteTailRuntimeEvidence | None:
        ...


@dataclass(frozen=True, slots=True)
class StaticByteTailRuntimeEvidenceProvider:
    """Provider for already-materialized in-memory byte-tail evidence."""

    evidence: ByteTailRuntimeEvidence

    def byte_tail_runtime_evidence(self, mba: Any) -> ByteTailRuntimeEvidence:
        return self.evidence


def normalize_byte_tail_runtime_evidence(
    provider: ByteTailRuntimeEvidenceProvider | None,
    mba: Any,
) -> ByteTailRuntimeEvidence:
    """Return a normalized evidence bundle for optional provider inputs."""
    if provider is None:
        return ByteTailRuntimeEvidence()
    try:
        evidence = provider.byte_tail_runtime_evidence(mba)
    except Exception:
        return ByteTailRuntimeEvidence()
    if evidence is None:
        return ByteTailRuntimeEvidence()
    return evidence


__all__ = [
    "ByteTailRuntimeEvidence",
    "ByteTailRuntimeEvidenceProvider",
    "StaticByteTailRuntimeEvidenceProvider",
    "TerminalTailPlannerEvidence",
    "normalize_byte_tail_runtime_evidence",
]
