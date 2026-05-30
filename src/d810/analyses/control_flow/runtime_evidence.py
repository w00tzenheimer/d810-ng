"""In-memory read-only reconstruction evidence for live lowering consumers."""
from __future__ import annotations

from dataclasses import dataclass

from d810.core.logging import getLogger
from d810.core.typing import Any

logger = getLogger("D810.recon.flow.runtime_evidence")

_LATEST_RECONSTRUCTION_DAG_BY_FUNC: dict[int, Any] = {}


@dataclass(frozen=True)
class RuntimeEvidenceSummary:
    """Small diagnostics record for a ``ValidatedFactView``-like object."""

    func_ea: int
    maturity: str
    phase: str
    terminal_byte_facts: int
    state_write_facts: int
    rewritten_mappings: int
    observation_count: int
    mapping_count: int


def record_latest_reconstruction_dag(func_ea: int, dag: Any) -> None:
    """Record the latest reconstructed state DAG for one function.

    This is intentionally process-local evidence, not a diagnostic sink.
    Consumers must treat the DAG as read-only.
    """
    _LATEST_RECONSTRUCTION_DAG_BY_FUNC[int(func_ea)] = dag


def get_latest_reconstruction_dag(func_ea: int) -> Any | None:
    return _LATEST_RECONSTRUCTION_DAG_BY_FUNC.get(int(func_ea))


def clear_latest_reconstruction_dag(func_ea: int | None = None) -> None:
    if func_ea is None:
        _LATEST_RECONSTRUCTION_DAG_BY_FUNC.clear()
        return
    _LATEST_RECONSTRUCTION_DAG_BY_FUNC.pop(int(func_ea), None)


def _has_terminal_byte_facts(fact_view: Any | None) -> bool:
    if fact_view is None:
        return False
    for obs in getattr(fact_view, "active_observations", ()) or ():
        if getattr(obs, "kind", None) == "TerminalByteEmitterFact":
            return True
    return False


def _count_kind(observations: tuple[Any, ...], kind: str) -> int:
    return sum(1 for obs in observations if getattr(obs, "kind", None) == kind)


def _count_rewritten_mappings(mappings: tuple[Any, ...]) -> int:
    total = 0
    for mapping in mappings:
        status = getattr(mapping, "status", None)
        status_value = getattr(status, "value", status)
        if str(status_value) == "STATE_CONST_REWRITTEN":
            total += 1
    return total


def summarize_fact_view(
    fact_view: Any | None,
    *,
    func_ea: int,
    phase: str = "runtime",
) -> RuntimeEvidenceSummary:
    """Summarize the in-memory fact view used by behavior consumers.

    This is the DB-free diagnostic equivalent of the common ``fact_observations``
    queries: callers pass the current ``ValidatedFactView`` and get a stable
    count record without touching SQLite.
    """
    observations = tuple(getattr(fact_view, "observations", ()) or ())
    active = tuple(getattr(fact_view, "active_observations", observations) or ())
    mappings = tuple(getattr(fact_view, "mappings", ()) or ())
    return RuntimeEvidenceSummary(
        func_ea=int(func_ea),
        maturity=str(getattr(fact_view, "maturity", "")),
        phase=str(phase),
        terminal_byte_facts=_count_kind(active, "TerminalByteEmitterFact"),
        state_write_facts=_count_kind(active, "StateWriteAnchorFact"),
        rewritten_mappings=_count_rewritten_mappings(mappings),
        observation_count=len(observations),
        mapping_count=len(mappings),
    )


def log_runtime_evidence_summary(
    label: str,
    summary: RuntimeEvidenceSummary,
) -> None:
    """Emit a grep-able one-line summary of in-memory fact evidence."""
    logger.info(
        "%s func=0x%x maturity=%s phase=%s terminal_byte_facts=%d "
        "state_write_facts=%d rewritten_mappings=%d observations=%d mappings=%d",
        label,
        int(summary.func_ea),
        summary.maturity,
        summary.phase,
        int(summary.terminal_byte_facts),
        int(summary.state_write_facts),
        int(summary.rewritten_mappings),
        int(summary.observation_count),
        int(summary.mapping_count),
    )


def ensure_terminal_byte_fact_view(
    target: Any,
    *,
    func_ea: int,
    maturity: int,
    fact_view: Any | None = None,
    phase: str = "runtime",
) -> Any | None:
    """Return a fact view with terminal-byte observations for live consumers.

    The maturity fact lifecycle is the preferred in-memory behavior substrate.
    This helper is a narrow fallback for the terminal-tail hook when explicitly
    enabled by ``D810_TERMINAL_TAIL_CASCADE_EGRESS_RUNTIME_FACTS``. It derives
    only terminal-byte facts and persists nothing.
    """
    if _has_terminal_byte_facts(fact_view):
        return fact_view

    try:
        from d810.analyses.value_flow.terminal_byte_emitter import (
            TerminalByteEmitterFactCollector,
        )
        from d810.analyses.value_flow.model import ValidatedFactView
    except Exception:
        return fact_view

    try:
        observations = TerminalByteEmitterFactCollector().collect(
            target,
            func_ea=int(func_ea),
            maturity=int(maturity),
            phase=str(phase),
        )
    except Exception:
        return fact_view

    if not observations:
        return fact_view

    maturity_text = getattr(observations[0], "maturity", str(maturity))
    return ValidatedFactView(
        maturity=str(maturity_text),
        observations=tuple(observations),
        mappings=tuple(getattr(fact_view, "mappings", ()) or ()),
    )


__all__ = [
    "RuntimeEvidenceSummary",
    "clear_latest_reconstruction_dag",
    "ensure_terminal_byte_fact_view",
    "get_latest_reconstruction_dag",
    "log_runtime_evidence_summary",
    "record_latest_reconstruction_dag",
    "summarize_fact_view",
]
