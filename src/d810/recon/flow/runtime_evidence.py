"""In-memory read-only reconstruction evidence for live lowering consumers."""
from __future__ import annotations

from d810.core.typing import Any


_LATEST_RECONSTRUCTION_DAG_BY_FUNC: dict[int, Any] = {}


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


def ensure_terminal_byte_fact_view(
    target: Any,
    *,
    func_ea: int,
    maturity: int,
    fact_view: Any | None = None,
    phase: str = "runtime",
) -> Any | None:
    """Return a fact view with terminal-byte observations for live consumers.

    The maturity fact lifecycle is diagnostic/observability infrastructure and
    may be disabled in normal runs.  Tail-lowering behavior still needs the
    same read-only evidence, so this helper derives just the terminal-byte
    facts directly from the live target when the supplied view is absent or
    empty.  Nothing is persisted here.
    """
    if _has_terminal_byte_facts(fact_view):
        return fact_view

    try:
        from d810.recon.facts.collectors.terminal_byte_emitter import (
            TerminalByteEmitterFactCollector,
        )
        from d810.recon.facts.model import ValidatedFactView
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
    "clear_latest_reconstruction_dag",
    "ensure_terminal_byte_fact_view",
    "get_latest_reconstruction_dag",
    "record_latest_reconstruction_dag",
]
