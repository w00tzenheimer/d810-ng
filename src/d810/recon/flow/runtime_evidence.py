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


__all__ = [
    "clear_latest_reconstruction_dag",
    "get_latest_reconstruction_dag",
    "record_latest_reconstruction_dag",
]
