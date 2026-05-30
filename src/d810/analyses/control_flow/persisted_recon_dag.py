"""Process-level cache for the canonical recon-time LinearizedStateDag.

Diagnostic dump utilities (e.g. ``dump_linearized_dag``) rebuild the DAG from
the live, post-mutation MBA when invoked late in the pipeline. That live
rebuild produces different anchor selections than what HCC's recon-time
``local_facts`` actually consumed, because the input CFG has moved between
recon time and dump time.

This module exposes a tiny process-level keyed-by-``func_ea`` cache that
captures the FIRST ``LinearizedStateDag`` produced by
``build_round_discovery_context`` for each function. Every subsequent build
in the same decompilation is ignored (the first one is the canonical
recon-time anchor selection). Diagnostic renderers consult the cache when
producing their dumps so they label what the engine actually saw.

Pure observability. No effect on lowering, anchor selection, or strategy
behavior.

Layer note: this lives in ``d810.recon.flow`` so both recon-time builders
and diagnostic dump utilities can import it without crossing layers.
"""
from __future__ import annotations

import threading
from d810.core.typing import TYPE_CHECKING

if TYPE_CHECKING:
    from d810.analyses.control_flow.linearized_state_dag import LinearizedStateDag


__all__ = (
    "store_persisted_recon_dag",
    "get_persisted_recon_dag",
    "clear_persisted_recon_dag",
    "clear_all_persisted_recon_dags",
)


_lock = threading.Lock()
_persisted_recon_dag_by_func_ea: dict[int, "LinearizedStateDag"] = {}


def store_persisted_recon_dag(
    func_ea: int,
    dag: "LinearizedStateDag",
) -> bool:
    """Store ``dag`` as the canonical recon-time DAG for ``func_ea``.

    Only the FIRST DAG seen per ``func_ea`` wins. Returns ``True`` if the
    DAG was stored, ``False`` if a previous DAG already exists for this
    function.
    """
    if dag is None:
        return False
    key = int(func_ea)
    with _lock:
        if key in _persisted_recon_dag_by_func_ea:
            return False
        _persisted_recon_dag_by_func_ea[key] = dag
    return True


def get_persisted_recon_dag(func_ea: int) -> "LinearizedStateDag | None":
    """Return the canonical recon-time DAG for ``func_ea``, or ``None``."""
    key = int(func_ea)
    with _lock:
        return _persisted_recon_dag_by_func_ea.get(key)


def clear_persisted_recon_dag(func_ea: int) -> None:
    """Drop the cached DAG for ``func_ea``."""
    key = int(func_ea)
    with _lock:
        _persisted_recon_dag_by_func_ea.pop(key, None)


def clear_all_persisted_recon_dags() -> None:
    """Drop every cached DAG. Used by test harnesses."""
    with _lock:
        _persisted_recon_dag_by_func_ea.clear()
