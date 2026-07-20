"Process-level cache for the canonical preanalysis-time LinearizedStateDag.\n\nDiagnostic dump utilities (e.g. ``dump_linearized_dag``) rebuild the DAG from\nthe live, post-mutation MBA when invoked late in the pipeline. That live\nrebuild produces different anchor selections than what HCC's preanalysis-time\n``local_facts`` actually consumed, because the input CFG has moved between\npreanalysis time and dump time.\n\nThis module exposes a tiny process-level keyed-by-``func_ea`` cache that\ncaptures the FIRST ``LinearizedStateDag`` produced by\n``build_round_discovery_context`` for each function. Every subsequent build\nin the same decompilation is ignored (the first one is the canonical\npreanalysis-time anchor selection). Diagnostic renderers consult the cache when\nproducing their dumps so they label what the engine actually saw.\n\nPure observability. No effect on lowering, anchor selection, or strategy\nbehavior.\n\nLayer note: this lives in ``d810.analyses.control_flow`` so both preanalysis-time builders\nand diagnostic dump utilities can import it without crossing layers.\n"
from __future__ import annotations

import threading
from d810.core.typing import TYPE_CHECKING

if TYPE_CHECKING:
    from d810.analyses.control_flow.linearized_state_dag import LinearizedStateDag


__all__ = (
    "store_persisted_preanalysis_dag",
    "get_persisted_preanalysis_dag",
    "clear_persisted_preanalysis_dag",
    "clear_all_persisted_preanalysis_dags",
)


_lock = threading.Lock()
_persisted_preanalysis_dag_by_func_ea: dict[int, "LinearizedStateDag"] = {}


def store_persisted_preanalysis_dag(
    func_ea: int,
    dag: "LinearizedStateDag",
) -> bool:
    "Store ``dag`` as the canonical preanalysis-time DAG for ``func_ea``.\n\n    Only the FIRST DAG seen per ``func_ea`` wins. Returns ``True`` if the\n    DAG was stored, ``False`` if a previous DAG already exists for this\n    function.\n    "
    if dag is None:
        return False
    key = int(func_ea)
    with _lock:
        if key in _persisted_preanalysis_dag_by_func_ea:
            return False
        _persisted_preanalysis_dag_by_func_ea[key] = dag
    return True


def get_persisted_preanalysis_dag(func_ea: int) -> "LinearizedStateDag | None":
    "Return the canonical preanalysis-time DAG for ``func_ea``, or ``None``."
    key = int(func_ea)
    with _lock:
        return _persisted_preanalysis_dag_by_func_ea.get(key)


def clear_persisted_preanalysis_dag(func_ea: int) -> None:
    """Drop the cached DAG for ``func_ea``."""
    key = int(func_ea)
    with _lock:
        _persisted_preanalysis_dag_by_func_ea.pop(key, None)


def clear_all_persisted_preanalysis_dags() -> None:
    """Drop every cached DAG. Used by test harnesses."""
    with _lock:
        _persisted_preanalysis_dag_by_func_ea.clear()
