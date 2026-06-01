"""AnalysisManager — the LLVM new-PassManager ``AnalysisManager`` analog (§1a ``facts``).

LLVM: analyses are lazy, cached, and keyed by the IR unit; a transform returns a
``PreservedAnalyses`` set that prunes the cache. LiSA: the CFG is the analysis unit and results
compose over it. This realizes that for the portable ``FlowGraph``:

* ``get(name, compute)`` computes an analysis once and caches it against the current graph;
* ``invalidate_to(new_graph, preserved)`` advances to a fresh snapshot identity (the sound
  invalidation base — a graph returned by ``MutationBackend.apply`` is a new epoch) and drops every
  cached result the transform did not explicitly preserve.

Satisfies the driver's ``FactStore`` protocol (``view`` + ``invalidate_to``). Portable + additive.
"""
from __future__ import annotations

from d810.core.typing import Callable
from d810.passes.pass_pipeline import PreservedAnalyses


class AnalysisManager:
    """Lazy, snapshot-keyed analysis cache for one function's pipeline run."""

    def __init__(self, graph: object) -> None:
        self._graph = graph
        self._cache: dict[str, object] = {}

    @property
    def graph(self) -> object:
        return self._graph

    def view(self) -> "AnalysisManager":
        """Return the read handle passed to passes as ``ctx.facts``."""
        return self

    def get(self, name: str, compute: Callable[[object], object]) -> object:
        """Return analysis ``name``, computing it once (lazily) over the current graph."""
        if name not in self._cache:
            self._cache[name] = compute(self._graph)
        return self._cache[name]

    def cached(self, name: str) -> bool:
        return name in self._cache

    def invalidate_to(self, new_graph: object, preserved: PreservedAnalyses) -> None:
        """Advance to ``new_graph`` and drop every result not in ``preserved``."""
        self._graph = new_graph
        self._cache = {
            name: result
            for name, result in self._cache.items()
            if preserved.preserves(name)
        }
