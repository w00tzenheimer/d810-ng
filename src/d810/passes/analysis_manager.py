"""AnalysisManager — the LLVM new-PassManager ``AnalysisManager`` analog (unflatten ``facts``).

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

from d810.core.typing import Callable, Mapping
from d810.analyses.value_flow.contract_evidence import contract_evidence_tokens
from d810.passes.pass_pipeline import PreservedAnalyses


class AnalysisManager:
    """Lazy, snapshot-keyed analysis cache for one function's pipeline run."""

    def __init__(
        self,
        graph: object,
        input_facts: object | None = None,
        providers: Mapping[str, Callable[[object], object]] | None = None,
    ) -> None:
        self._graph = graph
        self._cache: dict[str, object] = {}
        # The live input fact view (state observations etc.); portable passes that read
        # observations (resolve_state_transitions) see them through this manager transparently.
        self._input_facts = input_facts
        self._derived: dict[str, object] = {}
        self._facts: dict[str, list[object]] = {}
        self._evidence: dict[str, list[object]] = {}
        self._providers: dict[str, Callable[[object], object]] = dict(
            providers or {}
        )

    @property
    def graph(self) -> object:
        return self._graph

    @property
    def active_observations(self):
        """Forward to the input fact view so ``facts_from_validated_view(am)`` works."""
        return getattr(self._input_facts, "active_observations", ()) if self._input_facts else ()

    def set_input_facts(self, input_facts: object | None) -> None:
        """Replace the live fact view for the next pipeline pass run."""
        self._input_facts = input_facts

    def put_analysis(self, name: str, value: object) -> None:
        """Publish a pass result for later passes (the LLVM ``AnalysisManager.getResult`` edge)."""
        self._derived[name] = value

    def put_fact(self, name: str, value: object) -> None:
        """Publish a typed deobfuscation fact for later native contract checks."""
        self._facts.setdefault(str(name), []).append(value)

    def get_fact(self, name: str, default: object = None) -> object:
        """Return facts named ``name`` from published facts or live observations."""
        values = list(self._facts.get(name, ()))
        values.extend(
            observation
            for observation in self.active_observations
            if getattr(observation, "kind", None) == name
        )
        return tuple(values) if values else default

    def has_fact(self, name: str) -> bool:
        """Return whether ``name`` is available as a published or live observation fact."""
        return self.get_fact(name, default=None) is not None

    def put_evidence(self, name: str, value: object = True) -> None:
        """Publish an evidence token for later native contract checks."""
        self._evidence.setdefault(str(name), []).append(value)

    def get_evidence(self, name: str, default: object = None) -> object:
        """Return evidence named ``name`` from published evidence or live observations."""
        values = list(self._evidence.get(name, ()))
        values.extend(
            observation
            for observation in self.active_observations
            if name in contract_evidence_tokens(observation)
        )
        return tuple(values) if values else default

    def has_evidence(self, name: str) -> bool:
        """Return whether ``name`` is available as published or observation evidence."""
        return self.get_evidence(name, default=None) is not None

    def register_provider(
        self, name: str, compute: Callable[[object], object]
    ) -> None:
        """Register a lazy analysis provider for ``name``."""
        self._providers[str(name)] = compute

    def get_analysis(self, name: str, default: object = None) -> object:
        """Return a prior pass's published result, or ``default``."""
        if name in self._derived:
            return self._derived[name]
        if name in self._cache:
            return self._cache[name]
        provider = self._providers.get(name)
        if provider is not None:
            return self.get(name, provider)
        return default

    def require_analysis(self, name: str) -> object:
        """Return analysis ``name`` or raise when no result/provider exists."""
        if not self.has_analysis(name):
            raise KeyError(name)
        return self.get_analysis(name)

    def has_analysis(self, name: str) -> bool:
        """Return whether ``name`` is available as a published or cached analysis."""
        return name in self._derived or name in self._cache or name in self._providers

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
        self._derived = {
            name: result
            for name, result in self._derived.items()
            if preserved.preserves(name)
        }

    def invalidate_contract(self, contract) -> None:
        """Apply native contract invalidation separate from analysis preservation."""
        for name in contract.invalidates.analyses:
            self._cache.pop(name, None)
            self._derived.pop(name, None)
        for name in contract.invalidates.facts:
            self._facts.pop(name, None)
