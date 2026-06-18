"""Thin FunctionPassManager wrapper over the existing pipeline driver."""
from __future__ import annotations

from collections.abc import Mapping

from d810.capabilities.resolver import CapabilitySet
from d810.ir.maturity import IRMaturity
from d810.passes.analysis_manager import AnalysisManager
from d810.passes.driver import run_pipeline
from d810.passes.pass_pipeline import PreservedAnalyses
from d810.passes.scheduler import PassScheduler


class FunctionPassManager:
    """Own per-function pass-manager state while delegating execution to run_pipeline."""

    def __init__(self) -> None:
        self.scheduler = PassScheduler()
        self._analysis_by_func: dict[int, AnalysisManager] = {}

    def analysis_manager_for(self, func_ea: int) -> AnalysisManager | None:
        """Return the manager-owned facts for ``func_ea`` when one exists."""
        return self._analysis_by_func.get(int(func_ea))

    def reset_func(self, func_ea: int) -> None:
        """Forget cached facts and scheduled pipeline work for one function."""
        key = int(func_ea)
        self._analysis_by_func.pop(key, None)
        self.scheduler.reset_func(key)

    def reset_all(self) -> None:
        """Forget every cached fact and scheduled pipeline request."""
        self._analysis_by_func.clear()
        self.scheduler.reset_all()

    def _facts_for(
        self,
        source,
        *,
        input_facts: object | None = None,
    ) -> AnalysisManager:
        func_ea = int(source.func_ea)
        facts = self._analysis_by_func.get(func_ea)
        if facts is None:
            facts = AnalysisManager(source.flow_graph, input_facts=input_facts)
            self._analysis_by_func[func_ea] = facts
            return facts
        if facts.graph is not source.flow_graph:
            facts.invalidate_to(source.flow_graph, PreservedAnalyses.none())
        facts.set_input_facts(input_facts)
        return facts

    def facts_for(
        self,
        source,
        *,
        input_facts: object | None = None,
        analysis_seeds: Mapping[str, object] | None = None,
    ) -> AnalysisManager:
        """Return manager-owned facts, refreshing live inputs for this run."""
        facts = self._facts_for(source, input_facts=input_facts)
        for name, value in (analysis_seeds or {}).items():
            facts.put_analysis(name, value)
        return facts

    def run(
        self,
        *,
        source,
        family,
        backend,
        project_config,
        maturity: IRMaturity,
        capabilities: CapabilitySet | None = None,
        input_facts: object | None = None,
        analysis_seeds: Mapping[str, object] | None = None,
    ):
        """Run one family/function/maturity through the existing pipeline driver."""
        facts = self.facts_for(
            source,
            input_facts=input_facts,
            analysis_seeds=analysis_seeds,
        )
        return run_pipeline(
            source=source,
            family=family,
            backend=backend,
            facts=facts,
            project_config=project_config,
            maturity=maturity,
            capabilities=capabilities,
            scheduler=self.scheduler,
        )
