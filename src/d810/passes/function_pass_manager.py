"""Thin FunctionPassManager wrapper over the existing pipeline driver."""
from __future__ import annotations

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

    def _facts_for(self, source) -> AnalysisManager:
        func_ea = int(source.func_ea)
        facts = self._analysis_by_func.get(func_ea)
        if facts is None:
            facts = AnalysisManager(source.flow_graph)
            self._analysis_by_func[func_ea] = facts
            return facts
        if facts.graph is not source.flow_graph:
            facts.invalidate_to(source.flow_graph, PreservedAnalyses.none())
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
    ):
        """Run one family/function/maturity through the existing pipeline driver."""
        return run_pipeline(
            source=source,
            family=family,
            backend=backend,
            facts=self._facts_for(source),
            project_config=project_config,
            maturity=maturity,
            capabilities=capabilities,
            scheduler=self.scheduler,
        )
