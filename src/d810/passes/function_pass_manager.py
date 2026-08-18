"""Thin FunctionPassManager wrapper over the existing pipeline driver."""

from __future__ import annotations

from collections.abc import Callable, Mapping
import hashlib

from d810.analyses.control_flow.dominator import compute_dom_tree
from d810.capabilities.resolver import CapabilitySet
from d810.core.execution_journal import (
    DecompilationSessionId,
    ExecutionAttemptId,
    ExecutionDomain,
)
from d810.core.execution_journal_store import ExecutionJournalStore
from d810.core.execution_profile import (
    ExecutionProfileKey,
    build_execution_profile_preview,
)
from d810.ir.maturity import IRMaturity
from d810.passes.analysis_manager import AnalysisManager
from d810.passes.driver import run_pipeline
from d810.passes.pass_pipeline import (
    PassSpec,
    PreservedAnalyses,
    require_pipeline_v2_specs,
)
from d810.passes.profile_guidance import (
    ProfileCandidate,
    ProfileGuidancePlanner,
    record_profile_guidance_preview,
)
from d810.passes.scheduler import PassScheduler


def _compute_domtree(flow_graph: object) -> object:
    """Compute the backend-neutral dominator tree for a FlowGraph-like object."""
    blocks = getattr(flow_graph, "blocks")
    successors = {
        int(serial): tuple(int(succ) for succ in getattr(block, "succs", ()))
        for serial, block in blocks.items()
    }
    return compute_dom_tree(successors, int(getattr(flow_graph, "entry_serial")))


DEFAULT_ANALYSIS_PROVIDERS: dict[str, Callable[[object], object]] = {
    "domtree": _compute_domtree,
}


def flowgraph_structural_shape(flow_graph: object) -> str:
    """Return a deterministic topology signature for profile segregation."""

    blocks = getattr(flow_graph, "blocks")
    topology = tuple(
        sorted(
            (
                int(serial),
                tuple(int(successor) for successor in getattr(block, "succs", ())),
            )
            for serial, block in blocks.items()
        )
    )
    digest = hashlib.sha256(repr(topology).encode("utf-8")).hexdigest()
    return f"flowgraph-v1:{digest}"


def _maturity_label(phase_token: object) -> str:
    value = getattr(phase_token, "value", None)
    return str(value) if isinstance(value, str) and value else "unknown"


def _profile_guided_specs(
    *,
    specs: tuple[PassSpec, ...],
    source,
    maturity: IRMaturity,
    project_config: object,
    journal: ExecutionJournalStore | None,
    session_id: DecompilationSessionId | None,
    parent_attempt_id: ExecutionAttemptId | None,
) -> tuple[PassSpec, ...]:
    """Select configured optional specs from exact-key historical guidance.

    Only specs already present, enabled at the current maturity, and explicitly
    marked ``profile_guided_optional`` participate.  Mandatory and ineligible
    specs are immovable anchors; guidance can neither create nor enable a pass.
    """

    if not isinstance(project_config, Mapping) or not bool(
        project_config.get("profile_guidance_enabled", False)
    ):
        return specs
    if journal is None or session_id is None:
        return specs
    optional = tuple(
        spec
        for spec in specs
        if spec.enabled_at(maturity)
        and spec.options.get("profile_guided_optional") is True
    )
    if not optional:
        return specs
    native_key = journal.latest_native_key_for_function(int(source.func_ea))
    if native_key is None:
        return specs
    structural_shape = flowgraph_structural_shape(source.flow_graph)
    key = ExecutionProfileKey(
        database_identity=native_key.input_identity,
        function_fingerprint=native_key.function_fingerprint,
        config_fingerprint=native_key.profile_fingerprint,
        toolchain_fingerprint=native_key.sdk_fingerprint,
        maturity=_maturity_label(maturity),
        structural_shape=structural_shape,
    )
    history = build_execution_profile_preview(
        key, journal.attempts_for_native_key(native_key)
    )
    planner = ProfileGuidancePlanner(
        enabled=True,
        budget_ms=float(project_config.get("profile_guidance_budget_ms", 0.0)),
        exploration_slots=int(
            project_config.get("profile_guidance_exploration_slots", 1)
        ),
    )
    preview = planner.preview(
        key=key,
        candidates=tuple(
            ProfileCandidate(
                candidate_id=spec.pass_id,
                stage_id=spec.pass_id,
                domain=ExecutionDomain.PASS,
                estimated_cost_ms=float(
                    spec.options.get("profile_estimated_cost_ms", 0.0)
                ),
                explicit_user_selected=(
                    spec.options.get("profile_explicit_user_selected") is True
                ),
            )
            for spec in optional
        ),
        history=history,
    )
    record_profile_guidance_preview(
        journal,
        session_id,
        preview,
        parent_attempt_id=parent_attempt_id,
    )
    selected_order = tuple(
        decision.candidate.candidate_id
        for decision in preview.decisions
        if decision.recommended
    )
    selected_by_id = {spec.pass_id: spec for spec in optional}
    optional_ids = set(selected_by_id)
    output: list[PassSpec] = []
    index = 0
    while index < len(specs):
        if specs[index].pass_id not in optional_ids:
            output.append(specs[index])
            index += 1
            continue
        run_ids: set[str] = set()
        while index < len(specs) and specs[index].pass_id in optional_ids:
            run_ids.add(specs[index].pass_id)
            index += 1
        output.extend(
            selected_by_id[pass_id] for pass_id in selected_order if pass_id in run_ids
        )
    return tuple(output)


class FunctionPassManager:
    """Own per-function pass-manager state while delegating execution to run_pipeline."""

    def __init__(
        self,
        *,
        scheduler: PassScheduler | None = None,
        analysis_providers: Mapping[str, Callable[[object], object]] | None = None,
    ) -> None:
        self.scheduler = scheduler if scheduler is not None else PassScheduler()
        self._analysis_providers: dict[str, Callable[[object], object]] = dict(
            DEFAULT_ANALYSIS_PROVIDERS
        )
        self._analysis_providers.update(analysis_providers or {})
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
            facts = AnalysisManager(
                source.flow_graph,
                input_facts=input_facts,
                providers=self._analysis_providers,
            )
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

    def register_analysis_provider(
        self,
        name: str,
        compute: Callable[[object], object],
    ) -> None:
        """Register a provider for future and existing per-function managers."""
        self._analysis_providers[str(name)] = compute
        for facts in self._analysis_by_func.values():
            facts.register_provider(name, compute)

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
        pipeline_v2_specs: tuple[PassSpec, ...] | None = None,
        journal: ExecutionJournalStore | None = None,
        session_id: DecompilationSessionId | None = None,
        parent_attempt_id: ExecutionAttemptId | None = None,
    ):
        """Run one family/function/maturity through the existing pipeline driver.

        The manager/lifecycle owns the optional execution journal and the
        current session's root attempt.  This wrapper merely preserves that
        correlation through the portable config-v2 driver; it never creates a
        second session or treats provenance as execution authority.
        """
        compiled_specs = require_pipeline_v2_specs(pipeline_v2_specs)
        facts = self.facts_for(
            source,
            input_facts=input_facts,
            analysis_seeds=analysis_seeds,
        )
        effective_specs = _profile_guided_specs(
            specs=compiled_specs,
            source=source,
            maturity=maturity,
            project_config=project_config,
            journal=journal,
            session_id=session_id,
            parent_attempt_id=parent_attempt_id,
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
            pipeline_v2_specs=effective_specs,
            journal=journal,
            session_id=session_id,
            parent_attempt_id=parent_attempt_id,
            structural_shape=flowgraph_structural_shape(source.flow_graph),
        )
