"""``run_pipeline`` — the unflatten driver loop, portable + injected-dependency form.

The maturity-hook shell in ``optimizers/`` supplies the live Hex-Rays ``MutationBackend`` and the
lifted ``FunctionSource``; this function is the portable orchestration from the north-star
pseudocode (spec unflatten):

    family.detect -> for spec in family.pipeline_for(match, ctx):
        validate_capabilities; result = spec.pass_factory().run(ctx)
        if result.rewrite_plan has work: ctx = ctx(graph=backend.apply(...)); facts.invalidate_to(...)

Additive + behavior-neutral: not wired into the maturity hook yet. The live backend + lifter are
the seam-pending pieces (``backends/hexrays``); everything here is portable and unit-tested with a
null backend.
"""
from __future__ import annotations

from dataclasses import dataclass, replace

from d810.core.typing import Protocol, runtime_checkable
from d810.capabilities.resolver import CapabilitySet
from d810.passes.contract_vocabulary import (
    contract_name_in,
    contract_name_variants,
    resolve_contract_name,
    resolve_contract_names,
)
from d810.passes.pass_pipeline import (
    BackendRoute,
    CapabilityPolicy,
    FunctionPipelineContext,
    PipelineConfigError,
    PassSpec,
    PreservedAnalyses,
    SafetyPolicy,
    SchedulerPolicy,
)
from d810.passes.pipeline_shadow import (
    require_pipeline_v2_shadow_match as _require_pipeline_v2_shadow_match,
)
from d810.passes.registry import PassRegistry
from d810.passes.scheduler import PassScheduler, RunLaterDomain
from d810.transforms.plan import PatchPlan


class CapabilityError(RuntimeError):
    """A pass requires a backend capability the backend does not advertise."""


class AnalysisContractError(RuntimeError):
    """A pass violated its declared analysis contract."""


@dataclass(frozen=True)
class PassContractDiagnostic:
    """Structured detail for a native pass-contract failure."""

    pass_id: str
    namespace: str
    missing: tuple[str, ...] = ()
    undeclared: tuple[str, ...] = ()
    available: tuple[str, ...] = ()
    detail: str = ""


class PassContractError(RuntimeError):
    """A pass violated its native analysis/evidence/fact contract."""

    def __init__(
        self,
        message: str,
        *,
        diagnostics: tuple[PassContractDiagnostic, ...] = (),
    ) -> None:
        super().__init__(message)
        self.diagnostics = diagnostics


class BackendRouteError(RuntimeError):
    """A pass produced work incompatible with its declared backend route."""


@runtime_checkable
class Family(Protocol):
    name: str

    def detect(self, graph, capabilities, context=None): ...
    def pipeline_for(self, match, context) -> "tuple[PassSpec, ...]": ...


@runtime_checkable
class FactStore(Protocol):
    def view(self): ...
    def invalidate_to(self, graph, preserved: PreservedAnalyses) -> None: ...


def _plan_has_work(plan: PatchPlan) -> bool:
    return bool(plan.steps or plan.new_blocks or plan.planner_modifications)


def _graph_changed(old_graph, new_graph) -> bool:
    """Return whether backend apply produced a meaningfully new graph snapshot."""
    return new_graph != old_graph


def validate_capabilities(backend, requirements: CapabilityPolicy) -> None:
    """Fail loud if the backend cannot satisfy a pass's required capabilities."""
    have = frozenset(backend.capabilities())
    missing = frozenset(requirements.required) - have
    if missing:
        raise CapabilityError(
            f"backend missing capabilities {sorted(missing)} for pass requirements"
        )


def validate_contract_capabilities(spec: PassSpec, backend) -> None:
    """Fail loud if native ``requires.capabilities`` are unavailable."""
    required = spec.contract.requires.capabilities
    if not required:
        return
    have = frozenset(backend.capabilities())
    missing = tuple(sorted(required - have))
    if missing:
        raise CapabilityError(
            f"pass {spec.pass_id!r} missing backend capabilities {list(missing)} "
            "declared in requires.capabilities"
        )


def _require_analysis_methods(facts, *, pass_id: str, method_names: tuple[str, ...]) -> None:
    missing = tuple(name for name in method_names if not hasattr(facts, name))
    if missing:
        raise AnalysisContractError(
            f"pass {pass_id!r} declares analysis contracts but facts view "
            f"does not support {sorted(missing)}"
        )


def validate_required_analyses(spec: PassSpec, ctx: FunctionPipelineContext) -> None:
    """Fail loud when a pass's declared analysis prerequisites are unavailable."""
    if not spec.analyses.required:
        return
    _require_analysis_methods(
        ctx.facts, pass_id=spec.pass_id, method_names=("has_analysis",)
    )
    missing = tuple(
        sorted(
            key
            for key in spec.analyses.required
            if not ctx.facts.has_analysis(key)
        )
    )
    if missing:
        raise AnalysisContractError(
            f"pass {spec.pass_id!r} missing required analyses {list(missing)}"
        )


def _require_contract_methods(
    facts,
    *,
    pass_id: str,
    method_names: tuple[str, ...],
) -> None:
    missing = tuple(name for name in method_names if not hasattr(facts, name))
    if missing:
        raise PassContractError(
            f"pass {pass_id!r} declares native pass contracts but facts view "
            f"does not support {sorted(missing)}"
        )


def _available_names(facts, method_name: str) -> tuple[str, ...]:
    method = getattr(facts, method_name, None)
    if not callable(method):
        return ()
    return tuple(str(name) for name in method())


def _has_contract_name(facts, method_name: str, name: str) -> bool:
    method = getattr(facts, method_name, None)
    if not callable(method):
        return False
    return any(bool(method(variant)) for variant in contract_name_variants(name))


def validate_native_contract(spec: PassSpec, ctx: FunctionPipelineContext) -> None:
    """Fail loud when native pass-contract prerequisites are unavailable."""
    contract = spec.contract
    method_names: list[str] = []
    if contract.requires.analyses:
        method_names.append("has_analysis")
    if contract.requires.facts.required:
        method_names.append("has_fact")
    if contract.requires.evidence:
        method_names.append("has_evidence")
    if not method_names:
        return

    _require_contract_methods(
        ctx.facts,
        pass_id=spec.pass_id,
        method_names=tuple(method_names),
    )

    missing_analyses = tuple(
        sorted(
            name
            for name in contract.requires.analyses
            if not ctx.facts.has_analysis(name)
        )
    )
    missing_facts = tuple(
        sorted(
            name
            for name in contract.requires.facts.required
            if not _has_contract_name(ctx.facts, "has_fact", name)
        )
    )
    missing_evidence = tuple(
        sorted(
            name
            for name in contract.requires.evidence
            if not _has_contract_name(ctx.facts, "has_evidence", name)
        )
    )
    if missing_analyses or missing_facts or missing_evidence:
        parts: list[str] = []
        diagnostics: list[PassContractDiagnostic] = []
        if missing_analyses:
            parts.append(f"analyses {list(missing_analyses)}")
            diagnostics.append(
                PassContractDiagnostic(
                    pass_id=spec.pass_id,
                    namespace="requires.analyses",
                    missing=missing_analyses,
                    available=_available_names(ctx.facts, "available_analyses"),
                )
            )
        if missing_facts:
            parts.append(f"facts {list(missing_facts)}")
            diagnostics.append(
                PassContractDiagnostic(
                    pass_id=spec.pass_id,
                    namespace="requires.facts.required",
                    missing=missing_facts,
                    available=_available_names(ctx.facts, "available_facts"),
                )
            )
        if missing_evidence:
            parts.append(f"evidence {list(missing_evidence)}")
            diagnostics.append(
                PassContractDiagnostic(
                    pass_id=spec.pass_id,
                    namespace="requires.evidence",
                    missing=missing_evidence,
                    available=_available_names(ctx.facts, "available_evidence"),
                )
            )
        raise PassContractError(
            f"pass {spec.pass_id!r} missing native contract requirements: "
            + "; ".join(parts),
            diagnostics=tuple(diagnostics),
        )


def validate_analysis_outputs(spec: PassSpec, result) -> None:
    """Fail when a pass publishes undeclared typed analysis outputs."""
    if not result.analysis_outputs:
        return
    undeclared = frozenset(result.analysis_outputs) - spec.analyses.provided
    if undeclared:
        raise AnalysisContractError(
            f"pass {spec.pass_id!r} published undeclared analyses "
            f"{sorted(undeclared)}"
        )


def validate_contract_fact_outputs(spec: PassSpec, result) -> None:
    """Fail when a native-contract pass publishes undeclared or anonymous facts."""
    declared = spec.contract.outputs.facts
    if not declared:
        return

    undeclared: list[str] = []
    anonymous = 0
    for fact in result.facts:
        kind = getattr(fact, "kind", None)
        if kind is None:
            anonymous += 1
            continue
        if not contract_name_in(str(kind), declared):
            undeclared.append(str(kind))

    if anonymous:
        raise PassContractError(
            f"pass {spec.pass_id!r} published facts without a kind",
            diagnostics=(
                PassContractDiagnostic(
                    pass_id=spec.pass_id,
                    namespace="outputs.facts",
                    detail="published facts lacked kind",
                ),
            ),
        )
    if undeclared:
        raise PassContractError(
            f"pass {spec.pass_id!r} published undeclared contract facts "
            f"{sorted(undeclared)}",
            diagnostics=(
                PassContractDiagnostic(
                    pass_id=spec.pass_id,
                    namespace="outputs.facts",
                    undeclared=tuple(sorted(undeclared)),
                    available=tuple(sorted(declared)),
                ),
            ),
        )


def validate_contract_evidence_outputs(spec: PassSpec, result) -> None:
    """Fail when a native-contract pass publishes undeclared evidence."""
    if not result.evidence_outputs:
        return

    declared = spec.contract.outputs.evidence
    declared_names = resolve_contract_names(declared)
    undeclared = tuple(
        sorted(
            name
            for name in result.evidence_outputs
            if resolve_contract_name(str(name)) not in declared_names
        )
    )
    if undeclared:
        raise PassContractError(
            f"pass {spec.pass_id!r} published undeclared contract evidence "
            f"{list(undeclared)}",
            diagnostics=(
                PassContractDiagnostic(
                    pass_id=spec.pass_id,
                    namespace="outputs.evidence",
                    undeclared=undeclared,
                    available=tuple(sorted(declared)),
                ),
            ),
        )


def publish_analysis_outputs(
    spec: PassSpec, ctx: FunctionPipelineContext, result
) -> None:
    """Publish typed pass outputs through the analysis manager edge."""
    if not result.analysis_outputs:
        return
    _require_analysis_methods(
        ctx.facts, pass_id=spec.pass_id, method_names=("put_analysis",)
    )
    for name, value in result.analysis_outputs.items():
        ctx.facts.put_analysis(name, value)


def publish_contract_fact_outputs(
    spec: PassSpec,
    ctx: FunctionPipelineContext,
    result,
) -> None:
    """Publish declared native-contract facts through the analysis manager edge."""
    if not spec.contract.outputs.facts or not result.facts:
        return
    _require_contract_methods(
        ctx.facts, pass_id=spec.pass_id, method_names=("put_fact",)
    )
    for fact in result.facts:
        ctx.facts.put_fact(str(getattr(fact, "kind")), fact)


def publish_contract_evidence_outputs(
    spec: PassSpec,
    ctx: FunctionPipelineContext,
    result,
) -> None:
    """Publish declared native-contract evidence through the analysis manager edge."""
    if not result.evidence_outputs:
        return
    _require_contract_methods(
        ctx.facts, pass_id=spec.pass_id, method_names=("put_evidence",)
    )
    for name, value in result.evidence_outputs.items():
        ctx.facts.put_evidence(str(name), value)


def validate_backend_route(spec: PassSpec, result) -> None:
    """Fail when an analysis-only pass tries to emit backend mutation work."""
    if (
        spec.backend_route is BackendRoute.ANALYSIS_ONLY
        and _plan_has_work(result.rewrite_plan)
    ):
        raise BackendRouteError(
            f"analysis-only pass {spec.pass_id!r} produced a rewrite plan"
        )


def effective_preserved_analyses(
    spec: PassSpec, result
) -> PreservedAnalyses:
    """Return the invalidation hint chosen by result override or spec default."""
    if result.preserved_explicit:
        return result.preserved
    if spec.contract.preserves.analyses:
        return PreservedAnalyses.preserving(spec.contract.preserves.analyses)
    return spec.preservation


def effective_safety_policy(spec: PassSpec) -> SafetyPolicy:
    """Return the mutation-boundary safety policy for a pass spec."""
    if spec.safety_policy != SafetyPolicy():
        return spec.safety_policy
    safety = spec.contract.safety
    return SafetyPolicy(
        name=safety.policy,
        golden_required=safety.requires_oracle,
    )


def _run_pass_spec(
    *,
    spec: PassSpec,
    ctx: FunctionPipelineContext,
    backend,
    facts,
    scheduler: PassScheduler | None,
) -> FunctionPipelineContext:
    validate_capabilities(backend, spec.requirements)
    validate_contract_capabilities(spec, backend)
    validate_required_analyses(spec, ctx)
    validate_native_contract(spec, ctx)
    result = spec.pass_factory().run(ctx)
    validate_analysis_outputs(spec, result)
    validate_contract_fact_outputs(spec, result)
    validate_contract_evidence_outputs(spec, result)
    validate_backend_route(spec, result)
    if scheduler is not None:
        for request in result.run_later:
            scheduler.request(
                func_ea=ctx.source.func_ea,
                pass_id=spec.pass_id,
                current_maturity=ctx.maturity,
                run_later=request,
                domain=RunLaterDomain.PIPELINE_PASS,
            )
    publish_analysis_outputs(spec, ctx, result)
    publish_contract_fact_outputs(spec, ctx, result)
    publish_contract_evidence_outputs(spec, ctx, result)
    if _plan_has_work(result.rewrite_plan):
        new_graph = backend.apply(
            result.rewrite_plan, ctx.source.live_source, effective_safety_policy(spec)
        )
        if _graph_changed(ctx.graph, new_graph):
            facts.invalidate_to(new_graph, effective_preserved_analyses(spec, result))
            if hasattr(facts, "invalidate_contract"):
                facts.invalidate_contract(spec.contract)
            ctx = replace(ctx, graph=new_graph)
    return ctx


def _eligible_specs(
    specs: tuple[PassSpec, ...],
    maturity,
) -> tuple[PassSpec, ...]:
    return tuple(spec for spec in specs if spec.enabled_at(maturity))


def _build_pass_worklists(
    *,
    specs: tuple[PassSpec, ...],
    scheduler: PassScheduler | None,
    ctx: FunctionPipelineContext,
) -> tuple[tuple[PassSpec, ...], tuple[PassSpec, ...]]:
    worklist = list(_eligible_specs(specs, ctx.maturity))
    replay_after_pipeline: list[PassSpec] = []
    if scheduler is None:
        return tuple(worklist), ()

    specs_by_name = {spec.pass_id: spec for spec in specs}
    scheduled_worklist: list[PassSpec] = []
    for pending in scheduler.drain(
        func_ea=ctx.source.func_ea,
        current_maturity=ctx.maturity,
        domain=RunLaterDomain.PIPELINE_PASS,
    ):
        spec = specs_by_name.get(pending.pass_id)
        if spec is None or not spec.enabled_at(ctx.maturity):
            continue
        if spec.scheduler_policy is SchedulerPolicy.REPLAY_AFTER_PIPELINE:
            replay_after_pipeline.append(spec)
        else:
            scheduled_worklist.append(spec)

    queued_ids = {spec.pass_id for spec in worklist}
    for spec in scheduled_worklist:
        if spec.pass_id not in queued_ids:
            worklist.append(spec)
            queued_ids.add(spec.pass_id)
    return tuple(worklist), tuple(replay_after_pipeline)


def run_pipeline(
    *,
    source,
    family,
    backend,
    facts,
    project_config,
    maturity,
    capabilities=None,
    scheduler: PassScheduler | None = None,
    pipeline_v2_shadow_registry: PassRegistry | None = None,
    require_pipeline_v2_shadow_match: bool = False,
    pipeline_v2_specs: tuple[PassSpec, ...] | None = None,
):
    """Run one family's pipeline over one function/maturity. Returns the final graph.

    Mirrors unflatten ``run_d810_pipeline`` minus the lift/select bootstrap (the shell does those).
    ``capabilities`` is the backend-provided :class:`CapabilitySet` (typed capability instances)
    threaded into every pass's context; ``None`` -> an empty set (passes that only query
    ``optional`` are unaffected).
    """
    graph = source.flow_graph
    ctx = FunctionPipelineContext(
        source=source,
        graph=graph,
        maturity=maturity,
        project_config=project_config,
        facts=facts.view(),
        capabilities=capabilities if capabilities is not None else CapabilitySet(),
    )
    if pipeline_v2_specs is None:
        match = family.detect(graph, backend.capabilities(), context=project_config)
        if match is None:
            return graph
        specs = family.pipeline_for(match, ctx)
    else:
        specs = tuple(pipeline_v2_specs)
        if not specs:
            raise PipelineConfigError(
                "config-v2 execution requires at least one configured pass"
            )

    if require_pipeline_v2_shadow_match:
        if pipeline_v2_shadow_registry is None:
            raise PipelineConfigError(
                "pipeline_v2 shadow enforcement requires a pass registry"
            )
        _require_pipeline_v2_shadow_match(
            project_config=project_config,
            registry=pipeline_v2_shadow_registry,
            live_specs=specs,
        )
    worklist, replay_after_pipeline = _build_pass_worklists(
        specs=specs,
        scheduler=scheduler,
        ctx=ctx,
    )

    for spec in worklist:
        ctx = _run_pass_spec(
            spec=spec, ctx=ctx, backend=backend, facts=facts, scheduler=scheduler
        )

    for spec in replay_after_pipeline:
        ctx = _run_pass_spec(
            spec=spec, ctx=ctx, backend=backend, facts=facts, scheduler=scheduler
        )
    return ctx.graph
