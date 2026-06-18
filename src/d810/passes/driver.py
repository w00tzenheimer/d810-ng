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

from dataclasses import replace

from d810.core.typing import Protocol, runtime_checkable
from d810.capabilities.resolver import CapabilitySet
from d810.passes.pass_pipeline import (
    CapabilityPolicy,
    FunctionPipelineContext,
    PassSpec,
    PreservedAnalyses,
    SchedulerPolicy,
)
from d810.passes.scheduler import PassScheduler, RunLaterDomain
from d810.transforms.plan import PatchPlan


class CapabilityError(RuntimeError):
    """A pass requires a backend capability the backend does not advertise."""


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


def validate_capabilities(backend, requirements: CapabilityPolicy) -> None:
    """Fail loud if the backend cannot satisfy a pass's required capabilities."""
    have = frozenset(backend.capabilities())
    missing = frozenset(requirements.required) - have
    if missing:
        raise CapabilityError(
            f"backend missing capabilities {sorted(missing)} for pass requirements"
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
    result = spec.pass_factory().run(ctx)
    if scheduler is not None:
        for request in result.run_later:
            scheduler.request(
                func_ea=ctx.source.func_ea,
                pass_id=spec.pass_id,
                current_maturity=ctx.maturity,
                run_later=request,
                domain=RunLaterDomain.PIPELINE_PASS,
            )
    if _plan_has_work(result.rewrite_plan):
        new_graph = backend.apply(
            result.rewrite_plan, ctx.source.live_source, spec.safety_policy
        )
        facts.invalidate_to(new_graph, result.preserved)
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
):
    """Run one family's pipeline over one function/maturity. Returns the final graph.

    Mirrors unflatten ``run_d810_pipeline`` minus the lift/select bootstrap (the shell does those).
    ``capabilities`` is the backend-provided :class:`CapabilitySet` (typed capability instances)
    threaded into every pass's context; ``None`` -> an empty set (passes that only query
    ``optional`` are unaffected).
    """
    graph = source.flow_graph
    match = family.detect(graph, backend.capabilities(), context=project_config)
    if match is None:
        return graph

    ctx = FunctionPipelineContext(
        source=source,
        graph=graph,
        maturity=maturity,
        project_config=project_config,
        facts=facts.view(),
        capabilities=capabilities if capabilities is not None else CapabilitySet(),
    )
    specs = family.pipeline_for(match, ctx)
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
