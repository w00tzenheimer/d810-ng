"""``run_pipeline`` — the unflatten driver loop, portable + injected-dependency form.

The maturity-hook shell in ``optimizers/`` supplies the live Hex-Rays ``MutationBackend`` and the
lifted ``FunctionSource``; this function is the portable orchestration from the north-star
pseudocode (spec unflatten):

    family.detect -> for spec in family.pipeline_for(match, ctx):
        validate_capabilities; result = spec.pass_factory().run(ctx)
        if result.rewrite_plan has work: ctx = ctx(graph=backend.apply(...)); facts.invalidate_to(...)
        elif result.fragment_plan: ctx = ctx(graph=backend.apply(...)); facts.invalidate_to(...)

Fragment publication defers pass-output visibility until the backend returns a
committed, postvalidated graph snapshot. The live backend + lifter are supplied
from ``backends/hexrays``; everything here remains portable.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass, replace

from d810.core.typing import Protocol, runtime_checkable
from d810.capabilities.pass_contract_evidence import PassContractEvidenceObserver
from d810.capabilities.resolver import CapabilitySet
from d810.core.execution_journal import (
    DecompilationSessionId,
    ExecutionAttempt,
    ExecutionAttemptId,
    ExecutionAttemptStatus,
    ExecutionDomain,
    ExecutionEffectRef,
)
from d810.core.execution_journal_store import ExecutionJournalStore
from d810.core.logging import getLogger
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

logger = getLogger("d810.passes.driver")


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
    return bool(plan.steps or plan.new_blocks)


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


def _require_analysis_methods(
    facts, *, pass_id: str, method_names: tuple[str, ...]
) -> None:
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
        sorted(key for key in spec.analyses.required if not ctx.facts.has_analysis(key))
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
            f"pass {spec.pass_id!r} published undeclared analyses {sorted(undeclared)}"
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
    if not result.evidence_outputs and not result.evidence_publications:
        return

    declared = spec.contract.outputs.evidence
    declared_names = resolve_contract_names(declared)
    undeclared = tuple(
        sorted(
            name
            for name in (*result.evidence_outputs, *result.evidence_publications)
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

    publication_names = {
        resolve_contract_name(str(name)) for name in result.evidence_publications
    }
    output_names = {
        resolve_contract_name(str(name)) for name in result.evidence_outputs
    }
    unpaired = tuple(sorted(publication_names.difference(output_names)))
    if unpaired:
        raise PassContractError(
            f"pass {spec.pass_id!r} published evidence metadata without evidence "
            f"output {list(unpaired)}",
            diagnostics=(
                PassContractDiagnostic(
                    pass_id=spec.pass_id,
                    namespace="outputs.evidence_publications",
                    undeclared=unpaired,
                    available=tuple(sorted(result.evidence_outputs)),
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
    observer = ctx.capabilities.optional(PassContractEvidenceObserver)
    publications = {
        resolve_contract_name(str(token)): publication
        for token, publication in result.evidence_publications.items()
    }
    for name, value in result.evidence_outputs.items():
        ctx.facts.put_evidence(str(name), value)
        publication = publications.get(resolve_contract_name(str(name)))
        if publication is None or observer is None:
            continue
        try:
            observer.observe_contract_evidence(
                pass_id=spec.pass_id,
                evidence_token=resolve_contract_name(str(name)),
                function_ea=int(ctx.source.func_ea),
                producer_stage_id=ctx.maturity.value,
                publication=publication,
            )
        except Exception:
            # Observability is additive: a sink failure cannot alter pass execution.
            continue


def validate_backend_route(spec: PassSpec, result) -> None:
    """Require one declared authority route for each pass result."""
    has_rewrite_plan = _plan_has_work(result.rewrite_plan)
    has_fragment_plan = result.fragment_plan is not None
    if spec.backend_route is BackendRoute.ANALYSIS_ONLY:
        if has_rewrite_plan or has_fragment_plan:
            raise BackendRouteError(
                f"analysis-only pass {spec.pass_id!r} produced mutation work"
            )
        return
    if spec.backend_route is BackendRoute.MUTATION_BACKEND:
        if has_fragment_plan:
            raise BackendRouteError(
                f"mutation-backend pass {spec.pass_id!r} produced fragment "
                "publication work"
            )
        return
    if spec.backend_route is BackendRoute.FRAGMENT_PUBLICATION and has_rewrite_plan:
        raise BackendRouteError(
            f"fragment-publication pass {spec.pass_id!r} produced a rewrite plan"
        )


def effective_preserved_analyses(spec: PassSpec, result) -> PreservedAnalyses:
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


# Exceptions raised by the *declared-prerequisite* validation gates above
# (backend capability, native-contract capability/analyses/facts/evidence)
# mean "this pass's own declared preconditions are not satisfiable in this
# context" -- an expected, designed gate, not a bug in the pass. The generic
# driver records that outcome as ABSTAINED. Everything else (an unexpected
# exception raised by ``PipelinePass.run()`` itself, a route contract the
# pass's own result violated, a backend/facts failure while applying its
# plan) is recorded as FAILED. Both re-raise the original exception
# unchanged -- see ``_run_pass_spec``.
_ABSTAIN_EXCEPTION_TYPES: tuple[type[BaseException], ...] = (
    CapabilityError,
    AnalysisContractError,
    PassContractError,
)

#: Reason code recorded for a config-v2 pass present in the configured
#: pipeline but filtered out by ``PassSpec.enabled_at(maturity)`` before it
#: ever reached ``_run_pass_spec`` -- so it never validated, ran, or failed.
NOT_SCHEDULED_AT_MATURITY_REASON = "not_scheduled_at_maturity"


def _reason_code_for_exception(exc: BaseException) -> str:
    return f"{type(exc).__name__}: {exc}"


def _safe_begin_attempt(
    journal: ExecutionJournalStore,
    session_id: DecompilationSessionId,
    *,
    parent_attempt_id: ExecutionAttemptId | None,
    stage_id: str,
    domain: ExecutionDomain,
) -> ExecutionAttempt | None:
    """Record a STARTED attempt; never let a journal failure block a pass.

    Attempt recording is additive provenance, not pass authority: a store
    failure (disk full, a schema surprise, ...) must never prevent -- or
    change the outcome of -- the pass execution it is only observing.
    """
    try:
        return journal.begin_attempt(
            session_id,
            parent_attempt_id=parent_attempt_id,
            stage_id=stage_id,
            domain=domain,
        )
    except Exception:
        logger.debug(
            "execution journal: failed to begin attempt for stage=%s",
            stage_id,
            exc_info=True,
        )
        return None


def _safe_advance(
    journal: ExecutionJournalStore,
    attempt: ExecutionAttempt | None,
    *,
    status: ExecutionAttemptStatus,
    reason_code: str | None = None,
    effect_refs: tuple[ExecutionEffectRef, ...] | None = None,
) -> None:
    """Advance a recorded attempt; never let a journal failure propagate."""
    if attempt is None:
        return
    try:
        journal.advance(
            attempt,
            status=status,
            reason_code=reason_code,
            effect_refs=effect_refs,
        )
    except Exception:
        logger.debug(
            "execution journal: failed to advance attempt stage=%s",
            attempt.stage_id,
            exc_info=True,
        )


def _run_pass_spec(
    *,
    spec: PassSpec,
    ctx: FunctionPipelineContext,
    backend,
    facts,
    scheduler: PassScheduler | None,
    journal: ExecutionJournalStore | None = None,
    session_id: DecompilationSessionId | None = None,
    parent_attempt_id: ExecutionAttemptId | None = None,
) -> FunctionPipelineContext:
    attempt: ExecutionAttempt | None = None
    if journal is not None and session_id is not None:
        attempt = _safe_begin_attempt(
            journal,
            session_id,
            parent_attempt_id=parent_attempt_id,
            stage_id=spec.pass_id,
            domain=ExecutionDomain.PASS,
        )
    effect_refs: tuple[ExecutionEffectRef, ...] = ()
    try:
        validate_capabilities(backend, spec.requirements)
        validate_contract_capabilities(spec, backend)
        validate_required_analyses(spec, ctx)
        validate_native_contract(spec, ctx)
        result = spec.pass_factory().run(ctx)
        validate_analysis_outputs(spec, result)
        validate_contract_fact_outputs(spec, result)
        validate_contract_evidence_outputs(spec, result)
        validate_backend_route(spec, result)

        def publish_result_side_effects() -> None:
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

        defer_result_side_effects = (
            spec.backend_route is BackendRoute.FRAGMENT_PUBLICATION
            and result.fragment_plan is not None
        )
        if not defer_result_side_effects:
            publish_result_side_effects()
        if _plan_has_work(result.rewrite_plan):
            new_graph = backend.apply(
                result.rewrite_plan,
                ctx.source.live_source,
                effective_safety_policy(spec),
            )
            if _graph_changed(ctx.graph, new_graph):
                facts.invalidate_to(
                    new_graph, effective_preserved_analyses(spec, result)
                )
                if hasattr(facts, "invalidate_contract"):
                    facts.invalidate_contract(spec.contract)
                ctx = replace(ctx, graph=new_graph)
                effect_refs = effect_refs + (
                    ExecutionEffectRef(kind="rewrite_plan", ref_id=uuid.uuid4().hex),
                )
        fragment_plan = result.fragment_plan
        if fragment_plan is not None:
            new_graph = backend.apply(
                fragment_plan,
                ctx.source.live_source,
                effective_safety_policy(spec),
            )
            if _graph_changed(ctx.graph, new_graph):
                facts.invalidate_to(
                    new_graph,
                    effective_preserved_analyses(spec, result),
                )
                if hasattr(facts, "invalidate_contract"):
                    facts.invalidate_contract(spec.contract)
                ctx = replace(ctx, graph=new_graph)
                effect_refs = effect_refs + (
                    ExecutionEffectRef(kind="fragment_plan", ref_id=uuid.uuid4().hex),
                )
        if defer_result_side_effects:
            publish_result_side_effects()
    except BaseException as exc:
        status = (
            ExecutionAttemptStatus.ABSTAINED
            if isinstance(exc, _ABSTAIN_EXCEPTION_TYPES)
            else ExecutionAttemptStatus.FAILED
        )
        _safe_advance(
            journal,
            attempt,
            status=status,
            reason_code=_reason_code_for_exception(exc),
        )
        raise
    _safe_advance(
        journal,
        attempt,
        status=ExecutionAttemptStatus.COMPLETED,
        effect_refs=effect_refs,
    )
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
    session_id: DecompilationSessionId | None = None,
    journal: ExecutionJournalStore | None = None,
    parent_attempt_id: ExecutionAttemptId | None = None,
):
    """Run one family's pipeline over one function/maturity. Returns the final graph.

    Mirrors unflatten ``run_d810_pipeline`` minus the lift/select bootstrap (the shell does those).
    ``capabilities`` is the backend-provided :class:`CapabilitySet` (typed capability instances)
    threaded into every pass's context; ``None`` -> an empty set (passes that only query
    ``optional`` are unaffected).

    ``journal``/``session_id``/``parent_attempt_id`` are the generic execution-
    provenance wiring: when ``journal`` is supplied for a **config-v2**
    execution (``pipeline_v2_specs`` is not ``None``), every pass in the
    configured pipeline gets a mandatory outer :class:`~d810.core.
    execution_journal.ExecutionAttempt` record -- one that runs, safely
    abstains (its own declared prerequisites were not met), fails, or is not
    scheduled at the current maturity -- with no exception yet raised by
    ``run_pipeline`` ever recorded, this exists purely to persist provenance
    around it. Legacy family-detected pipelines (``pipeline_v2_specs`` is
    ``None``) never record attempts, even if a journal is supplied -- see the
    plan's Task 3, "mandatory outer execution attempt for config-v2 passes".
    ``session_id`` defaults to a fresh session scoped to this one call when a
    ``journal`` is given without one.
    """
    if journal is not None and session_id is None:
        session_id = DecompilationSessionId.new()
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

    # Attempt recording is mandatory for config-v2 execution only -- a
    # legacy family-detected pipeline never records attempts, even when a
    # caller supplies a journal (see the ``run_pipeline`` docstring).
    record_attempts = pipeline_v2_specs is not None and journal is not None
    effective_journal = journal if record_attempts else None

    for spec in worklist:
        ctx = _run_pass_spec(
            spec=spec,
            ctx=ctx,
            backend=backend,
            facts=facts,
            scheduler=scheduler,
            journal=effective_journal,
            session_id=session_id if record_attempts else None,
            parent_attempt_id=parent_attempt_id,
        )

    for spec in replay_after_pipeline:
        ctx = _run_pass_spec(
            spec=spec,
            ctx=ctx,
            backend=backend,
            facts=facts,
            scheduler=scheduler,
            journal=effective_journal,
            session_id=session_id if record_attempts else None,
            parent_attempt_id=parent_attempt_id,
        )

    if record_attempts:
        scheduled_ids = {spec.pass_id for spec in worklist}
        scheduled_ids.update(spec.pass_id for spec in replay_after_pipeline)
        for spec in specs:
            if spec.pass_id in scheduled_ids:
                continue
            attempt = _safe_begin_attempt(
                effective_journal,
                session_id,
                parent_attempt_id=parent_attempt_id,
                stage_id=spec.pass_id,
                domain=ExecutionDomain.PASS,
            )
            _safe_advance(
                effective_journal,
                attempt,
                status=ExecutionAttemptStatus.ABSTAINED,
                reason_code=NOT_SCHEDULED_AT_MATURITY_REASON,
            )
    return ctx.graph
