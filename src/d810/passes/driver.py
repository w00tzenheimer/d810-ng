"""``run_pipeline`` — the unflatten driver loop, portable + injected-dependency form.

The maturity-hook shell in ``optimizers/`` supplies the live Hex-Rays ``MutationBackend`` and the
lifted ``FunctionSource``; this function is the portable orchestration from the north-star
pseudocode (spec unflatten):

    for spec in pipeline_v2_specs:
        validate_capabilities; result = spec.pass_factory().run(ctx)
        if result.rewrite_plan has work: ctx = ctx(graph=backend.apply(...)); facts.invalidate_to(...)
        elif result.fragment_plan: ctx = ctx(graph=backend.apply(...)); facts.invalidate_to(...)

Fragment publication defers pass-output visibility until the backend returns a
committed, postvalidated graph snapshot. The live backend + lifter are supplied
from ``backends/hexrays``; everything here remains portable.
"""

from __future__ import annotations

from dataclasses import dataclass, replace

from d810.core.typing import Protocol, runtime_checkable
from d810.capabilities.native_cfg_normalization import NativeCfgFreezeObserver
from d810.capabilities.pass_contract_evidence import PassContractEvidenceObserver
from d810.capabilities.resolver import CapabilityNotProvided, CapabilitySet
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
from d810.ir.flowgraph import FlowGraph
from d810.ir.maturity import IRMaturity
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
    PassSpec,
    PreservedAnalyses,
    SafetyPolicy,
    SchedulerPolicy,
    require_pipeline_v2_specs,
)
from d810.passes.scheduler import PassScheduler, RunLaterDomain
from d810.transforms.cfg_transaction import CfgGenerationPoisoned
from d810.transforms.native_cfg_normalization import (
    NativeCfgPassMutationObservation,
    ObservedEdgeStateContract,
)
from d810.transforms.plan import PatchPlan

logger = getLogger("d810.passes.driver")

# Keep this key aligned with the transform-owned plan metadata.  The driver
# consumes it only after the backend reports a changed graph; plan membership
# alone is never an applied-route receipt.
NATIVE_BOUND_TRANSITION_ROUTE_RECEIPTS_METADATA = (
    "native_bound_transition_route_receipts"
)


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


@dataclass
class _NativeCfgObserverRunState:
    observer: NativeCfgFreezeObserver
    failed: bool = False


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


def _backend_mutation_receipt(backend: object) -> object | None:
    """Return the backend's receipt for the most recent committed apply."""
    receipt = getattr(backend, "last_mutation_receipt", None)
    if receipt is not None:
        return receipt
    execution = getattr(backend, "last_patch_execution", None)
    return getattr(execution, "receipt", None)


def _validated_route_operation_key(
    value: object,
) -> tuple[str, int, int | None, int | None] | None:
    if not isinstance(value, tuple) or len(value) != 4:
        return None
    mutation_kind, source_serial, old_target_serial, target_serial = value
    if not isinstance(mutation_kind, str) or not mutation_kind.strip():
        return None
    if any(separator in mutation_kind for separator in ("\x00", "\n", "\r")):
        return None

    def _serial(candidate: object) -> int | None:
        if candidate is None:
            return None
        if (
            not isinstance(candidate, int)
            or isinstance(candidate, bool)
            or candidate < 0
        ):
            return None
        return int(candidate)

    source = _serial(source_serial)
    if source is None:
        return None
    old_target = _serial(old_target_serial)
    if old_target_serial is not None and old_target is None:
        return None
    target = _serial(target_serial)
    if target_serial is not None and target is None:
        return None
    return (mutation_kind.strip(), source, old_target, target)


def _committed_operation_keys(
    mutation_receipt: object | None,
) -> tuple[tuple[str, int, int | None, int | None], ...] | None:
    if mutation_receipt is None:
        return None
    inventory = getattr(mutation_receipt, "committed_operation_inventory", None)
    if not isinstance(inventory, tuple):
        return None
    keys: list[tuple[str, int, int | None, int | None]] = []
    for item in inventory:
        raw_key = getattr(item, "operation_key", None)
        key = _validated_route_operation_key(raw_key)
        if raw_key is not None and key is None:
            return None
        if key is not None:
            keys.append(key)
    return tuple(keys)


def _log_applied_native_bound_route_receipts(
    plan: PatchPlan | object,
    *,
    pre_graph: object,
    new_graph: object,
    mutation_status: ExecutionAttemptStatus,
    mutation_receipt: object | None,
) -> None:
    """Log route receipts only after a changed graph was committed by apply."""
    if (
        mutation_status is not ExecutionAttemptStatus.COMPLETED
        or not _graph_changed(pre_graph, new_graph)
        or not logger.info_on
    ):
        return
    metadata_dict = getattr(plan, "metadata_dict", None)
    if not callable(metadata_dict):
        return
    try:
        metadata = metadata_dict()
    except Exception:
        return
    if not isinstance(metadata, dict):
        return
    receipts = metadata.get(NATIVE_BOUND_TRANSITION_ROUTE_RECEIPTS_METADATA)
    if not isinstance(receipts, tuple):
        return
    committed_operation_keys = _committed_operation_keys(mutation_receipt)
    if committed_operation_keys is None:
        return
    logged_operation_keys: set[tuple[str, int, int | None, int | None]] = set()
    for receipt in receipts:
        if not isinstance(receipt, dict):
            continue
        fact_id = receipt.get("fact_id")
        native_ea = receipt.get("native_ea")
        native_ea_hex = receipt.get("native_ea_hex")
        current_block = receipt.get("current_block")
        state = receipt.get("state")
        target = receipt.get("target")
        target_block = receipt.get("target_block")
        operation_key = _validated_route_operation_key(receipt.get("operation_key"))
        if (
            not isinstance(fact_id, str)
            or not fact_id
            or not isinstance(native_ea, int)
            or isinstance(native_ea, bool)
            or not 0 <= native_ea < 0xFFFFFFFFFFFFFFFF
            or native_ea_hex != f"0x{native_ea:X}"
            or not isinstance(current_block, str)
            or not current_block
            or not isinstance(state, int)
            or isinstance(state, bool)
            or not 0 <= state <= 0xFFFFFFFF
            or not isinstance(target, int)
            or isinstance(target, bool)
            or target < 0
            or not isinstance(target_block, str)
            or not target_block
            or operation_key is None
            or committed_operation_keys.count(operation_key) != 1
            or operation_key in logged_operation_keys
        ):
            continue
        logged_operation_keys.add(operation_key)
        logger.info(
            "native-bound transition route receipt: fact_id=%s native_ea=%s "
            "current=%s state=0x%08X target=%s",
            fact_id,
            native_ea_hex,
            current_block,
            state,
            target_block,
        )


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
    CapabilityNotProvided,
    AnalysisContractError,
    PassContractError,
)

#: Reason code recorded for a config-v2 pass present in the configured
#: pipeline but filtered out by ``PassSpec.enabled_at(maturity)`` before it
#: ever reached ``_run_pass_spec`` -- so it never validated, ran, or failed.
NOT_SCHEDULED_AT_MATURITY_REASON = "not_scheduled_at_maturity"


def _reason_code_for_exception(exc: BaseException) -> str:
    return f"{type(exc).__name__}: {exc}"


def _maturity_detail(phase_token: object) -> str:
    """Return a portable maturity label for execution provenance."""
    value = getattr(phase_token, "value", None)
    return str(value) if isinstance(value, str) and value else "unknown"


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
    details: dict[str, object] | None = None,
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
            details=details,
        )
    except Exception:
        logger.debug(
            "execution journal: failed to advance attempt stage=%s",
            attempt.stage_id,
            exc_info=True,
        )


def _mutation_status_for_error(exc: BaseException) -> ExecutionAttemptStatus:
    if isinstance(exc, CfgGenerationPoisoned):
        return ExecutionAttemptStatus.POISONED_RESTART_REQUIRED
    if type(exc).__name__ == "PatchTransactionPreflightRejected":
        return ExecutionAttemptStatus.REJECTED
    return ExecutionAttemptStatus.FAILED


def _plan_effect_ref(plan: PatchPlan | object, *, kind: str) -> ExecutionEffectRef:
    plan_id = str(getattr(plan, "plan_id", "") or "")
    if not plan_id:
        raise TypeError("mutation plan must expose a non-empty plan_id")
    steps = getattr(plan, "steps", ())
    operations = getattr(plan, "operations", ())
    detail: dict[str, object] = {"step_count": len(steps)}
    if operations:
        detail["operation_count"] = len(operations)
    return ExecutionEffectRef(
        kind=kind,
        ref_id=plan_id,
        detail=detail,
    )


def _backend_receipt_effect(backend: object) -> ExecutionEffectRef | None:
    """Extract a stable receipt summary without retaining a live backend object."""
    receipt = _backend_mutation_receipt(backend)
    if receipt is None:
        return None
    receipt_id = str(
        getattr(receipt, "mutation_batch_id", "")
        or getattr(getattr(receipt, "transaction_id", None), "value", "")
        or ""
    )
    if not receipt_id:
        return None
    detail: dict[str, object] = {}
    for field in (
        "operation_count",
        "planned_operation_count",
        "pre_generation",
        "post_generation",
        "evidence_generation",
    ):
        value = getattr(receipt, field, None)
        if isinstance(value, int) and not isinstance(value, bool):
            detail[field] = value
    return ExecutionEffectRef(
        kind="mutation_receipt",
        ref_id=receipt_id,
        detail=detail,
    )


def _valid_native_cfg_edge_contracts(
    contracts: tuple[ObservedEdgeStateContract, ...],
    *,
    pre_graph: object,
    post_graph: object,
) -> bool:
    """Require exact positive contracts against the observed graph transition."""
    if (
        not contracts
        or not isinstance(pre_graph, FlowGraph)
        or not isinstance(post_graph, FlowGraph)
    ):
        return False
    source_blocks: set[int] = set()
    for observed in contracts:
        if observed.source_block in source_blocks:
            return False
        source_blocks.add(observed.source_block)
        pre_block = pre_graph.blocks.get(observed.source_block)
        post_block = post_graph.blocks.get(observed.source_block)
        if (
            pre_block is None
            or post_block is None
            or tuple(pre_block.succs) != observed.inherited_successors
            or tuple(post_block.succs) != observed.final_successors
            or observed.inherited_successors == observed.final_successors
            or not observed.contract.permits_control_only_relink
        ):
            return False
    return True


def _observe_native_cfg_mutation(
    *,
    state: _NativeCfgObserverRunState | None,
    spec: PassSpec,
    maturity: IRMaturity | None,
    pre_graph: object,
    post_graph: object,
    plan: PatchPlan,
    mutation_status: ExecutionAttemptStatus,
    mutation_effects: tuple[ExecutionEffectRef, ...],
    edge_state_contracts: tuple[ObservedEdgeStateContract, ...],
    journal: ExecutionJournalStore | None,
    session_id: DecompilationSessionId | None,
    parent_attempt_id: ExecutionAttemptId | None,
) -> None:
    if (
        state is None
        or state.failed
        or spec.options.get("native_cfg_persistence") is not True
        or mutation_status is not ExecutionAttemptStatus.COMPLETED
        or not isinstance(maturity, IRMaturity)
        or not _valid_native_cfg_edge_contracts(
            edge_state_contracts,
            pre_graph=pre_graph,
            post_graph=post_graph,
        )
    ):
        return
    receipt_ref = next(
        (
            effect
            for effect in reversed(mutation_effects)
            if effect.kind == "mutation_receipt"
        ),
        None,
    )
    if receipt_ref is None:
        return
    observer_attempt = None
    if journal is not None and session_id is not None:
        observer_attempt = _safe_begin_attempt(
            journal,
            session_id,
            parent_attempt_id=parent_attempt_id,
            stage_id=f"native-cfg-observer:{spec.pass_id}",
            domain=ExecutionDomain.NATIVE_NORMALIZATION,
        )
    try:
        state.observer.observe_native_cfg_mutation(
            NativeCfgPassMutationObservation(
                pass_id=spec.pass_id,
                maturity=maturity,
                pre_graph=pre_graph,
                post_graph=post_graph,
                plan_fingerprint=plan.plan_id,
                receipt_ref=receipt_ref,
                edge_state_contracts=edge_state_contracts,
            )
        )
    except BaseException as exc:
        state.failed = True
        _safe_advance(
            journal,
            observer_attempt,
            status=ExecutionAttemptStatus.FAILED,
            reason_code=_reason_code_for_exception(exc),
            effect_refs=(receipt_ref,),
            details={"pass_id": spec.pass_id},
        )
        logger.warning(
            "native CFG observer rejected pass %s; Stage C disabled for this run",
            spec.pass_id,
            exc_info=True,
        )
        return
    _safe_advance(
        journal,
        observer_attempt,
        status=ExecutionAttemptStatus.COMPLETED,
        effect_refs=(receipt_ref,),
        details={"pass_id": spec.pass_id},
    )


def _apply_with_journal(
    *,
    backend,
    plan: PatchPlan | object,
    live_source: object,
    safety_policy: SafetyPolicy,
    journal: ExecutionJournalStore | None,
    session_id: DecompilationSessionId | None,
    parent_attempt_id: ExecutionAttemptId | None,
    stage_id: str,
    plan_effect_kind: str,
    pre_graph: object,
    profile_details: dict[str, object],
) -> tuple[object, tuple[ExecutionEffectRef, ...], ExecutionAttemptStatus, str | None]:
    """Apply one config-v2 mutation plan with a child receipt attempt.

    The backend remains the only mutation authority.  This wrapper observes
    its plan, terminal failure, and receipt without changing its return or
    exception contract.
    """
    plan_effect = _plan_effect_ref(plan, kind=plan_effect_kind)
    mutation_attempt = None
    if journal is not None and session_id is not None:
        mutation_attempt = _safe_begin_attempt(
            journal,
            session_id,
            parent_attempt_id=parent_attempt_id,
            stage_id=stage_id,
            domain=ExecutionDomain.MUTATION,
        )
    try:
        new_graph = backend.apply(plan, live_source, safety_policy)
    except BaseException as exc:
        status = _mutation_status_for_error(exc)
        reason_code = _reason_code_for_exception(exc)
        _safe_advance(
            journal,
            mutation_attempt,
            status=status,
            reason_code=reason_code,
            effect_refs=(plan_effect,),
            details=profile_details,
        )
        raise

    backend_failure = getattr(backend, "last_patch_failure", None)
    if isinstance(backend_failure, BaseException):
        status = _mutation_status_for_error(backend_failure)
        reason_code = _reason_code_for_exception(backend_failure)
        _safe_advance(
            journal,
            mutation_attempt,
            status=status,
            reason_code=reason_code,
            effect_refs=(plan_effect,),
            details=profile_details,
        )
        return new_graph, (plan_effect,), status, reason_code

    receipt_effect = _backend_receipt_effect(backend)
    effects = (
        (plan_effect,) if receipt_effect is None else (plan_effect, receipt_effect)
    )
    changed = _graph_changed(pre_graph, new_graph)
    status = (
        ExecutionAttemptStatus.COMPLETED
        if changed
        else ExecutionAttemptStatus.ABSTAINED
    )
    reason_code = None if changed else "no_graph_change"
    _safe_advance(
        journal,
        mutation_attempt,
        status=status,
        reason_code=reason_code,
        effect_refs=effects,
        details={**profile_details, "graph_changed": changed},
    )
    return new_graph, effects, status, reason_code


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
    structural_shape: str = "unclassified",
    native_cfg_observer_state: _NativeCfgObserverRunState | None = None,
) -> FunctionPipelineContext:
    profile_details = {
        "maturity": _maturity_detail(ctx.maturity),
        "structural_shape": str(structural_shape),
    }
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
        # A nested solver or backend adapter inherits the exact attempt that
        # invoked this pass.  It may record child provenance but cannot create
        # a session or turn a journal record into mutation authority.
        pass_context = replace(
            ctx,
            execution_journal=journal,
            execution_parent_attempt_id=(
                None if attempt is None else attempt.attempt_id
            ),
        )
        result = spec.pass_factory().run(pass_context)
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
        terminal_status = ExecutionAttemptStatus.COMPLETED
        terminal_reason: str | None = None
        if _plan_has_work(result.rewrite_plan):
            pre_mutation_graph = ctx.graph
            new_graph, mutation_effects, mutation_status, mutation_reason = (
                _apply_with_journal(
                    backend=backend,
                    plan=result.rewrite_plan,
                    live_source=ctx.source.live_source,
                    safety_policy=effective_safety_policy(spec),
                    journal=journal,
                    session_id=session_id,
                    parent_attempt_id=(None if attempt is None else attempt.attempt_id),
                    stage_id=f"mutation:{spec.pass_id}:rewrite",
                    plan_effect_kind="rewrite_plan",
                    pre_graph=ctx.graph,
                    profile_details=profile_details,
                )
            )
            effect_refs = effect_refs + mutation_effects
            _log_applied_native_bound_route_receipts(
                result.rewrite_plan,
                pre_graph=pre_mutation_graph,
                new_graph=new_graph,
                mutation_status=mutation_status,
                mutation_receipt=_backend_mutation_receipt(backend),
            )
            _observe_native_cfg_mutation(
                state=native_cfg_observer_state,
                spec=spec,
                maturity=ctx.maturity,
                pre_graph=pre_mutation_graph,
                post_graph=new_graph,
                plan=result.rewrite_plan,
                mutation_status=mutation_status,
                mutation_effects=mutation_effects,
                edge_state_contracts=result.native_cfg_edge_contracts,
                journal=journal,
                session_id=session_id,
                parent_attempt_id=(None if attempt is None else attempt.attempt_id),
            )
            if mutation_status is not ExecutionAttemptStatus.COMPLETED:
                terminal_status = mutation_status
                terminal_reason = mutation_reason
            if _graph_changed(ctx.graph, new_graph):
                facts.invalidate_to(
                    new_graph, effective_preserved_analyses(spec, result)
                )
                if hasattr(facts, "invalidate_contract"):
                    facts.invalidate_contract(spec.contract)
                ctx = replace(ctx, graph=new_graph)
        fragment_plan = result.fragment_plan
        if fragment_plan is not None:
            new_graph, mutation_effects, mutation_status, mutation_reason = (
                _apply_with_journal(
                    backend=backend,
                    plan=fragment_plan,
                    live_source=ctx.source.live_source,
                    safety_policy=effective_safety_policy(spec),
                    journal=journal,
                    session_id=session_id,
                    parent_attempt_id=(None if attempt is None else attempt.attempt_id),
                    stage_id=f"mutation:{spec.pass_id}:fragment",
                    plan_effect_kind="fragment_plan",
                    pre_graph=ctx.graph,
                    profile_details=profile_details,
                )
            )
            effect_refs = effect_refs + mutation_effects
            _log_applied_native_bound_route_receipts(
                fragment_plan,
                pre_graph=ctx.graph,
                new_graph=new_graph,
                mutation_status=mutation_status,
                mutation_receipt=_backend_mutation_receipt(backend),
            )
            _observe_native_cfg_mutation(
                state=native_cfg_observer_state,
                spec=spec,
                maturity=ctx.maturity,
                pre_graph=ctx.graph,
                post_graph=new_graph,
                plan=fragment_plan,
                mutation_status=mutation_status,
                mutation_effects=mutation_effects,
                edge_state_contracts=result.native_cfg_edge_contracts,
                journal=journal,
                session_id=session_id,
                parent_attempt_id=(None if attempt is None else attempt.attempt_id),
            )
            if mutation_status is not ExecutionAttemptStatus.COMPLETED:
                terminal_status = mutation_status
                terminal_reason = mutation_reason
            if _graph_changed(ctx.graph, new_graph):
                facts.invalidate_to(
                    new_graph,
                    effective_preserved_analyses(spec, result),
                )
                if hasattr(facts, "invalidate_contract"):
                    facts.invalidate_contract(spec.contract)
                ctx = replace(ctx, graph=new_graph)
        if defer_result_side_effects:
            publish_result_side_effects()
    except BaseException as exc:
        status = _mutation_status_for_error(exc)
        if status is ExecutionAttemptStatus.FAILED:
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
            details=profile_details,
        )
        raise
    _safe_advance(
        journal,
        attempt,
        status=terminal_status,
        reason_code=terminal_reason,
        effect_refs=effect_refs,
        details=profile_details,
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


def _freeze_native_cfg_observer(
    *,
    state: _NativeCfgObserverRunState | None,
    function_ea: int,
    maturity: IRMaturity | None,
    baseline_graph: object,
    final_graph: object,
    scheduled_pass_ids: tuple[str, ...],
    journal: ExecutionJournalStore | None,
    session_id: DecompilationSessionId | None,
    parent_attempt_id: ExecutionAttemptId | None,
) -> None:
    if (
        state is None
        or state.failed
        or not isinstance(maturity, IRMaturity)
        or not isinstance(baseline_graph, FlowGraph)
        or not isinstance(final_graph, FlowGraph)
    ):
        return
    freeze_attempt = None
    if journal is not None and session_id is not None:
        freeze_attempt = _safe_begin_attempt(
            journal,
            session_id,
            parent_attempt_id=parent_attempt_id,
            stage_id="native-cfg-freeze",
            domain=ExecutionDomain.NATIVE_NORMALIZATION,
        )
    try:
        topology = state.observer.freeze_native_cfg_topology(
            function_ea=function_ea,
            maturity=maturity,
            baseline_graph=baseline_graph,
            final_graph=final_graph,
            scheduled_pass_ids=scheduled_pass_ids,
        )
    except BaseException as exc:
        state.failed = True
        _safe_advance(
            journal,
            freeze_attempt,
            status=ExecutionAttemptStatus.FAILED,
            reason_code=_reason_code_for_exception(exc),
            details={"scheduled_pass_ids": scheduled_pass_ids},
        )
        logger.warning(
            "native CFG topology freeze failed; Stage C disabled for this run",
            exc_info=True,
        )
        return
    _safe_advance(
        journal,
        freeze_attempt,
        status=(
            ExecutionAttemptStatus.COMPLETED
            if topology is not None
            else ExecutionAttemptStatus.ABSTAINED
        ),
        reason_code=None if topology is not None else "no_eligible_cfg_changes",
        details={"scheduled_pass_ids": scheduled_pass_ids},
    )


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
    pipeline_v2_specs: tuple[PassSpec, ...] | None = None,
    session_id: DecompilationSessionId | None = None,
    journal: ExecutionJournalStore | None = None,
    parent_attempt_id: ExecutionAttemptId | None = None,
    structural_shape: str = "unclassified",
):
    """Run one family's pipeline over one function/maturity. Returns the final graph.

    Mirrors unflatten ``run_d810_pipeline`` minus the lift/select bootstrap (the shell does those).
    ``capabilities`` is the backend-provided :class:`CapabilitySet` (typed capability instances)
    threaded into every pass's context; ``None`` -> an empty set (passes that only query
    ``optional`` are unaffected).

    ``journal``/``session_id``/``parent_attempt_id`` are the generic execution-
    provenance wiring: when ``journal`` is supplied, every pass in the
    configured pipeline gets a mandatory outer :class:`~d810.core.
    execution_journal.ExecutionAttempt` record -- one that runs, safely
    abstains (its own declared prerequisites were not met), fails, or is not
    scheduled at the current maturity -- with no exception yet raised by
    ``run_pipeline`` ever recorded, this exists purely to persist provenance
    around it.
    ``session_id`` defaults to a fresh session scoped to this one call when a
    ``journal`` is given without one.
    """
    specs = require_pipeline_v2_specs(pipeline_v2_specs)
    if journal is not None and session_id is None:
        session_id = DecompilationSessionId.new()
    graph = source.flow_graph
    baseline_graph = graph
    ctx = FunctionPipelineContext(
        source=source,
        graph=graph,
        maturity=maturity,
        project_config=project_config,
        facts=facts.view(),
        capabilities=capabilities if capabilities is not None else CapabilitySet(),
    )
    worklist, replay_after_pipeline = _build_pass_worklists(
        specs=specs,
        scheduler=scheduler,
        ctx=ctx,
    )

    # Every execution is config-v2 and therefore participates in journal
    # provenance whenever a journal is supplied.
    record_attempts = journal is not None
    effective_journal = journal if record_attempts else None
    native_cfg_observer_state = None
    observer = ctx.capabilities.optional(NativeCfgFreezeObserver)
    if observer is not None:
        native_cfg_observer_state = _NativeCfgObserverRunState(observer=observer)

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
            structural_shape=structural_shape,
            native_cfg_observer_state=native_cfg_observer_state,
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
            structural_shape=structural_shape,
            native_cfg_observer_state=native_cfg_observer_state,
        )

    _freeze_native_cfg_observer(
        state=native_cfg_observer_state,
        function_ea=source.func_ea,
        maturity=ctx.maturity,
        baseline_graph=baseline_graph,
        final_graph=ctx.graph,
        scheduled_pass_ids=tuple(
            spec.pass_id for spec in (*worklist, *replay_after_pipeline)
        ),
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
                details={
                    "maturity": _maturity_detail(ctx.maturity),
                    "structural_shape": str(structural_shape),
                },
            )
    return ctx.graph
