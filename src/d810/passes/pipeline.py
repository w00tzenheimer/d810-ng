"""PassPipeline orchestrator for running FlowGraphTransform transforms through a CFGBackend.

The pipeline lifts backend state to FlowGraph, runs each pass's transform,
compiles the resulting modifications to PatchPlan, and delegates the complete
transaction to one runtime port.
"""

from __future__ import annotations

from collections.abc import Mapping

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
from d810.core.typing import Any
from d810.ir.maturity import MaturityEnvelope

from d810.transforms.cfg_transaction import (
    CfgGenerationPoisoned,
    PatchPlanExecutionResult,
)
from d810.transforms.plan import compile_patch_plan
from d810.transforms._base import FlowGraphTransform
from d810.transforms.protocol import PatchPlanRuntime

logger = getLogger(__name__, default_level=0)  # NOTSET: inherit from parent


def _safe_begin_attempt(
    journal: ExecutionJournalStore | None,
    session_id: DecompilationSessionId | None,
    *,
    parent_attempt_id: ExecutionAttemptId | None,
    stage_id: str,
    domain: ExecutionDomain,
) -> ExecutionAttempt | None:
    """Record provenance without giving a journal failure execution authority."""
    if journal is None or session_id is None:
        return None
    try:
        return journal.begin_attempt(
            session_id,
            parent_attempt_id=parent_attempt_id,
            stage_id=stage_id,
            domain=domain,
        )
    except Exception:
        logger.debug(
            "execution journal: failed to begin stage=%s",
            stage_id,
            exc_info=True,
        )
        return None


def _safe_advance_attempt(
    journal: ExecutionJournalStore | None,
    attempt: ExecutionAttempt | None,
    *,
    status: ExecutionAttemptStatus,
    reason_code: str | None = None,
    effect_refs: tuple[ExecutionEffectRef, ...] = (),
    details: Mapping[str, object] | None = None,
) -> None:
    """Terminally record provenance without masking the transform outcome."""
    if journal is None or attempt is None:
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
            "execution journal: failed to advance stage=%s",
            attempt.stage_id,
            exc_info=True,
        )


def _status_for_execution_error(exc: BaseException) -> ExecutionAttemptStatus:
    """Map the portable transaction failure taxonomy onto journal outcomes.

    ``PatchTransactionPreflightRejected`` lives in the Hex-Rays adapter layer,
    which a portable transform pipeline must not import.  Its stable type name
    is the adapter boundary: a future portable rejection base can replace this
    check without changing the persisted vocabulary.
    """
    if isinstance(exc, CfgGenerationPoisoned):
        return ExecutionAttemptStatus.POISONED_RESTART_REQUIRED
    if type(exc).__name__ == "PatchTransactionPreflightRejected":
        return ExecutionAttemptStatus.REJECTED
    return ExecutionAttemptStatus.FAILED


def _plan_effect(plan) -> ExecutionEffectRef:
    return ExecutionEffectRef(
        kind="patch_plan",
        ref_id=plan.plan_id,
        detail={"step_count": len(plan.steps)},
    )


def _receipt_effect(execution: PatchPlanExecutionResult) -> ExecutionEffectRef | None:
    """Make a live mutation receipt queryable without retaining its SDK object."""
    receipt = getattr(execution, "receipt", None)
    if receipt is None:
        return None
    receipt_id = str(getattr(receipt, "mutation_batch_id", "") or "")
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
        kind="mba_mutation_receipt",
        ref_id=receipt_id,
        detail=detail,
    )


class FlowGraphTransformPipeline:
    """Run a sequence of FlowGraphTransform transforms through a CFGBackend.

    Usage:
        pipeline = PassPipeline(backend, [pass1, pass2, pass3])
        total_changes = pipeline.run(
            backend_state,
            mutation_gateway=mutation_gateway,
        )
    """

    def __init__(
        self,
        backend: PatchPlanRuntime,
        passes: list[FlowGraphTransform],
    ) -> None:
        if not isinstance(backend, PatchPlanRuntime):
            raise TypeError("FlowGraphTransformPipeline requires PatchPlanRuntime")
        self.backend = backend
        self.passes = list(passes)  # defensive copy

    def run(
        self,
        backend_state: Any,
        *,
        mutation_gateway: object,
        maturity: str | None = None,
        journal: ExecutionJournalStore | None = None,
        session_id: DecompilationSessionId | None = None,
        parent_attempt_id: ExecutionAttemptId | None = None,
    ) -> int:
        """Execute all transform against backend_state.

        Returns total count of applied modifications across all transform.
        """
        total = 0
        maturity_detail = {
            "maturity": (
                str(maturity)
                if isinstance(maturity, str) and maturity.strip()
                else "unknown"
            )
        }
        cfg = self.backend.lift(backend_state)

        for pass_ in self.passes:
            transform_stage_id = f"flow_transform:{pass_.name}"
            transform_attempt = _safe_begin_attempt(
                journal,
                session_id,
                parent_attempt_id=parent_attempt_id,
                stage_id=transform_stage_id,
                domain=ExecutionDomain.TRANSFORM,
            )
            try:
                if not pass_.is_applicable(cfg):
                    logger.debug("Pass %s not applicable, skipping", pass_.name)
                    _safe_advance_attempt(
                        journal,
                        transform_attempt,
                        status=ExecutionAttemptStatus.ABSTAINED,
                        reason_code="not_applicable",
                        details=maturity_detail,
                    )
                    continue

                mods = pass_.transform(cfg)
                if not mods:
                    logger.debug("Pass %s produced no modifications", pass_.name)
                    _safe_advance_attempt(
                        journal,
                        transform_attempt,
                        status=ExecutionAttemptStatus.ABSTAINED,
                        reason_code="no_modifications",
                        details=maturity_detail,
                    )
                    continue

                identity_index = getattr(mutation_gateway, "identity_index", None)
                if identity_index is None:
                    raise TypeError(
                        "FlowGraph transform compilation requires exact block authority"
                    )
                source_maturity_id = getattr(identity_index, "maturity", None)
                if source_maturity_id is None:
                    raise TypeError(
                        "FlowGraph transform compilation requires exact maturity authority"
                    )
                patch_plan = compile_patch_plan(
                    mods,
                    cfg,
                    snapshot_id=identity_index.snapshot_id,
                    source_maturity=MaturityEnvelope(
                        ir=None,
                        provider="hexrays",
                        provider_id=int(source_maturity_id),
                    ),
                    source_generation=identity_index.generation,
                    block_refs_by_serial=identity_index.plan_refs_by_serial(),
                )
                effects = (_plan_effect(patch_plan),)
                mutation_attempt = _safe_begin_attempt(
                    journal,
                    session_id,
                    parent_attempt_id=(
                        transform_attempt.attempt_id
                        if transform_attempt is not None
                        else parent_attempt_id
                    ),
                    stage_id=f"mba_mutation:{pass_.name}",
                    domain=ExecutionDomain.MUTATION,
                )
                try:
                    execution = self.backend.execute_patch_plan(
                        patch_plan,
                        backend_state,
                        mutation_gateway=mutation_gateway,
                        pre_cfg=cfg,
                    )
                    if not isinstance(execution, PatchPlanExecutionResult):
                        raise TypeError(
                            "PatchPlan runtime returned invalid execution authority"
                        )
                except BaseException as exc:
                    status = _status_for_execution_error(exc)
                    reason_code = f"{type(exc).__name__}: {exc}"
                    _safe_advance_attempt(
                        journal,
                        mutation_attempt,
                        status=status,
                        reason_code=reason_code,
                        effect_refs=effects,
                        details=maturity_detail,
                    )
                    _safe_advance_attempt(
                        journal,
                        transform_attempt,
                        status=status,
                        reason_code=reason_code,
                        effect_refs=effects,
                    )
                    raise

                receipt_effect = _receipt_effect(execution)
                if receipt_effect is not None:
                    effects = effects + (receipt_effect,)
                count = execution.applied_count
                if count <= 0:
                    logger.debug(
                        "Pass %s: transaction committed no operations", pass_.name
                    )
                    _safe_advance_attempt(
                        journal,
                        mutation_attempt,
                        status=ExecutionAttemptStatus.ABSTAINED,
                        reason_code="committed_no_operations",
                        effect_refs=effects,
                        details={
                            **maturity_detail,
                            "applied_count": 0,
                            "plan_step_count": len(patch_plan.steps),
                        },
                    )
                    _safe_advance_attempt(
                        journal,
                        transform_attempt,
                        status=ExecutionAttemptStatus.ABSTAINED,
                        reason_code="committed_no_operations",
                        effect_refs=effects,
                        details={**maturity_detail, "operation_count": 0},
                    )
                    continue

                _safe_advance_attempt(
                    journal,
                    mutation_attempt,
                    status=ExecutionAttemptStatus.COMPLETED,
                    effect_refs=effects,
                    details={
                        **maturity_detail,
                        "applied_count": count,
                        "plan_step_count": len(patch_plan.steps),
                    },
                )
                _safe_advance_attempt(
                    journal,
                    transform_attempt,
                    status=ExecutionAttemptStatus.COMPLETED,
                    effect_refs=effects,
                    details={**maturity_detail, "operation_count": count},
                )
                cfg = execution.graph
                total += count
                logger.debug(
                    "Pass %s applied %d modifications (total: %d)",
                    pass_.name,
                    count,
                    total,
                )
            except BaseException as exc:
                # A compilation or transform failure happens before a child
                # mutation attempt exists.  Record it on the transform and
                # retain the original exception unchanged.
                if transform_attempt is not None:
                    # The nested execution path terminally advanced this
                    # attempt already; only advance it when the error arose
                    # before a runtime transaction was attempted.
                    current = None
                    if journal is not None:
                        try:
                            current = journal.get_attempt(transform_attempt.attempt_id)
                        except Exception:
                            current = None
                    if current is None or not current.status.is_terminal:
                        _safe_advance_attempt(
                            journal,
                            transform_attempt,
                            status=_status_for_execution_error(exc),
                            reason_code=f"{type(exc).__name__}: {exc}",
                            details=maturity_detail,
                        )
                raise

        return total

    def __repr__(self) -> str:
        pass_names = [p.name for p in self.passes]
        return f"PassPipeline(backend={self.backend.name!r}, transform={pass_names})"


__all__ = ["FlowGraphTransformPipeline"]
