"""Thin orchestrator sequencing contract checks around plan lowering.

Owns phase ordering from projected_contract through backend_apply result.
Does NOT compile plans, run semantic preflight, or own snapshot/restore.

Ownership:
- TransactionalExecutor: plan compilation, semantic preflight, stage policy
- IDACfgContract: invariant evaluation only
- IDAIRTranslator: finalized-plan lowering, apply-mode selection
- DeferredGraphModifier: live mutation, snapshot restore, cleanup, backend verify
- CfgTransactionEngine: phase ordering, projected/live validation sequencing,
  rollback policy selection, failure classification
"""
from __future__ import annotations

from dataclasses import dataclass

from d810.core import logging
from d810.core.typing import TYPE_CHECKING

if TYPE_CHECKING:
    from d810.cfg.contracts.ida_contract import IDACfgContract
    from d810.cfg.contracts.transaction_policy import FailureClassification
    from d810.cfg.flowgraph import FlowGraph
    from d810.cfg.plan import PatchPlan

logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class TransactionResult:
    """Result of a CfgTransactionEngine.apply() call."""

    success: bool
    applied_count: int = 0
    failure_phase: str | None = None
    classification: FailureClassification | None = None
    error: Exception | None = None

    @classmethod
    def ok(cls, count: int) -> TransactionResult:
        return cls(success=True, applied_count=count)

    @classmethod
    def failed(cls, phase: str, error: Exception) -> TransactionResult:
        from d810.cfg.contracts.transaction_policy import classify_failure

        classification = classify_failure(phase, str(error))
        return cls(
            success=False,
            failure_phase=phase,
            classification=classification,
            error=error,
        )


class CfgTransactionEngine:
    """Thin orchestrator that sequences contract checks around plan lowering.

    Owns phase ordering from projected_contract through backend_apply result.
    Does NOT compile plans, run semantic preflight, or own snapshot/restore.

    The translator already wires its own post_apply_hook for post-apply contract
    checks. This engine wraps the outer call and adds projected + pre checks
    that the translator does not own.
    """

    def __init__(
        self,
        translator,  # IDAIRTranslator
        contract: IDACfgContract | None = None,
    ) -> None:
        self._translator = translator
        self._contract = contract

    def apply(
        self,
        plan: PatchPlan,
        *,
        pre_cfg: FlowGraph,
        mba,
        post_apply_hook=None,
    ) -> TransactionResult:
        """Execute the transaction: projected check -> pre check -> lower/apply.

        Returns TransactionResult with classification from transaction_policy.
        The translator handles post-apply contract checks and native verify
        internally via its own hook wiring.
        """
        from d810.cfg.contracts.ida_contract import CfgContractViolationError

        # Phase: projected_contract -- reject before any live mutation
        if self._contract is not None:
            try:
                self._contract.verify_projected(pre_cfg, plan)
            except CfgContractViolationError as exc:
                return TransactionResult.failed("projected_contract", exc)

        # Phase: live_pre_check -- reject before any live mutation
        if self._contract is not None:
            try:
                self._contract.verify(mba, plan, phase="pre")
            except CfgContractViolationError as exc:
                return TransactionResult.failed("live_pre_check", exc)

        # Phase: lowering + backend_apply + post_apply_contract + native_verify
        # All handled inside translator.lower() -> deferred_modifier.apply()
        try:
            count = self._translator.lower(
                plan, mba, post_apply_hook=post_apply_hook,
            )
        except CfgContractViolationError as exc:
            # Post-apply contract failure propagated as exception
            return TransactionResult.failed("post_apply_contract", exc)
        except Exception as exc:
            # Unexpected failure during lowering/apply
            return TransactionResult.failed("backend_apply", exc)

        if count == 0:
            # lower() returned 0 -- verify_failed or no modifications applied
            return TransactionResult.failed(
                "backend_apply",
                RuntimeError(
                    "translator.lower() returned 0 applied modifications"
                ),
            )

        return TransactionResult.ok(count)
