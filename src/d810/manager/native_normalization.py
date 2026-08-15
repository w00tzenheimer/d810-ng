"""User policy, orchestration, certificate lookup, and startup recovery for
native normalization.

Task 6 ("Single-operation native gateway, reanalysis, and certificate") of
``_gitless/profile-guided-native-mutation-implementer-plan.md``, Step 5:
"Prove no-rerun and user-policy boundaries." This is the one place a native
write is authorized end to end -- everything below it
(``d810.backends.ida.native_patch.gateway.NativePatchGateway``) is a pure
mechanism that will apply *any* plan it is handed; this module is what
decides whether that plan should be handed to it at all.

Two boundaries, both non-negotiable per the plan's global constraints:

* **Explicit user opt-in only.** ``NativeNormalizationRequest.user_enabled``
  must be ``True`` for :func:`authorize_and_apply` to ever call
  ``gateway.apply()``. "A native write remains explicit-user-policy
  controlled. Profile guidance may rank, preview, and request read-only
  evidence, but cannot independently enable applying a patch" -- nothing in
  this module (or anywhere upstream of it, per Task 8's not-yet-built
  profile guidance) may set that flag on a caller's behalf from a profile
  signal alone.
* **One applied certificate owns one function.** A matching certificate
  short-circuits to an abstention; a different or stale applied certificate
  rejects the request before ``gateway.apply()``. Only explicit restore may
  reopen that function's certificate slot for another normalization.

Layering: ``d810.manager`` is the top layer, so this module may import
everything below it, including ``d810.backends.ida.native_patch.gateway``.
"""

from __future__ import annotations

import enum
from collections.abc import Iterable
from dataclasses import dataclass

from d810.backends.ida.native_patch.gateway import (
    NativeApplyReceipt,
    NativePatchGateway,
)
from d810.capabilities.native_patch import (
    NativeJournalState,
    NativePatchJournalStore,
    NativePatchTransactionId,
)
from d810.core.logging import getLogger
from d810.transforms.native_patch_plan import (
    NativeCertificate,
    NativeCertificateState,
    NativePatchPlan,
)

logger = getLogger("d810.manager.native_normalization")

__all__ = [
    "NativeNormalizationOutcome",
    "NativeNormalizationRequest",
    "NativeNormalizationResult",
    "authorize_and_apply",
    "recover_startup",
]


class NativeNormalizationOutcome(str, enum.Enum):
    APPLIED = "applied"
    ALREADY_NORMALIZED = "already_normalized"
    NOT_AUTHORIZED = "not_authorized"
    REJECTED = "rejected"


@dataclass(frozen=True, slots=True)
class NativeNormalizationRequest:
    """One explicit user request to normalize ``plan``.

    ``user_enabled`` is the sole authorization signal this module recognises
    -- see the module docstring's "explicit user opt-in only" boundary. There
    is deliberately no ``profile_suggested`` field here: profile guidance
    (Task 8, not yet built) may only ever influence what gets *offered* to a
    user upstream of this request being constructed, never flip this flag
    itself.
    """

    plan: NativePatchPlan
    user_enabled: bool


@dataclass(frozen=True, slots=True)
class NativeNormalizationResult:
    outcome: NativeNormalizationOutcome
    apply_receipt: NativeApplyReceipt | None
    certificate: NativeCertificate | None
    reason: str | None


def _certificate_matches(certificate: NativeCertificate, plan: NativePatchPlan) -> bool:
    """Section 14.5/15.1.1: a match requires current identity, the semantic
    and native plan hashes, and an ``applied`` state -- all exactly, never a
    partial/fuzzy match. See the module docstring."""
    return (
        certificate.state is NativeCertificateState.APPLIED
        and certificate.semantic_plan_hash == plan.proof_hash
        and certificate.database_identity == plan.database_identity
        and (
            certificate.function_identity == plan.function_identity
            if any(operation.metadata_actions for operation in plan.operations)
            else certificate.function_identity.entry_ea
            == plan.function_identity.entry_ea
        )
        and certificate.metadata_target_fingerprint == plan.metadata_target_fingerprint
        and (
            plan.issuer_id != "stage-c-native-cfg-normalizer"
            or certificate.observed_native_cfg_fingerprint
            == plan.target_cfg_fingerprint
        )
        and (
            any(operation.metadata_actions for operation in plan.operations)
            or certificate.native_plan_hash == plan.plan_hash
        )
    )


def authorize_and_apply(
    request: NativeNormalizationRequest, *, gateway: NativePatchGateway
) -> NativeNormalizationResult:
    """Authorize and, if authorized and not already normalized, apply.

    Profile mode alone can never reach ``gateway.apply()`` through this
    function: the only path to ``APPLIED`` requires
    ``request.user_enabled is True`` *and* no matching certificate already
    exists.
    """
    if not request.user_enabled:
        return NativeNormalizationResult(
            outcome=NativeNormalizationOutcome.NOT_AUTHORIZED,
            apply_receipt=None,
            certificate=None,
            reason="USER_NOT_OPTED_IN",
        )

    plan = request.plan
    existing = gateway.lookup_certificate(
        plan.function_identity.entry_ea, plan.database_identity
    )
    if existing is not None:
        if _certificate_matches(existing, plan) and gateway.certificate_matches_current(
            plan, existing
        ):
            logger.info(
                "native normalization: function %#x already certified under "
                "plan_hash=%s; abstaining",
                plan.function_identity.entry_ea,
                plan.plan_hash,
            )
            return NativeNormalizationResult(
                outcome=NativeNormalizationOutcome.ALREADY_NORMALIZED,
                apply_receipt=None,
                certificate=existing,
                reason="native_plan_hash matches an existing applied certificate",
            )
        logger.warning(
            "native normalization: function %#x has an applied certificate "
            "for a different or stale plan; explicit restore required",
            plan.function_identity.entry_ea,
        )
        return NativeNormalizationResult(
            outcome=NativeNormalizationOutcome.REJECTED,
            apply_receipt=None,
            certificate=existing,
            reason="FUNCTION_ALREADY_CERTIFIED_RESTORE_REQUIRED",
        )

    receipt = gateway.apply(plan)
    if receipt.ok or (
        plan.issuer_id == "stage-c-native-cfg-normalizer"
        and receipt.state is NativeJournalState.POSTCONDITION_PENDING
    ):
        return NativeNormalizationResult(
            outcome=NativeNormalizationOutcome.APPLIED,
            apply_receipt=receipt,
            certificate=receipt.certificate,
            reason=None,
        )
    return NativeNormalizationResult(
        outcome=NativeNormalizationOutcome.REJECTED,
        apply_receipt=receipt,
        certificate=None,
        reason="; ".join(receipt.rejection_reasons) or receipt.state.value,
    )


def recover_startup(
    transaction_ids: Iterable[NativePatchTransactionId] | None = None,
    *,
    journal: NativePatchJournalStore | None = None,
    gateway: NativePatchGateway,
    database_identity: str,
) -> tuple[NativePatchTransactionId, ...]:
    """Section 15.4: reconcile interrupted transactions on plugin load or IDB
    open. The caller may supply ``transaction_ids``; otherwise this enumerates
    durable apply and restore cut points that the gateway can safely resume.
    ``RECOVERY_REQUIRED`` remains operator-visible and read-only until its
    explicit acknowledgement. Both automatic enumeration and any caller-
    supplied ids are intersected with the current IDB's durable identity;
    recovery never trusts an arbitrary global-journal transaction id. Returns
    the ids recovery was attempted for -- a per-id failure is logged and does
    not stop the remaining ids from being processed, so one broken transaction
    cannot block the others.
    """
    if journal is None:
        raise TypeError("journal is required for identity-scoped recovery")
    recoverable = journal.recoverable_transaction_ids(
        database_identity=database_identity
    )
    if transaction_ids is None:
        transaction_ids = recoverable
    else:
        recoverable_set = frozenset(recoverable)
        transaction_ids = tuple(
            transaction_id
            for transaction_id in transaction_ids
            if transaction_id in recoverable_set
        )
    attempted: list[NativePatchTransactionId] = []
    for transaction_id in transaction_ids:
        try:
            gateway.recover(transaction_id)
        except Exception:
            logger.exception(
                "startup recovery failed for transaction %s", transaction_id.value
            )
        attempted.append(transaction_id)
    return tuple(attempted)
