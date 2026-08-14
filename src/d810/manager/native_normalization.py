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
* **A matching certificate short-circuits to an abstention, never a
  reapply.** :func:`_certificate_matches` requires current identity
  (``database_identity``, ``function_identity.entry_ea``), the semantic and
  native plan hashes, and an ``applied`` certificate state to agree exactly.
  Any mismatch falls through to ordinary live preflight via
  ``gateway.apply()`` -- it never reuses or silently trusts the old
  certificate's evidence (section 15.1.1's certification is one-way; only an
  explicit restore may reopen a certified function for a new normalization).

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
    if (
        existing is not None
        and _certificate_matches(existing, plan)
        and gateway.certificate_matches_current(plan, existing)
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

    receipt = gateway.apply(plan)
    if receipt.ok:
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
) -> tuple[NativePatchTransactionId, ...]:
    """Section 15.4: reconcile interrupted transactions on plugin load or IDB
    open. The caller may supply ``transaction_ids``; otherwise this enumerates
    durable apply and restore cut points that the gateway can safely resume.
    ``RECOVERY_REQUIRED`` remains operator-visible and read-only until its
    explicit acknowledgement. Returns the ids recovery was attempted for --
    a per-id failure is logged and does not stop the remaining ids from being
    processed, so one broken transaction cannot block the others.
    """
    if transaction_ids is None:
        if journal is None:
            raise TypeError("journal is required when transaction_ids is omitted")
        transaction_ids = journal.recoverable_transaction_ids()
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
