"""Transaction phase ordering and failure classification for CFG mutations.

The Hodur unflattening pipeline applies CFG modifications through a
transactional boundary. Each transaction passes through an ordered sequence
of phases. Failures at different phases require different recovery actions
depending on whether live MBA state has been mutated.

Transaction Boundary
====================

Phases before ``lowering`` operate on *projected* or *read-only* views of the
CFG. No live MBA mutation has occurred, so failures can be rejected cheaply
without rollback.

Phases from ``lowering`` onward mutate the live MBA via
``DeferredGraphModifier``. Failures in this region require snapshot-based
rollback to restore the MBA to its pre-mutation state.

Phase Ordering
==============

::

    semantic_preflight      executor: virtual-CFG plan shaping, cycle filter, sink proof
    projected_contract      contract: verify_projected() on projected FlowGraph
    live_pre_check          contract: check_pre() before live mutation
    lowering                translator: PatchPlan -> DeferredGraphModifier queue
    backend_apply           deferred_modifier: live MBA mutation
    post_apply_contract     contract: verify() after live mutation
    native_verify           IDA: mba.verify() final oracle
    rollback_restore        deferred_modifier: snapshot restore on failure
    rollback_verification   contract: check_rollback() after restore

Rollback Decision Matrix
=========================

- ``semantic_preflight`` failure: reject before mutation, no rollback needed.
- ``projected_contract`` failure: reject before mutation, no rollback needed.
- ``live_pre_check`` failure: reject before mutation, no rollback needed.
- ``lowering`` failure: no live state changed yet (queue build only), no rollback.
- ``backend_apply`` failure: live state mutated, snapshot rollback required.
- ``post_apply_contract`` failure: live state mutated, snapshot rollback required.
- ``native_verify`` failure: live state mutated, snapshot rollback required.
  Tagged as ``backend_verify_failure`` for diagnostics.
- ``rollback_restore`` failure: snapshot restore itself failed -- quarantine.
- ``rollback_verification`` failure: snapshot restored but contract check_rollback()
  found residual damage -- quarantine via ``verify_failed`` path.

Rollback Wiring
===============

After ``DeferredGraphModifier`` snapshot restore succeeds (phases
``rollback_restore``), the caller should invoke
``IDACfgContract.check_rollback(mba, plan)`` to verify the restored MBA
satisfies invariants. If ``check_rollback()`` finds violations, the MBA
enters the ``verify_failed`` quarantine path and no further pipeline stages
execute.
"""

from __future__ import annotations

from dataclasses import dataclass

from d810.core.typing import Literal


# -- Phase ordering ----------------------------------------------------------

TRANSACTION_PHASES: list[str] = [
    "semantic_preflight",
    "projected_contract",
    "live_pre_check",
    "lowering",
    "backend_apply",
    "post_apply_contract",
    "native_verify",
    "rollback_restore",
    "rollback_verification",
]

TransactionPhase = Literal[
    "semantic_preflight",
    "projected_contract",
    "live_pre_check",
    "lowering",
    "backend_apply",
    "post_apply_contract",
    "native_verify",
    "rollback_restore",
    "rollback_verification",
]

# Phases that operate before any live MBA mutation.
_PRE_MUTATION_PHASES: frozenset[str] = frozenset({
    "semantic_preflight",
    "projected_contract",
    "live_pre_check",
    "lowering",
})

# Phases where live MBA state has been mutated and rollback is required on failure.
_LIVE_MUTATION_PHASES: frozenset[str] = frozenset({
    "backend_apply",
    "post_apply_contract",
    "native_verify",
})

# Phases in the rollback/recovery path itself.
_ROLLBACK_PHASES: frozenset[str] = frozenset({
    "rollback_restore",
    "rollback_verification",
})


# -- Failure classification --------------------------------------------------

@dataclass(frozen=True)
class FailureClassification:
    """Classifies a phase failure into a recovery action.

    Attributes:
        phase: The transaction phase where the failure occurred.
        rollback_needed: Whether the live MBA needs snapshot rollback.
            False for pre-mutation failures (no live state to restore).
            True for post-mutation failures (live state must be restored).
        quarantine: Whether the MBA should be quarantined (no further
            pipeline stages). Set when rollback itself fails.
        tag: Optional diagnostic tag for downstream logging/metrics.
        error: The original error description.
    """

    phase: str
    rollback_needed: bool
    quarantine: bool = False
    tag: str | None = None
    error: str = ""


def classify_failure(
    phase: str,
    error: str = "",
) -> FailureClassification:
    """Classify a transaction phase failure into its recovery action.

    Args:
        phase: One of ``TRANSACTION_PHASES``.
        error: Human-readable error description.

    Returns:
        FailureClassification with appropriate rollback/quarantine flags.

    Raises:
        ValueError: If *phase* is not a recognized transaction phase.

    Examples:
        >>> result = classify_failure("projected_contract", "pred/succ mismatch")
        >>> result.rollback_needed
        False

        >>> result = classify_failure("post_apply_contract", "block type mismatch")
        >>> result.rollback_needed
        True

        >>> result = classify_failure("native_verify", "INTERR 50860")
        >>> result.tag
        'backend_verify_failure'

        >>> result = classify_failure("rollback_verification", "residual damage")
        >>> result.quarantine
        True
    """
    if phase not in frozenset(TRANSACTION_PHASES):
        raise ValueError(
            f"Unknown transaction phase: {phase!r}. "
            f"Valid phases: {TRANSACTION_PHASES}"
        )

    if phase in _PRE_MUTATION_PHASES:
        return FailureClassification(
            phase=phase,
            rollback_needed=False,
            quarantine=False,
            tag=None,
            error=error,
        )

    if phase in _LIVE_MUTATION_PHASES:
        tag = "backend_verify_failure" if phase == "native_verify" else None
        return FailureClassification(
            phase=phase,
            rollback_needed=True,
            quarantine=False,
            tag=tag,
            error=error,
        )

    # Rollback path failures -> quarantine
    if phase in _ROLLBACK_PHASES:
        return FailureClassification(
            phase=phase,
            rollback_needed=False,
            quarantine=True,
            tag="rollback_failed" if phase == "rollback_restore" else "rollback_verify_failed",
            error=error,
        )

    # Unreachable if TRANSACTION_PHASES is consistent with the phase sets,
    # but guard defensively.
    raise ValueError(f"Phase {phase!r} not covered by any classification set")


__all__ = [
    "TRANSACTION_PHASES",
    "TransactionPhase",
    "FailureClassification",
    "classify_failure",
]
