"""Gateway orchestration for detached semantic-fragment publication.

The central mutation backend implements the private realization port below.
This module owns ordering and recovery only: portable passes cannot invoke any
of these methods, and a fragment never receives a committed receipt until both
portable validation phases succeed.
"""

from __future__ import annotations

from d810.hexrays.mutation.fragment_publication_lifecycle import (
    FragmentPublicationLifecycleAuthority,
)
from d810.transforms.fragment_plan import FragmentPlan
from d810.transforms.fragment_validation import (
    FragmentValidationResult,
    ProjectedFragment,
    PublishedFragmentObservation,
    validate_fragment_projection,
    validate_published_fragment_observation,
)
from d810.hexrays.mutation.semantic_fragment_inventory import (
    SemanticFragmentRootInventory,
)


_BACKEND_PORT = (
    "_plan_semantic_fragment_root_publication_inventory",
    "_stage_semantic_fragment",
    "_semantic_fragment_current_mba_identity_binding",
    "_discard_staged_semantic_fragment",
    "_prepare_semantic_fragment_root_publication",
    "_publish_semantic_fragment_roots",
    "_rebuild_semantic_fragment_chains",
    "_observe_published_semantic_fragment",
    "_rollback_semantic_fragment_roots",
    "_complete_semantic_fragment_publication",
)


class SemanticFragmentPublicationRejected(RuntimeError):
    """A semantic precondition or postcondition rejected publication."""

    def __init__(self, phase: str, validation: FragmentValidationResult) -> None:
        self.phase = str(phase)
        self.validation = validation
        failures = ", ".join(
            f"{failure.postcondition.value}:{failure.subject_id}"
            for failure in validation.failures
        )
        super().__init__(f"{self.phase} semantic validation failed: {failures}")


class SemanticFragmentRollbackFailed(RuntimeError):
    """Root authority could not be restored after publication failure."""

    def __init__(self, original: Exception, recovery: Exception) -> None:
        self.original = original
        self.recovery = recovery
        super().__init__(
            f"semantic fragment rollback failed after {type(original).__name__}: "
            f"{type(recovery).__name__}: {recovery}"
        )


def _require_backend_port(backend: object) -> None:
    if getattr(backend, "mba", None) is None or any(
        not callable(getattr(backend, name, None)) for name in _BACKEND_PORT
    ):
        raise TypeError(
            "fragment publication requires the complete semantic-fragment backend port"
        )


def _require_lifecycle_authority(
    gateway: object,
) -> FragmentPublicationLifecycleAuthority:
    authority = getattr(gateway, "lifecycle_authority", None)
    if not isinstance(authority, FragmentPublicationLifecycleAuthority):
        raise TypeError(
            "fragment publication requires a lifecycle authority"
        )
    return authority


def _mark_lifecycle_staged(
    authority: FragmentPublicationLifecycleAuthority,
    plan: FragmentPlan,
) -> None:
    authority.record_fragment_staged(plan)


def _mark_lifecycle_plan_ready(
    authority: FragmentPublicationLifecycleAuthority,
    plan: FragmentPlan,
) -> None:
    authority.record_fragment_plan_ready(plan)


def _mark_lifecycle_validated(
    authority: FragmentPublicationLifecycleAuthority,
    plan: FragmentPlan,
    validation: FragmentValidationResult,
) -> None:
    authority.record_fragment_validated(plan, validation)


def _abort_lifecycle(
    authority: FragmentPublicationLifecycleAuthority,
    plan: FragmentPlan,
    *,
    reason: str,
) -> None:
    authority.abort_fragment_publication(plan, reason=reason)


def _commit_lifecycle(
    authority: FragmentPublicationLifecycleAuthority,
    plan: FragmentPlan,
    receipt: object,
) -> None:
    authority.commit_fragment_publication(plan, receipt)


def publish_semantic_fragment(gateway: object, backend: object, plan: FragmentPlan):
    """Publish one plan through a rollback-capable two-phase transaction."""
    if not isinstance(plan, FragmentPlan):
        raise TypeError("semantic fragment publication requires a FragmentPlan")
    if bool(getattr(gateway, "active", False)):
        raise RuntimeError(
            "semantic fragment publication requires an independent batch"
        )
    _require_backend_port(backend)
    lifecycle_authority = _require_lifecycle_authority(gateway)
    _mark_lifecycle_plan_ready(lifecycle_authority, plan)

    root_inventory = backend._plan_semantic_fragment_root_publication_inventory(plan)
    if not isinstance(root_inventory, SemanticFragmentRootInventory):
        raise TypeError("semantic-fragment backend returned an invalid root inventory")
    gateway._begin_semantic_fragment_batch(backend, plan, root_inventory)
    stage_attempted = False
    lifecycle_staged = False
    root_attempted = False
    rollback_token = None
    receipt = None
    try:
        stage_attempted = True
        projection = backend._stage_semantic_fragment(plan)
        if not isinstance(projection, ProjectedFragment):
            raise TypeError("semantic-fragment backend returned an invalid projection")
        gateway._record_fragment_staged(plan)
        _mark_lifecycle_staged(
            lifecycle_authority,
            plan,
        )
        lifecycle_staged = True
        gateway._record_fragment_current_mba_identity_binding(
            plan,
            backend._semantic_fragment_current_mba_identity_binding(plan),
        )
        prepublication = validate_fragment_projection(plan, projection)
        gateway._record_fragment_validation(
            plan=plan,
            phase="prepublication",
            validation=prepublication,
        )
        if not prepublication.passed:
            raise SemanticFragmentPublicationRejected(
                "prepublication",
                prepublication,
            )
        _mark_lifecycle_validated(
            lifecycle_authority,
            plan,
            prepublication,
        )

        rollback_token = backend._prepare_semantic_fragment_root_publication(
            plan,
            root_inventory,
        )
        root_attempted = True
        gateway._record_fragment_root_publication_attempted(plan)
        backend._publish_semantic_fragment_roots(plan, rollback_token)
        gateway._record_fragment_root_publication_succeeded(plan)
        for _root_edge in root_inventory.items:
            gateway.record_edge_redirect()
        backend._rebuild_semantic_fragment_chains(plan)
        observation = backend._observe_published_semantic_fragment(plan)
        if not isinstance(observation, PublishedFragmentObservation):
            raise TypeError(
                "semantic-fragment backend returned an invalid published observation"
            )
        postpublication = validate_published_fragment_observation(
            plan,
            observation,
            projection,
        )
        gateway._record_fragment_validation(
            plan=plan,
            phase="postpublication",
            validation=postpublication,
        )
        if not postpublication.passed:
            raise SemanticFragmentPublicationRejected(
                "postpublication",
                postpublication,
            )
        gateway._record_fragment_semantic_validation(
            plan=plan,
            prepublication=prepublication,
            postpublication=postpublication,
        )
        receipt = gateway.commit()
    except Exception as original_error:
        recovery_error: Exception | None = None
        recovery_succeeded = True
        if root_attempted:
            try:
                backend._rollback_semantic_fragment_roots(plan, rollback_token)
                backend._rebuild_semantic_fragment_chains(plan)
            except Exception as exc:
                recovery_error = exc
                recovery_succeeded = False
        if stage_attempted:
            try:
                backend._discard_staged_semantic_fragment(plan)
            except Exception as exc:
                recovery_succeeded = False
                if recovery_error is None:
                    recovery_error = exc
        if root_attempted or stage_attempted:
            try:
                gateway._record_fragment_rollback(
                    plan,
                    succeeded=recovery_succeeded,
                )
            except Exception as exc:
                recovery_succeeded = False
                if recovery_error is None:
                    recovery_error = exc
        reason = str(original_error)
        if recovery_error is not None:
            reason += (
                f"; rollback failed: {type(recovery_error).__name__}: {recovery_error}"
            )
        try:
            if bool(getattr(gateway, "active", False)):
                gateway.abort(reason=reason)
        except Exception as exc:
            if recovery_error is None:
                recovery_error = exc
        if lifecycle_staged:
            try:
                _abort_lifecycle(
                    lifecycle_authority,
                    plan,
                    reason=reason,
                )
            except Exception as exc:
                if recovery_error is None:
                    recovery_error = exc
        if recovery_error is not None:
            raise SemanticFragmentRollbackFailed(
                original_error,
                recovery_error,
            ) from recovery_error
        raise
    _commit_lifecycle(
        lifecycle_authority,
        plan,
        receipt,
    )
    backend._complete_semantic_fragment_publication(plan)
    return receipt


__all__ = [
    "SemanticFragmentPublicationRejected",
    "SemanticFragmentRollbackFailed",
    "publish_semantic_fragment",
]
