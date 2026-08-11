"""Gateway orchestration for detached semantic-fragment publication.

The central mutation backend implements the private realization port below.
This module owns ordering and recovery only: portable passes cannot invoke any
of these methods, and a fragment never receives a committed receipt until both
portable validation phases succeed.
"""

from __future__ import annotations

from dataclasses import dataclass, field
import re

from d810.hexrays.mutation.fragment_publication_lifecycle import (
    FragmentPublicationLifecycleAuthority,
)
from d810.hexrays.mutation.semantic_fragment_failure import (
    MbaSemanticFragmentFailure,
)
from d810.hexrays.mutation.semantic_fragment_preparation import (
    PreparedSemanticFragment,
    PreparedSemanticFragmentAuthority,
    SemanticFragmentSnapshotPreparation,
)
from d810.transforms.cfg_transaction import (
    BoundCfgTransaction,
    CfgGenerationPoisoned,
    CfgProjection,
    PlanBlockRef,
    PreparedCfgTransaction,
    TransactionAttemptId,
)
from d810.transforms.contract import CfgContract, CfgContractViolationError
from d810.transforms.fragment_plan import (
    FragmentBlockMaterialization,
    FragmentPlan,
)
from d810.transforms.fragment_projection import (
    FragmentProjectionFailure,
    fragment_cfg_projection,
    project_fragment,
)
from d810.transforms.detached_route_oracle import (
    DetachedRouteOracleRejected,
    compare_detached_route_oracle,
)
from d810.transforms.fragment_validation import (
    compare_fragment_projection_obligations,
    FragmentValidationOutcome,
    FragmentValidationPostcondition,
    FragmentValidationResult,
    ProjectedFragment,
    PublishedFragmentGraphObservation,
    validate_fragment_projection,
    validate_published_fragment_observation,
)
from d810.hexrays.mutation.semantic_fragment_inventory import (
    SemanticFragmentRootInventory,
)
from d810.hexrays.mutation.semantic_fragment_profile import (
    SemanticFragmentPublicationProfile,
)


_BACKEND_PORT = (
    "_plan_semantic_fragment_root_publication_inventory",
    "_snapshot_semantic_fragment_inputs",
    "_realize_semantic_patch_plan",
    "_observe_staged_semantic_fragment",
    "_semantic_fragment_current_mba_identity_binding",
    "_discard_staged_semantic_fragment",
    "_prepare_semantic_fragment_root_publication",
    "_publish_semantic_patch_roots",
    "_rebuild_semantic_fragment_chains",
    "_observe_published_semantic_fragment_graph",
    "_rollback_semantic_fragment_roots",
    "_finalize_semantic_fragment_for_commit",
    "_complete_semantic_fragment_publication",
)


@dataclass(frozen=True, slots=True)
class SemanticFragmentCfgProjection(CfgProjection):
    """Portable CFG projection carrying exact backend preflight inputs."""

    plan: FragmentPlan | None = field(default=None, repr=False, compare=False)
    snapshot_preparation: SemanticFragmentSnapshotPreparation | None = field(
        default=None,
        repr=False,
    )
    root_inventory: SemanticFragmentRootInventory | None = None
    semantic_projection: ProjectedFragment | None = None

    def __post_init__(self) -> None:
        CfgProjection.__post_init__(self)
        if not isinstance(self.plan, FragmentPlan):
            raise TypeError("semantic CFG projection requires an exact plan")
        if not isinstance(
            self.snapshot_preparation,
            SemanticFragmentSnapshotPreparation,
        ):
            raise TypeError("semantic CFG projection requires snapshot authority")
        if not isinstance(self.root_inventory, SemanticFragmentRootInventory):
            raise TypeError("semantic CFG projection requires root inventory")
        if not isinstance(self.semantic_projection, ProjectedFragment):
            raise TypeError("semantic CFG projection requires semantic projection")
        if (
            self.plan.plan_id != self.plan_id
            or self.snapshot_preparation.authority.plan_id != self.plan_id
            or self.snapshot_preparation.authority.projection_input.snapshot_id
            != self.snapshot_id
            or self.root_inventory.plan_id != self.plan_id
        ):
            raise ValueError("semantic CFG projection authority is inconsistent")


@dataclass(frozen=True, slots=True)
class PreparedSemanticCfgTransaction(PreparedCfgTransaction):
    """Portable preflight token paired with exact semantic realization authority."""

    plan: FragmentPlan | None = field(default=None, repr=False, compare=False)
    fragment: PreparedSemanticFragment | None = field(default=None, repr=False)
    validation: FragmentValidationResult | None = field(default=None, repr=False)

    def __post_init__(self) -> None:
        PreparedCfgTransaction.__post_init__(self)
        if not isinstance(self.plan, FragmentPlan):
            raise TypeError("prepared semantic transaction requires an exact plan")
        if not isinstance(self.fragment, PreparedSemanticFragment):
            raise TypeError("prepared semantic transaction requires fragment authority")
        if not isinstance(self.validation, FragmentValidationResult):
            raise TypeError("prepared semantic transaction requires validation")
        if (
            self.fragment.authority.attempt_id is not self.attempt_id
            or self.fragment.authority.plan_id != self.plan.plan_id
            or self.fragment.authority.cfg_projection.plan_id != self.projection.plan_id
            or self.fragment.authority.cfg_projection.snapshot_id
            != self.projection.snapshot_id
            or self.fragment.authority.cfg_projection.graph != self.projection.graph
            or self.fragment.authority.cfg_projection.focus_refs
            != self.projection.focus_refs
            or not self.validation.passed
        ):
            raise ValueError("prepared semantic transaction authority is inconsistent")


@dataclass(frozen=True, slots=True)
class BoundSemanticCfgTransaction(BoundCfgTransaction):
    """Exact identity-generation binding for one prepared semantic attempt."""

    plan: FragmentPlan | None = field(default=None, repr=False, compare=False)
    fragment: PreparedSemanticFragment | None = field(default=None, repr=False)
    patch_plan: object | None = field(default=None, repr=False)

    def __post_init__(self) -> None:
        BoundCfgTransaction.__post_init__(self)
        if not isinstance(self.prepared, PreparedSemanticCfgTransaction):
            raise TypeError("bound semantic transaction requires semantic preflight")
        if self.plan is not self.prepared.plan:
            raise ValueError("bound semantic transaction changed exact plan authority")
        if self.fragment is not self.prepared.fragment:
            raise ValueError(
                "bound semantic transaction changed exact fragment authority"
            )
        from d810.transforms.plan import PatchPlan

        if self.patch_plan is not None and not isinstance(self.patch_plan, PatchPlan):
            raise TypeError("bound semantic transaction PatchPlan is malformed")
        if self.patch_plan is not None and (
            self.patch_plan.plan_id != self.plan.plan_id
            or self.patch_plan.semantic_contract is None
            or self.patch_plan.semantic_contract.fragment_plan is not self.plan
        ):
            raise ValueError("bound semantic transaction changed PatchPlan authority")


@dataclass(frozen=True, slots=True)
class SemanticFragmentTransactionParticipant:
    """Production participant for immutable semantic-fragment transactions."""

    gateway: object
    backend: object
    attempt_id: TransactionAttemptId | None = None
    publication_profile: SemanticFragmentPublicationProfile = (
        SemanticFragmentPublicationProfile.CFG_READY
    )

    def __post_init__(self) -> None:
        if not isinstance(
            self.publication_profile,
            SemanticFragmentPublicationProfile,
        ):
            raise TypeError("semantic participant requires a typed profile")

    def project(self, plan: object, snapshot: object) -> CfgProjection:
        if not isinstance(plan, FragmentPlan):
            raise TypeError("semantic participant requires a FragmentPlan")
        if snapshot is not None:
            raise ValueError("semantic participant owns its immutable snapshot")
        if bool(getattr(self.gateway, "active", False)):
            raise RuntimeError("semantic projection requires an idle gateway")
        root_inventory = (
            self.backend._plan_semantic_fragment_root_publication_inventory(plan)
        )
        if not isinstance(root_inventory, SemanticFragmentRootInventory):
            raise TypeError(
                "semantic-fragment backend returned an invalid root inventory"
            )
        snapshot_preparation = self.backend._snapshot_semantic_fragment_inputs(plan)
        if not isinstance(
            snapshot_preparation,
            SemanticFragmentSnapshotPreparation,
        ):
            raise TypeError(
                "semantic-fragment backend returned invalid snapshot evidence"
            )
        snapshot_input = snapshot_preparation.authority.projection_input
        semantic_projection = project_fragment(
            plan,
            snapshot_input,
            root_inventory,
        )
        cfg_projection = fragment_cfg_projection(
            plan,
            snapshot_input,
            semantic_projection,
        )
        return SemanticFragmentCfgProjection(
            plan_id=cfg_projection.plan_id,
            snapshot_id=cfg_projection.snapshot_id,
            graph=cfg_projection.graph,
            focus_refs=cfg_projection.focus_refs,
            plan=plan,
            snapshot_preparation=snapshot_preparation,
            root_inventory=root_inventory,
            semantic_projection=semantic_projection,
        )

    def preflight(self, projection: CfgProjection) -> PreparedCfgTransaction:
        if not isinstance(projection, SemanticFragmentCfgProjection):
            raise TypeError("semantic participant requires its projected authority")
        if bool(getattr(self.gateway, "active", False)):
            raise RuntimeError("semantic preflight requires an idle gateway")
        plan = projection.plan
        assert plan is not None
        semantic_projection = projection.semantic_projection
        assert semantic_projection is not None
        validation = validate_fragment_projection(plan, semantic_projection)
        if not validation.passed:
            raise SemanticFragmentPublicationRejected(
                "prepublication",
                validation,
            )
        try:
            CfgContract().verify_projection(projection, scope="full")
        except CfgContractViolationError as error:
            rejection = FragmentValidationResult(
                plan_id=plan.plan_id,
                atomic_group_id=plan.atomic_group_id,
                outcomes=(
                    FragmentValidationOutcome(
                        postcondition=(FragmentValidationPostcondition.BLOCK_TOPOLOGY),
                        subject_id="cfg-projection",
                        passed=False,
                        reason=f"projected CFG contract failed: {error.summary}",
                    ),
                ),
            )
            raise SemanticFragmentPublicationRejected(
                "cfg_preflight",
                rejection,
            ) from error
        snapshot_preparation = projection.snapshot_preparation
        root_inventory = projection.root_inventory
        assert snapshot_preparation is not None
        assert root_inventory is not None
        attempt = self.attempt_id or TransactionAttemptId.new(
            plan.plan_id,
            str(self.gateway.session_id),
            int(self.gateway.generation),
        )
        if (
            attempt.plan_id != plan.plan_id
            or attempt.session_id != str(self.gateway.session_id)
            or attempt.generation != int(self.gateway.generation)
        ):
            raise ValueError("semantic participant attempt authority drifted")
        fragment = PreparedSemanticFragment(
            authority=PreparedSemanticFragmentAuthority(
                plan_id=plan.plan_id,
                atomic_group_id=plan.atomic_group_id,
                session_id=snapshot_preparation.authority.session_id,
                generation=snapshot_preparation.authority.generation,
                snapshot_id=projection.snapshot_id,
                attempt_id=attempt,
                root_inventory=root_inventory,
                snapshot=snapshot_preparation.authority,
                projection=semantic_projection,
                cfg_projection=CfgProjection(
                    plan_id=projection.plan_id,
                    snapshot_id=projection.snapshot_id,
                    graph=projection.graph,
                    focus_refs=projection.focus_refs,
                ),
            ),
            payload=snapshot_preparation.payload,
        )
        obligation_ids = tuple(
            f"{outcome.postcondition.value}:{outcome.subject_id}"
            for outcome in validation.outcomes
        )
        return PreparedSemanticCfgTransaction(
            attempt_id=attempt,
            projection=projection,
            obligation_ids=obligation_ids,
            plan=plan,
            fragment=fragment,
            validation=validation,
        )

    def bind(
        self,
        prepared: PreparedCfgTransaction,
        identity_index: object,
    ) -> BoundCfgTransaction:
        if not isinstance(prepared, PreparedSemanticCfgTransaction):
            raise TypeError("semantic participant requires semantic preflight")
        if identity_index is not self.gateway.identity_index:
            raise ValueError("semantic participant received a foreign identity index")
        if bool(getattr(self.gateway, "active", False)):
            raise RuntimeError("semantic binding requires an idle gateway")
        plan = prepared.plan
        assert plan is not None
        bindings: list[tuple[PlanBlockRef, object]] = []
        for ref in prepared.projection.focus_refs:
            if not isinstance(ref, PlanBlockRef):
                raise TypeError("semantic projection focus must be plan-local")
            try:
                block = plan.block(ref.local_block_id)
            except KeyError:
                bindings.append((ref, ref))
                continue
            if (
                block.materialization
                is not FragmentBlockMaterialization.REUSE_PUBLISHED
            ):
                bindings.append((ref, ref))
                continue
            if self.publication_profile.graph_free:
                bindings.append(
                    (
                        ref,
                        self.backend._generated_semantic_fragment_plan_handle(
                            plan,
                            ref.local_block_id,
                        ),
                    )
                )
            else:
                rebound = identity_index.rebind_identity(block.stable_identity)
                if rebound.block is None:
                    raise ValueError(
                        f"semantic binding cannot rebind {ref.local_block_id!r}"
                    )
                bindings.append((ref, rebound.block.handle))
        return BoundSemanticCfgTransaction(
            prepared=prepared,
            session_id=prepared.attempt_id.session_id,
            generation=prepared.attempt_id.generation,
            bindings=tuple(bindings),
            plan=plan,
            fragment=prepared.fragment,
        )

    def realize(self, bound: BoundCfgTransaction, gateway: object) -> object:
        if not isinstance(bound, BoundSemanticCfgTransaction):
            raise TypeError("semantic participant requires exact bound authority")
        if gateway is not self.gateway or gateway.identity_index is not (
            self.gateway.identity_index
        ):
            raise ValueError("semantic participant received a foreign gateway")
        if bool(getattr(gateway, "active", False)):
            raise RuntimeError("semantic realization requires an idle gateway")
        plan = bound.plan
        fragment = bound.fragment
        patch_plan = bound.patch_plan
        assert plan is not None
        assert fragment is not None
        if patch_plan is None:
            raise RuntimeError("semantic realization lacks final PatchPlan binding")
        gateway._begin_semantic_fragment_batch(
            self.backend,
            plan,
            fragment.authority.root_inventory,
            fragment.authority.attempt_id,
            fragment.authority.snapshot_id,
            fragment,
            patch_plan,
            self.publication_profile,
        )
        return self.backend._realize_semantic_patch_plan(patch_plan, fragment)

    def observe(self, receipt: object, live_graph: object) -> object:
        if not isinstance(receipt, ProjectedFragment):
            raise TypeError("semantic participant requires a realized projection")
        if live_graph is not getattr(self.backend, "mba", None):
            raise ValueError("semantic participant received a foreign live graph")
        if not bool(getattr(self.gateway, "active", False)):
            raise RuntimeError("semantic observation requires an active realization")
        plan = self.gateway._active_fragment_plan
        if not isinstance(plan, FragmentPlan):
            raise RuntimeError("semantic observation lacks exact plan authority")
        realized_validation = validate_fragment_projection(plan, receipt)
        if not realized_validation.passed:
            raise SemanticFragmentPublicationRejected(
                "staged_observation",
                realized_validation,
            )
        prepared = self.gateway._active_prepared_semantic_fragment
        if not isinstance(prepared, PreparedSemanticFragment):
            raise RuntimeError(
                "semantic observation lacks immutable preflight authority"
            )
        realized_divergence = compare_fragment_projection_obligations(
            prepared.authority.projection,
            receipt,
        )
        if realized_divergence:
            raise RuntimeError(
                "realized semantic fragment diverged from immutable preflight: "
                + ", ".join(realized_divergence)
            )
        observed = self.backend._observe_staged_semantic_fragment(plan)
        if not isinstance(observed, ProjectedFragment):
            raise TypeError("semantic backend returned an invalid live observation")
        validation = validate_fragment_projection(plan, observed)
        if not validation.passed:
            raise SemanticFragmentPublicationRejected(
                "staged_observation",
                validation,
            )
        divergence = compare_fragment_projection_obligations(
            prepared.authority.projection,
            observed,
        )
        if divergence:
            raise RuntimeError(
                "staged semantic fragment diverged from immutable preflight: "
                + ", ".join(divergence)
            )
        return observed


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


_INTERR_PATTERN = re.compile(r"\b(?:INTERR\s*:?\s*|Internal error\s+)(?P<code>\d+)\b")


def _exception_chain(error: Exception) -> tuple[Exception, ...]:
    """Return the causal exception chain from initiating cause to wrapper."""
    chain: list[Exception] = []
    seen: set[int] = set()
    current: BaseException | None = error
    while isinstance(current, Exception) and id(current) not in seen:
        seen.add(id(current))
        chain.append(current)
        current = (
            current.__cause__ if current.__cause__ is not None else current.__context__
        )
    chain.reverse()
    return tuple(chain)


def _explicit_exception_chain(error: Exception) -> tuple[Exception, ...]:
    """Return only causes explicitly owned by ``error`` and its wrappers."""
    chain: list[Exception] = []
    seen: set[int] = set()
    current: BaseException | None = error
    while isinstance(current, Exception) and id(current) not in seen:
        seen.add(id(current))
        chain.append(current)
        current = current.__cause__
    chain.reverse()
    return tuple(chain)


def _interr_code(error: Exception) -> int | None:
    observed = getattr(error, "d810_interr_code", None)
    if observed is not None:
        return int(observed)
    match = _INTERR_PATTERN.search(str(error))
    return None if match is None else int(match.group("code"))


def _failure_message(error: Exception) -> str:
    if isinstance(error, SemanticFragmentPublicationRejected):
        failures = "; ".join(
            f"{failure.postcondition.value}:{failure.subject_id} - {failure.reason}"
            for failure in error.validation.failures
        )
        if failures:
            return f"{error.phase} semantic validation failed: {failures}"
    return str(error) or "<no exception message>"


def _first_failed_obligation(error: Exception, *, failure_phase: str) -> str:
    """Return the first typed validation obligation, or a runtime phase id."""
    for candidate in _exception_chain(error):
        if isinstance(candidate, SemanticFragmentPublicationRejected):
            failures = candidate.validation.failures
            if failures:
                failure = failures[0]
                return f"{failure.postcondition.value}:{failure.subject_id}"
        if isinstance(candidate, FragmentProjectionFailure):
            return f"{candidate.postcondition.value}:{candidate.subject_id}"
    return f"runtime:{str(failure_phase)}"


def _record_primary_failure(
    gateway: object,
    plan: FragmentPlan,
    *,
    phase: str,
    error: Exception,
) -> None:
    chain = _exception_chain(error)
    primary = chain[0]
    primary_kind = "stage" if phase == "stage" else "publication"
    gateway._record_fragment_failure(
        plan,
        MbaSemanticFragmentFailure(
            failure_kind=primary_kind,
            phase=phase,
            error_type=type(primary).__name__,
            error_message=_failure_message(primary),
        ),
    )
    for candidate in chain:
        interr_code = _interr_code(candidate)
        if interr_code is None:
            continue
        gateway._record_fragment_failure(
            plan,
            MbaSemanticFragmentFailure(
                failure_kind="verifier",
                phase=(phase if candidate is primary else f"{phase}_cleanup"),
                error_type=type(candidate).__name__,
                error_message=_failure_message(candidate),
                interr_code=interr_code,
                verification_context=str(
                    getattr(
                        candidate,
                        "d810_verification_context",
                        "",
                    )
                ),
            ),
        )


def _record_rollback_failure(
    gateway: object,
    plan: FragmentPlan,
    error: Exception,
) -> None:
    gateway._record_fragment_failure(
        plan,
        MbaSemanticFragmentFailure(
            failure_kind="rollback",
            phase="rollback",
            error_type=type(error).__name__,
            error_message=_failure_message(error),
        ),
    )
    for candidate in _explicit_exception_chain(error):
        interr_code = _interr_code(candidate)
        if interr_code is None:
            continue
        gateway._record_fragment_failure(
            plan,
            MbaSemanticFragmentFailure(
                failure_kind="verifier",
                phase="rollback_verification",
                error_type=type(candidate).__name__,
                error_message=_failure_message(candidate),
                interr_code=interr_code,
                verification_context=str(
                    getattr(
                        candidate,
                        "d810_verification_context",
                        "",
                    )
                ),
            ),
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
        raise TypeError("fragment publication requires a lifecycle authority")
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


@dataclass
class _SemanticPatchLifecycle:
    """Hex-Rays lifecycle port driven exclusively by the shared coordinator."""

    gateway: object
    backend: object
    participant: SemanticFragmentTransactionParticipant
    bound: BoundSemanticCfgTransaction
    plan: FragmentPlan
    prepared: PreparedSemanticFragment
    projection: ProjectedFragment
    prepublication: FragmentValidationResult
    root_inventory: SemanticFragmentRootInventory
    lifecycle_authority: FragmentPublicationLifecycleAuthority
    publication_profile: SemanticFragmentPublicationProfile = (
        SemanticFragmentPublicationProfile.CFG_READY
    )
    stage_attempted: bool = False
    lifecycle_staged: bool = False
    root_attempted: bool = False
    rollback_token: object | None = None
    failure_phase: str = "begin"

    def begin(self, patch_plan):
        from dataclasses import replace
        from d810.transforms.plan import PatchPlan

        self.failure_phase = "begin"
        if (
            not isinstance(patch_plan, PatchPlan)
            or patch_plan.plan_id != self.plan.plan_id
            or patch_plan.semantic_contract is None
            or patch_plan.semantic_contract.fragment_plan is not self.plan
        ):
            raise ValueError("coordinator PatchPlan authority differs from preflight")
        return replace(self.bound, patch_plan=patch_plan)

    def realize(self, patch_plan, begun):
        self.failure_phase = "stage"
        self.stage_attempted = True
        staged = self.participant.realize(begun, self.gateway)
        if not isinstance(staged, ProjectedFragment):
            raise TypeError("semantic-fragment backend returned an invalid projection")
        staged = self.participant.observe(staged, self.backend.mba)
        self.gateway._record_fragment_staged(self.plan)
        _mark_lifecycle_staged(self.lifecycle_authority, self.plan)
        self.lifecycle_staged = True

        self.failure_phase = "current_identity_binding"
        self.gateway._record_fragment_current_mba_identity_binding(
            self.plan,
            self.backend._semantic_fragment_current_mba_identity_binding(self.plan),
        )

        self.failure_phase = "prepublication_validation"
        staged_validation = validate_fragment_projection(self.plan, staged)
        if not staged_validation.passed:
            raise SemanticFragmentPublicationRejected(
                "staged_observation",
                staged_validation,
            )
        divergence = compare_fragment_projection_obligations(
            self.projection,
            staged,
        )
        if divergence:
            raise RuntimeError(
                "staged semantic fragment diverged from immutable preflight: "
                + ", ".join(divergence)
            )
        staged_cfg = fragment_cfg_projection(
            self.plan,
            self.prepared.authority.snapshot.projection_input,
            staged,
        )
        CfgContract().verify_projection(staged_cfg, scope="full")
        self.gateway._record_fragment_validation(
            plan=self.plan,
            phase="prepublication",
            validation=self.prepublication,
        )
        if not self.prepublication.passed:
            raise SemanticFragmentPublicationRejected(
                "prepublication",
                self.prepublication,
            )
        if any(
            operation.reference_route_authority is not None
            for operation in self.plan.operations
        ):
            self.failure_phase = "detached_route_oracle"
            detached_oracle = compare_detached_route_oracle(self.plan, staged)
            self.gateway._record_fragment_route_oracle(self.plan, detached_oracle)
            if not detached_oracle.passed:
                failure = detached_oracle.first_failure
                assert failure is not None
                raise DetachedRouteOracleRejected(
                    "detached route oracle rejected "
                    f"{failure.route_id}: {failure.failed_invariant}: "
                    f"{failure.reason}",
                    reason_code="detached_route_oracle_comparison_failed",
                    payload={
                        "failed_invariant": failure.failed_invariant,
                        "route_id": failure.route_id,
                    },
                )
        _mark_lifecycle_validated(
            self.lifecycle_authority,
            self.plan,
            self.prepublication,
        )

        if self.publication_profile.graph_free:
            self.failure_phase = "logical_root_publication"
            self.gateway._record_fragment_root_publication_attempted(self.plan)
            for group in self.root_inventory.groups:
                self.gateway._record_fragment_root_group_publication_attempted(
                    self.plan,
                    group.group_id,
                )
                self.gateway._record_fragment_root_group_publication_succeeded(
                    self.plan,
                    group.group_id,
                )
            self.gateway._record_fragment_root_publication_succeeded(self.plan)
            self.failure_phase = "generated_verification"
            self.backend._verify_generated_semantic_fragment(self.plan)
            return staged

        self.failure_phase = "root_preparation"
        self.rollback_token = self.backend._prepare_semantic_fragment_root_publication(
            self.plan,
            self.root_inventory,
        )
        self.root_attempted = True
        self.gateway._record_fragment_root_publication_attempted(self.plan)
        self.failure_phase = "root_publication"
        self.gateway._record_fragment_mutation_started(self.plan)
        self.backend._publish_semantic_patch_roots(
            patch_plan,
            self.rollback_token,
        )
        self.gateway._record_fragment_root_publication_succeeded(self.plan)
        for _root_edge in self.root_inventory.items:
            self.gateway.record_edge_redirect()
        self.failure_phase = "root_rebuild"
        self.backend._rebuild_semantic_fragment_chains(self.plan)
        return staged

    def observe(self, patch_plan, realized):
        self.failure_phase = "postpublication_observation"
        observed = self.backend._observe_published_semantic_fragment_graph(self.plan)
        if not isinstance(observed, PublishedFragmentGraphObservation):
            raise TypeError(
                "semantic-fragment backend returned an invalid published graph observation"
            )
        return observed

    def validate(self, patch_plan, observed):
        self.failure_phase = "postpublication_validation"
        post_cfg = fragment_cfg_projection(
            self.plan,
            self.prepared.authority.snapshot.projection_input,
            observed.projection,
        )
        CfgContract().verify_projection(post_cfg, scope="full")
        postpublication = validate_published_fragment_observation(
            self.plan,
            observed.semantics,
            self.projection,
        )
        self.gateway._record_fragment_observed(self.plan)
        self.gateway._record_fragment_validation(
            plan=self.plan,
            phase="postpublication",
            validation=postpublication,
        )
        if not postpublication.passed:
            raise SemanticFragmentPublicationRejected(
                "postpublication",
                postpublication,
            )
        self.gateway._record_fragment_semantic_validation(
            plan=self.plan,
            prepublication=self.prepublication,
            postpublication=postpublication,
        )
        return postpublication

    def commit(self, patch_plan, validated):
        self.failure_phase = "commit_finalization"
        self.backend._finalize_semantic_fragment_for_commit(self.plan)
        self.failure_phase = "commit_identity_binding"
        self.gateway._replace_fragment_current_mba_identity_binding(
            self.plan,
            self.backend._semantic_fragment_current_mba_identity_binding(self.plan),
        )
        self.failure_phase = "commit"
        receipt = self.gateway.commit()
        _commit_lifecycle(self.lifecycle_authority, self.plan, receipt)
        self.backend._complete_semantic_fragment_publication(self.plan)
        return receipt

    def fail(self, patch_plan, original_error: Exception, phase: str) -> None:
        primary_error = _exception_chain(original_error)[0]
        if bool(getattr(self.gateway, "active", False)):
            _record_primary_failure(
                self.gateway,
                self.plan,
                phase=self.failure_phase,
                error=original_error,
            )
        if self.gateway.mutation_started:
            rollback_error: Exception | None = None
            rollback_succeeded = False
            if (
                not self.root_attempted
                and self.stage_attempted
                and bool(self.plan.constant_materializations)
            ):
                try:
                    self.backend._discard_staged_semantic_fragment(self.plan)
                    rollback_succeeded = True
                except Exception as error:
                    rollback_error = error
                    _record_rollback_failure(self.gateway, self.plan, error)
                try:
                    self.gateway._record_fragment_rollback(
                        self.plan,
                        succeeded=rollback_succeeded,
                    )
                except Exception as error:
                    rollback_error = rollback_error or error
                    rollback_succeeded = False
                    _record_rollback_failure(self.gateway, self.plan, error)
                if rollback_succeeded:
                    reason = _failure_message(primary_error)
                    self.gateway._record_rolled_back_cfg_failure(
                        reason=reason,
                        failure_phase=self.failure_phase,
                        first_failed_obligation=_first_failed_obligation(
                            original_error,
                            failure_phase=self.failure_phase,
                        ),
                        interr_code=_interr_code(primary_error),
                    )
                    self.gateway.abort(reason=reason)
                    if self.lifecycle_staged:
                        _abort_lifecycle(
                            self.lifecycle_authority,
                            self.plan,
                            reason=reason,
                        )
                    return
            poison_error = rollback_error or primary_error
            failure = self.gateway._poison_cfg_generation(
                reason=_failure_message(poison_error),
                failure_phase=self.failure_phase,
                first_failed_obligation=_first_failed_obligation(
                    poison_error,
                    failure_phase=self.failure_phase,
                ),
                interr_code=_interr_code(poison_error),
                plan=self.plan,
            )
            self.lifecycle_authority.request_poisoned_generation_restart(
                self.plan,
                failure,
            )
            raise CfgGenerationPoisoned(failure) from original_error

        if self.gateway.transaction_failure is None:
            self.gateway._record_clean_cfg_failure(
                reason=_failure_message(primary_error),
                failure_phase=self.failure_phase,
                first_failed_obligation=_first_failed_obligation(
                    original_error,
                    failure_phase=self.failure_phase,
                ),
                interr_code=_interr_code(primary_error),
            )
        stage_cleanup_failed = bool(
            getattr(
                original_error,
                "d810_semantic_stage_cleanup_failed",
                False,
            )
        )
        recovery_error: Exception | None = (
            original_error if stage_cleanup_failed else None
        )
        recovery_succeeded = not stage_cleanup_failed
        if self.root_attempted:
            try:
                self.backend._rollback_semantic_fragment_roots(
                    self.plan,
                    self.rollback_token,
                )
                self.backend._rebuild_semantic_fragment_chains(self.plan)
            except Exception as error:
                _record_rollback_failure(self.gateway, self.plan, error)
                recovery_error = error
                recovery_succeeded = False
        if self.stage_attempted and not stage_cleanup_failed:
            try:
                self.backend._discard_staged_semantic_fragment(self.plan)
            except Exception as error:
                _record_rollback_failure(self.gateway, self.plan, error)
                recovery_succeeded = False
                recovery_error = recovery_error or error
        if self.root_attempted or self.stage_attempted:
            try:
                self.gateway._record_fragment_rollback(
                    self.plan,
                    succeeded=recovery_succeeded,
                )
            except Exception as error:
                _record_rollback_failure(self.gateway, self.plan, error)
                recovery_succeeded = False
                recovery_error = recovery_error or error
        reason = _failure_message(primary_error)
        if recovery_error is not None:
            reason += (
                f"; rollback failed: {type(recovery_error).__name__}: {recovery_error}"
            )
        try:
            if bool(getattr(self.gateway, "active", False)):
                self.gateway.abort(reason=reason)
        except Exception as error:
            recovery_error = recovery_error or error
        if self.lifecycle_staged:
            try:
                _abort_lifecycle(
                    self.lifecycle_authority,
                    self.plan,
                    reason=reason,
                )
            except Exception as error:
                recovery_error = recovery_error or error
        if recovery_error is not None:
            raise SemanticFragmentRollbackFailed(
                primary_error,
                recovery_error,
            ) from recovery_error


def execute_patch_transaction(
    gateway: object,
    backend: object,
    plan: FragmentPlan,
    publication_profile: SemanticFragmentPublicationProfile = (
        SemanticFragmentPublicationProfile.CFG_READY
    ),
):
    """Project, preflight, bind, lower, realize, and commit one typed transaction."""
    if not isinstance(plan, FragmentPlan):
        raise TypeError("semantic fragment transaction requires a FragmentPlan")
    if not isinstance(publication_profile, SemanticFragmentPublicationProfile):
        raise TypeError(
            "semantic fragment transaction requires a typed publication profile"
        )
    if bool(getattr(gateway, "active", False)):
        raise RuntimeError(
            "semantic fragment transaction requires an independent batch"
        )
    _require_backend_port(backend)
    lifecycle_authority = _require_lifecycle_authority(gateway)
    transaction_attempt = TransactionAttemptId.new(
        plan.plan_id,
        str(gateway.session_id),
        int(gateway.generation),
    )
    gateway._record_fragment_attempt_planned(plan, transaction_attempt)
    _mark_lifecycle_plan_ready(lifecycle_authority, plan)
    participant = SemanticFragmentTransactionParticipant(
        gateway,
        backend,
        transaction_attempt,
        publication_profile,
    )
    try:
        projected = participant.project(plan, None)
        gateway._record_cfg_projected()
        prepared = participant.preflight(projected)
        gateway._record_cfg_preflighted()
        bound = participant.bind(prepared, gateway.identity_index)
    except FragmentProjectionFailure as error:
        rejection = FragmentValidationResult(
            plan_id=plan.plan_id,
            atomic_group_id=plan.atomic_group_id,
            outcomes=(
                FragmentValidationOutcome(
                    postcondition=error.postcondition,
                    subject_id=error.subject_id,
                    passed=False,
                    reason=error.reason,
                ),
            ),
        )
        raise SemanticFragmentPublicationRejected(
            "preflight_projection",
            rejection,
        ) from error
    if not isinstance(prepared, PreparedSemanticCfgTransaction):
        raise TypeError("semantic participant returned invalid preflight authority")
    if not isinstance(bound, BoundSemanticCfgTransaction):
        raise TypeError("semantic participant returned invalid bound authority")
    prepared_fragment = prepared.fragment
    prepublication = prepared.validation
    assert prepared_fragment is not None
    assert prepublication is not None

    from d810.transforms.fragment_to_patch import (
        CfgTransactionCoordinator,
        FragmentTransactionParticipant,
    )

    lifecycle = _SemanticPatchLifecycle(
        gateway=gateway,
        backend=backend,
        participant=participant,
        bound=bound,
        plan=plan,
        prepared=prepared_fragment,
        projection=prepared_fragment.authority.projection,
        prepublication=prepublication,
        root_inventory=prepared_fragment.authority.root_inventory,
        lifecycle_authority=lifecycle_authority,
        publication_profile=publication_profile,
    )
    coordinator = CfgTransactionCoordinator(lifecycle)
    return coordinator.execute(
        FragmentTransactionParticipant(),
        plan,
        prepared_projection=prepared_fragment,
    )


__all__ = [
    "BoundSemanticCfgTransaction",
    "PreparedSemanticCfgTransaction",
    "SemanticFragmentCfgProjection",
    "SemanticFragmentPublicationRejected",
    "SemanticFragmentRollbackFailed",
    "SemanticFragmentTransactionParticipant",
    "execute_patch_transaction",
]
