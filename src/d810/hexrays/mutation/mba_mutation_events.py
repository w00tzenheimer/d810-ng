"""Synchronous receipt gateway for structural MBA mutation."""

from __future__ import annotations

from dataclasses import dataclass, field, replace
from enum import Enum
import uuid

from d810.hexrays.mutation.fragment_publication_lifecycle import (
    FragmentPublicationLifecycleAuthority,
)
from d810.core.events import EventEmitter
from d810.core.logging import getLogger
from d810.core.native_preanalysis_key import NativePreanalysisKey
from d810.core.typing import Iterable
from d810.hexrays.ir.mba_identity_index import (
    MbaBlockIdentityIndex,
    PlanBlockCreationReceipt,
    PlanBlockReservation,
)
from d810.hexrays.ir.logical_block_proxy import (
    LogicalBlockVersion,
    LogicalBlockVersionTransition,
)
from d810.hexrays.ir.semantic_edge import (
    LogicalSemanticEdgeOperation,
    SemanticEdgeOperationRejected,
)
from d810.hexrays.mutation.semantic_fragment_inventory import (
    SemanticFragmentRootInventory,
    semantic_fragment_root_group_id,
)
from d810.hexrays.mutation.semantic_fragment_failure import (
    MbaSemanticFragmentFailure,
)
from d810.hexrays.mutation.semantic_fragment_preparation import (
    PreparedSemanticFragment,
)
from d810.ir.block_identity import (
    CurrentMbaIdentityBindingSnapshot,
    MbaBlockHandle,
    StableBlockIdentity,
)
from d810.ir.semantic_edge import SemanticEdgeRole
from d810.ir.flowgraph import FlowGraph
from d810.transforms.fragment_plan import (
    FragmentBlockMaterialization,
    FragmentConditionalSelectEnvelope,
    FragmentPlan,
    FragmentReferencedImportedConditionalSelectEnvelope,
    FragmentSetccFallthroughDelivery,
    FragmentSetccIndexedTableNormalization,
    serialize_fragment_plan,
)
from d810.transforms.detached_route_oracle import DetachedRouteOracleResult
from d810.transforms.fragment_validation import FragmentValidationResult
from d810.transforms.cfg_transaction import (
    CfgGenerationPoisoned,
    CfgTransactionFailure,
    CfgTransactionPhase,
    PlanBlockRef,
    TransactionAttemptId,
)


logger = getLogger(__name__)


class StructuralMutationKind(Enum):
    """Structural mutation families that can invalidate current bindings."""

    EDGE_REDIRECT = "edge_redirect"
    BLOCK_INSERT = "block_insert"
    BLOCK_REMOVE = "block_remove"
    BLOCK_REPLACE = "block_replace"
    FRAGMENT_PUBLICATION = "fragment_publication"


@dataclass(frozen=True, slots=True)
class MbaMutationRootPublicationGroup:
    """Serial-free status of one predecessor-atomic root publication group."""

    group_id: str
    predecessor_block_id: str
    predecessor_anchor_ea: int
    edge_ids: tuple[str, ...]
    edge_roles: tuple[SemanticEdgeRole, ...]
    original_block_ids: tuple[str, ...]
    replacement_block_ids: tuple[str, ...]
    publication_attempted: bool = False
    publication_succeeded: bool = False
    rollback_attempted: bool = False
    rollback_succeeded: bool | None = None

    def __post_init__(self) -> None:
        group_id = str(self.group_id)
        predecessor_block_id = str(self.predecessor_block_id)
        predecessor_anchor_ea = int(self.predecessor_anchor_ea)
        edge_ids = tuple(str(edge_id) for edge_id in self.edge_ids)
        edge_roles = tuple(self.edge_roles)
        original_block_ids = tuple(
            str(block_id) for block_id in self.original_block_ids
        )
        replacement_block_ids = tuple(
            str(block_id) for block_id in self.replacement_block_ids
        )
        if group_id != semantic_fragment_root_group_id(predecessor_block_id):
            raise ValueError("root publication group identity drifted")
        if predecessor_anchor_ea < 0:
            raise ValueError("root publication group requires an EA anchor")
        edge_count = len(edge_ids)
        if (
            edge_count == 0
            or len(set(edge_ids)) != edge_count
            or len(edge_roles) != edge_count
            or len(original_block_ids) != edge_count
            or len(replacement_block_ids) != edge_count
            or any(not edge_id for edge_id in edge_ids)
            or any(not block_id for block_id in original_block_ids)
            or any(not block_id for block_id in replacement_block_ids)
            or any(not isinstance(role, SemanticEdgeRole) for role in edge_roles)
        ):
            raise ValueError(
                "root publication group requires aligned semantic edge ownership"
            )
        publication_attempted = bool(self.publication_attempted)
        publication_succeeded = bool(self.publication_succeeded)
        rollback_attempted = bool(self.rollback_attempted)
        rollback_succeeded = (
            None if self.rollback_succeeded is None else bool(self.rollback_succeeded)
        )
        if publication_succeeded and not publication_attempted:
            raise ValueError("root publication cannot succeed before its attempt")
        if rollback_attempted != (rollback_succeeded is not None):
            raise ValueError(
                "root-group rollback outcome is present exactly when attempted"
            )
        if rollback_attempted and not publication_attempted:
            raise ValueError("root-group rollback requires a publication attempt")
        object.__setattr__(self, "group_id", group_id)
        object.__setattr__(self, "predecessor_block_id", predecessor_block_id)
        object.__setattr__(
            self,
            "predecessor_anchor_ea",
            predecessor_anchor_ea,
        )
        object.__setattr__(self, "edge_ids", edge_ids)
        object.__setattr__(self, "edge_roles", edge_roles)
        object.__setattr__(self, "original_block_ids", original_block_ids)
        object.__setattr__(self, "replacement_block_ids", replacement_block_ids)
        object.__setattr__(
            self,
            "publication_attempted",
            publication_attempted,
        )
        object.__setattr__(
            self,
            "publication_succeeded",
            publication_succeeded,
        )
        object.__setattr__(self, "rollback_attempted", rollback_attempted)
        object.__setattr__(self, "rollback_succeeded", rollback_succeeded)


@dataclass(frozen=True, slots=True)
class MbaMutationReceipt:
    """Post-commit record for one atomic structural mutation batch."""

    mutation_batch_id: str
    kind: StructuralMutationKind
    pre_generation: int
    post_generation: int
    evidence_generation: int
    affected_identities: tuple[StableBlockIdentity, ...]
    operation_count: int = 0
    planned_operation_count: int = 0
    description: str = ""
    version_transitions: tuple[LogicalBlockVersionTransition, ...] = ()
    fragment_plan_id: str = ""
    fragment_atomic_group_id: str = ""
    root_publication_groups: tuple[MbaMutationRootPublicationGroup, ...] = ()
    prepublication_validation: FragmentValidationResult | None = None
    postpublication_validation: FragmentValidationResult | None = None
    root_publication_confirmed: bool = False
    current_mba_identity_binding: CurrentMbaIdentityBindingSnapshot | None = None
    detached_route_oracle: DetachedRouteOracleResult | None = None

    def __post_init__(self) -> None:
        pre_generation = int(self.pre_generation)
        post_generation = int(self.post_generation)
        evidence_generation = int(self.evidence_generation)
        if pre_generation < 0 or post_generation != pre_generation + 1:
            raise ValueError("a mutation receipt must advance exactly one generation")
        if evidence_generation < 0:
            raise ValueError(
                "a mutation receipt requires a non-negative evidence generation"
            )
        if int(self.operation_count) < 0:
            raise ValueError("a mutation receipt cannot have negative operations")
        if not str(self.mutation_batch_id):
            raise ValueError("a mutation receipt requires a batch id")
        if int(self.planned_operation_count) < int(self.operation_count):
            raise ValueError("applied operations cannot exceed the planned count")
        object.__setattr__(self, "pre_generation", pre_generation)
        object.__setattr__(self, "post_generation", post_generation)
        object.__setattr__(self, "evidence_generation", evidence_generation)
        object.__setattr__(self, "operation_count", int(self.operation_count))
        object.__setattr__(
            self,
            "planned_operation_count",
            int(self.planned_operation_count),
        )
        object.__setattr__(
            self,
            "affected_identities",
            tuple(dict.fromkeys(self.affected_identities)),
        )
        fragment_plan_id = str(self.fragment_plan_id)
        fragment_atomic_group_id = str(self.fragment_atomic_group_id)
        root_publication_groups = tuple(self.root_publication_groups)
        current_mba_identity_binding = self.current_mba_identity_binding
        detached_route_oracle = self.detached_route_oracle
        if any(
            not isinstance(group, MbaMutationRootPublicationGroup)
            for group in root_publication_groups
        ) or len({group.group_id for group in root_publication_groups}) != len(
            root_publication_groups
        ):
            raise TypeError("fragment receipt contains invalid root groups")
        has_fragment = bool(fragment_plan_id)
        if (self.kind is StructuralMutationKind.FRAGMENT_PUBLICATION) != has_fragment:
            raise ValueError(
                "fragment-publication receipt requires validated fragment context"
            )
        if has_fragment != bool(fragment_atomic_group_id):
            raise ValueError("fragment receipt requires both plan and atomic-group ids")
        if has_fragment:
            if not isinstance(
                current_mba_identity_binding,
                CurrentMbaIdentityBindingSnapshot,
            ):
                raise ValueError(
                    "fragment receipt requires current-MBA identity binding"
                )
            if not root_publication_groups or any(
                not group.publication_attempted
                or not group.publication_succeeded
                or group.rollback_attempted
                for group in root_publication_groups
            ):
                raise ValueError(
                    "committed fragment requires every root group to be published"
                )
            for phase, validation in (
                ("prepublication", self.prepublication_validation),
                ("postpublication", self.postpublication_validation),
            ):
                if not isinstance(validation, FragmentValidationResult):
                    raise ValueError(f"fragment receipt requires {phase} validation")
                if not validation.passed:
                    raise ValueError(f"fragment receipt cannot contain failed {phase}")
                if (
                    validation.plan_id != fragment_plan_id
                    or validation.atomic_group_id != fragment_atomic_group_id
                ):
                    raise ValueError("fragment receipt validation scope drifted")
            if not self.root_publication_confirmed:
                raise ValueError("fragment receipt requires confirmed root publication")
            if detached_route_oracle is not None and (
                not isinstance(detached_route_oracle, DetachedRouteOracleResult)
                or detached_route_oracle.plan_id != fragment_plan_id
                or detached_route_oracle.atomic_group_id != fragment_atomic_group_id
                or not detached_route_oracle.passed
            ):
                raise ValueError(
                    "fragment receipt contains invalid detached route authority"
                )
        elif (
            self.prepublication_validation is not None
            or self.postpublication_validation is not None
            or self.root_publication_confirmed
            or root_publication_groups
            or current_mba_identity_binding is not None
            or detached_route_oracle is not None
        ):
            raise ValueError("non-fragment receipt cannot carry fragment validation")
        object.__setattr__(self, "fragment_plan_id", fragment_plan_id)
        object.__setattr__(
            self,
            "fragment_atomic_group_id",
            fragment_atomic_group_id,
        )
        object.__setattr__(
            self,
            "root_publication_groups",
            root_publication_groups,
        )
        object.__setattr__(
            self,
            "root_publication_confirmed",
            bool(self.root_publication_confirmed),
        )
        object.__setattr__(
            self,
            "current_mba_identity_binding",
            current_mba_identity_binding,
        )


@dataclass(frozen=True, slots=True)
class MbaMutationCommitted:
    """Typed observation emitted only after the index has applied a receipt."""

    session_id: str
    function_ea: int
    maturity: int
    mba_generation_before: int
    mba_generation_after: int
    evidence_generation: int
    receipt: MbaMutationReceipt


@dataclass(frozen=True, slots=True)
class MbaMutationPlanItem:
    item_index: int
    mutation_kind: str
    source_serial: int | None = None
    source_anchor_ea: int | None = None
    source_identity: StableBlockIdentity | None = None
    target_serial: int | None = None
    target_anchor_ea: int | None = None
    target_identity: StableBlockIdentity | None = None
    disposition: str = "planned"
    reason: str = ""


@dataclass(frozen=True, slots=True)
class MbaMutationPlanned:
    session_id: str
    function_ea: int
    maturity: int
    mba_generation: int
    evidence_generation: int
    mutation_batch_id: str
    kind: StructuralMutationKind
    planned_operation_count: int
    description: str
    items: tuple[MbaMutationPlanItem, ...] = ()
    fragment_plan_id: str = ""
    fragment_atomic_group_id: str = ""
    fragment_plan_json: str = ""
    root_publication_groups: tuple[MbaMutationRootPublicationGroup, ...] = ()


@dataclass(frozen=True, slots=True)
class MbaSemanticFragmentRouteOracleCompared:
    """Detached route comparison emitted before any root authority changes."""

    session_id: str
    function_ea: int
    maturity: int
    mba_generation: int
    evidence_generation: int
    mutation_batch_id: str
    run_id: str
    plan_id: str
    atomic_group_id: str
    reference_ledger_identities: tuple[tuple[str, str], ...]
    result: DetachedRouteOracleResult

    def __post_init__(self) -> None:
        if not all(
            str(value)
            for value in (
                self.session_id,
                self.mutation_batch_id,
                self.run_id,
                self.plan_id,
                self.atomic_group_id,
            )
        ):
            raise ValueError("detached route comparison requires complete identity")
        if (
            not isinstance(self.result, DetachedRouteOracleResult)
            or self.result.plan_id != self.plan_id
            or self.result.atomic_group_id != self.atomic_group_id
        ):
            raise ValueError("detached route comparison scope drifted")
        ledger_identities = tuple(
            (str(route_id), str(ledger_identity))
            for route_id, ledger_identity in self.reference_ledger_identities
        )
        comparison_route_ids = tuple(
            comparison.route_id for comparison in self.result.comparisons
        )
        if tuple(
            route_id for route_id, _ledger in ledger_identities
        ) != comparison_route_ids or any(
            not ledger_identity for _route, ledger_identity in ledger_identities
        ):
            raise ValueError(
                "detached route comparison requires aligned ledger identities"
            )
        object.__setattr__(
            self,
            "reference_ledger_identities",
            ledger_identities,
        )


def _fragment_reference_ledger_identities(
    plan: FragmentPlan,
) -> tuple[tuple[str, str], ...]:
    """Return every bound route in the plan's semantic operation order."""
    missing_direct_authority = tuple(
        operation.operation_id
        for operation in plan.operations
        if operation.direct_transfer_rewrite is not None
        and operation.reference_route_authority is None
    )
    if missing_direct_authority:
        raise ValueError(
            "detached route oracle lacks direct reference authority: "
            + ", ".join(missing_direct_authority)
        )
    return tuple(
        (
            authority.reference_route.route_id,
            authority.reference_route.reference_ledger_identity,
        )
        for operation in plan.operations
        if (authority := operation.reference_route_authority) is not None
    )


@dataclass(frozen=True, slots=True)
class MbaMutationAborted:
    session_id: str
    function_ea: int
    maturity: int
    mba_generation: int
    evidence_generation: int
    mutation_batch_id: str
    kind: StructuralMutationKind
    planned_operation_count: int
    applied_operation_count: int
    description: str
    reason: str
    discarded_versions: tuple[LogicalBlockVersion, ...] = ()
    fragment_plan_id: str = ""
    fragment_atomic_group_id: str = ""
    root_publication_groups: tuple[MbaMutationRootPublicationGroup, ...] = ()
    fragment_staged: bool = False
    root_publication_attempted: bool = False
    root_publication_succeeded: bool = False
    rollback_attempted: bool = False
    rollback_succeeded: bool | None = None
    prepublication_validation: FragmentValidationResult | None = None
    postpublication_validation: FragmentValidationResult | None = None
    fragment_failures: tuple[MbaSemanticFragmentFailure, ...] = ()


@dataclass(frozen=True, slots=True)
class MbaMutationObservationFailure:
    """Structured failure of a non-authoritative mutation observer."""

    phase: str
    event_name: str
    mutation_batch_id: str
    error_type: str
    error_message: str


@dataclass(frozen=True, slots=True)
class MbaCfgPlanBlockBindingObserved:
    """Actual logical binding for one plan-owned block reference."""

    plan_ref: PlanBlockRef
    logical_version: LogicalBlockVersion
    returned_serial: int

    def __post_init__(self) -> None:
        if not isinstance(self.plan_ref, PlanBlockRef):
            raise TypeError("plan binding witness requires a PlanBlockRef")
        if not isinstance(self.logical_version, LogicalBlockVersion):
            raise TypeError("plan binding witness requires a logical version")
        if int(self.returned_serial) < 0:
            raise ValueError("plan binding witness requires a live coordinate")


@dataclass(frozen=True, slots=True)
class MbaCfgTransactionAuthorityObserved:
    """Typed runtime authority for one portable transaction phase."""

    session_id: str
    function_ea: int
    maturity: int
    attempt_id: TransactionAttemptId
    phase: CfgTransactionPhase
    phase_index: int
    mba_generation: int
    evidence_generation: int
    mutation_started: bool
    poisoned: bool
    insertion_quantity_initial: int | None = None
    plan_refs: tuple[PlanBlockRef, ...] = ()
    plan_bindings: tuple[MbaCfgPlanBlockBindingObserved, ...] = ()
    reservations: tuple[PlanBlockReservation, ...] = ()
    creation_receipts: tuple[PlanBlockCreationReceipt, ...] = ()
    creation_quantities: tuple[tuple[PlanBlockRef, int, int], ...] = ()
    invalidated_refs: tuple[PlanBlockRef, ...] = ()
    failure: CfgTransactionFailure | None = None

    def __post_init__(self) -> None:
        if not isinstance(self.attempt_id, TransactionAttemptId):
            raise TypeError("CFG transaction observation requires typed authority")
        if self.session_id != self.attempt_id.session_id:
            raise ValueError("CFG transaction observation session authority differs")
        if not isinstance(self.phase, CfgTransactionPhase):
            raise TypeError("CFG transaction observation requires a typed phase")
        if bool(self.poisoned) != (
            self.phase is CfgTransactionPhase.POISONED_RESTART_REQUIRED
        ):
            raise ValueError("CFG transaction poison flag differs from its phase")
        if self.failure is not None and self.failure.attempt_id != self.attempt_id:
            raise ValueError("CFG transaction failure authority differs")
        if any(ref.plan_id != self.attempt_id.plan_id for ref in self.plan_refs):
            raise ValueError("CFG transaction plan reference authority differs")
        if len(set(self.plan_refs)) != len(self.plan_refs):
            raise ValueError("CFG transaction plan references are not unique")
        if (
            self.insertion_quantity_initial is not None
            and int(self.insertion_quantity_initial) < 0
        ):
            raise ValueError("CFG transaction initial quantity must be non-negative")
        declared = set(self.plan_refs)
        observed_bindings = {item.plan_ref: item for item in self.plan_bindings}
        if len(observed_bindings) != len(self.plan_bindings):
            raise ValueError("CFG transaction plan bindings are not unique")
        if any(item.plan_ref not in declared for item in self.plan_bindings):
            raise ValueError("CFG transaction plan binding is not declared")
        if any(item.plan_ref not in declared for item in self.reservations):
            raise ValueError("CFG transaction reservation is not declared")
        if any(item.plan_ref not in declared for item in self.creation_receipts):
            raise ValueError("CFG transaction creation receipt is not declared")
        for receipt in self.creation_receipts:
            binding = observed_bindings.get(receipt.plan_ref)
            if (
                binding is not None
                and binding.logical_version is not receipt.logical_version
            ):
                raise ValueError("CFG transaction creation binding differs")
        if any(item[0] not in declared for item in self.creation_quantities):
            raise ValueError("CFG transaction creation quantity is not declared")
        if any(item not in declared for item in self.invalidated_refs):
            raise ValueError("CFG transaction invalidation is not declared")


@dataclass(slots=True)
class MbaMutationGateway:
    """The sole control plane for serial shifts in a modifier transaction.

    The SDK mutation happens in the modifier.  Immediately afterwards that
    modifier records the effect here; the index is updated synchronously, so a
    later queued modification cannot observe a stale serial.  The emitted
    event is therefore diagnostic/lineage observation, never delayed routing.
    """

    native_key: NativePreanalysisKey
    generation: int = 0
    session_id: str = "mutation-gateway"
    function_ea: int = 0
    maturity: int = 0
    identity_index: MbaBlockIdentityIndex | None = None
    event_emitter: EventEmitter | None = None
    lifecycle_authority: FragmentPublicationLifecycleAuthority | None = None
    _receipts: list[MbaMutationReceipt] = field(default_factory=list, repr=False)
    _observation_failures: list[MbaMutationObservationFailure] = field(
        default_factory=list,
        repr=False,
    )
    _active_kind: StructuralMutationKind | None = field(default=None, init=False)
    _active_description: str = field(default="", init=False)
    _affected_identities: set[StableBlockIdentity] = field(
        default_factory=set,
        init=False,
        repr=False,
    )
    _operation_count: int = field(default=0, init=False)
    _active_batch_id: str | None = field(default=None, init=False)
    _planned_operation_count: int = field(default=0, init=False)
    # Planned steps that coalescing removed as redundant before they could be
    # applied. Reconciling the realization inventory needs these back:
    # applied + superseded == planned.
    _superseded_operation_count: int = field(default=0, init=False)
    _active_fragment_plan: FragmentPlan | None = field(
        default=None,
        init=False,
        repr=False,
    )
    _active_prepublication_validation: FragmentValidationResult | None = field(
        default=None,
        init=False,
        repr=False,
    )
    _active_postpublication_validation: FragmentValidationResult | None = field(
        default=None,
        init=False,
        repr=False,
    )
    _active_root_publication_confirmed: bool = field(default=False, init=False)
    _active_fragment_staged: bool = field(default=False, init=False)
    _active_root_publication_attempted: bool = field(default=False, init=False)
    _active_root_publication_succeeded: bool = field(default=False, init=False)
    _active_rollback_attempted: bool = field(default=False, init=False)
    _active_rollback_succeeded: bool | None = field(default=None, init=False)
    _active_root_publication_groups: dict[str, MbaMutationRootPublicationGroup] = field(
        default_factory=dict, init=False, repr=False
    )
    _active_fragment_root_inventory_signature: tuple[
        tuple[str, str, str, str, str, bool],
        ...,
    ] = field(default=(), init=False, repr=False)
    _active_fragment_snapshot_id: str = field(default="", init=False, repr=False)
    _active_prepared_semantic_fragment: PreparedSemanticFragment | None = field(
        default=None,
        init=False,
        repr=False,
    )
    _active_fragment_effect_requirements: dict[tuple[str, str], MbaMutationPlanItem] = (
        field(default_factory=dict, init=False, repr=False)
    )
    _applied_fragment_effects: set[tuple[str, str]] = field(
        default_factory=set,
        init=False,
        repr=False,
    )
    _active_current_mba_identity_binding: CurrentMbaIdentityBindingSnapshot | None = (
        field(
            default=None,
            init=False,
            repr=False,
        )
    )
    _active_current_mba_identity_binding_recorded: bool = field(
        default=False,
        init=False,
        repr=False,
    )
    _active_fragment_failures: list[MbaSemanticFragmentFailure] = field(
        default_factory=list,
        init=False,
        repr=False,
    )
    _active_detached_route_oracle: DetachedRouteOracleResult | None = field(
        default=None,
        init=False,
        repr=False,
    )
    _current_transaction_attempt: TransactionAttemptId | None = field(
        default=None,
        init=False,
        repr=False,
    )
    _transaction_failure: CfgTransactionFailure | None = field(
        default=None,
        init=False,
        repr=False,
    )
    _cfg_phase_index: int = field(default=0, init=False, repr=False)
    _cfg_bound_recorded: bool = field(default=False, init=False, repr=False)
    _cfg_plan_refs: tuple[PlanBlockRef, ...] = field(
        default=(),
        init=False,
        repr=False,
    )
    _cfg_plan_bindings: dict[PlanBlockRef, MbaCfgPlanBlockBindingObserved] = field(
        default_factory=dict,
        init=False,
        repr=False,
    )
    _cfg_reservations: dict[PlanBlockRef, PlanBlockReservation] = field(
        default_factory=dict,
        init=False,
        repr=False,
    )
    _cfg_creation_receipts: dict[PlanBlockRef, PlanBlockCreationReceipt] = field(
        default_factory=dict,
        init=False,
        repr=False,
    )
    _cfg_creation_quantities: dict[PlanBlockRef, tuple[int, int]] = field(
        default_factory=dict,
        init=False,
        repr=False,
    )
    _mutation_started: bool = field(default=False, init=False, repr=False)
    _cfg_invalidated_refs: set[PlanBlockRef] = field(
        default_factory=set,
        init=False,
        repr=False,
    )
    _cfg_initial_quantity: int | None = field(default=None, init=False, repr=False)

    def __post_init__(self) -> None:
        self.generation = int(self.generation)
        self.session_id = str(self.session_id)
        if self.generation < 0 or not self.session_id:
            raise ValueError("mutation gateway requires a session and generation")
        if self.identity_index is None:
            raise ValueError(
                "mutation gateway requires a coordinator-owned identity index"
            )
        if self.identity_index.session_id != self.session_id:
            raise ValueError("mutation gateway and identity index sessions differ")
        elif self.identity_index.generation != self.generation:
            raise ValueError("mutation gateway and identity index generations differ")
        elif self.identity_index.native_key != self.native_key:
            raise ValueError("mutation gateway and identity index native keys differ")
        authority = self.lifecycle_authority
        if authority is not None:
            if not isinstance(authority, FragmentPublicationLifecycleAuthority):
                raise TypeError(
                    "mutation gateway lifecycle authority has an invalid port"
                )
            if int(authority.evidence_generation) != int(
                self.identity_index.evidence_generation
            ):
                raise ValueError(
                    "mutation gateway and lifecycle evidence generations differ"
                )

    @property
    def receipts(self) -> tuple[MbaMutationReceipt, ...]:
        return tuple(self._receipts)

    @property
    def observation_failures(self) -> tuple[MbaMutationObservationFailure, ...]:
        return tuple(self._observation_failures)

    @property
    def active(self) -> bool:
        return self._active_kind is not None

    @property
    def active_batch_id(self) -> str | None:
        return self._active_batch_id

    @property
    def mutation_started(self) -> bool:
        return bool(self._mutation_started or self.identity_index.generation_poisoned)

    @property
    def generation_poisoned(self) -> bool:
        return self.identity_index.generation_poisoned

    @property
    def transaction_failure(self) -> CfgTransactionFailure | None:
        return self.identity_index.poisoned_failure or self._transaction_failure

    @property
    def current_transaction_attempt(self) -> TransactionAttemptId | None:
        return self._current_transaction_attempt

    @property
    def plan_creation_receipts(self) -> tuple[PlanBlockCreationReceipt, ...]:
        """Return exact plan-to-live creation proofs for the active attempt."""
        return tuple(self._cfg_creation_receipts.values())

    def _reset_cfg_context(self) -> None:
        self._current_transaction_attempt = None
        self._cfg_phase_index = 0
        self._cfg_bound_recorded = False
        self._cfg_plan_refs = ()
        self._cfg_plan_bindings.clear()
        self._cfg_reservations.clear()
        self._cfg_creation_receipts.clear()
        self._cfg_creation_quantities.clear()
        self._cfg_invalidated_refs.clear()
        self._cfg_initial_quantity = None
        self._mutation_started = False

    def _require_generation_usable(self) -> None:
        self.identity_index.require_generation_usable()

    def _record_cfg_attempt_planned(
        self,
        *,
        plan_id: str,
        plan_refs: Iterable[PlanBlockRef],
        attempt: TransactionAttemptId,
    ) -> None:
        """Install one immutable four-part attempt before projection begins."""
        self._require_generation_usable()
        if self.active:
            raise RuntimeError("cannot plan a CFG attempt inside an active batch")
        plan_id = str(plan_id)
        plan_refs = tuple(plan_refs)
        if not plan_id or attempt.plan_id != plan_id:
            raise ValueError("CFG attempt belongs to another plan")
        if attempt.session_id != self.session_id:
            raise ValueError("CFG attempt belongs to another session")
        if attempt.generation != self.identity_index.generation:
            raise ValueError("CFG attempt belongs to another generation")
        if len(set(plan_refs)) != len(plan_refs) or any(
            ref.plan_id != plan_id for ref in plan_refs
        ):
            raise ValueError("CFG attempt has invalid plan block authority")
        self._reset_cfg_context()
        self._current_transaction_attempt = attempt
        self._transaction_failure = None
        self._cfg_plan_refs = plan_refs
        self._emit_cfg_transaction_phase(CfgTransactionPhase.PLANNED)

    def _record_fragment_attempt_planned(
        self,
        plan: FragmentPlan,
        attempt: TransactionAttemptId,
    ) -> None:
        self._record_cfg_attempt_planned(
            plan_id=plan.plan_id,
            plan_refs=tuple(
                PlanBlockRef(plan.plan_id, block.block_id) for block in plan.blocks
            ),
            attempt=attempt,
        )

    def _emit_cfg_transaction_phase(
        self,
        phase: CfgTransactionPhase,
        *,
        failure: CfgTransactionFailure | None = None,
    ) -> None:
        attempt = self._current_transaction_attempt
        if attempt is None:
            raise RuntimeError("CFG transaction phase has no attempt authority")
        self._emit_observation(
            phase=phase.value,
            event_type=MbaCfgTransactionAuthorityObserved,
            payload=MbaCfgTransactionAuthorityObserved(
                session_id=self.session_id,
                function_ea=int(self.function_ea),
                maturity=int(self.maturity),
                attempt_id=attempt,
                phase=phase,
                phase_index=int(self._cfg_phase_index),
                mba_generation=int(attempt.generation),
                evidence_generation=int(self.identity_index.evidence_generation),
                mutation_started=bool(self._mutation_started),
                poisoned=(phase is CfgTransactionPhase.POISONED_RESTART_REQUIRED),
                insertion_quantity_initial=self._cfg_initial_quantity,
                plan_refs=self._cfg_plan_refs,
                plan_bindings=tuple(self._cfg_plan_bindings.values()),
                reservations=tuple(self._cfg_reservations.values()),
                creation_receipts=tuple(self._cfg_creation_receipts.values()),
                creation_quantities=tuple(
                    (plan_ref, before, after)
                    for plan_ref, (
                        before,
                        after,
                    ) in self._cfg_creation_quantities.items()
                ),
                invalidated_refs=tuple(
                    sorted(
                        self._cfg_invalidated_refs,
                        key=lambda ref: ref.local_block_id,
                    )
                ),
                failure=failure,
            ),
            mutation_batch_id=attempt.attempt_id,
        )
        self._cfg_phase_index += 1

    def _record_cfg_projected(self) -> None:
        self._emit_cfg_transaction_phase(CfgTransactionPhase.PROJECTED)

    def _record_cfg_preflighted(self) -> None:
        self._emit_cfg_transaction_phase(CfgTransactionPhase.PREFLIGHTED)

    def _prepare_patch_binding(
        self,
        attempt: TransactionAttemptId,
        *,
        serial_quantity: int,
    ) -> None:
        """Open exact identity binding after immutable preflight, before staging."""
        self._require_generation_usable()
        if self.active:
            raise RuntimeError("patch binding requires an idle mutation gateway")
        if attempt != self._current_transaction_attempt:
            raise ValueError("patch binding attempt differs from planned authority")
        serial_quantity = int(serial_quantity)
        if serial_quantity < 0:
            raise ValueError("patch binding quantity must be non-negative")
        self.identity_index.begin_transaction(attempt, serial_quantity)
        self._cfg_initial_quantity = serial_quantity

    def _record_cfg_bound(self) -> None:
        """Record exact binding once, after all prewrite reservations exist."""
        if self._current_transaction_attempt is None:
            raise RuntimeError("CFG binding has no transaction attempt")
        if self._cfg_bound_recorded:
            raise RuntimeError("CFG binding phase is already recorded")
        if self._mutation_started:
            raise RuntimeError("CFG binding cannot follow live mutation")
        self._cfg_bound_recorded = True
        self._emit_cfg_transaction_phase(CfgTransactionPhase.BOUND)

    def _record_clean_cfg_failure(
        self,
        *,
        reason: str,
        failure_phase: str,
        first_failed_obligation: str,
        interr_code: int | None = None,
    ) -> CfgTransactionFailure:
        self._require_generation_usable()
        if self._mutation_started:
            raise RuntimeError("live mutation cannot be recorded as a clean rejection")
        attempt = self._current_transaction_attempt
        if attempt is None:
            raise RuntimeError("clean rejection has no transaction attempt")
        failure = CfgTransactionFailure(
            attempt_id=attempt,
            phase=CfgTransactionPhase.REJECTED_CLEAN,
            reason=str(reason),
            live_mutation_started=False,
            first_failed_obligation=str(first_failed_obligation),
            failure_phase=str(failure_phase),
            interr_code=interr_code,
        )
        self._transaction_failure = failure
        self._cfg_invalidated_refs.update(self._cfg_reservations)
        self._emit_cfg_transaction_phase(
            CfgTransactionPhase.REJECTED_CLEAN,
            failure=failure,
        )
        return failure

    def _record_cfg_mutation_started(self) -> None:
        """Cross the irreversible boundary immediately before the first SDK write."""
        self._require_active()
        if self._current_transaction_attempt is None:
            raise RuntimeError("CFG mutation has no transaction attempt authority")
        if self._mutation_started:
            return
        self._mutation_started = True
        self._emit_cfg_transaction_phase(CfgTransactionPhase.REALIZING)

    def _record_rolled_back_cfg_failure(
        self,
        *,
        reason: str,
        failure_phase: str,
        first_failed_obligation: str,
        interr_code: int | None = None,
    ) -> CfgTransactionFailure:
        """Record an exact completed rollback without poisoning the generation."""
        self._require_generation_usable()
        if not self._mutation_started:
            raise RuntimeError("rolled-back rejection requires a live mutation")
        if self._active_rollback_succeeded is not True:
            raise RuntimeError("rolled-back rejection lacks completed recovery proof")
        attempt = self._current_transaction_attempt
        if attempt is None:
            raise RuntimeError("rolled-back rejection has no transaction attempt")
        failure = CfgTransactionFailure(
            attempt_id=attempt,
            phase=CfgTransactionPhase.ROLLED_BACK_CLEAN,
            reason=str(reason),
            live_mutation_started=True,
            first_failed_obligation=str(first_failed_obligation),
            failure_phase=str(failure_phase),
            interr_code=interr_code,
        )
        self._transaction_failure = failure
        self._cfg_invalidated_refs.update(self._cfg_reservations)
        self._emit_cfg_transaction_phase(
            CfgTransactionPhase.ROLLED_BACK_CLEAN,
            failure=failure,
        )
        return failure

    def _record_fragment_mutation_started(
        self,
        plan: FragmentPlan | None = None,
    ) -> None:
        if plan is None:
            plan = self._active_fragment_plan
        if not isinstance(plan, FragmentPlan):
            raise RuntimeError("fragment mutation has no active plan authority")
        self._require_active_fragment(plan)
        self._record_cfg_mutation_started()

    def _poison_cfg_generation(
        self,
        *,
        reason: str,
        failure_phase: str,
        first_failed_obligation: str,
        interr_code: int | None = None,
        plan: FragmentPlan | None = None,
    ) -> CfgTransactionFailure:
        if plan is None:
            self._require_active()
        else:
            self._require_active_fragment(plan)
        if not self._mutation_started:
            raise RuntimeError("cannot poison a generation before live mutation")
        attempt = self._current_transaction_attempt
        if attempt is None:
            raise RuntimeError("poisoned generation has no transaction attempt")
        failure = CfgTransactionFailure(
            attempt_id=attempt,
            phase=CfgTransactionPhase.POISONED_RESTART_REQUIRED,
            reason=str(reason),
            live_mutation_started=True,
            first_failed_obligation=str(first_failed_obligation),
            failure_phase=str(failure_phase),
            interr_code=interr_code,
        )
        self._transaction_failure = failure
        self._cfg_invalidated_refs.update(self._cfg_reservations)
        self.identity_index.poison_generation(failure)
        self._emit_cfg_transaction_phase(
            CfgTransactionPhase.POISONED_RESTART_REQUIRED,
            failure=failure,
        )
        self.abort(reason=str(reason))
        return failure

    def _reset_fragment_context(self) -> None:
        self._active_fragment_plan = None
        self._active_prepublication_validation = None
        self._active_postpublication_validation = None
        self._active_root_publication_confirmed = False
        self._active_fragment_staged = False
        self._active_root_publication_attempted = False
        self._active_root_publication_succeeded = False
        self._active_rollback_attempted = False
        self._active_rollback_succeeded = None
        self._active_root_publication_groups.clear()
        self._active_fragment_root_inventory_signature = ()
        self._active_fragment_snapshot_id = ""
        self._active_prepared_semantic_fragment = None
        self._active_fragment_effect_requirements.clear()
        self._applied_fragment_effects.clear()
        self._active_current_mba_identity_binding = None
        self._active_current_mba_identity_binding_recorded = False
        self._active_fragment_failures.clear()
        self._active_detached_route_oracle = None

    def new_transaction(self) -> MbaMutationGateway:
        """Return a fresh batch controller over this current-MBA index.

        A structural operation must own its transaction boundary, while every
        operation in the same live MBA must still resolve through one index.
        The returned gateway shares only that index and observer port; it
        carries neither this gateway's active batch nor its receipt history.
        """
        self._require_generation_usable()
        return MbaMutationGateway(
            native_key=self.native_key,
            generation=int(self.identity_index.generation),
            session_id=self.session_id,
            function_ea=self.function_ea,
            maturity=self.maturity,
            identity_index=self.identity_index,
            event_emitter=self.event_emitter,
            lifecycle_authority=self.lifecycle_authority,
        )

    def begin_batch(
        self,
        kind: StructuralMutationKind,
        *,
        serial_quantity: int | None = None,
        description: str = "",
        planned_operation_count: int = 1,
        plan_items: Iterable[MbaMutationPlanItem] = (),
        fragment_plan: FragmentPlan | None = None,
        fragment_root_publication_groups: Iterable[
            MbaMutationRootPublicationGroup
        ] = (),
        transaction_attempt: TransactionAttemptId | None = None,
        patch_plan_id: str | None = None,
        patch_plan_refs: Iterable[PlanBlockRef] = (),
    ) -> None:
        self._require_generation_usable()
        if self.active:
            raise RuntimeError("a structural mutation batch is already active")
        if not isinstance(kind, StructuralMutationKind):
            raise TypeError("structural mutation batch requires a mutation kind")
        planned_operation_count = int(planned_operation_count)
        if planned_operation_count < 0:
            raise ValueError("planned operation count must be non-negative")
        plan_items = tuple(plan_items)
        fragment_root_publication_groups = tuple(fragment_root_publication_groups)
        patch_plan_refs = tuple(patch_plan_refs)
        if (kind is StructuralMutationKind.FRAGMENT_PUBLICATION) != isinstance(
            fragment_plan, FragmentPlan
        ):
            raise ValueError(
                "fragment-publication batch requires exactly one FragmentPlan"
            )
        if isinstance(fragment_plan, FragmentPlan):
            group_ids = tuple(
                group.group_id for group in fragment_root_publication_groups
            )
            if (
                not fragment_root_publication_groups
                or len(set(group_ids)) != len(group_ids)
                or any(
                    group.publication_attempted
                    or group.publication_succeeded
                    or group.rollback_attempted
                    for group in fragment_root_publication_groups
                )
            ):
                raise ValueError(
                    "fragment publication requires pristine root-group inventory"
                )
        elif fragment_root_publication_groups:
            raise ValueError(
                "non-fragment mutation cannot carry root publication groups"
            )
        if transaction_attempt is not None:
            if not isinstance(transaction_attempt, TransactionAttemptId):
                raise TypeError("transaction attempt requires typed authority")
            if transaction_attempt.session_id != self.session_id:
                raise ValueError("transaction attempt belongs to another session")
            if transaction_attempt.generation != self.identity_index.generation:
                raise ValueError("transaction attempt belongs to another generation")
            if fragment_plan is not None and (
                transaction_attempt.plan_id != fragment_plan.plan_id
            ):
                raise ValueError("transaction attempt does not match fragment plan")
            if patch_plan_id is not None and (
                transaction_attempt.plan_id != str(patch_plan_id)
            ):
                raise ValueError("transaction attempt does not match patch plan")
            if any(
                ref.plan_id != transaction_attempt.plan_id for ref in patch_plan_refs
            ):
                raise ValueError("patch plan reference authority differs")
            if len(set(patch_plan_refs)) != len(patch_plan_refs):
                raise ValueError("patch plan references are not unique")
        elif patch_plan_refs:
            raise ValueError("patch plan references require transaction authority")
        if transaction_attempt is not None:
            if (
                self._current_transaction_attempt is not None
                and self._current_transaction_attempt != transaction_attempt
            ):
                raise ValueError("active CFG attempt authority differs from batch")
            if (
                patch_plan_refs
                and self._current_transaction_attempt is not None
                and self._cfg_plan_refs != patch_plan_refs
            ):
                raise ValueError("patch plan references differ from planned authority")
        serial_quantity = None if serial_quantity is None else int(serial_quantity)
        if transaction_attempt is not None:
            self._cfg_initial_quantity = serial_quantity
        batch_id = (
            uuid.uuid4().hex
            if transaction_attempt is None
            else transaction_attempt.attempt_id
        )
        identity_transaction_prepared = False
        if transaction_attempt is not None:
            try:
                self.identity_index.require_active_attempt(transaction_attempt)
            except ValueError:
                pass
            else:
                identity_transaction_prepared = True
                prepared_quantity = self.identity_index.transaction_quantity(
                    transaction_attempt.attempt_id
                )
                if serial_quantity is not None and prepared_quantity != serial_quantity:
                    raise ValueError(
                        "prepared patch binding quantity differs from live batch: "
                        f"prepared={prepared_quantity}, live={serial_quantity}"
                    )
        if not identity_transaction_prepared:
            self.identity_index.begin_transaction(
                transaction_attempt if transaction_attempt is not None else batch_id,
                serial_quantity,
            )

        self._reset_fragment_context()
        if transaction_attempt is None:
            self._reset_cfg_context()
        elif self._current_transaction_attempt is None:
            self._reset_cfg_context()
            self._current_transaction_attempt = transaction_attempt
            self._cfg_plan_refs = patch_plan_refs
            self._emit_cfg_transaction_phase(CfgTransactionPhase.PLANNED)
        self._active_fragment_plan = fragment_plan
        self._active_kind = kind
        self._active_description = str(description)
        self._active_batch_id = batch_id
        self._planned_operation_count = planned_operation_count
        self._active_root_publication_groups.update(
            (group.group_id, group) for group in fragment_root_publication_groups
        )
        self._affected_identities.clear()
        self._operation_count = 0
        # Scope the tally to this batch: a count left by an earlier batch must
        # never reconcile this one's inventory.
        self._superseded_operation_count = 0
        self._emit_observation(
            phase="planned",
            event_type=MbaMutationPlanned,
            payload=MbaMutationPlanned(
                session_id=self.session_id,
                function_ea=int(self.function_ea),
                maturity=int(self.maturity),
                mba_generation=int(self.identity_index.generation),
                evidence_generation=int(self.identity_index.evidence_generation),
                mutation_batch_id=self._active_batch_id,
                kind=kind,
                planned_operation_count=self._planned_operation_count,
                description=self._active_description,
                items=plan_items,
                fragment_plan_id=(
                    "" if fragment_plan is None else fragment_plan.plan_id
                ),
                fragment_atomic_group_id=(
                    "" if fragment_plan is None else fragment_plan.atomic_group_id
                ),
                fragment_plan_json=(
                    ""
                    if fragment_plan is None
                    else serialize_fragment_plan(fragment_plan)
                ),
                root_publication_groups=fragment_root_publication_groups,
            ),
            mutation_batch_id=batch_id,
        )
        if transaction_attempt is not None and not self._cfg_bound_recorded:
            self._record_cfg_bound()

    def register_patch_plan_reservations(
        self,
        reservations: Iterable[PlanBlockReservation],
    ) -> None:
        """Record the exact reservations produced during patch-plan binding."""
        attempt = self._current_transaction_attempt
        if attempt is None:
            raise RuntimeError("patch reservations have no transaction attempt")
        self.identity_index.require_active_attempt(attempt)
        declared = set(self._cfg_plan_refs)
        for reservation in reservations:
            if (
                reservation.attempt_id != self._current_transaction_attempt
                or reservation.plan_ref not in declared
            ):
                raise ValueError("patch plan reservation authority differs")
            self._cfg_reservations[reservation.plan_ref] = reservation

    def begin_patch_realization(
        self,
        attempt: TransactionAttemptId,
        *,
        plan_refs: Iterable[PlanBlockRef],
    ) -> None:
        """Cross the SDK-write boundary for exactly reserved patch blocks."""
        self._require_active()
        if attempt != self._current_transaction_attempt:
            raise ValueError("patch realization attempt is not the active batch")
        requested = tuple(plan_refs)
        if len(set(requested)) != len(requested):
            raise ValueError("patch realization references duplicate planned blocks")
        if set(requested) != set(self._cfg_plan_refs):
            raise ValueError("patch realization block ownership differs from its plan")
        if any(plan_ref not in self._cfg_reservations for plan_ref in requested):
            raise ValueError("patch realization references an unreserved plan block")
        self._record_cfg_mutation_started()

    def authorize_patch_block_creation(
        self,
        attempt: TransactionAttemptId,
        *,
        plan_refs: Iterable[PlanBlockRef],
    ) -> None:
        """Authorize imminent SDK creation for reserved members of this plan."""
        self._require_active()
        if attempt != self._current_transaction_attempt:
            raise ValueError("patch block creation attempt is not the active batch")
        if not self._mutation_started:
            raise RuntimeError("patch block creation requires started realization")
        requested = tuple(plan_refs)
        if not requested:
            raise ValueError("patch block creation requires planned block ownership")
        if len(set(requested)) != len(requested):
            raise ValueError("patch block creation references duplicate planned blocks")
        declared = set(self._cfg_plan_refs)
        if any(plan_ref not in declared for plan_ref in requested):
            raise ValueError("patch block creation ownership differs from its plan")
        if any(plan_ref not in self._cfg_reservations for plan_ref in requested):
            raise ValueError("patch block creation references an unreserved plan block")

    def record_coalesced_supersessions(self, count: int) -> None:
        """Record planned steps that coalescing removed before apply.

        Conflict resolution legitimately collapses several queued modifications
        that describe the same edge into one, so an applied count alone cannot
        be reconciled against the number of planned PatchPlan steps. Without
        this, a benign deduplication is indistinguishable from a lost operation
        and poisons the CFG generation.
        """
        self._require_active()
        superseded = int(count)
        if superseded < 0:
            raise ValueError("superseded operation count must be non-negative")
        self._superseded_operation_count = superseded

    def observe_patch_realization(
        self,
        live_graph: FlowGraph,
        *,
        applied_operation_count: int,
    ) -> None:
        """Record the complete live result of one ordinary typed PatchPlan."""
        self._require_active()
        if self._current_transaction_attempt is None:
            raise RuntimeError("patch observation has no transaction attempt")
        if self._active_fragment_plan is not None:
            raise RuntimeError("ordinary patch observation cannot own a fragment")
        if not self._mutation_started:
            raise RuntimeError("patch observation requires a started live mutation")
        if not isinstance(live_graph, FlowGraph):
            raise TypeError("patch observation requires a portable live graph")
        applied = int(applied_operation_count)
        # A planned step is accounted for when it was applied OR when conflict
        # resolution deliberately superseded it as redundant. Comparing applied
        # against planned alone reads a benign deduplication as corruption.
        superseded = int(self._superseded_operation_count)
        if applied + superseded != self._planned_operation_count:
            raise RuntimeError(
                "patch realization operation inventory mismatch: "
                f"planned={self._planned_operation_count} applied={applied} "
                f"superseded={superseded}"
            )
        if set(self._cfg_creation_receipts) != set(self._cfg_plan_refs):
            raise RuntimeError("patch observation lacks complete creation receipts")
        for plan_ref, receipt in self._cfg_creation_receipts.items():
            self._cfg_plan_bindings[plan_ref] = MbaCfgPlanBlockBindingObserved(
                plan_ref=plan_ref,
                logical_version=receipt.logical_version,
                returned_serial=int(receipt.returned_serial),
            )
        attempt = self._current_transaction_attempt
        self.identity_index.refresh_from_flow_graph(live_graph)
        self.identity_index.begin_transaction(attempt, live_graph.num_blocks)
        self._operation_count = applied
        self._emit_cfg_transaction_phase(CfgTransactionPhase.OBSERVED)

    def _emit_observation(
        self,
        *,
        phase: str,
        event_type: type,
        payload: object,
        mutation_batch_id: str,
    ) -> None:
        emitter = self.event_emitter
        if emitter is None:
            return
        for exc in emitter.emit_isolated(event_type, payload):
            failure = MbaMutationObservationFailure(
                phase=str(phase),
                event_name=event_type.__name__,
                mutation_batch_id=str(mutation_batch_id),
                error_type=type(exc).__name__,
                error_message=str(exc),
            )
            self._observation_failures.append(failure)
            logger.error(
                "mutation observer failed: phase=%s event=%s batch=%s error=%s: %s",
                failure.phase,
                failure.event_name,
                failure.mutation_batch_id,
                failure.error_type,
                failure.error_message,
            )

    def _fragment_plan_items(
        self,
        plan: FragmentPlan,
        root_inventory: SemanticFragmentRootInventory,
        publication_profile=None,
    ) -> tuple[MbaMutationPlanItem, ...]:
        from d810.hexrays.mutation.semantic_fragment_profile import (
            SemanticFragmentPublicationProfile,
        )

        if publication_profile is None:
            publication_profile = SemanticFragmentPublicationProfile.CFG_READY
        if not isinstance(
            publication_profile,
            SemanticFragmentPublicationProfile,
        ):
            raise TypeError("fragment plan inventory requires a typed profile")
        if (
            root_inventory.plan_id != plan.plan_id
            or root_inventory.atomic_group_id != plan.atomic_group_id
        ):
            raise ValueError("semantic-fragment root inventory scope drifted")
        items: list[MbaMutationPlanItem] = []
        for block in plan.blocks:
            if block.materialization is FragmentBlockMaterialization.CLONE_PUBLISHED:
                original = plan.block(str(block.replaces_block_id))
                items.append(
                    MbaMutationPlanItem(
                        item_index=len(items),
                        mutation_kind=("semantic_fragment_replacement_materialization"),
                        source_anchor_ea=int(original.semantic_anchor_ea),
                        source_identity=original.stable_identity,
                        target_anchor_ea=int(block.semantic_anchor_ea),
                        target_identity=block.stable_identity,
                        reason=f"replacement:{block.block_id}",
                    )
                )
            elif block.materialization is FragmentBlockMaterialization.CREATE_EMPTY:
                items.append(
                    MbaMutationPlanItem(
                        item_index=len(items),
                        mutation_kind="semantic_fragment_synthetic_materialization",
                        target_anchor_ea=int(block.semantic_anchor_ea),
                        reason=f"synthetic:{block.block_id}",
                    )
                )
            elif block.materialization is FragmentBlockMaterialization.IMPORT_NATIVE:
                items.append(
                    MbaMutationPlanItem(
                        item_index=len(items),
                        mutation_kind="semantic_fragment_native_body_materialization",
                        target_anchor_ea=int(block.semantic_anchor_ea),
                        target_identity=block.stable_identity,
                        reason=(f"native-body:{block.native_body_id}:{block.block_id}"),
                    )
                )
        for materialization in plan.constant_materializations:
            source = plan.block(materialization.source_block_id)
            items.append(
                MbaMutationPlanItem(
                    item_index=len(items),
                    mutation_kind=(
                        "semantic_fragment_constant_materialization"
                    ),
                    source_anchor_ea=int(materialization.instruction_ea),
                    source_identity=source.stable_identity,
                    target_anchor_ea=int(materialization.instruction_ea),
                    target_identity=source.stable_identity,
                    reason=f"constant:{materialization.materialization_id}",
                )
            )
        for carrier in plan.return_carriers:
            block = plan.block(carrier.block_id)
            items.append(
                MbaMutationPlanItem(
                    item_index=len(items),
                    mutation_kind=("semantic_fragment_return_carrier_materialization"),
                    source_anchor_ea=int(carrier.state_write_ea),
                    source_identity=block.stable_identity,
                    target_anchor_ea=int(carrier.carrier_ea),
                    target_identity=block.stable_identity,
                    reason=f"return-carrier:{carrier.carrier_id}",
                )
            )
        for terminal_return in plan.terminal_returns:
            block = plan.block(terminal_return.block_id)
            items.append(
                MbaMutationPlanItem(
                    item_index=len(items),
                    mutation_kind=("semantic_fragment_terminal_return_materialization"),
                    source_anchor_ea=int(terminal_return.instruction_ea),
                    source_identity=block.stable_identity,
                    reason=f"terminal-return:{terminal_return.return_id}",
                )
            )
        for operation in plan.operations:
            source = plan.block(operation.source_block_id)
            if operation.requires_fallthrough_helper:
                helper_target = None
                normalization = operation.computed_branch_normalization
                envelope = (
                    None
                    if normalization is None
                    else normalization.conditional_select_envelope
                )
                if publication_profile.graph_free and isinstance(
                    envelope,
                    (
                        FragmentConditionalSelectEnvelope,
                        FragmentReferencedImportedConditionalSelectEnvelope,
                    ),
                ):
                    helper_target = plan.block(envelope.selected_value_block_id)
                elif (
                    publication_profile.graph_free
                    and isinstance(
                        normalization,
                        FragmentSetccIndexedTableNormalization,
                    )
                    and normalization.fallthrough_delivery
                    is FragmentSetccFallthroughDelivery.PLANNED_HELPER
                ):
                    fallthrough_edges = tuple(
                        edge
                        for edge in operation.edges
                        if edge.role
                        is SemanticEdgeRole.CONDITIONAL_FALLTHROUGH
                    )
                    if len(fallthrough_edges) != 1:
                        raise ValueError(
                            "planned setcc fallthrough helper requires one typed arm"
                        )
                    helper_target = plan.block(
                        fallthrough_edges[0].target_block_id
                    )
                items.append(
                    MbaMutationPlanItem(
                        item_index=len(items),
                        mutation_kind=(
                            "semantic_fragment_operation_fallthrough_helper"
                        ),
                        source_anchor_ea=int(source.semantic_anchor_ea),
                        source_identity=source.stable_identity,
                        target_anchor_ea=(
                            None
                            if helper_target is None
                            else int(helper_target.semantic_anchor_ea)
                        ),
                        target_identity=(
                            None
                            if helper_target is None
                            else helper_target.stable_identity
                        ),
                        reason=f"operation:{operation.operation_id}",
                    )
                )
            for edge in operation.edges:
                target = plan.block(edge.target_block_id)
                items.append(
                    MbaMutationPlanItem(
                        item_index=len(items),
                        mutation_kind=f"semantic_fragment_{edge.role.value}",
                        source_anchor_ea=int(source.semantic_anchor_ea),
                        source_identity=source.stable_identity,
                        target_anchor_ea=int(target.semantic_anchor_ea),
                        target_identity=target.stable_identity,
                        reason=f"operation:{operation.operation_id}",
                    )
                )
        if not publication_profile.graph_free:
            for root_edge in root_inventory.items:
                if not root_edge.requires_helper:
                    continue
                predecessor = plan.block(root_edge.predecessor_block_id)
                replacement = plan.block(root_edge.root_block_id)
                items.append(
                    MbaMutationPlanItem(
                        item_index=len(items),
                        mutation_kind="semantic_fragment_root_fallthrough_helper",
                        source_anchor_ea=int(predecessor.semantic_anchor_ea),
                        source_identity=predecessor.stable_identity,
                        target_anchor_ea=int(replacement.semantic_anchor_ea),
                        target_identity=replacement.stable_identity,
                        reason=f"root-edge:{root_edge.edge_id}",
                    )
                )
            for root_edge in root_inventory.items:
                predecessor = plan.block(root_edge.predecessor_block_id)
                replacement = plan.block(root_edge.root_block_id)
                items.append(
                    MbaMutationPlanItem(
                        item_index=len(items),
                        mutation_kind=(
                            f"semantic_fragment_root_{root_edge.role.value}"
                        ),
                        source_anchor_ea=int(predecessor.semantic_anchor_ea),
                        source_identity=predecessor.stable_identity,
                        target_anchor_ea=int(replacement.semantic_anchor_ea),
                        target_identity=replacement.stable_identity,
                        reason=f"root-edge:{root_edge.edge_id}",
                    )
                )
        return tuple(items)

    @staticmethod
    def _fragment_root_publication_groups(
        plan: FragmentPlan,
        root_inventory: SemanticFragmentRootInventory,
    ) -> tuple[MbaMutationRootPublicationGroup, ...]:
        groups: list[MbaMutationRootPublicationGroup] = []
        for inventory_group in root_inventory.groups:
            predecessor = plan.block(inventory_group.predecessor_block_id)
            for item in inventory_group.items:
                replacement = plan.block(item.root_block_id)
                if replacement.replaces_block_id != item.original_block_id:
                    raise ValueError(
                        "root inventory original ownership drifted from the plan"
                    )
            groups.append(
                MbaMutationRootPublicationGroup(
                    group_id=inventory_group.group_id,
                    predecessor_block_id=inventory_group.predecessor_block_id,
                    predecessor_anchor_ea=int(predecessor.semantic_anchor_ea),
                    edge_ids=tuple(item.edge_id for item in inventory_group.items),
                    edge_roles=tuple(item.role for item in inventory_group.items),
                    original_block_ids=tuple(
                        item.original_block_id for item in inventory_group.items
                    ),
                    replacement_block_ids=tuple(
                        item.root_block_id for item in inventory_group.items
                    ),
                )
            )
        return tuple(groups)

    def _begin_semantic_fragment_batch(
        self,
        backend: object,
        plan: FragmentPlan,
        root_inventory: SemanticFragmentRootInventory,
        transaction_attempt: TransactionAttemptId,
        snapshot_id: str,
        prepared_fragment: PreparedSemanticFragment,
        patch_plan: object,
        publication_profile=None,
    ) -> None:
        mba = getattr(backend, "mba", None)
        if mba is None:
            raise TypeError("semantic-fragment backend requires a live MBA")
        if (
            not isinstance(prepared_fragment, PreparedSemanticFragment)
            or prepared_fragment.authority.attempt_id is not transaction_attempt
            or prepared_fragment.authority.snapshot_id != str(snapshot_id)
            or prepared_fragment.authority.plan_id != plan.plan_id
            or prepared_fragment.authority.root_inventory is not root_inventory
        ):
            raise ValueError(
                "prepared semantic-fragment authority differs from batch scope"
            )
        from d810.transforms.plan import (
            PatchFragmentOperation,
            PatchFragmentRootPublication,
            PatchPlan,
        )

        if not isinstance(patch_plan, PatchPlan):
            raise TypeError("semantic fragment lowering requires PatchPlan")
        if (
            patch_plan.plan_id != plan.plan_id
            or patch_plan.semantic_contract is None
            or patch_plan.semantic_contract.fragment_plan is not plan
        ):
            raise ValueError("lowered fragment PatchPlan authority differs")
        from d810.hexrays.mutation.semantic_fragment_profile import (
            SemanticFragmentPublicationProfile,
        )

        if publication_profile is None:
            publication_profile = SemanticFragmentPublicationProfile.CFG_READY
        helper_refs: list[PlanBlockRef] = []
        for step in patch_plan.steps:
            if not isinstance(
                step,
                (PatchFragmentOperation, PatchFragmentRootPublication),
            ) or step.fallthrough_helper_ref is None:
                continue
            if not publication_profile.graph_free:
                helper_refs.append(step.fallthrough_helper_ref)
                continue
            if not isinstance(step, PatchFragmentOperation):
                continue
            normalization = step.operation.computed_branch_normalization
            if (
                isinstance(normalization, FragmentSetccIndexedTableNormalization)
                and normalization.fallthrough_delivery
                is FragmentSetccFallthroughDelivery.PLANNED_HELPER
            ):
                helper_refs.append(step.fallthrough_helper_ref)
        self._cfg_plan_refs = tuple(
            dict.fromkeys(
                (
                    *(
                        PlanBlockRef(plan.plan_id, block.block_id)
                        for block in plan.blocks
                    ),
                    *tuple(helper_refs),
                )
            )
        )
        items = self._fragment_plan_items(
            plan,
            root_inventory,
            publication_profile,
        )
        root_publication_groups = self._fragment_root_publication_groups(
            plan,
            root_inventory,
        )
        self.begin_batch(
            StructuralMutationKind.FRAGMENT_PUBLICATION,
            serial_quantity=int(getattr(mba, "qty", 0) or 0),
            description=(
                f"publish semantic fragment {plan.plan_id} "
                f"atomic-group={plan.atomic_group_id}"
            ),
            planned_operation_count=len(items),
            plan_items=items,
            fragment_plan=plan,
            fragment_root_publication_groups=root_publication_groups,
            transaction_attempt=transaction_attempt,
            patch_plan_id=patch_plan.plan_id,
            patch_plan_refs=self._cfg_plan_refs,
        )
        self._active_fragment_root_inventory_signature = tuple(
            (
                item.edge_id,
                item.root_block_id,
                item.original_block_id,
                item.predecessor_block_id,
                item.role.value,
                item.requires_helper,
            )
            for item in root_inventory.items
        )
        self._active_fragment_snapshot_id = str(snapshot_id)
        self._active_prepared_semantic_fragment = prepared_fragment
        effect_kinds = {
            "semantic_fragment_constant_materialization",
            "semantic_fragment_return_carrier_materialization",
            "semantic_fragment_terminal_return_materialization",
        }
        if publication_profile.graph_free:
            effect_kinds.add("semantic_fragment_operation_fallthrough_helper")
        requirements = {
            (item.mutation_kind, item.reason): item
            for item in items
            if item.mutation_kind in effect_kinds
        }
        expected_effect_requirement_count = (
            len(plan.constant_materializations)
            + len(plan.return_carriers)
            + len(plan.terminal_returns)
            + (
                sum(
                    operation.requires_fallthrough_helper
                    for operation in plan.operations
                )
                if publication_profile.graph_free
                else 0
            )
        )
        if len(requirements) != expected_effect_requirement_count:
            raise ValueError("semantic-fragment effect inventory is ambiguous")
        self._active_fragment_effect_requirements.update(requirements)

    def _require_active_fragment(self, plan: FragmentPlan) -> None:
        self._require_active()
        if (
            self._active_kind is not StructuralMutationKind.FRAGMENT_PUBLICATION
            or self._active_fragment_plan is not plan
        ):
            raise RuntimeError("semantic-fragment transaction does not own this plan")

    def _record_fragment_staged(self, plan: FragmentPlan) -> None:
        self._require_active_fragment(plan)
        self._active_fragment_staged = True

    def _record_fragment_plan_bindings(
        self,
        plan: FragmentPlan,
        bindings: Iterable[tuple[PlanBlockRef, LogicalBlockVersion]],
    ) -> None:
        """Capture exact runtime versions for every declared plan block."""
        self._require_active_fragment(plan)
        observed: dict[PlanBlockRef, MbaCfgPlanBlockBindingObserved] = {}
        expected_refs = set(self._cfg_plan_refs)
        for plan_ref, version in bindings:
            if plan_ref not in expected_refs:
                raise ValueError("runtime plan binding is not declared by this plan")
            if plan_ref in observed:
                raise ValueError("runtime plan binding was observed more than once")
            bound = self.identity_index.resolve_logical_version(
                version,
                transaction_id=str(self._active_batch_id),
            )
            if bound is None:
                raise ValueError("runtime plan binding has no live coordinate")
            observed[plan_ref] = MbaCfgPlanBlockBindingObserved(
                plan_ref=plan_ref,
                logical_version=version,
                returned_serial=int(bound.serial),
            )
        missing = expected_refs - set(observed)
        if any(ref not in self._cfg_reservations for ref in missing):
            raise ValueError("runtime plan binding inventory is incomplete")
        self._cfg_plan_bindings = observed

    def _record_fragment_observed(self, plan: FragmentPlan) -> None:
        """Record complete live observation after staged and root realization."""
        self._require_active_fragment(plan)
        for plan_ref, receipt in self._cfg_creation_receipts.items():
            if plan_ref in self._cfg_plan_bindings:
                continue
            self._cfg_plan_bindings[plan_ref] = MbaCfgPlanBlockBindingObserved(
                plan_ref=plan_ref,
                logical_version=receipt.logical_version,
                returned_serial=int(receipt.returned_serial),
            )
        if set(self._cfg_plan_bindings) != set(self._cfg_plan_refs):
            raise RuntimeError("fragment observation lacks complete plan bindings")
        self._emit_cfg_transaction_phase(CfgTransactionPhase.OBSERVED)

    def _record_fragment_failure(
        self,
        plan: FragmentPlan,
        failure: MbaSemanticFragmentFailure,
    ) -> None:
        self._require_active_fragment(plan)
        if not isinstance(failure, MbaSemanticFragmentFailure):
            raise TypeError(
                "semantic-fragment failure must be a structured failure fact"
            )
        self._active_fragment_failures.append(failure)

    def _record_fragment_current_mba_identity_binding(
        self,
        plan: FragmentPlan,
        binding: CurrentMbaIdentityBindingSnapshot,
    ) -> None:
        """Attach staged live identity to the pending receipt, never to evidence."""
        self._require_active_fragment(plan)
        if not self._active_fragment_staged:
            raise RuntimeError(
                "current-MBA identity binding requires staged fragment authority"
            )
        if self._active_current_mba_identity_binding_recorded:
            raise RuntimeError(
                "current-MBA identity binding was recorded more than once"
            )
        if not isinstance(binding, CurrentMbaIdentityBindingSnapshot):
            raise TypeError("current-MBA identity binding must be a portable snapshot")
        self._active_current_mba_identity_binding = binding
        self._active_current_mba_identity_binding_recorded = True

    def _replace_fragment_current_mba_identity_binding(
        self,
        plan: FragmentPlan,
        binding: CurrentMbaIdentityBindingSnapshot,
    ) -> None:
        """Refresh the pending receipt after postvalidated commit finalization."""
        self._require_active_fragment(plan)
        if (
            not self._active_fragment_staged
            or not self._active_current_mba_identity_binding_recorded
        ):
            raise RuntimeError(
                "current-MBA identity binding replacement requires staged authority"
            )
        validation = self._active_postpublication_validation
        if validation is None or not validation.passed:
            raise RuntimeError(
                "current-MBA identity binding replacement requires postvalidation"
            )
        if not isinstance(binding, CurrentMbaIdentityBindingSnapshot):
            raise TypeError("current-MBA identity binding must be a portable snapshot")
        self._active_current_mba_identity_binding = binding

    def _record_fragment_validation(
        self,
        *,
        plan: FragmentPlan,
        phase: str,
        validation: FragmentValidationResult,
    ) -> None:
        self._require_active_fragment(plan)
        if not isinstance(validation, FragmentValidationResult):
            raise TypeError("fragment validation has the wrong type")
        if (
            validation.plan_id != plan.plan_id
            or validation.atomic_group_id != plan.atomic_group_id
        ):
            raise ValueError("fragment validation scope does not match the plan")
        if phase == "prepublication":
            self._active_prepublication_validation = validation
        elif phase == "postpublication":
            self._active_postpublication_validation = validation
        else:
            raise ValueError("fragment validation phase is invalid")

    def _record_fragment_route_oracle(
        self,
        plan: FragmentPlan,
        result: DetachedRouteOracleResult,
    ) -> None:
        """Persist one staged comparison in gateway state and emit it immediately."""

        self._require_active_fragment(plan)
        if self._active_detached_route_oracle is not None:
            raise RuntimeError("detached route oracle was recorded more than once")
        run = plan.reference_oracle_run
        if (
            not isinstance(result, DetachedRouteOracleResult)
            or result.plan_id != plan.plan_id
            or result.atomic_group_id != plan.atomic_group_id
            or run is None
        ):
            raise ValueError("detached route oracle does not match the active plan")
        ledger_identities = _fragment_reference_ledger_identities(plan)
        expected_route_ids = tuple(route_id for route_id, _ledger in ledger_identities)
        observed_route_ids = tuple(
            comparison.route_id for comparison in result.comparisons
        )
        if expected_route_ids != observed_route_ids:
            raise ValueError(
                "detached route oracle comparison order drifted: "
                f"expected={expected_route_ids!r} observed={observed_route_ids!r}"
            )
        self._active_detached_route_oracle = result
        batch_id = str(self._active_batch_id)
        self._emit_observation(
            phase="detached_route_oracle",
            event_type=MbaSemanticFragmentRouteOracleCompared,
            payload=MbaSemanticFragmentRouteOracleCompared(
                session_id=self.session_id,
                function_ea=int(self.function_ea),
                maturity=int(self.maturity),
                mba_generation=int(self.identity_index.generation),
                evidence_generation=int(self.identity_index.evidence_generation),
                mutation_batch_id=batch_id,
                run_id=run.run_id,
                plan_id=plan.plan_id,
                atomic_group_id=plan.atomic_group_id,
                reference_ledger_identities=ledger_identities,
                result=result,
            ),
            mutation_batch_id=batch_id,
        )

    def _record_fragment_root_publication_attempted(
        self,
        plan: FragmentPlan,
    ) -> None:
        self._require_active_fragment(plan)
        self._active_root_publication_attempted = True

    def _active_root_publication_group(
        self,
        plan: FragmentPlan,
        group_id: str,
    ) -> MbaMutationRootPublicationGroup:
        self._require_active_fragment(plan)
        try:
            return self._active_root_publication_groups[str(group_id)]
        except KeyError as exc:
            raise ValueError(
                f"semantic-fragment transaction has no root group {group_id!r}"
            ) from exc

    def _record_fragment_root_group_publication_attempted(
        self,
        plan: FragmentPlan,
        group_id: str,
    ) -> None:
        group = self._active_root_publication_group(plan, group_id)
        if not self._active_root_publication_attempted:
            raise RuntimeError(
                "root-group publication requires aggregate publication authority"
            )
        if group.publication_attempted:
            raise RuntimeError("root publication group was attempted twice")
        self._active_root_publication_groups[group.group_id] = replace(
            group,
            publication_attempted=True,
        )

    def _record_fragment_root_group_publication_succeeded(
        self,
        plan: FragmentPlan,
        group_id: str,
    ) -> None:
        group = self._active_root_publication_group(plan, group_id)
        if not group.publication_attempted or group.publication_succeeded:
            raise RuntimeError("root publication group success is out of order")
        self._active_root_publication_groups[group.group_id] = replace(
            group,
            publication_succeeded=True,
        )

    def _record_fragment_root_group_rollback_attempted(
        self,
        plan: FragmentPlan,
        group_id: str,
    ) -> None:
        group = self._active_root_publication_group(plan, group_id)
        if not group.publication_attempted or group.rollback_attempted:
            raise RuntimeError("root publication group rollback is out of order")
        self._active_root_publication_groups[group.group_id] = replace(
            group,
            rollback_attempted=True,
            rollback_succeeded=False,
        )

    def _record_fragment_root_group_rollback_finished(
        self,
        plan: FragmentPlan,
        group_id: str,
        *,
        succeeded: bool,
    ) -> None:
        group = self._active_root_publication_group(plan, group_id)
        if not group.rollback_attempted:
            raise RuntimeError("root publication group rollback was not attempted")
        self._active_root_publication_groups[group.group_id] = replace(
            group,
            rollback_succeeded=bool(succeeded),
        )

    def _record_fragment_root_publication_succeeded(
        self,
        plan: FragmentPlan,
    ) -> None:
        self._require_active_fragment(plan)
        if not self._active_root_publication_attempted:
            raise RuntimeError("root publication was not attempted")
        if any(
            not group.publication_attempted or not group.publication_succeeded
            for group in self._active_root_publication_groups.values()
        ):
            raise RuntimeError(
                "aggregate root publication requires every group to succeed"
            )
        self._active_root_publication_succeeded = True

    def _record_fragment_rollback(
        self,
        plan: FragmentPlan,
        *,
        succeeded: bool,
    ) -> None:
        self._require_active_fragment(plan)
        attempted_groups = tuple(
            group
            for group in self._active_root_publication_groups.values()
            if group.publication_attempted
        )
        if (
            bool(succeeded)
            and self._active_root_publication_attempted
            and any(
                not group.rollback_attempted or not group.rollback_succeeded
                for group in attempted_groups
            )
        ):
            raise RuntimeError(
                "aggregate rollback outcome disagrees with root-group recovery"
            )
        self._active_rollback_attempted = True
        self._active_rollback_succeeded = bool(succeeded)

    def _record_fragment_semantic_validation(
        self,
        *,
        plan: FragmentPlan,
        prepublication: FragmentValidationResult,
        postpublication: FragmentValidationResult,
    ) -> None:
        """Attach passed semantic proof to the pending fragment receipt."""
        self._require_active_fragment(plan)
        for phase, result in (
            ("prepublication", prepublication),
            ("postpublication", postpublication),
        ):
            if not isinstance(result, FragmentValidationResult) or not result.passed:
                raise ValueError(f"cannot receipt failed {phase} validation")
            if (
                result.plan_id != plan.plan_id
                or result.atomic_group_id != plan.atomic_group_id
            ):
                raise ValueError("fragment validation scope does not match the plan")
        if (
            self._active_prepublication_validation is not prepublication
            or self._active_postpublication_validation is not postpublication
        ):
            raise ValueError(
                "fragment receipt validation was not observed in transaction order"
            )
        if not self._active_root_publication_succeeded:
            raise ValueError("fragment receipt requires published root authority")
        self._active_prepublication_validation = prepublication
        self._active_postpublication_validation = postpublication
        self._active_root_publication_confirmed = True

    def execute_patch_transaction(
        self,
        backend: object,
        plan: FragmentPlan,
        publication_profile=None,
    ) -> MbaMutationReceipt:
        """Lower, bind, realize, observe, and commit one semantic PatchPlan."""
        self._require_generation_usable()
        from d810.hexrays.mutation.semantic_fragment_publication import (
            _failure_message,
            _first_failed_obligation,
            execute_patch_transaction,
        )
        from d810.hexrays.mutation.semantic_fragment_profile import (
            SemanticFragmentPublicationProfile,
        )

        if publication_profile is None:
            publication_profile = SemanticFragmentPublicationProfile.CFG_READY
        if not isinstance(
            publication_profile,
            SemanticFragmentPublicationProfile,
        ):
            raise TypeError(
                "semantic fragment transaction requires a typed publication profile"
            )

        try:
            return execute_patch_transaction(
                self,
                backend,
                plan,
                publication_profile,
            )
        except CfgGenerationPoisoned:
            raise
        except Exception as exc:
            if (
                not self._mutation_started
                and self._current_transaction_attempt is not None
                and self._transaction_failure is None
            ):
                failure_phase = str(getattr(exc, "phase", "preflight"))
                self._record_clean_cfg_failure(
                    reason=_failure_message(exc),
                    failure_phase=failure_phase,
                    first_failed_obligation=_first_failed_obligation(
                        exc,
                        failure_phase=failure_phase,
                    ),
                )
            raise

    def _require_active(self) -> None:
        self._require_generation_usable()
        if not self.active:
            raise RuntimeError("structural mutation must be inside a gateway batch")

    def _record_handle(self, handle: MbaBlockHandle | None) -> None:
        if handle is not None and handle.stable_identity is not None:
            self._affected_identities.add(handle.stable_identity)

    def resolve_serial(self, serial: int | None) -> int | None:
        self._require_generation_usable()
        if serial is None:
            return None
        serial = int(serial)
        if not self.active:
            # Planned-coordinate rebinding is transaction-local.  Outside an
            # active batch, callers are describing the current live MBA; a
            # baseline retained by an earlier transaction must not shift it.
            return serial
        return self.identity_index.resolve_planned_serial(
            str(self._active_batch_id),
            serial,
        )

    def resolve_block(self, handle: MbaBlockHandle):
        """Resolve through this transaction's staged logical version."""
        self._require_active()
        return self.identity_index.resolve(
            handle,
            transaction_id=str(self._active_batch_id),
        )

    def resolve_logical_proxy(self, proxy):
        """Resolve one logical proxy through this transaction's staged view."""
        self._require_active()
        return self.identity_index.resolve_logical_proxy(
            proxy,
            transaction_id=str(self._active_batch_id),
        )

    @staticmethod
    def _identity_anchor(identity: StableBlockIdentity | None) -> int | None:
        if identity is None:
            return None
        if identity.exact_instruction_eas:
            return min(int(ea) for ea in identity.exact_instruction_eas)
        return int(identity.native_ranges.intervals[0].start_ea)

    def _semantic_edge_proxy_metadata(self, mba: object, proxy):
        binding = self.identity_index.resolve_logical_proxy(proxy)
        if binding is None:
            raise SemanticEdgeOperationRejected(
                f"logical proxy {proxy.proxy_token} has no published version"
            )
        identity = binding.handle.stable_identity
        anchor = self._identity_anchor(identity)
        if anchor is None:
            block = mba.get_mblock(int(binding.serial))
            if block is not None:
                start = int(getattr(block, "start", -1) or -1)
                if 0 <= start < 0xFFFFFFFFFFFFFFFF:
                    anchor = start
                else:
                    head = getattr(block, "head", None)
                    head_ea = int(getattr(head, "ea", -1) or -1)
                    if 0 <= head_ea < 0xFFFFFFFFFFFFFFFF:
                        anchor = head_ea
        return binding, identity, anchor

    def _semantic_edge_plan_items(
        self,
        mba: object,
        operation: LogicalSemanticEdgeOperation,
    ) -> tuple[MbaMutationPlanItem, ...]:
        source_binding, source_identity, source_anchor = (
            self._semantic_edge_proxy_metadata(mba, operation.source)
        )
        items: list[MbaMutationPlanItem] = []
        if operation.roles.intersection(
            {
                SemanticEdgeRole.CALL_FALLTHROUGH,
                SemanticEdgeRole.CONDITIONAL_FALLTHROUGH,
            }
        ):
            items.append(
                MbaMutationPlanItem(
                    item_index=len(items),
                    mutation_kind="materialize_adjacent_fallthrough_helper",
                    source_serial=(
                        int(source_binding.serial)
                        if source_anchor is not None
                        else None
                    ),
                    source_anchor_ea=source_anchor,
                    source_identity=source_identity,
                    disposition="planned",
                    reason="physical semantic fallthrough invariant",
                )
            )
        for edge in operation.edges:
            target_binding, target_identity, target_anchor = (
                self._semantic_edge_proxy_metadata(mba, edge.target)
            )
            items.append(
                MbaMutationPlanItem(
                    item_index=len(items),
                    mutation_kind=f"semantic_edge_{edge.role.value}",
                    source_serial=(
                        int(source_binding.serial)
                        if source_anchor is not None
                        else None
                    ),
                    source_anchor_ea=source_anchor,
                    source_identity=source_identity,
                    target_serial=(
                        int(target_binding.serial)
                        if target_anchor is not None
                        else None
                    ),
                    target_anchor_ea=target_anchor,
                    target_identity=target_identity,
                    disposition="planned",
                    reason="logical-proxy semantic edge operation",
                )
            )
        return tuple(items)

    def apply_semantic_edge_operation(
        self,
        backend: object,
        operation: LogicalSemanticEdgeOperation,
    ) -> MbaMutationReceipt:
        """Realize and receipt one role-complete logical edge operation.

        Proxy ownership and publication are checked before a transaction is
        opened.  The injected central mutation backend exposes only this
        operation's internal realization port; callers cannot select a
        low-level CFG helper.  Unsupported or stale shapes abort with an
        explicit exception, and no arm is silently skipped.
        """
        if not isinstance(operation, LogicalSemanticEdgeOperation):
            raise TypeError("semantic edge gateway requires a logical operation")
        mba = getattr(backend, "mba", None)
        realize = getattr(backend, "_realize_semantic_edge_operation", None)
        if mba is None or not callable(realize):
            raise TypeError(
                "semantic edge gateway requires the central mutation backend"
            )
        if self.active:
            raise RuntimeError(
                "semantic edge operation requires an independent gateway batch"
            )
        proxies = [operation.source]
        for edge in operation.edges:
            proxies.append(edge.target)
            if edge.expected_target is not None:
                proxies.append(edge.expected_target)
        for proxy in proxies:
            if not self.identity_index.owns_logical_proxy(proxy):
                raise ValueError(
                    f"logical proxy {proxy.proxy_token} is not owned by this "
                    "identity index"
                )

        plan_items = self._semantic_edge_plan_items(mba, operation)
        self.begin_batch(
            StructuralMutationKind.EDGE_REDIRECT,
            serial_quantity=int(getattr(mba, "qty", 0) or 0),
            description=(
                operation.description or "apply logical semantic edge operation"
            ),
            planned_operation_count=len(plan_items),
            plan_items=plan_items,
        )
        try:
            realize(operation)
        except SemanticEdgeOperationRejected as exc:
            self.abort(reason=str(exc))
            raise
        except Exception as exc:
            self.abort(
                reason=(f"semantic edge backend raised {type(exc).__name__}: {exc}")
            )
            raise
        return self.commit()

    def stage_replacement(
        self,
        *,
        original: MbaBlockHandle,
        replacement: MbaBlockHandle,
        returned_serial: int,
    ) -> LogicalBlockVersion:
        """Stage one replacement without changing published authority."""
        self._require_active()
        staged = self.identity_index.stage_replacement(
            transaction_id=str(self._active_batch_id),
            original=original,
            replacement=replacement,
            returned_serial=int(returned_serial),
        )
        self._record_handle(original)
        self._record_handle(replacement)
        self._operation_count += 1
        return staged

    def stage_inserted_replacement(
        self,
        *,
        original: MbaBlockHandle,
        replacement: MbaBlockHandle,
        insertion_serial: int,
        returned_serial: int,
    ) -> LogicalBlockVersion:
        """Stage an inserted physical clone behind the original logical proxy."""
        self._require_active()
        staged = self.identity_index.stage_inserted_replacement(
            transaction_id=str(self._active_batch_id),
            original=original,
            replacement=replacement,
            insertion_serial=int(insertion_serial),
            returned_serial=int(returned_serial),
        )
        self._record_handle(original)
        self._record_handle(replacement)
        self._operation_count += 1
        return staged

    def reserve_new_proxy(self, handle: MbaBlockHandle):
        """Reserve a transaction-local owner before its physical insertion."""
        self._require_active()
        staged = self.identity_index.reserve_new_proxy(
            transaction_id=str(self._active_batch_id),
            handle=handle,
        )
        self._record_handle(handle)
        return staged

    def reserve_plan_block(
        self,
        attempt: TransactionAttemptId,
        plan_ref: PlanBlockRef,
        *,
        handle: MbaBlockHandle | None = None,
        replaces: MbaBlockHandle | None = None,
    ) -> PlanBlockReservation:
        """Reserve D810-owned plan identity before invoking the SDK."""
        self._require_active()
        if attempt != self._current_transaction_attempt:
            raise ValueError("plan reservation attempt is not the active batch")
        if plan_ref not in self._cfg_plan_refs:
            raise ValueError("plan reservation is not declared by the active plan")
        reservation = self.identity_index.reserve_plan_block(
            attempt,
            plan_ref,
            handle=handle,
            replaces=replaces,
        )
        self._cfg_reservations[plan_ref] = reservation
        self._record_handle(reservation.logical_version.handle)
        if set(self._cfg_reservations) == set(self._cfg_plan_refs):
            self._emit_cfg_transaction_phase(CfgTransactionPhase.BOUND)
        return reservation

    def bind_reserved_plan_block(
        self,
        attempt: TransactionAttemptId,
        plan_ref: PlanBlockRef,
        *,
        insertion_serial: int,
        returned_serial: int,
    ) -> PlanBlockCreationReceipt:
        """Bind a planned insertion to the exact block returned by the SDK."""
        self._require_active()
        if attempt != self._current_transaction_attempt:
            raise ValueError("plan binding attempt is not the active batch")
        if not self._mutation_started:
            raise RuntimeError(
                "plan binding requires a pre-SDK mutation-start authority marker"
            )
        before = self.identity_index.transaction_quantity(str(self._active_batch_id))
        receipt = self.identity_index.bind_reserved_plan_block(
            attempt,
            plan_ref,
            insertion_serial=int(insertion_serial),
            returned_serial=int(returned_serial),
        )
        after = self.identity_index.transaction_quantity(str(self._active_batch_id))
        self._cfg_creation_receipts[plan_ref] = receipt
        self._cfg_creation_quantities[plan_ref] = (before, after)
        self._record_handle(receipt.logical_version.handle)
        self._operation_count += 1
        if set(self._cfg_creation_receipts) == set(self._cfg_plan_refs):
            self._emit_cfg_transaction_phase(CfgTransactionPhase.OBSERVED)
        return receipt

    def record_insert(
        self,
        *,
        insertion_serial: int,
        returned_serial: int,
        created: MbaBlockHandle,
    ) -> MbaBlockHandle:
        self._require_active()
        self.identity_index.record_insert(
            transaction_id=str(self._active_batch_id),
            insertion_serial=int(insertion_serial),
            created=created,
            returned_serial=int(returned_serial),
        )
        self._record_handle(created)
        self._operation_count += 1
        return created

    def record_observed_insert(
        self,
        *,
        insertion_serial: int,
        returned_serial: int,
    ) -> MbaBlockHandle:
        """Record an SDK-created block that has no portable plan owner."""
        created = self.identity_index.create_observed_ephemeral_handle()
        return self.record_insert(
            insertion_serial=insertion_serial,
            returned_serial=returned_serial,
            created=created,
        )

    def discard_reserved_insert(self, handle: MbaBlockHandle) -> None:
        """Synchronize rollback after removing a reserved physical insertion."""
        self._require_active()
        self.identity_index.discard_reserved_insert(
            transaction_id=str(self._active_batch_id),
            handle=handle,
        )

    def record_realized_serial(
        self, *, expected_serial: int, returned_serial: int
    ) -> None:
        self._require_active()
        self.identity_index.record_realized_serial(
            transaction_id=str(self._active_batch_id),
            expected_serial=int(expected_serial),
            returned_serial=int(returned_serial),
        )
        self._operation_count += 1

    def record_edge_redirect(
        self,
        *,
        source: MbaBlockHandle | None = None,
        target: MbaBlockHandle | None = None,
    ) -> None:
        """Record one realized edge mutation without changing serial bindings."""
        self._require_active()
        self._record_handle(source)
        self._record_handle(target)
        self._operation_count += 1

    def _record_semantic_fragment_effect(
        self,
        *,
        mutation_kind: str,
        reason: str,
        block: MbaBlockHandle,
    ) -> None:
        self._require_active()
        if self._active_kind is not StructuralMutationKind.FRAGMENT_PUBLICATION:
            raise RuntimeError(
                "semantic-fragment effects require a fragment publication batch"
            )
        key = (str(mutation_kind), str(reason))
        item = self._active_fragment_effect_requirements.get(key)
        if item is None:
            raise ValueError(
                f"semantic-fragment effect is absent from the plan inventory: {key!r}"
            )
        if key in self._applied_fragment_effects:
            raise RuntimeError(
                f"semantic-fragment effect was recorded more than once: {key!r}"
            )
        identity = block.stable_identity
        expected_identities = {
            candidate
            for candidate in (item.source_identity, item.target_identity)
            if candidate is not None
        }
        generated_helper_anchor_matches = (
            mutation_kind == "semantic_fragment_operation_fallthrough_helper"
            and identity is not None
            and item.target_identity is not None
            and item.target_anchor_ea is not None
            and identity.native_key == item.target_identity.native_key
            and int(item.target_anchor_ea) in identity.exact_instruction_eas
            and identity.native_ranges.contains(int(item.target_anchor_ea))
            and item.target_identity.native_ranges.contains(int(item.target_anchor_ea))
        )
        generated_constant_anchor_matches = (
            mutation_kind == "semantic_fragment_constant_materialization"
            and identity is not None
            and item.source_identity is not None
            and item.source_anchor_ea is not None
            and identity.native_key == item.source_identity.native_key
            and int(item.source_anchor_ea) in identity.exact_instruction_eas
            and identity.native_ranges.contains(int(item.source_anchor_ea))
            and item.source_identity.native_ranges.contains(
                int(item.source_anchor_ea)
            )
        )
        if identity is None or (
            identity not in expected_identities
            and not generated_helper_anchor_matches
            and not generated_constant_anchor_matches
        ):
            raise ValueError(
                "semantic-fragment effect block identity does not match its "
                "EA-anchored plan item; "
                f"key={key!r} actual="
                f"{None if identity is None else identity.to_dict()!r} "
                f"expected={tuple(candidate.to_dict() for candidate in expected_identities)!r}"
            )
        self._applied_fragment_effects.add(key)
        self._record_handle(block)
        self._operation_count += 1

    def record_semantic_fragment_return_carrier(
        self,
        *,
        carrier_id: str,
        block: MbaBlockHandle,
    ) -> None:
        """Acknowledge one live-observed return carrier from the active plan."""
        self._record_semantic_fragment_effect(
            mutation_kind="semantic_fragment_return_carrier_materialization",
            reason=f"return-carrier:{carrier_id}",
            block=block,
        )

    def record_semantic_fragment_constant_materialization(
        self,
        *,
        materialization_id: str,
        block: MbaBlockHandle,
    ) -> None:
        """Acknowledge one exact in-place constant replacement."""
        self._record_semantic_fragment_effect(
            mutation_kind="semantic_fragment_constant_materialization",
            reason=f"constant:{str(materialization_id)}",
            block=block,
        )

    def record_semantic_fragment_terminal_return(
        self,
        *,
        return_id: str,
        block: MbaBlockHandle,
    ) -> None:
        """Acknowledge one live-observed terminal return from the active plan."""
        self._record_semantic_fragment_effect(
            mutation_kind="semantic_fragment_terminal_return_materialization",
            reason=f"terminal-return:{return_id}",
            block=block,
        )

    def record_generated_existing_fallthrough_helper(
        self,
        *,
        operation_id: str,
        block: MbaBlockHandle,
    ) -> None:
        """Acknowledge a GENERATED helper realized by an existing live block."""
        self._record_semantic_fragment_effect(
            mutation_kind="semantic_fragment_operation_fallthrough_helper",
            reason=f"operation:{str(operation_id)}",
            block=block,
        )

    def record_remove(self, handle: MbaBlockHandle) -> None:
        self._require_active()
        self.identity_index.mark_removed(
            handle,
            transaction_id=str(self._active_batch_id),
        )
        self._record_handle(handle)
        self._operation_count += 1

    def record_split(
        self,
        *,
        original: MbaBlockHandle,
        retained: MbaBlockHandle,
        created_tail: MbaBlockHandle,
        returned_tail_serial: int,
    ) -> None:
        """Record one SDK split through the receipt-owning control plane."""
        self._require_active()
        self.identity_index.record_split(
            transaction_id=str(self._active_batch_id),
            original=original,
            retained=retained,
            created_tail=created_tail,
            returned_tail_serial=int(returned_tail_serial),
        )
        self._record_handle(original)
        self._record_handle(retained)
        self._record_handle(created_tail)
        self._operation_count += 1

    def record_clone(
        self,
        *,
        source: MbaBlockHandle,
        returned_serial: int,
        created: MbaBlockHandle | None = None,
    ) -> MbaBlockHandle:
        """Record one SDK clone and return its transaction-local handle."""
        self._require_active()
        created = created or (
            self.identity_index.create_observed_ephemeral_handle()
            if source.stable_identity is None
            else self.identity_index.create_native_handle(
                source.stable_identity,
                provenance=source.provenance,
            )
        )
        self.identity_index.record_clone(
            transaction_id=str(self._active_batch_id),
            source=source,
            created=created,
            returned_serial=int(returned_serial),
        )
        self._record_handle(source)
        self._record_handle(created)
        self._operation_count += 1
        return created

    def record_unknown_sdk_operation(self, mba: object) -> None:
        """Refresh current bindings immediately after an unmodelled SDK mutation.

        The raw MBA remains callback-local: the index retains only rebuilt
        identities, handles, and integer coordinates.
        """
        self._require_active()
        transaction_id = str(self._active_batch_id)
        self.identity_index.refresh_from_mba(mba)
        self.identity_index.begin_transaction(
            transaction_id,
            int(getattr(mba, "qty", 0) or 0),
        )
        self._operation_count += 1

    def record_external_sdk_operations(
        self,
        mba: object,
        *,
        operation_count: int,
    ) -> None:
        """Refresh bindings after a coordinator-owned external SDK batch.

        Copy-and-swap applies several SDK writes behind one logical mutation
        plan item.  The gateway needs the final live MBA once, plus the exact
        number of successfully committed plan items that did not already
        record a modeled insert, split, clone, remove, or redirect.
        """
        self._require_active()
        count = int(operation_count)
        if count < 0:
            raise ValueError("external SDK operation count must be non-negative")
        transaction_id = str(self._active_batch_id)
        self.identity_index.refresh_from_mba(mba)
        self.identity_index.begin_transaction(
            transaction_id,
            int(getattr(mba, "qty", 0) or 0),
        )
        self._operation_count += count

    def commit(self) -> MbaMutationReceipt:
        self._require_active()
        fragment_plan = self._active_fragment_plan
        requires_reference_route_oracle = bool(
            fragment_plan is not None
            and any(
                operation.reference_route_authority is not None
                for operation in fragment_plan.operations
            )
        )
        if self._active_kind is StructuralMutationKind.FRAGMENT_PUBLICATION and (
            fragment_plan is None
            or self._active_prepublication_validation is None
            or self._active_postpublication_validation is None
            or not self._active_root_publication_confirmed
            or not self._active_current_mba_identity_binding_recorded
            or (
                requires_reference_route_oracle
                and (
                    self._active_detached_route_oracle is None
                    or not self._active_detached_route_oracle.passed
                )
            )
        ):
            raise RuntimeError(
                "fragment publication cannot commit before semantic postvalidation"
            )
        if (
            self._active_kind is StructuralMutationKind.FRAGMENT_PUBLICATION
            and self._operation_count != self._planned_operation_count
        ):
            raise RuntimeError(
                "fragment publication operation inventory mismatch: "
                f"planned={self._planned_operation_count} "
                f"applied={self._operation_count}"
            )
        if (
            self._current_transaction_attempt is not None
            and self._active_kind is not StructuralMutationKind.FRAGMENT_PUBLICATION
            # Same reconciliation as observe_patch_realization: a planned step
            # is accounted for when it was applied OR when conflict resolution
            # deliberately superseded it as redundant.
            and self._operation_count + self._superseded_operation_count
            != self._planned_operation_count
        ):
            raise RuntimeError(
                "patch realization operation inventory mismatch: "
                f"planned={self._planned_operation_count} "
                f"applied={self._operation_count} "
                f"superseded={self._superseded_operation_count}"
            )
        version_transitions = self.identity_index.commit_proxy_transaction(
            str(self._active_batch_id)
        )
        pre_generation = self.identity_index.generation
        post_generation = self.identity_index.advance_generation()
        receipt = MbaMutationReceipt(
            mutation_batch_id=str(self._active_batch_id),
            kind=self._active_kind,
            pre_generation=pre_generation,
            post_generation=post_generation,
            evidence_generation=int(self.identity_index.evidence_generation),
            affected_identities=tuple(self._affected_identities),
            operation_count=self._operation_count,
            planned_operation_count=(
                self._planned_operation_count
                if fragment_plan is not None
                else max(self._planned_operation_count, self._operation_count)
            ),
            description=self._active_description,
            version_transitions=version_transitions,
            fragment_plan_id=("" if fragment_plan is None else fragment_plan.plan_id),
            fragment_atomic_group_id=(
                "" if fragment_plan is None else fragment_plan.atomic_group_id
            ),
            root_publication_groups=tuple(
                self._active_root_publication_groups.values()
            ),
            prepublication_validation=self._active_prepublication_validation,
            postpublication_validation=self._active_postpublication_validation,
            root_publication_confirmed=self._active_root_publication_confirmed,
            current_mba_identity_binding=self._active_current_mba_identity_binding,
            detached_route_oracle=self._active_detached_route_oracle,
        )
        self.generation = post_generation
        self._receipts.append(receipt)
        if self._current_transaction_attempt is not None:
            self._emit_cfg_transaction_phase(CfgTransactionPhase.COMMITTED)
        committed_batch_id = str(self._active_batch_id)
        self._active_kind = None
        self._active_description = ""
        self._active_batch_id = None
        self._planned_operation_count = 0
        self._affected_identities.clear()
        self._operation_count = 0
        self._reset_fragment_context()
        committed = MbaMutationCommitted(
            session_id=self.session_id,
            function_ea=int(self.function_ea),
            maturity=int(self.maturity),
            mba_generation_before=pre_generation,
            mba_generation_after=post_generation,
            evidence_generation=int(self.identity_index.evidence_generation),
            receipt=receipt,
        )
        self._emit_observation(
            phase="committed",
            event_type=MbaMutationCommitted,
            payload=committed,
            mutation_batch_id=committed_batch_id,
        )
        self._reset_cfg_context()
        return receipt

    def abort(self, *, reason: str = "aborted") -> None:
        """Forget an uncommitted batch; callers must rebuild after SDK failure."""
        aborted_batch_id = str(self._active_batch_id)
        identity_transaction_id = (
            self._current_transaction_attempt.attempt_id
            if self._current_transaction_attempt is not None
            else str(self._active_batch_id)
        )
        discarded_versions = self.identity_index.abort_proxy_transaction(
            identity_transaction_id
        )
        if self.active:
            self._emit_observation(
                phase="aborted",
                event_type=MbaMutationAborted,
                payload=MbaMutationAborted(
                    session_id=self.session_id,
                    function_ea=int(self.function_ea),
                    maturity=int(self.maturity),
                    mba_generation=int(self.identity_index.generation),
                    evidence_generation=int(self.identity_index.evidence_generation),
                    mutation_batch_id=aborted_batch_id,
                    kind=self._active_kind,
                    planned_operation_count=int(self._planned_operation_count),
                    applied_operation_count=int(self._operation_count),
                    description=self._active_description,
                    reason=str(reason),
                    discarded_versions=discarded_versions,
                    fragment_plan_id=(
                        ""
                        if self._active_fragment_plan is None
                        else self._active_fragment_plan.plan_id
                    ),
                    fragment_atomic_group_id=(
                        ""
                        if self._active_fragment_plan is None
                        else self._active_fragment_plan.atomic_group_id
                    ),
                    root_publication_groups=tuple(
                        self._active_root_publication_groups.values()
                    ),
                    fragment_staged=self._active_fragment_staged,
                    root_publication_attempted=(
                        self._active_root_publication_attempted
                    ),
                    root_publication_succeeded=(
                        self._active_root_publication_succeeded
                    ),
                    rollback_attempted=self._active_rollback_attempted,
                    rollback_succeeded=self._active_rollback_succeeded,
                    prepublication_validation=(self._active_prepublication_validation),
                    postpublication_validation=(
                        self._active_postpublication_validation
                    ),
                    fragment_failures=tuple(self._active_fragment_failures),
                ),
                mutation_batch_id=aborted_batch_id,
            )
        self._active_kind = None
        self._active_description = ""
        self._active_batch_id = None
        self._planned_operation_count = 0
        self._affected_identities.clear()
        self._operation_count = 0
        self._reset_fragment_context()
        self._reset_cfg_context()

    def record(
        self,
        kind: StructuralMutationKind,
        *,
        affected_identities: Iterable[StableBlockIdentity] = (),
        description: str = "",
    ) -> MbaMutationReceipt:
        """Record one already-applied structural mutation as a one-op batch."""
        self.begin_batch(
            kind,
            description=description,
            planned_operation_count=1,
        )
        self._affected_identities.update(affected_identities)
        self._operation_count = 1
        return self.commit()


__all__ = [
    "MbaCfgTransactionAuthorityObserved",
    "MbaMutationCommitted",
    "MbaMutationAborted",
    "MbaMutationGateway",
    "MbaMutationObservationFailure",
    "MbaMutationPlanItem",
    "MbaMutationPlanned",
    "MbaMutationReceipt",
    "MbaMutationRootPublicationGroup",
    "MbaSemanticFragmentRouteOracleCompared",
    "StructuralMutationKind",
]
