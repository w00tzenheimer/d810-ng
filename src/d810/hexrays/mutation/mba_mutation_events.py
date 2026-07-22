"""Synchronous receipt gateway for structural MBA mutation."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
import uuid

from d810.core.events import EventEmitter
from d810.core.logging import getLogger
from d810.core.native_preanalysis_key import NativePreanalysisKey
from d810.core.typing import Iterable
from d810.hexrays.ir.mba_identity_index import MbaBlockIdentityIndex
from d810.hexrays.ir.logical_block_proxy import (
    LogicalBlockVersion,
    LogicalBlockVersionId,
    LogicalBlockVersionTransition,
)
from d810.hexrays.ir.semantic_edge import (
    LogicalSemanticEdgeOperation,
    SemanticEdgeOperationRejected,
)
from d810.ir.block_identity import MbaBlockHandle, StableBlockIdentity
from d810.ir.semantic_edge import SemanticEdgeRole
from d810.transforms.fragment_plan import FragmentPlan
from d810.transforms.fragment_validation import FragmentValidationResult


logger = getLogger(__name__)


class StructuralMutationKind(Enum):
    """Structural mutation families that can invalidate current bindings."""

    EDGE_REDIRECT = "edge_redirect"
    BLOCK_INSERT = "block_insert"
    BLOCK_REMOVE = "block_remove"
    BLOCK_REPLACE = "block_replace"
    FRAGMENT_PUBLICATION = "fragment_publication"


@dataclass(frozen=True, slots=True)
class MbaMutationReceipt:
    """Post-commit record for one atomic structural mutation batch."""

    mutation_batch_id: str
    kind: StructuralMutationKind
    pre_generation: int
    post_generation: int
    affected_identities: tuple[StableBlockIdentity, ...]
    operation_count: int = 0
    planned_operation_count: int = 0
    description: str = ""
    version_transitions: tuple[LogicalBlockVersionTransition, ...] = ()
    fragment_plan_id: str = ""
    fragment_atomic_group_id: str = ""
    prepublication_validation: FragmentValidationResult | None = None
    postpublication_validation: FragmentValidationResult | None = None
    root_publication_confirmed: bool = False

    def __post_init__(self) -> None:
        pre_generation = int(self.pre_generation)
        post_generation = int(self.post_generation)
        if pre_generation < 0 or post_generation != pre_generation + 1:
            raise ValueError("a mutation receipt must advance exactly one generation")
        if int(self.operation_count) < 0:
            raise ValueError("a mutation receipt cannot have negative operations")
        if not str(self.mutation_batch_id):
            raise ValueError("a mutation receipt requires a batch id")
        if int(self.planned_operation_count) < int(self.operation_count):
            raise ValueError("applied operations cannot exceed the planned count")
        object.__setattr__(self, "pre_generation", pre_generation)
        object.__setattr__(self, "post_generation", post_generation)
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
        has_fragment = bool(fragment_plan_id)
        if (self.kind is StructuralMutationKind.FRAGMENT_PUBLICATION) != has_fragment:
            raise ValueError(
                "fragment-publication receipt requires validated fragment context"
            )
        if has_fragment != bool(fragment_atomic_group_id):
            raise ValueError("fragment receipt requires both plan and atomic-group ids")
        if has_fragment:
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
        elif (
            self.prepublication_validation is not None
            or self.postpublication_validation is not None
            or self.root_publication_confirmed
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
            "root_publication_confirmed",
            bool(self.root_publication_confirmed),
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
    description: str
    reason: str
    discarded_version_ids: tuple[LogicalBlockVersionId, ...] = ()


@dataclass(frozen=True, slots=True)
class MbaMutationObservationFailure:
    """Structured failure of a non-authoritative mutation observer."""

    phase: str
    event_name: str
    mutation_batch_id: str
    error_type: str
    error_message: str


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

    def _reset_fragment_context(self) -> None:
        self._active_fragment_plan = None
        self._active_prepublication_validation = None
        self._active_postpublication_validation = None
        self._active_root_publication_confirmed = False

    def new_transaction(self) -> MbaMutationGateway:
        """Return a fresh batch controller over this current-MBA index.

        A structural operation must own its transaction boundary, while every
        operation in the same live MBA must still resolve through one index.
        The returned gateway shares only that index and observer port; it
        carries neither this gateway's active batch nor its receipt history.
        """
        return MbaMutationGateway(
            native_key=self.native_key,
            generation=int(self.identity_index.generation),
            session_id=self.session_id,
            function_ea=self.function_ea,
            maturity=self.maturity,
            identity_index=self.identity_index,
            event_emitter=self.event_emitter,
        )

    def begin_batch(
        self,
        kind: StructuralMutationKind,
        *,
        serial_quantity: int | None = None,
        description: str = "",
        planned_operation_count: int = 1,
        plan_items: Iterable[MbaMutationPlanItem] = (),
    ) -> None:
        if self.active:
            raise RuntimeError("a structural mutation batch is already active")
        if not isinstance(kind, StructuralMutationKind):
            raise TypeError("structural mutation batch requires a mutation kind")
        planned_operation_count = int(planned_operation_count)
        if planned_operation_count < 0:
            raise ValueError("planned operation count must be non-negative")
        plan_items = tuple(plan_items)
        serial_quantity = (
            None if serial_quantity is None else int(serial_quantity)
        )
        batch_id = uuid.uuid4().hex
        self.identity_index.begin_transaction(batch_id, serial_quantity)

        self._reset_fragment_context()
        self._active_kind = kind
        self._active_description = str(description)
        self._active_batch_id = batch_id
        self._planned_operation_count = planned_operation_count
        self._affected_identities.clear()
        self._operation_count = 0
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
            ),
            mutation_batch_id=batch_id,
        )

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
    ) -> tuple[MbaMutationPlanItem, ...]:
        items: list[MbaMutationPlanItem] = []
        for root_id in plan.roots:
            replacement = plan.block(root_id)
            original = plan.block(str(replacement.replaces_block_id))
            items.append(
                MbaMutationPlanItem(
                    item_index=len(items),
                    mutation_kind="semantic_fragment_root_publication",
                    source_anchor_ea=int(original.semantic_anchor_ea),
                    source_identity=original.stable_identity,
                    target_anchor_ea=int(replacement.semantic_anchor_ea),
                    target_identity=replacement.stable_identity,
                    reason=f"atomic-group:{plan.atomic_group_id}",
                )
            )
        for operation in plan.operations:
            source = plan.block(operation.source_block_id)
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
        return tuple(items)

    def _begin_semantic_fragment_batch(
        self,
        backend: object,
        plan: FragmentPlan,
    ) -> None:
        mba = getattr(backend, "mba", None)
        if mba is None:
            raise TypeError("semantic-fragment backend requires a live MBA")
        items = self._fragment_plan_items(plan)
        self.begin_batch(
            StructuralMutationKind.FRAGMENT_PUBLICATION,
            serial_quantity=int(getattr(mba, "qty", 0) or 0),
            description=(
                f"publish semantic fragment {plan.plan_id} "
                f"atomic-group={plan.atomic_group_id}"
            ),
            planned_operation_count=len(items),
            plan_items=items,
        )

    def _record_fragment_semantic_validation(
        self,
        *,
        plan: FragmentPlan,
        prepublication: FragmentValidationResult,
        postpublication: FragmentValidationResult,
    ) -> None:
        """Attach passed semantic proof to the pending fragment receipt."""
        self._require_active()
        if self._active_kind is not StructuralMutationKind.FRAGMENT_PUBLICATION:
            raise RuntimeError("semantic validation belongs to fragment publication")
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
        self._active_fragment_plan = plan
        self._active_prepublication_validation = prepublication
        self._active_postpublication_validation = postpublication
        self._active_root_publication_confirmed = True

    def publish_semantic_fragment(
        self,
        backend: object,
        plan: FragmentPlan,
    ) -> MbaMutationReceipt:
        """Stage, prove, publish, post-prove, and receipt one whole fragment."""
        from d810.hexrays.mutation.semantic_fragment_publication import (
            publish_semantic_fragment,
        )

        return publish_semantic_fragment(self, backend, plan)

    def _require_active(self) -> None:
        if not self.active:
            raise RuntimeError("structural mutation must be inside a gateway batch")

    def _record_handle(self, handle: MbaBlockHandle | None) -> None:
        if handle is not None and handle.stable_identity is not None:
            self._affected_identities.add(handle.stable_identity)

    def resolve_serial(self, serial: int | None) -> int | None:
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
        if SemanticEdgeRole.CONDITIONAL_FALLTHROUGH in operation.roles:
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
                    reason="physical conditional fallthrough invariant",
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

    def record_insert(
        self,
        *,
        insertion_serial: int,
        returned_serial: int,
        created: MbaBlockHandle | None = None,
    ) -> MbaBlockHandle:
        self._require_active()
        created = created or self.identity_index.create_synthetic_handle()
        self.identity_index.record_insert(
            transaction_id=str(self._active_batch_id),
            insertion_serial=int(insertion_serial),
            created=created,
            returned_serial=int(returned_serial),
        )
        self._record_handle(created)
        self._operation_count += 1
        return created

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
            self.identity_index.create_synthetic_handle()
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
        if self._active_kind is StructuralMutationKind.FRAGMENT_PUBLICATION and (
            fragment_plan is None
            or self._active_prepublication_validation is None
            or self._active_postpublication_validation is None
            or not self._active_root_publication_confirmed
        ):
            raise RuntimeError(
                "fragment publication cannot commit before semantic postvalidation"
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
            affected_identities=tuple(self._affected_identities),
            operation_count=self._operation_count,
            planned_operation_count=max(
                self._planned_operation_count,
                self._operation_count,
            ),
            description=self._active_description,
            version_transitions=version_transitions,
            fragment_plan_id=("" if fragment_plan is None else fragment_plan.plan_id),
            fragment_atomic_group_id=(
                "" if fragment_plan is None else fragment_plan.atomic_group_id
            ),
            prepublication_validation=self._active_prepublication_validation,
            postpublication_validation=self._active_postpublication_validation,
            root_publication_confirmed=self._active_root_publication_confirmed,
        )
        self.generation = post_generation
        self._receipts.append(receipt)
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
        return receipt

    def abort(self, *, reason: str = "aborted") -> None:
        """Forget an uncommitted batch; callers must rebuild after SDK failure."""
        aborted_batch_id = str(self._active_batch_id)
        discarded_version_ids = (
            self.identity_index.abort_proxy_transaction(str(self._active_batch_id))
            if self.active
            else ()
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
                    description=self._active_description,
                    reason=str(reason),
                    discarded_version_ids=discarded_version_ids,
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
    "MbaMutationCommitted",
    "MbaMutationAborted",
    "MbaMutationGateway",
    "MbaMutationObservationFailure",
    "MbaMutationPlanItem",
    "MbaMutationPlanned",
    "MbaMutationReceipt",
    "StructuralMutationKind",
]
