"""Current-MBA bindings for portable block identity.

The index deliberately owns all current serial coordinates.  It retains only
serial-free handles and derived integer bindings; an MBA is lifted by the
callback that needs it and is never retained here.
"""

from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass, field
from types import MappingProxyType

from d810.core.typing import Callable, Iterable, Mapping
from d810.core.native_preanalysis_key import NativePreanalysisKey
from d810.ir.block_identity import (
    BlockHandleProvenance,
    BoundBlock,
    CurrentMbaIdentityBindingSnapshot,
    MbaBlockHandle,
    NativeEaInterval,
    RebindResult,
    StableBlockIdentity,
    stable_block_identity_from_snapshot,
)
from d810.ir.flowgraph import FlowGraph
from d810.hexrays.ir.logical_block_proxy import (
    LogicalBlockProxy,
    LogicalBlockVersion,
    LogicalBlockVersionTransition,
)
from d810.transforms.cfg_transaction import (
    CfgGenerationPoisoned,
    CfgTransactionFailure,
    CfgTransactionPhase,
    LogicalBlockRef,
    NativeBlockRef,
    PlanBlockRef,
    TransactionAttemptId,
)


@dataclass(frozen=True, slots=True)
class PlanBlockReservation:
    """Pre-mutation ownership of one plan-local physical realization."""

    attempt_id: TransactionAttemptId
    plan_ref: PlanBlockRef
    session_id: str
    generation: int
    logical_version: LogicalBlockVersion

    def __post_init__(self) -> None:
        if not isinstance(self.attempt_id, TransactionAttemptId):
            raise TypeError("reservation requires a TransactionAttemptId")
        if not isinstance(self.plan_ref, PlanBlockRef):
            raise TypeError("reservation requires a PlanBlockRef")
        if self.attempt_id.plan_id != self.plan_ref.plan_id:
            raise ValueError("reservation plan authorities differ")
        if self.attempt_id.session_id != str(self.session_id):
            raise ValueError("reservation session authority differs")
        if self.attempt_id.generation != int(self.generation):
            raise ValueError("reservation generation authority differs")
        if not isinstance(self.logical_version, LogicalBlockVersion):
            raise TypeError("reservation requires a logical block version")


@dataclass(frozen=True, slots=True)
class PlanBlockCreationReceipt:
    """Immutable proof connecting portable intent to its live coordinate."""

    attempt_id: TransactionAttemptId
    plan_ref: PlanBlockRef
    logical_version: LogicalBlockVersion
    insertion_serial: int
    returned_serial: int
    block: BoundBlock

    def __post_init__(self) -> None:
        if not isinstance(self.attempt_id, TransactionAttemptId):
            raise TypeError("creation receipt requires a TransactionAttemptId")
        if not isinstance(self.plan_ref, PlanBlockRef):
            raise TypeError("creation receipt requires a PlanBlockRef")
        if self.attempt_id.plan_id != self.plan_ref.plan_id:
            raise ValueError("creation receipt plan authorities differ")
        if not isinstance(self.logical_version, LogicalBlockVersion):
            raise TypeError("creation receipt requires a logical block version")
        if not isinstance(self.block, BoundBlock):
            raise TypeError("creation receipt requires a bound block")
        if int(self.insertion_serial) < 0 or int(self.returned_serial) < 0:
            raise ValueError("creation receipt coordinates must be non-negative")
        if self.block.handle is not self.logical_version.handle:
            raise ValueError("creation receipt handle authority differs")
        if self.block.serial != int(self.returned_serial):
            raise ValueError("creation receipt must bind the exact returned coordinate")


@dataclass(frozen=True, slots=True)
class IdentityRebindObservation:
    decision_kind: str
    identity: StableBlockIdentity
    result: RebindResult
    mba_generation: int
    evidence_generation: int
    candidates: tuple[BoundBlock, ...] = ()


@dataclass(slots=True)
class MbaBlockIdentityIndex:
    """Session-local handles rebound into one mutable MBA generation.

    All shifts caused by structural mutation are applied here synchronously.
    Callers may retain a :class:`MbaBlockHandle`, but never a block serial.
    """

    session_id: str
    native_key: NativePreanalysisKey
    generation: int = 0
    evidence_generation: int | None = None
    maturity: int | None = None
    snapshot_id: str | None = None
    decision_observer: Callable[[IdentityRebindObservation], None] | None = field(
        default=None,
        repr=False,
    )
    _handles_by_token: dict[str, MbaBlockHandle] = field(
        default_factory=dict,
        init=False,
        repr=False,
    )
    _serial_by_token: dict[str, int] = field(
        default_factory=dict,
        init=False,
        repr=False,
    )
    _token_by_serial: dict[int, str] = field(
        default_factory=dict,
        init=False,
        repr=False,
    )
    _tokens_by_identity: dict[StableBlockIdentity, set[str]] = field(
        default_factory=lambda: defaultdict(set),
        init=False,
        repr=False,
    )
    _next_token: int = field(default=0, init=False, repr=False)
    _next_proxy_token: int = field(default=0, init=False, repr=False)
    _proxies_by_token: dict[str, LogicalBlockProxy] = field(
        default_factory=dict,
        init=False,
        repr=False,
    )
    _proxy_token_by_handle_token: dict[str, str] = field(
        default_factory=dict,
        init=False,
        repr=False,
    )
    _proxy_tokens_by_transaction: dict[str, set[str]] = field(
        default_factory=lambda: defaultdict(set),
        init=False,
        repr=False,
    )
    _proxy_actions_by_transaction: dict[str, dict[str, str]] = field(
        default_factory=lambda: defaultdict(dict),
        init=False,
        repr=False,
    )
    _serials_by_transaction: dict[str, dict[str, int]] = field(
        default_factory=dict,
        init=False,
        repr=False,
    )
    _baseline_tokens_by_transaction: dict[str, dict[int, str]] = field(
        default_factory=dict,
        init=False,
        repr=False,
    )
    _generation_by_transaction: dict[str, int] = field(
        default_factory=dict,
        init=False,
        repr=False,
    )
    _attempt_by_transaction: dict[str, TransactionAttemptId] = field(
        default_factory=dict,
        init=False,
        repr=False,
    )
    _insertion_serials_by_transaction: dict[str, dict[str, int]] = field(
        default_factory=dict,
        init=False,
        repr=False,
    )
    _plan_reservations: dict[
        tuple[TransactionAttemptId, PlanBlockRef], PlanBlockReservation
    ] = field(default_factory=dict, init=False, repr=False)
    _plan_creation_receipts: dict[
        tuple[TransactionAttemptId, PlanBlockRef], PlanBlockCreationReceipt
    ] = field(default_factory=dict, init=False, repr=False)
    _poisoned_generation: int | None = field(default=None, init=False, repr=False)
    _poisoned_failure: CfgTransactionFailure | None = field(
        default=None,
        init=False,
        repr=False,
    )

    def __post_init__(self) -> None:
        self.session_id = str(self.session_id)
        self.generation = int(self.generation)
        if self.evidence_generation is None:
            self.evidence_generation = self.generation
        else:
            self.evidence_generation = int(self.evidence_generation)
        if not self.session_id:
            raise ValueError("MBA identity index requires a session id")
        if not isinstance(self.native_key, NativePreanalysisKey):
            raise TypeError("MBA identity index requires a native key")
        if self.generation < 0:
            raise ValueError("MBA identity index generation must be non-negative")
        if self.evidence_generation < 0:
            raise ValueError("MBA identity evidence generation must be non-negative")
        if self.maturity is not None:
            self.maturity = int(self.maturity)
            if self.maturity < 0:
                raise ValueError("MBA identity maturity must be non-negative")
        if self.snapshot_id is None:
            maturity_label = "unknown" if self.maturity is None else str(self.maturity)
            self.snapshot_id = f"{self.session_id}:m{maturity_label}:g{self.generation}"
        elif not isinstance(self.snapshot_id, str) or not self.snapshot_id.strip():
            raise ValueError("MBA identity snapshot_id must be a non-empty string")

    @property
    def generation_poisoned(self) -> bool:
        """Whether an SDK write invalidated this exact live-MBA generation."""
        return self._poisoned_generation == self.generation

    @property
    def poisoned_failure(self) -> CfgTransactionFailure | None:
        """Return the first failure shared by every gateway over this index."""
        return self._poisoned_failure if self.generation_poisoned else None

    def poison_generation(self, failure: CfgTransactionFailure) -> None:
        """Latch the first post-write failure for this live MBA generation."""
        if not isinstance(failure, CfgTransactionFailure):
            raise TypeError(
                "MBA generation poison requires transaction failure evidence"
            )
        if failure.phase is not CfgTransactionPhase.POISONED_RESTART_REQUIRED:
            raise ValueError("MBA generation poison requires a poisoned failure phase")
        if self._poisoned_failure is None:
            self._poisoned_generation = int(self.generation)
            self._poisoned_failure = failure

    def require_generation_usable(self) -> None:
        """Reject every live-MBA operation after this generation diverged."""
        failure = self.poisoned_failure
        if failure is not None:
            raise CfgGenerationPoisoned(failure)

    @classmethod
    def from_bindings(
        cls,
        *,
        generation: int,
        native_key: NativePreanalysisKey,
        evidence_generation: int | None = None,
        maturity: int | None = None,
        snapshot_id: str | None = None,
        bindings: Iterable[tuple[StableBlockIdentity, int]],
        session_id: str = "identity-index",
        decision_observer: Callable[[IdentityRebindObservation], None] | None = None,
    ) -> MbaBlockIdentityIndex:
        index = cls(
            session_id=session_id,
            decision_observer=decision_observer,
            native_key=native_key,
            generation=generation,
            evidence_generation=evidence_generation,
            maturity=maturity,
            snapshot_id=snapshot_id,
        )
        for identity, serial in bindings:
            index._bind_new_native(identity, int(serial))
        return index

    @classmethod
    def from_mba(
        cls,
        mba: object,
        *,
        generation: int,
        native_key: NativePreanalysisKey,
        evidence_generation: int | None = None,
        maturity: int | None = None,
        snapshot_id: str | None = None,
        session_id: str = "live-mba",
        imported_instruction_origins: Mapping[int, int] | None = None,
        current_mba_identity_binding: CurrentMbaIdentityBindingSnapshot | None = None,
        decision_observer: Callable[[IdentityRebindObservation], None] | None = None,
    ) -> MbaBlockIdentityIndex:
        """Build current bindings directly from a callback-local live MBA.

        Only integer coordinates and serial-free identities are retained.  A
        cloned native block produces a second binding for the same identity,
        so later rebinding reports ``AMBIGUOUS`` instead of selecting the first
        matching serial.  Imported instructions are rebound through their
        native origins without lifting or cloning live operands; identity
        indexing must remain observationally read-only at Hex-Rays callbacks.
        """
        index = cls(
            session_id=session_id,
            decision_observer=decision_observer,
            native_key=native_key,
            generation=generation,
            evidence_generation=evidence_generation,
            maturity=maturity,
            snapshot_id=snapshot_id,
        )
        if current_mba_identity_binding is not None and not isinstance(
            current_mba_identity_binding,
            CurrentMbaIdentityBindingSnapshot,
        ):
            raise TypeError(
                "current-MBA identity binding must be a portable binding snapshot"
            )
        normalized_imported_origins = {
            int(live_ea): int(native_ea)
            for live_ea, native_ea in (imported_instruction_origins or {}).items()
        }
        current_block_bindings = ()
        if current_mba_identity_binding is not None:
            snapshot_origins = dict(current_mba_identity_binding.instruction_origins)
            if (
                imported_instruction_origins is not None
                and normalized_imported_origins != snapshot_origins
            ):
                raise ValueError(
                    "current-MBA identity binding conflicts with imported origins"
                )
            normalized_imported_origins = snapshot_origins
            current_block_bindings = current_mba_identity_binding.block_bindings
            if any(
                binding.stable_identity.native_key != native_key
                for binding in current_block_bindings
            ):
                raise ValueError(
                    "current-MBA identity binding uses a different native key"
                )
        quantity = int(getattr(mba, "qty", 0) or 0)
        for serial in range(quantity):
            block = mba.get_mblock(serial)
            if block is None:
                continue
            live_anchors: set[int] = set()
            native_anchors: set[int] = set()
            imported_anchors: set[int] = set()
            instruction = getattr(block, "head", None)
            while instruction is not None:
                instruction_ea = int(getattr(instruction, "ea", -1) or -1)
                live_anchors.add(instruction_ea)
                if instruction_ea in normalized_imported_origins:
                    native_ea = normalized_imported_origins[instruction_ea]
                    imported_anchors.add(native_ea)
                else:
                    native_ea = int(mba.map_fict_ea(instruction_ea))
                if 0 <= native_ea < 0xFFFFFFFFFFFFFFFF:
                    native_anchors.add(native_ea)
                instruction = getattr(instruction, "next", None)
            current_bindings = tuple(
                binding
                for binding in current_block_bindings
                if live_anchors.intersection(binding.live_instruction_eas)
            )
            if current_bindings:
                stable_identities = {
                    binding.stable_identity for binding in current_bindings
                }
                imported_identity = StableBlockIdentity.from_intervals(
                    (
                        interval
                        for identity in stable_identities
                        for interval in identity.native_ranges.intervals
                    ),
                    native_key=native_key,
                    exact_instruction_eas=imported_anchors,
                )
                index._bind_new_native(
                    imported_identity,
                    serial,
                    provenance=BlockHandleProvenance.IMPORTED_NATIVE,
                )
                continue
            imported_eas = tuple(
                ea for ea in sorted(imported_anchors) if 0 <= ea < 0xFFFFFFFFFFFFFFFF
            )
            if imported_eas:
                index._bind_new_native(
                    StableBlockIdentity.from_instruction_eas(
                        imported_eas,
                        native_key=native_key,
                    ),
                    serial,
                    provenance=BlockHandleProvenance.IMPORTED_NATIVE,
                )
                continue
            instruction_eas = tuple(sorted(native_anchors))
            start_ea = int(getattr(block, "start", -1))
            if 0 <= start_ea < 0xFFFFFFFFFFFFFFFF:
                mapped_start_ea = int(mba.map_fict_ea(start_ea))
                if 0 <= mapped_start_ea < 0xFFFFFFFFFFFFFFFF:
                    native_anchors.add(mapped_start_ea)
            if native_anchors:
                index._bind_new_native(
                    StableBlockIdentity.from_intervals(
                        (NativeEaInterval(ea, ea + 1) for ea in sorted(native_anchors)),
                        native_key=native_key,
                        exact_instruction_eas=instruction_eas,
                    ),
                    serial,
                )
            else:
                index._bind_new_synthetic(serial)
        return index

    @classmethod
    def from_flow_graph(
        cls,
        *,
        generation: int,
        native_key: NativePreanalysisKey,
        evidence_generation: int | None = None,
        maturity: int | None = None,
        snapshot_id: str | None = None,
        flow_graph: FlowGraph,
        session_id: str | None = None,
        imported_native_eas_by_serial: Mapping[int, Iterable[int]] | None = None,
    ) -> MbaBlockIdentityIndex:
        """Build callback-local bindings without retaining the MBA lift.

        Imported instructions often carry synthetic current-MBA EAs after a
        maturity transition.  Their importer-published native origins are the
        portable identity authority and deliberately replace, rather than
        merge with, the synthetic snapshot coordinates.
        """
        index = cls(
            session_id=session_id or f"flowgraph:{int(flow_graph.func_ea):X}",
            native_key=native_key,
            generation=generation,
            evidence_generation=evidence_generation,
            maturity=maturity,
            snapshot_id=snapshot_id,
        )
        imported_native_eas_by_serial = imported_native_eas_by_serial or {}
        for serial, block in flow_graph.blocks.items():
            imported_anchors = tuple(
                sorted(
                    {
                        int(ea)
                        for ea in imported_native_eas_by_serial.get(int(serial), ())
                        if 0 <= int(ea) < 0xFFFFFFFFFFFFFFFF
                    }
                )
            )
            if imported_anchors:
                identity = StableBlockIdentity.from_instruction_eas(
                    imported_anchors,
                    native_key=native_key,
                )
                index._bind_new_native(
                    identity,
                    int(serial),
                    provenance=BlockHandleProvenance.IMPORTED_NATIVE,
                )
                continue
            identity = stable_block_identity_from_snapshot(
                block,
                native_key=native_key,
            )
            if identity is None:
                index._bind_new_synthetic(int(serial))
            else:
                index._bind_new_native(identity, int(serial))
        return index

    @property
    def serials_by_identity(self):
        """Read-only current bindings, for diagnostics and invariant tests."""
        self.require_generation_usable()
        current: dict[StableBlockIdentity, set[int]] = defaultdict(set)
        for identity, tokens in self._tokens_by_identity.items():
            for token in tokens:
                bound = self.resolve(self._handles_by_token[token])
                if bound is not None:
                    current[identity].add(int(bound.serial))
        return MappingProxyType(
            {
                identity: tuple(sorted(serials))
                for identity, serials in current.items()
                if serials
            }
        )

    @property
    def logical_proxy_count(self) -> int:
        self.require_generation_usable()
        return len(self._proxies_by_token)

    def logical_proxy_for_handle(
        self,
        handle: MbaBlockHandle | None,
    ) -> LogicalBlockProxy | None:
        self.require_generation_usable()
        if handle is None:
            return None
        proxy_token = self._proxy_token_by_handle_token.get(handle.token)
        return None if proxy_token is None else self._proxies_by_token[proxy_token]

    def owns_logical_proxy(self, proxy: LogicalBlockProxy) -> bool:
        """Return whether *proxy* is this index's exact logical authority."""
        self.require_generation_usable()
        return self._proxies_by_token.get(proxy.proxy_token) is proxy

    def resolve_logical_proxy(
        self,
        proxy: LogicalBlockProxy,
        *,
        transaction_id: str | None = None,
    ):
        """Resolve one owned logical proxy to its current physical binding.

        The proxy selects the published or transaction-local version first;
        only then does the index bind that physical handle to a live serial.
        This keeps the serial lookup at the live backend boundary.
        """
        self.require_generation_usable()
        if not self.owns_logical_proxy(proxy):
            raise ValueError("logical proxy is not owned by this identity index")
        version = proxy.resolve(transaction_id=transaction_id)
        if version is None:
            return None
        return self.resolve(
            version.handle,
            transaction_id=transaction_id,
        )

    def resolve_logical_version(
        self,
        version: LogicalBlockVersion,
        *,
        transaction_id: str | None = None,
    ) -> BoundBlock | None:
        """Resolve one exact physical version without changing proxy authority."""
        self.require_generation_usable()
        if not isinstance(version, LogicalBlockVersion):
            raise TypeError("logical version resolution requires a version")
        proxy = self._proxies_by_token.get(version.version_id.proxy_token)
        if proxy is None or version.handle.session_id != self.session_id:
            return None
        serials = (
            self._serial_by_token
            if transaction_id is None
            else self._serials_by_transaction.get(str(transaction_id), {})
        )
        serial = serials.get(version.handle.token)
        if serial is None:
            return None
        identity = version.handle.stable_identity
        anchor_ea = None
        if identity is not None and identity.native_ranges.intervals:
            anchor_ea = identity.native_ranges.intervals[0].start_ea
        return BoundBlock(
            handle=version.handle,
            serial=int(serial),
            generation=self.generation,
            anchor_ea=anchor_ea,
        )

    def resolve_logical_ref(
        self,
        ref: LogicalBlockRef,
        *,
        transaction_id: str,
    ) -> BoundBlock | None:
        """Resolve an exact portable logical version in one active attempt."""
        self.require_generation_usable()
        if not isinstance(ref, LogicalBlockRef):
            raise TypeError("logical resolution requires a LogicalBlockRef")
        if ref.session_id != self.session_id:
            return None
        proxy = self._proxies_by_token.get(ref.proxy_token)
        if proxy is None:
            return None
        version = proxy.resolve(transaction_id=str(transaction_id))
        if version is None or version.version_id.version != ref.version:
            return None
        return self.resolve_logical_version(
            version,
            transaction_id=str(transaction_id),
        )

    def _new_token(self, prefix: str) -> str:
        token = f"{prefix}:{self._next_token}"
        self._next_token += 1
        return token

    def _new_handle(
        self,
        identity: StableBlockIdentity | None,
        *,
        token: str | None = None,
        provenance: BlockHandleProvenance | None = None,
    ) -> MbaBlockHandle:
        if provenance is None:
            provenance = (
                BlockHandleProvenance.NATIVE
                if identity is not None
                else BlockHandleProvenance.OBSERVED_EPHEMERAL
            )
        token = token or self._new_token(
            "native" if identity is not None else provenance.value
        )
        if token in self._handles_by_token:
            raise ValueError(f"duplicate MBA block-handle token: {token}")
        if identity is None:
            if provenance is BlockHandleProvenance.CREATED_SYNTHETIC:
                handle = MbaBlockHandle.created_synthetic(
                    session_id=self.session_id,
                    token=token,
                )
            elif provenance is BlockHandleProvenance.OBSERVED_EPHEMERAL:
                handle = MbaBlockHandle.observed_ephemeral(
                    session_id=self.session_id,
                    token=token,
                )
            else:
                raise ValueError("identity-free handle requires synthetic provenance")
        elif provenance is BlockHandleProvenance.IMPORTED_NATIVE:
            handle = MbaBlockHandle.imported_native(
                identity,
                session_id=self.session_id,
                token=token,
            )
        else:
            if provenance is not BlockHandleProvenance.NATIVE:
                raise ValueError("native identity requires native provenance")
            handle = MbaBlockHandle.native(
                identity,
                session_id=self.session_id,
                token=token,
            )
        if identity is not None:
            self._tokens_by_identity[identity].add(token)
        self._handles_by_token[token] = handle
        return handle

    def _bind(self, handle: MbaBlockHandle, serial: int) -> None:
        serial = int(serial)
        if serial < 0:
            raise ValueError("MBA serial bindings must be non-negative")
        if handle.session_id != self.session_id:
            raise ValueError("cannot bind a handle from another session")
        previous_serial = self._serial_by_token.pop(handle.token, None)
        if previous_serial is not None:
            self._refresh_primary_serial(previous_serial)
        self._serial_by_token[handle.token] = serial
        self._token_by_serial.setdefault(serial, handle.token)

    def _refresh_primary_serial(self, serial: int) -> None:
        """Select a physical binding for ``handle_for_serial`` after a move.

        Planned coordinates may intentionally alias a live serial while a
        transaction is being realized.  They remain resolvable by their own
        handles; this method only selects the representative returned by a
        current-serial lookup.
        """
        candidates = sorted(
            token
            for token, bound_serial in self._serial_by_token.items()
            if bound_serial == int(serial)
        )
        if candidates:
            self._token_by_serial[int(serial)] = candidates[0]
        else:
            self._token_by_serial.pop(int(serial), None)

    def _bind_new_native(
        self,
        identity: StableBlockIdentity,
        serial: int,
        *,
        provenance: BlockHandleProvenance = BlockHandleProvenance.NATIVE,
    ) -> MbaBlockHandle:
        if identity.native_key != self.native_key:
            raise ValueError("cannot bind identity from another native key")
        handle = self._new_handle(identity, provenance=provenance)
        self._bind(handle, serial)
        self._register_published_proxy(handle)
        return handle

    def _bind_new_synthetic(self, serial: int) -> MbaBlockHandle:
        handle = self._new_handle(
            None,
            provenance=BlockHandleProvenance.OBSERVED_EPHEMERAL,
        )
        self._bind(handle, serial)
        self._register_published_proxy(handle)
        return handle

    def _register_published_proxy(
        self,
        handle: MbaBlockHandle,
    ) -> LogicalBlockProxy:
        existing = self.logical_proxy_for_handle(handle)
        if existing is not None:
            return existing
        proxy_token = f"logical:{self._next_proxy_token}"
        self._next_proxy_token += 1
        proxy = LogicalBlockProxy.with_published(
            proxy_token=proxy_token,
            handle=handle,
            generation=self.generation,
        )
        self._proxies_by_token[proxy_token] = proxy
        self._proxy_token_by_handle_token[handle.token] = proxy_token
        return proxy

    def create_native_handle(
        self,
        identity: StableBlockIdentity,
        *,
        provenance: BlockHandleProvenance = BlockHandleProvenance.NATIVE,
    ) -> MbaBlockHandle:
        """Allocate an unbound native handle for a proved structural mutation."""
        self.require_generation_usable()
        return self._new_handle(identity, provenance=provenance)

    def create_imported_native_handle(
        self,
        identity: StableBlockIdentity,
    ) -> MbaBlockHandle:
        """Allocate an exact live handle for an imported native translation."""
        self.require_generation_usable()
        return self.create_native_handle(
            identity,
            provenance=BlockHandleProvenance.IMPORTED_NATIVE,
        )

    def _create_plan_handle(self) -> MbaBlockHandle:
        return self._new_handle(
            None,
            provenance=BlockHandleProvenance.CREATED_SYNTHETIC,
        )

    def create_observed_ephemeral_handle(self) -> MbaBlockHandle:
        """Allocate an unowned handle for a block discovered around SDK work."""
        self.require_generation_usable()
        return self._new_handle(
            None,
            provenance=BlockHandleProvenance.OBSERVED_EPHEMERAL,
        )

    def ensure_serial_space(self, quantity: int) -> None:
        """Give every current serial a published logical proxy exactly once."""
        self.require_generation_usable()
        for serial in range(int(quantity)):
            token = self._token_by_serial.get(serial)
            if token is None:
                self._bind_new_synthetic(serial)

    def begin_transaction(
        self,
        transaction_id: str | TransactionAttemptId,
        quantity: int | None = None,
    ) -> None:
        """Rebase planned coordinates onto the current live MBA serials.

        Baseline tokens are meaningful only inside one mutation transaction.
        After a committed insertion, the same integer denotes a current live
        block in the next transaction, not the prior transaction's planned
        coordinate.  Rebuild the map at every batch boundary so serial
        resolution cannot replay an obsolete shift.
        """
        self.require_generation_usable()
        attempt = (
            transaction_id if isinstance(transaction_id, TransactionAttemptId) else None
        )
        transaction_id = (
            attempt.attempt_id if attempt is not None else str(transaction_id)
        )
        if not transaction_id:
            raise ValueError("identity transaction requires a non-empty id")
        if transaction_id in self._serials_by_transaction:
            raise ValueError(f"identity transaction already active: {transaction_id}")
        if attempt is not None:
            if attempt.session_id != self.session_id:
                raise ValueError("transaction attempt belongs to another session")
            if attempt.generation != self.generation:
                raise ValueError("transaction attempt belongs to another generation")
        if quantity is None:
            quantity = max(self._token_by_serial, default=-1) + 1
        self.ensure_serial_space(int(quantity))
        self._serials_by_transaction[transaction_id] = dict(self._serial_by_token)
        self._generation_by_transaction[transaction_id] = self.generation
        if attempt is not None:
            self._attempt_by_transaction[transaction_id] = attempt
        self._insertion_serials_by_transaction[transaction_id] = {}
        self._baseline_tokens_by_transaction[transaction_id] = {
            int(serial): token for serial, token in self._token_by_serial.items()
        }

    def _validate_plan_attempt(
        self,
        attempt: TransactionAttemptId,
        plan_ref: PlanBlockRef,
    ) -> str:
        if not isinstance(attempt, TransactionAttemptId):
            raise TypeError("plan reservation requires a TransactionAttemptId")
        if not isinstance(plan_ref, PlanBlockRef):
            raise TypeError("plan reservation requires a PlanBlockRef")
        if attempt.plan_id != plan_ref.plan_id:
            raise ValueError("plan reservation plan authority differs")
        if attempt.session_id != self.session_id:
            raise ValueError("plan reservation session authority differs")
        if attempt.generation != self.generation:
            raise ValueError("plan reservation generation authority differs")
        transaction_id = attempt.attempt_id
        if transaction_id not in self._serials_by_transaction:
            raise ValueError("plan reservation requires an active identity transaction")
        if self._generation_by_transaction.get(transaction_id) != self.generation:
            raise ValueError("plan reservation belongs to a stale MBA generation")
        if self._attempt_by_transaction.get(transaction_id) != attempt:
            raise ValueError("transaction attempt authority differs")
        return transaction_id

    def reserve_plan_block(
        self,
        attempt: TransactionAttemptId,
        plan_ref: PlanBlockRef,
        *,
        handle: MbaBlockHandle | None = None,
        replaces: MbaBlockHandle | None = None,
    ) -> PlanBlockReservation:
        """Allocate plan ownership before the corresponding SDK insertion."""
        self.require_generation_usable()
        transaction_id = self._validate_plan_attempt(attempt, plan_ref)
        key = (attempt, plan_ref)
        if key in self._plan_reservations:
            raise ValueError("plan block is already reserved in this attempt")
        if handle is None and replaces is not None:
            raise ValueError(
                "plan replacement reservation requires a replacement handle"
            )
        if handle is None:
            handle = self._create_plan_handle()
        elif (
            not isinstance(handle, MbaBlockHandle)
            or handle.session_id != self.session_id
            or self._handles_by_token.get(handle.token) is not handle
            or self.resolve(handle) is not None
        ):
            raise ValueError("plan reservation requires an owned unbound handle")
        if replaces is None:
            logical_version = self._reserve_new_proxy(
                transaction_id=transaction_id,
                handle=handle,
                allow_created_synthetic=True,
            )
        else:
            if self.resolve(replaces, transaction_id=transaction_id) is None:
                raise ValueError("plan replacement source is stale or foreign")
            proxy = self._ensure_logical_proxy(replaces)
            logical_version = proxy.stage(
                transaction_id=transaction_id,
                handle=handle,
                generation=self.generation + 1,
            )
            self._proxy_token_by_handle_token[handle.token] = proxy.proxy_token
            self._proxy_tokens_by_transaction[transaction_id].add(proxy.proxy_token)
            self._proxy_actions_by_transaction[transaction_id][proxy.proxy_token] = (
                "replacement"
            )
        reservation = PlanBlockReservation(
            attempt_id=attempt,
            plan_ref=plan_ref,
            session_id=self.session_id,
            generation=self.generation,
            logical_version=logical_version,
        )
        self._plan_reservations[key] = reservation
        return reservation

    def bind_reserved_plan_block(
        self,
        attempt: TransactionAttemptId,
        plan_ref: PlanBlockRef,
        *,
        insertion_serial: int,
        returned_serial: int,
    ) -> PlanBlockCreationReceipt:
        """Bind the SDK result to its exact preallocated plan owner."""
        self.require_generation_usable()
        transaction_id = self._validate_plan_attempt(attempt, plan_ref)
        key = (attempt, plan_ref)
        if key in self._plan_creation_receipts:
            raise ValueError("plan block reservation is already bound")
        reservation = self._plan_reservations.get(key)
        if reservation is None:
            raise ValueError("planned insertion has no reserved plan owner")
        handle = reservation.logical_version.handle
        self._record_insert(
            transaction_id=transaction_id,
            insertion_serial=int(insertion_serial),
            created=handle,
            returned_serial=int(returned_serial),
            allow_created_synthetic=True,
        )
        block = self.resolve(handle, transaction_id=transaction_id)
        if block is None:
            raise RuntimeError("bound plan reservation did not resolve synchronously")
        receipt = PlanBlockCreationReceipt(
            attempt_id=attempt,
            plan_ref=plan_ref,
            logical_version=reservation.logical_version,
            insertion_serial=int(insertion_serial),
            returned_serial=int(returned_serial),
            block=block,
        )
        self._plan_creation_receipts[key] = receipt
        return receipt

    @property
    def plan_creation_receipts(self) -> tuple[PlanBlockCreationReceipt, ...]:
        self.require_generation_usable()
        return tuple(self._plan_creation_receipts.values())

    def transaction_quantity(self, transaction_id: str) -> int:
        """Return the exact staged block quantity for an active transaction."""
        self.require_generation_usable()
        serials = self._serials_by_transaction.get(str(transaction_id))
        if serials is None:
            raise ValueError("identity transaction is not active")
        return len(serials)

    def require_active_attempt(self, attempt_id: TransactionAttemptId) -> None:
        """Verify exact typed authority for an already-open transaction."""
        self.require_generation_usable()
        if not isinstance(attempt_id, TransactionAttemptId):
            raise TypeError("active attempt check requires TransactionAttemptId")
        active = self._attempt_by_transaction.get(attempt_id.attempt_id)
        if active != attempt_id:
            raise ValueError("transaction attempt is not active in this identity index")
        if (
            self._generation_by_transaction.get(attempt_id.attempt_id)
            != self.generation
        ):
            raise ValueError("transaction attempt belongs to a stale MBA generation")

    def resolve_planned_serial(
        self,
        transaction_id: str,
        planned_serial: int,
    ) -> int | None:
        self.require_generation_usable()
        transaction_id = str(transaction_id)
        planned_serial = int(planned_serial)
        baseline = self._baseline_tokens_by_transaction.get(transaction_id)
        if baseline is None:
            raise ValueError("identity transaction is not active")
        token = baseline.get(planned_serial)
        if token is None:
            return None
        bound = self.resolve(
            self._handles_by_token[token],
            transaction_id=transaction_id,
        )
        return None if bound is None else int(bound.serial)

    def identity_for_serial(self, serial: int) -> StableBlockIdentity | None:
        self.require_generation_usable()
        handle = self.handle_for_serial(serial)
        return None if handle is None else handle.stable_identity

    def plan_ref_for_serial(self, serial: int) -> NativeBlockRef | LogicalBlockRef:
        """Export current identity authority without leaking a live serial."""
        self.require_generation_usable()
        handle = self.handle_for_serial(serial)
        if handle is None:
            raise ValueError("current serial has no identity binding")
        if handle.stable_identity is not None:
            return NativeBlockRef(handle.stable_identity)
        proxy = self.logical_proxy_for_handle(handle)
        if proxy is None:
            raise ValueError("observed block has no published logical proxy")
        version = proxy.resolve()
        if version is None:
            raise ValueError("observed block has no published logical version")
        return LogicalBlockRef(
            session_id=self.session_id,
            proxy_token=version.version_id.proxy_token,
            version=version.version_id.version,
        )

    def plan_refs_by_serial(self) -> Mapping[int, NativeBlockRef | LogicalBlockRef]:
        """Return the current snapshot's complete typed compiler authority."""
        self.require_generation_usable()
        return MappingProxyType(
            {
                int(serial): self.plan_ref_for_serial(int(serial))
                for serial in sorted(self._token_by_serial)
            }
        )

    def handle_for_serial(self, serial: int) -> MbaBlockHandle | None:
        self.require_generation_usable()
        token = self._token_by_serial.get(int(serial))
        if token is None:
            return None
        return self._handles_by_token[token]

    def resolve(
        self,
        handle: MbaBlockHandle,
        *,
        transaction_id: str | None = None,
    ) -> BoundBlock | None:
        """Resolve one unbroken current-generation handle, never by guessing."""
        self.require_generation_usable()
        if handle.session_id != self.session_id:
            return None
        resolved_handle = handle
        proxy_token = self._proxy_token_by_handle_token.get(handle.token)
        if proxy_token is not None:
            version = self._proxies_by_token[proxy_token].resolve(
                transaction_id=transaction_id
            )
            if version is None:
                return None
            resolved_handle = version.handle
        serials = (
            self._serial_by_token
            if transaction_id is None
            else self._serials_by_transaction.get(str(transaction_id), {})
        )
        serial = serials.get(resolved_handle.token)
        if serial is None:
            return None
        identity = resolved_handle.stable_identity
        anchor_ea = None
        if identity is not None and identity.native_ranges.intervals:
            anchor_ea = identity.native_ranges.intervals[0].start_ea
        return BoundBlock(
            handle=resolved_handle,
            serial=serial,
            generation=self.generation,
            anchor_ea=anchor_ea,
        )

    def _ensure_logical_proxy(self, handle: MbaBlockHandle) -> LogicalBlockProxy:
        proxy_token = self._proxy_token_by_handle_token.get(handle.token)
        if proxy_token is not None:
            return self._proxies_by_token[proxy_token]
        if self.resolve(handle) is None:
            raise ValueError("cannot proxy an unbound or stale block handle")
        return self._register_published_proxy(handle)

    def stage_replacement(
        self,
        *,
        transaction_id: str,
        original: MbaBlockHandle,
        replacement: MbaBlockHandle,
        returned_serial: int,
    ) -> LogicalBlockVersion:
        """Stage one physical replacement behind its logical proxy."""
        self.require_generation_usable()
        transaction_id = str(transaction_id)
        serials = self._serials_by_transaction.get(transaction_id)
        if serials is None:
            raise ValueError("replacement requires an active identity transaction")
        proxy = self._ensure_logical_proxy(original)
        staged = proxy.stage(
            transaction_id=transaction_id,
            handle=replacement,
            generation=self.generation + 1,
        )
        self._proxy_token_by_handle_token[replacement.token] = proxy.proxy_token
        serials[replacement.token] = int(returned_serial)
        self._proxy_tokens_by_transaction[transaction_id].add(proxy.proxy_token)
        self._proxy_actions_by_transaction[transaction_id][proxy.proxy_token] = (
            "replacement"
        )
        return staged

    def stage_inserted_replacement(
        self,
        *,
        transaction_id: str,
        original: MbaBlockHandle,
        replacement: MbaBlockHandle,
        insertion_serial: int,
        returned_serial: int,
    ) -> LogicalBlockVersion:
        """Record one SDK insertion as the next version of an existing proxy."""
        self.require_generation_usable()
        transaction_id = str(transaction_id)
        serials = self._serials_by_transaction.get(transaction_id)
        if serials is None:
            raise ValueError(
                "inserted replacement requires an active identity transaction"
            )
        insertion_serial = int(insertion_serial)
        returned_serial = int(returned_serial)
        quantity = max(serials.values(), default=-1) + 1
        if not 0 <= insertion_serial <= quantity:
            raise ValueError("inserted replacement coordinate is outside the MBA")
        if returned_serial != insertion_serial:
            raise ValueError(
                "inserted replacement must bind at its actual insertion coordinate"
            )
        if self.resolve(original, transaction_id=transaction_id) is None:
            raise ValueError("inserted replacement original is stale or foreign")
        if (
            self.resolve(replacement) is not None
            or self.logical_proxy_for_handle(replacement) is not None
        ):
            raise ValueError("inserted replacement physical handle is already owned")

        staged = self.stage_replacement(
            transaction_id=transaction_id,
            original=original,
            replacement=replacement,
            returned_serial=returned_serial,
        )
        for token, serial in tuple(serials.items()):
            if token != replacement.token and serial >= insertion_serial:
                serials[token] = serial + 1
        return staged

    def reserve_new_proxy(
        self,
        *,
        transaction_id: str,
        handle: MbaBlockHandle,
    ) -> LogicalBlockVersion:
        """Reserve a new logical owner without claiming a physical coordinate."""
        self.require_generation_usable()
        return self._reserve_new_proxy(
            transaction_id=transaction_id,
            handle=handle,
            allow_created_synthetic=False,
        )

    def _reserve_new_proxy(
        self,
        *,
        transaction_id: str,
        handle: MbaBlockHandle,
        allow_created_synthetic: bool,
    ) -> LogicalBlockVersion:
        self.require_generation_usable()
        transaction_id = str(transaction_id)
        serials = self._serials_by_transaction.get(transaction_id)
        if serials is None:
            raise ValueError("block creation requires an active identity transaction")
        if (
            handle.provenance is BlockHandleProvenance.CREATED_SYNTHETIC
            and not allow_created_synthetic
        ):
            raise ValueError(
                "CREATED_SYNTHETIC reservation requires PlanBlockRef authority"
            )
        if self.logical_proxy_for_handle(handle) is not None:
            raise ValueError("new physical block already belongs to a logical proxy")
        proxy_token = f"logical:{self._next_proxy_token}"
        self._next_proxy_token += 1
        proxy = LogicalBlockProxy.without_published(
            proxy_token=proxy_token,
            session_id=self.session_id,
            stable_identity=handle.stable_identity,
            provenance=handle.provenance,
            generation=self.generation,
        )
        self._proxies_by_token[proxy_token] = proxy
        self._proxy_token_by_handle_token[handle.token] = proxy_token
        staged = proxy.stage(
            transaction_id=transaction_id,
            handle=handle,
            generation=self.generation + 1,
        )
        self._proxy_tokens_by_transaction[transaction_id].add(proxy_token)
        self._proxy_actions_by_transaction[transaction_id][proxy_token] = "new"
        return staged

    def stage_new_proxy(
        self,
        *,
        transaction_id: str,
        handle: MbaBlockHandle,
        returned_serial: int,
    ) -> LogicalBlockVersion:
        self.require_generation_usable()
        transaction_id = str(transaction_id)
        staged = self.reserve_new_proxy(
            transaction_id=transaction_id,
            handle=handle,
        )
        serials = self._serials_by_transaction[transaction_id]
        serials[handle.token] = int(returned_serial)
        return staged

    def stage_retirement(
        self,
        *,
        transaction_id: str,
        handle: MbaBlockHandle,
    ) -> None:
        self.require_generation_usable()
        transaction_id = str(transaction_id)
        if transaction_id not in self._serials_by_transaction:
            raise ValueError("block retirement requires an active identity transaction")
        proxy = self._ensure_logical_proxy(handle)
        proxy.stage_retirement(
            transaction_id=transaction_id,
            generation=self.generation + 1,
        )
        self._proxy_tokens_by_transaction[transaction_id].add(proxy.proxy_token)
        self._proxy_actions_by_transaction[transaction_id][proxy.proxy_token] = (
            "retirement"
        )

    def commit_proxy_transaction(
        self,
        transaction_id: str,
    ) -> tuple[LogicalBlockVersionTransition, ...]:
        """Promote every replacement staged by one gateway transaction."""
        self.require_generation_usable()
        transaction_id = str(transaction_id)
        serials = self._serials_by_transaction.get(transaction_id)
        if serials is None:
            raise ValueError("identity transaction is not active")
        proxy_tokens = tuple(
            sorted(self._proxy_tokens_by_transaction.get(transaction_id, ()))
        )
        actions = self._proxy_actions_by_transaction.get(transaction_id, {})
        future_versions: dict[str, LogicalBlockVersion | None] = {}
        for proxy_token in proxy_tokens:
            proxy = self._proxies_by_token[proxy_token]
            action = actions.get(proxy_token)
            published = proxy.resolve()
            transaction_version = proxy.resolve(transaction_id=transaction_id)
            if action == "retirement":
                if published is None or transaction_version is not None:
                    raise ValueError(
                        "future retired logical block has inconsistent authority"
                    )
                future_versions[proxy_token] = None
                continue
            if action not in {"replacement", "new"} or transaction_version is None:
                raise ValueError("future published logical block has no staged version")
            expected_predecessor = None if published is None else published.version_id
            if transaction_version.predecessor_version_id != expected_predecessor:
                raise ValueError(
                    "future published logical block has stale replacement lineage"
                )
            future_versions[proxy_token] = transaction_version

        future_published_serials: dict[str, int] = {}
        for proxy_token, proxy in self._proxies_by_token.items():
            future = future_versions.get(proxy_token, proxy.resolve())
            if future is None:
                continue
            serial = serials.get(future.handle.token)
            if serial is None:
                raise ValueError("future published logical block has no live serial")
            future_published_serials[future.handle.token] = int(serial)

        # All fallible consistency checks above run before the first proxy is
        # promoted.  LogicalBlockProxy.commit only applies the already-proved
        # staged transition, so this single-threaded section cannot discover a
        # late missing binding after changing publication authority.
        transitions: list[LogicalBlockVersionTransition] = []
        for proxy_token in proxy_tokens:
            proxy = self._proxies_by_token[proxy_token]
            transition = proxy.commit(transaction_id)
            transitions.append(transition)
        self._serials_by_transaction.pop(transaction_id)
        self._proxy_tokens_by_transaction.pop(transaction_id, None)
        self._serial_by_token = future_published_serials
        self._token_by_serial.clear()
        for token, serial in sorted(
            self._serial_by_token.items(),
            key=lambda item: (item[1], item[0]),
        ):
            self._token_by_serial.setdefault(serial, token)
        self._baseline_tokens_by_transaction.pop(transaction_id, None)
        self._generation_by_transaction.pop(transaction_id, None)
        self._attempt_by_transaction.pop(transaction_id, None)
        self._insertion_serials_by_transaction.pop(transaction_id, None)
        self._proxy_actions_by_transaction.pop(transaction_id, None)
        return tuple(transitions)

    def abort_proxy_transaction(
        self,
        transaction_id: str,
    ) -> tuple[LogicalBlockVersion, ...]:
        """Discard staged physical versions without changing publication."""
        transaction_id = str(transaction_id)
        discarded: list[LogicalBlockVersion] = []
        actions = self._proxy_actions_by_transaction.pop(transaction_id, {})
        for proxy_token in sorted(
            self._proxy_tokens_by_transaction.pop(transaction_id, ())
        ):
            proxy = self._proxies_by_token[proxy_token]
            if actions.get(proxy_token) == "retirement":
                proxy.abort_retirement(transaction_id)
                continue
            staged = proxy.abort(transaction_id)
            action = actions.get(proxy_token)
            if action in {"replacement", "new"}:
                self._proxy_token_by_handle_token.pop(staged.handle.token, None)
            if action == "new":
                self._proxies_by_token.pop(proxy_token, None)
                self._handles_by_token.pop(staged.handle.token, None)
                identity = staged.handle.stable_identity
                if identity is not None:
                    tokens = self._tokens_by_identity.get(identity)
                    if tokens is not None:
                        tokens.discard(staged.handle.token)
                        if not tokens:
                            self._tokens_by_identity.pop(identity, None)
            discarded.append(staged)
        self._serials_by_transaction.pop(transaction_id, None)
        self._baseline_tokens_by_transaction.pop(transaction_id, None)
        self._generation_by_transaction.pop(transaction_id, None)
        active_attempt = self._attempt_by_transaction.pop(transaction_id, None)
        self._insertion_serials_by_transaction.pop(transaction_id, None)
        for key in tuple(self._plan_reservations):
            if key[0] == active_attempt:
                self._plan_reservations.pop(key, None)
                self._plan_creation_receipts.pop(key, None)
        return tuple(discarded)

    def _current_for_tokens(
        self,
        tokens: Iterable[str],
    ) -> tuple[BoundBlock, ...]:
        current_by_handle = {
            bound.handle.token: bound
            for token in tokens
            if (bound := self.resolve(self._handles_by_token[token])) is not None
        }
        return tuple(
            sorted(
                current_by_handle.values(),
                key=lambda bound: (
                    int(bound.serial),
                    -1 if bound.anchor_ea is None else int(bound.anchor_ea),
                    bound.handle.token,
                ),
            )
        )

    @staticmethod
    def _result_for_candidates(
        current: tuple[BoundBlock, ...],
    ) -> RebindResult:
        if not current:
            return RebindResult.missing()
        if len(current) != 1:
            return RebindResult.ambiguous()
        return RebindResult.bound(current[0])

    def _bound_for_tokens(self, tokens: Iterable[str]) -> RebindResult:
        return self._result_for_candidates(self._current_for_tokens(tokens))

    def _tokens_for_identity(
        self,
        identity: StableBlockIdentity,
        provenance: BlockHandleProvenance | None,
    ) -> tuple[str, ...]:
        return tuple(
            token
            for token in self._tokens_by_identity.get(identity, ())
            if provenance is None
            or self._handles_by_token[token].provenance is provenance
        )

    def _rebind_identity(
        self,
        identity: StableBlockIdentity,
        *,
        provenance: BlockHandleProvenance | None,
    ) -> tuple[RebindResult, tuple[BoundBlock, ...]]:
        """Rebind via exact identity, containment, then unique overlap."""
        if identity.native_key != self.native_key:
            return RebindResult.missing(), ()
        exact_candidates = self._current_for_tokens(
            self._tokens_for_identity(identity, provenance)
        )
        exact = self._result_for_candidates(exact_candidates)
        if exact.block is not None or exact.status.name == "AMBIGUOUS":
            return exact, exact_candidates

        current = tuple(
            candidate
            for candidate in self.serials_by_identity
            if self._tokens_for_identity(candidate, provenance)
        )
        contained = tuple(
            candidate
            for candidate in current
            if all(
                candidate.native_ranges.contains(interval.start_ea)
                for interval in identity.native_ranges.intervals
            )
        )
        if len(contained) == 1:
            candidates = self._current_for_tokens(
                self._tokens_for_identity(contained[0], provenance)
            )
            return self._result_for_candidates(candidates), candidates
        if len(contained) > 1:
            candidates = self._current_for_tokens(
                token
                for candidate in contained
                for token in self._tokens_for_identity(candidate, provenance)
            )
            return RebindResult.ambiguous(), candidates

        def overlap(candidate: StableBlockIdentity) -> int:
            return sum(
                1
                for interval in identity.native_ranges.intervals
                if candidate.native_ranges.contains(interval.start_ea)
            )

        scored = [(overlap(candidate), candidate) for candidate in current]
        best_score = max((score for score, _candidate in scored), default=0)
        if best_score == 0:
            return RebindResult.missing(), ()
        best = tuple(candidate for score, candidate in scored if score == best_score)
        candidates = self._current_for_tokens(
            token
            for candidate in best
            for token in self._tokens_for_identity(candidate, provenance)
        )
        if len(best) != 1:
            return RebindResult.ambiguous(), candidates
        return self._result_for_candidates(candidates), candidates

    def rebind_identity(self, identity: StableBlockIdentity) -> RebindResult:
        """Rebind any unique current translation of portable native identity."""
        self.require_generation_usable()
        result, candidates = self._rebind_identity(identity, provenance=None)
        self._observe_decision(
            "rebind",
            identity,
            result,
            candidates=candidates,
        )
        return result

    def rebind_native_identity(
        self,
        identity: StableBlockIdentity,
    ) -> RebindResult:
        """Rebind only the unique non-imported live native translation."""
        self.require_generation_usable()
        result, candidates = self._rebind_identity(
            identity,
            provenance=BlockHandleProvenance.NATIVE,
        )
        self._observe_decision(
            "rebind_native",
            identity,
            result,
            candidates=candidates,
        )
        return result

    def rebind_imported_identity(
        self,
        identity: StableBlockIdentity,
    ) -> RebindResult:
        """Rebind only a unique importer-published native translation."""
        self.require_generation_usable()
        result, candidates = self._rebind_identity(
            identity,
            provenance=BlockHandleProvenance.IMPORTED_NATIVE,
        )
        self._observe_decision(
            "rebind_imported",
            identity,
            result,
            candidates=candidates,
        )
        return result

    def _observe_decision(
        self,
        decision_kind: str,
        identity: StableBlockIdentity,
        result: RebindResult,
        *,
        candidates: tuple[BoundBlock, ...] = (),
    ) -> None:
        observer = self.decision_observer
        if observer is None:
            return
        try:
            observer(
                IdentityRebindObservation(
                    decision_kind=decision_kind,
                    identity=identity,
                    result=result,
                    mba_generation=int(self.generation),
                    evidence_generation=int(self.evidence_generation),
                    candidates=tuple(candidates),
                )
            )
        except Exception:
            return

    def _rebind_region_boundary(
        self,
        region: StableBlockIdentity,
        *,
        entry: bool,
    ) -> RebindResult:
        tokens_by_anchor: dict[int, set[str]] = defaultdict(set)
        for identity in self.serials_by_identity:
            tokens = tuple(
                token
                for token in self._tokens_for_identity(identity, None)
                if self.resolve(self._handles_by_token[token]) is not None
            )
            if not tokens:
                continue
            for token in tokens:
                handle = self._handles_by_token[token]
                anchors = set(identity.exact_instruction_eas)
                if handle.provenance is not BlockHandleProvenance.IMPORTED_NATIVE:
                    anchors.update(
                        interval.start_ea
                        for interval in identity.native_ranges.intervals
                    )
                for anchor_ea in anchors:
                    if region.native_ranges.contains(anchor_ea):
                        tokens_by_anchor[int(anchor_ea)].add(token)

        intervals = region.native_ranges.intervals
        for interval in intervals if entry else reversed(intervals):
            anchors = tuple(
                anchor_ea
                for anchor_ea in tokens_by_anchor
                if interval.start_ea <= anchor_ea < interval.end_ea
            )
            if anchors:
                boundary_anchor = min(anchors) if entry else max(anchors)
                return self._bound_for_tokens(tokens_by_anchor[boundary_anchor])
        boundary_ea = intervals[0].start_ea if entry else intervals[-1].end_ea - 1
        imported_tokens = tuple(
            token
            for token, handle in self._handles_by_token.items()
            if handle.provenance is BlockHandleProvenance.IMPORTED_NATIVE
            and handle.stable_identity is not None
            and handle.stable_identity.native_key == region.native_key
            and handle.stable_identity.native_ranges.contains(boundary_ea)
            and self.resolve(handle) is not None
        )
        if imported_tokens:
            return self._bound_for_tokens(imported_tokens)
        return RebindResult.missing()

    def rebind_region_entry(
        self,
        region: StableBlockIdentity,
    ) -> RebindResult:
        """Bind the block owning a region's first surviving native anchor.

        A handler's exact entry instruction can disappear during LOCOPT while
        later instructions from the same resolver-owned native corridor remain
        in the regenerated MBA.  Native and imported translations are equally
        valid; duplicate ownership of the earliest anchor remains ambiguous.
        """
        self.require_generation_usable()
        result = self._rebind_region_boundary(region, entry=True)
        self._observe_decision("rebind_region_entry", region, result)
        return result

    def rebind_region_exit(
        self,
        region: StableBlockIdentity,
    ) -> RebindResult:
        """Bind the block owning a region's last surviving native anchor.

        Native handler replay may prove an exit instruction that LOCOPT folds
        away.  The latest surviving native or imported anchor in the same
        resolver-owned region is the portable mutation-time source.  Duplicate
        ownership of that anchor remains ambiguous.
        """
        self.require_generation_usable()
        result = self._rebind_region_boundary(region, entry=False)
        self._observe_decision("rebind_region_exit", region, result)
        return result

    def rebind(self, handle: MbaBlockHandle) -> RebindResult:
        """Rebind native identity; synthetic handles never cross a rebuild."""
        self.require_generation_usable()
        if handle.session_id != self.session_id:
            return RebindResult.stale_generation()
        if handle.stable_identity is None:
            return RebindResult.missing()
        if handle.provenance is BlockHandleProvenance.IMPORTED_NATIVE:
            return self.rebind_imported_identity(handle.stable_identity)
        return self.rebind_identity(handle.stable_identity)

    def identity_at_native_ea(self, anchor_ea: int) -> StableBlockIdentity | None:
        self.require_generation_usable()
        matches = tuple(
            identity
            for identity in self.serials_by_identity
            if identity.native_ranges.contains(int(anchor_ea))
        )
        return matches[0] if len(matches) == 1 else None

    def rebind_native_ea(
        self,
        anchor_ea: int,
        *,
        owner: MbaBlockHandle | None = None,
    ) -> RebindResult:
        """Resolve one EA only when exact instruction or ownership proves it."""
        self.require_generation_usable()
        anchor_ea = int(anchor_ea)
        candidates = tuple(
            (identity, token)
            for identity, tokens in self._tokens_by_identity.items()
            if identity.native_ranges.contains(anchor_ea)
            for token in tokens
            if self.resolve(self._handles_by_token[token]) is not None
        )
        if owner is not None:
            if not any(token == owner.token for _identity, token in candidates):
                return RebindResult.missing()
            bound = self.resolve(owner)
            return (
                RebindResult.missing() if bound is None else RebindResult.bound(bound)
            )
        exact_tokens = tuple(
            token
            for identity, token in candidates
            if anchor_ea in identity.exact_instruction_eas
        )
        if exact_tokens:
            return self._bound_for_tokens(exact_tokens)
        return self._bound_for_tokens(token for _identity, token in candidates)

    def record_insert(
        self,
        *,
        transaction_id: str,
        insertion_serial: int,
        created: MbaBlockHandle,
        returned_serial: int,
    ) -> None:
        """Record an unowned SDK insertion without consuming plan authority."""
        self.require_generation_usable()
        if created.provenance is BlockHandleProvenance.CREATED_SYNTHETIC:
            raise ValueError(
                "CREATED_SYNTHETIC insertion requires bind_reserved_plan_block"
            )
        self._record_insert(
            transaction_id=transaction_id,
            insertion_serial=insertion_serial,
            created=created,
            returned_serial=returned_serial,
            allow_created_synthetic=False,
        )

    def _record_insert(
        self,
        *,
        transaction_id: str,
        insertion_serial: int,
        created: MbaBlockHandle,
        returned_serial: int,
        allow_created_synthetic: bool,
    ) -> None:
        """Bind one insertion while preserving its ownership provenance."""
        transaction_id = str(transaction_id)
        serials = self._serials_by_transaction.get(transaction_id)
        if serials is None:
            raise ValueError("block insertion requires an active identity transaction")
        insertion_serial = int(insertion_serial)
        returned_serial = int(returned_serial)
        if insertion_serial < 0 or returned_serial < 0:
            raise ValueError("block insertion coordinates must be non-negative")
        if self._handles_by_token.get(created.token) is not created:
            raise ValueError("inserted block handle is stale or foreign")
        if (
            created.provenance is BlockHandleProvenance.CREATED_SYNTHETIC
            and not allow_created_synthetic
        ):
            raise ValueError(
                "CREATED_SYNTHETIC insertion requires bind_reserved_plan_block"
            )
        proxy = self.logical_proxy_for_handle(created)
        if proxy is None:
            if created.provenance is BlockHandleProvenance.CREATED_SYNTHETIC:
                raise ValueError("planned insertion has no reserved plan owner")
            for token, serial in tuple(serials.items()):
                if serial >= insertion_serial:
                    serials[token] = serial + 1
            self.stage_new_proxy(
                transaction_id=transaction_id,
                handle=created,
                returned_serial=returned_serial,
            )
            self._insertion_serials_by_transaction[transaction_id][created.token] = (
                insertion_serial
            )
            return
        action = self._proxy_actions_by_transaction.get(transaction_id, {}).get(
            proxy.proxy_token
        )
        staged = proxy.resolve(transaction_id=transaction_id)
        if (
            action not in {"new", "replacement"}
            or staged is None
            or staged.handle is not created
            or created.token in serials
        ):
            raise ValueError(
                "inserted block does not match a transaction-reserved logical owner"
            )
        for token, serial in tuple(serials.items()):
            if serial >= insertion_serial:
                serials[token] = serial + 1
        serials[created.token] = returned_serial
        self._insertion_serials_by_transaction[transaction_id][created.token] = (
            insertion_serial
        )

    def discard_reserved_insert(
        self,
        *,
        transaction_id: str,
        handle: MbaBlockHandle,
    ) -> None:
        """Unbind a physically rolled-back reserved insertion before abort."""
        self.require_generation_usable()
        transaction_id = str(transaction_id)
        serials = self._serials_by_transaction.get(transaction_id)
        proxy = self.logical_proxy_for_handle(handle)
        if serials is None or proxy is None:
            raise ValueError("reserved insertion rollback has no active owner")
        action = self._proxy_actions_by_transaction.get(transaction_id, {}).get(
            proxy.proxy_token
        )
        staged = proxy.resolve(transaction_id=transaction_id)
        removed_serial = serials.get(handle.token)
        insertion_serial = self._insertion_serials_by_transaction.get(
            transaction_id, {}
        ).get(handle.token)
        if (
            action not in {"new", "replacement"}
            or staged is None
            or removed_serial is None
            or insertion_serial is None
        ):
            raise ValueError("reserved insertion rollback does not own a live block")
        serials.pop(handle.token)
        self._insertion_serials_by_transaction[transaction_id].pop(handle.token, None)
        for key, receipt in tuple(self._plan_creation_receipts.items()):
            if receipt.logical_version.handle is handle:
                self._plan_creation_receipts.pop(key, None)
        for token, serial in tuple(serials.items()):
            if serial > int(insertion_serial):
                serials[token] = serial - 1

    def record_realized_serial(
        self,
        *,
        transaction_id: str,
        expected_serial: int,
        returned_serial: int,
    ) -> None:
        """Bind a planned serial's transaction handle to its SDK result."""
        self.require_generation_usable()
        transaction_id = str(transaction_id)
        expected_serial = int(expected_serial)
        baseline = self._baseline_tokens_by_transaction.get(transaction_id)
        serials = self._serials_by_transaction.get(transaction_id)
        if baseline is None or serials is None:
            raise ValueError("serial realization requires an active transaction")
        token = baseline.get(expected_serial)
        if token is None:
            handle = self._new_handle(
                None,
                token=f"planned:{transaction_id}:{expected_serial}",
                provenance=BlockHandleProvenance.OBSERVED_EPHEMERAL,
            )
            self.stage_new_proxy(
                transaction_id=transaction_id,
                handle=handle,
                returned_serial=int(returned_serial),
            )
            baseline[expected_serial] = handle.token
            return
        resolved = self.resolve(
            self._handles_by_token[token],
            transaction_id=transaction_id,
        )
        if resolved is None:
            raise ValueError("planned serial no longer resolves in this transaction")
        serials[resolved.handle.token] = int(returned_serial)

    def record_split(
        self,
        *,
        transaction_id: str,
        original: MbaBlockHandle,
        retained: MbaBlockHandle,
        created_tail: MbaBlockHandle,
        returned_tail_serial: int,
    ) -> None:
        """Record a split without inventing a native identity for its tail."""
        self.require_generation_usable()
        transaction_id = str(transaction_id)
        serials = self._serials_by_transaction.get(transaction_id)
        if serials is None:
            raise ValueError("block split requires an active identity transaction")
        original_bound = self.resolve(original, transaction_id=transaction_id)
        if original_bound is None:
            raise ValueError("cannot split a stale or foreign handle")
        tail_serial = int(returned_tail_serial)
        for token, serial in tuple(serials.items()):
            if token != original_bound.handle.token and serial >= tail_serial:
                serials[token] = serial + 1
        if (
            retained.stable_identity == original_bound.handle.stable_identity
            and retained.provenance is original_bound.handle.provenance
        ):
            self.stage_replacement(
                transaction_id=transaction_id,
                original=original,
                replacement=retained,
                returned_serial=original_bound.serial,
            )
        else:
            self.stage_retirement(transaction_id=transaction_id, handle=original)
            self.stage_new_proxy(
                transaction_id=transaction_id,
                handle=retained,
                returned_serial=original_bound.serial,
            )
        self.stage_new_proxy(
            transaction_id=transaction_id,
            handle=created_tail,
            returned_serial=tail_serial,
        )

    def record_clone(
        self,
        *,
        transaction_id: str,
        source: MbaBlockHandle,
        created: MbaBlockHandle,
        returned_serial: int,
    ) -> None:
        """Record an explicit clone handle; native duplicate rebinding stays ambiguous."""
        self.require_generation_usable()
        if self.resolve(source, transaction_id=str(transaction_id)) is None:
            raise ValueError("cannot clone a stale or foreign handle")
        self.stage_new_proxy(
            transaction_id=str(transaction_id),
            handle=created,
            returned_serial=int(returned_serial),
        )

    def mark_removed(
        self,
        handle: MbaBlockHandle,
        *,
        transaction_id: str,
    ) -> None:
        """Stage retirement and compact only transaction-local coordinates."""
        self.require_generation_usable()
        transaction_id = str(transaction_id)
        serials = self._serials_by_transaction.get(transaction_id)
        if serials is None:
            raise ValueError("block removal requires an active identity transaction")
        bound = self.resolve(handle, transaction_id=transaction_id)
        if bound is None:
            raise ValueError("cannot remove a stale or foreign handle")
        removed_serial = int(bound.serial)
        self.stage_retirement(transaction_id=transaction_id, handle=handle)
        for token, serial in tuple(serials.items()):
            if token != bound.handle.token and serial > removed_serial:
                serials[token] = serial - 1

    def advance_generation(self) -> int:
        """Mark one committed structural mutation batch without losing bindings."""
        self.require_generation_usable()
        self.generation += 1
        return self.generation

    def _replace_with_rebuilt(self, rebuilt: MbaBlockIdentityIndex) -> None:
        """Install rebuilt bindings while preserving uniquely proved handles."""
        previous_native: dict[StableBlockIdentity, tuple[BoundBlock, ...]] = {}
        for identity, tokens in self._tokens_by_identity.items():
            current_by_handle = {
                bound.handle.token: bound
                for token in tokens
                if (bound := self.resolve(self._handles_by_token[token])) is not None
            }
            previous_native[identity] = tuple(current_by_handle.values())
        for identity, serials in rebuilt.serials_by_identity.items():
            old_bounds = previous_native.get(identity, ())
            if len(old_bounds) == 1 and len(serials) == 1:
                handle = old_bounds[0].handle
                replacement_serial = int(serials[0])
                replacement_token = rebuilt._token_by_serial.get(replacement_serial)
                if replacement_token is None:
                    rebuilt._refresh_primary_serial(replacement_serial)
                    replacement_token = rebuilt._token_by_serial.get(replacement_serial)
                if replacement_token is None:
                    continue
                replacement_handle = rebuilt._handles_by_token[replacement_token]
                replacement_proxy_token = rebuilt._proxy_token_by_handle_token.pop(
                    replacement_token,
                    None,
                )
                if replacement_proxy_token is not None:
                    rebuilt._proxies_by_token.pop(replacement_proxy_token, None)
                rebuilt._serial_by_token.pop(replacement_token, None)
                rebuilt._handles_by_token.pop(replacement_token, None)
                rebuilt._tokens_by_identity[identity].discard(replacement_token)
                rebuilt._token_by_serial.pop(replacement_serial, None)
                if replacement_handle.stable_identity is None:
                    raise ValueError("native rebuild replacement lost stable identity")
                rebuilt._handles_by_token[handle.token] = handle
                rebuilt._tokens_by_identity[identity].add(handle.token)
                rebuilt._bind(handle, replacement_serial)
                rebuilt._register_published_proxy(handle)
        self._handles_by_token = rebuilt._handles_by_token
        self._serial_by_token = rebuilt._serial_by_token
        self._token_by_serial = rebuilt._token_by_serial
        self._tokens_by_identity = rebuilt._tokens_by_identity
        self._next_token = max(self._next_token, rebuilt._next_token)
        self._next_proxy_token = max(
            self._next_proxy_token,
            rebuilt._next_proxy_token,
        )
        self._proxies_by_token = rebuilt._proxies_by_token
        self._proxy_token_by_handle_token = rebuilt._proxy_token_by_handle_token
        self._proxy_tokens_by_transaction.clear()
        self._proxy_actions_by_transaction.clear()
        self._serials_by_transaction.clear()
        self._baseline_tokens_by_transaction.clear()
        self._generation_by_transaction.clear()
        self._attempt_by_transaction.clear()
        self._insertion_serials_by_transaction.clear()
        self._plan_reservations.clear()

    def refresh_from_mba(
        self,
        mba: object,
        *,
        imported_instruction_origins: Mapping[int, int] | None = None,
        current_mba_identity_binding: CurrentMbaIdentityBindingSnapshot | None = None,
    ) -> None:
        """Rebuild bindings from a callback-local MBA after an unknown SDK effect."""
        self.require_generation_usable()
        self._replace_with_rebuilt(
            type(self).from_mba(
                mba,
                generation=self.generation,
                native_key=self.native_key,
                evidence_generation=self.evidence_generation,
                maturity=self.maturity,
                snapshot_id=self.snapshot_id,
                session_id=self.session_id,
                imported_instruction_origins=imported_instruction_origins,
                current_mba_identity_binding=current_mba_identity_binding,
            )
        )

    def refresh_from_flow_graph(self, flow_graph: FlowGraph) -> None:
        """Discard unprovable handles and rebuild native bindings from a fresh lift."""
        self.require_generation_usable()
        self._replace_with_rebuilt(
            type(self).from_flow_graph(
                generation=self.generation,
                native_key=self.native_key,
                evidence_generation=self.evidence_generation,
                maturity=self.maturity,
                snapshot_id=self.snapshot_id,
                flow_graph=flow_graph,
                session_id=self.session_id,
            )
        )


__all__ = [
    "MbaBlockIdentityIndex",
    "PlanBlockCreationReceipt",
    "PlanBlockReservation",
]
