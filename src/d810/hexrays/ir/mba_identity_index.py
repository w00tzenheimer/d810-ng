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
    LogicalBlockVersionId,
    LogicalBlockVersionTransition,
)


@dataclass(frozen=True, slots=True)
class IdentityRebindObservation:
    decision_kind: str
    identity: StableBlockIdentity
    result: RebindResult
    mba_generation: int
    evidence_generation: int


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

    @classmethod
    def from_bindings(
        cls,
        *,
        generation: int,
        native_key: NativePreanalysisKey,
        evidence_generation: int | None = None,
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
        session_id: str = "live-mba",
        imported_instruction_origins: Mapping[int, int] | None = None,
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
        )
        imported_instruction_origins = imported_instruction_origins or {}
        quantity = int(getattr(mba, "qty", 0) or 0)
        for serial in range(quantity):
            block = mba.get_mblock(serial)
            if block is None:
                continue
            anchors: set[int] = set()
            imported_anchors: set[int] = set()
            instruction = getattr(block, "head", None)
            while instruction is not None:
                instruction_ea = int(getattr(instruction, "ea", -1) or -1)
                anchors.add(instruction_ea)
                if instruction_ea in imported_instruction_origins:
                    imported_anchors.add(
                        int(imported_instruction_origins[instruction_ea])
                    )
                instruction = getattr(instruction, "next", None)
            imported_eas = tuple(
                ea
                for ea in sorted(imported_anchors)
                if 0 <= ea < 0xFFFFFFFFFFFFFFFF
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
            instruction_eas = tuple(
                ea for ea in sorted(anchors) if 0 <= ea < 0xFFFFFFFFFFFFFFFF
            )
            native_anchors = set(instruction_eas)
            start_ea = int(getattr(block, "start", -1))
            if 0 <= start_ea < 0xFFFFFFFFFFFFFFFF:
                native_anchors.add(start_ea)
            if native_anchors:
                index._bind_new_native(
                    StableBlockIdentity.from_intervals(
                        (
                            NativeEaInterval(ea, ea + 1)
                            for ea in sorted(native_anchors)
                        ),
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
        return len(self._proxies_by_token)

    def logical_proxy_for_handle(
        self,
        handle: MbaBlockHandle | None,
    ) -> LogicalBlockProxy | None:
        if handle is None:
            return None
        proxy_token = self._proxy_token_by_handle_token.get(handle.token)
        return None if proxy_token is None else self._proxies_by_token[proxy_token]

    def _new_token(self, prefix: str) -> str:
        token = f"{prefix}:{self._next_token}"
        self._next_token += 1
        return token

    def _new_handle(
        self,
        identity: StableBlockIdentity | None,
        *,
        token: str | None = None,
        provenance: BlockHandleProvenance = BlockHandleProvenance.NATIVE,
    ) -> MbaBlockHandle:
        token = token or self._new_token(
            "native" if identity is not None else "synthetic"
        )
        if token in self._handles_by_token:
            raise ValueError(f"duplicate MBA block-handle token: {token}")
        if identity is None:
            handle = MbaBlockHandle.synthetic(
                session_id=self.session_id,
                token=token,
            )
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
        handle = self._new_handle(None)
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
        return self._new_handle(identity, provenance=provenance)

    def create_imported_native_handle(
        self,
        identity: StableBlockIdentity,
    ) -> MbaBlockHandle:
        """Allocate an exact live handle for an imported native translation."""
        return self.create_native_handle(
            identity,
            provenance=BlockHandleProvenance.IMPORTED_NATIVE,
        )

    def create_synthetic_handle(self) -> MbaBlockHandle:
        """Allocate an unbound transaction-only handle for synthetic CFG work."""
        return self._new_handle(None)

    def ensure_serial_space(self, quantity: int) -> None:
        """Give every current serial a published logical proxy exactly once."""
        for serial in range(int(quantity)):
            token = self._token_by_serial.get(serial)
            if token is None:
                self._bind_new_synthetic(serial)

    def begin_transaction(
        self,
        transaction_id: str,
        quantity: int | None = None,
    ) -> None:
        """Rebase planned coordinates onto the current live MBA serials.

        Baseline tokens are meaningful only inside one mutation transaction.
        After a committed insertion, the same integer denotes a current live
        block in the next transaction, not the prior transaction's planned
        coordinate.  Rebuild the map at every batch boundary so serial
        resolution cannot replay an obsolete shift.
        """
        transaction_id = str(transaction_id)
        if not transaction_id:
            raise ValueError("identity transaction requires a non-empty id")
        if transaction_id in self._serials_by_transaction:
            raise ValueError(f"identity transaction already active: {transaction_id}")
        if quantity is None:
            quantity = max(self._token_by_serial, default=-1) + 1
        self.ensure_serial_space(int(quantity))
        self._serials_by_transaction[transaction_id] = dict(self._serial_by_token)
        self._baseline_tokens_by_transaction[transaction_id] = {
            int(serial): token for serial, token in self._token_by_serial.items()
        }

    def resolve_planned_serial(
        self,
        transaction_id: str,
        planned_serial: int,
    ) -> int | None:
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
        handle = self.handle_for_serial(serial)
        return None if handle is None else handle.stable_identity

    def handle_for_serial(self, serial: int) -> MbaBlockHandle | None:
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

    def stage_new_proxy(
        self,
        *,
        transaction_id: str,
        handle: MbaBlockHandle,
        returned_serial: int,
    ) -> LogicalBlockVersion:
        transaction_id = str(transaction_id)
        serials = self._serials_by_transaction.get(transaction_id)
        if serials is None:
            raise ValueError("block creation requires an active identity transaction")
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
        serials[handle.token] = int(returned_serial)
        self._proxy_tokens_by_transaction[transaction_id].add(proxy_token)
        self._proxy_actions_by_transaction[transaction_id][proxy_token] = "new"
        return staged

    def stage_retirement(
        self,
        *,
        transaction_id: str,
        handle: MbaBlockHandle,
    ) -> None:
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
        transaction_id = str(transaction_id)
        serials = self._serials_by_transaction.pop(transaction_id, None)
        if serials is None:
            raise ValueError("identity transaction is not active")
        transitions: list[LogicalBlockVersionTransition] = []
        for proxy_token in sorted(
            self._proxy_tokens_by_transaction.pop(transaction_id, ())
        ):
            proxy = self._proxies_by_token[proxy_token]
            transition = proxy.commit(transaction_id)
            transitions.append(transition)
        published_serials: dict[str, int] = {}
        for proxy in self._proxies_by_token.values():
            published = proxy.resolve()
            if published is None:
                continue
            serial = serials.get(published.handle.token)
            if serial is None:
                raise ValueError("published logical block has no live serial")
            published_serials[published.handle.token] = int(serial)
        self._serial_by_token = published_serials
        self._token_by_serial.clear()
        for token, serial in sorted(
            self._serial_by_token.items(),
            key=lambda item: (item[1], item[0]),
        ):
            self._token_by_serial.setdefault(serial, token)
        self._baseline_tokens_by_transaction.pop(transaction_id, None)
        self._proxy_actions_by_transaction.pop(transaction_id, None)
        return tuple(transitions)

    def abort_proxy_transaction(
        self,
        transaction_id: str,
    ) -> tuple[LogicalBlockVersionId, ...]:
        """Discard staged physical versions without changing publication."""
        transaction_id = str(transaction_id)
        discarded: list[LogicalBlockVersionId] = []
        actions = self._proxy_actions_by_transaction.pop(transaction_id, {})
        for proxy_token in sorted(
            self._proxy_tokens_by_transaction.pop(transaction_id, ())
        ):
            proxy = self._proxies_by_token[proxy_token]
            if actions.get(proxy_token) == "retirement":
                proxy.abort_retirement(transaction_id)
                continue
            staged = proxy.abort(transaction_id)
            discarded.append(staged.version_id)
        self._serials_by_transaction.pop(transaction_id, None)
        self._baseline_tokens_by_transaction.pop(transaction_id, None)
        return tuple(discarded)

    def _bound_for_tokens(self, tokens: Iterable[str]) -> RebindResult:
        current_by_handle = {
            bound.handle.token: bound
            for token in tokens
            if (bound := self.resolve(self._handles_by_token[token])) is not None
        }
        current = tuple(current_by_handle.values())
        if not current:
            return RebindResult.missing()
        if len(current) != 1:
            return RebindResult.ambiguous()
        return RebindResult.bound(current[0])

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
    ) -> RebindResult:
        """Rebind via exact identity, containment, then unique overlap."""
        if identity.native_key != self.native_key:
            return RebindResult.missing()
        exact = self._bound_for_tokens(self._tokens_for_identity(identity, provenance))
        if exact.block is not None or exact.status.name == "AMBIGUOUS":
            return exact

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
            return self._bound_for_tokens(
                self._tokens_for_identity(contained[0], provenance)
            )
        if len(contained) > 1:
            return RebindResult.ambiguous()

        def overlap(candidate: StableBlockIdentity) -> int:
            return sum(
                1
                for interval in identity.native_ranges.intervals
                if candidate.native_ranges.contains(interval.start_ea)
            )

        scored = [(overlap(candidate), candidate) for candidate in current]
        best_score = max((score for score, _candidate in scored), default=0)
        if best_score == 0:
            return RebindResult.missing()
        best = tuple(candidate for score, candidate in scored if score == best_score)
        if len(best) != 1:
            return RebindResult.ambiguous()
        return self._bound_for_tokens(self._tokens_for_identity(best[0], provenance))

    def rebind_identity(self, identity: StableBlockIdentity) -> RebindResult:
        """Rebind any unique current translation of portable native identity."""
        result = self._rebind_identity(identity, provenance=None)
        self._observe_decision("rebind", identity, result)
        return result

    def rebind_native_identity(
        self,
        identity: StableBlockIdentity,
    ) -> RebindResult:
        """Rebind only the unique non-imported live native translation."""
        result = self._rebind_identity(
            identity,
            provenance=BlockHandleProvenance.NATIVE,
        )
        self._observe_decision("rebind_native", identity, result)
        return result

    def rebind_imported_identity(
        self,
        identity: StableBlockIdentity,
    ) -> RebindResult:
        """Rebind only a unique importer-published native translation."""
        result = self._rebind_identity(
            identity,
            provenance=BlockHandleProvenance.IMPORTED_NATIVE,
        )
        self._observe_decision("rebind_imported", identity, result)
        return result

    def _observe_decision(
        self,
        decision_kind: str,
        identity: StableBlockIdentity,
        result: RebindResult,
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
            for interval in identity.native_ranges.intervals:
                anchor_ea = int(interval.start_ea)
                if region.native_ranges.contains(anchor_ea):
                    tokens_by_anchor[anchor_ea].update(tokens)

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
        result = self._rebind_region_boundary(region, entry=False)
        self._observe_decision("rebind_region_exit", region, result)
        return result

    def rebind(self, handle: MbaBlockHandle) -> RebindResult:
        """Rebind native identity; synthetic handles never cross a rebuild."""
        if handle.session_id != self.session_id:
            return RebindResult.stale_generation()
        if handle.stable_identity is None:
            return RebindResult.missing()
        if handle.provenance is BlockHandleProvenance.IMPORTED_NATIVE:
            return self.rebind_imported_identity(handle.stable_identity)
        return self.rebind_identity(handle.stable_identity)

    def identity_at_native_ea(self, anchor_ea: int) -> StableBlockIdentity | None:
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
            return RebindResult.missing() if bound is None else RebindResult.bound(bound)
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
        """Stage an insertion and shifted coordinates inside one transaction."""
        transaction_id = str(transaction_id)
        serials = self._serials_by_transaction.get(transaction_id)
        if serials is None:
            raise ValueError("block insertion requires an active identity transaction")
        insertion_serial = int(insertion_serial)
        for token, serial in tuple(serials.items()):
            if serial >= insertion_serial:
                serials[token] = serial + 1
        self.stage_new_proxy(
            transaction_id=transaction_id,
            handle=created,
            returned_serial=int(returned_serial),
        )

    def record_realized_serial(
        self,
        *,
        transaction_id: str,
        expected_serial: int,
        returned_serial: int,
    ) -> None:
        """Bind a planned serial's transaction handle to its SDK result."""
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
                replacement_token = rebuilt._token_by_serial.get(
                    replacement_serial
                )
                if replacement_token is None:
                    rebuilt._refresh_primary_serial(replacement_serial)
                    replacement_token = rebuilt._token_by_serial.get(
                        replacement_serial
                    )
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

    def refresh_from_mba(
        self,
        mba: object,
        *,
        imported_instruction_origins: Mapping[int, int] | None = None,
    ) -> None:
        """Rebuild bindings from a callback-local MBA after an unknown SDK effect."""
        self._replace_with_rebuilt(
            type(self).from_mba(
                mba,
                generation=self.generation,
                native_key=self.native_key,
                evidence_generation=self.evidence_generation,
                session_id=self.session_id,
                imported_instruction_origins=imported_instruction_origins,
            )
        )

    def refresh_from_flow_graph(self, flow_graph: FlowGraph) -> None:
        """Discard unprovable handles and rebuild native bindings from a fresh lift."""
        self._replace_with_rebuilt(
            type(self).from_flow_graph(
                generation=self.generation,
                native_key=self.native_key,
                evidence_generation=self.evidence_generation,
                flow_graph=flow_graph,
                session_id=self.session_id,
            )
        )


__all__ = ["MbaBlockIdentityIndex"]
