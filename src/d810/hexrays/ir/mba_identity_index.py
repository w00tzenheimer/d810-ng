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
    _baseline_tokens: dict[int, str] = field(
        default_factory=dict,
        init=False,
        repr=False,
    )
    _stale_tokens: set[str] = field(default_factory=set, init=False, repr=False)
    _next_token: int = field(default=0, init=False, repr=False)

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
        return MappingProxyType(
            {
                identity: tuple(
                    sorted(
                        self._serial_by_token[token]
                        for token in tokens
                        if token in self._serial_by_token
                        and token not in self._stale_tokens
                    )
                )
                for identity, tokens in self._tokens_by_identity.items()
                if any(
                    token in self._serial_by_token and token not in self._stale_tokens
                    for token in tokens
                )
            }
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
        self._stale_tokens.discard(handle.token)

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
            if bound_serial == int(serial) and token not in self._stale_tokens
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
        return handle

    def _bind_new_synthetic(self, serial: int) -> MbaBlockHandle:
        handle = self._new_handle(None)
        self._bind(handle, serial)
        return handle

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
        """Give every initial serial a transaction-local handle exactly once."""
        for serial in range(int(quantity)):
            if serial in self._baseline_tokens:
                continue
            token = self._token_by_serial.get(serial)
            if token is None:
                handle = self._bind_new_synthetic(serial)
                token = handle.token
            self._baseline_tokens[serial] = token

    def begin_transaction(self, quantity: int) -> None:
        """Rebase planned coordinates onto the current live MBA serials.

        Baseline tokens are meaningful only inside one mutation transaction.
        After a committed insertion, the same integer denotes a current live
        block in the next transaction, not the prior transaction's planned
        coordinate.  Rebuild the map at every batch boundary so serial
        resolution cannot replay an obsolete shift.
        """
        self._baseline_tokens.clear()
        self.ensure_serial_space(int(quantity))

    def identity_for_serial(self, serial: int) -> StableBlockIdentity | None:
        handle = self.handle_for_serial(serial)
        return None if handle is None else handle.stable_identity

    def handle_for_serial(self, serial: int) -> MbaBlockHandle | None:
        token = self._token_by_serial.get(int(serial))
        if token is None or token in self._stale_tokens:
            return None
        return self._handles_by_token[token]

    def resolve(self, handle: MbaBlockHandle) -> BoundBlock | None:
        """Resolve one unbroken current-generation handle, never by guessing."""
        if handle.session_id != self.session_id or handle.token in self._stale_tokens:
            return None
        serial = self._serial_by_token.get(handle.token)
        if serial is None:
            return None
        identity = handle.stable_identity
        anchor_ea = None
        if identity is not None and identity.native_ranges.intervals:
            anchor_ea = identity.native_ranges.intervals[0].start_ea
        return BoundBlock(
            handle=handle,
            serial=serial,
            generation=self.generation,
            anchor_ea=anchor_ea,
        )

    def _bound_for_tokens(self, tokens: Iterable[str]) -> RebindResult:
        current = [
            bound
            for token in tokens
            if (bound := self.resolve(self._handles_by_token[token])) is not None
        ]
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

    def record_insert(
        self,
        *,
        insertion_serial: int,
        created: MbaBlockHandle,
        returned_serial: int,
    ) -> None:
        """Synchronously shift live bindings and bind the SDK-created handle."""
        insertion_serial = int(insertion_serial)
        for token, serial in tuple(self._serial_by_token.items()):
            if serial >= insertion_serial:
                self._serial_by_token[token] = serial + 1
        self._token_by_serial.clear()
        for serial in set(self._serial_by_token.values()):
            self._refresh_primary_serial(serial)
        self._bind(created, int(returned_serial))

    def record_realized_serial(
        self, *, expected_serial: int, returned_serial: int
    ) -> None:
        """Bind a planned serial's transaction handle to its SDK result."""
        expected_serial = int(expected_serial)
        token = self._baseline_tokens.get(expected_serial)
        if token is None:
            token = self._new_handle(None, token=f"planned:{expected_serial}").token
            self._baseline_tokens[expected_serial] = token
        self._bind(self._handles_by_token[token], int(returned_serial))

    def record_split(
        self,
        *,
        original: MbaBlockHandle,
        retained: MbaBlockHandle,
        created_tail: MbaBlockHandle,
        returned_tail_serial: int,
    ) -> None:
        """Record a split without inventing a native identity for its tail."""
        original_bound = self.resolve(original)
        if original_bound is None:
            raise ValueError("cannot split a stale or foreign handle")
        tail_serial = int(returned_tail_serial)
        for token, serial in tuple(self._serial_by_token.items()):
            if token != original.token and serial >= tail_serial:
                self._serial_by_token[token] = serial + 1
        self._token_by_serial.clear()
        for serial in set(self._serial_by_token.values()):
            self._refresh_primary_serial(serial)
        self._bind(retained, original_bound.serial)
        self._bind(created_tail, tail_serial)
        self._stale_tokens.add(original.token)
        self._refresh_primary_serial(original_bound.serial)

    def record_clone(
        self,
        *,
        source: MbaBlockHandle,
        created: MbaBlockHandle,
        returned_serial: int,
    ) -> None:
        """Record an explicit clone handle; native duplicate rebinding stays ambiguous."""
        if self.resolve(source) is None:
            raise ValueError("cannot clone a stale or foreign handle")
        self._bind(created, int(returned_serial))

    def mark_removed(self, handle: MbaBlockHandle) -> None:
        """Stale one removed block and compact all later live coordinates."""
        bound = self.resolve(handle)
        if bound is not None:
            removed_serial = int(bound.serial)
            self._serial_by_token.pop(handle.token, None)
            for token, serial in tuple(self._serial_by_token.items()):
                if serial > removed_serial:
                    self._serial_by_token[token] = serial - 1
            self._token_by_serial.clear()
            for serial in set(self._serial_by_token.values()):
                self._refresh_primary_serial(serial)
        self._stale_tokens.add(handle.token)

    def advance_generation(self) -> int:
        """Mark one committed structural mutation batch without losing bindings."""
        self.generation += 1
        return self.generation

    def _replace_with_rebuilt(self, rebuilt: MbaBlockIdentityIndex) -> None:
        """Install rebuilt bindings while preserving uniquely proved handles."""
        previous_native = {
            identity: tuple(
                token for token in tokens if self.resolve(self._handles_by_token[token])
            )
            for identity, tokens in self._tokens_by_identity.items()
        }
        previous_tokens = set(self._handles_by_token)
        preserved_tokens: set[str] = set()
        for identity, serials in rebuilt.serials_by_identity.items():
            old_tokens = previous_native.get(identity, ())
            if len(old_tokens) == 1 and len(serials) == 1:
                handle = self._handles_by_token[old_tokens[0]]
                replacement_token = rebuilt._token_by_serial[serials[0]]
                rebuilt._serial_by_token.pop(replacement_token, None)
                rebuilt._handles_by_token.pop(replacement_token, None)
                rebuilt._handles_by_token[handle.token] = handle
                rebuilt._tokens_by_identity[identity].discard(replacement_token)
                rebuilt._tokens_by_identity[identity].add(handle.token)
                rebuilt._token_by_serial.pop(serials[0], None)
                rebuilt._bind(handle, serials[0])
                preserved_tokens.add(handle.token)
        stale_tokens = self._stale_tokens | (previous_tokens - preserved_tokens)
        stale_tokens.difference_update(rebuilt._handles_by_token)
        self._handles_by_token = rebuilt._handles_by_token
        self._serial_by_token = rebuilt._serial_by_token
        self._token_by_serial = rebuilt._token_by_serial
        self._tokens_by_identity = rebuilt._tokens_by_identity
        self._stale_tokens = stale_tokens
        self._next_token = max(self._next_token, rebuilt._next_token)
        self._baseline_tokens.clear()

    def refresh_from_mba(self, mba: object) -> None:
        """Rebuild bindings from a callback-local MBA after an unknown SDK effect."""
        self._replace_with_rebuilt(
            type(self).from_mba(
                mba,
                generation=self.generation,
                native_key=self.native_key,
                evidence_generation=self.evidence_generation,
                session_id=self.session_id,
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
