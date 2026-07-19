"""Current-MBA bindings for portable block identity.

The index deliberately owns all current serial coordinates.  It retains only
serial-free handles and derived integer bindings; an MBA is lifted by the
callback that needs it and is never retained here.
"""
from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass, field
from types import MappingProxyType

from d810.core.typing import Iterable
from d810.ir.block_identity import (
    BlockHandleProvenance,
    BoundBlock,
    MbaBlockHandle,
    RebindResult,
    StableBlockIdentity,
    stable_block_identity_from_snapshot,
)
from d810.ir.flowgraph import FlowGraph


@dataclass(slots=True)
class MbaBlockIdentityIndex:
    """Session-local handles rebound into one mutable MBA generation.

    All shifts caused by structural mutation are applied here synchronously.
    Callers may retain a :class:`MbaBlockHandle`, but never a block serial.
    """

    session_id: str
    generation: int = 0
    evidence_generation: int | None = None
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
        if self.generation < 0:
            raise ValueError("MBA identity index generation must be non-negative")
        if self.evidence_generation < 0:
            raise ValueError("MBA identity evidence generation must be non-negative")

    @classmethod
    def from_bindings(
        cls,
        *,
        generation: int,
        evidence_generation: int | None = None,
        bindings: Iterable[tuple[StableBlockIdentity, int]],
        session_id: str = "identity-index",
    ) -> MbaBlockIdentityIndex:
        index = cls(
            session_id=session_id,
            generation=generation,
            evidence_generation=evidence_generation,
        )
        for identity, serial in bindings:
            index._bind_new_native(identity, int(serial))
        return index

    @classmethod
    def from_flow_graph(
        cls,
        *,
        generation: int,
        evidence_generation: int | None = None,
        flow_graph: FlowGraph,
        session_id: str | None = None,
    ) -> MbaBlockIdentityIndex:
        """Build bindings from a callback-local MBA lift without retaining it."""
        index = cls(
            session_id=session_id or f"flowgraph:{int(flow_graph.func_ea):X}",
            generation=generation,
            evidence_generation=evidence_generation,
        )
        for serial, block in flow_graph.blocks.items():
            identity = stable_block_identity_from_snapshot(block)
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
                    token in self._serial_by_token
                    and token not in self._stale_tokens
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
        else:
            handle = MbaBlockHandle.native(
                identity,
                session_id=self.session_id,
                token=token,
            )
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
    ) -> MbaBlockHandle:
        handle = self._new_handle(identity)
        self._bind(handle, serial)
        return handle

    def _bind_new_synthetic(self, serial: int) -> MbaBlockHandle:
        handle = self._new_handle(None)
        self._bind(handle, serial)
        return handle

    def create_native_handle(self, identity: StableBlockIdentity) -> MbaBlockHandle:
        """Allocate an unbound native handle for a proved structural mutation."""
        return self._new_handle(identity)

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

    def identity_for_serial(self, serial: int) -> StableBlockIdentity | None:
        handle = self.handle_for_serial(serial)
        return None if handle is None else handle.identity

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
        identity = handle.identity
        anchor_ea = None
        if identity is not None and identity.native_eas.intervals:
            anchor_ea = identity.native_eas.intervals[0].start_ea
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

    def rebind_identity(self, identity: StableBlockIdentity) -> RebindResult:
        """Rebind via exact identity, containment, then unique overlap."""
        exact = self._bound_for_tokens(self._tokens_by_identity.get(identity, ()))
        if exact.block is not None or exact.status.name == "AMBIGUOUS":
            return exact

        current = tuple(self.serials_by_identity)
        contained = tuple(
            candidate
            for candidate in current
            if all(
                candidate.native_eas.contains(interval.start_ea)
                for interval in identity.native_eas.intervals
            )
        )
        if len(contained) == 1:
            return self._bound_for_tokens(self._tokens_by_identity[contained[0]])
        if len(contained) > 1:
            return RebindResult.ambiguous()

        def overlap(candidate: StableBlockIdentity) -> int:
            return sum(
                1
                for interval in identity.native_eas.intervals
                if candidate.native_eas.contains(interval.start_ea)
            )

        scored = [(overlap(candidate), candidate) for candidate in current]
        best_score = max((score for score, _candidate in scored), default=0)
        if best_score == 0:
            return RebindResult.missing()
        best = tuple(candidate for score, candidate in scored if score == best_score)
        if len(best) != 1:
            return RebindResult.ambiguous()
        return self._bound_for_tokens(self._tokens_by_identity[best[0]])

    def rebind(self, handle: MbaBlockHandle) -> RebindResult:
        """Rebind native identity; synthetic handles never cross a rebuild."""
        if handle.session_id != self.session_id:
            return RebindResult.stale_generation()
        if handle.identity is None:
            return RebindResult.missing()
        return self.rebind_identity(handle.identity)

    def identity_at_native_ea(self, anchor_ea: int) -> StableBlockIdentity | None:
        matches = tuple(
            identity
            for identity in self.serials_by_identity
            if identity.native_eas.contains(int(anchor_ea))
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

    def record_realized_serial(self, *, expected_serial: int, returned_serial: int) -> None:
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
        self._bind(retained, original_bound.serial)
        self._bind(created_tail, int(returned_tail_serial))
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
        bound = self.resolve(handle)
        if bound is not None:
            self._serial_by_token.pop(handle.token, None)
            self._refresh_primary_serial(bound.serial)
        self._stale_tokens.add(handle.token)

    def advance_generation(self) -> int:
        """Mark one committed structural mutation batch without losing bindings."""
        self.generation += 1
        return self.generation

    def refresh_from_flow_graph(self, flow_graph: FlowGraph) -> None:
        """Discard unprovable handles and rebuild native bindings from a fresh lift."""
        previous_native = {
            identity: tuple(
                token for token in tokens if self.resolve(self._handles_by_token[token])
            )
            for identity, tokens in self._tokens_by_identity.items()
        }
        rebuilt = type(self).from_flow_graph(
            generation=self.generation,
            evidence_generation=self.evidence_generation,
            flow_graph=flow_graph,
            session_id=self.session_id,
        )
        for identity, serials in rebuilt.serials_by_identity.items():
            old_tokens = previous_native.get(identity, ())
            if len(old_tokens) == 1 and len(serials) == 1:
                handle = self._handles_by_token[old_tokens[0]]
                rebuilt._handles_by_token[handle.token] = handle
                rebuilt._tokens_by_identity[identity].discard(
                    rebuilt._token_by_serial[serials[0]]
                )
                rebuilt._token_by_serial.pop(serials[0], None)
                rebuilt._bind(handle, serials[0])
        self._stale_tokens.update(self._handles_by_token)
        self._handles_by_token = rebuilt._handles_by_token
        self._serial_by_token = rebuilt._serial_by_token
        self._token_by_serial = rebuilt._token_by_serial
        self._tokens_by_identity = rebuilt._tokens_by_identity
        self._baseline_tokens.clear()


__all__ = ["MbaBlockIdentityIndex"]
