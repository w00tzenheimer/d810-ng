"""Synchronous receipt gateway for structural MBA mutation."""
from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum

from d810.core.events import EventEmitter
from d810.core.typing import Iterable
from d810.hexrays.ir.mba_identity_index import MbaBlockIdentityIndex
from d810.ir.block_identity import MbaBlockHandle, StableBlockIdentity


class StructuralMutationKind(Enum):
    """Structural mutation families that can invalidate current bindings."""

    EDGE_REDIRECT = "edge_redirect"
    BLOCK_INSERT = "block_insert"
    BLOCK_REMOVE = "block_remove"
    BLOCK_REPLACE = "block_replace"


@dataclass(frozen=True, slots=True)
class MbaMutationReceipt:
    """Post-commit record for one atomic structural mutation batch."""

    kind: StructuralMutationKind
    pre_generation: int
    post_generation: int
    affected_identities: tuple[StableBlockIdentity, ...]
    operation_count: int = 0
    description: str = ""

    def __post_init__(self) -> None:
        pre_generation = int(self.pre_generation)
        post_generation = int(self.post_generation)
        if pre_generation < 0 or post_generation != pre_generation + 1:
            raise ValueError("a mutation receipt must advance exactly one generation")
        if int(self.operation_count) < 0:
            raise ValueError("a mutation receipt cannot have negative operations")
        object.__setattr__(self, "pre_generation", pre_generation)
        object.__setattr__(self, "post_generation", post_generation)
        object.__setattr__(self, "operation_count", int(self.operation_count))
        object.__setattr__(
            self,
            "affected_identities",
            tuple(dict.fromkeys(self.affected_identities)),
        )


@dataclass(frozen=True, slots=True)
class MbaMutationCommitted:
    """Typed observation emitted only after the index has applied a receipt."""

    session_id: str
    function_ea: int
    maturity: int
    mba_generation_before: int
    mba_generation_after: int
    receipt: MbaMutationReceipt


@dataclass(slots=True)
class MbaMutationGateway:
    """The sole control plane for serial shifts in a modifier transaction.

    The SDK mutation happens in the modifier.  Immediately afterwards that
    modifier records the effect here; the index is updated synchronously, so a
    later queued modification cannot observe a stale serial.  The emitted
    event is therefore diagnostic/lineage observation, never delayed routing.
    """

    generation: int = 0
    session_id: str = "mutation-gateway"
    function_ea: int = 0
    maturity: int = 0
    identity_index: MbaBlockIdentityIndex | None = None
    event_emitter: EventEmitter | None = None
    _receipts: list[MbaMutationReceipt] = field(default_factory=list, repr=False)
    _active_kind: StructuralMutationKind | None = field(default=None, init=False)
    _active_description: str = field(default="", init=False)
    _affected_identities: set[StableBlockIdentity] = field(
        default_factory=set,
        init=False,
        repr=False,
    )
    _operation_count: int = field(default=0, init=False)

    def __post_init__(self) -> None:
        self.generation = int(self.generation)
        self.session_id = str(self.session_id)
        if self.generation < 0 or not self.session_id:
            raise ValueError("mutation gateway requires a session and generation")
        if self.identity_index is None:
            self.identity_index = MbaBlockIdentityIndex(
                session_id=self.session_id,
                generation=self.generation,
            )
        elif self.identity_index.session_id != self.session_id:
            raise ValueError("mutation gateway and identity index sessions differ")
        elif self.identity_index.generation != self.generation:
            raise ValueError("mutation gateway and identity index generations differ")

    @property
    def receipts(self) -> tuple[MbaMutationReceipt, ...]:
        return tuple(self._receipts)

    @property
    def active(self) -> bool:
        return self._active_kind is not None

    def new_transaction(self) -> MbaMutationGateway:
        """Return a fresh batch controller over this current-MBA index.

        A structural operation must own its transaction boundary, while every
        operation in the same live MBA must still resolve through one index.
        The returned gateway shares only that index and observer port; it
        carries neither this gateway's active batch nor its receipt history.
        """
        return MbaMutationGateway(
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
    ) -> None:
        if self.active:
            raise RuntimeError("a structural mutation batch is already active")
        if serial_quantity is not None:
            self.identity_index.begin_transaction(int(serial_quantity))
        self._active_kind = kind
        self._active_description = str(description)
        self._affected_identities.clear()
        self._operation_count = 0

    def _require_active(self) -> None:
        if not self.active:
            raise RuntimeError("structural mutation must be inside a gateway batch")

    def _record_handle(self, handle: MbaBlockHandle | None) -> None:
        if handle is not None and handle.identity is not None:
            self._affected_identities.add(handle.identity)

    def resolve_serial(self, serial: int | None) -> int | None:
        if serial is None:
            return None
        serial = int(serial)
        if not self.active:
            # Planned-coordinate rebinding is transaction-local.  Outside an
            # active batch, callers are describing the current live MBA; a
            # baseline retained by an earlier transaction must not shift it.
            return serial
        baseline_handle = self.identity_index._baseline_tokens.get(serial)
        if baseline_handle is None:
            self.identity_index.ensure_serial_space(serial + 1)
            baseline_handle = self.identity_index._baseline_tokens[serial]
        bound = self.identity_index.resolve(
            self.identity_index._handles_by_token[baseline_handle]
        )
        return None if bound is None else bound.serial

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
            insertion_serial=int(insertion_serial),
            created=created,
            returned_serial=int(returned_serial),
        )
        self._record_handle(created)
        self._operation_count += 1
        return created

    def record_realized_serial(self, *, expected_serial: int, returned_serial: int) -> None:
        self._require_active()
        self.identity_index.record_realized_serial(
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
        self.identity_index.mark_removed(handle)
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
            if source.identity is None
            else self.identity_index.create_native_handle(
                source.identity,
                provenance=source.provenance,
            )
        )
        self.identity_index.record_clone(
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
        self.identity_index.refresh_from_mba(mba)
        self._operation_count += 1

    def commit(self) -> MbaMutationReceipt:
        self._require_active()
        pre_generation = self.identity_index.generation
        post_generation = self.identity_index.advance_generation()
        receipt = MbaMutationReceipt(
            kind=self._active_kind,
            pre_generation=pre_generation,
            post_generation=post_generation,
            affected_identities=tuple(self._affected_identities),
            operation_count=self._operation_count,
            description=self._active_description,
        )
        self.generation = post_generation
        self._receipts.append(receipt)
        self._active_kind = None
        self._active_description = ""
        self._affected_identities.clear()
        self._operation_count = 0
        committed = MbaMutationCommitted(
            session_id=self.session_id,
            function_ea=int(self.function_ea),
            maturity=int(self.maturity),
            mba_generation_before=pre_generation,
            mba_generation_after=post_generation,
            receipt=receipt,
        )
        if self.event_emitter is not None:
            self.event_emitter.emit(MbaMutationCommitted, committed)
        return receipt

    def abort(self) -> None:
        """Forget an uncommitted batch; callers must rebuild after SDK failure."""
        self._active_kind = None
        self._active_description = ""
        self._affected_identities.clear()
        self._operation_count = 0

    def record(
        self,
        kind: StructuralMutationKind,
        *,
        affected_identities: Iterable[StableBlockIdentity] = (),
        description: str = "",
    ) -> MbaMutationReceipt:
        """Record one already-applied structural mutation as a one-op batch."""
        self.begin_batch(kind, description=description)
        self._affected_identities.update(affected_identities)
        self._operation_count = 1
        return self.commit()


__all__ = [
    "MbaMutationCommitted",
    "MbaMutationGateway",
    "MbaMutationReceipt",
    "StructuralMutationKind",
]
