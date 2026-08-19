"""Immutable contracts for deferred hosted-block instruction transactions.

The contracts in this module deliberately separate callback-local evidence from
the live native objects used while a backend applies a batch.  Candidates and
receipts are safe to retain across the callback boundary; materialization
contexts are short-lived borrows owned by the backend.
"""

from __future__ import annotations

from dataclasses import dataclass

from d810.core.typing import Callable, Protocol
from d810.hexrays.mutation.instruction_commit import (
    NativeEpoch,
    fingerprint_minsn,
)
from d810.hexrays.mutation.fragment_publication_lifecycle import (
    NativeMutationQuarantined,
)


def _integer(value: object, name: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise TypeError(f"{name} must be an integer")
    return int(value)


def _non_negative(value: object, name: str) -> int:
    integer = _integer(value, name)
    if integer < 0:
        raise ValueError(f"{name} must be a non-negative integer")
    return integer


def _non_empty_string(value: object, name: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"{name} must be a non-empty string")
    return value


@dataclass(frozen=True, slots=True)
class BlockInstructionAnchor:
    """Snapshot identity for one source instruction in a hosted block."""

    block_serial: int
    block_start_ea: int
    ordinal: int
    instruction_ea: int
    opcode: int
    before_fingerprint: int

    def __post_init__(self) -> None:
        for name in (
            "block_serial",
            "block_start_ea",
            "ordinal",
            "instruction_ea",
            "opcode",
        ):
            object.__setattr__(self, name, _non_negative(getattr(self, name), name))
        # A fingerprint is an opaque hash value.  Python hashes may be negative,
        # so validate its type without imposing a sign that the shared helper
        # does not guarantee.
        object.__setattr__(
            self,
            "before_fingerprint",
            _integer(self.before_fingerprint, "before_fingerprint"),
        )


@dataclass(frozen=True, slots=True)
class AllocatedKreg:
    """Primitive ledger entry for a backend-owned kernel-register allocation."""

    register: int
    size: int

    def __post_init__(self) -> None:
        object.__setattr__(self, "register", _non_negative(self.register, "register"))
        object.__setattr__(self, "size", _non_negative(self.size, "size"))


@dataclass(frozen=True, slots=True)
class MaterializedBlockInstructionEdit:
    """Live objects produced by one materializer after backend preflight."""

    replacement: object
    insert_before: tuple[object, ...] = ()

    def __post_init__(self) -> None:
        if self.replacement is None:
            raise ValueError("replacement is required")
        if not isinstance(self.insert_before, tuple):
            raise TypeError("insert_before must be a tuple")
        if any(instruction is None for instruction in self.insert_before):
            raise ValueError("insert_before cannot contain None")


class BlockInstructionMaterializationContext:
    """Borrowed block/instruction context with a backend-owned kreg port.

    The backend supplies the allocation callback and ledger.  Materializers
    receive this narrow port instead of an MBA allocation authority, and the
    context records every successful register allocation before returning it.
    """

    __slots__ = ("block", "instruction", "_allocate_kreg", "_allocated_kregs")

    def __init__(
        self,
        *,
        block: object,
        instruction: object,
        allocate_kreg: Callable[[int], object | None],
        allocated_kregs: list[AllocatedKreg],
    ) -> None:
        if block is None:
            raise ValueError("block is required")
        if instruction is None:
            raise ValueError("instruction is required")
        if not callable(allocate_kreg):
            raise TypeError("allocate_kreg must be callable")
        if not isinstance(allocated_kregs, list):
            raise TypeError("allocated_kregs must be a list")
        self.block = block
        self.instruction = instruction
        self._allocate_kreg = allocate_kreg
        self._allocated_kregs = allocated_kregs

    def alloc_kreg(self, size: int) -> object | None:
        """Allocate through the backend port and ledger the primitive identity."""

        size = _non_negative(size, "size")
        allocated = self._allocate_kreg(size)
        if allocated is None:
            return None
        register = _non_negative(allocated, "register")
        self._allocated_kregs.append(AllocatedKreg(register=register, size=size))
        return allocated


class BlockInstructionMaterializer(Protocol):
    """Provider that materializes one already-preflighted source instruction."""

    def materialize(
        self,
        context: "BlockInstructionMaterializationContext",
    ) -> MaterializedBlockInstructionEdit | None: ...


@dataclass(frozen=True, slots=True)
class BlockInstructionEditIntent:
    """Detached intent naming one anchored source and its materializer."""

    anchor: BlockInstructionAnchor
    materializer: BlockInstructionMaterializer
    description: str

    def __post_init__(self) -> None:
        if not isinstance(self.anchor, BlockInstructionAnchor):
            raise TypeError("anchor must be a BlockInstructionAnchor")
        if not callable(getattr(self.materializer, "materialize", None)):
            raise TypeError("materializer must provide materialize(context)")
        object.__setattr__(
            self,
            "description",
            _non_empty_string(self.description, "description"),
        )


@dataclass(frozen=True, slots=True)
class BlockInstructionBatchCandidate:
    """Immutable callback-local proposal for one complete instruction batch."""

    edits: tuple[BlockInstructionEditIntent, ...]
    epoch_before: NativeEpoch
    pass_id: str
    stage_id: str
    rule_id: str

    def __post_init__(self) -> None:
        if not isinstance(self.edits, tuple):
            raise TypeError("edits must be a tuple")
        if not self.edits:
            raise ValueError("candidate requires at least one edit")
        for edit in self.edits:
            if not isinstance(edit, BlockInstructionEditIntent):
                raise TypeError("edits must contain BlockInstructionEditIntent values")
        anchors = tuple(edit.anchor for edit in self.edits)
        if len(set(anchors)) != len(anchors):
            raise ValueError("candidate contains a duplicate anchor")
        if not isinstance(self.epoch_before, NativeEpoch):
            raise TypeError("epoch_before must be a NativeEpoch")
        for name in ("pass_id", "stage_id", "rule_id"):
            object.__setattr__(self, name, _non_empty_string(getattr(self, name), name))


@dataclass(frozen=True, slots=True)
class BlockInstructionBatchReceipt:
    """Primitive-only outcome of one hosted-block instruction transaction."""

    committed: bool
    callback_result: int
    applied_edit_count: int
    inserted_instruction_count: int
    epoch_before: NativeEpoch
    epoch_after: NativeEpoch
    reason: str
    pass_id: str
    stage_id: str
    rule_id: str
    mutation_batch_id: str | None

    def __post_init__(self) -> None:
        if not isinstance(self.committed, bool):
            raise TypeError("committed must be a bool")
        callback_result = _non_negative(self.callback_result, "callback_result")
        applied_edit_count = _non_negative(
            self.applied_edit_count,
            "applied_edit_count",
        )
        inserted_instruction_count = _non_negative(
            self.inserted_instruction_count,
            "inserted_instruction_count",
        )
        object.__setattr__(self, "callback_result", callback_result)
        object.__setattr__(self, "applied_edit_count", applied_edit_count)
        object.__setattr__(
            self,
            "inserted_instruction_count",
            inserted_instruction_count,
        )
        if self.committed:
            if callback_result != 1 or applied_edit_count <= 0:
                raise ValueError("receipt counts do not match committed state")
        elif (
            callback_result != 0
            or applied_edit_count != 0
            or inserted_instruction_count != 0
        ):
            raise ValueError("receipt counts do not match rejected state")
        if not isinstance(self.epoch_before, NativeEpoch) or not isinstance(
            self.epoch_after,
            NativeEpoch,
        ):
            raise TypeError("receipt epochs must be NativeEpoch values")
        if self.epoch_after != self.epoch_before:
            raise ValueError("receipt must retain its lifecycle snapshot epoch")
        object.__setattr__(self, "reason", _non_empty_string(self.reason, "reason"))
        for name in ("pass_id", "stage_id", "rule_id"):
            object.__setattr__(self, name, _non_empty_string(getattr(self, name), name))
        if self.mutation_batch_id is not None:
            object.__setattr__(
                self,
                "mutation_batch_id",
                _non_empty_string(self.mutation_batch_id, "mutation_batch_id"),
            )

    def primitive_fields(self) -> dict[str, object]:
        """Return only JSON-safe primitive values for receipts and journals."""

        return {
            "committed": self.committed,
            "callback_result": self.callback_result,
            "applied_edit_count": self.applied_edit_count,
            "inserted_instruction_count": self.inserted_instruction_count,
            "function_ea": self.epoch_before.function_ea,
            "mba_identity": self.epoch_before.mba_identity,
            "maturity": self.epoch_before.maturity,
            "generation_before": self.epoch_before.generation,
            "generation_after": self.epoch_after.generation,
            "reason": self.reason,
            "pass_id": self.pass_id,
            "stage_id": self.stage_id,
            "rule_id": self.rule_id,
            "mutation_batch_id": self.mutation_batch_id,
        }


class HexRaysBlockInstructionCommitter:
    """Admission boundary for one DGM-owned hosted block instruction batch."""

    def __init__(
        self,
        *,
        lifecycle_authority: object | None = None,
        epoch_provider: Callable[[object], NativeEpoch] | None = None,
    ) -> None:
        self._lifecycle_authority = lifecycle_authority
        self._epoch_provider = epoch_provider

    @staticmethod
    def _rejected(
        candidate: BlockInstructionBatchCandidate,
        reason: str,
    ) -> BlockInstructionBatchReceipt:
        return BlockInstructionBatchReceipt(
            committed=False,
            callback_result=0,
            applied_edit_count=0,
            inserted_instruction_count=0,
            epoch_before=candidate.epoch_before,
            epoch_after=candidate.epoch_before,
            reason=reason,
            pass_id=candidate.pass_id,
            stage_id=candidate.stage_id,
            rule_id=candidate.rule_id,
            mutation_batch_id=None,
        )

    def commit(
        self,
        *,
        block: object,
        candidate: BlockInstructionBatchCandidate,
        modifier: object,
    ) -> BlockInstructionBatchReceipt:
        """Admit a batch and delegate all live writes to the DGM."""

        if block is None:
            return self._rejected(candidate, "block-context-required")
        mba = getattr(block, "mba", None)
        if mba is None:
            return self._rejected(candidate, "stale-epoch")
        authority = self._lifecycle_authority
        quarantined = getattr(authority, "native_mutation_quarantined", False)
        if callable(quarantined):
            quarantined = quarantined()
        if quarantined:
            return self._rejected(candidate, "native-mutation-quarantined")
        if self._epoch_provider is None:
            # A callback-local candidate cannot manufacture the lifecycle
            # generation it claims. Only the adapter has that provenance.
            return self._rejected(candidate, "epoch-context-required")
        current_epoch = self._epoch_provider(block)
        if not isinstance(current_epoch, NativeEpoch):
            raise TypeError("epoch_provider must return NativeEpoch")
        if current_epoch != candidate.epoch_before:
            return self._rejected(candidate, "stale-epoch")
        configure = getattr(modifier, "configure_instruction_batch_lifecycle", None)
        if callable(configure):
            configure(authority)
        configure_epoch = getattr(modifier, "configure_instruction_batch_epoch", None)
        if callable(configure_epoch):
            configure_epoch(current_epoch)
        queue = getattr(modifier, "queue_instruction_rewrite_batch", None)
        apply = getattr(modifier, "apply_instruction_rewrite_batch", None)
        if not callable(queue) or not callable(apply):
            raise TypeError("modifier does not support hosted instruction batches")
        queue(candidate)
        try:
            return apply()
        except NativeMutationQuarantined:
            raise


__all__ = [
    "AllocatedKreg",
    "BlockInstructionAnchor",
    "BlockInstructionBatchCandidate",
    "BlockInstructionBatchReceipt",
    "BlockInstructionEditIntent",
    "BlockInstructionMaterializationContext",
    "BlockInstructionMaterializer",
    "HexRaysBlockInstructionCommitter",
    "MaterializedBlockInstructionEdit",
    "fingerprint_minsn",
]
