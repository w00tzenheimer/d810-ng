"""Portable evidence records for exact dead-store elimination."""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum

from d810.ir.storage_identity import StorageIdentity, StorageIdentityKind

__all__ = [
    "DeadStoreCandidate",
    "DeadStoreEvidence",
    "DeadStoreRejection",
    "DeadStoreRejectionReason",
]


class DeadStoreRejectionReason(Enum):
    """Stable fail-closed outcomes emitted by a live evidence provider."""

    WRONG_MATURITY = "wrong_maturity"
    UNSUPPORTED_DESTINATION = "unsupported_destination"
    PARTIAL_DEFINITION = "partial_definition"
    EFFECTFUL_RHS = "effectful_rhs"
    AMBIGUOUS_DEFINITION = "ambiguous_definition"
    CHAIN_UNAVAILABLE = "chain_unavailable"
    REACHED_USE = "reached_use"
    RETURN_CARRIER = "return_carrier"
    ALIASED_STORAGE = "aliased_storage"
    NODEL_STORAGE = "nodel_storage"
    ALIAS_INFORMATION_UNAVAILABLE = "alias_information_unavailable"


@dataclass(frozen=True, slots=True)
class DeadStoreCandidate:
    """One exact scalar definition proven to have no observable use."""

    block_serial: int
    block_start_ea: int
    insn_ea: int
    ordinal: int
    opcode: int
    destination: StorageIdentity
    destination_width: int

    def __post_init__(self) -> None:
        if self.block_serial < 0 or self.ordinal < 0:
            raise ValueError("dead-store coordinates must be non-negative")
        if self.block_start_ea < 0 or self.insn_ea < 0:
            raise ValueError("dead-store EA anchors must be non-negative")
        if self.destination_width <= 0:
            raise ValueError("destination_width must be positive")
        if self.destination.kind not in {
            StorageIdentityKind.REGISTER,
            StorageIdentityKind.STACK,
        }:
            raise ValueError("dead-store destination must be register or stack")

    @property
    def destination_kind(self) -> str:
        return (
            "register"
            if self.destination.kind is StorageIdentityKind.REGISTER
            else "stack"
        )

    @property
    def destination_id(self) -> int:
        return int(self.destination.offset)

    @property
    def destination_size(self) -> int:
        return int(self.destination_width)


@dataclass(frozen=True, slots=True)
class DeadStoreRejection:
    """One considered definition that was not safe to remove."""

    block_serial: int
    block_start_ea: int
    insn_ea: int
    reason: DeadStoreRejectionReason
    detail: str = ""
    ordinal: int = -1
    opcode: int = -1
    destination: StorageIdentity | None = None
    destination_width: int = 0
    use_block_serial: int | None = None
    use_block_start_ea: int | None = None
    use_insn_ea: int | None = None
    use_ordinal: int | None = None
    use_opcode: int | None = None
    use_operand_path: str = ""
    use_kind: str = ""

    @property
    def destination_kind(self) -> str | None:
        if self.destination is None:
            return None
        return (
            "register"
            if self.destination.kind is StorageIdentityKind.REGISTER
            else "stack"
        )

    @property
    def destination_id(self) -> int | None:
        return None if self.destination is None else int(self.destination.offset)


@dataclass(frozen=True, slots=True)
class DeadStoreEvidence:
    """Complete result from one dead-store evidence provider invocation."""

    candidates: tuple[DeadStoreCandidate, ...] = ()
    rejections: tuple[DeadStoreRejection, ...] = ()
    authoritative: bool = False
