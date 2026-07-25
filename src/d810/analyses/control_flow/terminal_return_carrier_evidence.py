"""Portable proof of one terminal ABI return-value carrier.

The early Hex-Rays adapter may observe a return-register assignment that later
maturities discard.  This module retains only the semantic operation, stable
value identity, and native proof coordinates needed by canonical lowering.  It
intentionally carries no live ``minsn_t``, ``mop_t``, MBA, or block serial.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum

from d810.analyses.control_flow.materialized_indirect_transfer import (
    TerminalReturnCarrierRequest,
)
from d810.core.native_preanalysis_key import NativePreanalysisKey
from d810.ir.block_identity import StableBlockIdentity
from d810.ir.expressions import ValueOpKind
from d810.ir.storage_identity import StorageIdentity, StorageIdentityKind


_BADADDR = 0xFFFFFFFFFFFFFFFF


class TerminalReturnCarrierEvidenceRejected(ValueError):
    """Terminal carrier evidence is incomplete or not portable."""


class TerminalReturnCarrierSourceKind(str, Enum):
    """Portable shape of the value assigned to the ABI return result."""

    CONSTANT = "constant"
    STORAGE_VALUE = "storage_value"
    ADDRESS_OF_STORAGE = "address_of_storage"


def _native_ea(value: int, description: str) -> int:
    normalized = int(value)
    if not 0 < normalized < _BADADDR:
        raise TerminalReturnCarrierEvidenceRejected(
            f"{description} must be a native EA"
        )
    return normalized


@dataclass(frozen=True, slots=True)
class TerminalReturnCarrierSource:
    """One portable source value for a terminal return assignment."""

    kind: TerminalReturnCarrierSourceKind
    width: int
    storage_identity: StorageIdentity | None = None
    constant: int | None = None

    def __post_init__(self) -> None:
        if not isinstance(self.kind, TerminalReturnCarrierSourceKind):
            raise TypeError(
                "terminal return carrier source requires a typed source kind"
            )
        width = int(self.width)
        if not 1 <= width <= 8:
            raise TerminalReturnCarrierEvidenceRejected(
                "terminal return carrier source width must be 1..8 bytes"
            )
        storage_identity = self.storage_identity
        constant = self.constant
        if self.kind is TerminalReturnCarrierSourceKind.CONSTANT:
            if storage_identity is not None:
                raise TerminalReturnCarrierEvidenceRejected(
                    "constant terminal carrier source cannot name storage"
                )
            if constant is None or not 0 <= int(constant) < (1 << (width * 8)):
                raise TerminalReturnCarrierEvidenceRejected(
                    "terminal carrier constant must fit its source width"
                )
            constant = int(constant)
        else:
            if not isinstance(storage_identity, StorageIdentity):
                raise TerminalReturnCarrierEvidenceRejected(
                    "storage terminal carrier source requires stable storage identity"
                )
            if storage_identity.kind not in {
                StorageIdentityKind.STACK,
                StorageIdentityKind.GLOBAL,
            }:
                raise TerminalReturnCarrierEvidenceRejected(
                    "terminal carrier source supports only stable stack or global storage"
                )
            if int(storage_identity.offset) < 0:
                raise TerminalReturnCarrierEvidenceRejected(
                    "terminal carrier storage offset must be non-negative"
                )
            if constant is not None:
                raise TerminalReturnCarrierEvidenceRejected(
                    "storage terminal carrier source cannot carry a constant"
                )
        object.__setattr__(self, "width", width)
        object.__setattr__(self, "constant", constant)


@dataclass(frozen=True, slots=True)
class TerminalReturnCarrierEvidence:
    """Exact portable semantics captured for one proven terminal state."""

    request: TerminalReturnCarrierRequest
    capture_identity: StableBlockIdentity
    terminal_identity: StableBlockIdentity
    state_write_ea: int
    carrier_ea: int
    terminal_return_ea: int
    operation: ValueOpKind
    source: TerminalReturnCarrierSource
    return_width: int
    corridor_instruction_eas: tuple[int, ...]

    def __post_init__(self) -> None:
        if not isinstance(self.request, TerminalReturnCarrierRequest):
            raise TypeError(
                "terminal return carrier evidence requires its typed request"
            )
        if not isinstance(self.capture_identity, StableBlockIdentity) or not isinstance(
            self.terminal_identity,
            StableBlockIdentity,
        ):
            raise TypeError(
                "terminal return carrier evidence requires stable block identities"
            )
        if self.capture_identity.native_key != self.terminal_identity.native_key:
            raise TerminalReturnCarrierEvidenceRejected(
                "terminal carrier identities require one native key"
            )

        source_handler_ea = _native_ea(
            self.request.source_handler_ea,
            "terminal carrier source handler",
        )
        terminal_target_ea = _native_ea(
            self.request.terminal_target_ea,
            "terminal carrier target",
        )
        if not self.capture_identity.native_ranges.contains(source_handler_ea):
            raise TerminalReturnCarrierEvidenceRejected(
                "source handler is outside its capture identity"
            )
        if source_handler_ea not in self.capture_identity.exact_instruction_eas:
            raise TerminalReturnCarrierEvidenceRejected(
                "source handler is not an exact instruction in its capture identity"
            )
        if not self.terminal_identity.native_ranges.contains(terminal_target_ea):
            raise TerminalReturnCarrierEvidenceRejected(
                "terminal target is outside its terminal identity"
            )
        if terminal_target_ea not in self.terminal_identity.exact_instruction_eas:
            raise TerminalReturnCarrierEvidenceRejected(
                "terminal target is not an exact instruction in its terminal identity"
            )
        if int(self.request.state_var_reg) < 0:
            raise TerminalReturnCarrierEvidenceRejected(
                "terminal carrier state register must be non-negative"
            )
        if not 0 <= int(self.request.state_constant) < (1 << 32):
            raise TerminalReturnCarrierEvidenceRejected(
                "terminal carrier state constant must fit 32 bits"
            )

        state_write_ea = _native_ea(
            self.state_write_ea,
            "terminal carrier state-write anchor",
        )
        carrier_ea = _native_ea(
            self.carrier_ea,
            "terminal carrier anchor",
        )
        terminal_return_ea = _native_ea(
            self.terminal_return_ea,
            "terminal return instruction",
        )
        if not self.capture_identity.native_ranges.contains(state_write_ea):
            raise TerminalReturnCarrierEvidenceRejected(
                "state-write anchor is outside its capture identity"
            )
        if state_write_ea not in self.capture_identity.exact_instruction_eas:
            raise TerminalReturnCarrierEvidenceRejected(
                "state-write anchor is not an exact instruction in its capture identity"
            )
        if not self.capture_identity.native_ranges.contains(carrier_ea):
            raise TerminalReturnCarrierEvidenceRejected(
                "carrier anchor is outside its capture identity"
            )
        if carrier_ea not in self.capture_identity.exact_instruction_eas:
            raise TerminalReturnCarrierEvidenceRejected(
                "carrier anchor is not an exact instruction in its capture identity"
            )
        if carrier_ea == state_write_ea:
            raise TerminalReturnCarrierEvidenceRejected(
                "terminal state write and carrier require distinct anchors"
            )
        if not self.terminal_identity.native_ranges.contains(terminal_return_ea):
            raise TerminalReturnCarrierEvidenceRejected(
                "terminal return instruction is outside its terminal identity"
            )
        if terminal_return_ea not in self.terminal_identity.exact_instruction_eas:
            raise TerminalReturnCarrierEvidenceRejected(
                "terminal return instruction is not an exact instruction "
                "in its terminal identity"
            )

        if self.operation not in {
            ValueOpKind.MOVE,
            ValueOpKind.ZEXT,
            ValueOpKind.SEXT,
        }:
            raise TerminalReturnCarrierEvidenceRejected(
                "terminal carrier operation must be move, zero-extension, or sign-extension"
            )
        if not isinstance(self.source, TerminalReturnCarrierSource):
            raise TypeError("terminal return carrier requires a portable source")
        return_width = int(self.return_width)
        if not 1 <= return_width <= 8:
            raise TerminalReturnCarrierEvidenceRejected(
                "terminal return width must be 1..8 bytes"
            )
        if self.operation is ValueOpKind.MOVE and self.source.width != return_width:
            raise TerminalReturnCarrierEvidenceRejected(
                "terminal move source and result widths must match"
            )
        if self.operation in {ValueOpKind.ZEXT, ValueOpKind.SEXT} and not (
            self.source.width < return_width
        ):
            raise TerminalReturnCarrierEvidenceRejected(
                "terminal extension must widen its source"
            )

        corridor = tuple(
            _native_ea(ea, "terminal carrier corridor anchor")
            for ea in self.corridor_instruction_eas
        )
        if (
            len(corridor) < 2
            or corridor[0] != state_write_ea
            or corridor[-1] != carrier_ea
            or len(set(corridor)) != len(corridor)
        ):
            raise TerminalReturnCarrierEvidenceRejected(
                "terminal carrier corridor must run uniquely from state write to carrier"
            )
        if any(not self.capture_identity.native_ranges.contains(ea) for ea in corridor):
            raise TerminalReturnCarrierEvidenceRejected(
                "terminal carrier corridor escaped its capture identity"
            )
        if any(
            ea not in self.capture_identity.exact_instruction_eas for ea in corridor
        ):
            raise TerminalReturnCarrierEvidenceRejected(
                "terminal carrier corridor contains a non-exact instruction anchor"
            )

        object.__setattr__(self, "state_write_ea", state_write_ea)
        object.__setattr__(self, "carrier_ea", carrier_ea)
        object.__setattr__(self, "terminal_return_ea", terminal_return_ea)
        object.__setattr__(self, "return_width", return_width)
        object.__setattr__(self, "corridor_instruction_eas", corridor)

    @property
    def native_key(self) -> NativePreanalysisKey:
        return self.capture_identity.native_key

    def diagnostic_payload(self, *, generation: int) -> dict[str, object]:
        """Return the complete portable carrier in DB-queryable coordinates."""
        storage = self.source.storage_identity
        return {
            "generation": int(generation),
            "source_handler_ea": f"0x{int(self.request.source_handler_ea):X}",
            "terminal_target_ea": f"0x{int(self.request.terminal_target_ea):X}",
            "state_var_reg": int(self.request.state_var_reg),
            "state_constant": f"0x{int(self.request.state_constant):X}",
            "state_write_ea": f"0x{self.state_write_ea:X}",
            "carrier_ea": f"0x{self.carrier_ea:X}",
            "terminal_return_ea": f"0x{self.terminal_return_ea:X}",
            "operation": self.operation.value,
            "source_kind": self.source.kind.value,
            "source_width": self.source.width,
            "source_storage": None if storage is None else storage.to_record(),
            "source_constant": self.source.constant,
            "return_width": self.return_width,
            "corridor_instruction_eas": [
                f"0x{ea:X}" for ea in self.corridor_instruction_eas
            ],
        }


__all__ = [
    "TerminalReturnCarrierEvidence",
    "TerminalReturnCarrierEvidenceRejected",
    "TerminalReturnCarrierSource",
    "TerminalReturnCarrierSourceKind",
]
