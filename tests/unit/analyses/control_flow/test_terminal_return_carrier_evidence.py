"""Portable terminal-return carrier evidence invariants."""

from __future__ import annotations

import importlib

import pytest

from d810.analyses.control_flow.materialized_indirect_transfer import (
    TerminalReturnCarrierRequest,
)
from d810.ir.block_identity import NativeEaInterval, StableBlockIdentity
from d810.ir.expressions import ValueOpKind
from d810.ir.storage_identity import StorageIdentity, StorageIdentityKind
from tests.native_preanalysis import make_native_key


NATIVE_KEY = make_native_key()


def _carrier_types():
    module = importlib.import_module(
        "d810.analyses.control_flow.terminal_return_carrier_evidence"
    )
    return (
        module.TerminalReturnCarrierEvidence,
        module.TerminalReturnCarrierEvidenceRejected,
        module.TerminalReturnCarrierSource,
        module.TerminalReturnCarrierSourceKind,
    )


def _identity(
    start_ea: int,
    end_ea: int,
    *exact_instruction_eas: int,
) -> StableBlockIdentity:
    return StableBlockIdentity.from_intervals(
        (NativeEaInterval(start_ea, end_ea),),
        native_key=NATIVE_KEY,
        exact_instruction_eas=exact_instruction_eas,
    )


def _request() -> TerminalReturnCarrierRequest:
    return TerminalReturnCarrierRequest(
        source_handler_ea=0x401000,
        terminal_target_ea=0x402000,
        state_var_reg=20,
        state_constant=0x19A7218A,
    )


def test_terminal_return_carrier_is_portable_exact_evidence() -> None:
    (
        TerminalReturnCarrierEvidence,
        _TerminalReturnCarrierEvidenceRejected,
        TerminalReturnCarrierSource,
        TerminalReturnCarrierSourceKind,
    ) = _carrier_types()
    capture_identity = _identity(0x401000, 0x401010, 0x401000, 0x401005)
    terminal_identity = _identity(0x402000, 0x402010, 0x402000, 0x402008)
    source = TerminalReturnCarrierSource(
        kind=TerminalReturnCarrierSourceKind.STORAGE_VALUE,
        width=4,
        storage_identity=StorageIdentity(
            StorageIdentityKind.GLOBAL,
            0x48B8A4,
        ),
    )

    evidence = TerminalReturnCarrierEvidence(
        request=_request(),
        capture_identity=capture_identity,
        terminal_identity=terminal_identity,
        state_write_ea=0x401000,
        carrier_ea=0x401005,
        terminal_return_ea=0x402008,
        operation=ValueOpKind.MOVE,
        source=source,
        return_width=4,
        corridor_instruction_eas=(0x401000, 0x401005),
    )

    assert evidence.native_key == NATIVE_KEY
    assert evidence.source.storage_identity == StorageIdentity(
        StorageIdentityKind.GLOBAL,
        0x48B8A4,
    )
    assert evidence.diagnostic_payload(generation=7) == {
        "generation": 7,
        "source_handler_ea": "0x401000",
        "terminal_target_ea": "0x402000",
        "state_var_reg": 20,
        "state_constant": "0x19A7218A",
        "state_write_ea": "0x401000",
        "carrier_ea": "0x401005",
        "terminal_return_ea": "0x402008",
        "operation": "move",
        "source_kind": "storage_value",
        "source_width": 4,
        "source_storage": {
            "kind": "global",
            "prefix": "v",
            "offset": 0x48B8A4,
            "key": f"v{0x48B8A4}",
        },
        "source_constant": None,
        "return_width": 4,
        "corridor_instruction_eas": ["0x401000", "0x401005"],
    }


def test_terminal_return_carrier_uses_stable_stack_identity_for_extension() -> None:
    (
        TerminalReturnCarrierEvidence,
        _TerminalReturnCarrierEvidenceRejected,
        TerminalReturnCarrierSource,
        TerminalReturnCarrierSourceKind,
    ) = _carrier_types()
    source = TerminalReturnCarrierSource(
        kind=TerminalReturnCarrierSourceKind.STORAGE_VALUE,
        width=1,
        storage_identity=StorageIdentity(StorageIdentityKind.STACK, 0x1010),
    )

    evidence = TerminalReturnCarrierEvidence(
        request=_request(),
        capture_identity=_identity(0x401000, 0x401010, 0x401000, 0x401005),
        terminal_identity=_identity(0x402000, 0x402010, 0x402000),
        state_write_ea=0x401000,
        carrier_ea=0x401005,
        terminal_return_ea=0x402000,
        operation=ValueOpKind.ZEXT,
        source=source,
        return_width=4,
        corridor_instruction_eas=(0x401000, 0x401005),
    )

    assert evidence.source.storage_identity == StorageIdentity(
        StorageIdentityKind.STACK,
        0x1010,
    )


def test_terminal_return_carrier_rejects_unowned_exact_anchor() -> None:
    (
        TerminalReturnCarrierEvidence,
        TerminalReturnCarrierEvidenceRejected,
        TerminalReturnCarrierSource,
        TerminalReturnCarrierSourceKind,
    ) = _carrier_types()

    with pytest.raises(
        TerminalReturnCarrierEvidenceRejected,
        match="carrier anchor is outside its capture identity",
    ):
        TerminalReturnCarrierEvidence(
            request=_request(),
            capture_identity=_identity(0x401000, 0x401004, 0x401000),
            terminal_identity=_identity(0x402000, 0x402010, 0x402000),
            state_write_ea=0x401000,
            carrier_ea=0x401005,
            terminal_return_ea=0x402000,
            operation=ValueOpKind.MOVE,
            source=TerminalReturnCarrierSource(
                kind=TerminalReturnCarrierSourceKind.CONSTANT,
                width=4,
                constant=7,
            ),
            return_width=4,
            corridor_instruction_eas=(0x401000, 0x401005),
        )


def test_terminal_return_carrier_rejects_anchor_without_exact_identity() -> None:
    (
        TerminalReturnCarrierEvidence,
        TerminalReturnCarrierEvidenceRejected,
        TerminalReturnCarrierSource,
        TerminalReturnCarrierSourceKind,
    ) = _carrier_types()

    with pytest.raises(
        TerminalReturnCarrierEvidenceRejected,
        match="carrier anchor is not an exact instruction",
    ):
        TerminalReturnCarrierEvidence(
            request=_request(),
            capture_identity=_identity(0x401000, 0x401010, 0x401000),
            terminal_identity=_identity(0x402000, 0x402010, 0x402000),
            state_write_ea=0x401000,
            carrier_ea=0x401005,
            terminal_return_ea=0x402000,
            operation=ValueOpKind.MOVE,
            source=TerminalReturnCarrierSource(
                kind=TerminalReturnCarrierSourceKind.CONSTANT,
                width=4,
                constant=7,
            ),
            return_width=4,
            corridor_instruction_eas=(0x401000, 0x401005),
        )


def test_terminal_return_carrier_rejects_non_materializable_operation() -> None:
    (
        TerminalReturnCarrierEvidence,
        TerminalReturnCarrierEvidenceRejected,
        TerminalReturnCarrierSource,
        TerminalReturnCarrierSourceKind,
    ) = _carrier_types()

    with pytest.raises(
        TerminalReturnCarrierEvidenceRejected,
        match="move, zero-extension, or sign-extension",
    ):
        TerminalReturnCarrierEvidence(
            request=_request(),
            capture_identity=_identity(0x401000, 0x401010, 0x401000, 0x401005),
            terminal_identity=_identity(0x402000, 0x402010, 0x402000),
            state_write_ea=0x401000,
            carrier_ea=0x401005,
            terminal_return_ea=0x402000,
            operation=ValueOpKind.ADD,
            source=TerminalReturnCarrierSource(
                kind=TerminalReturnCarrierSourceKind.CONSTANT,
                width=4,
                constant=7,
            ),
            return_width=4,
            corridor_instruction_eas=(0x401000, 0x401005),
        )
