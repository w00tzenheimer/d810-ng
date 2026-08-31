"""Acceptance coverage for the Eid native-bound transition fixture."""

from __future__ import annotations

import re

import pytest

import d810.passes.driver as driver_module
from d810.testing.runner import run_deobfuscation_test
from tests.system.cases.libobfuscated_comprehensive import DAC_MASM_CASES


_FUNCTION = "Eid_ShowErrorAndTerminateProcess"
_CASE = next(case for case in DAC_MASM_CASES if case.function == _FUNCTION)
_RECEIPT_IDENTITY = re.compile(
    r"fact_id=.*:state=0x(?P<state>[0-9A-Fa-f]+):target=.*"
    r":resolver=(?P<resolver>[A-Za-z0-9_]+)\b"
)


@pytest.mark.usefixtures("configure_hexrays")
class TestNativeBoundTransitionRoutes:
    """Prove all native-bound routes survive real Hex-Rays lowering."""

    binary_name = "libobfuscated.dll"

    def test_fixture_recovers_effect_corridor_and_route_receipts(
        self,
        ida_database,
        d810_state,
        pseudocode_to_string,
        monkeypatch,
    ) -> None:
        del ida_database

        receipt_logger = driver_module.logger
        receipt_messages = []
        original_info = receipt_logger.info

        def capture_info(message, *args, **kwargs):
            if "native-bound transition route receipt:" in str(message):
                receipt_messages.append(
                    str(message) % args if args else str(message)
                )
            return original_info(message, *args, **kwargs)

        monkeypatch.setattr(receipt_logger, "info", capture_info)
        run_deobfuscation_test(
            case=_CASE,
            d810_state=d810_state,
            pseudocode_to_string=pseudocode_to_string,
        )

        # The driver invokes this logger only after the backend reports a
        # committed graph and the route operation key is correlated exactly
        # once; the unit receipt tests cover those inventory gates.
        assert len(receipt_messages) == 3, (
            "expected exactly three native-bound receipt calls, got: "
            f"{receipt_messages}"
        )
        assert len(set(receipt_messages)) == 3, (
            "duplicate native-bound receipt call: "
            f"{receipt_messages}"
        )
        identities = set()
        for message in receipt_messages:
            match = _RECEIPT_IDENTITY.search(message)
            assert match is not None, f"unexpected receipt format: {message}"
            identities.add(
                (
                    int(match.group("state"), 16),
                    match.group("resolver"),
                )
            )

        assert identities == {
            (0x16AA65E9, "interval_dispatcher_row"),
            (0x1939CB36, "interval_dispatcher_row"),
            (0x079323F9, "state_dispatcher_map_exact_row"),
        }
