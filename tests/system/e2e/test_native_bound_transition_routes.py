"""Acceptance coverage for the Eidolon native-bound transition fixture."""

from __future__ import annotations

import os

import pytest

import d810.passes.driver as driver_module
from d810.testing.runner import run_deobfuscation_test
from tests.system.cases.libobfuscated_comprehensive import DAC_MASM_CASES


_FUNCTION = "Eidolon_ShowErrorAndTerminateProcess"
_CASE = next(case for case in DAC_MASM_CASES if case.function == _FUNCTION)


@pytest.mark.usefixtures("configure_hexrays")
class TestNativeBoundTransitionRoutes:
    """Prove both native-bound routes survive real Hex-Rays lowering."""

    binary_name = os.environ.get("D810_TEST_BINARY", "libobfuscated_fixturetest.dll")

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

        assert len(receipt_messages) >= 2, (
            "expected one native-bound receipt per route, got: "
            f"{receipt_messages}"
        )
        receipt_text = "\n".join(receipt_messages)
        # The rebuilt PE has a different image base/section layout from the
        # source IDB.  Route-state constants are the stable fixture identity;
        # source EAs remain in each receipt as current-MBA provenance.
        assert "state=0x16AA65E9" in receipt_text
        assert "state=0x079323F9" in receipt_text
