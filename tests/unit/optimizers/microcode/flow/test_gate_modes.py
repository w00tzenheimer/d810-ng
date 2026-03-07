"""Unit tests for GateOperationMode contract."""
from __future__ import annotations

import pytest

from d810.core.gate_modes import GateOperationMode


class TestGateOperationModeEnum:
    """Verify the enum has exactly the expected members and semantics."""

    def test_has_exactly_three_members(self) -> None:
        assert len(GateOperationMode) == 3

    def test_member_values(self) -> None:
        assert GateOperationMode.COLLECT_ONLY.value == "collect_only"
        assert GateOperationMode.GATE_ONLY.value == "gate_only"
        assert GateOperationMode.GATE_SELECT.value == "gate_select"

    def test_is_str_enum(self) -> None:
        # GateOperationMode(str, Enum) — values are usable as strings
        assert isinstance(GateOperationMode.COLLECT_ONLY, str)
        assert GateOperationMode.GATE_ONLY == "gate_only"


class TestEnforcesGateProperty:
    """COLLECT_ONLY skips enforcement; GATE_ONLY and GATE_SELECT enforce."""

    def test_collect_only_does_not_enforce(self) -> None:
        assert GateOperationMode.COLLECT_ONLY.enforces_gate is False

    def test_gate_only_enforces(self) -> None:
        assert GateOperationMode.GATE_ONLY.enforces_gate is True

    def test_gate_select_enforces(self) -> None:
        assert GateOperationMode.GATE_SELECT.enforces_gate is True


class TestInfluencesPlannerProperty:
    """Only GATE_SELECT feeds into planner/strategy selection."""

    def test_collect_only_no_planner(self) -> None:
        assert GateOperationMode.COLLECT_ONLY.influences_planner is False

    def test_gate_only_no_planner(self) -> None:
        assert GateOperationMode.GATE_ONLY.influences_planner is False

    def test_gate_select_influences_planner(self) -> None:
        assert GateOperationMode.GATE_SELECT.influences_planner is True


class TestModeConstructionFromString:
    """Modes can be constructed from their string values."""

    @pytest.mark.parametrize(
        "value,expected",
        [
            ("collect_only", GateOperationMode.COLLECT_ONLY),
            ("gate_only", GateOperationMode.GATE_ONLY),
            ("gate_select", GateOperationMode.GATE_SELECT),
        ],
    )
    def test_from_string(self, value: str, expected: GateOperationMode) -> None:
        assert GateOperationMode(value) is expected

    def test_invalid_string_raises(self) -> None:
        with pytest.raises(ValueError):
            GateOperationMode("invalid_mode")


class TestModeSemanticsMatrix:
    """End-to-end semantics matrix from the design spec."""

    @pytest.mark.parametrize(
        "mode,recon,enforcement,planner",
        [
            (GateOperationMode.COLLECT_ONLY, True, False, False),
            (GateOperationMode.GATE_ONLY, True, True, False),
            (GateOperationMode.GATE_SELECT, True, True, True),
        ],
    )
    def test_semantics_matrix(
        self,
        mode: GateOperationMode,
        recon: bool,
        enforcement: bool,
        planner: bool,
    ) -> None:
        # Recon collection is always True (all modes run analysis)
        assert recon is True
        assert mode.enforces_gate is enforcement
        assert mode.influences_planner is planner
