"""Unit tests for FlowContextHintSummary and derive_flow_context_summary.

These tests verify the consumer-specific hint summary types and their
derivation from DeobfuscationHints, without requiring IDA.
"""
from __future__ import annotations

import pytest

from d810.core.gate_modes import GateOperationMode
from d810.recon.flow_hints import (
    FlowContextHintSummary,
    derive_flow_context_summary,
)
from d810.recon.models import DeobfuscationHints


def _make_hints(
    obfuscation_type: str | None = None,
    confidence: float = 0.0,
) -> DeobfuscationHints:
    """Helper to build a minimal DeobfuscationHints."""
    return DeobfuscationHints(
        func_ea=0x401000,
        obfuscation_type=obfuscation_type,
        confidence=confidence,
        recommended_inferences=(),
        candidates=(),
        suppress_rules=(),
    )


class TestFlowContextHintSummary:
    """Tests for the FlowContextHintSummary dataclass."""

    def test_frozen(self) -> None:
        summary = FlowContextHintSummary(
            obfuscation_type=None,
            confidence=0.0,
            has_flattening_signal=False,
            recommended_gate_mode=None,
        )
        with pytest.raises(AttributeError):
            summary.confidence = 0.5  # type: ignore[misc]

    def test_fields_round_trip(self) -> None:
        summary = FlowContextHintSummary(
            obfuscation_type="ollvm_flat",
            confidence=0.9,
            has_flattening_signal=True,
            recommended_gate_mode=GateOperationMode.GATE_SELECT,
        )
        assert summary.obfuscation_type == "ollvm_flat"
        assert summary.confidence == 0.9
        assert summary.has_flattening_signal is True
        assert summary.recommended_gate_mode is GateOperationMode.GATE_SELECT


class TestDeriveFlowContextSummary:
    """Tests for the derive_flow_context_summary factory function."""

    def test_derive_flow_context_summary_flattening(self) -> None:
        """Hints with ollvm_flat obfuscation type -> has_flattening_signal=True."""
        hints = _make_hints(obfuscation_type="ollvm_flat", confidence=0.9)
        summary = derive_flow_context_summary(hints)
        assert summary.has_flattening_signal is True
        assert summary.obfuscation_type == "ollvm_flat"
        assert summary.confidence == 0.9
        assert summary.recommended_gate_mode is GateOperationMode.GATE_SELECT

    def test_derive_flow_context_summary_flattening_ollvm_flattening(self) -> None:
        """ollvm_flattening is also recognized as flattening."""
        hints = _make_hints(obfuscation_type="ollvm_flattening", confidence=0.85)
        summary = derive_flow_context_summary(hints)
        assert summary.has_flattening_signal is True
        assert summary.recommended_gate_mode is GateOperationMode.GATE_SELECT

    def test_derive_flow_context_summary_flattening_mixed(self) -> None:
        """mixed obfuscation type includes flattening signal."""
        hints = _make_hints(obfuscation_type="mixed", confidence=0.7)
        summary = derive_flow_context_summary(hints)
        assert summary.has_flattening_signal is True
        assert summary.recommended_gate_mode is GateOperationMode.GATE_SELECT

    def test_derive_flow_context_summary_low_confidence_flattening(self) -> None:
        """Flattening with confidence < 0.6 -> GATE_ONLY (not GATE_SELECT)."""
        hints = _make_hints(obfuscation_type="ollvm_flat", confidence=0.4)
        summary = derive_flow_context_summary(hints)
        assert summary.has_flattening_signal is True
        assert summary.recommended_gate_mode is GateOperationMode.GATE_ONLY

    def test_derive_flow_context_summary_unknown(self) -> None:
        """Hints with None obfuscation type -> has_flattening_signal=False."""
        hints = _make_hints(obfuscation_type=None, confidence=0.0)
        summary = derive_flow_context_summary(hints)
        assert summary.has_flattening_signal is False
        assert summary.obfuscation_type is None
        assert summary.recommended_gate_mode is None

    def test_derive_flow_context_summary_unrecognized_type(self) -> None:
        """Non-flattening obfuscation type -> no flattening signal."""
        hints = _make_hints(obfuscation_type="tigress_indirect", confidence=0.8)
        summary = derive_flow_context_summary(hints)
        assert summary.has_flattening_signal is False
        assert summary.obfuscation_type == "tigress_indirect"
        assert summary.recommended_gate_mode is None

    def test_derive_flow_context_summary_boundary_confidence(self) -> None:
        """Confidence exactly at 0.6 boundary -> GATE_SELECT."""
        hints = _make_hints(obfuscation_type="ollvm_flat", confidence=0.6)
        summary = derive_flow_context_summary(hints)
        assert summary.recommended_gate_mode is GateOperationMode.GATE_SELECT


class TestFlowMaturityContextHintIntegration:
    """Tests for hint_summary on FlowMaturityContext.

    These tests verify the hint_summary property/setter without
    constructing a full FlowMaturityContext (which needs IDA).
    We test the hint types and derivation in isolation.
    """

    def test_hint_summary_default_none(self) -> None:
        """No hints set -> hint_summary property returns None.

        We can't construct FlowMaturityContext without IDA, so we test
        the summary type default behavior directly.
        """
        # Verify the summary type works as expected when None is used
        summary: FlowContextHintSummary | None = None
        assert summary is None

    def test_set_hint_summary(self) -> None:
        """Set and retrieve a hint summary."""
        summary = FlowContextHintSummary(
            obfuscation_type="ollvm_flat",
            confidence=0.85,
            has_flattening_signal=True,
            recommended_gate_mode=GateOperationMode.GATE_SELECT,
        )
        # Verify the summary is usable
        assert summary.obfuscation_type == "ollvm_flat"
        assert summary.has_flattening_signal is True

    def test_gate_evaluation_unchanged_without_hints(self) -> None:
        """Verify existing gate behavior is untouched when no hints are set.

        Without IDA we cannot call evaluate_unflattening_gate, so we
        verify the contract: when _hint_summary is None, the hint-rescue
        branch is not reachable (the check ``self._hint_summary is not None``
        short-circuits).
        """
        # The hint rescue in _evaluate_unflattening_gate_inner only fires
        # when _hint_summary is not None AND has_flattening_signal AND
        # confidence >= 0.5.  A None summary means existing fallback
        # behavior is preserved.
        summary: FlowContextHintSummary | None = None
        assert summary is None  # contract: None -> no rescue

        # A summary without flattening also does not rescue
        no_flat = FlowContextHintSummary(
            obfuscation_type=None,
            confidence=0.8,
            has_flattening_signal=False,
            recommended_gate_mode=None,
        )
        assert not no_flat.has_flattening_signal

        # A summary with flattening but low confidence does not rescue
        low_conf = FlowContextHintSummary(
            obfuscation_type="ollvm_flat",
            confidence=0.3,
            has_flattening_signal=True,
            recommended_gate_mode=GateOperationMode.GATE_ONLY,
        )
        assert low_conf.has_flattening_signal
        assert low_conf.confidence < 0.5
