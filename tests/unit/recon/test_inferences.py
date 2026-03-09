"""Tests for built-in inference factories."""
from __future__ import annotations

from d810.recon.inferences import unflattening_inference
from d810.recon.models import DeobfuscationHints


class TestUnflatteningInference:
    def _make_hints(self, confidence: float, obfuscation_type: str | None = None) -> DeobfuscationHints:
        return DeobfuscationHints(
            func_ea=0x1000,
            obfuscation_type=obfuscation_type,
            confidence=confidence,
            recommended_inferences=("unflattening",),
            candidates=(),
            suppress_rules=(),
        )

    def test_high_confidence_suppresses_constant_folding(self) -> None:
        hints = self._make_hints(confidence=0.8)
        deltas = unflattening_inference(hints)
        assert any(d.rule_name == "ConstantFolding" and d.action == "suppress" for d in deltas)

    def test_low_confidence_no_deltas(self) -> None:
        hints = self._make_hints(confidence=0.3)
        deltas = unflattening_inference(hints)
        assert len(deltas) == 0

    def test_threshold_boundary(self) -> None:
        hints = self._make_hints(confidence=0.7)
        deltas = unflattening_inference(hints)
        assert any(d.rule_name == "ConstantFolding" and d.action == "suppress" for d in deltas)

    def test_just_below_threshold(self) -> None:
        hints = self._make_hints(confidence=0.69)
        deltas = unflattening_inference(hints)
        assert len(deltas) == 0
