from __future__ import annotations
import time
from types import MappingProxyType
import pytest
from d810.recon.models import CandidateFlag, ReconResult, DeobfuscationHints


class TestCandidateFlag:
    def test_construction(self):
        flag = CandidateFlag(
            kind="flattened_switch",
            block_serial=3,
            confidence=0.85,
            detail="block 3 has 12 predecessors",
        )
        assert flag.kind == "flattened_switch"
        assert flag.block_serial == 3
        assert flag.confidence == 0.85
        assert flag.detail == "block 3 has 12 predecessors"

    def test_frozen(self):
        flag = CandidateFlag(kind="opaque_predicate", block_serial=0, confidence=0.5, detail="")
        with pytest.raises((AttributeError, TypeError)):
            flag.confidence = 0.9  # type: ignore[misc]

    def test_confidence_bounds(self):
        with pytest.raises(ValueError):
            CandidateFlag(kind="x", block_serial=0, confidence=1.5, detail="")
        with pytest.raises(ValueError):
            CandidateFlag(kind="x", block_serial=0, confidence=-0.1, detail="")


class TestReconResult:
    def test_construction(self):
        flag = CandidateFlag(kind="flattened_switch", block_serial=2, confidence=0.9, detail="d")
        result = ReconResult(
            collector_name="CFGShapeCollector",
            func_ea=0x401000,
            maturity=5,
            timestamp=1_000_000.0,
            metrics=MappingProxyType({"block_count": 20, "edge_count": 25, "flattening_score": 0.72}),
            candidates=(flag,),
        )
        assert result.collector_name == "CFGShapeCollector"
        assert result.func_ea == 0x401000
        assert result.metrics["block_count"] == 20
        assert len(result.candidates) == 1

    def test_frozen(self):
        result = ReconResult(
            collector_name="x", func_ea=0, maturity=0,
            timestamp=0.0, metrics=MappingProxyType({}), candidates=(),
        )
        with pytest.raises((AttributeError, TypeError)):
            result.func_ea = 1  # type: ignore[misc]

    def test_metrics_must_be_mapping_proxy(self):
        with pytest.raises(TypeError):
            ReconResult(
                collector_name="x", func_ea=0, maturity=0,
                timestamp=0.0, metrics={"raw": 1},  # type: ignore[arg-type]
                candidates=(),
            )


class TestDeobfuscationHints:
    def test_construction_no_obfuscation(self):
        hints = DeobfuscationHints(
            func_ea=0x402000,
            obfuscation_type=None,
            confidence=0.0,
            recommended_recipes=(),
            candidates=(),
            suppress_rules=(),
        )
        assert hints.obfuscation_type is None
        assert hints.confidence == 0.0
        assert hints.recommended_recipes == ()

    def test_construction_with_obfuscation(self):
        hints = DeobfuscationHints(
            func_ea=0x403000,
            obfuscation_type="ollvm_flat",
            confidence=0.85,
            recommended_recipes=("unflattening_recipe", "mba_recipe"),
            candidates=(),
            suppress_rules=("SlowRule",),
        )
        assert hints.obfuscation_type == "ollvm_flat"
        assert "unflattening_recipe" in hints.recommended_recipes
        assert "SlowRule" in hints.suppress_rules

    def test_frozen(self):
        hints = DeobfuscationHints(
            func_ea=0, obfuscation_type=None, confidence=0.0,
            recommended_recipes=(), candidates=(), suppress_rules=(),
        )
        with pytest.raises((AttributeError, TypeError)):
            hints.func_ea = 1  # type: ignore[misc]
