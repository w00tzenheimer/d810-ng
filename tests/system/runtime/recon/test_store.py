from __future__ import annotations
import time
from types import MappingProxyType
import pytest
from d810.recon.models import CandidateFlag, ReconResult, DeobfuscationHints
from d810.recon.store import ReconStore


@pytest.fixture
def store(tmp_path):
    s = ReconStore(tmp_path / "recon_test.db")
    yield s
    s.close()


@pytest.fixture
def sample_result() -> ReconResult:
    flag = CandidateFlag(kind="flattened_switch", block_serial=3, confidence=0.9, detail="hi")
    return ReconResult(
        collector_name="CFGShapeCollector",
        func_ea=0x401000,
        maturity=5,
        timestamp=time.time(),
        metrics=MappingProxyType({"block_count": 20, "flattening_score": 0.72}),
        candidates=(flag,),
    )


@pytest.fixture
def sample_hints() -> DeobfuscationHints:
    return DeobfuscationHints(
        func_ea=0x401000,
        obfuscation_type="ollvm_flat",
        confidence=0.85,
        recommended_inferences=("unflattening",),
        candidates=(),
        suppress_rules=(),
    )


class TestReconStoreSaveLoad:
    def test_save_and_load_recon_result(self, store, sample_result):
        store.save_recon_result(sample_result)
        loaded = store.load_recon_results(func_ea=0x401000, maturity=5)
        assert len(loaded) == 1
        r = loaded[0]
        assert r.collector_name == "CFGShapeCollector"
        assert r.func_ea == 0x401000
        assert r.maturity == 5
        assert r.metrics["block_count"] == 20
        assert r.metrics["flattening_score"] == pytest.approx(0.72)
        assert len(r.candidates) == 1
        assert r.candidates[0].kind == "flattened_switch"
        assert r.candidates[0].confidence == pytest.approx(0.9)

    def test_primary_key_upsert(self, store, sample_result):
        store.save_recon_result(sample_result)
        # Save again with updated metrics - should replace
        updated = ReconResult(
            collector_name="CFGShapeCollector",
            func_ea=0x401000,
            maturity=5,
            timestamp=time.time(),
            metrics=MappingProxyType({"block_count": 30}),
            candidates=(),
        )
        store.save_recon_result(updated)
        loaded = store.load_recon_results(func_ea=0x401000, maturity=5)
        assert len(loaded) == 1
        assert loaded[0].metrics["block_count"] == 30

    def test_load_returns_empty_for_unknown(self, store):
        results = store.load_recon_results(func_ea=0xDEAD, maturity=5)
        assert results == []

    def test_multiple_collectors_same_maturity(self, store):
        r1 = ReconResult(
            collector_name="CFGShapeCollector", func_ea=0x401000, maturity=5,
            timestamp=time.time(), metrics=MappingProxyType({"a": 1}), candidates=(),
        )
        r2 = ReconResult(
            collector_name="OpcodeDistributionCollector", func_ea=0x401000, maturity=5,
            timestamp=time.time(), metrics=MappingProxyType({"b": 2}), candidates=(),
        )
        store.save_recon_result(r1)
        store.save_recon_result(r2)
        loaded = store.load_recon_results(func_ea=0x401000, maturity=5)
        assert len(loaded) == 2
        names = {r.collector_name for r in loaded}
        assert names == {"CFGShapeCollector", "OpcodeDistributionCollector"}

    def test_load_all_for_func(self, store):
        for maturity in (5, 10, 15):
            r = ReconResult(
                collector_name="CFGShapeCollector", func_ea=0x401000, maturity=maturity,
                timestamp=time.time(), metrics=MappingProxyType({"m": maturity}), candidates=(),
            )
            store.save_recon_result(r)
        all_results = store.load_all_recon_results(func_ea=0x401000)
        assert len(all_results) == 3
        maturities = {r.maturity for r in all_results}
        assert maturities == {5, 10, 15}

    def test_load_latest_recon_result_prefers_highest_maturity(self, store):
        older = ReconResult(
            collector_name="handler_transitions",
            func_ea=0x401000,
            maturity=5,
            timestamp=1.0,
            metrics=MappingProxyType({"handlers_total": 1}),
            candidates=(),
        )
        newer = ReconResult(
            collector_name="handler_transitions",
            func_ea=0x401000,
            maturity=10,
            timestamp=0.5,
            metrics=MappingProxyType({"handlers_total": 2}),
            candidates=(),
        )
        store.save_recon_result(older)
        store.save_recon_result(newer)

        loaded = store.load_latest_recon_result(
            func_ea=0x401000,
            collector_name="handler_transitions",
        )

        assert loaded is not None
        assert loaded.maturity == 10
        assert loaded.metrics["handlers_total"] == 2

    def test_load_latest_recon_result_can_filter_exact_maturity(self, store):
        first = ReconResult(
            collector_name="handler_transitions",
            func_ea=0x401000,
            maturity=5,
            timestamp=1.0,
            metrics=MappingProxyType({"handlers_total": 1}),
            candidates=(),
        )
        second = ReconResult(
            collector_name="handler_transitions",
            func_ea=0x401000,
            maturity=5,
            timestamp=2.0,
            metrics=MappingProxyType({"handlers_total": 3}),
            candidates=(),
        )
        store.save_recon_result(first)
        store.save_recon_result(second)

        loaded = store.load_latest_recon_result(
            func_ea=0x401000,
            collector_name="handler_transitions",
            maturity=5,
        )

        assert loaded is not None
        assert loaded.maturity == 5
        assert loaded.metrics["handlers_total"] == 3


class TestReconStoreHints:
    def test_save_and_load_hints(self, store, sample_hints):
        store.save_hints(sample_hints)
        loaded = store.load_hints(func_ea=0x401000)
        assert loaded is not None
        assert loaded.obfuscation_type == "ollvm_flat"
        assert loaded.confidence == pytest.approx(0.85)
        assert "unflattening" in loaded.recommended_inferences

    def test_hints_upsert(self, store, sample_hints):
        store.save_hints(sample_hints)
        updated = DeobfuscationHints(
            func_ea=0x401000,
            obfuscation_type="mixed",
            confidence=0.55,
            recommended_inferences=("mba",),
            candidates=(),
            suppress_rules=("SlowRule",),
        )
        store.save_hints(updated)
        loaded = store.load_hints(func_ea=0x401000)
        assert loaded is not None
        assert loaded.obfuscation_type == "mixed"
        assert "SlowRule" in loaded.suppress_rules

    def test_load_hints_none_for_unknown(self, store):
        assert store.load_hints(func_ea=0xDEAD) is None

    def test_clear_func(self, store, sample_result, sample_hints):
        store.save_recon_result(sample_result)
        store.save_hints(sample_hints)
        store.clear_func(func_ea=0x401000)
        assert store.load_recon_results(func_ea=0x401000, maturity=5) == []
        assert store.load_hints(func_ea=0x401000) is None
