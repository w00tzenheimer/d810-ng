from __future__ import annotations
import time
from types import MappingProxyType
from unittest.mock import MagicMock
import pytest
from d810.recon.models import CandidateFlag, ReconResult
from d810.recon.phase import ReconPhase, ReconCollector


class FakeCollector:
    """Minimal collector stub for unit tests (no IDA dependency)."""
    name = "FakeCollector"
    maturities: frozenset[int] = frozenset({5, 10})
    level: str = "microcode"

    def __init__(self, result_metrics: dict | None = None):
        self._metrics = result_metrics or {"fake_metric": 42}
        self.call_log: list[tuple[int, int]] = []

    def collect(self, target, func_ea: int, maturity: int) -> ReconResult:
        self.call_log.append((func_ea, maturity))
        return ReconResult(
            collector_name=self.name,
            func_ea=func_ea,
            maturity=maturity,
            timestamp=time.time(),
            metrics=MappingProxyType(self._metrics),
            candidates=(),
        )


@pytest.fixture
def store(tmp_path):
    from d810.recon.store import ReconStore
    s = ReconStore(tmp_path / "phase_test.db")
    yield s
    s.close()


class TestReconPhaseRegistration:
    def test_register_collector(self, store):
        phase = ReconPhase(store=store)
        collector = FakeCollector()
        phase.register(collector)
        assert phase.collector_count == 1

    def test_register_duplicate_raises(self, store):
        phase = ReconPhase(store=store)
        collector = FakeCollector()
        phase.register(collector)
        with pytest.raises(ValueError, match="already registered"):
            phase.register(collector)

    def test_empty_phase_has_no_collectors(self, store):
        phase = ReconPhase(store=store)
        assert phase.collector_count == 0


class TestReconPhaseRunIfNeeded:
    def test_dispatches_collector_at_matching_maturity(self, store):
        phase = ReconPhase(store=store)
        collector = FakeCollector()
        phase.register(collector)

        fake_target = MagicMock()
        phase.run_microcode_collectors(fake_target, func_ea=0x401000, maturity=5)

        assert len(collector.call_log) == 1
        assert collector.call_log[0] == (0x401000, 5)

    def test_skips_collector_at_non_matching_maturity(self, store):
        phase = ReconPhase(store=store)
        collector = FakeCollector()  # maturities = {5, 10}
        phase.register(collector)

        fake_target = MagicMock()
        phase.run_microcode_collectors(fake_target, func_ea=0x401000, maturity=99)

        assert len(collector.call_log) == 0

    def test_results_persisted_to_store(self, store):
        phase = ReconPhase(store=store)
        collector = FakeCollector({"block_count": 7})
        phase.register(collector)

        phase.run_microcode_collectors(MagicMock(), func_ea=0x401000, maturity=5)

        loaded = store.load_recon_results(func_ea=0x401000, maturity=5)
        assert len(loaded) == 1
        assert loaded[0].metrics["block_count"] == 7

    def test_maturity_guard_prevents_double_fire(self, store):
        phase = ReconPhase(store=store)
        collector = FakeCollector()
        phase.register(collector)

        fake_target = MagicMock()
        # First call - should fire
        phase.run_microcode_collectors(fake_target, func_ea=0x401000, maturity=5)
        # Second call same maturity - should NOT fire again
        phase.run_microcode_collectors(fake_target, func_ea=0x401000, maturity=5)

        assert len(collector.call_log) == 1

    def test_reset_clears_maturity_guard(self, store):
        phase = ReconPhase(store=store)
        collector = FakeCollector()
        phase.register(collector)

        fake_target = MagicMock()
        phase.run_microcode_collectors(fake_target, func_ea=0x401000, maturity=5)
        phase.reset(func_ea=0x401000)
        phase.run_microcode_collectors(fake_target, func_ea=0x401000, maturity=5)

        assert len(collector.call_log) == 2

    def test_collector_exception_does_not_abort_others(self, store):
        class BrokenCollector(FakeCollector):
            name = "BrokenCollector"
            def collect(self, target, func_ea, maturity):
                raise RuntimeError("simulated collector crash")

        phase = ReconPhase(store=store)
        broken = BrokenCollector()
        good = FakeCollector()
        good.name = "GoodCollector"

        phase.register(broken)
        phase.register(good)

        # Should not raise; broken collector is skipped, good one fires
        phase.run_microcode_collectors(MagicMock(), func_ea=0x401000, maturity=5)
        assert len(good.call_log) == 1
