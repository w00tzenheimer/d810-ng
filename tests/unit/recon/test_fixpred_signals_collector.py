"""Unit tests for FixPredSignalsCollector.

Uses SimpleNamespace mock FlowGraph objects - no IDA dependency.
Tests the portable signal extraction path and collector protocol.
"""
from __future__ import annotations

from types import SimpleNamespace

import pytest

from d810.recon.collectors.fixpred_signals import (
    FixPredSignalsCollector,
    _canonical_dispatcher_type,
    _ratio,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_block(
    serial: int,
    block_type: int = 3,  # BLT_1WAY
    preds: tuple[int, ...] = (),
    succs: tuple[int, ...] = (),
) -> SimpleNamespace:
    return SimpleNamespace(
        serial=serial,
        block_type=block_type,
        preds=preds,
        succs=succs,
    )


def _make_target(
    blocks: dict[int, SimpleNamespace],
    entry_serial: int = 0,
    metadata: dict | None = None,
) -> SimpleNamespace:
    return SimpleNamespace(
        blocks=blocks,
        entry_serial=entry_serial,
        metadata=metadata or {},
    )


# ---------------------------------------------------------------------------
# Collector protocol
# ---------------------------------------------------------------------------

class TestFixPredSignalsCollectorProtocol:

    def test_name(self) -> None:
        collector = FixPredSignalsCollector()
        assert collector.name == "FixPredSignalsCollector"

    def test_level(self) -> None:
        collector = FixPredSignalsCollector()
        assert collector.level == "microcode"

    def test_maturities_include_calls_and_glbopt1(self) -> None:
        collector = FixPredSignalsCollector()
        assert 3 in collector.maturities   # MMAT_CALLS
        assert 14 in collector.maturities  # MMAT_GLBOPT1

    def test_maturities_are_frozen(self) -> None:
        collector = FixPredSignalsCollector()
        assert isinstance(collector.maturities, frozenset)


# ---------------------------------------------------------------------------
# Helper functions
# ---------------------------------------------------------------------------

class TestHelpers:

    def test_ratio_normal(self) -> None:
        assert _ratio(3, 10) == pytest.approx(0.3)

    def test_ratio_zero_denominator(self) -> None:
        assert _ratio(5, 0) == 0.0

    def test_ratio_negative_denominator(self) -> None:
        assert _ratio(5, -1) == 0.0

    def test_canonical_dispatcher_type_conditional(self) -> None:
        assert _canonical_dispatcher_type("CONDITIONAL_CHAIN") == "CONDITIONAL_CHAIN"
        assert _canonical_dispatcher_type("foo_CONDITIONAL_CHAIN") == "CONDITIONAL_CHAIN"

    def test_canonical_dispatcher_type_switch(self) -> None:
        assert _canonical_dispatcher_type("SWITCH_TABLE") == "SWITCH_TABLE"

    def test_canonical_dispatcher_type_indirect(self) -> None:
        assert _canonical_dispatcher_type("INDIRECT_JUMP") == "INDIRECT_JUMP"

    def test_canonical_dispatcher_type_unknown(self) -> None:
        assert _canonical_dispatcher_type("something_else") == "UNKNOWN"
        assert _canonical_dispatcher_type(None) == "UNKNOWN"
        assert _canonical_dispatcher_type("") == "UNKNOWN"


# ---------------------------------------------------------------------------
# Portable signal extraction
# ---------------------------------------------------------------------------

class TestPortableSignals:

    def test_empty_blocks_returns_zero_metrics(self) -> None:
        target = _make_target(blocks={})
        collector = FixPredSignalsCollector()
        result = collector.collect(target, func_ea=0x401000, maturity=3)

        assert result.collector_name == "FixPredSignalsCollector"
        assert result.func_ea == 0x401000
        assert result.maturity == 3
        assert result.metrics["dispatcher_count"] == 0
        assert result.metrics["strong_dispatcher_count"] == 0

    def test_single_dispatcher_2way(self) -> None:
        """A BLT_2WAY block (type=4) with 3 preds and 2 succs -> strong dispatcher."""
        blocks = {
            0: _make_block(0, block_type=3, preds=(), succs=(1,)),
            1: _make_block(1, block_type=4, preds=(0, 2, 3), succs=(4, 5)),
            2: _make_block(2, block_type=3, preds=(), succs=(1,)),
            3: _make_block(3, block_type=3, preds=(), succs=(1,)),
            4: _make_block(4, block_type=3, preds=(1,), succs=()),
            5: _make_block(5, block_type=3, preds=(1,), succs=()),
        }
        target = _make_target(blocks)
        collector = FixPredSignalsCollector()
        result = collector.collect(target, func_ea=0x401000, maturity=3)

        assert result.metrics["dispatcher_count"] == 1
        assert result.metrics["conditional_dispatcher_count"] == 1
        assert result.metrics["strong_dispatcher_count"] == 1
        assert result.metrics["max_dispatcher_predecessors"] == 3
        assert result.metrics["ambiguous_dispatcher_count"] == 0
        # Predecessors 0, 2, 3 are all BLT_1WAY (type=3)
        assert result.metrics["predecessor_1way_ratio"] == pytest.approx(1.0)
        assert result.metrics["predecessor_2way_ratio"] == pytest.approx(0.0)

    def test_candidates_generated_for_high_fanin(self) -> None:
        """When max fan-in >= 3, candidates are emitted."""
        blocks = {
            0: _make_block(0, block_type=3, preds=(), succs=(1,)),
            1: _make_block(1, block_type=4, preds=(0, 2, 3), succs=(4, 5)),
            2: _make_block(2, block_type=3, preds=(), succs=(1,)),
            3: _make_block(3, block_type=3, preds=(), succs=(1,)),
            4: _make_block(4, block_type=3, preds=(1,), succs=()),
            5: _make_block(5, block_type=3, preds=(1,), succs=()),
        }
        target = _make_target(blocks)
        collector = FixPredSignalsCollector()
        result = collector.collect(target, func_ea=0x401000, maturity=3)

        assert len(result.candidates) == 1
        cand = result.candidates[0]
        assert cand.kind == "fixpred_high_fanin_dispatcher"
        assert cand.block_serial == 1
        assert 0.0 <= cand.confidence <= 1.0

    def test_no_candidates_when_low_fanin(self) -> None:
        """No candidates when max fan-in < 3."""
        blocks = {
            0: _make_block(0, block_type=3, preds=(), succs=(1,)),
            1: _make_block(1, block_type=4, preds=(0, 2), succs=(3, 4)),
            2: _make_block(2, block_type=3, preds=(), succs=(1,)),
            3: _make_block(3, block_type=3, preds=(1,), succs=()),
            4: _make_block(4, block_type=3, preds=(1,), succs=()),
        }
        target = _make_target(blocks)
        collector = FixPredSignalsCollector()
        result = collector.collect(target, func_ea=0x401000, maturity=3)

        # Block 1 has 2 preds -> dispatcher but max_dispatcher_predecessors=2 < 3
        assert result.metrics["dispatcher_count"] == 1
        assert len(result.candidates) == 0

    def test_explicit_dispatchers_in_metadata(self) -> None:
        """When metadata['dispatchers'] is provided, use it instead of heuristic."""
        blocks = {
            0: _make_block(0, block_type=3, preds=(), succs=(1,)),
            1: _make_block(1, block_type=4, preds=(0,), succs=(2, 3)),
            2: _make_block(2, block_type=3, preds=(1,), succs=()),
            3: _make_block(3, block_type=3, preds=(1,), succs=()),
        }
        target = _make_target(blocks, metadata={"dispatchers": [1]})
        collector = FixPredSignalsCollector()
        result = collector.collect(target, func_ea=0x401000, maturity=3)

        assert result.metrics["dispatcher_count"] == 1
        assert result.metrics["conditional_dispatcher_count"] == 1

    def test_state_var_from_compare_chain(self) -> None:
        """State variable detection via compare_chain_comparisons metadata."""
        blocks = {
            0: _make_block(0, block_type=4, preds=(1, 2, 3), succs=(4, 5)),
            1: _make_block(1, block_type=3, preds=(), succs=(0,)),
            2: _make_block(2, block_type=3, preds=(), succs=(0,)),
            3: _make_block(3, block_type=3, preds=(), succs=(0,)),
            4: _make_block(4, block_type=3, preds=(0,), succs=()),
            5: _make_block(5, block_type=3, preds=(0,), succs=()),
        }
        target = _make_target(
            blocks,
            metadata={
                "dispatchers": [0],
                "compare_chain_comparisons": [
                    {"constant": 0xAABB},
                    {"constant": 0xCCDD},
                    {"constant": 0xAABB},  # duplicate
                ],
            },
        )
        collector = FixPredSignalsCollector()
        result = collector.collect(target, func_ea=0x401000, maturity=3)

        assert result.metrics["state_variable_present"] == 1
        assert result.metrics["dispatcher_state_constant_total"] == 2

    def test_state_var_from_state_writes(self) -> None:
        """State variable detection via state_writes metadata."""
        blocks = {
            0: _make_block(0, block_type=4, preds=(1, 2, 3), succs=(4, 5)),
            1: _make_block(1, block_type=3, preds=(), succs=(0,)),
            2: _make_block(2, block_type=3, preds=(), succs=(0,)),
            3: _make_block(3, block_type=3, preds=(), succs=(0,)),
            4: _make_block(4, block_type=3, preds=(0,), succs=()),
            5: _make_block(5, block_type=3, preds=(0,), succs=()),
        }
        target = _make_target(
            blocks,
            metadata={
                "dispatchers": [0],
                "state_writes": {
                    "blk1": [0x10, 0x20],
                    "blk2": [0x20, 0x30],
                },
            },
        )
        collector = FixPredSignalsCollector()
        result = collector.collect(target, func_ea=0x401000, maturity=3)

        assert result.metrics["state_variable_present"] == 1
        assert result.metrics["dispatcher_state_constant_total"] == 3

    def test_nway_dispatcher(self) -> None:
        """BLT_NWAY (type=5) dispatcher counted as switch."""
        blocks = {
            0: _make_block(0, block_type=5, preds=(1, 2, 3), succs=(4, 5, 6)),
            1: _make_block(1, block_type=3, preds=(), succs=(0,)),
            2: _make_block(2, block_type=3, preds=(), succs=(0,)),
            3: _make_block(3, block_type=3, preds=(), succs=(0,)),
            4: _make_block(4, block_type=3, preds=(0,), succs=()),
            5: _make_block(5, block_type=3, preds=(0,), succs=()),
            6: _make_block(6, block_type=3, preds=(0,), succs=()),
        }
        target = _make_target(blocks, metadata={"dispatchers": [0]})
        collector = FixPredSignalsCollector()
        result = collector.collect(target, func_ea=0x401000, maturity=3)

        assert result.metrics["switch_dispatcher_count"] == 1
        assert result.metrics["conditional_dispatcher_count"] == 0

    def test_ambiguous_nway_with_one_succ(self) -> None:
        """NWAY block with <= 1 successor is ambiguous."""
        blocks = {
            0: _make_block(0, block_type=5, preds=(1, 2, 3), succs=(4,)),
            1: _make_block(1, block_type=3, preds=(), succs=(0,)),
            2: _make_block(2, block_type=3, preds=(), succs=(0,)),
            3: _make_block(3, block_type=3, preds=(), succs=(0,)),
            4: _make_block(4, block_type=3, preds=(0,), succs=()),
        }
        target = _make_target(blocks, metadata={"dispatchers": [0]})
        collector = FixPredSignalsCollector()
        result = collector.collect(target, func_ea=0x401000, maturity=3)

        assert result.metrics["ambiguous_dispatcher_count"] == 1
        assert result.metrics["ambiguous_dispatcher_ratio"] == pytest.approx(1.0)

    def test_dispatcher_type_from_metadata(self) -> None:
        """Dispatcher type is read from metadata."""
        blocks = {
            0: _make_block(0, block_type=4, preds=(1, 2), succs=(3, 4)),
            1: _make_block(1, block_type=3, preds=(), succs=(0,)),
            2: _make_block(2, block_type=3, preds=(), succs=(0,)),
            3: _make_block(3, block_type=3, preds=(0,), succs=()),
            4: _make_block(4, block_type=3, preds=(0,), succs=()),
        }
        target = _make_target(
            blocks,
            metadata={
                "dispatchers": [0],
                "dispatcher_type": "CONDITIONAL_CHAIN",
            },
        )
        collector = FixPredSignalsCollector()
        result = collector.collect(target, func_ea=0x401000, maturity=3)

        assert result.metrics["dispatcher_type"] == "CONDITIONAL_CHAIN"

    def test_result_metrics_are_readonly(self) -> None:
        """ReconResult.metrics must be a read-only mapping."""
        target = _make_target(blocks={})
        collector = FixPredSignalsCollector()
        result = collector.collect(target, func_ea=0x401000, maturity=3)

        with pytest.raises(TypeError):
            result.metrics["new_key"] = 42

    def test_all_expected_metric_keys_present(self) -> None:
        """Verify all expected metric keys are in the result."""
        blocks = {
            0: _make_block(0, block_type=4, preds=(1, 2, 3), succs=(4, 5)),
            1: _make_block(1, block_type=3, preds=(), succs=(0,)),
            2: _make_block(2, block_type=3, preds=(), succs=(0,)),
            3: _make_block(3, block_type=3, preds=(), succs=(0,)),
            4: _make_block(4, block_type=3, preds=(0,), succs=()),
            5: _make_block(5, block_type=3, preds=(0,), succs=()),
        }
        target = _make_target(blocks, metadata={"dispatchers": [0]})
        collector = FixPredSignalsCollector()
        result = collector.collect(target, func_ea=0x401000, maturity=3)

        expected_keys = {
            "dispatcher_count",
            "strong_dispatcher_count",
            "conditional_dispatcher_count",
            "switch_dispatcher_count",
            "unknown_dispatcher_count",
            "max_dispatcher_predecessors",
            "mean_dispatcher_predecessors",
            "ambiguous_dispatcher_count",
            "ambiguous_dispatcher_ratio",
            "predecessor_sample_count",
            "predecessor_1way_ratio",
            "predecessor_2way_ratio",
            "predecessor_nway_ratio",
            "state_variable_present",
            "dispatcher_state_constant_total",
            "dispatcher_type",
        }
        assert set(result.metrics.keys()) == expected_keys
