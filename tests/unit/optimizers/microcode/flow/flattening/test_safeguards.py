"""Unit tests for edge-count safeguard logic."""
import logging
import pytest
from d810.optimizers.microcode.flow.flattening.safeguards import (
    should_apply_cfg_modifications,
    MIN_ABSOLUTE_EDGES,
)


class TestEdgeCountSafeguard:
    def test_zero_edges_rejected(self):
        assert not should_apply_cfg_modifications(0, 10)

    def test_one_edge_rejected(self):
        assert not should_apply_cfg_modifications(1, 10)

    def test_two_edges_rejected(self):
        assert not should_apply_cfg_modifications(2, 10)

    def test_three_edges_accepted_small_dispatcher(self):
        assert should_apply_cfg_modifications(3, 5)

    def test_thirty_percent_threshold_large_dispatcher(self):
        assert not should_apply_cfg_modifications(5, 30)
        assert not should_apply_cfg_modifications(9, 30)
        assert should_apply_cfg_modifications(10, 30)

    def test_zero_case_blocks_uses_absolute_minimum(self):
        assert not should_apply_cfg_modifications(2, 0)
        assert should_apply_cfg_modifications(3, 0)

    def test_all_redirected_passes(self):
        assert should_apply_cfg_modifications(50, 50)

    def test_context_logged(self, caplog):
        with caplog.at_level(logging.WARNING):
            should_apply_cfg_modifications(1, 10, context="hodur")
        assert "SAFEGUARD [hodur]" in caplog.text
