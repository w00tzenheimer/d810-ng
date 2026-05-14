"""Regression coverage for reusable unflattener rule configuration."""

from __future__ import annotations

import os
import platform

from d810.optimizers.microcode.flow.flattening.unflattener import Unflattener


def _get_default_binary() -> str:
    override = os.environ.get("D810_TEST_BINARY")
    if override:
        return override
    if platform.system() == "Darwin":
        return "libobfuscated.dylib"
    return "libobfuscated.dll"


class TestUnflattenerConfigureReset:
    binary_name = _get_default_binary()

    def test_configure_resets_prior_project_entropy_thresholds(self, ida_database):
        """Loading one project must not leak collector thresholds into the next.

        D810State keeps rule objects alive while switching projects. A previous
        project such as ``bogus_loops.json`` may deliberately widen OLLVM dispatcher
        entropy checks to ``0.0..1.0``. A later project that omits those fields must
        get the rule's class defaults, not the previous project's values.
        """
        rule = Unflattener()

        rule.configure({"min_entropy": 0.0, "max_entropy": 1.0})
        assert rule.dispatcher_collector.min_entropy == 0.0
        assert rule.dispatcher_collector.max_entropy == 1.0

        rule.configure({})
        assert (
            rule.dispatcher_collector.min_entropy
            == rule.dispatcher_collector.DEFAULT_MIN_ENTROPY
        )
        assert (
            rule.dispatcher_collector.max_entropy
            == rule.dispatcher_collector.DEFAULT_MAX_ENTROPY
        )

    def test_configure_resets_generic_dispatcher_thresholds(self, ida_database):
        """Project switches must also reset inherited dispatcher thresholds."""
        rule = Unflattener()

        rule.configure(
            {
                "min_dispatcher_internal_block": 7,
                "min_dispatcher_exit_block": 8,
                "min_dispatcher_comparison_value": 9,
                "max_passes": 11,
                "post_apply_const_prop": True,
            }
        )
        assert rule.dispatcher_collector.dispatcher_min_internal_block == 7
        assert rule.dispatcher_collector.dispatcher_min_exit_block == 8
        assert rule.dispatcher_collector.dispatcher_min_comparison_value == 9
        assert rule.max_passes == 11
        assert rule.post_apply_const_prop is True

        rule.configure({})
        assert (
            rule.dispatcher_collector.dispatcher_min_internal_block
            == rule.dispatcher_collector.DEFAULT_DISPATCHER_MIN_INTERNAL_BLOCK
        )
        assert (
            rule.dispatcher_collector.dispatcher_min_exit_block
            == rule.dispatcher_collector.DEFAULT_DISPATCHER_MIN_EXIT_BLOCK
        )
        assert (
            rule.dispatcher_collector.dispatcher_min_comparison_value
            == rule.dispatcher_collector.DEFAULT_DISPATCHER_MIN_COMPARISON_VALUE
        )
        assert rule.max_passes == rule.DEFAULT_MAX_PASSES
        assert rule.post_apply_const_prop is False
