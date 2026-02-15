"""System tests for the BlockMerger flow optimization rule.

Tests that the BlockMerger rule correctly identifies and merges blocks
connected by unconditional gotos in real IDA Pro microcode.

These tests require IDA Pro with Hex-Rays decompiler and exercise the
optimizer against real binaries -- no mocks.

Sample requirements:
    A binary containing functions with redundant goto chains that the
    BlockMerger should simplify. The libobfuscated sample contains
    OLLVM-flattened functions whose unflattening produces mergeable
    goto chains.
"""
from __future__ import annotations

import os
import platform

import pytest

from d810.testing.cases import DeobfuscationCase
from d810.testing.runner import run_deobfuscation_test


def _get_default_binary() -> str:
    """Get default binary name based on platform, with env var override."""
    override = os.environ.get("D810_TEST_BINARY")
    if override:
        return override
    return "libobfuscated.dylib" if platform.system() == "Darwin" else "libobfuscated.dll"


# ---------------------------------------------------------------------------
# Test cases
# ---------------------------------------------------------------------------
# BlockMerger fires as a cleanup pass after unflattening.  When the
# unflattener resolves a flattened switch-dispatch, it leaves behind
# small blocks connected by m_goto instructions.  BlockMerger NOPs
# those gotos so that IDA can merge the blocks.
#
# We verify this indirectly: if BlockMerger is active, the deobfuscated
# code should be cleaner (fewer goto artifacts) than without it.
# ---------------------------------------------------------------------------

BLOCK_MERGE_CASES = [
    DeobfuscationCase(
        function="test_function_ollvm_fla_bcf_sub",
        description=(
            "OLLVM FLA+BCF+SUB function produces many small blocks after "
            "unflattening.  BlockMerger should fire to clean up goto chains."
        ),
        project="default_unflattening_ollvm.json",
        must_change=True,
        check_stats=True,
        expected_rules=["BlockMerger"],
        deobfuscated_not_contains=["JUMPOUT"],
    ),
    DeobfuscationCase(
        function="tigress_minmaxarray",
        description=(
            "Tigress-flattened function.  After unflattening, redundant "
            "goto blocks should be merged by BlockMerger."
        ),
        project="default_unflattening_ollvm.json",
        must_change=True,
        check_stats=True,
        expected_rules=["BlockMerger"],
        skip="BlockMerger does not produce visible changes on Tigress patterns yet",
    ),
]


@pytest.fixture(scope="class")
def libobfuscated_setup(ida_database, configure_hexrays, setup_libobfuscated_funcs):
    """Setup fixture for libobfuscated tests -- runs once per class."""
    import idaapi
    if not idaapi.init_hexrays_plugin():
        pytest.skip("Hex-Rays decompiler plugin not available")
    return ida_database


class TestBlockMerger:
    """System tests for BlockMerger using real IDA Pro decompilation.

    BlockMerger identifies blocks whose only exit is an unconditional
    goto to a block with a single predecessor and NOPs the goto so IDA
    merges them.  These tests verify the rule fires on real obfuscated
    binaries and produces cleaner output.
    """

    binary_name = _get_default_binary()

    @pytest.mark.ida_required
    @pytest.mark.parametrize("case", BLOCK_MERGE_CASES, ids=lambda c: c.test_id)
    def test_block_merger(
        self,
        case,
        libobfuscated_setup,
        d810_state,
        pseudocode_to_string,
        code_comparator,
        capture_stats,
        load_expected_stats,
    ):
        """Verify BlockMerger fires and cleans up goto chains."""
        run_deobfuscation_test(
            case=case,
            d810_state=d810_state,
            pseudocode_to_string=pseudocode_to_string,
            code_comparator=code_comparator,
            capture_stats=capture_stats,
            load_expected_stats=load_expected_stats,
        )


# ---------------------------------------------------------------------------
# Attribute verification tests
# ---------------------------------------------------------------------------
# These do not need a binary -- they just import the class and check
# its class-level metadata.  They still run inside the system test
# conftest (which initialises idapro/idalib), so they have access to
# real ida_hexrays constants.
# ---------------------------------------------------------------------------

class TestBlockMergerAttributes:
    """Verify BlockMerger class-level attributes with real IDA constants."""

    binary_name = _get_default_binary()

    @pytest.mark.ida_required
    def test_name(self, libobfuscated_setup):
        from d810.optimizers.microcode.flow.block_merge import BlockMerger
        # NAME is not overridden; .name property returns __class__.__name__
        assert BlockMerger().name == "BlockMerger"

    @pytest.mark.ida_required
    def test_description_mentions_merge_or_split(self, libobfuscated_setup):
        from d810.optimizers.microcode.flow.block_merge import BlockMerger
        desc = BlockMerger.DESCRIPTION.lower()
        assert "split" in desc or "merge" in desc

    @pytest.mark.ida_required
    def test_uses_deferred_cfg_false(self, libobfuscated_setup):
        from d810.optimizers.microcode.flow.block_merge import BlockMerger
        assert BlockMerger.USES_DEFERRED_CFG is False

    @pytest.mark.ida_required
    def test_safe_maturities_contains_real_constants(self, libobfuscated_setup):
        import ida_hexrays
        from d810.optimizers.microcode.flow.block_merge import BlockMerger
        assert ida_hexrays.MMAT_CALLS in BlockMerger.SAFE_MATURITIES
        assert ida_hexrays.MMAT_GLBOPT1 in BlockMerger.SAFE_MATURITIES
