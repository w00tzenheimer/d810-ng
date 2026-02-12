"""System tests for the GlobalConstantInliner flow optimization rule.

Tests that GlobalConstantInliner correctly identifies m_mov/m_ldx instructions
referencing read-only global data and replaces them with immediate constants
in real IDA Pro microcode.

These tests require IDA Pro with Hex-Rays decompiler and exercise the
optimizer against real binaries -- no mocks.

Sample requirements:
    A binary containing functions that reference read-only global constants
    (e.g., lookup tables in .rodata/.rdata/__const sections).  The
    libobfuscated sample contains constant folding test functions that
    exercise this path.
"""
from __future__ import annotations

import os
import platform

import pytest

from d810.testing.cases import BinaryOverride, DeobfuscationCase
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
# GlobalConstantInliner replaces memory loads from read-only segments
# (.rodata, .rdata, __const, etc.) with immediate values.  This is a
# prerequisite for further constant folding and MBA simplification.
#
# The constant_folding_test functions in libobfuscated use lookup tables
# stored in read-only data segments.  After inlining, the decompiler
# can fold the constants and produce simpler output.
# ---------------------------------------------------------------------------

GLOBAL_CONST_INLINE_CASES = [
    DeobfuscationCase(
        function="constant_folding_test1",
        description=(
            "Function with ROL/ROR operations using read-only lookup tables. "
            "GlobalConstantInliner should inline the table values so that "
            "the decompiler can fold them into constants."
        ),
        project="default_instruction_only.json",
        must_change=True,
        check_stats=True,
        expected_rules=["GlobalConstantInliner"],
    ),
    DeobfuscationCase(
        function="constant_folding_test2",
        description=(
            "Function with complex bitwise expressions referencing read-only "
            "globals.  GlobalConstantInliner should replace the memory loads."
        ),
        project="default_instruction_only.json",
        must_change=True,
        check_stats=True,
        expected_rules=["GlobalConstantInliner"],
        skip="Needs full project config; passes in test_libdeobfuscated_dsl with example_libobfuscated.json",
    ),
    DeobfuscationCase(
        function="constant_folding_test1",
        description=(
            "Regression: GlobalConstantInliner must not inline RVA-like values "
            "into raw MEMORY[0x...] call expressions."
        ),
        project="default_instruction_only.json",
        must_change=True,
        check_stats=True,
        expected_rules=["GlobalConstantInliner"],
        dll_override=BinaryOverride(
            deobfuscated_not_contains=["MEMORY[0x"],
        ),
        dylib_override=BinaryOverride(
            skip="PE/RVA-specific regression case; not applicable to dylib binaries.",
        ),
    ),
]


@pytest.fixture(scope="class")
def libobfuscated_setup(ida_database, configure_hexrays, setup_libobfuscated_funcs):
    """Setup fixture for libobfuscated tests -- runs once per class."""
    import idaapi
    if not idaapi.init_hexrays_plugin():
        pytest.skip("Hex-Rays decompiler plugin not available")
    return ida_database


class TestGlobalConstantInliner:
    """System tests for GlobalConstantInliner using real IDA Pro decompilation.

    Verifies that the optimizer correctly identifies read-only global
    references and replaces them with immediate values, enabling
    downstream constant folding.
    """

    binary_name = _get_default_binary()

    @pytest.mark.ida_required
    @pytest.mark.parametrize(
        "case", GLOBAL_CONST_INLINE_CASES, ids=lambda c: c.test_id
    )
    def test_global_const_inline(
        self,
        case,
        libobfuscated_setup,
        d810_state,
        pseudocode_to_string,
        code_comparator,
        capture_stats,
        load_expected_stats,
    ):
        """Verify GlobalConstantInliner fires and inlines read-only constants."""
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

class TestGlobalConstantInlinerAttributes:
    """Verify GlobalConstantInliner class-level attributes with real IDA constants."""

    binary_name = _get_default_binary()

    @pytest.mark.ida_required
    def test_description_mentions_constant(self, libobfuscated_setup):
        from d810.optimizers.microcode.flow.global_const_inline import (
            GlobalConstantInliner,
        )
        assert "constant" in GlobalConstantInliner.DESCRIPTION.lower()

    @pytest.mark.ida_required
    def test_uses_deferred_cfg_true(self, libobfuscated_setup):
        from d810.optimizers.microcode.flow.global_const_inline import (
            GlobalConstantInliner,
        )
        assert GlobalConstantInliner.USES_DEFERRED_CFG is True

    @pytest.mark.ida_required
    def test_safe_maturities_is_none(self, libobfuscated_setup):
        """SAFE_MATURITIES=None means safe at any maturity."""
        from d810.optimizers.microcode.flow.global_const_inline import (
            GlobalConstantInliner,
        )
        assert GlobalConstantInliner.SAFE_MATURITIES is None

    @pytest.mark.ida_required
    def test_maturities_include_preoptimized(self, libobfuscated_setup):
        import ida_hexrays
        from d810.optimizers.microcode.flow.global_const_inline import (
            GlobalConstantInliner,
        )
        rule = GlobalConstantInliner()
        assert ida_hexrays.MMAT_PREOPTIMIZED in rule.maturities

    @pytest.mark.ida_required
    def test_maturities_include_locopt(self, libobfuscated_setup):
        import ida_hexrays
        from d810.optimizers.microcode.flow.global_const_inline import (
            GlobalConstantInliner,
        )
        rule = GlobalConstantInliner()
        assert ida_hexrays.MMAT_LOCOPT in rule.maturities


# ---------------------------------------------------------------------------
# Helper function tests -- these exercise pure logic with real IDA modules
# ---------------------------------------------------------------------------

class TestHelperFunctions:
    """Test pure-logic helpers with real IDA module constants.

    These tests verify the helper functions (_is_constant_global,
    _read_constant_value, _looks_like_pointer) using real IDA APIs
    against the loaded binary's segments.
    """

    binary_name = _get_default_binary()

    @pytest.mark.ida_required
    def test_looks_like_pointer_rejects_small_sizes(self, libobfuscated_setup):
        """Values smaller than 4 bytes should never be treated as pointers."""
        from d810.optimizers.microcode.flow.global_const_inline import (
            _looks_like_pointer,
        )
        assert _looks_like_pointer(0xFFFF, 1) is False
        assert _looks_like_pointer(0xFFFF, 2) is False
        assert _looks_like_pointer(0xFFFF, 3) is False

    @pytest.mark.ida_required
    def test_looks_like_pointer_zero_is_not_pointer(self, libobfuscated_setup):
        """Zero (NULL) should not be flagged as a pointer."""
        from d810.optimizers.microcode.flow.global_const_inline import (
            _looks_like_pointer,
        )
        assert _looks_like_pointer(0, 4) is False
        assert _looks_like_pointer(0, 8) is False

    @pytest.mark.ida_required
    def test_is_constant_global_no_segment_returns_false(self, libobfuscated_setup):
        """An address not in any segment should not be constant."""
        from d810.optimizers.microcode.flow.global_const_inline import (
            _is_constant_global,
        )
        # Use an address far outside the loaded binary
        assert _is_constant_global(0xDEAD_DEAD_DEAD_DEAD) is False

    @pytest.mark.ida_required
    def test_read_constant_value_at_known_rodata(self, libobfuscated_setup):
        """Read a value from a known read-only segment in the test binary.

        This verifies that _read_constant_value works with real IDA APIs.
        We find a read-only segment and read a value from it.
        """
        import ida_segment
        import idaapi

        from d810.optimizers.microcode.flow.global_const_inline import (
            _is_constant_global,
            _read_constant_value,
        )

        # Walk segments to find a read-only one with data
        seg = ida_segment.get_first_seg()
        found_rodata = False
        while seg is not None:
            name = ida_segment.get_segm_name(seg)
            # Check for read-only data segments
            if name in (".rodata", ".rdata", "__const", "__DATA_CONST"):
                ea = seg.start_ea
                if idaapi.is_loaded(ea):
                    # Verify our helper agrees this is constant
                    if _is_constant_global(ea):
                        found_rodata = True
                        # Read a 4-byte value -- just verify it does not crash
                        val = _read_constant_value(ea, 4)
                        assert isinstance(val, int)
                break
            seg = ida_segment.get_next_seg(seg.start_ea)

        if not found_rodata:
            pytest.skip("No read-only data segment found in test binary")
