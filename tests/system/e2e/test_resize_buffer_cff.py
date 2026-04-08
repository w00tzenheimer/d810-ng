"""Tests for buffer resize function with OLLVM CFF obfuscation.

This module tests the sub_7FFC1E9D3BB0_resize function which demonstrates:
- OLLVM Control-Flow Flattening (CFF) with nested while(1) loops
- Opaque constant table with MBA expressions for state transitions
- FoldReadonlyDataRule with fold_writable_constants configuration
- FixPredecessorOfConditionalJumpBlock for conditional chain dispatch
- GlobalConstantInliner for resolving opaque table loads

The function performs buffer resize/realloc operations with zero-fill,
obscured behind a complex state machine dispatcher.

To run:
    pytest tests/system/e2e/test_resize_buffer_cff.py -v
"""

import os
import platform

import pytest

import idaapi

from d810.testing.runner import get_func_ea, run_deobfuscation_test
from tests.system.cases.libobfuscated_comprehensive import RESIZE_BUFFER_CFF_CASES


def _get_default_binary() -> str:
    """Get default binary name based on platform, with env var override."""
    override = os.environ.get("D810_TEST_BINARY")
    if override:
        return override
    return (
        "libobfuscated.dylib" if platform.system() == "Darwin" else "libobfuscated.dll"
    )


@pytest.fixture(scope="class")
def libobfuscated_setup(ida_database, configure_hexrays, setup_libobfuscated_funcs):
    """Setup fixture for libobfuscated tests - runs once per class."""
    if not idaapi.init_hexrays_plugin():
        pytest.skip("Hex-Rays decompiler plugin not available")
    return ida_database


class TestResizeBufferCFF:
    """Tests for buffer resize with OLLVM CFF and opaque constant folding.

    This test validates the deobfuscation pipeline on a real-world pattern
    where control flow is flattened using opaque constants loaded from a
    volatile table. The deobfuscation must:

    1. Fold the opaque constant table accesses (FoldReadonlyDataRule)
    2. Resolve MBA expressions in state transitions
    3. Unpack the nested while(1)/if dispatcher (FixPredecessorOfConditionalJumpBlock)
    4. Restore linear control flow

    The underlying clean logic is a buffer resize with capacity check and zero-fill.
    """

    binary_name = _get_default_binary()

    @pytest.mark.ida_required
    @pytest.mark.parametrize("case", RESIZE_BUFFER_CFF_CASES, ids=lambda c: c.test_id)
    def test_resize_buffer_cff(
        self,
        case,
        libobfuscated_setup,
        d810_state,
        pseudocode_to_string,
        code_comparator,
        capture_stats,
        load_expected_stats,
    ):
        """Test deobfuscation of buffer resize with OLLVM CFF and opaque constants."""
        run_deobfuscation_test(
            case=case,
            d810_state=d810_state,
            pseudocode_to_string=pseudocode_to_string,
            code_comparator=code_comparator,
            capture_stats=capture_stats,
            load_expected_stats=load_expected_stats,
        )

