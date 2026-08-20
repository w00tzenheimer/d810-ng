"""DSL-based comprehensive tests for deobfuscation against libobfuscated binary.

This test module uses the data-driven testing approach where tests are defined
as DeobfuscationCase dataclasses in tests/system/cases/libobfuscated_comprehensive.py.

Coverage Goal: 100% coverage of src/d810/optimizers/microcode package

Test Organization:
- TestUnflatteningRules: Control flow unflattening patterns
- TestInstructionRules: MBA and constant folding patterns
- TestExceptionPaths: Edge cases and exception paths

Override binary via environment variable:
    D810_TEST_BINARY=libobfuscated.dll pytest tests/system/e2e/test_libdeobfuscated_dsl.py
"""

import os
import platform

import pytest

import idaapi
import ida_bytes
import ida_ua
import idc

from d810.testing.runner import run_deobfuscation_test
from tests.system.cases.libobfuscated_comprehensive import (
    EXCEPTION_PATH_CASES,
    MANUALLY_OBFUSCATED_CASES,
    ABC_F6_CASES,
    ABC_XOR_CASES,
    APPROOV_CASES,
    CONSTANT_FOLDING_CASES,
    DAC_MASM_CASES,
    DISPATCHER_PATTERN_CASES,
    HODUR_CASES,
    NESTED_DISPATCHER_CASES,
    OLLVM_CASES,
    TIGRESS_CASES,
    TIGRESS_ENGINE_CASES,
    UNWRAP_LOOPS_CASES,
    WHILE_SWITCH_CASES,
    HARDENED_OLLVM_COND_CHAIN_CASES,
    RESIZE_BUFFER_CFF_CASES,
)


def _get_default_binary() -> str:
    """Get default binary name based on platform, with env var override."""
    override = os.environ.get("D810_TEST_BINARY")
    if override:
        return override
    return (
        "libobfuscated.dylib" if platform.system() == "Darwin" else "libobfuscated.dll"
    )


_EXACT_MASM_CODE_EXTENTS = {
    # The linked fixture's single PROC range. The committed MASM contains only
    # instructions in this range, but a fresh IDA analysis can misclassify
    # bytes inside valid instruction spans as data and leave direct branch
    # targets undefined. Hex-Rays then renders those in-function targets as
    # JUMPOUTs. Recreate the exact dense instruction stream in the disposable
    # test IDB so the fixture preserves the source IDB's code-head oracle.
    # Fresh ml64/VS 2022 rebuild from the committed source: 0x4402 bytes.  The
    # first dispatcher transfer requires the five-byte near form once the
    # relative table is emitted immediately before the procedure.
    "sub_7FF856533A20": 0x4402,
}

def _materialize_exact_masm_code_extent(function: str) -> None:
    size = _EXACT_MASM_CODE_EXTENTS.get(function)
    if size is None:
        return
    start = idc.get_name_ea_simple(function)
    if start == idaapi.BADADDR:
        start = idc.get_name_ea_simple(f"_{function}")
    assert start != idaapi.BADADDR, function
    function_start = int(idc.get_func_attr(int(start), idc.FUNCATTR_START))
    function_end = int(idc.get_func_attr(int(start), idc.FUNCATTR_END))
    assert function_start != idaapi.BADADDR, function
    assert function_end != idaapi.BADADDR, function
    end = int(start) + int(size)
    assert function_start == int(start)
    assert function_end == end, (
        function,
        hex(function_start),
        hex(function_end),
        hex(end),
    )

    cursor = int(start)
    instruction = ida_ua.insn_t()
    while cursor < end:
        decoded_size = int(ida_ua.decode_insn(instruction, cursor))
        assert decoded_size > 0, f"cannot decode {function} at 0x{cursor:X}"
        assert cursor + decoded_size <= end, (
            f"instruction at 0x{cursor:X} crosses {function}'s exact extent"
        )
        overlapping_heads = {
            int(ida_bytes.get_item_head(ea))
            for ea in range(cursor, cursor + decoded_size)
        }
        for head in sorted(overlapping_heads):
            flags = ida_bytes.get_full_flags(head)
            if head == cursor and ida_bytes.is_code(flags):
                continue
            ida_bytes.del_items(
                head,
                ida_bytes.DELIT_SIMPLE,
                max(1, int(ida_bytes.get_item_size(head))),
            )
        created_size = int(ida_ua.create_insn(cursor))
        assert created_size == decoded_size, (
            f"instruction recreation drift at 0x{cursor:X}: "
            f"decoded={decoded_size} created={created_size}"
        )
        cursor += decoded_size

    idaapi.auto_wait()
    idaapi.mark_cfunc_dirty(int(start), False)


@pytest.fixture(scope="class")
def libobfuscated_setup(ida_database, configure_hexrays, setup_libobfuscated_funcs):
    """Setup fixture for libobfuscated tests - runs once per class."""
    if not idaapi.init_hexrays_plugin():
        pytest.skip("Hex-Rays decompiler plugin not available")
    return ida_database


class TestMBASimplification:
    """Tests for Mixed Boolean-Arithmetic (MBA) simplification.

    Tests patterns from manually_obfuscated.c:
    - XOR: (a + b) - 2*(a & b) => a ^ b
    - OR:  (a & b) + (a ^ b) => a | b
    - AND: (a | b) - (a ^ b) => a & b
    - NEG: ~x + 1 => -x
    """

    binary_name = _get_default_binary()

    @pytest.mark.parametrize("case", MANUALLY_OBFUSCATED_CASES, ids=lambda c: c.test_id)
    def test_mba_simplification(
        self,
        case,
        libobfuscated_setup,
        d810_state,
        pseudocode_to_string,
        code_comparator,
        capture_stats,
        load_expected_stats,
    ):
        """MBA pattern simplification."""
        run_deobfuscation_test(
            case=case,
            d810_state=d810_state,
            pseudocode_to_string=pseudocode_to_string,
            code_comparator=code_comparator,
            capture_stats=capture_stats,
            load_expected_stats=load_expected_stats,
        )


class TestConstantFolding:
    """Tests for constant folding optimizations.

    Tests patterns from constant_folding.c:
    - ROL/ROR operations
    - Lookup table access
    - Complex bitwise expressions
    """

    binary_name = _get_default_binary()

    @pytest.mark.parametrize("case", CONSTANT_FOLDING_CASES, ids=lambda c: c.test_id)
    def test_constant_folding(
        self,
        case,
        libobfuscated_setup,
        d810_state,
        pseudocode_to_string,
        code_comparator,
        capture_stats,
        load_expected_stats,
    ):
        """Constant folding patterns."""
        run_deobfuscation_test(
            case=case,
            d810_state=d810_state,
            pseudocode_to_string=pseudocode_to_string,
            code_comparator=code_comparator,
            capture_stats=capture_stats,
            load_expected_stats=load_expected_stats,
        )


class TestABCPatterns:
    """Tests for ABC-style dispatcher patterns with magic constants.

    Tests patterns from abc_f6_constants.c and abc_xor_dispatch.c.
    """

    binary_name = _get_default_binary()

    @pytest.mark.parametrize(
        "case", ABC_F6_CASES + ABC_XOR_CASES, ids=lambda c: c.test_id
    )
    def test_abc_patterns(
        self,
        case,
        libobfuscated_setup,
        d810_state,
        pseudocode_to_string,
        code_comparator,
        capture_stats,
        load_expected_stats,
    ):
        """ABC dispatcher patterns."""
        run_deobfuscation_test(
            case=case,
            d810_state=d810_state,
            pseudocode_to_string=pseudocode_to_string,
            code_comparator=code_comparator,
            capture_stats=capture_stats,
            load_expected_stats=load_expected_stats,
        )


class TestApproovPatterns:
    """Tests for Approov-style obfuscation patterns.

    Tests patterns from approov_flattened.c.
    """

    binary_name = _get_default_binary()

    @pytest.mark.parametrize("case", APPROOV_CASES, ids=lambda c: c.test_id)
    def test_approov_patterns(
        self,
        case,
        libobfuscated_setup,
        d810_state,
        pseudocode_to_string,
        code_comparator,
        capture_stats,
        load_expected_stats,
    ):
        """Approov obfuscation patterns."""
        run_deobfuscation_test(
            case=case,
            d810_state=d810_state,
            pseudocode_to_string=pseudocode_to_string,
            code_comparator=code_comparator,
            capture_stats=capture_stats,
            load_expected_stats=load_expected_stats,
        )


class TestDispatcherPatterns:
    """Tests for various dispatcher detection patterns.

    Tests patterns from dispatcher_patterns.c:
    - HIGH_FAN_IN
    - STATE_COMPARISON
    - NESTED_LOOP
    - SWITCH_JUMP
    """

    binary_name = _get_default_binary()

    @pytest.mark.parametrize("case", DISPATCHER_PATTERN_CASES, ids=lambda c: c.test_id)
    def test_dispatcher_patterns(
        self,
        case,
        libobfuscated_setup,
        d810_state,
        pseudocode_to_string,
        code_comparator,
        capture_stats,
        load_expected_stats,
    ):
        """Dispatcher detection patterns."""
        run_deobfuscation_test(
            case=case,
            d810_state=d810_state,
            pseudocode_to_string=pseudocode_to_string,
            code_comparator=code_comparator,
            capture_stats=capture_stats,
            load_expected_stats=load_expected_stats,
        )


class TestDacMasmFixtures:
    """Real dac.dll functions (issue #48) extracted to MASM and linked into
    libobfuscated.dll.

    These carry the issue-48 regressions in the tracked corpus so CI catches
    them without the gitless dac.dll sample.  Windows-PE-only: they SKIP on the
    .dylib/.so builds (skip_if_function_absent).  See d81-u3cg (the
    ``sub_1815C8C30`` loop-collapse regression) and d81-l3cu (this extraction).
    """

    binary_name = _get_default_binary()

    @pytest.mark.parametrize("case", DAC_MASM_CASES, ids=lambda c: c.test_id)
    def test_dac_masm_fixtures(
        self,
        case,
        libobfuscated_setup,
        d810_state,
        pseudocode_to_string,
        code_comparator,
        capture_stats,
        load_expected_stats,
    ):
        """dac.dll issue-48 functions extracted as MASM."""
        _materialize_exact_masm_code_extent(case.function)
        run_deobfuscation_test(
            case=case,
            d810_state=d810_state,
            pseudocode_to_string=pseudocode_to_string,
            code_comparator=code_comparator,
            capture_stats=capture_stats,
            load_expected_stats=load_expected_stats,
        )


class TestNestedDispatchers:
    """Tests for nested dispatcher patterns.

    Tests patterns from nested_dispatchers.c.
    """

    binary_name = _get_default_binary()

    @pytest.mark.parametrize("case", NESTED_DISPATCHER_CASES, ids=lambda c: c.test_id)
    def test_nested_dispatchers(
        self,
        case,
        libobfuscated_setup,
        d810_state,
        pseudocode_to_string,
        code_comparator,
        capture_stats,
        load_expected_stats,
    ):
        """Nested dispatcher patterns."""
        run_deobfuscation_test(
            case=case,
            d810_state=d810_state,
            pseudocode_to_string=pseudocode_to_string,
            code_comparator=code_comparator,
            capture_stats=capture_stats,
            load_expected_stats=load_expected_stats,
        )


class TestOLLVMPatterns:
    """Tests for O-LLVM obfuscation patterns.

    Tests patterns from ollvm_obfuscated.c.
    """

    binary_name = _get_default_binary()

    @pytest.mark.parametrize("case", OLLVM_CASES, ids=lambda c: c.test_id)
    def test_ollvm_patterns(
        self,
        case,
        libobfuscated_setup,
        d810_state,
        pseudocode_to_string,
        code_comparator,
        capture_stats,
        load_expected_stats,
    ):
        """O-LLVM obfuscation patterns."""
        run_deobfuscation_test(
            case=case,
            d810_state=d810_state,
            pseudocode_to_string=pseudocode_to_string,
            code_comparator=code_comparator,
            capture_stats=capture_stats,
            load_expected_stats=load_expected_stats,
        )


class TestTigressPatterns:
    """Tests for Tigress obfuscation patterns.

    Tests patterns from tigress_obfuscated.c.
    """

    binary_name = _get_default_binary()

    @pytest.mark.parametrize("case", TIGRESS_CASES, ids=lambda c: c.test_id)
    def test_tigress_patterns(
        self,
        case,
        libobfuscated_setup,
        d810_state,
        pseudocode_to_string,
        code_comparator,
        capture_stats,
        load_expected_stats,
    ):
        """Tigress obfuscation patterns."""
        run_deobfuscation_test(
            case=case,
            d810_state=d810_state,
            pseudocode_to_string=pseudocode_to_string,
            code_comparator=code_comparator,
            capture_stats=capture_stats,
            load_expected_stats=load_expected_stats,
        )


class TestTigressEnginePatterns:
    """Replacement-readiness gates for Tigress through the shared engine profile."""

    binary_name = _get_default_binary()

    @pytest.mark.parametrize("case", TIGRESS_ENGINE_CASES, ids=lambda c: c.test_id)
    def test_tigress_engine_patterns(
        self,
        case,
        libobfuscated_setup,
        d810_state,
        pseudocode_to_string,
        code_comparator,
        capture_stats,
        load_expected_stats,
    ):
        """Tigress switch-table state machines through EmulatedDispatcherUnflattener."""
        run_deobfuscation_test(
            case=case,
            d810_state=d810_state,
            pseudocode_to_string=pseudocode_to_string,
            code_comparator=code_comparator,
            capture_stats=capture_stats,
            load_expected_stats=load_expected_stats,
        )


class TestHodurPatterns:
    """Tests for Hodur C2 malware patterns.

    Tests patterns from hodur_c2_flattened.c.
    """

    binary_name = _get_default_binary()

    @pytest.mark.parametrize("case", HODUR_CASES, ids=lambda c: c.test_id)
    def test_hodur_patterns(
        self,
        case,
        libobfuscated_setup,
        d810_state,
        pseudocode_to_string,
        code_comparator,
        capture_stats,
        load_expected_stats,
    ):
        """Hodur C2 malware patterns."""
        run_deobfuscation_test(
            case=case,
            d810_state=d810_state,
            pseudocode_to_string=pseudocode_to_string,
            code_comparator=code_comparator,
            capture_stats=capture_stats,
            load_expected_stats=load_expected_stats,
        )


class TestLoopPatterns:
    """Tests for loop unwrapping patterns.

    Tests patterns from unwrap_loops.c and while_switch_flattened.c.
    """

    binary_name = _get_default_binary()

    @pytest.mark.parametrize(
        "case", UNWRAP_LOOPS_CASES + WHILE_SWITCH_CASES, ids=lambda c: c.test_id
    )
    def test_loop_patterns(
        self,
        case,
        libobfuscated_setup,
        d810_state,
        pseudocode_to_string,
        code_comparator,
        capture_stats,
        load_expected_stats,
    ):
        """Loop unwrapping patterns."""
        run_deobfuscation_test(
            case=case,
            d810_state=d810_state,
            pseudocode_to_string=pseudocode_to_string,
            code_comparator=code_comparator,
            capture_stats=capture_stats,
            load_expected_stats=load_expected_stats,
        )


class TestHardenedConditionalChains:
    """Tests for hardened OLLVM conditional-chain state machines.

    These cases use table-backed state constants and condition-chain dispatch, so
    they are owned by the whole-dispatcher reconstruction path rather than the
    predecessor-local conditional-jump fixup.
    """

    binary_name = _get_default_binary()

    @pytest.mark.parametrize(
        "case", HARDENED_OLLVM_COND_CHAIN_CASES, ids=lambda c: c.test_id
    )
    def test_hardened_conditional_chains(
        self,
        case,
        libobfuscated_setup,
        d810_state,
        pseudocode_to_string,
        code_comparator,
        capture_stats,
        load_expected_stats,
    ):
        """Hardened conditional-chain dispatcher patterns."""
        run_deobfuscation_test(
            case=case,
            d810_state=d810_state,
            pseudocode_to_string=pseudocode_to_string,
            code_comparator=code_comparator,
            capture_stats=capture_stats,
            load_expected_stats=load_expected_stats,
        )


class TestExceptionPaths:
    """Tests for exception and edge case handling.

    Tests patterns from exception_paths.c that verify correct behavior when:
    - State comes from external functions
    - Side effects prevent duplication
    - Duplication limits are reached
    """

    binary_name = _get_default_binary()

    @pytest.mark.parametrize("case", EXCEPTION_PATH_CASES, ids=lambda c: c.test_id)
    def test_exception_paths(
        self,
        case,
        libobfuscated_setup,
        d810_state,
        pseudocode_to_string,
        code_comparator,
        capture_stats,
        load_expected_stats,
    ):
        """Exception path handling."""
        run_deobfuscation_test(
            case=case,
            d810_state=d810_state,
            pseudocode_to_string=pseudocode_to_string,
            code_comparator=code_comparator,
            capture_stats=capture_stats,
            load_expected_stats=load_expected_stats,
        )


class TestResizeBufferCFF:
    """Tests for buffer resize with OLLVM CFF and opaque constant folding.

    Tests patterns from sub_7FFC1E9D3BB0.c:
    - OLLVM Control-Flow Flattening (CFF) with nested while(1) loops
    - Opaque constant table with MBA expressions
    - FoldReadonlyDataRule with fold_writable_constants
    - active whole-dispatcher unflattening for conditional chain dispatch
    """

    binary_name = _get_default_binary()

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
        """Buffer resize with OLLVM CFF patterns."""
        run_deobfuscation_test(
            case=case,
            d810_state=d810_state,
            pseudocode_to_string=pseudocode_to_string,
            code_comparator=code_comparator,
            capture_stats=capture_stats,
            load_expected_stats=load_expected_stats,
        )
