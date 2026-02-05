"""DSL-based comprehensive tests for deobfuscation against libobfuscated binary.

This test module uses the data-driven testing approach where tests are defined
as DeobfuscationCase dataclasses in tests/system/cases/libobfuscated_comprehensive.py.

Coverage Goal: 100% coverage of src/d810/optimizers/microcode package

Test Organization:
- TestCoreDeobfuscation: Core tests that must always pass
- TestUnflatteningRules: Control flow unflattening patterns
- TestInstructionRules: MBA and constant folding patterns
- TestExceptionPaths: Edge cases and exception paths
- TestSmoke: Quick smoke tests for CI

Override binary via environment variable:
    D810_TEST_BINARY=libobfuscated.dll pytest tests/system/test_libdeobfuscated_dsl.py
"""

import os
import platform

import pytest

import idaapi

from d810.testing import run_deobfuscation_test
from tests.system.cases.libobfuscated_comprehensive import (
    ALL_CASES,
    CORE_CASES,
    SMOKE_CASES,
    UNFLATTENING_CASES,
    INSTRUCTION_CASES,
    EXCEPTION_PATH_CASES,
    MANUALLY_OBFUSCATED_CASES,
    ABC_F6_CASES,
    ABC_XOR_CASES,
    APPROOV_CASES,
    CONSTANT_FOLDING_CASES,
    DISPATCHER_PATTERN_CASES,
    HODUR_CASES,
    NESTED_DISPATCHER_CASES,
    OLLVM_CASES,
    TIGRESS_CASES,
    UNWRAP_LOOPS_CASES,
    WHILE_SWITCH_CASES,
    TOTAL_FUNCTION_COUNT,
)


def _get_default_binary() -> str:
    """Get default binary name based on platform, with env var override."""
    override = os.environ.get("D810_TEST_BINARY")
    if override:
        return override
    return "libobfuscated.dylib" if platform.system() == "Darwin" else "libobfuscated.dll"


@pytest.fixture(scope="class")
def libobfuscated_setup(ida_database, configure_hexrays, setup_libobfuscated_funcs):
    """Setup fixture for libobfuscated tests - runs once per class."""
    if not idaapi.init_hexrays_plugin():
        pytest.skip("Hex-Rays decompiler plugin not available")
    return ida_database


class TestCoreDeobfuscation:
    """Core deobfuscation tests that must always pass.

    These test the most important and well-established patterns:
    - MBA simplification (XOR, OR, AND, NEG)
    - Tigress unflattening
    - OLLVM unflattening
    - Hodur unflattening
    """

    binary_name = _get_default_binary()

    @pytest.mark.parametrize("case", CORE_CASES, ids=lambda c: c.test_id)
    def test_core_deobfuscation(
        self,
        case,
        libobfuscated_setup,
        d810_state,
        pseudocode_to_string,
        code_comparator,
        capture_stats,
        load_expected_stats,
    ):
        """Core deobfuscation patterns that must work."""
        run_deobfuscation_test(
            case=case,
            d810_state=d810_state,
            pseudocode_to_string=pseudocode_to_string,
            code_comparator=code_comparator,
            capture_stats=capture_stats,
            load_expected_stats=load_expected_stats,
        )


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

    @pytest.mark.parametrize("case", ABC_F6_CASES + ABC_XOR_CASES, ids=lambda c: c.test_id)
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

    @pytest.mark.parametrize("case", UNWRAP_LOOPS_CASES + WHILE_SWITCH_CASES, ids=lambda c: c.test_id)
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


class TestSmoke:
    """Quick smoke tests for CI validation.

    Uses minimal subset of cases for fast feedback.
    """

    binary_name = _get_default_binary()

    @pytest.mark.parametrize("case", SMOKE_CASES, ids=lambda c: c.test_id)
    def test_smoke(
        self,
        case,
        libobfuscated_setup,
        d810_state,
        pseudocode_to_string,
        code_comparator,
        capture_stats,
        load_expected_stats,
    ):
        """Quick smoke tests."""
        run_deobfuscation_test(
            case=case,
            d810_state=d810_state,
            pseudocode_to_string=pseudocode_to_string,
            code_comparator=code_comparator,
            capture_stats=capture_stats,
            load_expected_stats=load_expected_stats,
        )


class TestAllCases:
    """Run all test cases for comprehensive coverage.

    Total cases: {TOTAL_FUNCTION_COUNT}

    Use this for full coverage testing:
        pytest tests/system/test_libdeobfuscated_dsl.py::TestAllCases -v --cov=src/d810/optimizers/microcode
    """

    binary_name = _get_default_binary()

    @pytest.mark.parametrize("case", ALL_CASES, ids=lambda c: c.test_id)
    def test_all(
        self,
        case,
        libobfuscated_setup,
        d810_state,
        pseudocode_to_string,
        code_comparator,
        capture_stats,
        load_expected_stats,
    ):
        """All deobfuscation patterns."""
        run_deobfuscation_test(
            case=case,
            d810_state=d810_state,
            pseudocode_to_string=pseudocode_to_string,
            code_comparator=code_comparator,
            capture_stats=capture_stats,
            load_expected_stats=load_expected_stats,
        )
