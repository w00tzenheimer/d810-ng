"""Real-IDA coverage for global reads handled by Simplify constants."""

from __future__ import annotations

import os
import platform
import struct

import pytest

import ida_bytes
import ida_segment
import idaapi

from d810.analyses.value_flow.global_constness import GlobalConstReason
from d810.backends.hexrays.evidence.global_constness import decide_hexrays_global_read
from d810.testing.cases import BinaryOverride, DeobfuscationCase
from d810.testing.runner import run_deobfuscation_test


def _get_default_binary() -> str:
    override = os.environ.get("D810_TEST_BINARY")
    if override:
        return override
    return (
        "libobfuscated.dylib"
        if platform.system() == "Darwin"
        else "libobfuscated.dll"
    )


def _find_in_readonly_data(target_value: int, size: int = 8) -> int:
    pattern = struct.pack("<Q" if size == 8 else "<I", target_value)
    segment = ida_segment.get_first_seg()
    while segment is not None:
        permissions = int(segment.perm)
        if (
            permissions & int(ida_segment.SEGPERM_READ)
            and not permissions & int(ida_segment.SEGPERM_WRITE)
        ):
            ea = segment.start_ea
            end = segment.end_ea - size + 1
            while ea < end:
                if ida_bytes.get_bytes(ea, size) == pattern:
                    return ea
                ea += 1
        segment = ida_segment.get_next_seg(segment.start_ea)
    return idaapi.BADADDR


GLOBAL_READ_CASES = [
    DeobfuscationCase(
        function="constant_folding_test1",
        description=(
            "Simplify constants materializes supported read-only table values "
            "before expression folding and propagation."
        ),
        project="default_instruction_only.json",
        must_change=False,
        check_stats=True,
        expected_rules=[],
    ),
    DeobfuscationCase(
        function="constant_folding_test2",
        description=(
            "Simplify constants replaces supported global-memory reads in "
            "complex bitwise expressions."
        ),
        project="default_instruction_only.json",
        deobfuscated_regexes=[r"return 0x8B8D2D6A09D84F79u?LL;"],
        must_change=True,
        check_stats=True,
        required_rules=["FoldReadonlyDataRule"],
        expected_rules=[],
    ),
    DeobfuscationCase(
        function="global_const_rva_guard",
        description=(
            "Simplify constants may inline ordinary numeric constants but must "
            "not materialize an RVA-like pointer as raw MEMORY[0x...] input."
        ),
        project="default_instruction_only.json",
        must_change=False,
        check_stats=True,
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
    import idaapi

    if not idaapi.init_hexrays_plugin():
        pytest.skip("Hex-Rays decompiler plugin not available")
    return ida_database


class TestConstantSimplificationGlobalReads:
    """Verify the consolidated operation against real decompilation output."""

    binary_name = _get_default_binary()

    @pytest.mark.ida_required
    @pytest.mark.parametrize("case", GLOBAL_READ_CASES, ids=lambda case: case.test_id)
    def test_global_read_simplification(
        self,
        case,
        libobfuscated_setup,
        d810_state,
        pseudocode_to_string,
        code_comparator,
        capture_stats,
        load_expected_stats,
    ):
        run_deobfuscation_test(
            case=case,
            d810_state=d810_state,
            pseudocode_to_string=pseudocode_to_string,
            code_comparator=code_comparator,
            capture_stats=capture_stats,
            load_expected_stats=load_expected_stats,
        )

    @pytest.mark.ida_required
    def test_rebased_rva_is_rejected_by_shared_decision(self, libobfuscated_setup):
        if platform.system() == "Darwin":
            pytest.skip("PE/RVA-specific fixture")
        ea = _find_in_readonly_data(0x2000)
        if ea == idaapi.BADADDR:
            pytest.skip("RVA_LIKE_OFFSET fixture not found")

        decision = decide_hexrays_global_read(ea, 8)

        assert decision.can_inline_read is False
        assert decision.reason is GlobalConstReason.POINTER_LIKE_VALUE

    @pytest.mark.ida_required
    def test_non_pointer_value_is_accepted_by_shared_decision(
        self, libobfuscated_setup
    ):
        safe_value = 0x1122334455667788
        ea = _find_in_readonly_data(safe_value)
        if ea == idaapi.BADADDR:
            pytest.skip("SAFE_INLINE_CONST fixture not found")

        decision = decide_hexrays_global_read(ea, 8)

        assert decision.can_inline_read is True
        assert decision.value == safe_value
