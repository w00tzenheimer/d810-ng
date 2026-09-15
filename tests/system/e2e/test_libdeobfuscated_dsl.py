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

import gc
import hashlib
import os
import platform
import time
from pathlib import Path

import pytest

import idaapi
import ida_bytes
import ida_frame
import ida_funcs
import ida_name
import ida_ua
import idc

from d810.testing.runner import get_func_ea, run_deobfuscation_test
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
from tests.system.e2e.hash_bound_fixture_receipts import (
    HASH_BOUND_LINKED_EXTENTS,
    assert_complete_recovery,
    load_hash_bound_fixture_receipt,
)
from tests.system.e2e.hash_bound.hash_bound_semantic_oracle import (
    evaluate_fixture_semantics,
    load_fixture_references,
    recovered_semantics_from_diagnostics,
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
    # d81-vp29: exact structural export of loader build 12.1.0.69587.
    # MASM relaxes several branches and removes the source table's absolute
    # displacement, so the linked fixture's measured dense instruction range
    # is 0x30C5 rather than the source function's 0x30E9.
    # Recreate it so fresh IDA analysis cannot truncate the function at its
    # embedded switch/jump-table edges.
    "sub_7FFB0DE93330": 0x30C5,
    # Hash-bound structural exports. These are the measured Microsoft-COFF
    # .text extents, not the source-image extents: ml64 branch relaxation can
    # shrink or grow a semantic reassembly.
    **HASH_BOUND_LINKED_EXTENTS,
}

_HASH_BOUND_MASM_FUNCTIONS = tuple(HASH_BOUND_LINKED_EXTENTS)
_HASH_BOUND_SEMANTICS = load_fixture_references(
    Path(__file__).resolve().parents[3]
    / "samples"
    / "src"
    / "masm"
    / "hash_bound_seven_semantics.json"
)
_X64_NONVOLATILE_GPRS = frozenset(
    {"rbx", "rbp", "rsi", "rdi", *(f"r{index}" for index in range(12, 16))}
)


def _assert_hash_bound_fixture_inventory() -> None:
    resolved = {}
    for function in _HASH_BOUND_MASM_FUNCTIONS:
        ea = idc.get_name_ea_simple(function)
        if ea == idaapi.BADADDR:
            ea = idc.get_name_ea_simple(f"_{function}")
        resolved[function] = ea
    present = {function for function, ea in resolved.items() if ea != idaapi.BADADDR}
    if not present and Path(_get_default_binary()).suffix.lower() != ".dll":
        return
    assert present == set(_HASH_BOUND_MASM_FUNCTIONS), (
        "partial hash-bound fixture corpus",
        sorted(set(_HASH_BOUND_MASM_FUNCTIONS) - present),
    )


def _restore_manual_x64_frame_shape(function: ida_funcs.func_t) -> None:
    """Restore the frame split proved by one canonical manual prologue."""

    cursor = int(function.start_ea)
    saved_register_size = 0
    while str(idc.print_insn_mnem(cursor) or "").lower() == "push":
        register = str(idc.print_operand(cursor, 0) or "").lower()
        if register not in _X64_NONVOLATILE_GPRS:
            return
        saved_register_size += 8
        cursor = int(ida_bytes.next_head(cursor, int(function.end_ea)))
    if (
        saved_register_size == 0
        or str(idc.print_insn_mnem(cursor) or "").lower() != "sub"
        or str(idc.print_operand(cursor, 0) or "").lower() != "rsp"
    ):
        return
    local_size = int(idc.get_operand_value(cursor, 1))
    if local_size <= 0:
        return
    # The loader can create a frame whose numeric total is plausible while its
    # mandatory return-address/saved-register members are absent.  Resizing
    # that object does not recreate those members, and Hex-Rays rejects it as
    # MERR_BADFRAME.  This is a disposable fixture IDB, so rebuild the frame
    # from the decoded canonical prologue instead of preserving stale members.
    if function.get_frame_object() is not None:
        assert ida_frame.del_frame(function)
    assert ida_frame.add_frame(
        function,
        local_size,
        saved_register_size,
        int(function.argsize),
    )
    assert int(function.frsize) == local_size
    assert int(function.frregs) == saved_register_size


def _materialize_exact_masm_code_extent(function: str) -> None:
    size = _EXACT_MASM_CODE_EXTENTS.get(function)
    if size is None:
        return
    start = idc.get_name_ea_simple(function)
    if start == idaapi.BADADDR:
        start = idc.get_name_ea_simple(f"_{function}")
    assign_canonical_name = False
    if start == idaapi.BADADDR and function in _HASH_BOUND_SEMANTICS:
        reference = _HASH_BOUND_SEMANTICS[function]
        start = int(idaapi.get_imagebase()) + int(reference.entry_rva)
        native_bytes = ida_bytes.get_bytes(int(start), int(reference.extent))
        assert native_bytes is not None and len(native_bytes) == reference.extent
        assert hashlib.sha256(native_bytes).hexdigest() == reference.linked_sha256
        assign_canonical_name = True
    assert start != idaapi.BADADDR, function
    end = int(start) + int(size)
    materialized = ida_funcs.get_func(int(start))
    if materialized is not None:
        assert int(materialized.start_ea) == int(start)

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

    if materialized is None:
        assert ida_funcs.add_func(int(start), end), (
            f"could not create exact fixture function {function}: "
            f"0x{int(start):X}-0x{end:X}"
        )
        idaapi.auto_wait()
        materialized = ida_funcs.get_func(int(start))
        assert materialized is not None, function

    function_end = int(materialized.end_ea)
    if function_end < end:
        assert ida_funcs.append_func_tail(materialized, function_end, end), (
            f"could not append the measured linked tail for {function}: "
            f"0x{function_end:X}-0x{end:X}"
        )
    elif function_end > end:
        assert ida_funcs.set_func_end(int(start), end), (
            f"could not trim {function} to its measured linked extent: "
            f"observed 0x{function_end:X}, expected 0x{end:X}"
        )
    idaapi.auto_wait()
    function_end = int(idc.get_func_attr(int(start), idc.FUNCATTR_END))
    assert function_end == end, (
        function,
        hex(int(start)),
        hex(function_end),
        hex(end),
    )
    _restore_manual_x64_frame_shape(materialized)
    if assign_canonical_name:
        exported_name = f"_{function}"
        assert idc.set_name(int(start), exported_name, ida_name.SN_FORCE)
        assert idc.get_name_ea_simple(exported_name) == int(start)
    idaapi.mark_cfunc_dirty(int(start), False)


def _materialize_hash_bound_masm_corpus() -> None:
    """Stabilize every fixture function before Hex-Rays caches any cfunc.

    Recreating a later fixture's instruction heads after an earlier fixture
    has already been decompiled can invalidate Hex-Rays' process-local
    pseudocode vector wrappers.  The symptom is a non-iterable SwigPyObject,
    not a recovery result.  Materialize the complete measured corpus first so
    the batch and isolated-test lifecycles exercise the same IDB topology.
    """

    for function in _HASH_BOUND_MASM_FUNCTIONS:
        _materialize_exact_masm_code_extent(function)


def _assert_hash_bound_route_certification(
    *, function: str, function_ea: int, diagnostics_db: Path
) -> None:
    """Certify affected dispatcher routes against exact native bytes."""

    reference = _HASH_BOUND_SEMANTICS[function]
    native_bytes = ida_bytes.get_bytes(function_ea, reference.extent)
    assert native_bytes is not None and len(native_bytes) == reference.extent
    assert hashlib.sha256(native_bytes).hexdigest() == reference.linked_sha256
    recovered = recovered_semantics_from_diagnostics(
        reference=reference,
        function_ea=function_ea,
        diagnostics_db=diagnostics_db,
    )
    result = evaluate_fixture_semantics(reference, recovered)
    assert result.passed, (
        function,
        tuple((item.code, item.detail) for item in result.blockers),
    )


def _assert_hash_bound_native_slice_semantics(*, function: str) -> None:
    """Run independent exact-byte selector slices where references exist."""

    if function not in {"sub_7FFB0E086BE0", "sub_7FFB0E1E69E0"}:
        return
    from tests.system.e2e.hash_bound.native_transition_oracle import (
        NativeTransitionStatus,
        prove_linked_native_transition,
    )
    from tests.system.e2e.hash_bound.native_transition_references import (
        e086be0_gs_selector_slice,
        e086be0_missing_native_slices,
        e1e69e0_native_slices,
    )

    if function == "sub_7FFB0E086BE0":
        image_slices = e086be0_missing_native_slices(int(idaapi.get_imagebase()))
        expected_targets = (
            "handler_8A5BB",
            "handler_8AFD5",
            "handler_8A988",
            "handler_8AD56",
            "handler_8A8B0",
        )
        expected_selector_values = (
            0x7ACCC969,
            0x76711AAE,
            0x51FAE032,
            0x7C35A383,
            0x4C815853,
        )
    else:
        image_slices = e1e69e0_native_slices(int(idaapi.get_imagebase()))
        expected_targets = ("state_6e8e902a", "atomic_lock_seto", "return")
        expected_selector_values = (0x6E8E902A, 0x199A79B7, 0x2E7FCF22)
    receipts = []
    for image_slice in image_slices:
        receipts.append(
            prove_linked_native_transition(
                image_slice,
                read_linked_bytes=lambda ea, size: ida_bytes.get_bytes(ea, size),
            )
        )
        gc.collect()
    assert tuple(receipt.status for receipt in receipts) == (
        NativeTransitionStatus.RESOLVED,
    ) * len(receipts), tuple(receipt.reason for receipt in receipts)
    assert tuple(receipt.target for receipt in receipts) == expected_targets
    assert tuple(receipt.selector_value for receipt in receipts) == (
        expected_selector_values
    )
    if function == "sub_7FFB0E086BE0":
        gs_receipt = prove_linked_native_transition(
            e086be0_gs_selector_slice(int(idaapi.get_imagebase())),
            read_linked_bytes=lambda ea, size: ida_bytes.get_bytes(ea, size),
        )
        gc.collect()
        assert gs_receipt.status is NativeTransitionStatus.RESOLVED
        assert gs_receipt.target == "selector_3076403d"
        assert gs_receipt.selector_value == 0x3076403D


def _assert_e086_native_selector_inventory(*, function_ea: int) -> None:
    """Require the complete pristine-native structural write inventory for E086."""

    from tests.system.e2e.hash_bound.native_ida_transition_adapter import (
        capture_native_selector_cfg,
    )
    from tests.system.e2e.hash_bound.native_transition_oracle import (
        enumerate_selector_routes,
    )

    blocks = capture_native_selector_cfg(
        function_ea,
        selector_stack_displacement=0x48,
        selector_width=4,
    )
    dispatcher_entry_ea = function_ea + (0x86B0B - 0x86958)
    routes = enumerate_selector_routes(
        blocks,
        dispatcher_entries=(dispatcher_entry_ea,),
    )
    expected_write_eas = tuple(
        function_ea + (rva - 0x86958)
        for rva in (
            0x869BD,
            0x86B07,
            0x86DC6,
            0x8A61F,
            0x8AA43,
            0x8AE45,
            0x8C463,
            0x8C968,
            0x8CC3D,
            0x8D0FD,
            0x8D56A,
            0x8E9D8,
            0x8EB73,
            0x8ECBF,
        )
    )
    observed_write_eas = tuple(
        sorted({route.state_write_ea for route in routes})
    )
    if observed_write_eas != expected_write_eas:
        rendered_routes = "\n".join(
            "source={} write={} dispatcher={} corridor={}".format(
                hex(route.source_ea),
                hex(route.state_write_ea),
                hex(route.dispatcher_entry_ea),
                ",".join(hex(ea) for ea in route.corridor_block_eas),
            )
            for route in routes
        )
        raise AssertionError(f"native route inventory changed:\n{rendered_routes}")
    route_counts_by_write = tuple(
        (
            hex(write_ea),
            sum(route.state_write_ea == write_ea for route in routes),
        )
        for write_ea in sorted({route.state_write_ea for route in routes})
    )
    expected_counts = (1, 5, 1, 1, 1, 1, 1, 1, 1, 1, 1, 3, 1, 2)
    assert tuple(count for _, count in route_counts_by_write) == expected_counts, (
        "\n".join(f"{write_ea}: {count}" for write_ea, count in route_counts_by_write)
    )
    assert len(routes) == sum(expected_counts), "\n".join(
        f"{write_ea}: {count}" for write_ea, count in route_counts_by_write
    )


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

    def test_hash_bound_native_transition_references(
        self, libobfuscated_setup
    ) -> None:
        """Keep exact native completeness/proof checks in the fast lane."""

        _materialize_hash_bound_masm_corpus()
        _assert_hash_bound_fixture_inventory()
        _assert_e086_native_selector_inventory(
            function_ea=int(get_func_ea("sub_7FFB0E086BE0"))
        )
        _assert_hash_bound_native_slice_semantics(function="sub_7FFB0E086BE0")
        _assert_hash_bound_native_slice_semantics(function="sub_7FFB0E1E69E0")

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
        if case.function in _HASH_BOUND_MASM_FUNCTIONS:
            _materialize_hash_bound_masm_corpus()
            _assert_hash_bound_fixture_inventory()
        else:
            _materialize_exact_masm_code_extent(case.function)
        started_at = time.monotonic()
        run_deobfuscation_test(
            case=case,
            d810_state=d810_state,
            pseudocode_to_string=pseudocode_to_string,
            code_comparator=code_comparator,
            capture_stats=capture_stats,
            load_expected_stats=load_expected_stats,
        )
        if case.function in _HASH_BOUND_MASM_FUNCTIONS:
            assert os.environ.get("D810_DIAG_SNAPSHOT", "").strip().lower() in {
                "1",
                "true",
                "yes",
                "on",
            }, "hash-bound fixtures require diagnostic capture"
            from d810.core.diag import find_latest_diag_db_path

            function_ea = int(get_func_ea(case.function))
            diagnostics_db = find_latest_diag_db_path(function_ea)
            assert diagnostics_db is not None, (
                f"diagnostics DB missing for {case.function} at 0x{function_ea:X}"
            )
            log_directory = Path(
                os.environ.get("D810_DIAG_LOG_DIR", diagnostics_db.parent)
            ).resolve()
            assert_complete_recovery(
                load_hash_bound_fixture_receipt(
                    function=case.function,
                    code_size=HASH_BOUND_LINKED_EXTENTS[case.function],
                    diagnostics_db=diagnostics_db,
                    run_directory=log_directory.parent,
                    wall_seconds=time.monotonic() - started_at,
                    selector=None,
                    # Reaching this point means the case-specific final
                    # pseudocode assertions above all passed.
                    final_output_verified=True,
                )
            )
            _assert_hash_bound_route_certification(
                function=case.function,
                function_ea=function_ea,
                diagnostics_db=diagnostics_db,
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
