from __future__ import annotations

import os
import platform

import pytest

try:
    import idaapi
    import idautils
    import idc

    _IDA_AVAILABLE = True
except Exception:
    _IDA_AVAILABLE = False

from d810.backends.hexrays.ctree_native_ranges import capture_ctree_native_ranges
from d810.ir.native_range_projection import NativeRange

pytestmark = pytest.mark.skipif(not _IDA_AVAILABLE, reason="IDA Pro not available")


def _binary_name() -> str:
    return os.environ.get(
        "D810_TEST_BINARY",
        "libobfuscated.dylib" if platform.system() == "Darwin" else "libobfuscated.dll",
    )


def _resolve_function(name: str) -> int:
    ea = int(idc.get_name_ea_simple(name))
    if ea == int(idaapi.BADADDR):
        ea = int(idc.get_name_ea_simple("_" + name))
    return ea


class TestCtreeNativeRanges:
    binary_name = _binary_name()

    @pytest.fixture(scope="class")
    @classmethod
    def libobfuscated_setup(
        cls,
        ida_database,
        configure_hexrays,
        setup_libobfuscated_funcs,
    ):
        assert idaapi.init_hexrays_plugin()
        return ida_database

    def test_live_boundaries_and_eamap_freeze_deterministically(
        self,
        libobfuscated_setup,
    ) -> None:
        function_ea = _resolve_function("test_function_ollvm_fla_bcf_sub")
        assert function_ea != int(idaapi.BADADDR)
        cfunc = idaapi.decompile(function_ea, flags=idaapi.DECOMP_NO_CACHE)
        assert cfunc is not None
        cfunc.get_pseudocode()

        function_ranges = tuple(
            NativeRange(int(start_ea), int(end_ea))
            for start_ea, end_ea in idautils.Chunks(function_ea)
        )
        first = capture_ctree_native_ranges(
            cfunc,
            function_ranges=function_ranges,
        )
        second = capture_ctree_native_ranges(
            cfunc,
            function_ranges=function_ranges,
        )

        assert first == second
        assert first.statements
        assert first.function_ranges == tuple(sorted(function_ranges))

        by_index = {row.citem_index: row for row in first.statements}
        for insn, rangeset in cfunc.get_boundaries().items():
            if insn.is_epilog():
                continue
            row = by_index[int(insn.index)]
            expected_ranges = tuple(
                NativeRange(
                    int(rangeset.getrange(index).start_ea),
                    int(rangeset.getrange(index).end_ea),
                )
                for index in range(int(rangeset.nranges()))
            )
            assert row.ranges == tuple(sorted(expected_ranges))
            expected_ea = int(insn.ea)
            assert row.representative_ea == (
                None if expected_ea == int(idaapi.BADADDR) else expected_ea
            )

        reverse = dict(first.ea_to_statement_indices)
        for ea, instructions in cfunc.get_eamap().items():
            assert reverse[int(ea)] == tuple(
                sorted(
                    {int(insn.index) for insn in instructions if not insn.is_epilog()}
                )
            )
