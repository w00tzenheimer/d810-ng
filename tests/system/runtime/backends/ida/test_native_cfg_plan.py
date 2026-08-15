from __future__ import annotations

import os
import platform

import pytest

try:
    import idaapi
    import ida_bytes
    import idautils
    import idc

    _IDA_AVAILABLE = True
except Exception:
    _IDA_AVAILABLE = False

from d810.backends.hexrays.ctree_native_ranges import capture_ctree_native_ranges
from d810.backends.hexrays.lifter import lift_function
from d810.backends.ida.native_patch.origin_mapper import IdaNativeOriginMapper
from d810.ir.native_range_projection import NativeRange

pytestmark = pytest.mark.skipif(not _IDA_AVAILABLE, reason="IDA Pro not available")


def _binary_name() -> str:
    return os.environ.get(
        "D810_TEST_BINARY",
        "libobfuscated.dylib" if platform.system() == "Darwin" else "libobfuscated.dll",
    )


class TestNativeCfgOriginMapper:
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

    def test_fresh_mapper_resolves_only_code_heads_inside_ctree_ranges(
        self,
        libobfuscated_setup,
    ) -> None:
        function_ea = int(idc.get_name_ea_simple("test_function_ollvm_fla_bcf_sub"))
        assert function_ea != int(idaapi.BADADDR)
        cfunc = idaapi.decompile(function_ea, flags=idaapi.DECOMP_NO_CACHE)
        assert cfunc is not None
        function_ranges = tuple(
            NativeRange(int(start_ea), int(end_ea))
            for start_ea, end_ea in idautils.Chunks(function_ea)
        )
        projection = capture_ctree_native_ranges(
            cfunc,
            function_ranges=function_ranges,
        )
        ranges = tuple(
            native_range
            for statement in projection.statements
            for native_range in statement.ranges
        )

        decoded = IdaNativeOriginMapper().decode_ranges(ranges)

        assert decoded.instructions
        assert len(decoded.instruction_heads) == len(decoded.instructions)
        assert all(
            any(native_range.contains(insn.ea) for native_range in ranges)
            for insn in decoded.instructions
        )

    def test_conditional_successors_cross_hexrays_native_order_exactly(
        self,
        libobfuscated_setup,
    ) -> None:
        function_ea = int(idc.get_name_ea_simple("test_function_ollvm_fla_bcf_sub"))
        assert function_ea != int(idaapi.BADADDR)
        cfunc = idaapi.decompile(function_ea, flags=idaapi.DECOMP_NO_CACHE)
        assert cfunc is not None
        graph = lift_function(cfunc.mba).flow_graph
        candidates = tuple(
            block
            for block in graph.blocks.values()
            if len(block.succs) == 2
            and block.tail is not None
            and block.tail.native_ea is not None
            and all(
                graph.blocks[target].native_start_ea is not None
                for target in block.succs
            )
        )
        assert candidates
        # BLT_2WAY is [fallthrough, taken]; the native decoder is
        # [taken, fallthrough]. Stage C plan construction normalizes exactly
        # this boundary before matching the live terminator. Some optimized
        # microblocks have a coarser native-start hint than the branch target;
        # those correctly remain unmappable and are not conditional witnesses.
        exact_rows = []
        for source in candidates:
            source_ea = int(source.tail.native_ea)
            source_size = int(ida_bytes.get_item_size(source_ea))
            decoded = IdaNativeOriginMapper().decode_ranges(
                (NativeRange(source_ea, source_ea + source_size),)
            )
            transfers = tuple(
                transfer
                for transfer in decoded.control_transfers
                if transfer.instruction.ea == source_ea
            )
            if len(transfers) != 1:
                continue
            hexrays_targets = tuple(
                int(graph.blocks[target].native_start_ea) for target in source.succs
            )
            if transfers[0].successors == tuple(reversed(hexrays_targets)):
                exact_rows.append((source.serial, source_ea, hexrays_targets))
        assert exact_rows, "fixture must expose an exact conditional origin mapping"
