from __future__ import annotations

import os
import platform

import pytest

try:
    import idaapi
    import idc

    _IDA_AVAILABLE = True
except Exception:
    _IDA_AVAILABLE = False

from d810.backends.hexrays.lifter import lift_function
from d810.backends.hexrays.native_cfg_state import HexRaysNativeEdgeStateProof

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


class TestNativeCfgState:
    binary_name = _binary_name()

    @pytest.fixture(scope="class")
    @classmethod
    def live_graph(cls, ida_database, configure_hexrays, setup_libobfuscated_funcs):
        assert idaapi.init_hexrays_plugin()
        function_ea = _resolve_function("test_function_ollvm_fla_bcf_sub")
        assert function_ea != int(idaapi.BADADDR)
        cfunc = idaapi.decompile(function_ea, flags=idaapi.DECOMP_NO_CACHE)
        assert cfunc is not None
        source = lift_function(cfunc.mba)
        return cfunc, source.flow_graph

    @staticmethod
    def _conditional_edge(graph):
        candidates = tuple(
            block
            for block in graph.blocks.values()
            if len(block.succs) == 2
            and block.native_start_ea is not None
            and all(
                graph.blocks[target].native_start_ea is not None
                for target in block.succs
            )
        )
        assert candidates, "fixture must expose a native-anchored conditional edge"
        source = candidates[0]
        return source, source.succs[0]

    def test_real_mba_lists_produce_a_portable_positive_contract(self, live_graph):
        cfunc, graph = live_graph
        mba = cfunc.mba
        source, target = self._conditional_edge(graph)
        provider = HexRaysNativeEdgeStateProof(
            mba,
            stack_delta_for_ea=lambda _ea: 0,
            target_reads_flags=lambda _ea: False,
        )

        contract = provider.prove_edge_transition(
            graph=graph,
            source_block=source.serial,
            inherited_successors=source.succs,
            final_successors=(target,),
            semantic_proof_ids=("live-mba-semantic-proof",),
        )

        assert contract is not None
        assert contract.permits_control_only_relink is True
        assert "live-mba-semantic-proof" in contract.proof_ids
        assert all(
            location.identity.startswith("hexrays-mlist:")
            for location in contract.required_target_inputs
        )

    @pytest.mark.parametrize(
        ("stack_delta_for_ea", "target_reads_flags"),
        (
            (lambda ea: 0 if ea % 2 == 0 else 8, lambda _ea: False),
            (lambda _ea: 0, lambda _ea: True),
        ),
    )
    def test_live_edge_abstains_on_unresolved_native_state(
        self,
        live_graph,
        stack_delta_for_ea,
        target_reads_flags,
    ):
        cfunc, graph = live_graph
        mba = cfunc.mba
        source, target = self._conditional_edge(graph)
        source_ea = source.tail.native_ea
        target_ea = graph.blocks[target].native_start_ea
        if stack_delta_for_ea(source_ea) == stack_delta_for_ea(target_ea):

            def unequal_stack_delta(ea, source_ea=source_ea):
                return 0 if ea == source_ea else 8

            stack_delta_for_ea = unequal_stack_delta
        provider = HexRaysNativeEdgeStateProof(
            mba,
            stack_delta_for_ea=stack_delta_for_ea,
            target_reads_flags=target_reads_flags,
        )

        assert (
            provider.prove_edge_transition(
                graph=graph,
                source_block=source.serial,
                inherited_successors=source.succs,
                final_successors=(target,),
                semantic_proof_ids=("live-mba-semantic-proof",),
            )
            is None
        )
