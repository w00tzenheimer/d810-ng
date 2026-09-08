"""Graph observation must preserve native instruction and edge identity."""
from __future__ import annotations

import pytest
import ida_hexrays

from d810.evaluator.hexrays_microcode import chains
from d810.hexrays.ir import exact_data_flow
from d810.backends.hexrays.evidence.instruction_value_flow_live import build_live_instruction_flow
from d810.backends.hexrays.evidence.dead_store_liveness_live import HexRaysDeadStoreLivenessBackend
from tests.system.runtime.conftest import gen_microcode_at_maturity, get_func_ea


def _fingerprint(mba):
    blocks = []
    for serial in range(mba.qty):
        block = mba.get_mblock(serial)
        instructions = []
        instruction = block.head
        while instruction is not None:
            instructions.append((int(instruction.this), int(instruction.ea), int(instruction.opcode), instruction.dstr()))
            instruction = instruction.next
        blocks.append((serial, int(block.start), tuple(block.succ(i) for i in range(block.nsucc())), tuple(instructions)))
    return tuple(blocks)


class _ObserveMba:
    """Forward real SDK access, recording forbidden rebuild attempts."""
    def __init__(self, mba):
        self.native = mba
        self.rebuilds = 0
        self.graph_reads = 0

    def __getattr__(self, name):
        return getattr(self.native, name)

    def get_graph(self):
        self.graph_reads += 1
        return self.native.get_graph()

    def build_graph(self):
        self.rebuilds += 1
        raise RuntimeError("read-only analysis attempted graph rebuild")


def _invoke(consumer, mba):
    if consumer == "collector":
        return HexRaysDeadStoreLivenessBackend().collect(mba)
    if consumer == "flow":
        return build_live_instruction_flow(mba, ())
    if consumer == "chains":
        return chains.ensure_graph_and_lists_ready(mba)
    return exact_data_flow.ensure_graph_and_lists_ready(mba)


@pytest.mark.usefixtures("libobfuscated_setup")
class TestNativeGraphObservation:
    binary_name = "libobfuscated.dll"

    @pytest.mark.parametrize("consumer", ("collector", "flow", "chains", "exact"))
    def test_mature_analysis_never_rebuilds_real_graph(self, consumer):
        mba = gen_microcode_at_maturity(get_func_ea("test_cst_simplification"), ida_hexrays.MMAT_GLBOPT2)
        assert mba is not None
        assert mba.get_graph() is not None
        before = _fingerprint(mba)
        observed = _ObserveMba(mba)
        _invoke(consumer, observed)
        assert observed.rebuilds == 0
        assert observed.graph_reads >= 1
        assert _fingerprint(mba) == before

    @pytest.mark.parametrize("maturity", (ida_hexrays.MMAT_PREOPTIMIZED, ida_hexrays.MMAT_LOCOPT))
    def test_early_graph_ownership_is_not_taken_by_analysis(self, maturity):
        from d810.hexrays.ir.graph_readiness import GraphReadinessUnavailable, require_graph_ready
        mba = gen_microcode_at_maturity(get_func_ea("test_cst_simplification"), maturity)
        assert mba is not None
        observed = _ObserveMba(mba)
        before = _fingerprint(mba)
        if maturity < ida_hexrays.MMAT_LOCOPT:
            with pytest.raises(GraphReadinessUnavailable, match="LOCOPT"):
                require_graph_ready(observed)
            assert observed.graph_reads == 0
        else:
            assert require_graph_ready(observed) is not None
        assert observed.rebuilds == 0
        assert _fingerprint(mba) == before

    @pytest.mark.parametrize("consumer", ("collector", "flow", "chains", "exact"))
    @pytest.mark.parametrize("failure", ("missing", "null", "runtime"))
    def test_unavailable_graph_never_falls_back_to_build(self, consumer, failure):
        from d810.hexrays.ir.graph_readiness import GraphReadinessUnavailable
        from d810.backends.hexrays.evidence.instruction_value_flow_live import LiveInstructionFlowUnavailable
        from d810.analyses.value_flow.dead_store import DeadStoreRejectionReason
        mba = gen_microcode_at_maturity(get_func_ea("test_cst_simplification"), ida_hexrays.MMAT_GLBOPT2)
        assert mba is not None
        observed = _ObserveMba(mba)
        def unavailable():
            if failure == "missing":
                raise AttributeError("get_graph")
            if failure == "runtime":
                raise RuntimeError("SDK graph unavailable")
            return None
        observed.get_graph = unavailable
        before = _fingerprint(mba)
        if consumer == "collector":
            evidence = _invoke(consumer, observed)
            assert not evidence.candidates
            assert {r.reason for r in evidence.rejections} == {DeadStoreRejectionReason.CHAIN_UNAVAILABLE}
        else:
            expected = LiveInstructionFlowUnavailable if consumer == "flow" else GraphReadinessUnavailable
            with pytest.raises(expected):
                _invoke(consumer, observed)
        assert observed.rebuilds == 0
        assert _fingerprint(mba) == before
