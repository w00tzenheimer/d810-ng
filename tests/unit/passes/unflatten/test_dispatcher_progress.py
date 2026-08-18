from __future__ import annotations

from d810.analyses.control_flow.dispatcher_resolution import (
    DispatcherCandidateIdentity,
)
from d810.capabilities.dispatcher import RouterKind
from d810.ir.flowgraph import (
    BlockSnapshot,
    FlowGraph,
    InsnKind,
    InsnSnapshot,
    MopSnapshot,
    OperandKind,
)
from d810.ir.maturity import IRMaturity
from d810.passes.unflatten.dispatcher_progress import (
    DispatcherProgressLedger,
    flowgraph_content_fingerprint,
)


_OUTER = DispatcherCandidateIdentity(
    resolver_name="equality_chain",
    router_kind=RouterKind.CONDITION_CHAIN,
    table_provenance=None,
    dispatcher_entry_ea=0x401100,
    state_location_kind="stack",
    state_location_value=0xC,
)
_MAT = IRMaturity.GLOBAL_ANALYZED
_MAT2 = IRMaturity.GLOBAL_OPTIMIZED


def test_repeated_no_progress_excludes_only_candidate_on_exact_graph():
    ledger = DispatcherProgressLedger(stall_threshold=2)

    ledger.record_no_progress(0x401000, _MAT, "graph-a", _OUTER)
    assert ledger.excluded_identities(0x401000, _MAT, "graph-a") == frozenset()

    ledger.record_no_progress(0x401000, _MAT, "graph-a", _OUTER)

    assert ledger.excluded_identities(0x401000, _MAT, "graph-a") == frozenset(
        {_OUTER}
    )
    assert ledger.excluded_identities(0x401000, _MAT, "graph-b") == frozenset()
    assert ledger.excluded_identities(0x401000, _MAT2, "graph-a") == frozenset()


def test_committed_progress_clears_stall_history_for_candidate():
    ledger = DispatcherProgressLedger(stall_threshold=2)
    ledger.record_no_progress(0x401000, _MAT, "graph-a", _OUTER)
    ledger.record_no_progress(0x401000, _MAT, "graph-a", _OUTER)
    assert _OUTER in ledger.excluded_identities(0x401000, _MAT, "graph-a")

    ledger.record_progress(0x401000, _MAT, _OUTER)

    assert ledger.excluded_identities(0x401000, _MAT, "graph-a") == frozenset()


def test_reset_function_does_not_clear_other_function_history():
    ledger = DispatcherProgressLedger(stall_threshold=1)
    ledger.record_no_progress(0x401000, _MAT, "graph-a", _OUTER)
    ledger.record_no_progress(0x402000, _MAT, "graph-b", _OUTER)

    ledger.reset_function(0x401000)

    assert ledger.excluded_identities(0x401000, _MAT, "graph-a") == frozenset()
    assert ledger.excluded_identities(0x402000, _MAT, "graph-b") == frozenset(
        {_OUTER}
    )


def test_exhausted_graph_is_exact_and_cleared_by_function_reset():
    ledger = DispatcherProgressLedger()

    ledger.record_exhausted(0x401000, _MAT, "graph-a")

    assert ledger.is_exhausted(0x401000, _MAT, "graph-a")
    assert not ledger.is_exhausted(0x401000, _MAT, "graph-b")
    assert not ledger.is_exhausted(0x401000, _MAT2, "graph-a")
    ledger.reset_function(0x401000)
    assert not ledger.is_exhausted(0x401000, _MAT, "graph-a")


def test_graph_fingerprint_ignores_instruction_changes_without_topology_change():
    def graph_with_instruction(opcode: int, value: int) -> FlowGraph:
        insn = InsnSnapshot(
            opcode=opcode,
            ea=0x401100,
            operands=(),
            kind=InsnKind.MOV,
            l=MopSnapshot(kind=OperandKind.NUMBER, value=value),
        )
        block = BlockSnapshot(
            serial=0,
            block_type=0,
            succs=(),
            preds=(),
            flags=0,
            start_ea=0x401100,
            insn_snapshots=(insn,),
        )
        return FlowGraph(
            blocks={0: block},
            entry_serial=0,
            func_ea=0x401000,
            metadata={"maturity_name": "MMAT_GLBOPT1"},
        )

    baseline = flowgraph_content_fingerprint(graph_with_instruction(1, 0x10))

    assert baseline == flowgraph_content_fingerprint(graph_with_instruction(2, 0x10))
    assert baseline == flowgraph_content_fingerprint(graph_with_instruction(1, 0x20))


def test_graph_fingerprint_changes_when_topology_changes():
    def graph_with_successors(*successors: int) -> FlowGraph:
        blocks = {
            serial: BlockSnapshot(
                serial=serial,
                block_type=0,
                succs=(() if serial else tuple(successors)),
                preds=(() if serial == 0 else (0,)),
                flags=0,
                start_ea=0x401100 + serial * 0x10,
                insn_snapshots=(),
            )
            for serial in range(max(successors, default=0) + 1)
        }
        return FlowGraph(
            blocks=blocks,
            entry_serial=0,
            func_ea=0x401000,
            metadata={"maturity_name": "MMAT_GLBOPT1"},
        )

    assert flowgraph_content_fingerprint(
        graph_with_successors(1)
    ) != flowgraph_content_fingerprint(graph_with_successors(1, 2))


def test_graph_fingerprint_ignores_control_tail_rewrites_when_edges_are_unchanged():
    def graph_with_tail(display_text: str) -> FlowGraph:
        tail = InsnSnapshot(
            opcode=1,
            ea=0x401100,
            operands=(),
            display_text=display_text,
            kind=InsnKind.GOTO,
            d=MopSnapshot(kind=OperandKind.BLOCK, block_ref=1),
        )
        return FlowGraph(
            blocks={
                0: BlockSnapshot(
                    serial=0,
                    block_type=1,
                    succs=(1,),
                    preds=(),
                    flags=0,
                    start_ea=0x401100,
                    insn_snapshots=(tail,),
                ),
                1: BlockSnapshot(
                    serial=1,
                    block_type=0,
                    succs=(),
                    preds=(0,),
                    flags=0,
                    start_ea=0x401110,
                    insn_snapshots=(),
                ),
            },
            entry_serial=0,
            func_ea=0x401000,
        )

    assert flowgraph_content_fingerprint(
        graph_with_tail("goto 1")
    ) == flowgraph_content_fingerprint(graph_with_tail("goto blk1"))
