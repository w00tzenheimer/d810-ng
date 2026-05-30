from d810.ir.block_identity import (
    block_fingerprint,
    block_label,
    edge_label,
    flow_graph_context_label,
)
from d810.ir.flowgraph import BlockSnapshot, FlowGraph, InsnSnapshot


def _graph() -> FlowGraph:
    return FlowGraph(
        blocks={
            33: BlockSnapshot(
                serial=33,
                block_type=1,
                succs=(24,),
                preds=(28,),
                flags=0,
                start_ea=0x18001340F,
                insn_snapshots=(
                    InsnSnapshot(opcode=1, ea=0x18001340F, operands=()),
                    InsnSnapshot(opcode=2, ea=0x180013421, operands=()),
                ),
            ),
            24: BlockSnapshot(
                serial=24,
                block_type=1,
                succs=(32,),
                preds=(33,),
                flags=0,
                start_ea=0x18001304A,
                insn_snapshots=(
                    InsnSnapshot(opcode=3, ea=0x18001304A, operands=()),
                ),
            ),
        },
        entry_serial=33,
        func_ea=0x180012B60,
        metadata={"maturity": 5, "snapshot_id": 8, "phase": "post_apply"},
    )


def test_block_identity_labels_include_ea_and_context():
    graph = _graph()

    assert block_label(graph, 33) == "blk[33]@0x18001340f"
    assert edge_label(graph, 33, 24) == (
        "blk[33]@0x18001340f -> blk[24]@0x18001304a"
    )
    assert flow_graph_context_label(graph) == (
        "maturity=MMAT_GLBOPT1 snapshot=8 phase=post_apply"
    )


def test_block_identity_fingerprint_uses_instruction_ea_and_opcode():
    graph = _graph()

    assert block_fingerprint(graph, 33) == (
        "fp=[0x18001340f:op1,0x180013421:op2]"
    )
