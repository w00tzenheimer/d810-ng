"""Exact semantic exclusions for structurally reachable effect branches."""

from dataclasses import replace

from d810.analyses.control_flow.effect_branch_exclusion import (
    build_exact_state_branch_effect_exclusion,
    validate_exact_state_branch_effect_exclusion,
)
from d810.ir.expressions import ValueOpKind
from d810.ir.flowgraph import (
    BlockKind,
    BlockSnapshot,
    FlowGraph,
    InsnKind,
    InsnSnapshot,
    MopSnapshot,
    OperandKind,
    PredicateKind,
)
from d810.ir.storage_identity import StorageIdentity, StorageIdentityKind


STATE = 0x40131868
STATE_OFFSET = 1724


def _number(value: int) -> MopSnapshot:
    return MopSnapshot(kind=OperandKind.NUMBER, size=4, value=int(value))


def _stack(offset: int) -> MopSnapshot:
    return MopSnapshot(
        kind=OperandKind.STACK,
        size=4,
        stkoff=int(offset),
        stack_refs=(int(offset),),
    )


def _block(
    serial: int,
    succs: tuple[int, ...],
    preds: tuple[int, ...],
    *,
    ea: int,
    insns: tuple[InsnSnapshot, ...] = (),
) -> BlockSnapshot:
    return BlockSnapshot(
        serial=int(serial),
        block_type=0,
        succs=succs,
        preds=preds,
        flags=0,
        start_ea=int(ea),
        native_start_ea=int(ea),
        insn_snapshots=insns,
        kind=(
            BlockKind.TWO_WAY
            if len(succs) == 2
            else BlockKind.ONE_WAY
            if len(succs) == 1
            else BlockKind.ZERO_WAY
        ),
    )


def _fixture() -> FlowGraph:
    state = _stack(STATE_OFFSET)
    source = _block(
        452,
        (78,),
        (361,),
        ea=0x18002A9CE,
        insns=(
            InsnSnapshot(
                opcode=4,
                ea=0x18002A9E6,
                native_ea=0x18002A9E6,
                operands=(),
                l=_number(STATE),
                d=state,
                kind=InsnKind.MOV,
                value_op_kind=ValueOpKind.MOVE,
            ),
            InsnSnapshot(
                opcode=55,
                ea=0x18002A9EC,
                native_ea=0x18002A9EC,
                operands=(),
                l=MopSnapshot(kind=OperandKind.BLOCK, block_ref=78),
                kind=InsnKind.GOTO,
            ),
        ),
    )
    predicate = _block(
        78,
        (79, 546),
        (77, 284, 452),
        ea=0x180016411,
        insns=(
            InsnSnapshot(
                opcode=43,
                ea=0x180016416,
                native_ea=0x180016416,
                operands=(),
                l=state,
                r=_number(STATE),
                d=MopSnapshot(kind=OperandKind.BLOCK, block_ref=546),
                kind=InsnKind.COND_JUMP,
                branch_predicate=PredicateKind.NE,
                is_conditional_jump=True,
            ),
        ),
    )
    effect = _block(
        546,
        (547,),
        (78,),
        ea=0x18002CF19,
        insns=(
            InsnSnapshot(
                opcode=57,
                ea=0x18002CF2E,
                native_ea=0x18002CF2E,
                operands=(),
                kind=InsnKind.CALL,
                is_call=True,
            ),
        ),
    )
    blocks = {
        0: _block(0, (361,), (), ea=0x180015110),
        361: _block(361, (452,), (0,), ea=0x180024900),
        77: _block(77, (78,), (), ea=0x180016400),
        284: _block(284, (78,), (), ea=0x18001D000),
        452: source,
        78: predicate,
        79: _block(79, (), (78,), ea=0x180016420),
        546: effect,
        547: _block(547, (), (546,), ea=0x18002CF40),
    }
    return FlowGraph(blocks=blocks, entry_serial=0, func_ea=0x180015110)


def _proof(graph: FlowGraph):
    return build_exact_state_branch_effect_exclusion(
        graph,
        graph,
        normalized_state=STATE,
        source_serial=452,
        predicate_serial=78,
        selected_target_serial=79,
        discarded_effect_serial=546,
        state_identity=StorageIdentity(StorageIdentityKind.STACK, STATE_OFFSET),
    )


def test_exact_ingress_state_certifies_private_infeasible_effect_arm() -> None:
    graph = _fixture()

    proof = _proof(graph)

    assert proof is not None
    assert proof.source_ea == 0x18002A9CE
    assert proof.source_write_ea == 0x18002A9E6
    assert proof.predicate_ea == 0x180016411
    assert proof.predicate_branch_ea == 0x180016416
    assert proof.discarded_effect_ea == 0x18002CF19
    assert validate_exact_state_branch_effect_exclusion(graph, graph, proof)


def test_exact_effect_exclusion_requires_exhaustive_reachable_ingress() -> None:
    graph = _fixture()
    proof = _proof(graph)
    assert proof is not None
    blocks = dict(graph.blocks)
    blocks[0] = replace(blocks[0], succs=(361, 77))
    blocks[77] = replace(blocks[77], preds=(0,))
    ambiguous = replace(graph, blocks=blocks)

    assert not validate_exact_state_branch_effect_exclusion(
        graph,
        ambiguous,
        proof,
    )


def test_exact_effect_exclusion_replays_source_state_and_predicate() -> None:
    graph = _fixture()
    proof = _proof(graph)
    assert proof is not None
    source = graph.blocks[452]
    write = source.insn_snapshots[0]
    forged_source = replace(
        source,
        insn_snapshots=(replace(write, l=_number(STATE + 1)), *source.insn_snapshots[1:]),
    )
    forged = replace(graph, blocks={**graph.blocks, 452: forged_source})

    assert not validate_exact_state_branch_effect_exclusion(forged, forged, proof)


def test_exact_effect_exclusion_is_limited_to_immediate_private_effect_block() -> None:
    graph = _fixture()
    proof = _proof(graph)
    assert proof is not None
    effect = replace(graph.blocks[546], preds=(78, 284))
    malformed = replace(graph, blocks={**graph.blocks, 546: effect})

    assert not validate_exact_state_branch_effect_exclusion(
        malformed,
        malformed,
        proof,
    )
