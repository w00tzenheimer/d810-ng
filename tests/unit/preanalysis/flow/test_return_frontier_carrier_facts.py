from __future__ import annotations

from d810.ir.flowgraph import (
    BlockSnapshot,
    BlockKind,
    FlowGraph,
    InsnKind,
    InsnSnapshot,
    MopSnapshot,
    OperandKind,
)
from d810.analyses.control_flow import return_frontier_carrier_facts as facts_mod
from d810.analyses.control_flow.return_frontier_artifacts import (
    ReturnFrontierArtifactKind,
    ReturnFrontierArtifactPriors,
    ReturnFrontierCarrierClassification,
)

M_MOV = 0x0F
M_XDU = 0x1B
M_XDS = 0x1C
MOP_N = 2
MOP_S = 5
MOP_R = 1
BLT_STOP = 1
KNOWN_IMPOSSIBLE_CONSTANT = 0xC5FB34A1D9A6E315
KNOWN_IMPOSSIBLE_PRIORS = (
    ReturnFrontierArtifactPriors.from_known_impossible_return_constants((
        KNOWN_IMPOSSIBLE_CONSTANT,
    ))
)


def _mov_const_to_return_slot(value: int, *, ea: int = 0x401000) -> InsnSnapshot:
    return InsnSnapshot(
        opcode=M_MOV,
        ea=ea,
        operands=(),
        kind=InsnKind.MOV,
        l=MopSnapshot(t=MOP_N, size=8, value=value, kind=OperandKind.NUMBER),
        d=MopSnapshot(t=MOP_S, size=8, stkoff=0x7F0, kind=OperandKind.STACK),
    )


def _xdu_state_to_return_slot(*, ea: int = 0x401000) -> InsnSnapshot:
    return InsnSnapshot(
        opcode=M_XDU,
        ea=ea,
        operands=(),
        kind=InsnKind.XDU,
        l=MopSnapshot(t=MOP_S, size=4, stkoff=0x3C, kind=OperandKind.STACK),
        d=MopSnapshot(t=MOP_S, size=8, stkoff=0x7F0, kind=OperandKind.STACK),
    )


def _xds_state_to_return_slot(*, ea: int = 0x401000) -> InsnSnapshot:
    return InsnSnapshot(
        opcode=M_XDS,
        ea=ea,
        operands=(),
        kind=InsnKind.XDS,
        l=MopSnapshot(t=MOP_S, size=4, stkoff=0x3C, kind=OperandKind.STACK),
        d=MopSnapshot(t=MOP_S, size=8, stkoff=0x7F0, kind=OperandKind.STACK),
    )


def _graph_with_return_writer(writer: InsnSnapshot) -> FlowGraph:
    return FlowGraph(
        blocks={
            41: BlockSnapshot(
                serial=41,
                block_type=3,
                succs=(218,),
                preds=(),
                flags=0,
                start_ea=0x401000,
                insn_snapshots=(writer,),
            ),
            218: BlockSnapshot(
                serial=218,
                block_type=BLT_STOP,
                succs=(),
                preds=(41,),
                flags=0,
                start_ea=0x402000,
                insn_snapshots=(),
                kind=BlockKind.STOP,
            ),
        },
        entry_serial=41,
        func_ea=0x400000,
    )


def _mov_return_slot_to_rax(*, ea: int = 0x402000) -> InsnSnapshot:
    return InsnSnapshot(
        opcode=M_MOV,
        ea=ea,
        operands=(),
        kind=InsnKind.MOV,
        l=MopSnapshot(t=MOP_S, size=8, stkoff=0x7F0, kind=OperandKind.STACK),
        d=MopSnapshot(t=MOP_R, size=8, reg=8, kind=OperandKind.REGISTER),
    )


def _graph_with_shared_return_suffix(
    *writers: tuple[int, InsnSnapshot],
) -> FlowGraph:
    blocks = {
        218: BlockSnapshot(
            serial=218,
            block_type=3,
            succs=(219,),
            preds=tuple(serial for serial, _ in writers),
            flags=0,
            start_ea=0x402000,
            insn_snapshots=(_mov_return_slot_to_rax(),),
        ),
        219: BlockSnapshot(
            serial=219,
            block_type=BLT_STOP,
            succs=(),
            preds=(218,),
            flags=0,
            start_ea=0x403000,
            insn_snapshots=(),
            kind=BlockKind.STOP,
        ),
    }
    for serial, writer in writers:
        blocks[serial] = BlockSnapshot(
            serial=serial,
            block_type=3,
            succs=(218,),
            preds=(),
            flags=0,
            start_ea=0x401000 + serial,
            insn_snapshots=(writer,),
        )
    return FlowGraph(blocks=blocks, entry_serial=writers[0][0], func_ea=0x400000)


def test_impossible_return_artifact_writer_emits_protective_fact() -> None:
    graph = _graph_with_return_writer(
        _mov_const_to_return_slot(KNOWN_IMPOSSIBLE_CONSTANT)
    )

    facts = facts_mod.detect_return_frontier_carrier_facts(
        graph,
        return_stkoff_hint=0x7F0,
        artifact_priors=KNOWN_IMPOSSIBLE_PRIORS,
    )

    assert len(facts) == 1
    assert (
        facts[0].classification
        == ReturnFrontierCarrierClassification.PROTECTED_NON_CARRIER_RETURN_WRITER
    )
    assert facts[0].writer_block == 41
    assert facts[0].carrier_lvar_idx is None
    assert facts[0].carrier_stkoff is None
    assert facts[0].writer_path_blocks == frozenset({41})
    assert (
        facts[0].artifact_kind
        == ReturnFrontierArtifactKind.KNOWN_IMPOSSIBLE_CONSTANT_RETURN_WRITER
    )


def test_other_constant_return_writer_is_not_a_carrier_fact() -> None:
    graph = _graph_with_return_writer(_mov_const_to_return_slot(0x1234))

    assert facts_mod.detect_return_frontier_carrier_facts(graph) == ()


def test_impossible_return_artifact_requires_explicit_prior() -> None:
    graph = _graph_with_return_writer(
        _mov_const_to_return_slot(KNOWN_IMPOSSIBLE_CONSTANT)
    )

    assert facts_mod.detect_return_frontier_carrier_facts(graph) == ()


def test_impossible_return_artifact_sibling_writer_is_protected() -> None:
    graph = _graph_with_shared_return_suffix(
        (27, _mov_const_to_return_slot(0x5644FD01B1049C4B, ea=0x401027)),
        (41, _mov_const_to_return_slot(KNOWN_IMPOSSIBLE_CONSTANT, ea=0x401041)),
    )

    facts = facts_mod.detect_return_frontier_carrier_facts(
        graph,
        return_stkoff_hint=0x7F0,
        artifact_priors=KNOWN_IMPOSSIBLE_PRIORS,
    )

    assert len(facts) == 1
    assert (
        facts[0].classification
        == ReturnFrontierCarrierClassification.PROTECTED_NON_CARRIER_RETURN_WRITER
    )
    assert facts[0].writer_block == 41
    assert facts[0].writer_path_blocks == frozenset({41})
    assert (
        facts[0].artifact_kind
        == ReturnFrontierArtifactKind.KNOWN_IMPOSSIBLE_CONSTANT_RETURN_WRITER
    )


def test_state_var_return_slot_sibling_writer_is_protected() -> None:
    graph = _graph_with_shared_return_suffix(
        (27, _mov_const_to_return_slot(0x5644FD01B1049C4B, ea=0x401027)),
        (41, _xdu_state_to_return_slot(ea=0x401041)),
    )

    facts = facts_mod.detect_return_frontier_carrier_facts(
        graph,
        return_stkoff_hint=0x7F0,
        state_var_stkoff=0x3C,
    )

    assert len(facts) == 1
    assert (
        facts[0].classification
        == ReturnFrontierCarrierClassification.PROTECTED_NON_CARRIER_RETURN_WRITER
    )
    assert facts[0].writer_block == 41
    assert facts[0].writer_path_blocks == frozenset({41})
    assert (
        facts[0].artifact_kind
        == ReturnFrontierArtifactKind.STATE_VARIABLE_RETURN_WRITER
    )


def test_signed_extend_state_var_return_writer_is_protected() -> None:
    graph = _graph_with_shared_return_suffix(
        (27, _mov_const_to_return_slot(0x5644FD01B1049C4B, ea=0x401027)),
        (41, _xds_state_to_return_slot(ea=0x401041)),
    )

    facts = facts_mod.detect_return_frontier_carrier_facts(
        graph,
        return_stkoff_hint=0x7F0,
        state_var_stkoff=0x3C,
    )

    assert len(facts) == 1
    assert (
        facts[0].classification
        == ReturnFrontierCarrierClassification.PROTECTED_NON_CARRIER_RETURN_WRITER
    )
    assert facts[0].writer_block == 41
    assert (
        facts[0].artifact_kind
        == ReturnFrontierArtifactKind.STATE_VARIABLE_RETURN_WRITER
    )


# ---------------------------------------------------------------------------
# Behavior-contract pins (llr-ykmh): storage-view classification must preserve
# the load-bearing accept-on-unknown / accept-any-register / accept-any-lvar /
# stack-offset-match semantics after the InsnSnapshot.l/.r/.d reads are removed.
# ---------------------------------------------------------------------------


def _mov_stack(
    src_stkoff: int | None, dst_stkoff: int, *, ea: int = 0x401000
) -> InsnSnapshot:
    """MOV from a (possibly unknown-offset) stack source to a stack dest."""
    return InsnSnapshot(
        opcode=M_MOV,
        ea=ea,
        operands=(),
        kind=InsnKind.MOV,
        l=MopSnapshot(t=MOP_S, size=8, stkoff=src_stkoff, kind=OperandKind.STACK),
        d=MopSnapshot(t=MOP_S, size=8, stkoff=dst_stkoff, kind=OperandKind.STACK),
    )


def test_dest_is_return_slot_accepts_any_register() -> None:
    insn = InsnSnapshot(
        opcode=M_MOV,
        ea=0x401000,
        operands=(),
        kind=InsnKind.MOV,
        l=MopSnapshot(t=MOP_S, size=8, stkoff=0x3C, kind=OperandKind.STACK),
        d=MopSnapshot(t=MOP_R, size=8, reg=0, kind=OperandKind.REGISTER),
    )
    assert facts_mod._dest_is_return_slot(insn, return_stkoff=0x7F0) is True


def test_dest_is_return_slot_accepts_any_lvar() -> None:
    insn = InsnSnapshot(
        opcode=M_MOV,
        ea=0x401000,
        operands=(),
        kind=InsnKind.MOV,
        l=MopSnapshot(t=MOP_S, size=8, stkoff=0x3C, kind=OperandKind.STACK),
        d=MopSnapshot(size=8, lvar_off=0x20, kind=OperandKind.LVAR),
    )
    assert facts_mod._dest_is_return_slot(insn, return_stkoff=0x7F0) is True


def test_dest_is_return_slot_accepts_unknown_offset_stack() -> None:
    # A stack dest whose concrete offset was not recovered (WeakStackSlot)
    # must be accepted (accept-on-unknown), NOT collapsed to a non-match.
    insn = _mov_stack(0x3C, dst_stkoff=None)
    assert insn.d.stkoff is None
    assert facts_mod._dest_is_return_slot(insn, return_stkoff=0x7F0) is True


def test_dest_is_return_slot_stack_matches_only_return_offset() -> None:
    matching = _mov_stack(0x3C, dst_stkoff=0x7F0)
    other = _mov_stack(0x3C, dst_stkoff=0x40)
    assert facts_mod._dest_is_return_slot(matching, return_stkoff=0x7F0) is True
    assert facts_mod._dest_is_return_slot(other, return_stkoff=0x7F0) is False


def test_writer_const_value_extracts_constant() -> None:
    writer = _mov_const_to_return_slot(0xDEADBEEF)
    assert facts_mod._writer_const_value(writer) == 0xDEADBEEF


def test_writer_const_value_none_for_non_constant() -> None:
    writer = _mov_stack(0x3C, dst_stkoff=0x7F0)
    assert facts_mod._writer_const_value(writer) is None


def test_writer_carrier_identity_stack_source() -> None:
    writer = _mov_stack(0x3C, dst_stkoff=0x7F0)
    lvar_idx, stkoff = facts_mod._writer_carrier_identity(writer)
    assert lvar_idx is None
    assert stkoff == 0x3C


def test_writer_carrier_identity_lvar_index_is_none_on_portable_path() -> None:
    # The portable Varnode LVAR identity carries a frame offset, not the live
    # lvar table index; carrier_lvar_idx must be None on this snapshot path.
    writer = InsnSnapshot(
        opcode=M_MOV,
        ea=0x401000,
        operands=(),
        kind=InsnKind.MOV,
        l=MopSnapshot(size=8, lvar_off=0x20, kind=OperandKind.LVAR),
        d=MopSnapshot(t=MOP_S, size=8, stkoff=0x7F0, kind=OperandKind.STACK),
    )
    lvar_idx, stkoff = facts_mod._writer_carrier_identity(writer)
    assert lvar_idx is None
    assert stkoff is None


def test_state_variable_return_writer_predicate() -> None:
    writer = _xdu_state_to_return_slot()
    assert facts_mod._writer_is_state_variable_return_writer(
        writer, state_var_stkoff=0x3C
    ) is True
    # dst == state_var is not a state-variable return writer.
    same = _mov_stack(0x3C, dst_stkoff=0x3C)
    assert facts_mod._writer_is_state_variable_return_writer(
        same, state_var_stkoff=0x3C
    ) is False


def test_insn_references_carrier_by_stack_offset() -> None:
    insn = _mov_stack(0x3C, dst_stkoff=0x7F0)
    assert facts_mod._insn_references_carrier(
        insn, carrier_lvar_idx=None, carrier_stkoff=0x3C
    ) is True
    assert facts_mod._insn_references_carrier(
        insn, carrier_lvar_idx=None, carrier_stkoff=0x40
    ) is False


def test_carrier_return_writer_emits_stack_carrier_fact() -> None:
    # A genuine stack-carried return writer (xdu state -> return slot, with NO
    # state_var hint so it is not reclassified as a protected non-carrier).
    graph = _graph_with_return_writer(_xdu_state_to_return_slot())
    facts = facts_mod.detect_return_frontier_carrier_facts(
        graph, return_stkoff_hint=0x7F0
    )
    assert len(facts) == 1
    assert facts[0].carrier_lvar_idx is None
    assert facts[0].carrier_stkoff == 0x3C
    assert (
        facts[0].classification
        == ReturnFrontierCarrierClassification.RETURN_CARRIER
    )
