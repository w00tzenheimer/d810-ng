from __future__ import annotations

from d810.cfg.flowgraph import (
    BlockSnapshot,
    FlowGraph,
    InsnSnapshot,
    MopSnapshot,
    OperandKind,
)
from d810.recon.flow import return_frontier_carrier_facts as facts_mod
from d810.recon.flow.return_frontier_artifacts import (
    ReturnFrontierArtifactKind,
    ReturnFrontierArtifactPriors,
    ReturnFrontierCarrierClassification,
)

M_MOV = 0x0F
M_STX = 0x0D
M_ADD = 0x10
M_XDU = 0x1B
M_RET = 0x59
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


def _patch_opcodes(monkeypatch) -> None:
    monkeypatch.setattr(
        facts_mod,
        "_resolve_opcodes",
        lambda: {
            "m_ret": M_RET,
            "m_mov": M_MOV,
            "m_stx": M_STX,
            "m_add": M_ADD,
            "m_xdu": M_XDU,
            "m_xds": 0x1C,
        },
    )


def _mov_const_to_return_slot(value: int, *, ea: int = 0x401000) -> InsnSnapshot:
    return InsnSnapshot(
        opcode=M_MOV,
        ea=ea,
        operands=(),
        l=MopSnapshot(t=MOP_N, size=8, value=value, kind=OperandKind.NUMBER),
        d=MopSnapshot(t=MOP_S, size=8, stkoff=0x7F0, kind=OperandKind.STACK),
    )


def _xdu_state_to_return_slot(*, ea: int = 0x401000) -> InsnSnapshot:
    return InsnSnapshot(
        opcode=M_XDU,
        ea=ea,
        operands=(),
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


def test_impossible_return_artifact_writer_emits_protective_fact(monkeypatch) -> None:
    _patch_opcodes(monkeypatch)
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


def test_other_constant_return_writer_is_not_a_carrier_fact(monkeypatch) -> None:
    _patch_opcodes(monkeypatch)
    graph = _graph_with_return_writer(_mov_const_to_return_slot(0x1234))

    assert facts_mod.detect_return_frontier_carrier_facts(graph) == ()


def test_impossible_return_artifact_requires_explicit_prior(monkeypatch) -> None:
    _patch_opcodes(monkeypatch)
    graph = _graph_with_return_writer(
        _mov_const_to_return_slot(KNOWN_IMPOSSIBLE_CONSTANT)
    )

    assert facts_mod.detect_return_frontier_carrier_facts(graph) == ()


def test_impossible_return_artifact_sibling_writer_is_protected(monkeypatch) -> None:
    _patch_opcodes(monkeypatch)
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


def test_state_var_return_slot_sibling_writer_is_protected(monkeypatch) -> None:
    _patch_opcodes(monkeypatch)
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
