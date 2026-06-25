"""Tests for StateTransitionAnchorFactCollector."""
from __future__ import annotations

import json
from types import SimpleNamespace

from d810.core.diag.snapshot import BlockSnapshot, InstructionSnapshot
from d810.ir.flowgraph import (
    BlockSnapshot as CfgBlockSnapshot,
    InsnKind,
    InsnSnapshot,
    MopSnapshot,
    OperandKind,
)
from d810.analyses.control_flow.state_transition_anchor import StateTransitionAnchorFactCollector
from d810.analyses.value_flow.induction_carrier import _MATURITY_VALUES

_OPCODE_ALIASES = {
    "m_mov": "move",
}

_OPERAND_TYPE_ALIASES = {
    "mop_S": "S",
    "mop_n": "c",
}


def _opcode_name(value: str) -> str:
    return _OPCODE_ALIASES.get(value, value)


def _operand_type(value: str | None) -> str | None:
    if value is None:
        return None
    return _OPERAND_TYPE_ALIASES.get(value, value)


def _state_insn(
    *,
    index: int,
    state_const: int,
    ea: int,
    stkoff: int = 0x3C,
) -> InstructionSnapshot:
    return InstructionSnapshot(
        index=index,
        ea=ea,
        opcode=0,
        opcode_name=_opcode_name("m_mov"),
        dest_type=_operand_type("mop_S"),
        dest_stkoff=stkoff,
        dest_size=4,
        src_l_type=_operand_type("mop_n"),
        src_l_stkoff=None,
        src_l_value=state_const,
        src_r_type=None,
        src_r_stkoff=None,
        src_r_value=None,
        dstr=f"mov #0x{state_const:08X}.4, %var_7BC.4",
    )


def _filler_insn(
    *,
    index: int,
    stkoff: int,
    ea: int,
) -> InstructionSnapshot:
    """Non-state-var const-write (e.g. byte-table store).  Helps the
    collector identify the canonical state-var by frequency."""
    return InstructionSnapshot(
        index=index,
        ea=ea,
        opcode=0,
        opcode_name=_opcode_name("m_mov"),
        dest_type=_operand_type("mop_S"),
        dest_stkoff=stkoff,
        dest_size=8,
        src_l_type=_operand_type("mop_n"),
        src_l_stkoff=None,
        src_l_value=0xDEADBEEF,
        src_r_type=None,
        src_r_stkoff=None,
        src_r_value=None,
        dstr=f"mov #0xDEADBEEF.8, %var_X.8",
    )


def _block(
    serial: int,
    *insns: InstructionSnapshot,
    succs: tuple[int, ...] = (),
    start_ea: int = 0,
) -> BlockSnapshot:
    return BlockSnapshot(
        serial=serial,
        block_type=1 if len(succs) <= 1 else 2,
        type_name="BLT_1WAY" if len(succs) <= 1 else "BLT_2WAY",
        start_ea=start_ea or (0x180014000 + serial),
        nsucc=len(succs),
        npred=0,
        succs=list(succs),
        preds=[],
        instructions=list(insns),
    )


def _target(*blocks: BlockSnapshot) -> SimpleNamespace:
    return SimpleNamespace(blocks={blk.serial: blk for blk in blocks})


def _collect(target: object) -> tuple[object, ...]:
    return StateTransitionAnchorFactCollector().collect(
        target,
        func_ea=0x180012df0,
        maturity=_MATURITY_VALUES["MMAT_LOCOPT"],
        phase="pre_d810",
    )


def test_direct_transition_records_both_consts() -> None:
    facts = _collect(
        _target(
            _block(
                100,
                _state_insn(index=0, state_const=0x5A21D9DB, ea=0x180014100),
                succs=(101,),
            ),
            _block(
                101,
                _state_insn(index=0, state_const=0x63D54755, ea=0x180014200),
                succs=(),
            ),
        ),
    )
    assert len(facts) == 2
    by_block = {f.payload["source_block_serial"]: f for f in facts}
    blk100 = by_block[100]
    assert blk100.kind == "StateTransitionAnchorFact"
    assert blk100.payload["source_state_const"] == 0x5A21D9DB
    assert blk100.payload["source_state_const_hex"] == "0x5a21d9db"
    assert blk100.payload["successor_block_serial"] == 101
    assert blk100.payload["next_state_const"] == 0x63D54755
    assert blk100.payload["next_state_const_hex"] == "0x63d54755"
    assert blk100.payload["transit_blocks"] == []
    assert blk100.payload["successor_kind"] == "direct"
    assert blk100.payload["state_var_stkoff"] == 0x3C
    assert (
        blk100.mop_signature
        == "state_transition:0x5a21d9db->0x63d54755:kind=direct"
    )


def test_transit_chain_records_intermediate_blocks() -> None:
    facts = _collect(
        _target(
            _block(
                100,
                _state_insn(index=0, state_const=0x5A21D9DB, ea=0x180014100),
                succs=(110,),
            ),
            # Two transit blocks with no canonical state-write.
            _block(
                110,
                _filler_insn(index=0, stkoff=0x68, ea=0x180014300),
                succs=(120,),
            ),
            _block(
                120,
                _filler_insn(index=0, stkoff=0x70, ea=0x180014400),
                succs=(130,),
            ),
            _block(
                130,
                _state_insn(index=0, state_const=0x10743C4C, ea=0x180014500),
                succs=(),
            ),
        ),
    )
    by_block = {f.payload["source_block_serial"]: f for f in facts}
    blk100 = by_block[100]
    assert blk100.payload["successor_kind"] == "transit"
    assert blk100.payload["transit_blocks"] == [110, 120]
    assert blk100.payload["successor_block_serial"] == 130
    assert blk100.payload["next_state_const"] == 0x10743C4C


def _seed_canonical_block() -> BlockSnapshot:
    """Helper: an unrelated block with a canonical state-write so the
    statistical detector picks 0x3c as the canonical stkoff (it needs
    at least 2 writes to the same stkoff to qualify)."""
    return _block(
        900,
        _state_insn(index=0, state_const=0xCAFEBABE, ea=0x180019000),
        succs=(),
    )


def test_branching_successor_marks_branch() -> None:
    facts = _collect(
        _target(
            _block(
                100,
                _state_insn(index=0, state_const=0x5A21D9DB, ea=0x180014100),
                succs=(110,),
            ),
            # Transit block with two successors — chain stops here.
            _block(
                110,
                _filler_insn(index=0, stkoff=0x68, ea=0x180014300),
                succs=(120, 121),
            ),
            _block(120, succs=()),
            _block(121, succs=()),
            _seed_canonical_block(),
        ),
    )
    by_block = {f.payload["source_block_serial"]: f for f in facts}
    blk100 = by_block[100]
    assert blk100.payload["successor_kind"] == "branch"
    assert blk100.payload["next_state_const"] is None
    assert blk100.payload["next_state_const_hex"] is None


def test_loop_marks_loop() -> None:
    facts = _collect(
        _target(
            _block(
                100,
                _state_insn(index=0, state_const=0x5A21D9DB, ea=0x180014100),
                succs=(101,),
            ),
            _block(
                101,
                _filler_insn(index=0, stkoff=0x68, ea=0x180014300),
                succs=(100,),
            ),
            _seed_canonical_block(),
        ),
    )
    by_block = {f.payload["source_block_serial"]: f for f in facts}
    blk100 = by_block[100]
    assert blk100.payload["successor_kind"] == "loop"
    assert blk100.payload["next_state_const"] is None


def test_exit_chain_marks_exit() -> None:
    facts = _collect(
        _target(
            _block(
                100,
                _state_insn(index=0, state_const=0x5A21D9DB, ea=0x180014100),
                succs=(101,),
            ),
            _block(
                101,
                _filler_insn(index=0, stkoff=0x68, ea=0x180014300),
                succs=(),
            ),
            _seed_canonical_block(),
        ),
    )
    by_block = {f.payload["source_block_serial"]: f for f in facts}
    blk100 = by_block[100]
    assert blk100.payload["successor_kind"] == "exit"
    assert blk100.payload["next_state_const"] is None
    assert blk100.payload["transit_blocks"] == [101]


def test_function_with_no_state_machine_emits_nothing() -> None:
    # Single state-write at one stkoff -- statistical detection requires
    # at least 2 writes to the same canonical stkoff.
    facts = _collect(
        _target(
            _block(
                100,
                _state_insn(index=0, state_const=0x5A21D9DB, ea=0x180014100),
                succs=(),
            ),
        ),
    )
    assert facts == ()


def test_canonical_stkoff_picked_by_frequency() -> None:
    # Two state-writes at 0x3C, one at 0x68 -- 0x3C is canonical.
    facts = _collect(
        _target(
            _block(
                10,
                _state_insn(index=0, state_const=0xAAAAAAAA, ea=0x180014000),
                _state_insn(index=1, state_const=0xBBBBBBBB, ea=0x180014008, stkoff=0x68),
                succs=(20,),
            ),
            _block(
                20,
                _state_insn(index=0, state_const=0xCCCCCCCC, ea=0x180014100),
                succs=(),
            ),
        ),
    )
    # Both transitions emitted are anchored on stkoff 0x3C; the 0x68
    # write should NOT produce a transition fact (it is not canonical).
    stkoffs = {f.payload["state_var_stkoff"] for f in facts}
    assert stkoffs == {0x3C}
    consts = {f.payload["source_state_const"] for f in facts}
    assert consts == {0xAAAAAAAA, 0xCCCCCCCC}
    assert 0xBBBBBBBB not in consts


def test_view_accessor_returns_per_source_block() -> None:
    """``ValidatedFactView.state_transitions_for_source_block`` filters
    correctly by source block."""
    from d810.analyses.value_flow.model import (
        FactObservation,
        ValidatedFactView,
    )

    facts = _collect(
        _target(
            _block(
                100,
                _state_insn(index=0, state_const=0x5A21D9DB, ea=0x180014100),
                succs=(101,),
            ),
            _block(
                101,
                _state_insn(index=0, state_const=0x63D54755, ea=0x180014200),
                succs=(),
            ),
        ),
    )
    assert len(facts) == 2
    obs_tuple = tuple(
        f if isinstance(f, FactObservation)
        else FactObservation(**f.__dict__)
        for f in facts
    )
    view = ValidatedFactView(
        maturity="MMAT_LOCOPT",
        observations=obs_tuple,
        mappings=(),
    )
    found_100 = view.state_transitions_for_source_block(100)
    assert len(found_100) == 1
    assert found_100[0].payload["source_state_const"] == 0x5A21D9DB
    assert view.state_transitions_for_source_block(999) == ()


# ---------------------------------------------------------------------------
# llr-3b41 S5: dual-currency port coverage.  The collector now consumes the
# canonical ``Instruction`` for meta-rich sources (a portable ``FlowGraph``
# block, or a diag row carrying a parseable ``meta`` operand tree) while
# meta-less rows (every test above) stay on the byte-identical legacy flat
# path.  These tests pin the two canonical sources and the two helper edge
# cases the canonical path introduces.
# ---------------------------------------------------------------------------


def _cfg_stack(stkoff: int, *, size: int = 4) -> MopSnapshot:
    return MopSnapshot(kind=OperandKind.STACK, stkoff=stkoff, size=size)


def _cfg_const(value: int, *, size: int = 4) -> MopSnapshot:
    return MopSnapshot(kind=OperandKind.NUMBER, value=value, size=size)


def _cfg_mov(
    *, index: int, state_const: int, ea: int, stkoff: int = 0x3C
) -> InsnSnapshot:
    """A ``mov #const, %var_<stkoff>`` canonical state write."""
    return InsnSnapshot(
        opcode=-1,
        raw_opcode=0x1000 + index,
        ea=ea,
        operands=(),
        operand_slots=(
            ("l", _cfg_const(state_const)),
            ("d", _cfg_stack(stkoff)),
        ),
        display_text=f"mov #0x{state_const:08X}.4, %var_7BC.4",
        l=_cfg_const(state_const),
        r=None,
        d=_cfg_stack(stkoff),
        kind=InsnKind.MOV,
    )


def _cfg_block(
    serial: int,
    *instructions: InsnSnapshot,
    succs: tuple[int, ...] = (),
    start_ea: int | None = None,
) -> CfgBlockSnapshot:
    return CfgBlockSnapshot(
        serial=serial,
        block_type=1 if len(succs) <= 1 else 2,
        succs=succs,
        preds=(),
        flags=0,
        start_ea=0x180014000 + serial if start_ea is None else start_ea,
        insn_snapshots=tuple(instructions),
    )


def _cfg_target(*blocks: CfgBlockSnapshot) -> SimpleNamespace:
    return SimpleNamespace(blocks={blk.serial: blk for blk in blocks})


def test_direct_transition_from_canonical_flowgraph_source() -> None:
    """A portable ``FlowGraph`` block routes through the canonical projection;
    ``dest_stkoff`` is read off ``Instruction.result`` and ``src_l_value`` off
    the first canonical input, so the transition fact matches the legacy
    diag-row result byte-for-byte."""
    facts = _collect(
        _cfg_target(
            _cfg_block(
                100,
                _cfg_mov(index=0, state_const=0x5A21D9DB, ea=0x180014100),
                succs=(101,),
            ),
            _cfg_block(
                101,
                _cfg_mov(index=0, state_const=0x63D54755, ea=0x180014200),
                succs=(),
            ),
        ),
    )
    assert len(facts) == 2
    blk100 = {f.payload["source_block_serial"]: f for f in facts}[100]
    assert blk100.payload["source_state_const"] == 0x5A21D9DB
    assert blk100.payload["state_var_stkoff"] == 0x3C
    assert blk100.payload["successor_block_serial"] == 101
    assert blk100.payload["next_state_const"] == 0x63D54755
    assert blk100.payload["successor_kind"] == "direct"
    assert blk100.payload["dest_var_signature"] == "%var_7BC.4"
    assert (
        blk100.mop_signature
        == "state_transition:0x5a21d9db->0x63d54755:kind=direct"
    )


def _meta_stack(stkoff: int, size: int = 4) -> dict:
    return {"type": "mop_S", "type_num": 5, "size": size, "dstr": "x", "stkoff": stkoff}


def _meta_const(value: int, size: int = 4) -> dict:
    return {
        "type": "mop_n",
        "type_num": 2,
        "size": size,
        "dstr": f"#{value:#x}",
        "value": value,
    }


def _meta_mov(
    *, index: int, state_const: int, ea: int, stkoff: int = 0x3C
) -> InstructionSnapshot:
    """A ``mov #const, %var`` diag row carrying a parseable ``meta`` operand
    tree -- routed through the canonical lift (``diag_row_has_operand_tree``)."""
    insn = InstructionSnapshot(
        index=index,
        ea=ea,
        opcode=0,
        opcode_name="m_mov",
        dest_type="S",
        dest_stkoff=None,
        dest_size=4,
        src_l_type="c",
        src_l_stkoff=None,
        src_l_value=None,
        src_r_type=None,
        src_r_stkoff=None,
        src_r_value=None,
        dstr=f"mov #0x{state_const:08X}.4, %var_7BC.4",
    )
    insn.meta = json.dumps(
        {"l": _meta_const(state_const), "d": _meta_stack(stkoff)}
    )
    return insn


def test_direct_transition_from_meta_rich_diag_row() -> None:
    """A diag row whose ``meta`` carries an operand tree is lifted through the
    SAME canonical projection (the flat ``dest_stkoff`` / ``src_l_value`` are
    intentionally ``None``); ``dest_stkoff`` / ``src_l_value`` are recovered
    from the canonical record, yielding the same transition fact."""
    facts = _collect(
        _target(
            _block(
                100,
                _meta_mov(index=0, state_const=0x5A21D9DB, ea=0x180014100),
                succs=(101,),
            ),
            _block(
                101,
                _meta_mov(index=0, state_const=0x63D54755, ea=0x180014200),
                succs=(),
            ),
        ),
    )
    assert len(facts) == 2
    blk100 = {f.payload["source_block_serial"]: f for f in facts}[100]
    assert blk100.payload["source_state_const"] == 0x5A21D9DB
    assert blk100.payload["state_var_stkoff"] == 0x3C
    assert blk100.payload["next_state_const"] == 0x63D54755
    assert blk100.payload["successor_kind"] == "direct"


def test_dest_var_signature_absent_when_dstr_has_no_var() -> None:
    """A canonical state write whose ``dstr`` lacks a ``%var_<off>.<sz>`` token
    yields ``dest_var_signature=None`` (the regex-miss branch)."""

    def _mov_no_var(*, index: int, state_const: int, ea: int) -> InsnSnapshot:
        return InsnSnapshot(
            opcode=-1,
            raw_opcode=0x2000 + index,
            ea=ea,
            operands=(),
            operand_slots=(
                ("l", _cfg_const(state_const)),
                ("d", _cfg_stack(0x3C)),
            ),
            display_text=f"mov #0x{state_const:08X}.4, eax.4",
            l=_cfg_const(state_const),
            r=None,
            d=_cfg_stack(0x3C),
            kind=InsnKind.MOV,
        )

    facts = _collect(
        _cfg_target(
            _cfg_block(
                100,
                _mov_no_var(index=0, state_const=0x5A21D9DB, ea=0x180014100),
                succs=(101,),
            ),
            _cfg_block(
                101,
                _mov_no_var(index=0, state_const=0x63D54755, ea=0x180014200),
                succs=(),
            ),
        ),
    )
    blk100 = {f.payload["source_block_serial"]: f for f in facts}[100]
    assert blk100.payload["dest_var_signature"] is None


def test_anchor_ea_falls_back_to_block_start_when_ea_zero() -> None:
    """When an instruction's ``ea`` is ``0`` the anchor EA falls back to
    ``block_start_ea + insn_index`` (canonical attrs carry ea=0)."""
    facts = _collect(
        _cfg_target(
            _cfg_block(
                100,
                _cfg_mov(index=0, state_const=0x5A21D9DB, ea=0),
                succs=(101,),
                start_ea=0x180014700,
            ),
            _cfg_block(
                101,
                _cfg_mov(index=0, state_const=0x63D54755, ea=0),
                succs=(),
                start_ea=0x180014800,
            ),
        ),
    )
    blk100 = {f.payload["source_block_serial"]: f for f in facts}[100]
    # ea=0 -> block_start_ea (0x180014700) + insn_index (0)
    assert blk100.payload["source_instruction_ea"] == 0x180014700
    assert blk100.source_ea == 0x180014700
