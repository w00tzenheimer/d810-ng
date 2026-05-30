"""Tests for StateTransitionAnchorFactCollector."""
from __future__ import annotations

from types import SimpleNamespace

from d810.core.diag.snapshot import BlockSnapshot, InstructionSnapshot
from d810.analyses.control_flow.state_transition_anchor import StateTransitionAnchorFactCollector
from d810.analyses.value_flow.induction_carrier import _MATURITY_VALUES


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
        opcode_name="m_mov",
        dest_type="mop_S",
        dest_stkoff=stkoff,
        dest_size=4,
        src_l_type="mop_n",
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
        opcode_name="m_mov",
        dest_type="mop_S",
        dest_stkoff=stkoff,
        dest_size=8,
        src_l_type="mop_n",
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
