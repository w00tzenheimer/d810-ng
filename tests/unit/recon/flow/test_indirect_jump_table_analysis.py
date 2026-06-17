from d810.capabilities.dispatcher import RouterKind
from d810.analyses.control_flow.indirect_jump_table_analysis import (
    IndirectJumpTableEntry,
    _find_dispatcher_serial_by_ea,
    _find_mba_block_for_ea,
    _find_mba_block_for_target_interval,
    build_state_dispatcher_map_from_indirect_entries,
)
from d810.ir.flowgraph import BlockSnapshot, FlowGraph, InsnKind, InsnSnapshot


def _fg(blocks: dict[int, tuple[int, tuple[int, ...]]]) -> FlowGraph:
    """Build a topology-free FlowGraph from ``{serial: (start_ea, (insn_ea, ...))}``.

    Only ``start_ea`` and the instruction EAs (the EA-lookup inputs) matter; the
    last instruction is the block tail.
    """
    snaps = {
        serial: BlockSnapshot(
            serial=serial,
            block_type=0,
            succs=(),
            preds=(),
            flags=0,
            start_ea=start_ea,
            insn_snapshots=tuple(
                InsnSnapshot(opcode=1, ea=ea, operands=(), kind=InsnKind.MOV)
                for ea in insn_eas
            ),
        )
        for serial, (start_ea, insn_eas) in blocks.items()
    }
    return FlowGraph(blocks=snaps, entry_serial=min(blocks), func_ea=0)


def test_indirect_jump_table_rows_preserve_unmaterialized_targets() -> None:
    dispatch_map = build_state_dispatcher_map_from_indirect_entries(
        (
            IndirectJumpTableEntry(1, 0x180017736, 7),
            IndirectJumpTableEntry(2, 0x180017AF6, None),
        ),
        dispatcher_serial=3,
        dispatcher_blocks=frozenset({3}),
        state_var_stkoff=None,
        initial_state=2,
        table_address=0x180019F10,
    )

    assert dispatch_map.router_kind is RouterKind.INDIRECT_TABLE
    assert dispatch_map.initial_state == 2
    assert dispatch_map.handler_state_map() == {7: 1}

    missing = dispatch_map.rows[1]
    assert missing.state_const == 2
    assert missing.target_block == -1
    assert missing.row_kind == "missing_mba_target"
    assert missing.branch_kind == "indirect_jump_table_missing_target"
    assert missing.payload["target_ea_hex"] == "0x0000000180017af6"
    assert missing.payload["target_materialized"] is False
    assert dispatch_map.resolve_target(1) == 7
    assert dispatch_map.resolve_target(2) is None


def test_indirect_jump_target_block_can_match_instruction_ea() -> None:
    fg = _fg({0: (0, ()), 1: (0, (0x18001761A,))})

    assert _find_mba_block_for_ea(fg, 0x18001761A) == 1


def test_indirect_jump_target_block_rejects_range_only_match() -> None:
    fg = _fg({0: (0x180017600, ())})

    assert _find_mba_block_for_ea(fg, 0x18001761A) is None


def test_indirect_jump_dispatcher_lookup_matches_tail_ea_not_range() -> None:
    fg = _fg(
        {
            0: (0x180017600, (0x180017700,)),
            1: (0x180017800, (0x1800177A8,)),
        }
    )

    assert _find_dispatcher_serial_by_ea(fg, 0x1800177A8) == 1


def test_indirect_jump_target_block_can_match_label_interval() -> None:
    fg = _fg(
        {
            0: (0, ()),
            1: (0, (0x180017629,)),
            2: (0, (0x18001764E,)),
        }
    )

    assert (
        _find_mba_block_for_target_interval(
            fg,
            0x18001761A,
            0x18001764E,
        )
        == 1
    )
