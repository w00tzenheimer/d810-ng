from types import SimpleNamespace

from d810.recon.flow.dispatcher_kind import DispatcherType
from d810.recon.flow.indirect_jump_table_analysis import (
    IndirectJumpTableEntry,
    _find_dispatcher_serial_by_ea,
    _find_mba_block_for_ea,
    _find_mba_block_for_target_interval,
    build_state_dispatcher_map_from_indirect_entries,
)


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

    assert dispatch_map.source is DispatcherType.INDIRECT_JUMP
    assert dispatch_map.initial_state == 2
    assert dispatch_map.handler_state_map() == {7: 1}

    missing = dispatch_map.rows[1]
    assert missing.state_const == 2
    assert missing.target_block == -1
    assert missing.row_kind == "missing_mba_target"
    assert missing.branch_kind == "indirect_jump_table_missing_target"
    assert missing.payload["target_ea_hex"] == "0x0000000180017af6"
    assert missing.payload["target_materialized"] is False


def test_indirect_jump_target_block_can_match_instruction_ea() -> None:
    insn = SimpleNamespace(ea=0x18001761A, next=None)
    blocks = {
        0: SimpleNamespace(start=0, end=0, head=None),
        1: SimpleNamespace(start=0, end=0, head=insn),
    }
    mba = SimpleNamespace(qty=2, get_mblock=lambda serial: blocks[serial])

    assert _find_mba_block_for_ea(mba, 0x18001761A) == 1


def test_indirect_jump_target_block_rejects_range_only_match() -> None:
    blocks = {
        0: SimpleNamespace(start=0x180017600, end=0x180017700, head=None),
    }
    mba = SimpleNamespace(qty=1, get_mblock=lambda serial: blocks[serial])

    assert _find_mba_block_for_ea(mba, 0x18001761A) is None


def test_indirect_jump_dispatcher_lookup_matches_tail_ea_not_range() -> None:
    blocks = {
        0: SimpleNamespace(
            start=0x180017600,
            end=0x180017800,
            head=None,
            tail=SimpleNamespace(ea=0x180017700),
        ),
        1: SimpleNamespace(
            start=0x180017800,
            end=0x180017820,
            head=None,
            tail=SimpleNamespace(ea=0x1800177A8),
        ),
    }
    mba = SimpleNamespace(qty=2, get_mblock=lambda serial: blocks[serial])

    assert _find_dispatcher_serial_by_ea(mba, 0x1800177A8) == 1


def test_indirect_jump_target_block_can_match_label_interval() -> None:
    folded_call = SimpleNamespace(ea=0x180017629, next=None)
    next_label = SimpleNamespace(ea=0x18001764E, next=None)
    blocks = {
        0: SimpleNamespace(head=None),
        1: SimpleNamespace(head=folded_call),
        2: SimpleNamespace(head=next_label),
    }
    mba = SimpleNamespace(qty=3, get_mblock=lambda serial: blocks[serial])

    assert (
        _find_mba_block_for_target_interval(
            mba,
            0x18001761A,
            0x18001764E,
        )
        == 1
    )
