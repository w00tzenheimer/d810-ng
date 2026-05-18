from d810.recon.flow.dispatcher_detection import DispatcherType
from d810.recon.flow.indirect_jump_table_analysis import (
    IndirectJumpTableEntry,
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
