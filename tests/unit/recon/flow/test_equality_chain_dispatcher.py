"""Tests for equality-chain dispatcher row extraction."""
from __future__ import annotations

from types import SimpleNamespace

from d810.recon.flow.equality_chain_dispatcher import (
    extract_state_dispatcher_map_from_mba,
)


def _mop_n(value: int):
    return SimpleNamespace(t="mop_n", value=value, size=4)


def _mop_n_snapshot(value: int):
    return SimpleNamespace(t=2, nnn_value=value, size=4)


def _mop_s(off: int):
    return SimpleNamespace(t="mop_S", s=SimpleNamespace(off=off), size=4)


def _mop_l(idx: int):
    return SimpleNamespace(t="mop_l", l=SimpleNamespace(idx=idx), size=4)


def _mop_b(serial: int):
    return SimpleNamespace(t="mop_b", b=serial, block_ref=serial)


def _mov(src, dst):
    return SimpleNamespace(opcode="m_mov", l=src, d=dst)


def _block(
    serial: int,
    *,
    opcode: str = "m_jz",
    state_mop=None,
    const: int = 0,
    jump_target: int = 0,
    succs: tuple[int, int] = (0, 0),
    insns: tuple[object, ...] = (),
):
    return SimpleNamespace(
        serial=serial,
        type="BLT_2WAY",
        succset=succs,
        insns=insns,
        tail=SimpleNamespace(
            opcode=opcode,
            l=state_mop if state_mop is not None else _mop_s(0x3C),
            r=_mop_n(const),
            d=_mop_b(jump_target),
        ),
    )


class _Mba:
    def __init__(self, blocks: dict[int, object]):
        self.blocks = blocks
        self.qty = max(blocks) + 1

    def get_mblock(self, serial: int):
        return self.blocks.get(int(serial))


def test_extracts_jz_exact_rows_from_linear_chain() -> None:
    mba = _Mba(
        {
            2: _block(2, const=0x10, jump_target=7, succs=(3, 7)),
            3: _block(3, const=0x20, jump_target=9, succs=(4, 9)),
        }
    )

    dispatch_map = extract_state_dispatcher_map_from_mba(
        mba,
        dispatcher_entry_block=2,
    )

    assert dispatch_map is not None
    assert dispatch_map.state_to_handler() == {0x10: 7, 0x20: 9}
    assert dispatch_map.dispatcher_blocks == frozenset({2, 3})
    assert dispatch_map.state_var_stkoff == 0x3C


def test_canonicalizes_direct_dispatcher_state_scratch_alias() -> None:
    state_var = _mop_s(0x364)
    scratch = _mop_s(0x350)
    mba = _Mba(
        {
            2: _block(
                2,
                opcode="m_jnz",
                state_mop=state_var,
                const=0x10,
                jump_target=3,
                succs=(7, 3),
                insns=(_mov(state_var, scratch),),
            ),
            3: _block(
                3,
                state_mop=scratch,
                const=0x20,
                jump_target=9,
                succs=(4, 9),
            ),
        }
    )

    dispatch_map = extract_state_dispatcher_map_from_mba(
        mba,
        dispatcher_entry_block=2,
    )

    assert dispatch_map is not None
    assert dispatch_map.state_to_handler() == {0x10: 7, 0x20: 9}
    assert dispatch_map.state_var_stkoff == 0x364


def test_extracts_snapshot_constants_from_nnn_value() -> None:
    mba = _Mba(
        {
            2: _block(
                2,
                const=0,
                jump_target=7,
                succs=(3, 7),
            ),
        }
    )
    mba.blocks[2].tail.r = _mop_n_snapshot(0x44)

    dispatch_map = extract_state_dispatcher_map_from_mba(
        mba,
        dispatcher_entry_block=2,
    )

    assert dispatch_map is not None
    assert dispatch_map.state_to_handler() == {0x44: 7}


def test_extracts_jnz_exact_row_from_fallthrough() -> None:
    mba = _Mba(
        {
            2: _block(
                2,
                opcode="m_jnz",
                const=0x10,
                jump_target=3,
                succs=(7, 3),
            ),
            3: _block(3, const=0x20, jump_target=9, succs=(4, 9)),
        }
    )

    dispatch_map = extract_state_dispatcher_map_from_mba(
        mba,
        dispatcher_entry_block=2,
    )

    assert dispatch_map is not None
    assert dispatch_map.state_to_handler() == {0x10: 7, 0x20: 9}


def test_rejects_mixed_state_variables() -> None:
    mba = _Mba(
        {
            2: _block(2, state_mop=_mop_s(0x3C), const=0x10, jump_target=7, succs=(3, 7)),
            3: _block(3, state_mop=_mop_s(0x44), const=0x20, jump_target=9, succs=(4, 9)),
        }
    )

    assert (
        extract_state_dispatcher_map_from_mba(mba, dispatcher_entry_block=2)
        is None
    )


def test_rejects_conflicting_duplicate_constants() -> None:
    mba = _Mba(
        {
            2: _block(2, const=0x10, jump_target=7, succs=(3, 7)),
            3: _block(3, const=0x10, jump_target=9, succs=(4, 9)),
        }
    )

    assert (
        extract_state_dispatcher_map_from_mba(mba, dispatcher_entry_block=2)
        is None
    )


def test_supports_promoted_lvar_state() -> None:
    mba = _Mba(
        {
            2: _block(
                2,
                state_mop=_mop_l(5),
                const=0x10,
                jump_target=7,
                succs=(3, 7),
            ),
        }
    )

    dispatch_map = extract_state_dispatcher_map_from_mba(
        mba,
        dispatcher_entry_block=2,
    )

    assert dispatch_map is not None
    assert dispatch_map.state_var_lvar_idx == 5
