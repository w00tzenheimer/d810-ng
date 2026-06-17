from __future__ import annotations

from types import SimpleNamespace

import idaapi

from d810.backends.hexrays.evidence import condition_chain_analysis


def _mop_b(serial: int):
    return SimpleNamespace(t=idaapi.mop_b, b=serial, block_ref=serial, size=0)


def _mop_n(value: int):
    return SimpleNamespace(t=idaapi.mop_n, nnn=SimpleNamespace(value=value), size=4)


def _mop_s(stkoff: int):
    return SimpleNamespace(t=idaapi.mop_S, s=SimpleNamespace(off=stkoff), size=4)


def _tail(opcode: int, *, l, r=None, d=None):
    return SimpleNamespace(
        opcode=opcode,
        l=l,
        r=r if r is not None else SimpleNamespace(t=getattr(idaapi, "mop_z", -1)),
        d=d if d is not None else SimpleNamespace(t=getattr(idaapi, "mop_z", -1)),
    )


class _Block:
    def __init__(self, serial: int, tail):
        self.serial = serial
        self.tail = tail
        self.head = tail


class _Mba:
    def __init__(self, blocks: dict[int, _Block]):
        self.blocks = blocks
        self.qty = max(blocks) + 1

    def get_mblock(self, serial: int):
        return self.blocks.get(int(serial))


def test_detect_state_var_stkoff_follows_mop_b_trampoline() -> None:
    mba = _Mba(
        {
            2: _Block(
                2,
                _tail(idaapi.m_goto, l=_mop_b(5)),
            ),
            5: _Block(
                5,
                _tail(
                    idaapi.m_jz,
                    l=_mop_s(0x38),
                    r=_mop_n(0x10),
                    d=_mop_b(8),
                ),
            ),
        }
    )

    result, diag_lines = condition_chain_analysis._detect_state_var_stkoff(mba, 2, diag=True)

    assert result == (0x38, None)
    assert any("mop_b block reference -> blk[5]" in line for line in diag_lines)
