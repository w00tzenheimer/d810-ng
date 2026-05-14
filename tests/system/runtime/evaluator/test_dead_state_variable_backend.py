from __future__ import annotations

from types import SimpleNamespace

import ida_hexrays

from d810.evaluator.hexrays_microcode import dead_state_variable_backend as backend_module
from d810.evaluator.hexrays_microcode.chains import UseSite
from d810.evaluator.hexrays_microcode.dead_state_variable_backend import (
    HexRaysDeadStateVariableEvidenceBackend,
    StateVariableRef,
)


class _Insn:
    def __init__(
        self,
        opcode: int,
        *,
        ea: int,
        l=None,
        r=None,
        d=None,
        next_insn=None,
    ) -> None:
        self.opcode = opcode
        self.ea = ea
        self.l = l
        self.r = r
        self.d = d
        self.next = next_insn
        self.prev = None
        if next_insn is not None:
            next_insn.prev = self


class _Block:
    def __init__(self, head, *, succs=()) -> None:
        self.head = head
        self.tail = head
        while self.tail is not None and self.tail.next is not None:
            self.tail = self.tail.next
        self._succs = tuple(succs)

    def nsucc(self) -> int:
        return len(self._succs)


class _Mba:
    def __init__(self, blocks) -> None:
        self._blocks = blocks

    def get_mblock(self, serial):
        return self._blocks.get(int(serial))


def _stkvar(stkoff: int, *, size: int = 4):
    return SimpleNamespace(
        t=ida_hexrays.mop_S,
        size=size,
        s=SimpleNamespace(off=stkoff),
    )


def _reg(*, size: int = 4):
    return SimpleNamespace(t=ida_hexrays.mop_r, size=size)


def test_resolve_state_variable_returns_neutral_ref() -> None:
    state_var = _stkvar(0x3C, size=8)

    ref = HexRaysDeadStateVariableEvidenceBackend().resolve_state_variable(
        detector=None,
        state_var=state_var,
    )

    assert ref == StateVariableRef(stkoff=0x3C, width=8)


def test_collect_dead_state_read_cleanup_sites(monkeypatch) -> None:
    insn = _Insn(
        ida_hexrays.m_mov,
        ea=0x18001000,
        l=_stkvar(0x3C),
        d=_reg(),
    )
    mba = _Mba({7: _Block(insn)})
    monkeypatch.setattr(
        backend_module,
        "find_all_uses_of_stkvar",
        lambda *_args: [UseSite(7, 0x18001000, ida_hexrays.m_mov)],
    )
    monkeypatch.setattr(
        backend_module,
        "run_valrange_fixpoint",
        lambda *_args: (_ for _ in ()).throw(RuntimeError("not needed")),
    )

    evidence = HexRaysDeadStateVariableEvidenceBackend().collect_dead_state_read_cleanup_evidence(
        mba,
        state_variable=StateVariableRef(0x3C, 4),
        known_state_constants={0x11223344},
    )

    assert evidence.use_site_count == 1
    assert len(evidence.sites) == 1
    assert evidence.sites[0].block_serial == 7
    assert evidence.sites[0].insn_ea == 0x18001000
    assert evidence.sites[0].opcode_name == "m_mov"


def test_collect_skips_non_state_destination_copy(monkeypatch) -> None:
    insn = _Insn(
        ida_hexrays.m_xdu,
        ea=0x18002000,
        l=_stkvar(0x3C),
        d=_stkvar(0x80, size=8),
    )
    mba = _Mba({9: _Block(insn)})
    monkeypatch.setattr(
        backend_module,
        "find_all_uses_of_stkvar",
        lambda *_args: [UseSite(9, 0x18002000, ida_hexrays.m_xdu)],
    )
    monkeypatch.setattr(
        backend_module,
        "run_valrange_fixpoint",
        lambda *_args: (_ for _ in ()).throw(RuntimeError("not needed")),
    )

    evidence = HexRaysDeadStateVariableEvidenceBackend().collect_dead_state_read_cleanup_evidence(
        mba,
        state_variable=StateVariableRef(0x3C, 4),
        known_state_constants=frozenset(),
    )

    assert evidence.sites == ()
    assert len(evidence.skips) == 1
    assert evidence.skips[0].reason == "dest_non_state_stkvar"
