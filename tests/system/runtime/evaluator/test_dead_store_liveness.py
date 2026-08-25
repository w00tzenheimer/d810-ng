"""Contract tests for exact GLBOPT2 dead-store evidence."""

from __future__ import annotations

from types import SimpleNamespace

import pytest


ida_hexrays = pytest.importorskip("ida_hexrays")

from d810.analyses.value_flow.dead_store import DeadStoreRejectionReason  # noqa: E402
from d810.evaluator.hexrays_microcode.dead_store_liveness import (  # noqa: E402
    HexRaysDeadStoreLivenessBackend,
)
import d810.evaluator.hexrays_microcode.dead_store_liveness as dead_store_liveness  # noqa: E402


class _Mop:
    def __init__(
        self,
        mop_type: int,
        *,
        register: int = 0,
        stack_offset: int = 0,
        size: int = 8,
        address_of: "_Mop | None" = None,
    ) -> None:
        self.t = int(mop_type)
        self.r = int(register)
        self.s = SimpleNamespace(off=int(stack_offset))
        self.size = int(size)
        self.a = address_of


class _Insn:
    def __init__(
        self,
        ea: int,
        *,
        destination: _Mop | None = None,
        uses: tuple[_Mop, ...] = (),
        may_uses: tuple[_Mop, ...] | None = None,
        effectful: bool = False,
        opcode: int | None = None,
    ) -> None:
        self.ea = int(ea)
        self.opcode = int(ida_hexrays.m_mov if opcode is None else opcode)
        self.l = SimpleNamespace(t=ida_hexrays.mop_d)  # computed pure RHS
        self.r = None
        self.d = destination
        self.uses = tuple(uses)
        self.may_uses = tuple(uses if may_uses is None else may_uses)
        self.effectful = bool(effectful)
        self.next = None

    def has_side_effects(self, include_ldx_and_divs: bool) -> bool:
        assert include_ldx_and_divs is False
        return self.effectful


class _LocationList:
    def __init__(self, locations=()) -> None:
        self.locations = frozenset(locations)

    def add(self, other: "_LocationList") -> None:
        self.locations = self.locations | other.locations

    def has_common(self, other: "_LocationList") -> bool:
        return bool(self.locations & other.locations)

    def includes(self, other: "_LocationList") -> bool:
        return self.locations >= other.locations

    def empty(self) -> bool:
        return not self.locations

    @property
    def mem(self):
        return self


class _Intervals:
    def __init__(self, offsets: tuple[int, ...] = ()) -> None:
        self.offsets = frozenset(offsets)

    def contains(self, offset: int) -> bool:
        return int(offset) in self.offsets

    def has_common(self, location: _LocationList) -> bool:
        stack_bytes = {
            item[1]
            for item in location.locations
            if item[0] == "S"
        }
        return bool(stack_bytes & self.offsets)


def _location(mop: _Mop) -> _LocationList:
    if mop.t == ida_hexrays.mop_r:
        return _LocationList(
            ("r", mop.r, byte) for byte in range(mop.size)
        )
    return _LocationList(
        ("S", mop.s.off + byte) for byte in range(mop.size)
    )


@pytest.fixture(autouse=True)
def _patch_location_lists(monkeypatch):
    def location_list(_block, destination):
        storage = dead_store_liveness._live_storage(destination)
        if storage.identity.kind.value == "r":
            return _LocationList(
                ("r", storage.identity.offset, byte)
                for byte in range(storage.width)
            )
        return _LocationList(
            ("S", storage.identity.offset + byte)
            for byte in range(storage.width)
        )

    monkeypatch.setattr(dead_store_liveness, "_location_list", location_list)


class _Block:
    def __init__(
        self,
        serial: int,
        instructions: tuple[_Insn, ...],
        *,
        successors: tuple[int, ...] = (),
    ) -> None:
        self.serial = int(serial)
        self.start = 0x401000 + serial * 0x100
        self.head = instructions[0] if instructions else None
        self.tail = instructions[-1] if instructions else None
        self._successors = tuple(successors)
        for current, following in zip(instructions, instructions[1:]):
            current.next = following

    def make_lists_ready(self) -> None:
        return None

    def build_use_list(self, insn: _Insn, maymust: int):
        result = _LocationList()
        uses = insn.may_uses if maymust == ida_hexrays.MAY_ACCESS else insn.uses
        for mop in uses:
            result.add(_location(mop))
        return result

    def build_def_list(self, insn: _Insn, maymust: int):
        if insn.d is None:
            return _LocationList()
        return _location(insn.d)

    def append_def_list(self, result, destination, maymust: int) -> None:
        result.add(_location(destination))

    def nsucc(self) -> int:
        return len(self._successors)

    def succ(self, index: int) -> int:
        return self._successors[index]


class _Mba:
    def __init__(
        self,
        blocks: tuple[_Block, ...],
        *,
        maturity: int = ida_hexrays.MMAT_GLBOPT2,
        aliased_offsets: tuple[int, ...] = (),
        nodel_offsets: tuple[int, ...] = (),
    ) -> None:
        self._blocks = blocks
        self.qty = len(blocks)
        self.maturity = int(maturity)
        self.aliased_memory = _Intervals(aliased_offsets)
        self.restricted_memory = _Intervals()
        self.nodel_memory = _LocationList(
            ("S", offset)
            for offset in nodel_offsets
        )

    def get_mblock(self, serial: int) -> _Block:
        return self._blocks[serial]

    def build_graph(self) -> None:
        return None


def _reasons(evidence) -> set[DeadStoreRejectionReason]:
    return {rejection.reason for rejection in evidence.rejections}


def test_accepts_pure_computed_stack_definition_across_unrelated_call() -> None:
    target = _Mop(ida_hexrays.mop_S, stack_offset=0x40)
    unrelated = _Mop(ida_hexrays.mop_r, register=12)
    dead = _Insn(0x401010, destination=target)
    call = _Insn(
        0x401020,
        uses=(unrelated,),
        opcode=ida_hexrays.m_call,
    )
    overwrite = _Insn(0x401030, destination=target, effectful=True)

    evidence = HexRaysDeadStoreLivenessBackend().collect(
        _Mba((_Block(0, (dead, call, overwrite)),))
    )

    assert [candidate.insn_ea for candidate in evidence.candidates] == [0x401010]
    assert evidence.authoritative is True


def test_ignores_call_wide_may_alias_for_unescaped_stack_storage() -> None:
    target = _Mop(ida_hexrays.mop_S, stack_offset=0x40)
    dead = _Insn(0x401010, destination=target)
    call = _Insn(
        0x401020,
        uses=(),
        may_uses=(target,),
        opcode=ida_hexrays.m_call,
    )
    overwrite = _Insn(0x401030, destination=target, effectful=True)

    evidence = HexRaysDeadStoreLivenessBackend().collect(
        _Mba((_Block(0, (dead, call, overwrite)),))
    )

    assert [candidate.insn_ea for candidate in evidence.candidates] == [0x401010]


def test_rejects_definition_read_by_call_argument() -> None:
    target = _Mop(ida_hexrays.mop_S, stack_offset=0x40)
    dead = _Insn(0x401010, destination=target)
    call = _Insn(0x401020, uses=(target,), opcode=ida_hexrays.m_call)

    evidence = HexRaysDeadStoreLivenessBackend().collect(
        _Mba((_Block(0, (dead, call)),))
    )

    assert evidence.candidates == ()
    assert DeadStoreRejectionReason.REACHED_USE in _reasons(evidence)


def test_rejects_stack_storage_whose_exact_address_escapes() -> None:
    target = _Mop(ida_hexrays.mop_S, stack_offset=0x40)
    address = _Mop(ida_hexrays.mop_a, address_of=target)
    dead = _Insn(0x401010, destination=target)
    escape = _Insn(0x401020, uses=(address,), opcode=ida_hexrays.m_call)
    escape.l = address

    evidence = HexRaysDeadStoreLivenessBackend().collect(
        _Mba((_Block(0, (dead, escape)),))
    )

    assert evidence.candidates == ()
    assert DeadStoreRejectionReason.ALIASED_STORAGE in _reasons(evidence)


def test_rejects_effectful_rhs_and_nodel_stack_storage() -> None:
    effectful_target = _Mop(ida_hexrays.mop_S, stack_offset=0x40)
    protected_target = _Mop(ida_hexrays.mop_S, stack_offset=0x50)
    effectful = _Insn(0x401010, destination=effectful_target, effectful=True)
    protected = _Insn(0x401020, destination=protected_target)

    evidence = HexRaysDeadStoreLivenessBackend().collect(
        _Mba(
            (_Block(0, (effectful, protected)),),
            nodel_offsets=(0x50,),
        )
    )

    assert evidence.candidates == ()
    assert _reasons(evidence) >= {
        DeadStoreRejectionReason.EFFECTFUL_RHS,
        DeadStoreRejectionReason.NODEL_STORAGE,
    }


def test_broad_alias_set_is_not_a_universal_barrier() -> None:
    target = _Mop(ida_hexrays.mop_S, stack_offset=0x50)
    dead = _Insn(0x401010, destination=target)
    overwrite = _Insn(0x401020, destination=target, effectful=True)

    evidence = HexRaysDeadStoreLivenessBackend().collect(
        _Mba(
            (_Block(0, (dead, overwrite)),),
            aliased_offsets=(0x50,),
        )
    )

    assert [candidate.insn_ea for candidate in evidence.candidates] == [0x401010]


def test_rejects_duplicate_definition_anchors() -> None:
    first = _Insn(
        0x401010,
        destination=_Mop(ida_hexrays.mop_r, register=10),
    )
    second = _Insn(
        0x401010,
        destination=_Mop(ida_hexrays.mop_r, register=11),
    )

    evidence = HexRaysDeadStoreLivenessBackend().collect(
        _Mba((_Block(0, (first, second)),))
    )

    assert evidence.candidates == ()
    assert _reasons(evidence) == {DeadStoreRejectionReason.AMBIGUOUS_DEFINITION}


def test_wrong_maturity_abstains_authoritatively() -> None:
    target = _Mop(ida_hexrays.mop_S, stack_offset=0x40)
    evidence = HexRaysDeadStoreLivenessBackend().collect(
        _Mba(
            (_Block(0, (_Insn(0x401010, destination=target),)),),
            maturity=ida_hexrays.MMAT_GLBOPT1,
        )
    )

    assert evidence.authoritative is True
    assert evidence.candidates == ()
    assert _reasons(evidence) == {DeadStoreRejectionReason.WRONG_MATURITY}
