"""Exact instruction-anchored chain queries for fragment validation."""

from __future__ import annotations

from dataclasses import dataclass

import pytest


ida_hexrays = pytest.importorskip("ida_hexrays")

from d810.evaluator.hexrays_microcode.chains import (  # noqa: E402
    DefSite,
    UseSite,
    find_reaching_defs_for_reg_use,
    find_reaching_defs_for_stkvar_use,
    find_uses_reached_by_reg_definition,
    find_uses_reached_by_stkvar_definition,
)


@dataclass
class _StackReference:
    off: int


class _Mop:
    def __init__(
        self,
        mop_type: int,
        *,
        register: int = 0,
        stack_offset: int = 0,
        size: int = 4,
    ) -> None:
        self.t = int(mop_type)
        self.r = int(register)
        self.s = _StackReference(int(stack_offset))
        self.size = int(size)


class _Instruction:
    def __init__(
        self,
        ea: int,
        *,
        source: _Mop | None = None,
        destination: _Mop | None = None,
    ) -> None:
        self.ea = int(ea)
        self.opcode = int(ida_hexrays.m_mov)
        self.l = source
        self.r = None
        self.d = destination
        self.next = None

    def for_all_ops(self, visitor) -> int:
        if self.l is not None:
            visitor.visit_mop(self.l, 0, False)
        if self.r is not None:
            visitor.visit_mop(self.r, 0, False)
        if self.d is not None:
            visitor.visit_mop(self.d, 0, True)
        return 0


class _Block:
    def __init__(self, serial: int, instructions: tuple[_Instruction, ...]) -> None:
        self.serial = int(serial)
        self.predset = ()
        self.head = instructions[0] if instructions else None
        self.tail = instructions[-1] if instructions else None
        for current, following in zip(instructions, instructions[1:]):
            current.next = following

    def make_lists_ready(self) -> None:
        return None


class _Chain:
    def __init__(self, block_serials: tuple[int, ...]) -> None:
        self._block_serials = tuple(int(value) for value in block_serials)

    def size(self) -> int:
        return len(self._block_serials)

    def at(self, index: int) -> int:
        return self._block_serials[index]


class _BlockChains:
    def __init__(
        self,
        *,
        register_targets: tuple[int, ...] = (),
        stack_targets: tuple[int, ...] = (),
    ) -> None:
        self._register_targets = register_targets
        self._stack_targets = stack_targets

    def get_reg_chain(self, _register: int, _size: int) -> _Chain:
        return _Chain(self._register_targets)

    def get_stk_chain(self, _offset: int, _size: int) -> _Chain:
        return _Chain(self._stack_targets)


class _GraphChains:
    def __init__(self, targets_by_block: dict[int, _BlockChains]) -> None:
        self._targets_by_block = targets_by_block

    def __getitem__(self, block_serial: int) -> _BlockChains:
        return self._targets_by_block[int(block_serial)]


class _Graph:
    def __init__(self, ud: _GraphChains, du: _GraphChains) -> None:
        self._ud = ud
        self._du = du

    def get_ud(self, _gctype: int) -> _GraphChains:
        return self._ud

    def get_du(self, _gctype: int) -> _GraphChains:
        return self._du


class _Mba:
    def __init__(
        self,
        blocks: tuple[_Block, ...],
        *,
        ud: _GraphChains,
        du: _GraphChains,
    ) -> None:
        self._blocks = {block.serial: block for block in blocks}
        self.qty = len(blocks)
        self._graph = _Graph(ud, du)

    def build_graph(self) -> None:
        return None

    def get_graph(self) -> _Graph:
        return self._graph

    def get_mblock(self, serial: int) -> _Block | None:
        return self._blocks.get(int(serial))


def _reg(register: int = 10) -> _Mop:
    return _Mop(ida_hexrays.mop_r, register=register)


def _stack(offset: int = 0x20) -> _Mop:
    return _Mop(ida_hexrays.mop_S, stack_offset=offset)


def _linear_mba(storage_factory) -> _Mba:
    block0 = _Block(
        0,
        (
            _Instruction(0x1000, destination=storage_factory()),
            _Instruction(0x1004, source=storage_factory()),
            _Instruction(0x1008, destination=storage_factory()),
            _Instruction(0x100C, source=storage_factory()),
        ),
    )
    block1 = _Block(
        1,
        (
            _Instruction(0x2000, source=storage_factory()),
            _Instruction(0x2004, destination=storage_factory()),
            _Instruction(0x2008, source=storage_factory()),
        ),
    )
    chains = {
        0: _BlockChains(register_targets=(1,), stack_targets=(1,)),
        1: _BlockChains(register_targets=(0,), stack_targets=(0,)),
    }
    return _Mba(
        (block0, block1),
        ud=_GraphChains(chains),
        du=_GraphChains(chains),
    )


def test_register_queries_respect_local_redefinitions_and_exact_definition() -> None:
    mba = _linear_mba(_reg)

    assert find_reaching_defs_for_reg_use(mba, 0, 0x1004, 10, 4) == [
        DefSite(0, 0x1000, ida_hexrays.m_mov)
    ]
    assert find_reaching_defs_for_reg_use(mba, 0, 0x100C, 10, 4) == [
        DefSite(0, 0x1008, ida_hexrays.m_mov)
    ]
    assert find_reaching_defs_for_reg_use(mba, 1, 0x2000, 10, 4) == [
        DefSite(0, 0x1008, ida_hexrays.m_mov)
    ]
    assert find_reaching_defs_for_reg_use(mba, 1, 0x2008, 10, 4) == [
        DefSite(1, 0x2004, ida_hexrays.m_mov)
    ]

    assert find_uses_reached_by_reg_definition(mba, 0, 0x1000, 10, 4) == [
        UseSite(0, 0x1004, ida_hexrays.m_mov)
    ]
    assert find_uses_reached_by_reg_definition(mba, 0, 0x1008, 10, 4) == [
        UseSite(0, 0x100C, ida_hexrays.m_mov),
        UseSite(1, 0x2000, ida_hexrays.m_mov),
    ]


def test_stack_queries_respect_local_redefinitions_and_exact_definition() -> None:
    mba = _linear_mba(_stack)

    assert find_reaching_defs_for_stkvar_use(mba, 1, 0x2000, 0x20, 4) == [
        DefSite(0, 0x1008, ida_hexrays.m_mov)
    ]
    assert find_reaching_defs_for_stkvar_use(mba, 1, 0x2008, 0x20, 4) == [
        DefSite(1, 0x2004, ida_hexrays.m_mov)
    ]
    assert find_uses_reached_by_stkvar_definition(
        mba,
        0,
        0x1008,
        0x20,
        4,
    ) == [
        UseSite(0, 0x100C, ida_hexrays.m_mov),
        UseSite(1, 0x2000, ida_hexrays.m_mov),
    ]


def test_exact_queries_abstain_when_ea_does_not_identify_one_instruction() -> None:
    block = _Block(
        0,
        (
            _Instruction(0x1000, destination=_reg()),
            _Instruction(0x1000, destination=_reg()),
            _Instruction(0x1004, source=_reg()),
            _Instruction(0x1004, source=_reg()),
        ),
    )
    chains = _GraphChains({0: _BlockChains(register_targets=(0,))})
    mba = _Mba((block,), ud=chains, du=chains)

    assert find_reaching_defs_for_reg_use(mba, 0, 0x1004, 10, 4) == []
    assert find_uses_reached_by_reg_definition(mba, 0, 0x1000, 10, 4) == []


def test_read_modify_write_counts_as_both_use_and_definition() -> None:
    shared_register = _reg()
    block = _Block(
        0,
        (
            _Instruction(0x1000, destination=_reg()),
            _Instruction(
                0x1004,
                source=shared_register,
                destination=shared_register,
            ),
            _Instruction(0x1008, source=_reg()),
        ),
    )
    chains = _GraphChains({0: _BlockChains(register_targets=(0,))})
    mba = _Mba((block,), ud=chains, du=chains)

    assert find_reaching_defs_for_reg_use(mba, 0, 0x1008, 10, 4) == [
        DefSite(0, 0x1004, ida_hexrays.m_mov)
    ]


def test_definition_query_preserves_duplicate_physical_use_anchors() -> None:
    block = _Block(
        0,
        (
            _Instruction(0x1000, destination=_reg()),
            _Instruction(0x1004, source=_reg()),
            _Instruction(0x1004, source=_reg()),
        ),
    )
    chains = _GraphChains({0: _BlockChains()})
    mba = _Mba((block,), ud=chains, du=chains)

    assert find_uses_reached_by_reg_definition(mba, 0, 0x1000, 10, 4) == [
        UseSite(0, 0x1004, ida_hexrays.m_mov),
        UseSite(0, 0x1004, ida_hexrays.m_mov),
    ]
