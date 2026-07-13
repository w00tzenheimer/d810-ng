"""Runtime contracts for importing detached microcode snippets."""

from __future__ import annotations

import copy
from types import SimpleNamespace

import ida_hexrays
import pytest

from d810.hexrays.mutation import detached_handler_island
from d810.hexrays.mutation import cfg_verify


class _Operand:
    def __init__(
        self,
        operand_type: int = ida_hexrays.mop_z,
        *,
        size: int = 4,
        stack_offset: int | None = None,
        address: "_Operand | None" = None,
        nested: "_Instruction | None" = None,
        arguments: tuple["_Operand", ...] = (),
        block_ref: int = -1,
        register: int = -1,
        value: int | None = None,
        target_ea: int = 0,
    ) -> None:
        self.t = int(operand_type)
        self.size = int(size)
        self.s = (
            SimpleNamespace(off=int(stack_offset))
            if stack_offset is not None
            else None
        )
        self.a = address
        self.d = nested
        self.f = SimpleNamespace(args=list(arguments))
        self.b = int(block_ref)
        self.r = int(register)
        self.g = int(target_ea)
        self.nnn = SimpleNamespace(value=int(value or 0))

    def make_stkvar(self, _mba: object, stack_offset: int) -> None:
        self.t = int(ida_hexrays.mop_S)
        self.s = SimpleNamespace(off=int(stack_offset))

    def make_blkref(self, serial: int) -> None:
        self.t = int(ida_hexrays.mop_b)
        self.b = int(serial)

    def erase(self) -> None:
        self.t = int(ida_hexrays.mop_z)

    def assign(self, other: "_Operand") -> None:
        self.__dict__ = copy.deepcopy(other.__dict__)

    def equal_mops(self, other: "_Operand", _flags: int) -> bool:
        if int(self.t) != int(other.t) or int(self.size) != int(other.size):
            return False
        if int(self.t) == int(ida_hexrays.mop_v):
            return int(self.g) == int(other.g)
        if int(self.t) == int(ida_hexrays.mop_r):
            return int(self.r) == int(other.r)
        if int(self.t) == int(ida_hexrays.mop_n):
            return int(self.nnn.value) == int(other.nnn.value)
        return int(self.t) == int(ida_hexrays.mop_z)


class _Instruction:
    def __init__(
        self,
        opcode: int,
        ea: int,
        *,
        left: _Operand | None = None,
        right: _Operand | None = None,
        dest: _Operand | None = None,
    ) -> None:
        self.opcode = int(opcode)
        self.ea = int(ea)
        self.l = left or _Operand()
        self.r = right or _Operand()
        self.d = dest or _Operand()
        self.next: _Instruction | None = None

    def setaddr(self, ea: int) -> None:
        self.ea = int(ea)


class _SerialList(list[int]):
    def push_back(self, serial: int) -> None:
        self.append(int(serial))

    def _del(self, serial: int) -> None:
        self.remove(int(serial))


class _Block:
    def __init__(
        self,
        serial: int,
        start_ea: int,
        instructions: tuple[_Instruction, ...],
        successors: tuple[int, ...] = (),
    ) -> None:
        self.serial = int(serial)
        self.start = int(start_ea)
        self.succset = _SerialList(successors)
        self.predset = _SerialList()
        self.type = int(ida_hexrays.BLT_0WAY)
        self.flags = 0
        self.dirty = 0
        self.owner: _MBA | None = None
        self._set_instructions(instructions)

    def _set_instructions(
        self,
        instructions: tuple[_Instruction, ...],
    ) -> None:
        self.head = instructions[0] if instructions else None
        self.tail = instructions[-1] if instructions else None
        for current, following in zip(instructions, instructions[1:]):
            current.next = following
        if self.tail is not None:
            self.tail.next = None

    def instructions(self) -> tuple[_Instruction, ...]:
        result: list[_Instruction] = []
        current = self.head
        while current is not None:
            result.append(current)
            current = current.next
        return tuple(result)

    def make_nop(self, instruction: _Instruction) -> None:
        instruction.opcode = int(ida_hexrays.m_nop)

    def remove_from_block(self, instruction: _Instruction) -> None:
        remaining = tuple(
            current
            for current in self.instructions()
            if current is not instruction
        )
        self._set_instructions(remaining)

    def insert_into_block(
        self,
        instruction: _Instruction,
        previous: _Instruction | None,
    ) -> None:
        current = list(self.instructions())
        index = 0 if previous is None else current.index(previous) + 1
        current.insert(index, instruction)
        self._set_instructions(tuple(current))

    def mark_lists_dirty(self) -> None:
        self.dirty += 1

    def nsucc(self) -> int:
        return len(self.succset)

    @property
    def mba(self) -> "_MBA":
        assert self.owner is not None
        return self.owner


class _MBA:
    def __init__(
        self,
        blocks: tuple[_Block, ...],
        *,
        vd_to_ida_delta: int = 0,
        ida_to_vd_delta: int = 0,
        maturity: int = ida_hexrays.MMAT_LOCOPT,
        stacksize: int = 0,
        frsize: int = 0,
        frregs: int = 0,
    ) -> None:
        self.blocks = list(blocks)
        self.entry_ea = int(blocks[0].start)
        self.vd_to_ida_delta = int(vd_to_ida_delta)
        self.ida_to_vd_delta = int(ida_to_vd_delta)
        self.maturity = int(maturity)
        self.stacksize = int(stacksize)
        self.frsize = int(frsize)
        self.frregs = int(frregs)
        self.chains_dirty = 0
        self.verify_calls = 0
        self.fictitious_ea_map: dict[int, int] = {}
        self.next_fictitious_ea = 0xF10000
        for block in self.blocks:
            block.owner = self

    @property
    def qty(self) -> int:
        return len(self.blocks)

    def append_block(self, block: _Block) -> None:
        block.owner = self
        self.blocks.append(block)

    def get_mblock(self, serial: int) -> _Block:
        return self.blocks[int(serial)]

    def stkoff_vd2ida(self, stack_offset: int) -> int:
        return int(stack_offset) + self.vd_to_ida_delta

    def stkoff_ida2vd(self, stack_offset: int) -> int:
        return int(stack_offset) + self.ida_to_vd_delta

    def mark_chains_dirty(self) -> None:
        self.chains_dirty += 1

    def alloc_fict_ea(self, real_ea: int) -> int:
        fictitious_ea = self.next_fictitious_ea
        self.next_fictitious_ea += 1
        self.fictitious_ea_map[fictitious_ea] = int(real_ea)
        return fictitious_ea

    def map_fict_ea(self, fictitious_ea: int) -> int:
        return self.fictitious_ea_map.get(
            int(fictitious_ea),
            int(fictitious_ea),
        )

    def verify(self, _always: bool) -> None:
        self.verify_calls += 1


def _fake_minsn(instruction: _Instruction | int) -> _Instruction:
    if isinstance(instruction, int):
        return _Instruction(ida_hexrays.m_nop, instruction)
    return copy.deepcopy(instruction)


def _install_runtime_fakes(monkeypatch) -> list[tuple[int, int]]:
    from d810.hexrays.mutation.deferred_modifier import DeferredGraphModifier

    created: list[tuple[int, int]] = []

    def create_standalone_block(
        modifier: DeferredGraphModifier,
        *,
        ref_serial: int,
        blk_ins: list[object] | tuple[object, ...] | None = None,
        target_serial: int | None = None,
        is_0_way: bool = False,
        verify: bool = True,
    ) -> int:
        assert ref_serial == 0
        assert not blk_ins
        assert target_serial is None
        assert is_0_way is True
        assert verify is False
        mba = modifier.mba
        serial = mba.qty
        anchor_ea = 0xF00000 + serial
        block = _Block(
            serial,
            anchor_ea,
            (_Instruction(ida_hexrays.m_nop, anchor_ea),),
        )
        mba.append_block(block)
        created.append((serial, anchor_ea))
        return serial

    monkeypatch.setattr(
        detached_handler_island.ida_hexrays,
        "minsn_t",
        _fake_minsn,
    )
    monkeypatch.setattr(
        DeferredGraphModifier,
        "create_standalone_block",
        create_standalone_block,
    )
    monkeypatch.setattr(
        detached_handler_island,
        "_DETACHED_SNIPPET_TEMPLATES",
        {},
    )
    monkeypatch.setattr(
        detached_handler_island,
        "_DETACHED_REPLACEMENT_SNIPPET_TEMPLATES",
        {},
        raising=False,
    )
    monkeypatch.setattr(
        detached_handler_island,
        "_IMPORTED_SNIPPET_ROOTS",
        {},
    )
    monkeypatch.setattr(
        detached_handler_island,
        "_IMPORTED_INSTRUCTION_ORIGINS",
        {},
    )
    return created


def test_recursively_rebases_all_stack_operand_shapes(monkeypatch) -> None:
    _install_runtime_fakes(monkeypatch)
    function_ea = 0x40A560
    target_ea = 0x40C4F6
    source_offsets = (0x40, 0x44, 0x48, 0x4C)
    nested = _Instruction(
        ida_hexrays.m_mov,
        target_ea + 2,
        left=_Operand(ida_hexrays.mop_S, stack_offset=source_offsets[2]),
        right=_Operand(
            ida_hexrays.mop_f,
            arguments=(
                _Operand(
                    ida_hexrays.mop_S,
                    stack_offset=source_offsets[3],
                    size=8,
                ),
            ),
        ),
    )
    source_instruction = _Instruction(
        ida_hexrays.m_mov,
        target_ea,
        left=_Operand(
            ida_hexrays.mop_S,
            stack_offset=source_offsets[0],
            size=1,
        ),
        right=_Operand(
            ida_hexrays.mop_a,
            address=_Operand(
                ida_hexrays.mop_S,
                stack_offset=source_offsets[1],
                size=2,
            ),
        ),
        dest=_Operand(ida_hexrays.mop_d, nested=nested),
    )
    source = _MBA(
        (_Block(0, target_ea, (source_instruction,)),),
        vd_to_ida_delta=0x1000,
    )
    destination = _MBA(
        (
            _Block(
                0,
                function_ea,
                (_Instruction(ida_hexrays.m_nop, function_ea),),
            ),
        ),
        ida_to_vd_delta=0x200,
    )

    assert detached_handler_island.capture_detached_snippet_template(
        function_ea,
        target_ea,
        source,
        ((target_ea, target_ea + 0x10),),
    )
    roots = detached_handler_island.materialize_detached_snippet_templates(
        destination,
        function_ea,
        (target_ea,),
    )

    imported = destination.get_mblock(roots[target_ea]).head
    assert imported is not None
    stable_destination_delta = 0x1000 + 0x200
    assert int(imported.l.s.off) == source_offsets[0] + stable_destination_delta
    assert int(imported.l.size) == 1
    assert (
        int(imported.r.a.s.off)
        == source_offsets[1] + stable_destination_delta
    )
    assert int(imported.r.a.size) == 2
    assert (
        int(imported.d.d.l.s.off)
        == source_offsets[2] + stable_destination_delta
    )
    imported_arg = imported.d.d.r.f.args[0]
    assert (
        int(imported_arg.s.off)
        == source_offsets[3] + stable_destination_delta
    )
    assert int(imported_arg.size) == 8


def test_capture_normalizes_negative_fragment_stack_identity_by_frame_size(
    monkeypatch,
) -> None:
    _install_runtime_fakes(monkeypatch)
    function_ea = 0x40A560
    target_ea = 0x40B287
    source_vd = 24
    monkeypatch.setattr(
        detached_handler_island.ida_funcs,
        "get_func",
        lambda ea: (
            SimpleNamespace(frsize=0x48C, frregs=4)
            if int(ea) == function_ea
            else None
        ),
    )
    source = _MBA(
        (
            _Block(
                0,
                target_ea,
                (
                    _Instruction(
                        ida_hexrays.m_mov,
                        target_ea,
                        dest=_Operand(ida_hexrays.mop_S, stack_offset=source_vd),
                    ),
                ),
            ),
        ),
        vd_to_ida_delta=-0x498,
        stacksize=0x498,
    )

    assert detached_handler_island.capture_detached_snippet_template(
        function_ea,
        target_ea,
        source,
        ((target_ea, target_ea + 1),),
    )
    template = detached_handler_island._DETACHED_SNIPPET_TEMPLATES[
        (function_ea, target_ea)
    ]
    assert template.stack_vd_to_ida == ((source_vd, -0x480),)
    assert template.stable_stack_vd_to_ida == ((source_vd, 16),)


def test_remaps_recursive_block_references_and_cfg_edges(monkeypatch) -> None:
    _install_runtime_fakes(monkeypatch)
    function_ea = 0x40A560
    root_ea = 0x40C4F6
    successor_ea = 0x40C505
    nested = _Instruction(
        ida_hexrays.m_mov,
        root_ea + 2,
        left=_Operand(ida_hexrays.mop_b, block_ref=1),
        right=_Operand(
            ida_hexrays.mop_f,
            arguments=(_Operand(ida_hexrays.mop_b, block_ref=1),),
        ),
    )
    source = _MBA(
        (
            _Block(
                0,
                root_ea,
                (
                    _Instruction(
                        ida_hexrays.m_goto,
                        root_ea,
                        left=_Operand(ida_hexrays.mop_b, block_ref=1),
                        right=_Operand(ida_hexrays.mop_d, nested=nested),
                        dest=_Operand(ida_hexrays.mop_b, block_ref=1),
                    ),
                ),
                (1,),
            ),
            _Block(
                1,
                successor_ea,
                (_Instruction(ida_hexrays.m_nop, successor_ea),),
            ),
        )
    )
    destination = _MBA(
        (
            _Block(
                0,
                function_ea,
                (_Instruction(ida_hexrays.m_nop, function_ea),),
            ),
        )
    )

    assert detached_handler_island.capture_detached_snippet_template(
        function_ea,
        root_ea,
        source,
        ((root_ea, root_ea + 0x10), (successor_ea, successor_ea + 0x10)),
    )
    roots = detached_handler_island.materialize_detached_snippet_templates(
        destination,
        function_ea,
        (root_ea,),
    )

    imported_root = destination.get_mblock(roots[root_ea])
    imported_successor = destination.get_mblock(imported_root.succset[0])
    instruction = imported_root.head
    assert instruction is not None
    expected_serial = int(imported_successor.serial)
    assert int(instruction.l.b) == expected_serial
    assert int(instruction.r.d.l.b) == expected_serial
    assert int(instruction.r.d.r.f.args[0].b) == expected_serial
    assert int(instruction.d.b) == expected_serial
    assert tuple(imported_root.succset) == (expected_serial,)
    assert tuple(imported_successor.predset) == (int(imported_root.serial),)


def test_summarizes_lost_conditional_template_for_portable_planner(
    monkeypatch,
) -> None:
    from d810.analyses.control_flow.detached_handler_island import (
        DetachedSnippetReplacementEvidence,
    )

    _install_runtime_fakes(monkeypatch)
    function_ea = 0x40A560
    target_ea = 0x40B8E6
    source = _MBA(
        (
            _Block(
                0,
                target_ea,
                (
                    _Instruction(
                        ida_hexrays.m_jnz,
                        0x40B90F,
                        dest=_Operand(ida_hexrays.mop_b, block_ref=4),
                    ),
                ),
                (1, 4),
            ),
            _Block(
                1,
                0x40B915,
                (
                    _Instruction(ida_hexrays.m_nop, 0x40B915),
                    _Instruction(
                        ida_hexrays.m_jge,
                        0x40B921,
                        dest=_Operand(ida_hexrays.mop_b, block_ref=5),
                    ),
                ),
                (2, 5),
            ),
            _Block(
                2,
                0x40B927,
                (
                    _Instruction(ida_hexrays.m_nop, 0x40B927),
                    _Instruction(ida_hexrays.m_ijmp, 0x40B931),
                ),
            ),
            _Block(
                3,
                0x40B931,
                (_Instruction(ida_hexrays.m_nop, 0x40B931),),
            ),
            _Block(
                4,
                0x40C6B5,
                (_Instruction(ida_hexrays.m_nop, 0x40C6B5),),
                (5,),
            ),
            _Block(
                5,
                0x40C6CC,
                (
                    _Instruction(ida_hexrays.m_nop, 0x40C6CC),
                    _Instruction(ida_hexrays.m_ijmp, 0x40C6D8),
                ),
            ),
        )
    )
    source.get_mblock(0).type = int(ida_hexrays.BLT_2WAY)
    source.get_mblock(1).type = int(ida_hexrays.BLT_2WAY)

    assert detached_handler_island.capture_detached_replacement_snippet_template(
        function_ea,
        target_ea,
        source,
        ((target_ea, 0x40B932), (0x40C6B5, 0x40C6D9)),
    )
    assert detached_handler_island.detached_snippet_replacement_evidence(
        function_ea,
        target_ea,
    ) == DetachedSnippetReplacementEvidence(
        target_ea=target_ea,
        conditional_branch_ea=0x40B90F,
        conditional_target_eas=(0x40B915, 0x40C6B5),
        terminal_exit_eas=(0x40B931, 0x40C6D8),
        calls_verify_safe=True,
        contains_calls=False,
    )
    assert detached_handler_island.capture_detached_snippet_template(
        function_ea,
        target_ea,
        source,
        ((target_ea, 0x40B932), (0x40C6B5, 0x40C6D9)),
    )
    assert detached_handler_island.detached_snippet_conditional_evidence(
        function_ea,
        target_ea,
    ) == DetachedSnippetReplacementEvidence(
        target_ea=target_ea,
        conditional_branch_ea=0x40B90F,
        conditional_target_eas=(0x40B915, 0x40C6B5),
        terminal_exit_eas=(0x40B931, 0x40C6D8),
        calls_verify_safe=True,
        contains_calls=False,
    )


def test_summarizes_detached_arm_after_calls_folds_its_range_prefix(
    monkeypatch,
) -> None:
    from d810.analyses.control_flow.detached_handler_island import (
        DetachedSnippetReplacementEvidence,
    )

    _install_runtime_fakes(monkeypatch)
    function_ea = 0x40A560
    target_ea = 0x40B8E6
    source = _MBA(
        (
            _Block(
                0,
                target_ea,
                (
                    _Instruction(
                        ida_hexrays.m_jnz,
                        0x40B90F,
                        dest=_Operand(ida_hexrays.mop_b, block_ref=2),
                    ),
                ),
                (1, 2),
            ),
            _Block(
                1,
                0x40B927,
                (
                    _Instruction(ida_hexrays.m_nop, 0x40B927),
                    _Instruction(ida_hexrays.m_ijmp, 0x40B931),
                ),
            ),
            _Block(
                2,
                0x40C6CC,
                (
                    _Instruction(ida_hexrays.m_nop, 0x40C6CC),
                    _Instruction(ida_hexrays.m_ijmp, 0x40C6D8),
                ),
            ),
        )
    )
    source.get_mblock(0).type = int(ida_hexrays.BLT_2WAY)

    assert detached_handler_island.capture_detached_replacement_snippet_template(
        function_ea,
        target_ea,
        source,
        ((target_ea, 0x40B932), (0x40C6B5, 0x40C6D9)),
    )
    assert detached_handler_island.detached_snippet_replacement_evidence(
        function_ea,
        target_ea,
    ) == DetachedSnippetReplacementEvidence(
        target_ea=target_ea,
        conditional_branch_ea=0x40B90F,
        conditional_target_eas=(0x40B927, 0x40C6CC),
        terminal_exit_eas=(0x40B931, 0x40C6D8),
        calls_verify_safe=True,
        contains_calls=False,
    )


def test_recovers_replacement_arm_states_from_locopt_template(
    monkeypatch,
) -> None:
    _install_runtime_fakes(monkeypatch)
    function_ea = 0x40A560
    target_ea = 0x40B8E6
    state_register = 20
    inherited_state = 0xA7933EA0
    taken_state = 0x7F9D6412
    source = _MBA(
        (
            _Block(
                0,
                target_ea,
                (
                    _Instruction(
                        ida_hexrays.m_mov,
                        0x40B908,
                        left=_Operand(ida_hexrays.mop_n, value=inherited_state),
                        dest=_Operand(
                            ida_hexrays.mop_r,
                            register=state_register,
                        ),
                    ),
                ),
                (1,),
            ),
            _Block(
                1,
                0x40B90F,
                (
                    _Instruction(
                        ida_hexrays.m_jnz,
                        0x40B90F,
                        dest=_Operand(ida_hexrays.mop_b, block_ref=3),
                    ),
                ),
                (3, 2),
            ),
            _Block(2, 0x40B915, (_Instruction(ida_hexrays.m_nop, 0x40B915),)),
            _Block(
                3,
                0x40C6B5,
                (
                    _Instruction(
                        ida_hexrays.m_mov,
                        0x40C6B5,
                        left=_Operand(ida_hexrays.mop_n, value=taken_state),
                        dest=_Operand(
                            ida_hexrays.mop_r,
                            register=state_register,
                        ),
                    ),
                ),
            ),
        )
    )
    source.get_mblock(1).type = int(ida_hexrays.BLT_2WAY)

    assert detached_handler_island.capture_detached_snippet_template(
        function_ea,
        target_ea,
        source,
        ((target_ea, 0x40B932), (0x40C6B5, 0x40C6DA)),
    )
    assert detached_handler_island.detached_snippet_replacement_arm_states(
        function_ea,
        target_ea,
        state_register=state_register,
        conditional_branch_ea=0x40B90F,
        conditional_target_eas=(0x40B915, 0x40C6B5),
    ) == (inherited_state, taken_state)


def test_recovers_replacement_arm_states_when_locopt_drops_predicate(
    monkeypatch,
) -> None:
    _install_runtime_fakes(monkeypatch)
    function_ea = 0x40A560
    target_ea = 0x40B8E6
    state_register = 20
    inherited_state = 0xA7933EA0
    taken_state = 0x7F9D6412
    source = _MBA(
        (
            _Block(
                0,
                target_ea,
                (
                    _Instruction(
                        ida_hexrays.m_mov,
                        0x40B908,
                        left=_Operand(ida_hexrays.mop_n, value=inherited_state),
                        dest=_Operand(ida_hexrays.mop_r, register=state_register),
                    ),
                ),
                (1,),
            ),
            _Block(1, 0x40B915, (_Instruction(ida_hexrays.m_nop, 0x40B915),)),
            _Block(
                2,
                0x40C6B5,
                (
                    _Instruction(
                        ida_hexrays.m_mov,
                        0x40C6B5,
                        left=_Operand(ida_hexrays.mop_n, value=taken_state),
                        dest=_Operand(ida_hexrays.mop_r, register=state_register),
                    ),
                ),
            ),
        )
    )

    assert detached_handler_island.capture_detached_snippet_template(
        function_ea,
        target_ea,
        source,
        ((target_ea, 0x40B932), (0x40C6B5, 0x40C6DA)),
    )
    assert detached_handler_island.detached_snippet_replacement_arm_states(
        function_ea,
        target_ea,
        state_register=state_register,
        conditional_branch_ea=0x40B90F,
        conditional_target_eas=(0x40B915, 0x40C6B5),
    ) == (inherited_state, taken_state)


def test_redirects_live_target_predecessors_to_imported_replacement() -> None:
    entry = _Block(0, 0x40A560, (), (1,))
    predecessor = _Block(
        1,
        0x40ADE6,
        (
            _Instruction(
                ida_hexrays.m_goto,
                0x40ADF0,
                left=_Operand(ida_hexrays.mop_b, block_ref=2),
            ),
        ),
        (2,),
    )
    old_target = _Block(2, 0x40B8E6, (), ())
    imported_root = _Block(3, 0x40A560, (), ())
    mba = _MBA(
        (entry, predecessor, old_target, imported_root),
        maturity=ida_hexrays.MMAT_CALLS,
    )
    predecessor.predset.push_back(0)
    old_target.predset.push_back(1)

    assert detached_handler_island.redirect_live_target_predecessors(
        mba,
        {2: 3},
    ) == 1
    assert tuple(predecessor.succset) == (3,)
    assert tuple(old_target.predset) == ()
    assert tuple(imported_root.predset) == (1,)


def test_live_target_replacement_abstains_atomically_on_two_way_predecessor() -> None:
    entry = _Block(0, 0x40A560, (), (1,))
    predecessor = _Block(1, 0x40ADE6, (), (2, 3))
    predecessor.type = int(ida_hexrays.BLT_2WAY)
    old_target = _Block(2, 0x40B8E6, (), ())
    sibling = _Block(3, 0x40A607, (), ())
    imported_root = _Block(4, 0x40A560, (), ())
    mba = _MBA(
        (entry, predecessor, old_target, sibling, imported_root),
        maturity=ida_hexrays.MMAT_CALLS,
    )
    predecessor.predset.push_back(0)
    old_target.predset.push_back(1)
    sibling.predset.push_back(1)

    assert detached_handler_island.redirect_live_target_predecessors(
        mba,
        {2: 4},
    ) == 0
    assert tuple(predecessor.succset) == (2, 3)
    assert tuple(old_target.predset) == (1,)
    assert tuple(imported_root.predset) == ()


def test_marks_template_with_untyped_call_as_verifier_unsafe(monkeypatch) -> None:
    _install_runtime_fakes(monkeypatch)
    function_ea = 0x40A560
    target_ea = 0x40B8E6
    source = _MBA(
        (
            _Block(
                0,
                target_ea,
                (
                    _Instruction(ida_hexrays.m_call, 0x40B900),
                    _Instruction(
                        ida_hexrays.m_jnz,
                        0x40B90F,
                        dest=_Operand(ida_hexrays.mop_b, block_ref=2),
                    ),
                ),
                (1, 2),
            ),
            _Block(
                1,
                0x40B915,
                (
                    _Instruction(ida_hexrays.m_nop, 0x40B915),
                    _Instruction(ida_hexrays.m_ijmp, 0x40B931),
                ),
            ),
            _Block(
                2,
                0x40C6B5,
                (
                    _Instruction(ida_hexrays.m_nop, 0x40C6B5),
                    _Instruction(ida_hexrays.m_ijmp, 0x40C6D8),
                ),
            ),
        )
    )
    source.get_mblock(0).type = int(ida_hexrays.BLT_2WAY)

    assert detached_handler_island.capture_detached_replacement_snippet_template(
        function_ea,
        target_ea,
        source,
        ((target_ea, 0x40B932), (0x40C6B5, 0x40C6D9)),
    )
    evidence = detached_handler_island.detached_snippet_replacement_evidence(
        function_ea,
        target_ea,
    )
    assert evidence is not None
    assert evidence.calls_verify_safe is False
    assert evidence.contains_calls is True


def test_import_uses_exact_analyzed_call_from_replacement_template(
    monkeypatch,
) -> None:
    """A raw pre-CALLS call must inherit the real analyzed argument list."""
    _install_runtime_fakes(monkeypatch)
    function_ea = 0x40A560
    target_ea = 0x40B9A6
    call_ea = 0x40BA56
    source_stack_offset = 0x44
    analyzed_source_stack_offset = 0x144

    raw_source = _MBA(
        (
            _Block(
                0,
                target_ea,
                (
                    _Instruction(
                        ida_hexrays.m_mov,
                        target_ea,
                        left=_Operand(
                            ida_hexrays.mop_S,
                            stack_offset=source_stack_offset,
                        ),
                    ),
                    _Instruction(ida_hexrays.m_call, call_ea),
                ),
            ),
        ),
        maturity=ida_hexrays.MMAT_PREOPTIMIZED,
    )
    analyzed_call = _Instruction(
        ida_hexrays.m_call,
        call_ea,
        dest=_Operand(
            ida_hexrays.mop_f,
            arguments=(
                _Operand(
                    ida_hexrays.mop_S,
                    stack_offset=analyzed_source_stack_offset,
                ),
            ),
        ),
    )
    analyzed_source = _MBA(
        (
            _Block(
                0,
                target_ea,
                (
                    _Instruction(
                        ida_hexrays.m_mov,
                        target_ea,
                        left=_Operand(
                            ida_hexrays.mop_d,
                            nested=analyzed_call,
                        ),
                    ),
                ),
            ),
        ),
        vd_to_ida_delta=-0x100,
        maturity=ida_hexrays.MMAT_CALLS,
    )
    destination = _MBA(
        (
            _Block(
                0,
                function_ea,
                (_Instruction(ida_hexrays.m_nop, function_ea),),
            ),
        ),
        ida_to_vd_delta=0x200,
        maturity=ida_hexrays.MMAT_PREOPTIMIZED,
    )

    assert detached_handler_island.capture_detached_snippet_template(
        function_ea,
        target_ea,
        raw_source,
        ((target_ea, call_ea + 1),),
    )
    assert detached_handler_island.capture_detached_replacement_snippet_template(
        function_ea,
        target_ea,
        analyzed_source,
        ((target_ea, call_ea + 1),),
    )
    instruction_tree = detached_handler_island._instruction_tree

    def swig_proxy_instruction_tree(instruction: object) -> tuple[object, ...]:
        rows = instruction_tree(instruction)
        return (rows[0], *(copy.deepcopy(row) for row in rows[1:]))

    monkeypatch.setattr(
        detached_handler_island,
        "_instruction_tree",
        swig_proxy_instruction_tree,
    )

    roots = detached_handler_island.materialize_detached_snippet_templates(
        destination,
        function_ea,
        (target_ea,),
    )

    imported_block = destination.get_mblock(roots[target_ea])
    assert int(imported_block.start) == function_ea
    assert int(imported_block.end) == function_ea + 1
    imported_call = imported_block.tail
    assert imported_call is not None
    assert int(imported_call.opcode) == int(ida_hexrays.m_call)
    assert int(imported_call.d.t) == int(ida_hexrays.mop_f)
    assert len(imported_call.d.f.args) == 1
    assert int(imported_call.d.f.args[0].s.off) == source_stack_offset + 0x200
    assert int(imported_call.ea) != call_ea
    assert destination.map_fict_ea(int(imported_call.ea)) == function_ea + 1
    origins = dict(
        detached_handler_island.imported_detached_snippet_instruction_origins(
            destination
        )
    )
    assert origins[int(imported_call.ea)] == call_ea


def test_import_omits_transient_stack_setup_subsumed_by_analyzed_call(
    monkeypatch,
) -> None:
    """Negative-identity outgoing args must not alias persistent locals."""
    _install_runtime_fakes(monkeypatch)
    function_ea = 0x40A560
    target_ea = 0x40B3FF
    persistent_ea = 0x40B450
    setup_ea = 0x40B49A
    call_ea = 0x40B49E
    persistent_source_vd = 0x140
    transient_source_vd = 4

    raw_source = _MBA(
        (
            _Block(
                0,
                target_ea,
                (
                    _Instruction(
                        ida_hexrays.m_mov,
                        persistent_ea,
                        dest=_Operand(
                            ida_hexrays.mop_S,
                            stack_offset=persistent_source_vd,
                        ),
                    ),
                    _Instruction(
                        ida_hexrays.m_mov,
                        setup_ea,
                        dest=_Operand(
                            ida_hexrays.mop_S,
                            stack_offset=transient_source_vd,
                        ),
                    ),
                    _Instruction(ida_hexrays.m_call, call_ea),
                ),
            ),
        ),
        vd_to_ida_delta=-0x100,
        maturity=ida_hexrays.MMAT_PREOPTIMIZED,
    )
    analyzed_source = _MBA(
        (
            _Block(
                0,
                target_ea,
                (
                    _Instruction(
                        ida_hexrays.m_call,
                        call_ea,
                        dest=_Operand(
                            ida_hexrays.mop_f,
                            arguments=(
                                _Operand(
                                    ida_hexrays.mop_d,
                                    nested=_Instruction(
                                        ida_hexrays.m_mov,
                                        setup_ea,
                                        left=_Operand(
                                            ida_hexrays.mop_n,
                                            value=300,
                                        ),
                                    ),
                                ),
                            ),
                        ),
                    ),
                ),
            ),
        ),
        maturity=ida_hexrays.MMAT_CALLS,
    )
    destination = _MBA(
        (
            _Block(
                0,
                function_ea,
                (_Instruction(ida_hexrays.m_nop, function_ea),),
            ),
        ),
        ida_to_vd_delta=0x200,
        maturity=ida_hexrays.MMAT_PREOPTIMIZED,
    )

    assert detached_handler_island.capture_detached_snippet_template(
        function_ea,
        target_ea,
        raw_source,
        ((target_ea, call_ea + 1),),
    )
    assert detached_handler_island.capture_detached_replacement_snippet_template(
        function_ea,
        target_ea,
        analyzed_source,
        ((target_ea, call_ea + 1),),
    )

    roots = detached_handler_island.materialize_detached_snippet_templates(
        destination,
        function_ea,
        (target_ea,),
    )

    imported = destination.get_mblock(roots[target_ea])
    origins = dict(
        detached_handler_island.imported_detached_snippet_instruction_origins(
            destination
        )
    )
    imported_native_eas = {
        int(origins[int(instruction.ea)])
        for instruction in imported.instructions()
    }
    assert imported_native_eas == {persistent_ea, call_ea}
    persistent_write = next(
        instruction
        for instruction in imported.instructions()
        if origins[int(instruction.ea)] == persistent_ea
    )
    assert int(persistent_write.d.s.off) == 0x240


def test_import_preserves_analyzed_call_result_carrier(
    monkeypatch,
) -> None:
    """A CALLS ``mov call -> carrier`` must survive detached import intact."""
    _install_runtime_fakes(monkeypatch)
    function_ea = 0x40A560
    target_ea = 0x40C1A0
    call_ea = 0x40C1BB
    raw_source_stack_offset = 0x44
    analyzed_argument_stack_offset = 0x144
    analyzed_result_stack_offset = 0x148

    raw_source = _MBA(
        (
            _Block(
                0,
                target_ea,
                (
                    _Instruction(
                        ida_hexrays.m_mov,
                        target_ea,
                        left=_Operand(
                            ida_hexrays.mop_S,
                            stack_offset=raw_source_stack_offset,
                        ),
                    ),
                    _Instruction(ida_hexrays.m_call, call_ea),
                ),
            ),
        ),
        maturity=ida_hexrays.MMAT_PREOPTIMIZED,
    )
    analyzed_call = _Instruction(
        ida_hexrays.m_call,
        call_ea,
        dest=_Operand(
            ida_hexrays.mop_f,
            arguments=(
                _Operand(
                    ida_hexrays.mop_S,
                    stack_offset=analyzed_argument_stack_offset,
                ),
            ),
        ),
    )
    analyzed_source = _MBA(
        (
            _Block(
                0,
                target_ea,
                (
                    _Instruction(
                        ida_hexrays.m_mov,
                        call_ea,
                        left=_Operand(
                            ida_hexrays.mop_d,
                            nested=analyzed_call,
                        ),
                        dest=_Operand(
                            ida_hexrays.mop_S,
                            stack_offset=analyzed_result_stack_offset,
                        ),
                    ),
                ),
            ),
        ),
        vd_to_ida_delta=-0x100,
        maturity=ida_hexrays.MMAT_CALLS,
    )
    destination = _MBA(
        (
            _Block(
                0,
                function_ea,
                (_Instruction(ida_hexrays.m_nop, function_ea),),
            ),
        ),
        ida_to_vd_delta=0x200,
        maturity=ida_hexrays.MMAT_PREOPTIMIZED,
    )

    assert detached_handler_island.capture_detached_snippet_template(
        function_ea,
        target_ea,
        raw_source,
        ((target_ea, call_ea + 1),),
    )
    assert detached_handler_island.capture_detached_replacement_snippet_template(
        function_ea,
        target_ea,
        analyzed_source,
        ((target_ea, call_ea + 1),),
    )
    instruction_tree = detached_handler_island._instruction_tree

    def swig_proxy_instruction_tree(instruction: object) -> tuple[object, ...]:
        rows = instruction_tree(instruction)
        return (rows[0], *(copy.deepcopy(row) for row in rows[1:]))

    monkeypatch.setattr(
        detached_handler_island,
        "_instruction_tree",
        swig_proxy_instruction_tree,
    )

    roots = detached_handler_island.materialize_detached_snippet_templates(
        destination,
        function_ea,
        (target_ea,),
    )

    imported_block = destination.get_mblock(roots[target_ea])
    imported_assignment = imported_block.tail
    assert imported_assignment is not None
    assert int(imported_assignment.opcode) == int(ida_hexrays.m_mov)
    assert int(imported_assignment.l.t) == int(ida_hexrays.mop_d)
    assert int(imported_assignment.l.d.opcode) == int(ida_hexrays.m_call)
    assert int(imported_assignment.l.d.d.t) == int(ida_hexrays.mop_f)
    assert int(imported_assignment.d.t) == int(ida_hexrays.mop_S)
    assert int(imported_assignment.d.s.off) == 0x248
    origins = dict(
        detached_handler_island.imported_detached_snippet_instruction_origins(
            destination
        )
    )
    assert origins[int(imported_assignment.ea)] == call_ea


@pytest.mark.parametrize(
    (
        "destination_delta",
        "expected_argument_vd",
        "expected_carrier_vd",
        "expected_unrelated_vd",
    ),
    (
        (0x200, 0x244, 0x248, 0x250),
        (-0x100, 0x44, 0x48, 0x50),
    ),
)
def test_import_rebases_persistent_stack_slots_through_ida_identity(
    monkeypatch,
    destination_delta: int,
    expected_argument_vd: int,
    expected_carrier_vd: int,
    expected_unrelated_vd: int,
) -> None:
    """A raw call/carrier/predicate envelope keeps its stable frame slots."""
    _install_runtime_fakes(monkeypatch)
    function_ea = 0x40A560
    target_ea = 0x40B287
    call_ea = 0x40B2A0
    carrier_ea = 0x40B2AB
    branch_ea = 0x40B2B1
    return_mreg = int(ida_hexrays.reg2mreg(0))
    argument_vd = 0x144
    argument_ida = 0x44
    carrier_vd = 0x148
    carrier_ida = 0x48
    unrelated_vd = 0x150

    setup = _Instruction(
        ida_hexrays.m_mov,
        0x40B293,
        left=_Operand(ida_hexrays.mop_n, value=7),
        dest=_Operand(ida_hexrays.mop_S, stack_offset=unrelated_vd),
    )
    raw_call = _Instruction(
        ida_hexrays.m_call,
        call_ea,
        left=_Operand(ida_hexrays.mop_v, target_ea=0x42E1E8),
    )
    raw_carrier = _Instruction(
        ida_hexrays.m_mov,
        carrier_ea,
        left=_Operand(ida_hexrays.mop_r, register=return_mreg),
        dest=_Operand(ida_hexrays.mop_S, stack_offset=carrier_vd),
    )
    branch = _Instruction(
        ida_hexrays.m_jnz,
        branch_ea,
        left=_Operand(ida_hexrays.mop_r, register=return_mreg),
        right=_Operand(ida_hexrays.mop_n, value=0),
        dest=_Operand(ida_hexrays.mop_b, block_ref=3),
    )
    raw_source = _MBA(
        (
            _Block(0, target_ea, (setup, raw_call), (1,)),
            _Block(1, 0x40B2A6, (raw_carrier, branch), (2, 3)),
            _Block(2, 0x40B2B7, (_Instruction(ida_hexrays.m_nop, 0x40B2B7),)),
            _Block(3, 0x40B668, (_Instruction(ida_hexrays.m_nop, 0x40B668),)),
        ),
        vd_to_ida_delta=-0x100,
        maturity=ida_hexrays.MMAT_PREOPTIMIZED,
    )
    raw_source.get_mblock(1).type = int(ida_hexrays.BLT_2WAY)

    analyzed_call = _Instruction(
        ida_hexrays.m_call,
        call_ea,
        left=_Operand(ida_hexrays.mop_v, target_ea=0x42E1E8),
        dest=_Operand(
            ida_hexrays.mop_f,
            arguments=(
                _Operand(ida_hexrays.mop_S, stack_offset=argument_vd),
            ),
        ),
    )
    analyzed_call_owner = _Instruction(
        ida_hexrays.m_mov,
        call_ea,
        left=_Operand(ida_hexrays.mop_d, nested=analyzed_call),
        dest=_Operand(ida_hexrays.mop_r, register=return_mreg),
    )
    analyzed_source = _MBA(
        (
            _Block(0, target_ea, (copy.deepcopy(setup), analyzed_call_owner), (1,)),
            _Block(
                1,
                0x40B2A6,
                (copy.deepcopy(raw_carrier), copy.deepcopy(branch)),
                (2, 3),
            ),
            _Block(2, 0x40B2B7, (_Instruction(ida_hexrays.m_nop, 0x40B2B7),)),
            _Block(3, 0x40B668, (_Instruction(ida_hexrays.m_nop, 0x40B668),)),
        ),
        vd_to_ida_delta=-0x100,
        maturity=ida_hexrays.MMAT_CALLS,
    )
    analyzed_source.get_mblock(1).type = int(ida_hexrays.BLT_2WAY)
    destination = _MBA(
        (
            _Block(
                0,
                function_ea,
                (_Instruction(ida_hexrays.m_nop, function_ea),),
            ),
        ),
        ida_to_vd_delta=destination_delta,
        maturity=ida_hexrays.MMAT_PREOPTIMIZED,
    )
    ranges = ((target_ea, 0x40B2DB), (0x40B668, 0x40B693))

    assert detached_handler_island.capture_detached_snippet_template(
        function_ea,
        target_ea,
        raw_source,
        ranges,
    )
    assert detached_handler_island.capture_detached_replacement_snippet_template(
        function_ea,
        target_ea,
        analyzed_source,
        ranges,
    )

    roots = detached_handler_island.materialize_detached_snippet_templates(
        destination,
        function_ea,
        (target_ea,),
    )

    imported_root = destination.get_mblock(roots[target_ea])
    imported_setup, imported_call_owner = imported_root.instructions()
    assert int(imported_setup.d.s.off) == expected_unrelated_vd
    assert int(imported_call_owner.opcode) == int(ida_hexrays.m_mov)
    assert int(imported_call_owner.l.d.d.f.args[0].s.off) == expected_argument_vd
    imported_carrier_block = destination.get_mblock(int(imported_root.succset[0]))
    imported_carrier = imported_carrier_block.head
    assert imported_carrier is not None
    assert int(imported_carrier.ea) != carrier_ea
    assert int(imported_carrier.d.s.off) == expected_carrier_vd


def test_safe_verify_repairs_normalized_registered_import_boundary(
    monkeypatch,
) -> None:
    """A registered imported fake block must retain an in-range logical end."""
    _install_runtime_fakes(monkeypatch)
    function_ea = 0x40A560
    target_ea = 0x40B9A6
    source = _MBA(
        (
            _Block(
                0,
                target_ea,
                (_Instruction(ida_hexrays.m_mov, target_ea),),
            ),
        )
    )
    destination = _MBA(
        (
            _Block(
                0,
                function_ea,
                (_Instruction(ida_hexrays.m_nop, function_ea),),
            ),
        )
    )

    def verify_boundaries(_always: bool) -> None:
        for block in destination.blocks:
            if (int(block.flags) & int(ida_hexrays.MBL_FAKE)) == 0:
                continue
            mapped_end = destination.map_fict_ea(int(block.end))
            if mapped_end - 1 != function_ea:
                raise RuntimeError("INTERR: 50870")

    original_mark_chains_dirty = destination.mark_chains_dirty

    def normalize_fake_boundaries() -> None:
        original_mark_chains_dirty()
        for block in destination.blocks:
            if (int(block.flags) & int(ida_hexrays.MBL_FAKE)) != 0:
                block.end = function_ea

    destination.verify = verify_boundaries
    destination.mark_chains_dirty = normalize_fake_boundaries
    assert detached_handler_island.capture_detached_snippet_template(
        function_ea,
        target_ea,
        source,
        ((target_ea, target_ea + 1),),
    )
    roots = detached_handler_island.materialize_detached_snippet_templates(
        destination,
        function_ea,
        (target_ea,),
    )
    imported_block = destination.get_mblock(roots[target_ea])
    imported_block.end = function_ea
    detached_handler_island.clear_imported_detached_snippet_roots()

    cfg_verify.safe_verify(destination, "registered imported fake block")

    assert destination.map_fict_ea(int(imported_block.end)) == function_ea + 1


def test_import_abstains_atomically_without_exact_analyzed_call(
    monkeypatch,
) -> None:
    created = _install_runtime_fakes(monkeypatch)
    function_ea = 0x40A560
    target_ea = 0x40B9A6
    call_ea = 0x40BA56
    raw_source = _MBA(
        (
            _Block(
                0,
                target_ea,
                (_Instruction(ida_hexrays.m_call, call_ea),),
            ),
        ),
        maturity=ida_hexrays.MMAT_PREOPTIMIZED,
    )
    destination = _MBA(
        (
            _Block(
                0,
                function_ea,
                (_Instruction(ida_hexrays.m_nop, function_ea),),
            ),
        ),
        maturity=ida_hexrays.MMAT_PREOPTIMIZED,
    )
    assert detached_handler_island.capture_detached_snippet_template(
        function_ea,
        target_ea,
        raw_source,
        ((target_ea, call_ea + 1),),
    )
    original_qty = destination.qty

    roots = detached_handler_island.materialize_detached_snippet_templates(
        destination,
        function_ea,
        (target_ea,),
    )

    assert roots == {}
    assert destination.qty == original_qty
    assert created == []


def test_imported_callinfo_defers_to_unique_live_native_authority(
    monkeypatch,
) -> None:
    """A full-function callinfo outranks an isolated detached-call analysis."""
    _install_runtime_fakes(monkeypatch)
    function_ea = 0x401000
    target_ea = 0x402000
    call_ea = 0x402020
    callee_ea = 0x405000
    wrong_argument_vd = 0x60
    correct_argument_vd = 0x24

    raw_call = _Instruction(
        ida_hexrays.m_call,
        call_ea,
        left=_Operand(ida_hexrays.mop_v, target_ea=callee_ea),
    )
    raw_source = _MBA(
        (_Block(0, target_ea, (raw_call,)),),
        maturity=ida_hexrays.MMAT_PREOPTIMIZED,
    )
    isolated_call = _Instruction(
        ida_hexrays.m_call,
        call_ea,
        left=_Operand(ida_hexrays.mop_v, target_ea=callee_ea),
        dest=_Operand(
            ida_hexrays.mop_f,
            arguments=(
                _Operand(
                    ida_hexrays.mop_S,
                    stack_offset=wrong_argument_vd,
                ),
            ),
        ),
    )
    isolated_source = _MBA(
        (_Block(0, target_ea, (isolated_call,)),),
        maturity=ida_hexrays.MMAT_CALLS,
    )
    live_call = _Instruction(
        ida_hexrays.m_call,
        call_ea,
        left=_Operand(ida_hexrays.mop_v, target_ea=callee_ea),
        dest=_Operand(
            ida_hexrays.mop_f,
            arguments=(
                _Operand(
                    ida_hexrays.mop_S,
                    stack_offset=correct_argument_vd,
                ),
            ),
        ),
    )
    destination = _MBA(
        (_Block(0, function_ea, (live_call,)),),
        maturity=ida_hexrays.MMAT_CALLS,
    )
    ranges = ((target_ea, call_ea + 1),)

    assert detached_handler_island.capture_detached_snippet_template(
        function_ea,
        target_ea,
        raw_source,
        ranges,
    )
    assert detached_handler_island.capture_detached_replacement_snippet_template(
        function_ea,
        target_ea,
        isolated_source,
        ranges,
    )
    roots = detached_handler_island.materialize_detached_snippet_templates(
        destination,
        function_ea,
        (target_ea,),
        expected_template_maturity=ida_hexrays.MMAT_PREOPTIMIZED,
    )
    imported_call = destination.get_mblock(roots[target_ea]).head
    assert imported_call is not None
    assert int(imported_call.d.f.args[0].s.off) == wrong_argument_vd

    changed = detached_handler_island.reconcile_imported_callinfo_with_live_native_calls(
        destination
    )

    assert changed == 1
    assert int(imported_call.d.f.args[0].s.off) == correct_argument_vd


def test_raw_template_reports_need_for_analyzed_call_authority(
    monkeypatch,
) -> None:
    _install_runtime_fakes(monkeypatch)
    function_ea = 0x40A560
    target_ea = 0x40C1A0
    call_ea = 0x40C1BB
    source = _MBA(
        (
            _Block(
                0,
                target_ea,
                (_Instruction(ida_hexrays.m_call, call_ea),),
            ),
        ),
        maturity=ida_hexrays.MMAT_PREOPTIMIZED,
    )
    assert detached_handler_island.capture_detached_snippet_template(
        function_ea,
        target_ea,
        source,
        ((target_ea, call_ea + 1),),
    )

    assert detached_handler_island.detached_snippet_requires_analyzed_calls(
        function_ea,
        target_ea,
    ) is True


def test_abstains_atomically_when_external_exit_is_ambiguous(monkeypatch) -> None:
    created = _install_runtime_fakes(monkeypatch)
    function_ea = 0x40A560
    target_ea = 0x40C4F6
    external_ea = 0x40B668
    source = _MBA(
        (
            _Block(
                0,
                target_ea,
                (
                    _Instruction(
                        ida_hexrays.m_goto,
                        target_ea,
                        dest=_Operand(ida_hexrays.mop_b, block_ref=1),
                    ),
                ),
                (1,),
            ),
            _Block(
                1,
                external_ea,
                (_Instruction(ida_hexrays.m_nop, external_ea),),
            ),
        )
    )
    destination = _MBA(
        (
            _Block(
                0,
                function_ea,
                (_Instruction(ida_hexrays.m_nop, function_ea),),
            ),
            _Block(
                1,
                external_ea,
                (_Instruction(ida_hexrays.m_nop, external_ea),),
            ),
            _Block(
                2,
                external_ea,
                (_Instruction(ida_hexrays.m_nop, external_ea),),
            ),
        )
    )

    assert detached_handler_island.capture_detached_snippet_template(
        function_ea,
        target_ea,
        source,
        ((target_ea, target_ea + 0x10),),
    )
    original_qty = destination.qty
    roots = detached_handler_island.materialize_detached_snippet_templates(
        destination,
        function_ea,
        (target_ea,),
    )

    assert roots == {}
    assert created == []
    assert destination.qty == original_qty
    assert destination.chains_dirty == 0
    assert destination.verify_calls == 0


def test_imports_locopt_template_into_preoptimized_destination_when_requested(
    monkeypatch,
) -> None:
    created = _install_runtime_fakes(monkeypatch)
    function_ea = 0x40A560
    target_ea = 0x40BF1B
    source = _MBA(
        (
            _Block(
                0,
                target_ea,
                (_Instruction(ida_hexrays.m_nop, target_ea),),
            ),
        ),
        maturity=ida_hexrays.MMAT_LOCOPT,
    )
    destination = _MBA(
        (
            _Block(
                0,
                function_ea,
                (_Instruction(ida_hexrays.m_nop, function_ea),),
            ),
        ),
        maturity=ida_hexrays.MMAT_PREOPTIMIZED,
    )

    assert detached_handler_island.capture_detached_snippet_template(
        function_ea,
        target_ea,
        source,
        ((target_ea, target_ea + 0x10),),
    )
    original_qty = destination.qty
    roots = detached_handler_island.materialize_detached_snippet_templates(
        destination,
        function_ea,
        (target_ea,),
    )

    assert roots == {}
    assert created == []
    assert destination.qty == original_qty
    assert destination.verify_calls == 0

    roots = detached_handler_island.materialize_detached_snippet_templates(
        destination,
        function_ea,
        (target_ea,),
        expected_template_maturity=ida_hexrays.MMAT_LOCOPT,
    )

    assert target_ea in roots
    assert destination.qty == original_qty + 1
    assert destination.verify_calls == 1


def test_import_materializes_nonadjacent_external_fallthrough_as_goto(
    monkeypatch,
) -> None:
    """Imported fallthrough cannot retain source ``serial+1`` semantics."""
    _install_runtime_fakes(monkeypatch)
    function_ea = 0x40A560
    target_ea = 0x40B236
    external_ea = 0x40A607
    source = _MBA(
        (
            _Block(
                0,
                target_ea,
                (_Instruction(ida_hexrays.m_mov, target_ea),),
                (1,),
            ),
            _Block(
                1,
                external_ea,
                (_Instruction(ida_hexrays.m_nop, external_ea),),
            ),
        )
    )
    source.get_mblock(0).type = int(ida_hexrays.BLT_1WAY)
    destination = _MBA(
        (
            _Block(
                0,
                function_ea,
                (_Instruction(ida_hexrays.m_nop, function_ea),),
            ),
            _Block(
                1,
                external_ea,
                (_Instruction(ida_hexrays.m_nop, external_ea),),
            ),
        )
    )

    assert detached_handler_island.capture_detached_snippet_template(
        function_ea,
        target_ea,
        source,
        ((target_ea, target_ea + 1),),
    )
    roots = detached_handler_island.materialize_detached_snippet_templates(
        destination,
        function_ea,
        (target_ea,),
    )

    imported = destination.get_mblock(roots[target_ea])
    assert int(imported.tail.opcode) == int(ida_hexrays.m_goto)
    assert int(imported.tail.l.t) == int(ida_hexrays.mop_b)
    assert int(imported.tail.l.b) == 1
    assert tuple(imported.succset) == (1,)
    assert (int(imported.flags) & int(ida_hexrays.MBL_GOTO)) != 0


def test_allocates_distinct_in_range_eas_for_converging_imported_defs(
    monkeypatch,
) -> None:
    _install_runtime_fakes(monkeypatch)
    function_ea = 0x40A560
    first_target_ea = 0x40AF00
    second_target_ea = 0x40B9A6
    shared_exit_ea = 0x40C659

    for target_ea in (first_target_ea, second_target_ea):
        source = _MBA(
            (
                _Block(
                    0,
                    target_ea,
                    (_Instruction(ida_hexrays.m_mov, target_ea),),
                    (1,),
                ),
                _Block(
                    1,
                    shared_exit_ea,
                    (_Instruction(ida_hexrays.m_nop, shared_exit_ea),),
                ),
            )
        )
        assert detached_handler_island.capture_detached_snippet_template(
            function_ea,
            target_ea,
            source,
            ((target_ea, target_ea + 0x10),),
        )

    destination = _MBA(
        (
            _Block(
                0,
                function_ea,
                (_Instruction(ida_hexrays.m_nop, function_ea),),
            ),
            _Block(
                1,
                shared_exit_ea,
                (_Instruction(ida_hexrays.m_nop, shared_exit_ea),),
            ),
        )
    )

    roots = detached_handler_island.materialize_detached_snippet_templates(
        destination,
        function_ea,
        (first_target_ea, second_target_ea),
    )

    imported_eas = {
        int(destination.get_mblock(root_serial).head.ea)
        for root_serial in roots.values()
    }
    assert len(imported_eas) == 2
    assert imported_eas.isdisjoint({first_target_ea, second_target_ea, function_ea})
    assert {
        destination.map_fict_ea(imported_ea)
        for imported_ea in imported_eas
    } == {function_ea + 1}


def test_relocates_imported_root_after_block_renumbering(monkeypatch) -> None:
    _install_runtime_fakes(monkeypatch)
    function_ea = 0x40A560
    target_ea = 0x40B9A6
    filler_ea = 0x40A5F0
    source = _MBA(
        (
            _Block(
                0,
                target_ea,
                (_Instruction(ida_hexrays.m_mov, target_ea),),
            ),
        )
    )
    destination = _MBA(
        (
            _Block(
                0,
                function_ea,
                (_Instruction(ida_hexrays.m_nop, function_ea),),
            ),
            _Block(
                1,
                filler_ea,
                (_Instruction(ida_hexrays.m_nop, filler_ea),),
            ),
        )
    )
    assert detached_handler_island.capture_detached_snippet_template(
        function_ea,
        target_ea,
        source,
        ((target_ea, target_ea + 0x10),),
    )
    roots = detached_handler_island.materialize_detached_snippet_templates(
        destination,
        function_ea,
        (target_ea,),
    )
    original_root = destination.get_mblock(roots[target_ea])

    destination.blocks[1], destination.blocks[2] = (
        destination.blocks[2],
        destination.blocks[1],
    )
    for serial, block in enumerate(destination.blocks):
        block.serial = serial

    relocated = detached_handler_island.find_unique_live_block_by_ea(
        destination,
        target_ea,
    )
    assert relocated is original_root
    assert int(relocated.serial) == 1


def test_relocates_imported_root_after_original_head_is_eliminated(
    monkeypatch,
) -> None:
    _install_runtime_fakes(monkeypatch)
    function_ea = 0x40A560
    target_ea = 0x40AF00
    source = _MBA(
        (
            _Block(
                0,
                target_ea,
                (
                    _Instruction(ida_hexrays.m_mov, target_ea),
                    _Instruction(ida_hexrays.m_add, target_ea + 4),
                ),
            ),
        )
    )
    destination = _MBA(
        (
            _Block(
                0,
                function_ea,
                (_Instruction(ida_hexrays.m_nop, function_ea),),
            ),
        )
    )
    assert detached_handler_island.capture_detached_snippet_template(
        function_ea,
        target_ea,
        source,
        ((target_ea, target_ea + 0x10),),
    )
    roots = detached_handler_island.materialize_detached_snippet_templates(
        destination,
        function_ea,
        (target_ea,),
    )
    root = destination.get_mblock(roots[target_ea])
    original_head = root.head
    surviving_instruction = original_head.next
    root.remove_from_block(original_head)

    relocated = detached_handler_island.find_unique_live_block_by_ea(
        destination,
        target_ea,
    )
    assert relocated is root
    assert relocated.head is surviving_instruction


def test_relocates_imported_root_from_surviving_owned_instruction_origin(
    monkeypatch,
) -> None:
    _install_runtime_fakes(monkeypatch)
    function_ea = 0x40A560
    target_ea = 0x40C1A0
    surviving_ea = 0x40C1AA
    source = _MBA(
        (
            _Block(
                0,
                target_ea,
                (_Instruction(ida_hexrays.m_mov, target_ea),),
                (1,),
            ),
            _Block(
                1,
                surviving_ea,
                (_Instruction(ida_hexrays.m_add, surviving_ea),),
            ),
        )
    )
    destination = _MBA(
        (
            _Block(
                0,
                function_ea,
                (_Instruction(ida_hexrays.m_nop, function_ea),),
            ),
        )
    )
    assert detached_handler_island.capture_detached_snippet_template(
        function_ea,
        target_ea,
        source,
        ((target_ea, target_ea + 0x20),),
    )
    roots = detached_handler_island.materialize_detached_snippet_templates(
        destination,
        function_ea,
        (target_ea,),
    )
    imported_root = destination.get_mblock(roots[target_ea])
    surviving_block = destination.get_mblock(roots[target_ea] + 1)
    for instruction in imported_root.instructions():
        imported_root.remove_from_block(instruction)

    relocated = detached_handler_island.find_unique_live_block_by_ea(
        destination,
        target_ea,
    )

    assert relocated is surviving_block
    assert int(relocated.head.ea) != surviving_ea


def test_preserves_native_origin_for_imported_terminal_indirect_jump(
    monkeypatch,
) -> None:
    _install_runtime_fakes(monkeypatch)
    function_ea = 0x40A560
    target_ea = 0x40B9A6
    native_exit_ea = 0x40C703
    source = _MBA(
        (
            _Block(
                0,
                target_ea,
                (_Instruction(ida_hexrays.m_ijmp, native_exit_ea),),
            ),
        )
    )
    destination = _MBA(
        (
            _Block(
                0,
                function_ea,
                (_Instruction(ida_hexrays.m_nop, function_ea),),
            ),
        )
    )
    assert detached_handler_island.capture_detached_snippet_template(
        function_ea,
        target_ea,
        source,
        ((target_ea, native_exit_ea + 1),),
    )
    roots = detached_handler_island.materialize_detached_snippet_templates(
        destination,
        function_ea,
        (target_ea,),
    )
    imported = destination.get_mblock(roots[target_ea]).tail
    assert imported is not None
    assert int(imported.ea) != native_exit_ea
    assert detached_handler_island.imported_detached_snippet_terminal_origins(
        destination
    ) == ((int(imported.ea), native_exit_ea),)
