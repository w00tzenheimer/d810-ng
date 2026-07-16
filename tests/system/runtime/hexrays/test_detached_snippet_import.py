"""Runtime contracts for importing detached microcode snippets."""

from __future__ import annotations

import copy
from enum import Enum
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
            SimpleNamespace(off=int(stack_offset)) if stack_offset is not None else None
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
        if int(self.t) == int(ida_hexrays.mop_S):
            return int(self.s.off) == int(other.s.off)
        if int(self.t) == int(ida_hexrays.mop_a):
            return self.a.equal_mops(other.a, _flags)
        if int(self.t) == int(ida_hexrays.mop_d):
            return (
                int(self.d.opcode) == int(other.d.opcode)
                and self.d.l.equal_mops(other.d.l, _flags)
                and self.d.r.equal_mops(other.d.r, _flags)
                and self.d.d.equal_mops(other.d.d, _flags)
            )
        if int(self.t) == int(ida_hexrays.mop_f):
            return len(self.f.args) == len(other.f.args) and all(
                left.equal_mops(right, _flags)
                for left, right in zip(self.f.args, other.f.args)
            )
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


class _RangeList(list[object]):
    def push_back(self, item: object) -> None:
        self.append(item)

    def size(self) -> int:
        return len(self)


class _MBARanges:
    def __init__(self) -> None:
        self.ranges = _RangeList()

    def range_contains(self, ea: int) -> bool:
        return any(
            int(item.start_ea) <= int(ea) < int(item.end_ea) for item in self.ranges
        )


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
            current for current in self.instructions() if current is not instruction
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

    def succ(self, index: int) -> int:
        return int(self.succset[index])

    def npred(self) -> int:
        return len(self.predset)

    def pred(self, index: int) -> int:
        return int(self.predset[index])

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
        self.flags2 = 0
        self.mbr = _MBARanges()
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

    def get_mba_flags2(self) -> int:
        return int(self.flags2)

    def set_mba_flags2(self, flags: int) -> None:
        self.flags2 |= int(flags)


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
        detached_handler_island.ida_hexrays,
        "mop_t",
        _Operand,
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
        "_DETACHED_CALLINFO_TEMPLATES",
        {},
        raising=False,
    )
    monkeypatch.setattr(
        detached_handler_island,
        "_DETACHED_CALLINFO_CONFLICTS",
        set(),
        raising=False,
    )
    monkeypatch.setattr(
        detached_handler_island,
        "_DETACHED_SNIPPET_GENERATIONS",
        {},
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
    monkeypatch.setattr(
        detached_handler_island,
        "_LAST_IMPORTED_INSTRUCTION_ORIGINS",
        {},
        raising=False,
    )
    monkeypatch.setattr(
        detached_handler_island,
        "_IMPORTED_DIRECT_BOUNDARY_EVIDENCE",
        {},
        raising=False,
    )
    monkeypatch.setattr(
        detached_handler_island,
        "_IMPORTED_CONDITIONAL_BOUNDARY_EVIDENCE",
        {},
        raising=False,
    )
    monkeypatch.setattr(
        detached_handler_island,
        "_TERMINAL_RETURN_CARRIER_TEMPLATES",
        {},
        raising=False,
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
    assert int(imported.r.a.s.off) == source_offsets[1] + stable_destination_delta
    assert int(imported.r.a.size) == 2
    assert int(imported.d.d.l.s.off) == source_offsets[2] + stable_destination_delta
    imported_arg = imported.d.d.r.f.args[0]
    assert int(imported_arg.s.off) == source_offsets[3] + stable_destination_delta
    assert int(imported_arg.size) == 8


def test_transparent_empty_entry_uses_first_anchored_successor_as_root(
    monkeypatch,
) -> None:
    _install_runtime_fakes(monkeypatch)
    function_ea = 0x40A560
    target_ea = 0x40A7AE
    body_ea = 0x40A7BD
    source = _MBA(
        (
            _Block(0, target_ea, (), (1,)),
            _Block(
                1,
                body_ea,
                (_Instruction(ida_hexrays.m_nop, body_ea),),
            ),
        ),
    )
    destination = _MBA(
        (
            _Block(
                0,
                function_ea,
                (_Instruction(ida_hexrays.m_nop, function_ea),),
            ),
        ),
    )

    assert detached_handler_island.capture_detached_snippet_template(
        function_ea,
        target_ea,
        source,
        ((target_ea, body_ea + 1),),
        owned_block_entry_eas=(target_ea, body_ea),
    )
    template = detached_handler_island._DETACHED_SNIPPET_TEMPLATES[
        (function_ea, target_ea)
    ]
    assert template.root_source_serial == 1

    roots = detached_handler_island.materialize_detached_snippet_templates(
        destination,
        function_ea,
        (target_ea,),
    )

    imported = destination.get_mblock(roots[target_ea])
    assert imported.head is not None
    root_block = next(
        block
        for block in template.blocks
        if int(block.source_serial) == int(template.root_source_serial)
    )
    assert root_block.native_entry_ea == body_ea


def test_range_capture_does_not_infer_empty_interior_block_ownership(
    monkeypatch,
) -> None:
    """Range-only LOCOPT capture leaves transparent tails in the live MBA."""
    _install_runtime_fakes(monkeypatch)
    function_ea = 0x40A560
    target_ea = 0x40B236
    empty_ea = 0x40B262
    dispatcher_ea = 0x40A607
    source = _MBA(
        (
            _Block(
                0,
                target_ea,
                (_Instruction(ida_hexrays.m_nop, target_ea),),
                (1,),
            ),
            _Block(1, empty_ea, (), (2,)),
            _Block(
                2,
                dispatcher_ea,
                (_Instruction(ida_hexrays.m_nop, dispatcher_ea),),
            ),
        ),
        maturity=ida_hexrays.MMAT_LOCOPT,
    )
    source.get_mblock(0).type = int(ida_hexrays.BLT_1WAY)
    source.get_mblock(1).type = int(ida_hexrays.BLT_1WAY)

    assert detached_handler_island.capture_detached_snippet_template(
        function_ea,
        target_ea,
        source,
        ((target_ea, empty_ea + 1),),
    )
    template = detached_handler_island._DETACHED_SNIPPET_TEMPLATES[
        (function_ea, target_ea)
    ]

    assert tuple(block.native_entry_ea for block in template.blocks) == (target_ea,)


def test_duplicate_empty_entry_alias_resolves_to_anchored_root(
    monkeypatch,
) -> None:
    _install_runtime_fakes(monkeypatch)
    function_ea = 0x40A560
    target_ea = 0x40A7AE
    source = _MBA(
        (
            _Block(0, target_ea, (), (1,)),
            _Block(
                1,
                target_ea,
                (_Instruction(ida_hexrays.m_nop, target_ea),),
            ),
        ),
    )

    assert detached_handler_island.capture_detached_snippet_template(
        function_ea,
        target_ea,
        source,
        ((target_ea, target_ea + 1),),
        owned_block_entry_eas=(target_ea,),
    )
    template = detached_handler_island._DETACHED_SNIPPET_TEMPLATES[
        (function_ea, target_ea)
    ]

    assert template.root_source_serial == 1
    assert tuple(block.source_serial for block in template.blocks) == (1,)


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
            SimpleNamespace(frsize=0x48C, frregs=4) if int(ea) == function_ea else None
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


def test_capture_prefers_unique_native_stack_identity_over_fragment_basis(
    monkeypatch,
) -> None:
    _install_runtime_fakes(monkeypatch)
    function_ea = 0x40A560
    target_ea = 0x40AF23
    source_vd = 216
    monkeypatch.setattr(
        detached_handler_island.ida_funcs,
        "get_func",
        lambda ea: (
            SimpleNamespace(frsize=0x48C, frregs=4) if int(ea) == function_ea else None
        ),
    )
    monkeypatch.setattr(
        detached_handler_island,
        "_native_instruction_stack_frame_offsets",
        lambda owner_ea, instruction_ea: (
            (204,)
            if int(owner_ea) == function_ea and int(instruction_ea) == target_ea
            else ()
        ),
        raising=False,
    )
    source = _MBA(
        (
            _Block(
                0,
                target_ea,
                (
                    _Instruction(
                        ida_hexrays.m_push,
                        target_ea,
                        left=_Operand(
                            ida_hexrays.mop_S,
                            stack_offset=source_vd,
                        ),
                    ),
                ),
            ),
        ),
        vd_to_ida_delta=-1172,
        stacksize=1172,
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
    assert template.stack_vd_to_ida == ((source_vd, -956),)
    assert template.stable_stack_vd_to_ida == ((source_vd, 204),)


def test_capture_prefers_pre_generation_native_stack_identity(
    monkeypatch,
) -> None:
    _install_runtime_fakes(monkeypatch)
    function_ea = 0x40D200
    target_ea = 0x40DABB
    source_vd = 176
    monkeypatch.setattr(
        detached_handler_island,
        "_native_instruction_stack_frame_offsets",
        lambda _owner_ea, _instruction_ea: (240,),
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
                        left=_Operand(
                            ida_hexrays.mop_S,
                            stack_offset=source_vd,
                        ),
                    ),
                ),
            ),
        ),
        vd_to_ida_delta=-88,
    )

    assert detached_handler_island.capture_detached_snippet_template(
        function_ea,
        target_ea,
        source,
        ((target_ea, target_ea + 1),),
        native_stack_frame_offsets_by_ea={target_ea: (88,)},
    )
    template = detached_handler_island._DETACHED_SNIPPET_TEMPLATES[
        (function_ea, target_ea)
    ]
    assert template.stable_stack_vd_to_ida == ((source_vd, 88),)
    assert template.instruction_stack_vd_to_ida == (
        (target_ea, source_vd, 88),
    )


@pytest.mark.parametrize("annotated", (False, True))
def test_native_stack_identity_prefers_esp_displacement_and_spd(
    monkeypatch,
    annotated: bool,
) -> None:
    function_ea = 0x40D200
    instruction_ea = 0x40DABB
    instruction = SimpleNamespace(
        ops=(
            SimpleNamespace(
                type=int(detached_handler_island.ida_ua.o_displ),
                reg=4,
                addr=0x58,
            ),
        )
    )
    monkeypatch.setattr(
        detached_handler_island.ida_ua,
        "insn_t",
        lambda: instruction,
    )
    monkeypatch.setattr(
        detached_handler_island.ida_ua,
        "decode_insn",
        lambda decoded, ea: 2 if decoded is instruction and int(ea) == instruction_ea else 0,
    )
    monkeypatch.setattr(detached_handler_island.ida_bytes, "get_flags", lambda _ea: 0)
    monkeypatch.setattr(
        detached_handler_island.ida_bytes,
        "is_stkvar",
        lambda _flags, _index: annotated,
    )
    monkeypatch.setattr(
        detached_handler_island.ida_frame,
        "calc_stkvar_struc_offset",
        lambda _function, _instruction, _index: 0xF0,
    )
    monkeypatch.setattr(
        detached_handler_island.ida_funcs,
        "get_func",
        lambda ea: (
            SimpleNamespace(frsize=0x88, frregs=0)
            if int(ea) == function_ea
            else None
        ),
    )
    monkeypatch.setattr(
        detached_handler_island.ida_frame,
        "get_spd",
        lambda _function, ea: -0x88 if int(ea) == instruction_ea else 0,
    )
    monkeypatch.setattr(
        detached_handler_island.ida_idp,
        "get_reg_name",
        lambda reg, width: "esp" if int(reg) == 4 and int(width) == 4 else "",
    )
    monkeypatch.setattr(
        detached_handler_island.ida_ida,
        "inf_is_64bit",
        lambda: False,
    )

    assert detached_handler_island._native_instruction_stack_frame_offsets(
        function_ea,
        instruction_ea,
    ) == (0x58,)


def test_same_fragment_vd_uses_instruction_specific_native_stack_identity(
    monkeypatch,
) -> None:
    _install_runtime_fakes(monkeypatch)
    function_ea = 0x40A560
    target_ea = 0x40AF23
    restored_ea = 0x40AF6A
    source_vd = 216
    monkeypatch.setattr(
        detached_handler_island.ida_funcs,
        "get_func",
        lambda ea: (
            SimpleNamespace(frsize=0x48C, frregs=4) if int(ea) == function_ea else None
        ),
    )
    native_identities = {
        target_ea: (204,),
        restored_ea: (216,),
    }
    monkeypatch.setattr(
        detached_handler_island,
        "_native_instruction_stack_frame_offsets",
        lambda owner_ea, instruction_ea: (
            native_identities.get(int(instruction_ea), ())
            if int(owner_ea) == function_ea
            else ()
        ),
        raising=False,
    )
    source = _MBA(
        (
            _Block(
                0,
                target_ea,
                (
                    _Instruction(
                        ida_hexrays.m_push,
                        target_ea,
                        left=_Operand(
                            ida_hexrays.mop_S,
                            stack_offset=source_vd,
                        ),
                    ),
                    _Instruction(
                        ida_hexrays.m_push,
                        restored_ea,
                        left=_Operand(
                            ida_hexrays.mop_S,
                            stack_offset=source_vd,
                        ),
                    ),
                ),
            ),
        ),
        vd_to_ida_delta=-1172,
        stacksize=1172,
    )

    assert detached_handler_island.capture_detached_snippet_template(
        function_ea,
        target_ea,
        source,
        ((target_ea, restored_ea + 1),),
    )
    template = detached_handler_island._DETACHED_SNIPPET_TEMPLATES[
        (function_ea, target_ea)
    ]
    assert template.stack_vd_to_ida == ((source_vd, -956),)
    assert template.stable_stack_vd_to_ida == ()
    assert template.instruction_stack_vd_to_ida == (
        (target_ea, source_vd, 204),
        (restored_ea, source_vd, 216),
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
    roots = detached_handler_island.materialize_detached_snippet_templates(
        destination,
        function_ea,
        (target_ea,),
    )
    imported = destination.get_mblock(roots[target_ea]).instructions()
    assert tuple(int(instruction.l.s.off) for instruction in imported) == (
        204 + 0x200,
        216 + 0x200,
    )


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

    assert (
        detached_handler_island.redirect_live_target_predecessors(
            mba,
            {2: 3},
        )
        == 1
    )
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

    assert (
        detached_handler_island.redirect_live_target_predecessors(
            mba,
            {2: 4},
        )
        == 0
    )
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
    assert (
        dict(
            detached_handler_island.last_imported_detached_snippet_instruction_origins(
                function_ea
            )
        )
        == origins
    )


def test_call_companion_validation_accepts_exact_native_call_pair() -> None:
    call_ea = 0x40BA56
    callee_ea = 0x40F830
    preopt = _MBA(
        (
            _Block(
                0,
                0x40B9A6,
                (
                    _Instruction(
                        ida_hexrays.m_call,
                        call_ea,
                        left=_Operand(
                            ida_hexrays.mop_v,
                            target_ea=callee_ea,
                        ),
                    ),
                ),
            ),
        ),
        maturity=ida_hexrays.MMAT_PREOPTIMIZED,
    )
    calls = _MBA(
        (
            _Block(
                0,
                0x40B9A6,
                (
                    _Instruction(
                        ida_hexrays.m_call,
                        call_ea,
                        left=_Operand(
                            ida_hexrays.mop_v,
                            target_ea=callee_ea,
                        ),
                        dest=_Operand(ida_hexrays.mop_f),
                    ),
                ),
            ),
        ),
        maturity=ida_hexrays.MMAT_CALLS,
    )

    result = detached_handler_island.validate_detached_call_companion(
        preopt,
        calls,
    )

    assert result.accepted is True
    assert result.call_eas == (call_ea,)
    assert result.reason is None
    assert result.mismatch_ea is None


@pytest.mark.parametrize(
    ("calls_instruction", "reason"),
    (
        (None, "call_ea_set_mismatch"),
        (
            _Instruction(
                ida_hexrays.m_icall,
                0x40BA56,
                left=_Operand(ida_hexrays.mop_r, register=8),
                dest=_Operand(ida_hexrays.mop_f),
            ),
            "call_opcode_mismatch",
        ),
        (
            _Instruction(
                ida_hexrays.m_call,
                0x40BA56,
                left=_Operand(ida_hexrays.mop_v, target_ea=0x40F900),
                dest=_Operand(ida_hexrays.mop_f),
            ),
            "direct_callee_mismatch",
        ),
        (
            _Instruction(
                ida_hexrays.m_call,
                0x40BA56,
                left=_Operand(ida_hexrays.mop_v, target_ea=0x40F830),
            ),
            "analyzed_arglist_missing",
        ),
    ),
)
def test_call_companion_validation_abstains_on_mismatch(
    calls_instruction: _Instruction | None,
    reason: str,
) -> None:
    call_ea = 0x40BA56
    preopt = _MBA(
        (
            _Block(
                0,
                0x40B9A6,
                (
                    _Instruction(
                        ida_hexrays.m_call,
                        call_ea,
                        left=_Operand(
                            ida_hexrays.mop_v,
                            target_ea=0x40F830,
                        ),
                    ),
                ),
            ),
        ),
        maturity=ida_hexrays.MMAT_PREOPTIMIZED,
    )
    calls = _MBA(
        (
            _Block(
                0,
                0x40B9A6,
                () if calls_instruction is None else (calls_instruction,),
            ),
        ),
        maturity=ida_hexrays.MMAT_CALLS,
    )

    result = detached_handler_island.validate_detached_call_companion(
        preopt,
        calls,
    )

    assert result.accepted is False
    assert result.reason == reason
    assert result.mismatch_ea == call_ea


def test_call_companion_validation_rejects_duplicate_native_call_ea() -> None:
    call_ea = 0x40BA56
    callee_ea = 0x40F830

    def raw_call() -> _Instruction:
        return _Instruction(
            ida_hexrays.m_call,
            call_ea,
            left=_Operand(ida_hexrays.mop_v, target_ea=callee_ea),
        )

    preopt = _MBA(
        (_Block(0, 0x40B9A6, (raw_call(), raw_call())),),
        maturity=ida_hexrays.MMAT_PREOPTIMIZED,
    )
    calls = _MBA(
        (
            _Block(
                0,
                0x40B9A6,
                (
                    _Instruction(
                        ida_hexrays.m_call,
                        call_ea,
                        left=_Operand(
                            ida_hexrays.mop_v,
                            target_ea=callee_ea,
                        ),
                        dest=_Operand(ida_hexrays.mop_f),
                    ),
                ),
            ),
        ),
        maturity=ida_hexrays.MMAT_CALLS,
    )

    result = detached_handler_island.validate_detached_call_companion(
        preopt,
        calls,
    )

    assert result.accepted is False
    assert result.reason == "preopt_duplicate_call_ea"
    assert result.mismatch_ea == call_ea


def test_companion_capture_publishes_primary_and_calls_atomically(
    monkeypatch,
) -> None:
    _install_runtime_fakes(monkeypatch)
    function_ea = 0x40A560
    target_ea = 0x40B9A6
    call_ea = 0x40BA56
    callee_ea = 0x40F830
    ranges = ((target_ea, call_ea + 1),)
    preopt = _MBA(
        (
            _Block(
                0,
                target_ea,
                (
                    _Instruction(
                        ida_hexrays.m_call,
                        call_ea,
                        left=_Operand(
                            ida_hexrays.mop_v,
                            target_ea=callee_ea,
                        ),
                    ),
                ),
            ),
        ),
        maturity=ida_hexrays.MMAT_PREOPTIMIZED,
    )
    calls = _MBA(
        (
            _Block(
                0,
                target_ea,
                (
                    _Instruction(
                        ida_hexrays.m_call,
                        call_ea,
                        left=_Operand(
                            ida_hexrays.mop_v,
                            target_ea=callee_ea,
                        ),
                        dest=_Operand(ida_hexrays.mop_f),
                    ),
                ),
            ),
        ),
        maturity=ida_hexrays.MMAT_CALLS,
    )

    result = detached_handler_island.capture_detached_snippet_companion_templates(
        function_ea,
        target_ea,
        preopt,
        calls,
        ranges,
    )

    assert result.captured is True
    assert result.replacement_required is True
    assert result.call_eas == (call_ea,)
    assert result.reason is None
    assert detached_handler_island.has_detached_snippet_template(
        function_ea,
        target_ea,
    )
    assert detached_handler_island.has_detached_replacement_snippet_template(
        function_ea,
        target_ea,
    )
    assert (
        detached_handler_island.detached_snippet_template_generation(function_ea) == 1
    )


def test_companion_capture_mismatch_leaves_both_caches_unchanged(
    monkeypatch,
) -> None:
    _install_runtime_fakes(monkeypatch)
    function_ea = 0x40A560
    target_ea = 0x40B9A6
    call_ea = 0x40BA56
    preopt = _MBA(
        (
            _Block(
                0,
                target_ea,
                (_Instruction(ida_hexrays.m_call, call_ea),),
            ),
        ),
        maturity=ida_hexrays.MMAT_PREOPTIMIZED,
    )
    calls = _MBA(
        (_Block(0, target_ea, ()),),
        maturity=ida_hexrays.MMAT_CALLS,
    )

    result = detached_handler_island.capture_detached_snippet_companion_templates(
        function_ea,
        target_ea,
        preopt,
        calls,
        ((target_ea, call_ea + 1),),
    )

    assert result.captured is False
    assert result.reason == "call_ea_set_mismatch"
    assert not detached_handler_island.has_detached_snippet_template(
        function_ea,
        target_ea,
    )
    assert not detached_handler_island.has_detached_replacement_snippet_template(
        function_ea,
        target_ea,
    )
    assert (
        detached_handler_island.detached_snippet_template_generation(function_ea) == 0
    )


def test_companion_capture_rolls_back_when_primary_capture_fails(
    monkeypatch,
) -> None:
    _install_runtime_fakes(monkeypatch)
    function_ea = 0x40A560
    target_ea = 0x40B9A6
    wrong_preopt_root = target_ea + 1
    call_ea = 0x40BA56
    callee_ea = 0x40F830
    raw_call = _Instruction(
        ida_hexrays.m_call,
        call_ea,
        left=_Operand(ida_hexrays.mop_v, target_ea=callee_ea),
    )
    preopt = _MBA(
        (_Block(0, wrong_preopt_root, (raw_call,)),),
        maturity=ida_hexrays.MMAT_PREOPTIMIZED,
    )
    calls = _MBA(
        (
            _Block(
                0,
                target_ea,
                (
                    _Instruction(
                        ida_hexrays.m_call,
                        call_ea,
                        left=_Operand(
                            ida_hexrays.mop_v,
                            target_ea=callee_ea,
                        ),
                        dest=_Operand(ida_hexrays.mop_f),
                    ),
                ),
            ),
        ),
        maturity=ida_hexrays.MMAT_CALLS,
    )

    result = detached_handler_island.capture_detached_snippet_companion_templates(
        function_ea,
        target_ea,
        preopt,
        calls,
        ((target_ea, call_ea + 1),),
    )

    assert result.captured is False
    assert result.reason == "primary_capture_failed"
    assert not detached_handler_island.has_detached_snippet_template(
        function_ea,
        target_ea,
    )
    assert not detached_handler_island.has_detached_replacement_snippet_template(
        function_ea,
        target_ea,
    )
    assert (
        detached_handler_island.detached_snippet_template_generation(function_ea) == 0
    )


def test_companion_capture_allows_no_call_primary_without_calls_mba(
    monkeypatch,
) -> None:
    _install_runtime_fakes(monkeypatch)
    function_ea = 0x40A560
    target_ea = 0x40B9A6
    preopt = _MBA(
        (
            _Block(
                0,
                target_ea,
                (_Instruction(ida_hexrays.m_nop, target_ea),),
            ),
        ),
        maturity=ida_hexrays.MMAT_PREOPTIMIZED,
    )

    result = detached_handler_island.capture_detached_snippet_companion_templates(
        function_ea,
        target_ea,
        preopt,
        None,
        ((target_ea, target_ea + 1),),
    )

    assert result.captured is True
    assert result.replacement_required is False
    assert result.call_eas == ()
    assert result.reason is None
    assert detached_handler_island.has_detached_snippet_template(
        function_ea,
        target_ea,
    )
    assert not detached_handler_island.has_detached_replacement_snippet_template(
        function_ea,
        target_ea,
    )


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
        int(origins[int(instruction.ea)]) for instruction in imported.instructions()
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
    carrier_vd = 0x148
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
            arguments=(_Operand(ida_hexrays.mop_S, stack_offset=argument_vd),),
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


def test_preopt_import_preserves_raw_call_for_destination_analysis(
    monkeypatch,
) -> None:
    """PREOPT injection may defer raw-call analysis to the destination MBA."""
    _install_runtime_fakes(monkeypatch)
    function_ea = 0x40A560
    target_ea = 0x40B9A6
    call_ea = 0x40BA56
    raw_push = _Instruction(ida_hexrays.m_push, call_ea - 1)
    raw_call = _Instruction(ida_hexrays.m_call, call_ea)
    raw_block = _Block(0, target_ea, (raw_push, raw_call))
    raw_block.flags = int(ida_hexrays.MBL_PUSH)
    raw_source = _MBA(
        (raw_block,),
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
        # hxe_preoptimized fires after the pass but before mba.maturity is
        # advanced from GENERATED to PREOPTIMIZED.
        maturity=ida_hexrays.MMAT_GENERATED,
    )
    assert detached_handler_island.capture_detached_snippet_template(
        function_ea,
        target_ea,
        raw_source,
        ((target_ea, call_ea + 1),),
    )

    roots = detached_handler_island.materialize_detached_snippet_templates(
        destination,
        function_ea,
        (target_ea,),
        expected_template_maturity=ida_hexrays.MMAT_PREOPTIMIZED,
        allow_raw_preopt_calls=True,
    )

    imported_block = destination.get_mblock(roots[target_ea])
    imported_call = imported_block.tail
    assert imported_call is not None
    assert int(imported_call.opcode) == int(ida_hexrays.m_call)
    assert int(imported_call.d.t) != int(ida_hexrays.mop_f)
    assert int(imported_block.flags) & int(ida_hexrays.MBL_PUSH)


def test_preopt_import_splits_multiple_raw_calls_into_closing_blocks(
    monkeypatch,
) -> None:
    """Every raw PREOPT call must close its own imported block."""
    _install_runtime_fakes(monkeypatch)
    function_ea = 0x40A560
    target_ea = 0x40B10C
    first_call_ea = 0x40B114
    second_call_ea = 0x40B11B
    suffix_ea = 0x40B121
    raw_block = _Block(
        0,
        target_ea,
        (
            _Instruction(ida_hexrays.m_push, first_call_ea - 1),
            _Instruction(ida_hexrays.m_call, first_call_ea),
            _Instruction(ida_hexrays.m_push, second_call_ea - 1),
            _Instruction(ida_hexrays.m_call, second_call_ea),
            _Instruction(ida_hexrays.m_mov, suffix_ea),
        ),
    )
    raw_block.flags = int(ida_hexrays.MBL_PUSH)
    raw_source = _MBA(
        (raw_block,),
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
        maturity=ida_hexrays.MMAT_GENERATED,
    )
    assert detached_handler_island.capture_detached_snippet_template(
        function_ea,
        target_ea,
        raw_source,
        ((target_ea, suffix_ea + 1),),
    )

    roots = detached_handler_island.materialize_detached_snippet_templates(
        destination,
        function_ea,
        (target_ea,),
        expected_template_maturity=ida_hexrays.MMAT_PREOPTIMIZED,
        allow_raw_preopt_calls=True,
    )

    first = destination.get_mblock(roots[target_ea])
    second = destination.get_mblock(int(first.succset[0]))
    suffix = destination.get_mblock(int(second.succset[0]))
    assert int(first.tail.opcode) == int(ida_hexrays.m_call)
    assert int(second.tail.opcode) == int(ida_hexrays.m_call)
    assert int(suffix.tail.opcode) == int(ida_hexrays.m_mov)
    assert all(
        int(instruction.opcode)
        not in {int(ida_hexrays.m_call), int(ida_hexrays.m_icall)}
        for block in (first, second, suffix)
        for instruction in block.instructions()[:-1]
    )


def test_locopt_capture_preserves_analyzed_call_block_shape(monkeypatch) -> None:
    """Raw-call normalization must not rewrite established LOCOPT templates."""
    _install_runtime_fakes(monkeypatch)
    function_ea = 0x40A560
    target_ea = 0x40B10C
    first_call_ea = 0x40B114
    second_call_ea = 0x40B11B
    suffix_ea = 0x40B121
    analyzed_source = _MBA(
        (
            _Block(
                0,
                target_ea,
                (
                    _Instruction(ida_hexrays.m_call, first_call_ea),
                    _Instruction(ida_hexrays.m_call, second_call_ea),
                    _Instruction(ida_hexrays.m_mov, suffix_ea),
                ),
            ),
        ),
        maturity=ida_hexrays.MMAT_LOCOPT,
    )

    assert detached_handler_island.capture_detached_snippet_template(
        function_ea,
        target_ea,
        analyzed_source,
        ((target_ea, suffix_ea + 1),),
    )

    template = detached_handler_island._DETACHED_SNIPPET_TEMPLATES[
        (function_ea, target_ea)
    ]
    assert len(template.blocks) == 1
    assert tuple(
        int(instruction.opcode) for instruction in template.blocks[0].instructions
    ) == (
        int(ida_hexrays.m_call),
        int(ida_hexrays.m_call),
        int(ida_hexrays.m_mov),
    )


def test_conditional_fallthrough_helper_is_raw_preopt_scoped(
    monkeypatch,
) -> None:
    """LOCOPT import must retain its established topology unchanged."""
    from d810.hexrays.mutation.deferred_modifier import DeferredGraphModifier

    _install_runtime_fakes(monkeypatch)
    function_ea = 0x40A560
    target_ea = 0x40AF00
    taken_ea = 0x40AF20
    fallthrough_ea = 0x40AF40
    source = _MBA(
        (
            _Block(
                0,
                target_ea,
                (
                    _Instruction(
                        ida_hexrays.m_jnz,
                        target_ea + 4,
                        dest=_Operand(ida_hexrays.mop_b, block_ref=1),
                    ),
                ),
                (1, 2),
            ),
            _Block(
                1,
                taken_ea,
                (_Instruction(ida_hexrays.m_nop, taken_ea),),
            ),
            _Block(
                2,
                fallthrough_ea,
                (_Instruction(ida_hexrays.m_nop, fallthrough_ea),),
            ),
        ),
        maturity=ida_hexrays.MMAT_LOCOPT,
    )
    source.get_mblock(0).type = int(ida_hexrays.BLT_2WAY)
    destination = _MBA(
        (
            _Block(
                0,
                function_ea,
                (_Instruction(ida_hexrays.m_nop, function_ea),),
            ),
        ),
        maturity=ida_hexrays.MMAT_LOCOPT,
    )

    def reject_preopt_helper(*_args, **_kwargs) -> int:
        raise AssertionError("PREOPT fallthrough helper used by LOCOPT import")

    monkeypatch.setattr(
        DeferredGraphModifier,
        "insert_nop_block_now",
        reject_preopt_helper,
    )
    assert detached_handler_island.capture_detached_snippet_template(
        function_ea,
        target_ea,
        source,
        ((target_ea, fallthrough_ea + 1),),
    )

    roots = detached_handler_island.materialize_detached_snippet_templates(
        destination,
        function_ea,
        (target_ea,),
    )

    assert target_ea in roots


def test_preopt_native_range_import_preserves_call_ea_and_marks_outline(
    monkeypatch,
) -> None:
    """Native-range PREOPT import retains the EAs needed by call analysis."""
    _install_runtime_fakes(monkeypatch)
    function_ea = 0x40A560
    target_ea = 0x40B9A6
    call_ea = 0x40BA56
    raw_push = _Instruction(ida_hexrays.m_push, call_ea - 1)
    raw_call = _Instruction(ida_hexrays.m_call, call_ea)
    raw_block = _Block(0, target_ea, (raw_push, raw_call))
    raw_block.flags = int(ida_hexrays.MBL_PUSH)
    raw_source = _MBA(
        (raw_block,),
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
        maturity=ida_hexrays.MMAT_GENERATED,
    )
    assert detached_handler_island.capture_detached_snippet_template(
        function_ea,
        target_ea,
        raw_source,
        ((target_ea, call_ea + 1),),
    )

    roots = detached_handler_island.materialize_detached_snippet_templates(
        destination,
        function_ea,
        (target_ea,),
        expected_template_maturity=ida_hexrays.MMAT_PREOPTIMIZED,
        allow_raw_preopt_calls=True,
        import_native_preopt_ranges=True,
    )

    imported_block = destination.get_mblock(roots[target_ea])
    imported_call = imported_block.tail
    assert imported_call is not None
    assert int(imported_call.ea) == call_ea
    assert int(destination.flags2) & int(ida_hexrays.MBA2_HAS_OUTLINES)
    assert destination.mbr.range_contains(target_ea)
    assert destination.mbr.range_contains(call_ea)


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

    changed = (
        detached_handler_island.reconcile_imported_callinfo_with_live_native_calls(
            destination
        )
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

    assert (
        detached_handler_island.detached_snippet_requires_analyzed_calls(
            function_ea,
            target_ea,
        )
        is True
    )


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


def test_empty_nonadjacent_fallthrough_can_be_made_explicit(
    monkeypatch,
) -> None:
    """A fully-subsumed CALLS setup block still needs a verifier-valid tail."""
    from d810.hexrays.mutation.deferred_modifier import DeferredGraphModifier

    _install_runtime_fakes(monkeypatch)
    function_ea = 0x40A560
    empty = _Block(0, function_ea, (), (2,))
    empty.type = int(ida_hexrays.BLT_1WAY)
    destination = _MBA(
        (
            empty,
            _Block(
                1,
                function_ea + 1,
                (_Instruction(ida_hexrays.m_nop, function_ea + 1),),
            ),
            _Block(
                2,
                0x40A607,
                (_Instruction(ida_hexrays.m_nop, 0x40A607),),
            ),
        )
    )

    DeferredGraphModifier(destination).make_displaced_fallthrough_explicit_now(empty)

    assert empty.tail is not None
    assert int(empty.tail.opcode) == int(ida_hexrays.m_goto)
    assert int(empty.tail.l.t) == int(ida_hexrays.mop_b)
    assert int(empty.tail.l.b) == 2
    assert tuple(empty.succset) == (2,)


def _direct_boundary_port(
    *,
    source_block_ea: int,
    endpoint_block_ea: int,
    old_successor_eas: tuple[int, ...],
    target_ea: int,
    source_owner: object,
    endpoint_owner: object,
    target_owner: object,
    old_successor_owners: tuple[object, ...] = (),
    delivery_mode: str = "redirect_edge",
) -> object:
    from d810.analyses.control_flow.detached_handler_island import (
        DetachedSnippetDirectBoundaryPort,
    )

    return DetachedSnippetDirectBoundaryPort(
        source_block_ea=source_block_ea,
        source_instruction_ea=source_block_ea,
        endpoint_block_ea=endpoint_block_ea,
        old_successor_eas=old_successor_eas,
        target_ea=target_ea,
        state_register=7,
        state_constant=0x1234,
        source_owner=source_owner,
        endpoint_owner=endpoint_owner,
        target_owner=target_owner,
        delivery_mode=delivery_mode,
        resolver_kind="runtime_test",
        old_successor_owners=old_successor_owners,
    )


def test_capture_boundary_port_wrapper_cannot_bypass_normalization() -> None:
    from d810.analyses.control_flow.detached_handler_island import (
        DetachedSnippetBoundaryPortOwner,
        DetachedSnippetBoundaryPorts,
    )

    first = _direct_boundary_port(
        source_block_ea=0x1000,
        endpoint_block_ea=0x1010,
        old_successor_eas=(0x1100,),
        target_ea=0x1200,
        source_owner=DetachedSnippetBoundaryPortOwner.IMPORTED,
        endpoint_owner=DetachedSnippetBoundaryPortOwner.IMPORTED,
        target_owner=DetachedSnippetBoundaryPortOwner.IMPORTED,
    )
    conflicting = _direct_boundary_port(
        source_block_ea=0x1000,
        endpoint_block_ea=0x1010,
        old_successor_eas=(0x1100,),
        target_ea=0x1300,
        source_owner=DetachedSnippetBoundaryPortOwner.IMPORTED,
        endpoint_owner=DetachedSnippetBoundaryPortOwner.IMPORTED,
        target_owner=DetachedSnippetBoundaryPortOwner.IMPORTED,
    )

    assert (
        detached_handler_island._normalize_capture_boundary_ports(
            DetachedSnippetBoundaryPorts(
                direct=(first, conflicting),
                conditional=(),
            )
        )
        is None
    )


def _conditional_boundary_port(
    *,
    source_block_ea: int,
    predicate_ea: int,
    old_taken_target_ea: int | None,
    old_fallthrough_target_ea: int | None,
    taken_target_ea: int,
    fallthrough_target_ea: int,
    source_owner: object,
    taken_target_owner: object,
    fallthrough_target_owner: object,
    old_taken_target_owner: object | None = None,
    old_fallthrough_target_owner: object | None = None,
    logical_source_anchor_ea: int | None = None,
    predicate_ida_stkoff: int | None = None,
    predicate_size: int | None = None,
    condition_code: int | None = None,
    state_register: int | None = 7,
    taken_state: int | None = 0x1234,
    fallthrough_state: int | None = 0x5678,
    resolver_kind: str = "runtime_test",
) -> object:
    from d810.analyses.control_flow.detached_handler_island import (
        DetachedSnippetConditionalBoundaryPort,
    )

    return DetachedSnippetConditionalBoundaryPort(
        source_block_ea=source_block_ea,
        predicate_ea=predicate_ea,
        old_taken_target_ea=old_taken_target_ea,
        old_fallthrough_target_ea=old_fallthrough_target_ea,
        taken_target_ea=taken_target_ea,
        fallthrough_target_ea=fallthrough_target_ea,
        state_register=state_register,
        taken_state=taken_state,
        fallthrough_state=fallthrough_state,
        source_owner=source_owner,
        taken_target_owner=taken_target_owner,
        fallthrough_target_owner=fallthrough_target_owner,
        resolver_kind=resolver_kind,
        old_taken_target_owner=old_taken_target_owner,
        old_fallthrough_target_owner=old_fallthrough_target_owner,
        logical_source_anchor_ea=logical_source_anchor_ea,
        predicate_ida_stkoff=predicate_ida_stkoff,
        predicate_size=predicate_size,
        condition_code=condition_code,
    )


def _terminal_return_import_fixture() -> tuple[
    int,
    int,
    int,
    int,
    object,
    _MBA,
    _MBA,
]:
    from d810.analyses.control_flow.detached_handler_island import (
        DetachedSnippetBoundaryPortOwner,
    )
    from d810.analyses.control_flow.materialized_indirect_transfer import (
        TerminalReturnCarrierRequest,
    )

    function_ea = 0x9000
    predicate_ea = 0x1008
    terminal_target_ea = 0x4000
    sibling_target_ea = 0x4100
    carrier_source_ea = 0x3000
    carrier_ea = 0x3005
    state_register = 20
    state_constant = 0x19A7218A
    request = TerminalReturnCarrierRequest(
        source_handler_ea=carrier_source_ea,
        terminal_target_ea=terminal_target_ea,
        state_var_reg=state_register,
        state_constant=state_constant,
    )
    state_write = _Instruction(
        ida_hexrays.m_mov,
        carrier_source_ea,
        left=_Operand(ida_hexrays.mop_n, value=state_constant),
        dest=_Operand(ida_hexrays.mop_r, register=state_register),
    )
    carrier = _Instruction(
        ida_hexrays.m_mov,
        carrier_ea,
        left=_Operand(ida_hexrays.mop_v, target_ea=0x48B8A4),
        dest=_Operand(
            ida_hexrays.mop_r,
            register=int(ida_hexrays.reg2mreg(0)),
        ),
    )
    carrier_source = _MBA(
        (_Block(0, carrier_source_ea, (state_write, carrier)),),
        maturity=ida_hexrays.MMAT_PREOPTIMIZED,
    )

    terminal = _Block(
        0,
        terminal_target_ea,
        (
            _Instruction(
                ida_hexrays.m_goto,
                terminal_target_ea,
                left=_Operand(ida_hexrays.mop_b, block_ref=2),
            ),
        ),
        (2,),
    )
    terminal.type = int(ida_hexrays.BLT_1WAY)
    sibling = _Block(
        1,
        sibling_target_ea,
        (_Instruction(ida_hexrays.m_nop, sibling_target_ea),),
    )
    synthetic_exit = _Block(2, 0xFFFFFFFFFFFFFFFF, ())
    source = _MBA(
        (terminal, sibling, synthetic_exit),
        maturity=ida_hexrays.MMAT_PREOPTIMIZED,
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
                0x1000,
                (_Instruction(ida_hexrays.m_jnz, predicate_ea),),
            ),
        ),
        maturity=ida_hexrays.MMAT_PREOPTIMIZED,
    )
    port = _conditional_boundary_port(
        source_block_ea=0x1000,
        predicate_ea=predicate_ea,
        old_taken_target_ea=None,
        old_fallthrough_target_ea=None,
        taken_target_ea=terminal_target_ea,
        fallthrough_target_ea=sibling_target_ea,
        source_owner=DetachedSnippetBoundaryPortOwner.LIVE,
        taken_target_owner=DetachedSnippetBoundaryPortOwner.IMPORTED,
        fallthrough_target_owner=DetachedSnippetBoundaryPortOwner.IMPORTED,
        state_register=state_register,
        taken_state=state_constant,
        fallthrough_state=None,
        resolver_kind="preopt_terminal_return_boundary",
    )
    assert detached_handler_island.capture_detached_snippet_template(
        function_ea,
        terminal_target_ea,
        source,
        (
            (terminal_target_ea, terminal_target_ea + 1),
            (sibling_target_ea, sibling_target_ea + 1),
        ),
        boundary_ports=(port,),
    )
    return (
        function_ea,
        terminal_target_ea,
        carrier_ea,
        state_constant,
        request,
        carrier_source,
        destination,
    )


def test_terminal_return_port_inserts_captured_carrier_in_imported_return_arm(
    monkeypatch,
) -> None:
    from d810.hexrays.mutation.deferred_modifier import DeferredGraphModifier

    _install_runtime_fakes(monkeypatch)
    (
        function_ea,
        terminal_target_ea,
        carrier_ea,
        _state_constant,
        request,
        carrier_source,
        destination,
    ) = _terminal_return_import_fixture()
    assert detached_handler_island.capture_terminal_return_carrier_template(
        function_ea,
        request,
        carrier_source,
    )
    monkeypatch.setattr(
        DeferredGraphModifier,
        "restore_pruned_conditional_now",
        lambda *_args, **_kwargs: True,
    )

    result = detached_handler_island.materialize_detached_snippet_templates(
        destination,
        function_ea,
        (terminal_target_ea,),
    )

    imported_return = destination.get_mblock(result[terminal_target_ea])
    instructions = imported_return.instructions()
    assert len(instructions) == 2
    inserted_carrier, preserved_return = instructions
    assert int(inserted_carrier.opcode) == int(ida_hexrays.m_mov)
    assert int(inserted_carrier.l.t) == int(ida_hexrays.mop_v)
    assert int(inserted_carrier.l.g) == 0x48B8A4
    assert int(inserted_carrier.d.t) == int(ida_hexrays.mop_r)
    assert int(inserted_carrier.d.r) == int(ida_hexrays.reg2mreg(0))
    assert int(preserved_return.opcode) == int(ida_hexrays.m_ret)
    assert int(imported_return.type) == int(ida_hexrays.BLT_0WAY)
    assert tuple(imported_return.succset) == ()
    origins = dict(
        detached_handler_island.imported_detached_snippet_instruction_origins(
            destination
        )
    )
    assert origins[int(inserted_carrier.ea)] == carrier_ea


def test_terminal_return_port_abstains_atomically_without_unique_carrier(
    monkeypatch,
) -> None:
    from d810.hexrays.mutation.deferred_modifier import DeferredGraphModifier

    _install_runtime_fakes(monkeypatch)
    (
        function_ea,
        terminal_target_ea,
        _carrier_ea,
        _state_constant,
        _request,
        _carrier_source,
        destination,
    ) = _terminal_return_import_fixture()
    restored: list[bool] = []
    monkeypatch.setattr(
        DeferredGraphModifier,
        "restore_pruned_conditional_now",
        lambda *_args, **_kwargs: restored.append(True) or True,
    )

    result = detached_handler_island.materialize_detached_snippet_templates(
        destination,
        function_ea,
        (terminal_target_ea,),
    )

    assert len(result) == 0
    assert result.applied_boundary_ports == ()
    assert len(result.abstained_boundary_ports) == 1
    assert restored == []


def test_preflight_uses_proven_logical_source_when_predicate_is_absent(
    monkeypatch,
) -> None:
    from d810.analyses.control_flow.detached_handler_island import (
        DetachedSnippetBoundaryPortOwner,
    )
    from d810.hexrays.mutation.deferred_modifier import DeferredGraphModifier

    _install_runtime_fakes(monkeypatch)
    function_ea = 0x9000
    source_ea = 0x1000
    predicate_ea = 0x1008
    anchor_ea = 0x1204
    taken_target_ea = 0x1100
    fallthrough_target_ea = 0x1180
    source = _MBA(
        (
            _Block(
                0,
                taken_target_ea,
                (_Instruction(ida_hexrays.m_nop, taken_target_ea),),
            ),
            _Block(
                1,
                fallthrough_target_ea,
                (_Instruction(ida_hexrays.m_nop, fallthrough_target_ea),),
            ),
        )
    )
    anchor = _Block(
        1,
        anchor_ea,
        (_Instruction(ida_hexrays.m_mov, anchor_ea),),
    )
    destination = _MBA(
        (
            _Block(
                0,
                function_ea,
                (_Instruction(ida_hexrays.m_nop, function_ea),),
            ),
            anchor,
        )
    )
    port = _conditional_boundary_port(
        source_block_ea=source_ea,
        predicate_ea=predicate_ea,
        old_taken_target_ea=anchor_ea,
        old_fallthrough_target_ea=predicate_ea,
        taken_target_ea=taken_target_ea,
        fallthrough_target_ea=fallthrough_target_ea,
        source_owner=DetachedSnippetBoundaryPortOwner.LIVE,
        taken_target_owner=DetachedSnippetBoundaryPortOwner.IMPORTED,
        fallthrough_target_owner=DetachedSnippetBoundaryPortOwner.IMPORTED,
        logical_source_anchor_ea=anchor_ea,
        predicate_ida_stkoff=0x18,
        predicate_size=4,
        condition_code=5,
    )
    assert detached_handler_island.capture_detached_snippet_template(
        function_ea,
        taken_target_ea,
        source,
        (
            (taken_target_ea, taken_target_ea + 1),
            (fallthrough_target_ea, fallthrough_target_ea + 1),
        ),
        boundary_ports=(port,),
    )
    template = detached_handler_island._DETACHED_SNIPPET_TEMPLATES[
        (function_ea, taken_target_ea)
    ]

    batch = detached_handler_island._preflight_boundary_port_batch(
        destination,
        (template,),
    )

    assert batch is not None
    assert len(batch.conditional) == 1
    mutation = batch.conditional[0]
    assert mutation.source.live_block is anchor
    assert mutation.materialize_logical_source is True

    queued_seed: list[dict[str, object]] = []
    queued_lowering: list[dict[str, object]] = []

    def _queue_seed(_modifier, **kwargs) -> None:
        queued_seed.append(kwargs)

    def _queue_lowering(_modifier, **kwargs) -> None:
        queued_lowering.append(kwargs)

    monkeypatch.setattr(
        DeferredGraphModifier,
        "queue_terminal_goto_change",
        _queue_seed,
    )
    monkeypatch.setattr(
        DeferredGraphModifier,
        "queue_lower_conditional_state_transition",
        _queue_lowering,
    )
    monkeypatch.setattr(
        DeferredGraphModifier,
        "apply",
        lambda _modifier, **_kwargs: 2,
    )
    taken_block = _Block(
        2,
        taken_target_ea,
        (_Instruction(ida_hexrays.m_nop, taken_target_ea),),
    )
    fallthrough_block = _Block(
        3,
        fallthrough_target_ea,
        (_Instruction(ida_hexrays.m_nop, fallthrough_target_ea),),
    )
    applied = detached_handler_island._apply_boundary_port_batch(
        destination,
        batch,
        {
            mutation.taken_target.imported_key: taken_block,
            mutation.fallthrough_target.imported_key: fallthrough_block,
        },
    )

    assert applied is not None
    assert len(applied) == 1
    assert queued_seed == [
        {
            "block_serial": int(anchor.serial),
            "goto_target": int(taken_block.serial),
            "description": "seed logical resolver conditional source",
            "priority": 5,
        }
    ]
    assert len(queued_lowering) == 1
    lowering = queued_lowering[0]
    assert lowering["source_serial"] == int(anchor.serial)
    assert lowering["rewrite_from_ea"] == anchor_ea
    assert lowering["false_target_serial"] == int(fallthrough_block.serial)
    assert lowering["true_target_serial"] == int(taken_block.serial)
    condition = lowering["condition_operand"]
    assert condition.t == int(ida_hexrays.mop_S)
    assert condition.s.off == 0x18
    assert condition.size == 4


def test_boundary_port_result_uses_template_record_kind_across_reload(
    monkeypatch,
) -> None:
    from d810.analyses.control_flow.detached_handler_island import (
        DetachedSnippetBoundaryPortOwner,
    )

    class ReloadedDirectBoundaryPort:
        pass

    port = _direct_boundary_port(
        source_block_ea=0x1000,
        endpoint_block_ea=0x1000,
        old_successor_eas=(0x1200,),
        target_ea=0x1100,
        source_owner=DetachedSnippetBoundaryPortOwner.LIVE,
        endpoint_owner=DetachedSnippetBoundaryPortOwner.LIVE,
        target_owner=DetachedSnippetBoundaryPortOwner.IMPORTED,
    )
    record = detached_handler_island.DetachedSnippetTemplateDirectBoundaryPort(
        port=port,
        source_serial=None,
        endpoint_serial=None,
        target_serial=0,
    )
    monkeypatch.setattr(
        detached_handler_island,
        "DetachedSnippetDirectBoundaryPort",
        ReloadedDirectBoundaryPort,
    )

    result = detached_handler_island._boundary_port_result(
        record,
        reason="preflight",
    )

    assert result.source_instruction_ea == 0x1000
    assert result.endpoint_block_ea == 0x1000
    assert result.target_eas == (0x1100,)
    assert result.reason == "preflight"


def test_boundary_port_binding_identity_uses_live_block_serial() -> None:
    class LiveBlockProxy:
        def __init__(self, serial: int) -> None:
            self.serial = serial

    first = detached_handler_island._BoundaryPortBlockBinding(
        native_ea=0x1200,
        live_block=LiveBlockProxy(7),
    )
    second = detached_handler_island._BoundaryPortBlockBinding(
        native_ea=0x1200,
        live_block=LiveBlockProxy(7),
    )

    assert detached_handler_island._boundary_port_binding_identity(
        first
    ) == detached_handler_island._boundary_port_binding_identity(second)


def test_import_boundary_port_connects_imported_source_to_imported_target(
    monkeypatch,
) -> None:
    from d810.analyses.control_flow.detached_handler_island import (
        DetachedSnippetBoundaryPortOwner,
    )

    _install_runtime_fakes(monkeypatch)
    function_ea = 0x9000
    source_ea = 0x1000
    target_ea = 0x1100
    dispatcher_ea = 0x1200
    source = _MBA(
        (
            _Block(
                0,
                source_ea,
                (_Instruction(ida_hexrays.m_nop, source_ea),),
                (2,),
            ),
            _Block(
                1,
                target_ea,
                (_Instruction(ida_hexrays.m_nop, target_ea),),
            ),
            _Block(
                2,
                dispatcher_ea,
                (_Instruction(ida_hexrays.m_nop, dispatcher_ea),),
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
            _Block(1, dispatcher_ea, (_Instruction(ida_hexrays.m_nop, dispatcher_ea),)),
        )
    )

    port = _direct_boundary_port(
        source_block_ea=source_ea,
        endpoint_block_ea=source_ea,
        old_successor_eas=(dispatcher_ea,),
        target_ea=target_ea,
        source_owner=DetachedSnippetBoundaryPortOwner.IMPORTED,
        endpoint_owner=DetachedSnippetBoundaryPortOwner.IMPORTED,
        target_owner=DetachedSnippetBoundaryPortOwner.IMPORTED,
    )
    assert detached_handler_island.capture_detached_snippet_template(
        function_ea,
        source_ea,
        source,
        ((source_ea, source_ea + 1), (target_ea, target_ea + 1)),
        boundary_ports=(port,),
    )

    result = detached_handler_island.materialize_detached_snippet_templates(
        destination,
        function_ea,
        (source_ea,),
    )

    imported_source = destination.get_mblock(result[source_ea])
    origins = dict(
        detached_handler_island.imported_detached_snippet_instruction_origins(
            destination
        )
    )
    imported_target = next(
        block
        for block in destination.blocks
        if block.head is not None and origins.get(int(block.head.ea)) == target_ea
    )
    assert tuple(imported_source.succset) == (int(imported_target.serial),)
    assert result.applied_boundary_ports[0].endpoint_block_ea == source_ea


def test_import_boundary_port_prefers_template_local_old_successor(
    monkeypatch,
) -> None:
    from d810.analyses.control_flow.detached_handler_island import (
        DetachedSnippetBoundaryPortOwner,
    )

    _install_runtime_fakes(monkeypatch)
    function_ea = 0x9000
    source_ea = 0x1000
    target_ea = 0x1100
    dispatcher_ea = 0x1200
    source = _MBA(
        (
            _Block(
                0,
                source_ea,
                (_Instruction(ida_hexrays.m_nop, source_ea),),
                (2,),
            ),
            _Block(
                1,
                target_ea,
                (_Instruction(ida_hexrays.m_nop, target_ea),),
            ),
            _Block(
                2,
                dispatcher_ea,
                (_Instruction(ida_hexrays.m_nop, dispatcher_ea),),
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
                dispatcher_ea,
                (_Instruction(ida_hexrays.m_nop, dispatcher_ea),),
            ),
        )
    )

    port = _direct_boundary_port(
        source_block_ea=source_ea,
        endpoint_block_ea=source_ea,
        old_successor_eas=(dispatcher_ea,),
        target_ea=target_ea,
        source_owner=DetachedSnippetBoundaryPortOwner.IMPORTED,
        endpoint_owner=DetachedSnippetBoundaryPortOwner.IMPORTED,
        target_owner=DetachedSnippetBoundaryPortOwner.IMPORTED,
    )
    assert detached_handler_island.capture_detached_snippet_template(
        function_ea,
        source_ea,
        source,
        (
            (source_ea, source_ea + 1),
            (target_ea, target_ea + 1),
            (dispatcher_ea, dispatcher_ea + 1),
        ),
        boundary_ports=(port,),
    )

    result = detached_handler_island.materialize_detached_snippet_templates(
        destination,
        function_ea,
        (source_ea,),
    )

    assert result[source_ea] >= 0
    imported_source = destination.get_mblock(result[source_ea])
    origins = dict(
        detached_handler_island.imported_detached_snippet_instruction_origins(
            destination
        )
    )
    imported_target = next(
        block
        for block in destination.blocks
        if block.head is not None and origins.get(int(block.head.ea)) == target_ea
    )
    assert tuple(imported_source.succset) == (int(imported_target.serial),)
    assert result.applied_boundary_ports[0].endpoint_block_ea == source_ea


def test_import_conditional_port_prefers_owned_old_targets_over_live_duplicates(
    monkeypatch,
) -> None:
    from d810.analyses.control_flow.detached_handler_island import (
        DetachedSnippetBoundaryPortOwner,
    )
    from d810.hexrays.mutation.deferred_modifier import DeferredGraphModifier

    _install_runtime_fakes(monkeypatch)
    function_ea = 0x9000
    source_ea = 0x1000
    predicate_ea = 0x1008
    old_taken_ea = 0x1100
    old_fallthrough_ea = 0x1200
    taken_target_ea = 0x1300
    fallthrough_target_ea = 0x1400
    source = _MBA(
        (
            _Block(
                0,
                source_ea,
                (
                    _Instruction(ida_hexrays.m_nop, source_ea),
                    _Instruction(
                        ida_hexrays.m_jnz,
                        predicate_ea,
                        dest=_Operand(ida_hexrays.mop_b, block_ref=2),
                    ),
                ),
                (2, 3),
            ),
            _Block(
                1,
                fallthrough_target_ea,
                (_Instruction(ida_hexrays.m_nop, fallthrough_target_ea),),
            ),
            _Block(
                2,
                old_taken_ea,
                (_Instruction(ida_hexrays.m_nop, old_taken_ea),),
            ),
            _Block(
                3,
                old_fallthrough_ea,
                (_Instruction(ida_hexrays.m_nop, old_fallthrough_ea),),
            ),
            _Block(
                4,
                taken_target_ea,
                (_Instruction(ida_hexrays.m_nop, taken_target_ea),),
            ),
        )
    )
    source.get_mblock(0).type = int(ida_hexrays.BLT_2WAY)
    destination = _MBA(
        (
            _Block(
                0,
                function_ea,
                (_Instruction(ida_hexrays.m_nop, function_ea),),
            ),
            _Block(
                1,
                old_taken_ea,
                (_Instruction(ida_hexrays.m_nop, old_taken_ea),),
            ),
            _Block(
                2,
                old_fallthrough_ea,
                (_Instruction(ida_hexrays.m_nop, old_fallthrough_ea),),
            ),
        )
    )

    inserted_helpers: list[int] = []

    def _insert_fake_fallthrough_helper(
        modifier,
        source_serial: int,
    ) -> int:
        block = modifier.mba.get_mblock(source_serial)
        conditional_target = int(block.tail.d.b)
        old_fallthrough = next(
            int(successor)
            for successor in block.succset
            if int(successor) != conditional_target
        )
        helper_serial = int(modifier.mba.qty)
        helper = _Block(
            helper_serial,
            0xF20000 + helper_serial,
            (
                _Instruction(
                    ida_hexrays.m_goto,
                    0xF20000 + helper_serial,
                    left=_Operand(
                        ida_hexrays.mop_b,
                        block_ref=old_fallthrough,
                    ),
                ),
            ),
            (old_fallthrough,),
        )
        helper.type = int(ida_hexrays.BLT_1WAY)
        helper.flags = int(ida_hexrays.MBL_GOTO)
        modifier.mba.append_block(helper)
        block.succset._del(old_fallthrough)
        block.succset.push_back(helper_serial)
        old_fallthrough_block = modifier.mba.get_mblock(old_fallthrough)
        old_fallthrough_block.predset._del(int(block.serial))
        old_fallthrough_block.predset.push_back(helper_serial)
        helper.predset.push_back(int(block.serial))
        inserted_helpers.append(helper_serial)
        return helper_serial

    monkeypatch.setattr(
        DeferredGraphModifier,
        "insert_nop_block_now",
        _insert_fake_fallthrough_helper,
    )
    port = _conditional_boundary_port(
        source_block_ea=source_ea,
        predicate_ea=predicate_ea,
        old_taken_target_ea=old_taken_ea,
        old_fallthrough_target_ea=old_fallthrough_ea,
        taken_target_ea=taken_target_ea,
        fallthrough_target_ea=fallthrough_target_ea,
        source_owner=DetachedSnippetBoundaryPortOwner.IMPORTED,
        taken_target_owner=DetachedSnippetBoundaryPortOwner.IMPORTED,
        fallthrough_target_owner=DetachedSnippetBoundaryPortOwner.IMPORTED,
    )
    assert detached_handler_island.capture_detached_snippet_template(
        function_ea,
        source_ea,
        source,
        tuple(
            (ea, ea + 1)
            for ea in (
                source_ea,
                old_taken_ea,
                old_fallthrough_ea,
                taken_target_ea,
                fallthrough_target_ea,
            )
        ),
        boundary_ports=(port,),
        owned_block_entry_eas=(
            source_ea,
            old_taken_ea,
            old_fallthrough_ea,
            taken_target_ea,
            fallthrough_target_ea,
        ),
    )

    result = detached_handler_island.materialize_detached_snippet_templates(
        destination,
        function_ea,
        (source_ea,),
    )

    imported_source = destination.get_mblock(result[source_ea])
    origins = dict(
        detached_handler_island.imported_detached_snippet_instruction_origins(
            destination
        )
    )
    imported_targets = {
        origins[int(block.head.ea)]: int(block.serial)
        for block in destination.blocks
        if block.head is not None
        and origins.get(int(block.head.ea)) in {taken_target_ea, fallthrough_target_ea}
    }
    assert inserted_helpers
    assert imported_targets[taken_target_ea] in imported_source.succset
    helper_serial = next(
        int(successor)
        for successor in imported_source.succset
        if int(successor) != imported_targets[taken_target_ea]
    )
    helper = destination.get_mblock(helper_serial)
    assert tuple(helper.succset) == (imported_targets[fallthrough_target_ea],)
    assert int(imported_source.tail.d.b) == imported_targets[taken_target_ea]
    assert len(result.applied_boundary_ports) == 1


def test_import_direct_port_collapses_conditional_through_owned_helper(
    monkeypatch,
) -> None:
    from d810.analyses.control_flow.detached_handler_island import (
        DetachedSnippetBoundaryPortOwner,
    )
    from d810.hexrays.mutation.deferred_modifier import DeferredGraphModifier

    _install_runtime_fakes(monkeypatch)
    function_ea = 0x9000
    source_ea = 0x1000
    predicate_ea = 0x1008
    old_taken_ea = 0x1100
    old_fallthrough_ea = 0x1200
    target_ea = 0x1300
    source = _MBA(
        (
            _Block(
                0,
                source_ea,
                (
                    _Instruction(ida_hexrays.m_nop, source_ea),
                    _Instruction(
                        ida_hexrays.m_jnz,
                        predicate_ea,
                        dest=_Operand(ida_hexrays.mop_b, block_ref=1),
                    ),
                ),
                (1, 2),
            ),
            _Block(
                1,
                old_taken_ea,
                (_Instruction(ida_hexrays.m_nop, old_taken_ea),),
            ),
            _Block(
                2,
                old_fallthrough_ea,
                (_Instruction(ida_hexrays.m_nop, old_fallthrough_ea),),
            ),
            _Block(
                3,
                target_ea,
                (_Instruction(ida_hexrays.m_nop, target_ea),),
            ),
        )
    )
    source.get_mblock(0).type = int(ida_hexrays.BLT_2WAY)
    destination = _MBA(
        (
            _Block(
                0,
                function_ea,
                (_Instruction(ida_hexrays.m_nop, function_ea),),
            ),
        )
    )

    def _insert_fake_fallthrough_helper(
        modifier,
        source_serial: int,
        *,
        force_adjacent: bool = False,
    ) -> int:
        assert not force_adjacent
        block = modifier.mba.get_mblock(source_serial)
        conditional_target = int(block.tail.d.b)
        old_fallthrough = next(
            int(successor)
            for successor in block.succset
            if int(successor) != conditional_target
        )
        helper_serial = int(modifier.mba.qty)
        helper = _Block(
            helper_serial,
            0xF40000 + helper_serial,
            (
                _Instruction(
                    ida_hexrays.m_goto,
                    0xF40000 + helper_serial,
                    left=_Operand(
                        ida_hexrays.mop_b,
                        block_ref=old_fallthrough,
                    ),
                ),
            ),
            (old_fallthrough,),
        )
        helper.type = int(ida_hexrays.BLT_1WAY)
        helper.flags = int(ida_hexrays.MBL_GOTO)
        modifier.mba.append_block(helper)
        block.succset._del(old_fallthrough)
        block.succset.push_back(helper_serial)
        old_fallthrough_block = modifier.mba.get_mblock(old_fallthrough)
        old_fallthrough_block.predset._del(int(block.serial))
        old_fallthrough_block.predset.push_back(helper_serial)
        helper.predset.push_back(int(block.serial))
        return helper_serial

    monkeypatch.setattr(
        DeferredGraphModifier,
        "insert_nop_block_now",
        _insert_fake_fallthrough_helper,
    )
    port = _direct_boundary_port(
        source_block_ea=source_ea,
        endpoint_block_ea=source_ea,
        old_successor_eas=(old_taken_ea, old_fallthrough_ea),
        target_ea=target_ea,
        source_owner=DetachedSnippetBoundaryPortOwner.IMPORTED,
        endpoint_owner=DetachedSnippetBoundaryPortOwner.IMPORTED,
        target_owner=DetachedSnippetBoundaryPortOwner.IMPORTED,
    )
    assert detached_handler_island.capture_detached_snippet_template(
        function_ea,
        source_ea,
        source,
        tuple(
            (ea, ea + 1)
            for ea in (
                source_ea,
                old_taken_ea,
                old_fallthrough_ea,
                target_ea,
            )
        ),
        boundary_ports=(port,),
    )

    result = detached_handler_island.materialize_detached_snippet_templates(
        destination,
        function_ea,
        (source_ea,),
    )

    imported_source = destination.get_mblock(result[source_ea])
    origins = dict(
        detached_handler_island.imported_detached_snippet_instruction_origins(
            destination
        )
    )
    imported_target = next(
        block
        for block in destination.blocks
        if block.head is not None and origins.get(int(block.head.ea)) == target_ea
    )
    assert int(imported_source.type) == int(ida_hexrays.BLT_1WAY)
    assert tuple(imported_source.succset) == (int(imported_target.serial),)
    assert len(result.applied_boundary_ports) == 1
    evidence = (
        detached_handler_island.imported_detached_snippet_direct_boundary_evidence(
            destination
        )
    )
    assert len(evidence) == 1
    assert evidence[0].port == port
    assert set(evidence[0].endpoint_anchor_eas) == {
        int(instruction.ea) for instruction in imported_source.instructions()
    }
    assert set(evidence[0].target_anchor_eas) == {
        int(instruction.ea) for instruction in imported_target.instructions()
    }


def test_import_boundary_port_connects_live_source_to_imported_target(
    monkeypatch,
) -> None:
    from d810.analyses.control_flow.detached_handler_island import (
        DetachedSnippetBoundaryPortOwner,
    )

    _install_runtime_fakes(monkeypatch)
    function_ea = 0x9000
    live_source_ea = 0x1000
    target_ea = 0x1100
    dispatcher_ea = 0x1200
    source = _MBA(
        (_Block(0, target_ea, (_Instruction(ida_hexrays.m_nop, target_ea),)),)
    )
    destination = _MBA(
        (
            _Block(0, function_ea, (_Instruction(ida_hexrays.m_nop, function_ea),)),
            _Block(
                1,
                live_source_ea,
                (_Instruction(ida_hexrays.m_nop, live_source_ea),),
                (2,),
            ),
            _Block(
                2,
                dispatcher_ea,
                (_Instruction(ida_hexrays.m_nop, dispatcher_ea),),
            ),
        )
    )
    destination.get_mblock(1).type = int(ida_hexrays.BLT_1WAY)
    destination.get_mblock(2).predset.push_back(1)
    port = _direct_boundary_port(
        source_block_ea=live_source_ea,
        endpoint_block_ea=live_source_ea,
        old_successor_eas=(dispatcher_ea,),
        target_ea=target_ea,
        source_owner=DetachedSnippetBoundaryPortOwner.LIVE,
        endpoint_owner=DetachedSnippetBoundaryPortOwner.LIVE,
        target_owner=DetachedSnippetBoundaryPortOwner.IMPORTED,
    )
    assert detached_handler_island.capture_detached_snippet_template(
        function_ea,
        target_ea,
        source,
        ((target_ea, target_ea + 1),),
        boundary_ports=(port,),
    )

    result = detached_handler_island.materialize_detached_snippet_templates(
        destination,
        function_ea,
        (target_ea,),
    )

    assert tuple(destination.get_mblock(1).succset) == (result[target_ea],)
    assert result.applied_boundary_ports[0].endpoint_block_ea == live_source_ea


def test_import_boundary_port_distinguishes_live_old_copy_from_imported_target(
    monkeypatch,
) -> None:
    from d810.analyses.control_flow.detached_handler_island import (
        DetachedSnippetBoundaryPortOwner,
    )

    _install_runtime_fakes(monkeypatch)
    function_ea = 0x9000
    live_source_ea = 0x1000
    shared_target_ea = 0x1100
    source = _MBA(
        (
            _Block(
                0,
                shared_target_ea,
                (_Instruction(ida_hexrays.m_nop, shared_target_ea),),
            ),
        )
    )
    destination = _MBA(
        (
            _Block(0, function_ea, (_Instruction(ida_hexrays.m_nop, function_ea),)),
            _Block(
                1,
                live_source_ea,
                (_Instruction(ida_hexrays.m_nop, live_source_ea),),
                (2,),
            ),
            _Block(
                2,
                shared_target_ea,
                (_Instruction(ida_hexrays.m_nop, shared_target_ea),),
            ),
        )
    )
    destination.get_mblock(1).type = int(ida_hexrays.BLT_1WAY)
    destination.get_mblock(2).predset.push_back(1)
    port = _direct_boundary_port(
        source_block_ea=live_source_ea,
        endpoint_block_ea=live_source_ea,
        old_successor_eas=(shared_target_ea,),
        target_ea=shared_target_ea,
        source_owner=DetachedSnippetBoundaryPortOwner.LIVE,
        endpoint_owner=DetachedSnippetBoundaryPortOwner.LIVE,
        target_owner=DetachedSnippetBoundaryPortOwner.IMPORTED,
        old_successor_owners=(DetachedSnippetBoundaryPortOwner.LIVE,),
    )
    assert detached_handler_island.capture_detached_snippet_template(
        function_ea,
        shared_target_ea,
        source,
        ((shared_target_ea, shared_target_ea + 1),),
        boundary_ports=(port,),
    )

    result = detached_handler_island.materialize_detached_snippet_templates(
        destination,
        function_ea,
        (shared_target_ea,),
    )

    assert result[shared_target_ea] != 2
    assert tuple(destination.get_mblock(1).succset) == (result[shared_target_ea],)


def test_import_boundary_port_accepts_owner_enum_from_reloaded_module(
    monkeypatch,
) -> None:
    class ReloadedBoundaryPortOwner(str, Enum):
        IMPORTED = "imported"
        LIVE = "live"

    _install_runtime_fakes(monkeypatch)
    function_ea = 0x9000
    live_source_ea = 0x1000
    target_ea = 0x1100
    dispatcher_ea = 0x1200
    source = _MBA(
        (_Block(0, target_ea, (_Instruction(ida_hexrays.m_nop, target_ea),)),)
    )
    destination = _MBA(
        (
            _Block(0, function_ea, (_Instruction(ida_hexrays.m_nop, function_ea),)),
            _Block(
                1,
                live_source_ea,
                (_Instruction(ida_hexrays.m_nop, live_source_ea),),
                (2,),
            ),
            _Block(2, dispatcher_ea, (_Instruction(ida_hexrays.m_nop, dispatcher_ea),)),
        )
    )
    destination.get_mblock(1).type = int(ida_hexrays.BLT_1WAY)
    destination.get_mblock(2).predset.push_back(1)
    port = _direct_boundary_port(
        source_block_ea=live_source_ea,
        endpoint_block_ea=live_source_ea,
        old_successor_eas=(dispatcher_ea,),
        target_ea=target_ea,
        source_owner=ReloadedBoundaryPortOwner.LIVE,
        endpoint_owner=ReloadedBoundaryPortOwner.LIVE,
        target_owner=ReloadedBoundaryPortOwner.IMPORTED,
    )
    assert detached_handler_island.capture_detached_snippet_template(
        function_ea,
        target_ea,
        source,
        ((target_ea, target_ea + 1),),
        boundary_ports=(port,),
    )

    result = detached_handler_island.materialize_detached_snippet_templates(
        destination,
        function_ea,
        (target_ea,),
    )

    assert tuple(destination.get_mblock(1).succset) == (result[target_ea],)


def test_import_boundary_port_materializes_pruned_live_frontier(
    monkeypatch,
) -> None:
    from d810.analyses.control_flow.detached_handler_island import (
        DetachedSnippetBoundaryPortOwner,
    )

    _install_runtime_fakes(monkeypatch)
    function_ea = 0x9000
    live_source_ea = 0x1000
    target_ea = 0x1100
    dispatcher_ea = 0x1200
    source = _MBA(
        (_Block(0, target_ea, (_Instruction(ida_hexrays.m_nop, target_ea),)),)
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
                live_source_ea,
                (_Instruction(ida_hexrays.m_jnz, live_source_ea),),
            ),
        )
    )
    port = _direct_boundary_port(
        source_block_ea=live_source_ea,
        endpoint_block_ea=live_source_ea,
        old_successor_eas=(dispatcher_ea,),
        target_ea=target_ea,
        source_owner=DetachedSnippetBoundaryPortOwner.LIVE,
        endpoint_owner=DetachedSnippetBoundaryPortOwner.LIVE,
        target_owner=DetachedSnippetBoundaryPortOwner.IMPORTED,
    )
    assert detached_handler_island.capture_detached_snippet_template(
        function_ea,
        target_ea,
        source,
        ((target_ea, target_ea + 1),),
        boundary_ports=(port,),
    )

    result = detached_handler_island.materialize_detached_snippet_templates(
        destination,
        function_ea,
        (target_ea,),
    )

    assert tuple(destination.get_mblock(1).succset) == (result[target_ea],)
    assert result.applied_boundary_ports[0].endpoint_block_ea == live_source_ea
    closing_instructions = tuple(
        instruction
        for instruction in destination.get_mblock(1).instructions()
        if ida_hexrays.is_mcode_jcond(int(instruction.opcode))
        or int(instruction.opcode) == int(ida_hexrays.m_goto)
    )
    assert len(closing_instructions) == 1
    assert int(closing_instructions[0].opcode) == int(ida_hexrays.m_goto)


def test_import_boundary_port_restores_pruned_live_conditional(
    monkeypatch,
) -> None:
    from d810.analyses.control_flow.detached_handler_island import (
        DetachedSnippetBoundaryPortOwner,
    )
    from d810.hexrays.mutation.deferred_modifier import DeferredGraphModifier

    _install_runtime_fakes(monkeypatch)
    function_ea = 0x9000
    live_source_ea = 0x1000
    predicate_ea = 0x1008
    taken_target_ea = 0x1100
    fallthrough_target_ea = 0x1180
    source = _MBA(
        (
            _Block(
                0,
                taken_target_ea,
                (_Instruction(ida_hexrays.m_nop, taken_target_ea),),
            ),
            _Block(
                1,
                fallthrough_target_ea,
                (_Instruction(ida_hexrays.m_nop, fallthrough_target_ea),),
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
                live_source_ea,
                (_Instruction(ida_hexrays.m_jnz, predicate_ea),),
            ),
        )
    )
    port = _conditional_boundary_port(
        source_block_ea=live_source_ea,
        predicate_ea=predicate_ea,
        old_taken_target_ea=None,
        old_fallthrough_target_ea=None,
        taken_target_ea=taken_target_ea,
        fallthrough_target_ea=fallthrough_target_ea,
        source_owner=DetachedSnippetBoundaryPortOwner.LIVE,
        taken_target_owner=DetachedSnippetBoundaryPortOwner.IMPORTED,
        fallthrough_target_owner=DetachedSnippetBoundaryPortOwner.IMPORTED,
    )
    assert detached_handler_island.capture_detached_snippet_template(
        function_ea,
        taken_target_ea,
        source,
        (
            (taken_target_ea, taken_target_ea + 1),
            (fallthrough_target_ea, fallthrough_target_ea + 1),
        ),
        boundary_ports=(port,),
    )

    restored: list[tuple[int, int, int]] = []

    def _restore(
        _modifier,
        live_source,
        *,
        taken_target,
        fallthrough_target,
    ) -> bool:
        restored.append(
            (
                int(live_source.start),
                int(taken_target.serial),
                int(fallthrough_target.serial),
            )
        )
        return True

    monkeypatch.setattr(
        DeferredGraphModifier,
        "restore_pruned_conditional_now",
        _restore,
    )

    result = detached_handler_island.materialize_detached_snippet_templates(
        destination,
        function_ea,
        (taken_target_ea,),
    )

    assert restored and restored[0][0] == live_source_ea
    assert len(result.applied_boundary_ports) == 1
    assert result.applied_boundary_ports[0].source_instruction_ea == predicate_ea
    evidence = (
        detached_handler_island.imported_detached_snippet_conditional_boundary_evidence(
            destination
        )
    )
    assert len(evidence) == 1
    assert evidence[0].port == port
    taken_block = destination.get_mblock(restored[0][1])
    fallthrough_block = destination.get_mblock(restored[0][2])
    assert evidence[0].taken_target_anchor_eas
    assert evidence[0].fallthrough_target_anchor_eas
    assert set(evidence[0].taken_target_anchor_eas) == {
        int(instruction.ea) for instruction in taken_block.instructions()
    }
    assert set(evidence[0].fallthrough_target_anchor_eas) == {
        int(instruction.ea) for instruction in fallthrough_block.instructions()
    }

    # CALLS may eliminate every instruction from the exact PREOPT target block
    # while the imported-root lineage still relocates that native target to a
    # surviving merged block.  Querying the applied evidence must refresh the
    # arm anchors from that live root instead of returning stale PREOPT anchors.
    rebound_anchor_ea = 0xF20000
    rebound_taken_block = _Block(
        destination.qty,
        rebound_anchor_ea,
        (_Instruction(ida_hexrays.m_nop, rebound_anchor_ea),),
    )
    destination.append_block(rebound_taken_block)
    identity = detached_handler_island.stable_mba_identity(destination)
    detached_handler_island._IMPORTED_SNIPPET_ROOTS[(identity, taken_target_ea)] = (
        detached_handler_island._ImportedSnippetRoot(
            serial_hint=int(rebound_taken_block.serial),
            anchor_eas=(rebound_anchor_ea,),
            owned_instruction_eas=(rebound_anchor_ea,),
        )
    )

    rebound_evidence = (
        detached_handler_island.imported_detached_snippet_conditional_boundary_evidence(
            destination
        )
    )
    assert rebound_evidence[0].taken_target_anchor_eas == (rebound_anchor_ea,)


def test_import_boundary_port_preserves_call_corridor(
    monkeypatch,
) -> None:
    from d810.analyses.control_flow.detached_handler_island import (
        DetachedSnippetBoundaryPortOwner,
    )
    from d810.hexrays.mutation.deferred_modifier import DeferredGraphModifier

    _install_runtime_fakes(monkeypatch)
    function_ea = 0x9000
    source_ea = 0x1000
    call_ea = 0x1008
    target_ea = 0x1100
    dispatcher_ea = 0x1200
    source = _MBA(
        (
            _Block(
                0,
                source_ea,
                (
                    _Instruction(ida_hexrays.m_nop, source_ea),
                    _Instruction(ida_hexrays.m_call, call_ea),
                ),
                (2,),
            ),
            _Block(1, target_ea, (_Instruction(ida_hexrays.m_nop, target_ea),)),
            _Block(2, dispatcher_ea, (_Instruction(ida_hexrays.m_nop, dispatcher_ea),)),
        ),
        maturity=ida_hexrays.MMAT_PREOPTIMIZED,
    )
    source.get_mblock(0).type = int(ida_hexrays.BLT_1WAY)
    destination = _MBA(
        (
            _Block(0, function_ea, (_Instruction(ida_hexrays.m_nop, function_ea),)),
            _Block(1, dispatcher_ea, (_Instruction(ida_hexrays.m_nop, dispatcher_ea),)),
        ),
        maturity=ida_hexrays.MMAT_PREOPTIMIZED,
    )
    inserted_helpers: list[int] = []

    def _insert_fake_call_fallthrough_helper(
        modifier,
        source_serial: int,
        *,
        force_adjacent: bool = False,
    ) -> int:
        assert force_adjacent
        block = modifier.mba.get_mblock(source_serial)
        old_fallthrough = int(block.succset[0])
        helper_serial = int(modifier.mba.qty)
        helper = _Block(
            helper_serial,
            0xF30000 + helper_serial,
            (
                _Instruction(
                    ida_hexrays.m_goto,
                    0xF30000 + helper_serial,
                    left=_Operand(
                        ida_hexrays.mop_b,
                        block_ref=old_fallthrough,
                    ),
                ),
            ),
            (old_fallthrough,),
        )
        helper.type = int(ida_hexrays.BLT_1WAY)
        helper.flags = int(ida_hexrays.MBL_GOTO)
        modifier.mba.append_block(helper)
        block.succset._del(old_fallthrough)
        block.succset.push_back(helper_serial)
        old_fallthrough_block = modifier.mba.get_mblock(old_fallthrough)
        old_fallthrough_block.predset._del(int(block.serial))
        old_fallthrough_block.predset.push_back(helper_serial)
        helper.predset.push_back(int(block.serial))
        inserted_helpers.append(helper_serial)
        return helper_serial

    monkeypatch.setattr(
        DeferredGraphModifier,
        "insert_nop_block_now",
        _insert_fake_call_fallthrough_helper,
    )
    port = _direct_boundary_port(
        source_block_ea=source_ea,
        endpoint_block_ea=source_ea,
        old_successor_eas=(dispatcher_ea,),
        target_ea=target_ea,
        source_owner=DetachedSnippetBoundaryPortOwner.IMPORTED,
        endpoint_owner=DetachedSnippetBoundaryPortOwner.IMPORTED,
        target_owner=DetachedSnippetBoundaryPortOwner.IMPORTED,
    )
    assert detached_handler_island.capture_detached_snippet_template(
        function_ea,
        source_ea,
        source,
        ((source_ea, source_ea + 1), (target_ea, target_ea + 1)),
        boundary_ports=(port,),
    )

    result = detached_handler_island.materialize_detached_snippet_templates(
        destination,
        function_ea,
        (source_ea,),
        allow_raw_preopt_calls=True,
    )

    imported_source = destination.get_mblock(result[source_ea])
    assert inserted_helpers
    assert int(imported_source.tail.opcode) == int(ida_hexrays.m_call)
    helper = destination.get_mblock(int(imported_source.succset[0]))
    origins = dict(
        detached_handler_island.imported_detached_snippet_instruction_origins(
            destination
        )
    )
    imported_target = next(
        block
        for block in destination.blocks
        if block.head is not None and origins.get(int(block.head.ea)) == target_ea
    )
    assert tuple(helper.succset) == (int(imported_target.serial),)
    assert result.applied_boundary_ports[0].endpoint_block_ea == source_ea


def test_import_boundary_port_restores_pruned_live_post_call_route(
    monkeypatch,
) -> None:
    from d810.analyses.control_flow.detached_handler_island import (
        DetachedSnippetBoundaryPortOwner,
    )

    _install_runtime_fakes(monkeypatch)
    function_ea = 0x9000
    live_source_ea = 0x1000
    call_ea = 0x1048
    target_ea = 0x1100
    source = _MBA(
        (
            _Block(
                0,
                target_ea,
                (_Instruction(ida_hexrays.m_nop, target_ea),),
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
            _Block(
                1,
                live_source_ea,
                (
                    _Instruction(ida_hexrays.m_nop, live_source_ea),
                    _Instruction(ida_hexrays.m_call, call_ea),
                ),
            ),
        ),
        maturity=ida_hexrays.MMAT_PREOPTIMIZED,
    )

    def copy_block(mba, reference, destination_serial, _flags):
        for block in mba.blocks[destination_serial:]:
            block.serial += 1
        copied = copy.deepcopy(reference)
        copied.serial = int(destination_serial)
        copied.owner = mba
        mba.blocks.insert(int(destination_serial), copied)
        return copied

    monkeypatch.setattr(_MBA, "copy_block", copy_block, raising=False)
    port = _direct_boundary_port(
        source_block_ea=live_source_ea,
        endpoint_block_ea=live_source_ea,
        old_successor_eas=(),
        target_ea=target_ea,
        source_owner=DetachedSnippetBoundaryPortOwner.LIVE,
        endpoint_owner=DetachedSnippetBoundaryPortOwner.LIVE,
        target_owner=DetachedSnippetBoundaryPortOwner.IMPORTED,
        delivery_mode="preserve_call",
    )
    assert detached_handler_island.capture_detached_snippet_template(
        function_ea,
        target_ea,
        source,
        ((target_ea, target_ea + 1),),
        boundary_ports=(port,),
    )

    result = detached_handler_island.materialize_detached_snippet_templates(
        destination,
        function_ea,
        (target_ea,),
        allow_raw_preopt_calls=True,
    )

    live_source = destination.get_mblock(1)
    assert any(
        int(instruction.opcode) == int(ida_hexrays.m_call)
        and int(instruction.ea) == call_ea
        for instruction in live_source.instructions()
    )
    assert int(live_source.tail.opcode) == int(ida_hexrays.m_call)
    (helper_serial,) = tuple(live_source.succset)
    helper = destination.get_mblock(helper_serial)
    assert int(helper.serial) == int(live_source.serial) + 1
    assert tuple(helper.succset) == (result[target_ea],)
    assert int(helper.tail.opcode) == int(ida_hexrays.m_goto)
    assert result.applied_boundary_ports[0].endpoint_block_ea == live_source_ea


def test_import_boundary_port_abstains_before_allocation_when_sibling_missing(
    monkeypatch,
) -> None:
    from d810.analyses.control_flow.detached_handler_island import (
        DetachedSnippetBoundaryPortOwner,
    )

    created = _install_runtime_fakes(monkeypatch)
    function_ea = 0x9000
    first_source_ea = 0x1000
    target_ea = 0x1100
    second_source_ea = 0x1200
    first_dispatcher_ea = 0x1300
    second_dispatcher_ea = 0x1400
    missing_target_ea = 0x1500
    source = _MBA(
        (
            _Block(
                0,
                first_source_ea,
                (_Instruction(ida_hexrays.m_nop, first_source_ea),),
                (3,),
            ),
            _Block(1, target_ea, (_Instruction(ida_hexrays.m_nop, target_ea),)),
            _Block(
                2,
                second_source_ea,
                (_Instruction(ida_hexrays.m_nop, second_source_ea),),
                (4,),
            ),
            _Block(
                3,
                first_dispatcher_ea,
                (_Instruction(ida_hexrays.m_nop, first_dispatcher_ea),),
            ),
            _Block(
                4,
                second_dispatcher_ea,
                (_Instruction(ida_hexrays.m_nop, second_dispatcher_ea),),
            ),
        )
    )
    source.get_mblock(0).type = int(ida_hexrays.BLT_1WAY)
    source.get_mblock(2).type = int(ida_hexrays.BLT_1WAY)
    destination = _MBA(
        (
            _Block(0, function_ea, (_Instruction(ida_hexrays.m_nop, function_ea),)),
            _Block(
                1,
                first_dispatcher_ea,
                (_Instruction(ida_hexrays.m_nop, first_dispatcher_ea),),
            ),
            _Block(
                2,
                second_dispatcher_ea,
                (_Instruction(ida_hexrays.m_nop, second_dispatcher_ea),),
            ),
        )
    )
    first_port = _direct_boundary_port(
        source_block_ea=first_source_ea,
        endpoint_block_ea=first_source_ea,
        old_successor_eas=(first_dispatcher_ea,),
        target_ea=target_ea,
        source_owner=DetachedSnippetBoundaryPortOwner.IMPORTED,
        endpoint_owner=DetachedSnippetBoundaryPortOwner.IMPORTED,
        target_owner=DetachedSnippetBoundaryPortOwner.IMPORTED,
    )
    missing_sibling = _direct_boundary_port(
        source_block_ea=second_source_ea,
        endpoint_block_ea=second_source_ea,
        old_successor_eas=(second_dispatcher_ea,),
        target_ea=missing_target_ea,
        source_owner=DetachedSnippetBoundaryPortOwner.IMPORTED,
        endpoint_owner=DetachedSnippetBoundaryPortOwner.IMPORTED,
        target_owner=DetachedSnippetBoundaryPortOwner.LIVE,
    )
    assert detached_handler_island.capture_detached_snippet_template(
        function_ea,
        first_source_ea,
        source,
        (
            (first_source_ea, first_source_ea + 1),
            (target_ea, target_ea + 1),
            (second_source_ea, second_source_ea + 1),
        ),
        boundary_ports=(first_port, missing_sibling),
    )
    original_qty = destination.qty

    result = detached_handler_island.materialize_detached_snippet_templates(
        destination,
        function_ea,
        (first_source_ea,),
    )

    assert result == {}
    assert created == []
    assert destination.qty == original_qty
    assert len(result.abstained_boundary_ports) == 2


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
    assert {destination.map_fict_ea(imported_ea) for imported_ea in imported_eas} == {
        function_ea + 1
    }


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


def test_live_lookup_uses_exact_instruction_when_imported_start_overlaps():
    source_entry_ea = 0x1000
    predicate_ea = 0x1008
    imported = _Block(
        0,
        source_entry_ea,
        (_Instruction(ida_hexrays.m_jnz, 0xF10008),),
    )
    live = _Block(
        1,
        0x9000,
        (_Instruction(ida_hexrays.m_jnz, predicate_ea),),
    )
    destination = _MBA((imported, live))

    result = detached_handler_island.find_unique_live_block_by_ea(
        destination,
        source_entry_ea,
        exact_instruction_ea=predicate_ea,
    )

    assert result is live


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


def test_resolver_cut_port_binds_exact_instruction_after_microblock_split(
    monkeypatch,
) -> None:
    from d810.analyses.control_flow.detached_handler_island import (
        DetachedSnippetBoundaryPortOwner,
        make_resolver_cut_boundary_port,
    )

    _install_runtime_fakes(monkeypatch)
    function_ea = 0x9000
    source_block_ea = 0x1000
    split_block_ea = 0x1008
    resolver_ea = 0x100E
    live_target_ea = 0x2000
    source = _MBA(
        (
            _Block(
                0,
                source_block_ea,
                (_Instruction(ida_hexrays.m_call, source_block_ea),),
                (1,),
            ),
            _Block(
                1,
                split_block_ea,
                (_Instruction(ida_hexrays.m_ijmp, resolver_ea),),
            ),
        ),
        maturity=ida_hexrays.MMAT_PREOPTIMIZED,
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
                live_target_ea,
                (_Instruction(ida_hexrays.m_nop, live_target_ea),),
            ),
        ),
        maturity=ida_hexrays.MMAT_PREOPTIMIZED,
    )
    port = make_resolver_cut_boundary_port(
        source_block_ea=source_block_ea,
        source_instruction_ea=resolver_ea,
        target_ea=live_target_ea,
        source_owner=DetachedSnippetBoundaryPortOwner.IMPORTED,
        target_owner=DetachedSnippetBoundaryPortOwner.LIVE,
        provenance="static_fixpoint",
    )
    assert detached_handler_island.capture_detached_snippet_template(
        function_ea,
        source_block_ea,
        source,
        ((source_block_ea, resolver_ea + 1),),
        boundary_ports=(port,),
    )

    result = detached_handler_island.materialize_detached_snippet_templates(
        destination,
        function_ea,
        (source_block_ea,),
        allow_raw_preopt_calls=True,
    )

    origins = dict(
        detached_handler_island.imported_detached_snippet_instruction_origins(
            destination
        )
    )
    imported_cut = next(
        block
        for block in destination.blocks
        if any(
            origins.get(int(instruction.ea)) == resolver_ea
            for instruction in block.instructions()
        )
    )
    assert tuple(imported_cut.succset) == (1,)
    assert int(imported_cut.tail.opcode) == int(ida_hexrays.m_goto)
    assert len(result.applied_boundary_ports) == 1


def test_resolver_cut_port_lowers_raw_one_way_call_to_goto(
    monkeypatch,
) -> None:
    from d810.analyses.control_flow.detached_handler_island import (
        DetachedSnippetBoundaryPortOwner,
        make_resolver_cut_boundary_port,
    )

    _install_runtime_fakes(monkeypatch)
    function_ea = 0x9000
    source_block_ea = 0x1000
    resolver_ea = 0x100E
    live_target_ea = 0x2000
    source = _MBA(
        (
            _Block(
                0,
                source_block_ea,
                (_Instruction(ida_hexrays.m_call, resolver_ea),),
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
            _Block(
                1,
                live_target_ea,
                (_Instruction(ida_hexrays.m_nop, live_target_ea),),
            ),
        ),
        maturity=ida_hexrays.MMAT_PREOPTIMIZED,
    )
    port = make_resolver_cut_boundary_port(
        source_block_ea=source_block_ea,
        source_instruction_ea=resolver_ea,
        target_ea=live_target_ea,
        source_owner=DetachedSnippetBoundaryPortOwner.IMPORTED,
        target_owner=DetachedSnippetBoundaryPortOwner.LIVE,
        provenance="static_fixpoint",
    )
    assert detached_handler_island.capture_detached_snippet_template(
        function_ea,
        source_block_ea,
        source,
        ((source_block_ea, resolver_ea + 1),),
        boundary_ports=(port,),
    )

    result = detached_handler_island.materialize_detached_snippet_templates(
        destination,
        function_ea,
        (source_block_ea,),
        allow_raw_preopt_calls=True,
    )

    origins = dict(
        detached_handler_island.imported_detached_snippet_instruction_origins(
            destination
        )
    )
    imported_cut = next(
        block
        for block in destination.blocks
        if any(
            origins.get(int(instruction.ea)) == resolver_ea
            for instruction in block.instructions()
        )
    )
    assert tuple(imported_cut.succset) == (1,)
    assert int(imported_cut.tail.opcode) == int(ida_hexrays.m_goto)
    assert all(
        int(instruction.opcode)
        not in {int(ida_hexrays.m_call), int(ida_hexrays.m_icall)}
        for instruction in imported_cut.instructions()
    )
    assert len(result.applied_boundary_ports) == 1


def test_resolver_cut_port_lowers_preopt_transfer_envelope_to_goto(
    monkeypatch,
) -> None:
    from d810.analyses.control_flow.detached_handler_island import (
        DetachedSnippetBoundaryPortOwner,
        make_resolver_cut_boundary_port,
    )

    _install_runtime_fakes(monkeypatch)
    function_ea = 0x9000
    source_block_ea = 0x1000
    resolver_ea = 0x100E
    live_target_ea = 0x2000
    source = _MBA(
        (
            _Block(
                0,
                source_block_ea,
                (_Instruction(ida_hexrays.m_mov, resolver_ea),),
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
            _Block(
                1,
                live_target_ea,
                (_Instruction(ida_hexrays.m_nop, live_target_ea),),
            ),
        ),
        maturity=ida_hexrays.MMAT_PREOPTIMIZED,
    )
    port = make_resolver_cut_boundary_port(
        source_block_ea=source_block_ea,
        source_instruction_ea=resolver_ea,
        target_ea=live_target_ea,
        source_owner=DetachedSnippetBoundaryPortOwner.IMPORTED,
        target_owner=DetachedSnippetBoundaryPortOwner.LIVE,
        provenance="static_fixpoint",
    )
    assert detached_handler_island.capture_detached_snippet_template(
        function_ea,
        source_block_ea,
        source,
        ((source_block_ea, resolver_ea + 1),),
        boundary_ports=(port,),
    )

    result = detached_handler_island.materialize_detached_snippet_templates(
        destination,
        function_ea,
        (source_block_ea,),
        allow_raw_preopt_calls=True,
    )

    origins = dict(
        detached_handler_island.imported_detached_snippet_instruction_origins(
            destination
        )
    )
    imported_cut = next(
        block
        for block in destination.blocks
        if any(
            origins.get(int(instruction.ea)) == resolver_ea
            for instruction in block.instructions()
        )
    )
    resolver_instructions = tuple(
        instruction
        for instruction in imported_cut.instructions()
        if origins.get(int(instruction.ea)) == resolver_ea
    )
    assert len(resolver_instructions) == 1
    assert int(resolver_instructions[0].opcode) == int(ida_hexrays.m_nop)
    assert tuple(imported_cut.succset) == (1,)
    assert int(imported_cut.tail.opcode) == int(ida_hexrays.m_goto)
    assert len(result.applied_boundary_ports) == 1


def test_capture_can_own_only_missing_blocks_from_a_full_function_mba(
    monkeypatch,
) -> None:
    _install_runtime_fakes(monkeypatch)
    function_ea = 0xA000
    missing_entry_ea = 0x1100
    live_entry_ea = 0x2200
    source = _MBA(
        (
            _Block(
                0,
                missing_entry_ea,
                (_Instruction(ida_hexrays.m_nop, missing_entry_ea),),
                (1,),
            ),
            _Block(
                1,
                live_entry_ea,
                (_Instruction(ida_hexrays.m_nop, live_entry_ea),),
            ),
        ),
        maturity=ida_hexrays.MMAT_PREOPTIMIZED,
    )
    source.get_mblock(0).type = int(ida_hexrays.BLT_1WAY)

    assert detached_handler_island.capture_detached_snippet_template(
        function_ea,
        missing_entry_ea,
        source,
        (
            (missing_entry_ea, missing_entry_ea + 1),
            (live_entry_ea, live_entry_ea + 1),
        ),
        owned_block_entry_eas=(missing_entry_ea,),
    )
    assert detached_handler_island.detached_snippet_template_block_eas(
        function_ea,
        missing_entry_ea,
    ) == (missing_entry_ea,)


def test_capture_drops_only_the_synthetic_exit_after_a_native_return(
    monkeypatch,
) -> None:
    _install_runtime_fakes(monkeypatch)
    function_ea = 0xB000
    return_ea = 0x3300
    source = _MBA(
        (
            _Block(
                0,
                return_ea,
                (
                    _Instruction(
                        ida_hexrays.m_goto,
                        return_ea,
                        left=_Operand(
                            ida_hexrays.mop_b,
                            block_ref=1,
                        ),
                    ),
                ),
                (1,),
            ),
            _Block(1, 0xFFFFFFFFFFFFFFFF, ()),
        ),
        maturity=ida_hexrays.MMAT_PREOPTIMIZED,
    )
    source.get_mblock(0).type = int(ida_hexrays.BLT_1WAY)
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
        return_ea,
        source,
        ((return_ea, return_ea + 1),),
    )
    roots = detached_handler_island.materialize_detached_snippet_templates(
        destination,
        function_ea,
        (return_ea,),
        allow_raw_preopt_calls=True,
    )
    imported_return = destination.get_mblock(roots[return_ea])
    assert int(imported_return.tail.opcode) == int(ida_hexrays.m_ret)
    assert int(imported_return.type) == int(ida_hexrays.BLT_0WAY)
    assert tuple(imported_return.succset) == ()


def test_import_abstains_from_nonreturn_stop_template(monkeypatch) -> None:
    _install_runtime_fakes(monkeypatch)
    function_ea = 0xB000
    target_ea = 0x3300
    source = _MBA(
        (
            _Block(
                0,
                target_ea,
                (_Instruction(ida_hexrays.m_nop, target_ea),),
            ),
        ),
        maturity=ida_hexrays.MMAT_PREOPTIMIZED,
    )
    source.get_mblock(0).type = int(ida_hexrays.BLT_STOP)
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
        ((target_ea, target_ea + 1),),
    )
    original_qty = destination.qty

    roots = detached_handler_island.materialize_detached_snippet_templates(
        destination,
        function_ea,
        (target_ea,),
        allow_raw_preopt_calls=True,
    )

    assert roots == {}
    assert destination.qty == original_qty
