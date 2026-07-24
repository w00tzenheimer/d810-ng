"""Runtime contracts for importing detached microcode snippets."""

from __future__ import annotations

import copy
from dataclasses import replace
from enum import Enum
from types import SimpleNamespace

import ida_hexrays
import pytest

from d810.hexrays.mutation import detached_handler_island
from d810.hexrays.mutation import cfg_verify
from d810.hexrays.ir.mba_identity_index import MbaBlockIdentityIndex
from d810.hexrays.mutation.mba_mutation_events import MbaMutationGateway
from d810.ir.block_identity import (
    BlockHandleProvenance,
    NativeEaInterval,
    StableBlockIdentity,
)
from d810.transforms.fragment_plan import (
    FragmentBlock,
    FragmentBlockMaterialization,
    FragmentBlockRole,
    FragmentComputedBranchNormalization,
    FragmentEdge,
    FragmentImportedConditionalSelectEnvelope,
    FragmentNativeBody,
    FragmentOperation,
    FragmentStoragePredicateMaterialization,
)
from d810.ir.semantic_edge import SemanticEdgeRole
from d810.ir.semantics import PredicateKind
from d810.ir.storage_identity import StorageIdentity, StorageIdentityKind
from tests.native_preanalysis import make_native_key
from tests.system.runtime.mutation_gateway import make_mutation_gateway

NATIVE_KEY = make_native_key()


class _Operand:
    def __init__(
        self,
        operand_type: int = ida_hexrays.mop_z,
        *,
        size: int = 4,
        stack_offset: int | None = None,
        lvar_index: int | None = None,
        lvar_offset: int = 0,
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
        self.l = (
            SimpleNamespace(idx=int(lvar_index), off=int(lvar_offset))
            if lvar_index is not None
            else None
        )
        self.a = address
        self.d = nested
        self.f = SimpleNamespace(args=list(arguments))
        self.b = int(block_ref)
        self.r = int(register)
        self.g = int(target_ea)
        self.nnn = SimpleNamespace(value=int(value or 0))

    def make_stkvar(self, mba: object, stack_offset: int) -> None:
        self.t = int(ida_hexrays.mop_S)
        self.s = SimpleNamespace(off=int(stack_offset), mba=mba)

    def make_blkref(self, serial: int) -> None:
        self.t = int(ida_hexrays.mop_b)
        self.b = int(serial)

    def make_reg(self, register: int, size: int) -> None:
        self.t = int(ida_hexrays.mop_r)
        self.r = int(register)
        self.size = int(size)

    def make_number(self, value: int, size: int, _ea: int) -> None:
        self.t = int(ida_hexrays.mop_n)
        self.nnn = SimpleNamespace(value=int(value))
        self.size = int(size)

    def create_from_insn(self, instruction: "_Instruction") -> None:
        self.t = int(ida_hexrays.mop_d)
        self.d = copy.deepcopy(instruction)

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
        self.end = max(
            (int(instruction.ea) + 1 for instruction in instructions),
            default=int(start_ea) + 1,
        )
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

    def insert_block(self, destination_serial: int) -> _Block:
        destination_serial = int(destination_serial)
        for block in self.blocks[destination_serial:]:
            block.serial += 1
        for block in self.blocks:
            block.succset[:] = [
                int(serial) + (int(serial) >= destination_serial)
                for serial in block.succset
            ]
            block.predset[:] = [
                int(serial) + (int(serial) >= destination_serial)
                for serial in block.predset
            ]
        inserted = _Block(destination_serial, self.entry_ea, ())
        inserted.owner = self
        self.blocks.insert(destination_serial, inserted)
        return inserted

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


def _install_runtime_fakes(monkeypatch) -> list[tuple[object, int, int]]:
    from d810.hexrays.mutation.deferred_modifier import DeferredGraphModifier

    created: list[tuple[object, int, int]] = []

    def create_standalone_block(
        modifier: DeferredGraphModifier,
        *,
        ref_serial: int,
        blk_ins: list[object] | tuple[object, ...] | None = None,
        target_serial: int | None = None,
        is_0_way: bool = False,
        verify: bool = True,
        stable_identity: object | None = None,
        handle_provenance: BlockHandleProvenance = BlockHandleProvenance.NATIVE,
    ) -> int:
        assert ref_serial == 0
        assert not blk_ins
        assert target_serial is None
        assert is_0_way is True
        assert verify is False
        mba = modifier.mba
        for prior_mba, prior_serial, _anchor_ea in created:
            if prior_mba is not mba:
                continue
            prior = mba.get_mblock(prior_serial)
            assert int(prior.flags) & int(ida_hexrays.MBL_FAKE)
            assert int(prior.start) == int(mba.entry_ea)
            assert int(prior.end) == int(mba.entry_ea) + 1
        old_qty = int(mba.qty)
        serial = mba.qty
        anchor_ea = 0xF00000 + serial
        block = _Block(
            serial,
            anchor_ea,
            (_Instruction(ida_hexrays.m_nop, anchor_ea),),
        )
        mba.append_block(block)
        if modifier._mutation_gateway is not None:
            handle = (
                None
                if stable_identity is None
                else modifier._mutation_gateway.identity_index.create_native_handle(
                    stable_identity,
                    provenance=handle_provenance,
                )
            )
            modifier._record_serial_insertion(
                serial,
                old_qty,
                created=handle,
            )
        created.append((mba, serial, anchor_ea))
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
        "_PREOPT_UNION_SNIPPET_TEMPLATES",
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
        "_IMPORTED_NATIVE_BLOCK_RANGES",
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


class _NativeBodyPlan:
    def __init__(
        self,
        blocks: tuple[FragmentBlock, ...],
        operations: tuple[FragmentOperation, ...] = (),
    ) -> None:
        self.plan_id = "native-body-runtime-test"
        self.native_key = NATIVE_KEY
        self._blocks = {block.block_id: block for block in blocks}
        self.operations = tuple(operations)

    def block(self, block_id: str) -> FragmentBlock:
        return self._blocks[str(block_id)]


class _NativeBodyStagingContext:
    def __init__(self, mba: _MBA, plan: _NativeBodyPlan) -> None:
        self.mba = mba
        self.plan = plan
        self.staged_block_ids: list[str] = []
        self.populated_block_ids: list[str] = []
        self.blocks: dict[str, _Block] = {}
        self.instruction_origins: dict[tuple[str, int], int] = {}

    def stage_block(self, block_id: str) -> None:
        block_id = str(block_id)
        assert block_id not in self.blocks
        block = _Block(self.mba.qty, self.mba.entry_ea, ())
        self.mba.append_block(block)
        self.staged_block_ids.append(block_id)
        self.blocks[block_id] = block

    def populate_block(
        self,
        *,
        block_id: str,
        instructions: tuple[tuple[int, _Instruction], ...],
        block_flags: int,
    ) -> None:
        block_id = str(block_id)
        assert block_id in self.blocks
        assert block_id not in self.populated_block_ids
        block = self.blocks[block_id]
        assert block.head is None
        assert block.tail is None
        assert int(block.nsucc()) == 0
        assert int(block.npred()) == 0
        for native_ea, instruction in instructions:
            live_ea = int(self.mba.alloc_fict_ea(int(native_ea)))
            instruction.setaddr(live_ea)
            block.insert_into_block(instruction, block.tail)
            self.bind_instruction_origin(
                block_id=block_id,
                live_ea=live_ea,
                native_ea=int(native_ea),
            )
        block.type = int(ida_hexrays.BLT_0WAY)
        block.flags = (
            int(block_flags) & int(ida_hexrays.MBL_PUSH)
        ) | int(ida_hexrays.MBL_KEEP) | int(ida_hexrays.MBL_FAKE)
        block.start = int(self.mba.entry_ea)
        block.end = int(self.mba.entry_ea) + 1
        block.mark_lists_dirty()
        self.mba.mark_chains_dirty()
        self.populated_block_ids.append(block_id)

    def bind_instruction_origin(
        self,
        *,
        block_id: str,
        live_ea: int,
        native_ea: int,
    ) -> None:
        key = (str(block_id), int(live_ea))
        assert key not in self.instruction_origins
        self.instruction_origins[key] = int(native_ea)


def _prepare_and_stage_native_body(
    materializer,
    *,
    context: _NativeBodyStagingContext,
    native_body: FragmentNativeBody,
) -> None:
    preparation = materializer.prepare_native_body(
        plan=context.plan,
        native_body=native_body,
    )
    materializer.stage_native_body(
        context=context,
        native_body=native_body,
        preparation=preparation,
    )


def _imported_fragment_block(
    block_id: str,
    body_id: str,
    start_ea: int,
    end_ea: int,
) -> FragmentBlock:
    return FragmentBlock(
        block_id=block_id,
        role=FragmentBlockRole.IMPORTED,
        materialization=FragmentBlockMaterialization.IMPORT_NATIVE,
        semantic_anchor_ea=int(start_ea),
        stable_identity=StableBlockIdentity.from_intervals(
            (NativeEaInterval(int(start_ea), int(end_ea)),),
            native_key=NATIVE_KEY,
            exact_instruction_eas=(int(start_ea),),
        ),
        native_body_id=body_id,
    )


def _single_block_native_body_runtime(
    *,
    function_ea: int,
    entry_ea: int,
    opcode: int,
    destination_maturity: int,
) -> tuple[_MBA, FragmentNativeBody, _NativeBodyStagingContext]:
    source = _MBA(
        (
            _Block(
                0,
                entry_ea,
                (_Instruction(opcode, entry_ea),),
            ),
        ),
        maturity=ida_hexrays.MMAT_PREOPTIMIZED,
    )
    assert detached_handler_island.capture_preopt_union_snippet_template(
        function_ea,
        entry_ea,
        source,
        ((entry_ea, entry_ea + 1),),
        owned_block_entry_eas=(entry_ea,),
    )
    destination = _MBA(
        (
            _Block(
                0,
                function_ea,
                (_Instruction(ida_hexrays.m_nop, function_ea),),
            ),
        ),
        maturity=destination_maturity,
    )
    body_id = f"native-body:single:{entry_ea:X}"
    imported = _imported_fragment_block(
        "imported-single",
        body_id,
        entry_ea,
        entry_ea + 1,
    )
    native_body = FragmentNativeBody(
        body_id=body_id,
        block_ids=(imported.block_id,),
        entry_block_ids=(imported.block_id,),
        terminal_block_ids=(),
        native_ranges=(NativeEaInterval(entry_ea, entry_ea + 1),),
        proof_ids=("proof:single",),
    )
    context = _NativeBodyStagingContext(
        destination,
        _NativeBodyPlan(
            (imported,),
            operations=(
                FragmentOperation(
                    operation_id="native-body-single-edge",
                    source_block_id=imported.block_id,
                    edges=(
                        FragmentEdge(
                            role=SemanticEdgeRole.DIRECT,
                            target_block_id=imported.block_id,
                        ),
                    ),
                ),
            ),
        ),
    )
    return destination, native_body, context


def test_preopt_native_body_materializer_populates_only_unpublished_bodies(
    monkeypatch,
) -> None:
    _install_runtime_fakes(monkeypatch)
    function_ea = 0xB000
    entry_ea = 0x3300
    terminal_ea = 0x3304
    source = _MBA(
        (
            _Block(
                0,
                entry_ea,
                (_Instruction(ida_hexrays.m_mov, entry_ea),),
                (1,),
            ),
            _Block(
                1,
                terminal_ea,
                (_Instruction(ida_hexrays.m_ret, terminal_ea),),
            ),
        ),
        maturity=ida_hexrays.MMAT_PREOPTIMIZED,
    )
    source.get_mblock(0).type = int(ida_hexrays.BLT_1WAY)
    assert detached_handler_island.capture_preopt_union_snippet_template(
        function_ea,
        entry_ea,
        source,
        ((entry_ea, terminal_ea + 1),),
        owned_block_entry_eas=(entry_ea, terminal_ea),
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
    body_id = "native-body:test"
    entry_block = _imported_fragment_block(
        "imported-entry",
        body_id,
        entry_ea,
        terminal_ea,
    )
    terminal_block = _imported_fragment_block(
        "imported-terminal",
        body_id,
        terminal_ea,
        terminal_ea + 1,
    )
    native_body = FragmentNativeBody(
        body_id=body_id,
        block_ids=(entry_block.block_id, terminal_block.block_id),
        entry_block_ids=(entry_block.block_id,),
        terminal_block_ids=(terminal_block.block_id,),
        native_ranges=(NativeEaInterval(entry_ea, terminal_ea + 1),),
        proof_ids=("proof:preopt-union",),
    )
    context = _NativeBodyStagingContext(
        destination,
        _NativeBodyPlan(
            (entry_block, terminal_block),
            operations=(
                FragmentOperation(
                    operation_id="native-body-entry-edge",
                    source_block_id=entry_block.block_id,
                    edges=(
                        FragmentEdge(
                            role=SemanticEdgeRole.DIRECT,
                            target_block_id=terminal_block.block_id,
                        ),
                    ),
                ),
            ),
        ),
    )
    materializer = (
        detached_handler_island.PreoptUnionSemanticNativeBodyMaterializer(
            mba=destination,
            function_ea=function_ea,
        )
    )

    _prepare_and_stage_native_body(
        materializer,
        context=context,
        native_body=native_body,
    )

    assert context.staged_block_ids == [
        entry_block.block_id,
        terminal_block.block_id,
    ]
    assert context.populated_block_ids == [
        entry_block.block_id,
        terminal_block.block_id,
    ]
    assert tuple(context.blocks[entry_block.block_id].succset) == ()
    assert tuple(context.blocks[terminal_block.block_id].succset) == ()
    assert int(context.blocks[entry_block.block_id].type) == int(
        ida_hexrays.BLT_0WAY
    )
    assert int(context.blocks[terminal_block.block_id].type) == int(
        ida_hexrays.BLT_0WAY
    )
    imported_entry = context.blocks[entry_block.block_id].instructions()
    imported_terminal = context.blocks[terminal_block.block_id].instructions()
    assert tuple(instruction.opcode for instruction in imported_entry) == (
        ida_hexrays.m_mov,
    )
    assert tuple(instruction.opcode for instruction in imported_terminal) == (
        ida_hexrays.m_ret,
    )
    assert all(
        int(instruction.ea) not in {entry_ea, terminal_ea}
        for instruction in (*imported_entry, *imported_terminal)
    )
    assert set(context.instruction_origins.values()) == {entry_ea, terminal_ea}
    assert destination.verify_calls == 0


def test_calls_native_body_materializer_populates_call_free_unpublished_body(
    monkeypatch,
) -> None:
    _install_runtime_fakes(monkeypatch)
    function_ea = 0xB000
    entry_ea = 0x3340
    destination, native_body, context = _single_block_native_body_runtime(
        function_ea=function_ea,
        entry_ea=entry_ea,
        opcode=ida_hexrays.m_mov,
        destination_maturity=ida_hexrays.MMAT_CALLS,
    )

    _prepare_and_stage_native_body(
        detached_handler_island.CallsSemanticNativeBodyMaterializer(
            mba=destination,
            function_ea=function_ea,
        ),
        context=context,
        native_body=native_body,
    )

    assert context.staged_block_ids == ["imported-single"]
    assert context.populated_block_ids == ["imported-single"]
    imported = context.blocks["imported-single"]
    assert tuple(instruction.opcode for instruction in imported.instructions()) == (
        ida_hexrays.m_mov,
    )
    assert imported.dirty == 1
    assert destination.chains_dirty == 1
    assert destination.verify_calls == 0


def test_calls_native_body_rejects_returns_before_staging(
    monkeypatch,
) -> None:
    _install_runtime_fakes(monkeypatch)
    function_ea = 0xB000
    destination, native_body, context = _single_block_native_body_runtime(
        function_ea=function_ea,
        entry_ea=0x3350,
        opcode=ida_hexrays.m_ret,
        destination_maturity=ida_hexrays.MMAT_CALLS,
    )
    native_body = replace(
        native_body,
        terminal_block_ids=("imported-single",),
    )
    context.plan = _NativeBodyPlan(
        (context.plan.block("imported-single"),),
    )

    with pytest.raises(
        detached_handler_island.SemanticFragmentBackendRejected,
        match="CALLS native body cannot contain a return",
    ):
        _prepare_and_stage_native_body(
            detached_handler_island.CallsSemanticNativeBodyMaterializer(
                mba=destination,
                function_ea=function_ea,
            ),
            context=context,
            native_body=native_body,
        )

    assert context.staged_block_ids == []
    assert context.populated_block_ids == []
    assert destination.qty == 1
    assert destination.chains_dirty == 0


def test_calls_native_body_rejects_other_maturity_before_staging(
    monkeypatch,
) -> None:
    _install_runtime_fakes(monkeypatch)
    function_ea = 0xB000
    destination, native_body, context = _single_block_native_body_runtime(
        function_ea=function_ea,
        entry_ea=0x3360,
        opcode=ida_hexrays.m_mov,
        destination_maturity=ida_hexrays.MMAT_GLBOPT1,
    )

    with pytest.raises(
        detached_handler_island.SemanticFragmentBackendRejected,
        match="CALLS native body requires an MMAT_CALLS destination MBA",
    ):
        _prepare_and_stage_native_body(
            detached_handler_island.CallsSemanticNativeBodyMaterializer(
                mba=destination,
                function_ea=function_ea,
            ),
            context=context,
            native_body=native_body,
        )

    assert context.staged_block_ids == []
    assert context.populated_block_ids == []
    assert destination.qty == 1
    assert destination.chains_dirty == 0


def test_preopt_union_call_companion_reports_both_mismatched_inventories(
    monkeypatch,
) -> None:
    _install_runtime_fakes(monkeypatch)
    function_ea = 0xB000
    union_target_ea = 0x3300
    native_range = (0x3340, 0x3380)
    first_call_ea = 0x3350
    second_call_ea = 0x3360
    invented_call_ea = 0x3370
    signature = detached_handler_island._DetachedCallSignature(
        opcode=ida_hexrays.m_call,
        direct_callee_ea=0x500000,
        has_arglist=True,
    )
    raw_template = object()
    monkeypatch.setitem(
        detached_handler_island._PREOPT_UNION_SNIPPET_TEMPLATES,
        (function_ea, union_target_ea),
        raw_template,
    )
    monkeypatch.setattr(
        detached_handler_island,
        "_template_call_signatures_in_range",
        lambda template, candidate_range: (
            {
                first_call_ea: signature,
                second_call_ea: signature,
            },
            None,
        )
        if template is raw_template and candidate_range == native_range
        else ({}, None),
    )
    calls_mba = SimpleNamespace(maturity=ida_hexrays.MMAT_CALLS)
    monkeypatch.setattr(
        detached_handler_island,
        "_mba_call_signatures_in_range",
        lambda mba, candidate_range: (
            {
                first_call_ea: signature,
                invented_call_ea: signature,
            },
            None,
        )
        if mba is calls_mba and candidate_range == native_range
        else ({}, None),
    )

    result = (
        detached_handler_island.capture_preopt_union_call_companion_template(
            function_ea,
            union_target_ea,
            native_range[0],
            calls_mba,
            native_range,
            calls_native_ranges=(native_range,),
        )
    )

    assert not result.captured
    assert result.reason == "call_ea_set_mismatch"
    assert result.call_eas == (first_call_ea, second_call_ea)
    assert result.observed_call_eas == (first_call_ea, invented_call_ea)
    assert result.mismatch_ea == second_call_ea


def test_preopt_union_call_companion_captures_only_calls_analysis_ranges(
    monkeypatch,
) -> None:
    _install_runtime_fakes(monkeypatch)
    function_ea = 0xB000
    union_target_ea = 0x3300
    native_range = (0x3340, 0x3380)
    calls_native_ranges = ((0x3340, 0x337E),)
    call_ea = 0x3350
    signature = detached_handler_island._DetachedCallSignature(
        opcode=ida_hexrays.m_call,
        direct_callee_ea=0x500000,
        has_arglist=True,
    )
    raw_template = object()
    monkeypatch.setitem(
        detached_handler_island._PREOPT_UNION_SNIPPET_TEMPLATES,
        (function_ea, union_target_ea),
        raw_template,
    )
    inventory_queries: list[tuple[str, tuple[int, int]]] = []
    monkeypatch.setattr(
        detached_handler_island,
        "_template_call_signatures_in_range",
        lambda template, candidate_range: (
            inventory_queries.append(("preopt", candidate_range))
            or ({call_ea: signature}, None)
        ),
    )
    calls_mba = SimpleNamespace(maturity=ida_hexrays.MMAT_CALLS)
    monkeypatch.setattr(
        detached_handler_island,
        "_mba_call_signatures_in_range",
        lambda mba, candidate_range: (
            inventory_queries.append(("calls", candidate_range))
            or ({call_ea: signature}, None)
        ),
    )
    captured_ranges: list[tuple[tuple[int, int], ...]] = []
    monkeypatch.setattr(
        detached_handler_island,
        "capture_detached_replacement_snippet_template",
        lambda _function_ea, _target_ea, _mba, ranges, **_kwargs: (
            captured_ranges.append(ranges) or True
        ),
    )
    monkeypatch.setattr(
        detached_handler_island,
        "_analyzed_replacement_calls_by_ea",
        lambda _function_ea, _target_ea: {call_ea: object()},
    )

    result = (
        detached_handler_island.capture_preopt_union_call_companion_template(
            function_ea,
            union_target_ea,
            native_range[0],
            calls_mba,
            native_range,
            calls_native_ranges=calls_native_ranges,
        )
    )

    assert result.captured
    assert inventory_queries == [
        ("preopt", native_range),
        ("calls", native_range),
    ]
    assert captured_ranges == [calls_native_ranges]


def _calls_native_body_with_raw_call(
    monkeypatch,
    *,
    capture_companion: bool,
):
    _install_runtime_fakes(monkeypatch)
    function_ea = 0xB000
    entry_ea = 0x3340
    first_push_ea = 0x3344
    second_push_ea = 0x3346
    call_ea = 0x3348
    continuation_ea = 0x3350
    callee_ea = 0x500000
    raw_entry = _Block(
        0,
        entry_ea,
        (
            _Instruction(
                ida_hexrays.m_push,
                first_push_ea,
                left=_Operand(ida_hexrays.mop_n, value=1),
            ),
            _Instruction(
                ida_hexrays.m_push,
                second_push_ea,
                left=_Operand(ida_hexrays.mop_n, value=2),
            ),
            _Instruction(
                ida_hexrays.m_call,
                call_ea,
                left=_Operand(ida_hexrays.mop_v, target_ea=callee_ea),
            ),
        ),
        (1,),
    )
    raw_entry.type = int(ida_hexrays.BLT_1WAY)
    raw_entry.flags = int(ida_hexrays.MBL_PUSH)
    raw_continuation = _Block(
        1,
        continuation_ea,
        (_Instruction(ida_hexrays.m_nop, continuation_ea),),
        (1,),
    )
    raw_continuation.type = int(ida_hexrays.BLT_1WAY)
    raw_source = _MBA(
        (raw_entry, raw_continuation),
        maturity=ida_hexrays.MMAT_PREOPTIMIZED,
    )
    component_range = (entry_ea, continuation_ea + 1)
    assert detached_handler_island.capture_preopt_union_snippet_template(
        function_ea,
        entry_ea,
        raw_source,
        (component_range,),
        owned_block_entry_eas=(entry_ea, continuation_ea),
    )

    if capture_companion:
        call_arguments = _Operand(
            ida_hexrays.mop_f,
            arguments=(
                _Operand(ida_hexrays.mop_n, value=1),
                _Operand(ida_hexrays.mop_n, value=2),
            ),
        )
        call_arguments.f.call_spd = 0x20
        call_arguments.f.stkargs_top = 0x28
        analyzed_call = _Instruction(
            ida_hexrays.m_call,
            call_ea,
            left=_Operand(ida_hexrays.mop_v, target_ea=callee_ea),
            dest=call_arguments,
        )
        analyzed_owner = _Instruction(
            ida_hexrays.m_mov,
            call_ea,
            left=_Operand(ida_hexrays.mop_d, nested=analyzed_call),
            dest=_Operand(ida_hexrays.mop_r, register=7),
        )
        calls_entry = _Block(0, entry_ea, (analyzed_owner,), (1,))
        calls_entry.type = int(ida_hexrays.BLT_1WAY)
        calls_continuation = _Block(
            1,
            continuation_ea,
            (_Instruction(ida_hexrays.m_nop, continuation_ea),),
            (1,),
        )
        calls_continuation.type = int(ida_hexrays.BLT_1WAY)
        calls_source = _MBA(
            (calls_entry, calls_continuation),
            maturity=ida_hexrays.MMAT_CALLS,
        )
        result = (
            detached_handler_island.capture_preopt_union_call_companion_template(
                function_ea,
                entry_ea,
                entry_ea,
                calls_source,
                component_range,
                calls_native_ranges=(component_range,),
                owned_block_entry_eas=(entry_ea, continuation_ea),
            )
        )
        assert result.captured is True
        assert result.call_eas == (call_ea,)

    destination = _MBA(
        (
            _Block(
                0,
                function_ea,
                (_Instruction(ida_hexrays.m_nop, function_ea),),
            ),
        ),
        maturity=ida_hexrays.MMAT_CALLS,
        ida_to_vd_delta=0x80,
    )
    body_id = "native-body:call-companion"
    entry_block = _imported_fragment_block(
        "imported-call-entry",
        body_id,
        entry_ea,
        continuation_ea,
    )
    continuation_block = _imported_fragment_block(
        "imported-call-continuation",
        body_id,
        continuation_ea,
        continuation_ea + 1,
    )
    native_body = FragmentNativeBody(
        body_id=body_id,
        block_ids=(entry_block.block_id, continuation_block.block_id),
        entry_block_ids=(entry_block.block_id,),
        terminal_block_ids=(),
        native_ranges=(NativeEaInterval(*component_range),),
        proof_ids=("proof:call-companion",),
    )
    context = _NativeBodyStagingContext(
        destination,
        _NativeBodyPlan(
            (entry_block, continuation_block),
            operations=(
                FragmentOperation(
                    operation_id="native-body-call-fallthrough",
                    source_block_id=entry_block.block_id,
                    edges=(
                        FragmentEdge(
                            role=SemanticEdgeRole.CALL_FALLTHROUGH,
                            target_block_id=continuation_block.block_id,
                        ),
                    ),
                ),
                FragmentOperation(
                    operation_id="native-body-continuation",
                    source_block_id=continuation_block.block_id,
                    edges=(
                        FragmentEdge(
                            role=SemanticEdgeRole.DIRECT,
                            target_block_id=continuation_block.block_id,
                        ),
                    ),
                ),
            ),
        ),
    )
    return (
        destination,
        native_body,
        context,
        component_range,
        call_ea,
        (first_push_ea, second_push_ea),
    )


def test_calls_native_body_requests_missing_companion_before_staging(
    monkeypatch,
) -> None:
    (
        destination,
        native_body,
        context,
        component_range,
        _call_ea,
        _push_eas,
    ) = _calls_native_body_with_raw_call(
        monkeypatch,
        capture_companion=False,
    )
    requested: list[tuple[tuple[int, int], ...]] = []
    materializer = detached_handler_island.CallsSemanticNativeBodyMaterializer(
        mba=destination,
        function_ea=0xB000,
        request_call_companions=lambda ranges: requested.append(ranges) or True,
    )

    with pytest.raises(
        detached_handler_island.SemanticFragmentBackendRejected,
        match="CALLS companion preparation requested",
    ):
        materializer.prepare_native_body(
            plan=context.plan,
            native_body=native_body,
        )

    assert requested == [((int(component_range[0]), int(component_range[1])),)]
    assert context.staged_block_ids == []
    assert context.populated_block_ids == []
    assert destination.qty == 1
    assert destination.chains_dirty == 0


def test_calls_native_body_uses_exact_companion_and_removes_raw_pushes(
    monkeypatch,
) -> None:
    (
        destination,
        native_body,
        context,
        _component_range,
        call_ea,
        push_eas,
    ) = _calls_native_body_with_raw_call(
        monkeypatch,
        capture_companion=True,
    )
    materializer = detached_handler_island.CallsSemanticNativeBodyMaterializer(
        mba=destination,
        function_ea=0xB000,
    )

    preparation = materializer.prepare_native_body(
        plan=context.plan,
        native_body=native_body,
    )

    assert destination.qty == 1
    assert context.staged_block_ids == []
    materializer.stage_native_body(
        context=context,
        native_body=native_body,
        preparation=preparation,
    )

    imported = context.blocks["imported-call-entry"]
    rows = imported.instructions()
    assert tuple(
        context.instruction_origins[
            ("imported-call-entry", int(instruction.ea))
        ]
        for instruction in rows
    ) == (call_ea,)
    assert not set(push_eas).intersection(
        context.instruction_origins.values()
    )
    assert len(rows) == 1
    owner = rows[0]
    assert int(owner.opcode) == int(ida_hexrays.m_mov)
    assert int(owner.l.t) == int(ida_hexrays.mop_d)
    analyzed_call = owner.l.d
    assert int(analyzed_call.opcode) == int(ida_hexrays.m_call)
    assert int(analyzed_call.d.t) == int(ida_hexrays.mop_f)
    assert len(analyzed_call.d.f.args) == 2
    assert int(analyzed_call.d.f.call_spd) == 0x78
    assert int(analyzed_call.d.f.stkargs_top) == 0x80
    assert not int(imported.flags) & int(ida_hexrays.MBL_PUSH)
    assert destination.verify_calls == 0


def test_calls_native_body_reports_insufficient_destination_stack_window(
    monkeypatch,
) -> None:
    (
        destination,
        native_body,
        context,
        _component_range,
        call_ea,
        _push_eas,
    ) = _calls_native_body_with_raw_call(
        monkeypatch,
        capture_companion=True,
    )
    destination.ida_to_vd_delta = 4
    materializer = detached_handler_island.CallsSemanticNativeBodyMaterializer(
        mba=destination,
        function_ea=0xB000,
    )

    with pytest.raises(
        detached_handler_island.SemanticFragmentBackendRejected,
        match="CALLS companion stack window cannot be rebound",
    ) as caught:
        materializer.prepare_native_body(
            plan=context.plan,
            native_body=native_body,
        )

    error = caught.value
    assert error.reason_code == (
        "calls_companion_destination_stack_window_insufficient"
    )
    assert error.anchor_ea == call_ea
    assert error.payload == {
        "argument_count": 2,
        "destination_frregs": 0,
        "destination_frsize": 0,
        "destination_fullsize": None,
        "destination_minstkref": None,
        "destination_stack_zero_vd": 4,
        "destination_stacksize": 0,
        "destination_tmpstk_size": None,
        "failed_invariant": (
            "destination_stack_zero_vd >= source_stack_span"
        ),
        "required_stack_growth": 4,
        "source_call_spd": 0x20,
        "source_stack_span": 8,
        "source_stkargs_top": 0x28,
    }
    assert context.staged_block_ids == []
    assert context.populated_block_ids == []
    assert destination.qty == 1


def test_preopt_native_body_rejects_non_control_block_refs_before_staging(
    monkeypatch,
) -> None:
    _install_runtime_fakes(monkeypatch)
    function_ea = 0xB000
    entry_ea = 0x3400
    source = _MBA(
        (
            _Block(
                0,
                entry_ea,
                (
                    _Instruction(
                        ida_hexrays.m_mov,
                        entry_ea,
                        left=_Operand(ida_hexrays.mop_b, block_ref=7),
                    ),
                ),
            ),
        ),
        maturity=ida_hexrays.MMAT_PREOPTIMIZED,
    )
    assert detached_handler_island.capture_preopt_union_snippet_template(
        function_ea,
        entry_ea,
        source,
        ((entry_ea, entry_ea + 1),),
        owned_block_entry_eas=(entry_ea,),
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
    body_id = "native-body:block-ref"
    imported = _imported_fragment_block(
        "imported-block-ref",
        body_id,
        entry_ea,
        entry_ea + 1,
    )
    native_body = FragmentNativeBody(
        body_id=body_id,
        block_ids=(imported.block_id,),
        entry_block_ids=(imported.block_id,),
        terminal_block_ids=(),
        native_ranges=(NativeEaInterval(entry_ea, entry_ea + 1),),
        proof_ids=("proof:block-ref",),
    )
    context = _NativeBodyStagingContext(
        destination,
        _NativeBodyPlan((imported,)),
    )

    with pytest.raises(
        detached_handler_island.SemanticFragmentBackendRejected,
        match="block reference",
    ):
        _prepare_and_stage_native_body(
            detached_handler_island.PreoptUnionSemanticNativeBodyMaterializer(
                mba=destination,
                function_ea=function_ea,
            ),
            context=context,
            native_body=native_body,
        )

    assert context.staged_block_ids == []
    assert destination.qty == 1


def test_preopt_native_body_rejects_terminal_without_return_before_staging(
    monkeypatch,
) -> None:
    _install_runtime_fakes(monkeypatch)
    function_ea = 0xB000
    entry_ea = 0x3500
    source = _MBA(
        (
            _Block(
                0,
                entry_ea,
                (_Instruction(ida_hexrays.m_nop, entry_ea),),
            ),
        ),
        maturity=ida_hexrays.MMAT_PREOPTIMIZED,
    )
    assert detached_handler_island.capture_preopt_union_snippet_template(
        function_ea,
        entry_ea,
        source,
        ((entry_ea, entry_ea + 1),),
        owned_block_entry_eas=(entry_ea,),
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
    body_id = "native-body:terminal"
    imported = _imported_fragment_block(
        "imported-terminal",
        body_id,
        entry_ea,
        entry_ea + 1,
    )
    native_body = FragmentNativeBody(
        body_id=body_id,
        block_ids=(imported.block_id,),
        entry_block_ids=(imported.block_id,),
        terminal_block_ids=(imported.block_id,),
        native_ranges=(NativeEaInterval(entry_ea, entry_ea + 1),),
        proof_ids=("proof:terminal",),
    )
    context = _NativeBodyStagingContext(
        destination,
        _NativeBodyPlan((imported,)),
    )

    with pytest.raises(
        detached_handler_island.SemanticFragmentBackendRejected,
        match="terminal return",
    ):
        _prepare_and_stage_native_body(
            detached_handler_island.PreoptUnionSemanticNativeBodyMaterializer(
                mba=destination,
                function_ea=function_ea,
            ),
            context=context,
            native_body=native_body,
        )

    assert context.staged_block_ids == []
    assert destination.qty == 1


def test_preopt_native_body_rejects_unowned_topology_before_staging(
    monkeypatch,
) -> None:
    _install_runtime_fakes(monkeypatch)
    function_ea = 0xB000
    entry_ea = 0x3600
    source = _MBA(
        (
            _Block(
                0,
                entry_ea,
                (_Instruction(ida_hexrays.m_mov, entry_ea),),
            ),
        ),
        maturity=ida_hexrays.MMAT_PREOPTIMIZED,
    )
    assert detached_handler_island.capture_preopt_union_snippet_template(
        function_ea,
        entry_ea,
        source,
        ((entry_ea, entry_ea + 1),),
        owned_block_entry_eas=(entry_ea,),
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
    body_id = "native-body:unowned-topology"
    imported = _imported_fragment_block(
        "imported-nonterminal",
        body_id,
        entry_ea,
        entry_ea + 1,
    )
    native_body = FragmentNativeBody(
        body_id=body_id,
        block_ids=(imported.block_id,),
        entry_block_ids=(imported.block_id,),
        terminal_block_ids=(),
        native_ranges=(NativeEaInterval(entry_ea, entry_ea + 1),),
        proof_ids=("proof:unowned-topology",),
    )
    context = _NativeBodyStagingContext(
        destination,
        _NativeBodyPlan((imported,)),
    )

    with pytest.raises(
        detached_handler_island.SemanticFragmentBackendRejected,
        match=(
            "topology.*block='imported-nonterminal'@0x3600.*"
            "operations=0.*expected_operations=1"
        ),
    ):
        _prepare_and_stage_native_body(
            detached_handler_island.PreoptUnionSemanticNativeBodyMaterializer(
                mba=destination,
                function_ea=function_ea,
            ),
            context=context,
            native_body=native_body,
        )

    assert context.staged_block_ids == []
    assert destination.qty == 1


@pytest.mark.parametrize(
    ("semantic_predicate", "expected_branch_opcode"),
    (
        (PredicateKind.EQ, ida_hexrays.m_jnz),
        (PredicateKind.NE, ida_hexrays.m_jz),
        (PredicateKind.SLT, None),
    ),
)
def test_preopt_native_body_normalizes_proof_owned_computed_branch_before_staging(
    monkeypatch,
    semantic_predicate,
    expected_branch_opcode,
) -> None:
    _install_runtime_fakes(monkeypatch)
    function_ea = 0xB000
    source_ea = 0x3600
    condition_producer_ea = 0x3604
    predicate_ea = 0x3608
    unresolved_transfer_ea = 0x3610
    predicate_register = 55
    source = _MBA(
        (
            _Block(
                0,
                source_ea,
                (
                    _Instruction(
                        ida_hexrays.m_setz,
                        condition_producer_ea,
                        dest=_Operand(
                            ida_hexrays.mop_r,
                            register=predicate_register,
                            size=1,
                        ),
                    ),
                    _Instruction(
                        ida_hexrays.m_xdu,
                        predicate_ea,
                        left=_Operand(
                            ida_hexrays.mop_r,
                            register=predicate_register,
                            size=1,
                        ),
                        dest=_Operand(
                            ida_hexrays.mop_r,
                            register=7,
                            size=4,
                        ),
                    ),
                    _Instruction(
                        ida_hexrays.m_ijmp,
                        unresolved_transfer_ea,
                        left=_Operand(
                            ida_hexrays.mop_r,
                            register=7,
                            size=4,
                        ),
                    ),
                ),
            ),
        ),
        maturity=ida_hexrays.MMAT_PREOPTIMIZED,
    )
    assert detached_handler_island.capture_preopt_union_snippet_template(
        function_ea,
        source_ea,
        source,
        ((source_ea, unresolved_transfer_ea + 1),),
        owned_block_entry_eas=(source_ea,),
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
    body_id = "native-body:computed-branch"
    imported = _imported_fragment_block(
        "imported-computed-branch",
        body_id,
        source_ea,
        unresolved_transfer_ea + 1,
    )
    operation_id = "proof:computed-branch"
    native_body = FragmentNativeBody(
        body_id=body_id,
        block_ids=(imported.block_id,),
        entry_block_ids=(imported.block_id,),
        terminal_block_ids=(),
        native_ranges=(
            NativeEaInterval(source_ea, unresolved_transfer_ea + 1),
        ),
        proof_ids=(operation_id,),
    )
    context = _NativeBodyStagingContext(
        destination,
        _NativeBodyPlan(
            (imported,),
            operations=(
                FragmentOperation(
                    operation_id=operation_id,
                    source_block_id=imported.block_id,
                    predicate_anchor_ea=predicate_ea,
                    computed_branch_normalization=(
                        FragmentComputedBranchNormalization(
                            predicate_kind=semantic_predicate,
                            normalization_start_ea=predicate_ea,
                            condition_producer_ea=condition_producer_ea,
                            unresolved_transfer_ea=unresolved_transfer_ea,
                        )
                    ),
                    edges=(
                        FragmentEdge(
                            role=SemanticEdgeRole.CONDITIONAL_TAKEN,
                            target_block_id="taken",
                        ),
                        FragmentEdge(
                            role=SemanticEdgeRole.CONDITIONAL_FALLTHROUGH,
                            target_block_id="fallthrough",
                        ),
                    ),
                ),
            ),
        ),
    )

    materializer = (
        detached_handler_island.PreoptUnionSemanticNativeBodyMaterializer(
            mba=destination,
            function_ea=function_ea,
        )
    )
    if expected_branch_opcode is None:
        with pytest.raises(
            detached_handler_island.SemanticFragmentBackendRejected,
            match="condition producer does not match",
        ):
            _prepare_and_stage_native_body(
                materializer,
                context=context,
                native_body=native_body,
            )
        assert context.staged_block_ids == []
        return

    _prepare_and_stage_native_body(
        materializer,
        context=context,
        native_body=native_body,
    )

    staged = context.blocks[imported.block_id].instructions()
    assert tuple(int(instruction.opcode) for instruction in staged) == (
        int(ida_hexrays.m_setz),
        int(expected_branch_opcode),
    )
    branch = staged[-1]
    assert int(branch.l.t) == int(ida_hexrays.mop_r)
    assert int(branch.l.r) == predicate_register
    assert int(branch.l.size) == 1
    assert int(branch.r.t) == int(ida_hexrays.mop_n)
    assert int(branch.r.nnn.value) == 0
    assert set(context.instruction_origins.values()) == {
        condition_producer_ea,
        predicate_ea,
    }


def test_preopt_native_body_materializes_storage_predicate_before_staging(
    monkeypatch,
) -> None:
    _install_runtime_fakes(monkeypatch)
    function_ea = 0xB000
    consumer_ea = 0x3700
    dispatcher_compare_ea = 0x3704
    dispatcher_select_ea = 0x3708
    unresolved_transfer_ea = 0x3710
    predicate_ida_stkoff = 0x498
    destination_stack_delta = 12
    source = _MBA(
        (
            _Block(
                0,
                consumer_ea,
                (
                    _Instruction(
                        ida_hexrays.m_mov,
                        consumer_ea,
                        left=_Operand(
                            ida_hexrays.mop_S,
                            stack_offset=0x40,
                            size=4,
                        ),
                        dest=_Operand(
                            ida_hexrays.mop_r,
                            register=12,
                            size=4,
                        ),
                    ),
                    _Instruction(
                        ida_hexrays.m_setz,
                        dispatcher_compare_ea,
                        dest=_Operand(
                            ida_hexrays.mop_r,
                            register=13,
                            size=1,
                        ),
                    ),
                    _Instruction(
                        ida_hexrays.m_mov,
                        dispatcher_select_ea,
                        left=_Operand(
                            ida_hexrays.mop_r,
                            register=12,
                            size=4,
                        ),
                        dest=_Operand(
                            ida_hexrays.mop_r,
                            register=14,
                            size=4,
                        ),
                    ),
                    _Instruction(
                        ida_hexrays.m_ijmp,
                        unresolved_transfer_ea,
                        left=_Operand(
                            ida_hexrays.mop_r,
                            register=14,
                            size=4,
                        ),
                    ),
                ),
            ),
        ),
        maturity=ida_hexrays.MMAT_PREOPTIMIZED,
    )
    assert detached_handler_island.capture_preopt_union_snippet_template(
        function_ea,
        consumer_ea,
        source,
        ((consumer_ea, unresolved_transfer_ea + 1),),
        owned_block_entry_eas=(consumer_ea,),
    )
    destination = _MBA(
        (
            _Block(
                0,
                function_ea,
                (_Instruction(ida_hexrays.m_nop, function_ea),),
            ),
        ),
        ida_to_vd_delta=destination_stack_delta,
        maturity=ida_hexrays.MMAT_PREOPTIMIZED,
    )
    body_id = "native-body:storage-predicate"
    imported = _imported_fragment_block(
        "imported-storage-predicate",
        body_id,
        consumer_ea,
        unresolved_transfer_ea + 1,
    )
    operation_id = "proof:storage-predicate"
    native_body = FragmentNativeBody(
        body_id=body_id,
        block_ids=(imported.block_id,),
        entry_block_ids=(imported.block_id,),
        terminal_block_ids=(),
        native_ranges=(
            NativeEaInterval(consumer_ea, unresolved_transfer_ea + 1),
        ),
        proof_ids=(operation_id,),
    )
    context = _NativeBodyStagingContext(
        destination,
        _NativeBodyPlan(
            (imported,),
            operations=(
                FragmentOperation(
                    operation_id=operation_id,
                    source_block_id=imported.block_id,
                    predicate_anchor_ea=consumer_ea,
                    storage_predicate_materialization=(
                        FragmentStoragePredicateMaterialization(
                            predicate_kind=PredicateKind.EQ,
                            storage_identity=StorageIdentity(
                                StorageIdentityKind.STACK,
                                predicate_ida_stkoff,
                            ),
                            width=4,
                            compare_constant=0,
                            cut_after_ea=consumer_ea,
                        )
                    ),
                    edges=(
                        FragmentEdge(
                            role=SemanticEdgeRole.CONDITIONAL_TAKEN,
                            target_block_id="taken",
                        ),
                        FragmentEdge(
                            role=SemanticEdgeRole.CONDITIONAL_FALLTHROUGH,
                            target_block_id="fallthrough",
                        ),
                    ),
                ),
            ),
        ),
    )

    _prepare_and_stage_native_body(
        detached_handler_island.PreoptUnionSemanticNativeBodyMaterializer(
            mba=destination,
            function_ea=function_ea,
        ),
        context=context,
        native_body=native_body,
    )

    staged = context.blocks[imported.block_id].instructions()
    assert tuple(int(instruction.opcode) for instruction in staged) == (
        int(ida_hexrays.m_mov),
        int(ida_hexrays.m_jz),
    )
    branch = staged[-1]
    assert int(branch.l.t) == int(ida_hexrays.mop_S)
    assert int(branch.l.s.off) == (
        predicate_ida_stkoff + destination_stack_delta
    )
    assert int(branch.l.size) == 4
    assert int(branch.r.t) == int(ida_hexrays.mop_n)
    assert int(branch.r.nnn.value) == 0
    assert int(branch.r.size) == 4
    assert set(context.instruction_origins.values()) == {consumer_ea}


@pytest.mark.parametrize(
    (
        "predicate_kind",
        "predicate_combine_opcode",
        "selected_opcode",
        "join_opcode",
        "join_flags",
        "continuation_flags",
        "normalization_succeeds",
    ),
    (
        (
            PredicateKind.EQ,
            None,
            ida_hexrays.m_mov,
            ida_hexrays.m_ijmp,
            0,
            0,
            True,
        ),
        (
            PredicateKind.EQ,
            None,
            ida_hexrays.m_add,
            ida_hexrays.m_ijmp,
            0,
            0,
            False,
        ),
        (
            PredicateKind.EQ,
            None,
            ida_hexrays.m_mov,
            ida_hexrays.m_icall,
            ida_hexrays.MBL_TCAL,
            ida_hexrays.MBL_FAKE,
            True,
        ),
        (
            PredicateKind.EQ,
            None,
            ida_hexrays.m_mov,
            ida_hexrays.m_icall,
            0,
            ida_hexrays.MBL_FAKE,
            False,
        ),
        (
            PredicateKind.EQ,
            None,
            ida_hexrays.m_mov,
            ida_hexrays.m_icall,
            ida_hexrays.MBL_TCAL | ida_hexrays.MBL_CALL,
            ida_hexrays.MBL_FAKE,
            False,
        ),
        (
            PredicateKind.EQ,
            None,
            ida_hexrays.m_mov,
            ida_hexrays.m_icall,
            ida_hexrays.MBL_TCAL,
            0,
            False,
        ),
        (
            PredicateKind.SLT,
            ida_hexrays.m_xor,
            ida_hexrays.m_mov,
            ida_hexrays.m_ijmp,
            0,
            0,
            True,
        ),
        (
            PredicateKind.SLT,
            ida_hexrays.m_or,
            ida_hexrays.m_mov,
            ida_hexrays.m_ijmp,
            0,
            0,
            False,
        ),
    ),
)
def test_preopt_native_body_normalizes_only_exact_split_conditional_select(
    monkeypatch,
    predicate_kind,
    predicate_combine_opcode,
    selected_opcode,
    join_opcode,
    join_flags,
    continuation_flags,
    normalization_succeeds,
) -> None:
    _install_runtime_fakes(monkeypatch)
    function_ea = 0xB000
    source_ea = 0x40A5CA
    predicate_ea = 0x40A5D0
    selected_ea = 0x40A5DC
    join_ea = 0x40A5DF
    unresolved_transfer_ea = 0x40A5E3
    zero_flag_register = 55
    zero_flag = _Operand(
        ida_hexrays.mop_r,
        register=zero_flag_register,
        size=1,
    )
    overflow_flag = _Operand(
        ida_hexrays.mop_r,
        register=52,
        size=1,
    )
    sign_flag = _Operand(
        ida_hexrays.mop_r,
        register=54,
        size=1,
    )
    predicate_result = zero_flag
    if predicate_combine_opcode is not None:
        predicate_result = _Operand(
            ida_hexrays.mop_d,
            nested=_Instruction(
                predicate_combine_opcode,
                selected_ea,
                left=sign_flag,
                right=overflow_flag,
            ),
            size=1,
        )
    skip_selected = _Instruction(
        ida_hexrays.m_lnot,
        selected_ea,
        left=predicate_result,
        dest=_Operand(
            ida_hexrays.mop_r,
            register=56,
            size=1,
        ),
    )
    source = _Block(
        0,
        source_ea,
        (
            _Instruction(
                ida_hexrays.m_setb,
                source_ea,
                dest=_Operand(ida_hexrays.mop_r, register=51, size=1),
            ),
            _Instruction(
                ida_hexrays.m_seto,
                source_ea,
                dest=overflow_flag,
            ),
            _Instruction(
                ida_hexrays.m_setz,
                source_ea,
                dest=zero_flag,
            ),
            _Instruction(
                ida_hexrays.m_setp,
                source_ea,
                dest=_Operand(ida_hexrays.mop_r, register=53, size=1),
            ),
            _Instruction(
                ida_hexrays.m_sets,
                source_ea,
                dest=sign_flag,
            ),
            _Instruction(ida_hexrays.m_mov, predicate_ea),
            _Instruction(ida_hexrays.m_mov, 0x40A5D6),
            _Instruction(
                ida_hexrays.m_jcnd,
                selected_ea,
                left=_Operand(
                    ida_hexrays.mop_d,
                    nested=skip_selected,
                    size=1,
                ),
                dest=_Operand(ida_hexrays.mop_b, block_ref=2),
            ),
        ),
        (1, 2),
    )
    source.type = int(ida_hexrays.BLT_2WAY)
    selected = _Block(
        1,
        selected_ea,
        (_Instruction(selected_opcode, selected_ea),),
        (2,),
    )
    selected.type = int(ida_hexrays.BLT_1WAY)
    join = _Block(
        2,
        join_ea,
        (
            _Instruction(ida_hexrays.m_add, 0x40A5E1),
            _Instruction(
                join_opcode,
                unresolved_transfer_ea,
                left=_Operand(
                    ida_hexrays.mop_r,
                    register=7,
                    size=(
                        2
                        if int(join_opcode) == int(ida_hexrays.m_icall)
                        else 4
                    ),
                ),
                right=(
                    _Operand(ida_hexrays.mop_r, register=8, size=4)
                    if int(join_opcode) == int(ida_hexrays.m_icall)
                    else None
                ),
            ),
        ),
        (() if int(join_opcode) == int(ida_hexrays.m_ijmp) else (3,)),
    )
    if int(join_opcode) == int(ida_hexrays.m_icall):
        join.type = int(ida_hexrays.BLT_1WAY)
        join.flags |= int(join_flags)
    continuation = _Block(
        3,
        unresolved_transfer_ea,
        (_Instruction(ida_hexrays.m_ret, unresolved_transfer_ea),),
    )
    continuation.type = int(ida_hexrays.BLT_STOP)
    continuation.flags |= int(continuation_flags)
    native = _MBA(
        (
            source,
            selected,
            join,
            *((continuation,) if int(join_opcode) == int(ida_hexrays.m_icall) else ()),
        ),
        maturity=ida_hexrays.MMAT_PREOPTIMIZED,
    )
    assert detached_handler_island.capture_preopt_union_snippet_template(
        function_ea,
        source_ea,
        native,
        (
            (
                source_ea,
                unresolved_transfer_ea
                + (2 if int(join_opcode) == int(ida_hexrays.m_icall) else 1),
            ),
        ),
        owned_block_entry_eas=(
            source_ea,
            selected_ea,
            join_ea,
            *(
                (unresolved_transfer_ea,)
                if int(join_opcode) == int(ida_hexrays.m_icall)
                else ()
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
        maturity=ida_hexrays.MMAT_PREOPTIMIZED,
    )
    body_id = "native-body:split-conditional-select"
    imported = FragmentBlock(
        block_id="imported-split-conditional-select",
        role=FragmentBlockRole.IMPORTED,
        materialization=FragmentBlockMaterialization.IMPORT_NATIVE,
        semantic_anchor_ea=source_ea,
        stable_identity=StableBlockIdentity.from_intervals(
            (NativeEaInterval(source_ea, selected_ea),),
            native_key=NATIVE_KEY,
            exact_instruction_eas=(source_ea, predicate_ea),
        ),
        native_body_id=body_id,
    )
    operation_id = "native-indirect-transfer@0x40A5E3"
    native_body = FragmentNativeBody(
        body_id=body_id,
        block_ids=(imported.block_id,),
        entry_block_ids=(imported.block_id,),
        terminal_block_ids=(),
        native_ranges=(
            NativeEaInterval(source_ea, unresolved_transfer_ea + 1),
        ),
        proof_ids=(operation_id,),
    )
    context = _NativeBodyStagingContext(
        destination,
        _NativeBodyPlan(
            (imported,),
            operations=(
                FragmentOperation(
                    operation_id=operation_id,
                    source_block_id=imported.block_id,
                    predicate_anchor_ea=predicate_ea,
                    computed_branch_normalization=(
                        FragmentComputedBranchNormalization(
                            predicate_kind=predicate_kind,
                            normalization_start_ea=predicate_ea,
                            condition_producer_ea=source_ea,
                            unresolved_transfer_ea=unresolved_transfer_ea,
                            conditional_select_envelope=(
                                FragmentImportedConditionalSelectEnvelope(
                                    source_branch_ea=selected_ea - 1,
                                    selected_value_ea=selected_ea,
                                    selected_value_identity=(
                                        StableBlockIdentity.from_intervals(
                                            (
                                                NativeEaInterval(
                                                    selected_ea,
                                                    join_ea,
                                                ),
                                            ),
                                            native_key=NATIVE_KEY,
                                            exact_instruction_eas=(selected_ea,),
                                        )
                                    ),
                                    join_identity=(
                                        StableBlockIdentity.from_intervals(
                                            (
                                                NativeEaInterval(
                                                    join_ea,
                                                    unresolved_transfer_ea + 1,
                                                ),
                                            ),
                                            native_key=NATIVE_KEY,
                                            exact_instruction_eas=(
                                                join_ea,
                                                unresolved_transfer_ea,
                                            ),
                                        )
                                    ),
                                )
                            ),
                        )
                    ),
                    edges=(
                        FragmentEdge(
                            role=SemanticEdgeRole.CONDITIONAL_TAKEN,
                            target_block_id="taken",
                        ),
                        FragmentEdge(
                            role=SemanticEdgeRole.CONDITIONAL_FALLTHROUGH,
                            target_block_id="fallthrough",
                        ),
                    ),
                ),
            ),
        ),
    )

    materializer = detached_handler_island.PreoptUnionSemanticNativeBodyMaterializer(
        mba=destination,
        function_ea=function_ea,
    )
    if not normalization_succeeds:
        rejection = pytest.raises(
            detached_handler_island.SemanticFragmentBackendRejected,
            match="split conditional-select envelope",
        )
        with rejection as raised:
            _prepare_and_stage_native_body(
                materializer,
                context=context,
                native_body=native_body,
            )
        if int(join_opcode) == int(ida_hexrays.m_icall):
            reason = str(raised.value)
            assert "source_instruction_shapes=" in reason
            assert "join_successors=('blk3@0x40A5E3',)" in reason
            assert "join_successor_shapes=" in reason
            assert f"join_flags=0x{int(join_flags):X}" in reason
            assert (
                f"join_is_tail_call={bool(int(join_flags) & int(ida_hexrays.MBL_TCAL))}"
                in reason
            )
            assert "join_has_callinfo=False" in reason
            assert (
                "join_tail_operands="
                f"(('l', {int(ida_hexrays.mop_r)}, 2), "
                f"('r', {int(ida_hexrays.mop_r)}, 4), "
                f"('d', {int(ida_hexrays.mop_z)}, 4))"
                in reason
            )
        assert context.staged_block_ids == []
        return

    _prepare_and_stage_native_body(
        materializer,
        context=context,
        native_body=native_body,
    )

    staged = context.blocks[imported.block_id].instructions()
    assert tuple(int(instruction.opcode) for instruction in staged) == (
        int(ida_hexrays.m_setb),
        int(ida_hexrays.m_seto),
        int(ida_hexrays.m_setz),
        int(ida_hexrays.m_setp),
        int(ida_hexrays.m_sets),
        int(ida_hexrays.m_jnz),
    )
    branch = staged[-1]
    if predicate_combine_opcode is None:
        assert int(branch.l.t) == int(ida_hexrays.mop_r)
        assert int(branch.l.r) == zero_flag_register
    else:
        assert int(branch.l.t) == int(ida_hexrays.mop_d)
        assert int(branch.l.d.opcode) == int(predicate_combine_opcode)
        assert {
            int(branch.l.d.l.r),
            int(branch.l.d.r.r),
        } == {int(sign_flag.r), int(overflow_flag.r)}
    assert int(branch.r.t) == int(ida_hexrays.mop_n)
    assert int(branch.r.nnn.value) == 0
    assert set(context.instruction_origins.values()) == {
        source_ea,
        predicate_ea,
    }


@pytest.mark.parametrize(
    ("normalization_start_ea", "normalization_succeeds"),
    (
        (0x40ADFD, True),
        (0x40ADFE, False),
        (0x40ADFF, False),
    ),
)
def test_preopt_native_body_normalizes_split_signed_select_from_real_start(
    monkeypatch,
    normalization_start_ea,
    normalization_succeeds,
) -> None:
    _install_runtime_fakes(monkeypatch)
    function_ea = 0xB000
    source_ea = 0x40ADF2
    condition_producer_ea = 0x40ADF7
    real_normalization_start_ea = 0x40ADFD
    selected_ea = 0x40AE05
    join_ea = 0x40AE08
    predicate_ea = 0x40AE09
    unresolved_transfer_ea = 0x40AE18
    overflow_flag = _Operand(
        ida_hexrays.mop_r,
        register=3,
        size=1,
    )
    sign_flag = _Operand(
        ida_hexrays.mop_r,
        register=2,
        size=1,
    )
    signed_less_than = _Instruction(
        ida_hexrays.m_xor,
        predicate_ea,
        left=sign_flag,
        right=overflow_flag,
    )
    skip_selected = _Instruction(
        ida_hexrays.m_lnot,
        predicate_ea,
        left=_Operand(
            ida_hexrays.mop_d,
            nested=signed_less_than,
            size=1,
        ),
    )
    source = _Block(
        0,
        source_ea,
        (
            _Instruction(ida_hexrays.m_mov, source_ea),
            _Instruction(
                ida_hexrays.m_setb,
                condition_producer_ea,
                dest=_Operand(ida_hexrays.mop_r, register=0, size=1),
            ),
            _Instruction(
                ida_hexrays.m_seto,
                condition_producer_ea,
                dest=overflow_flag,
            ),
            _Instruction(
                ida_hexrays.m_setz,
                condition_producer_ea,
                dest=_Operand(ida_hexrays.mop_r, register=1, size=1),
            ),
            _Instruction(
                ida_hexrays.m_setp,
                condition_producer_ea,
                dest=_Operand(ida_hexrays.mop_r, register=4, size=1),
            ),
            _Instruction(
                ida_hexrays.m_sets,
                condition_producer_ea,
                dest=sign_flag,
            ),
            _Instruction(ida_hexrays.m_mov, real_normalization_start_ea),
            _Instruction(ida_hexrays.m_mov, 0x40ADFF),
            _Instruction(
                ida_hexrays.m_jcnd,
                selected_ea,
                left=_Operand(
                    ida_hexrays.mop_d,
                    nested=skip_selected,
                    size=1,
                ),
                dest=_Operand(ida_hexrays.mop_b, block_ref=2),
            ),
        ),
        (1, 2),
    )
    source.type = int(ida_hexrays.BLT_2WAY)
    selected = _Block(
        1,
        selected_ea,
        (_Instruction(ida_hexrays.m_mov, selected_ea),),
        (2,),
    )
    selected.type = int(ida_hexrays.BLT_1WAY)
    join = _Block(
        2,
        join_ea,
        (
            _Instruction(ida_hexrays.m_mov, join_ea),
            _Instruction(
                ida_hexrays.m_ijmp,
                unresolved_transfer_ea,
                left=_Operand(
                    ida_hexrays.mop_r,
                    register=8,
                    size=4,
                ),
            ),
        ),
    )
    native = _MBA(
        (source, selected, join),
        maturity=ida_hexrays.MMAT_PREOPTIMIZED,
    )
    assert detached_handler_island.capture_preopt_union_snippet_template(
        function_ea,
        source_ea,
        native,
        ((source_ea, unresolved_transfer_ea + 1),),
        owned_block_entry_eas=(source_ea, selected_ea, join_ea),
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
    body_id = "native-body:synthetic-signed-select"
    imported = _imported_fragment_block(
        "imported-synthetic-signed-select",
        body_id,
        source_ea,
        unresolved_transfer_ea + 1,
    )
    operation_id = f"native-indirect-transfer@0x{unresolved_transfer_ea:X}"
    native_body = FragmentNativeBody(
        body_id=body_id,
        block_ids=(imported.block_id,),
        entry_block_ids=(imported.block_id,),
        terminal_block_ids=(),
        native_ranges=(
            NativeEaInterval(source_ea, unresolved_transfer_ea + 1),
        ),
        proof_ids=(operation_id,),
    )
    context = _NativeBodyStagingContext(
        destination,
        _NativeBodyPlan(
            (imported,),
            operations=(
                FragmentOperation(
                    operation_id=operation_id,
                    source_block_id=imported.block_id,
                    predicate_anchor_ea=predicate_ea,
                    computed_branch_normalization=(
                        FragmentComputedBranchNormalization(
                            predicate_kind=PredicateKind.SLT,
                            normalization_start_ea=normalization_start_ea,
                            condition_producer_ea=condition_producer_ea,
                            unresolved_transfer_ea=unresolved_transfer_ea,
                        )
                    ),
                    edges=(
                        FragmentEdge(
                            role=SemanticEdgeRole.CONDITIONAL_TAKEN,
                            target_block_id="taken",
                        ),
                        FragmentEdge(
                            role=SemanticEdgeRole.CONDITIONAL_FALLTHROUGH,
                            target_block_id="fallthrough",
                        ),
                    ),
                ),
            ),
        ),
    )
    materializer = (
        detached_handler_island.PreoptUnionSemanticNativeBodyMaterializer(
            mba=destination,
            function_ea=function_ea,
        )
    )
    if not normalization_succeeds:
        with pytest.raises(
            detached_handler_island.SemanticFragmentBackendRejected,
            match="split conditional-select envelope",
        ):
            _prepare_and_stage_native_body(
                materializer,
                context=context,
                native_body=native_body,
            )
        assert context.staged_block_ids == []
        return

    _prepare_and_stage_native_body(
        materializer,
        context=context,
        native_body=native_body,
    )

    staged = context.blocks[imported.block_id].instructions()
    assert tuple(int(instruction.opcode) for instruction in staged) == (
        int(ida_hexrays.m_mov),
        int(ida_hexrays.m_setb),
        int(ida_hexrays.m_seto),
        int(ida_hexrays.m_setz),
        int(ida_hexrays.m_setp),
        int(ida_hexrays.m_sets),
        int(ida_hexrays.m_jnz),
    )
    branch = staged[-1]
    assert int(branch.l.t) == int(ida_hexrays.mop_d)
    assert int(branch.l.d.opcode) == int(ida_hexrays.m_xor)
    assert {
        int(branch.l.d.l.r),
        int(branch.l.d.r.r),
    } == {int(sign_flag.r), int(overflow_flag.r)}
    assert tuple(context.instruction_origins.values()) == (
        source_ea,
        condition_producer_ea,
        condition_producer_ea,
        condition_producer_ea,
        condition_producer_ea,
        condition_producer_ea,
        predicate_ea,
    )


@pytest.mark.parametrize(
    (
        "semantic_predicate",
        "combine_opcode",
        "predicate_layout",
        "expected_branch_opcode",
    ),
    (
        (PredicateKind.SLT, ida_hexrays.m_xor, "nested", ida_hexrays.m_jnz),
        (PredicateKind.SGE, ida_hexrays.m_xor, "nested", ida_hexrays.m_jz),
        (PredicateKind.SLT, ida_hexrays.m_or, "nested", None),
        (
            PredicateKind.SLT,
            ida_hexrays.m_xor,
            "separate-direct",
            ida_hexrays.m_jnz,
        ),
        (
            PredicateKind.SGE,
            ida_hexrays.m_xor,
            "separate-lnot",
            ida_hexrays.m_jz,
        ),
        (PredicateKind.SGE, ida_hexrays.m_xor, "separate-direct", None),
        (PredicateKind.SGE, ida_hexrays.m_xor, "separate-lnot-mismatch", None),
    ),
)
def test_preopt_native_body_normalizes_signed_flag_xor_before_staging(
    monkeypatch,
    semantic_predicate,
    combine_opcode,
    predicate_layout,
    expected_branch_opcode,
) -> None:
    _install_runtime_fakes(monkeypatch)
    function_ea = 0xB000
    source_ea = 0x3700
    condition_producer_ea = 0x3702
    predicate_ea = 0x3708
    unresolved_transfer_ea = 0x3710
    overflow_register = 60
    sign_register = 61
    predicate_register = 7
    overflow_result = _Operand(
        ida_hexrays.mop_r,
        register=overflow_register,
        size=1,
    )
    sign_result = _Operand(
        ida_hexrays.mop_r,
        register=sign_register,
        size=1,
    )
    predicate_expression = _Instruction(
        combine_opcode,
        predicate_ea,
        left=sign_result,
        right=overflow_result,
    )
    predicate_result = _Operand(
        ida_hexrays.mop_r,
        register=predicate_register,
        size=4,
    )
    if predicate_layout == "nested":
        predicate_instructions = (
            _Instruction(
                ida_hexrays.m_xdu,
                predicate_ea,
                left=_Operand(
                    ida_hexrays.mop_d,
                    size=1,
                    nested=predicate_expression,
                ),
                dest=predicate_result,
            ),
        )
    else:
        combine_result = _Operand(
            ida_hexrays.mop_r,
            register=predicate_register + 1,
            size=1,
        )
        if predicate_layout == "separate-direct":
            zext_source = combine_result
        else:
            lnot_source = (
                combine_result
                if predicate_layout == "separate-lnot"
                else _Operand(
                    ida_hexrays.mop_r,
                    register=predicate_register + 2,
                    size=1,
                )
            )
            zext_source = _Operand(
                ida_hexrays.mop_d,
                size=1,
                nested=_Instruction(
                    ida_hexrays.m_lnot,
                    predicate_ea,
                    left=lnot_source,
                    dest=_Operand(ida_hexrays.mop_z, size=1),
                ),
            )
        predicate_expression.d = combine_result
        predicate_instructions = (
            predicate_expression,
            _Instruction(
                ida_hexrays.m_xdu,
                predicate_ea,
                left=zext_source,
                dest=predicate_result,
            ),
        )
    source = _MBA(
        (
            _Block(
                0,
                source_ea,
                (
                    _Instruction(
                        ida_hexrays.m_seto,
                        condition_producer_ea,
                        dest=overflow_result,
                    ),
                    _Instruction(
                        ida_hexrays.m_sets,
                        condition_producer_ea,
                        dest=sign_result,
                    ),
                    *predicate_instructions,
                    _Instruction(
                        ida_hexrays.m_mul,
                        predicate_ea + 3,
                        left=_Operand(
                            ida_hexrays.mop_n,
                            value=0x100,
                            size=4,
                        ),
                        right=_Operand(
                            ida_hexrays.mop_r,
                            register=predicate_register,
                            size=4,
                        ),
                        dest=_Operand(
                            ida_hexrays.mop_r,
                            register=predicate_register,
                            size=4,
                        ),
                    ),
                    _Instruction(
                        ida_hexrays.m_ijmp,
                        unresolved_transfer_ea,
                        left=_Operand(
                            ida_hexrays.mop_r,
                            register=predicate_register,
                            size=4,
                        ),
                    ),
                ),
            ),
        ),
        maturity=ida_hexrays.MMAT_PREOPTIMIZED,
    )
    assert detached_handler_island.capture_preopt_union_snippet_template(
        function_ea,
        source_ea,
        source,
        ((source_ea, unresolved_transfer_ea + 1),),
        owned_block_entry_eas=(source_ea,),
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
    body_id = "native-body:signed-computed-branch"
    imported = _imported_fragment_block(
        "imported-signed-computed-branch",
        body_id,
        source_ea,
        unresolved_transfer_ea + 1,
    )
    operation_id = "proof:signed-computed-branch"
    native_body = FragmentNativeBody(
        body_id=body_id,
        block_ids=(imported.block_id,),
        entry_block_ids=(imported.block_id,),
        terminal_block_ids=(),
        native_ranges=(
            NativeEaInterval(source_ea, unresolved_transfer_ea + 1),
        ),
        proof_ids=(operation_id,),
    )
    context = _NativeBodyStagingContext(
        destination,
        _NativeBodyPlan(
            (imported,),
            operations=(
                FragmentOperation(
                    operation_id=operation_id,
                    source_block_id=imported.block_id,
                    predicate_anchor_ea=predicate_ea,
                    computed_branch_normalization=(
                        FragmentComputedBranchNormalization(
                            predicate_kind=semantic_predicate,
                            normalization_start_ea=predicate_ea,
                            condition_producer_ea=condition_producer_ea,
                            unresolved_transfer_ea=unresolved_transfer_ea,
                        )
                    ),
                    edges=(
                        FragmentEdge(
                            role=SemanticEdgeRole.CONDITIONAL_TAKEN,
                            target_block_id="taken",
                        ),
                        FragmentEdge(
                            role=SemanticEdgeRole.CONDITIONAL_FALLTHROUGH,
                            target_block_id="fallthrough",
                        ),
                    ),
                ),
            ),
        ),
    )
    materializer = (
        detached_handler_island.PreoptUnionSemanticNativeBodyMaterializer(
            mba=destination,
            function_ea=function_ea,
        )
    )
    if expected_branch_opcode is None:
        with pytest.raises(
            detached_handler_island.SemanticFragmentBackendRejected,
            match="condition producer does not match",
        ) as rejected:
            _prepare_and_stage_native_body(
                materializer,
                context=context,
                native_body=native_body,
            )
        assert "observed_predicate_shapes=" in str(rejected.value)
        assert context.staged_block_ids == []
        return

    _prepare_and_stage_native_body(
        materializer,
        context=context,
        native_body=native_body,
    )

    staged = context.blocks[imported.block_id].instructions()
    assert tuple(int(instruction.opcode) for instruction in staged) == (
        int(ida_hexrays.m_seto),
        int(ida_hexrays.m_sets),
        int(expected_branch_opcode),
    )
    branch = staged[-1]
    assert int(branch.l.t) == int(ida_hexrays.mop_d)
    assert int(branch.l.d.opcode) == int(combine_opcode)
    assert {
        int(branch.l.d.l.r),
        int(branch.l.d.r.r),
    } == {sign_register, overflow_register}
    assert int(branch.l.size) == 1
    assert int(branch.r.t) == int(ida_hexrays.mop_n)
    assert int(branch.r.nnn.value) == 0
    assert tuple(context.instruction_origins.values()) == (
        condition_producer_ea,
        condition_producer_ea,
        predicate_ea,
    )


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
    for operand in detached_handler_island._instruction_operands(source_instruction):
        if int(operand.t) == int(ida_hexrays.mop_S):
            operand.s.mba = source
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
        mutation_gateway=make_mutation_gateway(destination),
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
    assert all(
        operand.s.mba is destination
        for operand in detached_handler_island._instruction_operands(imported)
        if int(operand.t) == int(ida_hexrays.mop_S)
    )


def test_local_variable_operand_abstains_before_destination_mutation(
    monkeypatch,
) -> None:
    _install_runtime_fakes(monkeypatch)
    function_ea = 0x40A560
    target_ea = 0x40C4F6
    source = _MBA(
        (
            _Block(
                0,
                target_ea,
                (
                    _Instruction(
                        ida_hexrays.m_mov,
                        target_ea,
                        left=_Operand(ida_hexrays.mop_l, lvar_index=7),
                    ),
                ),
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
        ((target_ea, target_ea + 1),),
    )
    original_qty = int(destination.qty)

    assert (
        detached_handler_island.materialize_detached_snippet_templates(
            destination,
            function_ea,
            (target_ea,),
            mutation_gateway=make_mutation_gateway(destination),
        )
        == {}
    )
    assert int(destination.qty) == original_qty


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
        mutation_gateway=make_mutation_gateway(destination),
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


def test_range_capture_bypasses_empty_split_to_owned_successor(
    monkeypatch,
) -> None:
    _install_runtime_fakes(monkeypatch)
    function_ea = 0x40C8B0
    target_ea = 0x40CADE
    empty_split_ea = 0x40CAF4
    body_ea = 0x40CAF7
    source = _MBA(
        (
            _Block(
                0,
                target_ea,
                (_Instruction(ida_hexrays.m_nop, target_ea),),
                (1,),
            ),
            _Block(1, empty_split_ea, (), (2,)),
            _Block(
                2,
                body_ea,
                (_Instruction(ida_hexrays.m_nop, body_ea),),
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
        ((target_ea, body_ea + 1),),
    )
    template = detached_handler_island._DETACHED_SNIPPET_TEMPLATES[
        (function_ea, target_ea)
    ]

    assert tuple(block.source_serial for block in template.blocks) == (0, 2)
    entry = next(block for block in template.blocks if block.source_serial == 0)
    assert entry.successor_serials == (2,)
    assert entry.external_successor_eas == (0,)


def test_preopt_union_capture_rebinds_resolver_proven_internal_successor(
    monkeypatch,
) -> None:
    """A synthetic PREOPT exit is rebound only through native-EA proof."""
    _install_runtime_fakes(monkeypatch)
    function_ea = 0x40D200
    source_ea = 0x40F819
    resolver_ea = 0x40F81F
    target_ea = 0x40E5C0
    synthetic_exit = 0xFFFFFFFFFFFFFFFF
    source = _MBA(
        (
            _Block(
                0,
                source_ea,
                (_Instruction(ida_hexrays.m_icall, resolver_ea),),
                (2,),
            ),
            _Block(
                1,
                target_ea,
                (_Instruction(ida_hexrays.m_nop, target_ea),),
            ),
            _Block(2, synthetic_exit, ()),
        ),
        maturity=ida_hexrays.MMAT_PREOPTIMIZED,
    )
    source.get_mblock(0).type = int(ida_hexrays.BLT_1WAY)

    assert detached_handler_island.capture_preopt_union_snippet_template(
        function_ea,
        source_ea,
        source,
        ((target_ea, target_ea + 1), (source_ea, resolver_ea + 1)),
        owned_block_entry_eas=(source_ea, target_ea),
        resolver_proven_internal_successor_eas={resolver_ea: target_ea},
    )
    template = detached_handler_island._PREOPT_UNION_SNIPPET_TEMPLATES[
        (function_ea, source_ea)
    ]
    captured_source = next(
        block for block in template.blocks if block.native_entry_ea == source_ea
    )
    assert captured_source.successor_serials == (1,)
    assert captured_source.external_successor_eas == (0,)


def test_preopt_union_capture_preserves_owned_elided_target_entry(
    monkeypatch,
) -> None:
    """An owned block start survives when its entry instruction was optimized out."""
    _install_runtime_fakes(monkeypatch)
    function_ea = 0x40A560
    source_ea = 0x40B7A4
    resolver_ea = 0x40B7A8
    target_ea = 0x40B940
    first_surviving_ea = 0x40B942
    synthetic_exit = 0xFFFFFFFFFFFFFFFF
    source = _MBA(
        (
            _Block(
                0,
                source_ea,
                (_Instruction(ida_hexrays.m_icall, resolver_ea),),
                (2,),
            ),
            _Block(
                1,
                target_ea,
                (_Instruction(ida_hexrays.m_nop, first_surviving_ea),),
            ),
            _Block(2, synthetic_exit, ()),
        ),
        maturity=ida_hexrays.MMAT_PREOPTIMIZED,
    )
    source.get_mblock(0).type = int(ida_hexrays.BLT_1WAY)

    assert detached_handler_island.capture_preopt_union_snippet_template(
        function_ea,
        source_ea,
        source,
        (
            (source_ea, resolver_ea + 1),
            (target_ea, first_surviving_ea + 1),
        ),
        owned_block_entry_eas=(source_ea, target_ea),
        resolver_proven_internal_successor_eas={resolver_ea: target_ea},
    )
    template = detached_handler_island._PREOPT_UNION_SNIPPET_TEMPLATES[
        (function_ea, source_ea)
    ]
    captured_source = next(
        block for block in template.blocks if block.native_entry_ea == source_ea
    )
    captured_target = next(
        block for block in template.blocks if block.native_entry_ea == target_ea
    )

    assert captured_source.successor_serials == (captured_target.source_serial,)
    assert captured_source.external_successor_eas == (0,)


def test_preopt_union_capture_splits_embedded_resolver_proven_internal_successor(
    monkeypatch,
) -> None:
    """An exact internal target may follow a prefix in one Hex-Rays block."""
    _install_runtime_fakes(monkeypatch)
    function_ea = 0x40A560
    source_ea = 0x40A675
    resolver_ea = 0x40A679
    target_prefix_ea = 0x40AE20
    target_ea = 0x40AE26
    synthetic_exit = 0xFFFFFFFFFFFFFFFF
    source = _MBA(
        (
            _Block(
                0,
                source_ea,
                (_Instruction(ida_hexrays.m_icall, resolver_ea),),
                (2,),
            ),
            _Block(
                1,
                target_prefix_ea,
                (
                    _Instruction(ida_hexrays.m_nop, target_prefix_ea),
                    _Instruction(ida_hexrays.m_nop, target_ea),
                ),
            ),
            _Block(2, synthetic_exit, ()),
        ),
        maturity=ida_hexrays.MMAT_PREOPTIMIZED,
    )
    source.get_mblock(0).type = int(ida_hexrays.BLT_1WAY)

    assert detached_handler_island.capture_preopt_union_snippet_template(
        function_ea,
        source_ea,
        source,
        (
            (source_ea, resolver_ea + 1),
            (target_prefix_ea, target_ea + 1),
        ),
        owned_block_entry_eas=(source_ea, target_ea),
        resolver_proven_internal_successor_eas={resolver_ea: target_ea},
    )
    template = detached_handler_island._PREOPT_UNION_SNIPPET_TEMPLATES[
        (function_ea, source_ea)
    ]
    captured_source = next(
        block for block in template.blocks if block.native_entry_ea == source_ea
    )
    captured_target = next(
        block for block in template.blocks if block.native_entry_ea == target_ea
    )

    assert captured_source.successor_serials == (captured_target.source_serial,)
    assert captured_source.external_successor_eas == (0,)


def test_preopt_union_capture_lowers_proven_zero_way_route_before_import(
    monkeypatch,
) -> None:
    """A proven indirect route becomes a closed direct edge in the template."""
    _install_runtime_fakes(monkeypatch)
    function_ea = 0x40A560
    delivery_ea = 0x40A70E
    target_ea = 0x40ADF2
    source = _MBA(
        (
            _Block(
                0,
                delivery_ea,
                (_Instruction(ida_hexrays.m_ijmp, delivery_ea),),
            ),
            _Block(
                1,
                target_ea,
                (_Instruction(ida_hexrays.m_nop, target_ea),),
            ),
        ),
        maturity=ida_hexrays.MMAT_PREOPTIMIZED,
    )

    assert detached_handler_island.capture_preopt_union_snippet_template(
        function_ea,
        delivery_ea,
        source,
        ((delivery_ea, delivery_ea + 1), (target_ea, target_ea + 1)),
        owned_block_entry_eas=(delivery_ea, target_ea),
        resolver_proven_internal_successor_eas={delivery_ea: target_ea},
    )
    template = detached_handler_island._PREOPT_UNION_SNIPPET_TEMPLATES[
        (function_ea, delivery_ea)
    ]
    captured_source = next(
        block for block in template.blocks if block.native_entry_ea == delivery_ea
    )

    assert captured_source.successor_serials == (1,)
    assert captured_source.external_successor_eas == (0,)
    assert captured_source.block_type == ida_hexrays.BLT_1WAY
    assert captured_source.block_flags & ida_hexrays.MBL_GOTO
    assert captured_source.instructions[-1].opcode == ida_hexrays.m_goto
    assert captured_source.instructions[-1].l.t == ida_hexrays.mop_b
    assert captured_source.instructions[-1].l.b == 1


def test_preopt_union_capture_closes_proven_conditional_fallthrough_arm(
    monkeypatch,
) -> None:
    """A proven state route may close one arm without collapsing its predicate."""
    _install_runtime_fakes(monkeypatch)
    function_ea = 0x40A560
    predicate_ea = 0x40B4DC
    taken_ea = 0x40A7E5
    false_target_ea = 0x40B758
    synthetic_exit = 0xFFFFFFFFFFFFFFFF
    source = _MBA(
        (
            _Block(
                0,
                predicate_ea,
                (
                    _Instruction(
                        ida_hexrays.m_jl,
                        predicate_ea,
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
            _Block(2, synthetic_exit, ()),
            _Block(
                3,
                false_target_ea,
                (_Instruction(ida_hexrays.m_nop, false_target_ea),),
            ),
        ),
        maturity=ida_hexrays.MMAT_PREOPTIMIZED,
    )
    source.get_mblock(0).type = int(ida_hexrays.BLT_2WAY)

    assert detached_handler_island.capture_preopt_union_snippet_template(
        function_ea,
        predicate_ea,
        source,
        (
            (predicate_ea, predicate_ea + 1),
            (taken_ea, taken_ea + 1),
            (false_target_ea, false_target_ea + 1),
        ),
        owned_block_entry_eas=(predicate_ea, taken_ea, false_target_ea),
        resolver_proven_internal_successor_eas={
            predicate_ea: false_target_ea,
        },
    )
    template = detached_handler_island._PREOPT_UNION_SNIPPET_TEMPLATES[
        (function_ea, predicate_ea)
    ]
    captured_source = next(
        block for block in template.blocks if block.native_entry_ea == predicate_ea
    )

    assert captured_source.successor_serials == (1, 3)
    assert captured_source.external_successor_eas == (0, 0)
    assert captured_source.block_type == ida_hexrays.BLT_2WAY
    assert captured_source.instructions[-1].opcode == ida_hexrays.m_jl
    assert captured_source.instructions[-1].d.b == 1


def test_preopt_union_capture_replaces_explicit_resolver_fallthrough_arm(
    monkeypatch,
) -> None:
    """A native resolver fallthrough is replaced without collapsing its predicate."""
    _install_runtime_fakes(monkeypatch)
    function_ea = 0x40A560
    source_ea = 0x40B4C5
    predicate_ea = 0x40B4DC
    taken_ea = 0x40A7E5
    resolver_fallthrough_ea = 0x40B4E2
    false_target_ea = 0x40B758
    source = _MBA(
        (
            _Block(
                0,
                source_ea,
                (
                    _Instruction(
                        ida_hexrays.m_jl,
                        predicate_ea,
                        dest=_Operand(ida_hexrays.mop_b, block_ref=1),
                    ),
                ),
                (2, 1),
            ),
            _Block(
                1,
                taken_ea,
                (_Instruction(ida_hexrays.m_nop, taken_ea),),
            ),
            _Block(
                2,
                resolver_fallthrough_ea,
                (
                    _Instruction(ida_hexrays.m_nop, resolver_fallthrough_ea),
                    _Instruction(ida_hexrays.m_ijmp, 0x40B4EE),
                ),
            ),
            _Block(
                3,
                false_target_ea,
                (_Instruction(ida_hexrays.m_nop, false_target_ea),),
            ),
        ),
        maturity=ida_hexrays.MMAT_PREOPTIMIZED,
    )
    source.get_mblock(0).type = int(ida_hexrays.BLT_2WAY)
    source.get_mblock(0).end = resolver_fallthrough_ea

    assert detached_handler_island.capture_preopt_union_snippet_template(
        function_ea,
        source_ea,
        source,
        (
            (source_ea, resolver_fallthrough_ea),
            (taken_ea, taken_ea + 1),
            (false_target_ea, false_target_ea + 1),
        ),
        owned_block_entry_eas=(source_ea, taken_ea, false_target_ea),
        resolver_proven_internal_successor_eas={
            predicate_ea: false_target_ea,
        },
    )
    template = detached_handler_island._PREOPT_UNION_SNIPPET_TEMPLATES[
        (function_ea, source_ea)
    ]
    captured_source = next(
        block for block in template.blocks if block.native_entry_ea == source_ea
    )

    assert captured_source.successor_serials == (3, 1)
    assert captured_source.external_successor_eas == (0, 0)
    assert captured_source.block_type == ida_hexrays.BLT_2WAY
    assert captured_source.instructions[-1].opcode == ida_hexrays.m_jl
    assert captured_source.instructions[-1].d.b == 1


def test_range_capture_includes_resolver_created_leader_without_native_anchor(
    monkeypatch,
) -> None:
    _install_runtime_fakes(monkeypatch)
    function_ea = 0x40C8B0
    target_ea = 0x40CADE
    patch_leader_ea = 0x40CAF4
    body_ea = 0x40CAF7
    source = _MBA(
        (
            _Block(
                0,
                target_ea,
                (_Instruction(ida_hexrays.m_nop, target_ea),),
                (1,),
            ),
            _Block(
                1,
                patch_leader_ea,
                (_Instruction(ida_hexrays.m_goto, 0xFFFFFFFFFFFFFFFF),),
                (2,),
            ),
            _Block(
                2,
                body_ea,
                (_Instruction(ida_hexrays.m_nop, body_ea),),
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
        ((target_ea, body_ea + 1),),
        additional_owned_block_entry_eas=(patch_leader_ea,),
    )
    template = detached_handler_island._DETACHED_SNIPPET_TEMPLATES[
        (function_ea, target_ea)
    ]

    assert tuple(block.source_serial for block in template.blocks) == (0, 1, 2)
    entry = next(block for block in template.blocks if block.source_serial == 0)
    assert entry.successor_serials == (1,)
    assert entry.external_successor_eas == (0,)


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


def test_capture_keeps_nonnegative_fragment_identity_over_stale_native_spd(
    monkeypatch,
) -> None:
    _install_runtime_fakes(monkeypatch)
    function_ea = 0x40CDA0
    target_ea = 0x40CF38
    source_vd = 64
    monkeypatch.setattr(
        detached_handler_island.ida_funcs,
        "get_func",
        lambda ea: (
            SimpleNamespace(frsize=20, frregs=0) if int(ea) == function_ea else None
        ),
    )
    monkeypatch.setattr(
        detached_handler_island,
        "_native_instruction_stack_frame_offsets",
        lambda owner_ea, instruction_ea: (
            (48,)
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
        vd_to_ida_delta=-36,
        stacksize=36,
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
    assert template.stack_vd_to_ida == ((source_vd, 28),)
    assert template.stable_stack_vd_to_ida == ((source_vd, 28),)
    assert template.instruction_stack_vd_to_ida == ((target_ea, source_vd, 28),)


def test_capture_prefers_authoritative_carrier_over_nonnegative_fragment_basis(
    monkeypatch,
) -> None:
    _install_runtime_fakes(monkeypatch)
    function_ea = 0x40D200
    target_ea = 0x40EAA7
    source_vd = 64
    monkeypatch.setattr(
        detached_handler_island,
        "_native_instruction_stack_frame_offsets",
        lambda _owner_ea, _instruction_ea: (220,),
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
        vd_to_ida_delta=4,
    )

    assert detached_handler_island.capture_detached_snippet_template(
        function_ea,
        target_ea,
        source,
        ((target_ea, target_ea + 1),),
        native_stack_frame_offsets_by_ea={target_ea: (220,)},
        authoritative_stack_frame_offsets_by_ea={target_ea: (84,)},
    )
    template = detached_handler_island._DETACHED_SNIPPET_TEMPLATES[
        (function_ea, target_ea)
    ]
    assert template.stack_vd_to_ida == ((source_vd, 68),)
    assert template.stable_stack_vd_to_ida == ((source_vd, 84),)
    assert template.instruction_stack_vd_to_ida == ((target_ea, source_vd, 84),)


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
    assert template.instruction_stack_vd_to_ida == ((target_ea, source_vd, 88),)


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
        lambda decoded, ea: (
            2 if decoded is instruction and int(ea) == instruction_ea else 0
        ),
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
            SimpleNamespace(frsize=0x88, frregs=0) if int(ea) == function_ea else None
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
        mutation_gateway=make_mutation_gateway(destination),
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
        mutation_gateway=make_mutation_gateway(destination),
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
            mba, {2: 3}, mutation_gateway=make_mutation_gateway(mba)
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
            mba, {2: 4}, mutation_gateway=make_mutation_gateway(mba)
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
    raw_source.get_mblock(0).type = int(ida_hexrays.BLT_1WAY)
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
        mutation_gateway=make_mutation_gateway(destination),
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


def test_companion_capture_rolls_back_when_primary_capture_raises(
    monkeypatch,
) -> None:
    _install_runtime_fakes(monkeypatch)
    function_ea = 0x40A560
    target_ea = 0x40B9A6
    call_ea = 0x40BA56
    callee_ea = 0x40F830
    preopt = _MBA(
        (
            _Block(
                0,
                target_ea,
                (
                    _Instruction(
                        ida_hexrays.m_call,
                        call_ea,
                        left=_Operand(ida_hexrays.mop_v, target_ea=callee_ea),
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
                        left=_Operand(ida_hexrays.mop_v, target_ea=callee_ea),
                        dest=_Operand(ida_hexrays.mop_f),
                    ),
                ),
            ),
        ),
        maturity=ida_hexrays.MMAT_CALLS,
    )
    monkeypatch.setattr(
        detached_handler_island,
        "capture_detached_snippet_template",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(
            RuntimeError("synthetic primary capture failure")
        ),
    )

    result = detached_handler_island.capture_detached_snippet_companion_templates(
        function_ea,
        target_ea,
        preopt,
        calls,
        ((target_ea, call_ea + 1),),
    )

    assert result.captured is False
    assert result.reason == "capture_exception"
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


def test_detached_snippet_mba_has_calls_finds_nested_call() -> None:
    call_ea = 0x40BA56
    nested_call = _Instruction(ida_hexrays.m_call, call_ea)
    owner = _Instruction(
        ida_hexrays.m_mov,
        call_ea - 1,
        left=_Operand(ida_hexrays.mop_d, nested=nested_call),
    )
    mba = _MBA((_Block(0, 0x40B9A6, (owner,)),))

    assert detached_handler_island.detached_snippet_mba_has_calls(mba)


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
        mutation_gateway=make_mutation_gateway(destination),
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
        mutation_gateway=make_mutation_gateway(destination),
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
        mutation_gateway=make_mutation_gateway(destination),
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
        mutation_gateway=make_mutation_gateway(destination),
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
        mutation_gateway=make_mutation_gateway(destination),
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
        mutation_gateway=make_mutation_gateway(destination),
    )

    imported_block = destination.get_mblock(roots[target_ea])
    imported_call = imported_block.tail
    assert imported_call is not None
    assert int(imported_call.opcode) == int(ida_hexrays.m_call)
    assert int(imported_call.d.t) != int(ida_hexrays.mop_f)
    assert int(imported_block.flags) & int(ida_hexrays.MBL_PUSH)


def test_preopt_import_relocates_a_call_ea_already_owned_by_the_live_mba(
    monkeypatch,
) -> None:
    """Reachable imported calls must not alias an existing live location."""
    _install_runtime_fakes(monkeypatch)
    function_ea = 0x40A560
    target_ea = 0x40B9A6
    call_ea = 0x40BA56
    raw_source = _MBA(
        (
            _Block(
                0,
                target_ea,
                (
                    _Instruction(ida_hexrays.m_push, call_ea - 1),
                    _Instruction(ida_hexrays.m_call, call_ea),
                ),
            ),
        ),
        maturity=ida_hexrays.MMAT_PREOPTIMIZED,
    )
    destination = _MBA(
        (
            _Block(
                0,
                function_ea,
                (_Instruction(ida_hexrays.m_call, call_ea),),
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
        mutation_gateway=make_mutation_gateway(destination),
    )

    imported_call = destination.get_mblock(roots[target_ea]).tail
    assert imported_call is not None
    assert int(imported_call.ea) != call_ea
    assert destination.map_fict_ea(int(imported_call.ea)) == call_ea
    origins = dict(
        detached_handler_island.imported_detached_snippet_instruction_origins(
            destination
        )
    )
    assert origins[int(imported_call.ea)] == call_ea


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
        mutation_gateway=make_mutation_gateway(destination),
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
        mutation_gateway=make_mutation_gateway(destination),
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
        mutation_gateway=make_mutation_gateway(destination),
    )

    imported_block = destination.get_mblock(roots[target_ea])
    imported_call = imported_block.tail
    assert imported_call is not None
    assert int(imported_call.ea) == call_ea
    assert int(destination.flags2) & int(ida_hexrays.MBA2_HAS_OUTLINES)
    assert destination.mbr.range_contains(target_ea)
    assert destination.mbr.range_contains(call_ea)


def test_preopt_capture_records_direct_call_relative_push_delta(
    monkeypatch,
) -> None:
    """Detached call analysis must use its route-local outgoing push depth."""
    _install_runtime_fakes(monkeypatch)
    function_ea = 0x40CDA0
    target_ea = 0x40CE3C
    call_ea = 0x40CE49
    callee_ea = 0x41E67D
    source = _MBA(
        (
            _Block(
                0,
                target_ea,
                (
                    _Instruction(
                        ida_hexrays.m_push,
                        call_ea - 1,
                        left=_Operand(ida_hexrays.mop_n, value=0x14),
                    ),
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

    assert detached_handler_island.capture_preopt_union_snippet_template(
        function_ea,
        target_ea,
        source,
        ((target_ea, call_ea + 1),),
    )

    assert detached_handler_island.detached_preopt_call_stack_points(function_ea) == (
        (call_ea, -4),
    )


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
        mutation_gateway=make_mutation_gateway(destination),
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
        mutation_gateway=make_mutation_gateway(destination),
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
        mutation_gateway=make_mutation_gateway(destination),
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
        mutation_gateway=make_mutation_gateway(destination),
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
        mutation_gateway=make_mutation_gateway(destination),
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
    source_instruction_ea: int | None = None,
    endpoint_block_ea: int,
    old_successor_eas: tuple[int, ...],
    target_ea: int,
    source_owner: object,
    endpoint_owner: object,
    target_owner: object,
    old_successor_owners: tuple[object, ...] = (),
    delivery_mode: str = "redirect_edge",
    source_replaces_dispatcher_envelope: bool = False,
) -> object:
    from d810.analyses.control_flow.detached_handler_island import (
        DetachedSnippetDirectBoundaryPort,
    )

    return DetachedSnippetDirectBoundaryPort(
        source_block_ea=source_block_ea,
        source_instruction_ea=(
            source_block_ea if source_instruction_ea is None else source_instruction_ea
        ),
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
        source_replaces_dispatcher_envelope=(source_replaces_dispatcher_envelope),
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
    logical_source_owner: object | None = None,
    predicate_ida_stkoff: int | None = None,
    predicate_stack_value: int | None = None,
    predicate_size: int | None = None,
    condition_code: int | None = None,
    predicate_register: int | None = None,
    predicate_constant: int | None = None,
    predicate_true_is_taken: bool | None = None,
    logical_source_replaces_dispatcher_envelope: bool = False,
    taken_target_is_boundary_source: bool = False,
    fallthrough_target_is_boundary_source: bool = False,
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
        logical_source_owner=logical_source_owner,
        predicate_ida_stkoff=predicate_ida_stkoff,
        predicate_stack_value=predicate_stack_value,
        predicate_size=predicate_size,
        condition_code=condition_code,
        predicate_register=predicate_register,
        predicate_constant=predicate_constant,
        predicate_true_is_taken=predicate_true_is_taken,
        logical_source_replaces_dispatcher_envelope=(
            logical_source_replaces_dispatcher_envelope
        ),
        taken_target_is_boundary_source=taken_target_is_boundary_source,
        fallthrough_target_is_boundary_source=fallthrough_target_is_boundary_source,
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
        mutation_gateway=make_mutation_gateway(destination),
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
    qty_before = int(destination.qty)
    blocks_before = tuple(
        tuple(int(instruction.opcode) for instruction in block.instructions())
        for block in destination.blocks
    )
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
        mutation_gateway=make_mutation_gateway(destination),
    )

    assert len(result) == 0
    assert result.applied_boundary_ports == ()
    assert len(result.abstained_boundary_ports) == 1
    assert restored == []
    assert int(destination.qty) == qty_before
    assert tuple(
        tuple(int(instruction.opcode) for instruction in block.instructions())
        for block in destination.blocks
    ) == blocks_before


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
        mutation_gateway=make_mutation_gateway(destination),
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


def test_live_conditional_boundary_port_applies_one_atomic_lowering(
    monkeypatch,
) -> None:
    from d810.analyses.control_flow.detached_handler_island import (
        DetachedSnippetBoundaryPortOwner,
    )
    from d810.hexrays.mutation.deferred_modifier import DeferredGraphModifier
    from d810.transforms.graph_modification import SyntheticStackValueEqualsCondition

    _install_runtime_fakes(monkeypatch)
    function_ea = 0x9000
    predicate_ea = 0x9010
    carrier_ea = 0x9020
    taken_target_ea = 0xA000
    fallthrough_target_ea = 0xA100
    dispatcher_ea = 0xA200
    carrier = _Block(
        0,
        carrier_ea,
        (_Instruction(ida_hexrays.m_mov, carrier_ea),),
        (3,),
    )
    destination = _MBA(
        (
            carrier,
            _Block(
                1,
                taken_target_ea,
                (_Instruction(ida_hexrays.m_nop, taken_target_ea),),
            ),
            _Block(
                2,
                fallthrough_target_ea,
                (_Instruction(ida_hexrays.m_nop, fallthrough_target_ea),),
            ),
            _Block(
                3,
                dispatcher_ea,
                (_Instruction(ida_hexrays.m_nop, dispatcher_ea),),
            ),
        )
    )
    port = _conditional_boundary_port(
        source_block_ea=function_ea,
        predicate_ea=predicate_ea,
        old_taken_target_ea=None,
        old_fallthrough_target_ea=None,
        taken_target_ea=taken_target_ea,
        fallthrough_target_ea=fallthrough_target_ea,
        source_owner=DetachedSnippetBoundaryPortOwner.LIVE,
        taken_target_owner=DetachedSnippetBoundaryPortOwner.LIVE,
        fallthrough_target_owner=DetachedSnippetBoundaryPortOwner.LIVE,
        logical_source_anchor_ea=carrier_ea,
        logical_source_owner=DetachedSnippetBoundaryPortOwner.LIVE,
        predicate_ida_stkoff=0x40,
        predicate_stack_value=0xA0716E5B,
        predicate_size=4,
        condition_code=5,
        resolver_kind="preopt_entry_bridge",
    )
    queued: list[dict[str, object]] = []
    monkeypatch.setattr(
        DeferredGraphModifier,
        "queue_lower_conditional_state_transition",
        lambda _modifier, **kwargs: queued.append(kwargs),
    )
    monkeypatch.setattr(
        DeferredGraphModifier,
        "apply",
        lambda _modifier, **_kwargs: 1,
    )

    applied = detached_handler_island.apply_live_conditional_boundary_ports(
        destination,
        function_ea,
        (port,),
        mutation_gateway=make_mutation_gateway(destination),
    )

    assert applied is not None
    assert len(applied) == 1
    assert len(queued) == 1
    lowering = queued[0]
    assert lowering["source_serial"] == int(carrier.serial)
    assert lowering["old_dispatcher_serial"] == 3
    assert lowering["rewrite_from_ea"] == carrier_ea
    assert lowering["true_target_serial"] == 1
    assert lowering["false_target_serial"] == 2
    condition = lowering["condition_operand"]
    assert isinstance(condition, SyntheticStackValueEqualsCondition)
    assert condition.stack_stkoff == 0x40
    assert condition.stack_size == 4
    assert condition.value == 0xA0716E5B


def test_preflight_binds_proven_logical_source_from_imported_consumer(
    monkeypatch,
) -> None:
    from d810.analyses.control_flow.detached_handler_island import (
        DetachedSnippetBoundaryPortOwner,
    )
    from d810.hexrays.mutation.deferred_modifier import DeferredGraphModifier

    _install_runtime_fakes(monkeypatch)
    function_ea = 0x9000
    proof_source_ea = 0x1000
    proof_predicate_ea = 0x1008
    consumer_ea = 0x2000
    consumer_load_ea = 0x2004
    taken_target_ea = 0x3000
    fallthrough_target_ea = 0x3100
    source = _MBA(
        (
            _Block(
                0,
                consumer_ea,
                (_Instruction(ida_hexrays.m_mov, consumer_load_ea),),
                (1, 2),
            ),
            _Block(
                1,
                taken_target_ea,
                (_Instruction(ida_hexrays.m_nop, taken_target_ea),),
            ),
            _Block(
                2,
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
        )
    )
    port = _conditional_boundary_port(
        source_block_ea=proof_source_ea,
        predicate_ea=proof_predicate_ea,
        old_taken_target_ea=None,
        old_fallthrough_target_ea=None,
        taken_target_ea=taken_target_ea,
        fallthrough_target_ea=fallthrough_target_ea,
        source_owner=DetachedSnippetBoundaryPortOwner.LIVE,
        taken_target_owner=DetachedSnippetBoundaryPortOwner.IMPORTED,
        fallthrough_target_owner=DetachedSnippetBoundaryPortOwner.IMPORTED,
        logical_source_anchor_ea=consumer_load_ea,
        logical_source_owner=DetachedSnippetBoundaryPortOwner.IMPORTED,
        predicate_ida_stkoff=0x5C,
        predicate_stack_value=0x11223344,
        predicate_size=4,
        logical_source_replaces_dispatcher_envelope=True,
    )
    assert detached_handler_island.capture_detached_snippet_template(
        function_ea,
        consumer_ea,
        source,
        (
            (consumer_ea, consumer_load_ea + 1),
            (taken_target_ea, taken_target_ea + 1),
            (fallthrough_target_ea, fallthrough_target_ea + 1),
        ),
        boundary_ports=(port,),
    )
    template = detached_handler_island._DETACHED_SNIPPET_TEMPLATES[
        (function_ea, consumer_ea)
    ]
    (captured,) = template.boundary_ports.conditional
    assert captured.source_serial is None
    assert captured.logical_source_serial == 0

    batch = detached_handler_island._preflight_boundary_port_batch(
        destination,
        (template,),
    )

    assert batch is not None
    assert len(batch.conditional) == 1
    mutation = batch.conditional[0]
    assert mutation.source.imported_key == (consumer_ea, 0)
    assert mutation.materialize_logical_source is True

    synthetic_consumer_ea = 0xF10004
    imported_consumer = _Block(
        1,
        consumer_ea,
        (_Instruction(ida_hexrays.m_mov, synthetic_consumer_ea),),
        (2, 3),
    )
    imported_taken = _Block(
        2,
        taken_target_ea,
        (_Instruction(ida_hexrays.m_nop, 0xF10008),),
    )
    imported_fallthrough = _Block(
        3,
        fallthrough_target_ea,
        (_Instruction(ida_hexrays.m_nop, 0xF1000C),),
    )
    destination.append_block(imported_consumer)
    destination.append_block(imported_taken)
    destination.append_block(imported_fallthrough)
    queued: list[dict[str, object]] = []
    monkeypatch.setattr(
        DeferredGraphModifier,
        "queue_lower_conditional_state_transition",
        lambda _modifier, **kwargs: queued.append(kwargs),
    )
    monkeypatch.setattr(
        DeferredGraphModifier,
        "apply",
        lambda _modifier, **_kwargs: 1,
    )
    identity = detached_handler_island.stable_mba_identity(destination)

    applied = detached_handler_island._apply_boundary_port_batch(
        destination,
        batch,
        {
            mutation.source.imported_key: imported_consumer,
            mutation.taken_target.imported_key: imported_taken,
            mutation.fallthrough_target.imported_key: imported_fallthrough,
        },
        pending_instruction_origins={
            (identity, synthetic_consumer_ea): consumer_load_ea,
        },
        mutation_gateway=make_mutation_gateway(destination),
    )

    assert applied is not None
    assert len(queued) == 1
    assert queued[0]["source_serial"] == int(imported_consumer.serial)
    assert queued[0]["rewrite_from_ea"] == synthetic_consumer_ea


def test_preflight_binds_nested_boundary_source_arms_to_logical_sources(
    monkeypatch,
) -> None:
    from d810.analyses.control_flow.detached_handler_island import (
        DetachedSnippetBoundaryPortOwner,
    )

    _install_runtime_fakes(monkeypatch)
    function_ea = 0x9000
    outer_predicate_ea = 0x1010
    outer_anchor_ea = 0x1100
    taken_nested_predicate_ea = 0x1208
    taken_nested_anchor_ea = 0x1200
    fallthrough_nested_predicate_ea = 0x1308
    fallthrough_nested_anchor_ea = 0x1300
    imported_arm_eas = (0x2000, 0x2100, 0x2200, 0x2300)
    source = _MBA(
        tuple(
            _Block(
                serial,
                target_ea,
                (_Instruction(ida_hexrays.m_nop, target_ea),),
            )
            for serial, target_ea in enumerate(imported_arm_eas)
        )
    )
    outer_anchor = _Block(
        1,
        outer_anchor_ea,
        (_Instruction(ida_hexrays.m_mov, outer_anchor_ea),),
    )
    taken_nested_anchor = _Block(
        2,
        taken_nested_anchor_ea,
        (_Instruction(ida_hexrays.m_mov, taken_nested_anchor_ea),),
    )
    fallthrough_nested_anchor = _Block(
        3,
        fallthrough_nested_anchor_ea,
        (_Instruction(ida_hexrays.m_mov, fallthrough_nested_anchor_ea),),
    )
    destination = _MBA(
        (
            _Block(
                0,
                function_ea,
                (_Instruction(ida_hexrays.m_nop, function_ea),),
            ),
            outer_anchor,
            taken_nested_anchor,
            fallthrough_nested_anchor,
        )
    )
    owner = DetachedSnippetBoundaryPortOwner
    outer = _conditional_boundary_port(
        source_block_ea=function_ea,
        predicate_ea=outer_predicate_ea,
        old_taken_target_ea=None,
        old_fallthrough_target_ea=None,
        taken_target_ea=taken_nested_predicate_ea,
        fallthrough_target_ea=fallthrough_nested_predicate_ea,
        source_owner=owner.LIVE,
        taken_target_owner=owner.LIVE,
        fallthrough_target_owner=owner.LIVE,
        logical_source_anchor_ea=outer_anchor_ea,
        predicate_ida_stkoff=0x18,
        predicate_stack_value=0xAAAA,
        predicate_size=4,
        condition_code=5,
        taken_target_is_boundary_source=True,
        fallthrough_target_is_boundary_source=True,
    )
    taken_nested = _conditional_boundary_port(
        source_block_ea=function_ea,
        predicate_ea=taken_nested_predicate_ea,
        old_taken_target_ea=None,
        old_fallthrough_target_ea=None,
        taken_target_ea=imported_arm_eas[0],
        fallthrough_target_ea=imported_arm_eas[1],
        source_owner=owner.LIVE,
        taken_target_owner=owner.IMPORTED,
        fallthrough_target_owner=owner.IMPORTED,
        logical_source_anchor_ea=taken_nested_anchor_ea,
        predicate_ida_stkoff=0x1C,
        predicate_stack_value=0xBBBB,
        predicate_size=4,
        condition_code=5,
    )
    fallthrough_nested = _conditional_boundary_port(
        source_block_ea=function_ea,
        predicate_ea=fallthrough_nested_predicate_ea,
        old_taken_target_ea=None,
        old_fallthrough_target_ea=None,
        taken_target_ea=imported_arm_eas[2],
        fallthrough_target_ea=imported_arm_eas[3],
        source_owner=owner.LIVE,
        taken_target_owner=owner.IMPORTED,
        fallthrough_target_owner=owner.IMPORTED,
        logical_source_anchor_ea=fallthrough_nested_anchor_ea,
        predicate_ida_stkoff=0x20,
        predicate_stack_value=0xCCCC,
        predicate_size=4,
        condition_code=5,
    )
    assert detached_handler_island.capture_detached_snippet_template(
        function_ea,
        imported_arm_eas[0],
        source,
        tuple((target_ea, target_ea + 1) for target_ea in imported_arm_eas),
        boundary_ports=(outer, taken_nested, fallthrough_nested),
    )
    template = detached_handler_island._DETACHED_SNIPPET_TEMPLATES[
        (function_ea, imported_arm_eas[0])
    ]

    batch = detached_handler_island._preflight_boundary_port_batch(
        destination,
        (template,),
    )

    assert batch is not None
    outer_mutation = next(
        mutation
        for mutation in batch.conditional
        if mutation.record.port.predicate_ea == outer_predicate_ea
    )
    assert outer_mutation.taken_target.live_block is taken_nested_anchor
    assert outer_mutation.fallthrough_target.live_block is fallthrough_nested_anchor


def test_preopt_import_materializes_stack_selected_state_at_later_live_endpoint(
    monkeypatch,
) -> None:
    from d810.analyses.control_flow.detached_handler_island import (
        DetachedSnippetBoundaryPortOwner,
    )
    from d810.hexrays.mutation.deferred_modifier import DeferredGraphModifier
    from d810.transforms.graph_modification import SyntheticStackValueEqualsCondition

    _install_runtime_fakes(monkeypatch)
    function_ea = 0x9000
    original_predicate_ea = 0x1014
    live_source_ea = 0x1200
    original_source_ea = live_source_ea
    live_terminal_ea = 0x1208
    old_router_ea = 0x1300
    taken_target_ea = 0x2000
    fallthrough_target_ea = 0x2100
    selected_state = 0xA1B2C3D4

    source_template = _MBA(
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
    live_source = _Block(
        1,
        live_source_ea,
        (
            _Instruction(ida_hexrays.m_mov, original_predicate_ea),
            _Instruction(ida_hexrays.m_goto, live_terminal_ea),
        ),
        (2,),
    )
    destination = _MBA(
        (
            _Block(
                0,
                function_ea,
                (_Instruction(ida_hexrays.m_nop, function_ea),),
            ),
            live_source,
            _Block(
                2,
                old_router_ea,
                (_Instruction(ida_hexrays.m_nop, old_router_ea),),
            ),
        ),
        ida_to_vd_delta=0x20,
        maturity=ida_hexrays.MMAT_PREOPTIMIZED,
    )
    port = _conditional_boundary_port(
        source_block_ea=original_source_ea,
        predicate_ea=original_predicate_ea,
        old_taken_target_ea=None,
        old_fallthrough_target_ea=None,
        taken_target_ea=taken_target_ea,
        fallthrough_target_ea=fallthrough_target_ea,
        source_owner=DetachedSnippetBoundaryPortOwner.LIVE,
        taken_target_owner=DetachedSnippetBoundaryPortOwner.IMPORTED,
        fallthrough_target_owner=DetachedSnippetBoundaryPortOwner.IMPORTED,
        logical_source_anchor_ea=live_terminal_ea,
        predicate_ida_stkoff=0x18,
        predicate_stack_value=selected_state,
        predicate_size=4,
        condition_code=12,
        predicate_register=8,
        predicate_constant=0x113,
        predicate_true_is_taken=True,
        taken_state=selected_state,
        fallthrough_state=0x55667788,
        resolver_kind="resolver_proven_static_stack_carried_entry_choice",
    )
    assert detached_handler_island.capture_detached_snippet_template(
        function_ea,
        taken_target_ea,
        source_template,
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
    assert mutation.source.live_block is live_source
    assert mutation.materialize_logical_source is True

    queued: list[dict[str, object]] = []
    monkeypatch.setattr(
        DeferredGraphModifier,
        "queue_lower_conditional_state_transition",
        lambda _modifier, **kwargs: queued.append(kwargs),
    )
    monkeypatch.setattr(
        DeferredGraphModifier,
        "apply",
        lambda _modifier, **_kwargs: 1,
    )
    taken_block = _Block(
        3,
        taken_target_ea,
        (_Instruction(ida_hexrays.m_nop, taken_target_ea),),
    )
    fallthrough_block = _Block(
        4,
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
        mutation_gateway=make_mutation_gateway(destination),
    )

    assert applied is not None
    assert len(queued) == 1
    lowering = queued[0]
    assert lowering["source_serial"] == int(live_source.serial)
    assert lowering["old_dispatcher_serial"] == 2
    assert lowering["rewrite_from_ea"] == live_terminal_ea
    assert lowering["false_target_serial"] == int(fallthrough_block.serial)
    assert lowering["true_target_serial"] == int(taken_block.serial)
    condition = lowering["condition_operand"]
    assert isinstance(condition, SyntheticStackValueEqualsCondition)
    assert condition.stack_stkoff == 0x38
    assert condition.stack_size == 4
    assert condition.value == selected_state


def test_preflight_prefers_late_stack_choice_anchor_over_live_predicate(
    monkeypatch,
) -> None:
    from d810.analyses.control_flow.detached_handler_island import (
        DetachedSnippetBoundaryPortOwner,
    )
    from d810.hexrays.mutation.deferred_modifier import DeferredGraphModifier

    _install_runtime_fakes(monkeypatch)
    function_ea = 0x9000
    source_block_ea = 0x1000
    predicate_ea = 0x1008
    late_source_ea = 0x1200
    late_anchor_ea = 0x1208
    old_router_ea = 0x1300
    taken_target_ea = 0x2000
    fallthrough_target_ea = 0x2100
    selected_state = 0xB13A6E93

    source_template = _MBA(
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
    predicate = _Instruction(
        ida_hexrays.m_jge,
        predicate_ea,
        left=_Operand(ida_hexrays.mop_r, register=28),
        right=_Operand(ida_hexrays.mop_n, value=0x113),
        dest=_Operand(ida_hexrays.mop_b, block_ref=1),
    )
    live_predicate = _Block(
        0,
        source_block_ea,
        (_Instruction(ida_hexrays.m_mov, source_block_ea), predicate),
        (1, 2),
    )
    late_source = _Block(
        3,
        late_source_ea,
        (
            _Instruction(ida_hexrays.m_mov, late_source_ea),
            _Instruction(ida_hexrays.m_goto, late_anchor_ea),
        ),
        (4,),
    )
    destination = _MBA(
        (
            live_predicate,
            _Block(1, 0x1010, (_Instruction(ida_hexrays.m_nop, 0x1010),)),
            _Block(2, 0x1020, (_Instruction(ida_hexrays.m_nop, 0x1020),)),
            late_source,
            _Block(
                4,
                old_router_ea,
                (_Instruction(ida_hexrays.m_nop, old_router_ea),),
            ),
        ),
        maturity=ida_hexrays.MMAT_PREOPTIMIZED,
    )
    port = _conditional_boundary_port(
        source_block_ea=source_block_ea,
        predicate_ea=predicate_ea,
        old_taken_target_ea=None,
        old_fallthrough_target_ea=None,
        taken_target_ea=taken_target_ea,
        fallthrough_target_ea=fallthrough_target_ea,
        source_owner=DetachedSnippetBoundaryPortOwner.LIVE,
        taken_target_owner=DetachedSnippetBoundaryPortOwner.IMPORTED,
        fallthrough_target_owner=DetachedSnippetBoundaryPortOwner.IMPORTED,
        logical_source_anchor_ea=late_anchor_ea,
        predicate_ida_stkoff=0x18,
        predicate_stack_value=selected_state,
        predicate_size=4,
        condition_code=12,
        predicate_register=28,
        predicate_constant=0x113,
        predicate_true_is_taken=False,
        taken_state=selected_state,
        fallthrough_state=0x4D34CF70,
        resolver_kind="resolver_proven_static_stack_carried_entry_choice",
    )
    assert detached_handler_island.capture_detached_snippet_template(
        function_ea,
        taken_target_ea,
        source_template,
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
    assert mutation.source.live_block is late_source
    assert mutation.materialize_logical_source is True
    assert mutation.preserve_live_predicate is False

    queued: list[dict[str, object]] = []
    monkeypatch.setattr(
        DeferredGraphModifier,
        "queue_lower_conditional_state_transition",
        lambda _modifier, **kwargs: queued.append(kwargs),
    )
    monkeypatch.setattr(
        DeferredGraphModifier,
        "apply",
        lambda _modifier, **_kwargs: 1,
    )
    taken_block = _Block(
        5,
        taken_target_ea,
        (_Instruction(ida_hexrays.m_nop, taken_target_ea),),
    )
    fallthrough_block = _Block(
        6,
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
        mutation_gateway=make_mutation_gateway(destination),
    )

    assert applied is not None
    assert len(queued) == 1
    assert queued[0]["source_serial"] == int(late_source.serial)
    assert queued[0]["rewrite_from_ea"] == late_anchor_ea


def test_preopt_import_preserves_fresh_live_predicate_for_imported_arms(
    monkeypatch,
) -> None:
    from d810.analyses.control_flow.detached_handler_island import (
        DetachedSnippetBoundaryPortOwner,
    )
    from d810.hexrays.mutation.deferred_modifier import DeferredGraphModifier

    _install_runtime_fakes(monkeypatch)
    function_ea = 0x9000
    source_block_ea = 0x1000
    predicate_ea = 0x1008
    old_taken_ea = 0x1010
    old_fallthrough_ea = 0x1020
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
    predicate = _Instruction(
        ida_hexrays.m_jnz,
        predicate_ea,
        left=_Operand(ida_hexrays.mop_r, register=8),
        right=_Operand(ida_hexrays.mop_n, value=0),
        dest=_Operand(ida_hexrays.mop_b, block_ref=1),
    )
    live_source = _Block(
        0,
        source_block_ea,
        (_Instruction(ida_hexrays.m_mov, source_block_ea), predicate),
        (1, 2),
    )
    destination = _MBA(
        (
            live_source,
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
        ),
        maturity=ida_hexrays.MMAT_PREOPTIMIZED,
    )
    port = _conditional_boundary_port(
        source_block_ea=source_block_ea,
        predicate_ea=predicate_ea,
        old_taken_target_ea=None,
        old_fallthrough_target_ea=None,
        taken_target_ea=taken_target_ea,
        fallthrough_target_ea=fallthrough_target_ea,
        source_owner=DetachedSnippetBoundaryPortOwner.LIVE,
        taken_target_owner=DetachedSnippetBoundaryPortOwner.IMPORTED,
        fallthrough_target_owner=DetachedSnippetBoundaryPortOwner.IMPORTED,
        logical_source_anchor_ea=predicate_ea,
        predicate_register=8,
        predicate_size=4,
        predicate_constant=0,
        condition_code=5,
        predicate_true_is_taken=True,
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
    assert mutation.source.live_block is live_source
    assert mutation.preserve_live_predicate is True

    queued: list[dict[str, object]] = []
    monkeypatch.setattr(
        DeferredGraphModifier,
        "queue_lower_conditional_state_transition",
        lambda _modifier, **kwargs: queued.append(kwargs),
    )
    monkeypatch.setattr(
        DeferredGraphModifier,
        "apply",
        lambda _modifier, **_kwargs: 1,
    )
    taken_block = _Block(
        3,
        taken_target_ea,
        (_Instruction(ida_hexrays.m_nop, taken_target_ea),),
    )
    fallthrough_block = _Block(
        4,
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
        mutation_gateway=make_mutation_gateway(destination),
    )

    assert applied is not None


def test_preopt_import_preserves_exact_imported_predicate_for_imported_arms(
    monkeypatch,
) -> None:
    import d810.core.observability as observability

    from d810.analyses.control_flow.detached_handler_island import (
        DetachedSnippetBoundaryPortOwner,
    )
    from d810.hexrays.mutation.deferred_modifier import DeferredGraphModifier

    _install_runtime_fakes(monkeypatch)
    function_ea = 0x9000
    source_block_ea = 0x1000
    predicate_ea = 0x1008
    taken_target_ea = 0x1100
    fallthrough_target_ea = 0x1180
    predicate = _Instruction(
        ida_hexrays.m_jcnd,
        predicate_ea,
        left=_Operand(
            ida_hexrays.mop_d,
            size=1,
            nested=_Instruction(
                ida_hexrays.m_lnot,
                predicate_ea,
                left=_Operand(ida_hexrays.mop_r, size=1, register=1),
            ),
        ),
    )
    source = _MBA(
        (
            _Block(
                0,
                source_block_ea,
                (_Instruction(ida_hexrays.m_mov, source_block_ea),),
                (1,),
            ),
            _Block(
                1,
                source_block_ea + 4,
                (predicate,),
                (2, 3),
            ),
            _Block(
                2,
                taken_target_ea,
                (_Instruction(ida_hexrays.m_nop, taken_target_ea),),
            ),
            _Block(
                3,
                fallthrough_target_ea,
                (_Instruction(ida_hexrays.m_nop, fallthrough_target_ea),),
            ),
        )
    )
    source.get_mblock(0).type = int(ida_hexrays.BLT_1WAY)
    source.get_mblock(1).type = int(ida_hexrays.BLT_2WAY)
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
    port = _conditional_boundary_port(
        source_block_ea=source_block_ea,
        predicate_ea=predicate_ea,
        old_taken_target_ea=None,
        old_fallthrough_target_ea=None,
        taken_target_ea=taken_target_ea,
        fallthrough_target_ea=fallthrough_target_ea,
        source_owner=DetachedSnippetBoundaryPortOwner.IMPORTED,
        taken_target_owner=DetachedSnippetBoundaryPortOwner.IMPORTED,
        fallthrough_target_owner=DetachedSnippetBoundaryPortOwner.IMPORTED,
        logical_source_anchor_ea=predicate_ea,
        condition_code=5,
        predicate_register=8,
        predicate_size=4,
        predicate_constant=7,
        predicate_true_is_taken=False,
    )
    assert detached_handler_island.capture_detached_snippet_template(
        function_ea,
        source_block_ea,
        source,
        (
            (source_block_ea, source_block_ea + 0x10),
            (taken_target_ea, taken_target_ea + 1),
            (fallthrough_target_ea, fallthrough_target_ea + 1),
        ),
        boundary_ports=(port,),
        owned_block_entry_eas=(
            source_block_ea,
            source_block_ea + 4,
            predicate_ea,
            taken_target_ea,
            fallthrough_target_ea,
        ),
    )
    template = detached_handler_island._DETACHED_SNIPPET_TEMPLATES[
        (function_ea, source_block_ea)
    ]
    template.blocks[1].instructions[-1].d.erase()
    assert int(template.blocks[1].instructions[-1].d.t) == int(ida_hexrays.mop_z)
    record = template.boundary_ports.conditional[0]
    assert record.source_serial == 0
    imported_source = detached_handler_island._BoundaryPortBlockBinding(
        native_ea=source_block_ea,
        imported_key=(source_block_ea, 1),
    )
    assert (
        detached_handler_island._exact_imported_predicate_true_is_taken(
            port,
            imported_source,
            templates_by_target={source_block_ea: template},
        )
        is True
    )
    assert (
        detached_handler_island._exact_imported_predicate_true_is_taken(
            replace(port, predicate_constant=None),
            imported_source,
            templates_by_target={source_block_ea: template},
        )
        is None
    )
    assert (
        detached_handler_island._exact_imported_predicate_true_is_taken(
            replace(port, condition_code=4, predicate_true_is_taken=False),
            imported_source,
            templates_by_target={source_block_ea: template},
        )
        is False
    )
    equality_expression = template.blocks[1].instructions[-1].l.d
    template.blocks[1].instructions[-1].l.d = _Instruction(
        ida_hexrays.m_lnot,
        predicate_ea,
        left=_Operand(
            ida_hexrays.mop_d,
            size=1,
            nested=_Instruction(
                ida_hexrays.m_xor,
                predicate_ea,
                left=_Operand(ida_hexrays.mop_r, size=1, register=1),
                right=_Operand(ida_hexrays.mop_r, size=1, register=2),
            ),
        ),
    )
    assert (
        detached_handler_island._exact_imported_predicate_true_is_taken(
            replace(port, condition_code=13, predicate_true_is_taken=True),
            imported_source,
            templates_by_target={source_block_ea: template},
        )
        is True
    )
    template.blocks[1].instructions[-1].l.d = equality_expression

    identity_events: list[object] = []
    monkeypatch.setattr(
        observability,
        "emit",
        identity_events.append,
    )
    batch = detached_handler_island._preflight_boundary_port_batch(
        destination,
        (template,),
        mutation_gateway=make_mutation_gateway(destination),
    )

    assert batch is not None
    assert len(batch.conditional) == 1
    mutation = batch.conditional[0]
    assert mutation.source.imported_key == (source_block_ea, 1)
    assert mutation.preserve_live_predicate is True
    assert mutation.preserved_predicate_true_is_taken is False
    assert identity_events
    assert all(event.primary_anchor_ea is not None for event in identity_events)
    assert all(
        event.current_serial is None or event.primary_anchor_ea is not None
        for event in identity_events
    )
    assert {event.consumer for event in identity_events} == {"detached_snippet_import"}
    orientation_events = [
        event
        for event in identity_events
        if event.decision_kind == "conditional_predicate_orientation"
    ]
    assert orientation_events
    assert {event.primary_anchor_ea for event in orientation_events} == {predicate_ea}
    assert {event.outcome for event in orientation_events} == {"matched"}
    assert {event.reason for event in orientation_events} == {
        "exact imported predicate orientation proven (inverted)"
    }

    imported_predicate_ea = 0xF10000
    imported_source_block = _Block(
        1,
        imported_predicate_ea,
        (
            _Instruction(
                ida_hexrays.m_jcnd,
                imported_predicate_ea,
                left=copy.deepcopy(predicate.l),
                dest=_Operand(ida_hexrays.mop_b, block_ref=3),
            ),
        ),
        (2, 3),
    )
    imported_source_block.type = int(ida_hexrays.BLT_2WAY)
    imported_taken_block = _Block(
        2,
        0xF11000,
        (_Instruction(ida_hexrays.m_nop, 0xF11000),),
    )
    imported_fallthrough_block = _Block(
        3,
        0xF11800,
        (_Instruction(ida_hexrays.m_nop, 0xF11800),),
    )
    destination.append_block(imported_source_block)
    destination.append_block(imported_taken_block)
    destination.append_block(imported_fallthrough_block)
    queued: list[dict[str, object]] = []
    monkeypatch.setattr(
        DeferredGraphModifier,
        "queue_lower_conditional_state_transition",
        lambda _modifier, **kwargs: queued.append(kwargs),
    )
    monkeypatch.setattr(
        DeferredGraphModifier,
        "apply",
        lambda _modifier, **_kwargs: 1,
    )
    mba_identity = detached_handler_island.stable_mba_identity(destination)
    applied = detached_handler_island._apply_boundary_port_batch(
        destination,
        batch,
        {
            mutation.source.imported_key: imported_source_block,
            mutation.taken_target.imported_key: imported_taken_block,
            mutation.fallthrough_target.imported_key: imported_fallthrough_block,
        },
        pending_instruction_origins={
            (mba_identity, imported_predicate_ea): predicate_ea,
        },
        selected_templates=(template,),
        mutation_gateway=make_mutation_gateway(destination),
    )

    assert applied is not None
    assert len(queued) == 1
    assert queued[0]["rewrite_from_ea"] == imported_predicate_ea
    assert queued[0]["condition_operand"].predicate_ea == imported_predicate_ea
    assert queued[0]["condition_operand"].true_is_taken is False


def test_preopt_import_preserves_inverted_signed_live_predicate(
    monkeypatch,
) -> None:
    from d810.analyses.control_flow.detached_handler_island import (
        DetachedSnippetBoundaryPortOwner,
    )

    _install_runtime_fakes(monkeypatch)
    source_block_ea = 0x40D252
    predicate_ea = 0x40D266
    taken_target_ea = 0x40F20B
    fallthrough_target_ea = 0x40DABB
    predicate = _Instruction(
        ida_hexrays.m_jge,
        predicate_ea,
        left=_Operand(ida_hexrays.mop_r, register=28),
        right=_Operand(ida_hexrays.mop_n, value=0x113),
        dest=_Operand(ida_hexrays.mop_b, block_ref=1),
    )
    live_source = _Block(
        0,
        source_block_ea,
        (_Instruction(ida_hexrays.m_mov, source_block_ea), predicate),
        (1, 2),
    )
    destination = _MBA(
        (
            live_source,
            _Block(1, 0x40D269, (_Instruction(ida_hexrays.m_nop, 0x40D269),)),
            _Block(2, 0x40D26D, (_Instruction(ida_hexrays.m_nop, 0x40D26D),)),
        ),
        maturity=ida_hexrays.MMAT_PREOPTIMIZED,
    )
    port = _conditional_boundary_port(
        source_block_ea=source_block_ea,
        predicate_ea=predicate_ea,
        old_taken_target_ea=None,
        old_fallthrough_target_ea=None,
        taken_target_ea=taken_target_ea,
        fallthrough_target_ea=fallthrough_target_ea,
        source_owner=DetachedSnippetBoundaryPortOwner.LIVE,
        taken_target_owner=DetachedSnippetBoundaryPortOwner.IMPORTED,
        fallthrough_target_owner=DetachedSnippetBoundaryPortOwner.IMPORTED,
        logical_source_anchor_ea=0x40D256,
        predicate_register=28,
        predicate_size=4,
        predicate_constant=0x113,
        condition_code=12,
        predicate_true_is_taken=False,
    )

    source = detached_handler_island._BoundaryPortBlockBinding(
        native_ea=source_block_ea,
        live_block=live_source,
    )
    assert (
        detached_handler_island._exact_live_predicate_true_is_taken(
            port,
            source,
        )
        is False
    )
    assert destination.get_mblock(0) is live_source


def test_preopt_import_orients_exact_opaque_live_predicate_by_native_jcc(
    monkeypatch,
) -> None:
    from d810.analyses.control_flow.detached_handler_island import (
        DetachedSnippetBoundaryPortOwner,
    )

    _install_runtime_fakes(monkeypatch)
    source_block_ea = 0x40E1F6
    predicate_ea = 0x40E20E
    nested_left = _Instruction(ida_hexrays.m_ldx, predicate_ea)
    nested_right = _Instruction(ida_hexrays.m_ldx, predicate_ea)
    predicate = _Instruction(
        ida_hexrays.m_jz,
        predicate_ea,
        left=_Operand(ida_hexrays.mop_d, nested=nested_left),
        right=_Operand(ida_hexrays.mop_d, nested=nested_right),
        dest=_Operand(ida_hexrays.mop_b, block_ref=1),
    )
    live_source = _Block(0, source_block_ea, (predicate,), (1, 2))
    destination = _MBA(
        (
            live_source,
            _Block(1, 0x40E583, (_Instruction(ida_hexrays.m_nop, 0x40E583),)),
            _Block(2, 0x40E214, (_Instruction(ida_hexrays.m_nop, 0x40E214),)),
        ),
        maturity=ida_hexrays.MMAT_PREOPTIMIZED,
    )
    port = _conditional_boundary_port(
        source_block_ea=source_block_ea,
        predicate_ea=predicate_ea,
        old_taken_target_ea=0x40E583,
        old_fallthrough_target_ea=0x40E214,
        taken_target_ea=0x40F12D,
        fallthrough_target_ea=0x40DC04,
        source_owner=DetachedSnippetBoundaryPortOwner.LIVE,
        taken_target_owner=DetachedSnippetBoundaryPortOwner.IMPORTED,
        fallthrough_target_owner=DetachedSnippetBoundaryPortOwner.IMPORTED,
        condition_code=4,
        predicate_true_is_taken=True,
        predicate_register=None,
        predicate_size=None,
        predicate_constant=None,
    )
    binding = detached_handler_island._BoundaryPortBlockBinding(
        native_ea=source_block_ea,
        live_block=live_source,
    )

    assert (
        detached_handler_island._exact_live_predicate_true_is_taken(
            port,
            binding,
        )
        is True
    )
    assert destination.get_mblock(0) is live_source


def test_preopt_import_orients_cmov_conditional_skip_predicate(monkeypatch) -> None:
    from d810.analyses.control_flow.detached_handler_island import (
        DetachedSnippetBoundaryPortOwner,
    )

    _install_runtime_fakes(monkeypatch)
    predicate_ea = 0x40D266
    predicate = _Instruction(
        ida_hexrays.m_jcnd,
        predicate_ea,
        left=_Operand(ida_hexrays.mop_r, register=1),
        dest=_Operand(ida_hexrays.mop_b, block_ref=2),
    )
    source = _Block(0, 0x40D252, (predicate,), (1, 2))
    copy_block = _Block(
        1,
        predicate_ea,
        (
            _Instruction(
                ida_hexrays.m_mov,
                predicate_ea,
                left=_Operand(ida_hexrays.mop_r, register=16),
                dest=_Operand(ida_hexrays.mop_r, register=24),
            ),
        ),
        (2,),
    )
    join = _Block(2, 0x40D269, (_Instruction(ida_hexrays.m_nop, 0x40D269),))
    destination = _MBA(
        (source, copy_block, join),
        maturity=ida_hexrays.MMAT_PREOPTIMIZED,
    )
    port = _conditional_boundary_port(
        source_block_ea=0x40D200,
        predicate_ea=predicate_ea,
        old_taken_target_ea=None,
        old_fallthrough_target_ea=None,
        taken_target_ea=0x40F20B,
        fallthrough_target_ea=0x40DABB,
        source_owner=DetachedSnippetBoundaryPortOwner.LIVE,
        taken_target_owner=DetachedSnippetBoundaryPortOwner.IMPORTED,
        fallthrough_target_owner=DetachedSnippetBoundaryPortOwner.IMPORTED,
        logical_source_anchor_ea=0x40D256,
        predicate_register=20,
        predicate_size=4,
        predicate_constant=0x113,
        condition_code=12,
        predicate_true_is_taken=False,
    )

    binding = detached_handler_island._BoundaryPortBlockBinding(
        native_ea=0x40D200,
        live_block=source,
    )
    assert (
        detached_handler_island._exact_live_predicate_true_is_taken(
            port,
            binding,
        )
        is False
    )
    assert destination.get_mblock(1) is copy_block


def test_conditional_boundary_binding_relocates_after_prior_block_insertion() -> None:
    native_ea = 0x2000
    predicate_ea = 0x2008
    current = _Block(
        1,
        native_ea,
        (_Instruction(ida_hexrays.m_icall, predicate_ea),),
    )
    mba = _MBA(
        (
            _Block(0, 0x1000, (_Instruction(ida_hexrays.m_nop, 0x1000),)),
            current,
        )
    )
    stale = _Block(
        1,
        native_ea,
        (_Instruction(ida_hexrays.m_icall, predicate_ea),),
    )
    key = (0x3000, 7)
    binding = detached_handler_island._BoundaryPortBlockBinding(
        native_ea=native_ea,
        imported_key=key,
    )

    resolved = detached_handler_island._rebind_boundary_port_block(
        mba,
        binding,
        {key: stale},
        exact_instruction_ea=predicate_ea,
    )

    assert resolved is current


def test_imported_rebind_prefers_unique_origin_over_native_duplicate() -> None:
    native_ea = 0x2000
    logical_anchor_ea = 0x2004
    imported_instruction_ea = 0xF10004
    template_target_ea = 0x3000
    template_serial = 7
    imported_owner = _Block(
        1,
        native_ea,
        (_Instruction(ida_hexrays.m_mov, imported_instruction_ea),),
    )
    duplicate_origin = _Block(
        2,
        native_ea,
        (_Instruction(ida_hexrays.m_mov, logical_anchor_ea),),
    )
    mba = _MBA(
        (
            _Block(0, 0x1000, (_Instruction(ida_hexrays.m_nop, 0x1000),)),
            imported_owner,
            duplicate_origin,
        )
    )
    template = detached_handler_island.DetachedSnippetTemplate(
        function_ea=0x1000,
        target_ea=template_target_ea,
        maturity=int(ida_hexrays.MMAT_PREOPTIMIZED),
        root_source_serial=template_serial,
        blocks=(
            detached_handler_island.DetachedSnippetBlockTemplate(
                source_serial=template_serial,
                native_entry_ea=native_ea,
                native_end_ea=logical_anchor_ea + 1,
                instructions=(_Instruction(ida_hexrays.m_mov, logical_anchor_ea),),
                block_type=int(ida_hexrays.BLT_0WAY),
                block_flags=0,
                successor_serials=(),
                external_successor_eas=(),
            ),
        ),
        stack_vd_to_ida=(),
        owned_ranges=((native_ea, logical_anchor_ea + 1),),
    )
    key = (template_target_ea, template_serial)
    binding = detached_handler_island._BoundaryPortBlockBinding(
        native_ea=native_ea,
        imported_key=key,
    )
    identity = detached_handler_island.stable_mba_identity(mba)

    resolved = detached_handler_island._rebind_boundary_port_block(
        mba,
        binding,
        {key: imported_owner},
        exact_instruction_ea=logical_anchor_ea,
        instruction_origins={
            (identity, imported_instruction_ea): logical_anchor_ea,
        },
        templates_by_target={template_target_ea: template},
    )

    assert resolved is imported_owner


def test_imported_boundary_binding_keeps_template_owner_over_live_overlap() -> None:
    native_entry_ea = 0x40CEAB
    native_instruction_ea = 0x40CEAD
    imported_instruction_ea = 0xF1C00210
    template_target_ea = 0x40CE3C
    template_serial = 23
    live = _Block(
        0,
        native_entry_ea,
        (_Instruction(ida_hexrays.m_nop, native_entry_ea),),
    )
    imported = _Block(
        1,
        0x40CDA0,
        (_Instruction(ida_hexrays.m_mov, imported_instruction_ea),),
    )
    mba = _MBA((live, imported), maturity=ida_hexrays.MMAT_PREOPTIMIZED)
    template = detached_handler_island.DetachedSnippetTemplate(
        function_ea=0x40CDA0,
        target_ea=template_target_ea,
        maturity=int(ida_hexrays.MMAT_PREOPTIMIZED),
        root_source_serial=12,
        blocks=(
            detached_handler_island.DetachedSnippetBlockTemplate(
                source_serial=template_serial,
                native_entry_ea=native_entry_ea,
                native_end_ea=native_instruction_ea + 1,
                instructions=(_Instruction(ida_hexrays.m_mov, native_instruction_ea),),
                block_type=int(ida_hexrays.BLT_1WAY),
                block_flags=0,
                successor_serials=(),
                external_successor_eas=(),
            ),
        ),
        stack_vd_to_ida=(),
        owned_ranges=((native_entry_ea, native_instruction_ea + 1),),
    )
    key = (template_target_ea, template_serial)
    binding = detached_handler_island._BoundaryPortBlockBinding(
        native_ea=native_entry_ea,
        imported_key=key,
    )
    identity = detached_handler_island.stable_mba_identity(mba)

    resolved = detached_handler_island._rebind_boundary_port_block(
        mba,
        binding,
        {key: imported},
        instruction_origins={
            (identity, imported_instruction_ea): native_instruction_ea,
        },
        templates_by_target={template_target_ea: template},
    )

    assert resolved is imported


def test_template_block_rebind_prefers_lowered_conditional_source() -> None:
    from d810.analyses.control_flow.detached_handler_island import (
        DetachedSnippetBoundaryPortOwner,
    )

    native_entry_ea = 0x2000
    predicate_ea = 0x2008
    source_instruction_ea = 0xF10008
    helper_instruction_ea = 0xF10018
    template_block = detached_handler_island.DetachedSnippetBlockTemplate(
        source_serial=7,
        native_entry_ea=native_entry_ea,
        native_end_ea=predicate_ea + 1,
        instructions=(_Instruction(ida_hexrays.m_icall, predicate_ea),),
        block_type=int(ida_hexrays.BLT_0WAY),
        block_flags=0,
        successor_serials=(),
        external_successor_eas=(),
    )
    port = _conditional_boundary_port(
        source_block_ea=native_entry_ea,
        predicate_ea=predicate_ea,
        old_taken_target_ea=None,
        old_fallthrough_target_ea=None,
        taken_target_ea=0x3000,
        fallthrough_target_ea=0x3100,
        source_owner=DetachedSnippetBoundaryPortOwner.IMPORTED,
        taken_target_owner=DetachedSnippetBoundaryPortOwner.LIVE,
        fallthrough_target_owner=DetachedSnippetBoundaryPortOwner.LIVE,
    )
    template = detached_handler_island.DetachedSnippetTemplate(
        function_ea=0x1000,
        target_ea=native_entry_ea,
        maturity=int(ida_hexrays.MMAT_PREOPTIMIZED),
        root_source_serial=7,
        blocks=(template_block,),
        stack_vd_to_ida=(),
        owned_ranges=((native_entry_ea, predicate_ea + 1),),
        boundary_ports=detached_handler_island.DetachedSnippetTemplateBoundaryPorts(
            direct=(),
            conditional=(
                detached_handler_island.DetachedSnippetTemplateConditionalBoundaryPort(
                    port=port,
                    source_serial=7,
                    logical_source_serial=None,
                    taken_target_serial=None,
                    fallthrough_target_serial=None,
                ),
            ),
        ),
    )
    source = _Block(
        0,
        0x1000,
        (_Instruction(ida_hexrays.m_jnz, source_instruction_ea),),
    )
    helper = _Block(
        1,
        0x1000,
        (_Instruction(ida_hexrays.m_goto, helper_instruction_ea),),
    )
    mba = _MBA((source, helper), maturity=ida_hexrays.MMAT_PREOPTIMIZED)
    identity = detached_handler_island.stable_mba_identity(mba)
    origins = {
        (identity, source_instruction_ea): predicate_ea,
        (identity, helper_instruction_ea): predicate_ea,
    }

    rebound = detached_handler_island._rebind_imported_template_block(
        mba,
        template,
        7,
        origins,
    )

    assert rebound is source


def test_preopt_import_lowers_resolver_register_compare_cut_to_two_way(
    monkeypatch,
) -> None:
    from d810.analyses.control_flow.detached_handler_island import (
        DetachedSnippetBoundaryPortOwner,
    )
    from d810.hexrays.mutation.deferred_modifier import DeferredGraphModifier

    _install_runtime_fakes(monkeypatch)
    function_ea = 0x9000
    source_ea = 0x1000
    cut_source_ea = 0x1008
    resolver_ea = 0x100E
    taken_target_ea = 0x1100
    fallthrough_target_ea = 0x1180
    source = _MBA(
        (
            _Block(
                0,
                source_ea,
                (_Instruction(ida_hexrays.m_nop, source_ea),),
                (1,),
            ),
            _Block(
                1,
                cut_source_ea,
                (_Instruction(ida_hexrays.m_icall, resolver_ea),),
                (2,),
            ),
            _Block(
                2,
                resolver_ea,
                (_Instruction(ida_hexrays.m_ret, resolver_ea),),
            ),
        ),
        maturity=ida_hexrays.MMAT_PREOPTIMIZED,
    )
    source.get_mblock(0).type = int(ida_hexrays.BLT_1WAY)
    source.get_mblock(1).type = int(ida_hexrays.BLT_1WAY)
    destination = _MBA(
        (
            _Block(
                0,
                function_ea,
                (_Instruction(ida_hexrays.m_nop, function_ea),),
            ),
            _Block(
                1,
                taken_target_ea,
                (_Instruction(ida_hexrays.m_nop, taken_target_ea),),
            ),
            _Block(
                2,
                fallthrough_target_ea,
                (_Instruction(ida_hexrays.m_nop, fallthrough_target_ea),),
            ),
        ),
        maturity=ida_hexrays.MMAT_PREOPTIMIZED,
    )
    port = _conditional_boundary_port(
        source_block_ea=cut_source_ea,
        predicate_ea=resolver_ea,
        old_taken_target_ea=None,
        old_fallthrough_target_ea=None,
        taken_target_ea=taken_target_ea,
        fallthrough_target_ea=fallthrough_target_ea,
        source_owner=DetachedSnippetBoundaryPortOwner.IMPORTED,
        taken_target_owner=DetachedSnippetBoundaryPortOwner.LIVE,
        fallthrough_target_owner=DetachedSnippetBoundaryPortOwner.LIVE,
        predicate_register=16,
        predicate_size=4,
        predicate_constant=0xA4C94734,
        condition_code=5,
        state_register=None,
        taken_state=None,
        fallthrough_state=None,
        resolver_kind="static_fixpoint",
    )
    assert detached_handler_island.capture_preopt_union_snippet_template(
        function_ea,
        source_ea,
        source,
        ((source_ea, resolver_ea + 1),),
        owned_block_entry_eas=(source_ea, cut_source_ea, resolver_ea),
    )
    assert detached_handler_island.bind_preopt_union_snippet_boundary_ports(
        function_ea,
        source_ea,
        (port,),
    )

    calls: list[tuple[int, int, int, int, int, int]] = []

    def lower(
        _modifier,
        source_block,
        taken_target,
        fallthrough_target,
        *,
        indirect_instruction_ea,
        predicate_register,
        predicate_size,
        predicate_constant,
        condition_code,
    ) -> bool:
        calls.append(
            (
                int(taken_target.start),
                int(fallthrough_target.start),
                int(indirect_instruction_ea),
                int(predicate_register),
                int(predicate_constant),
                int(condition_code),
            )
        )
        assert int(predicate_size) == 4
        return True

    monkeypatch.setattr(
        DeferredGraphModifier,
        "lower_proven_indirect_transfer_to_conditional_now",
        lower,
        raising=False,
    )

    result = detached_handler_island.materialize_preopt_union_snippet_templates(
        destination,
        function_ea,
        (source_ea,),
        mutation_gateway=make_mutation_gateway(destination),
    )

    assert len(result.applied_boundary_ports) == 1
    assert calls == [
        (
            taken_target_ea,
            fallthrough_target_ea,
            resolver_ea,
            16,
            0xA4C94734,
            5,
        )
    ]


def test_resolver_conditional_cut_accepts_fictitious_synthetic_return_ea(
    monkeypatch,
) -> None:
    """The imported m_ret envelope has a fictitious, not native, address."""
    from d810.hexrays.mutation.deferred_modifier import DeferredGraphModifier

    _install_runtime_fakes(monkeypatch)
    resolver_ea = 0x100E
    source = _Block(
        0,
        0x1008,
        (_Instruction(ida_hexrays.m_icall, resolver_ea),),
        (1,),
    )
    synthetic_return = _Block(
        1,
        0xF10000,
        (_Instruction(ida_hexrays.m_ret, 0xF10000),),
    )
    taken = _Block(2, 0x1100, (_Instruction(ida_hexrays.m_nop, 0x1100),))
    fallthrough = _Block(
        3,
        0x1180,
        (_Instruction(ida_hexrays.m_nop, 0x1180),),
    )
    mba = _MBA((source, synthetic_return, taken, fallthrough))
    source.type = int(ida_hexrays.BLT_1WAY)
    synthetic_return.type = int(ida_hexrays.BLT_0WAY)
    # SWIG may return distinct Python proxies for the same one-instruction
    # C++ block head/tail.  Structural cardinality, not ``is``, is the proof.
    source.tail = copy.deepcopy(source.head)
    synthetic_return.tail = copy.deepcopy(synthetic_return.head)
    applied: list[dict[str, object]] = []

    def apply_lowering(_modifier, _source, **kwargs) -> bool:
        applied.append(kwargs)
        return True

    monkeypatch.setattr(
        DeferredGraphModifier,
        "_apply_lower_conditional_state_transition",
        apply_lowering,
    )

    assert DeferredGraphModifier(mba).lower_proven_indirect_transfer_to_conditional_now(
        source,
        taken,
        fallthrough,
        indirect_instruction_ea=resolver_ea,
        predicate_register=16,
        predicate_size=4,
        predicate_constant=0xA4C94734,
        condition_code=5,
    )
    assert len(applied) == 1
    assert applied[0]["old_dispatcher_serial"] == int(synthetic_return.serial)


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
        mutation_gateway=make_mutation_gateway(destination),
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
        mutation_gateway=make_mutation_gateway(destination),
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
        predicate_register=16,
        predicate_size=4,
        predicate_constant=0xA4C94734,
        condition_code=5,
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
        mutation_gateway=make_mutation_gateway(destination),
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
        mutation_gateway=make_mutation_gateway(destination),
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
        int(instruction.ea)
        for instruction in imported_source.instructions()
        if origins.get(int(instruction.ea)) is not None
    }
    assert set(evidence[0].target_anchor_eas) == {
        int(instruction.ea)
        for instruction in imported_target.instructions()
        if origins.get(int(instruction.ea)) is not None
    }

    # Hex-Rays may synthesize a root-EA goto in every imported block.  It is
    # not importer-owned instruction provenance and must never make one exact
    # endpoint appear to match the whole imported union.
    synthetic_root = _Instruction(ida_hexrays.m_nop, function_ea)
    imported_source.insert_into_block(synthetic_root, imported_source.tail)
    refreshed = (
        detached_handler_island.imported_detached_snippet_direct_boundary_evidence(
            destination
        )
    )
    assert function_ea not in refreshed[0].endpoint_anchor_eas
    assert set(refreshed[0].endpoint_anchor_eas) == {
        int(instruction.ea)
        for instruction in imported_source.instructions()
        if origins.get(int(instruction.ea)) is not None
    }


def test_pruned_direct_endpoint_receipt_does_not_migrate_to_handler_entry(
    monkeypatch,
) -> None:
    from d810.analyses.control_flow.detached_handler_island import (
        AppliedDetachedSnippetDirectBoundaryPort,
        DetachedSnippetBoundaryPortOwner,
    )

    _install_runtime_fakes(monkeypatch)
    handler_entry_ea = 0x40CADE
    resolver_ea = 0x40CAF7
    terminal_ea = 0x40CD8C
    stale_resolver_anchor = 0xF1C00330
    handler_entry = _Block(
        0,
        handler_entry_ea,
        (_Instruction(ida_hexrays.m_mov, handler_entry_ea),),
    )
    terminal = _Block(
        1,
        terminal_ea,
        (_Instruction(ida_hexrays.m_nop, terminal_ea),),
    )
    mba = _MBA((handler_entry, terminal))
    port = _direct_boundary_port(
        source_block_ea=handler_entry_ea,
        source_instruction_ea=resolver_ea,
        endpoint_block_ea=handler_entry_ea,
        old_successor_eas=(),
        target_ea=terminal_ea,
        source_owner=DetachedSnippetBoundaryPortOwner.IMPORTED,
        endpoint_owner=DetachedSnippetBoundaryPortOwner.IMPORTED,
        target_owner=DetachedSnippetBoundaryPortOwner.LIVE,
        delivery_mode="terminal_goto",
    )
    identity = detached_handler_island.stable_mba_identity(mba)
    detached_handler_island._IMPORTED_DIRECT_BOUNDARY_EVIDENCE[identity] = (
        AppliedDetachedSnippetDirectBoundaryPort(
            port=port,
            endpoint_anchor_eas=(stale_resolver_anchor,),
            target_anchor_eas=(terminal_ea,),
        ),
    )

    evidence = (
        detached_handler_island.imported_detached_snippet_direct_boundary_evidence(mba)
    )

    assert len(evidence) == 1
    assert evidence[0].endpoint_anchor_eas == (stale_resolver_anchor,)
    assert handler_entry_ea not in evidence[0].endpoint_anchor_eas


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
        mutation_gateway=make_mutation_gateway(destination),
    )

    assert tuple(destination.get_mblock(1).succset) == (result[target_ea],)
    assert result.applied_boundary_ports[0].endpoint_block_ea == live_source_ea


def test_import_boundary_port_binds_imported_target_by_represented_range(
    monkeypatch,
) -> None:
    from d810.analyses.control_flow.detached_handler_island import (
        DetachedSnippetBoundaryPortOwner,
    )

    _install_runtime_fakes(monkeypatch)
    function_ea = 0x9000
    live_source_ea = 0x1000
    imported_root_ea = 0x1080
    imported_target_ea = 0x1100
    imported_survivor_ea = 0x1102
    dispatcher_ea = 0x1200
    source = _MBA(
        (
            _Block(
                0,
                imported_root_ea,
                (_Instruction(ida_hexrays.m_nop, imported_root_ea),),
            ),
            _Block(
                1,
                imported_survivor_ea,
                (_Instruction(ida_hexrays.m_nop, imported_survivor_ea),),
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
        target_ea=imported_target_ea,
        source_owner=DetachedSnippetBoundaryPortOwner.LIVE,
        endpoint_owner=DetachedSnippetBoundaryPortOwner.LIVE,
        target_owner=DetachedSnippetBoundaryPortOwner.IMPORTED,
    )

    assert detached_handler_island.capture_detached_snippet_template(
        function_ea,
        imported_root_ea,
        source,
        (
            (imported_root_ea, imported_root_ea + 1),
            (imported_target_ea, imported_target_ea + 0x10),
        ),
        boundary_ports=(port,),
    )
    result = detached_handler_island.materialize_detached_snippet_templates(
        destination,
        function_ea,
        (imported_root_ea,),
        mutation_gateway=make_mutation_gateway(destination),
    )

    origins = dict(
        detached_handler_island.imported_detached_snippet_instruction_origins(
            destination
        )
    )
    imported_target = next(
        block
        for block in destination.blocks
        if block.head is not None
        and origins.get(int(block.head.ea)) == imported_survivor_ea
    )
    assert tuple(destination.get_mblock(1).succset) == (int(imported_target.serial),)
    assert int(imported_target.serial) != result[imported_root_ea]
    assert result.applied_boundary_ports[0].target_eas == (imported_target_ea,)


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
        mutation_gateway=make_mutation_gateway(destination),
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
        mutation_gateway=make_mutation_gateway(destination),
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
        mutation_gateway=make_mutation_gateway(destination),
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
        mutation_gateway=make_mutation_gateway(destination),
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
    taken_block._set_instructions(())
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
    detached_handler_island._IMPORTED_INSTRUCTION_ORIGINS[
        (identity, rebound_anchor_ea)
    ] = taken_target_ea

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
        mutation_gateway=make_mutation_gateway(destination),
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
        mutation_gateway=make_mutation_gateway(destination),
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
        mutation_gateway=make_mutation_gateway(destination),
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
        mutation_gateway=make_mutation_gateway(destination),
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
        mutation_gateway=make_mutation_gateway(destination),
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
        mutation_gateway=make_mutation_gateway(destination),
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


def test_native_lookup_uses_imported_instruction_origin(monkeypatch) -> None:
    _install_runtime_fakes(monkeypatch)
    imported_ea = 0xF1C001C4
    native_ea = 0x40CF38
    imported = _Block(
        0,
        0x40CDA0,
        (_Instruction(ida_hexrays.m_mov, imported_ea),),
    )
    destination = _MBA((imported,))
    detached_handler_island._IMPORTED_INSTRUCTION_ORIGINS[
        (detached_handler_island.stable_mba_identity(destination), imported_ea)
    ] = native_ea

    result = detached_handler_island.find_unique_live_block_by_native_ea(
        destination,
        native_ea,
    )

    assert result is imported


def test_native_lookup_ignores_empty_external_placeholder_collision(
    monkeypatch,
) -> None:
    _install_runtime_fakes(monkeypatch)
    native_ea = 0x40CD46
    imported_ea = 0xF1C00148
    external = _Block(0, native_ea, ())
    external.type = int(ida_hexrays.BLT_XTRN)
    imported = _Block(
        1,
        0x40C8B0,
        (_Instruction(ida_hexrays.m_mov, imported_ea),),
    )
    destination = _MBA((external, imported))
    detached_handler_island._IMPORTED_INSTRUCTION_ORIGINS[
        (detached_handler_island.stable_mba_identity(destination), imported_ea)
    ] = native_ea

    result = detached_handler_island.find_unique_live_block_by_native_ea(
        destination,
        native_ea,
    )

    assert result is imported


def test_native_lookup_abstains_on_competing_instruction_backed_live_owner(
    monkeypatch,
) -> None:
    _install_runtime_fakes(monkeypatch)
    native_ea = 0x40E4A1
    imported_ea = 0xF1C017EC
    live = _Block(
        0,
        native_ea,
        (_Instruction(ida_hexrays.m_mov, native_ea),),
    )
    imported = _Block(
        1,
        0x40D200,
        (_Instruction(ida_hexrays.m_mov, imported_ea),),
    )
    destination = _MBA((live, imported))
    detached_handler_island._IMPORTED_INSTRUCTION_ORIGINS[
        (detached_handler_island.stable_mba_identity(destination), imported_ea)
    ] = native_ea

    result = detached_handler_island.find_unique_live_block_by_native_ea(
        destination,
        native_ea,
    )

    assert result is None


def test_materialized_handler_lookup_prefers_unique_exact_imported_owner(
    monkeypatch,
) -> None:
    _install_runtime_fakes(monkeypatch)
    native_ea = 0x40E4A1
    imported_ea = 0xF1C017EC
    live = _Block(
        0,
        native_ea,
        (_Instruction(ida_hexrays.m_mov, native_ea),),
    )
    imported = _Block(
        1,
        0x40D200,
        (_Instruction(ida_hexrays.m_mov, imported_ea),),
    )
    destination = _MBA((live, imported))
    detached_handler_island._IMPORTED_INSTRUCTION_ORIGINS[
        (detached_handler_island.stable_mba_identity(destination), imported_ea)
    ] = native_ea

    result = detached_handler_island.find_materialized_handler_block_by_native_ea(
        destination,
        native_ea,
    )

    assert result is imported


def test_materialized_handler_lookup_uses_exact_imported_range_when_entry_is_eliminated(
    monkeypatch,
) -> None:
    _install_runtime_fakes(monkeypatch)
    native_entry_ea = 0x40B199
    native_predicate_ea = 0x40B1B0
    imported_entry_ea = 0xF1C00A60
    imported_predicate_ea = 0xF1C00A74
    live = _Block(
        0,
        0x40B18D,
        (_Instruction(ida_hexrays.m_mov, native_entry_ea),),
    )
    imported = _Block(
        1,
        0x40A560,
        (
            _Instruction(ida_hexrays.m_mov, imported_entry_ea),
            _Instruction(ida_hexrays.m_jnz, imported_predicate_ea),
        ),
    )
    destination = _MBA((live, imported))
    identity = detached_handler_island.stable_mba_identity(destination)
    detached_handler_island._IMPORTED_NATIVE_BLOCK_RANGES[
        (identity, native_entry_ea, native_predicate_ea + 2)
    ] = (
        detached_handler_island._ImportedSnippetRoot(
            serial_hint=1,
            anchor_eas=(imported_entry_ea, imported_predicate_ea),
            owned_instruction_eas=(imported_entry_ea, imported_predicate_ea),
        )
    )
    detached_handler_island._IMPORTED_INSTRUCTION_ORIGINS.update(
        {
            (identity, imported_entry_ea): 0x40B1A0,
            (identity, imported_predicate_ea): native_predicate_ea,
        }
    )

    result = detached_handler_island.find_materialized_handler_block_by_native_ea(
        destination,
        native_entry_ea,
        required_native_eas=(native_predicate_ea,),
    )

    assert result is imported


def test_materialized_handler_lookup_abstains_on_range_only_competitor(
    monkeypatch,
) -> None:
    _install_runtime_fakes(monkeypatch)
    native_ea = 0x40E4A1
    imported_ea = 0xF1C017EC
    range_ea = 0xF1C01800
    exact = _Block(
        0,
        0x40D200,
        (_Instruction(ida_hexrays.m_mov, imported_ea),),
    )
    range_only = _Block(
        1,
        0x40D200,
        (_Instruction(ida_hexrays.m_mov, range_ea),),
    )
    destination = _MBA((exact, range_only))
    identity = detached_handler_island.stable_mba_identity(destination)
    detached_handler_island._IMPORTED_INSTRUCTION_ORIGINS[(identity, imported_ea)] = (
        native_ea
    )
    detached_handler_island._IMPORTED_NATIVE_BLOCK_RANGES[
        (identity, native_ea - 4, native_ea + 4)
    ] = detached_handler_island._ImportedSnippetRoot(
        serial_hint=1,
        anchor_eas=(range_ea,),
        owned_instruction_eas=(range_ea,),
    )

    result = detached_handler_island.find_materialized_handler_block_by_native_ea(
        destination,
        native_ea,
    )

    assert result is None


def test_materialized_handler_lookup_uses_unique_native_owner_after_clone_folds(
    monkeypatch,
) -> None:
    _install_runtime_fakes(monkeypatch)
    native_ea = 0x40DC04
    imported_ea = 0xF1C00C10
    live = _Block(
        0,
        native_ea,
        (_Instruction(ida_hexrays.m_mov, native_ea),),
    )
    range_only = _Block(
        1,
        0x40D200,
        (_Instruction(ida_hexrays.m_mov, imported_ea),),
    )
    destination = _MBA((live, range_only))
    identity = detached_handler_island.stable_mba_identity(destination)
    detached_handler_island._IMPORTED_INSTRUCTION_ORIGINS[(identity, imported_ea)] = (
        native_ea + 6
    )
    detached_handler_island._IMPORTED_NATIVE_BLOCK_RANGES[
        (identity, native_ea, native_ea + 0x26)
    ] = detached_handler_island._ImportedSnippetRoot(
        serial_hint=1,
        anchor_eas=(imported_ea,),
        owned_instruction_eas=(imported_ea,),
    )

    result = detached_handler_island.find_materialized_handler_block_by_native_ea(
        destination,
        native_ea,
    )

    assert result is live


def test_materialized_handler_lookup_abstains_on_multiple_exact_imports(
    monkeypatch,
) -> None:
    _install_runtime_fakes(monkeypatch)
    native_ea = 0x40E4A1
    first_imported_ea = 0xF1C017EC
    second_imported_ea = 0xF1C017F0
    first = _Block(
        0,
        0x40D200,
        (_Instruction(ida_hexrays.m_mov, first_imported_ea),),
    )
    second = _Block(
        1,
        0x40D200,
        (_Instruction(ida_hexrays.m_mov, second_imported_ea),),
    )
    destination = _MBA((first, second))
    identity = detached_handler_island.stable_mba_identity(destination)
    detached_handler_island._IMPORTED_INSTRUCTION_ORIGINS.update(
        {
            (identity, first_imported_ea): native_ea,
            (identity, second_imported_ea): native_ea,
        }
    )

    result = detached_handler_island.find_materialized_handler_block_by_native_ea(
        destination,
        native_ea,
    )

    assert result is None


def test_native_presence_accepts_multiple_instruction_backed_provenance_owners(
    monkeypatch,
) -> None:
    _install_runtime_fakes(monkeypatch)
    native_ea = 0x40CF38
    first_imported_ea = 0xF1C001C4
    second_imported_ea = 0xF1C001D4
    first = _Block(
        0,
        0x40CDA0,
        (_Instruction(ida_hexrays.m_mov, first_imported_ea),),
    )
    second = _Block(
        1,
        0x40CDA0,
        (_Instruction(ida_hexrays.m_goto, second_imported_ea),),
    )
    destination = _MBA((first, second))
    identity = detached_handler_island.stable_mba_identity(destination)
    detached_handler_island._IMPORTED_INSTRUCTION_ORIGINS.update(
        {
            (identity, first_imported_ea): native_ea,
            (identity, second_imported_ea): native_ea,
        }
    )

    assert detached_handler_island.has_instruction_backed_native_block(
        destination,
        native_ea,
    )


def test_native_lookup_uses_range_owner_over_empty_external_placeholder(
    monkeypatch,
) -> None:
    _install_runtime_fakes(monkeypatch)
    native_entry_ea = 0x40CE3C
    native_instruction_ea = 0x40CE48
    native_end_ea = 0x40CE73
    imported_ea = 0xF1C00098
    external = _Block(0, native_entry_ea, ())
    external.type = int(ida_hexrays.BLT_XTRN)
    imported = _Block(
        1,
        0x40CDA0,
        (_Instruction(ida_hexrays.m_mov, imported_ea),),
    )
    destination = _MBA((external, imported))
    identity = detached_handler_island.stable_mba_identity(destination)
    detached_handler_island._IMPORTED_INSTRUCTION_ORIGINS[(identity, imported_ea)] = (
        native_instruction_ea
    )
    detached_handler_island._IMPORTED_NATIVE_BLOCK_RANGES[
        (identity, native_entry_ea, native_end_ea)
    ] = detached_handler_island._ImportedSnippetRoot(
        serial_hint=1,
        anchor_eas=(imported_ea,),
        owned_instruction_eas=(imported_ea,),
    )

    result = detached_handler_island.find_unique_live_block_by_native_ea(
        destination,
        native_entry_ea,
    )

    assert result is imported


def test_native_lookup_uses_imported_block_range_for_empty_entry(
    monkeypatch,
) -> None:
    _install_runtime_fakes(monkeypatch)
    native_entry_ea = 0x40CF38
    native_instruction_ea = 0x40CF3C
    native_end_ea = 0x40CF76
    imported_ea = 0xF1C001C4
    imported = _Block(
        0,
        0x40CDA0,
        (_Instruction(ida_hexrays.m_mov, imported_ea),),
    )
    destination = _MBA((imported,))
    identity = detached_handler_island.stable_mba_identity(destination)
    detached_handler_island._IMPORTED_INSTRUCTION_ORIGINS[(identity, imported_ea)] = (
        native_instruction_ea
    )
    detached_handler_island._IMPORTED_NATIVE_BLOCK_RANGES[
        (identity, native_entry_ea, native_end_ea)
    ] = detached_handler_island._ImportedSnippetRoot(
        serial_hint=0,
        anchor_eas=(imported_ea,),
        owned_instruction_eas=(imported_ea,),
    )

    result = detached_handler_island.find_unique_live_block_by_native_ea(
        destination,
        native_entry_ea,
    )

    assert result is imported


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
        mutation_gateway=make_mutation_gateway(destination),
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
        mutation_gateway=make_mutation_gateway(destination),
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
        mutation_gateway=make_mutation_gateway(destination),
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
        mutation_gateway=make_mutation_gateway(destination),
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


def test_resolver_cut_port_replaces_synthetic_return_envelope(
    monkeypatch,
) -> None:
    from d810.analyses.control_flow.detached_handler_island import (
        DetachedSnippetBoundaryPortOwner,
    )

    _install_runtime_fakes(monkeypatch)
    resolver_ea = 0x100E
    synthetic_return_ea = 0x1010
    target_ea = 0x2000
    source = _Block(
        0,
        resolver_ea,
        (_Instruction(ida_hexrays.m_icall, resolver_ea),),
        (1,),
    )
    source.type = int(ida_hexrays.BLT_1WAY)
    synthetic_return = _Block(
        1,
        synthetic_return_ea,
        (_Instruction(ida_hexrays.m_ret, synthetic_return_ea),),
    )
    synthetic_return.type = int(ida_hexrays.BLT_STOP)
    synthetic_return.predset.push_back(int(source.serial))
    target = _Block(
        2,
        target_ea,
        (_Instruction(ida_hexrays.m_nop, target_ea),),
    )
    destination = _MBA(
        (source, synthetic_return, target),
        maturity=ida_hexrays.MMAT_PREOPTIMIZED,
    )
    port = _direct_boundary_port(
        source_block_ea=resolver_ea,
        endpoint_block_ea=resolver_ea,
        old_successor_eas=(),
        target_ea=target_ea,
        source_owner=DetachedSnippetBoundaryPortOwner.LIVE,
        endpoint_owner=DetachedSnippetBoundaryPortOwner.LIVE,
        target_owner=DetachedSnippetBoundaryPortOwner.LIVE,
        delivery_mode="terminal_goto",
    )
    record = detached_handler_island.DetachedSnippetTemplateDirectBoundaryPort(
        port=port,
        source_serial=None,
        endpoint_serial=None,
        target_serial=None,
    )
    batch = detached_handler_island._BoundaryPortMutationBatch(
        direct=(
            detached_handler_island._DirectBoundaryPortMutation(
                records=(record,),
                endpoint=detached_handler_island._BoundaryPortBlockBinding(
                    native_ea=resolver_ea,
                    live_block=source,
                    exact_instruction_opcode=int(ida_hexrays.m_icall),
                ),
                old_targets=(),
                target=detached_handler_island._BoundaryPortBlockBinding(
                    native_ea=target_ea,
                    live_block=target,
                ),
            ),
        ),
        conditional=(),
    )

    applied = detached_handler_island._apply_boundary_port_batch(
        destination, batch, {}, mutation_gateway=make_mutation_gateway(destination)
    )

    assert applied is not None
    assert len(applied) == 1
    assert tuple(source.succset) == (int(target.serial),)
    assert int(source.tail.opcode) == int(ida_hexrays.m_goto)
    assert int(source.tail.l.b) == int(target.serial)
    assert int(source.serial) not in synthetic_return.predset
    assert int(source.serial) in target.predset


def test_resolver_cut_port_rebinds_split_imported_endpoint_by_origin(
    monkeypatch,
) -> None:
    """A post-import split must not strand the resolver-cut instruction."""
    from d810.analyses.control_flow.detached_handler_island import (
        DetachedSnippetBoundaryPortOwner,
    )

    _install_runtime_fakes(monkeypatch)
    source_ea = 0x40CADE
    resolver_ea = 0x40CAF7
    synthetic_resolver_ea = 0xF1C0030C
    target_ea = 0x40CD8C
    imported_key = (source_ea, 7)

    imported_root = _Block(
        0,
        source_ea,
        (_Instruction(ida_hexrays.m_mov, source_ea),),
        (1,),
    )
    imported_root.type = int(ida_hexrays.BLT_1WAY)
    split_endpoint = _Block(
        1,
        source_ea,
        (_Instruction(ida_hexrays.m_ijmp, synthetic_resolver_ea),),
        (2,),
    )
    split_endpoint.type = int(ida_hexrays.BLT_1WAY)
    target = _Block(
        2,
        target_ea,
        (_Instruction(ida_hexrays.m_nop, target_ea),),
    )
    imported_root.predset = _SerialList()
    split_endpoint.predset.push_back(int(imported_root.serial))
    target.predset.push_back(int(split_endpoint.serial))
    destination = _MBA(
        (imported_root, split_endpoint, target),
        maturity=ida_hexrays.MMAT_PREOPTIMIZED,
    )
    port = _direct_boundary_port(
        source_block_ea=source_ea,
        source_instruction_ea=resolver_ea,
        endpoint_block_ea=source_ea,
        old_successor_eas=(),
        target_ea=target_ea,
        source_owner=DetachedSnippetBoundaryPortOwner.IMPORTED,
        endpoint_owner=DetachedSnippetBoundaryPortOwner.IMPORTED,
        target_owner=DetachedSnippetBoundaryPortOwner.LIVE,
        delivery_mode="terminal_goto",
    )
    record = detached_handler_island.DetachedSnippetTemplateDirectBoundaryPort(
        port=port,
        source_serial=7,
        endpoint_serial=7,
        target_serial=None,
    )
    batch = detached_handler_island._BoundaryPortMutationBatch(
        direct=(
            detached_handler_island._DirectBoundaryPortMutation(
                records=(record,),
                endpoint=detached_handler_island._BoundaryPortBlockBinding(
                    native_ea=source_ea,
                    imported_key=imported_key,
                    exact_instruction_opcode=int(ida_hexrays.m_icall),
                ),
                old_targets=(),
                target=detached_handler_island._BoundaryPortBlockBinding(
                    native_ea=target_ea,
                    live_block=target,
                ),
            ),
        ),
        conditional=(),
    )
    instruction_origins = {
        (
            detached_handler_island.stable_mba_identity(destination),
            synthetic_resolver_ea,
        ): resolver_ea
    }
    applied = detached_handler_island._apply_boundary_port_batch(
        destination,
        batch,
        {imported_key: imported_root},
        pending_instruction_origins=instruction_origins,
        mutation_gateway=make_mutation_gateway(destination),
    )

    assert applied is not None
    assert len(applied) == 1
    assert tuple(split_endpoint.succset) == (int(target.serial),)
    assert int(split_endpoint.tail.opcode) == int(ida_hexrays.m_goto)
    assert (
        detached_handler_island._rebind_direct_boundary_evidence_blocks(
            destination,
            batch.direct[0],
            {imported_key: imported_root},
            instruction_origins={},
            templates_by_target={},
        )
        is None
    )
    # The native runtime preserves the imported synthetic EA when replacing
    # the transfer; the lightweight fake gateway uses the function EA.
    split_endpoint.tail.ea = synthetic_resolver_ea
    assert detached_handler_island._rebind_direct_boundary_evidence_blocks(
        destination,
        batch.direct[0],
        {imported_key: imported_root},
        instruction_origins=instruction_origins,
        templates_by_target={},
    ) == (split_endpoint, target)


def test_exact_state_route_collapses_two_way_dispatcher_envelope(
    monkeypatch,
) -> None:
    from d810.analyses.control_flow.detached_handler_island import (
        DetachedSnippetBoundaryPortOwner,
    )

    _install_runtime_fakes(monkeypatch)
    source_ea = 0x1000
    resolver_ea = 0x100E
    first_router_ea = 0x1100
    second_router_ea = 0x1200
    target_ea = 0x2000
    source = _Block(
        0,
        source_ea,
        (
            _Instruction(
                ida_hexrays.m_jnz,
                resolver_ea,
                dest=_Operand(ida_hexrays.mop_b, block_ref=1),
            ),
        ),
        (1, 2),
    )
    source.type = int(ida_hexrays.BLT_2WAY)
    first_router = _Block(
        1,
        first_router_ea,
        (_Instruction(ida_hexrays.m_nop, first_router_ea),),
    )
    second_router = _Block(
        2,
        second_router_ea,
        (_Instruction(ida_hexrays.m_nop, second_router_ea),),
    )
    target = _Block(
        3,
        target_ea,
        (_Instruction(ida_hexrays.m_nop, target_ea),),
    )
    first_router.predset.push_back(int(source.serial))
    second_router.predset.push_back(int(source.serial))
    destination = _MBA((source, first_router, second_router, target))
    port = _direct_boundary_port(
        source_block_ea=source_ea,
        endpoint_block_ea=source_ea,
        old_successor_eas=(),
        target_ea=target_ea,
        source_owner=DetachedSnippetBoundaryPortOwner.LIVE,
        endpoint_owner=DetachedSnippetBoundaryPortOwner.LIVE,
        target_owner=DetachedSnippetBoundaryPortOwner.LIVE,
        delivery_mode="terminal_goto",
        source_replaces_dispatcher_envelope=True,
    )
    record = detached_handler_island.DetachedSnippetTemplateDirectBoundaryPort(
        port=port,
        source_serial=None,
        endpoint_serial=None,
        target_serial=None,
    )
    batch = detached_handler_island._BoundaryPortMutationBatch(
        direct=(
            detached_handler_island._DirectBoundaryPortMutation(
                records=(record,),
                endpoint=detached_handler_island._BoundaryPortBlockBinding(
                    native_ea=source_ea,
                    live_block=source,
                ),
                old_targets=(),
                target=detached_handler_island._BoundaryPortBlockBinding(
                    native_ea=target_ea,
                    live_block=target,
                ),
            ),
        ),
        conditional=(),
    )

    applied = detached_handler_island._apply_boundary_port_batch(
        destination, batch, {}, mutation_gateway=make_mutation_gateway(destination)
    )

    assert applied is not None
    assert len(applied) == 1
    assert tuple(source.succset) == (int(target.serial),)
    assert int(source.tail.opcode) == int(ida_hexrays.m_goto)
    assert int(source.tail.l.b) == int(target.serial)
    assert int(source.serial) not in first_router.predset
    assert int(source.serial) not in second_router.predset
    assert int(source.serial) in target.predset


def test_exact_state_route_collapses_preopt_call_dispatcher_envelope(
    monkeypatch,
) -> None:
    from d810.analyses.control_flow.detached_handler_island import (
        DetachedSnippetBoundaryPortOwner,
    )

    _install_runtime_fakes(monkeypatch)
    source_ea = 0x1000
    resolver_ea = 0x100E
    router_ea = 0x1100
    target_ea = 0x2000
    source = _Block(
        0,
        source_ea,
        (_Instruction(ida_hexrays.m_call, resolver_ea),),
        (1,),
    )
    source.type = int(ida_hexrays.BLT_1WAY)
    source.flags |= int(ida_hexrays.MBL_CALL)
    router = _Block(
        1,
        router_ea,
        (_Instruction(ida_hexrays.m_nop, router_ea),),
    )
    target = _Block(
        2,
        target_ea,
        (_Instruction(ida_hexrays.m_nop, target_ea),),
    )
    router.predset.push_back(int(source.serial))
    destination = _MBA((source, router, target))
    port = _direct_boundary_port(
        source_block_ea=source_ea,
        endpoint_block_ea=source_ea,
        old_successor_eas=(),
        target_ea=target_ea,
        source_owner=DetachedSnippetBoundaryPortOwner.LIVE,
        endpoint_owner=DetachedSnippetBoundaryPortOwner.LIVE,
        target_owner=DetachedSnippetBoundaryPortOwner.LIVE,
        delivery_mode="terminal_goto",
        source_replaces_dispatcher_envelope=True,
    )
    record = detached_handler_island.DetachedSnippetTemplateDirectBoundaryPort(
        port=port,
        source_serial=None,
        endpoint_serial=None,
        target_serial=None,
    )
    batch = detached_handler_island._BoundaryPortMutationBatch(
        direct=(
            detached_handler_island._DirectBoundaryPortMutation(
                records=(record,),
                endpoint=detached_handler_island._BoundaryPortBlockBinding(
                    native_ea=source_ea,
                    live_block=source,
                ),
                old_targets=(),
                target=detached_handler_island._BoundaryPortBlockBinding(
                    native_ea=target_ea,
                    live_block=target,
                ),
            ),
        ),
        conditional=(),
    )

    applied = detached_handler_island._apply_boundary_port_batch(
        destination, batch, {}, mutation_gateway=make_mutation_gateway(destination)
    )

    assert applied is not None
    assert len(applied) == 1
    assert tuple(source.succset) == (int(target.serial),)
    assert int(source.tail.opcode) == int(ida_hexrays.m_goto)
    assert not (int(source.flags) & int(ida_hexrays.MBL_CALL))
    assert int(source.serial) not in router.predset
    assert int(source.serial) in target.predset


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
        mutation_gateway=make_mutation_gateway(destination),
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
        mutation_gateway=make_mutation_gateway(destination),
    )
    imported_return = destination.get_mblock(roots[return_ea])
    assert int(imported_return.tail.opcode) == int(ida_hexrays.m_ret)
    assert int(imported_return.type) == int(ida_hexrays.BLT_0WAY)
    assert tuple(imported_return.succset) == ()


def test_capture_normalizes_native_mret_with_synthetic_exit_to_terminal_block(
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
                    _Instruction(ida_hexrays.m_mov, return_ea),
                    _Instruction(ida_hexrays.m_ret, return_ea + 1),
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
        ((return_ea, return_ea + 2),),
    )
    roots = detached_handler_island.materialize_detached_snippet_templates(
        destination,
        function_ea,
        (return_ea,),
        allow_raw_preopt_calls=True,
        mutation_gateway=make_mutation_gateway(destination),
    )
    imported_return = destination.get_mblock(roots[return_ea])
    assert tuple(
        int(instruction.opcode) for instruction in imported_return.instructions()
    ) == (int(ida_hexrays.m_mov), int(ida_hexrays.m_ret))
    assert int(imported_return.type) == int(ida_hexrays.BLT_0WAY)
    assert tuple(imported_return.succset) == ()


def test_capture_appends_return_only_for_native_terminal_evidence(monkeypatch) -> None:
    _install_runtime_fakes(monkeypatch)
    function_ea = 0xB000
    return_ea = 0x3300
    original = _Instruction(ida_hexrays.m_mov, return_ea)
    source = _MBA(
        (
            _Block(0, return_ea, (original,), (1,)),
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

    assert not detached_handler_island.capture_detached_snippet_template(
        function_ea,
        return_ea,
        source,
        ((return_ea, return_ea + 1),),
    )
    assert detached_handler_island.capture_detached_snippet_template(
        function_ea,
        return_ea,
        source,
        ((return_ea, return_ea + 1),),
        terminal_return_entry_eas=(return_ea,),
    )

    roots = detached_handler_island.materialize_detached_snippet_templates(
        destination,
        function_ea,
        (return_ea,),
        allow_raw_preopt_calls=True,
        mutation_gateway=make_mutation_gateway(destination),
    )
    imported_return = destination.get_mblock(roots[return_ea])
    opcodes = tuple(
        int(instruction.opcode) for instruction in imported_return.instructions()
    )
    assert opcodes == (int(ida_hexrays.m_mov), int(ida_hexrays.m_ret))
    assert int(imported_return.type) == int(ida_hexrays.BLT_0WAY)
    assert tuple(imported_return.succset) == ()


def test_capture_materializes_empty_proven_native_return(monkeypatch) -> None:
    _install_runtime_fakes(monkeypatch)
    function_ea = 0xB000
    return_ea = 0x3300
    source = _MBA(
        (_Block(0, return_ea, ()),),
        maturity=ida_hexrays.MMAT_PREOPTIMIZED,
    )
    source.get_mblock(0).type = int(ida_hexrays.BLT_0WAY)
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
        terminal_return_entry_eas=(return_ea,),
    )

    roots = detached_handler_island.materialize_detached_snippet_templates(
        destination,
        function_ea,
        (return_ea,),
        allow_raw_preopt_calls=True,
        mutation_gateway=make_mutation_gateway(destination),
    )
    imported_return = destination.get_mblock(roots[return_ea])
    assert tuple(
        int(instruction.opcode) for instruction in imported_return.instructions()
    ) == (int(ida_hexrays.m_ret),)
    assert int(imported_return.type) == int(ida_hexrays.BLT_0WAY)
    assert tuple(imported_return.succset) == ()


def test_preopt_union_template_does_not_replace_legacy_fallback(monkeypatch) -> None:
    _install_runtime_fakes(monkeypatch)
    function_ea = 0xB000
    target_ea = 0x3300
    legacy_source = _MBA(
        (
            _Block(
                0,
                target_ea,
                (_Instruction(ida_hexrays.m_mov, target_ea),),
            ),
        ),
        maturity=ida_hexrays.MMAT_LOCOPT,
    )
    union_source = _MBA(
        (
            _Block(
                0,
                target_ea,
                (_Instruction(ida_hexrays.m_xor, target_ea),),
            ),
        ),
        maturity=ida_hexrays.MMAT_PREOPTIMIZED,
    )

    assert detached_handler_island.capture_detached_snippet_template(
        function_ea,
        target_ea,
        legacy_source,
        ((target_ea, target_ea + 1),),
    )
    assert detached_handler_island.capture_preopt_union_snippet_template(
        function_ea,
        target_ea,
        union_source,
        ((target_ea, target_ea + 1),),
    )
    assert detached_handler_island.has_detached_snippet_template(
        function_ea,
        target_ea,
    )
    assert detached_handler_island.has_preopt_union_snippet_template(
        function_ea,
        target_ea,
    )

    legacy_destination = _MBA(
        (
            _Block(
                0,
                function_ea,
                (_Instruction(ida_hexrays.m_nop, function_ea),),
            ),
        ),
        maturity=ida_hexrays.MMAT_LOCOPT,
    )
    union_destination = _MBA(
        (
            _Block(
                0,
                function_ea,
                (_Instruction(ida_hexrays.m_nop, function_ea),),
            ),
        ),
        maturity=ida_hexrays.MMAT_PREOPTIMIZED,
    )
    legacy_roots = detached_handler_island.materialize_detached_snippet_templates(
        legacy_destination,
        function_ea,
        (target_ea,),
        mutation_gateway=make_mutation_gateway(legacy_destination),
    )
    union_roots = detached_handler_island.materialize_preopt_union_snippet_templates(
        union_destination,
        function_ea,
        (target_ea,),
        mutation_gateway=make_mutation_gateway(union_destination),
    )

    assert int(
        legacy_destination.get_mblock(legacy_roots[target_ea]).head.opcode
    ) == int(ida_hexrays.m_mov)
    assert int(union_destination.get_mblock(union_roots[target_ea]).head.opcode) == int(
        ida_hexrays.m_xor
    )


def test_preopt_union_capture_owns_instruction_backed_range_splits(
    monkeypatch,
) -> None:
    _install_runtime_fakes(monkeypatch)
    function_ea = 0xB000
    target_ea = 0x3300
    split_ea = 0x3304
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
                split_ea,
                (_Instruction(ida_hexrays.m_xor, split_ea),),
            ),
        ),
        maturity=ida_hexrays.MMAT_PREOPTIMIZED,
    )
    source.get_mblock(0).type = int(ida_hexrays.BLT_1WAY)

    assert detached_handler_island.capture_preopt_union_snippet_template(
        function_ea,
        target_ea,
        source,
        ((target_ea, split_ea + 1),),
        owned_block_entry_eas=(target_ea, split_ea),
    )
    template = detached_handler_island._PREOPT_UNION_SNIPPET_TEMPLATES[
        (function_ea, target_ea)
    ]
    assert tuple(block.native_entry_ea for block in template.blocks) == (
        target_ea,
        split_ea,
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
    roots = detached_handler_island.materialize_preopt_union_snippet_templates(
        destination,
        function_ea,
        (target_ea,),
        mutation_gateway=make_mutation_gateway(destination),
    )

    assert set(roots) == {target_ea}
    secondary = detached_handler_island.find_unique_live_block_by_native_ea(
        destination,
        split_ea,
    )
    assert secondary is not None
    assert secondary.head is not None
    assert int(secondary.head.ea) != split_ea


def test_preopt_union_import_publishes_native_blocks_to_session_identity_index(
    monkeypatch,
) -> None:
    _install_runtime_fakes(monkeypatch)
    function_ea = 0xB000
    target_ea = 0x40EAA7
    source = _MBA(
        (
            _Block(
                0,
                target_ea,
                (_Instruction(ida_hexrays.m_mov, target_ea),),
            ),
        ),
        maturity=ida_hexrays.MMAT_PREOPTIMIZED,
    )
    assert detached_handler_island.capture_preopt_union_snippet_template(
        function_ea,
        target_ea,
        source,
        ((target_ea, target_ea + 1),),
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
    session_id = "rhad.i64:0xB000:1"
    entry_identity = StableBlockIdentity.from_intervals(
        (NativeEaInterval(function_ea, function_ea + 1),), native_key=NATIVE_KEY
    )
    imported_identity = StableBlockIdentity.from_intervals(
        (NativeEaInterval(target_ea, target_ea + 1),), native_key=NATIVE_KEY
    )
    index = MbaBlockIdentityIndex.from_bindings(
        generation=0,
        bindings=((entry_identity, 0),),
        session_id=session_id,
        native_key=NATIVE_KEY,
    )
    gateway = MbaMutationGateway(
        session_id=session_id,
        function_ea=function_ea,
        maturity=ida_hexrays.MMAT_PREOPTIMIZED,
        identity_index=index,
        native_key=NATIVE_KEY,
    )

    roots = detached_handler_island.materialize_preopt_union_snippet_templates(
        destination,
        function_ea,
        (target_ea,),
        mutation_gateway=gateway,
    )

    rebound = index.rebind_identity(imported_identity)
    assert rebound.block is not None
    assert rebound.block.serial == roots[target_ea]
    assert rebound.block.handle.provenance is BlockHandleProvenance.IMPORTED_NATIVE
    assert index.rebind_imported_identity(imported_identity).block == rebound.block
    assert index.generation == 1


def test_preopt_union_import_barrier_rejects_same_mba_reentry(monkeypatch) -> None:
    mba = SimpleNamespace(this=0x1234)
    observed: list[bool] = []

    def materialize(*_args, **_kwargs):
        observed.append(detached_handler_island.preopt_union_import_in_progress(mba))
        assert (
            detached_handler_island.materialize_preopt_union_snippet_templates(
                mba, 0xB000, (0x40EAA7,), mutation_gateway=make_mutation_gateway(mba)
            )
            == {}
        )
        return {0x40EAA7: 7}

    monkeypatch.setattr(
        detached_handler_island,
        "_materialize_detached_snippet_templates",
        materialize,
    )

    result = detached_handler_island.materialize_preopt_union_snippet_templates(
        mba, 0xB000, (0x40EAA7,), mutation_gateway=make_mutation_gateway(mba)
    )

    assert result == {0x40EAA7: 7}
    assert observed == [True]
    assert not detached_handler_island.preopt_union_import_in_progress(mba)


def test_zero_width_template_sentinel_has_no_native_identity() -> None:
    sentinel = detached_handler_island.DetachedSnippetBlockTemplate(
        source_serial=0,
        native_entry_ea=0x40F821,
        native_end_ea=0x40F821,
        instructions=(),
        block_type=int(ida_hexrays.BLT_0WAY),
        block_flags=0,
        successor_serials=(),
        external_successor_eas=(),
    )

    assert (
        detached_handler_island._template_block_stable_identity(
            sentinel, native_key=NATIVE_KEY
        )
        is None
    )


def test_template_ranges_backfill_microcode_silent_native_entry() -> None:
    native_entry_ea = 0x3300
    first_microcode_ea = 0x3302
    native_end_ea = 0x3310
    block = detached_handler_island.DetachedSnippetBlockTemplate(
        source_serial=7,
        native_entry_ea=first_microcode_ea,
        native_end_ea=native_end_ea,
        instructions=(_Instruction(ida_hexrays.m_mov, first_microcode_ea),),
        block_type=int(ida_hexrays.BLT_0WAY),
        block_flags=0,
        successor_serials=(),
        external_successor_eas=(),
    )

    backfilled = detached_handler_island._backfill_owned_native_entries(
        (block,),
        owned_entries={native_entry_ea},
        owned_ranges=((native_entry_ea, native_end_ea),),
    )

    assert len(backfilled) == 1
    assert backfilled[0].native_entry_ea == native_entry_ea
    assert backfilled[0].native_end_ea == native_end_ea


def test_boundary_target_entry_splits_off_preceding_dispatcher_tail() -> None:
    from d810.analyses.control_flow.detached_handler_island import (
        DetachedSnippetBoundaryPortOwner,
        DetachedSnippetBoundaryPorts,
    )

    dispatcher_tail_ea = 0x40C629
    handler_entry_ea = 0x40C62F
    handler_tail_ea = 0x40C634
    successor_serial = 9
    block = detached_handler_island.DetachedSnippetBlockTemplate(
        source_serial=7,
        native_entry_ea=dispatcher_tail_ea,
        native_end_ea=0x40C640,
        instructions=(
            _Instruction(ida_hexrays.m_mov, dispatcher_tail_ea),
            _Instruction(ida_hexrays.m_mov, handler_entry_ea),
            _Instruction(ida_hexrays.m_goto, handler_tail_ea),
        ),
        block_type=int(ida_hexrays.BLT_1WAY),
        block_flags=0,
        successor_serials=(successor_serial,),
        external_successor_eas=(0,),
    )
    port = _direct_boundary_port(
        source_block_ea=0x40BC36,
        source_instruction_ea=0x40BC50,
        endpoint_block_ea=0x40BC36,
        old_successor_eas=(),
        target_ea=handler_entry_ea,
        source_owner=DetachedSnippetBoundaryPortOwner.IMPORTED,
        endpoint_owner=DetachedSnippetBoundaryPortOwner.IMPORTED,
        target_owner=DetachedSnippetBoundaryPortOwner.IMPORTED,
        delivery_mode="terminal_goto",
    )

    split = detached_handler_island._split_semantic_target_entry_blocks(
        (block,),
        DetachedSnippetBoundaryPorts(direct=(port,), conditional=()),
        {},
    )

    assert split is not None
    assert len(split) == 2
    prefix, handler = split
    assert prefix.source_serial == 7
    assert prefix.native_entry_ea == dispatcher_tail_ea
    assert prefix.native_end_ea == handler_entry_ea
    assert tuple(instruction.ea for instruction in prefix.instructions) == (
        dispatcher_tail_ea,
    )
    assert prefix.successor_serials == (handler.source_serial,)
    assert prefix.external_successor_eas == (0,)
    assert handler.native_entry_ea == handler_entry_ea
    assert tuple(instruction.ea for instruction in handler.instructions) == (
        handler_entry_ea,
        handler_tail_ea,
    )
    assert handler.successor_serials == (successor_serial,)


def test_preopt_union_range_publication_relocates_stale_created_proxies(
    monkeypatch,
) -> None:
    _install_runtime_fakes(monkeypatch)
    function_ea = 0xB000
    target_ea = 0x3300
    split_ea = 0x3304
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
                split_ea,
                (
                    _Instruction(ida_hexrays.m_xor, split_ea),
                    _Instruction(ida_hexrays.m_mov, split_ea + 2),
                ),
            ),
        ),
        maturity=ida_hexrays.MMAT_PREOPTIMIZED,
    )
    source.get_mblock(0).type = int(ida_hexrays.BLT_1WAY)
    assert detached_handler_island.capture_preopt_union_snippet_template(
        function_ea,
        target_ea,
        source,
        ((target_ea, split_ea + 3),),
        owned_block_entry_eas=(target_ea, split_ea),
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

    def reallocate_live_blocks(
        mba,
        _batch,
        _created,
        **_kwargs,
    ) -> tuple[object, ...]:
        stale_blocks = tuple(mba.blocks)
        live_blocks = []
        for stale in stale_blocks:
            live = _Block(
                int(stale.serial),
                int(stale.start),
                tuple(copy.deepcopy(stale.instructions())),
                tuple(int(serial) for serial in stale.succset),
            )
            live.type = int(stale.type)
            live.flags = int(stale.flags)
            live.predset = _SerialList(int(serial) for serial in stale.predset)
            live.owner = mba
            live_blocks.append(live)
        mba.blocks = live_blocks
        for stale in stale_blocks:
            stale._set_instructions(())
        return ()

    monkeypatch.setattr(
        detached_handler_island,
        "_apply_boundary_port_batch",
        reallocate_live_blocks,
    )

    roots = detached_handler_island.materialize_preopt_union_snippet_templates(
        destination,
        function_ea,
        (target_ea,),
        mutation_gateway=make_mutation_gateway(destination),
    )

    assert set(roots) == {target_ea}
    secondary = detached_handler_island.find_unique_live_block_by_native_ea(
        destination,
        split_ea + 1,
    )
    assert secondary is not None
    assert secondary.head is not None


def test_preopt_union_template_can_bind_boundary_ports_after_source_capture(
    monkeypatch,
) -> None:
    _install_runtime_fakes(monkeypatch)
    from d810.analyses.control_flow.detached_handler_island import (
        DetachedSnippetBoundaryPortOwner,
        DetachedSnippetBoundaryPorts,
    )

    function_ea = 0xB000
    source_ea = 0x3300
    target_ea = 0x4400
    source = _MBA(
        (
            _Block(
                0,
                source_ea,
                (_Instruction(ida_hexrays.m_mov, source_ea),),
            ),
        ),
        maturity=ida_hexrays.MMAT_PREOPTIMIZED,
    )

    assert detached_handler_island.capture_preopt_union_snippet_template(
        function_ea,
        source_ea,
        source,
        ((source_ea, source_ea + 1),),
    )
    assert (
        detached_handler_island.detached_snippet_template_generation(function_ea) == 1
    )
    port = _direct_boundary_port(
        source_block_ea=source_ea,
        endpoint_block_ea=source_ea,
        old_successor_eas=(),
        target_ea=target_ea,
        source_owner=DetachedSnippetBoundaryPortOwner.IMPORTED,
        endpoint_owner=DetachedSnippetBoundaryPortOwner.IMPORTED,
        target_owner=DetachedSnippetBoundaryPortOwner.LIVE,
        delivery_mode="terminal_goto",
    )

    assert detached_handler_island.bind_preopt_union_snippet_boundary_ports(
        function_ea,
        source_ea,
        DetachedSnippetBoundaryPorts((port,), ()),
    )
    assert (
        detached_handler_island.detached_snippet_template_generation(function_ea) == 2
    )
    assert detached_handler_island.bind_preopt_union_snippet_boundary_ports(
        function_ea,
        source_ea,
        DetachedSnippetBoundaryPorts((port,), ()),
    )
    assert (
        detached_handler_island.detached_snippet_template_generation(function_ea) == 2
    )
    template = detached_handler_island._PREOPT_UNION_SNIPPET_TEMPLATES[
        (function_ea, source_ea)
    ]
    assert tuple(row.port for row in template.boundary_ports.direct) == (port,)


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
        mutation_gateway=make_mutation_gateway(destination),
    )

    assert roots == {}
    assert destination.qty == original_qty
