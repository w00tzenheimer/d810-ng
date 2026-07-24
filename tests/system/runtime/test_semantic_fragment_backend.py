"""Live-backend staging for detached semantic fragment publication."""

from __future__ import annotations

import json
import os
import platform
from copy import deepcopy
from dataclasses import replace

import pytest

ida_hexrays = pytest.importorskip("ida_hexrays")

from d810.core.events import EventEmitter  # noqa: E402
from d810.core.diag import create_diag_database  # noqa: E402
from d810.core.diag.event_handlers import (  # noqa: E402
    install_diag_event_handlers,
    uninstall_diag_event_handlers,
)
from d810.core.observability import (  # noqa: E402
    emit as emit_diagnostic,
    reset_diagnostic_bus,
)
from d810.core.observability_events import DiagnosticSessionObserved  # noqa: E402
from d810.hexrays.mutation import deferred_modifier as dm  # noqa: E402
from d810.hexrays.mutation import detached_handler_island as dhi  # noqa: E402
from d810.hexrays.mutation import semantic_fragment_backend as sfb  # noqa: E402
from d810.hexrays.mutation.mba_mutation_events import (  # noqa: E402
    MbaMutationAborted,
    MbaMutationCommitted,
    MbaMutationPlanned,
)
from d810.hexrays.ir.exact_data_flow import DefSite, UseSite  # noqa: E402
from d810.hexrays.ir.exact_value_ranges import (  # noqa: E402
    ExactValueRangeProof,
    prove_exact_unsigned_range,
)
from d810.hexrays.mutation.semantic_fragment_publication import (  # noqa: E402
    SemanticFragmentPublicationRejected,
)
from d810.ir.expressions import ValueOpKind  # noqa: E402
from d810.ir.block_identity import (  # noqa: E402
    BlockHandleProvenance,
    NativeEaInterval,
    StableBlockIdentity,
)
from d810.ir.flowgraph import BlockKind  # noqa: E402
from d810.ir.semantic_edge import SemanticEdgeRole  # noqa: E402
from d810.ir.semantics import PredicateKind  # noqa: E402
from d810.ir.storage_identity import (  # noqa: E402
    StorageIdentity,
    StorageIdentityKind,
)
from d810.manager.manager import D810Manager  # noqa: E402
from d810.transforms.fragment_plan import (  # noqa: E402
    FragmentBlock,
    FragmentBlockMaterialization,
    FragmentBlockRole,
    FragmentComputedBranchNormalization,
    FragmentConditionalSelectEnvelope,
    FragmentDataFlowObligation,
    FragmentDataFlowRole,
    FragmentEdge,
    FragmentFlagCorridor,
    FragmentNativeBody,
    FragmentOperation,
    FragmentPlan,
    FragmentPublicationPurpose,
    FragmentRangeAssumption,
    FragmentRangeObservation,
    FragmentReturnCarrier,
    FragmentReturnSource,
    FragmentReturnSourceKind,
    FragmentTerminalReturn,
    FragmentTerminalRoute,
    FragmentValueSite,
    FragmentWorkItemScope,
)
from d810.transforms.fragment_validation import (  # noqa: E402
    FragmentBindingState,
    FragmentValidationPostcondition,
    ProjectedDataFlowRelation,
    ProjectedRangeFact,
    validate_fragment_projection,
)
from tests.system.runtime.mutation_gateway import (  # noqa: E402
    make_fragment_publication_gateway,
)


def _fragment_gateway(mba):
    return make_fragment_publication_gateway(
        mba,
        publication_purpose=FragmentPublicationPurpose.CANONICAL_SEMANTIC_LOWERING,
    )


def _persisted_version_transition_row(version, from_state: str, to_state: str):
    identity = version.handle.stable_identity
    anchor_ea = (
        None
        if identity is None
        else min(
            identity.exact_instruction_eas,
            default=identity.native_ranges.intervals[0].start_ea,
        )
    )
    predecessor = version.predecessor_version_id
    return (
        version.version_id.proxy_token,
        version.version_id.version,
        version.handle.token,
        version.generation,
        version.handle.provenance.value,
        (
            None
            if identity is None
            else json.dumps(identity.to_dict(), sort_keys=True)
        ),
        None if anchor_ea is None else f"0x{anchor_ea:016x}",
        anchor_ea,
        None if predecessor is None else predecessor.version,
        from_state,
        to_state,
    )


def _get_default_binary() -> str:
    override = os.environ.get("D810_TEST_BINARY")
    if override:
        return override
    return {
        "Windows": "libobfuscated.dll",
        "Darwin": "libobfuscated.dylib",
    }.get(platform.system(), "libobfuscated.so")


class _EdgeSet:
    def __init__(self, values=()):
        self.values = [int(value) for value in values]

    def __iter__(self):
        return iter(tuple(self.values))

    def __getitem__(self, index: int) -> int:
        return self.values[index]

    def size(self) -> int:
        return len(self.values)

    def push_back(self, value: int) -> None:
        value = int(value)
        if value not in self.values:
            self.values.append(value)

    def _del(self, value: int) -> None:
        try:
            self.values.remove(int(value))
        except ValueError:
            pass

    def clear(self) -> None:
        self.values.clear()


class _AddressRange:
    def __init__(self, start_ea: int, end_ea: int):
        self.start_ea = int(start_ea)
        self.end_ea = int(end_ea)


class _AddressRangeVector:
    def __init__(self, ranges=()):
        self.values = [
            _AddressRange(start_ea, end_ea)
            for start_ea, end_ea in ranges
        ]

    def __getitem__(self, index: int) -> _AddressRange:
        return self.values[int(index)]

    def size(self) -> int:
        return len(self.values)

    def clear(self) -> None:
        self.values.clear()

    def push_back(self, address_range) -> None:
        self.values.append(
            _AddressRange(
                int(address_range.start_ea),
                int(address_range.end_ea),
            )
        )


class _MbaRanges:
    def __init__(self, ranges=()):
        self.pfn = None
        self.ranges = _AddressRangeVector(ranges)


class _BlockReference:
    def __init__(self, serial: int | None = None):
        self.t = int(ida_hexrays.mop_z if serial is None else ida_hexrays.mop_b)
        self.b = -1 if serial is None else int(serial)
        self.size = 0
        self.r = -1
        self.g = -1
        self.nnn = None
        self.s = None
        self.a = None
        self.d = None
        self.writes_ccflags = False
        self.writes_cc = False

    def _reset_value(self) -> None:
        self.b = -1
        self.size = 0
        self.r = -1
        self.g = -1
        self.nnn = None
        self.s = None
        self.a = None
        self.d = None

    def make_blkref(self, serial: int) -> None:
        self._reset_value()
        self.t = int(ida_hexrays.mop_b)
        self.b = int(serial)

    def make_number(self, value: int, size: int, *_args) -> None:
        self._reset_value()
        self.t = int(ida_hexrays.mop_n)
        self.size = int(size)
        self.nnn = type("_Number", (), {"value": int(value)})()

    def make_reg(self, register: int, size: int) -> None:
        self._reset_value()
        self.t = int(ida_hexrays.mop_r)
        self.r = int(register)
        self.size = int(size)

    def make_gvar(self, address: int) -> None:
        self._reset_value()
        self.t = int(ida_hexrays.mop_v)
        self.g = int(address)

    def make_stkvar(self, _mba, offset: int) -> None:
        self._reset_value()
        self.t = int(ida_hexrays.mop_S)
        self.s = type("_StackReference", (), {"off": int(offset)})()

    def assign(self, other):
        self.t = int(other.t)
        self.b = int(getattr(other, "b", -1))
        self.size = int(getattr(other, "size", 0))
        self.r = int(getattr(other, "r", -1))
        self.g = int(getattr(other, "g", -1))
        self.nnn = deepcopy(getattr(other, "nnn", None))
        self.s = deepcopy(getattr(other, "s", None))
        self.a = deepcopy(getattr(other, "a", None))
        self.d = deepcopy(getattr(other, "d", None))
        return self

    def create_from_insn(self, instruction: "_Instruction") -> None:
        self._reset_value()
        self.t = int(ida_hexrays.mop_d)
        self.d = deepcopy(instruction)
        self.size = int(instruction.d.size)

    def erase(self) -> None:
        self._reset_value()
        self.t = int(ida_hexrays.mop_z)

    def is_ccflags(self) -> bool:
        return self.writes_ccflags

    def is_cc(self) -> bool:
        return self.writes_cc


class _AddressOperand(_BlockReference):
    def __init__(self, inner: _BlockReference, _insize: int, outsize: int):
        super().__init__()
        self.t = int(ida_hexrays.mop_a)
        self.size = int(outsize)
        self.a = type("_AddressReference", (), {"v": deepcopy(inner)})()


class _Instruction:
    def __init__(self, opcode: int, ea: int, target: int | None = None):
        self.opcode = int(opcode)
        self.ea = int(ea)
        self.l = _BlockReference(target)
        self.r = _BlockReference()
        self.d = _BlockReference()
        self.next = None

    def setaddr(self, ea: int) -> None:
        self.ea = int(ea)


def _fake_minsn(ea: int) -> _Instruction:
    return _Instruction(ida_hexrays.m_nop, int(ea))


class _Block:
    def __init__(self, serial: int, *, start: int, block_type: int):
        self.serial = int(serial)
        self.start = int(start)
        self.end = int(start) + 1
        self.type = int(block_type)
        self.flags = 0
        self.head = None
        self.tail = None
        self.succset = _EdgeSet()
        self.predset = _EdgeSet()
        self.mba = None
        self.nextb = None
        self.prevb = None
        self.valrange_bounds: list[tuple[int | None, int | None]] = []
        self.valrange_queries: list[tuple[int, int]] = []

    def nsucc(self) -> int:
        return self.succset.size()

    def npred(self) -> int:
        return self.predset.size()

    def mark_lists_dirty(self) -> None:
        return None

    def make_nop(self, instruction) -> None:
        instruction.opcode = int(ida_hexrays.m_nop)

    def get_valranges(self, result, _vivl, instruction, flags: int) -> bool:
        self.valrange_queries.append((int(instruction.ea), int(flags)))
        if not self.valrange_bounds:
            return False
        lo, hi = self.valrange_bounds.pop(0)
        observed = ida_hexrays.valrng_t(int(result.get_size()))
        observed.set_all()
        if lo is not None:
            lower = ida_hexrays.valrng_t(int(result.get_size()))
            lower.set_cmp(ida_hexrays.CMP_AE, int(lo))
            observed.intersect_with(lower)
        if hi is not None:
            upper = ida_hexrays.valrng_t(int(result.get_size()))
            upper.set_cmp(ida_hexrays.CMP_BE, int(hi))
            observed.intersect_with(upper)
        result.swap(observed)
        return True

    def remove_from_block(self, instruction) -> None:
        previous = None
        current = self.head
        while current is not None and current is not instruction:
            previous = current
            current = current.next
        if current is None:
            return
        if previous is None:
            self.head = current.next
        else:
            previous.next = current.next
        if self.tail is current:
            self.tail = previous
        current.next = None

    def insert_into_block(self, instruction, after) -> None:
        if self.head is None:
            instruction.next = None
            self.head = instruction
            self.tail = instruction
            return
        if after is None:
            instruction.next = self.head
            self.head = instruction
            return
        instruction.next = after.next
        after.next = instruction
        if self.tail is after:
            self.tail = instruction


class _Mba:
    def __init__(self, blocks: tuple[_Block, ...]):
        self.blocks = {block.serial: block for block in blocks}
        self.qty = len(blocks)
        self.removed_block_ranges: list[tuple[int, int]] = []
        self.removed_unreachable_calls = 0
        self.verify_calls = 0
        self.entry_ea = 0x401000
        self.maturity = int(ida_hexrays.MMAT_PREOPTIMIZED)
        self._flags2 = 0
        self.mbr = _MbaRanges(((self.entry_ea, self.entry_ea + 0x100),))
        self.chains_dirty = False
        self.next_fictitious_ea = 0xF10000
        self.fictitious_ea_map: dict[int, int] = {}
        for block in blocks:
            block.mba = self
            if 0 < int(block.serial) < len(blocks) - 1:
                block.flags |= int(ida_hexrays.MBL_KEEP)
        self._relink()

    def get_mblock(self, serial: int):
        return self.blocks.get(int(serial))

    def mark_chains_dirty(self) -> None:
        self.chains_dirty = True

    def verify(self, _always: bool) -> None:
        self.verify_calls += 1
        for serial in range(self.qty):
            block = self.get_mblock(serial)
            assert block is not None
            assert int(block.serial) == serial
            assert (block.prevb is None) == (serial == 0)
            assert (block.nextb is None) == (serial == self.qty - 1)

    def alloc_fict_ea(self, native_ea: int) -> int:
        live_ea = int(self.next_fictitious_ea)
        self.next_fictitious_ea += 1
        self.fictitious_ea_map[live_ea] = int(native_ea)
        return live_ea

    def map_fict_ea(self, live_ea: int) -> int:
        return int(self.fictitious_ea_map.get(int(live_ea), int(live_ea)))

    def get_mba_flags2(self) -> int:
        return int(self._flags2)

    def set_mba_flags2(self, flags: int) -> None:
        self._flags2 |= int(flags)

    def clr_mba_flags2(self, flags: int) -> None:
        self._flags2 &= ~int(flags)

    @staticmethod
    def stkoff_ida2vd(stack_offset: int) -> int:
        return int(stack_offset)

    @staticmethod
    def stkoff_vd2ida(stack_offset: int) -> int:
        return int(stack_offset)

    def copy_block(self, source: _Block, destination: int, _flags: int):
        destination = int(destination)
        self._shift_coordinates(destination, 1)
        clone = _Block(
            destination,
            start=int(source.start),
            block_type=int(source.type),
        )
        clone.flags = int(source.flags)
        clone.succset = _EdgeSet(source.succset)
        clone.predset = _EdgeSet(source.predset)
        if source.head is not None:
            clone.head = deepcopy(source.head)
            clone.tail = clone.head
            while clone.tail.next is not None:
                clone.tail = clone.tail.next
        clone.mba = self
        self.blocks[destination] = clone
        self.qty += 1
        for successor_serial in clone.succset:
            successor = self.get_mblock(successor_serial)
            if successor is not None:
                successor.predset.push_back(destination)
        self._relink()
        return clone

    def insert_block(self, destination: int):
        destination = int(destination)
        self._shift_coordinates(destination, 1)
        inserted = _Block(
            destination,
            start=self.entry_ea,
            block_type=ida_hexrays.BLT_0WAY,
        )
        inserted.mba = self
        self.blocks[destination] = inserted
        self.qty += 1
        self._relink()
        return inserted

    def remove_block(self, block: _Block) -> None:
        removed_serial = int(block.serial)
        self.blocks.pop(removed_serial)
        self.qty -= 1
        self._shift_coordinates(removed_serial + 1, -1)
        self._relink()

    def remove_blocks(self, start: int, end: int) -> None:
        start = int(start)
        end = int(end)
        self.removed_block_ranges.append((start, end))
        for serial in range(start, end):
            self.blocks.pop(serial)
        self.qty -= end - start
        self._shift_coordinates(end, start - end)
        self._relink()

    def remove_empty_and_unreachable_blocks(self) -> bool:
        self.removed_unreachable_calls += 1
        removed = tuple(
            serial
            for serial, block in sorted(self.blocks.items())
            if 0 < serial < self.qty - 1
            and not int(block.flags) & int(ida_hexrays.MBL_KEEP)
            and int(block.npred()) == 0
        )
        for serial in reversed(removed):
            block = self.get_mblock(serial)
            assert block is not None
            self.remove_block(block)
        return bool(removed)

    def _shift_coordinates(self, threshold: int, delta: int) -> None:
        for block in tuple(self.blocks.values()):
            if int(block.serial) >= int(threshold):
                block.serial += int(delta)
            block.succset.values = [
                value + int(delta) if value >= int(threshold) else value
                for value in block.succset.values
            ]
            block.predset.values = [
                value + int(delta) if value >= int(threshold) else value
                for value in block.predset.values
            ]
            tail = block.tail
            if (
                tail is not None
                and int(tail.l.t) == int(ida_hexrays.mop_b)
                and int(tail.l.b) >= int(threshold)
            ):
                tail.l.b += int(delta)
            if (
                tail is not None
                and int(tail.d.t) == int(ida_hexrays.mop_b)
                and int(tail.d.b) >= int(threshold)
            ):
                tail.d.b += int(delta)
        self.blocks = {int(block.serial): block for block in self.blocks.values()}

    def _relink(self) -> None:
        ordered = tuple(self.blocks[index] for index in sorted(self.blocks))
        for index, block in enumerate(ordered):
            block.prevb = None if index == 0 else ordered[index - 1]
            block.nextb = None if index + 1 == len(ordered) else ordered[index + 1]


def _connect(source: _Block, target: _Block) -> None:
    source.type = int(ida_hexrays.BLT_1WAY)
    source.tail = _Instruction(ida_hexrays.m_goto, source.start, target.serial)
    source.head = source.tail
    source.succset.push_back(target.serial)
    target.predset.push_back(source.serial)


def _outline_ranges(mba: _Mba) -> tuple[tuple[int, int], ...]:
    return tuple(
        (
            int(mba.mbr.ranges[index].start_ea),
            int(mba.mbr.ranges[index].end_ea),
        )
        for index in range(int(mba.mbr.ranges.size()))
    )


def _connect_conditional(
    source: _Block,
    *,
    taken: _Block,
    fallthrough: _Block,
) -> None:
    source.type = int(ida_hexrays.BLT_2WAY)
    source.tail = _Instruction(ida_hexrays.m_jz, source.start)
    source.tail.d.make_blkref(taken.serial)
    source.head = source.tail
    source.succset.push_back(fallthrough.serial)
    source.succset.push_back(taken.serial)
    fallthrough.predset.push_back(source.serial)
    taken.predset.push_back(source.serial)


def _create_fake_standalone_block(
    *,
    ref_blk: _Block,
    blk_ins,
    target_serial: int | None = None,
    is_0_way: bool = False,
    verify: bool = False,
):
    del verify
    mba = ref_blk.mba
    created = mba.copy_block(ref_blk, mba.qty - 1, 1)
    for successor_serial in tuple(created.succset):
        successor = mba.get_mblock(successor_serial)
        if successor is not None:
            successor.predset._del(created.serial)
    created.succset.clear()
    created.predset.clear()
    created.head = None
    created.tail = None
    previous = None
    for instruction in blk_ins:
        copied = deepcopy(instruction)
        created.insert_into_block(copied, previous)
        previous = copied
    if is_0_way:
        created.type = int(ida_hexrays.BLT_0WAY)
    elif target_serial is not None:
        created.type = int(ida_hexrays.BLT_1WAY)
        created.tail = _Instruction(
            ida_hexrays.m_goto,
            mba.entry_ea,
            target_serial,
        )
        created.head = created.tail
        created.succset.push_back(target_serial)
        target = mba.get_mblock(target_serial)
        if target is not None:
            target.predset.push_back(created.serial)
    return created


def _change_fake_zero_way_successor(
    block: _Block,
    target_serial: int,
    *,
    verify: bool = False,
) -> bool:
    del verify
    target_serial = int(target_serial)
    block.type = int(ida_hexrays.BLT_1WAY)
    block.tail = _Instruction(
        ida_hexrays.m_goto,
        block.mba.entry_ea,
        target_serial,
    )
    block.head = block.tail
    block.succset.push_back(target_serial)
    target = block.mba.get_mblock(target_serial)
    if target is not None:
        target.predset.push_back(block.serial)
    block.mba.mark_chains_dirty()
    return True


def _change_fake_zero_way_successor_preserving_instructions(
    block: _Block,
    target_serial: int,
    *,
    verify: bool = False,
) -> bool:
    del verify
    target_serial = int(target_serial)
    goto = _Instruction(
        ida_hexrays.m_goto,
        block.mba.entry_ea,
        target_serial,
    )
    block.insert_into_block(goto, block.tail)
    block.type = int(ida_hexrays.BLT_1WAY)
    block.succset.push_back(target_serial)
    target = block.mba.get_mblock(target_serial)
    if target is not None:
        target.predset.push_back(block.serial)
    block.mba.mark_chains_dirty()
    return True


def _change_fake_conditional_successor(
    block: _Block,
    target_serial: int,
    *,
    verify: bool = False,
    old_target: int | None = None,
) -> bool:
    del verify
    if block.nsucc() != 2 or block.tail is None:
        return False
    previous_serial = int(block.tail.d.b)
    if old_target is not None and previous_serial != int(old_target):
        return False
    previous = block.mba.get_mblock(previous_serial)
    target = block.mba.get_mblock(int(target_serial))
    if previous is None or target is None:
        return False
    block.tail.d.erase()
    block.tail.d.make_blkref(int(target_serial))
    block.succset._del(previous_serial)
    block.succset.push_back(int(target_serial))
    previous.predset._del(block.serial)
    target.predset.push_back(block.serial)
    block.mba.mark_chains_dirty()
    return True


def _insert_fake_goto_instruction(
    block: _Block,
    target_serial: int,
    nop_previous_instruction: bool = False,
) -> None:
    if nop_previous_instruction and block.tail is not None:
        block.make_nop(block.tail)
    goto = _Instruction(
        ida_hexrays.m_goto,
        block.mba.entry_ea,
        int(target_serial),
    )
    block.insert_into_block(goto, block.tail)


def _plan(gateway, *, entry: int, original: int, target: int, dispatcher: int):
    index = gateway.identity_index

    def _native(block_id: str, role: FragmentBlockRole, serial: int, **kwargs):
        handle = index.handle_for_serial(serial)
        assert handle is not None
        assert handle.stable_identity is not None
        return FragmentBlock(
            block_id=block_id,
            role=role,
            materialization=(
                FragmentBlockMaterialization.CLONE_PUBLISHED
                if role is FragmentBlockRole.REPLACEMENT
                else FragmentBlockMaterialization.REUSE_PUBLISHED
            ),
            semantic_anchor_ea=int(index.resolve(handle).anchor_ea),
            stable_identity=handle.stable_identity,
            **kwargs,
        )

    original_block = _native("original", FragmentBlockRole.ORIGINAL, original)
    replacement = FragmentBlock(
        block_id="replacement",
        role=FragmentBlockRole.REPLACEMENT,
        materialization=FragmentBlockMaterialization.CLONE_PUBLISHED,
        semantic_anchor_ea=original_block.semantic_anchor_ea,
        stable_identity=original_block.stable_identity,
        replaces_block_id=original_block.block_id,
    )
    return FragmentPlan(
        plan_id="runtime-direct-fragment",
        atomic_group_id="route@0x401010",
        publication_purpose=FragmentPublicationPurpose.CANONICAL_SEMANTIC_LOWERING,
        native_key=gateway.native_key,
        blocks=(
            _native("entry", FragmentBlockRole.EXTERNAL, entry),
            original_block,
            replacement,
            _native("target", FragmentBlockRole.EXTERNAL, target),
            _native("dispatcher", FragmentBlockRole.EXTERNAL, dispatcher),
        ),
        roots=(replacement.block_id,),
        owned_originals=(original_block.block_id,),
        prohibited_dispatcher_blocks=("dispatcher",),
        operations=(
            FragmentOperation(
                operation_id="direct-route",
                source_block_id=replacement.block_id,
                edges=(
                    FragmentEdge(
                        role=SemanticEdgeRole.DIRECT,
                        target_block_id="target",
                    ),
                ),
            ),
        ),
    )


def _plan_with_imported_terminal(
    gateway,
    *,
    entry: int,
    original: int,
    target: int,
    dispatcher: int,
) -> FragmentPlan:
    plan = _plan(
        gateway,
        entry=entry,
        original=original,
        target=target,
        dispatcher=dispatcher,
    )
    native_range = NativeEaInterval(0x500000, 0x500010)
    imported_identity = StableBlockIdentity.from_intervals(
        (native_range,),
        native_key=gateway.native_key,
        exact_instruction_eas=(0x500000,),
    )
    imported = FragmentBlock(
        block_id="imported-terminal",
        role=FragmentBlockRole.IMPORTED,
        materialization=FragmentBlockMaterialization.IMPORT_NATIVE,
        semantic_anchor_ea=0x500000,
        stable_identity=imported_identity,
        native_body_id="native-body",
    )
    direct_route = plan.operations[0]
    return replace(
        plan,
        plan_id="runtime-imported-native-body",
        blocks=tuple(block for block in plan.blocks if block.block_id != "target")
        + (imported,),
        operations=(
            replace(
                direct_route,
                edges=(
                    FragmentEdge(
                        role=SemanticEdgeRole.DIRECT,
                        target_block_id=imported.block_id,
                    ),
                ),
            ),
        ),
        native_bodies=(
            FragmentNativeBody(
                body_id="native-body",
                block_ids=(imported.block_id,),
                entry_block_ids=(imported.block_id,),
                terminal_block_ids=(imported.block_id,),
                native_ranges=(native_range,),
                proof_ids=("proof:native-body",),
            ),
        ),
    )


class _RecordingNativeBodyMaterializer:
    def __init__(self) -> None:
        self.calls: list[tuple[str, str, str | None]] = []

    def stage_native_body(
        self,
        *,
        context,
        native_body: FragmentNativeBody,
    ) -> None:
        self.calls.append(
            (
                context.plan.plan_id,
                native_body.body_id,
                context.transaction_id,
            )
        )
        for block_id in native_body.block_ids:
            context.stage_block(block_id)


class _TerminalEffectNativeBodyMaterializer:
    def __init__(self, *, conflicting_carrier: bool = False) -> None:
        self.conflicting_carrier = bool(conflicting_carrier)

    def stage_native_body(
        self,
        *,
        context,
        native_body: FragmentNativeBody,
    ) -> None:
        assert native_body.block_ids == (
            "imported-carrier",
            "imported-return",
        )
        for block_id in native_body.block_ids:
            context.stage_block(block_id)
        carrier_instructions = [
            (
                0x500000,
                _Instruction(ida_hexrays.m_mov, 0x500000),
            ),
        ]
        if self.conflicting_carrier:
            carrier_instructions.append(
                (
                    0x500004,
                    _Instruction(ida_hexrays.m_add, 0x500004),
                )
            )
        context.populate_block(
            block_id="imported-carrier",
            instructions=tuple(carrier_instructions),
            block_flags=0,
        )
        context.populate_block(
            block_id="imported-return",
            instructions=(),
            block_flags=0,
        )


def _plan_with_terminal_effects(
    gateway,
    *,
    entry: int,
    original: int,
    target: int,
    dispatcher: int,
) -> FragmentPlan:
    plan = _plan(
        gateway,
        entry=entry,
        original=original,
        target=target,
        dispatcher=dispatcher,
    )
    carrier_range = NativeEaInterval(0x500000, 0x500010)
    return_range = NativeEaInterval(0x500100, 0x500110)
    carrier = FragmentBlock(
        block_id="imported-carrier",
        role=FragmentBlockRole.IMPORTED,
        materialization=FragmentBlockMaterialization.IMPORT_NATIVE,
        semantic_anchor_ea=0x500000,
        stable_identity=StableBlockIdentity.from_intervals(
            (carrier_range,),
            native_key=gateway.native_key,
            exact_instruction_eas=(0x500000, 0x500004),
        ),
        native_body_id="terminal-native-body",
    )
    terminal = FragmentBlock(
        block_id="imported-return",
        role=FragmentBlockRole.IMPORTED,
        materialization=FragmentBlockMaterialization.IMPORT_NATIVE,
        semantic_anchor_ea=0x500100,
        stable_identity=StableBlockIdentity.from_intervals(
            (return_range,),
            native_key=gateway.native_key,
            exact_instruction_eas=(0x500100,),
        ),
        native_body_id="terminal-native-body",
    )
    root_route = replace(
        plan.operations[0],
        edges=(
            FragmentEdge(
                role=SemanticEdgeRole.DIRECT,
                target_block_id=carrier.block_id,
            ),
        ),
    )
    terminal_route = FragmentOperation(
        operation_id="carrier-to-return",
        source_block_id=carrier.block_id,
        edges=(
            FragmentEdge(
                role=SemanticEdgeRole.DIRECT,
                target_block_id=terminal.block_id,
            ),
        ),
    )
    return replace(
        plan,
        plan_id="runtime-terminal-fragment",
        atomic_group_id="terminal@0x500000",
        blocks=tuple(block for block in plan.blocks if block.block_id != "target")
        + (carrier, terminal),
        operations=(root_route, terminal_route),
        native_bodies=(
            FragmentNativeBody(
                body_id="terminal-native-body",
                block_ids=(carrier.block_id, terminal.block_id),
                entry_block_ids=(carrier.block_id,),
                terminal_block_ids=(terminal.block_id,),
                native_ranges=(carrier_range, return_range),
                proof_ids=("proof:terminal-native-body",),
            ),
        ),
        return_carriers=(
            FragmentReturnCarrier(
                carrier_id="return-value",
                block_id=carrier.block_id,
                state_write_ea=0x500000,
                carrier_ea=0x500004,
                operation=ValueOpKind.MOVE,
                source=FragmentReturnSource(
                    kind=FragmentReturnSourceKind.CONSTANT,
                    width=4,
                    constant=7,
                ),
                return_width=4,
                corridor_instruction_eas=(0x500000, 0x500004),
            ),
        ),
        terminal_returns=(
            FragmentTerminalReturn(
                return_id="function-return",
                block_id=terminal.block_id,
                instruction_ea=0x500100,
                return_width=4,
            ),
        ),
        terminal_routes=(
            FragmentTerminalRoute(
                terminal_route_id="carrier-terminal-route",
                operation_id=terminal_route.operation_id,
                carrier_id="return-value",
                return_id="function-return",
            ),
        ),
    )


def _terminal_effect_runtime_case(
    monkeypatch,
    *,
    source: FragmentReturnSource | None = None,
    operation: ValueOpKind = ValueOpKind.MOVE,
    return_width: int = 4,
    materializer: _TerminalEffectNativeBodyMaterializer | None = None,
):
    entry = _Block(0, start=0x401000, block_type=ida_hexrays.BLT_1WAY)
    original = _Block(1, start=0x401010, block_type=ida_hexrays.BLT_1WAY)
    target = _Block(2, start=0x401020, block_type=ida_hexrays.BLT_0WAY)
    dispatcher = _Block(3, start=0x401030, block_type=ida_hexrays.BLT_0WAY)
    stop = _Block(4, start=0x401040, block_type=ida_hexrays.BLT_STOP)
    _connect(entry, original)
    _connect(original, dispatcher)
    mba = _Mba((entry, original, target, dispatcher, stop))
    gateway = _fragment_gateway(mba)
    monkeypatch.setattr(sfb.ida_hexrays, "minsn_t", _fake_minsn)
    monkeypatch.setattr(sfb.ida_hexrays, "mop_t", _BlockReference)
    monkeypatch.setattr(sfb.ida_hexrays, "mop_addr_t", _AddressOperand)
    monkeypatch.setattr(dm, "create_standalone_block", _create_fake_standalone_block)
    monkeypatch.setattr(
        dm,
        "change_0way_block_successor",
        _change_fake_zero_way_successor_preserving_instructions,
    )
    modifier = dm.DeferredGraphModifier(
        mba,
        mutation_gateway=gateway,
        semantic_native_body_materializer=(
            materializer or _TerminalEffectNativeBodyMaterializer()
        ),
    )
    plan = _plan_with_terminal_effects(
        gateway,
        entry=0,
        original=1,
        target=2,
        dispatcher=3,
    )
    if source is not None:
        carrier = replace(
            plan.return_carriers[0],
            operation=operation,
            source=source,
            return_width=int(return_width),
        )
        terminal_return = replace(
            plan.terminal_returns[0],
            return_width=int(return_width),
        )
        plan = replace(
            plan,
            return_carriers=(carrier,),
            terminal_returns=(terminal_return,),
        )
    return mba, gateway, modifier, plan, entry, original


class _OriginBoundConditionalNativeBodyMaterializer:
    def __init__(self, *, live_ea: int, native_ea: int) -> None:
        self.live_ea = int(live_ea)
        self.native_ea = int(native_ea)

    def stage_native_body(
        self,
        *,
        context,
        native_body: FragmentNativeBody,
    ) -> None:
        assert len(native_body.block_ids) == 1
        block_id = native_body.block_ids[0]
        block = context.stage_block(block_id)
        conditional = _Instruction(ida_hexrays.m_jz, self.live_ea)
        block.insert_into_block(conditional, block.tail)
        context.bind_instruction_origin(
            block_id=block_id,
            live_ea=self.live_ea,
            native_ea=self.native_ea,
        )


class _UnboundNativeBodyMaterializer:
    def stage_native_body(
        self,
        *,
        context,
        native_body: FragmentNativeBody,
    ) -> None:
        assert len(native_body.block_ids) == 1
        block = context.stage_block(native_body.block_ids[0])
        block.insert_into_block(
            _Instruction(ida_hexrays.m_nop, 0xF10000),
            block.tail,
        )


def _plan_with_imported_conditional(
    gateway,
    *,
    entry: int,
    original: int,
    target: int,
    dispatcher: int,
    predicate_native_ea: int,
    condition_producer_native_ea: int | None = None,
    unresolved_transfer_native_ea: int | None = None,
) -> FragmentPlan:
    plan = _plan(
        gateway,
        entry=entry,
        original=original,
        target=target,
        dispatcher=dispatcher,
    )
    native_range = NativeEaInterval(0x500000, 0x500010)
    exact_instruction_eas = {
        0x500000,
        int(predicate_native_ea),
    }
    if condition_producer_native_ea is not None:
        exact_instruction_eas.add(int(condition_producer_native_ea))
    if unresolved_transfer_native_ea is not None:
        exact_instruction_eas.add(int(unresolved_transfer_native_ea))
    imported_identity = StableBlockIdentity.from_intervals(
        (native_range,),
        native_key=gateway.native_key,
        exact_instruction_eas=tuple(sorted(exact_instruction_eas)),
    )
    imported = FragmentBlock(
        block_id="imported-conditional",
        role=FragmentBlockRole.IMPORTED,
        materialization=FragmentBlockMaterialization.IMPORT_NATIVE,
        semantic_anchor_ea=0x500000,
        stable_identity=imported_identity,
        native_body_id="native-body",
    )
    direct_route = plan.operations[0]
    return replace(
        plan,
        plan_id="runtime-imported-native-conditional",
        publication_purpose=(
            FragmentPublicationPurpose.FRONTEND_NORMALIZATION
            if unresolved_transfer_native_ea is not None
            else plan.publication_purpose
        ),
        work_item_scope=(
            FragmentWorkItemScope(
                work_item_id="runtime-imported-native-conditional:complete",
                selected_obligation_ids=("imported-conditional-route",),
                remaining_obligation_ids=(),
                unreachable_obligation_ids=(),
            )
            if unresolved_transfer_native_ea is not None
            else None
        ),
        blocks=plan.blocks + (imported,),
        prohibited_dispatcher_blocks=(),
        operations=(
            replace(
                direct_route,
                edges=(
                    FragmentEdge(
                        role=SemanticEdgeRole.DIRECT,
                        target_block_id=imported.block_id,
                    ),
                ),
            ),
            FragmentOperation(
                operation_id="imported-conditional-route",
                source_block_id=imported.block_id,
                predicate_anchor_ea=int(predicate_native_ea),
                computed_branch_normalization=(
                    None
                    if unresolved_transfer_native_ea is None
                    else FragmentComputedBranchNormalization(
                        predicate_kind=PredicateKind.NE,
                        normalization_start_ea=int(predicate_native_ea),
                        condition_producer_ea=int(
                            condition_producer_native_ea
                        ),
                        unresolved_transfer_ea=int(
                            unresolved_transfer_native_ea
                        ),
                    )
                ),
                edges=(
                    FragmentEdge(
                        role=SemanticEdgeRole.CONDITIONAL_TAKEN,
                        target_block_id="target",
                    ),
                    FragmentEdge(
                        role=SemanticEdgeRole.CONDITIONAL_FALLTHROUGH,
                        target_block_id="dispatcher",
                    ),
                ),
            ),
        ),
        native_bodies=(
            FragmentNativeBody(
                body_id="native-body",
                block_ids=(imported.block_id,),
                entry_block_ids=(imported.block_id,),
                terminal_block_ids=(),
                native_ranges=(native_range,),
                proof_ids=(
                    "proof:native-body",
                    *(
                        ("imported-conditional-route",)
                        if unresolved_transfer_native_ea is not None
                        else ()
                    ),
                ),
            ),
        ),
        flag_corridors=(
            ()
            if condition_producer_native_ea is None
            else (
                FragmentFlagCorridor(
                    corridor_id="imported-conditional-flags",
                    producer=FragmentValueSite(
                        site_id="imported-conditional-producer",
                        block_id=imported.block_id,
                        value_id="imported-condition-codes",
                        instruction_ea=int(condition_producer_native_ea),
                    ),
                    consumer=FragmentValueSite(
                        site_id="imported-conditional-consumer",
                        block_id=imported.block_id,
                        value_id="imported-condition-codes",
                        instruction_ea=int(predicate_native_ea),
                    ),
                    block_path=(imported.block_id,),
                    permitted_flag_write_eas=frozenset(
                        {int(condition_producer_native_ea)}
                    ),
                ),
            )
        ),
    )


def _plan_with_imported_call(
    gateway,
    *,
    entry: int,
    original: int,
    target: int,
    dispatcher: int,
    call_native_ea: int,
) -> FragmentPlan:
    plan = _plan(
        gateway,
        entry=entry,
        original=original,
        target=target,
        dispatcher=dispatcher,
    )
    native_range = NativeEaInterval(0x500000, 0x500010)
    imported_identity = StableBlockIdentity.from_intervals(
        (native_range,),
        native_key=gateway.native_key,
        exact_instruction_eas=(0x500000, int(call_native_ea)),
    )
    imported = FragmentBlock(
        block_id="imported-call",
        role=FragmentBlockRole.IMPORTED,
        materialization=FragmentBlockMaterialization.IMPORT_NATIVE,
        semantic_anchor_ea=0x500000,
        stable_identity=imported_identity,
        native_body_id="native-body",
    )
    direct_route = plan.operations[0]
    return replace(
        plan,
        plan_id="runtime-imported-native-call",
        blocks=plan.blocks + (imported,),
        operations=(
            replace(
                direct_route,
                edges=(
                    FragmentEdge(
                        role=SemanticEdgeRole.DIRECT,
                        target_block_id=imported.block_id,
                    ),
                ),
            ),
            FragmentOperation(
                operation_id="imported-call-continuation",
                source_block_id=imported.block_id,
                edges=(
                    FragmentEdge(
                        role=SemanticEdgeRole.CALL_FALLTHROUGH,
                        target_block_id="target",
                    ),
                ),
            ),
        ),
        native_bodies=(
            FragmentNativeBody(
                body_id="native-body",
                block_ids=(imported.block_id,),
                entry_block_ids=(imported.block_id,),
                terminal_block_ids=(),
                native_ranges=(native_range,),
                proof_ids=("proof:native-body",),
            ),
        ),
    )


def _with_data_flow(
    plan: FragmentPlan,
    storage: StorageIdentity,
) -> FragmentPlan:
    definition = FragmentValueSite(
        site_id="state.def",
        block_id="replacement",
        value_id="state",
        instruction_ea=0x401010,
        storage_identity=storage,
        width=4,
    )
    use = FragmentValueSite(
        site_id="state.use",
        block_id="replacement",
        value_id="state",
        instruction_ea=0x401010,
        storage_identity=storage,
        width=4,
    )
    return replace(
        plan,
        data_flow_obligations=(
            FragmentDataFlowObligation(
                obligation_id="state-flow",
                role=FragmentDataFlowRole.STATE_VALUE,
                definition=definition,
                uses=(use,),
            ),
        ),
    )


def _with_flag_corridor(
    plan: FragmentPlan,
    *,
    consumer_ea: int,
) -> FragmentPlan:
    producer = FragmentValueSite(
        site_id="flags.producer",
        block_id="replacement",
        value_id="condition-codes",
        instruction_ea=0x401010,
    )
    consumer = FragmentValueSite(
        site_id="flags.consumer",
        block_id="target",
        value_id="condition-codes",
        instruction_ea=consumer_ea,
    )
    return replace(
        plan,
        flag_corridors=(
            FragmentFlagCorridor(
                corridor_id="branch-flags",
                producer=producer,
                consumer=consumer,
                block_path=("replacement", "target"),
                permitted_flag_write_eas=frozenset({0x401010}),
            ),
        ),
    )


def _with_value_range(
    plan: FragmentPlan,
    *,
    observation: FragmentRangeObservation = (
        FragmentRangeObservation.AFTER_INSTRUCTION
    ),
) -> FragmentPlan:
    storage = StorageIdentity(StorageIdentityKind.REGISTER, offset=10)
    definition = FragmentValueSite(
        site_id="selector.def",
        block_id="replacement",
        value_id="selector",
        instruction_ea=0x401010,
        storage_identity=storage,
        width=1,
    )
    use = FragmentValueSite(
        site_id="selector.range",
        block_id="target",
        value_id="selector",
        instruction_ea=0x401020,
        storage_identity=storage,
        width=1,
    )
    return replace(
        plan,
        data_flow_obligations=(
            FragmentDataFlowObligation(
                obligation_id="selector-flow",
                role=FragmentDataFlowRole.CONDITION,
                definition=definition,
                uses=(use,),
            ),
        ),
        value_range_assumptions=(
            FragmentRangeAssumption(
                assumption_id="selector-domain",
                site=use,
                observation=observation,
                lo=0,
                hi=1,
            ),
        ),
    )


def _set_block_instructions(block: _Block, *instructions: _Instruction) -> None:
    for current, following in zip(instructions, instructions[1:]):
        current.next = following
    if instructions:
        instructions[-1].next = None
        block.head = instructions[0]
        block.tail = instructions[-1]
        block.end = max(instruction.ea for instruction in instructions) + 1
    else:
        block.head = None
        block.tail = None


def _plan_with_conditional_predecessor(
    gateway,
    *,
    entry: int,
    predecessor: int,
    sibling: int,
    original: int,
    target: int,
    dispatcher: int,
) -> FragmentPlan:
    plan = _plan(
        gateway,
        entry=entry,
        original=original,
        target=target,
        dispatcher=dispatcher,
    )
    index = gateway.identity_index

    def _external(block_id: str, serial: int) -> FragmentBlock:
        handle = index.handle_for_serial(serial)
        assert handle is not None and handle.stable_identity is not None
        rebound = index.resolve(handle)
        assert rebound is not None and rebound.anchor_ea is not None
        return FragmentBlock(
            block_id=block_id,
            role=FragmentBlockRole.EXTERNAL,
            materialization=FragmentBlockMaterialization.REUSE_PUBLISHED,
            semantic_anchor_ea=int(rebound.anchor_ea),
            stable_identity=handle.stable_identity,
        )

    return replace(
        plan,
        blocks=plan.blocks
        + (
            _external("predecessor", predecessor),
            _external("sibling", sibling),
        ),
    )


def _plan_with_shared_conditional_roots(
    gateway,
    *,
    entry: int,
    predecessor: int,
    fallthrough_original: int,
    taken_original: int,
    target: int,
    dispatcher: int,
) -> FragmentPlan:
    plan = _plan(
        gateway,
        entry=entry,
        original=fallthrough_original,
        target=target,
        dispatcher=dispatcher,
    )
    index = gateway.identity_index

    def _published(
        block_id: str,
        role: FragmentBlockRole,
        serial: int,
    ) -> FragmentBlock:
        handle = index.handle_for_serial(serial)
        assert handle is not None and handle.stable_identity is not None
        rebound = index.resolve(handle)
        assert rebound is not None and rebound.anchor_ea is not None
        return FragmentBlock(
            block_id=block_id,
            role=role,
            materialization=FragmentBlockMaterialization.REUSE_PUBLISHED,
            semantic_anchor_ea=int(rebound.anchor_ea),
            stable_identity=handle.stable_identity,
        )

    taken_original_block = _published(
        "taken-original",
        FragmentBlockRole.ORIGINAL,
        taken_original,
    )
    taken_replacement = FragmentBlock(
        block_id="taken-replacement",
        role=FragmentBlockRole.REPLACEMENT,
        materialization=FragmentBlockMaterialization.CLONE_PUBLISHED,
        semantic_anchor_ea=taken_original_block.semantic_anchor_ea,
        stable_identity=taken_original_block.stable_identity,
        replaces_block_id=taken_original_block.block_id,
    )
    return replace(
        plan,
        plan_id="runtime-shared-conditional-root-fragment",
        atomic_group_id="conditional-roots@0x401010",
        blocks=plan.blocks
        + (
            _published(
                "conditional-predecessor",
                FragmentBlockRole.EXTERNAL,
                predecessor,
            ),
            taken_original_block,
            taken_replacement,
        ),
        roots=("replacement", taken_replacement.block_id),
        owned_originals=("original", taken_original_block.block_id),
        operations=(
            plan.operations[0],
            FragmentOperation(
                operation_id="taken-replacement-route",
                source_block_id=taken_replacement.block_id,
                edges=(
                    FragmentEdge(
                        role=SemanticEdgeRole.DIRECT,
                        target_block_id="target",
                    ),
                ),
            ),
        ),
    )


def _conditional_plan(
    gateway,
    *,
    entry: int,
    original: int,
    taken: int,
    fallthrough: int,
    dispatcher: int,
    predicate_ea: int = 0x401010,
) -> FragmentPlan:
    index = gateway.identity_index

    def _native(block_id: str, role: FragmentBlockRole, serial: int):
        handle = index.handle_for_serial(serial)
        assert handle is not None
        assert handle.stable_identity is not None
        rebound = index.resolve(handle)
        assert rebound is not None and rebound.anchor_ea is not None
        return FragmentBlock(
            block_id=block_id,
            role=role,
            materialization=(
                FragmentBlockMaterialization.CLONE_PUBLISHED
                if role is FragmentBlockRole.REPLACEMENT
                else FragmentBlockMaterialization.REUSE_PUBLISHED
            ),
            semantic_anchor_ea=int(rebound.anchor_ea),
            stable_identity=handle.stable_identity,
        )

    original_block = _native("original", FragmentBlockRole.ORIGINAL, original)
    replacement = FragmentBlock(
        block_id="replacement",
        role=FragmentBlockRole.REPLACEMENT,
        materialization=FragmentBlockMaterialization.CLONE_PUBLISHED,
        semantic_anchor_ea=original_block.semantic_anchor_ea,
        stable_identity=original_block.stable_identity,
        replaces_block_id=original_block.block_id,
    )
    return FragmentPlan(
        plan_id="runtime-conditional-fragment",
        atomic_group_id="condition@0x401010",
        publication_purpose=FragmentPublicationPurpose.CANONICAL_SEMANTIC_LOWERING,
        native_key=gateway.native_key,
        blocks=(
            _native("entry", FragmentBlockRole.EXTERNAL, entry),
            original_block,
            replacement,
            _native("taken", FragmentBlockRole.EXTERNAL, taken),
            _native("fallthrough", FragmentBlockRole.EXTERNAL, fallthrough),
            _native("dispatcher", FragmentBlockRole.EXTERNAL, dispatcher),
        ),
        roots=(replacement.block_id,),
        owned_originals=(original_block.block_id,),
        prohibited_dispatcher_blocks=("dispatcher",),
        operations=(
            FragmentOperation(
                operation_id="conditional-route",
                source_block_id=replacement.block_id,
                predicate_anchor_ea=int(predicate_ea),
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
    )


def _conditional_select_plan(
    gateway,
    *,
    entry: int,
    original: int,
    selected_value: int,
    join: int,
    taken: int,
    fallthrough: int,
) -> FragmentPlan:
    plan = _conditional_plan(
        gateway,
        entry=entry,
        original=original,
        taken=taken,
        fallthrough=fallthrough,
        dispatcher=join,
        predicate_ea=0x40A5F6,
    )
    selected_handle = gateway.identity_index.handle_for_serial(selected_value)
    assert selected_handle is not None
    assert selected_handle.stable_identity is not None
    selected_rebound = gateway.identity_index.resolve(selected_handle)
    assert selected_rebound is not None
    selected_block = FragmentBlock(
        block_id="selected-value",
        role=FragmentBlockRole.EXTERNAL,
        materialization=FragmentBlockMaterialization.REUSE_PUBLISHED,
        semantic_anchor_ea=int(selected_rebound.anchor_ea),
        stable_identity=selected_handle.stable_identity,
    )
    operation = plan.operations[0]
    return replace(
        plan,
        plan_id="runtime-conditional-select-normalization",
        publication_purpose=FragmentPublicationPurpose.FRONTEND_NORMALIZATION,
        work_item_scope=FragmentWorkItemScope(
            work_item_id="conditional-select@0x40A605",
            selected_obligation_ids=("native-indirect-transfer@0x40A605",),
            remaining_obligation_ids=(),
            unreachable_obligation_ids=(),
        ),
        blocks=plan.blocks + (selected_block,),
        operations=(
            replace(
                operation,
                operation_id="native-indirect-transfer@0x40A605",
                predicate_anchor_ea=0x40A5F6,
                computed_branch_normalization=(
                    FragmentComputedBranchNormalization(
                        predicate_kind=PredicateKind.SLT,
                        normalization_start_ea=0x40A5F6,
                        condition_producer_ea=0x40A5F0,
                        unresolved_transfer_ea=0x40A605,
                        conditional_select_envelope=(
                            FragmentConditionalSelectEnvelope(
                                predicate_ea=0x40A5FE,
                                observed_predicate_kind=PredicateKind.SGE,
                                selected_value_block_id=selected_block.block_id,
                                join_block_id="dispatcher",
                            )
                        ),
                    )
                ),
            ),
        ),
    )


def _conditional_plan_with_staged_targets(
    gateway,
    *,
    entry: int,
    original: int,
    taken: int,
    fallthrough: int,
    dispatcher: int,
) -> FragmentPlan:
    plan = _conditional_plan(
        gateway,
        entry=entry,
        original=original,
        taken=taken,
        fallthrough=fallthrough,
        dispatcher=dispatcher,
    )
    blocks = {block.block_id: block for block in plan.blocks}
    taken_original = replace(
        blocks["taken"],
        block_id="taken-original",
        role=FragmentBlockRole.ORIGINAL,
    )
    taken_replacement = FragmentBlock(
        block_id="taken-replacement",
        role=FragmentBlockRole.REPLACEMENT,
        materialization=FragmentBlockMaterialization.CLONE_PUBLISHED,
        semantic_anchor_ea=taken_original.semantic_anchor_ea,
        stable_identity=taken_original.stable_identity,
        replaces_block_id=taken_original.block_id,
    )
    fallthrough_original = replace(
        blocks["fallthrough"],
        block_id="fallthrough-original",
        role=FragmentBlockRole.ORIGINAL,
    )
    fallthrough_replacement = FragmentBlock(
        block_id="fallthrough-replacement",
        role=FragmentBlockRole.REPLACEMENT,
        materialization=FragmentBlockMaterialization.CLONE_PUBLISHED,
        semantic_anchor_ea=fallthrough_original.semantic_anchor_ea,
        stable_identity=fallthrough_original.stable_identity,
        replaces_block_id=fallthrough_original.block_id,
    )
    operation = plan.operations[0]
    return replace(
        plan,
        plan_id="runtime-conditional-staged-target-fragment",
        blocks=(
            blocks["entry"],
            blocks["original"],
            blocks["replacement"],
            taken_original,
            taken_replacement,
            fallthrough_original,
            fallthrough_replacement,
            blocks["dispatcher"],
        ),
        owned_originals=(
            "original",
            taken_original.block_id,
            fallthrough_original.block_id,
        ),
        operations=(
            replace(
                operation,
                edges=(
                    FragmentEdge(
                        role=SemanticEdgeRole.CONDITIONAL_TAKEN,
                        target_block_id=taken_replacement.block_id,
                    ),
                    FragmentEdge(
                        role=SemanticEdgeRole.CONDITIONAL_FALLTHROUGH,
                        target_block_id=fallthrough_replacement.block_id,
                    ),
                ),
            ),
        ),
    )


def test_backend_stages_hidden_replacement_and_projects_root_publication() -> None:
    entry = _Block(0, start=0x401000, block_type=ida_hexrays.BLT_1WAY)
    original = _Block(1, start=0x401010, block_type=ida_hexrays.BLT_1WAY)
    target = _Block(2, start=0x401020, block_type=ida_hexrays.BLT_0WAY)
    dispatcher = _Block(3, start=0x401030, block_type=ida_hexrays.BLT_0WAY)
    stop = _Block(4, start=0x401040, block_type=ida_hexrays.BLT_STOP)
    _connect(entry, original)
    _connect(original, dispatcher)
    mba = _Mba((entry, original, target, dispatcher, stop))
    gateway = _fragment_gateway(mba)
    modifier = dm.DeferredGraphModifier(mba, mutation_gateway=gateway)
    plan = _plan(gateway, entry=0, original=1, target=2, dispatcher=3)
    original_handle = gateway.identity_index.handle_for_serial(1)
    assert original_handle is not None
    proxy = gateway.identity_index.logical_proxy_for_handle(original_handle)
    assert proxy is not None
    published = proxy.resolve()
    assert published is not None
    root_inventory = modifier._plan_semantic_fragment_root_publication_inventory(plan)
    gateway._begin_semantic_fragment_batch(modifier, plan, root_inventory)

    projection = modifier._stage_semantic_fragment(plan)

    result = validate_fragment_projection(plan, projection)
    assert result.passed, result.failures
    assert tuple(entry.succset) == (1,)
    assert tuple(original.succset) == (3,)
    assert projection.block("entry").successors == ("replacement",)
    assert projection.block("replacement").successors == ("target",)
    assert projection.block("original").predecessors == ()
    assert projection.binding("original").state is FragmentBindingState.PUBLISHED
    assert projection.binding("replacement").state is FragmentBindingState.STAGED
    assert proxy.resolve() is published
    staged = proxy.resolve(transaction_id=str(gateway._active_batch_id))
    assert staged is not None and staged is not published
    staged_binding = gateway.identity_index.resolve_logical_version(
        staged,
        transaction_id=str(gateway._active_batch_id),
    )
    assert staged_binding is not None
    replacement_live = mba.get_mblock(staged_binding.serial)
    assert replacement_live is not None
    assert tuple(replacement_live.predset) == ()
    assert tuple(replacement_live.succset) == (2,)

    modifier._discard_staged_semantic_fragment(plan)
    gateway.abort(reason="runtime staging test cleanup")

    assert mba.qty == 5
    assert tuple(entry.succset) == (1,)
    assert tuple(original.succset) == (3,)
    assert tuple(target.predset) == ()
    assert proxy.resolve() is published
    assert gateway.active is False


def test_backend_stages_native_body_inside_active_fragment_transaction(
    monkeypatch,
) -> None:
    entry = _Block(0, start=0x401000, block_type=ida_hexrays.BLT_1WAY)
    original = _Block(1, start=0x401010, block_type=ida_hexrays.BLT_1WAY)
    target = _Block(2, start=0x401020, block_type=ida_hexrays.BLT_0WAY)
    dispatcher = _Block(3, start=0x401030, block_type=ida_hexrays.BLT_0WAY)
    stop = _Block(4, start=0x401040, block_type=ida_hexrays.BLT_STOP)
    _connect(entry, original)
    _connect(original, dispatcher)
    mba = _Mba((entry, original, target, dispatcher, stop))
    gateway = _fragment_gateway(mba)
    materializer = _RecordingNativeBodyMaterializer()
    monkeypatch.setattr(dm, "create_standalone_block", _create_fake_standalone_block)
    modifier = dm.DeferredGraphModifier(
        mba,
        mutation_gateway=gateway,
        semantic_native_body_materializer=materializer,
    )
    plan = _plan_with_imported_terminal(
        gateway,
        entry=0,
        original=1,
        target=2,
        dispatcher=3,
    )
    original_ranges = _outline_ranges(mba)
    assert not int(mba.get_mba_flags2()) & int(
        ida_hexrays.MBA2_HAS_OUTLINES
    )
    root_inventory = modifier._plan_semantic_fragment_root_publication_inventory(plan)
    gateway._begin_semantic_fragment_batch(modifier, plan, root_inventory)
    transaction_id = gateway.active_batch_id
    assert transaction_id is not None

    projection = modifier._stage_semantic_fragment(plan)

    assert materializer.calls == [
        (plan.plan_id, "native-body", transaction_id),
    ]
    validation = validate_fragment_projection(plan, projection)
    assert validation.passed, validation.failures
    imported_binding = projection.binding("imported-terminal")
    assert imported_binding.state is FragmentBindingState.STAGED
    state = modifier._semantic_fragment_state
    assert state is not None
    imported_runtime = state.binding("imported-terminal")
    assert (
        imported_runtime.version.handle.provenance
        is BlockHandleProvenance.IMPORTED_NATIVE
    )
    imported_proxy = imported_runtime.proxy
    assert imported_proxy.resolve() is None
    assert (
        imported_proxy.resolve(transaction_id=transaction_id)
        is imported_runtime.version
    )
    assert gateway.active
    assert gateway.receipts == ()
    assert _outline_ranges(mba) == (
        *original_ranges,
        (0x500000, 0x500010),
    )
    assert int(mba.get_mba_flags2()) & int(
        ida_hexrays.MBA2_HAS_OUTLINES
    )

    modifier._discard_staged_semantic_fragment(plan)
    gateway.abort(reason="runtime imported native-body staging cleanup")

    assert mba.qty == 5
    assert _outline_ranges(mba) == original_ranges
    assert not int(mba.get_mba_flags2()) & int(
        ida_hexrays.MBA2_HAS_OUTLINES
    )
    assert gateway.active is False
    assert gateway.receipts == ()


def test_backend_materializes_and_observes_terminal_effects_from_live_mba(
    monkeypatch,
) -> None:
    mba, gateway, modifier, plan, _entry, _original = (
        _terminal_effect_runtime_case(monkeypatch)
    )
    root_inventory = modifier._plan_semantic_fragment_root_publication_inventory(plan)
    gateway._begin_semantic_fragment_batch(modifier, plan, root_inventory)

    projection = modifier._stage_semantic_fragment(plan)

    validation = validate_fragment_projection(plan, projection)
    assert validation.passed, validation.failures
    assert projection.return_carriers == plan.return_carriers
    assert projection.terminal_returns == plan.terminal_returns
    assert projection.block("imported-carrier").instruction_eas[:2] == (
        0x500000,
        0x500004,
    )
    assert projection.block("imported-return").instruction_eas == (0x500100,)
    assert projection.block("imported-return").kind is BlockKind.ZERO_WAY

    state = modifier._semantic_fragment_state
    assert state is not None
    carrier_block = sfb._live_block_for_binding(
        modifier,
        state.binding("imported-carrier"),
    )
    carrier_live_ea = state.live_instruction_ea(
        "imported-carrier",
        0x500004,
    )
    carrier_matches = tuple(
        instruction
        for instruction in sfb._iter_block_instructions(carrier_block)
        if int(instruction.ea) == carrier_live_ea
    )
    assert len(carrier_matches) == 1
    carrier_instruction = carrier_matches[0]
    assert int(carrier_instruction.opcode) == int(ida_hexrays.m_mov)
    assert int(carrier_instruction.l.t) == int(ida_hexrays.mop_n)
    assert int(carrier_instruction.l.nnn.value) == 7
    assert int(carrier_instruction.l.size) == 4
    assert int(carrier_instruction.d.t) == int(ida_hexrays.mop_r)
    assert int(carrier_instruction.d.r) == int(ida_hexrays.reg2mreg(0))
    assert int(carrier_instruction.d.size) == 4

    terminal_block = sfb._live_block_for_binding(
        modifier,
        state.binding("imported-return"),
    )
    assert terminal_block.tail is not None
    assert int(terminal_block.tail.opcode) == int(ida_hexrays.m_ret)
    assert int(terminal_block.type) == int(ida_hexrays.BLT_0WAY)
    assert tuple(terminal_block.succset) == ()

    carrier_instruction.opcode = int(ida_hexrays.m_xdu)
    corrupted = sfb._project_fragment(modifier, plan, state)
    assert corrupted.return_carriers == ()

    modifier._discard_staged_semantic_fragment(plan)
    gateway.abort(reason="runtime terminal-effect staging cleanup")


def test_gateway_receipts_terminal_effects_in_atomic_publication_inventory(
    monkeypatch,
) -> None:
    _mba, gateway, modifier, plan, _entry, _original = (
        _terminal_effect_runtime_case(monkeypatch)
    )
    emitter = EventEmitter()
    planned: list[MbaMutationPlanned] = []
    committed: list[MbaMutationCommitted] = []
    emitter.on(MbaMutationPlanned, planned.append)
    emitter.on(MbaMutationCommitted, committed.append)
    gateway.event_emitter = emitter

    receipt = gateway.publish_semantic_fragment(modifier, plan)

    assert receipt.prepublication_validation.passed
    assert receipt.postpublication_validation.passed
    assert receipt.operation_count == receipt.planned_operation_count == 8
    assert gateway.receipts == (receipt,)
    assert len(planned) == len(committed) == 1
    assert planned[0].fragment_plan_id == plan.plan_id
    assert planned[0].fragment_atomic_group_id == plan.atomic_group_id
    persisted_plan = json.loads(planned[0].fragment_plan_json)
    assert persisted_plan["plan_id"] == plan.plan_id
    assert persisted_plan["atomic_group_id"] == plan.atomic_group_id
    assert {block["block_id"] for block in persisted_plan["blocks"]} == {
        block.block_id for block in plan.blocks
    }
    assert committed[0].receipt.version_transitions


def test_live_fragment_publication_is_reconstructible_from_diagnostic_db(
    monkeypatch,
) -> None:
    _mba, gateway, modifier, plan, _entry, _original = (
        _terminal_effect_runtime_case(monkeypatch)
    )
    diag_conn = create_diag_database(":memory:").connection()
    reset_diagnostic_bus()
    monkeypatch.setattr(
        "d810.core.diag.event_handlers.get_diag_conn",
        lambda *_args, **_kwargs: diag_conn,
    )
    install_diag_event_handlers()
    emitter = EventEmitter()
    emitter.on(MbaMutationPlanned, D810Manager._on_mutation_planned)
    emitter.on(MbaMutationCommitted, D810Manager._on_mutation_committed)
    gateway.event_emitter = emitter
    emit_diagnostic(
        DiagnosticSessionObserved(
            gateway.session_id,
            gateway.function_ea,
            1,
            gateway.native_key.to_json(),
            "active",
        )
    )

    try:
        receipt = gateway.publish_semantic_fragment(modifier, plan)
    finally:
        uninstall_diag_event_handlers()
        reset_diagnostic_bus()

    assert receipt.root_publication_confirmed
    assert diag_conn.execute(
        "SELECT plan_id,atomic_group_id,outcome,fragment_staged,"
        "root_publication_succeeded,rollback_attempted "
        "FROM semantic_fragment_transactions"
    ).fetchone() == (
        plan.plan_id,
        plan.atomic_group_id,
        "committed",
        1,
        1,
        0,
    )
    persisted_plan = json.loads(
        diag_conn.execute(
            "SELECT plan_json FROM semantic_fragment_transactions"
        ).fetchone()[0]
    )
    assert {block["block_id"] for block in persisted_plan["blocks"]} == {
        block.block_id for block in plan.blocks
    }
    validation_rows = diag_conn.execute(
        "SELECT phase,postcondition,passed "
        "FROM semantic_fragment_validation_outcomes "
        "ORDER BY outcome_index"
    ).fetchall()
    assert validation_rows
    assert {phase for phase, _postcondition, _passed in validation_rows} == {
        "prepublication",
        "postpublication",
    }
    assert all(passed for _phase, _postcondition, passed in validation_rows)
    assert validation_rows == [
        (
            phase,
            outcome.postcondition.value,
            int(outcome.passed),
        )
        for phase, validation in (
            ("prepublication", receipt.prepublication_validation),
            ("postpublication", receipt.postpublication_validation),
        )
        for outcome in validation.outcomes
    ]
    expected_version_rows = []
    for transition in receipt.version_transitions:
        if transition.retired_version is not None:
            expected_version_rows.append(
                _persisted_version_transition_row(
                    transition.retired_version,
                    "published",
                    "retired",
                )
            )
        if transition.promoted_version is not None:
            expected_version_rows.append(
                _persisted_version_transition_row(
                    transition.promoted_version,
                    "staged",
                    "published",
                )
            )
    assert diag_conn.execute(
        "SELECT proxy_token,version,physical_handle_token,generation,"
        "provenance,stable_identity_json,anchor_ea_hex,anchor_ea_i64,"
        "predecessor_version,from_state,to_state "
        "FROM logical_block_version_transitions ORDER BY transition_index"
    ).fetchall() == expected_version_rows
    root_group = diag_conn.execute(
        "SELECT group_id,predecessor_block_id,predecessor_anchor_ea_i64,"
        "edge_ids_json,edge_roles_json,original_block_ids_json,"
        "replacement_block_ids_json,publication_attempted,"
        "publication_succeeded,rollback_attempted,rollback_succeeded "
        "FROM semantic_fragment_root_publication_groups"
    ).fetchone()
    assert root_group[:3] == ("root-group:entry", "entry", 0x401000)
    assert tuple(json.loads(payload) for payload in root_group[3:7]) == (
        ["replacement:entry:direct"],
        ["direct"],
        ["original"],
        ["replacement"],
    )
    assert root_group[7:] == (1, 1, 0, None)


def test_failed_live_staging_restores_graph_and_records_rollback(
    monkeypatch,
) -> None:
    entry = _Block(0, start=0x401000, block_type=ida_hexrays.BLT_1WAY)
    original = _Block(1, start=0x401010, block_type=ida_hexrays.BLT_0WAY)
    taken = _Block(2, start=0x401020, block_type=ida_hexrays.BLT_0WAY)
    fallthrough = _Block(3, start=0x401030, block_type=ida_hexrays.BLT_0WAY)
    dispatcher = _Block(4, start=0x401040, block_type=ida_hexrays.BLT_0WAY)
    stop = _Block(5, start=0x401050, block_type=ida_hexrays.BLT_STOP)
    _connect(entry, original)
    original.tail = _Instruction(ida_hexrays.m_jz, 0x401010)
    original.head = original.tail
    mba = _Mba((entry, original, taken, fallthrough, dispatcher, stop))
    gateway = _fragment_gateway(mba)
    modifier = dm.DeferredGraphModifier(mba, mutation_gateway=gateway)
    monkeypatch.setattr(dm, "insert_goto_instruction", _insert_fake_goto_instruction)
    plan = _conditional_plan(
        gateway,
        entry=0,
        original=1,
        taken=2,
        fallthrough=3,
        dispatcher=4,
    )
    diag_conn = create_diag_database(":memory:").connection()
    reset_diagnostic_bus()
    monkeypatch.setattr(
        "d810.core.diag.event_handlers.get_diag_conn",
        lambda *_args, **_kwargs: diag_conn,
    )
    install_diag_event_handlers()
    emitter = EventEmitter()
    aborted: list[MbaMutationAborted] = []
    emitter.on(MbaMutationPlanned, D810Manager._on_mutation_planned)
    emitter.on(MbaMutationAborted, D810Manager._on_mutation_aborted)
    emitter.on(MbaMutationAborted, aborted.append)
    gateway.event_emitter = emitter
    emit_diagnostic(
        DiagnosticSessionObserved(
            gateway.session_id,
            gateway.function_ea,
            1,
            gateway.native_key.to_json(),
            "active",
        )
    )

    def _reject_after_helper(*_blocks) -> None:
        raise RuntimeError("post-helper failure")

    monkeypatch.setattr(modifier, "_semantic_edge_mark", _reject_after_helper)
    try:
        with pytest.raises(RuntimeError, match="post-helper failure"):
            gateway.publish_semantic_fragment(modifier, plan)
    finally:
        uninstall_diag_event_handlers()
        reset_diagnostic_bus()

    assert mba.qty == 6
    assert tuple(entry.succset) == (1,)
    assert tuple(original.succset) == ()
    assert tuple(taken.predset) == ()
    assert tuple(fallthrough.predset) == ()
    assert gateway.receipts == ()
    assert gateway.active is False
    assert len(aborted) == 1
    assert aborted[0].rollback_attempted
    assert aborted[0].rollback_succeeded
    assert diag_conn.execute(
        "SELECT outcome,fragment_staged,root_publication_attempted,"
        "rollback_attempted,rollback_succeeded,reason "
        "FROM semantic_fragment_transactions"
    ).fetchone() == (
        "aborted",
        0,
        0,
        1,
        1,
        "post-helper failure",
    )
    assert diag_conn.execute(
        "SELECT event_kind,outcome FROM semantic_fragment_transaction_events "
        "ORDER BY event_index"
    ).fetchall() == [
        ("plan_recorded", "planned"),
        ("fragment_staged", "failed"),
        ("rollback", "succeeded"),
        ("receipt", "aborted"),
    ]


def test_staged_block_discard_uses_protected_unreachable_sweep(
    monkeypatch,
) -> None:
    entry = _Block(0, start=0x401000, block_type=ida_hexrays.BLT_0WAY)
    original = _Block(1, start=0x401010, block_type=ida_hexrays.BLT_0WAY)
    staged_first = _Block(2, start=0xF10000, block_type=ida_hexrays.BLT_0WAY)
    staged_second = _Block(3, start=0xF10001, block_type=ida_hexrays.BLT_0WAY)
    stop = _Block(4, start=0x401020, block_type=ida_hexrays.BLT_STOP)
    original.flags |= int(ida_hexrays.MBL_KEEP)
    staged_first.flags |= int(ida_hexrays.MBL_KEEP)
    staged_second.flags |= int(ida_hexrays.MBL_KEEP)
    mba = _Mba((entry, original, staged_first, staged_second, stop))
    original.flags &= ~int(ida_hexrays.MBL_KEEP)
    gateway = _fragment_gateway(mba)
    modifier = dm.DeferredGraphModifier(mba, mutation_gateway=gateway)

    def reject_low_level_batch_removal(_start, _end) -> None:
        raise AssertionError("low-level block removal leaves stale serials")

    monkeypatch.setattr(mba, "remove_blocks", reject_low_level_batch_removal)

    modifier._discard_semantic_fragment_blocks(
        (staged_first, staged_second),
    )

    assert mba.removed_unreachable_calls == 1
    assert mba.qty == 3
    assert mba.get_mblock(2) is stop
    assert int(stop.serial) == 2
    assert not int(original.flags) & int(ida_hexrays.MBL_KEEP)
    assert mba.verify_calls == 1


def test_gateway_rolls_back_disappeared_terminal_effect_and_receipts_applied_work(
    monkeypatch,
) -> None:
    mba, gateway, modifier, plan, entry, original = _terminal_effect_runtime_case(
        monkeypatch
    )
    emitter = EventEmitter()
    aborted: list[MbaMutationAborted] = []
    diag_conn = create_diag_database(":memory:").connection()
    reset_diagnostic_bus()
    monkeypatch.setattr(
        "d810.core.diag.event_handlers.get_diag_conn",
        lambda *_args, **_kwargs: diag_conn,
    )
    install_diag_event_handlers()
    emitter.on(MbaMutationPlanned, D810Manager._on_mutation_planned)
    emitter.on(MbaMutationAborted, D810Manager._on_mutation_aborted)
    emitter.on(MbaMutationAborted, aborted.append)
    gateway.event_emitter = emitter
    emit_diagnostic(
        DiagnosticSessionObserved(
            gateway.session_id,
            gateway.function_ea,
            1,
            gateway.native_key.to_json(),
            "active",
        )
    )
    observe_published = modifier._observe_published_semantic_fragment

    def _observe_after_carrier_corruption(observed_plan):
        state = modifier._semantic_fragment_state
        assert state is not None
        carrier_block = sfb._live_block_for_binding(
            modifier,
            state.binding("imported-carrier"),
        )
        carrier_live_ea = state.live_instruction_ea(
            "imported-carrier",
            0x500004,
        )
        carrier_instruction = next(
            instruction
            for instruction in sfb._iter_block_instructions(carrier_block)
            if int(instruction.ea) == carrier_live_ea
        )
        carrier_instruction.opcode = int(ida_hexrays.m_xdu)
        return observe_published(observed_plan)

    monkeypatch.setattr(
        modifier,
        "_observe_published_semantic_fragment",
        _observe_after_carrier_corruption,
    )

    try:
        with pytest.raises(
            SemanticFragmentPublicationRejected,
            match="postpublication.*observable_return_carrier:return-value",
        ):
            gateway.publish_semantic_fragment(modifier, plan)
    finally:
        uninstall_diag_event_handlers()
        reset_diagnostic_bus()

    assert mba.qty == 5
    assert tuple(entry.succset) == (1,)
    assert tuple(original.succset) == (3,)
    assert gateway.receipts == ()
    assert gateway.active is False
    assert len(aborted) == 1
    assert aborted[0].planned_operation_count == 8
    assert aborted[0].applied_operation_count == 8
    assert "observable_return_carrier:return-value" in aborted[0].reason
    assert aborted[0].fragment_plan_id == plan.plan_id
    assert aborted[0].fragment_atomic_group_id == plan.atomic_group_id
    assert aborted[0].fragment_staged
    assert aborted[0].root_publication_attempted
    assert aborted[0].root_publication_succeeded
    assert aborted[0].rollback_attempted
    assert aborted[0].rollback_succeeded
    assert aborted[0].prepublication_validation is not None
    assert aborted[0].prepublication_validation.passed
    assert aborted[0].postpublication_validation is not None
    assert not aborted[0].postpublication_validation.passed
    assert aborted[0].discarded_versions
    assert diag_conn.execute(
        "SELECT proxy_token,version,physical_handle_token,generation,"
        "provenance,stable_identity_json,anchor_ea_hex,anchor_ea_i64,"
        "predecessor_version,from_state,to_state "
        "FROM logical_block_version_transitions ORDER BY transition_index"
    ).fetchall() == [
        _persisted_version_transition_row(version, "staged", "aborted")
        for version in aborted[0].discarded_versions
    ]
    assert diag_conn.execute(
        "SELECT group_id,publication_attempted,publication_succeeded,"
        "rollback_attempted,rollback_succeeded "
        "FROM semantic_fragment_root_publication_groups"
    ).fetchone() == ("root-group:entry", 1, 1, 1, 1)
    assert diag_conn.execute(
        "SELECT event_kind,outcome,detail_json "
        "FROM semantic_fragment_transaction_events "
        "WHERE event_kind LIKE 'root_group_%' ORDER BY event_index"
    ).fetchall() == [
        (
            "root_group_publication",
            "published",
            '{"group_id":"root-group:entry"}',
        ),
        (
            "root_group_rollback",
            "succeeded",
            '{"group_id":"root-group:entry"}',
        ),
    ]


@pytest.mark.parametrize(
    ("operation", "source", "return_width", "expected_opcode", "expected_type"),
    (
        (
            ValueOpKind.ZEXT,
            FragmentReturnSource(
                kind=FragmentReturnSourceKind.STORAGE_VALUE,
                width=1,
                storage_identity=StorageIdentity(
                    StorageIdentityKind.STACK,
                    0x30,
                ),
            ),
            4,
            ida_hexrays.m_xdu,
            ida_hexrays.mop_S,
        ),
        (
            ValueOpKind.SEXT,
            FragmentReturnSource(
                kind=FragmentReturnSourceKind.STORAGE_VALUE,
                width=2,
                storage_identity=StorageIdentity(
                    StorageIdentityKind.GLOBAL,
                    0x600000,
                ),
            ),
            4,
            ida_hexrays.m_xds,
            ida_hexrays.mop_v,
        ),
        (
            ValueOpKind.MOVE,
            FragmentReturnSource(
                kind=FragmentReturnSourceKind.ADDRESS_OF_STORAGE,
                width=8,
                storage_identity=StorageIdentity(
                    StorageIdentityKind.GLOBAL,
                    0x600000,
                ),
            ),
            8,
            ida_hexrays.m_mov,
            ida_hexrays.mop_a,
        ),
        (
            ValueOpKind.MOVE,
            FragmentReturnSource(
                kind=FragmentReturnSourceKind.ADDRESS_OF_STORAGE,
                width=8,
                storage_identity=StorageIdentity(
                    StorageIdentityKind.STACK,
                    0x38,
                ),
            ),
            8,
            ida_hexrays.m_mov,
            ida_hexrays.mop_a,
        ),
    ),
)
def test_backend_round_trips_portable_terminal_carrier_sources(
    monkeypatch,
    operation: ValueOpKind,
    source: FragmentReturnSource,
    return_width: int,
    expected_opcode: int,
    expected_type: int,
) -> None:
    _mba, gateway, modifier, plan, _entry, _original = (
        _terminal_effect_runtime_case(
            monkeypatch,
            source=source,
            operation=operation,
            return_width=return_width,
        )
    )
    root_inventory = modifier._plan_semantic_fragment_root_publication_inventory(plan)
    gateway._begin_semantic_fragment_batch(modifier, plan, root_inventory)

    projection = modifier._stage_semantic_fragment(plan)

    validation = validate_fragment_projection(plan, projection)
    assert validation.passed, validation.failures
    assert projection.return_carriers == plan.return_carriers
    state = modifier._semantic_fragment_state
    assert state is not None
    carrier_block = sfb._live_block_for_binding(
        modifier,
        state.binding("imported-carrier"),
    )
    carrier_live_ea = state.live_instruction_ea(
        "imported-carrier",
        0x500004,
    )
    carrier_instruction = next(
        instruction
        for instruction in sfb._iter_block_instructions(carrier_block)
        if int(instruction.ea) == carrier_live_ea
    )
    assert int(carrier_instruction.opcode) == int(expected_opcode)
    assert int(carrier_instruction.l.t) == int(expected_type)
    assert int(carrier_instruction.d.size) == return_width

    modifier._discard_staged_semantic_fragment(plan)
    gateway.abort(reason="runtime terminal-source round-trip cleanup")


def test_backend_rejects_conflicting_terminal_carrier_atomically(
    monkeypatch,
) -> None:
    mba, gateway, modifier, plan, entry, original = _terminal_effect_runtime_case(
        monkeypatch,
        materializer=_TerminalEffectNativeBodyMaterializer(
            conflicting_carrier=True,
        ),
    )
    root_inventory = modifier._plan_semantic_fragment_root_publication_inventory(plan)
    gateway._begin_semantic_fragment_batch(modifier, plan, root_inventory)

    with pytest.raises(
        sfb.SemanticFragmentBackendRejected,
        match="return carrier conflicts",
    ):
        modifier._stage_semantic_fragment(plan)
    gateway.abort(reason="runtime conflicting terminal carrier cleanup")

    assert mba.qty == 5
    assert tuple(entry.succset) == (original.serial,)
    assert gateway.active is False
    assert modifier._semantic_fragment_state is None


def test_native_body_origin_binding_translates_operations_and_projection(
    monkeypatch,
) -> None:
    entry = _Block(0, start=0x401000, block_type=ida_hexrays.BLT_1WAY)
    original = _Block(1, start=0x401010, block_type=ida_hexrays.BLT_1WAY)
    target = _Block(2, start=0x401020, block_type=ida_hexrays.BLT_0WAY)
    dispatcher = _Block(3, start=0x401030, block_type=ida_hexrays.BLT_0WAY)
    stop = _Block(4, start=0x401040, block_type=ida_hexrays.BLT_STOP)
    _connect(entry, original)
    _connect(original, dispatcher)
    mba = _Mba((entry, original, target, dispatcher, stop))
    gateway = _fragment_gateway(mba)
    predicate_native_ea = 0x500004
    predicate_live_ea = 0xF10004
    mba.fictitious_ea_map[predicate_live_ea] = predicate_native_ea
    materializer = _OriginBoundConditionalNativeBodyMaterializer(
        live_ea=predicate_live_ea,
        native_ea=predicate_native_ea,
    )
    monkeypatch.setattr(dm, "create_standalone_block", _create_fake_standalone_block)
    monkeypatch.setattr(dm, "insert_goto_instruction", _insert_fake_goto_instruction)
    modifier = dm.DeferredGraphModifier(
        mba,
        mutation_gateway=gateway,
        semantic_native_body_materializer=materializer,
    )
    plan = _plan_with_imported_conditional(
        gateway,
        entry=0,
        original=1,
        target=2,
        dispatcher=3,
        predicate_native_ea=predicate_native_ea,
    )
    root_inventory = modifier._plan_semantic_fragment_root_publication_inventory(plan)
    gateway._begin_semantic_fragment_batch(modifier, plan, root_inventory)

    projection = modifier._stage_semantic_fragment(plan)

    imported = projection.block("imported-conditional")
    assert imported.instruction_eas == (predicate_native_ea,)
    assert set(imported.successors) == {
        "target",
        "fallthrough-helper:imported-conditional-route",
    }
    assert gateway.receipts == ()

    modifier._discard_staged_semantic_fragment(plan)
    gateway.abort(reason="runtime imported origin binding cleanup")


@pytest.mark.parametrize(
    "destination_maturity",
    (ida_hexrays.MMAT_GENERATED, ida_hexrays.MMAT_PREOPTIMIZED),
)
@pytest.mark.parametrize("empty_topology_duplicate", (False, True))
@pytest.mark.parametrize("split_predicate_microblock", (False, True))
@pytest.mark.parametrize("template_provenance_ea", (0x500000, 0x4FFF00))
def test_cached_preopt_body_materializes_through_the_fragment_transaction(
    monkeypatch,
    destination_maturity,
    empty_topology_duplicate,
    split_predicate_microblock,
    template_provenance_ea,
) -> None:
    def create_with_live_placeholder(**kwargs):
        created = _create_fake_standalone_block(**kwargs)
        if created.head is None:
            placeholder = _Instruction(ida_hexrays.m_nop, created.mba.entry_ea)
            created.insert_into_block(placeholder, created.head)
        return created

    entry = _Block(0, start=0x401000, block_type=ida_hexrays.BLT_1WAY)
    original = _Block(1, start=0x401010, block_type=ida_hexrays.BLT_1WAY)
    target = _Block(2, start=0x401020, block_type=ida_hexrays.BLT_0WAY)
    dispatcher = _Block(3, start=0x401030, block_type=ida_hexrays.BLT_0WAY)
    stop = _Block(4, start=0x401040, block_type=ida_hexrays.BLT_STOP)
    _connect(entry, original)
    _connect(original, dispatcher)
    mba = _Mba((entry, original, target, dispatcher, stop))
    mba.maturity = int(destination_maturity)
    gateway = _fragment_gateway(mba)
    predicate_native_ea = 0x500004
    plan = _plan_with_imported_conditional(
        gateway,
        entry=0,
        original=1,
        target=2,
        dispatcher=3,
        predicate_native_ea=predicate_native_ea,
        condition_producer_native_ea=0x500001,
    )
    producer_instruction = _Instruction(ida_hexrays.m_nop, 0x500001)
    producer_instruction.d.writes_ccflags = True
    template = dhi.DetachedSnippetTemplate(
        function_ea=int(gateway.function_ea),
        target_ea=template_provenance_ea,
        maturity=int(ida_hexrays.MMAT_PREOPTIMIZED),
        root_source_serial=0,
        blocks=(
            *(
                (
                    dhi.DetachedSnippetBlockTemplate(
                        source_serial=0,
                        native_entry_ea=0x500000,
                        native_end_ea=0x500000,
                        instructions=(),
                        block_type=int(ida_hexrays.BLT_1WAY),
                        block_flags=0,
                        successor_serials=(1,),
                        external_successor_eas=(),
                    ),
                )
                if empty_topology_duplicate
                else ()
            ),
            dhi.DetachedSnippetBlockTemplate(
                source_serial=1,
                native_entry_ea=0x500000,
                native_end_ea=0x500010,
                instructions=(
                    producer_instruction,
                    _Instruction(ida_hexrays.m_nop, 0x500001),
                    _Instruction(ida_hexrays.m_jz, predicate_native_ea),
                ),
                block_type=int(ida_hexrays.BLT_0WAY),
                block_flags=0,
                successor_serials=(),
                external_successor_eas=(),
            ),
            *(
                (
                    dhi.DetachedSnippetBlockTemplate(
                        source_serial=2,
                        native_entry_ea=predicate_native_ea,
                        native_end_ea=0x500010,
                        instructions=(
                            _Instruction(ida_hexrays.m_jz, predicate_native_ea),
                        ),
                        block_type=int(ida_hexrays.BLT_0WAY),
                        block_flags=0,
                        successor_serials=(),
                        external_successor_eas=(),
                    ),
                )
                if split_predicate_microblock
                else ()
            ),
        ),
        stack_vd_to_ida=(),
        owned_ranges=((0x500000, 0x500010),),
    )
    monkeypatch.setattr(
        dhi,
        "_PREOPT_UNION_SNIPPET_TEMPLATES",
        {(int(gateway.function_ea), template_provenance_ea): template},
    )
    monkeypatch.setattr(dhi.ida_hexrays, "minsn_t", deepcopy)
    monkeypatch.setattr(dm, "create_standalone_block", create_with_live_placeholder)
    monkeypatch.setattr(dm, "insert_goto_instruction", _insert_fake_goto_instruction)
    modifier = dm.DeferredGraphModifier(
        mba,
        mutation_gateway=gateway,
        semantic_native_body_materializer=(
            dhi.PreoptUnionSemanticNativeBodyMaterializer(
                mba=mba,
                function_ea=int(gateway.function_ea),
            )
        ),
    )
    root_inventory = modifier._plan_semantic_fragment_root_publication_inventory(plan)
    gateway._begin_semantic_fragment_batch(modifier, plan, root_inventory)

    projection = modifier._stage_semantic_fragment(plan)

    imported = projection.block("imported-conditional")
    assert imported.instruction_eas == (0x500001, predicate_native_ea)
    assert set(imported.successors) == {
        "target",
        "fallthrough-helper:imported-conditional-route",
    }
    assert tuple(mba.fictitious_ea_map.values()) == (
        0x500001,
        0x500001,
        predicate_native_ea,
    )
    assert gateway.receipts == ()

    modifier._discard_staged_semantic_fragment(plan)
    gateway.abort(reason="runtime cached PREOPT body cleanup")


def test_cached_preopt_body_binds_one_native_block_split_into_select_microblocks(
    monkeypatch,
) -> None:
    entry = _Block(0, start=0x401000, block_type=ida_hexrays.BLT_1WAY)
    original = _Block(1, start=0x401010, block_type=ida_hexrays.BLT_1WAY)
    target = _Block(2, start=0x401020, block_type=ida_hexrays.BLT_0WAY)
    dispatcher = _Block(3, start=0x401030, block_type=ida_hexrays.BLT_0WAY)
    stop = _Block(4, start=0x401040, block_type=ida_hexrays.BLT_STOP)
    _connect(entry, original)
    _connect(original, dispatcher)
    mba = _Mba((entry, original, target, dispatcher, stop))
    gateway = _fragment_gateway(mba)
    condition_producer_ea = 0x500001
    predicate_ea = 0x500004
    select_ea = 0x500008
    unresolved_transfer_ea = 0x50000C
    plan = _plan_with_imported_conditional(
        gateway,
        entry=0,
        original=1,
        target=2,
        dispatcher=3,
        predicate_native_ea=predicate_ea,
        condition_producer_native_ea=condition_producer_ea,
        unresolved_transfer_native_ea=unresolved_transfer_ea,
    )

    producer = _Instruction(ida_hexrays.m_setz, condition_producer_ea)
    producer.d.make_reg(2, 1)
    producer.d.writes_ccflags = True
    predicate = _Instruction(ida_hexrays.m_mov, predicate_ea)
    source_tail = _Instruction(ida_hexrays.m_jcnd, select_ea)
    source_tail.l.assign(producer.d)
    source_tail.d.make_blkref(2)
    selected_value = _Instruction(ida_hexrays.m_mov, select_ea)
    template = dhi.DetachedSnippetTemplate(
        function_ea=int(gateway.function_ea),
        target_ea=0x500000,
        maturity=int(ida_hexrays.MMAT_PREOPTIMIZED),
        root_source_serial=0,
        blocks=(
            dhi.DetachedSnippetBlockTemplate(
                source_serial=0,
                native_entry_ea=0x500000,
                native_end_ea=0x500010,
                instructions=(producer, predicate, source_tail),
                block_type=int(ida_hexrays.BLT_2WAY),
                block_flags=0,
                successor_serials=(1, 2),
                external_successor_eas=(),
            ),
            dhi.DetachedSnippetBlockTemplate(
                source_serial=1,
                native_entry_ea=select_ea,
                native_end_ea=0x500010,
                instructions=(selected_value,),
                block_type=int(ida_hexrays.BLT_1WAY),
                block_flags=0,
                successor_serials=(2,),
                external_successor_eas=(),
            ),
            dhi.DetachedSnippetBlockTemplate(
                source_serial=2,
                native_entry_ea=unresolved_transfer_ea,
                native_end_ea=0x500010,
                instructions=(
                    _Instruction(
                        ida_hexrays.m_ijmp,
                        unresolved_transfer_ea,
                    ),
                ),
                block_type=int(ida_hexrays.BLT_0WAY),
                block_flags=0,
                successor_serials=(),
                external_successor_eas=(),
            ),
        ),
        stack_vd_to_ida=(),
        owned_ranges=((0x500000, 0x500010),),
    )
    monkeypatch.setattr(
        dhi,
        "_PREOPT_UNION_SNIPPET_TEMPLATES",
        {(int(gateway.function_ea), 0x500000): template},
    )
    monkeypatch.setattr(
        _BlockReference,
        "equal_mops",
        lambda left, right, _flags: (
            int(left.t),
            int(left.size),
            int(left.r),
        )
        == (
            int(right.t),
            int(right.size),
            int(right.r),
        ),
        raising=False,
    )
    monkeypatch.setattr(
        dhi.ida_hexrays,
        "minsn_t",
        lambda value: (
            _Instruction(ida_hexrays.m_nop, value)
            if isinstance(value, int)
            else deepcopy(value)
        ),
    )
    monkeypatch.setattr(dhi.ida_hexrays, "mop_t", _BlockReference)
    monkeypatch.setattr(dm, "create_standalone_block", _create_fake_standalone_block)
    monkeypatch.setattr(dm, "insert_goto_instruction", _insert_fake_goto_instruction)
    modifier = dm.DeferredGraphModifier(
        mba,
        mutation_gateway=gateway,
        semantic_native_body_materializer=(
            dhi.PreoptUnionSemanticNativeBodyMaterializer(
                mba=mba,
                function_ea=int(gateway.function_ea),
            )
        ),
    )
    root_inventory = modifier._plan_semantic_fragment_root_publication_inventory(plan)
    gateway._begin_semantic_fragment_batch(modifier, plan, root_inventory)

    projection = modifier._stage_semantic_fragment(plan)

    imported = projection.block("imported-conditional")
    assert imported.instruction_eas == (
        condition_producer_ea,
        predicate_ea,
    )
    assert set(imported.successors) == {
        "target",
        "fallthrough-helper:imported-conditional-route",
    }

    modifier._discard_staged_semantic_fragment(plan)
    gateway.abort(reason="runtime split PREOPT select cleanup")


def test_cached_preopt_call_materializes_with_gateway_owned_fallthrough(
    monkeypatch,
) -> None:
    entry = _Block(0, start=0x401000, block_type=ida_hexrays.BLT_1WAY)
    original = _Block(1, start=0x401010, block_type=ida_hexrays.BLT_1WAY)
    target = _Block(2, start=0x401020, block_type=ida_hexrays.BLT_0WAY)
    dispatcher = _Block(3, start=0x401030, block_type=ida_hexrays.BLT_0WAY)
    stop = _Block(4, start=0x401040, block_type=ida_hexrays.BLT_STOP)
    _connect(entry, original)
    _connect(original, dispatcher)
    mba = _Mba((entry, original, target, dispatcher, stop))
    gateway = _fragment_gateway(mba)
    call_native_ea = 0x500004
    plan = _plan_with_imported_call(
        gateway,
        entry=0,
        original=1,
        target=2,
        dispatcher=3,
        call_native_ea=call_native_ea,
    )
    template = dhi.DetachedSnippetTemplate(
        function_ea=int(gateway.function_ea),
        target_ea=0x500000,
        maturity=int(ida_hexrays.MMAT_PREOPTIMIZED),
        root_source_serial=0,
        blocks=(
            dhi.DetachedSnippetBlockTemplate(
                source_serial=0,
                native_entry_ea=0x500000,
                native_end_ea=0x500010,
                instructions=(
                    _Instruction(ida_hexrays.m_call, call_native_ea),
                ),
                block_type=int(ida_hexrays.BLT_0WAY),
                block_flags=0,
                successor_serials=(),
                external_successor_eas=(),
            ),
        ),
        stack_vd_to_ida=(),
        owned_ranges=((0x500000, 0x500010),),
    )
    monkeypatch.setattr(
        dhi,
        "_PREOPT_UNION_SNIPPET_TEMPLATES",
        {(int(gateway.function_ea), 0x500000): template},
    )
    monkeypatch.setattr(dhi.ida_hexrays, "minsn_t", deepcopy)
    monkeypatch.setattr(dm, "create_standalone_block", _create_fake_standalone_block)
    monkeypatch.setattr(dm, "insert_goto_instruction", _insert_fake_goto_instruction)
    modifier = dm.DeferredGraphModifier(
        mba,
        mutation_gateway=gateway,
        semantic_native_body_materializer=(
            dhi.PreoptUnionSemanticNativeBodyMaterializer(
                mba=mba,
                function_ea=int(gateway.function_ea),
            )
        ),
    )
    root_inventory = modifier._plan_semantic_fragment_root_publication_inventory(plan)
    gateway._begin_semantic_fragment_batch(modifier, plan, root_inventory)

    projection = modifier._stage_semantic_fragment(plan)

    imported = projection.block("imported-call")
    helper = projection.block(
        "fallthrough-helper:imported-call-continuation"
    )
    assert imported.instruction_eas == (call_native_ea,)
    assert imported.successors == (helper.block_id,)
    assert helper.successors == ("target",)
    assert helper.physical_position == imported.physical_position + 1
    observation = sfb.observe_published_semantic_fragment(modifier, plan)
    assert tuple(
        operation.operation_id for operation in observation.observable_operations
    ) == (
        plan.operations[0].operation_id,
        "imported-call-continuation",
    )
    assert gateway.receipts == ()

    modifier._discard_staged_semantic_fragment(plan)
    gateway.abort(reason="runtime cached PREOPT call cleanup")


def test_native_body_rejects_an_unbound_materialized_instruction(
    monkeypatch,
) -> None:
    entry = _Block(0, start=0x401000, block_type=ida_hexrays.BLT_1WAY)
    original = _Block(1, start=0x401010, block_type=ida_hexrays.BLT_1WAY)
    target = _Block(2, start=0x401020, block_type=ida_hexrays.BLT_0WAY)
    dispatcher = _Block(3, start=0x401030, block_type=ida_hexrays.BLT_0WAY)
    stop = _Block(4, start=0x401040, block_type=ida_hexrays.BLT_STOP)
    _connect(entry, original)
    _connect(original, dispatcher)
    mba = _Mba((entry, original, target, dispatcher, stop))
    gateway = _fragment_gateway(mba)
    monkeypatch.setattr(dm, "create_standalone_block", _create_fake_standalone_block)
    modifier = dm.DeferredGraphModifier(
        mba,
        mutation_gateway=gateway,
        semantic_native_body_materializer=_UnboundNativeBodyMaterializer(),
    )
    plan = _plan_with_imported_terminal(
        gateway,
        entry=0,
        original=1,
        target=2,
        dispatcher=3,
    )
    root_inventory = modifier._plan_semantic_fragment_root_publication_inventory(plan)
    gateway._begin_semantic_fragment_batch(modifier, plan, root_inventory)

    with pytest.raises(
        sfb.SemanticFragmentBackendRejected,
        match="unbound live instruction",
    ):
        modifier._stage_semantic_fragment(plan)

    assert mba.qty == 5
    assert gateway.active
    assert gateway.receipts == ()
    gateway.abort(reason="runtime unbound imported instruction cleanup")


def test_gateway_publishes_native_body_in_one_balanced_receipt(monkeypatch) -> None:
    entry = _Block(0, start=0x401000, block_type=ida_hexrays.BLT_1WAY)
    original = _Block(1, start=0x401010, block_type=ida_hexrays.BLT_1WAY)
    target = _Block(2, start=0x401020, block_type=ida_hexrays.BLT_0WAY)
    dispatcher = _Block(3, start=0x401030, block_type=ida_hexrays.BLT_0WAY)
    stop = _Block(4, start=0x401040, block_type=ida_hexrays.BLT_STOP)
    _connect(entry, original)
    _connect(original, dispatcher)
    mba = _Mba((entry, original, target, dispatcher, stop))
    gateway = _fragment_gateway(mba)
    materializer = _RecordingNativeBodyMaterializer()
    monkeypatch.setattr(dm, "create_standalone_block", _create_fake_standalone_block)
    modifier = dm.DeferredGraphModifier(
        mba,
        mutation_gateway=gateway,
        semantic_native_body_materializer=materializer,
    )
    plan = _plan_with_imported_terminal(
        gateway,
        entry=0,
        original=1,
        target=2,
        dispatcher=3,
    )
    imported_identity = plan.block("imported-terminal").stable_identity
    assert imported_identity is not None
    original_ranges = _outline_ranges(mba)

    receipt = gateway.publish_semantic_fragment(modifier, plan)

    assert receipt.operation_count == receipt.planned_operation_count == 4
    assert receipt.root_publication_confirmed
    assert receipt.prepublication_validation.passed
    assert receipt.postpublication_validation.passed
    assert materializer.calls == [
        (plan.plan_id, "native-body", receipt.mutation_batch_id),
    ]
    rebound = gateway.identity_index.rebind_identity(imported_identity)
    assert rebound.block is not None
    imported_proxy = gateway.identity_index.logical_proxy_for_handle(
        rebound.block.handle
    )
    assert imported_proxy is not None
    assert imported_proxy.resolve() is not None
    assert gateway.active is False
    assert modifier._semantic_fragment_state is None
    assert gateway.receipts == (receipt,)
    assert _outline_ranges(mba) == (
        *original_ranges,
        (0x500000, 0x500010),
    )
    assert int(mba.get_mba_flags2()) & int(
        ida_hexrays.MBA2_HAS_OUTLINES
    )


@pytest.mark.parametrize(
    ("storage_kind", "storage_offset"),
    (
        (StorageIdentityKind.REGISTER, 10),
        (StorageIdentityKind.STACK, 0x20),
    ),
)
@pytest.mark.parametrize("extra_use", (False, True))
def test_backend_projects_exact_data_flow_without_hiding_extra_uses(
    monkeypatch,
    storage_kind: StorageIdentityKind,
    storage_offset: int,
    extra_use: bool,
) -> None:
    entry = _Block(0, start=0x401000, block_type=ida_hexrays.BLT_1WAY)
    original = _Block(1, start=0x401010, block_type=ida_hexrays.BLT_1WAY)
    target = _Block(2, start=0x401020, block_type=ida_hexrays.BLT_0WAY)
    dispatcher = _Block(3, start=0x401030, block_type=ida_hexrays.BLT_0WAY)
    stop = _Block(4, start=0x401040, block_type=ida_hexrays.BLT_STOP)
    _connect(entry, original)
    _connect(original, dispatcher)
    mba = _Mba((entry, original, target, dispatcher, stop))
    gateway = _fragment_gateway(mba)
    modifier = dm.DeferredGraphModifier(mba, mutation_gateway=gateway)
    plan = _with_data_flow(
        _plan(gateway, entry=0, original=1, target=2, dispatcher=3),
        StorageIdentity(storage_kind, offset=storage_offset),
    )

    def _reaching_definitions(
        _mba,
        block_serial: int,
        use_ea: int,
        identifier: int,
        size: int,
    ) -> list[DefSite]:
        assert use_ea == 0x401010
        assert identifier == storage_offset
        assert size == 4
        return [DefSite(block_serial, 0x401010, ida_hexrays.m_mov)]

    def _reached_uses(
        _mba,
        block_serial: int,
        definition_ea: int,
        identifier: int,
        size: int,
    ) -> list[UseSite]:
        assert definition_ea == 0x401010
        assert identifier == storage_offset
        assert size == 4
        result = [UseSite(block_serial, 0x401010, ida_hexrays.m_mov)]
        if extra_use:
            result.append(UseSite(entry.serial, 0x401000, ida_hexrays.m_mov))
        return result

    reaching_query_name = (
        "find_reaching_defs_for_reg_use"
        if storage_kind is StorageIdentityKind.REGISTER
        else "find_reaching_defs_for_stkvar_use"
    )
    reached_uses_query_name = (
        "find_uses_reached_by_reg_definition"
        if storage_kind is StorageIdentityKind.REGISTER
        else "find_uses_reached_by_stkvar_definition"
    )
    monkeypatch.setattr(sfb, reaching_query_name, _reaching_definitions)
    monkeypatch.setattr(sfb, reached_uses_query_name, _reached_uses)
    root_inventory = modifier._plan_semantic_fragment_root_publication_inventory(plan)
    gateway._begin_semantic_fragment_batch(modifier, plan, root_inventory)

    projection = modifier._stage_semantic_fragment(plan)

    planned_relation = ProjectedDataFlowRelation(
        value_id="state",
        definition_site_id="state.def",
        use_site_id="state.use",
        use_def_observed=True,
        def_use_observed=False,
    )
    reverse_relation = ProjectedDataFlowRelation(
        value_id="state",
        definition_site_id="state.def",
        use_site_id="state.use",
        use_def_observed=False,
        def_use_observed=True,
    )
    assert planned_relation in projection.data_flow_relations
    assert reverse_relation in projection.data_flow_relations
    validation = validate_fragment_projection(plan, projection)
    if extra_use:
        assert len(projection.data_flow_relations) == 3
        assert any(
            relation.use_site_id.startswith("unplanned-use:")
            for relation in projection.data_flow_relations
        )
        assert any(
            not outcome.passed
            and outcome.postcondition
            is FragmentValidationPostcondition.DEF_USE_INTEGRITY
            for outcome in validation.outcomes
        )
    else:
        assert set(projection.data_flow_relations) == {
            planned_relation,
            reverse_relation,
        }
        assert validation.passed, validation.failures

    modifier._discard_staged_semantic_fragment(plan)
    gateway.abort(reason="runtime data-flow projection cleanup")


def test_backend_rejects_duplicate_physical_data_flow_anchors(
    monkeypatch,
) -> None:
    entry = _Block(0, start=0x401000, block_type=ida_hexrays.BLT_1WAY)
    original = _Block(1, start=0x401010, block_type=ida_hexrays.BLT_1WAY)
    target = _Block(2, start=0x401020, block_type=ida_hexrays.BLT_0WAY)
    dispatcher = _Block(3, start=0x401030, block_type=ida_hexrays.BLT_0WAY)
    stop = _Block(4, start=0x401040, block_type=ida_hexrays.BLT_STOP)
    _connect(entry, original)
    _connect(original, dispatcher)
    mba = _Mba((entry, original, target, dispatcher, stop))
    gateway = _fragment_gateway(mba)
    modifier = dm.DeferredGraphModifier(mba, mutation_gateway=gateway)
    plan = _with_data_flow(
        _plan(gateway, entry=0, original=1, target=2, dispatcher=3),
        StorageIdentity(StorageIdentityKind.REGISTER, offset=10),
    )

    monkeypatch.setattr(
        sfb,
        "find_reaching_defs_for_reg_use",
        lambda _mba, block_serial, *_args: [
            DefSite(block_serial, 0x401010, ida_hexrays.m_mov)
        ],
    )
    monkeypatch.setattr(
        sfb,
        "find_uses_reached_by_reg_definition",
        lambda _mba, block_serial, *_args: [
            UseSite(block_serial, 0x401010, ida_hexrays.m_mov),
            UseSite(block_serial, 0x401010, ida_hexrays.m_mov),
        ],
    )
    root_inventory = modifier._plan_semantic_fragment_root_publication_inventory(plan)
    gateway._begin_semantic_fragment_batch(modifier, plan, root_inventory)

    with pytest.raises(
        sfb.SemanticFragmentBackendRejected,
        match="use observation is ambiguous.*replacement@0x401010",
    ):
        modifier._stage_semantic_fragment(plan)

    assert modifier._semantic_fragment_state is None
    assert mba.qty == 5
    assert tuple(entry.succset) == (original.serial,)
    gateway.abort(reason="runtime ambiguous data-flow cleanup")


def test_backend_rejects_unsupported_data_flow_storage_namespace() -> None:
    entry = _Block(0, start=0x401000, block_type=ida_hexrays.BLT_1WAY)
    original = _Block(1, start=0x401010, block_type=ida_hexrays.BLT_1WAY)
    target = _Block(2, start=0x401020, block_type=ida_hexrays.BLT_0WAY)
    dispatcher = _Block(3, start=0x401030, block_type=ida_hexrays.BLT_0WAY)
    stop = _Block(4, start=0x401040, block_type=ida_hexrays.BLT_STOP)
    _connect(entry, original)
    _connect(original, dispatcher)
    mba = _Mba((entry, original, target, dispatcher, stop))
    gateway = _fragment_gateway(mba)
    modifier = dm.DeferredGraphModifier(mba, mutation_gateway=gateway)
    plan = _with_data_flow(
        _plan(gateway, entry=0, original=1, target=2, dispatcher=3),
        StorageIdentity(StorageIdentityKind.GLOBAL, offset=0x404000),
    )
    root_inventory = modifier._plan_semantic_fragment_root_publication_inventory(plan)
    gateway._begin_semantic_fragment_batch(modifier, plan, root_inventory)

    with pytest.raises(
        sfb.SemanticFragmentBackendRejected,
        match="unsupported storage namespace global",
    ):
        modifier._stage_semantic_fragment(plan)

    assert modifier._semantic_fragment_state is None
    assert mba.qty == 5
    assert tuple(entry.succset) == (original.serial,)
    gateway.abort(reason="runtime unsupported data-flow cleanup")


def _flag_corridor_runtime_case(*, intervening_clobber: bool):
    entry = _Block(0, start=0x401000, block_type=ida_hexrays.BLT_1WAY)
    original = _Block(1, start=0x401010, block_type=ida_hexrays.BLT_1WAY)
    target = _Block(2, start=0x401020, block_type=ida_hexrays.BLT_0WAY)
    dispatcher = _Block(3, start=0x401030, block_type=ida_hexrays.BLT_0WAY)
    stop = _Block(4, start=0x401040, block_type=ida_hexrays.BLT_STOP)
    _connect(entry, original)
    _connect(original, dispatcher)
    assert original.tail is not None
    original.tail.d.writes_ccflags = True
    consumer_ea = 0x401024 if intervening_clobber else 0x401020
    consumer = _Instruction(ida_hexrays.m_nop, consumer_ea)
    if intervening_clobber:
        clobber = _Instruction(ida_hexrays.m_mov, 0x401020)
        clobber.d.writes_cc = True
        _set_block_instructions(target, clobber, consumer)
    else:
        _set_block_instructions(target, consumer)
    mba = _Mba((entry, original, target, dispatcher, stop))
    gateway = _fragment_gateway(mba)
    modifier = dm.DeferredGraphModifier(mba, mutation_gateway=gateway)
    plan = _with_flag_corridor(
        _plan(gateway, entry=0, original=1, target=2, dispatcher=3),
        consumer_ea=consumer_ea,
    )
    return mba, gateway, modifier, plan, entry, original


def test_backend_projects_exact_condition_code_writes() -> None:
    mba, gateway, modifier, plan, entry, original = _flag_corridor_runtime_case(
        intervening_clobber=False,
    )
    root_inventory = modifier._plan_semantic_fragment_root_publication_inventory(plan)
    gateway._begin_semantic_fragment_batch(modifier, plan, root_inventory)

    projection = modifier._stage_semantic_fragment(plan)

    replacement = projection.block("replacement")
    assert replacement.flag_write_eas == frozenset({0x401010})
    assert validate_fragment_projection(plan, projection).passed
    modifier._discard_staged_semantic_fragment(plan)
    gateway.abort(reason="runtime flag projection cleanup")
    assert mba.qty == 5
    assert tuple(entry.succset) == (original.serial,)


@pytest.mark.parametrize("intervening_clobber", (False, True))
def test_gateway_validates_live_flag_corridor_atomically(
    intervening_clobber: bool,
) -> None:
    mba, gateway, modifier, plan, entry, original = _flag_corridor_runtime_case(
        intervening_clobber=intervening_clobber,
    )
    original_handle = gateway.identity_index.handle_for_serial(original.serial)
    assert original_handle is not None
    proxy = gateway.identity_index.logical_proxy_for_handle(original_handle)
    assert proxy is not None
    published = proxy.resolve()
    assert published is not None

    if intervening_clobber:
        with pytest.raises(
            SemanticFragmentPublicationRejected,
            match="prepublication.*flag_corridor_integrity:branch-flags",
        ):
            gateway.publish_semantic_fragment(modifier, plan)
        assert proxy.resolve() is published
        assert tuple(entry.succset) == (original.serial,)
        assert tuple(original.predset) == (entry.serial,)
        assert mba.qty == 5
        assert gateway.active is False
        assert modifier._semantic_fragment_state is None
        return

    receipt = gateway.publish_semantic_fragment(modifier, plan)

    assert receipt.prepublication_validation.passed
    assert receipt.postpublication_validation.passed
    assert any(
        outcome.passed
        and outcome.postcondition
        is FragmentValidationPostcondition.FLAG_CORRIDOR_INTEGRITY
        for outcome in receipt.prepublication_validation.outcomes
    )
    assert any(
        outcome.passed
        and outcome.postcondition
        is FragmentValidationPostcondition.FLAG_CORRIDOR_INTEGRITY
        for outcome in receipt.postpublication_validation.outcomes
    )
    assert gateway.active is False
    assert modifier._semantic_fragment_state is None


def test_backend_rejects_ambiguous_flag_corridor_endpoint() -> None:
    mba, gateway, modifier, plan, entry, original = _flag_corridor_runtime_case(
        intervening_clobber=False,
    )
    target = mba.get_mblock(2)
    assert target is not None and target.head is not None
    duplicate_consumer = _Instruction(ida_hexrays.m_nop, 0x401020)
    _set_block_instructions(target, target.head, duplicate_consumer)
    root_inventory = modifier._plan_semantic_fragment_root_publication_inventory(plan)
    gateway._begin_semantic_fragment_batch(modifier, plan, root_inventory)

    with pytest.raises(
        sfb.SemanticFragmentBackendRejected,
        match="consumer.*target@0x401020.*observed 2",
    ):
        modifier._stage_semantic_fragment(plan)

    assert modifier._semantic_fragment_state is None
    assert mba.qty == 5
    assert tuple(entry.succset) == (original.serial,)
    gateway.abort(reason="runtime ambiguous flag endpoint cleanup")


def test_backend_groups_native_flag_producer_microinstructions() -> None:
    mba, gateway, modifier, plan, entry, original = _flag_corridor_runtime_case(
        intervening_clobber=False,
    )
    producer_microinstructions = tuple(
        _Instruction(ida_hexrays.m_mov, 0x401010) for _index in range(5)
    )
    for instruction in producer_microinstructions:
        instruction.d.writes_ccflags = True
    assert original.tail is not None
    original.tail.ea = 0x401014
    original.tail.d.writes_ccflags = False
    _set_block_instructions(
        original,
        *producer_microinstructions,
        original.tail,
    )
    root_inventory = modifier._plan_semantic_fragment_root_publication_inventory(plan)
    gateway._begin_semantic_fragment_batch(modifier, plan, root_inventory)

    projection = modifier._stage_semantic_fragment(plan)

    replacement = projection.block("replacement")
    assert replacement.flag_write_eas == frozenset({0x401010})
    assert validate_fragment_projection(plan, projection).passed
    modifier._discard_staged_semantic_fragment(plan)
    assert mba.qty == 5
    assert tuple(entry.succset) == (original.serial,)
    gateway.abort(reason="runtime grouped flag producer cleanup")


def test_gateway_rolls_back_postpublication_flag_clobber(monkeypatch) -> None:
    mba, gateway, modifier, plan, entry, original = _flag_corridor_runtime_case(
        intervening_clobber=True,
    )
    target = mba.get_mblock(2)
    assert target is not None and target.head is not None
    target.head.d.writes_cc = False
    original_handle = gateway.identity_index.handle_for_serial(original.serial)
    assert original_handle is not None
    proxy = gateway.identity_index.logical_proxy_for_handle(original_handle)
    assert proxy is not None
    published = proxy.resolve()
    assert published is not None
    target_query_count = 0
    query_writes = sfb.condition_code_write_eas

    def _changing_flag_writes(block) -> tuple[int, ...]:
        nonlocal target_query_count
        if block is target:
            target_query_count += 1
            if target_query_count == 2:
                return (0x401020,)
        return query_writes(block)

    monkeypatch.setattr(sfb, "condition_code_write_eas", _changing_flag_writes)

    with pytest.raises(
        SemanticFragmentPublicationRejected,
        match="postpublication.*flag_corridor_integrity:branch-flags",
    ):
        gateway.publish_semantic_fragment(modifier, plan)

    assert target_query_count == 2
    assert proxy.resolve() is published
    assert tuple(entry.succset) == (original.serial,)
    assert tuple(original.predset) == (entry.serial,)
    assert mba.qty == 5
    assert gateway.active is False
    assert modifier._semantic_fragment_state is None


def _range_runtime_case(
    *bounds: tuple[int | None, int | None],
    observation: FragmentRangeObservation = FragmentRangeObservation.AFTER_INSTRUCTION,
):
    entry = _Block(0, start=0x401000, block_type=ida_hexrays.BLT_1WAY)
    original = _Block(1, start=0x401010, block_type=ida_hexrays.BLT_1WAY)
    target = _Block(2, start=0x401020, block_type=ida_hexrays.BLT_0WAY)
    dispatcher = _Block(3, start=0x401030, block_type=ida_hexrays.BLT_0WAY)
    stop = _Block(4, start=0x401040, block_type=ida_hexrays.BLT_STOP)
    _connect(entry, original)
    _connect(original, dispatcher)
    _set_block_instructions(target, _Instruction(ida_hexrays.m_nop, 0x401020))
    target.valrange_bounds.extend(bounds)
    mba = _Mba((entry, original, target, dispatcher, stop))
    gateway = _fragment_gateway(mba)
    modifier = dm.DeferredGraphModifier(mba, mutation_gateway=gateway)
    plan = _with_value_range(
        _plan(gateway, entry=0, original=1, target=2, dispatcher=3),
        observation=observation,
    )
    return mba, gateway, modifier, plan, entry, original, target


def _install_range_data_flow_queries(monkeypatch, target: _Block) -> None:
    current_definition_serial = -1

    def _reached_uses(
        _mba,
        block_serial: int,
        *_args,
    ) -> list[UseSite]:
        nonlocal current_definition_serial
        current_definition_serial = int(block_serial)
        return [UseSite(target.serial, 0x401020, ida_hexrays.m_nop)]

    def _reaching_definitions(
        _mba,
        _block_serial: int,
        *_args,
    ) -> list[DefSite]:
        assert current_definition_serial >= 0
        return [
            DefSite(current_definition_serial, 0x401010, ida_hexrays.m_goto),
        ]

    monkeypatch.setattr(
        sfb,
        "find_uses_reached_by_reg_definition",
        _reached_uses,
    )
    monkeypatch.setattr(
        sfb,
        "find_reaching_defs_for_reg_use",
        _reaching_definitions,
    )


def _install_range_value_query(monkeypatch) -> None:
    def _prove(
        block: _Block,
        instruction: _Instruction,
        _storage: StorageIdentity,
        _width: int,
        *,
        at_end: bool,
        required_lo: int | None,
        required_hi: int | None,
    ) -> ExactValueRangeProof | None:
        block.valrange_queries.append(
            (
                int(instruction.ea),
                int(ida_hexrays.VR_EXACT)
                | int(ida_hexrays.VR_AT_END if at_end else ida_hexrays.VR_AT_START),
            )
        )
        if not block.valrange_bounds:
            return None
        lo, hi = block.valrange_bounds.pop(0)
        if required_lo is not None and (lo is None or lo < required_lo):
            return None
        if required_hi is not None and (hi is None or hi > required_hi):
            return None
        return ExactValueRangeProof(lo=lo, hi=hi)

    monkeypatch.setattr(sfb, "prove_exact_unsigned_range", _prove)


@pytest.mark.parametrize(
    ("observation", "expected_position"),
    (
        (FragmentRangeObservation.BEFORE_INSTRUCTION, ida_hexrays.VR_AT_START),
        (FragmentRangeObservation.AFTER_INSTRUCTION, ida_hexrays.VR_AT_END),
    ),
)
def test_backend_projects_exact_live_value_range(
    monkeypatch,
    observation: FragmentRangeObservation,
    expected_position: int,
) -> None:
    mba, gateway, modifier, plan, entry, original, target = _range_runtime_case(
        (1, 1),
        observation=observation,
    )
    _install_range_data_flow_queries(monkeypatch, target)
    _install_range_value_query(monkeypatch)
    root_inventory = modifier._plan_semantic_fragment_root_publication_inventory(plan)
    gateway._begin_semantic_fragment_batch(modifier, plan, root_inventory)

    projection = modifier._stage_semantic_fragment(plan)

    assert projection.value_ranges == (
        ProjectedRangeFact(
            site_id="selector.range",
            value_id="selector",
            observation=observation,
            lo=1,
            hi=1,
        ),
    )
    assert target.valrange_queries == [
        (0x401020, int(ida_hexrays.VR_EXACT) | int(expected_position)),
    ]
    assert validate_fragment_projection(plan, projection).passed
    modifier._discard_staged_semantic_fragment(plan)
    gateway.abort(reason="runtime value-range projection cleanup")
    assert mba.qty == 5
    assert tuple(entry.succset) == (original.serial,)


@pytest.mark.parametrize("live_bounds", ((0, 1), (0, 2)))
def test_gateway_validates_live_value_range_atomically(
    monkeypatch,
    live_bounds: tuple[int, int],
) -> None:
    mba, gateway, modifier, plan, entry, original, target = _range_runtime_case(
        live_bounds,
        live_bounds,
    )
    _install_range_data_flow_queries(monkeypatch, target)
    _install_range_value_query(monkeypatch)
    original_handle = gateway.identity_index.handle_for_serial(original.serial)
    assert original_handle is not None
    proxy = gateway.identity_index.logical_proxy_for_handle(original_handle)
    assert proxy is not None
    published = proxy.resolve()
    assert published is not None

    if live_bounds == (0, 2):
        with pytest.raises(
            SemanticFragmentPublicationRejected,
            match="prepublication.*value_range_proven:selector-domain",
        ):
            gateway.publish_semantic_fragment(modifier, plan)
        assert proxy.resolve() is published
        assert tuple(entry.succset) == (original.serial,)
        assert tuple(original.predset) == (entry.serial,)
        assert mba.qty == 5
        assert gateway.active is False
        assert modifier._semantic_fragment_state is None
        return

    receipt = gateway.publish_semantic_fragment(modifier, plan)

    assert receipt.prepublication_validation.passed
    assert receipt.postpublication_validation.passed
    assert any(
        outcome.passed
        and outcome.postcondition is FragmentValidationPostcondition.VALUE_RANGE_PROVEN
        for outcome in receipt.prepublication_validation.outcomes
    )
    assert any(
        outcome.passed
        and outcome.postcondition is FragmentValidationPostcondition.VALUE_RANGE_PROVEN
        for outcome in receipt.postpublication_validation.outcomes
    )
    assert gateway.active is False
    assert modifier._semantic_fragment_state is None


def test_gateway_rolls_back_postpublication_value_range_drift(
    monkeypatch,
) -> None:
    mba, gateway, modifier, plan, entry, original, target = _range_runtime_case(
        (0, 1),
        (0, 2),
    )
    _install_range_data_flow_queries(monkeypatch, target)
    _install_range_value_query(monkeypatch)
    original_handle = gateway.identity_index.handle_for_serial(original.serial)
    assert original_handle is not None
    proxy = gateway.identity_index.logical_proxy_for_handle(original_handle)
    assert proxy is not None
    published = proxy.resolve()
    assert published is not None

    with pytest.raises(
        SemanticFragmentPublicationRejected,
        match="postpublication.*value_range_proven:selector-domain",
    ):
        gateway.publish_semantic_fragment(modifier, plan)

    assert proxy.resolve() is published
    assert tuple(entry.succset) == (original.serial,)
    assert tuple(original.predset) == (entry.serial,)
    assert mba.qty == 5
    assert gateway.active is False
    assert modifier._semantic_fragment_state is None


class TestExactValueRangeSdk:
    binary_name = _get_default_binary()

    @pytest.mark.parametrize(
        ("storage", "at_end", "expected_position"),
        (
            (
                StorageIdentity(StorageIdentityKind.REGISTER, offset=10),
                False,
                ida_hexrays.VR_AT_START,
            ),
            (
                StorageIdentity(StorageIdentityKind.STACK, offset=0x20),
                True,
                ida_hexrays.VR_AT_END,
            ),
        ),
    )
    def test_proves_exact_unsigned_singleton_at_declared_side(
        self,
        libobfuscated_setup,
        storage: StorageIdentity,
        at_end: bool,
        expected_position: int,
    ) -> None:
        block = _Block(0, start=0x401020, block_type=ida_hexrays.BLT_0WAY)
        instruction = _Instruction(ida_hexrays.m_nop, 0x401020)
        _set_block_instructions(block, instruction)
        block.valrange_bounds.append((1, 1))

        proof = prove_exact_unsigned_range(
            block,
            instruction,
            storage,
            1,
            at_end=at_end,
            required_lo=0,
            required_hi=1,
        )

        assert proof == ExactValueRangeProof(lo=1, hi=1)
        assert block.valrange_queries == [
            (0x401020, int(ida_hexrays.VR_EXACT) | int(expected_position)),
        ]

    @pytest.mark.parametrize(
        ("live_bounds", "expected"),
        (
            ((0, 1), ExactValueRangeProof(lo=0, hi=1)),
            ((0, 2), None),
        ),
    )
    def test_proves_only_ranges_within_required_envelope(
        self,
        libobfuscated_setup,
        live_bounds: tuple[int, int],
        expected: ExactValueRangeProof | None,
    ) -> None:
        block = _Block(0, start=0x401020, block_type=ida_hexrays.BLT_0WAY)
        instruction = _Instruction(ida_hexrays.m_nop, 0x401020)
        _set_block_instructions(block, instruction)
        block.valrange_bounds.append(live_bounds)

        proof = prove_exact_unsigned_range(
            block,
            instruction,
            StorageIdentity(StorageIdentityKind.REGISTER, offset=10),
            1,
            at_end=False,
            required_lo=0,
            required_hi=1,
        )

        assert proof == expected


@pytest.mark.parametrize("postpublication_extra_use", (False, True))
def test_gateway_revalidates_data_flow_after_root_publication(
    monkeypatch,
    postpublication_extra_use: bool,
) -> None:
    entry = _Block(0, start=0x401000, block_type=ida_hexrays.BLT_1WAY)
    original = _Block(1, start=0x401010, block_type=ida_hexrays.BLT_1WAY)
    target = _Block(2, start=0x401020, block_type=ida_hexrays.BLT_0WAY)
    dispatcher = _Block(3, start=0x401030, block_type=ida_hexrays.BLT_0WAY)
    stop = _Block(4, start=0x401040, block_type=ida_hexrays.BLT_STOP)
    _connect(entry, original)
    _connect(original, dispatcher)
    mba = _Mba((entry, original, target, dispatcher, stop))
    gateway = _fragment_gateway(mba)
    modifier = dm.DeferredGraphModifier(mba, mutation_gateway=gateway)
    plan = _with_data_flow(
        _plan(gateway, entry=0, original=1, target=2, dispatcher=3),
        StorageIdentity(StorageIdentityKind.REGISTER, offset=10),
    )
    original_handle = gateway.identity_index.handle_for_serial(original.serial)
    assert original_handle is not None
    proxy = gateway.identity_index.logical_proxy_for_handle(original_handle)
    assert proxy is not None
    published = proxy.resolve()
    assert published is not None
    reached_use_calls = 0

    monkeypatch.setattr(
        sfb,
        "find_reaching_defs_for_reg_use",
        lambda _mba, block_serial, *_args: [
            DefSite(block_serial, 0x401010, ida_hexrays.m_mov)
        ],
    )

    def _reached_uses(_mba, block_serial: int, *_args) -> list[UseSite]:
        nonlocal reached_use_calls
        reached_use_calls += 1
        result = [UseSite(block_serial, 0x401010, ida_hexrays.m_mov)]
        if postpublication_extra_use and reached_use_calls == 2:
            result.append(UseSite(entry.serial, 0x401000, ida_hexrays.m_mov))
        return result

    monkeypatch.setattr(
        sfb,
        "find_uses_reached_by_reg_definition",
        _reached_uses,
    )

    if postpublication_extra_use:
        with pytest.raises(
            SemanticFragmentPublicationRejected,
            match="postpublication",
        ):
            gateway.publish_semantic_fragment(modifier, plan)
        assert reached_use_calls == 2
        assert proxy.resolve() is published
        assert tuple(entry.succset) == (original.serial,)
        assert tuple(original.predset) == (entry.serial,)
        assert mba.qty == 5
        assert gateway.active is False
        assert modifier._semantic_fragment_state is None
        return

    receipt = gateway.publish_semantic_fragment(modifier, plan)

    assert reached_use_calls == 2
    assert receipt.prepublication_validation.passed
    assert receipt.postpublication_validation.passed
    assert any(
        outcome.passed
        and outcome.postcondition is FragmentValidationPostcondition.USE_DEF_INTEGRITY
        for outcome in receipt.postpublication_validation.outcomes
    )
    assert any(
        outcome.passed
        and outcome.postcondition is FragmentValidationPostcondition.DEF_USE_INTEGRITY
        for outcome in receipt.postpublication_validation.outcomes
    )
    assert gateway.active is False
    assert modifier._semantic_fragment_state is None


def test_gateway_publishes_direct_fragment_root_from_entry() -> None:
    entry = _Block(0, start=0x401000, block_type=ida_hexrays.BLT_1WAY)
    original = _Block(1, start=0x401010, block_type=ida_hexrays.BLT_1WAY)
    target = _Block(2, start=0x401020, block_type=ida_hexrays.BLT_0WAY)
    dispatcher = _Block(3, start=0x401030, block_type=ida_hexrays.BLT_0WAY)
    stop = _Block(4, start=0x401040, block_type=ida_hexrays.BLT_STOP)
    _connect(entry, original)
    _connect(original, dispatcher)
    mba = _Mba((entry, original, target, dispatcher, stop))
    gateway = _fragment_gateway(mba)
    modifier = dm.DeferredGraphModifier(mba, mutation_gateway=gateway)
    plan = _plan(gateway, entry=0, original=1, target=2, dispatcher=3)
    original_handle = gateway.identity_index.handle_for_serial(1)
    assert original_handle is not None
    proxy = gateway.identity_index.logical_proxy_for_handle(original_handle)
    assert proxy is not None
    published = proxy.resolve()
    assert published is not None

    receipt = gateway.publish_semantic_fragment(modifier, plan)

    promoted = proxy.resolve()
    assert promoted is not None and promoted is not published
    promoted_binding = gateway.identity_index.resolve_logical_version(promoted)
    assert promoted_binding is not None
    replacement = mba.get_mblock(promoted_binding.serial)
    assert replacement is not None
    assert tuple(entry.succset) == (replacement.serial,)
    assert tuple(original.predset) == ()
    assert tuple(replacement.predset) == (entry.serial,)
    assert tuple(replacement.succset) == (target.serial,)
    assert receipt.root_publication_confirmed
    assert receipt.prepublication_validation.passed
    assert receipt.postpublication_validation.passed
    assert receipt.operation_count == 3
    assert receipt.planned_operation_count == 3
    lifecycle = gateway.lifecycle_authority
    assert lifecycle is not None
    state = lifecycle.state
    assert state.semantic_fragment_staged_generation == 1
    assert state.semantic_fragment_validated_generation == 1
    assert state.semantic_fragment_published_postvalidated_generation == 1
    assert state.receipt_committed_generation == 1
    assert gateway.active is False
    assert modifier._semantic_fragment_state is None


def test_gateway_publishes_implicit_entry_root_through_adjacent_helper(
    monkeypatch,
) -> None:
    entry = _Block(0, start=0x401000, block_type=ida_hexrays.BLT_1WAY)
    entry.end = entry.start
    original = _Block(1, start=0x401010, block_type=ida_hexrays.BLT_1WAY)
    target = _Block(2, start=0x401020, block_type=ida_hexrays.BLT_0WAY)
    dispatcher = _Block(3, start=0x401030, block_type=ida_hexrays.BLT_0WAY)
    stop = _Block(4, start=0x401040, block_type=ida_hexrays.BLT_STOP)
    entry.succset.push_back(original.serial)
    original.predset.push_back(entry.serial)
    _connect(original, dispatcher)
    mba = _Mba((entry, original, target, dispatcher, stop))
    gateway = _fragment_gateway(mba)
    modifier = dm.DeferredGraphModifier(mba, mutation_gateway=gateway)
    monkeypatch.setattr(
        dm,
        "insert_goto_instruction",
        _insert_fake_goto_instruction,
    )
    plan = _plan(gateway, entry=0, original=1, target=2, dispatcher=3)
    original_handle = gateway.identity_index.handle_for_serial(1)
    assert original_handle is not None
    proxy = gateway.identity_index.logical_proxy_for_handle(original_handle)
    assert proxy is not None

    receipt = gateway.publish_semantic_fragment(modifier, plan)

    promoted = proxy.resolve()
    assert promoted is not None
    promoted_binding = gateway.identity_index.resolve_logical_version(promoted)
    assert promoted_binding is not None
    replacement = mba.get_mblock(promoted_binding.serial)
    helper = entry.nextb
    assert replacement is not None
    assert helper is not None
    assert int(helper.serial) == int(entry.serial) + 1
    assert tuple(entry.succset) == (helper.serial,)
    assert tuple(helper.predset) == (entry.serial,)
    assert tuple(helper.succset) == (replacement.serial,)
    assert helper.tail is not None
    assert int(helper.tail.opcode) == int(ida_hexrays.m_goto)
    assert int(helper.tail.l.b) == int(replacement.serial)
    assert int(helper.start) == int(mba.entry_ea)
    assert int(helper.end) == int(mba.entry_ea) + 1
    assert int(helper.flags) & int(ida_hexrays.MBL_KEEP)
    assert int(helper.flags) & int(ida_hexrays.MBL_FAKE)
    assert tuple(original.predset) == ()
    assert tuple(replacement.predset) == (helper.serial,)
    assert receipt.root_publication_confirmed
    assert receipt.prepublication_validation.passed
    assert receipt.postpublication_validation.passed
    assert receipt.operation_count == 4
    assert receipt.planned_operation_count == 4
    assert gateway.active is False
    assert modifier._semantic_fragment_state is None


def test_gateway_collapses_detached_conditional_to_proven_direct_route(
    monkeypatch,
) -> None:
    entry = _Block(0, start=0x401000, block_type=ida_hexrays.BLT_1WAY)
    original = _Block(1, start=0x401010, block_type=ida_hexrays.BLT_2WAY)
    old_fallthrough = _Block(
        2,
        start=0x401020,
        block_type=ida_hexrays.BLT_0WAY,
    )
    old_taken = _Block(3, start=0x401030, block_type=ida_hexrays.BLT_0WAY)
    target = _Block(4, start=0x401040, block_type=ida_hexrays.BLT_0WAY)
    stop = _Block(5, start=0x401050, block_type=ida_hexrays.BLT_STOP)
    _connect(entry, original)
    _connect_conditional(
        original,
        taken=old_taken,
        fallthrough=old_fallthrough,
    )
    mba = _Mba((entry, original, old_taken, old_fallthrough, target, stop))
    gateway = _fragment_gateway(mba)
    modifier = dm.DeferredGraphModifier(mba, mutation_gateway=gateway)
    monkeypatch.setattr(
        dm,
        "insert_goto_instruction",
        _insert_fake_goto_instruction,
    )
    plan = _plan(
        gateway,
        entry=entry.serial,
        original=original.serial,
        target=target.serial,
        dispatcher=old_taken.serial,
    )
    fallthrough_handle = gateway.identity_index.handle_for_serial(
        old_fallthrough.serial
    )
    assert fallthrough_handle is not None
    assert fallthrough_handle.stable_identity is not None
    fallthrough_binding = gateway.identity_index.resolve(fallthrough_handle)
    assert fallthrough_binding is not None
    assert fallthrough_binding.anchor_ea is not None
    plan = replace(
        plan,
        blocks=plan.blocks
        + (
            FragmentBlock(
                block_id="old-fallthrough",
                role=FragmentBlockRole.EXTERNAL,
                materialization=FragmentBlockMaterialization.REUSE_PUBLISHED,
                semantic_anchor_ea=int(fallthrough_binding.anchor_ea),
                stable_identity=fallthrough_handle.stable_identity,
            ),
        ),
    )
    original_handle = gateway.identity_index.handle_for_serial(original.serial)
    assert original_handle is not None
    proxy = gateway.identity_index.logical_proxy_for_handle(original_handle)
    assert proxy is not None

    receipt = gateway.publish_semantic_fragment(modifier, plan)

    promoted = proxy.resolve()
    assert promoted is not None
    promoted_binding = gateway.identity_index.resolve_logical_version(promoted)
    assert promoted_binding is not None
    replacement = mba.get_mblock(promoted_binding.serial)
    assert replacement is not None
    assert int(replacement.type) == int(ida_hexrays.BLT_1WAY)
    assert int(replacement.tail.opcode) == int(ida_hexrays.m_goto)
    assert tuple(replacement.succset) == (target.serial,)
    assert tuple(entry.succset) == (replacement.serial,)
    assert tuple(original.succset) == (
        old_fallthrough.serial,
        old_taken.serial,
    )
    assert tuple(original.predset) == ()
    assert receipt.root_publication_confirmed
    assert receipt.prepublication_validation.passed
    assert receipt.postpublication_validation.passed


def test_gateway_allows_staged_internal_predecessor_for_publication_root() -> None:
    entry = _Block(0, start=0x401000, block_type=ida_hexrays.BLT_1WAY)
    original_a = _Block(1, start=0x401010, block_type=ida_hexrays.BLT_1WAY)
    bridge = _Block(2, start=0x401020, block_type=ida_hexrays.BLT_1WAY)
    original_b = _Block(3, start=0x401030, block_type=ida_hexrays.BLT_1WAY)
    target = _Block(4, start=0x401040, block_type=ida_hexrays.BLT_0WAY)
    dispatcher = _Block(5, start=0x401050, block_type=ida_hexrays.BLT_0WAY)
    stop = _Block(6, start=0x401060, block_type=ida_hexrays.BLT_STOP)
    _connect(entry, original_a)
    _connect(original_a, dispatcher)
    _connect(bridge, original_b)
    _connect(original_b, dispatcher)
    mba = _Mba(
        (entry, original_a, bridge, original_b, target, dispatcher, stop)
    )
    gateway = _fragment_gateway(mba)
    modifier = dm.DeferredGraphModifier(mba, mutation_gateway=gateway)
    original_a_handle = gateway.identity_index.handle_for_serial(original_a.serial)
    original_b_handle = gateway.identity_index.handle_for_serial(original_b.serial)
    assert original_a_handle is not None
    assert original_b_handle is not None
    original_a_proxy = gateway.identity_index.logical_proxy_for_handle(
        original_a_handle
    )
    original_b_proxy = gateway.identity_index.logical_proxy_for_handle(
        original_b_handle
    )
    assert original_a_proxy is not None
    assert original_b_proxy is not None
    plan = _plan(
        gateway,
        entry=entry.serial,
        original=original_a.serial,
        target=target.serial,
        dispatcher=dispatcher.serial,
    )
    index = gateway.identity_index

    def _native(block_id: str, role: FragmentBlockRole, serial: int) -> FragmentBlock:
        handle = index.handle_for_serial(serial)
        assert handle is not None and handle.stable_identity is not None
        rebound = index.resolve(handle)
        assert rebound is not None and rebound.anchor_ea is not None
        return FragmentBlock(
            block_id=block_id,
            role=role,
            materialization=FragmentBlockMaterialization.REUSE_PUBLISHED,
            semantic_anchor_ea=int(rebound.anchor_ea),
            stable_identity=handle.stable_identity,
        )

    original_b_plan = _native(
        "original-b",
        FragmentBlockRole.ORIGINAL,
        original_b.serial,
    )
    replacement_b = FragmentBlock(
        block_id="replacement-b",
        role=FragmentBlockRole.REPLACEMENT,
        materialization=FragmentBlockMaterialization.CLONE_PUBLISHED,
        semantic_anchor_ea=original_b_plan.semantic_anchor_ea,
        stable_identity=original_b_plan.stable_identity,
        replaces_block_id=original_b_plan.block_id,
    )
    plan = replace(
        plan,
        plan_id="runtime-two-root-fragment",
        blocks=plan.blocks
        + (
            _native("bridge", FragmentBlockRole.EXTERNAL, bridge.serial),
            original_b_plan,
            replacement_b,
        ),
        roots=("replacement", replacement_b.block_id),
        owned_originals=("original", original_b_plan.block_id),
        operations=(
            replace(
                plan.operations[0],
                edges=(
                    FragmentEdge(
                        role=SemanticEdgeRole.DIRECT,
                        target_block_id=replacement_b.block_id,
                    ),
                ),
            ),
            FragmentOperation(
                operation_id="direct-route-b",
                source_block_id=replacement_b.block_id,
                edges=(
                    FragmentEdge(
                        role=SemanticEdgeRole.DIRECT,
                        target_block_id="target",
                    ),
                ),
            ),
        ),
    )

    receipt = gateway.publish_semantic_fragment(modifier, plan)

    replacement_a_version = original_a_proxy.resolve()
    replacement_b_version = original_b_proxy.resolve()
    assert replacement_a_version is not None
    assert replacement_b_version is not None
    replacement_a_binding = gateway.identity_index.resolve_logical_version(
        replacement_a_version
    )
    replacement_b_binding = gateway.identity_index.resolve_logical_version(
        replacement_b_version
    )
    assert replacement_a_binding is not None
    assert replacement_b_binding is not None
    replacement_a = mba.get_mblock(replacement_a_binding.serial)
    replacement_b_live = mba.get_mblock(replacement_b_binding.serial)
    assert tuple(entry.succset) == (replacement_a.serial,)
    assert tuple(bridge.succset) == (replacement_b_live.serial,)
    assert tuple(replacement_a.succset) == (replacement_b_live.serial,)
    assert set(replacement_b_live.predset) == {bridge.serial, replacement_a.serial}
    assert receipt.root_publication_confirmed


def test_direct_root_partial_write_restores_previous_authority(monkeypatch) -> None:
    entry = _Block(0, start=0x401000, block_type=ida_hexrays.BLT_1WAY)
    original = _Block(1, start=0x401010, block_type=ida_hexrays.BLT_1WAY)
    target = _Block(2, start=0x401020, block_type=ida_hexrays.BLT_0WAY)
    dispatcher = _Block(3, start=0x401030, block_type=ida_hexrays.BLT_0WAY)
    stop = _Block(4, start=0x401040, block_type=ida_hexrays.BLT_STOP)
    _connect(entry, original)
    _connect(original, dispatcher)
    mba = _Mba((entry, original, target, dispatcher, stop))
    gateway = _fragment_gateway(mba)
    modifier = dm.DeferredGraphModifier(mba, mutation_gateway=gateway)
    plan = _plan(gateway, entry=0, original=1, target=2, dispatcher=3)
    original_handle = gateway.identity_index.handle_for_serial(1)
    assert original_handle is not None
    proxy = gateway.identity_index.logical_proxy_for_handle(original_handle)
    assert proxy is not None
    published = proxy.resolve()
    assert published is not None
    mark = modifier._semantic_edge_mark
    entry_write_failed = False

    def _fail_once_after_entry_write(*blocks) -> None:
        nonlocal entry_write_failed
        mark(*blocks)
        if not entry_write_failed and any(int(block.serial) == 0 for block in blocks):
            entry_write_failed = True
            raise RuntimeError("failure after entry root write")

    monkeypatch.setattr(modifier, "_semantic_edge_mark", _fail_once_after_entry_write)

    with pytest.raises(RuntimeError, match="failure after entry root write"):
        gateway.publish_semantic_fragment(modifier, plan)

    assert entry_write_failed
    assert mba.qty == 5
    assert tuple(entry.succset) == (original.serial,)
    assert tuple(original.predset) == (entry.serial,)
    assert tuple(original.succset) == (dispatcher.serial,)
    assert tuple(target.predset) == ()
    assert proxy.resolve() is published
    assert gateway.active is False
    assert modifier._semantic_fragment_state is None


@pytest.mark.parametrize("fail_during_taken_write", (False, True))
def test_gateway_publishes_shared_conditional_roots_as_one_atomic_group(
    monkeypatch,
    fail_during_taken_write: bool,
) -> None:
    entry = _Block(0, start=0x401000, block_type=ida_hexrays.BLT_1WAY)
    predecessor = _Block(1, start=0x401010, block_type=ida_hexrays.BLT_2WAY)
    fallthrough_original = _Block(
        2,
        start=0x401020,
        block_type=ida_hexrays.BLT_1WAY,
    )
    taken_original = _Block(
        3,
        start=0x401030,
        block_type=ida_hexrays.BLT_1WAY,
    )
    target = _Block(4, start=0x401040, block_type=ida_hexrays.BLT_0WAY)
    dispatcher = _Block(5, start=0x401050, block_type=ida_hexrays.BLT_0WAY)
    stop = _Block(6, start=0x401060, block_type=ida_hexrays.BLT_STOP)
    _connect(entry, predecessor)
    _connect_conditional(
        predecessor,
        taken=taken_original,
        fallthrough=fallthrough_original,
    )
    _connect(fallthrough_original, dispatcher)
    _connect(taken_original, dispatcher)
    mba = _Mba(
        (
            entry,
            predecessor,
            fallthrough_original,
            taken_original,
            target,
            dispatcher,
            stop,
        )
    )
    gateway = _fragment_gateway(mba)
    modifier = dm.DeferredGraphModifier(mba, mutation_gateway=gateway)
    monkeypatch.setattr(dm, "insert_goto_instruction", _insert_fake_goto_instruction)

    def _conditional_successor(*args, **kwargs) -> bool:
        changed = _change_fake_conditional_successor(*args, **kwargs)
        if not fail_during_taken_write:
            return changed
        block = args[0]
        target_serial = int(args[1])
        block.type = int(ida_hexrays.BLT_1WAY)
        block.succset.clear()
        block.succset.push_back(target_serial)
        raise RuntimeError("partial shared conditional root write")

    monkeypatch.setattr(
        dm,
        "change_2way_block_conditional_successor",
        _conditional_successor,
    )
    plan = _plan_with_shared_conditional_roots(
        gateway,
        entry=entry.serial,
        predecessor=predecessor.serial,
        fallthrough_original=fallthrough_original.serial,
        taken_original=taken_original.serial,
        target=target.serial,
        dispatcher=dispatcher.serial,
    )
    fallthrough_handle = gateway.identity_index.handle_for_serial(
        fallthrough_original.serial
    )
    taken_handle = gateway.identity_index.handle_for_serial(taken_original.serial)
    assert fallthrough_handle is not None
    assert taken_handle is not None
    fallthrough_proxy = gateway.identity_index.logical_proxy_for_handle(
        fallthrough_handle
    )
    taken_proxy = gateway.identity_index.logical_proxy_for_handle(taken_handle)
    assert fallthrough_proxy is not None
    assert taken_proxy is not None
    fallthrough_published = fallthrough_proxy.resolve()
    taken_published = taken_proxy.resolve()
    assert fallthrough_published is not None
    assert taken_published is not None

    if fail_during_taken_write:
        with pytest.raises(
            RuntimeError,
            match="partial shared conditional root write",
        ):
            gateway.publish_semantic_fragment(modifier, plan)
        assert mba.qty == 7
        assert predecessor.type == int(ida_hexrays.BLT_2WAY)
        assert predecessor.nextb is fallthrough_original
        assert predecessor.tail.d.b == taken_original.serial
        assert tuple(predecessor.succset) == (
            fallthrough_original.serial,
            taken_original.serial,
        )
        assert tuple(fallthrough_original.predset) == (predecessor.serial,)
        assert tuple(taken_original.predset) == (predecessor.serial,)
        assert fallthrough_proxy.resolve() is fallthrough_published
        assert taken_proxy.resolve() is taken_published
        assert gateway.active is False
        assert modifier._semantic_fragment_state is None
        return

    receipt = gateway.publish_semantic_fragment(modifier, plan)

    fallthrough_promoted = fallthrough_proxy.resolve()
    taken_promoted = taken_proxy.resolve()
    assert fallthrough_promoted is not None
    assert taken_promoted is not None
    assert fallthrough_promoted is not fallthrough_published
    assert taken_promoted is not taken_published
    fallthrough_binding = gateway.identity_index.resolve_logical_version(
        fallthrough_promoted
    )
    taken_binding = gateway.identity_index.resolve_logical_version(taken_promoted)
    assert fallthrough_binding is not None
    assert taken_binding is not None
    fallthrough_replacement = mba.get_mblock(fallthrough_binding.serial)
    taken_replacement = mba.get_mblock(taken_binding.serial)
    helper = predecessor.nextb
    assert fallthrough_replacement is not None
    assert taken_replacement is not None
    assert helper is not None and helper is not fallthrough_original
    assert predecessor.type == int(ida_hexrays.BLT_2WAY)
    assert predecessor.tail.d.b == taken_replacement.serial
    assert tuple(predecessor.succset) == (
        helper.serial,
        taken_replacement.serial,
    )
    assert tuple(helper.predset) == (predecessor.serial,)
    assert tuple(helper.succset) == (fallthrough_replacement.serial,)
    assert tuple(fallthrough_original.predset) == ()
    assert tuple(taken_original.predset) == ()
    assert receipt.root_publication_confirmed
    assert receipt.prepublication_validation.passed
    assert receipt.postpublication_validation.passed
    assert receipt.operation_count == 7
    assert receipt.planned_operation_count == 7
    assert gateway.active is False
    assert modifier._semantic_fragment_state is None


@pytest.mark.parametrize("fail_after_root_write", (False, True))
def test_gateway_publishes_one_way_call_root_through_owned_helper(
    monkeypatch,
    fail_after_root_write: bool,
) -> None:
    entry = _Block(0, start=0x401000, block_type=ida_hexrays.BLT_1WAY)
    call_predecessor = _Block(
        1,
        start=0x401010,
        block_type=ida_hexrays.BLT_1WAY,
    )
    original = _Block(2, start=0x401020, block_type=ida_hexrays.BLT_1WAY)
    target = _Block(3, start=0x401030, block_type=ida_hexrays.BLT_0WAY)
    dispatcher = _Block(4, start=0x401040, block_type=ida_hexrays.BLT_0WAY)
    stop = _Block(5, start=0x401050, block_type=ida_hexrays.BLT_STOP)
    _connect(entry, call_predecessor)
    call = _Instruction(ida_hexrays.m_call, call_predecessor.start)
    call_predecessor.head = call
    call_predecessor.tail = call
    call_predecessor.succset.push_back(original.serial)
    original.predset.push_back(call_predecessor.serial)
    _connect(original, dispatcher)
    mba = _Mba((entry, call_predecessor, original, target, dispatcher, stop))
    gateway = _fragment_gateway(mba)
    modifier = dm.DeferredGraphModifier(mba, mutation_gateway=gateway)
    monkeypatch.setattr(dm, "insert_goto_instruction", _insert_fake_goto_instruction)
    plan = _plan(
        gateway,
        entry=entry.serial,
        original=original.serial,
        target=target.serial,
        dispatcher=dispatcher.serial,
    )
    predecessor_handle = gateway.identity_index.handle_for_serial(
        call_predecessor.serial
    )
    assert predecessor_handle is not None
    assert predecessor_handle.stable_identity is not None
    predecessor_binding = gateway.identity_index.resolve(predecessor_handle)
    assert predecessor_binding is not None
    assert predecessor_binding.anchor_ea is not None
    plan = replace(
        plan,
        plan_id="runtime-call-root-fragment",
        atomic_group_id="call-root@0x401010",
        blocks=plan.blocks
        + (
            FragmentBlock(
                block_id="call-predecessor",
                role=FragmentBlockRole.EXTERNAL,
                materialization=FragmentBlockMaterialization.REUSE_PUBLISHED,
                semantic_anchor_ea=int(predecessor_binding.anchor_ea),
                stable_identity=predecessor_handle.stable_identity,
            ),
        ),
    )
    inventory = modifier._plan_semantic_fragment_root_publication_inventory(plan)
    assert len(inventory.items) == 1
    assert inventory.items[0].role is SemanticEdgeRole.CALL_FALLTHROUGH

    original_handle = gateway.identity_index.handle_for_serial(original.serial)
    assert original_handle is not None
    proxy = gateway.identity_index.logical_proxy_for_handle(original_handle)
    assert proxy is not None
    published = proxy.resolve()
    assert published is not None
    mark = modifier._semantic_edge_mark
    root_write_failed = False

    def _fail_once_after_root_write(*blocks) -> None:
        nonlocal root_write_failed
        mark(*blocks)
        if (
            fail_after_root_write
            and not root_write_failed
            and any(
                int(block.start) == int(call_predecessor.start)
                for block in blocks
            )
        ):
            root_write_failed = True
            raise RuntimeError("failure after one-way call root write")

    monkeypatch.setattr(modifier, "_semantic_edge_mark", _fail_once_after_root_write)

    if fail_after_root_write:
        with pytest.raises(
            RuntimeError,
            match="failure after one-way call root write",
        ):
            gateway.publish_semantic_fragment(modifier, plan)
        assert root_write_failed
        assert mba.qty == 6
        assert call_predecessor.nextb is original
        assert call_predecessor.tail.opcode == int(ida_hexrays.m_call)
        assert tuple(call_predecessor.succset) == (original.serial,)
        assert tuple(original.predset) == (call_predecessor.serial,)
        assert proxy.resolve() is published
        assert gateway.active is False
        assert modifier._semantic_fragment_state is None
        return

    receipt = gateway.publish_semantic_fragment(modifier, plan)

    promoted = proxy.resolve()
    assert promoted is not None and promoted is not published
    promoted_binding = gateway.identity_index.resolve_logical_version(promoted)
    assert promoted_binding is not None
    replacement = mba.get_mblock(promoted_binding.serial)
    helper = call_predecessor.nextb
    assert replacement is not None
    assert helper is not None and helper is not original
    assert call_predecessor.tail.opcode == int(ida_hexrays.m_call)
    assert tuple(call_predecessor.succset) == (helper.serial,)
    assert tuple(helper.predset) == (call_predecessor.serial,)
    assert tuple(helper.succset) == (replacement.serial,)
    assert tuple(original.predset) == ()
    assert receipt.root_publication_confirmed
    assert receipt.prepublication_validation.passed
    assert receipt.postpublication_validation.passed
    assert receipt.operation_count == 4
    assert receipt.planned_operation_count == 4
    assert gateway.active is False
    assert modifier._semantic_fragment_state is None


@pytest.mark.parametrize("fail_after_root_write", (False, True))
def test_gateway_publishes_conditional_taken_fragment_root(
    monkeypatch,
    fail_after_root_write: bool,
) -> None:
    entry = _Block(0, start=0x401000, block_type=ida_hexrays.BLT_1WAY)
    predecessor = _Block(1, start=0x401010, block_type=ida_hexrays.BLT_2WAY)
    sibling = _Block(2, start=0x401020, block_type=ida_hexrays.BLT_0WAY)
    original = _Block(3, start=0x401030, block_type=ida_hexrays.BLT_1WAY)
    target = _Block(4, start=0x401040, block_type=ida_hexrays.BLT_0WAY)
    dispatcher = _Block(5, start=0x401050, block_type=ida_hexrays.BLT_0WAY)
    stop = _Block(6, start=0x401060, block_type=ida_hexrays.BLT_STOP)
    _connect(entry, predecessor)
    _connect_conditional(predecessor, taken=original, fallthrough=sibling)
    _connect(original, dispatcher)
    mba = _Mba((entry, predecessor, sibling, original, target, dispatcher, stop))
    gateway = _fragment_gateway(mba)
    modifier = dm.DeferredGraphModifier(mba, mutation_gateway=gateway)
    root_write_failed = False

    def _conditional_successor(*args, **kwargs) -> bool:
        nonlocal root_write_failed
        changed = _change_fake_conditional_successor(*args, **kwargs)
        if fail_after_root_write and not root_write_failed:
            root_write_failed = True
            raise RuntimeError("failure after conditional taken root write")
        return changed

    monkeypatch.setattr(
        dm,
        "change_2way_block_conditional_successor",
        _conditional_successor,
    )
    plan = _plan_with_conditional_predecessor(
        gateway,
        entry=0,
        predecessor=1,
        sibling=2,
        original=3,
        target=4,
        dispatcher=5,
    )
    original_handle = gateway.identity_index.handle_for_serial(3)
    assert original_handle is not None
    proxy = gateway.identity_index.logical_proxy_for_handle(original_handle)
    assert proxy is not None
    published = proxy.resolve()
    assert published is not None

    if fail_after_root_write:
        with pytest.raises(
            RuntimeError,
            match="failure after conditional taken root write",
        ):
            gateway.publish_semantic_fragment(modifier, plan)
        assert root_write_failed
        assert mba.qty == 7
        assert predecessor.tail.d.b == original.serial
        assert tuple(predecessor.succset) == (sibling.serial, original.serial)
        assert tuple(original.predset) == (predecessor.serial,)
        assert tuple(sibling.predset) == (predecessor.serial,)
        assert proxy.resolve() is published
        assert gateway.active is False
        assert modifier._semantic_fragment_state is None
        return

    receipt = gateway.publish_semantic_fragment(modifier, plan)

    promoted = proxy.resolve()
    assert promoted is not None and promoted is not published
    promoted_binding = gateway.identity_index.resolve_logical_version(promoted)
    assert promoted_binding is not None
    replacement = mba.get_mblock(promoted_binding.serial)
    assert replacement is not None
    assert predecessor.tail.d.b == replacement.serial
    assert tuple(predecessor.succset) == (sibling.serial, replacement.serial)
    assert tuple(original.predset) == ()
    assert tuple(replacement.predset) == (predecessor.serial,)
    assert tuple(sibling.predset) == (predecessor.serial,)
    assert receipt.root_publication_confirmed
    assert receipt.postpublication_validation.passed
    assert receipt.operation_count == 3
    assert receipt.planned_operation_count == 3
    assert gateway.active is False
    assert modifier._semantic_fragment_state is None


@pytest.mark.parametrize("insertion_retargets_fallthrough", (False, True))
@pytest.mark.parametrize("fail_after_root_write", (False, True))
def test_gateway_publishes_conditional_fallthrough_fragment_root(
    monkeypatch,
    fail_after_root_write: bool,
    insertion_retargets_fallthrough: bool,
) -> None:
    entry = _Block(0, start=0x401000, block_type=ida_hexrays.BLT_1WAY)
    predecessor = _Block(1, start=0x401010, block_type=ida_hexrays.BLT_2WAY)
    original = _Block(2, start=0x401020, block_type=ida_hexrays.BLT_1WAY)
    sibling = _Block(3, start=0x401030, block_type=ida_hexrays.BLT_0WAY)
    target = _Block(4, start=0x401040, block_type=ida_hexrays.BLT_0WAY)
    dispatcher = _Block(5, start=0x401050, block_type=ida_hexrays.BLT_0WAY)
    stop = _Block(6, start=0x401060, block_type=ida_hexrays.BLT_STOP)
    _connect(entry, predecessor)
    _connect_conditional(predecessor, taken=sibling, fallthrough=original)
    _connect(original, dispatcher)
    mba = _Mba((entry, predecessor, original, sibling, target, dispatcher, stop))
    gateway = _fragment_gateway(mba)
    modifier = dm.DeferredGraphModifier(mba, mutation_gateway=gateway)
    monkeypatch.setattr(dm, "insert_goto_instruction", _insert_fake_goto_instruction)
    if insertion_retargets_fallthrough:
        copy_block_keep = dm.copy_block_keep

        def _copy_block_with_live_fallthrough_transient(*args, **kwargs):
            source = args[1]
            clone = copy_block_keep(*args, **kwargs)
            if int(source.start) != int(predecessor.start):
                return clone
            taken_serial = int(source.tail.d.b)
            source.succset.clear()
            source.succset.push_back(int(clone.serial))
            source.succset.push_back(taken_serial)
            return clone

        monkeypatch.setattr(
            dm,
            "copy_block_keep",
            _copy_block_with_live_fallthrough_transient,
        )
    mark = modifier._semantic_edge_mark
    root_write_failed = False

    def _fail_once_after_root_write(*blocks) -> None:
        nonlocal root_write_failed
        mark(*blocks)
        if (
            fail_after_root_write
            and not root_write_failed
            and any(int(block.start) == 0x401010 for block in blocks)
        ):
            root_write_failed = True
            raise RuntimeError("failure after conditional fallthrough root write")

    monkeypatch.setattr(modifier, "_semantic_edge_mark", _fail_once_after_root_write)
    plan = _plan_with_conditional_predecessor(
        gateway,
        entry=0,
        predecessor=1,
        sibling=3,
        original=2,
        target=4,
        dispatcher=5,
    )
    original_handle = gateway.identity_index.handle_for_serial(2)
    assert original_handle is not None
    proxy = gateway.identity_index.logical_proxy_for_handle(original_handle)
    assert proxy is not None
    published = proxy.resolve()
    assert published is not None
    proxy_count = gateway.identity_index.logical_proxy_count

    if fail_after_root_write:
        with pytest.raises(
            RuntimeError,
            match="failure after conditional fallthrough root write",
        ):
            gateway.publish_semantic_fragment(modifier, plan)
        assert root_write_failed
        assert mba.qty == 7
        assert predecessor.nextb is original
        assert tuple(predecessor.succset) == (original.serial, sibling.serial)
        assert predecessor.tail.d.b == sibling.serial
        assert tuple(original.predset) == (predecessor.serial,)
        assert tuple(sibling.predset) == (predecessor.serial,)
        assert tuple(target.predset) == ()
        assert proxy.resolve() is published
        assert gateway.identity_index.logical_proxy_count == proxy_count
        assert gateway.active is False
        assert modifier._semantic_fragment_state is None
        return

    receipt = gateway.publish_semantic_fragment(modifier, plan)

    promoted = proxy.resolve()
    assert promoted is not None and promoted is not published
    promoted_binding = gateway.identity_index.resolve_logical_version(promoted)
    assert promoted_binding is not None
    replacement = mba.get_mblock(promoted_binding.serial)
    helper = predecessor.nextb
    assert replacement is not None
    assert helper is not None and helper is not original
    assert tuple(predecessor.succset) == (helper.serial, sibling.serial)
    assert predecessor.tail.d.b == sibling.serial
    assert tuple(helper.predset) == (predecessor.serial,)
    assert tuple(helper.succset) == (replacement.serial,)
    assert tuple(original.predset) == ()
    assert tuple(replacement.predset) == (helper.serial,)
    helper_handle = gateway.identity_index.handle_for_serial(helper.serial)
    assert helper_handle is not None and helper_handle.stable_identity is None
    assert receipt.root_publication_confirmed
    assert receipt.postpublication_validation.passed
    assert receipt.operation_count == 4
    assert receipt.planned_operation_count == 4
    assert gateway.active is False
    assert modifier._semantic_fragment_state is None


def test_backend_stages_plan_owned_empty_synthetic_block(monkeypatch) -> None:
    entry = _Block(0, start=0x401000, block_type=ida_hexrays.BLT_1WAY)
    original = _Block(1, start=0x401010, block_type=ida_hexrays.BLT_1WAY)
    target = _Block(2, start=0x401020, block_type=ida_hexrays.BLT_0WAY)
    dispatcher = _Block(3, start=0x401030, block_type=ida_hexrays.BLT_0WAY)
    stop = _Block(4, start=0x401040, block_type=ida_hexrays.BLT_STOP)
    _connect(entry, original)
    _connect(original, dispatcher)
    mba = _Mba((entry, original, target, dispatcher, stop))
    gateway = _fragment_gateway(mba)
    modifier = dm.DeferredGraphModifier(mba, mutation_gateway=gateway)
    monkeypatch.setattr(dm, "create_standalone_block", _create_fake_standalone_block)
    monkeypatch.setattr(
        dm,
        "change_0way_block_successor",
        _change_fake_zero_way_successor,
    )
    plan = _plan(gateway, entry=0, original=1, target=2, dispatcher=3)
    synthetic = FragmentBlock(
        block_id="synthetic",
        role=FragmentBlockRole.SYNTHETIC,
        materialization=FragmentBlockMaterialization.CREATE_EMPTY,
        semantic_anchor_ea=0x401015,
    )
    plan = replace(
        plan,
        blocks=plan.blocks + (synthetic,),
        operations=(
            FragmentOperation(
                operation_id="replacement-to-synthetic",
                source_block_id="replacement",
                edges=(
                    FragmentEdge(
                        role=SemanticEdgeRole.DIRECT,
                        target_block_id=synthetic.block_id,
                    ),
                ),
            ),
            FragmentOperation(
                operation_id="synthetic-to-target",
                source_block_id=synthetic.block_id,
                edges=(
                    FragmentEdge(
                        role=SemanticEdgeRole.DIRECT,
                        target_block_id="target",
                    ),
                ),
            ),
        ),
    )
    root_inventory = modifier._plan_semantic_fragment_root_publication_inventory(plan)
    gateway._begin_semantic_fragment_batch(modifier, plan, root_inventory)

    projection = modifier._stage_semantic_fragment(plan)

    result = validate_fragment_projection(plan, projection)
    assert result.passed, result.failures
    assert projection.block("replacement").successors == ("synthetic",)
    assert projection.block("synthetic").successors == ("target",)
    assert projection.binding("synthetic").state is FragmentBindingState.STAGED
    assert projection.binding("synthetic").stable_identity is None
    assert mba.qty == 7

    modifier._discard_staged_semantic_fragment(plan)
    gateway.abort(reason="runtime synthetic staging test cleanup")

    assert mba.qty == 5
    assert tuple(entry.succset) == (1,)
    assert tuple(original.succset) == (3,)
    assert tuple(target.predset) == ()
    assert gateway.active is False


def test_backend_stages_complete_conditional_with_owned_fallthrough_helper(
    monkeypatch,
) -> None:
    entry = _Block(0, start=0x401000, block_type=ida_hexrays.BLT_1WAY)
    original = _Block(1, start=0x401010, block_type=ida_hexrays.BLT_0WAY)
    taken = _Block(2, start=0x401020, block_type=ida_hexrays.BLT_0WAY)
    fallthrough = _Block(3, start=0x401030, block_type=ida_hexrays.BLT_0WAY)
    dispatcher = _Block(4, start=0x401040, block_type=ida_hexrays.BLT_0WAY)
    stop = _Block(5, start=0x401050, block_type=ida_hexrays.BLT_STOP)
    _connect(entry, original)
    original.type = int(ida_hexrays.BLT_0WAY)
    original.tail = _Instruction(ida_hexrays.m_jz, 0x401010)
    original.head = original.tail
    mba = _Mba((entry, original, taken, fallthrough, dispatcher, stop))
    gateway = _fragment_gateway(mba)
    modifier = dm.DeferredGraphModifier(mba, mutation_gateway=gateway)
    monkeypatch.setattr(dm, "insert_goto_instruction", _insert_fake_goto_instruction)
    plan = _conditional_plan(
        gateway,
        entry=0,
        original=1,
        taken=2,
        fallthrough=3,
        dispatcher=4,
    )
    root_inventory = modifier._plan_semantic_fragment_root_publication_inventory(plan)
    gateway._begin_semantic_fragment_batch(modifier, plan, root_inventory)

    projection = modifier._stage_semantic_fragment(plan)

    result = validate_fragment_projection(plan, projection)
    assert result.passed, result.failures
    helpers = projection.fallthrough_helpers
    assert len(helpers) == 1
    helper = helpers[0]
    assert helper.operation_id == "conditional-route"
    assert helper.source_block_id == "replacement"
    assert helper.semantic_target_block_id == "fallthrough"
    assert projection.block("replacement").successors == (
        helper.helper_block_id,
        "taken",
    )
    assert projection.block(helper.helper_block_id).successors == ("fallthrough",)
    assert (
        projection.binding(helper.helper_block_id).state is FragmentBindingState.STAGED
    )
    assert projection.binding(helper.helper_block_id).stable_identity is None
    assert mba.qty == 8

    modifier._discard_staged_semantic_fragment(plan)
    gateway.abort(reason="runtime conditional staging test cleanup")

    assert mba.qty == 6
    assert tuple(entry.succset) == (1,)
    assert tuple(original.succset) == ()
    assert tuple(taken.predset) == ()
    assert tuple(fallthrough.predset) == ()
    assert gateway.active is False


def test_backend_normalizes_conditional_select_only_on_detached_replacement(
    monkeypatch,
) -> None:
    entry = _Block(0, start=0x40A5E0, block_type=ida_hexrays.BLT_1WAY)
    original = _Block(1, start=0x40A5F0, block_type=ida_hexrays.BLT_2WAY)
    selected = _Block(2, start=0x40A5FE, block_type=ida_hexrays.BLT_1WAY)
    join = _Block(3, start=0x40A601, block_type=ida_hexrays.BLT_0WAY)
    taken = _Block(4, start=0x40B6C0, block_type=ida_hexrays.BLT_0WAY)
    fallthrough = _Block(5, start=0x40A607, block_type=ida_hexrays.BLT_0WAY)
    stop = _Block(6, start=0x40C000, block_type=ida_hexrays.BLT_STOP)
    original.end = 0x40A5FF
    selected.end = 0x40A5FF
    join.end = 0x40A607
    _connect(entry, original)
    original_instructions = (
        _Instruction(ida_hexrays.m_nop, 0x40A5F0),
        _Instruction(ida_hexrays.m_mov, 0x40A5F6),
        _Instruction(ida_hexrays.m_mov, 0x40A5F8),
        _Instruction(ida_hexrays.m_jge, 0x40A5FE),
    )
    original.head = original_instructions[0]
    for current, following in zip(
        original_instructions[:-1],
        original_instructions[1:],
        strict=True,
    ):
        current.next = following
    original.tail = original_instructions[-1]
    original.tail.d.make_blkref(join.serial)
    original.succset = _EdgeSet((selected.serial, join.serial))
    selected.predset.push_back(original.serial)
    join.predset.push_back(original.serial)
    selected.head = selected.tail = _Instruction(
        ida_hexrays.m_mov,
        0x40A5FE,
    )
    selected.succset.push_back(join.serial)
    join.predset.push_back(selected.serial)
    join_prefix = _Instruction(ida_hexrays.m_add, 0x40A601)
    join_transfer = _Instruction(ida_hexrays.m_ijmp, 0x40A605)
    join_prefix.next = join_transfer
    join.head = join_prefix
    join.tail = join_transfer
    mba = _Mba((entry, original, selected, join, taken, fallthrough, stop))
    gateway = make_fragment_publication_gateway(
        mba,
        publication_purpose=(
            FragmentPublicationPurpose.FRONTEND_NORMALIZATION
        ),
    )
    modifier = dm.DeferredGraphModifier(mba, mutation_gateway=gateway)
    monkeypatch.setattr(sfb.ida_hexrays, "minsn_t", deepcopy)
    monkeypatch.setattr(dm, "create_standalone_block", _create_fake_standalone_block)
    monkeypatch.setattr(dm, "insert_goto_instruction", _insert_fake_goto_instruction)
    plan = _conditional_select_plan(
        gateway,
        entry=0,
        original=1,
        selected_value=2,
        join=3,
        taken=4,
        fallthrough=5,
    )
    root_inventory = modifier._plan_semantic_fragment_root_publication_inventory(plan)
    gateway._begin_semantic_fragment_batch(modifier, plan, root_inventory)

    projection = modifier._stage_semantic_fragment(plan)

    state = modifier._semantic_fragment_state
    assert state is not None
    replacement = sfb._live_block_for_binding(
        modifier,
        state.binding("replacement"),
    )
    replacement_instructions = tuple(sfb._iter_block_instructions(replacement))
    assert tuple(
        (int(instruction.ea), int(instruction.opcode))
        for instruction in replacement_instructions
    ) == (
        (0x40A5F0, int(ida_hexrays.m_nop)),
        (0x40A5F6, int(ida_hexrays.m_jl)),
    )
    assert tuple(
        (int(instruction.ea), int(instruction.opcode))
        for instruction in sfb._iter_block_instructions(original)
    ) == (
        (0x40A5F0, int(ida_hexrays.m_nop)),
        (0x40A5F6, int(ida_hexrays.m_mov)),
        (0x40A5F8, int(ida_hexrays.m_mov)),
        (0x40A5FE, int(ida_hexrays.m_jge)),
    )
    assert set(projection.block("replacement").successors) == {
        "taken",
        "fallthrough-helper:native-indirect-transfer@0x40A605",
    }

    modifier._discard_staged_semantic_fragment(plan)
    gateway.abort(reason="runtime conditional-select staging cleanup")


def test_backend_clones_nested_signed_skip_before_replacing_parent(
    monkeypatch,
) -> None:
    entry = _Block(0, start=0x40A5E0, block_type=ida_hexrays.BLT_1WAY)
    original = _Block(1, start=0x40A5F0, block_type=ida_hexrays.BLT_2WAY)
    selected = _Block(2, start=0x40A5FE, block_type=ida_hexrays.BLT_1WAY)
    join = _Block(3, start=0x40A601, block_type=ida_hexrays.BLT_0WAY)
    taken = _Block(4, start=0x40B6C0, block_type=ida_hexrays.BLT_0WAY)
    fallthrough = _Block(5, start=0x40A607, block_type=ida_hexrays.BLT_0WAY)
    stop = _Block(6, start=0x40C000, block_type=ida_hexrays.BLT_STOP)
    original.end = 0x40A5FF
    selected.end = 0x40A5FF
    join.end = 0x40A607
    _connect(entry, original)

    sign = _Instruction(ida_hexrays.m_sets, 0x40A5F0)
    sign.d.make_reg(2, 1)
    overflow = _Instruction(ida_hexrays.m_seto, 0x40A5F0)
    overflow.d.make_reg(3, 1)
    predicate_anchor = _Instruction(ida_hexrays.m_mov, 0x40A5F6)
    carrier = _Instruction(ida_hexrays.m_mov, 0x40A5F8)
    signed_flag_xor = _Instruction(ida_hexrays.m_xor, 0x40A5FE)
    signed_flag_xor.l.make_reg(2, 1)
    signed_flag_xor.r.make_reg(3, 1)
    signed_flag_xor.d.size = 1
    complement = _Instruction(ida_hexrays.m_lnot, 0x40A5FE)
    complement.l.create_from_insn(signed_flag_xor)
    complement.d.size = 1
    skip = _Instruction(ida_hexrays.m_jcnd, 0x40A5FE)
    skip.l.create_from_insn(complement)
    skip.d.make_blkref(join.serial)
    original_instructions = (
        sign,
        overflow,
        predicate_anchor,
        carrier,
        skip,
    )
    original.head = original_instructions[0]
    for current, following in zip(
        original_instructions[:-1],
        original_instructions[1:],
        strict=True,
    ):
        current.next = following
    original.tail = skip
    original.succset = _EdgeSet((selected.serial, join.serial))
    selected.predset.push_back(original.serial)
    join.predset.push_back(original.serial)
    selected.head = selected.tail = _Instruction(
        ida_hexrays.m_mov,
        0x40A5FE,
    )
    selected.succset.push_back(join.serial)
    join.predset.push_back(selected.serial)
    join_prefix = _Instruction(ida_hexrays.m_add, 0x40A601)
    join_transfer = _Instruction(ida_hexrays.m_ijmp, 0x40A605)
    join_prefix.next = join_transfer
    join.head = join_prefix
    join.tail = join_transfer
    mba = _Mba((entry, original, selected, join, taken, fallthrough, stop))
    gateway = make_fragment_publication_gateway(
        mba,
        publication_purpose=(
            FragmentPublicationPurpose.FRONTEND_NORMALIZATION
        ),
    )
    modifier = dm.DeferredGraphModifier(mba, mutation_gateway=gateway)

    assign_operand = _BlockReference.assign

    def _assign_with_sdk_overlap_semantics(
        destination: _BlockReference,
        source: _BlockReference,
    ):
        nested = (
            destination.d is not None
            and source
            in {
                destination.d.l,
                destination.d.r,
                destination.d.d,
            }
        )
        if nested:
            destination.erase()
            return destination
        return assign_operand(destination, source)

    monkeypatch.setattr(sfb.ida_hexrays, "minsn_t", deepcopy)
    monkeypatch.setattr(sfb.ida_hexrays, "mop_t", _BlockReference)
    monkeypatch.setattr(
        _BlockReference,
        "assign",
        _assign_with_sdk_overlap_semantics,
    )
    monkeypatch.setattr(dm, "create_standalone_block", _create_fake_standalone_block)
    monkeypatch.setattr(dm, "insert_goto_instruction", _insert_fake_goto_instruction)
    plan = _conditional_select_plan(
        gateway,
        entry=0,
        original=1,
        selected_value=2,
        join=3,
        taken=4,
        fallthrough=5,
    )
    root_inventory = modifier._plan_semantic_fragment_root_publication_inventory(plan)
    gateway._begin_semantic_fragment_batch(modifier, plan, root_inventory)

    projection = modifier._stage_semantic_fragment(plan)

    state = modifier._semantic_fragment_state
    assert state is not None
    replacement = sfb._live_block_for_binding(
        modifier,
        state.binding("replacement"),
    )
    replacement_instructions = tuple(sfb._iter_block_instructions(replacement))
    assert tuple(
        (int(instruction.ea), int(instruction.opcode))
        for instruction in replacement_instructions
    ) == (
        (0x40A5F0, int(ida_hexrays.m_sets)),
        (0x40A5F0, int(ida_hexrays.m_seto)),
        (0x40A5F6, int(ida_hexrays.m_jcnd)),
    )
    normalized_branch = replacement_instructions[-1]
    assert int(normalized_branch.l.t) == int(ida_hexrays.mop_d)
    assert int(normalized_branch.l.d.opcode) == int(ida_hexrays.m_xor)
    assert {
        int(normalized_branch.l.d.l.r),
        int(normalized_branch.l.d.r.r),
    } == {2, 3}
    assert int(original.tail.l.d.opcode) == int(ida_hexrays.m_lnot)
    assert set(projection.block("replacement").successors) == {
        "taken",
        "fallthrough-helper:native-indirect-transfer@0x40A605",
    }

    modifier._discard_staged_semantic_fragment(plan)
    gateway.abort(reason="runtime nested conditional-select staging cleanup")


def test_backend_rejects_stale_conditional_select_copy_shape(monkeypatch) -> None:
    entry = _Block(0, start=0x40A5E0, block_type=ida_hexrays.BLT_1WAY)
    original = _Block(1, start=0x40A5F0, block_type=ida_hexrays.BLT_2WAY)
    selected = _Block(2, start=0x40A5FE, block_type=ida_hexrays.BLT_1WAY)
    join = _Block(3, start=0x40A601, block_type=ida_hexrays.BLT_0WAY)
    taken = _Block(4, start=0x40B6C0, block_type=ida_hexrays.BLT_0WAY)
    fallthrough = _Block(5, start=0x40A607, block_type=ida_hexrays.BLT_0WAY)
    stop = _Block(6, start=0x40C000, block_type=ida_hexrays.BLT_STOP)
    original.end = 0x40A5FF
    selected.end = 0x40A5FF
    join.end = 0x40A607
    _connect(entry, original)
    original_head = _Instruction(ida_hexrays.m_nop, 0x40A5F0)
    original_cut = _Instruction(ida_hexrays.m_mov, 0x40A5F6)
    original_tail = _Instruction(
        ida_hexrays.m_jge,
        0x40A5FE,
    )
    original_head.next = original_cut
    original_cut.next = original_tail
    original.head = original_head
    original.tail = original_tail
    original.tail.d.make_blkref(join.serial)
    original.succset = _EdgeSet((selected.serial, join.serial))
    selected.predset.push_back(original.serial)
    join.predset.push_back(original.serial)
    selected.head = selected.tail = _Instruction(
        ida_hexrays.m_add,
        0x40A5FE,
    )
    selected.succset.push_back(join.serial)
    join.predset.push_back(selected.serial)
    join.head = join.tail = _Instruction(ida_hexrays.m_ijmp, 0x40A605)
    mba = _Mba((entry, original, selected, join, taken, fallthrough, stop))
    gateway = make_fragment_publication_gateway(
        mba,
        publication_purpose=(
            FragmentPublicationPurpose.FRONTEND_NORMALIZATION
        ),
    )
    modifier = dm.DeferredGraphModifier(mba, mutation_gateway=gateway)
    monkeypatch.setattr(sfb.ida_hexrays, "minsn_t", deepcopy)
    plan = _conditional_select_plan(
        gateway,
        entry=0,
        original=1,
        selected_value=2,
        join=3,
        taken=4,
        fallthrough=5,
    )
    root_inventory = modifier._plan_semantic_fragment_root_publication_inventory(plan)
    gateway._begin_semantic_fragment_batch(modifier, plan, root_inventory)

    with pytest.raises(
        sfb.SemanticFragmentBackendRejected,
        match="conditional-select envelope",
    ):
        modifier._stage_semantic_fragment(plan)

    assert tuple(entry.succset) == (original.serial,)
    assert gateway.active
    gateway.abort(reason="runtime stale conditional-select cleanup")


def test_backend_stages_conditional_with_transaction_local_targets(
    monkeypatch,
) -> None:
    entry = _Block(0, start=0x401000, block_type=ida_hexrays.BLT_1WAY)
    original = _Block(1, start=0x401010, block_type=ida_hexrays.BLT_0WAY)
    taken = _Block(2, start=0x401020, block_type=ida_hexrays.BLT_0WAY)
    fallthrough = _Block(3, start=0x401030, block_type=ida_hexrays.BLT_0WAY)
    dispatcher = _Block(4, start=0x401040, block_type=ida_hexrays.BLT_0WAY)
    stop = _Block(5, start=0x401050, block_type=ida_hexrays.BLT_STOP)
    _connect(entry, original)
    original.tail = _Instruction(ida_hexrays.m_jz, 0x401010)
    original.head = original.tail
    mba = _Mba((entry, original, taken, fallthrough, dispatcher, stop))
    gateway = _fragment_gateway(mba)
    modifier = dm.DeferredGraphModifier(mba, mutation_gateway=gateway)
    monkeypatch.setattr(dm, "insert_goto_instruction", _insert_fake_goto_instruction)
    plan = _conditional_plan_with_staged_targets(
        gateway,
        entry=0,
        original=1,
        taken=2,
        fallthrough=3,
        dispatcher=4,
    )
    root_inventory = modifier._plan_semantic_fragment_root_publication_inventory(plan)
    gateway._begin_semantic_fragment_batch(modifier, plan, root_inventory)

    projection = modifier._stage_semantic_fragment(plan)

    result = validate_fragment_projection(plan, projection)
    assert result.passed, result.failures
    assert projection.block("replacement").successors[1] == "taken-replacement"
    helper = projection.fallthrough_helpers[0]
    assert projection.block(helper.helper_block_id).successors == (
        "fallthrough-replacement",
    )

    modifier._discard_staged_semantic_fragment(plan)
    gateway.abort(reason="runtime staged-target conditional cleanup")

    assert mba.qty == 6
    assert tuple(entry.succset) == (1,)
    assert gateway.active is False


def test_conditional_staging_failure_discards_helper_and_replacement(
    monkeypatch,
) -> None:
    entry = _Block(0, start=0x401000, block_type=ida_hexrays.BLT_1WAY)
    original = _Block(1, start=0x401010, block_type=ida_hexrays.BLT_0WAY)
    taken = _Block(2, start=0x401020, block_type=ida_hexrays.BLT_0WAY)
    fallthrough = _Block(3, start=0x401030, block_type=ida_hexrays.BLT_0WAY)
    dispatcher = _Block(4, start=0x401040, block_type=ida_hexrays.BLT_0WAY)
    stop = _Block(5, start=0x401050, block_type=ida_hexrays.BLT_STOP)
    _connect(entry, original)
    original.type = int(ida_hexrays.BLT_0WAY)
    original.tail = _Instruction(ida_hexrays.m_jz, 0x401010)
    original.head = original.tail
    mba = _Mba((entry, original, taken, fallthrough, dispatcher, stop))
    gateway = _fragment_gateway(mba)
    modifier = dm.DeferredGraphModifier(mba, mutation_gateway=gateway)
    monkeypatch.setattr(dm, "insert_goto_instruction", _insert_fake_goto_instruction)
    plan = _conditional_plan(
        gateway,
        entry=0,
        original=1,
        taken=2,
        fallthrough=3,
        dispatcher=4,
    )
    root_inventory = modifier._plan_semantic_fragment_root_publication_inventory(plan)
    gateway._begin_semantic_fragment_batch(modifier, plan, root_inventory)

    def _reject_after_helper(*_blocks) -> None:
        raise RuntimeError("post-helper failure")

    monkeypatch.setattr(modifier, "_semantic_edge_mark", _reject_after_helper)

    with pytest.raises(RuntimeError, match="post-helper failure"):
        modifier._stage_semantic_fragment(plan)
    gateway.abort(reason="runtime conditional failure cleanup")

    assert mba.qty == 6
    assert tuple(entry.succset) == (1,)
    assert tuple(original.succset) == ()
    assert tuple(taken.predset) == ()
    assert tuple(fallthrough.predset) == ()
    assert gateway.active is False
