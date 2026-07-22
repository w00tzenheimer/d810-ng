"""Live-backend staging for detached semantic fragment publication."""

from __future__ import annotations

from copy import deepcopy

import pytest

ida_hexrays = pytest.importorskip("ida_hexrays")

from d810.hexrays.mutation import deferred_modifier as dm  # noqa: E402
from d810.ir.semantic_edge import SemanticEdgeRole  # noqa: E402
from d810.transforms.fragment_plan import (  # noqa: E402
    FragmentBlock,
    FragmentBlockMaterialization,
    FragmentBlockRole,
    FragmentEdge,
    FragmentOperation,
    FragmentPlan,
)
from d810.transforms.fragment_validation import (  # noqa: E402
    FragmentBindingState,
    validate_fragment_projection,
)
from tests.system.runtime.mutation_gateway import make_mutation_gateway  # noqa: E402


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


class _BlockReference:
    def __init__(self, serial: int | None = None):
        self.t = int(ida_hexrays.mop_z if serial is None else ida_hexrays.mop_b)
        self.b = -1 if serial is None else int(serial)

    def make_blkref(self, serial: int) -> None:
        self.t = int(ida_hexrays.mop_b)
        self.b = int(serial)


class _Instruction:
    def __init__(self, opcode: int, ea: int, target: int | None = None):
        self.opcode = int(opcode)
        self.ea = int(ea)
        self.l = _BlockReference(target)
        self.d = _BlockReference()
        self.next = None


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

    def nsucc(self) -> int:
        return self.succset.size()

    def mark_lists_dirty(self) -> None:
        return None


class _Mba:
    def __init__(self, blocks: tuple[_Block, ...]):
        self.blocks = {block.serial: block for block in blocks}
        self.qty = len(blocks)
        self.entry_ea = 0x401000
        self.maturity = int(ida_hexrays.MMAT_PREOPTIMIZED)
        self.chains_dirty = False
        for block in blocks:
            block.mba = self
        self._relink()

    def get_mblock(self, serial: int):
        return self.blocks.get(int(serial))

    def mark_chains_dirty(self) -> None:
        self.chains_dirty = True

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
        if source.tail is not None:
            clone.tail = deepcopy(source.tail)
            clone.head = clone.tail
        clone.mba = self
        self.blocks[destination] = clone
        self.qty += 1
        for successor_serial in clone.succset:
            successor = self.get_mblock(successor_serial)
            if successor is not None:
                successor.predset.push_back(destination)
        self._relink()
        return clone

    def remove_block(self, block: _Block) -> None:
        removed_serial = int(block.serial)
        self.blocks.pop(removed_serial)
        self.qty -= 1
        self._shift_coordinates(removed_serial + 1, -1)
        self._relink()

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


def test_backend_stages_hidden_replacement_and_projects_root_publication() -> None:
    entry = _Block(0, start=0x401000, block_type=ida_hexrays.BLT_1WAY)
    original = _Block(1, start=0x401010, block_type=ida_hexrays.BLT_1WAY)
    target = _Block(2, start=0x401020, block_type=ida_hexrays.BLT_0WAY)
    dispatcher = _Block(3, start=0x401030, block_type=ida_hexrays.BLT_0WAY)
    stop = _Block(4, start=0x401040, block_type=ida_hexrays.BLT_STOP)
    _connect(entry, original)
    _connect(original, dispatcher)
    mba = _Mba((entry, original, target, dispatcher, stop))
    gateway = make_mutation_gateway(mba)
    modifier = dm.DeferredGraphModifier(mba, mutation_gateway=gateway)
    plan = _plan(gateway, entry=0, original=1, target=2, dispatcher=3)
    original_handle = gateway.identity_index.handle_for_serial(1)
    assert original_handle is not None
    proxy = gateway.identity_index.logical_proxy_for_handle(original_handle)
    assert proxy is not None
    published = proxy.resolve()
    assert published is not None
    gateway._begin_semantic_fragment_batch(modifier, plan)

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
