"""Live-backend staging for detached semantic fragment publication."""

from __future__ import annotations

from copy import deepcopy
from dataclasses import replace

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

    def erase(self) -> None:
        self.t = int(ida_hexrays.mop_z)
        self.b = -1


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

    def make_nop(self, instruction) -> None:
        instruction.opcode = int(ida_hexrays.m_nop)

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


def _conditional_plan(
    gateway,
    *,
    entry: int,
    original: int,
    taken: int,
    fallthrough: int,
    dispatcher: int,
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
                predicate_anchor_ea=0x401010,
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


def test_gateway_publishes_direct_fragment_root_from_entry() -> None:
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
    assert gateway.active is False
    assert modifier._semantic_fragment_state is None


def test_direct_root_partial_write_restores_previous_authority(monkeypatch) -> None:
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


def test_backend_stages_plan_owned_empty_synthetic_block(monkeypatch) -> None:
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
    gateway._begin_semantic_fragment_batch(modifier, plan)

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
    gateway = make_mutation_gateway(mba)
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
    gateway._begin_semantic_fragment_batch(modifier, plan)

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
    assert projection.binding(helper.helper_block_id).state is FragmentBindingState.STAGED
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
    gateway = make_mutation_gateway(mba)
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
    gateway._begin_semantic_fragment_batch(modifier, plan)

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
