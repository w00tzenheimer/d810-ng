"""Live-backend staging for detached semantic fragment publication."""

from __future__ import annotations

import os
import platform
from copy import deepcopy
from dataclasses import replace

import pytest

ida_hexrays = pytest.importorskip("ida_hexrays")

from d810.hexrays.mutation import deferred_modifier as dm  # noqa: E402
from d810.hexrays.mutation import semantic_fragment_backend as sfb  # noqa: E402
from d810.hexrays.ir.exact_data_flow import DefSite, UseSite  # noqa: E402
from d810.hexrays.ir.exact_value_ranges import (  # noqa: E402
    ExactValueRangeProof,
    prove_exact_unsigned_range,
)
from d810.hexrays.mutation.semantic_fragment_publication import (  # noqa: E402
    SemanticFragmentPublicationRejected,
)
from d810.ir.semantic_edge import SemanticEdgeRole  # noqa: E402
from d810.ir.storage_identity import (  # noqa: E402
    StorageIdentity,
    StorageIdentityKind,
)
from d810.transforms.fragment_plan import (  # noqa: E402
    FragmentBlock,
    FragmentBlockMaterialization,
    FragmentBlockRole,
    FragmentDataFlowObligation,
    FragmentDataFlowRole,
    FragmentEdge,
    FragmentFlagCorridor,
    FragmentOperation,
    FragmentPlan,
    FragmentPublicationPurpose,
    FragmentRangeAssumption,
    FragmentRangeObservation,
    FragmentValueSite,
)
from d810.transforms.fragment_validation import (  # noqa: E402
    FragmentBindingState,
    FragmentValidationPostcondition,
    ProjectedDataFlowRelation,
    ProjectedRangeFact,
    validate_fragment_projection,
)
from tests.system.runtime.mutation_gateway import make_mutation_gateway  # noqa: E402


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


class _BlockReference:
    def __init__(self, serial: int | None = None):
        self.t = int(ida_hexrays.mop_z if serial is None else ida_hexrays.mop_b)
        self.b = -1 if serial is None else int(serial)
        self.writes_ccflags = False
        self.writes_cc = False

    def make_blkref(self, serial: int) -> None:
        self.t = int(ida_hexrays.mop_b)
        self.b = int(serial)

    def erase(self) -> None:
        self.t = int(ida_hexrays.mop_z)
        self.b = -1

    def is_ccflags(self) -> bool:
        return self.writes_ccflags

    def is_cc(self) -> bool:
        return self.writes_cc


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
        self.valrange_bounds: list[tuple[int | None, int | None]] = []
        self.valrange_queries: list[tuple[int, int]] = []

    def nsucc(self) -> int:
        return self.succset.size()

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
    gateway = make_mutation_gateway(mba)
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
    gateway = make_mutation_gateway(mba)
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
    gateway = make_mutation_gateway(mba)
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
    gateway = make_mutation_gateway(mba)
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


def test_backend_rejects_duplicate_physical_flag_writers() -> None:
    mba, gateway, modifier, plan, entry, original = _flag_corridor_runtime_case(
        intervening_clobber=False,
    )
    dispatcher = mba.get_mblock(3)
    assert dispatcher is not None
    first_writer = _Instruction(ida_hexrays.m_mov, 0x401030)
    first_writer.d.writes_ccflags = True
    second_writer = _Instruction(ida_hexrays.m_mov, 0x401030)
    second_writer.d.writes_cc = True
    _set_block_instructions(dispatcher, first_writer, second_writer)
    root_inventory = modifier._plan_semantic_fragment_root_publication_inventory(plan)
    gateway._begin_semantic_fragment_batch(modifier, plan, root_inventory)

    with pytest.raises(
        sfb.SemanticFragmentBackendRejected,
        match="condition-code writer is ambiguous at dispatcher@0x401030",
    ):
        modifier._stage_semantic_fragment(plan)

    assert modifier._semantic_fragment_state is None
    assert mba.qty == 5
    assert tuple(entry.succset) == (original.serial,)
    gateway.abort(reason="runtime duplicate flag writer cleanup")


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
    gateway = make_mutation_gateway(mba)
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
                | int(
                    ida_hexrays.VR_AT_END
                    if at_end
                    else ida_hexrays.VR_AT_START
                ),
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
        and outcome.postcondition
        is FragmentValidationPostcondition.VALUE_RANGE_PROVEN
        for outcome in receipt.prepublication_validation.outcomes
    )
    assert any(
        outcome.passed
        and outcome.postcondition
        is FragmentValidationPostcondition.VALUE_RANGE_PROVEN
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
    gateway = make_mutation_gateway(mba)
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
    assert receipt.operation_count == 3
    assert receipt.planned_operation_count == 3
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
    gateway = make_mutation_gateway(mba)
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


@pytest.mark.parametrize("fail_after_root_write", (False, True))
def test_gateway_publishes_conditional_fallthrough_fragment_root(
    monkeypatch,
    fail_after_root_write: bool,
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
    gateway = make_mutation_gateway(mba)
    modifier = dm.DeferredGraphModifier(mba, mutation_gateway=gateway)
    monkeypatch.setattr(dm, "insert_goto_instruction", _insert_fake_goto_instruction)
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
