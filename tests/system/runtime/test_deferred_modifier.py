from __future__ import annotations

import logging
import os
import platform
from types import SimpleNamespace

import ida_hexrays
import pytest

from d810.hexrays.contracts.cfg_contract import CfgContractViolationError
from d810.hexrays.mutation import cfg_mutations
from d810.hexrays.mutation import semantic_fragment_backend as sfb
from d810.hexrays.ir.mba_identity_index import MbaBlockIdentityIndex
from d810.hexrays.mutation.mba_mutation_events import (
    MbaMutationGateway,
    StructuralMutationKind,
)
from d810.ir.block_identity import (
    BlockHandleProvenance,
    NativeEaInterval,
    StableBlockIdentity,
)
from d810.transforms.report import InvariantViolation
from d810.ir.flowgraph import InsnSnapshot
from d810.transforms.cfg_transaction import PlanBlockRef, TransactionAttemptId
from d810.transforms.fragment_plan import FragmentTerminalReturn
from d810.hexrays.mutation import deferred_modifier as dm
from tests.system.runtime.conftest import gen_microcode_at_maturity, get_func_ea
from tests.native_preanalysis import make_native_key
from tests.system.runtime.mutation_gateway import make_mutation_gateway

NATIVE_KEY = make_native_key()


def _seed_current_serials(
    modifier: dm.DeferredGraphModifier,
    bindings: dict[int, int],
) -> None:
    """Seed planned-to-current bindings through the mutation gateway."""
    modifier._begin_mutation_batch(
        serial_quantity=max(
            int(getattr(modifier.mba, "qty", 0) or 0),
            *(int(serial) + 1 for serial in bindings),
        )
    )
    for expected_serial, current_serial in bindings.items():
        gateway = modifier._mutation_gateway
        assert gateway is not None
        gateway.record_realized_serial(
            expected_serial=expected_serial,
            returned_serial=current_serial,
        )


@pytest.mark.ida_required
class TestRealTerminalCompensation:
    binary_name = (
        "libobfuscated.dylib"
        if platform.system() == "Darwin"
        else "libobfuscated.dll"
    )

    def test_restores_owned_return_copy(self, libobfuscated_setup) -> None:
        """Never retain or dereference a removed SWIG instruction."""
        func_ea = get_func_ea("test_cst_simplification")
        mba = gen_microcode_at_maturity(func_ea, ida_hexrays.MMAT_PREOPTIMIZED)
        assert mba is not None
        mba.build_graph()
        stop = mba.get_mblock(int(mba.qty) - 1)
        assert stop is not None and int(stop.type) == int(ida_hexrays.BLT_STOP)
        block = mba.get_mblock(0)
        assert block is not None
        original_successors = tuple(int(value) for value in block.succset)
        tail = block.tail
        if tail is not None and (
            ida_hexrays.is_mcode_jcond(int(tail.opcode))
            or int(tail.opcode)
            in {
                int(ida_hexrays.m_goto),
                int(ida_hexrays.m_ijmp),
                int(ida_hexrays.m_jtbl),
                int(ida_hexrays.m_ret),
            }
        ):
            block.remove_from_block(tail)
        del tail
        for successor in original_successors:
            target = mba.get_mblock(successor)
            assert target is not None
            sfb._replace_serial_collection(
                target.predset,
                tuple(
                    int(value)
                    for value in target.predset
                    if int(value) != int(block.serial)
                ),
            )
        prefix_ea = int(mba.alloc_fict_ea(int(mba.entry_ea)))
        prefix_instruction = ida_hexrays.minsn_t(prefix_ea)
        prefix_instruction.opcode = int(ida_hexrays.m_nop)
        prefix_instruction.l.erase()
        prefix_instruction.r.erase()
        prefix_instruction.d.erase()
        block.insert_into_block(prefix_instruction, block.tail)
        terminal_ea = int(mba.alloc_fict_ea(int(mba.entry_ea)))
        terminal_instruction = ida_hexrays.minsn_t(terminal_ea)
        terminal_instruction.opcode = int(ida_hexrays.m_ret)
        terminal_instruction.l.erase()
        terminal_instruction.r.erase()
        terminal_instruction.d.erase()
        block.insert_into_block(terminal_instruction, block.tail)
        block.type = int(ida_hexrays.BLT_0WAY)
        block.succset.clear()
        stop_predecessors_without_terminal = tuple(
            int(value)
            for value in stop.predset
            if int(value) != int(block.serial)
        )
        sfb._replace_serial_collection(
            stop.predset,
            stop_predecessors_without_terminal,
        )
        block.mark_lists_dirty()
        stop.mark_lists_dirty()
        mba.mark_chains_dirty()
        tail = block.tail
        assert tail is not None and int(tail.opcode) == int(ida_hexrays.m_ret)
        tail_copy = ida_hexrays.minsn_t(tail)
        block_type = int(block.type)
        successors = tuple(int(value) for value in block.succset)
        stop_predecessors = tuple(int(value) for value in stop.predset)
        del tail

        terminal = FragmentTerminalReturn(
            return_id="real-runtime-terminal-compensation",
            block_id="runtime-terminal",
            instruction_ea=terminal_ea,
            return_width=4,
        )
        snapshot = sfb._SemanticCommitFinalizationSnapshot(
            instruction_addresses=(),
            instruction_origins_by_block_id=(
                ("runtime-terminal", ((terminal_ea, terminal_ea),)),
            ),
            predicate_live_eas_by_operation_id=(),
            constant_materialization_rollbacks=(),
            terminals=(
                sfb._SemanticTerminalFinalizationSnapshot(
                    terminal=terminal,
                    block=block,
                    tail_copy=tail_copy,
                    live_ea=terminal_ea,
                    block_type=block_type,
                    successors=successors,
                ),
            ),
            stop=stop,
            stop_predecessors=stop_predecessors,
        )
        state = SimpleNamespace(
            instruction_origins_by_block_id={
                "runtime-terminal": {terminal_ea: terminal_ea}
            },
            predicate_live_eas_by_operation_id={},
            constant_materialization_rollbacks=[],
        )
        modifier = SimpleNamespace(mba=mba)
        modifier._restore_semantic_terminal_finalization_now = lambda **kwargs: (
            dm.DeferredGraphModifier._restore_semantic_terminal_finalization_now(
                modifier,
                **kwargs,
            )
        )
        modifier._restore_semantic_stop_finalization_now = lambda **kwargs: (
            dm.DeferredGraphModifier._restore_semantic_stop_finalization_now(
                modifier,
                **kwargs,
            )
        )

        assert cfg_mutations.canonicalize_explicit_return_to_stop_edge(block, stop)
        assert block.tail is not None
        assert int(block.tail.ea) == prefix_ea
        assert int(block.tail.opcode) == int(ida_hexrays.m_nop)
        sfb._restore_semantic_commit_finalization(modifier, state, snapshot)

        assert block.tail is not None
        assert int(block.tail.ea) == terminal_ea
        assert int(block.tail.opcode) == int(ida_hexrays.m_ret)
        assert int(block.type) == block_type
        assert tuple(int(value) for value in block.succset) == successors
        assert tuple(int(value) for value in stop.predset) == stop_predecessors
        assert cfg_mutations.canonicalize_explicit_return_to_stop_edge(block, stop)
        assert block.tail is not None
        assert int(block.tail.ea) == prefix_ea
        assert int(block.tail.opcode) == int(ida_hexrays.m_nop)
        assert tuple(int(value) for value in block.succset) == (int(stop.serial),)


class _FakeEdgeSet:
    """Minimal stub for IDA succset/predset (intvec_t-like interface)."""

    def __init__(self, items: list[int] | None = None):
        self._items: list[int] = list(items) if items else []

    def size(self) -> int:
        return len(self._items)

    def __getitem__(self, idx: int) -> int:
        return self._items[idx]

    def __iter__(self):
        return iter(list(self._items))

    def clear(self) -> None:
        self._items.clear()

    def push_back(self, val: int) -> None:
        self._items.append(val)

    def _del(self, val: int) -> None:
        try:
            self._items.remove(val)
        except ValueError:
            return None


class _FakeBlock:
    # Base EA for deriving stable start addresses for fake blocks.  The
    # staged_atomic Bug 3 fix re-resolves blocks by ``mblock_t.start``
    # (the block's byte-address range start, which IDA guarantees is
    # stable across serial-shifting mutations).  Every fake block now
    # has a default ``start`` derived from its initial serial.
    _DEFAULT_EA_BASE = 0x18000000

    def __init__(self, serial: int, *, start: int | None = None):
        self.serial = serial
        self.type = ida_hexrays.BLT_1WAY
        self.flags = 0
        self.head = None
        self.tail = SimpleNamespace(
            opcode=ida_hexrays.m_goto, ea=0x1000, l=None, d=None, r=None
        )
        self.succset = _FakeEdgeSet()
        self.predset = _FakeEdgeSet()
        self.prevb = None
        # Stable byte-address range start (see class docstring).
        self.start = (
            start if start is not None else self._DEFAULT_EA_BASE + serial * 0x100
        )
        self.end = self.start + 0x100

    def nsucc(self) -> int:
        return 1

    def succ(self, _idx: int) -> int:
        return 0

    def npred(self) -> int:
        return 0

    def pred(self, _idx: int) -> int:
        return 0

    def mark_lists_dirty(self) -> None:
        return None


class _FakeMBA:
    def __init__(self):
        self.blocks = {0: _FakeBlock(0)}
        self.cleaned = 0
        self.marked_dirty = 0
        self.qty = len(self.blocks)
        self.entry_ea = 0x180000000

    def get_mblock(self, serial: int):
        return self.blocks.get(serial)

    @staticmethod
    def map_fict_ea(ea: int) -> int:
        return int(ea)

    def mark_chains_dirty(self):
        self.marked_dirty += 1

    def optimize_local(self, _flags: int):
        pass

    def insert_block(self, insertion_serial: int):
        insertion_serial = int(insertion_serial)
        for block in tuple(self.blocks.values()):
            if int(block.serial) >= insertion_serial:
                block.serial += 1
        helper = _FakeBlock(insertion_serial, start=self.entry_ea)
        helper.mba = self
        helper.head = None
        helper.tail = None
        helper.type = int(ida_hexrays.BLT_0WAY)
        helper.nsucc = lambda: 0  # type: ignore[method-assign]
        helper.npred = lambda: 0  # type: ignore[method-assign]
        self.blocks = {int(block.serial): block for block in self.blocks.values()}
        self.blocks[insertion_serial] = helper
        self.qty += 1
        return helper


def test_modifier_uses_an_injected_session_mutation_gateway() -> None:
    mba = _FakeMBA()
    gateway = make_mutation_gateway(mba)

    modifier = dm.DeferredGraphModifier(mba, mutation_gateway=gateway)
    modifier._begin_mutation_batch(serial_quantity=mba.qty)

    assert modifier._mutation_gateway is gateway
    assert gateway.active is True


def test_exact_constant_replacement_preserves_destination_and_rolls_back(
    monkeypatch,
) -> None:
    """The central instruction edit is exact, in-place, and reversible."""
    mop_z = int(ida_hexrays.mop_z)
    mop_n = int(ida_hexrays.mop_n)
    m_ldx = int(ida_hexrays.m_ldx)
    m_mov = int(ida_hexrays.m_mov)

    class FakeMop:
        def __init__(self, kind=mop_z, *, value=0, size=0):
            self.t = int(kind)
            self.nnn = SimpleNamespace(value=int(value))
            self.size = int(size)

        def make_number(self, value, size, _ea):
            self.t = mop_n
            self.nnn.value = int(value)
            self.size = int(size)

        def erase(self):
            self.t = mop_z
            self.nnn.value = 0
            self.size = 0

        def assign(self, other):
            self.t = int(other.t)
            self.nnn.value = int(other.nnn.value)
            self.size = int(other.size)

    class FakeInsn:
        def __init__(self, source=None):
            if source is None:
                self.ea = 0x401234
                self.opcode = m_ldx
                self.iprops = 7
                self.l = FakeMop(ida_hexrays.mop_r, size=2)
                self.r = FakeMop(ida_hexrays.mop_r, size=4)
                self.d = FakeMop(ida_hexrays.mop_r, size=4)
            else:
                self.ea = int(source.ea)
                self.opcode = int(source.opcode)
                self.iprops = int(source.iprops)
                self.l = FakeMop()
                self.r = FakeMop()
                self.d = FakeMop()
                self.l.assign(source.l)
                self.r.assign(source.r)
                self.d.assign(source.d)
            self.next = None

    target = FakeInsn()
    block = _FakeBlock(0, start=0x401200)
    block.head = block.tail = target
    mba = _FakeMBA()
    mba.blocks = {0: block}
    monkeypatch.setattr(dm.ida_hexrays, "minsn_t", FakeInsn)
    modifier = dm.DeferredGraphModifier(mba)

    original = modifier.replace_instruction_with_constant_now(
        block,
        instruction_index=0,
        expected_ea=0x401234,
        expected_opcode=m_ldx,
        constant_value=0x3776723F,
        value_size=4,
    )

    assert int(target.opcode) == m_mov
    assert (int(target.l.t), int(target.l.nnn.value), int(target.l.size)) == (
        mop_n,
        0x3776723F,
        4,
    )
    assert int(target.r.t) == mop_z
    assert (int(target.d.t), int(target.d.size)) == (
        int(ida_hexrays.mop_r),
        4,
    )
    modifier.restore_instruction_from_snapshot_now(
        block,
        instruction_index=0,
        expected_ea=0x401234,
        expected_opcode=m_mov,
        original=original,
    )
    assert int(target.opcode) == m_ldx
    assert int(target.iprops) == 7
    assert (int(target.l.t), int(target.l.size)) == (
        int(ida_hexrays.mop_r),
        2,
    )
    assert (int(target.r.t), int(target.r.size)) == (
        int(ida_hexrays.mop_r),
        4,
    )
    assert (int(target.d.t), int(target.d.size)) == (
        int(ida_hexrays.mop_r),
        4,
    )


def test_exact_left_operand_constant_replacement_preserves_xor_and_rolls_back(
    monkeypatch,
) -> None:
    """The typed byte-XOR edit replaces only the proved global operand."""
    mop_z = int(ida_hexrays.mop_z)
    mop_n = int(ida_hexrays.mop_n)
    mop_r = int(ida_hexrays.mop_r)
    m_xor = int(ida_hexrays.m_xor)

    class FakeMop:
        def __init__(self, kind=mop_z, *, value=0, size=0):
            self.t = int(kind)
            self.nnn = SimpleNamespace(value=int(value))
            self.g = int(value)
            self.size = int(size)

        def make_number(self, value, size, _ea):
            self.t = mop_n
            self.nnn.value = int(value)
            self.size = int(size)

        def assign(self, other):
            self.t = int(other.t)
            self.nnn.value = int(other.nnn.value)
            self.g = int(other.g)
            self.size = int(other.size)

    class FakeInsn:
        def __init__(self, source=None):
            if source is None:
                self.ea = 0x40C322
                self.opcode = m_xor
                self.iprops = 11
                self.l = FakeMop(ida_hexrays.mop_v, value=0x48AEC8, size=1)
                self.r = FakeMop(mop_r, value=8, size=1)
                self.d = FakeMop(mop_r, value=8, size=1)
            else:
                self.ea = int(source.ea)
                self.opcode = int(source.opcode)
                self.iprops = int(source.iprops)
                self.l = FakeMop()
                self.r = FakeMop()
                self.d = FakeMop()
                self.l.assign(source.l)
                self.r.assign(source.r)
                self.d.assign(source.d)
            self.next = None

    target = FakeInsn()
    block = _FakeBlock(0, start=0x40C315)
    block.head = block.tail = target
    mba = _FakeMBA()
    mba.blocks = {0: block}
    monkeypatch.setattr(dm.ida_hexrays, "minsn_t", FakeInsn)
    modifier = dm.DeferredGraphModifier(mba)

    original = modifier.replace_instruction_left_global_with_constant_now(
        block,
        instruction_index=0,
        expected_ea=0x40C322,
        expected_opcode=m_xor,
        expected_data_ea=0x48AEC8,
        constant_value=1,
        value_size=1,
    )

    assert int(target.opcode) == m_xor
    assert (int(target.l.t), int(target.l.nnn.value), int(target.l.size)) == (
        mop_n,
        1,
        1,
    )
    assert (int(target.r.t), int(target.r.nnn.value), int(target.r.size)) == (
        mop_r,
        8,
        1,
    )
    assert (int(target.d.t), int(target.d.nnn.value), int(target.d.size)) == (
        mop_r,
        8,
        1,
    )
    modifier.restore_instruction_from_snapshot_now(
        block,
        instruction_index=0,
        expected_ea=0x40C322,
        expected_opcode=m_xor,
        original=original,
    )
    assert int(target.opcode) == m_xor
    assert int(target.l.t) == int(ida_hexrays.mop_v)
    assert int(target.l.g) == 0x48AEC8
    assert int(target.l.size) == 1


def test_constant_replacement_rejects_a_changed_preflight_anchor() -> None:
    target = SimpleNamespace(
        ea=0x401235,
        opcode=ida_hexrays.m_ldx,
        next=None,
    )
    block = _FakeBlock(0, start=0x401200)
    block.head = block.tail = target
    modifier = dm.DeferredGraphModifier(_FakeMBA())

    with pytest.raises(ValueError, match="changed after immutable preflight"):
        modifier.replace_instruction_with_constant_now(
            block,
            instruction_index=0,
            expected_ea=0x401234,
            expected_opcode=ida_hexrays.m_ldx,
            constant_value=1,
            value_size=4,
        )


def test_standalone_native_block_is_published_to_the_injected_identity_index(
    monkeypatch,
) -> None:
    mba = _FakeMBA()
    existing_identity = StableBlockIdentity.from_intervals(
        (NativeEaInterval(0x180000000, 0x180000100),), native_key=NATIVE_KEY
    )
    imported_identity = StableBlockIdentity.from_intervals(
        (NativeEaInterval(0x40EAA7, 0x40EAB0),), native_key=NATIVE_KEY
    )
    index = MbaBlockIdentityIndex.from_bindings(
        generation=0,
        bindings=((existing_identity, 0),),
        session_id="sample.i64:0x180000000:1",
        native_key=NATIVE_KEY,
    )
    gateway = MbaMutationGateway(
        session_id=index.session_id,
        function_ea=mba.entry_ea,
        maturity=4,
        identity_index=index,
        native_key=NATIVE_KEY,
    )

    def create_block(**_kwargs):
        assert gateway.active is True
        block = _FakeBlock(1, start=0x40EAA7)
        mba.blocks[1] = block
        mba.qty = 2
        return block

    monkeypatch.setattr(dm, "create_standalone_block", create_block)
    modifier = dm.DeferredGraphModifier(mba, mutation_gateway=gateway)

    serial = modifier.create_standalone_block(
        ref_serial=0,
        is_0_way=True,
        verify=False,
        stable_identity=imported_identity,
        handle_provenance=BlockHandleProvenance.IMPORTED_NATIVE,
    )
    modifier.commit_immediate_mutations()

    assert serial == 1
    rebound = index.rebind_identity(imported_identity)
    assert rebound.block is not None
    assert rebound.block.serial == 1
    assert rebound.block.handle.provenance is BlockHandleProvenance.IMPORTED_NATIVE
    assert len(gateway.receipts) == 1
    assert gateway.receipts[0].operation_count == 1


def test_standalone_block_fails_closed_before_sdk_write_without_gateway(
    monkeypatch,
) -> None:
    mba = _FakeMBA()
    sdk_calls = 0

    def create_block(**_kwargs):
        nonlocal sdk_calls
        sdk_calls += 1
        return _FakeBlock(1)

    monkeypatch.setattr(dm, "create_standalone_block", create_block)

    with pytest.raises(
        RuntimeError,
        match="structural mutation requires a coordinator-owned gateway",
    ):
        dm.DeferredGraphModifier(mba).create_standalone_block(
            ref_serial=0,
            is_0_way=True,
            verify=False,
        )

    assert sdk_calls == 0


def test_failed_standalone_block_aborts_the_prewrite_gateway_batch(monkeypatch) -> None:
    mba = _FakeMBA()
    gateway = make_mutation_gateway(mba)

    def create_block(**_kwargs):
        assert gateway.active is True
        return None

    monkeypatch.setattr(dm, "create_standalone_block", create_block)
    modifier = dm.DeferredGraphModifier(mba, mutation_gateway=gateway)

    assert (
        modifier.create_standalone_block(
            ref_serial=0,
            is_0_way=True,
            verify=False,
        )
        is None
    )
    assert gateway.active is False
    assert gateway.receipts == ()


def test_insert_nop_block_opens_gateway_batch_before_sdk_write(monkeypatch) -> None:
    mba = _FakeMBA()
    gateway = make_mutation_gateway(mba)

    def insert_block(_source, *, force_adjacent):
        assert gateway.active is True
        assert force_adjacent is True
        block = _FakeBlock(1)
        mba.blocks[1] = block
        mba.qty = 2
        return block

    monkeypatch.setattr(dm, "insert_nop_blk", insert_block)
    modifier = dm.DeferredGraphModifier(mba, mutation_gateway=gateway)

    assert modifier.insert_nop_block_now(0, force_adjacent=True) == 1
    modifier.commit_immediate_mutations()

    assert len(gateway.receipts) == 1
    assert gateway.receipts[0].operation_count == 1


def test_insert_nop_block_fails_closed_before_sdk_write_without_gateway(
    monkeypatch,
) -> None:
    mba = _FakeMBA()
    sdk_calls = 0

    def insert_block(_source, *, force_adjacent):
        nonlocal sdk_calls
        sdk_calls += 1
        return _FakeBlock(1)

    monkeypatch.setattr(dm, "insert_nop_blk", insert_block)

    with pytest.raises(
        RuntimeError,
        match="structural mutation requires a coordinator-owned gateway",
    ):
        dm.DeferredGraphModifier(mba).insert_nop_block_now(0)

    assert sdk_calls == 0


def test_immediate_redirect_is_receipted_through_prewrite_gateway(monkeypatch) -> None:
    mba = _FakeMBA()
    gateway = make_mutation_gateway(mba)

    def redirect(_source, target_serial, *, verify):
        assert gateway.active is True
        assert target_serial == 0
        assert verify is False
        return True

    monkeypatch.setattr(dm, "change_1way_block_successor", redirect)
    modifier = dm.DeferredGraphModifier(mba, mutation_gateway=gateway)

    assert modifier.redirect_one_way_now(0, 0, verify=False) is True
    modifier.commit_immediate_mutations()

    assert len(gateway.receipts) == 1
    assert gateway.receipts[0].operation_count == 1
    assert gateway.receipts[0].kind is StructuralMutationKind.EDGE_REDIRECT


def test_split_block_replaces_original_handle_and_receipts_one_split() -> None:
    mba = _FakeMBA()
    gateway = make_mutation_gateway(mba)
    original = gateway.identity_index.handle_for_serial(0)
    assert original is not None
    source = mba.get_mblock(0)
    split_point = object()

    def split_block(block, start_insn):
        assert gateway.active is True
        assert block is source
        assert start_insn is split_point
        tail = _FakeBlock(1)
        mba.blocks[1] = tail
        mba.qty = 2
        return tail

    mba.split_block = split_block
    modifier = dm.DeferredGraphModifier(mba, mutation_gateway=gateway)

    tail = modifier.split_block_now(source, split_point)

    assert tail is mba.get_mblock(1)
    assert gateway.identity_index.resolve(original) is None
    retained = gateway.identity_index.handle_for_serial(0)
    created_tail = gateway.identity_index.handle_for_serial(1)
    assert retained is not None and retained is not original
    assert created_tail is not None and created_tail is not original
    assert retained is not created_tail
    assert len(gateway.receipts) == 1
    assert gateway.receipts[0].kind is StructuralMutationKind.BLOCK_REPLACE
    assert gateway.receipts[0].operation_count == 1


def test_split_block_partitions_exact_native_identity_when_provable() -> None:
    mba = _FakeMBA()
    source = mba.get_mblock(0)
    first = SimpleNamespace(ea=0x401000, next=None)
    second = SimpleNamespace(ea=0x401004, next=None)
    first.next = second
    source.head = first
    source.tail = second
    gateway = make_mutation_gateway(mba)

    def split_block(block, start_insn):
        assert block is source
        assert start_insn is second
        first.next = None
        source.tail = first
        tail = _FakeBlock(1)
        tail.head = second
        tail.tail = second
        mba.blocks[1] = tail
        mba.qty = 2
        return tail

    mba.split_block = split_block
    modifier = dm.DeferredGraphModifier(mba, mutation_gateway=gateway)

    assert modifier.split_block_now(source, second) is mba.get_mblock(1)

    retained = gateway.identity_index.handle_for_serial(0)
    tail = gateway.identity_index.handle_for_serial(1)
    assert retained is not None and retained.stable_identity is not None
    assert tail is not None and tail.stable_identity is not None
    assert retained.stable_identity.exact_instruction_eas == frozenset({0x401000})
    assert tail.stable_identity.exact_instruction_eas == frozenset({0x401004})


def test_zero_way_existing_goto_is_retargeted_without_appending(monkeypatch) -> None:
    class _Operand:
        def __init__(self) -> None:
            self.block_serial: int | None = None

        def make_blkref(self, serial: int) -> None:
            self.block_serial = int(serial)

    class _Mba:
        def __init__(self) -> None:
            self.qty = 3
            self.marked_dirty = False
            self.blocks: dict[int, object] = {}

        def get_mblock(self, serial: int) -> object | None:
            return self.blocks.get(int(serial))

        def mark_chains_dirty(self) -> None:
            self.marked_dirty = True

    class _Block:
        def __init__(self, mba: _Mba, serial: int) -> None:
            self.mba = mba
            self.serial = int(serial)
            self.type = ida_hexrays.BLT_0WAY
            self.flags = 0
            self.succset = _FakeEdgeSet()
            self.predset = _FakeEdgeSet()
            self.tail = SimpleNamespace(
                opcode=ida_hexrays.m_goto,
                l=_Operand(),
            )
            self.lists_dirty = False

        def nsucc(self) -> int:
            return self.succset.size()

        def mark_lists_dirty(self) -> None:
            self.lists_dirty = True

    mba = _Mba()
    source = _Block(mba, 1)
    target = _Block(mba, 2)
    mba.blocks = {1: source, 2: target}

    def _unexpected_insert(*_args, **_kwargs) -> None:
        raise AssertionError("an existing m_goto must be retargeted in place")

    monkeypatch.setattr(cfg_mutations, "insert_goto_instruction", _unexpected_insert)

    assert cfg_mutations.change_0way_block_successor(source, 2, verify=False)
    assert source.tail.l.block_serial == 2
    assert tuple(source.succset) == (2,)
    assert tuple(target.predset) == (1,)
    assert source.type == ida_hexrays.BLT_1WAY
    assert source.flags & ida_hexrays.MBL_GOTO
    assert mba.marked_dirty is True


def test_materialize_zero_way_goto_replaces_predicate_and_binds_edge(
    monkeypatch,
) -> None:
    """A generated predicate and its direct route form one exact mutation."""
    mba = _FakeMBA()
    source = _FakeBlock(3, start=0x40A7AE)
    source.tail = SimpleNamespace(
        ea=0x40A7DF,
        opcode=ida_hexrays.m_jnz,
        d=SimpleNamespace(t=ida_hexrays.mop_v),
    )
    source.succset = _FakeEdgeSet()
    source.nsucc = lambda: 0  # type: ignore[assignment]
    target = _FakeBlock(9, start=0x40BCAF)
    mba.blocks = {3: source, 9: target}
    mba.qty = 10
    inserted: list[tuple[int, int, bool, int | None]] = []

    def _insert_goto(
        block,
        target_serial,
        *,
        nop_previous_instruction,
        instruction_ea=None,
    ):
        inserted.append(
            (
                int(block.serial),
                int(target_serial),
                bool(nop_previous_instruction),
                None if instruction_ea is None else int(instruction_ea),
            )
        )
        block.tail = SimpleNamespace(
            ea=int(instruction_ea),
            opcode=ida_hexrays.m_goto,
            l=SimpleNamespace(t=ida_hexrays.mop_b, b=int(target_serial)),
        )

    monkeypatch.setattr(dm, "insert_goto_instruction", _insert_goto)
    modifier = dm.DeferredGraphModifier(mba)

    assert modifier._apply_materialize_zero_way_goto(
        source,
        predicate_ea=0x40A7DF,
        target_serial=9,
    )
    assert inserted == [(3, 9, True, 0x40A7DF)]
    assert source.tail.opcode == ida_hexrays.m_goto
    assert source.type == ida_hexrays.BLT_1WAY
    assert source.flags & ida_hexrays.MBL_GOTO
    assert source.succset._items == [9]
    assert target.predset._items == [3]

    indirect_source = _FakeBlock(4, start=0x40B469)
    indirect_source.tail = SimpleNamespace(
        ea=0x40B49E,
        opcode=ida_hexrays.m_call,
        d=SimpleNamespace(t=ida_hexrays.mop_z),
    )
    indirect_source.succset = _FakeEdgeSet()
    indirect_source.nsucc = lambda: 0  # type: ignore[assignment]
    indirect_source.flags = ida_hexrays.MBL_CALL
    indirect_target = _FakeBlock(10, start=0x40C592)
    mba.blocks.update({4: indirect_source, 10: indirect_target})

    assert modifier._apply_materialize_zero_way_goto(
        indirect_source,
        predicate_ea=0x40B49E,
        target_serial=10,
    )
    assert inserted[-1] == (4, 10, True, 0x40B49E)
    assert indirect_source.tail.opcode == ida_hexrays.m_goto
    assert not indirect_source.flags & ida_hexrays.MBL_CALL
    assert indirect_source.succset._items == [10]
    assert indirect_target.predset._items == [4]


def test_queue_materialize_zero_way_goto_keeps_predicate_identity() -> None:
    mba = _FakeMBA()
    modifier = dm.DeferredGraphModifier(mba)

    modifier.queue_materialize_zero_way_goto(
        source_serial=3,
        predicate_ea=0x40A7DF,
        target_serial=9,
        rule_priority=100,
    )

    assert len(modifier.modifications) == 1
    modification = modifier.modifications[0]
    assert modification.mod_type is dm.ModificationType.MATERIALIZE_ZERO_WAY_GOTO
    assert modification.block_serial == 3
    assert modification.rewrite_from_ea == 0x40A7DF
    assert modification.new_target == 9
    assert modification.rule_priority == 100


def test_apply_aborts_on_first_failed_modification_and_cleans(monkeypatch):
    mba = _FakeMBA()
    modifier = dm.DeferredGraphModifier(
        mba, mutation_gateway=make_mutation_gateway(mba)
    )
    modifier.modifications = [
        dm.QueuedModification(
            dm.ModificationType.BLOCK_GOTO_CHANGE, block_serial=0, new_target=1
        ),
        dm.QueuedModification(
            dm.ModificationType.INSN_NOP, block_serial=0, insn_ea=0x1000
        ),
        dm.QueuedModification(
            dm.ModificationType.INSN_REMOVE, block_serial=0, insn_ea=0x1001
        ),
    ]

    calls: list[int] = []

    def _fake_apply_single(_mod):
        calls.append(1)
        # first succeeds, second fails -> must abort before third
        return len(calls) == 1

    monkeypatch.setattr(modifier, "_apply_single", _fake_apply_single)
    monkeypatch.setattr(dm, "_format_block_info", lambda _blk: "<blk>")
    monkeypatch.setattr(dm, "safe_verify", lambda *_a, **_k: None)
    monkeypatch.setattr(
        dm,
        "mba_deep_cleaning",
        lambda *_a, **_k: setattr(mba, "cleaned", mba.cleaned + 1),
    )

    applied = modifier.apply(run_optimize_local=False, run_deep_cleaning=False)
    assert applied == 1
    assert len(calls) == 2
    assert mba.cleaned == 1


def test_apply_orders_conditional_block_insertions_by_descending_source(
    monkeypatch,
):
    """Later-source helper insertion must not drift an earlier source serial."""
    mba = _FakeMBA()
    mba.blocks = {
        10: _FakeBlock(10, start=0x40DD15),
        20: _FakeBlock(20, start=0x40DE51),
    }
    mba.qty = 30
    modifier = dm.DeferredGraphModifier(
        mba, mutation_gateway=make_mutation_gateway(mba)
    )
    modifier.modifications = [
        dm.QueuedModification(
            dm.ModificationType.LOWER_CONDITIONAL_STATE_TRANSITION,
            block_serial=10,
            new_target=25,
            old_target=22,
            false_target=24,
            true_target=25,
            rewrite_from_ea=0x40DD38,
        ),
        dm.QueuedModification(
            dm.ModificationType.LOWER_CONDITIONAL_STATE_TRANSITION,
            block_serial=20,
            new_target=27,
            old_target=22,
            false_target=26,
            true_target=27,
            rewrite_from_ea=0x40DE69,
        ),
    ]
    applied_sources: list[int] = []

    monkeypatch.setattr(
        modifier,
        "_apply_single",
        lambda mod: applied_sources.append(int(mod.block_serial)) or True,
    )
    monkeypatch.setattr(dm, "_format_block_info", lambda _blk: "<blk>")
    monkeypatch.setattr(dm, "safe_verify", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(dm, "mba_deep_cleaning", lambda *_args, **_kwargs: None)

    assert modifier.apply(run_optimize_local=False, run_deep_cleaning=False) == 2
    assert applied_sources == [20, 10]


def test_apply_transactional_rolls_back_when_mid_batch_aborts(monkeypatch):
    """transactional=True must restore pre-snapshot if the loop breaks early.

    Non-transactional apply returns the partial count (1/3) and leaves the
    first mutation live on the MBA. Transactional apply on the same scenario
    must invoke the snapshot restore path and return 0.
    """
    mba = _FakeMBA()
    modifier = dm.DeferredGraphModifier(
        mba, mutation_gateway=make_mutation_gateway(mba)
    )
    modifier.modifications = [
        dm.QueuedModification(
            dm.ModificationType.BLOCK_GOTO_CHANGE, block_serial=0, new_target=1
        ),
        dm.QueuedModification(
            dm.ModificationType.INSN_NOP, block_serial=0, insn_ea=0x1000
        ),
        dm.QueuedModification(
            dm.ModificationType.INSN_REMOVE, block_serial=0, insn_ea=0x1001
        ),
    ]

    calls: list[int] = []

    def _fake_apply_single(_mod):
        calls.append(1)
        return len(calls) == 1

    restore_calls: list[object] = []

    def _fake_restore(_snap):
        restore_calls.append(_snap)
        return True

    monkeypatch.setattr(modifier, "_apply_single", _fake_apply_single)
    monkeypatch.setattr(modifier, "_restore_from_snapshot", _fake_restore)
    monkeypatch.setattr(dm, "_format_block_info", lambda _blk: "<blk>")
    monkeypatch.setattr(dm, "safe_verify", lambda *_a, **_k: None)
    monkeypatch.setattr(dm, "mba_deep_cleaning", lambda *_a, **_k: None)
    monkeypatch.setattr(
        dm, "lift", lambda _m: SimpleNamespace(num_blocks=1, entry_serial=0)
    )

    applied = modifier.apply(
        run_optimize_local=False,
        run_deep_cleaning=False,
        transactional=True,
    )
    assert applied == 0
    assert len(calls) == 2
    assert len(restore_calls) == 1


def test_apply_transactional_returns_full_count_when_all_mods_succeed(monkeypatch):
    """transactional=True must return the full applied count on success.

    No rollback should fire when every queued mod lands cleanly.
    """
    mba = _FakeMBA()
    modifier = dm.DeferredGraphModifier(
        mba, mutation_gateway=make_mutation_gateway(mba)
    )
    modifier.modifications = [
        dm.QueuedModification(
            dm.ModificationType.BLOCK_GOTO_CHANGE, block_serial=0, new_target=1
        ),
        dm.QueuedModification(
            dm.ModificationType.INSN_NOP, block_serial=0, insn_ea=0x1000
        ),
    ]

    restore_calls: list[object] = []

    monkeypatch.setattr(modifier, "_apply_single", lambda _mod: True)
    monkeypatch.setattr(
        modifier,
        "_restore_from_snapshot",
        lambda snap: restore_calls.append(snap) or True,
    )
    monkeypatch.setattr(dm, "_format_block_info", lambda _blk: "<blk>")
    monkeypatch.setattr(dm, "safe_verify", lambda *_a, **_k: None)
    monkeypatch.setattr(dm, "mba_deep_cleaning", lambda *_a, **_k: None)
    monkeypatch.setattr(
        dm, "lift", lambda _m: SimpleNamespace(num_blocks=1, entry_serial=0)
    )

    applied = modifier.apply(
        run_optimize_local=False,
        run_deep_cleaning=False,
        transactional=True,
    )
    assert applied == 2
    assert restore_calls == []


def test_apply_transactional_rejects_batch_with_contradictory_redirects(monkeypatch):
    """transactional=True must reject a batch where two BLOCK_GOTO_CHANGE
    mods on the same source block prescribe different targets.

    This is the Mode 1 pattern we observed on sub_7FFD3338C040:
        mod[26]: RedirectGoto src=76 tgt=11
        mod[75]: RedirectGoto src=76 tgt=2
    Both succeed individually; the pair cancels. The gate catches it
    before any live mutation so verify_failed is set and apply loop is
    never entered.
    """
    mba = _FakeMBA()
    modifier = dm.DeferredGraphModifier(
        mba, mutation_gateway=make_mutation_gateway(mba)
    )
    modifier.modifications = [
        dm.QueuedModification(
            dm.ModificationType.BLOCK_GOTO_CHANGE, block_serial=76, new_target=11
        ),
        dm.QueuedModification(
            dm.ModificationType.BLOCK_GOTO_CHANGE, block_serial=76, new_target=2
        ),
    ]

    apply_calls: list[int] = []
    monkeypatch.setattr(
        modifier, "_apply_single", lambda _mod: apply_calls.append(1) or True
    )
    monkeypatch.setattr(dm, "_format_block_info", lambda _blk: "<blk>")
    monkeypatch.setattr(dm, "safe_verify", lambda *_a, **_k: None)
    monkeypatch.setattr(dm, "mba_deep_cleaning", lambda *_a, **_k: None)
    monkeypatch.setattr(
        dm, "lift", lambda _m: SimpleNamespace(num_blocks=1, entry_serial=0)
    )

    applied = modifier.apply(
        run_optimize_local=False,
        run_deep_cleaning=False,
        transactional=True,
    )
    assert applied == 0
    # Apply loop must not have been entered.
    assert apply_calls == []
    assert modifier.verify_failed is True


def test_detect_transactional_batch_conflicts_direct():
    """Unit-test the gate's conflict-detection logic in isolation.

    Covers the decision predicate without running the full apply() flow,
    because the coalescer already deduplicates many same-(src, mod_type)
    pairs before the gate would see them. The gate is defense-in-depth
    for cases the coalescer misses (different old_targets etc.) and is
    easiest to validate directly.
    """
    mba = _FakeMBA()
    modifier = dm.DeferredGraphModifier(
        mba, mutation_gateway=make_mutation_gateway(mba)
    )

    # No conflict: single graph mod.
    modifier.modifications = [
        dm.QueuedModification(
            dm.ModificationType.BLOCK_GOTO_CHANGE, block_serial=76, new_target=11
        ),
    ]
    assert modifier._detect_transactional_batch_conflicts() is None

    # No conflict: graph mod + instruction mod on same block.
    modifier.modifications = [
        dm.QueuedModification(
            dm.ModificationType.BLOCK_GOTO_CHANGE, block_serial=76, new_target=11
        ),
        dm.QueuedModification(
            dm.ModificationType.INSN_NOP, block_serial=76, insn_ea=0x1000
        ),
    ]
    assert modifier._detect_transactional_batch_conflicts() is None

    # Conflict: two graph mods on blk[76] pointing at different targets.
    modifier.modifications = [
        dm.QueuedModification(
            dm.ModificationType.BLOCK_GOTO_CHANGE, block_serial=76, new_target=11
        ),
        dm.QueuedModification(
            dm.ModificationType.BLOCK_GOTO_CHANGE, block_serial=76, new_target=2
        ),
    ]
    reason = modifier._detect_transactional_batch_conflicts()
    assert reason is not None
    assert "blk[76]" in reason
    assert "new_targets" in reason

    # No conflict: same block, same target (redundant but consistent).
    modifier.modifications = [
        dm.QueuedModification(
            dm.ModificationType.BLOCK_GOTO_CHANGE, block_serial=76, new_target=11
        ),
        dm.QueuedModification(
            dm.ModificationType.BLOCK_GOTO_CHANGE, block_serial=76, new_target=11
        ),
    ]
    assert modifier._detect_transactional_batch_conflicts() is None


def test_apply_transactional_marks_verify_failed_when_rollback_itself_fails(
    monkeypatch,
):
    """If the snapshot restore call returns False, MBA is in an inconsistent
    state and verify_failed must be set so callers can abort gracefully.
    """
    mba = _FakeMBA()
    modifier = dm.DeferredGraphModifier(
        mba, mutation_gateway=make_mutation_gateway(mba)
    )
    modifier.modifications = [
        dm.QueuedModification(
            dm.ModificationType.BLOCK_GOTO_CHANGE, block_serial=0, new_target=1
        ),
        dm.QueuedModification(
            dm.ModificationType.INSN_NOP, block_serial=0, insn_ea=0x1000
        ),
    ]

    calls: list[int] = []

    def _fake_apply_single(_mod):
        calls.append(1)
        return False  # first one fails immediately

    monkeypatch.setattr(modifier, "_apply_single", _fake_apply_single)
    monkeypatch.setattr(modifier, "_restore_from_snapshot", lambda _snap: False)
    monkeypatch.setattr(dm, "_format_block_info", lambda _blk: "<blk>")
    monkeypatch.setattr(dm, "safe_verify", lambda *_a, **_k: None)
    monkeypatch.setattr(dm, "mba_deep_cleaning", lambda *_a, **_k: None)
    monkeypatch.setattr(
        dm, "lift", lambda _m: SimpleNamespace(num_blocks=1, entry_serial=0)
    )

    applied = modifier.apply(
        run_optimize_local=False,
        run_deep_cleaning=False,
        transactional=True,
    )
    # restore failed → we cannot claim successful rollback → return partial count
    # and signal verify_failed so the caller can quarantine the function.
    assert applied == 0
    assert modifier.verify_failed is True


def test_apply_transactional_rolls_back_alias_scalarization_verify_failure(monkeypatch):
    mba = _FakeMBA()
    modifier = dm.DeferredGraphModifier(
        mba, mutation_gateway=make_mutation_gateway(mba)
    )
    modifier.modifications = [
        dm.QueuedModification(
            dm.ModificationType.INSN_SCALARIZE_LOCAL_ALIAS_ACCESS,
            block_serial=0,
            insn_ea=0x1000,
            host_opcode=ida_hexrays.m_ldx,
            alias_token="%var_378",
            base_token="%var_18",
            description="alias scalarization must rollback on verify failure",
        ),
    ]

    apply_calls = {"count": 0}
    restore_calls = {"count": 0}
    verify_calls = {"count": 0}

    def _apply_alias(*_args, **_kwargs):
        apply_calls["count"] += 1
        return True

    def _safe_verify(*_args, **_kwargs):
        verify_calls["count"] += 1
        if verify_calls["count"] == 2:
            raise RuntimeError("alias scalarization verify failure")

    monkeypatch.setattr(modifier, "_apply_scalarize_local_alias_access", _apply_alias)
    monkeypatch.setattr(
        modifier,
        "_restore_from_snapshot",
        lambda _snap: (
            restore_calls.__setitem__("count", restore_calls["count"] + 1) or True
        ),
    )
    monkeypatch.setattr(dm, "_format_block_info", lambda _blk: "<blk>")
    monkeypatch.setattr(dm, "safe_verify", _safe_verify)
    monkeypatch.setattr(dm, "mba_deep_cleaning", lambda *_a, **_k: None)
    monkeypatch.setattr(
        dm, "lift", lambda _m: SimpleNamespace(num_blocks=1, entry_serial=0)
    )

    applied = modifier.apply(
        run_optimize_local=False,
        run_deep_cleaning=False,
        verify_each_mod=True,
        rollback_on_verify_failure=True,
        transactional=True,
    )

    assert applied == 0
    assert apply_calls["count"] == 1
    assert restore_calls["count"] == 1
    assert modifier.verify_failed is False


def test_scalarize_local_alias_access_revalidates_live_host_text_hash() -> None:
    mba = _FakeMBA()
    modifier = dm.DeferredGraphModifier(
        mba, mutation_gateway=make_mutation_gateway(mba)
    )
    block = _FakeBlock(0)
    host = SimpleNamespace(
        opcode=ida_hexrays.m_ldx,
        ea=0x18000F123,
        next=None,
        dstr=lambda: "ldx [ds.2:%var_378.8].4, %var_420.4",
    )
    block.head = host

    assert (
        modifier._apply_scalarize_local_alias_access(
            block,
            0x18000F123,
            ida_hexrays.m_ldx,
            "%var_378",
            "%var_18",
            "definitely-wrong",
            4,
        )
        is False
    )


def test_retarget_output_store_rewrites_only_store_address_operand(monkeypatch) -> None:
    class _Mop:
        def __init__(self, text: str, size: int = 8):
            self._text = text
            self.size = size

        def dstr(self) -> str:
            return self._text

        def assign(self, other) -> None:
            self._text = other.dstr()
            self.size = getattr(other, "size", self.size)

    def _copy_mop(mop):
        return _Mop(mop.dstr(), getattr(mop, "size", 0))

    monkeypatch.setattr(dm, "_copy_mop_for_alias_scalarization", _copy_mop)

    mba = _FakeMBA()
    entry = _FakeBlock(0)
    entry.head = SimpleNamespace(
        opcode=ida_hexrays.m_mov,
        ea=0x18000E7A9,
        d=_Mop("%var_30.8"),
        l=_Mop("rdx.8"),
        r=_Mop("", 0),
        next=None,
        dstr=lambda: "mov rdx.8, %var_30.8",
    )
    target = _Mop("[ds.2:%var_370.8].8")
    value = _Mop("((bnot([ds.2:%var_378.8].4) & #0x173063C1.4))", 4)
    host = SimpleNamespace(
        opcode=ida_hexrays.m_stx,
        ea=0x18000FA83,
        d=target,
        l=value,
        r=_Mop("ds.2", 2),
        next=None,
        dstr=lambda: (
            "stx ((bnot([ds.2:%var_378.8].4) & #0x173063C1.4)), "
            "ds.2, [ds.2:%var_370.8].8"
        ),
    )
    store_block = _FakeBlock(1)
    store_block.head = host
    mba.blocks = {0: entry, 1: store_block}
    mba.qty = 2
    modifier = dm.DeferredGraphModifier(
        mba, mutation_gateway=make_mutation_gateway(mba)
    )

    assert (
        modifier._apply_retarget_output_store(
            store_block,
            0x18000FA83,
            ida_hexrays.m_stx,
            "%var_370",
            "%var_30",
            None,
            4,
        )
        is True
    )
    assert target.dstr() == "%var_30.8"
    assert value.dstr().startswith("((bnot")


def test_scalarize_local_alias_access_coalesce_keeps_distinct_live_anchors() -> None:
    mba = _FakeMBA()
    modifier = dm.DeferredGraphModifier(
        mba, mutation_gateway=make_mutation_gateway(mba)
    )
    modifier.queue_scalarize_local_alias_access(
        7,
        0x180010000,
        ida_hexrays.m_ldx,
        "%var_378",
        "%var_18",
        host_text_sha1="hash-a",
        value_size=4,
    )
    modifier.queue_scalarize_local_alias_access(
        7,
        0x180010010,
        ida_hexrays.m_ldx,
        "%var_378",
        "%var_18",
        host_text_sha1="hash-b",
        value_size=4,
    )

    assert modifier.coalesce() == 0
    assert len(modifier.modifications) == 2


def test_apply_tolerates_queued_mod_logging_introspection_failure(monkeypatch):
    mba = _FakeMBA()
    modifier = dm.DeferredGraphModifier(
        mba, mutation_gateway=make_mutation_gateway(mba)
    )
    modifier.modifications = [
        dm.QueuedModification(
            dm.ModificationType.BLOCK_GOTO_CHANGE,
            block_serial=0,
            new_target=0,
            description="self-loop debug case",
        ),
    ]

    state = {"calls": 0}

    def _boom_once(_blk):
        state["calls"] += 1
        if state["calls"] == 1:
            raise RuntimeError("debug formatter blew up")
        return "<blk>"

    monkeypatch.setattr(dm, "_format_block_info", _boom_once)
    monkeypatch.setattr(dm, "safe_verify", lambda *_a, **_k: None)
    monkeypatch.setattr(dm, "mba_deep_cleaning", lambda *_a, **_k: None)
    monkeypatch.setattr(modifier, "_apply_single", lambda _mod: True)

    applied = modifier.apply(run_optimize_local=False, run_deep_cleaning=False)

    assert applied == 1


def test_block_target_change_rejects_unplanned_fallthrough_helper_before_mutation(
    monkeypatch,
):
    mba = _FakeMBA()
    blk = _FakeBlock(15)
    blk.type = ida_hexrays.BLT_2WAY
    blk.tail.opcode = ida_hexrays.m_jnz
    blk.tail.d = SimpleNamespace(t=ida_hexrays.mop_b, b=17)
    blk.succset = _FakeEdgeSet([16, 17])
    blk.nextb = SimpleNamespace(serial=16)
    blk.nsucc = lambda: 2  # type: ignore[assignment]
    blk.succ = lambda idx: [16, 17][idx]  # type: ignore[assignment]
    fallthrough_destination = _FakeBlock(66, start=0x406600)
    conditional_destination = _FakeBlock(202, start=0x420200)
    mba.blocks = {
        15: blk,
        66: fallthrough_destination,
        202: conditional_destination,
    }
    mba.qty = 300

    modifier = dm.DeferredGraphModifier(
        mba, mutation_gateway=make_mutation_gateway(mba)
    )

    nop_blk = _FakeBlock(16)
    helper_targets: list[tuple[int, int]] = []
    conditional_targets: list[tuple[int, int, int | None]] = []

    def _insert_nop(_blk):
        for block in mba.blocks.values():
            if int(block.serial) >= int(nop_blk.serial):
                block.serial += 1
        mba.blocks = {int(block.serial): block for block in mba.blocks.values()}
        mba.blocks[int(nop_blk.serial)] = nop_blk
        mba.qty += 1
        return nop_blk

    def _change_1way(_blk, new_target, verify=False):
        helper_targets.append((_blk.serial, new_target))
        return True

    def _change_2way(_blk, new_target, verify=False, old_target=None):
        conditional_targets.append((_blk.serial, new_target, old_target))
        return True

    monkeypatch.setattr(dm, "insert_nop_blk", _insert_nop)
    monkeypatch.setattr(dm, "change_1way_block_successor", _change_1way)
    monkeypatch.setattr(dm, "change_2way_block_conditional_successor", _change_2way)

    modifier._begin_mutation_batch(
        serial_quantity=300,
        planned_operation_count=2,
    )

    with pytest.raises(
        RuntimeError,
        match="fallthrough branch rewrite lacks reserved PlanBlockRef helper",
    ):
        modifier._apply_single(
            dm.QueuedModification(
                dm.ModificationType.BLOCK_TARGET_CHANGE,
                block_serial=15,
                new_target=66,
                old_target=16,
            )
        )

    assert helper_targets == []
    assert conditional_targets == []
    assert mba.qty == 300
    modifier._mutation_gateway.abort()


def test_planned_helper_creation_accepts_one_member_of_multi_block_plan() -> None:
    mba = _FakeMBA()
    gateway = make_mutation_gateway(mba)
    attempt = TransactionAttemptId(
        plan_id="multi-helper-plan",
        session_id=gateway.session_id,
        generation=gateway.generation,
        attempt_id="multi-helper-attempt",
    )
    first = PlanBlockRef("multi-helper-plan", "helper:0")
    second = PlanBlockRef("multi-helper-plan", "helper:1")
    gateway.begin_batch(
        StructuralMutationKind.BLOCK_INSERT,
        serial_quantity=mba.qty,
        transaction_attempt=attempt,
        patch_plan_refs=(first, second),
    )
    gateway.reserve_plan_block(attempt, first)
    gateway.reserve_plan_block(attempt, second)
    gateway.begin_patch_realization(attempt, plan_refs=(first, second))
    modifier = dm.DeferredGraphModifier(mba, mutation_gateway=gateway)
    modifier._patch_plan_ref_by_bound_serial = {mba.qty: first, mba.qty + 1: second}

    modifier._begin_patch_block_creation(mba.qty)


def test_block_target_change_rejects_unplanned_helper_after_serial_drift(
    monkeypatch,
):
    """A remapped serial must not retarget the handler to its fallthrough."""
    mba = _FakeMBA()
    source = _FakeBlock(237, start=0x40C32F)
    source.type = ida_hexrays.BLT_2WAY
    source.tail.opcode = ida_hexrays.m_jnz
    source.tail.d = SimpleNamespace(t=ida_hexrays.mop_b, b=239)
    source.succset = _FakeEdgeSet([238, 239])
    source.nextb = SimpleNamespace(serial=238)
    source.nsucc = lambda: 2  # type: ignore[assignment]
    source.succ = lambda idx: [238, 239][idx]  # type: ignore[assignment]
    handler = _FakeBlock(51, start=0x40AB25)
    handler_fallthrough = _FakeBlock(52, start=0x40AB56)
    mba.blocks = {
        51: handler,
        52: handler_fallthrough,
        237: source,
    }
    mba.qty = 300

    modifier = dm.DeferredGraphModifier(
        mba, mutation_gateway=make_mutation_gateway(mba)
    )
    # The original target blk50@0x40AB25 is currently blk51@0x40AB25.
    # Another original block 51 independently maps to live serial 52.  Once
    # _apply_single resolves new_target 50 -> 51, the fallthrough helper must
    # treat 51 as a live serial, not resolve it again through the original-key
    # mapping 51 -> 52.
    _seed_current_serials(modifier, {226: 237, 227: 238, 50: 51, 51: 52})
    helper = _FakeBlock(238)
    rewritten_targets: list[int] = []

    def _insert_nop(_source):
        mba.qty += 1
        return helper

    monkeypatch.setattr(dm, "insert_nop_blk", _insert_nop)
    monkeypatch.setattr(
        dm,
        "change_1way_block_successor",
        lambda _helper, target, verify=False: rewritten_targets.append(target) or True,
    )

    with pytest.raises(
        RuntimeError,
        match="fallthrough branch rewrite lacks reserved PlanBlockRef helper",
    ):
        modifier._apply_single(
            dm.QueuedModification(
                dm.ModificationType.BLOCK_TARGET_CHANGE,
                block_serial=226,
                new_target=50,
                old_target=227,
            )
        )
    assert rewritten_targets == []
    modifier._mutation_gateway.abort()


def test_conditional_lowering_helper_remaps_later_branch_targets(monkeypatch):
    """A helper insertion must shift targets used by later queued rewrites."""
    mba = _FakeMBA()
    guard = _FakeBlock(10)
    guard.mba = mba
    guard.head = None
    target = _FakeBlock(20)
    target.mba = mba
    helper = _FakeBlock(11)
    helper.mba = mba
    helper.head = None
    helper.tail = None
    helper.nsucc = lambda: 0  # type: ignore[method-assign]
    helper.npred = lambda: 0  # type: ignore[method-assign]
    helper.mark_lists_dirty = lambda: None  # type: ignore[assignment]
    source = _FakeBlock(5)
    source.mba = mba
    mba.blocks = {5: source, 10: guard, 20: target}
    mba.qty = 30

    def _insert_block(insertion_serial):
        assert insertion_serial == 11
        mba.qty += 1
        target.serial = 21
        mba.blocks = {int(block.serial): block for block in mba.blocks.values()}
        mba.blocks[11] = helper
        return helper

    mba.insert_block = _insert_block  # type: ignore[attr-defined]
    monkeypatch.setattr(dm, "insert_goto_instruction", lambda *_a, **_k: None)

    modifier = dm.DeferredGraphModifier(
        mba, mutation_gateway=make_mutation_gateway(mba)
    )
    modifier._begin_mutation_batch(
        serial_quantity=30,
        planned_operation_count=2,
    )
    assert modifier._build_fallthrough_goto_helper(guard, target) == 11

    captured: list[tuple[int, int | None]] = []
    monkeypatch.setattr(
        modifier,
        "_apply_target_change",
        lambda _blk, new_target, old_target=None, **_kwargs: (
            captured.append((new_target, old_target)) or True
        ),
    )
    assert modifier._apply_single(
        dm.QueuedModification(
            dm.ModificationType.BLOCK_TARGET_CHANGE,
            block_serial=5,
            new_target=20,
            old_target=10,
        )
    )

    assert modifier.current_serial_for_planned(20) == 21
    assert captured == [(21, 10)]
    modifier._mutation_gateway.commit()


def test_restore_pruned_conditional_preserves_predicate_and_builds_both_arms(
    monkeypatch,
) -> None:
    class _BlockReference:
        def __init__(self) -> None:
            self.t = ida_hexrays.mop_z
            self.b = -1

        def make_blkref(self, serial: int) -> None:
            self.t = ida_hexrays.mop_b
            self.b = int(serial)

    mba = _FakeMBA()
    guard = _FakeBlock(10, start=0x40C10A)
    guard.mba = mba
    guard.head = None
    guard.nsucc = lambda: 0
    guard.tail = SimpleNamespace(
        opcode=ida_hexrays.m_jnz,
        ea=0x40C12C,
        d=_BlockReference(),
    )
    # Imported union blocks share the function start EA.  Their live handles,
    # not that broad start coordinate, must survive the helper insertion.
    taken_target = _FakeBlock(20, start=0x40A560)
    taken_target.mba = mba
    fallthrough_target = _FakeBlock(30, start=0x40A560)
    fallthrough_target.mba = mba
    mba.blocks = {
        int(guard.serial): guard,
        int(taken_target.serial): taken_target,
        int(fallthrough_target.serial): fallthrough_target,
    }
    mba.qty = 40

    def _insert_block(insertion_serial):
        rebuilt: dict[int, _FakeBlock] = {}
        for block in tuple(mba.blocks.values()):
            replacement = _FakeBlock(
                int(block.serial) + (int(block.serial) >= int(insertion_serial)),
                start=int(block.start),
            )
            replacement.mba = mba
            replacement.type = int(block.type)
            replacement.flags = int(block.flags)
            replacement.head = block.head
            replacement.tail = block.tail
            replacement.succset = _FakeEdgeSet(tuple(int(x) for x in block.succset))
            replacement.predset = _FakeEdgeSet(tuple(int(x) for x in block.predset))
            if int(block.start) == 0x40C10A:
                replacement.tail = SimpleNamespace(
                    opcode=ida_hexrays.m_jnz,
                    ea=0x40C12C,
                    d=_BlockReference(),
                )
                replacement.nsucc = lambda: 0  # type: ignore[method-assign]
            rebuilt[int(replacement.serial)] = replacement
        helper = _FakeBlock(int(insertion_serial), start=0xF1C10000)
        helper.mba = mba
        helper.head = None
        helper.tail = None
        helper.nsucc = lambda: 0  # type: ignore[method-assign]
        helper.npred = lambda: 0  # type: ignore[method-assign]
        rebuilt[int(helper.serial)] = helper
        mba.blocks = rebuilt
        mba.qty += 1
        return helper

    mba.insert_block = _insert_block  # type: ignore[attr-defined]
    monkeypatch.setattr(dm, "insert_goto_instruction", lambda *_a, **_k: None)
    monkeypatch.setattr(dm.ida_hexrays, "mop_t", _BlockReference)

    gateway = make_mutation_gateway(mba)
    modifier = dm.DeferredGraphModifier(mba, mutation_gateway=gateway)
    assert modifier.restore_pruned_conditional_now(
        guard,
        taken_target=taken_target,
        fallthrough_target=fallthrough_target,
    )

    live_guard = mba.get_mblock(10)
    helper = mba.get_mblock(11)
    live_taken_target = mba.get_mblock(21)
    live_fallthrough_target = mba.get_mblock(31)
    assert live_guard.type == ida_hexrays.BLT_2WAY
    assert tuple(live_guard.succset) == (11, int(live_taken_target.serial))
    assert live_guard.tail.ea == 0x40C12C
    assert live_guard.tail.d.t == ida_hexrays.mop_b
    assert live_guard.tail.d.b == int(live_taken_target.serial)
    assert tuple(helper.succset) == (int(live_fallthrough_target.serial),)
    assert tuple(helper.predset) == (int(live_guard.serial),)
    assert int(live_guard.serial) in tuple(live_taken_target.predset)
    assert len(gateway.receipts) == 1
    assert gateway.receipts[0].operation_count == 3
    assert gateway.receipts[0].planned_operation_count == 3
    assert gateway.receipts[0].description == (
        "restore proven pruned conditional fragment"
    )


def test_conditional_lowering_helpers_keep_target_identity_across_two_insertions(
    monkeypatch,
):
    """The second helper must target the same EA after the first insert shifts it."""
    mba = _FakeMBA()
    guard = _FakeBlock(10, start=0x40AC64)
    guard.mba = mba
    guard.head = None
    taken_target = _FakeBlock(20, start=0x40B0CA)
    taken_target.mba = mba
    fallthrough_target = _FakeBlock(30, start=0x40C0FE)
    fallthrough_target.mba = mba
    mba.blocks = {
        int(guard.serial): guard,
        int(taken_target.serial): taken_target,
        int(fallthrough_target.serial): fallthrough_target,
    }
    mba.qty = 40

    goto_targets: list[tuple[_FakeBlock, int]] = []

    def _insert_block(insertion_serial):
        helper = _FakeBlock(int(insertion_serial), start=0xF1C00000 + mba.qty)
        helper.mba = mba
        helper.head = None
        helper.tail = None
        helper.nsucc = lambda: 0  # type: ignore[method-assign]
        helper.npred = lambda: 0  # type: ignore[method-assign]
        helper.mark_lists_dirty = lambda: None  # type: ignore[assignment]
        for block in tuple(mba.blocks.values()):
            if int(block.serial) >= int(insertion_serial):
                block.serial += 1
        mba.blocks = {int(block.serial): block for block in mba.blocks.values()}
        mba.blocks[int(helper.serial)] = helper
        mba.qty += 1
        return helper

    mba.insert_block = _insert_block  # type: ignore[attr-defined]
    monkeypatch.setattr(
        dm,
        "insert_goto_instruction",
        lambda helper, target, **_kwargs: goto_targets.append((helper, target)),
    )

    modifier = dm.DeferredGraphModifier(
        mba, mutation_gateway=make_mutation_gateway(mba)
    )
    assert modifier._build_fallthrough_goto_helper(guard, taken_target) is not None
    assert (
        modifier._build_fallthrough_goto_helper(guard, fallthrough_target) is not None
    )

    second_target_serial = int(goto_targets[1][1])
    assert int(mba.get_mblock(second_target_serial).start) == 0x40C0FE


def test_conditional_helper_inserts_empty_block_without_copying_imported_body(
    monkeypatch,
) -> None:
    mba = _FakeMBA()
    source = _FakeBlock(10, start=0x40A5CA)
    source.mba = mba
    source.head = SimpleNamespace(ea=0xF1C00018, next=None)
    source.tail = source.head
    target = _FakeBlock(20, start=0x40C898)
    target.mba = mba
    mba.blocks = {
        int(source.serial): source,
        int(target.serial): target,
    }
    mba.qty = 30
    inserted: list[int] = []
    goto_targets: list[int] = []

    def _insert_block(insertion_serial: int):
        insertion_serial = int(insertion_serial)
        inserted.append(insertion_serial)
        for block in tuple(mba.blocks.values()):
            if int(block.serial) >= insertion_serial:
                block.serial += 1
        helper = _FakeBlock(insertion_serial, start=mba.entry_ea)
        helper.mba = mba
        helper.head = None
        helper.tail = None
        helper.type = int(ida_hexrays.BLT_0WAY)
        helper.nsucc = lambda: 0  # type: ignore[method-assign]
        helper.npred = lambda: 0  # type: ignore[method-assign]
        mba.blocks = {int(block.serial): block for block in mba.blocks.values()}
        mba.blocks[insertion_serial] = helper
        mba.qty += 1
        return helper

    mba.insert_block = _insert_block  # type: ignore[attr-defined]

    def _reject_body_copy(*_args, **_kwargs):
        raise AssertionError("adjacent helper must not copy an imported body")

    monkeypatch.setattr(dm, "copy_block_keep", _reject_body_copy)
    monkeypatch.setattr(
        dm,
        "insert_goto_instruction",
        lambda _helper, target_serial, **_kwargs: goto_targets.append(
            int(target_serial)
        ),
    )

    modifier = dm.DeferredGraphModifier(
        mba,
        mutation_gateway=make_mutation_gateway(mba),
    )
    assert modifier._build_fallthrough_goto_helper(source, target) == 11

    assert inserted == [11]
    assert goto_targets == [21]
    helper = mba.get_mblock(11)
    assert helper is not None
    assert helper.head is None
    assert tuple(helper.succset) == (21,)
    assert int(mba.get_mblock(21).start) == 0x40C898


def test_conditional_helper_accepts_ordinary_transaction_authority(
    monkeypatch,
) -> None:
    mba = _FakeMBA()
    source = _FakeBlock(10, start=0x1800144E4)
    source.mba = mba
    source.head = None
    source.tail = SimpleNamespace(ea=0x1800144F4, next=None)
    target = _FakeBlock(20, start=0x18001452B)
    target.mba = mba
    mba.blocks = {
        int(source.serial): source,
        int(target.serial): target,
    }
    mba.qty = 30
    mba.map_fict_ea = lambda ea: ea  # type: ignore[attr-defined]
    inserted: list[int] = []

    def _insert_block(insertion_serial: int):
        insertion_serial = int(insertion_serial)
        inserted.append(insertion_serial)
        for block in tuple(mba.blocks.values()):
            if int(block.serial) >= insertion_serial:
                block.serial += 1
        helper = _FakeBlock(insertion_serial, start=mba.entry_ea)
        helper.mba = mba
        helper.head = None
        helper.tail = None
        helper.type = int(ida_hexrays.BLT_0WAY)
        helper.nsucc = lambda: 0  # type: ignore[method-assign]
        helper.npred = lambda: 0  # type: ignore[method-assign]
        mba.blocks = {int(block.serial): block for block in mba.blocks.values()}
        mba.blocks[insertion_serial] = helper
        mba.qty += 1
        return helper

    mba.insert_block = _insert_block  # type: ignore[attr-defined]
    monkeypatch.setattr(dm, "insert_goto_instruction", lambda *_args, **_kwargs: None)

    gateway = make_mutation_gateway(mba)
    attempt = TransactionAttemptId.new(
        "tigress-conditional-lowering",
        gateway.session_id,
        gateway.generation,
    )
    gateway.begin_batch(
        StructuralMutationKind.BLOCK_REPLACE,
        serial_quantity=mba.qty,
        planned_operation_count=1,
        transaction_attempt=attempt,
        patch_plan_id=attempt.plan_id,
    )
    gateway.begin_patch_realization(attempt, plan_refs=())

    modifier = dm.DeferredGraphModifier(mba, mutation_gateway=gateway)
    assert modifier._build_fallthrough_goto_helper(source, target) == 11
    assert inserted == [11]


def test_conditional_helper_rebinds_target_when_proxy_serial_stays_stale(
    monkeypatch,
) -> None:
    mba = _FakeMBA()
    guard = _FakeBlock(10, start=0x40AC64)
    guard.mba = mba
    guard.head = None
    stale_target = _FakeBlock(20, start=0x40B0CA)
    stale_target.mba = mba
    mba.blocks = {
        int(guard.serial): guard,
        int(stale_target.serial): stale_target,
    }
    mba.qty = 30
    goto_targets: list[int] = []

    def _insert_block(insertion_serial):
        rebuilt: dict[int, _FakeBlock] = {}
        for serial, block in tuple(mba.blocks.items()):
            if int(serial) < int(insertion_serial):
                rebuilt[int(serial)] = block
                continue
            replacement = _FakeBlock(
                int(serial) + 1,
                start=int(block.start),
            )
            replacement.mba = mba
            rebuilt[int(replacement.serial)] = replacement
        helper = _FakeBlock(int(insertion_serial), start=0xF1C20000)
        helper.mba = mba
        helper.head = None
        helper.tail = None
        helper.nsucc = lambda: 0  # type: ignore[method-assign]
        helper.npred = lambda: 0  # type: ignore[method-assign]
        helper.mark_lists_dirty = lambda: None  # type: ignore[assignment]
        rebuilt[int(helper.serial)] = helper
        mba.blocks = rebuilt
        mba.qty += 1
        return helper

    mba.insert_block = _insert_block  # type: ignore[attr-defined]
    monkeypatch.setattr(
        dm,
        "insert_goto_instruction",
        lambda _helper, target, **_kwargs: goto_targets.append(int(target)),
    )

    modifier = dm.DeferredGraphModifier(
        mba, mutation_gateway=make_mutation_gateway(mba)
    )
    assert modifier._build_fallthrough_goto_helper(guard, stale_target) == 11

    assert goto_targets == [21]
    assert int(mba.get_mblock(goto_targets[0]).start) == 0x40B0CA


def test_conditional_reacquire_uses_current_insertion_position_before_ea_fallback():
    mba = _FakeMBA()
    source_ea = 0x40DD7C
    target_ea = 0xF1C01C08

    def _instruction(ea: int) -> SimpleNamespace:
        return SimpleNamespace(ea=int(ea), opcode=ida_hexrays.m_mov, next=None)

    source = _FakeBlock(108, start=0x40DD66)
    source.head = source.tail = _instruction(source_ea)
    copied_helper = _FakeBlock(109, start=0x40DD66)
    copied_helper.head = copied_helper.tail = _instruction(source_ea)
    shifted_target = _FakeBlock(665, start=0x40D200)
    shifted_target.head = shifted_target.tail = _instruction(target_ea)
    duplicate_ea = _FakeBlock(700, start=0x40D200)
    duplicate_ea.head = duplicate_ea.tail = _instruction(target_ea)
    mba.blocks = {
        108: source,
        109: copied_helper,
        665: shifted_target,
        700: duplicate_ea,
    }
    mba.qty = 701
    modifier = dm.DeferredGraphModifier(
        mba, mutation_gateway=make_mutation_gateway(mba)
    )
    modifier._serial_remap = {108: 400, 664: 800}

    assert (
        modifier._reacquire_block_after_insertion(
            108,
            0x40DD66,
            exact_instruction_ea=source_ea,
            insertion_serial=109,
        )
        is source
    )
    assert (
        modifier._reacquire_block_after_insertion(
            664,
            0x40D200,
            exact_instruction_ea=target_ea,
            insertion_serial=109,
        )
        is shifted_target
    )


def test_conditional_lowering_resolves_dispatcher_serial_once(monkeypatch):
    """The lowering callee owns target remapping; do not pre-remap its old edge."""
    mba = _FakeMBA()
    source = _FakeBlock(87)
    mba.blocks = {87: source}
    mba.qty = 143
    modifier = dm.DeferredGraphModifier(
        mba, mutation_gateway=make_mutation_gateway(mba)
    )
    _seed_current_serials(
        modifier,
        {
            86: 87,
            140: 141,
            141: 142,
        },
    )

    captured: dict[str, int] = {}

    def _lower(_block, **kwargs):
        captured["source"] = int(_block.serial)
        captured["old_dispatcher"] = int(kwargs["old_dispatcher_serial"])
        return True

    monkeypatch.setattr(
        modifier,
        "_apply_lower_conditional_state_transition",
        _lower,
    )

    assert modifier._apply_single(
        dm.QueuedModification(
            dm.ModificationType.LOWER_CONDITIONAL_STATE_TRANSITION,
            block_serial=86,
            new_target=245,
            old_target=140,
            rewrite_from_ea=0x40AFEB,
            condition_operand=object(),
            false_target=227,
            true_target=245,
        )
    )
    assert captured == {
        "source": 87,
        "old_dispatcher": 140,
    }


def test_create_and_redirect_rejects_non_1way_source(monkeypatch):
    mba = _FakeMBA()
    modifier = dm.DeferredGraphModifier(
        mba, mutation_gateway=make_mutation_gateway(mba)
    )
    src = _FakeBlock(5)
    src.nsucc = lambda: 2  # type: ignore[assignment]

    called = {"create": 0}
    monkeypatch.setattr(
        dm,
        "create_standalone_block",
        lambda *_a, **_k: called.__setitem__("create", called["create"] + 1),
    )

    ok = modifier._apply_create_and_redirect(
        source_blk=src,
        final_target=0,
        instructions_to_copy=[SimpleNamespace()],
        is_0_way=False,
        expected_serial=None,
    )
    assert ok is False
    assert called["create"] == 0


def test_create_and_redirect_materializes_symbolic_snapshots_before_block_creation(
    monkeypatch,
):
    mba = _FakeMBA()
    modifier = dm.DeferredGraphModifier(
        mba, mutation_gateway=make_mutation_gateway(mba)
    )
    src = _FakeBlock(5)

    captured: dict[str, object] = {}
    rebuilt_instructions = [SimpleNamespace(opcode=ida_hexrays.m_nop, ea=0x1234)]

    monkeypatch.setattr(
        dm,
        "materialize_insn_snapshots",
        lambda instructions, *, safe_ea: (
            captured.update({"instructions": instructions, "safe_ea": safe_ea})
            or rebuilt_instructions
        ),
    )
    monkeypatch.setattr(
        dm,
        "create_standalone_block",
        lambda *_a, **_k: (
            captured.update({"blk_ins": _a[1]}) or SimpleNamespace(serial=1, head=None)
        ),
    )
    monkeypatch.setattr(dm, "change_1way_block_successor", lambda *_a, **_k: True)

    ok = modifier._apply_create_and_redirect(
        source_blk=src,
        final_target=0,
        instructions_to_copy=[
            InsnSnapshot(opcode=ida_hexrays.m_nop, ea=0x1234, operands=())
        ],
        is_0_way=False,
        expected_serial=None,
    )

    assert ok is True
    assert captured["instructions"] == (
        InsnSnapshot(opcode=ida_hexrays.m_nop, ea=0x1234, operands=()),
    )
    assert captured["safe_ea"] == mba.entry_ea
    assert captured["blk_ins"] is rebuilt_instructions


def test_apply_pre_rejects_create_and_redirect_from_entry_block(monkeypatch):
    mba = _FakeMBA()
    modifier = dm.DeferredGraphModifier(
        mba, mutation_gateway=make_mutation_gateway(mba)
    )
    modifier.modifications = [
        dm.QueuedModification(
            dm.ModificationType.BLOCK_CREATE_WITH_REDIRECT,
            block_serial=0,
            new_target=0,
            final_target=0,
            instructions_to_copy=[],
            description="entry insert should pre-reject",
        )
    ]

    called = {"apply_single": 0}
    monkeypatch.setattr(
        modifier, "_apply_single", lambda _m: called.__setitem__("apply_single", 1)
    )
    monkeypatch.setattr(dm, "_format_block_info", lambda _blk: "<blk>")
    monkeypatch.setattr(dm, "safe_verify", lambda *_a, **_k: None)
    monkeypatch.setattr(
        dm,
        "mba_deep_cleaning",
        lambda *_a, **_k: setattr(mba, "cleaned", mba.cleaned + 1),
    )

    applied = modifier.apply(run_optimize_local=False, run_deep_cleaning=False)

    assert applied == 0
    assert called["apply_single"] == 0


def test_coalesce_resolves_mixed_terminal_conflicts():
    mba = _FakeMBA()
    modifier = dm.DeferredGraphModifier(
        mba, mutation_gateway=make_mutation_gateway(mba)
    )
    modifier.modifications = [
        dm.QueuedModification(
            dm.ModificationType.BLOCK_CREATE_WITH_REDIRECT,
            block_serial=7,
            new_target=11,
            final_target=11,
            instructions_to_copy=[SimpleNamespace(opcode=ida_hexrays.m_mov)],
            rule_priority=0,
        ),
        dm.QueuedModification(
            dm.ModificationType.BLOCK_GOTO_CHANGE,
            block_serial=7,
            new_target=22,
            rule_priority=100,
        ),
    ]

    removed = modifier.coalesce()

    assert removed == 1
    assert len(modifier.modifications) == 1
    assert modifier.modifications[0].mod_type == dm.ModificationType.BLOCK_GOTO_CHANGE
    assert modifier.modifications[0].new_target == 22


def test_apply_runs_conservative_cleanup_without_optimize_local(monkeypatch):
    mba = _FakeMBA()
    modifier = dm.DeferredGraphModifier(
        mba, mutation_gateway=make_mutation_gateway(mba)
    )
    modifier.modifications = [
        dm.QueuedModification(
            dm.ModificationType.BLOCK_GOTO_CHANGE, block_serial=0, new_target=1
        ),
    ]

    monkeypatch.setattr(modifier, "_apply_single", lambda _m: True)
    monkeypatch.setattr(dm, "_format_block_info", lambda _blk: "<blk>")
    monkeypatch.setattr(dm, "safe_verify", lambda *_a, **_k: None)
    monkeypatch.setattr(
        dm,
        "mba_deep_cleaning",
        lambda *_a, **_k: setattr(mba, "cleaned", mba.cleaned + 1),
    )

    applied = modifier.apply(run_optimize_local=False, run_deep_cleaning=False)
    assert applied == 1
    assert mba.cleaned == 1


def test_apply_attempts_verify_recovery(monkeypatch):
    # With unconditional pre-apply verify: the first safe_verify call is the
    # pre-apply check. When it raises, _repair_wrong_successors() is attempted
    # (finds nothing to fix on this fake MBA) and apply proceeds optimistically.
    # The second safe_verify call is the post-apply check, which passes.
    # mba_deep_cleaning is NOT called in this path (run_optimize_local=True
    # takes the optimize_local(0) branch, and post-apply verify succeeds so
    # the recovery branch is not entered).
    mba = _FakeMBA()
    modifier = dm.DeferredGraphModifier(
        mba, mutation_gateway=make_mutation_gateway(mba)
    )
    modifier.modifications = [
        dm.QueuedModification(
            dm.ModificationType.BLOCK_GOTO_CHANGE, block_serial=0, new_target=1
        ),
    ]

    monkeypatch.setattr(modifier, "_apply_single", lambda _m: True)
    monkeypatch.setattr(dm, "_format_block_info", lambda _blk: "<blk>")
    monkeypatch.setattr(
        dm,
        "mba_deep_cleaning",
        lambda *_a, **_k: setattr(mba, "cleaned", mba.cleaned + 1),
    )

    verify_calls = {"n": 0}

    def _safe_verify(*_a, **_k):
        verify_calls["n"] += 1
        if verify_calls["n"] == 1:
            raise RuntimeError("boom")

    monkeypatch.setattr(dm, "safe_verify", _safe_verify)

    applied = modifier.apply(run_optimize_local=True, run_deep_cleaning=False)
    assert applied == 1
    assert verify_calls["n"] == 2
    assert modifier.verify_failed is False


def test_apply_attempts_verify_recovery_on_non_runtime_preapply_exception(monkeypatch):
    mba = _FakeMBA()
    modifier = dm.DeferredGraphModifier(
        mba, mutation_gateway=make_mutation_gateway(mba)
    )
    modifier.modifications = [
        dm.QueuedModification(
            dm.ModificationType.BLOCK_GOTO_CHANGE, block_serial=0, new_target=1
        ),
    ]

    monkeypatch.setattr(modifier, "_apply_single", lambda _m: True)
    monkeypatch.setattr(dm, "_format_block_info", lambda _blk: "<blk>")
    monkeypatch.setattr(
        dm,
        "mba_deep_cleaning",
        lambda *_a, **_k: setattr(mba, "cleaned", mba.cleaned + 1),
    )

    verify_calls = {"n": 0}

    def _safe_verify(*_a, **_k):
        verify_calls["n"] += 1
        if verify_calls["n"] == 1:
            raise ValueError("opaque verify failure")

    monkeypatch.setattr(dm, "safe_verify", _safe_verify)

    applied = modifier.apply(run_optimize_local=True, run_deep_cleaning=False)
    assert applied == 1
    assert verify_calls["n"] == 2
    assert modifier.verify_failed is False


def test_apply_executes_post_apply_hook(monkeypatch):
    mba = _FakeMBA()
    modifier = dm.DeferredGraphModifier(
        mba, mutation_gateway=make_mutation_gateway(mba)
    )
    modifier.modifications = [
        dm.QueuedModification(
            dm.ModificationType.BLOCK_GOTO_CHANGE, block_serial=0, new_target=1
        ),
    ]

    hook_calls = {"count": 0}

    monkeypatch.setattr(modifier, "_apply_single", lambda _m: True)
    monkeypatch.setattr(dm, "_format_block_info", lambda _blk: "<blk>")
    monkeypatch.setattr(dm, "safe_verify", lambda *_a, **_k: None)
    monkeypatch.setattr(
        dm,
        "mba_deep_cleaning",
        lambda *_a, **_k: setattr(mba, "cleaned", mba.cleaned + 1),
    )

    def _hook():
        hook_calls["count"] += 1

    applied = modifier.apply(
        run_optimize_local=False,
        run_deep_cleaning=False,
        post_apply_hook=_hook,
    )

    assert applied == 1
    assert hook_calls["count"] == 1
    assert mba.cleaned == 1
    assert modifier.verify_failed is False


def test_apply_pre_rejects_illegal_edge_split_trampoline_and_continues(monkeypatch):
    mba = _FakeMBA()
    modifier = dm.DeferredGraphModifier(
        mba, mutation_gateway=make_mutation_gateway(mba)
    )
    modifier.modifications = [
        dm.QueuedModification(
            dm.ModificationType.EDGE_SPLIT_TRAMPOLINE,
            block_serial=0,
            new_target=1,
            src_block=2,
            old_target=3,
            via_pred=4,
            expected_serial=5,
            priority=5,
            description="bad trampoline",
        ),
        dm.QueuedModification(
            dm.ModificationType.INSN_NOP,
            block_serial=0,
            insn_ea=0x1000,
            priority=10,
            description="good nop",
        ),
    ]

    calls: list[dm.ModificationType] = []

    monkeypatch.setattr(
        modifier,
        "_check_edge_split_trampoline_preconditions",
        lambda **_kwargs: False,
    )
    monkeypatch.setattr(
        modifier,
        "_apply_single",
        lambda mod: calls.append(mod.mod_type) or True,
    )
    monkeypatch.setattr(dm, "_format_block_info", lambda _blk: "<blk>")
    monkeypatch.setattr(dm, "safe_verify", lambda *_a, **_k: None)
    monkeypatch.setattr(
        dm,
        "mba_deep_cleaning",
        lambda *_a, **_k: setattr(mba, "cleaned", mba.cleaned + 1),
    )

    applied = modifier.apply(run_optimize_local=False, run_deep_cleaning=False)

    assert applied == 1
    assert calls == [dm.ModificationType.INSN_NOP]


def test_create_conditional_redirect_rejects_unowned_planned_creation(
    monkeypatch, request
):
    import logging

    mba = _FakeMBA()
    source = _FakeBlock(5)
    ref = _FakeBlock(6)
    mba.blocks.update({5: source, 6: ref})
    mba.qty = len(mba.blocks)

    modifier = dm.DeferredGraphModifier(
        mba, mutation_gateway=make_mutation_gateway(mba)
    )
    _seed_current_serials(modifier, {10: 13, 11: 14})

    monkeypatch.setattr(dm.ida_hexrays, "is_mcode_jcond", lambda _opcode: True)
    monkeypatch.setattr(
        dm,
        "duplicate_block",
        lambda *_a, **_k: (_FakeBlock(7), _FakeBlock(8)),
    )

    records: list[logging.LogRecord] = []

    class _ListHandler(logging.Handler):
        def emit(self, record: logging.LogRecord) -> None:
            records.append(record)

    handler = _ListHandler(level=logging.WARNING)
    dm.logger.addHandler(handler)
    request.addfinalizer(lambda: dm.logger.removeHandler(handler))

    cond_calls = {"count": 0}
    ft_calls = {"count": 0}
    src_calls = {"count": 0}
    cond_targets: list[int] = []
    ft_targets: list[int] = []
    src_targets: list[int] = []

    def _change_2way(_blk, new_target, *_a, **_k):
        cond_calls["count"] += 1
        cond_targets.append(new_target)
        return True

    def _change_1way(blk, new_target, *_a, **_k):
        if blk.serial == 8:
            ft_calls["count"] += 1
            ft_targets.append(new_target)
        else:
            src_calls["count"] += 1
            src_targets.append(new_target)
        return True

    monkeypatch.setattr(
        dm,
        "change_2way_block_conditional_successor",
        _change_2way,
    )
    monkeypatch.setattr(
        dm,
        "change_1way_block_successor",
        _change_1way,
    )

    ok = modifier._apply_create_conditional_redirect(
        source_blk=source,
        ref_blk_serial=6,
        conditional_target_serial=10,
        fallthrough_target_serial=11,
        expected_conditional_serial=9,
        expected_fallthrough_serial=12,
    )

    assert ok is False
    assert cond_calls["count"] == 0
    assert ft_calls["count"] == 0
    assert src_calls["count"] == 0
    assert cond_targets == []
    assert ft_targets == []
    assert src_targets == []
    messages = [record.getMessage() for record in records]
    assert any(
        "patch creation lacks typed attempt authority" in message
        for message in messages
    )


def test_create_conditional_redirect_rejects_stale_source_edge_before_cloning(
    monkeypatch,
):
    mba = _FakeMBA()
    source = _FakeBlock(5)
    source.succset = _FakeEdgeSet([9])
    source.succ = lambda _idx: 9
    mba.blocks.update({5: source})
    mba.qty = len(mba.blocks)

    modifier = dm.DeferredGraphModifier(
        mba, mutation_gateway=make_mutation_gateway(mba)
    )
    duplicate_calls = {"count": 0}

    def _duplicate_block(*_args, **_kwargs):
        duplicate_calls["count"] += 1
        return (_FakeBlock(7), _FakeBlock(8))

    monkeypatch.setattr(dm, "duplicate_block", _duplicate_block)

    ok = modifier._apply_create_conditional_redirect(
        source_blk=source,
        ref_blk_serial=6,
        conditional_target_serial=10,
        fallthrough_target_serial=11,
        old_target_serial=6,
    )

    assert ok is False
    assert duplicate_calls["count"] == 0


def test_duplicate_block_rejects_unowned_planned_creation(monkeypatch):
    mba = _FakeMBA()
    source = _FakeBlock(5)
    pred = _FakeBlock(7)
    source.mba = mba
    pred.mba = mba
    source.head = None
    source.tail = None
    source.nsucc = lambda: 1  # type: ignore[assignment]
    source.succ = lambda _idx: 0  # type: ignore[assignment]
    pred.nsucc = lambda: 1  # type: ignore[assignment]
    mba.blocks.update({5: source, 7: pred})
    mba.qty = len(mba.blocks)

    modifier = dm.DeferredGraphModifier(
        mba, mutation_gateway=make_mutation_gateway(mba)
    )

    monkeypatch.setattr(
        modifier,
        "_check_duplicate_block_preconditions",
        lambda **_kwargs: True,
    )
    monkeypatch.setattr(
        dm,
        "create_standalone_block",
        lambda *_a, **_k: SimpleNamespace(
            serial=223,
            predset=_FakeEdgeSet(),
            succset=_FakeEdgeSet(),
        ),
    )
    monkeypatch.setattr(dm, "change_1way_block_successor", lambda *_a, **_k: True)

    ok = modifier._apply_duplicate_block_and_redirect(
        source_blk=source,
        pred_serial=7,
        target_serial=0,
        expected_serial=225,
    )

    assert ok is False
    assert mba.qty == 3


def test_duplicate_replay_queue_records_single_composite_modification():
    mba = _FakeMBA()
    modifier = dm.DeferredGraphModifier(
        mba, mutation_gateway=make_mutation_gateway(mba)
    )
    body = (InsnSnapshot(opcode=ida_hexrays.m_nop, ea=0, operands=()),)

    modifier.queue_duplicate_replay_and_redirect(
        source_block_serial=5,
        dispatcher_entry_serial=2,
        per_pred_replays=(
            (8, 3, 20, None, body),
            (9, 4, 21, 22, body),
        ),
        description="duplicate replay test",
    )

    assert len(modifier.modifications) == 1
    queued = modifier.modifications[0]
    assert queued.mod_type == dm.ModificationType.BLOCK_DUPLICATE_REPLAY_AND_REDIRECT
    assert queued.block_serial == 5
    assert queued.new_target == 2
    assert queued.replay_entries == (
        (8, 3, 20, None, body),
        (9, 4, 21, 22, body),
    )
    assert modifier.coalesce() == 0


def _clone_as_goto_fixture():
    mba = _FakeMBA()
    source = _FakeBlock(5)
    pred = _FakeBlock(6)
    fallthrough = _FakeBlock(20)
    target = _FakeBlock(30)
    clone = _FakeBlock(7)

    source.type = ida_hexrays.BLT_2WAY
    source.succset = _FakeEdgeSet([20, 30])
    source.predset = _FakeEdgeSet([6])
    source.nsucc = lambda: 2  # type: ignore[assignment]
    source.succ = lambda idx: (20, 30)[idx]  # type: ignore[assignment]
    source.tail = SimpleNamespace(
        opcode=ida_hexrays.m_jnz,
        ea=0x1005,
        d=SimpleNamespace(t=ida_hexrays.mop_b, b=30),
    )

    pred.succset = _FakeEdgeSet([5])
    pred.nsucc = lambda: 1  # type: ignore[assignment]
    pred.succ = lambda _idx: 5  # type: ignore[assignment]

    clone.type = ida_hexrays.BLT_2WAY
    clone.succset = _FakeEdgeSet([20, 30])
    clone.predset = _FakeEdgeSet([6, 9])
    clone.nsucc = lambda: 2  # type: ignore[assignment]
    clone.succ = lambda idx: (20, 30)[idx]  # type: ignore[assignment]
    clone.tail = SimpleNamespace(
        opcode=ida_hexrays.m_jnz,
        ea=0x1005,
        d=SimpleNamespace(t=ida_hexrays.mop_b, b=30),
    )

    mba.blocks = {
        5: source,
        6: pred,
        7: clone,
        20: fallthrough,
        30: target,
    }
    mba.qty = 31

    return mba, source, pred, clone


def test_clone_conditional_as_goto_rejects_unowned_planned_creation(
    monkeypatch,
):
    mba, source, pred, clone = _clone_as_goto_fixture()
    modifier = dm.DeferredGraphModifier(
        mba, mutation_gateway=make_mutation_gateway(mba)
    )
    trace: list[tuple] = []

    monkeypatch.setattr(dm, "copy_block_keep", lambda *_a, **_k: clone)

    def _convert(blk, target, **_kwargs):
        trace.append(("convert", blk.serial, target))
        return True

    def _redirect(blk, new_target, **_kwargs):
        trace.append(("redirect", blk.serial, blk.succ(0), new_target))
        return True

    monkeypatch.setattr(dm, "make_2way_block_goto", _convert)
    monkeypatch.setattr(dm, "change_1way_block_successor", _redirect)

    ok = modifier._apply_clone_conditional_as_goto(
        source_blk=source,
        pred_serial=pred.serial,
        goto_target_serial=30,
        expected_serial=9,
    )

    assert ok is False
    assert list(clone.predset) == [6, 9]
    assert trace == []


def _clone_as_goto_from_arm_fixture():
    """Mirror of :func:`_clone_as_goto_fixture` but with a 2-way predecessor.

    pred blk[6] is 2-way: explicit branch arm targets source blk[5] (arm=1),
    fallthrough arm targets blk[40].  source blk[5] is itself 2-way with
    arms blk[20] (fallthrough) / blk[30] (explicit branch).  Selected
    target is blk[30] (the branch arm of source).
    """
    mba = _FakeMBA()
    source = _FakeBlock(5)
    pred = _FakeBlock(6)
    fallthrough = _FakeBlock(20)
    target = _FakeBlock(30)
    pred_other = _FakeBlock(40)
    clone = _FakeBlock(7)

    source.type = ida_hexrays.BLT_2WAY
    source.succset = _FakeEdgeSet([20, 30])
    source.predset = _FakeEdgeSet([6])
    source.nsucc = lambda: 2  # type: ignore[assignment]
    source.succ = lambda idx: (20, 30)[idx]  # type: ignore[assignment]
    source.tail = SimpleNamespace(
        opcode=ida_hexrays.m_jnz,
        ea=0x1005,
        d=SimpleNamespace(t=ida_hexrays.mop_b, b=30),
    )

    # pred is 2-way; explicit branch arm targets source (arm == 1).
    pred.type = ida_hexrays.BLT_2WAY
    pred.succset = _FakeEdgeSet([40, 5])
    pred.nsucc = lambda: 2  # type: ignore[assignment]
    pred.succ = lambda idx: (40, 5)[idx]  # type: ignore[assignment]
    pred.tail = SimpleNamespace(
        opcode=ida_hexrays.m_jnz,
        ea=0x1006,
        d=SimpleNamespace(t=ida_hexrays.mop_b, b=5),
    )

    clone.type = ida_hexrays.BLT_2WAY
    clone.succset = _FakeEdgeSet([20, 30])
    clone.predset = _FakeEdgeSet([6, 9])
    clone.nsucc = lambda: 2  # type: ignore[assignment]
    clone.succ = lambda idx: (20, 30)[idx]  # type: ignore[assignment]
    clone.tail = SimpleNamespace(
        opcode=ida_hexrays.m_jnz,
        ea=0x1005,
        d=SimpleNamespace(t=ida_hexrays.mop_b, b=30),
    )

    mba.blocks = {
        5: source,
        6: pred,
        7: clone,
        20: fallthrough,
        30: target,
        40: pred_other,
    }
    mba.qty = 41

    return mba, source, pred, clone


def test_clone_conditional_as_goto_from_branch_arm_rejects_unowned_creation(
    monkeypatch,
):
    mba, source, pred, clone = _clone_as_goto_from_arm_fixture()
    modifier = dm.DeferredGraphModifier(
        mba, mutation_gateway=make_mutation_gateway(mba)
    )
    trace: list[tuple] = []

    monkeypatch.setattr(dm, "copy_block_keep", lambda *_a, **_k: clone)

    def _convert(blk, target, **_kwargs):
        trace.append(("convert", blk.serial, target))
        return True

    def _rewire_branch(blk, new_target, **kwargs):
        trace.append(
            (
                "rewire_branch",
                blk.serial,
                int(blk.tail.d.b),
                new_target,
                kwargs.get("old_target"),
            )
        )
        return True

    monkeypatch.setattr(dm, "make_2way_block_goto", _convert)
    monkeypatch.setattr(dm, "change_2way_block_conditional_successor", _rewire_branch)

    ok = modifier._apply_clone_conditional_as_goto_from_branch_arm(
        source_blk=source,
        pred_serial=pred.serial,
        goto_target_serial=30,
        expected_serial=9,
    )

    assert ok is False
    assert list(clone.predset) == [6, 9]
    assert trace == []


def test_clone_conditional_as_goto_from_fallthrough_rejects_unowned_creation(
    monkeypatch,
):
    mba, source, pred, clone = _clone_as_goto_from_arm_fixture()
    modifier = dm.DeferredGraphModifier(
        mba, mutation_gateway=make_mutation_gateway(mba)
    )
    trace: list[tuple] = []

    # pred's explicit branch arm targets the other successor, so source blk[5]
    # is reached through pred's implicit fallthrough arm.
    pred.tail = SimpleNamespace(
        opcode=ida_hexrays.m_jnz,
        ea=0x1006,
        d=SimpleNamespace(t=ida_hexrays.mop_b, b=40),
    )

    monkeypatch.setattr(dm, "copy_block_keep", lambda *_a, **_k: clone)

    def _convert(blk, target, **_kwargs):
        trace.append(("convert", blk.serial, target))
        return True

    monkeypatch.setattr(dm, "make_2way_block_goto", _convert)
    monkeypatch.setattr(
        dm,
        "change_2way_block_conditional_successor",
        lambda *_a, **_k: pytest.fail("branch-arm helper must not handle arm=0"),
    )

    def _insert_helper(blk):
        assert blk.serial == pred.serial
        helper = _FakeBlock(7)
        shifted_blocks = {}
        for serial, block in sorted(mba.blocks.items(), reverse=True):
            if serial >= 7:
                block.serial = serial + 1
                shifted_blocks[serial + 1] = block
            else:
                shifted_blocks[serial] = block
        shifted_blocks[7] = helper
        mba.blocks = shifted_blocks
        mba.qty += 1
        return helper

    def _rewire_helper(blk, new_target, **_kwargs):
        trace.append(("rewire_fallthrough", blk.serial, blk.succ(0), new_target))
        return True

    monkeypatch.setattr(dm, "insert_nop_blk", _insert_helper)
    monkeypatch.setattr(dm, "change_1way_block_successor", _rewire_helper)

    ok = modifier._apply_clone_conditional_as_goto_from_branch_arm(
        source_blk=source,
        pred_serial=pred.serial,
        pred_arm=0,
        goto_target_serial=30,
        expected_serial=9,
    )

    assert ok is False
    assert list(clone.predset) == [6, 9]
    assert trace == []


def test_clone_conditional_as_goto_from_branch_arm_refuses_one_way_predecessor(
    monkeypatch,
):
    """Apply path rejects when pred is 1-way at apply-time (drift / mis-queue)."""
    mba, source, pred, clone = _clone_as_goto_from_arm_fixture()
    modifier = dm.DeferredGraphModifier(
        mba, mutation_gateway=make_mutation_gateway(mba)
    )

    # Mutate pred to 1-way to simulate stale/drifted topology.
    pred.nsucc = lambda: 1  # type: ignore[assignment]

    monkeypatch.setattr(dm, "copy_block_keep", lambda *_a, **_k: clone)
    monkeypatch.setattr(
        dm,
        "make_2way_block_goto",
        lambda *_a, **_k: pytest.fail("convert must not run when pred is 1-way"),
    )
    monkeypatch.setattr(
        dm,
        "change_2way_block_conditional_successor",
        lambda *_a, **_k: pytest.fail("rewire must not run when pred is 1-way"),
    )

    ok = modifier._apply_clone_conditional_as_goto_from_branch_arm(
        source_blk=source,
        pred_serial=pred.serial,
        goto_target_serial=30,
    )

    assert ok is False


def test_clone_conditional_as_goto_from_branch_arm_refuses_branch_arm_mismatch(
    monkeypatch,
):
    """Apply path rejects when pred's explicit branch arm doesn't point at source."""
    mba, source, pred, clone = _clone_as_goto_from_arm_fixture()
    modifier = dm.DeferredGraphModifier(
        mba, mutation_gateway=make_mutation_gateway(mba)
    )

    # Flip pred's explicit branch operand to target the OTHER successor.
    pred.tail = SimpleNamespace(
        opcode=ida_hexrays.m_jnz,
        ea=0x1006,
        d=SimpleNamespace(t=ida_hexrays.mop_b, b=40),
    )

    monkeypatch.setattr(dm, "copy_block_keep", lambda *_a, **_k: clone)
    monkeypatch.setattr(
        dm,
        "make_2way_block_goto",
        lambda *_a, **_k: pytest.fail("convert must not run on fallthrough arm"),
    )
    monkeypatch.setattr(
        dm,
        "change_2way_block_conditional_successor",
        lambda *_a, **_k: pytest.fail("rewire must not run on fallthrough arm"),
    )

    ok = modifier._apply_clone_conditional_as_goto_from_branch_arm(
        source_blk=source,
        pred_serial=pred.serial,
        goto_target_serial=30,
    )

    assert ok is False


def _get_default_binary() -> str:
    override = os.environ.get("D810_TEST_BINARY")
    if override:
        return override
    return (
        "libobfuscated.dylib" if platform.system() == "Darwin" else "libobfuscated.dll"
    )


def _verify_error(mba) -> str | None:
    try:
        mba.verify(True)
    except Exception as exc:  # pragma: no cover - real IDA failure surface
        return f"{type(exc).__name__}: {exc}"
    return None


@pytest.mark.ida_required
class TestCreateConditionalRedirectIntegration:
    binary_name = _get_default_binary()

    def test_legacy_like_goto_batch_rejects_two_way_goto_rewrite(
        self,
        libobfuscated_setup,
    ) -> None:
        func_ea = get_func_ea("approov_real_pattern")
        if func_ea == 0xFFFFFFFFFFFFFFFF:
            pytest.skip("Function 'approov_real_pattern' not found")

        mba = gen_microcode_at_maturity(func_ea, ida_hexrays.MMAT_GLBOPT1)
        if mba is None:
            pytest.skip("Failed to generate GLBOPT1 microcode for approov_real_pattern")

        legacy_like = dm.DeferredGraphModifier(
            mba, mutation_gateway=make_mutation_gateway(mba)
        )
        legacy_like.queue_goto_change(2, 8, description="legacy-like goto 2->8")
        legacy_like.queue_goto_change(8, 9, description="legacy-like goto 8->9")
        applied = legacy_like.apply(run_optimize_local=True, run_deep_cleaning=False)
        # BLOCK_GOTO_CHANGE is legal only on 1-way blocks. blk[8] is 2-way in
        # this pattern, so the second queued legacy mutation must be rejected
        # and the batch must abort before compounding CFG corruption. Do not
        # "fix" this back to 2: rewriting a 2-way block via goto loses a branch.
        assert applied == 1
        assert _verify_error(mba) is None
        mba.mark_chains_dirty()
        assert _verify_error(mba) is None


def test_apply_pre_rejects_duplicate_block_with_fallthrough_predecessor(monkeypatch):
    mba = _FakeMBA()
    source = _FakeBlock(5)
    pred = _FakeBlock(6)
    target = _FakeBlock(7)
    pred.nsucc = lambda: 2  # type: ignore[assignment]
    pred.tail = SimpleNamespace(
        opcode=ida_hexrays.m_jnz,
        ea=0x1000,
        l=None,
        r=None,
        d=SimpleNamespace(t=ida_hexrays.mop_b, b=99),
    )
    source.nsucc = lambda: 1  # type: ignore[assignment]
    mba.blocks.update({5: source, 6: pred, 7: target})
    mba.qty = len(mba.blocks)

    modifier = dm.DeferredGraphModifier(
        mba, mutation_gateway=make_mutation_gateway(mba)
    )
    modifier.modifications = [
        dm.QueuedModification(
            dm.ModificationType.BLOCK_DUPLICATE_AND_REDIRECT,
            block_serial=5,
            via_pred=6,
            new_target=7,
            description="duplicate fallthrough edge should pre-reject",
        )
    ]

    called = {"apply_single": 0}
    monkeypatch.setattr(
        modifier,
        "_apply_single",
        lambda _m: (
            called.__setitem__("apply_single", called["apply_single"] + 1) or True
        ),
    )
    monkeypatch.setattr(dm, "_format_block_info", lambda _blk: "<blk>")
    monkeypatch.setattr(dm, "safe_verify", lambda *_a, **_k: None)
    monkeypatch.setattr(
        dm,
        "mba_deep_cleaning",
        lambda *_a, **_k: setattr(mba, "cleaned", mba.cleaned + 1),
    )

    applied = modifier.apply(run_optimize_local=False, run_deep_cleaning=False)

    assert applied == 0
    assert called["apply_single"] == 0


def test_duplicate_block_rejects_unexpected_secondary_serial(monkeypatch):
    mba = _FakeMBA()
    source = _FakeBlock(5)
    pred = _FakeBlock(6)
    pred.succ = lambda _idx: 5  # type: ignore[assignment]
    source.nsucc = lambda: 2  # type: ignore[assignment]
    mba.blocks.update({5: source, 6: pred})
    mba.qty = len(mba.blocks)

    modifier = dm.DeferredGraphModifier(
        mba, mutation_gateway=make_mutation_gateway(mba)
    )

    monkeypatch.setattr(
        dm,
        "duplicate_block",
        lambda *_a, **_k: (_FakeBlock(7), _FakeBlock(8)),
    )

    calls = {"pred": 0, "clone": 0}
    monkeypatch.setattr(
        dm,
        "change_1way_block_successor",
        lambda blk, *_a, **_k: (
            (
                calls.__setitem__("pred", calls["pred"] + 1)
                if blk.serial == 6
                else calls.__setitem__("clone", calls["clone"] + 1)
            )
            or True
        ),
    )

    ok = modifier._apply_duplicate_block_and_redirect(
        source_blk=source,
        pred_serial=6,
        target_serial=None,
        expected_serial=7,
        expected_secondary_serial=9,
    )

    assert ok is False
    assert calls["pred"] == 0
    assert calls["clone"] == 0


def test_duplicate_block_applies_explicit_conditional_targets(monkeypatch):
    mba = _FakeMBA()
    source = _FakeBlock(5)
    pred = _FakeBlock(6)
    conditional_target = _FakeBlock(30)
    fallthrough_target = _FakeBlock(40)
    duplicated_blk = _FakeBlock(7)
    duplicated_default = _FakeBlock(8)

    source.type = ida_hexrays.BLT_2WAY
    source.nsucc = lambda: 2  # type: ignore[assignment]
    source.succ = lambda idx: (2, 10)[idx]  # type: ignore[assignment]
    source.tail = SimpleNamespace(
        opcode=ida_hexrays.m_jnz,
        ea=0x1000,
        l=None,
        r=None,
        d=SimpleNamespace(t=ida_hexrays.mop_b, b=2),
    )
    pred.succ = lambda _idx: 5  # type: ignore[assignment]
    duplicated_blk.succset = _FakeEdgeSet([2, 10])
    duplicated_blk.predset = _FakeEdgeSet([6])

    mba.blocks.update(
        {5: source, 6: pred, 30: conditional_target, 40: fallthrough_target}
    )
    mba.qty = len(mba.blocks)
    mba.copy_block = lambda *_args, **_kwargs: duplicated_blk  # type: ignore[attr-defined]

    modifier = dm.DeferredGraphModifier(
        mba, mutation_gateway=make_mutation_gateway(mba)
    )

    monkeypatch.setattr(dm.ida_hexrays, "is_mcode_jcond", lambda _opcode: True)
    monkeypatch.setattr(
        dm,
        "create_standalone_block",
        lambda *_args, **kwargs: (
            duplicated_default if kwargs.get("target_serial") == 40 else None
        ),
    )

    rewired: dict[str, object] = {}
    monkeypatch.setattr(
        dm,
        "_rewire_edge",
        lambda _blk, old_succs, new_succs, **_kwargs: (
            rewired.update({"old": list(old_succs), "new": list(new_succs)}) or True
        ),
    )

    pred_calls = {"count": 0}
    monkeypatch.setattr(
        dm,
        "change_1way_block_successor",
        lambda blk, new_target, **_kwargs: (
            (
                pred_calls.__setitem__("count", pred_calls["count"] + 1)
                if blk.serial == 6 and new_target == 7
                else None
            )
            or True
        ),
    )

    monkeypatch.setattr(
        dm.ida_hexrays,
        "mop_t",
        lambda: SimpleNamespace(make_blkref=lambda _value: None),
    )

    ok = modifier._apply_duplicate_block_and_redirect(
        source_blk=source,
        pred_serial=6,
        target_serial=None,
        conditional_target=30,
        fallthrough_target=40,
        expected_serial=None,
        expected_secondary_serial=None,
    )

    assert ok is True
    assert rewired == {"old": [2, 10], "new": [8, 30]}
    assert pred_calls["count"] == 1


def test_apply_marks_verify_failed_on_post_apply_hook_exception(monkeypatch):
    mba = _FakeMBA()
    modifier = dm.DeferredGraphModifier(
        mba, mutation_gateway=make_mutation_gateway(mba)
    )
    modifier.modifications = [
        dm.QueuedModification(
            dm.ModificationType.BLOCK_GOTO_CHANGE, block_serial=0, new_target=1
        ),
    ]

    monkeypatch.setattr(modifier, "_apply_single", lambda _m: True)
    monkeypatch.setattr(dm, "_format_block_info", lambda _blk: "<blk>")
    monkeypatch.setattr(dm, "capture_failure_artifact", lambda *_a, **_k: None)
    monkeypatch.setattr(dm, "safe_verify", lambda *_a, **_k: None)
    monkeypatch.setattr(dm, "mba_deep_cleaning", lambda *_a, **_k: None)

    def _hook():
        raise RuntimeError("hook failure")

    applied = modifier.apply(
        run_optimize_local=False,
        run_deep_cleaning=False,
        post_apply_hook=_hook,
    )

    assert applied == 1
    assert modifier.verify_failed is True


def test_apply_skips_post_native_verify_after_contract_failure(monkeypatch):
    mba = _FakeMBA()
    modifier = dm.DeferredGraphModifier(
        mba, mutation_gateway=make_mutation_gateway(mba)
    )
    modifier.modifications = [
        dm.QueuedModification(
            dm.ModificationType.BLOCK_GOTO_CHANGE, block_serial=0, new_target=1
        ),
    ]

    verify_calls = {"count": 0}

    monkeypatch.setattr(modifier, "_apply_single", lambda _m: True)
    monkeypatch.setattr(dm, "_format_block_info", lambda _blk: "<blk>")
    monkeypatch.setattr(dm, "capture_failure_artifact", lambda *_a, **_k: None)
    monkeypatch.setattr(
        dm,
        "safe_verify",
        lambda *_a, **_k: verify_calls.__setitem__("count", verify_calls["count"] + 1),
    )
    monkeypatch.setattr(dm, "mba_deep_cleaning", lambda *_a, **_k: None)

    def _hook():
        raise CfgContractViolationError(
            phase="post",
            violations=(
                InvariantViolation(
                    code="CFG_BAD",
                    message="bad succset",
                    phase="post",
                    block_serial=0,
                ),
            ),
        )

    applied = modifier.apply(
        run_optimize_local=False,
        run_deep_cleaning=False,
        post_apply_hook=_hook,
    )

    assert applied == 1
    assert modifier.verify_failed is True
    assert verify_calls["count"] == 1


def test_apply_rolls_back_snapshot_after_contract_failure(monkeypatch):
    mba = _FakeMBA()
    modifier = dm.DeferredGraphModifier(
        mba, mutation_gateway=make_mutation_gateway(mba)
    )
    modifier.modifications = [
        dm.QueuedModification(
            dm.ModificationType.BLOCK_GOTO_CHANGE, block_serial=0, new_target=1
        ),
    ]

    verify_calls = {"count": 0}
    restored = {"count": 0}

    monkeypatch.setattr(modifier, "_apply_single", lambda _m: True)
    monkeypatch.setattr(
        modifier,
        "_restore_from_snapshot",
        lambda _snap: restored.__setitem__("count", restored["count"] + 1) or True,
    )
    monkeypatch.setattr(dm, "_format_block_info", lambda _blk: "<blk>")
    monkeypatch.setattr(dm, "capture_failure_artifact", lambda *_a, **_k: None)
    monkeypatch.setattr(
        dm, "lift", lambda _mba: SimpleNamespace(num_blocks=1, entry_serial=0)
    )
    monkeypatch.setattr(
        dm,
        "safe_verify",
        lambda *_a, **_k: verify_calls.__setitem__("count", verify_calls["count"] + 1),
    )
    monkeypatch.setattr(dm, "mba_deep_cleaning", lambda *_a, **_k: None)

    def _hook():
        raise CfgContractViolationError(
            phase="post",
            violations=(
                InvariantViolation(
                    code="CFG_BAD",
                    message="bad succset",
                    phase="post",
                    block_serial=0,
                ),
            ),
        )

    applied = modifier.apply(
        run_optimize_local=False,
        run_deep_cleaning=False,
        enable_snapshot_rollback=True,
        post_apply_hook=_hook,
    )

    assert applied == 0
    assert modifier.verify_failed is False
    assert restored["count"] == 1
    assert verify_calls["count"] == 1


def test_apply_rolls_back_failed_mod_and_continues(monkeypatch):
    mba = _FakeMBA()
    modifier = dm.DeferredGraphModifier(
        mba, mutation_gateway=make_mutation_gateway(mba)
    )
    modifier.modifications = [
        dm.QueuedModification(
            dm.ModificationType.BLOCK_GOTO_CHANGE,
            block_serial=0,
            new_target=1,
            description="first",
        ),
        dm.QueuedModification(
            dm.ModificationType.BLOCK_GOTO_CHANGE,
            block_serial=1,
            new_target=2,
            description="second",
        ),
    ]

    apply_calls = {"count": 0}
    rollback_calls = {"count": 0}
    verify_calls = {"count": 0}

    def _apply_single(_mod):
        apply_calls["count"] += 1
        return True

    def _prepare_rollback(mod):
        if mod.description != "first":
            return None

        def _rb():
            rollback_calls["count"] += 1
            return True

        return ("restore first", _rb)

    def _safe_verify(*_args, **_kwargs):
        verify_calls["count"] += 1
        # Call 1: pre-apply verify (unconditional) -> passes through
        # Call 2: after first mod apply -> fails, triggers rollback
        # Call 3: after rollback verify -> passes
        # Call 4: after second mod apply -> passes
        # Call 5: post-apply verify -> passes
        if verify_calls["count"] == 2:
            raise RuntimeError("verify failed")

    monkeypatch.setattr(modifier, "_apply_single", _apply_single)
    monkeypatch.setattr(modifier, "_prepare_rollback", _prepare_rollback)
    monkeypatch.setattr(dm, "_format_block_info", lambda _blk: "<blk>")
    monkeypatch.setattr(dm, "safe_verify", _safe_verify)
    monkeypatch.setattr(dm, "mba_deep_cleaning", lambda *_a, **_k: None)

    applied = modifier.apply(
        run_optimize_local=False,
        run_deep_cleaning=False,
        verify_each_mod=True,
        rollback_on_verify_failure=True,
        continue_on_verify_failure=True,
    )

    assert applied == 1
    assert apply_calls["count"] == 2
    assert rollback_calls["count"] == 1
    assert verify_calls["count"] == 5
    assert modifier.verify_failed is False


def test_apply_sets_verify_failed_if_rollback_cannot_recover(monkeypatch):
    mba = _FakeMBA()
    modifier = dm.DeferredGraphModifier(
        mba, mutation_gateway=make_mutation_gateway(mba)
    )
    modifier.modifications = [
        dm.QueuedModification(
            dm.ModificationType.BLOCK_GOTO_CHANGE,
            block_serial=0,
            new_target=1,
            description="bad",
        ),
    ]

    monkeypatch.setattr(modifier, "_apply_single", lambda _mod: True)
    monkeypatch.setattr(
        modifier,
        "_prepare_rollback",
        lambda _mod: ("restore bad", lambda: False),
    )
    monkeypatch.setattr(dm, "_format_block_info", lambda _blk: "<blk>")

    verify_calls = {"count": 0}

    def _fail_after_precheck(*_args, **_kwargs):
        verify_calls["count"] += 1
        # Call 1: pre-apply verify -> pass (no pre-existing stale succset)
        # Call 2+: per-mod verify -> fail, triggering rollback path
        if verify_calls["count"] > 1:
            raise RuntimeError("verify failed")

    monkeypatch.setattr(dm, "safe_verify", _fail_after_precheck)
    monkeypatch.setattr(dm, "mba_deep_cleaning", lambda *_a, **_k: None)

    applied = modifier.apply(
        run_optimize_local=False,
        run_deep_cleaning=False,
        verify_each_mod=True,
        rollback_on_verify_failure=True,
        continue_on_verify_failure=True,
    )

    assert applied == 0
    assert modifier.verify_failed is True


# ---------------------------------------------------------------------------
#  Helpers for PrivateTerminalSuffix tests
# ---------------------------------------------------------------------------


class _SuffixEdgeSet(_FakeEdgeSet):
    """Extended edge set with __iter__, __len__, and _del for suffix tests."""

    def __iter__(self):
        return iter(list(self._items))

    def __len__(self) -> int:
        return len(self._items)

    def _del(self, val: int) -> None:
        try:
            self._items.remove(val)
        except ValueError:
            pass


class _FakeInsn:
    """Minimal instruction stub with a linked-list ``next`` pointer."""

    def __init__(self, opcode: int = 0, ea: int = 0x1000):
        self.opcode = opcode
        self.ea = ea
        self.next = None  # type: _FakeInsn | None

    def setaddr(self, _ea: int) -> None:
        pass


def _make_suffix_block(
    serial: int,
    *,
    nsucc: int = 1,
    succ_serial: int = 0,
    insn_opcodes: tuple[int, ...] = (),
    tail_opcode: int | None = None,
) -> _FakeBlock:
    """Build a _FakeBlock with configurable successor count and instruction chain."""
    blk = _FakeBlock(serial)
    blk.succset = _SuffixEdgeSet([succ_serial] if nsucc >= 1 else [])
    blk.predset = _SuffixEdgeSet()
    blk.nsucc = lambda _nsucc=nsucc: _nsucc  # type: ignore[assignment]
    blk.succ = lambda _idx, _s=succ_serial: _s  # type: ignore[assignment]

    # Build instruction linked list
    head = None
    prev = None
    for opc in insn_opcodes or (ida_hexrays.m_nop,):
        ins = _FakeInsn(opcode=opc, ea=0x1000 + serial)
        if head is None:
            head = ins
        if prev is not None:
            prev.next = ins
        prev = ins

    blk.head = head
    if tail_opcode is not None and head is not None:
        # Walk to tail and set its opcode
        cur = head
        while cur.next is not None:
            cur = cur.next
        cur.opcode = tail_opcode
        blk.tail = cur
    elif head is not None:
        cur = head
        while cur.next is not None:
            cur = cur.next
        blk.tail = cur
    else:
        blk.tail = None

    return blk


def _build_suffix_mba(blocks: dict[int, _FakeBlock]) -> _FakeMBA:
    """Build a _FakeMBA with the given blocks."""
    mba = _FakeMBA()
    mba.blocks = blocks
    mba.qty = max(blocks.keys()) + 1 if blocks else 0
    return mba


def _patch_suffix_dependencies(monkeypatch, mba):
    """Monkeypatch ida_hexrays.minsn_t copy constructor and create_standalone_block.

    Returns a state dict tracking created clones and successor changes.
    """
    state = {
        "clones_created": [],  # list of (template_serial, clone_serial, is_0_way, target_serial)
        "successor_changes": [],  # list of (blk_serial, new_target)
        "next_serial": mba.qty,  # next serial for new clones
    }

    # Monkeypatch ida_hexrays.minsn_t as identity copy constructor
    original_minsn_t = ida_hexrays.minsn_t
    monkeypatch.setattr(
        dm.ida_hexrays,
        "minsn_t",
        lambda obj, _orig=original_minsn_t: (
            obj if isinstance(obj, _FakeInsn) else _orig(obj)
        ),
    )

    def _fake_create_standalone_block(
        ref_blk, blk_ins, target_serial=None, is_0_way=False, verify=True
    ):
        serial = state["next_serial"]
        state["next_serial"] += 1

        clone = _make_suffix_block(
            serial,
            nsucc=0 if is_0_way else 1,
            succ_serial=target_serial if target_serial is not None else 0,
            insn_opcodes=(ida_hexrays.m_nop,),
        )
        mba.blocks[serial] = clone
        mba.qty = max(mba.blocks.keys()) + 1

        state["clones_created"].append(
            (ref_blk.serial, serial, is_0_way, target_serial)
        )
        return clone

    def _fake_change_1way(blk, new_target, verify=True):
        state["successor_changes"].append((blk.serial, new_target))
        # Update the fake block's successor
        blk.succ = lambda _idx, _t=new_target: _t  # type: ignore[assignment]
        blk.succset = _SuffixEdgeSet([new_target])
        return True

    monkeypatch.setattr(dm, "create_standalone_block", _fake_create_standalone_block)
    monkeypatch.setattr(dm, "change_1way_block_successor", _fake_change_1way)

    return state


class TestEdgeRedirectViaPredSplitCorridor:
    """Apply-time guards for typed predecessor-scoped corridor splits."""

    def test_one_block_corridor_accepts_prior_source_retarget(self, monkeypatch):
        """A one-block corridor may run after the source was already retargeted.

        This models the shared-block reconstruction plan: one predecessor keeps
        the live source block after an earlier rewrite, while later predecessors
        get private one-block copies routed to their own targets.
        """
        pred = _make_suffix_block(
            24, nsucc=1, succ_serial=32, tail_opcode=ida_hexrays.m_goto
        )
        src = _make_suffix_block(
            32, nsucc=1, succ_serial=62, tail_opcode=ida_hexrays.m_goto
        )
        current_target = _make_suffix_block(62, nsucc=1, succ_serial=99)
        new_target = _make_suffix_block(70, nsucc=1, succ_serial=99)
        src.predset.push_back(24)

        mba = _build_suffix_mba({24: pred, 32: src, 62: current_target, 70: new_target})
        state = _patch_suffix_dependencies(monkeypatch, mba)
        modifier = dm.DeferredGraphModifier(
            mba, mutation_gateway=make_mutation_gateway(mba)
        )

        ok = modifier._apply_edge_redirect_via_pred_split_corridor(
            blk=src,
            old_target=2,
            new_target=70,
            via_pred=24,
            clone_until=32,
        )

        assert ok is True
        assert len(state["clones_created"]) == 1
        template_serial, clone_serial, is_0_way, target_serial = state[
            "clones_created"
        ][0]
        assert (template_serial, is_0_way, target_serial) == (32, False, 70)
        assert state["successor_changes"] == [(24, clone_serial)]
        assert src.succ(0) == 62

    def test_one_block_corridor_can_clone_when_source_already_on_target(
        self, monkeypatch
    ):
        """The private-copy proof remains valid after the original source retargets."""
        pred = _make_suffix_block(
            24, nsucc=1, succ_serial=32, tail_opcode=ida_hexrays.m_goto
        )
        src = _make_suffix_block(
            32, nsucc=1, succ_serial=62, tail_opcode=ida_hexrays.m_goto
        )
        target = _make_suffix_block(62, nsucc=1, succ_serial=99)
        src.predset.push_back(24)

        mba = _build_suffix_mba({24: pred, 32: src, 62: target})
        state = _patch_suffix_dependencies(monkeypatch, mba)
        modifier = dm.DeferredGraphModifier(
            mba, mutation_gateway=make_mutation_gateway(mba)
        )

        ok = modifier._apply_edge_redirect_via_pred_split_corridor(
            blk=src,
            old_target=2,
            new_target=62,
            via_pred=24,
            clone_until=32,
        )

        assert ok is True
        assert len(state["clones_created"]) == 1
        template_serial, clone_serial, is_0_way, target_serial = state[
            "clones_created"
        ][0]
        assert (template_serial, is_0_way, target_serial) == (32, False, 62)
        assert state["successor_changes"] == [(24, clone_serial)]
        assert src.succ(0) == 62

    def test_multi_block_corridor_rejects_prior_source_retarget(self, monkeypatch):
        """Multi-block corridor proof remains tied to the planned old target."""
        pred = _make_suffix_block(
            9, nsucc=1, succ_serial=10, tail_opcode=ida_hexrays.m_goto
        )
        src = _make_suffix_block(
            10, nsucc=1, succ_serial=11, tail_opcode=ida_hexrays.m_goto
        )
        tail = _make_suffix_block(
            11, nsucc=1, succ_serial=12, tail_opcode=ida_hexrays.m_goto
        )
        src.predset.push_back(9)

        mba = _build_suffix_mba({9: pred, 10: src, 11: tail})
        state = _patch_suffix_dependencies(monkeypatch, mba)
        modifier = dm.DeferredGraphModifier(
            mba, mutation_gateway=make_mutation_gateway(mba)
        )

        ok = modifier._apply_edge_redirect_via_pred_split_corridor(
            blk=src,
            old_target=2,
            new_target=70,
            via_pred=9,
            clone_until=11,
        )

        assert ok is False
        assert state["clones_created"] == []
        assert state["successor_changes"] == []


# ---------------------------------------------------------------------------
#  TestPrivateTerminalSuffix
# ---------------------------------------------------------------------------


class TestPrivateTerminalSuffix:
    """Tests for _apply_private_terminal_suffix covering P1 fixes."""

    def test_apply_suffix_creates_private_chain(self, monkeypatch):
        """Queue and apply a 2-block suffix (S->T) for anchor A.

        Topology before:  A(1) -> S(2) -> T(3, 0-way stop)
        Expected after:   A(1) -> clone_S(4) -> clone_T(5, 0-way)
                          S(2) -> T(3) still exists unchanged.
        """
        # Block 3 is 0-way (BLT_STOP equivalent), block 2 is 1-way -> 3
        blk_a = _make_suffix_block(
            1, nsucc=1, succ_serial=2, tail_opcode=ida_hexrays.m_goto
        )
        blk_s = _make_suffix_block(
            2, nsucc=1, succ_serial=3, tail_opcode=ida_hexrays.m_goto
        )
        blk_t = _make_suffix_block(
            3, nsucc=0, succ_serial=0, tail_opcode=ida_hexrays.m_nop
        )

        mba = _build_suffix_mba({1: blk_a, 2: blk_s, 3: blk_t})
        state = _patch_suffix_dependencies(monkeypatch, mba)
        modifier = dm.DeferredGraphModifier(
            mba, mutation_gateway=make_mutation_gateway(mba)
        )

        ok = modifier._apply_private_terminal_suffix(
            anchor_blk=blk_a,
            shared_entry_serial=2,
            suffix_serials=(2, 3),
            clone_expected_serials=(),
        )

        assert ok is True

        # Two clones created: one for S (serial 4), one for T (serial 5)
        assert len(state["clones_created"]) == 2
        clone_s_info = state["clones_created"][0]
        clone_t_info = state["clones_created"][1]
        assert clone_s_info[0] == 2  # template = S
        assert clone_s_info[2] is False  # not 0-way (interior)
        assert clone_s_info[3] == 2  # placeholder target = shared_entry_serial
        assert clone_t_info[0] == 3  # template = T
        assert clone_t_info[2] is True  # 0-way (final)
        assert clone_t_info[3] is None  # no target for 0-way

        clone_s_serial = clone_s_info[1]
        clone_t_serial = clone_t_info[1]

        # Successor changes: chain wiring + anchor redirect
        # 1. Wire clone_S -> clone_T
        # 2. Redirect anchor A -> clone_S
        wiring_changes = [
            (s, t)
            for s, t in state["successor_changes"]
            if s not in (1,)  # exclude anchor redirect and stop-block fixes
            and s >= 4  # only cloned blocks
        ]
        anchor_redirects = [(s, t) for s, t in state["successor_changes"] if s == 1]

        assert any(
            s == clone_s_serial and t == clone_t_serial for s, t in wiring_changes
        ), (
            f"Expected clone_S({clone_s_serial}) -> clone_T({clone_t_serial}), got {wiring_changes}"
        )
        assert any(t == clone_s_serial for _, t in anchor_redirects), (
            f"Expected anchor redirect to clone_S({clone_s_serial}), got {anchor_redirects}"
        )

        # Original S->T chain is unchanged (blocks still in MBA)
        assert 2 in mba.blocks
        assert 3 in mba.blocks

    def test_apply_suffix_anchor_wrong_successor_fails_closed(self, monkeypatch):
        """When anchor does NOT point at shared_entry_serial, apply rejects (P1 Bug 2)."""
        # Anchor points at block 5 (not the shared entry 2)
        blk_a = _make_suffix_block(
            1, nsucc=1, succ_serial=5, tail_opcode=ida_hexrays.m_goto
        )
        blk_s = _make_suffix_block(
            2, nsucc=1, succ_serial=3, tail_opcode=ida_hexrays.m_goto
        )
        blk_t = _make_suffix_block(3, nsucc=0, succ_serial=0)
        blk_other = _make_suffix_block(5, nsucc=1, succ_serial=3)

        mba = _build_suffix_mba({1: blk_a, 2: blk_s, 3: blk_t, 5: blk_other})
        state = _patch_suffix_dependencies(monkeypatch, mba)
        modifier = dm.DeferredGraphModifier(
            mba, mutation_gateway=make_mutation_gateway(mba)
        )

        ok = modifier._apply_private_terminal_suffix(
            anchor_blk=blk_a,
            shared_entry_serial=2,  # anchor points at 5, not 2
            suffix_serials=(2, 3),
            clone_expected_serials=(),
        )

        assert ok is False
        # No clones should have been created
        assert len(state["clones_created"]) == 0
        # Anchor successor unchanged
        assert blk_a.succ(0) == 5

    def test_apply_suffix_multi_block_chain(self, monkeypatch):
        """3-block suffix (S1->S2->T) exercises multi-block chain wiring (P1 Bug 3).

        Non-final clones must get placeholder target_serial for chain wiring.
        """
        blk_a = _make_suffix_block(
            1, nsucc=1, succ_serial=2, tail_opcode=ida_hexrays.m_goto
        )
        blk_s1 = _make_suffix_block(
            2, nsucc=1, succ_serial=3, tail_opcode=ida_hexrays.m_goto
        )
        blk_s2 = _make_suffix_block(
            3, nsucc=1, succ_serial=4, tail_opcode=ida_hexrays.m_goto
        )
        blk_t = _make_suffix_block(4, nsucc=0, succ_serial=0)

        mba = _build_suffix_mba({1: blk_a, 2: blk_s1, 3: blk_s2, 4: blk_t})
        state = _patch_suffix_dependencies(monkeypatch, mba)
        modifier = dm.DeferredGraphModifier(
            mba, mutation_gateway=make_mutation_gateway(mba)
        )

        ok = modifier._apply_private_terminal_suffix(
            anchor_blk=blk_a,
            shared_entry_serial=2,
            suffix_serials=(2, 3, 4),
            clone_expected_serials=(),
        )

        assert ok is True

        # Three clones created
        assert len(state["clones_created"]) == 3

        # Non-final clones (S1, S2) get placeholder target (shared_entry_serial=2)
        clone_s1_info = state["clones_created"][0]
        clone_s2_info = state["clones_created"][1]
        clone_t_info = state["clones_created"][2]

        assert clone_s1_info[2] is False  # not 0-way
        assert clone_s1_info[3] == 2  # placeholder target = shared_entry_serial
        assert clone_s2_info[2] is False  # not 0-way
        assert clone_s2_info[3] == 2  # placeholder target = shared_entry_serial
        assert clone_t_info[2] is True  # 0-way (final)
        assert clone_t_info[3] is None  # no target

        clone_s1_serial = clone_s1_info[1]
        clone_s2_serial = clone_s2_info[1]
        clone_t_serial = clone_t_info[1]

        # Chain wiring: clone_S1 -> clone_S2 -> clone_T
        chain_wires = [
            (s, t)
            for s, t in state["successor_changes"]
            if s in (clone_s1_serial, clone_s2_serial)
        ]
        assert (clone_s1_serial, clone_s2_serial) in chain_wires
        assert (clone_s2_serial, clone_t_serial) in chain_wires

        # Anchor redirect: A -> clone_S1
        assert any(
            s == 1 and t == clone_s1_serial for s, t in state["successor_changes"]
        )

    def test_apply_suffix_clone_serial_mismatch_non_fatal(self, monkeypatch):
        """Expected serials that don't match actual IDA serials are non-fatal (P1 Bug 1).

        Apply must still succeed with clones created and anchor rewired.
        """
        blk_a = _make_suffix_block(
            1, nsucc=1, succ_serial=2, tail_opcode=ida_hexrays.m_goto
        )
        blk_s = _make_suffix_block(
            2, nsucc=1, succ_serial=3, tail_opcode=ida_hexrays.m_goto
        )
        blk_t = _make_suffix_block(3, nsucc=0, succ_serial=0)

        mba = _build_suffix_mba({1: blk_a, 2: blk_s, 3: blk_t})
        state = _patch_suffix_dependencies(monkeypatch, mba)
        modifier = dm.DeferredGraphModifier(
            mba, mutation_gateway=make_mutation_gateway(mba)
        )

        # Expected serials (99, 100) will NOT match actual (4, 5)
        ok = modifier._apply_private_terminal_suffix(
            anchor_blk=blk_a,
            shared_entry_serial=2,
            suffix_serials=(2, 3),
            clone_expected_serials=(99, 100),
        )

        # Must succeed despite serial mismatch (informational only)
        assert ok is True
        assert len(state["clones_created"]) == 2

        # Anchor was redirected to actual clone serial (not the expected one)
        clone_s_serial = state["clones_created"][0][1]
        assert any(
            s == 1 and t == clone_s_serial for s, t in state["successor_changes"]
        )


# ---------------------------------------------------------------------------
#  TestStagedAtomic -- Strategy B: stage-into-new-blocks apply path
# ---------------------------------------------------------------------------


class _StagedFakeBlock(_FakeBlock):
    """Extended fake block with configurable nsucc, iterable predset, and stable ``start`` EA.

    The ``start`` field models ``mblock_t.start`` — the byte-address range
    start, which IDA guarantees is stable across ``insert_block`` /
    ``copy_block`` / ``remove_block``.  Serials shift; ``start`` does not.
    The staged_atomic Bug 3 fix re-resolves blocks by ``start`` EA at every
    phase boundary so stale serials are never dereferenced.
    """

    def __init__(
        self,
        serial: int,
        *,
        nsucc: int = 1,
        succ_serial: int = 0,
        start: int | None = None,
    ):
        super().__init__(serial, start=start)
        self.succset = _SuffixEdgeSet([succ_serial] if nsucc >= 1 else [])
        self.predset = _SuffixEdgeSet()
        self._nsucc_override = nsucc
        self._succ_override = succ_serial

    def nsucc(self) -> int:  # type: ignore[override]
        return self.succset.size()

    def succ(self, _idx: int) -> int:  # type: ignore[override]
        return self.succset[_idx]


class _StagedFakeMBA(_FakeMBA):
    """Extended fake MBA with copy_block + remove_block hooks for staging tests.

    ``get_mblock(serial)`` respects the positional block array: after a
    simulated ``remove_block`` or ``copy_block`` shifts serials, lookups
    by the *old* serial return the block now sitting at that index, not
    the original block.  This reproduces the serial-shift behaviour of
    real IDA MBA that exposed Bug 3 in the staged_atomic pipeline.
    """

    def __init__(self):
        super().__init__()
        self.copied_blocks: list[tuple[int, int]] = []  # (src_serial, new_serial)
        self.removed_blocks: list[int] = []
        # Inject a BLT_STOP block so mba.qty - 1 is valid.
        self.blocks[1] = _StagedFakeBlock(1, nsucc=0)
        self.qty = 2

    def copy_block(self, src_blk, new_serial, cpblk_flags=3):
        """Simulate mba.copy_block -- append a copy at new_serial, shift BLT_STOP.

        The freshly-minted copy gets a fresh ``start`` EA (distinct from the
        source) so tests can confirm the staged_atomic pipeline tracks each
        block by its stable start address.
        """
        # Synthesize a fresh start EA for the copy — in real IDA the
        # copy shares the source's byte range, but for test purposes we
        # need a distinct EA so we can validate EA-based resolution of
        # copy-vs-original.  Place it in the high range so it doesn't
        # collide with existing fake blocks.
        fresh_start = 0x1F000000 + len(self.copied_blocks) * 0x100
        copy = _StagedFakeBlock(new_serial, nsucc=0, start=fresh_start)
        # Faithfully replicate the full succset (2-way blocks need both edges).
        for k in range(src_blk.succset.size()):
            copy.succset.push_back(src_blk.succset[k])
        copy.type = src_blk.type
        copy.tail = src_blk.tail
        # copy_block inherits predset/succset from src
        for k in range(src_blk.predset.size()):
            copy.predset.push_back(src_blk.predset[k])
        self.copied_blocks.append((src_blk.serial, new_serial))

        # Shift existing BLT_STOP (highest serial) up by one — this is
        # exactly the serial-drift pattern that makes serial-based handles
        # unsafe in the staged_atomic pipeline.
        max_existing = max(self.blocks.keys())
        old_stop = self.blocks.pop(max_existing)
        new_stop_serial = max_existing + 1
        old_stop.serial = new_stop_serial
        self.blocks[new_stop_serial] = old_stop
        self.blocks[new_serial] = copy
        self.qty = new_stop_serial + 1
        return copy

    def remove_block(self, blk):
        self.removed_blocks.append(blk.serial)
        if blk.serial in self.blocks:
            del self.blocks[blk.serial]

    def simulate_serial_shift(self, *, removed_serial: int) -> None:
        """Helper: simulate IDA's post-``remove_block`` serial compaction.

        Real IDA ``remove_block`` shifts every serial greater than the
        removed index down by one.  ``_StagedFakeMBA.remove_block`` by
        itself only deletes the dict entry; this helper mirrors the
        positional-compaction behaviour so unit tests can exercise the
        EA-based lookup under *real* serial drift.
        """
        shifted: dict[int, _StagedFakeBlock] = {}
        for serial, blk in self.blocks.items():
            if serial > removed_serial:
                new_serial = serial - 1
                blk.serial = new_serial
                shifted[new_serial] = blk
            else:
                shifted[serial] = blk
        self.blocks = shifted
        self.qty = max(self.blocks.keys()) + 1 if self.blocks else 0


def _staged_patch_wiring(monkeypatch, mba):
    """Patch change_*_block_successor to operate on _StagedFakeBlock succset."""
    changes: list[tuple[int, int, str]] = []

    def _fake_1way(blk, new_target, verify=True):
        old_target = blk.succset[0] if blk.succset.size() > 0 else None
        blk.succset.clear()
        blk.succset.push_back(new_target)
        if old_target is not None:
            old_succ = mba.get_mblock(old_target)
            if old_succ is not None:
                old_succ.predset._del(blk.serial)
        new_succ = mba.get_mblock(new_target)
        if new_succ is not None:
            new_succ.predset.push_back(blk.serial)
        changes.append((blk.serial, new_target, "1way"))
        return True

    def _fake_2way(blk, new_target, verify=True, old_target=None):
        if blk.tail is not None and hasattr(blk.tail, "d") and blk.tail.d is not None:
            blk.tail.d.b = new_target
        blk.succset.clear()
        blk.succset.push_back(new_target)
        new_succ = mba.get_mblock(new_target)
        if new_succ is not None:
            new_succ.predset.push_back(blk.serial)
        changes.append((blk.serial, new_target, "2way"))
        return True

    def _fake_0way(blk, new_target, verify=True, *, instruction_ea=None):
        del instruction_ea
        assert blk.succset.size() == 0
        blk.succset.push_back(new_target)
        new_succ = mba.get_mblock(new_target)
        if new_succ is not None:
            new_succ.predset.push_back(blk.serial)
        changes.append((blk.serial, new_target, "0way"))
        return True

    def _fake_make_goto(blk, new_target, verify=True):
        blk.succset.clear()
        blk.succset.push_back(new_target)
        changes.append((blk.serial, new_target, "make_goto"))
        return True

    def _fake_remove_edge(blk, to_serial, verify=True):
        blk.succset._del(to_serial)
        changes.append((blk.serial, to_serial, "remove_edge"))
        return True

    monkeypatch.setattr(dm, "change_1way_block_successor", _fake_1way)
    monkeypatch.setattr(dm, "change_2way_block_conditional_successor", _fake_2way)
    monkeypatch.setattr(dm, "change_0way_block_successor", _fake_0way)
    monkeypatch.setattr(dm, "make_2way_block_goto", _fake_make_goto)
    monkeypatch.setattr(dm, "remove_block_edge", _fake_remove_edge)
    monkeypatch.setattr(dm, "_format_block_info", lambda _blk: "<blk>")
    monkeypatch.setattr(dm, "safe_verify", lambda *_a, **_k: None)
    monkeypatch.setattr(
        dm,
        "mba_deep_cleaning",
        lambda *_a, **_k: setattr(mba, "cleaned", mba.cleaned + 1),
    )

    return changes


class TestStagedAtomicClassification:
    """Module-level classification helpers for staged_atomic."""

    def test_classify_for_staged_atomic_goto_is_destructive_expressible(self):
        """BLOCK_GOTO_CHANGE is a destructive-expressible mod under staged_atomic."""
        cls = dm.classify_for_staged_atomic(dm.ModificationType.BLOCK_GOTO_CHANGE)
        assert cls == dm.StagedAtomicClassification.DESTRUCTIVE_EXPRESSIBLE

    def test_classify_for_staged_atomic_insn_nop_is_instruction_only(self):
        """INSN_NOP touches instructions only, never topology."""
        cls = dm.classify_for_staged_atomic(dm.ModificationType.INSN_NOP)
        assert cls == dm.StagedAtomicClassification.INSTRUCTION_ONLY

    def test_classify_for_staged_atomic_reorder_is_additive(self):
        """REORDER_BLOCKS already uses copy_block pattern -- classified ADDITIVE."""
        cls = dm.classify_for_staged_atomic(dm.ModificationType.REORDER_BLOCKS)
        assert cls == dm.StagedAtomicClassification.ADDITIVE

    def test_classify_all_known_mod_types_have_classification(self):
        """Every ModificationType must have a staged_atomic classification."""
        for mod_type in dm.ModificationType:
            cls = dm.classify_for_staged_atomic(mod_type)
            assert isinstance(cls, dm.StagedAtomicClassification), (
                f"{mod_type.name} returned {cls!r}"
            )

    def test_classify_destructive_expressible_bucket_contents(self):
        """Every in-place topology mutation must use staged copy-and-swap."""
        expected = {
            dm.ModificationType.BLOCK_GOTO_CHANGE,
            dm.ModificationType.BLOCK_TARGET_CHANGE,
            dm.ModificationType.BLOCK_TERMINAL_GOTO_CHANGE,
            dm.ModificationType.BLOCK_CONVERT_TO_GOTO,
            dm.ModificationType.EDGE_REMOVE,
            dm.ModificationType.MATERIALIZE_ZERO_WAY_CONDITIONAL,
            dm.ModificationType.MATERIALIZE_ZERO_WAY_GOTO,
            dm.ModificationType.LOWER_CONDITIONAL_STATE_TRANSITION,
        }
        actual = {
            mt
            for mt in dm.ModificationType
            if dm.classify_for_staged_atomic(mt)
            == dm.StagedAtomicClassification.DESTRUCTIVE_EXPRESSIBLE
        }
        assert actual == expected


class TestStagedAtomicPendingRewire:
    """Data contract for the _StagedPendingRewire record."""

    def test_pending_rewire_carries_block_pointers(self):
        """_StagedPendingRewire holds direct mblock_t pointers.

        Bug 4 fix: copy_block preserves source ``start`` EA, so
        EA-based lookup cannot distinguish original from copy.  The
        record now holds direct block pointers (stable across
        insert_block/copy_block) and uses them for all phase-boundary
        re-resolution.  Serial/EA fields are kept for diagnostics.
        """
        orig = _FakeBlock(10, start=0x1800C100)
        new = _FakeBlock(42, start=0x1F000000)
        pred_a = _FakeBlock(5, start=0x1800C500)
        pred_b = _FakeBlock(6, start=0x1800C600)
        rw = dm._StagedPendingRewire(
            original_blk=orig,
            new_blk=new,
            preds_to_redirect=(pred_a, pred_b),
            mod_type=dm.ModificationType.BLOCK_GOTO_CHANGE,
            original_serial=10,
            new_serial=42,
            original_start_ea=0x1800C100,
            new_start_ea=0x1F000000,
        )
        assert rw.original_blk is orig
        assert rw.new_blk is new
        assert rw.preds_to_redirect == (pred_a, pred_b)
        assert rw.original_serial == 10
        assert rw.new_serial == 42
        assert rw.original_start_ea == 0x1800C100
        assert rw.new_start_ea == 0x1F000000
        import dataclasses

        assert dataclasses.is_dataclass(rw)


class TestStagedAtomicApply:
    """Integration tests for DeferredGraphModifier.apply(staged_atomic=True)."""

    def test_staged_atomic_remaps_late_copy_edge_to_earlier_target_copy(
        self,
        monkeypatch,
    ):
        """A staged route must target the staged version of another source.

        Stage the target route first, then a source route that points at that
        target.  The target's predecessor snapshot cannot contain the later
        source copy, so the commit phase must explicitly close this intra-batch
        edge over the final original-to-copy map.
        """
        mba = _StagedFakeMBA()
        external_pred = _StagedFakeBlock(4, nsucc=1, succ_serial=5)
        source = _StagedFakeBlock(5, nsucc=1, succ_serial=30)
        source.predset.push_back(4)
        target = _StagedFakeBlock(10, nsucc=1, succ_serial=30)
        final = _StagedFakeBlock(20, nsucc=0)
        dispatcher = _StagedFakeBlock(30, nsucc=0)
        stop = _StagedFakeBlock(40, nsucc=0)
        stop.type = ida_hexrays.BLT_STOP
        dispatcher.predset.push_back(5)
        dispatcher.predset.push_back(10)
        mba.blocks.update(
            {
                4: external_pred,
                5: source,
                10: target,
                20: final,
                30: dispatcher,
                40: stop,
            }
        )
        mba.qty = max(mba.blocks) + 1

        _staged_patch_wiring(monkeypatch, mba)
        modifier = dm.DeferredGraphModifier(
            mba,
            mutation_gateway=make_mutation_gateway(mba),
        )
        modifier.modifications = [
            dm.QueuedModification(
                dm.ModificationType.BLOCK_GOTO_CHANGE,
                block_serial=10,
                new_target=20,
                description="target route",
            ),
            dm.QueuedModification(
                dm.ModificationType.BLOCK_GOTO_CHANGE,
                block_serial=5,
                new_target=10,
                description="source route to staged target",
            ),
        ]

        applied = modifier.apply(
            run_optimize_local=False,
            run_deep_cleaning=False,
            transactional=True,
            staged_atomic=True,
        )

        assert applied == 2
        assert len(mba.copied_blocks) == 2
        target_copy = mba.get_mblock(mba.copied_blocks[0][1])
        source_copy = mba.get_mblock(mba.copied_blocks[1][1])
        assert target_copy is not None
        assert source_copy is not None
        assert tuple(source_copy.succset) == (int(target_copy.serial),)
        assert int(source_copy.serial) in tuple(target_copy.predset)
        assert int(source_copy.serial) not in tuple(target.predset)

    def test_staged_atomic_conditional_lowering_mutates_only_the_copy(
        self,
        monkeypatch,
    ):
        """Conditional lowering must use copy-and-swap in staged mode."""
        mba = _StagedFakeMBA()
        source = _StagedFakeBlock(5, nsucc=1, succ_serial=20)
        source.predset.push_back(4)
        pred = _StagedFakeBlock(4, nsucc=1, succ_serial=5)
        dispatcher = _StagedFakeBlock(20, nsucc=0)
        false_target = _StagedFakeBlock(30, nsucc=0)
        true_target = _StagedFakeBlock(40, nsucc=0)
        stop = _StagedFakeBlock(50, nsucc=0)
        stop.type = ida_hexrays.BLT_STOP
        mba.blocks.update(
            {
                4: pred,
                5: source,
                20: dispatcher,
                30: false_target,
                40: true_target,
                50: stop,
            }
        )
        mba.qty = max(mba.blocks) + 1
        _staged_patch_wiring(monkeypatch, mba)

        lowered_blocks: list[object] = []

        def _lower(copy_block, **_kwargs):
            lowered_blocks.append(copy_block)
            copy_block.succset.clear()
            copy_block.succset.push_back(40)
            return True

        modifier = dm.DeferredGraphModifier(
            mba,
            mutation_gateway=make_mutation_gateway(mba),
        )
        monkeypatch.setattr(
            modifier,
            "_apply_lower_conditional_state_transition",
            _lower,
        )
        modifier.queue_lower_conditional_state_transition(
            source_serial=5,
            old_dispatcher_serial=20,
            rewrite_from_ea=0x401000,
            condition_operand=object(),
            false_target_serial=30,
            true_target_serial=40,
        )

        applied = modifier.apply(
            run_optimize_local=False,
            run_deep_cleaning=False,
            staged_atomic=True,
        )

        assert applied == 1
        assert len(lowered_blocks) == 1
        assert lowered_blocks[0] is not source
        assert 5 in mba.removed_blocks

    def test_staged_conditional_lowering_rebinds_copied_fallthrough(
        self,
        monkeypatch,
    ):
        """A copied 2-way block validates its new physical fallthrough."""
        mba = _StagedFakeMBA()
        original = _StagedFakeBlock(5, nsucc=2, succ_serial=20)
        original.succset.push_back(21)
        copy = _StagedFakeBlock(50, nsucc=2, succ_serial=51)
        copy.succset.push_back(21)
        mba.blocks.update({5: original, 20: _StagedFakeBlock(20, nsucc=0)})
        mba.blocks.update({21: _StagedFakeBlock(21, nsucc=0), 50: copy})
        mba.qty = 52
        modifier = dm.DeferredGraphModifier(
            mba,
            mutation_gateway=make_mutation_gateway(mba),
        )
        observed_old_dispatchers: list[int] = []

        def _lower(_copy_block, **kwargs):
            observed_old_dispatchers.append(int(kwargs["old_dispatcher_serial"]))
            return True

        monkeypatch.setattr(
            modifier,
            "_apply_lower_conditional_state_transition",
            _lower,
        )
        modification = dm.QueuedModification(
            dm.ModificationType.LOWER_CONDITIONAL_STATE_TRANSITION,
            block_serial=5,
            old_target=20,
            rewrite_from_ea=0x401000,
            condition_operand=object(),
            false_target=30,
            true_target=40,
        )

        assert modifier._apply_destructive_on_copy(
            copy,
            modification,
            original_blk=original,
        )
        assert observed_old_dispatchers == [51]

    def test_staged_atomic_goto_change_stages_copy_and_redirects_preds(
        self,
        monkeypatch,
    ):
        """Destructive-expressible BLOCK_GOTO_CHANGE is lowered to copy-and-swap.

        Before: blk[5] (pred=10) -> blk[20]
        After:  blk[10] -> copy(5) -> blk[30]; original blk[5] orphaned.
        """
        mba = _StagedFakeMBA()
        # Build: blk[5] is 1-way -> blk[20]; blk[10] is pred targeting blk[5].
        src = _StagedFakeBlock(5, nsucc=1, succ_serial=20)
        src.predset.push_back(10)
        pred = _StagedFakeBlock(10, nsucc=1, succ_serial=5)
        tgt = _StagedFakeBlock(20, nsucc=0)
        tgt.predset.push_back(5)
        mba.blocks.update({5: src, 10: pred, 20: tgt})
        mba.qty = max(mba.blocks.keys()) + 1

        changes = _staged_patch_wiring(monkeypatch, mba)

        gateway = make_mutation_gateway(mba)
        modifier = dm.DeferredGraphModifier(mba, mutation_gateway=gateway)
        modifier.modifications = [
            dm.QueuedModification(
                dm.ModificationType.BLOCK_GOTO_CHANGE,
                block_serial=5,
                new_target=30,
                description="goto 5 -> 30",
            ),
        ]

        applied = modifier.apply(
            run_optimize_local=False,
            run_deep_cleaning=False,
            staged_atomic=True,
        )

        # Exactly one copy was staged.
        assert len(mba.copied_blocks) == 1
        src_serial, copy_serial = mba.copied_blocks[0]
        assert src_serial == 5

        # Commit phase redirected pred blk[10] to the copy.
        pred_redirects = [(s, t, kind) for (s, t, kind) in changes if s == 10]
        assert any(t == copy_serial for (_, t, _) in pred_redirects)

        # applied counts both staging and commit rewire.
        assert applied >= 1
        assert gateway.receipts[-1].planned_operation_count == 1
        assert gateway.receipts[-1].operation_count == 1

    def test_staged_atomic_redirects_two_way_fallthrough_to_staged_copy(
        self,
        monkeypatch,
    ):
        """A committed swap must not leave the original on a fallthrough arm."""
        mba = _StagedFakeMBA()
        source = _StagedFakeBlock(5, nsucc=1, succ_serial=20)
        source.predset.push_back(4)
        pred = _StagedFakeBlock(4, nsucc=2, succ_serial=5)
        pred.succset.push_back(30)
        pred.type = ida_hexrays.BLT_2WAY
        pred.tail = SimpleNamespace(
            opcode=ida_hexrays.m_jcnd,
            ea=0x401000,
            d=SimpleNamespace(t=ida_hexrays.mop_b, b=30),
        )
        old_target = _StagedFakeBlock(20, nsucc=0)
        branch_target = _StagedFakeBlock(30, nsucc=0)
        stop = _StagedFakeBlock(40, nsucc=0)
        stop.type = ida_hexrays.BLT_STOP
        mba.blocks.update(
            {
                4: pred,
                5: source,
                20: old_target,
                30: branch_target,
                40: stop,
            }
        )
        mba.qty = max(mba.blocks) + 1
        _staged_patch_wiring(monkeypatch, mba)

        fallthrough_rewrites: list[tuple[int, int, int]] = []
        modifier = dm.DeferredGraphModifier(
            mba,
            mutation_gateway=make_mutation_gateway(mba),
        )

        def _redirect_fallthrough(block, new_target, *, old_target):
            fallthrough_rewrites.append(
                (int(block.serial), int(old_target), int(new_target))
            )
            block.succset._del(int(old_target))
            block.succset.push_back(int(new_target))
            source.predset._del(int(block.serial))
            copy = mba.get_mblock(int(new_target))
            assert copy is not None
            copy.predset.push_back(int(block.serial))
            return True

        monkeypatch.setattr(
            modifier,
            "_apply_fallthrough_change",
            _redirect_fallthrough,
        )
        modifier.modifications = [
            dm.QueuedModification(
                dm.ModificationType.BLOCK_GOTO_CHANGE,
                block_serial=5,
                new_target=30,
                description="goto 5 -> 30 through conditional fallthrough",
            ),
        ]

        applied = modifier.apply(
            run_optimize_local=False,
            run_deep_cleaning=False,
            staged_atomic=True,
        )

        assert applied == 1
        assert len(fallthrough_rewrites) == 1
        _pred_serial, original_serial, copy_serial = fallthrough_rewrites[0]
        assert original_serial == 5
        assert copy_serial in tuple(pred.succset)
        assert original_serial not in tuple(pred.succset)
        assert 5 in mba.removed_blocks
        assert modifier._mutation_gateway.receipts[-1].planned_operation_count == 1
        assert modifier._mutation_gateway.receipts[-1].operation_count == 1

    def test_staged_atomic_terminal_goto_stages_copy_and_redirects_preds(
        self,
        monkeypatch,
    ):
        """A 0-way-to-1-way route is not applied sequentially in staged mode."""
        mba = _StagedFakeMBA()
        source = _StagedFakeBlock(5, nsucc=0)
        source.predset.push_back(10)
        pred = _StagedFakeBlock(10, nsucc=1, succ_serial=5)
        target = _StagedFakeBlock(20, nsucc=0)
        mba.blocks.update({5: source, 10: pred, 20: target})
        mba.qty = max(mba.blocks.keys()) + 1

        changes = _staged_patch_wiring(monkeypatch, mba)
        gateway = make_mutation_gateway(mba)
        modifier = dm.DeferredGraphModifier(mba, mutation_gateway=gateway)
        modifier.modifications = [
            dm.QueuedModification(
                dm.ModificationType.BLOCK_TERMINAL_GOTO_CHANGE,
                block_serial=5,
                new_target=20,
                description="terminal 5 -> 20",
            ),
        ]

        applied = modifier.apply(
            run_optimize_local=False,
            run_deep_cleaning=False,
            staged_atomic=True,
        )

        assert len(mba.copied_blocks) == 1
        _, copy_serial = mba.copied_blocks[0]
        assert (copy_serial, 20, "0way") in changes
        assert any(
            source_serial == 10 and target_serial == copy_serial
            for source_serial, target_serial, _kind in changes
        )
        assert applied >= 1
        assert gateway.receipts[-1].planned_operation_count == 1
        assert gateway.receipts[-1].operation_count == 1

    def test_staged_atomic_instruction_only_bypasses_staging(self, monkeypatch):
        """INSN_NOP must NOT trigger copy_block; it runs through _apply_single."""
        mba = _StagedFakeMBA()
        blk = _StagedFakeBlock(5, nsucc=1, succ_serial=1)
        blk.head = _FakeInsn(opcode=ida_hexrays.m_mov, ea=0x1234)
        blk.tail = blk.head
        mba.blocks[5] = blk
        mba.qty = 6

        _staged_patch_wiring(monkeypatch, mba)

        modifier = dm.DeferredGraphModifier(
            mba, mutation_gateway=make_mutation_gateway(mba)
        )
        modifier.modifications = [
            dm.QueuedModification(
                dm.ModificationType.INSN_NOP,
                block_serial=5,
                insn_ea=0x1234,
                description="nop insn",
            ),
        ]

        nop_calls: list[int] = []

        def _fake_make_nop(self, _ins):
            nop_calls.append(self.serial)

        monkeypatch.setattr(_StagedFakeBlock, "make_nop", _fake_make_nop, raising=False)

        applied = modifier.apply(
            run_optimize_local=False,
            run_deep_cleaning=False,
            staged_atomic=True,
        )

        # No block copies were made: instruction-only mods skip staging.
        assert len(mba.copied_blocks) == 0
        assert applied >= 1

    def test_staged_atomic_default_false_does_not_change_control_flow(
        self,
        monkeypatch,
    ):
        """staged_atomic=False (default) preserves the existing sequential path."""
        mba = _StagedFakeMBA()
        modifier = dm.DeferredGraphModifier(
            mba, mutation_gateway=make_mutation_gateway(mba)
        )
        modifier.modifications = [
            dm.QueuedModification(
                dm.ModificationType.BLOCK_GOTO_CHANGE,
                block_serial=0,
                new_target=1,
            ),
        ]

        captured_calls: list[str] = []

        def _fake_apply_single(_mod):
            captured_calls.append("sequential")
            return True

        monkeypatch.setattr(modifier, "_apply_single", _fake_apply_single)
        monkeypatch.setattr(dm, "_format_block_info", lambda _blk: "<blk>")
        monkeypatch.setattr(dm, "safe_verify", lambda *_a, **_k: None)
        monkeypatch.setattr(dm, "mba_deep_cleaning", lambda *_a, **_k: None)

        applied = modifier.apply(run_optimize_local=False, run_deep_cleaning=False)
        # Default path still uses _apply_single via the sequential for-loop.
        assert applied == 1
        assert captured_calls == ["sequential"]
        # No staging copies performed.
        assert len(mba.copied_blocks) == 0

    def test_staged_atomic_failed_staging_does_not_rewire_preds(self, monkeypatch):
        """If staging fails, no commit rewire is issued and preds stay on original."""
        mba = _StagedFakeMBA()
        src = _StagedFakeBlock(
            5, nsucc=2, succ_serial=20
        )  # 2-way — rejects BLOCK_GOTO_CHANGE staging
        src.succset.push_back(30)
        src.predset.push_back(10)
        pred = _StagedFakeBlock(10, nsucc=1, succ_serial=5)
        mba.blocks.update({5: src, 10: pred})
        mba.qty = max(mba.blocks.keys()) + 1

        changes = _staged_patch_wiring(monkeypatch, mba)

        modifier = dm.DeferredGraphModifier(
            mba, mutation_gateway=make_mutation_gateway(mba)
        )
        modifier.modifications = [
            dm.QueuedModification(
                dm.ModificationType.BLOCK_GOTO_CHANGE,
                block_serial=5,
                new_target=30,
            ),
        ]

        applied = modifier.apply(
            run_optimize_local=False,
            run_deep_cleaning=False,
            staged_atomic=True,
        )

        # Mutation on the copy fails (block is 2-way, not 1-way).
        # BUT: copy_block IS called first (stage step 2).  The mutation (step 3)
        # fails, so NO pending rewire is recorded, and NO external pred is
        # redirected.  Result: pred blk[10] still targets blk[5].
        pred_changes = [(s, t) for (s, t, _) in changes if s == 10]
        assert not pred_changes, f"pred should not be redirected, got {pred_changes}"
        assert applied == 0
        assert all(
            copy_serial not in mba.blocks for _, copy_serial in mba.copied_blocks
        )

    def test_staged_atomic_required_stage_failure_aborts_entire_batch(
        self,
        monkeypatch,
    ):
        """One required staging refusal must prevent every sibling swap."""
        mba = _StagedFakeMBA()
        source = _StagedFakeBlock(5, nsucc=1, succ_serial=20)
        source.predset.push_back(10)
        predecessor = _StagedFakeBlock(10, nsucc=1, succ_serial=5)
        old_target = _StagedFakeBlock(20, nsucc=0)
        new_target = _StagedFakeBlock(30, nsucc=0)
        mba.blocks.update(
            {
                5: source,
                10: predecessor,
                20: old_target,
                30: new_target,
            }
        )
        mba.qty = max(mba.blocks) + 1

        changes = _staged_patch_wiring(monkeypatch, mba)
        removed_copies: list[int] = []

        def _strict_remove_block(self, block):
            if block.succset.size() or block.predset.size():
                raise RuntimeError(f"INTERR 51919: blk[{block.serial}] still has edges")
            removed_copies.append(int(block.serial))
            self.blocks.pop(int(block.serial), None)

        monkeypatch.setattr(
            _StagedFakeMBA,
            "remove_block",
            _strict_remove_block,
        )
        gateway = make_mutation_gateway(mba)
        modifier = dm.DeferredGraphModifier(mba, mutation_gateway=gateway)
        modifier.modifications = [
            dm.QueuedModification(
                dm.ModificationType.BLOCK_GOTO_CHANGE,
                block_serial=5,
                new_target=30,
                description="stageable sibling",
            ),
            dm.QueuedModification(
                dm.ModificationType.LOWER_CONDITIONAL_STATE_TRANSITION,
                block_serial=0,
                old_target=5,
                rewrite_from_ea=0x180000000,
                condition_operand=object(),
                false_target=20,
                true_target=30,
                description="positionally invariant entry consumer",
            ),
        ]

        applied = modifier.apply(
            run_optimize_local=False,
            run_deep_cleaning=False,
            staged_atomic=True,
        )

        assert applied == 0
        assert tuple(predecessor.succset) == (5,)
        assert not [change for change in changes if change[0] == 10]
        assert all(
            copy_serial not in mba.blocks for _, copy_serial in mba.copied_blocks
        )
        assert removed_copies
        assert gateway.receipts == ()
        assert gateway.active is False

    def test_staged_atomic_classify_mixed_bucket(self, monkeypatch):
        """Mixed mod list: one destructive, one instruction-only, one additive."""
        mba = _StagedFakeMBA()
        src = _StagedFakeBlock(5, nsucc=1, succ_serial=20)
        src.predset.push_back(10)
        pred = _StagedFakeBlock(10, nsucc=1, succ_serial=5)
        tgt = _StagedFakeBlock(20, nsucc=0)
        tgt.predset.push_back(5)
        other = _StagedFakeBlock(7, nsucc=1, succ_serial=1)
        other.head = _FakeInsn(opcode=ida_hexrays.m_mov, ea=0x5678)
        other.tail = other.head
        mba.blocks.update({5: src, 10: pred, 20: tgt, 7: other})
        mba.qty = max(mba.blocks.keys()) + 1

        _staged_patch_wiring(monkeypatch, mba)
        # Stub make_nop so INSN_NOP doesn't crash.
        monkeypatch.setattr(
            _StagedFakeBlock,
            "make_nop",
            lambda self, _ins: None,
            raising=False,
        )

        modifier = dm.DeferredGraphModifier(
            mba, mutation_gateway=make_mutation_gateway(mba)
        )
        modifier.modifications = [
            dm.QueuedModification(
                dm.ModificationType.BLOCK_GOTO_CHANGE,
                block_serial=5,
                new_target=30,
                description="destructive",
            ),
            dm.QueuedModification(
                dm.ModificationType.INSN_NOP,
                block_serial=7,
                insn_ea=0x5678,
                description="insn-only",
            ),
        ]

        applied = modifier.apply(
            run_optimize_local=False,
            run_deep_cleaning=False,
            staged_atomic=True,
        )

        # Both mods applied, each through its own path:
        # - destructive via stage + commit rewire
        # - instruction-only via _apply_single
        assert applied >= 2
        # Exactly one copy was made (for the destructive mod's source block).
        assert len(mba.copied_blocks) == 1

    def test_staged_atomic_entry_block_pred_rewires_via_direct_succset(
        self,
        monkeypatch,
    ):
        """Bug 1 — Entry-block (serial 0) rewire must bypass change_1way_block_successor.

        The 1-way wiring helper rejects ``serial == 0`` unconditionally.  When
        the source block's sole pred is the synthetic function-entry block
        (blk[0]), staged_atomic must rewire via direct succset/predset ``_del`` +
        ``push_back`` rather than routing through the rejecting helper.  If the
        direct-rewire path is missing, the entry edge stays on the original
        block and the copy is orphaned from the outside.
        """
        mba = _StagedFakeMBA()
        # Build: entry blk[0] -> blk[5] (1-way) -> blk[20].
        src = _StagedFakeBlock(5, nsucc=1, succ_serial=20)
        src.predset.push_back(0)  # sole pred is the synthetic entry block
        # Make blk[0] a real 1-way block targeting blk[5].  It is the ONLY
        # pred of blk[5] (no other fake preds).
        entry = mba.blocks[0]
        entry.succset = _SuffixEdgeSet([5])
        tgt = _StagedFakeBlock(20, nsucc=0)
        tgt.predset.push_back(5)
        mba.blocks.update({5: src, 20: tgt})
        mba.qty = max(mba.blocks.keys()) + 1

        changes = _staged_patch_wiring(monkeypatch, mba)

        modifier = dm.DeferredGraphModifier(
            mba, mutation_gateway=make_mutation_gateway(mba)
        )
        modifier.modifications = [
            dm.QueuedModification(
                dm.ModificationType.BLOCK_GOTO_CHANGE,
                block_serial=5,
                new_target=30,
                description="goto 5 -> 30 (entry block pred)",
            ),
        ]

        applied = modifier.apply(
            run_optimize_local=False,
            run_deep_cleaning=False,
            staged_atomic=True,
        )

        # A copy was staged.
        assert len(mba.copied_blocks) == 1
        _src_serial, copy_serial = mba.copied_blocks[0]

        # The direct-rewire path must have severed blk[0] -> blk[5] and
        # wired blk[0] -> copy.  Because we bypass change_1way_block_successor
        # for serial 0, no (0, *, "1way") entry is recorded by the patched
        # wiring helpers — we validate the succset/predset state instead.
        assert 5 not in list(entry.succset), (
            "entry blk[0] must no longer target the original blk[5]"
        )
        assert copy_serial in list(entry.succset), (
            "entry blk[0] must target the copy after direct rewire"
        )
        assert 0 not in list(src.predset), (
            "original blk[5] must no longer list blk[0] as a pred"
        )
        copy_blk = mba.get_mblock(copy_serial)
        assert 0 in list(copy_blk.predset), (
            "copy must list blk[0] as a pred after direct rewire"
        )
        # Sanity: no "1way"-style wrapper call ever fired for the entry block.
        assert not any(s == 0 for (s, _t, _k) in changes), (
            "entry-block rewire must avoid change_1way_block_successor "
            "(which rejects serial 0)"
        )
        # Commit rewire counts toward applied.
        assert applied >= 1

    def test_staged_atomic_cleanup_pre_disconnects_edges_before_remove(
        self,
        monkeypatch,
    ):
        """Bug 2 — cleanup must strip succset/predset entries before remove_block.

        IDA's ``mba.remove_block`` errors with INTERR 51919 when the block
        still has outgoing (succset) or incoming (predset) entries at removal
        time.  The cleanup phase must pre-disconnect both sides of every edge
        before invoking ``remove_block``.  Simulate a _StagedFakeMBA whose
        ``remove_block`` raises unless both sides are empty — confirm the
        cleanup phase satisfies the precondition in practice.
        """
        mba = _StagedFakeMBA()
        src = _StagedFakeBlock(5, nsucc=1, succ_serial=20)
        src.predset.push_back(10)
        pred = _StagedFakeBlock(10, nsucc=1, succ_serial=5)
        tgt = _StagedFakeBlock(20, nsucc=0)
        tgt.predset.push_back(5)
        mba.blocks.update({5: src, 10: pred, 20: tgt})
        mba.qty = max(mba.blocks.keys()) + 1

        _staged_patch_wiring(monkeypatch, mba)

        # Tighten remove_block: INTERR 51919 if the block still has edges.
        removed_ok: list[int] = []
        remove_calls: list[
            tuple[int, int, int]
        ] = []  # (serial, succset_sz, predset_sz)

        def _strict_remove_block(self, blk):
            succsz = blk.succset.size()
            predsz = blk.predset.size()
            remove_calls.append((blk.serial, succsz, predsz))
            if succsz != 0 or predsz != 0:
                raise RuntimeError(
                    f"INTERR 51919: blk[{blk.serial}] still has "
                    f"succset={succsz} predset={predsz}"
                )
            removed_ok.append(blk.serial)
            if blk.serial in self.blocks:
                del self.blocks[blk.serial]

        monkeypatch.setattr(_StagedFakeMBA, "remove_block", _strict_remove_block)

        modifier = dm.DeferredGraphModifier(
            mba, mutation_gateway=make_mutation_gateway(mba)
        )
        modifier.modifications = [
            dm.QueuedModification(
                dm.ModificationType.BLOCK_GOTO_CHANGE,
                block_serial=5,
                new_target=30,
                description="goto 5 -> 30 (cleanup test)",
            ),
        ]

        applied = modifier.apply(
            run_optimize_local=False,
            run_deep_cleaning=False,
            staged_atomic=True,
        )

        # The staged rewire + cleanup pipeline must have disconnected
        # edges on the original block BEFORE calling remove_block, so the
        # strict-remove guard never fires INTERR 51919.
        assert remove_calls, "cleanup phase never invoked remove_block"
        assert 5 in removed_ok, (
            "original blk[5] must have been removed after cleanup "
            f"(remove_calls={remove_calls}, removed={removed_ok})"
        )
        # Every recorded remove_block call saw empty succset/predset.
        for serial, succsz, predsz in remove_calls:
            assert succsz == 0, (
                f"remove_block(blk[{serial}]) saw succset size {succsz} -- "
                "cleanup failed to pre-disconnect outgoing edges"
            )
            assert predsz == 0, (
                f"remove_block(blk[{serial}]) saw predset size {predsz} -- "
                "cleanup failed to pre-disconnect incoming edges"
            )
        assert applied >= 1


class TestStagedAtomicEaIdentity:
    """Bug 3 — EA-based identity for stage -> commit -> cleanup pipeline.

    ``mba.remove_block`` / ``mba.copy_block`` / ``mba.insert_block`` shift
    block *serials* while ``mblock_t.start`` (byte-address range start) is
    stable.  The staged_atomic pipeline must therefore use start EAs as
    block *handles* across phase boundaries.  These tests validate:

    1. Staging captures each block's start EA (not just serials).
    2. Commit re-resolves by start EA after simulated serial drift.
    3. Cleanup does not remove the wrong block when serials have shifted.
    4. A captured-EA block removed out-of-band causes a skipped rewire
       with a warning (no crash, no wrong-block mutation).
    """

    def test_get_mblock_by_start_ea_returns_none_when_missing(self):
        """Helper must return None for an unknown EA (no exception)."""
        mba = _StagedFakeMBA()
        assert dm._get_mblock_by_start_ea(mba, 0xDEADBEEF) is None

    def test_get_mblock_by_start_ea_finds_block_after_simulated_shift(self):
        """After a simulated serial shift, EA-based lookup still finds the right block."""
        mba = _StagedFakeMBA()
        src = _StagedFakeBlock(5, nsucc=1, succ_serial=20, start=0x18001000)
        mba.blocks[5] = src
        mba.qty = max(mba.blocks.keys()) + 1

        # Baseline: EA lookup finds the block at serial 5.
        found = dm._get_mblock_by_start_ea(mba, 0x18001000)
        assert found is src
        assert found.serial == 5

        # Simulate a copy_block that shifted serial 5's position.
        # (We manually shift — not via mba.copy_block — to isolate the
        # lookup behaviour under pure serial drift.)
        shifted = {}
        for serial, blk in mba.blocks.items():
            if serial == 5:
                blk.serial = 7
                shifted[7] = blk
            else:
                shifted[serial] = blk
        mba.blocks = shifted
        mba.qty = max(mba.blocks.keys()) + 1

        # Lookup by serial 5 now returns None (or the wrong block).
        # Lookup by start EA must still find the block at its new serial.
        found_after = dm._get_mblock_by_start_ea(mba, 0x18001000)
        assert found_after is src
        assert found_after.serial == 7, "EA-based lookup must find the drifted block"

    def test_stage_captures_start_eas_on_pending_rewire(self, monkeypatch):
        """_stage_destructive_mod_via_copy records start EA for original + copy + preds."""
        mba = _StagedFakeMBA()
        src = _StagedFakeBlock(5, nsucc=1, succ_serial=20, start=0x18005000)
        src.predset.push_back(10)
        pred = _StagedFakeBlock(10, nsucc=1, succ_serial=5, start=0x1800A000)
        tgt = _StagedFakeBlock(20, nsucc=0, start=0x18014000)
        tgt.predset.push_back(5)
        mba.blocks.update({5: src, 10: pred, 20: tgt})
        mba.qty = max(mba.blocks.keys()) + 1

        _staged_patch_wiring(monkeypatch, mba)

        modifier = dm.DeferredGraphModifier(
            mba, mutation_gateway=make_mutation_gateway(mba)
        )
        mod = dm.QueuedModification(
            dm.ModificationType.BLOCK_GOTO_CHANGE,
            block_serial=5,
            new_target=30,
        )
        rewire = modifier._stage_destructive_mod_via_copy(mod, index=0)

        assert rewire is not None, "staging must succeed for 1-way BLOCK_GOTO_CHANGE"
        # Original serial/ea captured pre-copy.
        assert rewire.original_serial == 5
        assert rewire.original_start_ea == 0x18005000
        # Copy got a fresh EA (0x1F000000 by the fake MBA's synthesizer).
        assert rewire.new_start_ea != rewire.original_start_ea
        copy_blk = mba.get_mblock(rewire.new_serial)
        assert copy_blk is not None
        assert rewire.new_start_ea == copy_blk.start
        # Pred snapshot recorded as mblock_t pointers (Bug 4 fix).
        # copy_block preserves source EAs, so EA-based lookup cannot
        # disambiguate original from copy; the record now holds direct
        # pointers captured at stage time.
        assert len(rewire.preds_to_redirect) == 1
        assert rewire.preds_to_redirect[0] is pred

    def test_stage_accepts_nonzero_imported_block_sharing_function_entry_ea(
        self,
        monkeypatch,
    ):
        """A broad imported start EA must not imply positional entry ownership."""
        mba = _StagedFakeMBA()
        source = _StagedFakeBlock(
            5,
            nsucc=1,
            succ_serial=20,
            start=mba.entry_ea,
        )
        source.predset.push_back(10)
        predecessor = _StagedFakeBlock(10, nsucc=1, succ_serial=5)
        target = _StagedFakeBlock(20, nsucc=0)
        target.predset.push_back(5)
        mba.blocks.update({5: source, 10: predecessor, 20: target})
        mba.qty = max(mba.blocks) + 1

        _staged_patch_wiring(monkeypatch, mba)
        modifier = dm.DeferredGraphModifier(
            mba,
            mutation_gateway=make_mutation_gateway(mba),
        )
        modification = dm.QueuedModification(
            dm.ModificationType.BLOCK_GOTO_CHANGE,
            block_serial=5,
            new_target=30,
        )

        rewire = modifier._stage_destructive_mod_via_copy(
            modification,
            index=0,
        )

        assert rewire is not None
        assert rewire.original_blk is source
        assert rewire.original_serial == 5

    def test_staged_goto_change_resolves_remapped_source_to_its_ea(
        self,
        monkeypatch,
    ):
        """A queued goto change must stage the remapped source, not its old slot."""
        mba = _StagedFakeMBA()
        stale_slot = _StagedFakeBlock(
            100,
            nsucc=1,
            succ_serial=102,
            start=0x40B149,
        )
        intended_source = _StagedFakeBlock(
            101,
            nsucc=1,
            succ_serial=102,
            start=0x40B157,
        )
        destination = _StagedFakeBlock(102, nsucc=0, start=0x40B163)
        stop = _StagedFakeBlock(112, nsucc=0)
        stop.type = ida_hexrays.BLT_STOP
        mba.blocks.update(
            {
                100: stale_slot,
                101: intended_source,
                102: destination,
                112: stop,
            }
        )
        mba.qty = 113

        _staged_patch_wiring(monkeypatch, mba)
        modifier = dm.DeferredGraphModifier(
            mba, mutation_gateway=make_mutation_gateway(mba)
        )
        _seed_current_serials(modifier, {100: 101})
        mod = dm.QueuedModification(
            dm.ModificationType.BLOCK_GOTO_CHANGE,
            block_serial=100,
            new_target=102,
        )

        rewire = modifier._stage_destructive_mod_via_copy(mod, index=0)

        assert rewire is not None
        assert rewire.original_start_ea == 0x40B157

    def test_commit_re_resolves_original_by_ea_after_staging_shift(self, monkeypatch):
        """After a Phase 2 inner staging shift, commit still hits the right block.

        Simulate: a later staging step shifts the serial of an already-staged
        original block (e.g. BLT_STOP moves, compacting inner serials).
        The commit phase must locate the original by its captured start EA,
        not by the now-stale ``original_serial``.
        """
        mba = _StagedFakeMBA()
        src = _StagedFakeBlock(5, nsucc=1, succ_serial=20, start=0x18005000)
        src.predset.push_back(10)
        pred = _StagedFakeBlock(10, nsucc=1, succ_serial=5, start=0x1800A000)
        tgt = _StagedFakeBlock(20, nsucc=0, start=0x18014000)
        tgt.predset.push_back(5)
        mba.blocks.update({5: src, 10: pred, 20: tgt})
        mba.qty = max(mba.blocks.keys()) + 1

        changes = _staged_patch_wiring(monkeypatch, mba)

        modifier = dm.DeferredGraphModifier(
            mba, mutation_gateway=make_mutation_gateway(mba)
        )
        mod = dm.QueuedModification(
            dm.ModificationType.BLOCK_GOTO_CHANGE,
            block_serial=5,
            new_target=30,
        )
        rewire = modifier._stage_destructive_mod_via_copy(mod, index=0)
        assert rewire is not None
        staged_orig_serial = rewire.original_serial
        staged_copy_serial = rewire.new_serial

        # Simulate a drift: shuffle serial numbers without touching start EAs.
        # This models what a second copy_block (for a different staged mod)
        # would do to the positional block array: IDA's real copy_block
        # not only shifts blk.serial but also rewrites every succset/predset
        # entry pointing at any shifted block.  Mirror both effects so the
        # fake MBA behaves like the real one.
        SHIFT = 3
        old_to_new = {s: s + SHIFT for s in mba.blocks}
        shuffled: dict[int, _StagedFakeBlock] = {}
        for serial, blk in mba.blocks.items():
            new_serial = old_to_new[serial]
            blk.serial = new_serial
            # Update every outgoing edge to point at the new serial of its target.
            remapped_succs = [
                old_to_new.get(int(blk.succset[k]), int(blk.succset[k]))
                for k in range(blk.succset.size())
            ]
            blk.succset.clear()
            for s in remapped_succs:
                blk.succset.push_back(s)
            # Update every incoming edge the same way.
            remapped_preds = [
                old_to_new.get(int(blk.predset[k]), int(blk.predset[k]))
                for k in range(blk.predset.size())
            ]
            blk.predset.clear()
            for s in remapped_preds:
                blk.predset.push_back(s)
            shuffled[new_serial] = blk
        mba.blocks = shuffled
        mba.qty = max(mba.blocks.keys()) + 1

        # After drift, the staging serials are stale.  Commit must re-resolve
        # by EA.
        ok = modifier._commit_staged_rewire(rewire)
        assert ok is True, (
            "commit must succeed even after serial drift, by re-resolving "
            "original + copy + preds via their captured start EAs"
        )
        # The recorded wiring change targeted the (post-drift) copy serial.
        copy_blk_now = dm._get_mblock_by_start_ea(mba, rewire.new_start_ea)
        assert copy_blk_now is not None
        assert any(t == copy_blk_now.serial for (_, t, _) in changes), (
            f"commit must redirect pred to the copy's CURRENT serial "
            f"({copy_blk_now.serial}), not the staging-time serial "
            f"({staged_copy_serial}); changes={changes}, "
            f"staged_orig_serial={staged_orig_serial}"
        )

    def test_cleanup_ignores_stale_serial_and_uses_ea(self, monkeypatch):
        """Cleanup must remove the block with the captured EA, even if serials shifted.

        If we relied on ``rewire.original_serial`` after the commit phase
        did its work, cleanup would either (a) fail silently because the
        serial now points to a different block, or (b) worse, remove the
        wrong block.  EA-based re-resolution eliminates both failure modes.
        """
        mba = _StagedFakeMBA()
        src = _StagedFakeBlock(5, nsucc=1, succ_serial=20, start=0x18005000)
        src.predset.push_back(10)
        pred = _StagedFakeBlock(10, nsucc=1, succ_serial=5, start=0x1800A000)
        tgt = _StagedFakeBlock(20, nsucc=0, start=0x18014000)
        tgt.predset.push_back(5)
        mba.blocks.update({5: src, 10: pred, 20: tgt})
        mba.qty = max(mba.blocks.keys()) + 1

        _staged_patch_wiring(monkeypatch, mba)

        modifier = dm.DeferredGraphModifier(
            mba, mutation_gateway=make_mutation_gateway(mba)
        )
        modifier.modifications = [
            dm.QueuedModification(
                dm.ModificationType.BLOCK_GOTO_CHANGE,
                block_serial=5,
                new_target=30,
            ),
        ]

        # Capture the src object up-front — tests that cleanup removed
        # *this specific object*, regardless of its serial at removal time.
        original_src_id = id(src)

        applied = modifier.apply(
            run_optimize_local=False,
            run_deep_cleaning=False,
            staged_atomic=True,
        )
        assert applied >= 1

        # Cleanup must have called remove_block on the block at start_ea
        # 0x18005000 — the original src.  Inject a marker: ensure mba.removed_blocks
        # contains the serial that the src had at the *time of removal*
        # (which may differ from the staging-time serial 5 if drift occurred).
        # Regardless of serial, src must no longer be in mba.blocks.
        assert not any(id(b) == original_src_id for b in mba.blocks.values()), (
            "cleanup must have removed the specific src block object "
            "(identified by its captured start EA), not a wrong block "
            "at the stale serial"
        )

    def test_cleanup_removes_correct_block_after_multi_stage_serial_drift(
        self,
        monkeypatch,
    ):
        """Multiple staged mods -> cumulative serial drift -> cleanup targets each by EA.

        Stage two destructive mods on different source blocks.  Each copy_block
        shifts the BLT_STOP serial.  Cleanup, iterating in descending EA order,
        must re-resolve each original by its captured start EA and remove the
        correct object — not fall for the stale serial that now points at a
        different (live) block.
        """
        mba = _StagedFakeMBA()
        # Two independent source blocks, each with a distinct pred and succ.
        src_a = _StagedFakeBlock(5, nsucc=1, succ_serial=20, start=0x18005000)
        src_a.predset.push_back(10)
        pred_a = _StagedFakeBlock(10, nsucc=1, succ_serial=5, start=0x1800A000)
        tgt_a = _StagedFakeBlock(20, nsucc=0, start=0x18014000)
        tgt_a.predset.push_back(5)

        src_b = _StagedFakeBlock(6, nsucc=1, succ_serial=21, start=0x18006000)
        src_b.predset.push_back(11)
        pred_b = _StagedFakeBlock(11, nsucc=1, succ_serial=6, start=0x1800B000)
        tgt_b = _StagedFakeBlock(21, nsucc=0, start=0x18015000)
        tgt_b.predset.push_back(6)

        mba.blocks.update(
            {
                5: src_a,
                6: src_b,
                10: pred_a,
                11: pred_b,
                20: tgt_a,
                21: tgt_b,
            }
        )
        mba.qty = max(mba.blocks.keys()) + 1

        _staged_patch_wiring(monkeypatch, mba)

        modifier = dm.DeferredGraphModifier(
            mba, mutation_gateway=make_mutation_gateway(mba)
        )
        modifier.modifications = [
            dm.QueuedModification(
                dm.ModificationType.BLOCK_GOTO_CHANGE,
                block_serial=5,
                new_target=30,
                description="destructive A",
            ),
            dm.QueuedModification(
                dm.ModificationType.BLOCK_GOTO_CHANGE,
                block_serial=6,
                new_target=31,
                description="destructive B",
            ),
        ]

        applied = modifier.apply(
            run_optimize_local=False,
            run_deep_cleaning=False,
            staged_atomic=True,
        )
        assert applied >= 2, f"expected two staged rewires, got applied={applied}"

        # Both original source objects must be gone from mba.blocks, identified
        # by their stable start EAs — not by their staging-time serials.
        live_starts = {b.start for b in mba.blocks.values()}
        assert src_a.start not in live_starts, (
            "src_a (ea=0x18005000) must be removed by cleanup"
        )
        assert src_b.start not in live_starts, (
            "src_b (ea=0x18006000) must be removed by cleanup"
        )
        # Both copies survived (distinct synthetic EAs per _StagedFakeMBA).
        assert len(mba.copied_blocks) == 2
