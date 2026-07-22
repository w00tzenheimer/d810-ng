"""Runtime contract for the one authoritative semantic-edge operation."""

from __future__ import annotations

from types import SimpleNamespace

import pytest

ida_hexrays = pytest.importorskip("ida_hexrays")

from d810.core.events import EventEmitter  # noqa: E402
from d810.hexrays.ir.semantic_edge import (  # noqa: E402
    LogicalSemanticEdge,
    LogicalSemanticEdgeOperation,
    SemanticEdgeOperationRejected,
)
from d810.hexrays.mutation import deferred_modifier as dm  # noqa: E402
from d810.hexrays.mutation.mba_mutation_events import (  # noqa: E402
    MbaMutationAborted,
    MbaMutationGateway,
)
from d810.ir.semantic_edge import SemanticEdgeRole  # noqa: E402
from tests.system.runtime.mutation_gateway import make_mutation_gateway  # noqa: E402


class _EdgeSet:
    def __init__(self, values=()):
        self._values = [int(value) for value in values]

    def __iter__(self):
        return iter(tuple(self._values))

    def __getitem__(self, index: int) -> int:
        return self._values[index]

    def size(self) -> int:
        return len(self._values)

    def push_back(self, value: int) -> None:
        self._values.append(int(value))

    def _del(self, value: int) -> None:
        try:
            self._values.remove(int(value))
        except ValueError:
            pass

    def clear(self) -> None:
        self._values.clear()


class _BlockReference:
    def __init__(self, serial: int | None = None, *, kind: int | None = None):
        self.t = int(ida_hexrays.mop_z if kind is None else kind)
        self.b = -1 if serial is None else int(serial)

    def make_blkref(self, serial: int) -> None:
        self.t = int(ida_hexrays.mop_b)
        self.b = int(serial)


class _Block:
    def __init__(self, serial: int, *, start: int):
        self.serial = int(serial)
        self.start = int(start)
        self.end = int(start) + 1
        self.type = int(ida_hexrays.BLT_0WAY)
        self.flags = 0
        self.head = None
        self.tail = None
        self.succset = _EdgeSet()
        self.predset = _EdgeSet()
        self.mba = None
        self.nextb = None
        self.prevb = None
        self.lists_dirty = False

    def nsucc(self) -> int:
        return self.succset.size()

    def mark_lists_dirty(self) -> None:
        self.lists_dirty = True

    def make_nop(self, _instruction) -> None:
        return None


class _Mba:
    def __init__(self, *blocks: _Block):
        self.blocks = {int(block.serial): block for block in blocks}
        self.qty = max(self.blocks, default=-1) + 1
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

    def _relink(self) -> None:
        ordered = sorted(self.blocks.values(), key=lambda block: block.serial)
        for index, block in enumerate(ordered):
            block.prevb = None if index == 0 else ordered[index - 1]
            block.nextb = None if index + 1 == len(ordered) else ordered[index + 1]


def _goto_tail(target: int, *, ea: int):
    return SimpleNamespace(
        opcode=int(ida_hexrays.m_goto),
        ea=int(ea),
        l=_BlockReference(target, kind=ida_hexrays.mop_b),
        d=_BlockReference(),
    )


def _conditional_tail(target: int | None, *, ea: int):
    return SimpleNamespace(
        opcode=int(ida_hexrays.m_jnz),
        ea=int(ea),
        l=_BlockReference(),
        d=_BlockReference(
            target,
            kind=(ida_hexrays.mop_v if target is None else ida_hexrays.mop_b),
        ),
    )


def _proxy(gateway: MbaMutationGateway, serial: int):
    handle = gateway.identity_index.handle_for_serial(int(serial))
    assert handle is not None
    proxy = gateway.identity_index.logical_proxy_for_handle(handle)
    assert proxy is not None
    return proxy


def _operation(
    gateway: MbaMutationGateway,
    *,
    source: int,
    role: SemanticEdgeRole,
    target: int,
    expected: int | None = None,
) -> LogicalSemanticEdgeOperation:
    return LogicalSemanticEdgeOperation(
        source=_proxy(gateway, source),
        edges=(
            LogicalSemanticEdge(
                role=role,
                target=_proxy(gateway, target),
                expected_target=(
                    None if expected is None else _proxy(gateway, expected)
                ),
            ),
        ),
    )


def _apply(
    gateway: MbaMutationGateway,
    mba: _Mba,
    operation: LogicalSemanticEdgeOperation,
):
    backend = dm.DeferredGraphModifier(mba, mutation_gateway=gateway)
    return gateway.apply_semantic_edge_operation(backend, operation)


def _install_helper_builder(monkeypatch) -> None:
    def _build(self, source, target, **_kwargs):
        insertion_serial = int(source.serial) + 1
        old_qty = int(self.mba.qty)
        for block in tuple(self.mba.blocks.values()):
            if int(block.serial) >= insertion_serial:
                block.serial += 1
        for block in tuple(self.mba.blocks.values()):
            block.succset._values = [
                value + (value >= insertion_serial) for value in block.succset._values
            ]
            block.predset._values = [
                value + (value >= insertion_serial) for value in block.predset._values
            ]
            if (
                block.tail is not None
                and int(block.tail.opcode) == int(ida_hexrays.m_goto)
                and int(block.tail.l.t) == int(ida_hexrays.mop_b)
                and int(block.tail.l.b) >= insertion_serial
            ):
                block.tail.l.b += 1
            if (
                block.tail is not None
                and ida_hexrays.is_mcode_jcond(int(block.tail.opcode))
                and int(block.tail.d.t) == int(ida_hexrays.mop_b)
                and int(block.tail.d.b) >= insertion_serial
            ):
                block.tail.d.b += 1
        helper = _Block(insertion_serial, start=0xF0000000 + insertion_serial)
        helper.mba = self.mba
        helper.type = int(ida_hexrays.BLT_1WAY)
        helper.flags = int(ida_hexrays.MBL_GOTO)
        helper.tail = _goto_tail(int(target.serial), ea=source.tail.ea)
        helper.succset.push_back(int(target.serial))
        target.predset.push_back(int(helper.serial))
        self.mba.blocks = {
            int(block.serial): block for block in self.mba.blocks.values()
        }
        self.mba.blocks[insertion_serial] = helper
        self.mba.qty += 1
        self.mba._relink()
        self._record_serial_insertion(insertion_serial, old_qty)
        return insertion_serial

    monkeypatch.setattr(
        dm.DeferredGraphModifier,
        "_build_fallthrough_goto_helper",
        _build,
    )


def test_gateway_materializes_zero_way_direct_edge() -> None:
    source = _Block(1, start=0x401010)
    target = _Block(2, start=0x401020)
    source.tail = _goto_tail(-1, ea=0x401011)
    mba = _Mba(source, target)
    gateway = make_mutation_gateway(mba)

    receipt = _apply(
        gateway,
        mba,
        _operation(
            gateway,
            source=1,
            role=SemanticEdgeRole.DIRECT,
            target=2,
        ),
    )

    assert receipt is not None
    assert receipt.operation_count == 1
    assert tuple(source.succset) == (2,)
    assert tuple(target.predset) == (1,)
    assert int(source.type) == int(ida_hexrays.BLT_1WAY)


def test_gateway_redirects_one_way_edge() -> None:
    source = _Block(1, start=0x401010)
    old = _Block(2, start=0x401020)
    target = _Block(3, start=0x401030)
    source.type = int(ida_hexrays.BLT_1WAY)
    source.tail = _goto_tail(2, ea=0x401011)
    source.succset.push_back(2)
    old.predset.push_back(1)
    mba = _Mba(source, old, target)
    gateway = make_mutation_gateway(mba)

    receipt = _apply(
        gateway,
        mba,
        _operation(
            gateway,
            source=1,
            role=SemanticEdgeRole.DIRECT,
            expected=2,
            target=3,
        ),
    )

    assert receipt is not None
    assert tuple(source.succset) == (3,)
    assert tuple(old.predset) == ()
    assert tuple(target.predset) == (1,)
    assert int(source.tail.l.b) == 3


def test_gateway_redirects_explicit_conditional_taken_arm(monkeypatch) -> None:
    source = _Block(1, start=0x401010)
    fallthrough = _Block(2, start=0x401020)
    old_taken = _Block(3, start=0x401030)
    new_taken = _Block(4, start=0x401040)
    source.type = int(ida_hexrays.BLT_2WAY)
    source.tail = _conditional_tail(3, ea=0x401011)
    source.succset = _EdgeSet((2, 3))
    fallthrough.predset.push_back(1)
    old_taken.predset.push_back(1)
    mba = _Mba(source, fallthrough, old_taken, new_taken)
    gateway = make_mutation_gateway(mba)
    monkeypatch.setattr(dm.ida_hexrays, "mop_t", _BlockReference)

    receipt = _apply(
        gateway,
        mba,
        _operation(
            gateway,
            source=1,
            role=SemanticEdgeRole.CONDITIONAL_TAKEN,
            expected=3,
            target=4,
        ),
    )

    assert receipt is not None
    assert set(source.succset) == {2, 4}
    assert int(source.tail.d.b) == 4
    assert tuple(old_taken.predset) == ()
    assert tuple(new_taken.predset) == (1,)


def test_gateway_routes_physical_fallthrough_through_adjacent_helper(
    monkeypatch,
) -> None:
    source = _Block(1, start=0x401010)
    old_fallthrough = _Block(2, start=0x401020)
    taken = _Block(3, start=0x401030)
    new_fallthrough = _Block(4, start=0x401040)
    source.type = int(ida_hexrays.BLT_2WAY)
    source.tail = _conditional_tail(3, ea=0x401011)
    source.succset = _EdgeSet((2, 3))
    old_fallthrough.predset.push_back(1)
    taken.predset.push_back(1)
    mba = _Mba(source, old_fallthrough, taken, new_fallthrough)
    gateway = make_mutation_gateway(mba)
    operation = _operation(
        gateway,
        source=1,
        role=SemanticEdgeRole.CONDITIONAL_FALLTHROUGH,
        expected=2,
        target=4,
    )
    _install_helper_builder(monkeypatch)

    receipt = _apply(gateway, mba, operation)

    assert receipt is not None
    helper = mba.get_mblock(2)
    live_source = mba.get_mblock(1)
    live_taken = mba.get_mblock(4)
    live_old_fallthrough = mba.get_mblock(3)
    live_new_fallthrough = mba.get_mblock(5)
    assert helper is not None
    assert tuple(live_source.succset) == (2, int(live_taken.serial))
    assert tuple(helper.succset) == (int(live_new_fallthrough.serial),)
    assert tuple(live_old_fallthrough.predset) == ()
    assert tuple(helper.predset) == (1,)
    assert receipt.operation_count == 2


def test_gateway_reconstructs_predicate_and_both_destinations_atomically(
    monkeypatch,
) -> None:
    source = _Block(1, start=0x401010)
    taken = _Block(3, start=0x401030)
    fallthrough = _Block(4, start=0x401040)
    source.tail = _conditional_tail(None, ea=0x401011)
    mba = _Mba(source, taken, fallthrough)
    gateway = make_mutation_gateway(mba)
    monkeypatch.setattr(dm.ida_hexrays, "mop_t", _BlockReference)
    operation = LogicalSemanticEdgeOperation(
        source=_proxy(gateway, 1),
        predicate_anchor_ea=0x401011,
        edges=(
            LogicalSemanticEdge(
                role=SemanticEdgeRole.CONDITIONAL_TAKEN,
                target=_proxy(gateway, 3),
            ),
            LogicalSemanticEdge(
                role=SemanticEdgeRole.CONDITIONAL_FALLTHROUGH,
                target=_proxy(gateway, 4),
            ),
        ),
    )
    _install_helper_builder(monkeypatch)

    receipt = _apply(gateway, mba, operation)

    assert receipt is not None
    live_source = mba.get_mblock(1)
    helper = mba.get_mblock(2)
    live_taken = mba.get_mblock(4)
    live_fallthrough = mba.get_mblock(5)
    assert int(live_source.type) == int(ida_hexrays.BLT_2WAY)
    assert int(live_source.tail.ea) == 0x401011
    assert int(live_source.tail.d.b) == int(live_taken.serial)
    assert tuple(live_source.succset) == (2, int(live_taken.serial))
    assert tuple(helper.succset) == (int(live_fallthrough.serial),)
    assert receipt.operation_count == 3
    assert receipt.planned_operation_count == 3


def test_gateway_rejects_wrong_arm_without_mutating_or_committing() -> None:
    source = _Block(1, start=0x401010)
    old = _Block(2, start=0x401020)
    target = _Block(3, start=0x401030)
    source.type = int(ida_hexrays.BLT_1WAY)
    source.tail = _goto_tail(2, ea=0x401011)
    source.succset.push_back(2)
    old.predset.push_back(1)
    mba = _Mba(source, old, target)
    emitter = EventEmitter()
    aborted: list[MbaMutationAborted] = []
    emitter.on(MbaMutationAborted, aborted.append)
    base = make_mutation_gateway(mba)
    gateway = MbaMutationGateway(
        native_key=base.native_key,
        generation=base.generation,
        session_id=base.session_id,
        function_ea=base.function_ea,
        maturity=base.maturity,
        identity_index=base.identity_index,
        event_emitter=emitter,
    )

    with pytest.raises(
        SemanticEdgeOperationRejected,
        match="requires a two-way conditional",
    ):
        _apply(
            gateway,
            mba,
            _operation(
                gateway,
                source=1,
                role=SemanticEdgeRole.CONDITIONAL_TAKEN,
                expected=2,
                target=3,
            ),
        )

    assert tuple(source.succset) == (2,)
    assert gateway.receipts == ()
    assert gateway.generation == 0
    assert aborted and "requires a two-way conditional" in aborted[-1].reason


def test_gateway_rejects_stale_expected_fallthrough_before_helper_creation(
    monkeypatch,
) -> None:
    source = _Block(1, start=0x401010)
    actual_fallthrough = _Block(2, start=0x401020)
    taken = _Block(3, start=0x401030)
    stale_expected = _Block(4, start=0x401040)
    target = _Block(5, start=0x401050)
    source.type = int(ida_hexrays.BLT_2WAY)
    source.tail = _conditional_tail(3, ea=0x401011)
    source.succset = _EdgeSet((2, 3))
    actual_fallthrough.predset.push_back(1)
    taken.predset.push_back(1)
    mba = _Mba(source, actual_fallthrough, taken, stale_expected, target)
    gateway = make_mutation_gateway(mba)
    helper_calls = 0

    def _unexpected_helper(*_args, **_kwargs):
        nonlocal helper_calls
        helper_calls += 1
        return None

    monkeypatch.setattr(
        dm.DeferredGraphModifier,
        "_build_fallthrough_goto_helper",
        _unexpected_helper,
    )

    with pytest.raises(SemanticEdgeOperationRejected, match="expected fallthrough"):
        _apply(
            gateway,
            mba,
            _operation(
                gateway,
                source=1,
                role=SemanticEdgeRole.CONDITIONAL_FALLTHROUGH,
                expected=4,
                target=5,
            ),
        )

    assert helper_calls == 0
    assert tuple(source.succset) == (2, 3)
    assert gateway.generation == 0


def test_gateway_rejects_foreign_proxy_before_opening_a_batch() -> None:
    source = _Block(1, start=0x401010)
    target = _Block(2, start=0x401020)
    source.tail = _goto_tail(-1, ea=0x401011)
    mba = _Mba(source, target)
    gateway = make_mutation_gateway(mba)
    foreign_mba = _Mba(_Block(1, start=0x501010))
    foreign_gateway = make_mutation_gateway(foreign_mba)
    operation = LogicalSemanticEdgeOperation(
        source=_proxy(foreign_gateway, 1),
        edges=(
            LogicalSemanticEdge(
                role=SemanticEdgeRole.DIRECT,
                target=_proxy(gateway, 2),
            ),
        ),
    )

    with pytest.raises(ValueError, match="not owned by this identity index"):
        _apply(gateway, mba, operation)

    assert gateway.active is False
    assert gateway.receipts == ()


def test_gateway_aborts_when_adjacent_fallthrough_helper_cannot_be_built(
    monkeypatch,
) -> None:
    source = _Block(1, start=0x401010)
    old_fallthrough = _Block(2, start=0x401020)
    taken = _Block(3, start=0x401030)
    target = _Block(4, start=0x401040)
    source.type = int(ida_hexrays.BLT_2WAY)
    source.tail = _conditional_tail(3, ea=0x401011)
    source.succset = _EdgeSet((2, 3))
    old_fallthrough.predset.push_back(1)
    taken.predset.push_back(1)
    mba = _Mba(source, old_fallthrough, taken, target)
    emitter = EventEmitter()
    aborted: list[MbaMutationAborted] = []
    emitter.on(MbaMutationAborted, aborted.append)
    base = make_mutation_gateway(mba)
    gateway = MbaMutationGateway(
        native_key=base.native_key,
        generation=base.generation,
        session_id=base.session_id,
        function_ea=base.function_ea,
        maturity=base.maturity,
        identity_index=base.identity_index,
        event_emitter=emitter,
    )
    monkeypatch.setattr(
        dm.DeferredGraphModifier,
        "_build_fallthrough_goto_helper",
        lambda *_args, **_kwargs: None,
    )

    with pytest.raises(SemanticEdgeOperationRejected, match="fallthrough helper"):
        _apply(
            gateway,
            mba,
            _operation(
                gateway,
                source=1,
                role=SemanticEdgeRole.CONDITIONAL_FALLTHROUGH,
                expected=2,
                target=4,
            ),
        )

    assert tuple(source.succset) == (2, 3)
    assert gateway.generation == 0
    assert aborted and "fallthrough helper" in aborted[-1].reason
