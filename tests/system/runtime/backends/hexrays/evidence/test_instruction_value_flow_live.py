"""Live Hex-Rays adapter tests for portable instruction value flow."""

from __future__ import annotations

from dataclasses import dataclass
from types import SimpleNamespace

import ida_hexrays
import pytest

from d810.backends.hexrays.evidence.instruction_value_flow_live import (
    LiveInstructionFlowUnavailable,
    build_live_instruction_flow,
)
from d810.backends.hexrays.evidence.stack_value_flow_live import (
    build_live_liveness_facts,
    build_live_reaching_facts,
)
from d810.ir.handles import InsnHandle
from d810.ir.locations import RegisterLocation, StackSlot


@dataclass(frozen=True)
class _LocationMarker:
    tokens: frozenset[str]


class _FakeMList:
    def __init__(self, tokens=()):
        self.tokens = frozenset(tokens)

    def has_common(self, other: _LocationMarker) -> bool:
        return bool(self.tokens & other.tokens)

    def includes(self, other: _LocationMarker) -> bool:
        return other.tokens <= self.tokens


class _FakeInsn:
    def __init__(self, ordinal: int, ea: int):
        self.ordinal = ordinal
        self.ea = ea
        self.next = None


class _FakeBlock:
    def __init__(self, serial: int, start: int, insns=(), successors=()):
        self.serial = serial
        self.start = start
        self._successors = tuple(successors)
        self._insns = tuple(insns)
        self.access_calls: list[tuple[str, int, int]] = []
        for current, following in zip(self._insns, self._insns[1:]):
            current.next = following
        self.head = self._insns[0] if self._insns else None
        self.tail = self._insns[-1] if self._insns else None

    def make_lists_ready(self):
        return None

    def nsucc(self):
        return len(self._successors)

    def succ(self, index):
        return self._successors[index]

    def build_use_list(self, insn, access):
        self.access_calls.append(("use", insn.ordinal, access))
        return _FakeMList(getattr(insn, f"uses_{access}", ()))

    def build_def_list(self, insn, access):
        self.access_calls.append(("def", insn.ordinal, access))
        return _FakeMList(getattr(insn, f"defs_{access}", ()))


class _FakeMba:
    def __init__(self, blocks):
        self._blocks = {block.serial: block for block in blocks}
        self.qty = len(blocks)

    def build_graph(self):
        return None

    def get_mblock(self, serial):
        return self._blocks.get(serial)


@pytest.fixture
def location_markers(monkeypatch):
    def marker(location):
        if isinstance(location, StackSlot):
            prefix = f"s:{location.offset}:"
        else:
            prefix = f"r:{location.register_id}:"
        return _LocationMarker(
            frozenset(f"{prefix}{byte}" for byte in range(location.size))
        )

    monkeypatch.setattr(
        "d810.backends.hexrays.evidence.instruction_value_flow_live._location_mlist",
        marker,
    )


def test_builds_instruction_topology_and_stable_coordinates(location_markers) -> None:
    first = _FakeInsn(0, 0x401000)
    second = _FakeInsn(1, 0x401004)
    flow = build_live_instruction_flow(
        _FakeMba([_FakeBlock(0, 0x401000, (first, second))]),
        (),
    )

    assert flow.graph.nodes == (InsnHandle(0), InsnHandle(1))
    assert flow.graph.entry_nodes == (InsnHandle(0),)
    assert flow.graph.successors(InsnHandle(0)) == (InsnHandle(1),)
    assert flow.graph.successors(InsnHandle(1)) == ()
    assert flow.coordinate(InsnHandle(1)).block_serial == 0
    assert flow.coordinate(InsnHandle(1)).block_start_ea == 0x401000
    assert flow.coordinate(InsnHandle(1)).insn_ea == 0x401004
    assert flow.handle_for(0, 1) == InsnHandle(1)


def test_empty_entry_block_preserves_branched_entries(location_markers) -> None:
    left = _FakeInsn(0, 0x402000)
    right = _FakeInsn(0, 0x403000)
    flow = build_live_instruction_flow(
        _FakeMba(
            [
                _FakeBlock(0, 0x401000, successors=(1, 2)),
                _FakeBlock(1, 0x402000, (left,)),
                _FakeBlock(2, 0x403000, (right,)),
            ]
        ),
        (),
    )

    assert flow.graph.entry_nodes == (InsnHandle(0), InsnHandle(1))


def test_stack_uses_are_exact_but_register_uses_are_conservative(
    location_markers,
) -> None:
    stack = StackSlot(offset=0x40, size=8)
    register = RegisterLocation(register_id=7, size=8)
    insn = _FakeInsn(0, 0x401000)
    setattr(insn, f"uses_{ida_hexrays.MUST_ACCESS}", {"s:64:0"})
    setattr(insn, f"uses_{ida_hexrays.MAY_ACCESS}", {"r:7:0"})
    block = _FakeBlock(0, 0x401000, (insn,))

    flow = build_live_instruction_flow(_FakeMba([block]), (stack, register))

    assert flow.graph.facts_by_node[InsnHandle(0)].uses == frozenset({stack, register})
    assert ("use", 0, ida_hexrays.MUST_ACCESS) in block.access_calls
    assert ("use", 0, ida_hexrays.MAY_ACCESS) in block.access_calls


def test_partial_stack_definition_is_may_def_not_must_def(location_markers) -> None:
    stack = StackSlot(offset=0x40, size=8)
    insn = _FakeInsn(0, 0x401000)
    setattr(
        insn,
        f"defs_{ida_hexrays.MUST_ACCESS}",
        {f"s:64:{byte}" for byte in range(4)},
    )

    flow = build_live_instruction_flow(
        _FakeMba([_FakeBlock(0, 0x401000, (insn,))]),
        (stack,),
    )
    facts = flow.graph.facts_by_node[InsnHandle(0)]

    assert facts.must_defs == frozenset()
    assert facts.may_defs == frozenset({stack})


def test_caller_supplied_native_location_coordinates_take_precedence(
    monkeypatch,
) -> None:
    stack = StackSlot(offset=0x40, size=8)
    native_location = _LocationMarker(frozenset({"native-stack-byte"}))
    insn = _FakeInsn(0, 0x401000)
    setattr(
        insn,
        f"defs_{ida_hexrays.MUST_ACCESS}",
        {"native-stack-byte"},
    )

    def raw_location_must_not_run(location):
        raise AssertionError(f"raw location rebuilt for {location!r}")

    monkeypatch.setattr(
        "d810.backends.hexrays.evidence.instruction_value_flow_live._location_mlist",
        raw_location_must_not_run,
    )
    flow = build_live_instruction_flow(
        _FakeMba([_FakeBlock(0, 0x401000, (insn,))]),
        (stack,),
        native_locations={stack: native_location},
    )

    assert flow.graph.facts_by_node[InsnHandle(0)].must_defs == frozenset({stack})


def test_empty_cfg_cycle_fails_closed(location_markers) -> None:
    mba = _FakeMba(
        [
            _FakeBlock(0, 0x401000, successors=(1,)),
            _FakeBlock(1, 0x402000, successors=(0,)),
        ]
    )

    with pytest.raises(LiveInstructionFlowUnavailable, match="instruction"):
        build_live_instruction_flow(mba, ())


def test_cyclic_native_instruction_chain_fails_closed(location_markers) -> None:
    first = _FakeInsn(0, 0x401000)
    second = _FakeInsn(1, 0x401004)
    block = _FakeBlock(0, 0x401000, (first, second))
    block.tail = None
    second.next = first

    with pytest.raises(LiveInstructionFlowUnavailable, match="chain"):
        build_live_instruction_flow(_FakeMba([block]), ())


def test_stack_block_facts_fold_shared_instruction_evidence(
    location_markers,
) -> None:
    first = _FakeInsn(0, 0x401000)
    second = _FakeInsn(1, 0x401004)
    third = _FakeInsn(2, 0x401008)
    full_slot = {f"s:64:{byte}" for byte in range(8)}
    setattr(first, f"uses_{ida_hexrays.MUST_ACCESS}", full_slot)
    setattr(second, f"defs_{ida_hexrays.MUST_ACCESS}", full_slot)
    setattr(third, f"uses_{ida_hexrays.MUST_ACCESS}", full_slot)
    mba = _FakeMba([_FakeBlock(0, 0x401000, (first, second, third))])
    flow_graph = SimpleNamespace(blocks={0: object()})

    reaching = build_live_reaching_facts(mba, flow_graph, {0x40: 8})
    liveness = build_live_liveness_facts(mba, flow_graph, {0x40: 8})

    assert reaching[0].gen == {0x40: frozenset({(0, 0x401004)})}
    assert liveness[0].used == frozenset({0x40})
    assert liveness[0].defined == frozenset({0x40})
