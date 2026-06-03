"""FlowGraph -> reaching-defs/liveness provider (Slice 1b).

Encodes the sub_7FFD ``0x298372CC`` carrier scenario on a synthetic graph whose
stubs mirror the real ``FlowGraph`` / ``InsnSnapshot`` / ``MopSnapshot``
structural interface (the provider reads ``blocks``, ``successors`` /
``predecessors``, ``entry_serial``, ``insn_snapshots``, ``insn.d/l/r``,
``mop.stkoff`` -- all by attribute).
"""
from __future__ import annotations

from dataclasses import dataclass

from d810.analyses.value_flow.stack_value_flow import (
    analyze_return_carrier,
    build_liveness_facts,
    build_reaching_facts,
)

RET, CARRIER, STATE = 0x7F0, 0x178, 0x3C


@dataclass(frozen=True)
class _Mop:
    stkoff: int | None = None


@dataclass(frozen=True)
class _Insn:
    ea: int
    d: object = None
    l: object = None
    r: object = None


@dataclass(frozen=True)
class _Block:
    serial: int
    succs: tuple
    preds: tuple
    insn_snapshots: tuple


class _Graph:
    def __init__(self, blocks, entry_serial):
        self.blocks = {b.serial: b for b in blocks}
        self.entry_serial = entry_serial

    def successors(self, serial):
        blk = self.blocks.get(serial)
        return blk.succs if blk else ()

    def predecessors(self, serial):
        blk = self.blocks.get(serial)
        return blk.preds if blk else ()


def _carrier_graph():
    # 0 entry: ret <- entry-default(state); v49 <- carrier(a5+0xD0); state <- x  -> {1, 2}
    b0 = _Block(0, (1, 2), (), (
        _Insn(0x100, d=_Mop(RET)),
        _Insn(0x104, d=_Mop(CARRIER)),
        _Insn(0x108, d=_Mop(STATE)),
    ))
    # 1 aligned terminal: returns ret (uses ret), defines nothing
    b1 = _Block(1, (), (0,), (_Insn(0x200, l=_Mop(RET)),))
    # 2 byte path: uses state, redefines ret
    b2 = _Block(2, (), (0,), (_Insn(0x300, l=_Mop(STATE), d=_Mop(RET)),))
    return _Graph([b0, b1, b2], entry_serial=0)


def test_carrier_verdict_at_aligned_terminal():
    verdict = analyze_return_carrier(
        _carrier_graph(),
        return_off=RET,
        carrier_off=CARRIER,
        state_off=STATE,
        terminal_serial=1,
    )
    # Only the entry-default definition reaches the return slot at the aligned terminal.
    assert verdict.return_reaching == frozenset({(0, 0x100)})
    # The real carrier (v49 = a5+0xD0) dominates -> a value is available to deliver.
    assert verdict.carrier_dominates is True
    # The dispatcher state var is dead there -> its entry-default write is removable.
    assert verdict.state_dead is True


def test_build_facts_shapes():
    graph = _carrier_graph()
    reaching = build_reaching_facts(graph, {RET, CARRIER, STATE})
    assert reaching[0].gen[RET] == frozenset({(0, 0x100)})
    assert reaching[0].gen[CARRIER] == frozenset({(0, 0x104)})
    liveness = build_liveness_facts(graph, {RET, CARRIER, STATE})
    assert STATE in liveness[2].used        # byte path reads the state var
    assert RET in liveness[2].defined        # ...and redefines the return slot
    assert STATE not in liveness[1].used     # aligned terminal does not read the state var
