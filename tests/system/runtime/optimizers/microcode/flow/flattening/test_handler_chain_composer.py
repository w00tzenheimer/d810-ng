"""Unit tests for HandlerChainComposerStrategy (uee-b7ze, option β).

Tests cover:
* Default-OFF behavior (gate flag).
* Chain detection on a hand-crafted MBA stub.
* Composition correctness (m_stx + setup ops are concatenated in order).
* InsertBlock emission shape (pred_serial / succ_serial wiring).
* Composition refusal when handler contains non-whitelisted opcodes.

The strategy itself imports ``ida_hexrays`` for opcode constants, so the
tests live under ``system/runtime/``.  We do **not** spin up a real
mba_t; instead we use lightweight stubs that mimic the
``mba.get_mblock`` / ``blk.head`` / ``insn.next`` walking surface.
"""
from __future__ import annotations

import pytest

try:
    import ida_hexrays
    IDA_AVAILABLE = True
except ImportError:
    IDA_AVAILABLE = False

pytestmark = pytest.mark.skipif(not IDA_AVAILABLE, reason="IDA not available")

if IDA_AVAILABLE:
    from d810.cfg.flowgraph import InsnSnapshot
    from d810.cfg.graph_modification import InsertBlock
    from d810.optimizers.microcode.flow.flattening.hodur.strategies.handler_chain_composer import (
        HandlerChainCandidate,
        HandlerChainComposerStrategy,
    )


# ---- Stub MBA / mblock_t / minsn_t ----

class _StubMop:
    """Minimal ``mop_t`` stand-in.  Only ``t`` is used by capture path."""

    def __init__(self, t: int = 0) -> None:
        self.t = t
        self.size = 0
        self.r = 0
        self.d = None
        self.l = None
        self.r_op = None
        # Stub fields used by capture_insn_snapshot's MopSnapshot path:
        self.nnn = None
        self.s = None


class _StubInsn:
    """Walks via ``.next``.  Provides ``opcode``, ``ea``, ``l``, ``r``, ``d``."""

    def __init__(self, opcode: int, ea: int) -> None:
        self.opcode = opcode
        self.ea = ea
        self.l = _StubMop()
        self.r = _StubMop()
        self.d = _StubMop()
        self.next = None


class _StubBlock:
    def __init__(
        self,
        serial: int,
        succs: tuple[int, ...],
        preds: tuple[int, ...],
        insns: list[_StubInsn] | None = None,
    ) -> None:
        self.serial = serial
        self._succs = succs
        self._preds = preds
        # Link insns into a singly-linked list head -> next chain.
        self.head = None
        if insns:
            for cur, nxt in zip(insns, insns[1:]):
                cur.next = nxt
            insns[-1].next = None
            self.head = insns[0]

    def nsucc(self) -> int:
        return len(self._succs)

    def succ(self, idx: int) -> int:
        return self._succs[idx]

    def npred(self) -> int:
        return len(self._preds)

    def pred(self, idx: int) -> int:
        return self._preds[idx]


class _StubMba:
    def __init__(self, blocks: dict[int, _StubBlock]) -> None:
        self._blocks = blocks
        self.qty = (max(blocks) + 1) if blocks else 0

    def get_mblock(self, serial: int) -> _StubBlock | None:
        return self._blocks.get(serial)


class _StubHandler:
    """Mirrors the real ``StateHandler`` shape (transition_builder.py).

    Real fields: ``state_value``, ``check_block``, ``handler_blocks``.
    The strategy reads ``handler_blocks[0]`` first, falling back to
    ``check_block``.
    """

    def __init__(self, entry_serial: int) -> None:
        # Tests pre-existing semantics: a single entry serial is the
        # handler entry block.  Use it as both check_block and the
        # singleton handler_blocks list so the strategy's preference
        # order resolves to it.
        self.state_value = 0
        self.check_block = entry_serial
        self.handler_blocks = [entry_serial]


class _StubStateMachine:
    def __init__(self, handler_serials: list[int]) -> None:
        # Real ``DispatcherStateMachine.handlers`` is ``dict[int,
        # StateHandler]``; mirror that here so the strategy's
        # ``handlers_attr.values()`` walk works.
        self.handlers = {
            i: _StubHandler(s) for i, s in enumerate(handler_serials)
        }


class _StubSnapshot:
    """Minimal ``AnalysisSnapshot`` stand-in.

    Only the attributes the strategy reads are populated.
    """

    def __init__(
        self,
        mba: _StubMba,
        state_machine: _StubStateMachine | None,
    ) -> None:
        self.mba = mba
        self.state_machine = state_machine
        # Required by ModificationBuilder.from_snapshot helpers (if called).
        self.flow_graph = None


def _stx_insn(ea: int) -> _StubInsn:
    return _StubInsn(ida_hexrays.m_stx, ea)


def _mov_insn(ea: int) -> _StubInsn:
    return _StubInsn(ida_hexrays.m_mov, ea)


def _call_insn(ea: int) -> _StubInsn:
    """Non-whitelisted opcode (m_call) — should abort composition."""
    return _StubInsn(ida_hexrays.m_call, ea)


# ---- Tests ----

class TestDefaultOff:
    """Verify the strategy is OFF by default."""

    def test_class_flag_default_false(self) -> None:
        assert HandlerChainComposerStrategy.HANDLER_CHAIN_COMPOSER_ENABLED is False

    def test_is_applicable_returns_false_when_disabled(self) -> None:
        strat = HandlerChainComposerStrategy()
        assert strat.HANDLER_CHAIN_COMPOSER_ENABLED is False
        # Even with a fully-populated snapshot, gate is OFF.
        mba = _StubMba({0: _StubBlock(0, (), ())})
        sm = _StubStateMachine([0])
        snap = _StubSnapshot(mba, sm)
        assert strat.is_applicable(snap) is False

    def test_plan_returns_none_when_disabled(self) -> None:
        strat = HandlerChainComposerStrategy()
        # Build a chain candidate scenario but keep the gate off.
        mba = _make_three_handler_chain_mba()
        sm = _StubStateMachine([10, 11, 12])
        snap = _StubSnapshot(mba, sm)
        result = strat.plan(snap)
        assert result is None


def _make_three_handler_chain_mba() -> _StubMba:
    """Build a 5-block MBA modeling pred -> [h0, h1, h2] -> succ.

    Block 1 = pred (chain anchor), succs=(10,)
    Block 10 = h0 with two m_stx insns, succs=(11,), preds=(1,)
    Block 11 = h1 with one m_stx insn, succs=(12,), preds=(10,)
    Block 12 = h2 with one m_stx insn, succs=(20,), preds=(11,)
    Block 20 = succ (chain exit), succs=(), preds=(12,)
    """
    pred_blk = _StubBlock(1, (10,), ())
    h0 = _StubBlock(10, (11,), (1,), insns=[_stx_insn(0x1000), _mov_insn(0x1004)])
    h1 = _StubBlock(11, (12,), (10,), insns=[_stx_insn(0x1100)])
    h2 = _StubBlock(12, (20,), (11,), insns=[_stx_insn(0x1200)])
    succ_blk = _StubBlock(20, (), (12,))
    return _StubMba({1: pred_blk, 10: h0, 11: h1, 12: h2, 20: succ_blk})


class TestChainDetection:
    """Detection of sequential state-setter chains."""

    def test_detects_three_handler_chain(self) -> None:
        strat = HandlerChainComposerStrategy()
        # Force the gate ON for the test scope.
        strat.HANDLER_CHAIN_COMPOSER_ENABLED = True
        mba = _make_three_handler_chain_mba()
        sm = _StubStateMachine([10, 11, 12])
        snap = _StubSnapshot(mba, sm)

        candidates = strat.detect_chains(snap)
        assert len(candidates) == 1
        c = candidates[0]
        assert c.handler_serials == (10, 11, 12)
        assert c.pred_serial == 1
        assert c.succ_serial == 20
        # Composition: 2 + 1 + 1 = 4 instructions in chain order.
        assert len(c.composed_instructions) == 4
        eas = [int(i.ea) for i in c.composed_instructions]
        assert eas == [0x1000, 0x1004, 0x1100, 0x1200]

    def test_rejects_chain_with_non_whitelisted_opcode(self) -> None:
        """Handler with m_call opcode should abort composition for that
        handler — and since that handler is the chain start, the chain
        shrinks below the min-length-2 threshold and is dropped.
        """
        strat = HandlerChainComposerStrategy()
        strat.HANDLER_CHAIN_COMPOSER_ENABLED = True
        pred_blk = _StubBlock(1, (10,), ())
        h0 = _StubBlock(
            10, (11,), (1,), insns=[_call_insn(0x1000)],  # bad opcode
        )
        h1 = _StubBlock(11, (20,), (10,), insns=[_stx_insn(0x1100)])
        succ_blk = _StubBlock(20, (), (11,))
        mba = _StubMba({1: pred_blk, 10: h0, 11: h1, 20: succ_blk})
        sm = _StubStateMachine([10, 11])
        snap = _StubSnapshot(mba, sm)

        candidates = strat.detect_chains(snap)
        assert candidates == []

    def test_accepts_single_handler_chain(self) -> None:
        """A single composable handler is now a valid candidate.

        Length-1 chains are kept because the goal is use-def
        preservation (lift the body onto the linearized path), not
        structural compaction.  Even one isolated state-setter handler
        whose def is being severed by linearization should be a
        candidate for InsertBlock-based body relocation.
        """
        strat = HandlerChainComposerStrategy()
        strat.HANDLER_CHAIN_COMPOSER_ENABLED = True
        pred_blk = _StubBlock(1, (10,), ())
        h0 = _StubBlock(10, (20,), (1,), insns=[_stx_insn(0x1000)])
        succ_blk = _StubBlock(20, (), (10,))
        mba = _StubMba({1: pred_blk, 10: h0, 20: succ_blk})
        sm = _StubStateMachine([10])
        snap = _StubSnapshot(mba, sm)

        candidates = strat.detect_chains(snap)
        assert len(candidates) == 1
        assert candidates[0].handler_serials == (10,)
        assert candidates[0].pred_serial == 1
        assert candidates[0].succ_serial == 20


class TestPlanEmission:
    """Verify plan() emits InsertBlock with the composed body."""

    def test_plan_emits_insert_block(self) -> None:
        strat = HandlerChainComposerStrategy()
        strat.HANDLER_CHAIN_COMPOSER_ENABLED = True
        mba = _make_three_handler_chain_mba()
        sm = _StubStateMachine([10, 11, 12])
        snap = _StubSnapshot(mba, sm)

        fragment = strat.plan(snap)
        assert fragment is not None
        assert fragment.strategy_name == "handler_chain_composer"
        assert len(fragment.modifications) == 1
        mod = fragment.modifications[0]
        assert isinstance(mod, InsertBlock)
        assert mod.pred_serial == 1
        assert mod.succ_serial == 20
        assert len(mod.instructions) == 4
        # Owned blocks include all handlers and the predecessor anchor.
        assert {10, 11, 12, 1}.issubset(fragment.ownership.blocks)

    def test_plan_returns_none_without_state_machine(self) -> None:
        strat = HandlerChainComposerStrategy()
        strat.HANDLER_CHAIN_COMPOSER_ENABLED = True
        mba = _StubMba({0: _StubBlock(0, (), ())})
        snap = _StubSnapshot(mba, state_machine=None)
        assert strat.plan(snap) is None
