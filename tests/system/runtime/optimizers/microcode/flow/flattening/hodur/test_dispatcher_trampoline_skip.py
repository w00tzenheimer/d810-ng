"""Return-carrier const-feed gate tests for DispatcherTrampolineSkipStrategy.

The strategy emits ``goto_redirect`` modifications to short-circuit residual
trampoline blocks past the BST root.  These tests cover the fact-rooted
return-carrier gate that suppresses redirects whose source block introduces
constant feeds into a downstream return-carrier writer.

The gate is fact-rooted only: when the snapshot has no
``diagnostic_fact_view`` attached, no rejection is performed.
"""
from __future__ import annotations

import logging as stdlib_logging
from types import SimpleNamespace

import ida_hexrays
import pytest

from d810.ir.flowgraph import BlockSnapshot, FlowGraph
from d810.transforms.snapshot import (
    AnalysisSnapshot,
)
from d810.transforms.planner_context import (
    CumulativePlannerView,
)
from d810.optimizers.microcode.flow.flattening.hodur.strategies.dispatcher_trampoline_skip import (
    DispatcherTrampolineSkipStrategy,
)


# ---------------------------------------------------------------------------
# Minimal mba/blk/insn fakes -- just enough to drive plan() through both the
# scan loop and the goto_redirect emission path.
# ---------------------------------------------------------------------------


class _FakeNumberOp:
    def __init__(self, value: int) -> None:
        self.value = value


class _FakeStkOp:
    def __init__(self, off: int) -> None:
        self.off = off


class _FakeMop:
    def __init__(
        self,
        t: int,
        *,
        value: int | None = None,
        stkoff: int | None = None,
        block_target: int | None = None,
        size: int = 4,
        dstr: str | None = None,
    ) -> None:
        self.t = t
        self.size = size
        self.nnn = _FakeNumberOp(value) if value is not None else None
        self.s = _FakeStkOp(stkoff) if stkoff is not None else None
        self.b = block_target if block_target is not None else 0
        self._dstr = dstr or ""

    def dstr(self) -> str:
        return self._dstr


class _FakeInsn:
    def __init__(
        self,
        opcode: int,
        *,
        l: _FakeMop | None = None,
        r: _FakeMop | None = None,
        d: _FakeMop | None = None,
    ) -> None:
        self.opcode = opcode
        self.l = l
        self.r = r
        self.d = d
        self.prev = None
        self.next = None


def _link_insns(insns: list[_FakeInsn]) -> _FakeInsn | None:
    """Link a list of instructions into a doubly-linked list, return tail."""
    if not insns:
        return None
    for prev_insn, next_insn in zip(insns, insns[1:]):
        prev_insn.next = next_insn
        next_insn.prev = prev_insn
    return insns[-1]


class _FakeBlk:
    def __init__(
        self,
        serial: int,
        succs: tuple[int, ...],
        insns: list[_FakeInsn],
    ) -> None:
        self.serial = serial
        self._succs = succs
        self.tail = _link_insns(insns)
        self.head = insns[0] if insns else None

    def nsucc(self) -> int:
        return len(self._succs)

    def succ(self, j: int) -> int:
        return self._succs[j]


class _FakeMba:
    def __init__(self, blocks: dict[int, _FakeBlk]) -> None:
        self._blocks = blocks
        self.qty = (max(blocks) + 1) if blocks else 0
        self.entry_ea = 0x401000
        self.maturity = ida_hexrays.MMAT_GLBOPT1

    def get_mblock(self, serial: int) -> _FakeBlk | None:
        return self._blocks.get(serial)


def _build_state_var_stkoff() -> int:
    return 0x3C


def _make_source_block(
    serial: int,
    *,
    state_value: int,
    state_var_stkoff: int,
    bst_root: int,
    extra_var_writes: tuple[str, ...] = (),
) -> _FakeBlk:
    """Build a 1-way trampoline block:

        mov #const, %var_NNN  (for each var name in extra_var_writes)
        mov #state_value, [stkoff=state_var_stkoff]   <-- last state write
        goto bst_root
    """
    insns: list[_FakeInsn] = []
    for var_name in extra_var_writes:
        insns.append(
            _FakeInsn(
                opcode=ida_hexrays.m_mov,
                l=_FakeMop(ida_hexrays.mop_n, value=0xDEADBEEF),
                d=_FakeMop(
                    ida_hexrays.mop_S,
                    stkoff=int(var_name, 16),
                    dstr=f"%var_{var_name}",
                ),
            )
        )
    insns.append(
        _FakeInsn(
            opcode=ida_hexrays.m_mov,
            l=_FakeMop(ida_hexrays.mop_n, value=state_value),
            d=_FakeMop(
                ida_hexrays.mop_S,
                stkoff=state_var_stkoff,
                dstr="%var_state",
            ),
        )
    )
    insns.append(
        _FakeInsn(
            opcode=ida_hexrays.m_goto,
            l=_FakeMop(ida_hexrays.mop_b, block_target=bst_root),
        )
    )
    return _FakeBlk(serial=serial, succs=(bst_root,), insns=insns)


def _make_bst_root_block(serial: int, target_serial: int) -> _FakeBlk:
    """Single passthrough goto -> target_serial. The walker resolves it."""
    insn = _FakeInsn(
        opcode=ida_hexrays.m_goto,
        l=_FakeMop(ida_hexrays.mop_b, block_target=target_serial),
    )
    return _FakeBlk(serial=serial, succs=(target_serial,), insns=[insn])


def _make_target_block(serial: int) -> _FakeBlk:
    """Empty body; just exists so get_mblock() returns non-None."""
    return _FakeBlk(serial=serial, succs=(), insns=[])


def _build_snapshot(
    *,
    fact_view: object | None,
    extra_var_writes: tuple[str, ...] = (),
    cumulative_planner_view: CumulativePlannerView | None = None,
) -> tuple[AnalysisSnapshot, _FakeMba]:
    state_var_stkoff = _build_state_var_stkoff()
    state_value = 0x1234
    source_serial = 132
    bst_root_serial = 2
    target_serial = 93

    source_blk = _make_source_block(
        source_serial,
        state_value=state_value,
        state_var_stkoff=state_var_stkoff,
        bst_root=bst_root_serial,
        extra_var_writes=extra_var_writes,
    )
    bst_blk = _make_bst_root_block(bst_root_serial, target_serial)
    target_blk = _make_target_block(target_serial)

    blocks = {
        0: _FakeBlk(0, (), []),
        1: _FakeBlk(1, (), []),
        bst_root_serial: bst_blk,
        target_serial: target_blk,
        source_serial: source_blk,
    }
    mba = _FakeMba(blocks)

    flow_graph = FlowGraph(
        blocks={
            serial: BlockSnapshot(serial, 0, blk._succs, (), 0, 0, ())
            for serial, blk in blocks.items()
        },
        entry_serial=0,
        func_ea=mba.entry_ea,
    )

    state_machine = SimpleNamespace(
        state_var=_FakeMop(ida_hexrays.mop_S, stkoff=state_var_stkoff),
        handlers={},
        transitions=[],
    )
    bst_result = SimpleNamespace(
        bst_node_blocks={bst_root_serial},
        handler_state_map={},
    )

    snapshot = AnalysisSnapshot(
        mba=mba,
        state_machine=state_machine,
        detector=None,
        bst_result=bst_result,
        bst_dispatcher_serial=bst_root_serial,
        maturity=mba.maturity,
        flow_graph=flow_graph,
        diagnostic_fact_view=fact_view,
        cumulative_planner_view=cumulative_planner_view,
    )
    return snapshot, mba


def _make_fact_view(
    *,
    block_serial: int,
    var_refs: tuple[str, ...],
) -> object:
    site = SimpleNamespace(
        fact_id="rc-fixture-1",
        kind="ReturnCarrierFact",
        payload={
            "upstream_writer_block_serial": block_serial,
            "upstream_writer_var_refs": list(var_refs),
            "upstream_writer_ea": 0x401234,
        },
    )

    def _sites_for(target: int) -> tuple:
        if int(target) == int(block_serial):
            return (site,)
        return ()

    return SimpleNamespace(return_carrier_sites_for_block=_sites_for)


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


@pytest.fixture(autouse=True)
def enable_trampoline_skip_for_strategy_tests(monkeypatch):
    """Exercise plan() with the opt-in strategy gate enabled."""
    monkeypatch.setenv("D810_HODUR_ENABLE_TRAMPOLINE_SKIP", "1")
    monkeypatch.delenv("D810_HODUR_DISABLE_TRAMPOLINE_SKIP", raising=False)


@pytest.fixture
def captured_strategy_log():
    """Attach a memory handler to the strategy logger and yield captured records."""
    target_logger = stdlib_logging.getLogger(
        "D810.hodur.strategy.dispatcher_trampoline_skip"
    )
    records: list[stdlib_logging.LogRecord] = []

    class _ListHandler(stdlib_logging.Handler):
        def emit(self, record: stdlib_logging.LogRecord) -> None:
            records.append(record)

    handler = _ListHandler(level=stdlib_logging.DEBUG)
    target_logger.addHandler(handler)
    try:
        yield records
    finally:
        target_logger.removeHandler(handler)


def test_disabled_by_default(monkeypatch):
    """Trampoline skip is no longer a default live cleanup pass."""
    monkeypatch.delenv("D810_HODUR_ENABLE_TRAMPOLINE_SKIP", raising=False)
    monkeypatch.delenv("D810_HODUR_DISABLE_TRAMPOLINE_SKIP", raising=False)
    snapshot, _ = _build_snapshot(
        fact_view=None,
        extra_var_writes=("228",),
    )

    strategy = DispatcherTrampolineSkipStrategy()

    assert not strategy.is_applicable(snapshot)
    assert strategy.plan(snapshot) is None


def test_rejects_when_fact_overlap_with_const_writes(captured_strategy_log):
    """Const-feed overlap with a return-carrier fact -> redirect rejected."""
    fact_view = _make_fact_view(block_serial=93, var_refs=("228", "650"))
    snapshot, _ = _build_snapshot(
        fact_view=fact_view,
        extra_var_writes=("228", "650"),
    )

    strategy = DispatcherTrampolineSkipStrategy()
    fragment = strategy.plan(snapshot)

    assert fragment is None
    assert any(
        "RECON_REDIRECT_REJECTED_RETURN_CARRIER_CONST_FEED" in record.getMessage()
        for record in captured_strategy_log
    )


def test_permits_when_no_fact_overlap(captured_strategy_log):
    """Const writes don't overlap fact var refs -> redirect emitted."""
    fact_view = _make_fact_view(block_serial=93, var_refs=("999",))
    snapshot, _ = _build_snapshot(
        fact_view=fact_view,
        extra_var_writes=("228",),
    )

    strategy = DispatcherTrampolineSkipStrategy()
    fragment = strategy.plan(snapshot)

    assert fragment is not None
    assert len(fragment.modifications) == 1
    assert not any(
        "RECON_REDIRECT_REJECTED_RETURN_CARRIER_CONST_FEED" in record.getMessage()
        for record in captured_strategy_log
    )


def test_permits_when_fact_view_is_none(captured_strategy_log):
    """No fact view attached -> no rejection (gate is a strict no-op)."""
    snapshot, _ = _build_snapshot(
        fact_view=None,
        extra_var_writes=("228",),
    )
    assert snapshot.diagnostic_fact_view is None

    strategy = DispatcherTrampolineSkipStrategy()
    fragment = strategy.plan(snapshot)

    assert fragment is not None
    assert len(fragment.modifications) == 1
    assert not any(
        "RECON_REDIRECT_REJECTED_RETURN_CARRIER_CONST_FEED" in record.getMessage()
        for record in captured_strategy_log
    )


def test_permits_when_no_facts_for_target_block(captured_strategy_log):
    """Fact view returns no sites for the target -> redirect emitted."""
    fact_view = _make_fact_view(block_serial=4242, var_refs=("228",))
    snapshot, _ = _build_snapshot(
        fact_view=fact_view,
        extra_var_writes=("228",),
    )

    strategy = DispatcherTrampolineSkipStrategy()
    fragment = strategy.plan(snapshot)

    assert fragment is not None
    assert len(fragment.modifications) == 1
    assert not any(
        "RECON_REDIRECT_REJECTED_RETURN_CARRIER_CONST_FEED" in record.getMessage()
        for record in captured_strategy_log
    )


def test_rejects_when_prior_planner_directly_vetoed_source(
    captured_strategy_log,
):
    """Cleanup must not re-emit redirects directly vetoed upstream."""
    view = CumulativePlannerView.empty()
    view = CumulativePlannerView(
        linearization_decisions=view.linearization_decisions,
        neutralized_state_writes=view.neutralized_state_writes,
        claimed_sources=frozenset({132}),
        direct_use_def_veto_sources=frozenset({132}),
        dag_authority=view.dag_authority,
    )
    snapshot, _ = _build_snapshot(
        fact_view=None,
        cumulative_planner_view=view,
    )

    strategy = DispatcherTrampolineSkipStrategy()
    fragment = strategy.plan(snapshot)

    assert fragment is None
    assert any(
        "RECON_REDIRECT_REJECTED_PRIOR_USE_DEF_VETO" in record.getMessage()
        for record in captured_strategy_log
    )


def test_permits_when_source_claimed_without_direct_use_def_veto(
    captured_strategy_log,
):
    """Generic planner claims do not block this cleanup path."""
    view = CumulativePlannerView.empty()
    view = CumulativePlannerView(
        linearization_decisions=view.linearization_decisions,
        neutralized_state_writes=view.neutralized_state_writes,
        claimed_sources=frozenset({132}),
        direct_use_def_veto_sources=frozenset(),
        dag_authority=view.dag_authority,
    )
    snapshot, _ = _build_snapshot(
        fact_view=None,
        cumulative_planner_view=view,
    )

    strategy = DispatcherTrampolineSkipStrategy()
    fragment = strategy.plan(snapshot)

    assert fragment is not None
    assert len(fragment.modifications) == 1
    assert not any(
        "RECON_REDIRECT_REJECTED_PRIOR_USE_DEF_VETO" in record.getMessage()
        for record in captured_strategy_log
    )
