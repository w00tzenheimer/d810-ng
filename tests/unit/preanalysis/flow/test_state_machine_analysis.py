from __future__ import annotations

import inspect
from types import SimpleNamespace

import pytest

from d810.ir.flowgraph import (
    BlockSnapshot,
    FlowGraph,
    InsnKind,
    InsnSnapshot,
    MopSnapshot,
    OperandKind,
    PredicateKind,
)
from d810.analyses.value_flow import state_write as portable_state_write
from d810.analyses.control_flow import state_machine_analysis as sma
from d810.ir.expressions import ValueOpKind
from d810.ir.insn_projection import project_instruction_sequence


def test_state_machine_analysis_does_not_import_live_hexrays():
    source = inspect.getsource(sma)

    assert "import ida_hexrays" not in source
    assert "ida_hexrays." not in source


def _mop_s(off: int):
    return MopSnapshot(kind=OperandKind.STACK, size=4, stkoff=off)


def _mop_n(value: int):
    return MopSnapshot(kind=OperandKind.NUMBER, size=4, value=value)


def _mop_r(register_id: int, *, size: int = 4):
    return MopSnapshot(kind=OperandKind.REGISTER, size=size, reg=register_id)


def _mop_g(address: int, *, size: int = 4):
    return MopSnapshot(kind=OperandKind.GLOBAL, size=size, gaddr=address)


def _block_with_insns(
    serial: int,
    succs: tuple[int, ...],
    preds: tuple[int, ...],
    *insns: InsnSnapshot,
) -> BlockSnapshot:
    return BlockSnapshot(
        serial=serial,
        block_type=0,
        succs=succs,
        preds=preds,
        flags=0,
        start_ea=0x180010000 + serial * 0x10,
        insn_snapshots=tuple(insns),
    )


def _path_state_meter_graph(*, reverse_block_insertion: bool = False) -> FlowGraph:
    """Branching/cyclic graph with exactly nine DFS queue pops."""

    blocks = {
        0: _block_with_insns(0, (), ()),
        1: _block_with_insns(1, (2, 3), ()),
        2: _block_with_insns(2, (4,), (1,)),
        3: _block_with_insns(3, (4,), (1,)),
        4: _block_with_insns(4, (5,), (2, 3, 5)),
        5: _block_with_insns(5, (4,), (4,)),
    }
    if reverse_block_insertion:
        blocks = dict(reversed(tuple(blocks.items())))
    return FlowGraph(blocks=blocks, entry_serial=1, func_ea=0x180010000)


def _evaluate_meter_graph(
    graph: FlowGraph,
    work_consumer=None,
):
    return sma.evaluate_handler_paths(
        graph,
        entry_serial=1,
        incoming_state=0x741CA546,
        condition_chain_blocks={0},
        state_var_stkoff=0x364,
        flow_graph=graph,
        known_handler_states=set(),
        classify_condition_chain_exits=False,
        _path_state_work_consumer=work_consumer,
    )


def test_evaluate_handler_paths_consumes_before_each_dfs_queue_pop() -> None:
    from d810.analyses.control_flow.linearized_state_dag import (
        LiveDagDiagnosticWorkBudget,
        LiveDagDiagnosticWorkBudgetExhausted,
    )

    graph = _path_state_meter_graph()
    complete_budget = LiveDagDiagnosticWorkBudget(limit=9)

    assert _evaluate_meter_graph(
        graph,
        lambda: complete_budget.consume("test_handler_path_state"),
    ) == []
    assert complete_budget.consumed == 9

    incomplete_budget = LiveDagDiagnosticWorkBudget(limit=8)
    with pytest.raises(LiveDagDiagnosticWorkBudgetExhausted) as exc_info:
        _evaluate_meter_graph(
            graph,
            lambda: incomplete_budget.consume("test_handler_path_state"),
        )
    assert incomplete_budget.consumed == 8
    assert exc_info.value.consumed == 8
    assert exc_info.value.phase == "test_handler_path_state"


@pytest.mark.parametrize("limit", (0, 1))
def test_evaluate_handler_paths_path_state_meter_zero_and_one(limit: int) -> None:
    from d810.analyses.control_flow.linearized_state_dag import (
        LiveDagDiagnosticWorkBudget,
        LiveDagDiagnosticWorkBudgetExhausted,
    )

    budget = LiveDagDiagnosticWorkBudget(limit=limit)
    with pytest.raises(LiveDagDiagnosticWorkBudgetExhausted):
        _evaluate_meter_graph(
            _path_state_meter_graph(),
            lambda: budget.consume("test_handler_path_state"),
        )
    assert budget.consumed == limit


def test_evaluate_handler_paths_path_state_meter_is_insertion_order_deterministic() -> None:
    counts: list[int] = []
    for graph in (
        _path_state_meter_graph(),
        _path_state_meter_graph(reverse_block_insertion=True),
    ):
        count = 0

        def consume() -> None:
            nonlocal count
            count += 1

        assert _evaluate_meter_graph(graph, consume) == []
        counts.append(count)

    assert counts == [9, 9]


def test_evaluate_handler_paths_path_state_meter_propagates_callback_failures() -> None:
    class StopDiagnosticWork(BaseException):
        pass

    def raise_runtime_error() -> None:
        raise RuntimeError("provider failed")

    def raise_stop() -> None:
        raise StopDiagnosticWork

    graph = _path_state_meter_graph()
    with pytest.raises(RuntimeError, match="provider failed"):
        _evaluate_meter_graph(graph, raise_runtime_error)
    with pytest.raises(StopDiagnosticWork):
        _evaluate_meter_graph(graph, raise_stop)


def test_evaluate_handler_paths_default_meter_is_byte_identical_to_none() -> None:
    graph = _path_state_meter_graph()

    assert sma.evaluate_handler_paths(
        graph,
        entry_serial=1,
        incoming_state=0x741CA546,
        condition_chain_blocks={0},
        state_var_stkoff=0x364,
        flow_graph=graph,
        known_handler_states=set(),
        classify_condition_chain_exits=False,
    ) == _evaluate_meter_graph(graph, None)


def test_evaluate_handler_paths_projects_each_snapshot_once_per_invocation(
    monkeypatch,
) -> None:
    """Reconvergent path replay reuses projection, never evaluated maps/results."""

    state_stkoff = 0x364
    left_value = 0x10203040
    right_value = 0xA0B0C0D0
    mask = 0x00FF00FF

    left_write = InsnSnapshot(
        opcode=1,
        ea=0x180010020,
        operands=(),
        kind=InsnKind.MOV,
        l=_mop_n(left_value),
        d=_mop_r(1),
    )
    right_write = InsnSnapshot(
        opcode=1,
        ea=0x180010030,
        operands=(),
        kind=InsnKind.MOV,
        l=_mop_n(right_value),
        d=_mop_r(1),
    )
    nested_xor = MopSnapshot(
        kind=OperandKind.SUBINSN,
        size=4,
        sub_value_op_kind=ValueOpKind.XOR,
        sub_l=_mop_r(1),
        sub_r=_mop_n(mask),
    )
    shared_formula = InsnSnapshot(
        opcode=1,
        ea=0x180010040,
        operands=(),
        kind=InsnKind.MOV,
        l=nested_xor,
        d=_mop_r(2),
    )
    shared_state_write = InsnSnapshot(
        opcode=1,
        ea=0x180010060,
        operands=(),
        kind=InsnKind.MOV,
        l=_mop_r(2),
        d=_mop_s(state_stkoff),
    )
    graph = FlowGraph(
        blocks={
            0: _block_with_insns(0, (), (6,)),
            1: _block_with_insns(1, (2, 3), ()),
            2: _block_with_insns(2, (4,), (1,), left_write),
            3: _block_with_insns(3, (4,), (1,), right_write),
            4: _block_with_insns(4, (5, 6), (2, 3, 5), shared_formula),
            5: _block_with_insns(5, (4,), (4,)),
            6: _block_with_insns(6, (0,), (4,), shared_state_write),
        },
        entry_serial=1,
        func_ea=0x180010000,
    )

    projections: list[int] = []

    def counted_project(snapshot: InsnSnapshot):
        projections.append(id(snapshot))
        return project_instruction_sequence(snapshot)

    # Current production projects inside the portable evaluator.  GREEN owns
    # projection in state_machine_analysis, so patch both names across the RED.
    monkeypatch.setattr(
        portable_state_write,
        "project_instruction_sequence",
        counted_project,
    )
    monkeypatch.setattr(
        sma,
        "project_instruction_sequence",
        counted_project,
        raising=False,
    )

    expected = [
        (
            left_value ^ mask,
            [(6, shared_state_write.ea)],
            [1, 2, 4, 6],
        ),
        (
            right_value ^ mask,
            [(6, shared_state_write.ea)],
            [1, 3, 4, 6],
        ),
    ]

    def run_once():
        return sma.evaluate_handler_paths(
            graph,
            entry_serial=1,
            incoming_state=0x741CA546,
            condition_chain_blocks={0},
            state_var_stkoff=state_stkoff,
            flow_graph=graph,
            known_handler_states={left_value ^ mask, right_value ^ mask},
            classify_condition_chain_exits=False,
        )

    first = run_once()
    assert sorted(
        (result.final_state, result.state_writes, result.ordered_path)
        for result in first
    ) == expected
    assert len(projections) == 4
    assert len(set(projections)) == 4

    second = run_once()
    assert sorted(
        (result.final_state, result.state_writes, result.ordered_path)
        for result in second
    ) == expected
    assert len(projections) == 8


def test_cached_projection_re_evaluates_mixed_width_and_unresolved_destinations(
    monkeypatch,
) -> None:
    state_stkoff = 0x364
    widen = InsnSnapshot(
        opcode=2,
        ea=0x180011000,
        operands=(),
        kind=InsnKind.XDU,
        l=_mop_r(1, size=1),
        d=_mop_r(2, size=8),
    )
    write_state = InsnSnapshot(
        opcode=1,
        ea=0x180011004,
        operands=(),
        kind=InsnKind.MOV,
        l=_mop_r(2, size=4),
        d=_mop_s(state_stkoff),
    )
    block = _block_with_insns(10, (), (), widen, write_state)
    cache = sma._SnapshotProjectionCache()
    projection_count = 0

    def counted_project(snapshot: InsnSnapshot):
        nonlocal projection_count
        projection_count += 1
        return project_instruction_sequence(snapshot)

    monkeypatch.setattr(sma, "project_instruction_sequence", counted_project)

    out_stk, out_reg = sma._transfer_snapshot_constant_block(
        block,
        {},
        {1: 0xFF},
        state_stkoff,
        _projection_cache=cache,
    )
    assert out_stk[state_stkoff] == 0xFF
    assert out_reg[2] == 0xFF

    unresolved_stk, unresolved_reg = sma._transfer_snapshot_constant_block(
        block,
        {state_stkoff: 0x12345678},
        {2: 0xA5A5A5A5},
        state_stkoff,
        _projection_cache=cache,
    )
    # Preserve the legacy unresolved-write behavior exactly: a pre-existing
    # destination constant is retained, so the following MOVE carries it.
    assert unresolved_stk[state_stkoff] == 0xA5A5A5A5
    assert unresolved_reg[2] == 0xA5A5A5A5
    assert projection_count == 2


def test_cached_projection_preserves_global_fold_and_write_site_metadata() -> None:
    state_stkoff = 0x364
    global_cell = 0x180080000
    global_write = InsnSnapshot(
        opcode=1,
        ea=0x180012000,
        operands=(),
        kind=InsnKind.MOV,
        l=_mop_g(global_cell),
        d=_mop_s(state_stkoff),
    )
    block = _block_with_insns(11, (), (), global_write)

    out_stk, _out_reg = sma._transfer_snapshot_constant_block(
        block,
        {},
        {},
        state_stkoff,
        foldable_global_reads={
            global_write.ea: {global_cell: 0xCAFEBABE},
        },
    )
    assert out_stk[state_stkoff] == 0xCAFEBABE

    first_write = InsnSnapshot(
        opcode=1,
        ea=0x180012010,
        operands=(),
        kind=InsnKind.MOV,
        l=_mop_n(0x11111111),
        d=_mop_s(state_stkoff),
    )
    final_write = InsnSnapshot(
        opcode=1,
        ea=0x180012014,
        operands=(),
        kind=InsnKind.MOV,
        l=_mop_n(0x22222222),
        d=_mop_s(state_stkoff),
    )
    trailing_call = InsnSnapshot(
        opcode=3,
        ea=0x180012018,
        operands=(),
        kind=InsnKind.CALL,
        is_call=True,
    )
    graph = FlowGraph(
        blocks={
            12: _block_with_insns(
                12,
                (),
                (),
                first_write,
                final_write,
                trailing_call,
            )
        },
        entry_serial=12,
        func_ea=0x180012000,
    )

    sites = sma.find_state_write_sites_snapshot(graph, 12, state_stkoff)
    assert [site.state_value for site in sites] == [0x11111111, 0x22222222]
    assert sites[-1].insn_ea == final_write.ea
    assert sites[-1].trailing_insn_eas == (trailing_call.ea,)
    assert sites[-1].unsafe_trailing_reasons == ("call",)


def test_projection_cache_fails_loud_on_projector_runtime_error(monkeypatch) -> None:
    insn = InsnSnapshot(
        opcode=1,
        ea=0x180013000,
        operands=(),
        kind=InsnKind.MOV,
        l=_mop_n(1),
        d=_mop_r(1),
    )
    block = _block_with_insns(13, (), (), insn)

    def fail_projection(_snapshot: InsnSnapshot):
        raise RuntimeError("provider failed")

    monkeypatch.setattr(sma, "project_instruction_sequence", fail_projection)

    with pytest.raises(RuntimeError, match="provider failed"):
        sma._transfer_snapshot_constant_block(block, {}, {}, 0x364)


def test_projection_cache_rejects_malformed_cached_program() -> None:
    insn = InsnSnapshot(
        opcode=1,
        ea=0x180013010,
        operands=(),
        kind=InsnKind.MOV,
        l=_mop_n(1),
        d=_mop_r(1),
    )
    cache = sma._SnapshotProjectionCache()
    cache._entries[id(insn)] = sma._ProjectedSnapshotProgram(  # type: ignore[arg-type]
        source=insn,
        instructions=(object(),),
    )

    with pytest.raises(TypeError, match="non-canonical"):
        cache.instructions_for(insn)


def test_projection_cache_rejects_malformed_projector_program(monkeypatch) -> None:
    insn = InsnSnapshot(
        opcode=1,
        ea=0x180013014,
        operands=(),
        kind=InsnKind.MOV,
        l=_mop_n(1),
        d=_mop_r(1),
    )
    canonical = project_instruction_sequence(insn)[0]
    monkeypatch.setattr(
        sma,
        "project_instruction_sequence",
        lambda _snapshot: [canonical],
    )

    with pytest.raises(TypeError, match="malformed program"):
        sma._SnapshotProjectionCache().instructions_for(insn)


class _SnapshotBlock:
    def __init__(
        self,
        serial: int,
        succs: tuple[int, ...],
        *,
        opcode: int | None = None,
        kind: InsnKind = InsnKind.UNKNOWN,
        branch_predicate: PredicateKind | None = None,
        cmp_value: int | None = None,
        insn_count: int = 1,
    ):
        self.serial = serial
        self.succs = succs
        if opcode is None:
            self.insn_snapshots = ()
            self.tail = None
            self.tail_opcode = None
        else:
            # Production-faithful tail shape: a real ``InsnSnapshot`` whose ``d``
            # (dest) slot defaults to ``None``.  The condition-chain walk now
            # reads the compared ``l`` / ``r`` operands through the canonical
            # ``operand_kinds`` / ``operand_storages`` accessors, which project
            # the ``l`` / ``r`` / ``d`` slots -- a duck-typed ``SimpleNamespace``
            # without a ``d`` attribute is not what the live lift ever produces.
            insn = InsnSnapshot(
                opcode=0,
                ea=0,
                operands=(),
                kind=kind,
                branch_predicate=branch_predicate,
                l=_mop_s(0x364),
                r=_mop_n(cmp_value or 0),
            )
            self.insn_snapshots = (insn,) * insn_count
            self.tail = insn
            self.tail_opcode = opcode

    @property
    def nsucc(self) -> int:
        return len(self.succs)


class _SnapshotFlowGraph:
    def __init__(self, blocks: dict[int, _SnapshotBlock]):
        self._blocks = blocks

    def get_block(self, serial: int):
        return self._blocks.get(int(serial))


def _topology_flow_graph(succ_map: dict[int, tuple[int, ...]]) -> FlowGraph:
    """Build a portable ``FlowGraph`` from a ``{serial: succs}`` topology.

    Blocks carry no instructions (``insn_snapshots=()``); the path evaluator's
    final state comes from the mocked
    ``find_last_state_write_site_on_path_snapshot`` snapshot resolver, so only
    block topology matters (ticket llr-f1cs F5 -- the path analyses are
    FlowGraph-only and no longer accept a live ``mba``).
    """
    preds: dict[int, list[int]] = {serial: [] for serial in succ_map}
    for serial, succs in succ_map.items():
        for succ in succs:
            preds.setdefault(succ, [])
            preds[succ].append(serial)
    blocks: dict[int, BlockSnapshot] = {}
    for serial, succs in succ_map.items():
        blocks[serial] = BlockSnapshot(
            serial=serial,
            block_type=0,
            succs=tuple(succs),
            preds=tuple(preds.get(serial, ())),
            flags=0,
            start_ea=0,
            insn_snapshots=(),
        )
    entry = min(succ_map) if succ_map else 0
    return FlowGraph(blocks=blocks, entry_serial=entry, func_ea=0)


def test_evaluate_handler_paths_uses_snapshot_state_for_condition_chain_exit(
    monkeypatch,
):
    mba = _topology_flow_graph(
        {
            1: (2,),
            2: (0,),
        }
    )

    calls = []

    def fake_snapshot_state(
        flow_graph, ordered_path, state_var_stkoff, *, _projection_cache=None
    ):
        calls.append((flow_graph, tuple(ordered_path), state_var_stkoff))
        return (
            2,
            SimpleNamespace(
                state_value=0xA3130002,
                insn_ea=0x1800,
            ),
        )

    monkeypatch.setattr(
        sma,
        "find_last_state_write_site_on_path_snapshot",
        fake_snapshot_state,
    )

    flow_graph = object()
    results = sma.evaluate_handler_paths(
        mba,
        entry_serial=1,
        incoming_state=0x741CA546,
        condition_chain_blocks={0},
        state_var_stkoff=0x364,
        flow_graph=flow_graph,
        known_handler_states={0xA3130002},
        dispatcher_root_serial=0,
        state_machine_blocks={0, 1, 2},
    )

    assert calls == [(flow_graph, (1, 2), 0x364)]
    assert len(results) == 1
    assert results[0].final_state == 0xA3130002
    assert results[0].state_writes == [(2, 0x1800)]
    assert results[0].ordered_path == [1, 2]


def test_evaluate_handler_paths_uses_snapshot_state_for_handler_handoff(
    monkeypatch,
):
    mba = _topology_flow_graph(
        {
            1: (2,),
            2: (3,),
            3: (),
        }
    )

    def fake_snapshot_state(
        _flow_graph, ordered_path, _state_var_stkoff, *, _projection_cache=None
    ):
        assert tuple(ordered_path) == (1, 2)
        return (
            2,
            SimpleNamespace(
                state_value=0xE01F6CFA,
                insn_ea=0x1810,
            ),
        )

    monkeypatch.setattr(
        sma,
        "find_last_state_write_site_on_path_snapshot",
        fake_snapshot_state,
    )

    results = sma.evaluate_handler_paths(
        mba,
        entry_serial=1,
        incoming_state=0x741CA546,
        condition_chain_blocks={0},
        state_var_stkoff=0x364,
        handler_entry_blocks={1, 3},
        flow_graph=object(),
    )

    assert len(results) == 1
    assert results[0].final_state == 0xE01F6CFA
    assert results[0].state_writes == [(2, 0x1810)]
    assert results[0].ordered_path == [1, 2]


def test_evaluate_handler_paths_resolves_no_successor_state_write_stub(
    monkeypatch,
):
    mba = _topology_flow_graph(
        {
            1: (2,),
            2: (),
        }
    )

    def fake_snapshot_state(
        _flow_graph, ordered_path, _state_var_stkoff, *, _projection_cache=None
    ):
        assert tuple(ordered_path) == (1, 2)
        return (
            2,
            SimpleNamespace(
                state_value=0x24,
                insn_ea=0x1820,
            ),
        )

    monkeypatch.setattr(
        sma,
        "find_last_state_write_site_on_path_snapshot",
        fake_snapshot_state,
    )

    results = sma.evaluate_handler_paths(
        mba,
        entry_serial=1,
        incoming_state=0x11,
        condition_chain_blocks={0},
        state_var_stkoff=0x364,
        flow_graph=object(),
        known_handler_states={0x24},
    )

    assert len(results) == 1
    assert results[0].final_state == 0x24
    assert results[0].state_writes == [(2, 0x1820)]
    assert results[0].ordered_path == [1, 2]


def test_evaluate_handler_paths_keeps_unknown_no_successor_write_terminal(
    monkeypatch,
):
    mba = _topology_flow_graph(
        {
            1: (2,),
            2: (),
        }
    )

    def fake_snapshot_state(
        _flow_graph, _ordered_path, _state_var_stkoff, *, _projection_cache=None
    ):
        return (
            2,
            SimpleNamespace(
                state_value=0x99,
                insn_ea=0x1830,
            ),
        )

    monkeypatch.setattr(
        sma,
        "find_last_state_write_site_on_path_snapshot",
        fake_snapshot_state,
    )

    results = sma.evaluate_handler_paths(
        mba,
        entry_serial=1,
        incoming_state=0x11,
        condition_chain_blocks={0},
        state_var_stkoff=0x364,
        flow_graph=object(),
        known_handler_states={0x24},
    )

    assert len(results) == 1
    assert results[0].final_state is None
    assert results[0].state_writes == []
    assert results[0].ordered_path == [1, 2]


def test_resolve_exit_via_condition_chain_default_snapshot_skips_trivial_connectors():
    flow_graph = _SnapshotFlowGraph(
        {
            6: _SnapshotBlock(
                6,
                (7, 20),
                opcode="m_jnz",
                kind=InsnKind.EQUALITY_JUMP,
                branch_predicate=PredicateKind.NE,
                cmp_value=0x1000,
            ),
            20: _SnapshotBlock(20, (22,)),
            22: _SnapshotBlock(
                22,
                (122, 23),
                opcode="m_jnz",
                kind=InsnKind.EQUALITY_JUMP,
                branch_predicate=PredicateKind.NE,
                cmp_value=0x790A1FEB,
            ),
            122: _SnapshotBlock(
                122,
                (2,),
                opcode="m_mov",
                kind=InsnKind.MOV,
                cmp_value=0xE581B47B,
                insn_count=2,
            ),
        }
    )

    assert (
        sma.resolve_exit_via_condition_chain_default_snapshot(
            flow_graph,
            6,
            0x790A1FEB,
        )
        == 122
    )


def test_resolve_exit_via_condition_chain_default_snapshot_keeps_empty_handler_anchor():
    flow_graph = _SnapshotFlowGraph(
        {
            6: _SnapshotBlock(
                6,
                (20, 122),
                opcode="m_jnz",
                kind=InsnKind.EQUALITY_JUMP,
                branch_predicate=PredicateKind.NE,
                cmp_value=0x1000,
            ),
            20: _SnapshotBlock(20, (8,)),
            8: _SnapshotBlock(8, ()),
            122: _SnapshotBlock(
                122,
                (2,),
                opcode="m_mov",
                kind=InsnKind.MOV,
                cmp_value=0xE581B47B,
                insn_count=2,
            ),
        }
    )

    assert (
        sma.resolve_exit_via_condition_chain_default_snapshot(
            flow_graph,
            6,
            0x1000,
        )
        == 20
    )
