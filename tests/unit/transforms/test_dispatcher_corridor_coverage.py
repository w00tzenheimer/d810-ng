"""Regression coverage for post-plan dispatcher corridor diagnostics."""

from __future__ import annotations

from dataclasses import replace
from types import SimpleNamespace

import pytest

from d810.analyses.control_flow.interval_map import IntervalDispatcher, IntervalRow
from d810.ir.expressions import ValueOpKind
from d810.ir.flowgraph import (
    BlockKind,
    BlockSnapshot,
    FlowGraph,
    InsnKind,
    InsnSnapshot,
    MopSnapshot,
    OperandKind,
    PredicateKind,
)
from d810.transforms import dispatcher_corridor_coverage as corridor_module
from d810.transforms import minimal_unflatten_emit as emit_module
from d810.transforms.dispatcher_corridor_coverage import (
    DispatcherCorridorCoverage,
    analyze_dispatcher_corridor_coverage,
    build_detached_dead_handler_component_analysis,
    build_dispatcher_removal_forecast,
)
from d810.transforms.unflatten_authority.legacy_keys import LEGACY_UNFLATTEN_KEYS
from d810.transforms.graph_modification import (
    EdgeRedirectViaPredSplit,
    LowerConditionalStateTransition,
    PreserveLivePredicateCondition,
    RedirectGoto,
    SyntheticRegisterNonzeroCondition,
)
from d810.transforms.use_def_redirect_filter import (
    UseDefSeveranceAudit,
    audit_use_def_severances,
)
from tests.typed_patch_authority import (
    compile_patch_plan,
    emit_minimal_unflatten,
    graph_modifications,
)


def _block(
    serial: int,
    succs: tuple[int, ...],
    preds: tuple[int, ...],
    ea: int,
    *,
    kind: BlockKind = BlockKind.UNKNOWN,
    insns: tuple[InsnSnapshot, ...] = (),
    tail_kind: InsnKind | None = None,
) -> BlockSnapshot:
    return BlockSnapshot(
        serial=serial,
        block_type=1,
        succs=succs,
        preds=preds,
        flags=0,
        start_ea=ea,
        insn_snapshots=insns,
        kind=kind,
        tail_kind=tail_kind,
    )


def test_transaction_replay_validator_seams_are_not_exported() -> None:
    """The corridor module exposes producer proofs, not a second authority."""

    removed = (
        "validate_dispatcher_corridor_coverage_metadata",
        "validate_dispatcher_removal_preflight_proof",
        "validated_exact_effect_exclusion_serials",
        "has_unreachable_cyclic_switch_dispatcher_residue",
    )
    assert all(name not in vars(corridor_module) for name in removed)


def test_coverage_projects_predecessor_scoped_feeder_clone() -> None:
    """A pred-split clone cuts only its exact original dispatcher corridor."""

    graph = FlowGraph(
        blocks={
            1: _block(1, (10,), (), 0x1000, kind=BlockKind.ONE_WAY),
            10: _block(10, (20,), (1,), 0x1010, kind=BlockKind.ONE_WAY),
            20: _block(20, (30,), (10,), 0x1020, kind=BlockKind.ONE_WAY),
            30: _block(30, (40,), (20,), 0x1030, kind=BlockKind.ONE_WAY),
            40: _block(40, (), (30,), 0x1040, kind=BlockKind.ZERO_WAY),
        },
        entry_serial=1,
        func_ea=0x1000,
    )

    coverage = analyze_dispatcher_corridor_coverage(
        graph,
        modifications=(
            EdgeRedirectViaPredSplit(
                src_block=20,
                old_target=30,
                new_target=40,
                via_pred=10,
                clone_until=20,
            ),
        ),
        dispatcher_entry_serial=30,
    )

    assert tuple(corridor.label for corridor in coverage.covered_corridors) == (
        "blk1@0x1000 -> blk10@0x1010 -> blk20@0x1020 -> blk30@0x1030",
    )
    assert coverage.residual_corridors == ()






def _conditional_observation_fixture(
    *,
    true_is_taken: bool = True,
    stateful: bool = False,
    condition_operand: object | None = None,
    predicate_ea: int = 0x1005,
) -> tuple[FlowGraph, FlowGraph, SimpleNamespace]:
    """Build one shifted live lowering with its physical helper topology."""
    if condition_operand is None:
        condition_operand = SyntheticRegisterNonzeroCondition(
            predicate_reg=9,
            predicate_size=4,
        )
    predicate = InsnSnapshot(
        opcode=0x71,
        ea=0xF0001005,
        native_ea=predicate_ea,
        operands=(),
        l=MopSnapshot(kind=OperandKind.REGISTER, reg=9, size=4),
        r=MopSnapshot(kind=OperandKind.NUMBER, value=0, size=4),
        kind=InsnKind.COND_JUMP,
        predicate_kind=PredicateKind.NE,
        branch_predicate=PredicateKind.NE,
    )
    preserve_live = isinstance(condition_operand, PreserveLivePredicateCondition)
    pre_source_succs = (20, 30) if preserve_live else (20,)
    pre_graph = FlowGraph(
        blocks={
            10: _block(
                10,
                pre_source_succs,
                (),
                0x1000,
                kind=BlockKind.TWO_WAY if preserve_live else BlockKind.ONE_WAY,
                insns=(predicate,) if preserve_live else (),
                tail_kind=(InsnKind.COND_JUMP if preserve_live else InsnKind.GOTO),
            ),
            20: _block(20, (), (10,), 0x1100, kind=BlockKind.ZERO_WAY),
            30: _block(
                30,
                (),
                (10,) if preserve_live else (),
                0x1200,
                kind=BlockKind.ZERO_WAY,
            ),
            40: _block(40, (), (), 0x1300, kind=BlockKind.ZERO_WAY),
        },
        entry_serial=10,
        func_ea=0x1000,
    )

    fallthrough_observed = 31 if true_is_taken else 41
    taken_observed = 41 if true_is_taken else 31
    successors: dict[int, tuple[int, ...]] = {
        10: (11, 12) if stateful else (11, taken_observed),
        11: (fallthrough_observed,),
        21: (),
        31: (),
        41: (),
    }
    if stateful:
        successors[12] = (taken_observed,)

    observed_blocks = {
        10: _block(
            10,
            successors[10],
            (),
            0x1000,
            kind=BlockKind.TWO_WAY,
            insns=(predicate,),
            tail_kind=InsnKind.COND_JUMP,
        ),
        11: _block(
            11,
            successors[11],
            (),
            0x2000,
            kind=BlockKind.ONE_WAY,
            tail_kind=InsnKind.GOTO,
        ),
        21: _block(21, (), (), 0x1100, kind=BlockKind.ZERO_WAY),
        31: _block(31, (), (), 0x1200, kind=BlockKind.ZERO_WAY),
        41: _block(41, (), (), 0x1300, kind=BlockKind.ZERO_WAY),
    }
    if stateful:
        fallthrough_state = 0x11 if true_is_taken else 0x22
        taken_state = 0x22 if true_is_taken else 0x11

        def state_write(value: int, target: int) -> tuple[InsnSnapshot, ...]:
            return (
                InsnSnapshot(
                    opcode=0x01,
                    ea=predicate_ea,
                    native_ea=predicate_ea,
                    operands=(),
                    l=MopSnapshot(kind=OperandKind.NUMBER, value=value, size=4),
                    d=MopSnapshot(kind=OperandKind.REGISTER, reg=7, size=4),
                    kind=InsnKind.MOV,
                ),
                InsnSnapshot(
                    opcode=0x02,
                    ea=predicate_ea,
                    native_ea=predicate_ea,
                    operands=(),
                    l=MopSnapshot(kind=OperandKind.BLOCK, block_ref=target),
                    kind=InsnKind.GOTO,
                ),
            )

        observed_blocks[11] = replace(
            observed_blocks[11],
            insn_snapshots=state_write(fallthrough_state, fallthrough_observed),
        )
        observed_blocks[12] = _block(
            12,
            successors[12],
            (),
            0x2001,
            kind=BlockKind.ONE_WAY,
            insns=state_write(taken_state, taken_observed),
            tail_kind=InsnKind.GOTO,
        )
    predecessor_map: dict[int, list[int]] = {serial: [] for serial in observed_blocks}
    for source, targets in successors.items():
        for target in targets:
            predecessor_map[target].append(source)
    observed_graph = FlowGraph(
        blocks={
            serial: replace(
                block,
                preds=tuple(sorted(set(predecessor_map[serial]))),
            )
            for serial, block in observed_blocks.items()
        },
        entry_serial=10,
        func_ea=0x1000,
    )
    plan = compile_patch_plan(
        [
            LowerConditionalStateTransition(
                source_serial=10,
                old_dispatcher_serial=20,
                rewrite_from_ea=predicate_ea,
                condition_operand=condition_operand,
                false_target_serial=30,
                true_target_serial=40,
                state_register=7 if stateful else None,
                state_size=4 if stateful else None,
                false_state=0x11 if stateful else None,
                true_state=0x22 if stateful else None,
            ),
        ],
        pre_graph,
    )
    return pre_graph, observed_graph, plan


def _replace_observed_edges(
    graph: FlowGraph,
    successors: dict[int, tuple[int, ...]],
    *,
    overrides: dict[int, dict[str, object]] | None = None,
) -> FlowGraph:
    """Rebuild raw observed predecessors for topology-specific negatives."""
    overrides = overrides or {}
    predecessor_map: dict[int, list[int]] = {serial: [] for serial in graph.blocks}
    for source, targets in successors.items():
        for target in targets:
            predecessor_map[target].append(source)
    blocks = {}
    for serial, block in graph.blocks.items():
        block = replace(
            block,
            succs=successors.get(serial, block.succs),
            preds=tuple(sorted(set(predecessor_map[serial]))),
        )
        if serial in overrides:
            block = replace(block, **overrides[serial])
        blocks[serial] = block
    return FlowGraph(
        blocks=blocks,
        entry_serial=graph.entry_serial,
        func_ea=graph.func_ea,
        metadata=graph.metadata,
    )


def _nested_merge_corridor_graph() -> FlowGraph:
    """The two real MMORPG residual corridors, in portable CFG form."""
    return FlowGraph(
        blocks={
            0: _block(0, (45, 122), (), 0x7FF859C06F60),
            45: _block(45, (123,), (0,), 0x7FF859C07656),
            122: _block(122, (123,), (0,), 0x7FF859C08BFE),
            123: _block(123, (3,), (45, 122), 0x7FF859C08D35),
            3: _block(3, (4,), (123,), 0x7FF859C070C0),
            4: _block(4, (121, 34), (3,), 0x7FF859C070C4),
            121: _block(121, (), (4,), 0x7FF859C08B37),
            34: _block(34, (), (4,), 0x7FF859C0747A),
        },
        entry_serial=0,
        func_ea=0x7FF859C06F60,
    )


@pytest.mark.parametrize("redirect_count", [358, 360])
def test_high_fan_in_feeder_accounts_for_every_immediate_corridor(redirect_count):
    inputs = tuple(range(1, 361))
    graph = FlowGraph(blocks={
        0: _block(0, inputs, (), 0x1000),
        **{serial: _block(serial, (1000,), (0,), 0x1000 + serial * 16)
           for serial in inputs},
        1000: _block(1000, (1001,), inputs, 0x6000),
        1001: _block(1001, (1002,), (1000,), 0x6010),
        1002: _block(1002, (), (1001,), 0x6020, kind=BlockKind.STOP),
    }, entry_serial=0, func_ea=0x1000)
    report = analyze_dispatcher_corridor_coverage(
        graph,
        modifications=tuple(
            RedirectGoto(from_serial=serial, old_target=1000, new_target=1002)
            for serial in inputs[:redirect_count]
        ),
        dispatcher_entry_serial=1001,
    )
    assert report.enumeration_complete
    assert len(report.covered_corridors) == redirect_count
    assert tuple(
        tuple(anchor.serial for anchor in corridor.path)
        for corridor in report.residual_corridors
    ) == (() if redirect_count == 360 else ((359, 1000, 1001), (360, 1000, 1001)))


def test_high_fan_in_floor_does_not_unbound_upstream_merge_expansion():
    inputs = tuple(range(1, 361))
    successors = {
        **{serial: (1000,) for serial in inputs},
        1000: (1001,), 1001: (), 2000: (1,), 2001: (1,),
    }
    paths, complete = corridor_module._upstream_corridor_paths(
        successors, feeder_serial=1000, dispatcher_serial=1001,
    )
    assert not complete
    assert len(paths) == 360
    assert (2000, 1, 1000, 1001) in paths
    assert (2001, 1, 1000, 1001) in paths


@pytest.mark.parametrize("extra_successor", [False, True])
def test_direct_dispatcher_self_edge_is_one_explicit_corridor(extra_successor):
    successors = {0: (2,), 2: (2, 3) if extra_successor else (2,), 3: ()}
    paths, complete = corridor_module._upstream_corridor_paths(
        successors, feeder_serial=2, dispatcher_serial=2,
    )
    assert complete
    assert paths == ((2, 2),)


@pytest.mark.parametrize("redirect_entry", [False, True])
def test_direct_dispatcher_self_edge_coverage_tracks_reachability(redirect_entry):
    graph = FlowGraph(blocks={
        0: _block(0, (2,), (), 0x1000),
        2: _block(2, (2,), (0, 2), 0x1020),
        3: _block(3, (), (), 0x1030, kind=BlockKind.STOP),
    }, entry_serial=0, func_ea=0x1000)
    report = analyze_dispatcher_corridor_coverage(
        graph, dispatcher_entry_serial=2,
        modifications=(RedirectGoto(from_serial=0, old_target=2, new_target=3),)
        if redirect_entry else (),
    )
    assert report.enumeration_complete
    paths = report.covered_corridors if redirect_entry else report.residual_corridors
    assert {tuple(a.serial for a in path.path) for path in paths} == {(0, 2), (2, 2)}
    assert not (report.residual_corridors if redirect_entry else report.covered_corridors)


def _dispatcher_self_reentry_corridor_graph(
    *,
    reverse_cycle: bool = False,
    merge_reverse_cycle: bool = False,
) -> FlowGraph:
    """Small C-shaped dispatcher graph with optional unrelated reverse cycles."""
    if merge_reverse_cycle:
        return FlowGraph(
            blocks={
                0: _block(0, (1, 8), (), 0x1000),
                1: _block(1, (3,), (0,), 0x1010),
                8: _block(8, (4,), (0,), 0x1080),
                3: _block(3, (4,), (1, 2, 4), 0x1030),
                4: _block(4, (5, 10, 3), (8, 3), 0x1040),
                5: _block(5, (6,), (4,), 0x1050),
                6: _block(6, (2,), (5,), 0x1060),
                2: _block(2, (3,), (6,), 0x1020),
                10: _block(10, (), (4,), 0x10A0, kind=BlockKind.STOP),
                9: _block(9, (), (), 0x1090, kind=BlockKind.STOP),
            },
            entry_serial=0,
            func_ea=0x1000,
        )
    blocks = {
        0: _block(0, (1, 8), (), 0x1000),
        1: _block(1, (3,), (0,), 0x1010),
        8: _block(8, (0 if reverse_cycle else 4,), (0,), 0x1080),
        3: _block(3, (4,), (1, 2), 0x1030),
        4: _block(4, (5, 10), (8, 3), 0x1040),
        5: _block(5, (6,), (4,), 0x1050),
        6: _block(6, (2,), (5,), 0x1060),
        2: _block(2, (3,), (6,), 0x1020),
        10: _block(10, (), (4,), 0x10A0, kind=BlockKind.STOP),
        9: _block(9, (), (), 0x1090, kind=BlockKind.STOP),
    }
    if reverse_cycle:
        blocks[0] = _block(0, (1, 8), (8,), 0x1000)
        blocks[8] = _block(8, (0,), (0,), 0x1080)
    return FlowGraph(blocks=blocks, entry_serial=0, func_ea=0x1000)



def test_dispatcher_self_reentry_corridor_is_enumerated_completely() -> None:
    graph = _dispatcher_self_reentry_corridor_graph()
    report = analyze_dispatcher_corridor_coverage(
        graph,
        modifications=(
            RedirectGoto(from_serial=1, old_target=3, new_target=9),
            RedirectGoto(from_serial=2, old_target=3, new_target=9),
        ),
        dispatcher_entry_serial=3,
    )

    assert report.enumeration_complete
    assert not report.residual_corridors
    assert report.covered_corridors
    assert all(
        len({(anchor.serial, anchor.ea) for anchor in corridor.path})
        == len(corridor.path)
        for corridor in report.covered_corridors
    ), tuple(tuple(anchor.serial for anchor in corridor.path) for corridor in report.covered_corridors)
    for corridor in report.covered_corridors:
        assert corridor.label == " -> ".join(
            f"blk{anchor.serial}@0x{anchor.ea:x}" for anchor in corridor.path
        )


def test_unrelated_reverse_cycle_keeps_corridor_enumeration_incomplete() -> None:
    graph = _dispatcher_self_reentry_corridor_graph(reverse_cycle=True)
    report = analyze_dispatcher_corridor_coverage(
        graph,
        modifications=(
            RedirectGoto(from_serial=1, old_target=3, new_target=9),
            RedirectGoto(from_serial=2, old_target=3, new_target=9),
        ),
        dispatcher_entry_serial=3,
    )

    assert not report.enumeration_complete


@pytest.mark.parametrize("redirect", (False, True))
def test_payload_self_loop_has_finite_exit_corridor_without_retiring_loop(redirect) -> None:
    """69814: blk391 loops locally before blk392 returns to the dispatcher."""
    graph = FlowGraph({
        0: _block(0, (1,), (), 0x1000),
        1: _block(1, (1, 2), (0, 1, 3), 0x1010),
        2: _block(2, (3,), (1,), 0x1020),
        3: _block(3, (1,), (2,), 0x1030),
        4: _block(4, (), (), 0x1040),
    }, entry_serial=0, func_ea=0x1000)
    edits = (RedirectGoto(from_serial=2, old_target=3, new_target=4),) if redirect else ()
    report = analyze_dispatcher_corridor_coverage(graph, modifications=edits, dispatcher_entry_serial=3)
    assert report.enumeration_complete
    assert bool(report.residual_corridors) is not redirect
    corridors = (*report.covered_corridors, *report.residual_corridors)
    assert any(tuple(point.serial for point in row.path) == (1, 2, 3) for row in corridors)
    assert all(len({point.serial for point in row.path}) == len(row.path) for row in corridors)
    assert all(row.state_merge_anchor is None for row in corridors)
    # Only the exit is redirected; the payload's self-loop is still executable.
    assert corridor_module._rewired_successors(graph, edits)[1] == (1, 2)


def test_payload_self_loop_replacement_return_remains_residual() -> None:
    graph = FlowGraph({
        0: _block(0, (1,), (), 0x1000),
        1: _block(1, (1, 2), (0, 1, 3), 0x1010),
        2: _block(2, (3,), (1,), 0x1020),
        3: _block(3, (1,), (2, 4), 0x1030),
        4: _block(4, (3,), (), 0x1040),
    }, entry_serial=0, func_ea=0x1000)
    report = analyze_dispatcher_corridor_coverage(
        graph, modifications=(RedirectGoto(from_serial=2, old_target=3, new_target=4),),
        dispatcher_entry_serial=3,
    )
    assert report.enumeration_complete
    assert report.residual_corridors
    assert not report.full_unflattening_claim


def test_payload_self_loop_with_additional_exit_is_not_this_bounded_shape() -> None:
    paths, complete = corridor_module._upstream_corridor_paths(
        {0: (1,), 1: (1, 2, 4), 2: (3,), 3: (1,), 4: ()},
        feeder_serial=2, dispatcher_serial=3,
    )
    assert not complete


def test_repeated_merge_node_keeps_corridor_enumeration_incomplete() -> None:
    graph = _dispatcher_self_reentry_corridor_graph(merge_reverse_cycle=True)
    report = analyze_dispatcher_corridor_coverage(
        graph,
        modifications=(
            RedirectGoto(from_serial=1, old_target=3, new_target=9),
            RedirectGoto(from_serial=2, old_target=3, new_target=9),
        ),
        dispatcher_entry_serial=3,
    )

    assert not report.enumeration_complete


def test_corridor_scope_does_not_promote_unrelated_reverse_cycle() -> None:
    """A foreign cycle is diagnostic context, not covered dispatcher scope."""

    graph = _dispatcher_self_reentry_corridor_graph(reverse_cycle=True)
    report = analyze_dispatcher_corridor_coverage(
        graph,
        modifications=(
            RedirectGoto(from_serial=1, old_target=3, new_target=9),
            RedirectGoto(from_serial=2, old_target=3, new_target=9),
        ),
        dispatcher_entry_serial=3,
    )

    assert report.covered_corridors
    covered_identities = {
        (anchor.serial, anchor.ea)
        for corridor in report.covered_corridors
        for anchor in corridor.path
    }
    assert not report.enumeration_complete
    assert {(0, 0x1000), (8, 0x1080)}.isdisjoint(covered_identities)
    for corridor in report.covered_corridors:
        assert corridor.label == " -> ".join(
            f"blk{anchor.serial}@0x{anchor.ea:x}" for anchor in corridor.path
        )


@pytest.mark.parametrize(
    ("cap_name", "cap_value"),
    (("_MAX_CORRIDOR_DEPTH", 2), ("_MAX_CORRIDORS", 1)),
)
def test_dispatcher_self_reentry_respects_corridor_caps(
    monkeypatch,
    cap_name: str,
    cap_value: int,
) -> None:
    monkeypatch.setattr(corridor_module, cap_name, cap_value)
    graph = _dispatcher_self_reentry_corridor_graph()
    report = analyze_dispatcher_corridor_coverage(
        graph,
        modifications=(
            RedirectGoto(from_serial=1, old_target=3, new_target=9),
            RedirectGoto(from_serial=2, old_target=3, new_target=9),
        ),
        dispatcher_entry_serial=3,
    )

    assert not report.enumeration_complete
    assert not report.residual_corridors



def _nested_merge_behind_shared_feeder_graph() -> FlowGraph:
    """Target shape when other handlers also re-enter the same feeder."""
    graph = _nested_merge_corridor_graph()
    return FlowGraph(
        blocks={
            **graph.blocks,
            0: _block(0, (2, 26, 45, 122), (), 0x7FF859C06F60),
            2: _block(2, (3,), (0,), 0x7FF859C06FE3),
            26: _block(26, (3,), (0,), 0x7FF859C0731C),
            3: _block(3, (4,), (2, 26, 123), 0x7FF859C070C0),
        },
        entry_serial=0,
        func_ea=0x7FF859C06F60,
    )


def _target_shape_corridor_graph() -> FlowGraph:
    """Portable 43-corridor router shape used by the safety regression."""
    dispatcher = 0
    entry = 1
    feeders = tuple(range(2, 45))
    terminal = 45
    blocks = {
        dispatcher: _block(dispatcher, (terminal,), feeders, 0x700000),
        entry: _block(entry, feeders, (), 0x700100),
        terminal: _block(terminal, (), (dispatcher,), 0x700200),
    }
    blocks.update(
        {
            feeder: _block(feeder, (dispatcher,), (entry,), 0x700000 + feeder)
            for feeder in feeders
        }
    )
    return FlowGraph(blocks=blocks, entry_serial=entry, func_ea=0x700000)


def test_use_def_audit_keeps_block_start_separate_from_instruction_ea() -> None:
    class _PortableCfg:
        def get_block(self, serial: int) -> object:
            return SimpleNamespace(
                start_ea={1: 0x700100, 2: 0x700180, 45: 0x700200}[serial]
            )

    class _UseDefSafety:
        @staticmethod
        def redirect_use_def_violations(*_args: object) -> tuple[object, ...]:
            return (
                SimpleNamespace(
                    var_stkoff=0x70,
                    var_size=4,
                    use_block=45,
                    use_ea=0x7002AA,
                ),
            )

    audit = audit_use_def_severances(
        (RedirectGoto(from_serial=1, old_target=2, new_target=45),),
        use_def_safety=_UseDefSafety(),
        live_function=object(),
        pre_cfg=_PortableCfg(),
        state_var_stkoff=0x64,
    )

    evidence = audit.violations[0]
    assert evidence.use.serial == 45
    assert evidence.use.ea == 0x700200
    assert evidence.use.label == "blk45@0x700200"
    assert evidence.use_instruction_ea == 0x7002AA
    assert (
        audit.to_metadata(function_ea=0x700000)["violations"][0]["use_instruction_ea"]
        == 0x7002AA
    )


def test_target_shape_advisory_and_explicit_veto_preserve_exact_counts(
    monkeypatch,
) -> None:
    """43 corridors, 25 candidates, and 3 findings stay deterministic."""
    graph = _target_shape_corridor_graph()
    candidate_redirects = tuple(
        RedirectGoto(from_serial=feeder, old_target=0, new_target=45)
        for feeder in range(2, 27)
    )
    recovered = analyze_dispatcher_corridor_coverage(
        graph,
        modifications=(),
        dispatcher_entry_serial=0,
    )
    planned = analyze_dispatcher_corridor_coverage(
        graph,
        modifications=candidate_redirects,
        dispatcher_entry_serial=0,
    )
    assert len(candidate_redirects) == 25
    assert len(recovered.covered_corridors) + len(recovered.residual_corridors) == 43
    assert len(planned.covered_corridors) == 25
    assert len(planned.residual_corridors) == 18

    class _TargetUseDefSafety:
        def __init__(self) -> None:
            self.calls = 0

        def redirect_use_def_violations(self, *_args: object) -> tuple[object, ...]:
            index = self.calls
            self.calls += 1
            if index < 3:
                return (
                    SimpleNamespace(
                        var_stkoff=0x70,
                        var_size=4,
                        use_block=45,
                        use_ea=0x7002AA,
                    ),
                )
            return ()

    monkeypatch.setattr(
        emit_module,
        "recover_state_write_transitions_via_partitioned_fixpoint",
        lambda *_args, **_kwargs: (),
    )
    monkeypatch.setattr(
        emit_module,
        "_dispatcher_entry_preds",
        lambda *_args, **_kwargs: [],
    )
    monkeypatch.setattr(
        emit_module,
        "build_state_write_redirects",
        lambda *_args, **_kwargs: list(candidate_redirects),
    )

    dispatcher = IntervalDispatcher(
        [
            IntervalRow(lo=0, hi=1, target=2),
            IntervalRow(lo=1, hi=0x100000000, target=45),
        ]
    )

    monkeypatch.setenv("D810_USE_DEF_VETO", "0")
    monkeypatch.delenv("D810_S1A_SEVERANCE_BAIL", raising=False)
    advisory_plan = emit_minimal_unflatten(
        graph,
        dispatcher,
        state_var_stkoff=0x64,
        dispatcher_entry_serial=0,
        use_def_safety=_TargetUseDefSafety(),
        live_function=object(),
    )
    assert len(graph_modifications(advisory_plan)) == 25
    assert not set(advisory_plan.metadata_dict()).intersection(LEGACY_UNFLATTEN_KEYS)

    monkeypatch.setenv("D810_USE_DEF_VETO", "1")
    enforced_plan = emit_minimal_unflatten(
        graph,
        dispatcher,
        state_var_stkoff=0x64,
        dispatcher_entry_serial=0,
        use_def_safety=_TargetUseDefSafety(),
        live_function=object(),
    )
    assert graph_modifications(enforced_plan) == []
    assert not set(enforced_plan.metadata_dict()).intersection(LEGACY_UNFLATTEN_KEYS)


def test_coverage_descends_one_shared_merge_behind_a_shared_feeder() -> None:
    """The known blk45/blk122 merge must not collapse into source blk123."""
    report = analyze_dispatcher_corridor_coverage(
        _nested_merge_behind_shared_feeder_graph(),
        modifications=(),
        dispatcher_entry_serial=4,
    )

    paths = {
        tuple(anchor.serial for anchor in corridor.path)
        for corridor in report.residual_corridors
    }
    assert (45, 123, 3, 4) in paths
    assert (122, 123, 3, 4) in paths
    assert (123, 3, 4) not in paths
    assert {
        corridor.state_merge.serial
        for corridor in report.residual_corridors
        if corridor.source.serial in {45, 122} and corridor.state_merge is not None
    } == {123}




def test_coverage_reports_each_reachable_nested_dispatcher_corridor() -> None:
    report = analyze_dispatcher_corridor_coverage(
        _nested_merge_corridor_graph(),
        modifications=(),
        dispatcher_entry_serial=4,
    )

    assert report.completion_status == "pending_patch_application"
    assert report.planned_completion_status == "planned_partial_residual_dispatcher"
    assert report.full_unflattening_claim is False
    assert {
        tuple(anchor.serial for anchor in corridor.path)
        for corridor in report.residual_corridors
    } == {
        (45, 123, 3, 4),
        (122, 123, 3, 4),
    }
    assert {
        tuple(anchor.ea for anchor in corridor.path)
        for corridor in report.residual_corridors
    } == {
        (0x7FF859C07656, 0x7FF859C08D35, 0x7FF859C070C0, 0x7FF859C070C4),
        (0x7FF859C08BFE, 0x7FF859C08D35, 0x7FF859C070C0, 0x7FF859C070C4),
    }

def test_coverage_marks_both_nested_corridors_covered_only_after_bypass() -> None:
    report = analyze_dispatcher_corridor_coverage(
        _nested_merge_corridor_graph(),
        modifications=(
            RedirectGoto(from_serial=45, old_target=123, new_target=121),
            RedirectGoto(from_serial=122, old_target=123, new_target=34),
        ),
        dispatcher_entry_serial=4,
    )

    assert report.completion_status == "pending_patch_application"
    assert report.planned_completion_status == "planned_dispatcher_corridors_covered"
    assert report.full_unflattening_claim is False
    assert report.whole_function_proof_status == "not_claimed"
    assert not report.residual_corridors
    assert {
        tuple(anchor.serial for anchor in corridor.path)
        for corridor in report.covered_corridors
    } == {
        (45, 123, 3, 4),
        (122, 123, 3, 4),
    }

def test_dispatcher_removal_forecast_contains_only_typed_infrastructure_loss() -> None:
    graph = _nested_merge_corridor_graph()
    coverage = analyze_dispatcher_corridor_coverage(
        graph,
        modifications=(
            RedirectGoto(from_serial=45, old_target=123, new_target=121),
            RedirectGoto(from_serial=122, old_target=123, new_target=34),
        ),
        dispatcher_entry_serial=4,
    )
    post_graph = FlowGraph(
        blocks={
            **graph.blocks,
            0: _block(0, (45, 122), (), 0x7FF859C06F60),
            45: _block(45, (121,), (0,), 0x7FF859C07656),
            122: _block(122, (34,), (0,), 0x7FF859C08BFE),
            123: _block(123, (3,), (), 0x7FF859C08D35),
            3: _block(3, (4,), (123,), 0x7FF859C070C0),
        },
        entry_serial=0,
        func_ea=0x7FF859C06F60,
    )
    forecast = corridor_module.build_dispatcher_removal_forecast(
        graph,
        coverage=coverage,
        dispatcher_entry_serial=4,
    )
    assert {
        (item.role, item.anchor.serial) for item in forecast.retirement_candidates
    } == {
        ("comparison_dispatcher", 4),
        ("dispatcher_feeder", 3),
        ("state_merge", 123),
    }
    assert not hasattr(forecast, "passed")
    assert not hasattr(forecast, "reason")


def test_incomplete_removal_forecast_abstains_without_verdict() -> None:
    graph = _nested_merge_corridor_graph()
    coverage = analyze_dispatcher_corridor_coverage(
        graph,
        modifications=(),
        dispatcher_entry_serial=4,
    )
    forecast = corridor_module.build_dispatcher_removal_forecast(
        graph,
        coverage=coverage,
        dispatcher_entry_serial=4,
    )
    assert forecast.residual_corridors
    assert forecast.dispatcher == coverage.dispatcher
    assert not hasattr(forecast, "passed")
    assert not hasattr(forecast, "reason")


def test_detached_component_analysis_proposes_only_dead_handler_island() -> None:
    state = MopSnapshot(kind=OperandKind.STACK, stkoff=40, size=4)
    branch = InsnSnapshot(
        opcode=42,
        ea=0x1200,
        operands=(),
        l=state,
        r=MopSnapshot(kind=OperandKind.NUMBER, value=7, size=4),
        d=MopSnapshot(kind=OperandKind.BLOCK, block_ref=21),
        kind=InsnKind.COND_JUMP,
        predicate_kind=PredicateKind.EQ,
    )
    pre_graph = FlowGraph(
        blocks={
            0: _block(0, (4,), (), 0x1000, kind=BlockKind.ONE_WAY),
            4: _block(4, (20, 21), (0, 21), 0x1200, kind=BlockKind.TWO_WAY, insns=(branch,)),
            20: _block(20, (), (4,), 0x1300, kind=BlockKind.STOP),
            21: _block(21, (4,), (4,), 0x1310, kind=BlockKind.ONE_WAY),
        },
        entry_serial=0,
        func_ea=0x1000,
    )
    post_graph = _replace_observed_edges(
        pre_graph,
        {0: (20,), 4: (20, 21), 20: (), 21: (4,)},
    )
    coverage = analyze_dispatcher_corridor_coverage(
        pre_graph,
        modifications=(RedirectGoto(from_serial=0, old_target=4, new_target=20),),
        dispatcher_entry_serial=4,
    )
    assert coverage.enumeration_complete
    assert {
        tuple(anchor.serial for anchor in corridor.path)
        for corridor in coverage.covered_corridors
    } == {(0, 4), (21, 4)}
    assert all(
        len({(anchor.serial, anchor.ea) for anchor in corridor.path})
        == len(corridor.path)
        for corridor in coverage.covered_corridors
    )

    analysis = build_detached_dead_handler_component_analysis(
        pre_graph,
        post_graph=post_graph,
        coverage=coverage,
        authoritative_handler_serials=frozenset({20, 21}),
    )

    assert analysis is not None
    assert {anchor.serial for anchor in analysis.dead_handlers} == {21}
    assert {anchor.serial for anchor in analysis.retained_handlers} == {20}
    assert {anchor.serial for anchor in analysis.component} == {21}


def _detached_dead_handler_component_fixture() -> tuple[FlowGraph, FlowGraph, object]:
    """One candidate with a retained handler and a dead handler island."""
    state = MopSnapshot(kind=OperandKind.STACK, stkoff=40, size=4)
    branch = InsnSnapshot(
        opcode=42,
        ea=0x1200,
        operands=(),
        l=state,
        r=MopSnapshot(kind=OperandKind.NUMBER, value=7, size=4),
        d=MopSnapshot(kind=OperandKind.BLOCK, block_ref=21),
        kind=InsnKind.COND_JUMP,
        predicate_kind=PredicateKind.EQ,
    )
    dead_local_write = InsnSnapshot(
        opcode=1,
        ea=0x1310,
        operands=(),
        l=MopSnapshot(kind=OperandKind.NUMBER, value=1, size=4),
        d=MopSnapshot(kind=OperandKind.REGISTER, reg=8, size=4),
        kind=InsnKind.MOV,
        value_op_kind=ValueOpKind.MOVE,
    )
    move_state = InsnSnapshot(
        opcode=2,
        ea=0x1320,
        operands=(),
        l=MopSnapshot(kind=OperandKind.NUMBER, value=9, size=4),
        d=state,
        kind=InsnKind.MOV,
        value_op_kind=ValueOpKind.MOVE,
    )
    pre_graph = FlowGraph(
        blocks={
            0: _block(0, (10, 12), (), 0x1000, kind=BlockKind.N_WAY),
            10: _block(10, (123,), (0,), 0x1010, kind=BlockKind.ONE_WAY),
            12: _block(12, (112,), (0,), 0x1020, kind=BlockKind.ONE_WAY),
            123: _block(123, (3,), (10,), 0x1100, kind=BlockKind.ONE_WAY),
            3: _block(3, (4,), (123,), 0x1110, kind=BlockKind.ONE_WAY),
            112: _block(112, (4,), (12,), 0x1120, kind=BlockKind.ONE_WAY),
            4: _block(
                4,
                (20, 21),
                (3, 112, 113),
                0x1200,
                kind=BlockKind.TWO_WAY,
                insns=(branch,),
            ),
            20: _block(20, (), (4,), 0x1300, kind=BlockKind.STOP),
            21: _block(
                21,
                (113,),
                (4,),
                0x1310,
                kind=BlockKind.ONE_WAY,
                insns=(dead_local_write,),
            ),
            113: _block(
                113,
                (4,),
                (21,),
                0x1320,
                kind=BlockKind.ONE_WAY,
                insns=(move_state,),
            ),
        },
        entry_serial=0,
        func_ea=0x1000,
    )
    coverage = analyze_dispatcher_corridor_coverage(
        pre_graph,
        modifications=(
            RedirectGoto(from_serial=10, old_target=123, new_target=20),
            RedirectGoto(from_serial=12, old_target=112, new_target=20),
            RedirectGoto(from_serial=21, old_target=113, new_target=20),
        ),
        dispatcher_entry_serial=4,
    )
    assert coverage.enumeration_complete
    assert {
        tuple(anchor.serial for anchor in corridor.path)
        for corridor in coverage.covered_corridors
    } == {(0, 10, 123, 3, 4), (0, 12, 112, 4), (21, 113, 4)}
    assert all(
        len({(anchor.serial, anchor.ea) for anchor in corridor.path})
        == len(corridor.path)
        for corridor in coverage.covered_corridors
    )
    post_graph = _replace_observed_edges(
        pre_graph,
        {
            **{
                serial: tuple(block.succs)
                for serial, block in pre_graph.blocks.items()
            },
            0: (10, 12),
            10: (20,),
            12: (20,),
            21: (20,),
        },
    )
    return pre_graph, post_graph, coverage


def test_detached_component_analysis_uses_state_aware_decision_forest(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    pre_graph, post_graph, coverage = _detached_dead_handler_component_fixture()
    monkeypatch.setattr(
        corridor_module,
        "_independent_comparison_dispatcher_region",
        lambda *_args, **_kwargs: frozenset(),
    )

    analysis = build_detached_dead_handler_component_analysis(
        pre_graph,
        post_graph=post_graph,
        coverage=coverage,
        authoritative_handler_serials=frozenset({20, 21}),
    )

    assert analysis is not None
    assert {item.serial for item in analysis.dead_handlers} == {21}
    assert {item.serial for item in analysis.component} == {21, 113}


def test_detached_component_analysis_uses_bounded_pure_control_fallback(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    pre_graph, post_graph, coverage = _detached_dead_handler_component_fixture()
    monkeypatch.setattr(
        corridor_module,
        "_independent_comparison_dispatcher_region",
        lambda *_args, **_kwargs: frozenset(),
    )
    monkeypatch.setattr(
        corridor_module,
        "build_current_u32_decision_forest",
        lambda *_args, **_kwargs: None,
        raising=False,
    )

    analysis = build_detached_dead_handler_component_analysis(
        pre_graph,
        post_graph=post_graph,
        coverage=coverage,
        authoritative_handler_serials=frozenset({20, 21}),
    )

    assert analysis is not None
    assert {item.serial for item in analysis.component} == {21, 113}
