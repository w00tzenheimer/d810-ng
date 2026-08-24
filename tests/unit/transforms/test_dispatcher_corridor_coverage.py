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
    DispatcherRemovalPreflightProof,
    analyze_dispatcher_corridor_coverage,
    build_detached_dead_handler_component_analysis,
    build_dispatcher_removal_preflight_proof,
    collect_dispatcher_corridor_coverage_observations,
    collect_dispatcher_corridor_coverage_observations_from_metadata,
    collect_use_def_severance_observations_from_metadata,
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


def _executed_fragment_safety() -> dict[str, bool]:
    """The only producer evidence eligible for the narrow retirement proof."""
    return {
        "fragment_atomic": True,
        "non_state_use_def_veto": True,
        "non_state_use_def_checked": True,
        "non_state_use_def_severances_zero": True,
    }




def _state_transition_plumbing_fixture(
    *,
    semantic_side_effect: bool = False,
    missing_state_write: bool = False,
) -> tuple[FlowGraph, FlowGraph, object, object]:
    """Pure transition expressions feeding the bound dispatcher state slot."""

    def value(
        operation: ValueOpKind,
        ea: int,
        left: MopSnapshot,
        right: MopSnapshot | None,
        destination: MopSnapshot,
    ) -> InsnSnapshot:
        return InsnSnapshot(
            opcode=0x40,
            ea=ea,
            operands=(),
            l=left,
            r=right,
            d=destination,
            kind=InsnKind.UNKNOWN,
            value_op_kind=operation,
        )

    state = MopSnapshot(kind=OperandKind.STACK, stkoff=40, size=4)
    eax = MopSnapshot(kind=OperandKind.REGISTER, reg=8, size=4)
    ecx = MopSnapshot(kind=OperandKind.REGISTER, reg=24, size=4)
    edx = MopSnapshot(kind=OperandKind.REGISTER, reg=16, size=4)
    feeder_destination = edx if missing_state_write else state
    merge_destination = (
        MopSnapshot(kind=OperandKind.GLOBAL, gaddr=0x140003000, size=4)
        if semantic_side_effect
        else edx
    )
    dispatcher_branch = InsnSnapshot(
        opcode=42,
        ea=0x1200,
        operands=(),
        l=state,
        r=MopSnapshot(kind=OperandKind.NUMBER, value=0x12345678, size=4),
        d=MopSnapshot(kind=OperandKind.BLOCK, block_ref=20),
        kind=InsnKind.COND_JUMP,
        predicate_kind=PredicateKind.EQ,
    )
    pre_graph = FlowGraph(
        blocks={
            0: _block(0, (10, 12), (), 0x1000, kind=BlockKind.N_WAY),
            10: _block(10, (123,), (0,), 0x1010, kind=BlockKind.ONE_WAY),
            12: _block(12, (112,), (0,), 0x1020, kind=BlockKind.ONE_WAY),
            123: _block(
                123,
                (3,),
                (10,),
                0x1100,
                kind=BlockKind.ONE_WAY,
                insns=(value(ValueOpKind.XOR, 0x1100, eax, ecx, merge_destination),),
                tail_kind=InsnKind.GOTO,
            ),
            3: _block(
                3,
                (4,),
                (123,),
                0x1110,
                kind=BlockKind.ONE_WAY,
                insns=(value(ValueOpKind.MOVE, 0x1110, edx, None, feeder_destination),),
                tail_kind=InsnKind.GOTO,
            ),
            112: _block(
                112,
                (4,),
                (12,),
                0x1120,
                kind=BlockKind.ONE_WAY,
                insns=(value(ValueOpKind.ADD, 0x1120, eax, ecx, state),),
                tail_kind=InsnKind.GOTO,
            ),
            4: _block(
                4,
                (21, 20),
                (3, 112),
                0x1200,
                kind=BlockKind.TWO_WAY,
                insns=(dispatcher_branch,),
                tail_kind=InsnKind.COND_JUMP,
            ),
            20: _block(20, (), (4,), 0x1300, kind=BlockKind.STOP),
            21: _block(21, (), (4,), 0x1310, kind=BlockKind.STOP),
        },
        entry_serial=0,
        func_ea=0x1000,
    )
    modifications = (
        RedirectGoto(from_serial=10, old_target=123, new_target=20),
        RedirectGoto(from_serial=12, old_target=112, new_target=21),
    )
    coverage = analyze_dispatcher_corridor_coverage(
        pre_graph,
        modifications=modifications,
        dispatcher_entry_serial=4,
    )
    post_graph = _replace_observed_edges(
        pre_graph,
        {
            **{
                serial: tuple(block.succs) for serial, block in pre_graph.blocks.items()
            },
            10: (20,),
            12: (21,),
        },
    )
    proof = build_dispatcher_removal_preflight_proof(
        pre_graph,
        post_graph=post_graph,
        coverage=coverage,
        dispatcher_entry_serial=4,
        authoritative_handler_serials=frozenset({10, 12, 20, 21}),
        dispatcher_region_serials=frozenset({4}),
        producer_safety=_executed_fragment_safety(),
        state_plumbing_serials=frozenset({3, 112, 123}),
    )
    return pre_graph, post_graph, coverage, proof




@pytest.mark.parametrize(
    "fixture_overrides",
    (
        {"semantic_side_effect": True},
        {"missing_state_write": True},
    ),
)


def _partitioned_state_transition_retirement_fixture(
    *,
    mismatched_internal_target: bool = False,
    mismatched_secondary_target: bool = False,
    effectful_secondary_comparison: bool = False,
    state_carrier_handler_leaf: bool = False,
    secondary_foreign_comparison_leaf: bool = False,
    internal_goto_alias: bool = False,
    effectful_internal_alias: bool = False,
    intermediate_post_route: bool = False,
    mismatched_intermediate_post_route: bool = False,
    same_nonhandler_endpoint: bool = False,
    observed_discards_exact_effect: bool = False,
) -> tuple[FlowGraph, FlowGraph, object, object]:
    """Exact source partitions entering main and secondary state forests."""

    state = MopSnapshot(kind=OperandKind.STACK, stkoff=40, size=4)
    eax = MopSnapshot(kind=OperandKind.REGISTER, reg=8, size=4)
    ecx = MopSnapshot(kind=OperandKind.REGISTER, reg=16, size=4)

    def constant(ea: int, value: int, destination: MopSnapshot) -> InsnSnapshot:
        return InsnSnapshot(
            opcode=0x40,
            ea=ea,
            operands=(),
            l=MopSnapshot(kind=OperandKind.NUMBER, value=value, size=4),
            r=None,
            d=destination,
            kind=InsnKind.UNKNOWN,
            value_op_kind=ValueOpKind.MOVE,
        )

    def value(
        operation: ValueOpKind,
        ea: int,
        left: MopSnapshot,
        right: MopSnapshot | None,
        destination: MopSnapshot,
    ) -> InsnSnapshot:
        return InsnSnapshot(
            opcode=0x41,
            ea=ea,
            operands=(),
            l=left,
            r=right,
            d=destination,
            kind=InsnKind.UNKNOWN,
            value_op_kind=operation,
        )

    def branch(
        ea: int,
        predicate: PredicateKind,
        constant_value: int,
        target: int,
    ) -> InsnSnapshot:
        return InsnSnapshot(
            opcode=0x42,
            ea=ea,
            operands=(),
            l=state,
            r=MopSnapshot(
                kind=OperandKind.NUMBER,
                value=constant_value,
                size=4,
            ),
            d=MopSnapshot(kind=OperandKind.BLOCK, block_ref=target),
            kind=InsnKind.COND_JUMP,
            predicate_kind=predicate,
        )

    def goto(ea: int, target: int) -> InsnSnapshot:
        return InsnSnapshot(
            opcode=0x43,
            ea=ea,
            operands=(),
            d=MopSnapshot(kind=OperandKind.BLOCK, block_ref=target),
            kind=InsnKind.GOTO,
        )

    effectful_store = InsnSnapshot(
        opcode=0x43,
        ea=0x12FF,
        operands=(),
        l=MopSnapshot(kind=OperandKind.NUMBER, value=1, size=4),
        r=None,
        d=MopSnapshot(kind=OperandKind.GLOBAL, gaddr=0x2000, size=4),
        kind=InsnKind.UNKNOWN,
        value_op_kind=ValueOpKind.MOVE,
    )

    blocks = {
        0: _block(
            0,
            (
                10,
                11,
                12,
                13,
                *((14,) if internal_goto_alias else ()),
                101,
                103,
                104,
                105,
                *((107,) if secondary_foreign_comparison_leaf else ()),
                *((90,) if observed_discards_exact_effect else ()),
            ),
            (),
            0x1000,
            kind=BlockKind.N_WAY,
        ),
        10: _block(
            10,
            (30,),
            (0,),
            0x1010,
            kind=BlockKind.ONE_WAY,
            insns=(constant(0x1010, 0x10, eax),),
            tail_kind=InsnKind.GOTO,
        ),
        11: _block(
            11,
            (31,),
            (0,),
            0x1020,
            kind=BlockKind.ONE_WAY,
            insns=(
                constant(0x1020, 0x18, eax),
                constant(0x1024, 0x08, ecx),
            ),
            tail_kind=InsnKind.GOTO,
        ),
        12: _block(
            12,
            (32,),
            (0,),
            0x1030,
            kind=BlockKind.ONE_WAY,
            insns=(
                constant(0x1030, 0x50, eax),
                constant(0x1034, 0x20, ecx),
            ),
            tail_kind=InsnKind.GOTO,
        ),
        13: _block(
            13,
            (32,),
            (0,),
            0x1040,
            kind=BlockKind.ONE_WAY,
            insns=(
                constant(0x1040, 0x70, eax),
                constant(0x1044, 0x20, ecx),
            ),
            tail_kind=InsnKind.GOTO,
        ),
        **(
            {
                14: _block(
                    14,
                    (33,),
                    (0,),
                    0x1050,
                    kind=BlockKind.ONE_WAY,
                    insns=(constant(0x1050, 0x20, eax),),
                    tail_kind=InsnKind.GOTO,
                ),
                33: _block(
                    33,
                    (50,),
                    (14,),
                    0x1130,
                    kind=BlockKind.ONE_WAY,
                    insns=(value(ValueOpKind.MOVE, 0x1130, eax, None, state),),
                    tail_kind=InsnKind.GOTO,
                ),
            }
            if internal_goto_alias
            else {}
        ),
        30: _block(
            30,
            (50,),
            (10,),
            0x1100,
            kind=BlockKind.ONE_WAY,
            insns=(value(ValueOpKind.MOVE, 0x1100, eax, None, state),),
            tail_kind=InsnKind.GOTO,
        ),
        31: _block(
            31,
            (51,),
            (11,),
            0x1110,
            kind=BlockKind.ONE_WAY,
            insns=(value(ValueOpKind.ADD, 0x1110, eax, ecx, state),),
            tail_kind=InsnKind.GOTO,
        ),
        32: _block(
            32,
            (70,),
            (12, 13),
            0x1120,
            kind=BlockKind.ONE_WAY,
            insns=(value(ValueOpKind.SUB, 0x1120, eax, ecx, state),),
            tail_kind=InsnKind.GOTO,
        ),
        50: _block(
            50,
            (
                (51, 80)
                if same_nonhandler_endpoint
                else ((60, 100) if internal_goto_alias else (51, 100))
            ),
            ((30, 33) if internal_goto_alias else (30,)),
            0x1200,
            kind=BlockKind.TWO_WAY,
            insns=(
                branch(
                    0x1200,
                    PredicateKind.EQ,
                    0x10,
                    80 if same_nonhandler_endpoint else 100,
                ),
            ),
            tail_kind=InsnKind.COND_JUMP,
        ),
        51: _block(
            51,
            (103, 101),
            ((60, 31) if internal_goto_alias else (50, 31)),
            0x1210,
            kind=BlockKind.TWO_WAY,
            insns=(branch(0x1210, PredicateKind.EQ, 0x20, 101),),
            tail_kind=InsnKind.COND_JUMP,
        ),
        **(
            {
                60: _block(
                    60,
                    (51,),
                    (50,),
                    0x1220,
                    kind=BlockKind.ONE_WAY,
                    insns=(
                        *((effectful_store,) if effectful_internal_alias else ()),
                        goto(0x1220, 51),
                    ),
                    tail_kind=InsnKind.GOTO,
                )
            }
            if internal_goto_alias
            else {}
        ),
        70: _block(
            70,
            (71, 72),
            (32,),
            0x1300,
            kind=BlockKind.TWO_WAY,
            insns=(
                *((effectful_store,) if effectful_secondary_comparison else ()),
                branch(
                    0x1300,
                    PredicateKind.ULT,
                    0x40,
                    71,
                ),
            ),
            tail_kind=InsnKind.COND_JUMP,
        ),
        71: _block(
            71,
            (103, 102),
            (70,),
            0x1310,
            kind=BlockKind.TWO_WAY,
            insns=(branch(0x1310, PredicateKind.EQ, 0x30, 102),),
            tail_kind=InsnKind.COND_JUMP,
        ),
        72: _block(
            72,
            ((107, 104) if secondary_foreign_comparison_leaf else (105, 104)),
            (70,),
            0x1320,
            kind=BlockKind.TWO_WAY,
            insns=(branch(0x1320, PredicateKind.EQ, 0x50, 104),),
            tail_kind=InsnKind.COND_JUMP,
        ),
        **(
            {
                80: _block(
                    80,
                    (
                        (100, 103)
                        if mismatched_intermediate_post_route
                        else (103, 100)
                    ),
                    (),
                    0x1380,
                    kind=BlockKind.TWO_WAY,
                    insns=(
                        (
                            InsnSnapshot(
                                opcode=0x42,
                                ea=0x1380,
                                operands=(),
                                l=MopSnapshot(
                                    kind=OperandKind.STACK,
                                    stkoff=64,
                                    size=8,
                                ),
                                r=MopSnapshot(
                                    kind=OperandKind.NUMBER,
                                    value=0,
                                    size=8,
                                ),
                                d=MopSnapshot(
                                    kind=OperandKind.BLOCK,
                                    block_ref=100,
                                ),
                                kind=InsnKind.COND_JUMP,
                                predicate_kind=PredicateKind.EQ,
                            )
                            if same_nonhandler_endpoint
                            else branch(
                                0x1380,
                                PredicateKind.EQ,
                                0x10,
                                103
                                if mismatched_intermediate_post_route
                                else 100,
                            )
                        ),
                    ),
                    tail_kind=InsnKind.COND_JUMP,
                )
            }
            if intermediate_post_route or same_nonhandler_endpoint
            else {}
        ),
        100: (
            _block(
                100,
                (101,),
                (50,),
                0x1400,
                kind=BlockKind.ONE_WAY,
                insns=(value(ValueOpKind.MOVE, 0x1400, state, None, eax),),
                tail_kind=InsnKind.GOTO,
            )
            if state_carrier_handler_leaf
            else _block(100, (), (50,), 0x1400, kind=BlockKind.STOP)
        ),
        101: _block(101, (), (51,), 0x1410, kind=BlockKind.STOP),
        102: _block(102, (), (71,), 0x1420, kind=BlockKind.STOP),
        103: _block(103, (), (51, 71), 0x1430, kind=BlockKind.STOP),
        104: _block(104, (), (72,), 0x1440, kind=BlockKind.STOP),
        105: _block(
            105,
            (),
            ((72, 107) if secondary_foreign_comparison_leaf else (72,)),
            0x1450,
            kind=BlockKind.STOP,
        ),
        **(
            {
                90: _block(
                    90,
                    (91,),
                    (0,),
                    0x1490,
                    kind=BlockKind.ONE_WAY,
                    insns=(
                        constant(0x1490, 0x10, state),
                        goto(0x1494, 91),
                    ),
                    tail_kind=InsnKind.GOTO,
                ),
                91: _block(
                    91,
                    (92, 100),
                    (90,),
                    0x14A0,
                    kind=BlockKind.TWO_WAY,
                    insns=(branch(0x14A0, PredicateKind.EQ, 0x10, 100),),
                    tail_kind=InsnKind.COND_JUMP,
                ),
                92: _block(
                    92,
                    (100,),
                    (91,),
                    0x14B0,
                    kind=BlockKind.ONE_WAY,
                    insns=(
                        InsnSnapshot(
                            opcode=0x44,
                            ea=0x14B0,
                            operands=(),
                            kind=InsnKind.CALL,
                            is_call=True,
                        ),
                    ),
                    tail_kind=InsnKind.GOTO,
                ),
            }
            if observed_discards_exact_effect
            else {}
        ),
        **(
            {
                107: _block(
                    107,
                    (105, 103),
                    (0, 72),
                    0x1470,
                    kind=BlockKind.TWO_WAY,
                    insns=(
                        InsnSnapshot(
                            opcode=0x42,
                            ea=0x1470,
                            operands=(),
                            l=MopSnapshot(
                                kind=OperandKind.STACK,
                                stkoff=64,
                                size=8,
                            ),
                            r=MopSnapshot(
                                kind=OperandKind.NUMBER,
                                value=0,
                                size=8,
                            ),
                            d=MopSnapshot(kind=OperandKind.BLOCK, block_ref=103),
                            kind=InsnKind.COND_JUMP,
                            predicate_kind=PredicateKind.EQ,
                        ),
                    ),
                    tail_kind=InsnKind.COND_JUMP,
                )
            }
            if secondary_foreign_comparison_leaf
            else {}
        ),
    }
    pre_graph = FlowGraph(blocks=blocks, entry_serial=0, func_ea=0x1000)
    pre_graph = _replace_observed_edges(
        pre_graph,
        {serial: tuple(block.succs) for serial, block in pre_graph.blocks.items()},
    )
    target_11 = 103 if mismatched_internal_target else 101
    target_13 = 102 if mismatched_secondary_target else 104
    target_10 = 80 if intermediate_post_route or same_nonhandler_endpoint else 100
    modifications = [
        RedirectGoto(from_serial=10, old_target=30, new_target=target_10),
        RedirectGoto(from_serial=11, old_target=31, new_target=target_11),
        RedirectGoto(from_serial=12, old_target=32, new_target=102),
        RedirectGoto(from_serial=13, old_target=32, new_target=target_13),
    ]
    if internal_goto_alias:
        modifications.append(
            RedirectGoto(from_serial=14, old_target=33, new_target=101)
        )
    coverage = analyze_dispatcher_corridor_coverage(
        pre_graph,
        modifications=tuple(modifications),
        dispatcher_entry_serial=50,
    )
    post_successors = {
        serial: tuple(block.succs) for serial, block in pre_graph.blocks.items()
    }
    post_successors.update(
        {10: (target_10,), 11: (target_11,), 12: (102,), 13: (target_13,)}
    )
    if internal_goto_alias:
        post_successors[14] = (101,)
    producer_post_graph = _replace_observed_edges(pre_graph, post_successors)
    proof = build_dispatcher_removal_preflight_proof(
        pre_graph,
        post_graph=producer_post_graph,
        coverage=coverage,
        dispatcher_entry_serial=50,
        authoritative_handler_serials=frozenset(
            {100, 101, 102, 103, 104, 105}
        ),
        dispatcher_region_serials=frozenset({50, 51}),
        producer_safety=_executed_fragment_safety(),
        state_plumbing_serials=frozenset({30, 31, 32}),
    )
    post_graph = (
        _replace_observed_edges(
            producer_post_graph,
            {
                serial: ((100,) if serial == 91 else tuple(block.succs))
                for serial, block in producer_post_graph.blocks.items()
            },
        )
        if observed_discards_exact_effect
        else producer_post_graph
    )
    return pre_graph, post_graph, coverage, proof




















































@pytest.mark.parametrize(
    "fixture_overrides",
    (
        {"duplicate_carrier_destination": True},
        {"carrier_branch_is_call": True},
    ),
)




@pytest.mark.parametrize(
    "fixture_overrides",
    (
        {"extra_normalizer_operation": True},
        {"carrier_register": 9},
        {"feeder_state_stkoff": 999},
        {"normalized_value": 0x33333333},
        {"semantic_normalizer_predecessor": True},
        {"retain_dynamic_corridor": True},
    ),
)


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


def test_partial_use_def_audit_metadata_and_collection_report_unavailable_safety():
    audit = UseDefSeveranceAudit(
        executed=False,
        severance_count=1,
        failure_reason="query_failed:LookupError",
        enforced=True,
    )

    metadata = audit.to_metadata(function_ea=0x700000)
    assert metadata["enforcement_status"] == "safety_unavailable"

    observations = collect_use_def_severance_observations_from_metadata(
        metadata,
        maturity="MMAT_GLBOPT1",
        phase="lower_state_machine",
    )
    assert len(observations) == 1
    assert observations[0].kind == "UnflattenUseDefSeveranceSummary"
    assert observations[0].payload["enforcement_status"] == "safety_unavailable"
    assert observations[0].payload["severance_count"] == 1


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

    observations = collect_dispatcher_corridor_coverage_observations(
        report,
        maturity="MMAT_GLBOPT1",
        phase="lower_state_machine",
    )
    residual = [
        observation
        for observation in observations
        if observation.payload.get("coverage") == "residual"
    ]
    assert len(residual) == 2
    assert all(observation.source_block in {45, 122} for observation in residual)
    assert all(
        observation.source_ea in {0x7FF859C07656, 0x7FF859C08BFE}
        for observation in residual
    )
    assert all(
        observation.payload["state_merge"]
        == {
            "serial": 123,
            "ea": 0x7FF859C08D35,
            "label": "blk123@0x7ff859c08d35",
        }
        for observation in residual
    )
    assert all(
        "blk45@0x7ff859c07656" in observation.fact_id
        or "blk122@0x7ff859c08bfe" in observation.fact_id
        for observation in residual
    )

    from_metadata = collect_dispatcher_corridor_coverage_observations_from_metadata(
        report.to_metadata(),
        maturity="MMAT_GLBOPT1",
        phase="lower_state_machine",
    )
    assert {observation.fact_id for observation in from_metadata} == {
        observation.fact_id for observation in observations
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
    assert not report.residual_corridors
    assert {
        tuple(anchor.serial for anchor in corridor.path)
        for corridor in report.covered_corridors
    } == {
        (45, 123, 3, 4),
        (122, 123, 3, 4),
    }

    pending = collect_dispatcher_corridor_coverage_observations(
        report,
        maturity="MMAT_GLBOPT1",
        phase="lower_state_machine",
    )
    pending_rows = [
        observation
        for observation in pending
        if observation.kind == "UnflattenDispatcherCorridorCoverage"
    ]
    assert {row.payload["coverage"] for row in pending_rows} == {"pending"}
    assert {row.payload["planned_coverage"] for row in pending_rows} == {"covered"}
    assert {row.payload["completion_status"] for row in pending_rows} == {
        "pending_patch_application"
    }

    rejected = collect_dispatcher_corridor_coverage_observations(
        report,
        maturity="MMAT_GLBOPT1",
        phase="patch_transaction",
        application_status="rejected_preflight",
        outcome_reason="entry reachability collapsed",
    )
    rejected_rows = [
        observation
        for observation in rejected
        if observation.kind == "UnflattenDispatcherCorridorCoverage"
    ]
    assert {row.payload["coverage"] for row in rejected_rows} == {"residual"}
    assert {row.payload["application_status"] for row in rejected_rows} == {
        "rejected_preflight"
    }
    assert {row.payload["completion_status"] for row in rejected_rows} == {
        "abstained_rejected_preflight"
    }


def test_dispatcher_removal_proof_accepts_only_typed_infrastructure_loss() -> None:
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

    proof = build_dispatcher_removal_preflight_proof(
        graph,
        post_graph=post_graph,
        coverage=coverage,
        dispatcher_entry_serial=4,
        authoritative_handler_serials=frozenset({34, 121}),
        dispatcher_region_serials=frozenset({4}),
        producer_safety=_executed_fragment_safety(),
    )

    assert isinstance(proof, DispatcherRemovalPreflightProof)
    assert proof.passed
    assert proof.lost_blocks == {
        3,
        4,
        123,
    }
    assert {anchor.serial for anchor in proof.post_reachable_handlers} == {34, 121}
    assert {
        (entry.role, entry.anchor.serial) for entry in proof.retired_infrastructure
    } == {
        ("comparison_dispatcher", 4),
        ("dispatcher_feeder", 3),
        ("state_merge", 123),
    }






def _populated_router_block(*operands: MopSnapshot) -> BlockSnapshot:
    predicate = InsnSnapshot(
        opcode=0x71,
        ea=0x7FF859C0A000,
        operands=(),
        l=operands[0] if operands else None,
        r=operands[1] if len(operands) > 1 else None,
        d=MopSnapshot(kind=OperandKind.BLOCK, block_ref=1),
        kind=InsnKind.COND_JUMP,
        predicate_kind=PredicateKind.NE,
    )
    return _block(
        10,
        (1, 2),
        (),
        0x7FF859C0A000,
        kind=BlockKind.TWO_WAY,
        insns=(predicate,),
        tail_kind=InsnKind.COND_JUMP,
    )


@pytest.mark.parametrize(
    "operand",
    (
        MopSnapshot(kind=OperandKind.GLOBAL, gaddr=0x7FF859C0B000),
        MopSnapshot(
            kind=OperandKind.ADDRESS,
            sub_l=MopSnapshot(kind=OperandKind.STACK, stkoff=0x20),
        ),
        MopSnapshot(
            kind=OperandKind.SUBINSN,
            sub_kind=InsnKind.CALL,
            sub_l=MopSnapshot(kind=OperandKind.REGISTER, reg=1),
        ),
        MopSnapshot(kind=OperandKind.UNKNOWN),
    ),
)
def test_effect_free_dispatcher_router_rejects_effectful_or_unresolved_operands(
    operand: MopSnapshot,
) -> None:
    """Router kind alone cannot prove a predicate is effect-free."""
    assert not corridor_module._is_effect_free_dispatcher_router(
        _populated_router_block(operand, MopSnapshot(kind=OperandKind.NUMBER, value=0))
    )




def test_dispatcher_removal_proof_skips_direct_corridor_in_mixed_coverage() -> None:
    """A direct feeder must not veto an independently typed merge forest."""
    nested = _nested_merge_corridor_graph()
    graph = FlowGraph(
        blocks={
            **nested.blocks,
            0: _block(0, (45, 122, 200), (), 0x7FF859C06F60),
            4: _block(4, (121, 34), (3, 200), 0x7FF859C070C4),
            200: _block(200, (4,), (0,), 0x7FF859C09000),
        },
        entry_serial=0,
        func_ea=0x7FF859C06F60,
    )
    coverage = analyze_dispatcher_corridor_coverage(
        graph,
        modifications=(
            RedirectGoto(from_serial=45, old_target=123, new_target=121),
            RedirectGoto(from_serial=122, old_target=123, new_target=34),
            RedirectGoto(from_serial=200, old_target=4, new_target=121),
        ),
        dispatcher_entry_serial=4,
    )
    assert any(
        corridor.state_merge is None
        for corridor in coverage.covered_corridors
    )
    post_graph = FlowGraph(
        blocks={
            **graph.blocks,
            45: _block(45, (121,), (0,), 0x7FF859C07656),
            122: _block(122, (34,), (0,), 0x7FF859C08BFE),
            200: _block(200, (121,), (0,), 0x7FF859C09000),
        },
        entry_serial=0,
        func_ea=0x7FF859C06F60,
    )
    proof = build_dispatcher_removal_preflight_proof(
        graph,
        post_graph=post_graph,
        coverage=coverage,
        dispatcher_entry_serial=4,
        authoritative_handler_serials=frozenset({34, 121}),
        dispatcher_region_serials=frozenset({4}),
        producer_safety=_executed_fragment_safety(),
    )

    assert proof.passed
    assert ("comparison_corridor", 200) not in {
        (entry.role, entry.anchor.serial)
        for entry in proof.retired_infrastructure
    }


def test_dispatcher_removal_proof_rejects_lost_handler_near_miss() -> None:
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
            45: _block(45, (121,), (0,), 0x7FF859C07656),
            122: _block(122, (34,), (0,), 0x7FF859C08BFE),
        },
        entry_serial=0,
        func_ea=0x7FF859C06F60,
    )

    proof = build_dispatcher_removal_preflight_proof(
        graph,
        post_graph=post_graph,
        coverage=coverage,
        dispatcher_entry_serial=4,
        authoritative_handler_serials=frozenset({34, 121, 123}),
        dispatcher_region_serials=frozenset({4}),
        producer_safety=_executed_fragment_safety(),
    )

    assert not proof.passed
    assert proof.reason == "authoritative_handler_lost"


def test_dispatcher_removal_proof_rejects_empty_authoritative_handlers() -> None:
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
            45: _block(45, (121,), (0,), 0x7FF859C07656),
            122: _block(122, (34,), (0,), 0x7FF859C08BFE),
        },
        entry_serial=0,
        func_ea=0x7FF859C06F60,
    )

    proof = build_dispatcher_removal_preflight_proof(
        graph,
        post_graph=post_graph,
        coverage=coverage,
        dispatcher_entry_serial=4,
        authoritative_handler_serials=frozenset(),
        dispatcher_region_serials=frozenset({4}),
        producer_safety=_executed_fragment_safety(),
    )

    assert not proof.passed
    assert proof.reason == "authoritative_handlers_empty"


def test_dispatcher_removal_proof_rejects_unexecuted_use_def_safety() -> None:
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
            45: _block(45, (121,), (0,), 0x7FF859C07656),
            122: _block(122, (34,), (0,), 0x7FF859C08BFE),
        },
        entry_serial=0,
        func_ea=0x7FF859C06F60,
    )

    proof = build_dispatcher_removal_preflight_proof(
        graph,
        post_graph=post_graph,
        coverage=coverage,
        dispatcher_entry_serial=4,
        authoritative_handler_serials=frozenset({34, 121}),
        dispatcher_region_serials=frozenset({4}),
        producer_safety={
            "fragment_atomic": True,
            "non_state_use_def_veto": True,
            "non_state_use_def_checked": False,
            "non_state_use_def_severances_zero": False,
        },
    )

    assert not proof.passed
    assert proof.reason == "producer_safety_missing"


def test_dispatcher_removal_proof_rejects_linear_semantic_body_labeled_merge() -> None:
    graph = FlowGraph(
        blocks={
            0: _block(0, (1,), (), 0x1000),
            1: _block(1, (2,), (0,), 0x1001),
            2: _block(2, (3,), (1,), 0x1002),
            3: _block(3, (4,), (2,), 0x1003),
            4: _block(4, (), (3,), 0x1004),
        },
        entry_serial=0,
        func_ea=0x1000,
    )
    coverage = analyze_dispatcher_corridor_coverage(
        graph,
        modifications=(RedirectGoto(from_serial=0, old_target=1, new_target=4),),
        dispatcher_entry_serial=3,
    )
    post_graph = FlowGraph(
        blocks={
            **graph.blocks,
            0: _block(0, (4,), (), 0x1000),
        },
        entry_serial=0,
        func_ea=0x1000,
    )

    proof = build_dispatcher_removal_preflight_proof(
        graph,
        post_graph=post_graph,
        coverage=coverage,
        dispatcher_entry_serial=3,
        authoritative_handler_serials=frozenset({4}),
        dispatcher_region_serials=frozenset({1, 3}),
        producer_safety=_executed_fragment_safety(),
    )

    assert not proof.passed
    assert proof.reason == "untyped_lost_block"
    assert coverage.covered_corridors[0].state_merge is None










def test_dispatcher_removal_proof_rejects_effectful_state_merge() -> None:
    graph = _nested_merge_corridor_graph()
    effectful = InsnSnapshot(
        opcode=4,
        ea=0x7FF859C08D37,
        operands=(),
        kind=InsnKind.UNKNOWN,
    )
    graph = FlowGraph(
        blocks={
            **graph.blocks,
            123: _block(
                123,
                (3,),
                (45, 122),
                0x7FF859C08D35,
                insns=(effectful,),
            ),
        },
        entry_serial=0,
        func_ea=0x7FF859C06F60,
    )
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
            45: _block(45, (121,), (0,), 0x7FF859C07656),
            122: _block(122, (34,), (0,), 0x7FF859C08BFE),
        },
        entry_serial=0,
        func_ea=0x7FF859C06F60,
    )

    proof = build_dispatcher_removal_preflight_proof(
        graph,
        post_graph=post_graph,
        coverage=coverage,
        dispatcher_entry_serial=4,
        authoritative_handler_serials=frozenset({34, 121}),
        dispatcher_region_serials=frozenset({4}),
        producer_safety=_executed_fragment_safety(),
        # Raw producer metadata may call this state plumbing; it is not bound
        # authority at the generic validator boundary.
        state_plumbing_serials=frozenset({3, 123}),
    )

    assert not proof.passed
    assert proof.reason == "untyped_lost_block"
    assert 123 in proof.lost_blocks


def _detached_dead_handler_component_fixture() -> tuple[FlowGraph, FlowGraph, object]:
    """One typed producer candidate with a retained and a dead handler."""
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
                21, (113,), (4,), 0x1310, kind=BlockKind.ONE_WAY,
                insns=(dead_local_write,),
            ),
            113: _block(
                113, (4,), (21,), 0x1320, kind=BlockKind.ONE_WAY,
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
    post_graph = _replace_observed_edges(
        pre_graph,
        {
            **{serial: tuple(block.succs) for serial, block in pre_graph.blocks.items()},
            0: (10, 12), 10: (20,), 12: (20,), 21: (20,),
        },
    )
    return pre_graph, post_graph, coverage


def test_detached_component_analysis_uses_state_aware_decision_forest(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The typed producer recovers a state-aware forest if structural routing abstains."""
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


def test_detached_component_analysis_uses_pure_control_fallback_for_wrapper_shape(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A strict forest abstention still permits only the bounded pure-control walk."""
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
