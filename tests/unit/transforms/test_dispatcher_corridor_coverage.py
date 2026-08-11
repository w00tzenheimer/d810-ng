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
from d810.transforms import minimal_unflatten_emit as emit_module
from d810.transforms.dispatcher_corridor_coverage import (
    DispatcherRemovalPreflightProof,
    build_dispatcher_removal_preflight_proof,
    collect_dispatcher_corridor_coverage_observations,
    collect_dispatcher_corridor_coverage_observations_from_metadata,
    collect_dispatcher_removal_preflight_proof_observations_from_metadata,
    collect_use_def_severance_observations_from_metadata,
    analyze_dispatcher_corridor_coverage,
    canonicalize_observed_dispatcher_graph,
    USE_DEF_SEVERANCE_AUDIT_METADATA,
    validate_dispatcher_corridor_coverage_metadata,
    validate_dispatcher_removal_preflight_proof,
)
from d810.transforms.graph_modification import (
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
                tail_kind=(
                    InsnKind.COND_JUMP if preserve_live else InsnKind.GOTO
                ),
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
    predecessor_map: dict[int, list[int]] = {
        serial: [] for serial in observed_blocks
    }
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


@pytest.mark.parametrize(
    ("helper_kind", "helper_tail"),
    (
        (BlockKind.STOP, InsnKind.GOTO),
        (BlockKind.TWO_WAY, InsnKind.COND_JUMP),
        (BlockKind.ONE_WAY, InsnKind.COND_JUMP),
    ),
)
def test_observed_collapsed_helper_requires_one_way_goto(
    helper_kind: BlockKind,
    helper_tail: InsnKind,
) -> None:
    _pre, observed, plan = _conditional_observation_fixture()
    observed = _replace_observed_edges(
        observed,
        {serial: block.succs for serial, block in observed.blocks.items()},
        overrides={11: {"kind": helper_kind, "tail_kind": helper_tail}},
    )

    with pytest.raises(ValueError, match="helper"):
        canonicalize_observed_dispatcher_graph(_pre, observed, plan)


@pytest.mark.parametrize(
    ("source_kind", "source_tail"),
    (
        (BlockKind.ONE_WAY, InsnKind.GOTO),
        (BlockKind.TWO_WAY, InsnKind.GOTO),
    ),
)
def test_observed_lowering_source_requires_two_way_conditional_tail(
    source_kind: BlockKind,
    source_tail: InsnKind | None,
) -> None:
    _pre, observed, plan = _conditional_observation_fixture()
    observed = _replace_observed_edges(
        observed,
        {serial: block.succs for serial, block in observed.blocks.items()},
        overrides={
            10: {"kind": source_kind, "tail_kind": source_tail},
        },
    )

    with pytest.raises(ValueError, match="source"):
        canonicalize_observed_dispatcher_graph(_pre, observed, plan)


@pytest.mark.parametrize("true_is_taken", (True, False))
def test_observed_lowering_validates_physical_fallthrough_taken_order(
    true_is_taken: bool,
) -> None:
    condition = PreserveLivePredicateCondition(
        predicate_ea=0x1005,
        true_is_taken=true_is_taken,
    )
    pre, observed, plan = _conditional_observation_fixture(
        true_is_taken=true_is_taken,
        condition_operand=condition,
    )
    canonical = canonicalize_observed_dispatcher_graph(pre, observed, plan)
    assert canonical.blocks[10].succs == (30, 40)

    fallthrough_target = 31 if true_is_taken else 41
    taken_target = 41 if true_is_taken else 31
    swapped = _replace_observed_edges(
        observed,
        {
            **{
                serial: block.succs
                for serial, block in observed.blocks.items()
                if serial not in {10, 11}
            },
            10: (11, fallthrough_target),
            11: (taken_target,),
        },
    )
    assert swapped.blocks[10].succs == (11, fallthrough_target)
    with pytest.raises(ValueError, match="arms|helper"):
        canonicalize_observed_dispatcher_graph(pre, swapped, plan)


def test_observed_lowering_defaults_true_is_taken_to_true() -> None:
    pre, observed, plan = _conditional_observation_fixture()
    canonical = canonicalize_observed_dispatcher_graph(pre, observed, plan)

    assert canonical.blocks[10].succs == (30, 40)


def test_observed_predecessor_mismatch_is_not_repaired() -> None:
    pre, observed, plan = _conditional_observation_fixture()
    corrupted = _replace_observed_edges(
        observed,
        {serial: block.succs for serial, block in observed.blocks.items()},
        overrides={31: {"preds": (10,)}},
    )

    with pytest.raises(ValueError, match="CFG_50858"):
        canonicalize_observed_dispatcher_graph(pre, corrupted, plan)


def test_observed_lowering_requires_exact_helper_inventory_and_ownership() -> None:
    pre, direct_arms, plan = _conditional_observation_fixture()
    zero_helpers = _replace_observed_edges(
        direct_arms,
        {
            **{
                serial: block.succs
                for serial, block in direct_arms.blocks.items()
                if serial not in {10, 11}
            },
            10: (31, 41),
            11: (),
        },
    )
    with pytest.raises(ValueError, match="helper"):
        canonicalize_observed_dispatcher_graph(pre, zero_helpers, plan)

    _pre, stateful, stateful_plan = _conditional_observation_fixture(stateful=True)
    one_helper_stateful = _replace_observed_edges(
        stateful,
        {
            **{serial: block.succs for serial, block in stateful.blocks.items()},
            10: (11, 41),
            11: (31,),
            12: (41,),
        },
    )
    with pytest.raises(ValueError, match="helper"):
        canonicalize_observed_dispatcher_graph(_pre, one_helper_stateful, stateful_plan)

    multi_hop = _replace_observed_edges(
        stateful,
        {
            **{serial: block.succs for serial, block in stateful.blocks.items()},
            10: (11, 12),
            11: (12,),
            12: (31,),
        },
    )
    with pytest.raises(ValueError, match="helper"):
        canonicalize_observed_dispatcher_graph(_pre, multi_hop, stateful_plan)

    shared = _replace_observed_edges(
        direct_arms,
        {
            **{
                serial: block.succs
                for serial, block in direct_arms.blocks.items()
            },
            10: (11, 11),
            11: (31,),
        },
    )
    with pytest.raises(ValueError, match="helper|CFG_50858"):
        canonicalize_observed_dispatcher_graph(pre, shared, plan)


def test_observed_lowering_requires_predicate_and_rewrite_identity() -> None:
    condition = PreserveLivePredicateCondition(
        predicate_ea=0x1005,
        true_is_taken=True,
    )
    pre, observed, plan = _conditional_observation_fixture(
        condition_operand=condition,
    )
    canonical = canonicalize_observed_dispatcher_graph(pre, observed, plan)
    assert canonical.blocks[10].tail_kind is InsnKind.COND_JUMP

    wrong_predicate_step = replace(
        plan.steps[0],
        rewrite_from_ea=0x1006,
        condition_operand=replace(condition, predicate_ea=0x1006),
    )
    wrong_predicate_plan = SimpleNamespace(
        steps=(wrong_predicate_step,),
        source_coordinates=(),
    )
    with pytest.raises(ValueError, match="identity"):
        canonicalize_observed_dispatcher_graph(pre, observed, wrong_predicate_plan)

    source = observed.blocks[10]
    untyped_predicate = replace(
        source.insn_snapshots[0],
        predicate_kind=None,
        branch_predicate=None,
    )
    missing_identity = FlowGraph(
        blocks={
            **observed.blocks,
            10: replace(source, insn_snapshots=(untyped_predicate,)),
        },
        entry_serial=observed.entry_serial,
        func_ea=observed.func_ea,
    )
    with pytest.raises(ValueError, match="identity"):
        canonicalize_observed_dispatcher_graph(pre, missing_identity, plan)

    changed_semantics = replace(
        source.insn_snapshots[0],
        opcode=0x72,
        raw_opcode=0x72,
        predicate_kind=PredicateKind.EQ,
        branch_predicate=PredicateKind.EQ,
    )
    wrong_semantics = replace(
        observed,
        blocks={
            **observed.blocks,
            10: replace(source, insn_snapshots=(changed_semantics,)),
        },
    )
    with pytest.raises(ValueError, match="identity"):
        canonicalize_observed_dispatcher_graph(pre, wrong_semantics, plan)


def test_observed_stateful_helpers_require_exact_adjacent_state_writes() -> None:
    pre, observed, plan = _conditional_observation_fixture(stateful=True)
    assert canonicalize_observed_dispatcher_graph(pre, observed, plan)

    empty_helpers = replace(
        observed,
        blocks={
            **observed.blocks,
            11: replace(observed.blocks[11], insn_snapshots=()),
            12: replace(observed.blocks[12], insn_snapshots=()),
        },
    )
    with pytest.raises(ValueError, match="state write"):
        canonicalize_observed_dispatcher_graph(pre, empty_helpers, plan)

    bad_write = replace(
        observed.blocks[12].insn_snapshots[0],
        l=MopSnapshot(kind=OperandKind.NUMBER, value=0x99, size=4),
    )
    wrong_value = replace(
        observed,
        blocks={
            **observed.blocks,
            12: replace(
                observed.blocks[12],
                insn_snapshots=(bad_write, observed.blocks[12].insn_snapshots[1]),
            ),
        },
    )
    with pytest.raises(ValueError, match="state write"):
        canonicalize_observed_dispatcher_graph(pre, wrong_value, plan)

    successors = {
        serial: block.succs for serial, block in observed.blocks.items()
    }
    moved_blocks = dict(observed.blocks)
    moved_blocks[99] = replace(
        moved_blocks.pop(12),
        serial=99,
        preds=(10,),
    )
    successors.pop(12)
    successors[10] = (11, 99)
    successors[99] = moved_blocks[99].succs
    moved = FlowGraph(
        blocks=moved_blocks,
        entry_serial=observed.entry_serial,
        func_ea=observed.func_ea,
    )
    moved = _replace_observed_edges(moved, successors)
    with pytest.raises(ValueError, match="adjacent"):
        canonicalize_observed_dispatcher_graph(pre, moved, plan)


def _nested_merge_corridor_graph() -> FlowGraph:
    """The two real WowClassicT residual corridors, in portable CFG form."""
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


def _executed_fragment_safety() -> dict[str, bool]:
    """The only producer evidence eligible for the narrow retirement proof."""
    return {
        "fragment_atomic": True,
        "non_state_use_def_veto": True,
        "non_state_use_def_checked": True,
        "non_state_use_def_severances_zero": True,
    }


def _interval_state_normalizer_fixture(
    *,
    extra_normalizer_operation: bool = False,
    carrier_register: int = 8,
    feeder_state_stkoff: int = 452,
    normalized_value: int = 0x37E2E8EF,
    semantic_normalizer_predecessor: bool = False,
    retain_dynamic_corridor: bool = False,
) -> tuple[FlowGraph, FlowGraph, object, object]:
    """One strict interval-normalizer plus a predecessor-partitioned state merge."""

    def move(
        ea: int,
        source: MopSnapshot,
        destination: MopSnapshot,
    ) -> InsnSnapshot:
        return InsnSnapshot(
            opcode=4,
            ea=ea,
            operands=(),
            l=source,
            d=destination,
            kind=InsnKind.MOV,
        )

    state = MopSnapshot(kind=OperandKind.STACK, stkoff=452, size=4)
    feeder_state = MopSnapshot(
        kind=OperandKind.STACK,
        stkoff=feeder_state_stkoff,
        size=4,
    )
    carrier = MopSnapshot(kind=OperandKind.REGISTER, reg=carrier_register, size=4)
    normalizer_insns = (
        move(
            0x1450,
            MopSnapshot(
                kind=OperandKind.NUMBER,
                value=normalized_value,
                size=4,
            ),
            MopSnapshot(kind=OperandKind.REGISTER, reg=8, size=4),
        ),
    )
    if extra_normalizer_operation:
        normalizer_insns += (
            move(
                0x1451,
                MopSnapshot(kind=OperandKind.NUMBER, value=0x99, size=4),
                MopSnapshot(kind=OperandKind.REGISTER, reg=10, size=4),
            ),
        )
    normalizer_insns += (
        InsnSnapshot(
            opcode=55,
            ea=0x1452,
            operands=(),
            l=MopSnapshot(kind=OperandKind.BLOCK, block_ref=3),
            kind=InsnKind.GOTO,
        ),
    )
    dispatcher_branch = InsnSnapshot(
        opcode=42,
        ea=0x1200,
        operands=(),
        l=state,
        r=MopSnapshot(
            kind=OperandKind.NUMBER,
            value=0x37E2E8EF,
            size=4,
        ),
        d=MopSnapshot(kind=OperandKind.BLOCK, block_ref=43),
        kind=InsnKind.COND_JUMP,
        predicate_kind=PredicateKind.EQ,
    )
    secondary_dispatcher_branch = InsnSnapshot(
        opcode=42,
        ea=0x1210,
        operands=(),
        l=state,
        r=MopSnapshot(kind=OperandKind.NUMBER, value=0x22222222, size=4),
        d=MopSnapshot(kind=OperandKind.BLOCK, block_ref=70),
        kind=InsnKind.COND_JUMP,
        predicate_kind=PredicateKind.EQ,
    )
    unrelated_handler_branch = InsnSnapshot(
        opcode=42,
        ea=0x1710,
        operands=(),
        l=MopSnapshot(kind=OperandKind.GLOBAL, gaddr=0x140003000, size=4),
        r=MopSnapshot(kind=OperandKind.NUMBER, value=0, size=4),
        d=MopSnapshot(kind=OperandKind.BLOCK, block_ref=89),
        kind=InsnKind.COND_JUMP,
        predicate_kind=PredicateKind.NE,
    )
    semantic_handler = move(
        0x1600,
        MopSnapshot(kind=OperandKind.NUMBER, value=7, size=4),
        MopSnapshot(kind=OperandKind.REGISTER, reg=11, size=4),
    )
    dynamic_state_write = InsnSnapshot(
        opcode=21,
        ea=0x1500,
        operands=(),
        l=MopSnapshot(kind=OperandKind.REGISTER, reg=24, size=4),
        r=MopSnapshot(kind=OperandKind.REGISTER, reg=16, size=4),
        d=state,
        kind=InsnKind.UNKNOWN,
        value_op_kind=ValueOpKind.XOR,
    )
    entry_successors = (10, 12, 99) if semantic_normalizer_predecessor else (10, 12)
    normalizer_predecessors = (5, 99) if semantic_normalizer_predecessor else (5,)
    blocks = {
        0: _block(0, entry_successors, (), 0x1000, kind=BlockKind.N_WAY),
        3: _block(
            3,
            (4,),
            (10, 50),
            0x1100,
            kind=BlockKind.ONE_WAY,
            insns=(move(0x1100, carrier, feeder_state),),
            tail_kind=InsnKind.GOTO,
        ),
        4: _block(
            4,
            (5, 43),
            (3, 65),
            0x1200,
            kind=BlockKind.TWO_WAY,
            insns=(dispatcher_branch,),
            tail_kind=InsnKind.COND_JUMP,
        ),
        5: _block(
            5,
            (50, 70),
            (4,),
            0x1210,
            kind=BlockKind.TWO_WAY,
            insns=(secondary_dispatcher_branch,),
            tail_kind=InsnKind.COND_JUMP,
        ),
        10: _block(10, (3,), (0,), 0x1300, kind=BlockKind.ONE_WAY),
        12: _block(12, (65,), (0,), 0x1350, kind=BlockKind.ONE_WAY),
        43: _block(
            43,
            (88,),
            (4, 71),
            0x1400,
            kind=BlockKind.ONE_WAY,
            insns=(semantic_handler,),
        ),
        50: _block(
            50,
            (3,),
            normalizer_predecessors,
            0x1450,
            kind=BlockKind.ONE_WAY,
            insns=normalizer_insns,
            tail_kind=InsnKind.GOTO,
        ),
        65: _block(
            65,
            (4,),
            (12,),
            0x1500,
            kind=BlockKind.ONE_WAY,
            insns=(dynamic_state_write,),
            tail_kind=InsnKind.GOTO,
        ),
        70: _block(
            70,
            (71,),
            (5,),
            0x1680,
            kind=BlockKind.ONE_WAY,
            tail_kind=InsnKind.GOTO,
        ),
        71: _block(
            71,
            (43, 89),
            (70,),
            0x1710,
            kind=BlockKind.TWO_WAY,
            insns=(unrelated_handler_branch,),
            tail_kind=InsnKind.COND_JUMP,
        ),
        88: _block(88, (), (43,), 0x1780, kind=BlockKind.STOP),
        89: _block(89, (), (71,), 0x1790, kind=BlockKind.STOP),
    }
    if semantic_normalizer_predecessor:
        blocks[99] = _block(99, (50,), (0,), 0x1800, kind=BlockKind.ONE_WAY)
    pre_graph = FlowGraph(blocks=blocks, entry_serial=0, func_ea=0x1000)
    modifications = [
        RedirectGoto(from_serial=10, old_target=3, new_target=43),
    ]
    if not retain_dynamic_corridor:
        modifications.append(
            RedirectGoto(from_serial=12, old_target=65, new_target=71)
        )
    coverage = analyze_dispatcher_corridor_coverage(
        pre_graph,
        modifications=tuple(modifications),
        dispatcher_entry_serial=4,
    )
    post_successors = {
        serial: tuple(block.succs) for serial, block in pre_graph.blocks.items()
    }
    post_successors[10] = (43,)
    if not retain_dynamic_corridor:
        post_successors[12] = (71,)
    post_graph = _replace_observed_edges(pre_graph, post_successors)
    proof = build_dispatcher_removal_preflight_proof(
        pre_graph,
        post_graph=post_graph,
        coverage=coverage,
        dispatcher_entry_serial=4,
        authoritative_handler_serials=frozenset({43, 50, 71}),
        dispatcher_region_serials=frozenset({4}),
        producer_safety=_executed_fragment_safety(),
        state_plumbing_serials=frozenset({3, 50, 65}),
    )
    return pre_graph, post_graph, coverage, proof


def test_interval_state_normalizer_retirement_is_independently_proven() -> None:
    pre_graph, post_graph, coverage, proof = _interval_state_normalizer_fixture()

    assert not proof.passed
    assert proof.reason == "authoritative_handler_lost"
    validation = validate_dispatcher_removal_preflight_proof(
        pre_graph,
        post_graph=post_graph,
        plan_metadata={
            "dispatcher_corridor_coverage": coverage.to_metadata(),
            "dispatcher_removal_preflight_proof": proof.to_metadata(),
        },
    )

    assert validation.passed
    assert validation.reason == "interval_state_normalizer_retirement"
    payload = validation.to_payload()["interval_state_normalizer_retirement"]
    assert payload["normalizers"] == [
        {
            "normalizer": {"serial": 50, "ea": 0x1450, "label": "blk50@0x1450"},
            "state_feeder": {"serial": 3, "ea": 0x1100, "label": "blk3@0x1100"},
            "normalized_value": 0x37E2E8EF,
            "routed_handler": {"serial": 43, "ea": 0x1400, "label": "blk43@0x1400"},
        }
    ]
    assert {
        (item["role"], item["anchor"]["serial"])
        for item in payload["retired_state_plumbing"]
    } == {
        ("dispatcher_state_feeder", 3),
        ("state_normalizer", 50),
        ("dispatcher_state_merge", 65),
    }

    observations = collect_dispatcher_removal_preflight_proof_observations_from_metadata(
        proof.to_metadata(),
        coverage_metadata=coverage.to_metadata(),
        maturity="MMAT_GLBOPT1",
        phase="lower_state_machine",
        application_status="applied",
        projected_validation=validation,
        observed_validation=validation,
        plan_id="interval-normalizer-plan",
        attempt_id="interval-normalizer-attempt",
    )
    assert len(observations) == 1
    persisted_payload = observations[0].payload
    assert persisted_payload["projected_validation"]["reason"] == (
        "interval_state_normalizer_retirement"
    )
    assert persisted_payload["observed_validation"][
        "interval_state_normalizer_retirement"
    ]["normalizers"][0]["normalizer"] == {
        "serial": 50,
        "ea": 0x1450,
        "label": "blk50@0x1450",
    }


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
def test_interval_state_normalizer_retirement_rejects_unsafe_near_misses(
    fixture_overrides: dict[str, object],
) -> None:
    pre_graph, post_graph, coverage, proof = _interval_state_normalizer_fixture(
        **fixture_overrides
    )

    validation = validate_dispatcher_removal_preflight_proof(
        pre_graph,
        post_graph=post_graph,
        plan_metadata={
            "dispatcher_corridor_coverage": coverage.to_metadata(),
            "dispatcher_removal_preflight_proof": proof.to_metadata(),
        },
    )

    assert not validation.passed


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
    assert audit.to_metadata(function_ea=0x700000)["violations"][0][
        "use_instruction_ea"
    ] == 0x7002AA


def test_target_shape_advisory_and_explicit_veto_preserve_exact_counts(monkeypatch) -> None:
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
    advisory = advisory_plan.metadata_dict()[USE_DEF_SEVERANCE_AUDIT_METADATA]
    assert advisory["severance_count"] == 3
    assert advisory["enforced"] is False
    assert len(advisory["violations"]) == 3
    assert {
        (
            violation["use"]["serial"],
            violation["use"]["ea"],
            violation["use"]["label"],
            violation["use_instruction_ea"],
        )
        for violation in advisory["violations"]
    } == {(45, 0x700200, "blk45@0x700200", 0x7002AA)}
    observations = collect_use_def_severance_observations_from_metadata(
        advisory,
        maturity="MMAT_GLBOPT1",
        phase="lower_state_machine",
    )
    assert len(observations) == 4
    assert sum(item.kind == "UnflattenUseDefSeverance" for item in observations) == 3
    assert all(
        item.payload["use"]
        == {"serial": 45, "ea": 0x700200, "label": "blk45@0x700200"}
        and item.payload["use_instruction_ea"] == 0x7002AA
        for item in observations
        if item.kind == "UnflattenUseDefSeverance"
    )

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
    enforced = enforced_plan.metadata_dict()[USE_DEF_SEVERANCE_AUDIT_METADATA]
    assert enforced["severance_count"] == 3
    assert enforced["enforced"] is True
    assert enforced["enforcement_status"] == "fragment_rejected"


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
        if corridor.source.serial in {45, 122}
        and corridor.state_merge is not None
    } == {123}


def test_coverage_validation_preserves_shared_merge_paths_from_flowgraph() -> None:
    """Validation must normalize list-valued FlowGraph adjacency at the boundary."""
    graph = _nested_merge_behind_shared_feeder_graph()
    coverage = analyze_dispatcher_corridor_coverage(
        graph,
        modifications=(),
        dispatcher_entry_serial=4,
    )

    validation = validate_dispatcher_corridor_coverage_metadata(
        graph,
        post_graph=graph,
        plan_metadata={
            "dispatcher_corridor_coverage": coverage.to_metadata(),
        },
    )

    assert validation.passed
    assert validation.reason == "dispatcher_corridor_coverage_matches_observed"


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
    assert all(observation.source_ea in {0x7FF859C07656, 0x7FF859C08BFE} for observation in residual)
    assert all(
        observation.payload["state_merge"]
        == {
            "serial": 123,
            "ea": 0x7FF859C08D35,
            "label": "blk123@0x7ff859c08d35",
        }
        for observation in residual
    )
    assert all("blk45@0x7ff859c07656" in observation.fact_id or "blk122@0x7ff859c08bfe" in observation.fact_id for observation in residual)

    from_metadata = collect_dispatcher_corridor_coverage_observations_from_metadata(
        report.to_metadata(),
        maturity="MMAT_GLBOPT1",
        phase="lower_state_machine",
    )
    assert {
        observation.fact_id for observation in from_metadata
    } == {observation.fact_id for observation in observations}


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
        (entry.role, entry.anchor.serial)
        for entry in proof.retired_infrastructure
    } == {
        ("comparison_dispatcher", 4),
        ("dispatcher_feeder", 3),
        ("state_merge", 123),
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


def test_dispatcher_removal_validation_rejects_handler_ea_drift() -> None:
    graph = _nested_merge_corridor_graph()
    coverage = analyze_dispatcher_corridor_coverage(
        graph,
        modifications=(
            RedirectGoto(from_serial=45, old_target=123, new_target=121),
            RedirectGoto(from_serial=122, old_target=123, new_target=34),
        ),
        dispatcher_entry_serial=4,
    )
    projected = FlowGraph(
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
        post_graph=projected,
        coverage=coverage,
        dispatcher_entry_serial=4,
        authoritative_handler_serials=frozenset({34, 121}),
        dispatcher_region_serials=frozenset({4}),
        producer_safety=_executed_fragment_safety(),
    )
    observed = FlowGraph(
        blocks={
            **projected.blocks,
            121: _block(121, (), (4,), 0xDEADBEEF),
        },
        entry_serial=0,
        func_ea=0x7FF859C06F60,
    )

    validation = validate_dispatcher_removal_preflight_proof(
        graph,
        post_graph=observed,
        plan_metadata={
            "dispatcher_corridor_coverage": coverage.to_metadata(),
            "dispatcher_removal_preflight_proof": proof.to_metadata(),
        },
    )

    assert not validation.passed
    assert validation.reason == "dispatcher_removal_proof_coverage_drift" or (
        validation.proof is not None
        and validation.proof.reason == "authoritative_handler_identity_drift"
    )


def test_dispatcher_removal_validation_rejects_terminal_shape_drift() -> None:
    original = _nested_merge_corridor_graph()
    graph = FlowGraph(
        blocks={
            **original.blocks,
            34: _block(34, (), (4,), 0x7FF859C0747A, kind=BlockKind.STOP),
            121: _block(121, (), (4,), 0x7FF859C08B37, kind=BlockKind.STOP),
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
    projected = FlowGraph(
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
        post_graph=projected,
        coverage=coverage,
        dispatcher_entry_serial=4,
        authoritative_handler_serials=frozenset({34, 121}),
        dispatcher_region_serials=frozenset({4}),
        producer_safety=_executed_fragment_safety(),
    )
    observed = FlowGraph(
        blocks={
            **projected.blocks,
            34: _block(
                34,
                (121,),
                (4,),
                0x7FF859C0747A,
                kind=BlockKind.ONE_WAY,
            ),
        },
        entry_serial=0,
        func_ea=0x7FF859C06F60,
    )

    validation = validate_dispatcher_removal_preflight_proof(
        graph,
        post_graph=observed,
        plan_metadata={
            "dispatcher_corridor_coverage": coverage.to_metadata(),
            "dispatcher_removal_preflight_proof": proof.to_metadata(),
        },
    )

    assert not validation.passed
    assert validation.reason == "dispatcher_removal_proof_coverage_drift" or (
        validation.proof is not None
        and validation.proof.reason == "reachable_terminal_lost"
    )


def test_dispatcher_removal_validation_rejects_terminal_ea_drift() -> None:
    original = _nested_merge_corridor_graph()
    graph = FlowGraph(
        blocks={
            **original.blocks,
            34: _block(34, (), (4,), 0x7FF859C0747A, kind=BlockKind.STOP),
            121: _block(121, (), (4,), 0x7FF859C08B37, kind=BlockKind.STOP),
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
    projected = FlowGraph(
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
        post_graph=projected,
        coverage=coverage,
        dispatcher_entry_serial=4,
        authoritative_handler_serials=frozenset({121}),
        dispatcher_region_serials=frozenset({4}),
        producer_safety=_executed_fragment_safety(),
    )
    observed = FlowGraph(
        blocks={
            **projected.blocks,
            34: _block(34, (), (4,), 0xDEADBEEF, kind=BlockKind.STOP),
        },
        entry_serial=0,
        func_ea=0x7FF859C06F60,
    )

    validation = validate_dispatcher_removal_preflight_proof(
        graph,
        post_graph=observed,
        plan_metadata={
            "dispatcher_corridor_coverage": coverage.to_metadata(),
            "dispatcher_removal_preflight_proof": proof.to_metadata(),
        },
    )

    assert not validation.passed
    assert validation.reason == "dispatcher_removal_proof_drift"
    assert validation.proof is not None
    assert validation.proof.reason == "reachable_terminal_identity_drift"


def test_dispatcher_removal_proof_requires_typed_plumbing_for_effectful_feeder() -> None:
    graph = _nested_merge_corridor_graph()
    effectful = InsnSnapshot(
        opcode=4,
        ea=0x7FF859C070C0,
        operands=(),
        kind=InsnKind.MOV,
    )
    graph = FlowGraph(
        blocks={
            **graph.blocks,
            3: _block(
                3,
                (4,),
                (123,),
                0x7FF859C070C0,
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

    unavailable = build_dispatcher_removal_preflight_proof(
        graph,
        post_graph=post_graph,
        coverage=coverage,
        dispatcher_entry_serial=4,
        authoritative_handler_serials=frozenset({34, 121}),
        dispatcher_region_serials=frozenset({4}),
        producer_safety=_executed_fragment_safety(),
    )
    proved = build_dispatcher_removal_preflight_proof(
        graph,
        post_graph=post_graph,
        coverage=coverage,
        dispatcher_entry_serial=4,
        authoritative_handler_serials=frozenset({34, 121}),
        dispatcher_region_serials=frozenset({4}),
        producer_safety=_executed_fragment_safety(),
        state_plumbing_serials=frozenset({3}),
    )

    assert not unavailable.passed
    assert unavailable.reason == "untyped_lost_block"
    assert proved.passed
    assert [anchor.serial for anchor in proved.state_plumbing] == [3]

    # A plan payload can self-label the effectful feeder as plumbing and stamp
    # producer-safety booleans.  The transaction validator has no bound
    # use-def/plumbing authority, so those metadata fields must not unlock the
    # narrow entry-count exception.
    validation = validate_dispatcher_removal_preflight_proof(
        graph,
        post_graph=post_graph,
        plan_metadata={
            "dispatcher_corridor_coverage": coverage.to_metadata(),
            "dispatcher_removal_preflight_proof": proved.to_metadata(),
        },
    )

    assert not validation.passed
    assert validation.reason == "dispatcher_removal_proof_drift"
    assert validation.proof is not None
    assert validation.proof.reason == "untyped_lost_block"
    assert validation.proof.state_plumbing == ()


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


def test_dispatcher_removal_validator_rejects_forged_comparison_role_metadata() -> None:
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
        blocks={**graph.blocks, 0: _block(0, (4,), (), 0x1000)},
        entry_serial=0,
        func_ea=0x1000,
    )
    proof = build_dispatcher_removal_preflight_proof(
        graph,
        post_graph=post_graph,
        coverage=coverage,
        dispatcher_entry_serial=3,
        authoritative_handler_serials=frozenset({4}),
        dispatcher_region_serials=frozenset({3}),
        producer_safety=_executed_fragment_safety(),
    )
    forged = proof.to_metadata()
    forged["proof_status"] = "accepted"
    forged["reason"] = "typed_dispatcher_infrastructure_removed"
    forged["retired_infrastructure"] = [
        {
            "role": "comparison_dispatcher",
            "anchor": {"serial": 1, "ea": 0x1001, "label": "blk1@0x1001"},
        },
        {
            "role": "dispatcher_feeder",
            "anchor": {"serial": 2, "ea": 0x1002, "label": "blk2@0x1002"},
        },
        {
            "role": "comparison_dispatcher",
            "anchor": {"serial": 3, "ea": 0x1003, "label": "blk3@0x1003"},
        },
    ]

    validation = validate_dispatcher_removal_preflight_proof(
        graph,
        post_graph=post_graph,
        plan_metadata={
            "dispatcher_corridor_coverage": coverage.to_metadata(),
            "dispatcher_removal_preflight_proof": forged,
        },
    )

    assert not validation.passed
    assert validation.reason == "dispatcher_removal_proof_drift"
    assert validation.proof is not None
    assert validation.proof.reason == "untyped_lost_block"
