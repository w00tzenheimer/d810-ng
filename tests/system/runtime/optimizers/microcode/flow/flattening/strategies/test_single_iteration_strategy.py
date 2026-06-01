"""Runtime tests for the shared single-iteration engine strategy."""
from __future__ import annotations

from d810.ir.flowgraph import BlockSnapshot, FlowGraph
from d810.transforms.graph_modification import ConvertToGoto, RedirectGoto
from d810.transforms.snapshot import (
    AnalysisSnapshot,
)
from d810.transforms.plan_fragment import (
    FAMILY_CLEANUP,
)
from d810.passes.single_iteration import (
    SINGLE_ITERATION_CONVERTS_METADATA_KEY,
    SINGLE_ITERATION_FIXES_METADATA_KEY,
    SingleIterationConvertFix,
    SingleIterationPredFix,
    SingleIterationStrategy,
    build_single_iteration_modifications,
    extract_single_iteration_converts,
    extract_single_iteration_fixes,
    serialize_single_iteration_converts,
    serialize_single_iteration_fixes,
)


def _block(
    serial: int,
    succs: tuple[int, ...],
    preds: tuple[int, ...],
    *,
    block_type: int = 1,
    start_ea: int | None = None,
) -> BlockSnapshot:
    return BlockSnapshot(
        serial=serial,
        block_type=block_type,
        succs=succs,
        preds=preds,
        flags=0,
        start_ea=serial if start_ea is None else start_ea,
        insn_snapshots=(),
    )


def test_single_iteration_strategy_has_expected_identity() -> None:
    strategy = SingleIterationStrategy()

    assert strategy.name == "single_iteration"
    assert strategy.family == FAMILY_CLEANUP


def test_single_iteration_strategy_is_metadata_driven() -> None:
    strategy = SingleIterationStrategy()

    assert strategy.is_applicable(AnalysisSnapshot(mba=object())) is False

    cfg = FlowGraph(
        blocks={
            0: _block(0, (1,), (), start_ea=0x1000),
            1: _block(1, (2,), (0,), start_ea=0x1001),
            2: _block(2, (3, 4), (1, 3), block_type=4),
            3: _block(3, (2,), (2,), start_ea=0x1003),
            4: _block(4, (), (2,), block_type=2),
        },
        entry_serial=0,
        func_ea=0x1000,
        metadata={SINGLE_ITERATION_FIXES_METADATA_KEY: {2: {1: 3, 3: 4}}},
    )

    assert strategy.is_applicable(
        AnalysisSnapshot(mba=object(), flow_graph=cfg),
    ) is True


def test_extract_single_iteration_fixes_keeps_per_predecessor_decisions() -> None:
    cfg = FlowGraph(
        blocks={
            0: _block(0, (1,), (), start_ea=0x1000),
            1: _block(1, (2,), (0,), start_ea=0x1001),
            2: _block(2, (3, 4), (1, 3), block_type=4),
            3: _block(3, (2,), (2,), start_ea=0x1003),
            4: _block(4, (), (2,), block_type=2),
        },
        entry_serial=0,
        func_ea=0x1000,
        metadata={SINGLE_ITERATION_FIXES_METADATA_KEY: {"2": {"1": "3", "3": "4"}}},
    )

    assert extract_single_iteration_fixes(cfg) == (
        SingleIterationPredFix(loop_header=2, pred_block=1, new_target=3),
        SingleIterationPredFix(loop_header=2, pred_block=3, new_target=4),
    )


def test_single_iteration_strategy_plans_per_predecessor_redirects() -> None:
    cfg = FlowGraph(
        blocks={
            0: _block(0, (1,), (), start_ea=0x1000),
            1: _block(1, (2,), (0,), start_ea=0x1001),
            2: _block(2, (3, 4), (1, 3), block_type=4),
            3: _block(3, (2,), (2,), start_ea=0x1003),
            4: _block(4, (), (2,), block_type=2),
        },
        entry_serial=0,
        func_ea=0x1000,
        metadata={SINGLE_ITERATION_FIXES_METADATA_KEY: {2: {1: 3, 3: 4}}},
    )

    fragment = SingleIterationStrategy().plan(
        AnalysisSnapshot(mba=object(), flow_graph=cfg),
    )

    assert fragment is not None
    assert fragment.metadata[SINGLE_ITERATION_FIXES_METADATA_KEY] == {2: {1: 3, 3: 4}}
    assert fragment.metadata["safeguard_min_required"] == 1
    assert fragment.ownership.blocks == frozenset({1, 3})
    assert fragment.ownership.edges == frozenset({(1, 2), (3, 2)})
    assert fragment.modifications == [
        RedirectGoto(from_serial=1, old_target=2, new_target=3),
        RedirectGoto(from_serial=3, old_target=2, new_target=4),
    ]


def test_single_iteration_strategy_plans_header_conversions() -> None:
    cfg = FlowGraph(
        blocks={
            0: _block(0, (1,), (), start_ea=0x1000),
            1: _block(1, (2,), (0,), start_ea=0x1001),
            2: _block(2, (3, 2), (1, 2), block_type=4),
            3: _block(3, (), (2,), block_type=2),
        },
        entry_serial=0,
        func_ea=0x1000,
        metadata={SINGLE_ITERATION_CONVERTS_METADATA_KEY: {2: 3}},
    )

    fragment = SingleIterationStrategy().plan(
        AnalysisSnapshot(mba=object(), flow_graph=cfg),
    )

    assert fragment is not None
    assert fragment.metadata[SINGLE_ITERATION_CONVERTS_METADATA_KEY] == {2: 3}
    assert fragment.ownership.blocks == frozenset({2})
    assert fragment.ownership.edges == frozenset()
    assert fragment.modifications == [ConvertToGoto(block_serial=2, goto_target=3)]


def test_single_iteration_strategy_drops_invalid_targets_and_shapes() -> None:
    cfg = FlowGraph(
        blocks={
            0: _block(0, (1,), (), start_ea=0x1000),
            1: _block(1, (2,), (0,), start_ea=0x1001),
            2: _block(2, (3, 4), (1, 3, 5), block_type=4),
            3: _block(3, (2,), (2,), start_ea=0x1003),
            4: _block(4, (), (2,), block_type=2),
            5: _block(5, (2, 6), (), block_type=4, start_ea=0x1005),
            6: _block(6, (), (5,), block_type=2),
        },
        entry_serial=0,
        func_ea=0x1000,
        metadata={
            SINGLE_ITERATION_FIXES_METADATA_KEY: {
                2: {
                    1: 999,
                    3: 4,
                    5: 4,
                },
            },
        },
    )

    assert extract_single_iteration_fixes(cfg) == (
        SingleIterationPredFix(loop_header=2, pred_block=3, new_target=4),
    )


def test_single_iteration_strategy_drops_self_loop_redirects() -> None:
    cfg = FlowGraph(
        blocks={
            0: _block(0, (1,), (), start_ea=0x1000),
            1: _block(1, (2,), (0,), start_ea=0x1001),
            2: _block(2, (1, 4), (1,), block_type=4),
            4: _block(4, (), (2,), block_type=2),
        },
        entry_serial=0,
        func_ea=0x1000,
        metadata={SINGLE_ITERATION_FIXES_METADATA_KEY: {2: {1: 1}}},
    )

    assert extract_single_iteration_fixes(cfg) == ()
    assert SingleIterationStrategy().plan(
        AnalysisSnapshot(mba=object(), flow_graph=cfg),
    ) is None


def test_build_single_iteration_modifications_emits_legacy_redirect_shape() -> None:
    modifications = build_single_iteration_modifications(
        (
            SingleIterationPredFix(loop_header=2, pred_block=1, new_target=3),
            SingleIterationPredFix(loop_header=2, pred_block=3, new_target=4),
        )
    )

    assert modifications == [
        RedirectGoto(from_serial=1, old_target=2, new_target=3),
        RedirectGoto(from_serial=3, old_target=2, new_target=4),
    ]


def test_build_single_iteration_modifications_emits_header_conversions() -> None:
    modifications = build_single_iteration_modifications(
        (),
        (
            SingleIterationConvertFix(loop_header=2, new_target=3),
            SingleIterationConvertFix(loop_header=5, new_target=6),
        ),
    )

    assert modifications == [
        ConvertToGoto(block_serial=2, goto_target=3),
        ConvertToGoto(block_serial=5, goto_target=6),
    ]


def test_serialize_single_iteration_fixes_round_trips() -> None:
    fixes = (
        SingleIterationPredFix(loop_header=2, pred_block=1, new_target=3),
        SingleIterationPredFix(loop_header=2, pred_block=3, new_target=4),
    )

    cfg = FlowGraph(
        blocks={
            0: _block(0, (1,), (), start_ea=0x1000),
            1: _block(1, (2,), (0,), start_ea=0x1001),
            2: _block(2, (3, 4), (1, 3), block_type=4),
            3: _block(3, (2,), (2,), start_ea=0x1003),
            4: _block(4, (), (2,), block_type=2),
        },
        entry_serial=0,
        func_ea=0x1000,
        metadata={
            SINGLE_ITERATION_FIXES_METADATA_KEY: serialize_single_iteration_fixes(
                fixes
            )
        },
    )

    assert extract_single_iteration_fixes(cfg) == fixes


def test_serialize_single_iteration_converts_round_trips() -> None:
    fixes = (
        SingleIterationConvertFix(loop_header=2, new_target=3),
        SingleIterationConvertFix(loop_header=5, new_target=6),
    )

    cfg = FlowGraph(
        blocks={
            0: _block(0, (1,), (), start_ea=0x1000),
            1: _block(1, (2,), (0,), start_ea=0x1001),
            2: _block(2, (3, 2), (1, 2), block_type=4),
            3: _block(3, (), (2,), block_type=2),
            5: _block(5, (6, 5), (4, 5), block_type=4),
            6: _block(6, (), (5,), block_type=2),
        },
        entry_serial=0,
        func_ea=0x1000,
        metadata={
            SINGLE_ITERATION_CONVERTS_METADATA_KEY: (
                serialize_single_iteration_converts(fixes)
            )
        },
    )

    assert extract_single_iteration_converts(cfg) == fixes
