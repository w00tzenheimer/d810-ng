"""Runtime tests for the first engine-native FakeJump wrapper."""
from __future__ import annotations

from d810.cfg.flowgraph import BlockSnapshot, FlowGraph
from d810.cfg.graph_modification import RedirectGoto
from d810.optimizers.microcode.flow.flattening.engine.snapshot import (
    AnalysisSnapshot,
)
from d810.optimizers.microcode.flow.flattening.engine.strategy import (
    FAMILY_CLEANUP,
)
from d810.optimizers.microcode.flow.flattening.strategies.fake_jump import (
    FAKE_JUMP_FIXES_METADATA_KEY,
    FakeJumpPredFix,
    FakeJumpStrategy,
    build_fake_jump_modifications,
    extract_fake_jump_fixes,
    resolve_fake_jump_target,
    should_skip_fake_jump_predecessor,
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


def test_fake_jump_strategy_has_expected_identity() -> None:
    strategy = FakeJumpStrategy()

    assert strategy.name == "fake_jump"
    assert strategy.family == FAMILY_CLEANUP


def test_fake_jump_strategy_is_metadata_driven() -> None:
    strategy = FakeJumpStrategy()

    assert strategy.is_applicable(AnalysisSnapshot(mba=object())) is False

    cfg = FlowGraph(
        blocks={
            0: _block(0, (5,), (), start_ea=0x1000),
            2: _block(2, (10, 20), (5, 6), block_type=4),
            5: _block(5, (2,), (0,), start_ea=0x1005),
            6: _block(6, (2,), (), start_ea=0x1006),
            10: _block(10, (), (2,), block_type=2),
            20: _block(20, (), (2,), block_type=2),
        },
        entry_serial=0,
        func_ea=0x1000,
        metadata={FAKE_JUMP_FIXES_METADATA_KEY: {2: {5: 10, 6: 20}}},
    )
    assert strategy.is_applicable(
        AnalysisSnapshot(mba=object(), flow_graph=cfg),
    ) is True


def test_extract_fake_jump_fixes_keeps_per_predecessor_decisions() -> None:
    cfg = FlowGraph(
        blocks={
            0: _block(0, (5,), (), start_ea=0x1000),
            2: _block(2, (10, 20), (5, 6), block_type=4),
            5: _block(5, (2,), (0,), start_ea=0x1005),
            6: _block(6, (2,), (), start_ea=0x1006),
            10: _block(10, (), (2,), block_type=2),
            20: _block(20, (), (2,), block_type=2),
        },
        entry_serial=0,
        func_ea=0x1000,
        metadata={FAKE_JUMP_FIXES_METADATA_KEY: {"2": {"5": "10", "6": "20"}}},
    )

    assert extract_fake_jump_fixes(cfg) == (
        FakeJumpPredFix(fake_block=2, pred_block=5, new_target=10),
        FakeJumpPredFix(fake_block=2, pred_block=6, new_target=20),
    )


def test_fake_jump_strategy_plans_per_predecessor_redirects() -> None:
    cfg = FlowGraph(
        blocks={
            0: _block(0, (5,), (), start_ea=0x1000),
            2: _block(2, (10, 20), (5, 6), block_type=4),
            5: _block(5, (2,), (0,), start_ea=0x1005),
            6: _block(6, (2,), (), start_ea=0x1006),
            10: _block(10, (), (2,), block_type=2),
            20: _block(20, (), (2,), block_type=2),
        },
        entry_serial=0,
        func_ea=0x1000,
        metadata={FAKE_JUMP_FIXES_METADATA_KEY: {2: {5: 10, 6: 20}}},
    )

    fragment = FakeJumpStrategy().plan(
        AnalysisSnapshot(mba=object(), flow_graph=cfg),
    )

    assert fragment is not None
    assert fragment.metadata[FAKE_JUMP_FIXES_METADATA_KEY] == {2: {5: 10, 6: 20}}
    assert fragment.metadata["safeguard_min_required"] == 1
    assert fragment.ownership.blocks == frozenset({5, 6})
    assert fragment.ownership.edges == frozenset({(5, 2), (6, 2)})
    assert fragment.modifications == [
        RedirectGoto(from_serial=5, old_target=2, new_target=10),
        RedirectGoto(from_serial=6, old_target=2, new_target=20),
    ]


def test_fake_jump_strategy_drops_invalid_targets_and_non_legacy_shapes() -> None:
    cfg = FlowGraph(
        blocks={
            2: _block(2, (10, 20), (5, 6, 7), block_type=4),
            5: _block(5, (2,), (), start_ea=0x1005),
            6: _block(6, (2, 30), (), block_type=4, start_ea=0x1006),
            7: _block(7, (20,), (), start_ea=0x1007),
            10: _block(10, (), (2,), block_type=2),
            20: _block(20, (), (2, 7), block_type=2),
            30: _block(30, (), (6,), block_type=2),
        },
        entry_serial=5,
        func_ea=0x1000,
        metadata={
            FAKE_JUMP_FIXES_METADATA_KEY: {
                2: {
                    5: 999,
                    6: 10,
                    7: 10,
                    5_000: 10,
                },
            },
        },
    )

    fixes = extract_fake_jump_fixes(cfg)
    assert fixes == ()
    assert FakeJumpStrategy().plan(
        AnalysisSnapshot(mba=object(), flow_graph=cfg),
    ) is None


def test_fake_jump_strategy_drops_self_loop_redirects() -> None:
    cfg = FlowGraph(
        blocks={
            0: _block(0, (5,), (), start_ea=0x1000),
            2: _block(2, (5, 20), (5,), block_type=4),
            5: _block(5, (2,), (0,), start_ea=0x1005),
            20: _block(20, (), (2,), block_type=2),
        },
        entry_serial=0,
        func_ea=0x1000,
        metadata={FAKE_JUMP_FIXES_METADATA_KEY: {2: {5: 5}}},
    )

    assert extract_fake_jump_fixes(cfg) == ()
    assert FakeJumpStrategy().plan(
        AnalysisSnapshot(mba=object(), flow_graph=cfg),
    ) is None


def test_build_fake_jump_modifications_emits_legacy_redirect_shape() -> None:
    modifications = build_fake_jump_modifications(
        (
            FakeJumpPredFix(fake_block=2, pred_block=5, new_target=10),
            FakeJumpPredFix(fake_block=2, pred_block=6, new_target=20),
        )
    )

    assert modifications == [
        RedirectGoto(from_serial=5, old_target=2, new_target=10),
        RedirectGoto(from_serial=6, old_target=2, new_target=20),
    ]


def test_fake_jump_resolution_helpers_match_legacy_jz_jnz_rules() -> None:
    jz = 1
    jnz = 2

    jz_taken = resolve_fake_jump_target(
        opcode=jz,
        compared_value=7,
        pred_comparison_values=[7, 7],
        taken_target=10,
        fallthrough_target=11,
        jz_opcode=jz,
        jnz_opcode=jnz,
    )
    assert jz_taken.new_target == 10
    assert jz_taken.always_taken is True
    assert jz_taken.always_not_taken is False

    jnz_not_taken = resolve_fake_jump_target(
        opcode=jnz,
        compared_value=7,
        pred_comparison_values=[7, 7],
        taken_target=10,
        fallthrough_target=11,
        jz_opcode=jz,
        jnz_opcode=jnz,
    )
    assert jnz_not_taken.new_target == 11
    assert jnz_not_taken.always_taken is False
    assert jnz_not_taken.always_not_taken is True

    mixed = resolve_fake_jump_target(
        opcode=jz,
        compared_value=7,
        pred_comparison_values=[7, 8],
        taken_target=10,
        fallthrough_target=11,
        jz_opcode=jz,
        jnz_opcode=jnz,
    )
    assert mixed.new_target is None


def test_fake_jump_resolution_supports_unsigned_jump_conditions() -> None:
    jae = 3
    jb = 4

    jae_taken = resolve_fake_jump_target(
        opcode=jae,
        compared_value=10,
        pred_comparison_values=[10, 11, 12],
        taken_target=20,
        fallthrough_target=21,
        jz_opcode=1,
        jnz_opcode=2,
        jae_opcode=jae,
        jb_opcode=jb,
    )
    assert jae_taken.new_target == 20
    assert jae_taken.always_taken is True

    jb_not_taken = resolve_fake_jump_target(
        opcode=jb,
        compared_value=10,
        pred_comparison_values=[10, 11, 12],
        taken_target=20,
        fallthrough_target=21,
        jz_opcode=1,
        jnz_opcode=2,
        jae_opcode=jae,
        jb_opcode=jb,
    )
    assert jb_not_taken.new_target == 21
    assert jb_not_taken.always_not_taken is True


def test_fake_jump_resolution_supports_signed_jump_conditions() -> None:
    jg = 5
    jl = 6

    signed_less_taken = resolve_fake_jump_target(
        opcode=jl,
        compared_value=0,
        pred_comparison_values=[0xFFFFFFFF, 0xFFFFFFFE],
        taken_target=30,
        fallthrough_target=31,
        jz_opcode=1,
        jnz_opcode=2,
        jg_opcode=jg,
        jl_opcode=jl,
        operand_size=4,
    )
    assert signed_less_taken.new_target == 30
    assert signed_less_taken.always_taken is True

    signed_greater_not_taken = resolve_fake_jump_target(
        opcode=jg,
        compared_value=0,
        pred_comparison_values=[0xFFFFFFFF, 0xFFFFFFFE],
        taken_target=30,
        fallthrough_target=31,
        jz_opcode=1,
        jnz_opcode=2,
        jg_opcode=jg,
        jl_opcode=jl,
        operand_size=4,
    )
    assert signed_greater_not_taken.new_target == 31
    assert signed_greater_not_taken.always_not_taken is True


def test_fake_jump_unresolved_ratio_helper_matches_runtime_guard() -> None:
    assert should_skip_fake_jump_predecessor(0, 0) is True
    assert should_skip_fake_jump_predecessor(2, 21) is True
    assert should_skip_fake_jump_predecessor(3, 31) is False
    assert should_skip_fake_jump_predecessor(4, 0) is False
