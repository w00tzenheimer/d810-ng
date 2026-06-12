"""Runtime tests for the first engine-native FakeJump wrapper."""
from __future__ import annotations

from types import SimpleNamespace

from d810.ir.flowgraph import (
    BlockSnapshot,
    FlowGraph,
    InsnKind,
    InsnSnapshot,
    MopSnapshot,
    OperandKind,
)
from d810.transforms.graph_modification import (
    CloneConditionalAsGoto,
    ConvertToGoto,
    RedirectBranch,
    RedirectGoto,
)
from d810.transforms.snapshot import (
    AnalysisSnapshot,
)
from d810.transforms.plan_fragment import (
    FAMILY_CLEANUP,
)
from d810.passes.fake_jump import (
    FAKE_JUMP_FIXES_METADATA_KEY,
    PAYLOAD_FAKE_JUMP_FIXES_METADATA_KEY,
    FakeJumpPredFix,
    FakeJumpStrategy,
    PayloadFakeJumpFix,
    build_fake_jump_modifications,
    build_payload_fake_jump_modifications,
    collect_payload_fake_jump_fixes,
    extract_fake_jump_fixes,
    extract_payload_fake_jump_fixes,
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


def _rich_block(
    serial: int,
    succs: tuple[int, ...],
    preds: tuple[int, ...],
    *insns: InsnSnapshot,
    block_type: int | None = None,
) -> BlockSnapshot:
    return BlockSnapshot(
        serial=serial,
        block_type=(
            block_type
            if block_type is not None
            else 4 if len(succs) == 2 else 1 if len(succs) == 1 else 2
        ),
        succs=succs,
        preds=preds,
        flags=0,
        start_ea=0x1000 + serial,
        insn_snapshots=tuple(insns),
    )


def _reg(reg: int, size: int = 4) -> MopSnapshot:
    return MopSnapshot(t=1, size=size, reg=reg, kind=OperandKind.REGISTER)


def _num(value: int) -> MopSnapshot:
    return MopSnapshot(t=2, size=4, value=value, kind=OperandKind.NUMBER)


def _blk(serial: int) -> MopSnapshot:
    return MopSnapshot(t=7, size=-1, block_ref=serial, kind=OperandKind.BLOCK)


def _rich_blk(serial: int) -> SimpleNamespace:
    return SimpleNamespace(block_num=serial)


def _mov(src: MopSnapshot, dst: MopSnapshot) -> InsnSnapshot:
    return InsnSnapshot(
        opcode=4,
        ea=0x1000,
        operands=(),
        operand_slots=(("l", src), ("d", dst)),
        l=src,
        d=dst,
        kind=InsnKind.MOV,
    )


def _jnz(left: MopSnapshot, right: MopSnapshot, target: int) -> InsnSnapshot:
    target_operand = _rich_blk(target)
    return InsnSnapshot(
        opcode=43,
        ea=0x1000,
        operands=(),
        operand_slots=(("l", left), ("r", right), ("d", target_operand)),
        l=left,
        r=right,
        d=_blk(target),
        kind=InsnKind.COND_JUMP,
    )


def _jcnd(selector: MopSnapshot, target: int) -> InsnSnapshot:
    target_operand = _rich_blk(target)
    return InsnSnapshot(
        opcode=42,
        ea=0x1000,
        operands=(),
        operand_slots=(("l", selector), ("d", target_operand)),
        l=selector,
        d=_blk(target),
        kind=InsnKind.COND_JUMP,
    )


def _payload_fake_jump_cfg() -> FlowGraph:
    flag = _reg(20, 1)
    selector = _reg(21)
    default_value = _reg(22, 8)
    selected_value = _reg(23, 8)
    output = _reg(24, 8)
    blocks = {
        12: _rich_block(
            12,
            (13, 14),
            (),
            _mov(_num(0xBCF37D88), selector),
            _jcnd(flag, 14),
        ),
        13: _rich_block(
            13,
            (14,),
            (12,),
            _mov(_num(0xCF87A00D), selector),
        ),
        14: _rich_block(
            14,
            (15, 16),
            (12, 13),
            _mov(default_value, output),
            _jnz(selector, _num(0xCF87A00D), 16),
        ),
        15: _rich_block(15, (16,), (14,), _mov(selected_value, output)),
        16: _rich_block(16, (17,), (14, 15)),
        17: _rich_block(17, (), (16,), block_type=2),
    }
    return FlowGraph(blocks=blocks, entry_serial=12, func_ea=0x1000)


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
            10: _block(10, (11,), (2,)),
            11: _block(11, (), (10,), block_type=2),
            20: _block(20, (21,), (2,)),
            21: _block(21, (), (20,), block_type=2),
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
            10: _block(10, (11,), (2,)),
            11: _block(11, (), (10,), block_type=2),
            20: _block(20, (21,), (2,)),
            21: _block(21, (), (20,), block_type=2),
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
            10: _block(10, (11,), (2,)),
            11: _block(11, (), (10,), block_type=2),
            20: _block(20, (21,), (2,)),
            21: _block(21, (), (20,), block_type=2),
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


def test_payload_fake_jump_preserves_branch_body_with_clone_and_convert() -> None:
    cfg = _payload_fake_jump_cfg()

    assert collect_payload_fake_jump_fixes(cfg) == (
        PayloadFakeJumpFix(
            fake_block=14,
            original_target=16,
            clone_redirects=((13, 15),),
        ),
    )

    assert extract_payload_fake_jump_fixes(cfg) == (
        PayloadFakeJumpFix(
            fake_block=14,
            original_target=16,
            clone_redirects=((13, 15),),
        ),
    )

    assert build_payload_fake_jump_modifications(
        extract_payload_fake_jump_fixes(cfg),
        cfg,
    ) == [
        CloneConditionalAsGoto(
            source_block=14,
            pred_serial=13,
            goto_target=15,
            reason="payload_fake_jump_clone_as_goto",
        ),
        ConvertToGoto(block_serial=14, goto_target=16),
    ]


def test_fake_jump_strategy_plans_payload_preserving_fake_jump() -> None:
    cfg = _payload_fake_jump_cfg()

    fragment = FakeJumpStrategy().plan(
        AnalysisSnapshot(mba=object(), flow_graph=cfg),
    )

    assert fragment is not None
    assert fragment.metadata[PAYLOAD_FAKE_JUMP_FIXES_METADATA_KEY] == (
        {
            "fake_block": 14,
            "original_target": 16,
            "clone_redirects": ((13, 15),),
        },
    )
    assert fragment.ownership.blocks == frozenset({14})
    assert fragment.ownership.edges == frozenset({(13, 14)})
    assert fragment.modifications == [
        CloneConditionalAsGoto(
            source_block=14,
            pred_serial=13,
            goto_target=15,
            reason="payload_fake_jump_clone_as_goto",
        ),
        ConvertToGoto(block_serial=14, goto_target=16),
    ]


def test_fake_jump_strategy_prefers_plain_fixes_over_payload_derivation() -> None:
    cfg = _payload_fake_jump_cfg()
    cfg = FlowGraph(
        blocks=cfg.blocks,
        entry_serial=cfg.entry_serial,
        func_ea=cfg.func_ea,
        metadata={FAKE_JUMP_FIXES_METADATA_KEY: {14: {12: 16, 13: 15}}},
    )

    fragment = FakeJumpStrategy().plan(
        AnalysisSnapshot(mba=object(), flow_graph=cfg),
    )

    assert fragment is not None
    assert fragment.metadata[FAKE_JUMP_FIXES_METADATA_KEY] == {14: {13: 15}}
    assert fragment.metadata[PAYLOAD_FAKE_JUMP_FIXES_METADATA_KEY] == ()
    assert fragment.modifications == [
        RedirectGoto(from_serial=13, old_target=14, new_target=15),
    ]


def test_fake_jump_strategy_redirects_branch_arm_predecessors() -> None:
    cfg = FlowGraph(
        blocks={
            0: _block(0, (17,), (), start_ea=0x1000),
            17: _block(17, (18, 19), (0,), block_type=4, start_ea=0x1017),
            18: _block(18, (19,), (17,), start_ea=0x1018),
            19: _block(19, (20, 21), (17, 18), block_type=4, start_ea=0x1019),
            20: _block(20, (22,), (19,), start_ea=0x1020),
            21: _block(21, (23,), (19,), start_ea=0x1021),
            22: _block(22, (), (20,), block_type=2, start_ea=0x1022),
            23: _block(23, (), (21,), block_type=2, start_ea=0x1023),
        },
        entry_serial=0,
        func_ea=0x1000,
        metadata={FAKE_JUMP_FIXES_METADATA_KEY: {19: {17: 20, 18: 21}}},
    )

    fragment = FakeJumpStrategy().plan(
        AnalysisSnapshot(mba=object(), flow_graph=cfg),
    )

    assert fragment is not None
    assert fragment.ownership.blocks == frozenset({17, 18})
    assert fragment.ownership.edges == frozenset({(17, 19), (18, 19)})
    assert fragment.modifications == [
        RedirectBranch(from_serial=17, old_target=19, new_target=20),
        RedirectGoto(from_serial=18, old_target=19, new_target=21),
    ]


def test_fake_jump_strategy_drops_invalid_targets_and_non_legacy_shapes() -> None:
    cfg = FlowGraph(
        blocks={
            2: _block(2, (10, 20), (5, 6, 7), block_type=4),
            5: _block(5, (2,), (), start_ea=0x1005),
            6: _block(6, (30, 40), (), block_type=4, start_ea=0x1006),
            7: _block(7, (20,), (), start_ea=0x1007),
            10: _block(10, (), (2,), block_type=2),
            20: _block(20, (), (2, 7), block_type=2),
            30: _block(30, (), (6,), block_type=2),
            40: _block(40, (), (6,), block_type=2),
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


def test_build_fake_jump_modifications_can_emit_branch_redirects() -> None:
    cfg = FlowGraph(
        blocks={
            0: _block(0, (17,), (), start_ea=0x1000),
            17: _block(17, (18, 19), (0,), block_type=4, start_ea=0x1017),
            18: _block(18, (19,), (17,), start_ea=0x1018),
            19: _block(19, (20, 21), (17, 18), block_type=4, start_ea=0x1019),
            20: _block(20, (), (19,), block_type=2, start_ea=0x1020),
            21: _block(21, (), (19,), block_type=2, start_ea=0x1021),
        },
        entry_serial=0,
        func_ea=0x1000,
    )

    modifications = build_fake_jump_modifications(
        (
            FakeJumpPredFix(fake_block=19, pred_block=17, new_target=20),
            FakeJumpPredFix(fake_block=19, pred_block=18, new_target=21),
        ),
        cfg,
    )

    assert modifications == [
        RedirectBranch(from_serial=17, old_target=19, new_target=20),
        RedirectGoto(from_serial=18, old_target=19, new_target=21),
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
