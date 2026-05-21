"""Tests for the generic non-Hodur cleanup family pilot."""
from __future__ import annotations

from types import SimpleNamespace

import ida_hexrays

from d810.cfg.flowgraph import (
    BlockSnapshot,
    FlowGraph,
    InsnKind,
    InsnSnapshot,
    MopSnapshot,
    OperandKind,
)
from d810.cfg.graph_modification import (
    ConvertToGoto,
    CreateConditionalRedirect,
    DuplicateBlock,
    DuplicateReplayAndRedirect,
    InsertBlock,
    NopInstructions,
    RedirectGoto,
)
from d810.cfg.materialization_payload import (
    CapturedBlockBody,
    CapturedBlockBodySummary,
)
from d810.cfg.plan import (
    ExecutionPolicy,
    LegacyBlockOperation,
    PatchConditionalRedirect,
    PatchDuplicateBlock,
    PatchDuplicateReplayAndRedirect,
    PatchInsertBlock,
    PatchNopInstructions,
    compile_patch_plan,
)
from d810.optimizers.microcode.flow.flattening import (
    cleanup_backend as backend_module,
    unflattener_cleanup_family as shell_module,
)
from d810.optimizers.microcode.flow.flattening.cleanup_backend import (
    LiveSimpleFlatteningCleanupBackend,
)
from d810.optimizers.microcode.flow.flattening.cleanup_evidence import (
    CLEANUP_CONDITIONAL_REDIRECT_PROOF_METADATA_KEY,
    CLEANUP_DUPLICATE_REPLAY_METADATA_KEY,
    CLEANUP_FOLLOW_UP_RECLASSIFICATION_METADATA_KEY,
    CLEANUP_SIDE_EFFECT_REPLAY_METADATA_KEY,
    CLEANUP_TRAMPOLINE_ISOLATION_METADATA_KEY,
    CleanupFollowUpResolutionBucket,
    CleanupProofVerdict,
    CleanupProofState,
    CleanupPerPredReplay,
    bad_while_loop_conditional_redirect_proof,
    bad_while_loop_duplicate_group_replay_candidate,
    bad_while_loop_side_effect_replay_candidate,
    bad_while_loop_trampoline_isolation_candidate,
    explain_bad_while_loop_conditional_redirect,
    extract_conditional_redirect_proofs,
    extract_duplicate_group_replay_candidates,
    extract_follow_up_reclassifications,
    extract_side_effect_replay_candidates,
    extract_trampoline_isolation_candidates,
)
from d810.optimizers.microcode.flow.flattening.cleanup_family import (
    CLEANUP_FAMILY_METADATA_KEY,
    SimpleFlatteningCleanupDetection,
    SimpleFlatteningCleanupFamily,
    SimpleFlatteningCleanupMetadata,
)
from d810.optimizers.microcode.flow.flattening.engine.provenance import (
    PipelineProvenance,
)
from d810.optimizers.microcode.flow.flattening.engine.runtime import (
    ExecutedPipeline,
    PlannedPipeline,
)
from d810.optimizers.microcode.flow.flattening.engine.snapshot import (
    AnalysisSnapshot,
    StateModelSummary,
)
from d810.optimizers.microcode.flow.flattening.engine.strategy import (
    FAMILY_CLEANUP,
    BenefitMetrics,
    OwnershipScope,
    PlanFragment,
)
from d810.optimizers.microcode.flow.flattening.strategies.bad_while_loop import (
    BAD_WHILE_LOOP_DEPENDENCY_DIAGNOSTICS_METADATA_KEY,
    BAD_WHILE_LOOP_EDITS_METADATA_KEY,
    BAD_WHILE_LOOP_FOLLOW_UP_METADATA_KEY,
    BAD_WHILE_LOOP_DUPLICATE_AND_REDIRECT,
    BAD_WHILE_LOOP_INSERT_BLOCK,
    BadWhileLoopAnalysis,
    BadWhileLoopConditionalDuplicate,
    BadWhileLoopConditionalRedirect,
    BadWhileLoopDuplicateRedirect,
    BadWhileLoopFollowUp,
    BadWhileLoopGotoConversion,
    BadWhileLoopGotoRedirect,
    BadWhileLoopStrategy,
    extract_bad_while_loop_dependency_diagnostics,
    extract_bad_while_loop_edits,
    extract_bad_while_loop_follow_up,
)
from d810.optimizers.microcode.flow.flattening.strategies.fake_jump import (
    FAKE_JUMP_FIXES_METADATA_KEY,
    FakeJumpPredFix,
    extract_fake_jump_fixes,
)
from d810.optimizers.microcode.flow.flattening.strategies.single_iteration import (
    SINGLE_ITERATION_FIXES_METADATA_KEY,
    SingleIterationPredFix,
    extract_single_iteration_fixes,
)
from d810.optimizers.microcode.flow.flattening.strategies.tail_goto_merge import (
    TAIL_GOTO_MERGE_METADATA_KEY,
    TailGotoMergeCandidate,
    TailGotoMergeStrategy,
    collect_tail_goto_merge_candidates,
    extract_tail_goto_merge_candidates,
)
from d810.optimizers.microcode.flow.flattening.unflattener_cleanup_family import (
    SimpleFlatteningCleanupUnflattener,
)


def _block(
    serial: int,
    succs: tuple[int, ...],
    preds: tuple[int, ...],
    *,
    block_type: int = 1,
    start_ea: int | None = None,
    tail_target: int | None = None,
) -> BlockSnapshot:
    insn_snapshots = ()
    if tail_target is not None:
        target_mop = MopSnapshot(
            t=7,
            size=4,
            block_ref=tail_target,
            kind=OperandKind.BLOCK,
        )
        insn_snapshots = (
            InsnSnapshot(
                opcode=0x200,
                ea=0x5000 + serial,
                operands=(target_mop,),
                operand_slots=(("d", target_mop),),
                d=target_mop,
                kind=InsnKind.GOTO,
            ),
        )
    return BlockSnapshot(
        serial=serial,
        block_type=block_type,
        succs=succs,
        preds=preds,
        flags=0,
        start_ea=serial if start_ea is None else start_ea,
        insn_snapshots=insn_snapshots,
    )


def _cleanup_flow_graph() -> FlowGraph:
    return FlowGraph(
        blocks={
            0: _block(0, (5,), (), start_ea=0x401000),
            2: _block(2, (10, 20), (5,), block_type=4),
            5: _block(5, (2,), (0,), start_ea=0x401005),
            10: _block(10, (), (2,), block_type=2),
            20: _block(20, (), (2,), block_type=2),
            29: _block(29, (30,), (), start_ea=0x401029),
            30: _block(30, (31, 32), (29, 31), block_type=4),
            31: _block(31, (30,), (30,), start_ea=0x401031),
            32: _block(32, (), (30,), block_type=2),
            40: _block(40, (41,), (), start_ea=0x401040),
            41: _block(41, (42, 43), (40, 44), block_type=4),
            42: _block(42, (), (41,), block_type=2),
            43: _block(43, (), (41,), block_type=2),
            44: _block(44, (41, 45), (), block_type=4, start_ea=0x401044),
            45: _block(45, (), (44,), block_type=2),
            50: _block(50, (41,), (51, 52), start_ea=0x401050),
            51: _block(51, (50,), (), start_ea=0x401051),
            52: _block(52, (50,), (), start_ea=0x401052),
            60: _block(60, (41,), (61, 62, 63), start_ea=0x401060),
            61: _block(61, (60,), (), start_ea=0x401061),
            62: _block(62, (60,), (), start_ea=0x401062),
            63: _block(63, (60,), (), start_ea=0x401063),
            70: _block(70, (71,), (), start_ea=0x401070, tail_target=71),
            71: _block(71, (72,), (70,), start_ea=0x401071),
            72: _block(72, (), (71,), block_type=2, start_ea=0x401072),
        },
        entry_serial=0,
        func_ea=0x401000,
    )


def _conditional_redirect_flow_graph() -> FlowGraph:
    return FlowGraph(
        blocks={
            0: _block(0, (1,), (), start_ea=0x401000),
            1: _block(1, (2,), (0,), start_ea=0x401001),
            2: _block(2, (12, 99), (1,), block_type=4, start_ea=0x401002),
            3: _block(3, (), (12,), block_type=2, start_ea=0x401003),
            4: _block(4, (), (12,), block_type=2, start_ea=0x401004),
            12: _block(
                12,
                (4, 3),
                (2,),
                block_type=4,
                start_ea=0x40100C,
                tail_target=3,
            ),
            99: _block(99, (), (2,), block_type=2, start_ea=0x401099),
        },
        entry_serial=0,
        func_ea=0x401000,
    )


def _conditional_promotion_flow_graph() -> FlowGraph:
    return FlowGraph(
        blocks={
            0: _block(0, (1, 8), (), block_type=4, start_ea=0x401000),
            1: _block(1, (2,), (0,), start_ea=0x401001),
            2: _block(2, (12, 99), (1, 6), block_type=4, start_ea=0x401002),
            3: _block(3, (), (12,), block_type=2, start_ea=0x401003),
            4: _block(4, (), (12, 6), block_type=2, start_ea=0x401004),
            6: _block(
                6,
                (2, 4),
                (8,),
                block_type=4,
                start_ea=0x401006,
                tail_target=2,
            ),
            8: _block(8, (6,), (0,), start_ea=0x401008),
            12: _block(
                12,
                (4, 3),
                (2,),
                block_type=4,
                start_ea=0x40100C,
                tail_target=3,
            ),
            99: _block(99, (), (2,), block_type=2, start_ea=0x401099),
        },
        entry_serial=0,
        func_ea=0x401000,
    )


def _side_effect_body(source_serial: int = 40) -> CapturedBlockBody:
    instructions = (InsnSnapshot(opcode=0x77, ea=0x401077, operands=()),)
    return CapturedBlockBody(
        backend_id="hexrays.insn_snapshot",
        capture_id=f"cleanup-family-test:{source_serial}",
        summary=CapturedBlockBodySummary(
            source_blocks=(source_serial,),
            instruction_count=len(instructions),
            source_eas=frozenset({0x401077}),
            contains_call=False,
        ),
        payload=instructions,
    )


class _FakeTranslator:
    def __init__(self, flow_graph: FlowGraph) -> None:
        self.flow_graph = flow_graph

    def lift(self, _mba: object) -> FlowGraph:
        return self.flow_graph


class _FakeBackend:
    def __init__(self, detection: SimpleFlatteningCleanupDetection) -> None:
        self.detection = detection
        self.calls: list[tuple[object, object | None]] = []

    def collect(
        self,
        mba: object,
        *,
        logger: object | None = None,
    ) -> SimpleFlatteningCleanupDetection:
        self.calls.append((mba, logger))
        return self.detection


def _fake_mba() -> SimpleNamespace:
    return SimpleNamespace(
        maturity=ida_hexrays.MMAT_GLBOPT1,
        entry_ea=0x401000,
        qty=0,
        get_mblock=lambda _serial: None,
    )


def test_simple_cleanup_family_registers_cleanup_strategies() -> None:
    empty_graph = FlowGraph(blocks={}, entry_serial=0, func_ea=0)
    family = SimpleFlatteningCleanupFamily(
        cfg_translator=_FakeTranslator(empty_graph)
    )

    assert family.name == "simple_flattening_cleanup"
    assert [strategy.name for strategy in family.strategies] == [
        "fake_jump",
        "single_iteration",
        "guarded_state_machine",
        "local_select_loop",
        "side_effect_select_loop",
        "bad_while_loop",
        "fix_predecessor_branch_arm",
        "tail_goto_merge",
    ]


def test_live_cleanup_backend_wraps_existing_collectors(monkeypatch) -> None:
    fake_jump_fix = FakeJumpPredFix(fake_block=2, pred_block=5, new_target=10)
    single_iteration_fix = SingleIterationPredFix(
        loop_header=30,
        pred_block=29,
        new_target=31,
    )
    bad_while_loop_edit = BadWhileLoopGotoRedirect(
        dispatcher_entry=41,
        from_serial=40,
        new_target=42,
    )
    safe_bad_while_loop_duplicate = BadWhileLoopDuplicateRedirect(
        dispatcher_entry=41,
        source_serial=50,
        per_pred_targets=((51, 42), (52, 43)),
    )
    unsafe_bad_while_loop_duplicate = BadWhileLoopDuplicateRedirect(
        dispatcher_entry=41,
        source_serial=60,
        per_pred_targets=((61, 42), (62, 43)),
    )
    unsafe_bad_while_loop_conditional_duplicate = BadWhileLoopConditionalDuplicate(
        dispatcher_entry=41,
        source_serial=44,
        pred_serial=40,
        conditional_target=42,
        fallthrough_target=43,
    )
    unsafe_bad_while_loop_conditional_redirect = BadWhileLoopConditionalRedirect(
        dispatcher_entry=41,
        source_serial=40,
        ref_block=44,
        conditional_target=42,
        fallthrough_target=43,
    )
    bad_while_loop_follow_up = BadWhileLoopFollowUp(
        dispatcher_entry=41,
        from_serial=44,
        category="create_conditional_redirect",
        reason="conditional_exit_with_loopback",
        target_serial=42,
        fallthrough_target=45,
    )
    calls: dict[str, object] = {}

    def _collect_fake_jump(mba, **kwargs):
        calls["fake_jump"] = (mba, kwargs)
        return (fake_jump_fix,)

    def _collect_single_iteration(mba, **kwargs):
        calls["single_iteration"] = (mba, kwargs)
        return (single_iteration_fix,)

    def _collect_bad_while_loop(mba, **kwargs):
        calls["bad_while_loop"] = (mba, kwargs)
        return BadWhileLoopAnalysis(
            edits=(
                bad_while_loop_edit,
                safe_bad_while_loop_duplicate,
                unsafe_bad_while_loop_duplicate,
                unsafe_bad_while_loop_conditional_duplicate,
                unsafe_bad_while_loop_conditional_redirect,
            ),
            follow_up=(bad_while_loop_follow_up,),
        )

    monkeypatch.setattr(
        backend_module,
        "collect_live_fake_jump_fixes",
        _collect_fake_jump,
    )
    monkeypatch.setattr(
        backend_module,
        "collect_live_single_iteration_fixes",
        _collect_single_iteration,
    )
    monkeypatch.setattr(
        backend_module,
        "collect_live_bad_while_loop_analysis",
        _collect_bad_while_loop,
    )
    monkeypatch.setattr(
        backend_module,
        "IDAIRTranslator",
        lambda: _FakeTranslator(_cleanup_flow_graph()),
    )

    backend = LiveSimpleFlatteningCleanupBackend()
    mba = _fake_mba()
    detection = backend.collect(mba, logger=None)

    assert detection.fake_jump_fixes == (fake_jump_fix,)
    assert detection.single_iteration_fixes == (single_iteration_fix,)
    assert detection.bad_while_loop_edits == (
        bad_while_loop_edit,
    )
    assert detection.bad_while_loop_deferred_edits == (
        safe_bad_while_loop_duplicate,
        unsafe_bad_while_loop_duplicate,
        unsafe_bad_while_loop_conditional_duplicate,
        unsafe_bad_while_loop_conditional_redirect,
    )
    assert len(detection.bad_while_loop_conditional_redirect_proofs) == 1
    conditional_proof = detection.bad_while_loop_conditional_redirect_proofs[0]
    assert conditional_proof.defer_reason == "conditional_redirect_not_promoted"
    assert conditional_proof.dispatcher_entry == 41
    assert conditional_proof.source_serial == 40
    assert conditional_proof.ref_block == 44
    assert conditional_proof.verdict is CleanupProofVerdict.UNSAFE
    assert detection.bad_while_loop_follow_up == (bad_while_loop_follow_up,)
    assert detection.tail_goto_merges == (
        TailGotoMergeCandidate(
            block_serial=70,
            successor_serial=71,
            insn_ea=0x5000 + 70,
        ),
    )
    assert detection.collection_errors == ()
    assert calls["fake_jump"][0] is mba
    assert calls["fake_jump"][1]["max_nb_block"] == 100
    assert calls["fake_jump"][1]["max_path"] == 100
    assert calls["single_iteration"][0] is mba
    assert calls["bad_while_loop"][0] is mba

def test_live_cleanup_backend_promotes_safe_conditional_cleanup_edits(
    monkeypatch,
) -> None:
    conditional_duplicate = BadWhileLoopConditionalDuplicate(
        dispatcher_entry=2,
        source_serial=6,
        pred_serial=8,
        conditional_target=3,
        fallthrough_target=4,
    )
    conditional_redirect = BadWhileLoopConditionalRedirect(
        dispatcher_entry=2,
        source_serial=1,
        ref_block=12,
        conditional_target=3,
        fallthrough_target=4,
        dispatcher_internal_serials=(2,),
        copied_side_effects_absent=True,
    )

    def _collect_empty(_mba, **_kwargs):
        return ()

    def _collect_bad_while_loop(_mba, **_kwargs):
        return BadWhileLoopAnalysis(
            edits=(conditional_duplicate, conditional_redirect),
            follow_up=(),
        )

    monkeypatch.setattr(backend_module, "collect_live_fake_jump_fixes", _collect_empty)
    monkeypatch.setattr(
        backend_module,
        "collect_live_single_iteration_fixes",
        _collect_empty,
    )
    monkeypatch.setattr(
        backend_module,
        "collect_live_bad_while_loop_analysis",
        _collect_bad_while_loop,
    )
    monkeypatch.setattr(
        backend_module,
        "IDAIRTranslator",
        lambda: _FakeTranslator(_conditional_promotion_flow_graph()),
    )

    detection = LiveSimpleFlatteningCleanupBackend().collect(_fake_mba(), logger=None)

    assert detection.bad_while_loop_edits == (
        conditional_duplicate,
        conditional_redirect,
    )
    assert detection.bad_while_loop_deferred_edits == ()
    assert len(detection.bad_while_loop_conditional_redirect_proofs) == 1
    proof = detection.bad_while_loop_conditional_redirect_proofs[0]
    assert proof.defer_reason == "conditional_redirect_promoted"
    assert proof.verdict is CleanupProofVerdict.SAFE_SHAPE
    assert detection.detected is True


def test_live_cleanup_backend_keeps_negative_conditional_proof_deferred(
    monkeypatch,
) -> None:
    edit = BadWhileLoopConditionalRedirect(
        dispatcher_entry=2,
        source_serial=1,
        ref_block=12,
        conditional_target=3,
        fallthrough_target=4,
        dispatcher_internal_serials=(2,),
        copied_side_effects_absent=False,
    )
    proof = bad_while_loop_conditional_redirect_proof(
        edit,
        _conditional_redirect_flow_graph(),
    )
    assert proof is not None
    assert proof.state is CleanupProofState.UNPROVEN

    monkeypatch.setattr(
        backend_module,
        "collect_live_fake_jump_fixes",
        lambda *_args, **_kwargs: (),
    )
    monkeypatch.setattr(
        backend_module,
        "collect_live_single_iteration_fixes",
        lambda *_args, **_kwargs: (),
    )
    monkeypatch.setattr(
        backend_module,
        "collect_live_bad_while_loop_analysis",
        lambda *_args, **_kwargs: BadWhileLoopAnalysis(
            edits=(edit,),
            follow_up=(),
        ),
    )
    monkeypatch.setattr(
        backend_module,
        "collect_live_fix_predecessor_branch_arm_fixes",
        lambda *_args, **_kwargs: (),
    )
    monkeypatch.setattr(
        backend_module,
        "IDAIRTranslator",
        lambda: _FakeTranslator(_conditional_redirect_flow_graph()),
    )

    detection = LiveSimpleFlatteningCleanupBackend().collect(
        _fake_mba(),
        logger=None,
    )

    assert detection.bad_while_loop_edits == ()
    assert detection.bad_while_loop_deferred_edits == (edit,)
    assert len(detection.bad_while_loop_conditional_redirect_proofs) == 1
    assert (
        detection.bad_while_loop_conditional_redirect_proofs[0].defer_reason
        == "conditional_redirect_not_promoted"
    )


def test_live_cleanup_backend_promotes_direct_side_effect_replay_only(
    monkeypatch,
) -> None:
    replay_candidate = bad_while_loop_side_effect_replay_candidate(
        dispatcher_entry=41,
        source_serial=40,
        target_serial=42,
        captured_body=_side_effect_body(),
        dispatcher_internal_serials=(41,),
    )
    assert replay_candidate is not None
    direct_follow_up = BadWhileLoopFollowUp(
        dispatcher_entry=41,
        from_serial=40,
        category=BAD_WHILE_LOOP_INSERT_BLOCK,
        reason="copied_side_effects",
        target_serial=42,
    )
    unsafe_follow_up = BadWhileLoopFollowUp(
        dispatcher_entry=41,
        from_serial=40,
        category=BAD_WHILE_LOOP_INSERT_BLOCK,
        reason="copied_side_effects_not_dependency_safe",
        target_serial=42,
    )
    duplicate_group_follow_up = BadWhileLoopFollowUp(
        dispatcher_entry=41,
        from_serial=50,
        category=BAD_WHILE_LOOP_INSERT_BLOCK,
        reason="duplicate_group_copied_side_effects",
        target_serial=42,
    )
    dependency_diagnostic = {
        "dispatcher_entry": 41,
        "source_serial": 40,
        "target_serial": 42,
        "category": BAD_WHILE_LOOP_INSERT_BLOCK,
        "reason": "copied_side_effects_not_dependency_safe",
        "raw_instruction_count": 1,
        "dependency_safe_instruction_count": 0,
        "source_liveins": [],
        "source_defs": [],
        "copied_instructions": [],
        "missing_uses": [],
        "final_bucket": "mixed_unknown",
        "bucket_reason": "test diagnostic",
    }
    calls: dict[str, object] = {}

    def _collect_empty(_mba, **_kwargs):
        return ()

    def _collect_bad_while_loop(mba, **kwargs):
        calls["bad_while_loop"] = (mba, kwargs)
        return BadWhileLoopAnalysis(
            edits=(),
            follow_up=(direct_follow_up, unsafe_follow_up, duplicate_group_follow_up),
            replay_candidates=(replay_candidate,),
            dependency_diagnostics=(dependency_diagnostic,),
        )

    monkeypatch.setattr(backend_module, "collect_live_fake_jump_fixes", _collect_empty)
    monkeypatch.setattr(
        backend_module,
        "collect_live_single_iteration_fixes",
        _collect_empty,
    )
    monkeypatch.setattr(
        backend_module,
        "collect_live_bad_while_loop_analysis",
        _collect_bad_while_loop,
    )
    monkeypatch.setattr(
        backend_module,
        "IDAIRTranslator",
        lambda: _FakeTranslator(_cleanup_flow_graph()),
    )

    detection = LiveSimpleFlatteningCleanupBackend().collect(_fake_mba(), logger=None)

    assert detection.bad_while_loop_replay_candidates == (replay_candidate,)
    assert detection.bad_while_loop_follow_up == (
        unsafe_follow_up,
        duplicate_group_follow_up,
    )
    assert detection.bad_while_loop_dependency_diagnostics == (
        dependency_diagnostic,
    )
    assert detection.detected is True
    assert "side_effect_capture" in calls["bad_while_loop"][1]


def test_live_cleanup_backend_promotes_tagged_dependency_rescue_replay(
    monkeypatch,
) -> None:
    rescued_body = CapturedBlockBody(
        backend_id="hexrays.insn_snapshot",
        capture_id="dependency-rescue",
        summary=CapturedBlockBodySummary(
            source_blocks=(12, 40),
            instruction_count=2,
            source_eas=frozenset({0x401012, 0x401040}),
            contains_call=False,
        ),
        payload=(
            InsnSnapshot(opcode=0x77, ea=0x401012, operands=()),
            InsnSnapshot(opcode=0x77, ea=0x401040, operands=()),
        ),
        metadata={"bad_while_loop_dependency_rescue": True},
    )
    replay_candidate = bad_while_loop_side_effect_replay_candidate(
        dispatcher_entry=41,
        source_serial=40,
        target_serial=42,
        captured_body=rescued_body,
        dispatcher_internal_serials=(41,),
    )
    assert replay_candidate is not None
    unsafe_follow_up = BadWhileLoopFollowUp(
        dispatcher_entry=41,
        from_serial=40,
        category=BAD_WHILE_LOOP_INSERT_BLOCK,
        reason="copied_side_effects_not_dependency_safe",
        target_serial=42,
    )

    def _collect_empty(_mba, **_kwargs):
        return ()

    def _collect_bad_while_loop(_mba, **_kwargs):
        return BadWhileLoopAnalysis(
            edits=(),
            follow_up=(unsafe_follow_up,),
            replay_candidates=(replay_candidate,),
        )

    monkeypatch.setattr(backend_module, "collect_live_fake_jump_fixes", _collect_empty)
    monkeypatch.setattr(
        backend_module,
        "collect_live_single_iteration_fixes",
        _collect_empty,
    )
    monkeypatch.setattr(
        backend_module,
        "collect_live_bad_while_loop_analysis",
        _collect_bad_while_loop,
    )
    monkeypatch.setattr(
        backend_module,
        "IDAIRTranslator",
        lambda: _FakeTranslator(_cleanup_flow_graph()),
    )

    detection = LiveSimpleFlatteningCleanupBackend().collect(_fake_mba(), logger=None)

    assert detection.bad_while_loop_replay_candidates == (replay_candidate,)
    assert detection.bad_while_loop_follow_up == ()
    assert detection.detected is True


def test_live_cleanup_backend_promotes_duplicate_group_replay_and_keeps_unsafe_deferred(
    monkeypatch,
) -> None:
    replay_candidate = bad_while_loop_duplicate_group_replay_candidate(
        dispatcher_entry=41,
        source_serial=50,
        per_pred_replays=(
            CleanupPerPredReplay(
                pred_serial=51,
                target_serial=42,
                captured_body=_side_effect_body(50),
            ),
            CleanupPerPredReplay(
                pred_serial=52,
                target_serial=43,
                captured_body=_side_effect_body(50),
            ),
        ),
        dispatcher_internal_serials=(41,),
    )
    assert replay_candidate is not None
    promoted_follow_up = BadWhileLoopFollowUp(
        dispatcher_entry=41,
        from_serial=50,
        category=BAD_WHILE_LOOP_INSERT_BLOCK,
        reason="duplicate_group_copied_side_effects",
        target_serial=42,
    )
    unsafe_follow_up = BadWhileLoopFollowUp(
        dispatcher_entry=41,
        from_serial=60,
        category=BAD_WHILE_LOOP_INSERT_BLOCK,
        reason="duplicate_group_copied_side_effects_not_dependency_safe",
        target_serial=42,
    )

    def _collect_empty(_mba, **_kwargs):
        return ()

    def _collect_bad_while_loop(_mba, **_kwargs):
        return BadWhileLoopAnalysis(
            edits=(),
            follow_up=(promoted_follow_up, unsafe_follow_up),
            duplicate_replay_candidates=(replay_candidate,),
        )

    monkeypatch.setattr(backend_module, "collect_live_fake_jump_fixes", _collect_empty)
    monkeypatch.setattr(
        backend_module,
        "collect_live_single_iteration_fixes",
        _collect_empty,
    )
    monkeypatch.setattr(
        backend_module,
        "collect_live_bad_while_loop_analysis",
        _collect_bad_while_loop,
    )
    monkeypatch.setattr(
        backend_module,
        "IDAIRTranslator",
        lambda: _FakeTranslator(_cleanup_flow_graph()),
    )

    detection = LiveSimpleFlatteningCleanupBackend().collect(_fake_mba(), logger=None)

    assert detection.bad_while_loop_duplicate_replay_candidates == (replay_candidate,)
    assert detection.bad_while_loop_follow_up == (unsafe_follow_up,)
    assert detection.detected is True


def test_live_cleanup_backend_promotes_unique_trampoline_isolation(
    monkeypatch,
) -> None:
    candidate = bad_while_loop_trampoline_isolation_candidate(
        dispatcher_entry=2,
        source_serial=1,
        target_serial=12,
        dispatcher_internal_serials=(2,),
    )
    assert candidate is not None
    promoted_follow_up = BadWhileLoopFollowUp(
        dispatcher_entry=2,
        from_serial=1,
        category=BAD_WHILE_LOOP_DUPLICATE_AND_REDIRECT,
        reason="duplicate_group_requires_trampoline",
        target_serial=12,
    )
    branch_follow_up = BadWhileLoopFollowUp(
        dispatcher_entry=2,
        from_serial=6,
        category="unsupported",
        reason="dispatcher_case_triangle_requires_trampoline",
        target_serial=12,
    )

    def _collect_empty(_mba, **_kwargs):
        return ()

    def _collect_bad_while_loop(_mba, **_kwargs):
        return BadWhileLoopAnalysis(
            edits=(),
            follow_up=(promoted_follow_up, branch_follow_up),
            trampoline_isolation_candidates=(candidate,),
        )

    monkeypatch.setattr(backend_module, "collect_live_fake_jump_fixes", _collect_empty)
    monkeypatch.setattr(
        backend_module,
        "collect_live_single_iteration_fixes",
        _collect_empty,
    )
    monkeypatch.setattr(
        backend_module,
        "collect_live_bad_while_loop_analysis",
        _collect_bad_while_loop,
    )
    monkeypatch.setattr(
        backend_module,
        "IDAIRTranslator",
        lambda: _FakeTranslator(_conditional_redirect_flow_graph()),
    )

    detection = LiveSimpleFlatteningCleanupBackend().collect(_fake_mba(), logger=None)

    assert detection.bad_while_loop_trampoline_isolation_candidates == (candidate,)
    assert detection.bad_while_loop_follow_up == (branch_follow_up,)
    assert detection.detected is True


def test_simple_cleanup_family_selects_and_plans_conditional_cleanup_edits() -> None:
    conditional_duplicate = BadWhileLoopConditionalDuplicate(
        dispatcher_entry=2,
        source_serial=6,
        pred_serial=8,
        conditional_target=3,
        fallthrough_target=4,
    )
    conditional_redirect = BadWhileLoopConditionalRedirect(
        dispatcher_entry=2,
        source_serial=1,
        ref_block=12,
        conditional_target=3,
        fallthrough_target=4,
        dispatcher_internal_serials=(2,),
        copied_side_effects_absent=True,
    )
    backend = _FakeBackend(
        SimpleFlatteningCleanupDetection(
            bad_while_loop_edits=(conditional_duplicate, conditional_redirect),
            maturity=ida_hexrays.MMAT_GLBOPT1,
            func_ea=0x401000,
        )
    )
    family = SimpleFlatteningCleanupFamily(
        backend=backend,
        cfg_translator=_FakeTranslator(_conditional_promotion_flow_graph()),
    )

    snapshot = family.build_snapshot(_fake_mba(), family.detect(_fake_mba()))
    metadata = snapshot.flow_graph.metadata[CLEANUP_FAMILY_METADATA_KEY]

    assert metadata.planning_ready is True
    assert metadata.collected_bad_while_loop_edits == 2
    assert metadata.selected_bad_while_loop_edits == 2
    assert metadata.deferred_bad_while_loop_edits == 0
    assert extract_bad_while_loop_edits(snapshot.flow_graph) == (
        conditional_duplicate,
        conditional_redirect,
    )

    fragment = BadWhileLoopStrategy().plan(snapshot)
    assert fragment is not None
    assert DuplicateBlock(
        source_block=6,
        target_block=None,
        pred_serial=8,
        conditional_target=3,
        fallthrough_target=4,
    ) in fragment.modifications
    assert CreateConditionalRedirect(
        source_block=1,
        ref_block=12,
        conditional_target=3,
        fallthrough_target=4,
        old_target_serial=2,
    ) in fragment.modifications

    patch_plan = compile_patch_plan(fragment.modifications, snapshot.flow_graph)
    assert any(isinstance(step, PatchDuplicateBlock) for step in patch_plan.steps)
    assert any(
        isinstance(step, PatchConditionalRedirect)
        for step in patch_plan.steps
    )
    assert not any(
        isinstance(step, LegacyBlockOperation)
        for step in patch_plan.steps
    )


def test_simple_cleanup_family_uses_backend_evidence_for_metadata() -> None:
    fake_jump_fix = FakeJumpPredFix(fake_block=2, pred_block=5, new_target=10)
    single_iteration_fixes = (
        SingleIterationPredFix(loop_header=30, pred_block=29, new_target=31),
        SingleIterationPredFix(loop_header=30, pred_block=31, new_target=32),
    )
    bad_while_loop_edits = (
        BadWhileLoopGotoRedirect(
            dispatcher_entry=41,
            from_serial=40,
            new_target=42,
        ),
        BadWhileLoopGotoConversion(
            dispatcher_entry=41,
            block_serial=44,
            goto_target=43,
        ),
        BadWhileLoopDuplicateRedirect(
            dispatcher_entry=41,
            source_serial=50,
            per_pred_targets=((51, 42), (52, 43)),
        ),
    )
    bad_while_loop_follow_up = (
        BadWhileLoopFollowUp(
            dispatcher_entry=41,
            from_serial=44,
            category="create_conditional_redirect",
            reason="conditional_exit_with_loopback",
            target_serial=42,
            fallthrough_target=45,
        ),
    )
    tail_goto_merge = TailGotoMergeCandidate(
        block_serial=70,
        successor_serial=71,
        insn_ea=0x5000 + 70,
    )
    backend = _FakeBackend(
        SimpleFlatteningCleanupDetection(
            fake_jump_fixes=(fake_jump_fix,),
            single_iteration_fixes=single_iteration_fixes,
            bad_while_loop_edits=bad_while_loop_edits,
            bad_while_loop_follow_up=bad_while_loop_follow_up,
            tail_goto_merges=(tail_goto_merge,),
            maturity=ida_hexrays.MMAT_GLBOPT1,
            func_ea=0x401000,
        )
    )
    family = SimpleFlatteningCleanupFamily(
        backend=backend,
        cfg_translator=_FakeTranslator(_cleanup_flow_graph())
    )

    mba = _fake_mba()
    detection = family.detect(mba)
    snapshot = family.build_snapshot(mba, detection)

    assert backend.calls and backend.calls[0][0] is mba
    assert detection.detected is True
    assert extract_fake_jump_fixes(snapshot.flow_graph) == (fake_jump_fix,)
    assert extract_single_iteration_fixes(snapshot.flow_graph) == single_iteration_fixes
    assert extract_bad_while_loop_edits(snapshot.flow_graph) == bad_while_loop_edits[:2]
    assert extract_bad_while_loop_follow_up(snapshot.flow_graph) == (
        bad_while_loop_follow_up
    )
    assert extract_tail_goto_merge_candidates(snapshot.flow_graph) == (
        tail_goto_merge,
    )
    assert snapshot.state_machine is None
    assert snapshot.state_summary == StateModelSummary(
        state_constants=frozenset(),
        handler_count=0,
        transition_count=0,
    )

    metadata = snapshot.flow_graph.metadata[CLEANUP_FAMILY_METADATA_KEY]
    assert isinstance(metadata, SimpleFlatteningCleanupMetadata)
    assert metadata.strategy_names == (
        "fake_jump",
        "single_iteration",
        "guarded_state_machine",
        "local_select_loop",
        "side_effect_select_loop",
        "bad_while_loop",
        "fix_predecessor_branch_arm",
        "tail_goto_merge",
    )
    assert metadata.collected_fake_jump_fixes == 1
    assert metadata.selected_fake_jump_fixes == 1
    assert metadata.collected_single_iteration_fixes == 2
    assert metadata.selected_single_iteration_fixes == 2
    assert metadata.collected_bad_while_loop_edits == 3
    assert metadata.selected_bad_while_loop_edits == 2
    assert metadata.deferred_bad_while_loop_edits == 0
    assert metadata.bad_while_loop_follow_up == 1
    assert metadata.collected_tail_goto_merges == 1
    assert metadata.selected_tail_goto_merges == 1
    assert metadata.collected_guarded_state_machine_fixes == 0
    assert metadata.selected_guarded_state_machine_fixes == 0
    assert metadata.collected_local_select_loop_fixes == 0
    assert metadata.selected_local_select_loop_fixes == 0
    assert metadata.planning_ready is True

    fragment = BadWhileLoopStrategy().plan(snapshot)
    assert fragment is not None
    assert fragment.modifications == [
        RedirectGoto(from_serial=40, old_target=41, new_target=42),
        ConvertToGoto(block_serial=44, goto_target=43),
    ]

    patch_plan = compile_patch_plan(fragment.modifications, snapshot.flow_graph)
    assert not any(isinstance(step, LegacyBlockOperation) for step in patch_plan.steps)


def test_tail_goto_merge_strategy_emits_relaxed_nop_cleanup() -> None:
    cfg = FlowGraph(
        blocks={
            0: _block(0, (1,), (), start_ea=0x401000),
            1: _block(1, (2,), (0,), start_ea=0x401001, tail_target=2),
            2: _block(2, (), (1,), block_type=2, start_ea=0x401002),
        },
        entry_serial=0,
        func_ea=0x401000,
    )
    candidate = TailGotoMergeCandidate(
        block_serial=1,
        successor_serial=2,
        insn_ea=0x5000 + 1,
    )
    assert collect_tail_goto_merge_candidates(cfg) == (candidate,)

    backend = _FakeBackend(
        SimpleFlatteningCleanupDetection(
            tail_goto_merges=(candidate,),
            maturity=ida_hexrays.MMAT_CALLS,
            func_ea=0x401000,
        )
    )
    family = SimpleFlatteningCleanupFamily(
        backend=backend,
        cfg_translator=_FakeTranslator(cfg),
    )
    snapshot = family.build_snapshot(_fake_mba(), family.detect(_fake_mba()))
    metadata = snapshot.flow_graph.metadata[CLEANUP_FAMILY_METADATA_KEY]

    assert metadata.planning_ready is True
    assert metadata.collected_tail_goto_merges == 1
    assert metadata.selected_tail_goto_merges == 1
    assert extract_tail_goto_merge_candidates(snapshot.flow_graph) == (candidate,)

    fragment = TailGotoMergeStrategy().plan(snapshot)
    assert fragment is not None
    assert fragment.modifications == [
        NopInstructions(block_serial=1, insn_eas=(0x5001,))
    ]
    assert fragment.metadata["execution_policy"] == "nop_merge_blocks_relaxed"
    assert fragment.metadata[TAIL_GOTO_MERGE_METADATA_KEY] == [
        {"block_serial": 1, "successor_serial": 2, "insn_ea": 0x5001}
    ]

    patch_plan = compile_patch_plan(
        fragment.modifications,
        snapshot.flow_graph,
        execution_policy=ExecutionPolicy.NOP_MERGE_BLOCKS_RELAXED,
    )
    assert patch_plan.execution_policy is ExecutionPolicy.NOP_MERGE_BLOCKS_RELAXED
    assert patch_plan.steps == (
        PatchNopInstructions(block_serial=1, insn_eas=(0x5001,)),
    )


def test_tail_goto_merge_rejects_non_fallthrough_successor() -> None:
    cfg = FlowGraph(
        blocks={
            0: _block(0, (1,), (), start_ea=0x401000),
            1: _block(1, (3,), (0,), start_ea=0x401001, tail_target=3),
            2: _block(2, (), (), block_type=2, start_ea=0x401002),
            3: _block(3, (), (1,), block_type=2, start_ea=0x401003),
        },
        entry_serial=0,
        func_ea=0x401000,
    )

    assert collect_tail_goto_merge_candidates(cfg) == ()


def test_simple_cleanup_family_selects_and_plans_direct_side_effect_replay() -> None:
    replay_candidate = bad_while_loop_side_effect_replay_candidate(
        dispatcher_entry=41,
        source_serial=40,
        target_serial=42,
        captured_body=_side_effect_body(),
        dispatcher_internal_serials=(41,),
    )
    assert replay_candidate is not None
    unsafe_follow_up = BadWhileLoopFollowUp(
        dispatcher_entry=41,
        from_serial=40,
        category=BAD_WHILE_LOOP_INSERT_BLOCK,
        reason="copied_side_effects_not_dependency_safe",
        target_serial=42,
    )
    backend = _FakeBackend(
        SimpleFlatteningCleanupDetection(
            bad_while_loop_replay_candidates=(replay_candidate,),
            bad_while_loop_follow_up=(unsafe_follow_up,),
            maturity=ida_hexrays.MMAT_GLBOPT1,
            func_ea=0x401000,
        )
    )
    flow_graph = _cleanup_flow_graph()
    family = SimpleFlatteningCleanupFamily(
        backend=backend,
        cfg_translator=_FakeTranslator(flow_graph),
    )

    snapshot = family.build_snapshot(_fake_mba(), family.detect(_fake_mba()))
    metadata = snapshot.flow_graph.metadata[CLEANUP_FAMILY_METADATA_KEY]

    assert metadata.planning_ready is True
    assert metadata.collected_bad_while_loop_replay_candidates == 1
    assert metadata.selected_bad_while_loop_replay_candidates == 1
    assert extract_side_effect_replay_candidates(snapshot.flow_graph) == (
        replay_candidate,
    )
    assert snapshot.flow_graph.metadata[CLEANUP_SIDE_EFFECT_REPLAY_METADATA_KEY] == (
        replay_candidate,
    )
    assert extract_bad_while_loop_follow_up(snapshot.flow_graph) == (unsafe_follow_up,)

    fragment = BadWhileLoopStrategy().plan(snapshot)
    assert fragment is not None
    assert fragment.modifications == [
        InsertBlock(
            pred_serial=40,
            succ_serial=42,
            old_target_serial=41,
            captured_body=replay_candidate.captured_body,
        )
    ]

    patch_plan = compile_patch_plan(fragment.modifications, snapshot.flow_graph)
    assert any(isinstance(step, PatchInsertBlock) for step in patch_plan.steps)
    assert not any(
        isinstance(step, LegacyBlockOperation)
        for step in patch_plan.steps
    )


def test_simple_cleanup_family_selects_and_plans_duplicate_group_replay() -> None:
    replay_candidate = bad_while_loop_duplicate_group_replay_candidate(
        dispatcher_entry=41,
        source_serial=50,
        per_pred_replays=(
            CleanupPerPredReplay(
                pred_serial=51,
                target_serial=42,
                captured_body=_side_effect_body(50),
            ),
            CleanupPerPredReplay(
                pred_serial=52,
                target_serial=43,
                captured_body=_side_effect_body(50),
            ),
        ),
        dispatcher_internal_serials=(41,),
    )
    assert replay_candidate is not None
    backend = _FakeBackend(
        SimpleFlatteningCleanupDetection(
            bad_while_loop_duplicate_replay_candidates=(replay_candidate,),
            maturity=ida_hexrays.MMAT_GLBOPT1,
            func_ea=0x401000,
        )
    )
    family = SimpleFlatteningCleanupFamily(
        backend=backend,
        cfg_translator=_FakeTranslator(_cleanup_flow_graph()),
    )

    snapshot = family.build_snapshot(_fake_mba(), family.detect(_fake_mba()))
    metadata = snapshot.flow_graph.metadata[CLEANUP_FAMILY_METADATA_KEY]

    assert metadata.planning_ready is True
    assert metadata.collected_bad_while_loop_duplicate_replay_candidates == 1
    assert metadata.selected_bad_while_loop_duplicate_replay_candidates == 1
    assert extract_duplicate_group_replay_candidates(snapshot.flow_graph) == (
        replay_candidate,
    )
    assert snapshot.flow_graph.metadata[CLEANUP_DUPLICATE_REPLAY_METADATA_KEY] == (
        replay_candidate,
    )

    fragment = BadWhileLoopStrategy().plan(snapshot)
    assert fragment is not None
    assert len(fragment.modifications) == 1
    modification = fragment.modifications[0]
    assert isinstance(modification, DuplicateReplayAndRedirect)
    assert modification.source_serial == 50
    assert modification.dispatcher_entry == 41
    assert [
        (row.pred_serial, row.target_serial)
        for row in modification.per_pred_replays
    ] == [(51, 42), (52, 43)]

    patch_plan = compile_patch_plan(fragment.modifications, snapshot.flow_graph)
    assert any(
        isinstance(step, PatchDuplicateReplayAndRedirect)
        for step in patch_plan.steps
    )
    assert not any(
        isinstance(step, LegacyBlockOperation)
        for step in patch_plan.steps
    )


def test_simple_cleanup_family_selects_trampoline_isolation_candidate() -> None:
    candidate = bad_while_loop_trampoline_isolation_candidate(
        dispatcher_entry=2,
        source_serial=1,
        target_serial=12,
        dispatcher_internal_serials=(2,),
    )
    assert candidate is not None
    follow_up = BadWhileLoopFollowUp(
        dispatcher_entry=2,
        from_serial=1,
        category=BAD_WHILE_LOOP_DUPLICATE_AND_REDIRECT,
        reason="duplicate_group_requires_trampoline",
        target_serial=12,
    )
    backend = _FakeBackend(
        SimpleFlatteningCleanupDetection(
            bad_while_loop_trampoline_isolation_candidates=(candidate,),
            bad_while_loop_follow_up=(follow_up,),
            maturity=ida_hexrays.MMAT_GLBOPT1,
            func_ea=0x401000,
        )
    )
    family = SimpleFlatteningCleanupFamily(
        backend=backend,
        cfg_translator=_FakeTranslator(_conditional_redirect_flow_graph()),
    )

    snapshot = family.build_snapshot(_fake_mba(), family.detect(_fake_mba()))
    metadata = snapshot.flow_graph.metadata[CLEANUP_FAMILY_METADATA_KEY]

    assert metadata.planning_ready is True
    assert metadata.collected_bad_while_loop_trampoline_isolation_candidates == 1
    assert metadata.selected_bad_while_loop_trampoline_isolation_candidates == 1
    assert metadata.bad_while_loop_follow_up_reclassifications == 1
    assert extract_trampoline_isolation_candidates(snapshot.flow_graph) == (
        candidate,
    )
    assert snapshot.flow_graph.metadata[CLEANUP_TRAMPOLINE_ISOLATION_METADATA_KEY] == (
        candidate,
    )
    reclassifications = extract_follow_up_reclassifications(snapshot.flow_graph)
    assert len(reclassifications) == 1
    assert (
        reclassifications[0].bucket
        is CleanupFollowUpResolutionBucket.NEEDS_TRAMPOLINE_ISOLATION
    )
    assert reclassifications[0].proof_state is CleanupProofState.PROVEN
    assert (
        snapshot.flow_graph.metadata[
            CLEANUP_FOLLOW_UP_RECLASSIFICATION_METADATA_KEY
        ]
        != []
    )

    fragment = BadWhileLoopStrategy().plan(snapshot)
    assert fragment is not None
    assert fragment.modifications == [
        InsertBlock(
            pred_serial=1,
            succ_serial=12,
            old_target_serial=2,
            instructions=(),
        )
    ]

    patch_plan = compile_patch_plan(fragment.modifications, snapshot.flow_graph)
    assert any(isinstance(step, PatchInsertBlock) for step in patch_plan.steps)
    assert not any(
        isinstance(step, LegacyBlockOperation)
        for step in patch_plan.steps
    )


def test_simple_cleanup_family_carries_dependency_diagnostics_without_planning() -> None:
    diagnostic = {
        "dispatcher_entry": 41,
        "source_serial": 40,
        "target_serial": 42,
        "category": BAD_WHILE_LOOP_INSERT_BLOCK,
        "reason": "copied_side_effects_not_dependency_safe",
        "raw_instruction_count": 1,
        "dependency_safe_instruction_count": 0,
        "source_liveins": [],
        "source_defs": [],
        "copied_instructions": [],
        "missing_uses": [],
        "final_bucket": "memory_or_alias_unknown",
        "bucket_reason": "test diagnostic",
    }
    backend = _FakeBackend(
        SimpleFlatteningCleanupDetection(
            bad_while_loop_dependency_diagnostics=(diagnostic,),
            maturity=ida_hexrays.MMAT_GLBOPT1,
            func_ea=0x401000,
        )
    )
    family = SimpleFlatteningCleanupFamily(
        backend=backend,
        cfg_translator=_FakeTranslator(_cleanup_flow_graph()),
    )

    snapshot = family.build_snapshot(_fake_mba(), family.detect(_fake_mba()))
    metadata = snapshot.flow_graph.metadata[CLEANUP_FAMILY_METADATA_KEY]

    assert metadata.planning_ready is False
    assert metadata.bad_while_loop_dependency_diagnostics == 1
    assert snapshot.flow_graph.metadata[
        BAD_WHILE_LOOP_DEPENDENCY_DIAGNOSTICS_METADATA_KEY
    ] == [diagnostic]
    assert extract_bad_while_loop_dependency_diagnostics(snapshot.flow_graph) == (
        diagnostic,
    )
    assert BadWhileLoopStrategy().plan(snapshot) is None


def test_simple_cleanup_family_defers_unsafe_bad_while_loop_edits() -> None:
    unsafe_edit = BadWhileLoopConditionalRedirect(
        dispatcher_entry=41,
        source_serial=40,
        ref_block=44,
        conditional_target=42,
        fallthrough_target=43,
    )
    proof_edit = BadWhileLoopConditionalRedirect(
        dispatcher_entry=2,
        source_serial=1,
        ref_block=12,
        conditional_target=3,
        fallthrough_target=4,
        dispatcher_internal_serials=(2,),
        copied_side_effects_absent=True,
    )
    conditional_proof = explain_bad_while_loop_conditional_redirect(
        proof_edit,
        _conditional_redirect_flow_graph(),
        defer_reason="conditional_redirect_not_promoted",
    )
    assert conditional_proof is not None
    assert conditional_proof.verdict is CleanupProofVerdict.SAFE_SHAPE
    unsafe_conditional_duplicate = BadWhileLoopConditionalDuplicate(
        dispatcher_entry=41,
        source_serial=44,
        pred_serial=40,
        conditional_target=42,
        fallthrough_target=43,
    )
    side_effect_follow_up = BadWhileLoopFollowUp(
        dispatcher_entry=41,
        from_serial=40,
        category="insert_block",
        reason="copied_side_effects",
        target_serial=42,
    )
    backend = _FakeBackend(
        SimpleFlatteningCleanupDetection(
            bad_while_loop_deferred_edits=(unsafe_edit, unsafe_conditional_duplicate),
            bad_while_loop_conditional_redirect_proofs=(conditional_proof,),
            bad_while_loop_follow_up=(side_effect_follow_up,),
            maturity=ida_hexrays.MMAT_GLBOPT1,
            func_ea=0x401000,
        )
    )
    family = SimpleFlatteningCleanupFamily(
        backend=backend,
        cfg_translator=_FakeTranslator(_cleanup_flow_graph())
    )

    detection = family.detect(_fake_mba())
    snapshot = family.build_snapshot(_fake_mba(), detection)

    metadata = snapshot.flow_graph.metadata[CLEANUP_FAMILY_METADATA_KEY]
    assert detection.detected is False
    assert detection.diagnostic_only is True
    assert extract_bad_while_loop_edits(snapshot.flow_graph) == ()
    assert extract_bad_while_loop_follow_up(snapshot.flow_graph) == (
        side_effect_follow_up,
    )
    assert snapshot.flow_graph.metadata[BAD_WHILE_LOOP_EDITS_METADATA_KEY] == []
    assert snapshot.flow_graph.metadata[BAD_WHILE_LOOP_FOLLOW_UP_METADATA_KEY] != []
    assert (
        extract_conditional_redirect_proofs(snapshot.flow_graph)
        == (conditional_proof,)
    )
    assert (
        snapshot.flow_graph.metadata[CLEANUP_CONDITIONAL_REDIRECT_PROOF_METADATA_KEY]
        != []
    )
    assert metadata.collected_bad_while_loop_edits == 2
    assert metadata.selected_bad_while_loop_edits == 0
    assert metadata.deferred_bad_while_loop_edits == 2
    assert metadata.bad_while_loop_follow_up == 1
    assert metadata.collected_bad_while_loop_conditional_redirect_proofs == 1
    assert metadata.selected_bad_while_loop_conditional_redirect_proofs == 1
    assert metadata.planning_ready is False


def test_simple_cleanup_family_records_backend_errors() -> None:
    backend = _FakeBackend(
        SimpleFlatteningCleanupDetection(
            collection_errors=("fake_jump:RuntimeError",),
            maturity=ida_hexrays.MMAT_GLBOPT1,
            func_ea=0x401000,
        )
    )
    family = SimpleFlatteningCleanupFamily(
        backend=backend,
        cfg_translator=_FakeTranslator(_cleanup_flow_graph())
    )

    detection = family.detect(_fake_mba())
    snapshot = family.build_snapshot(_fake_mba(), detection)

    metadata = snapshot.flow_graph.metadata[CLEANUP_FAMILY_METADATA_KEY]
    assert detection.detected is False
    assert detection.collection_errors == ("fake_jump:RuntimeError",)
    assert metadata.collection_errors == ("fake_jump:RuntimeError",)
    assert metadata.planning_ready is False
    assert snapshot.flow_graph.metadata[FAKE_JUMP_FIXES_METADATA_KEY] == {}
    assert snapshot.flow_graph.metadata[SINGLE_ITERATION_FIXES_METADATA_KEY] == {}
    assert snapshot.flow_graph.metadata[BAD_WHILE_LOOP_EDITS_METADATA_KEY] == []
    assert snapshot.flow_graph.metadata[BAD_WHILE_LOOP_FOLLOW_UP_METADATA_KEY] == []


def test_cleanup_unflattener_uses_shared_runtime(monkeypatch) -> None:
    mba = _fake_mba()
    metadata = SimpleFlatteningCleanupMetadata(
        family_name="simple_flattening_cleanup",
        strategy_names=("fake_jump", "single_iteration", "bad_while_loop"),
        maturity=ida_hexrays.MMAT_GLBOPT1,
        func_ea=0x401000,
        collected_fake_jump_fixes=1,
        selected_fake_jump_fixes=1,
        collected_single_iteration_fixes=0,
        selected_single_iteration_fixes=0,
        planning_ready=True,
    )
    flow_graph = FlowGraph(
        blocks={},
        entry_serial=0,
        func_ea=0x401000,
        metadata={CLEANUP_FAMILY_METADATA_KEY: metadata},
    )
    snapshot = AnalysisSnapshot(
        mba=mba,
        flow_graph=flow_graph,
        state_summary=StateModelSummary(),
    )
    fragment = PlanFragment(
        strategy_name="fake_jump",
        family=FAMILY_CLEANUP,
        ownership=OwnershipScope(
            blocks=frozenset({5}),
            edges=frozenset({(5, 2)}),
            transitions=frozenset(),
        ),
        prerequisites=[],
        expected_benefit=BenefitMetrics(
            handlers_resolved=0,
            transitions_resolved=0,
            blocks_freed=1,
            conflict_density=0.0,
        ),
        risk_score=0.1,
        modifications=[RedirectGoto(from_serial=5, old_target=2, new_target=10)],
    )
    provenance = PipelineProvenance(rows=())
    calls: dict[str, object] = {}

    class _FakeFamily:
        def detect(self, _mba: object) -> SimpleFlatteningCleanupDetection:
            calls["detect"] = True
            return SimpleFlatteningCleanupDetection(
                fake_jump_fixes=(FakeJumpPredFix(2, 5, 10),),
                maturity=ida_hexrays.MMAT_GLBOPT1,
                func_ea=0x401000,
            )

        def build_snapshot(
            self,
            _mba: object,
            _detection: SimpleFlatteningCleanupDetection,
        ) -> AnalysisSnapshot:
            calls["snapshot"] = True
            return snapshot

        def strategies_for_maturity(self, maturity: int) -> list:
            calls["maturity"] = maturity
            return []

        def post_execute_cleanup(
            self,
            _mba: object,
            *,
            snapshot: AnalysisSnapshot,
            total_changes: int,
        ) -> int:
            calls["cleanup"] = (snapshot, total_changes)
            return 1

    def _plan_family_pipeline(snapshot_arg, strategies, *, planner, inputs):
        calls["plan"] = (snapshot_arg, strategies, inputs.total_handlers)
        return PlannedPipeline(pipeline=[fragment], provenance=provenance)

    def _execute_family_pipeline(
        snapshot_arg,
        planned,
        *,
        executor_factory,
        flow_context,
    ):
        calls["execute"] = (snapshot_arg, planned, executor_factory, flow_context)
        return ExecutedPipeline(
            pipeline=planned.pipeline,
            results=[],
            provenance=provenance,
            total_changes=2,
            executor=None,
        )

    monkeypatch.setattr(shell_module, "plan_family_pipeline", _plan_family_pipeline)
    monkeypatch.setattr(shell_module, "execute_family_pipeline", _execute_family_pipeline)

    rule = SimpleFlatteningCleanupUnflattener()
    rule._family = _FakeFamily()

    assert rule.optimize(SimpleNamespace(mba=mba)) == 3
    assert calls["detect"] is True
    assert calls["snapshot"] is True
    assert calls["plan"] == (snapshot, [], 0)
    assert calls["cleanup"] == (snapshot, 2)
    assert calls["execute"][0] is snapshot

    observation = rule.get_last_observation()
    assert observation["total_changes"] == 3
