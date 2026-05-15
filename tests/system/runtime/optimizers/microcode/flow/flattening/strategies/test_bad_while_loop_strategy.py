"""Runtime tests for the safe BadWhileLoop engine strategy subset."""
from __future__ import annotations

from types import SimpleNamespace

import pytest

from d810.cfg.flowgraph import BlockSnapshot, FlowGraph, InsnSnapshot
from d810.cfg.graph_modification import (
    ConvertToGoto,
    CreateConditionalRedirect,
    DuplicateBlock,
    DuplicateAndRedirect,
    DuplicateReplayAndRedirect,
    InsertBlock,
    RedirectGoto,
)
from d810.cfg.materialization_payload import (
    CapturedBlockBody,
    CapturedBlockBodySummary,
)
from d810.evaluator.hexrays_microcode.definition_rescue_backend import (
    DefinitionSiteEvidence,
)
from d810.optimizers.microcode.flow.flattening.cleanup_evidence import (
    CLEANUP_DUPLICATE_REPLAY_METADATA_KEY,
    CLEANUP_SIDE_EFFECT_REPLAY_METADATA_KEY,
    CleanupPerPredReplay,
    bad_while_loop_duplicate_group_replay_candidate,
    bad_while_loop_side_effect_replay_candidate,
)
from d810.optimizers.microcode.flow.flattening.engine.snapshot import (
    AnalysisSnapshot,
)
from d810.optimizers.microcode.flow.flattening.engine.strategy import (
    FAMILY_CLEANUP,
)
from d810.optimizers.microcode.flow.flattening.strategies.bad_while_loop import (
    BAD_WHILE_LOOP_EDITS_METADATA_KEY,
    BAD_WHILE_LOOP_FOLLOW_UP_METADATA_KEY,
    BAD_WHILE_LOOP_CREATE_CONDITIONAL_REDIRECT,
    BAD_WHILE_LOOP_DUPLICATE_AND_REDIRECT,
    BAD_WHILE_LOOP_INSERT_BLOCK,
    BAD_WHILE_LOOP_UNSUPPORTED,
    BadWhileLoopConditionalDuplicate,
    BadWhileLoopConditionalRedirect,
    BadWhileLoopFollowUp,
    BadWhileLoopDuplicateRedirect,
    BadWhileLoopGotoConversion,
    BadWhileLoopGotoRedirect,
    BadWhileLoopStrategy,
    build_bad_while_loop_modifications,
    collect_live_bad_while_loop_analysis,
    extract_bad_while_loop_edits,
    extract_bad_while_loop_follow_up,
    serialize_bad_while_loop_edits,
    serialize_bad_while_loop_follow_up,
)
from d810.optimizers.microcode.flow.flattening.strategies.bad_while_loop_dependency_diagnostics import (
    build_bad_while_loop_dependency_diagnostic,
)


def _block(
    serial: int,
    succs: tuple[int, ...],
    preds: tuple[int, ...],
    *,
    block_type: int = 1,
    start_ea: int | None = None,
    tail_opcode: int | None = None,
) -> BlockSnapshot:
    return BlockSnapshot(
        serial=serial,
        block_type=block_type,
        succs=succs,
        preds=preds,
        flags=0,
        start_ea=serial if start_ea is None else start_ea,
        insn_snapshots=(),
        tail_opcode=tail_opcode,
    )


def _captured_body(
    source_serial: int = 5,
    *,
    contains_call: bool = False,
) -> CapturedBlockBody:
    instructions = (InsnSnapshot(opcode=0x77, ea=0x2000, operands=()),)
    return CapturedBlockBody(
        backend_id="hexrays.insn_snapshot",
        capture_id=f"bad-while-loop-test:{source_serial}",
        summary=CapturedBlockBodySummary(
            source_blocks=(source_serial,),
            instruction_count=len(instructions),
            source_eas=frozenset({0x2000}),
            contains_call=contains_call,
        ),
        payload=instructions,
    )


def test_bad_while_loop_strategy_has_expected_identity() -> None:
    strategy = BadWhileLoopStrategy()

    assert strategy.name == "bad_while_loop"
    assert strategy.family == FAMILY_CLEANUP


def test_bad_while_loop_strategy_is_metadata_driven() -> None:
    strategy = BadWhileLoopStrategy()

    assert strategy.is_applicable(AnalysisSnapshot(mba=object())) is False

    cfg = FlowGraph(
        blocks={
            0: _block(0, (1,), (), start_ea=0x1000),
            1: _block(1, (2,), (0,), start_ea=0x1001),
            2: _block(2, (3, 4), (1, 5), block_type=4),
            3: _block(3, (), (2,), block_type=2),
            4: _block(4, (), (2,), block_type=2),
            5: _block(5, (2, 8), (), block_type=4, start_ea=0x1005),
            8: _block(8, (), (5,), block_type=2),
        },
        entry_serial=0,
        func_ea=0x1000,
        metadata={
            BAD_WHILE_LOOP_EDITS_METADATA_KEY: [
                {
                    "kind": "redirect_goto",
                    "dispatcher_entry": 2,
                    "from_serial": 1,
                    "new_target": 3,
                },
                {
                    "kind": "convert_to_goto",
                    "dispatcher_entry": 2,
                    "block_serial": 5,
                    "goto_target": 4,
                },
            ]
        },
    )

    assert strategy.is_applicable(
        AnalysisSnapshot(mba=object(), flow_graph=cfg),
    ) is True


def test_bad_while_loop_strategy_ignores_follow_up_only_metadata() -> None:
    cfg = FlowGraph(
        blocks={
            0: _block(0, (1,), (), start_ea=0x1000),
            1: _block(1, (2,), (0,), start_ea=0x1001),
            2: _block(2, (3, 4), (1, 5), block_type=4),
            3: _block(3, (), (2,), block_type=2),
            4: _block(4, (), (2,), block_type=2),
            5: _block(5, (2, 8), (), block_type=4, start_ea=0x1005),
            8: _block(8, (), (5,), block_type=2),
        },
        entry_serial=0,
        func_ea=0x1000,
        metadata={
            BAD_WHILE_LOOP_FOLLOW_UP_METADATA_KEY: [
                {
                    "dispatcher_entry": 2,
                    "from_serial": 5,
                    "category": BAD_WHILE_LOOP_CREATE_CONDITIONAL_REDIRECT,
                    "reason": "conditional_exit_with_loopback",
                    "target_serial": 3,
                    "fallthrough_target": 8,
                }
            ]
        },
    )

    strategy = BadWhileLoopStrategy()
    snapshot = AnalysisSnapshot(mba=object(), flow_graph=cfg)

    assert strategy.is_applicable(snapshot) is False
    assert strategy.plan(snapshot) is None


def test_extract_bad_while_loop_edits_round_trips() -> None:
    cfg = FlowGraph(
        blocks={
            0: _block(0, (1,), (), start_ea=0x1000),
            1: _block(1, (2,), (0,), start_ea=0x1001),
            2: _block(2, (3, 4), (1, 5, 6), block_type=4),
            3: _block(3, (), (2,), block_type=2),
            4: _block(4, (), (2,), block_type=2),
            5: _block(5, (2,), (8, 9), block_type=1, start_ea=0x1005),
            6: _block(6, (2, 10), (11,), block_type=4, start_ea=0x1006),
            8: _block(8, (5,), (), start_ea=0x1008),
            9: _block(9, (5,), (), start_ea=0x1009),
            10: _block(10, (), (6,), block_type=2),
            11: _block(11, (6,), (), start_ea=0x100B),
            12: _block(12, (3, 4), (2,), block_type=4, start_ea=0x100C),
        },
        entry_serial=0,
        func_ea=0x1000,
        metadata={
            BAD_WHILE_LOOP_EDITS_METADATA_KEY: serialize_bad_while_loop_edits(
                (
                    BadWhileLoopGotoRedirect(
                        dispatcher_entry=2,
                        from_serial=1,
                        new_target=3,
                    ),
                    BadWhileLoopGotoConversion(
                        dispatcher_entry=2,
                        block_serial=6,
                        goto_target=4,
                    ),
                    BadWhileLoopDuplicateRedirect(
                        dispatcher_entry=2,
                        source_serial=5,
                        per_pred_targets=((8, 3), (9, 4)),
                    ),
                    BadWhileLoopConditionalDuplicate(
                        dispatcher_entry=2,
                        source_serial=6,
                        pred_serial=11,
                        conditional_target=3,
                        fallthrough_target=10,
                    ),
                    BadWhileLoopConditionalRedirect(
                        dispatcher_entry=2,
                        source_serial=1,
                        ref_block=12,
                        conditional_target=3,
                        fallthrough_target=4,
                    ),
                )
            )
        },
    )

    assert extract_bad_while_loop_edits(cfg) == (
        BadWhileLoopGotoRedirect(dispatcher_entry=2, from_serial=1, new_target=3),
        BadWhileLoopGotoConversion(dispatcher_entry=2, block_serial=6, goto_target=4),
        BadWhileLoopDuplicateRedirect(
            dispatcher_entry=2,
            source_serial=5,
            per_pred_targets=((8, 3), (9, 4)),
        ),
        BadWhileLoopConditionalDuplicate(
            dispatcher_entry=2,
            source_serial=6,
            pred_serial=11,
            conditional_target=3,
            fallthrough_target=10,
        ),
        BadWhileLoopConditionalRedirect(
            dispatcher_entry=2,
            source_serial=1,
            ref_block=12,
            conditional_target=3,
            fallthrough_target=4,
        ),
    )


def test_extract_bad_while_loop_follow_up_round_trips() -> None:
    cfg = FlowGraph(
        blocks={
            0: _block(0, (1,), (), start_ea=0x1000),
            1: _block(1, (2,), (0,), start_ea=0x1001),
            2: _block(2, (3, 4), (1, 5), block_type=4),
            3: _block(3, (), (2,), block_type=2),
            4: _block(4, (), (2,), block_type=2),
            5: _block(5, (2, 8), (), block_type=4, start_ea=0x1005),
            8: _block(8, (), (5,), block_type=2),
        },
        entry_serial=0,
        func_ea=0x1000,
        metadata={
            BAD_WHILE_LOOP_FOLLOW_UP_METADATA_KEY: serialize_bad_while_loop_follow_up(
                (
                    BadWhileLoopFollowUp(
                        dispatcher_entry=2,
                        from_serial=1,
                        category=BAD_WHILE_LOOP_INSERT_BLOCK,
                        reason="copied_side_effects",
                        target_serial=3,
                    ),
                    BadWhileLoopFollowUp(
                        dispatcher_entry=2,
                        from_serial=5,
                        category=BAD_WHILE_LOOP_CREATE_CONDITIONAL_REDIRECT,
                        reason="conditional_exit_with_loopback",
                        target_serial=3,
                        fallthrough_target=8,
                    ),
                )
            )
        },
    )

    assert extract_bad_while_loop_follow_up(cfg) == (
        BadWhileLoopFollowUp(
            dispatcher_entry=2,
            from_serial=1,
            category=BAD_WHILE_LOOP_INSERT_BLOCK,
            reason="copied_side_effects",
            target_serial=3,
        ),
        BadWhileLoopFollowUp(
            dispatcher_entry=2,
            from_serial=5,
            category=BAD_WHILE_LOOP_CREATE_CONDITIONAL_REDIRECT,
            reason="conditional_exit_with_loopback",
            target_serial=3,
            fallthrough_target=8,
        ),
    )


def test_collect_live_bad_while_loop_analysis_records_missing_emulation_target(
    monkeypatch,
) -> None:
    from d810.evaluator.hexrays_microcode import tracker as tracker_module
    from d810.optimizers.microcode.flow.flattening import (
        unflattener_badwhile_loop as legacy_module,
    )

    father = SimpleNamespace(
        serial=5,
        tail=SimpleNamespace(opcode=0x100),
        nsucc=lambda: 1,
    )
    dispatcher_entry_blk = SimpleNamespace(
        serial=2,
        predset=[5],
        nsucc=lambda: 0,
        succ=lambda _idx: (_ for _ in ()).throw(IndexError),
    )
    dispatcher_info = SimpleNamespace(
        entry_block=SimpleNamespace(
            blk=dispatcher_entry_blk,
            use_before_def_list=(),
        ),
        dispatcher_internal_blocks=[SimpleNamespace(serial=2)],
        emulate_dispatcher_with_father_history=lambda *_args, **_kwargs: (None, ()),
    )

    class FakeBadWhileLoop:
        def __init__(self) -> None:
            self.dispatcher_list = [dispatcher_info]
            self.mba = None

        def retrieve_all_dispatchers(self) -> None:
            return None

        def get_dispatcher_father_histories(self, *_args, **_kwargs):
            return ("history",)

        def check_if_histories_are_resolved(self, histories) -> bool:
            return bool(histories)

    mba = SimpleNamespace(
        maturity=1,
        get_mblock=lambda serial: father if serial == 5 else None,
    )

    monkeypatch.setattr(legacy_module, "BadWhileLoop", FakeBadWhileLoop)
    monkeypatch.setattr(
        tracker_module,
        "get_all_possibles_values",
        lambda *_args, **_kwargs: ((0x1234,),),
    )
    monkeypatch.setattr(
        tracker_module,
        "check_if_all_values_are_found",
        lambda *_args, **_kwargs: True,
    )

    analysis = collect_live_bad_while_loop_analysis(
        mba,
        allowed_maturities=(1,),
    )

    assert analysis.edits == ()
    assert analysis.follow_up == (
        BadWhileLoopFollowUp(
            dispatcher_entry=2,
            from_serial=5,
            category=BAD_WHILE_LOOP_UNSUPPORTED,
            reason="emulation_returned_no_target",
        ),
    )


def test_collect_live_bad_while_loop_analysis_captures_direct_side_effect_replay(
    monkeypatch,
) -> None:
    from d810.evaluator.hexrays_microcode import tracker as tracker_module
    from d810.optimizers.microcode.flow.flattening import (
        unflattener_badwhile_loop as legacy_module,
    )

    side_effect_insn = SimpleNamespace(opcode=0x77)
    father = SimpleNamespace(
        serial=5,
        tail=SimpleNamespace(opcode=0x100),
        nsucc=lambda: 1,
        succ=lambda _idx: 2,
    )
    dispatcher_entry_blk = SimpleNamespace(
        serial=2,
        predset=[5],
        nsucc=lambda: 0,
        succ=lambda _idx: (_ for _ in ()).throw(IndexError),
    )
    target_blk = SimpleNamespace(
        serial=7,
        tail=None,
        nsucc=lambda: 0,
    )
    dispatcher_info = SimpleNamespace(
        entry_block=SimpleNamespace(
            blk=dispatcher_entry_blk,
            use_before_def_list=(),
        ),
        dispatcher_internal_blocks=[SimpleNamespace(serial=2)],
        emulate_dispatcher_with_father_history=lambda *_args, **_kwargs: (
            target_blk,
            (side_effect_insn,),
        ),
    )

    class FakeBadWhileLoop:
        def __init__(self) -> None:
            self.dispatcher_list = [dispatcher_info]
            self.mba = None

        def retrieve_all_dispatchers(self) -> None:
            return None

        def get_dispatcher_father_histories(self, *_args, **_kwargs):
            return ("history",)

        def check_if_histories_are_resolved(self, histories) -> bool:
            return bool(histories)

        def _filter_dependency_safe_copies(self, _father, copied_side_effects):
            return tuple(copied_side_effects)

    captured: list[tuple[int, tuple[object, ...]]] = []

    def _capture(source_serial: int, instructions):
        captured.append((source_serial, tuple(instructions)))
        return _captured_body(source_serial)

    mba = SimpleNamespace(
        maturity=1,
        get_mblock=lambda serial: father if serial == 5 else None,
    )

    monkeypatch.setattr(legacy_module, "BadWhileLoop", FakeBadWhileLoop)
    monkeypatch.setattr(
        tracker_module,
        "get_all_possibles_values",
        lambda *_args, **_kwargs: ((0x1234,),),
    )
    monkeypatch.setattr(
        tracker_module,
        "check_if_all_values_are_found",
        lambda *_args, **_kwargs: True,
    )

    analysis = collect_live_bad_while_loop_analysis(
        mba,
        allowed_maturities=(1,),
        side_effect_capture=_capture,
    )

    assert captured == [(5, (side_effect_insn,))]
    assert analysis.replay_candidates
    assert analysis.replay_candidates[0].source_serial == 5
    assert analysis.replay_candidates[0].target_serial == 7
    assert analysis.replay_candidates[0].captured_body.payload == _captured_body(5).payload
    assert analysis.follow_up == (
        BadWhileLoopFollowUp(
            dispatcher_entry=2,
            from_serial=5,
            category=BAD_WHILE_LOOP_INSERT_BLOCK,
            reason="copied_side_effects",
            target_serial=7,
        ),
    )


def test_collect_live_bad_while_loop_analysis_rejects_direct_call_replay(
    monkeypatch,
) -> None:
    from d810.evaluator.hexrays_microcode import tracker as tracker_module
    from d810.optimizers.microcode.flow.flattening import (
        unflattener_badwhile_loop as legacy_module,
    )

    side_effect_insn = SimpleNamespace(opcode=0x77)
    father = SimpleNamespace(
        serial=5,
        tail=SimpleNamespace(opcode=0x100),
        nsucc=lambda: 1,
        succ=lambda _idx: 2,
    )
    dispatcher_entry_blk = SimpleNamespace(
        serial=2,
        predset=[5],
        nsucc=lambda: 0,
        succ=lambda _idx: (_ for _ in ()).throw(IndexError),
    )
    target_blk = SimpleNamespace(serial=7, tail=None, nsucc=lambda: 0)
    dispatcher_info = SimpleNamespace(
        entry_block=SimpleNamespace(
            blk=dispatcher_entry_blk,
            use_before_def_list=(),
        ),
        dispatcher_internal_blocks=[SimpleNamespace(serial=2)],
        emulate_dispatcher_with_father_history=lambda *_args, **_kwargs: (
            target_blk,
            (side_effect_insn,),
        ),
    )

    class FakeBadWhileLoop:
        def __init__(self) -> None:
            self.dispatcher_list = [dispatcher_info]
            self.mba = None

        def retrieve_all_dispatchers(self) -> None:
            return None

        def get_dispatcher_father_histories(self, *_args, **_kwargs):
            return ("history",)

        def check_if_histories_are_resolved(self, histories) -> bool:
            return bool(histories)

        def _filter_dependency_safe_copies(self, _father, copied_side_effects):
            return tuple(copied_side_effects)

    captured: list[tuple[int, tuple[object, ...]]] = []

    def _capture(source_serial: int, instructions):
        captured.append((source_serial, tuple(instructions)))
        return _captured_body(source_serial, contains_call=True)

    mba = SimpleNamespace(
        maturity=1,
        get_mblock=lambda serial: father if serial == 5 else None,
    )

    monkeypatch.setattr(legacy_module, "BadWhileLoop", FakeBadWhileLoop)
    monkeypatch.setattr(
        tracker_module,
        "get_all_possibles_values",
        lambda *_args, **_kwargs: ((0x1234,),),
    )
    monkeypatch.setattr(
        tracker_module,
        "check_if_all_values_are_found",
        lambda *_args, **_kwargs: True,
    )

    analysis = collect_live_bad_while_loop_analysis(
        mba,
        allowed_maturities=(1,),
        side_effect_capture=_capture,
    )

    assert captured == [(5, (side_effect_insn,))]
    assert analysis.replay_candidates == ()
    assert analysis.follow_up == (
        BadWhileLoopFollowUp(
            dispatcher_entry=2,
            from_serial=5,
            category=BAD_WHILE_LOOP_INSERT_BLOCK,
            reason="copied_side_effects_contains_call",
            target_serial=7,
        ),
    )


def test_collect_live_bad_while_loop_analysis_records_direct_dependency_diagnostic(
    monkeypatch,
) -> None:
    import ida_hexrays

    from d810.evaluator.hexrays_microcode import tracker as tracker_module
    from d810.optimizers.microcode.flow.flattening import (
        unflattener_badwhile_loop as legacy_module,
    )

    missing_stack = SimpleNamespace(
        t=ida_hexrays.mop_S,
        size=4,
        s=SimpleNamespace(off=0x7BC),
        dstr=lambda: "stk_7bc.4",
    )
    side_effect_insn = SimpleNamespace(
        opcode=0x77,
        ea=0x2000,
        display="mov stk_7bc.4, eax.4",
    )
    father = SimpleNamespace(
        serial=5,
        tail=SimpleNamespace(opcode=0x111),
        nsucc=lambda: 1,
        succ=lambda _idx: 2,
        predset=[4],
    )
    dispatcher_entry_blk = SimpleNamespace(
        serial=2,
        predset=[5],
        nsucc=lambda: 0,
        succ=lambda _idx: (_ for _ in ()).throw(IndexError),
    )
    target_blk = SimpleNamespace(serial=7, tail=None, nsucc=lambda: 0)
    dispatcher_info = SimpleNamespace(
        entry_block=SimpleNamespace(
            blk=dispatcher_entry_blk,
            use_before_def_list=(),
        ),
        dispatcher_internal_blocks=[SimpleNamespace(serial=2)],
        emulate_dispatcher_with_father_history=lambda *_args, **_kwargs: (
            target_blk,
            (side_effect_insn,),
        ),
    )

    class FakeBadWhileLoop:
        def __init__(self) -> None:
            self.dispatcher_list = [dispatcher_info]
            self.mba = None

        def retrieve_all_dispatchers(self) -> None:
            return None

        def get_dispatcher_father_histories(self, *_args, **_kwargs):
            return ("history",)

        def check_if_histories_are_resolved(self, histories) -> bool:
            return bool(histories)

        def _filter_dependency_safe_copies(self, *_args, **_kwargs):
            return ()

        def _collect_block_liveins_and_defs(self, _blk):
            return (), ()

        def _collect_instruction_uses_defs(self, _insn):
            return (missing_stack,), ()

    captured: list[tuple[int, tuple[object, ...]]] = []

    def _capture(source_serial: int, instructions):
        captured.append((source_serial, tuple(instructions)))
        return _captured_body(source_serial)

    mba = SimpleNamespace(
        maturity=1,
        get_mblock=lambda serial: father if serial == 5 else None,
    )

    monkeypatch.setattr(legacy_module, "BadWhileLoop", FakeBadWhileLoop)
    monkeypatch.setattr(
        tracker_module,
        "get_all_possibles_values",
        lambda *_args, **_kwargs: ((0x1234,),),
    )
    monkeypatch.setattr(
        tracker_module,
        "check_if_all_values_are_found",
        lambda *_args, **_kwargs: True,
    )

    analysis = collect_live_bad_while_loop_analysis(
        mba,
        allowed_maturities=(1,),
        side_effect_capture=_capture,
    )

    assert captured == []
    assert analysis.replay_candidates == ()
    assert analysis.follow_up == (
        BadWhileLoopFollowUp(
            dispatcher_entry=2,
            from_serial=5,
            category=BAD_WHILE_LOOP_INSERT_BLOCK,
            reason="copied_side_effects_not_dependency_safe",
            target_serial=7,
        ),
    )
    assert len(analysis.dependency_diagnostics) == 1
    diagnostic = analysis.dependency_diagnostics[0]
    assert diagnostic["dispatcher_entry"] == 2
    assert diagnostic["source_serial"] == 5
    assert diagnostic["target_serial"] == 7
    assert diagnostic["reason"] == "copied_side_effects_not_dependency_safe"
    assert diagnostic["raw_instruction_count"] == 1
    assert diagnostic["dependency_safe_instruction_count"] == 0
    assert diagnostic["final_bucket"] == "stack_external_or_no_reaching_def"
    copied = diagnostic["copied_instructions"][0]
    assert copied["accepted_by_current_filter"] is False
    assert copied["missing_uses"][0]["mop"]["stack"]["stkoff"] == 0x7BC


def test_collect_live_bad_while_loop_analysis_builds_conditional_redirect(
    monkeypatch,
) -> None:
    import ida_hexrays

    from d810.evaluator.hexrays_microcode import tracker as tracker_module
    from d810.optimizers.microcode.flow.flattening import (
        unflattener_badwhile_loop as legacy_module,
    )

    father = SimpleNamespace(
        serial=5,
        tail=SimpleNamespace(opcode=0x100),
        nsucc=lambda: 1,
        succ=lambda _idx: 2,
    )
    dispatcher_entry_blk = SimpleNamespace(
        serial=2,
        predset=[5],
        nsucc=lambda: 1,
        succ=lambda _idx: 12,
    )
    target_blk = SimpleNamespace(
        serial=12,
        tail=SimpleNamespace(opcode=0x200),
        nsucc=lambda: 2,
        succ=lambda idx: (3, 4)[idx],
    )
    dispatcher_info = SimpleNamespace(
        entry_block=SimpleNamespace(
            blk=dispatcher_entry_blk,
            use_before_def_list=(),
        ),
        dispatcher_internal_blocks=[SimpleNamespace(serial=2)],
        emulate_dispatcher_with_father_history=lambda *_args, **_kwargs: (
            target_blk,
            (),
        ),
    )

    class FakeBadWhileLoop:
        def __init__(self) -> None:
            self.dispatcher_list = [dispatcher_info]
            self.mba = None

        def retrieve_all_dispatchers(self) -> None:
            return None

        def get_dispatcher_father_histories(self, *_args, **_kwargs):
            return ("history",)

        def check_if_histories_are_resolved(self, histories) -> bool:
            return bool(histories)

        def _filter_dependency_safe_copies(self, *_args, **_kwargs):
            return ()

    mba = SimpleNamespace(
        maturity=1,
        get_mblock=lambda serial: father if serial == 5 else None,
    )

    monkeypatch.setattr(legacy_module, "BadWhileLoop", FakeBadWhileLoop)
    monkeypatch.setattr(ida_hexrays, "is_mcode_jcond", lambda _opcode: True)
    monkeypatch.setattr(
        tracker_module,
        "get_all_possibles_values",
        lambda *_args, **_kwargs: ((0x1234,),),
    )
    monkeypatch.setattr(
        tracker_module,
        "check_if_all_values_are_found",
        lambda *_args, **_kwargs: True,
    )

    analysis = collect_live_bad_while_loop_analysis(
        mba,
        allowed_maturities=(1,),
    )

    assert analysis.edits == (
        BadWhileLoopConditionalRedirect(
            dispatcher_entry=2,
            source_serial=5,
            ref_block=12,
            conditional_target=3,
            fallthrough_target=4,
            dispatcher_internal_serials=(2,),
            copied_side_effects_absent=True,
        ),
    )
    assert analysis.follow_up == ()


def test_collect_live_bad_while_loop_analysis_builds_conditional_duplicates(
    monkeypatch,
) -> None:
    from d810.evaluator.hexrays_microcode import tracker as tracker_module
    from d810.hexrays.ir import conditional_exit as conditional_exit_module
    from d810.optimizers.microcode.flow.flattening import (
        unflattener_badwhile_loop as legacy_module,
    )

    pred_left = SimpleNamespace(serial=8, nsucc=lambda: 1, succ=lambda _idx: 5)
    pred_right = SimpleNamespace(serial=9, nsucc=lambda: 1, succ=lambda _idx: 5)
    father = SimpleNamespace(
        serial=5,
        predset=[8, 9],
        nsucc=lambda: 2,
        succ=lambda idx: (2, 10)[idx],
        tail=SimpleNamespace(opcode=0x100),
    )
    dispatcher_entry_blk = SimpleNamespace(
        serial=2,
        predset=[5],
        nsucc=lambda: 0,
        succ=lambda _idx: (_ for _ in ()).throw(IndexError),
    )
    dispatcher_info = SimpleNamespace(
        entry_block=SimpleNamespace(
            blk=dispatcher_entry_blk,
            use_before_def_list=(),
        ),
        dispatcher_internal_blocks=[SimpleNamespace(serial=2)],
        mop_compared=object(),
        emulate_dispatcher_with_father_history=lambda *_args, **_kwargs: (
            SimpleNamespace(serial=12, nsucc=lambda: 0, tail=None),
            (),
        ),
    )

    class FakeBadWhileLoop:
        def __init__(self) -> None:
            self.dispatcher_list = [dispatcher_info]
            self.mba = None

        def retrieve_all_dispatchers(self) -> None:
            return None

        def get_dispatcher_father_histories(self, *_args, **_kwargs):
            return ("history",)

        def check_if_histories_are_resolved(self, histories) -> bool:
            return bool(histories)

        def _filter_dependency_safe_copies(self, *_args, **_kwargs):
            return ()

    mba = SimpleNamespace(
        maturity=1,
        get_mblock=lambda serial: {
            5: father,
            8: pred_left,
            9: pred_right,
        }.get(serial),
    )

    monkeypatch.setattr(legacy_module, "BadWhileLoop", FakeBadWhileLoop)
    monkeypatch.setattr(
        tracker_module,
        "get_all_possibles_values",
        lambda *_args, **_kwargs: ((0x1234,),),
    )
    monkeypatch.setattr(
        tracker_module,
        "check_if_all_values_are_found",
        lambda *_args, **_kwargs: True,
    )
    monkeypatch.setattr(
        conditional_exit_module,
        "resolve_loopback_target",
        lambda *_args, **_kwargs: (3, 0x55),
    )

    analysis = collect_live_bad_while_loop_analysis(
        mba,
        allowed_maturities=(1,),
    )

    assert analysis.edits == (
        BadWhileLoopConditionalDuplicate(
            dispatcher_entry=2,
            source_serial=5,
            pred_serial=8,
            conditional_target=3,
            fallthrough_target=10,
        ),
        BadWhileLoopConditionalDuplicate(
            dispatcher_entry=2,
            source_serial=5,
            pred_serial=9,
            conditional_target=3,
            fallthrough_target=10,
        ),
    )
    assert analysis.follow_up == ()


def test_bad_while_loop_strategy_plans_redirects_and_conversions() -> None:
    cfg = FlowGraph(
        blocks={
            0: _block(0, (1,), (), start_ea=0x1000),
            1: _block(1, (2,), (0,), start_ea=0x1001),
            2: _block(2, (3, 4), (1, 5), block_type=4),
            3: _block(3, (), (2,), block_type=2),
            4: _block(4, (), (2,), block_type=2),
            5: _block(5, (2, 8), (), block_type=4, start_ea=0x1005),
            8: _block(8, (), (5,), block_type=2),
        },
        entry_serial=0,
        func_ea=0x1000,
        metadata={
            BAD_WHILE_LOOP_EDITS_METADATA_KEY: [
                {
                    "kind": "redirect_goto",
                    "dispatcher_entry": 2,
                    "from_serial": 1,
                    "new_target": 3,
                },
                {
                    "kind": "convert_to_goto",
                    "dispatcher_entry": 2,
                    "block_serial": 5,
                    "goto_target": 4,
                },
            ]
        },
    )

    fragment = BadWhileLoopStrategy().plan(
        AnalysisSnapshot(mba=object(), flow_graph=cfg),
    )

    assert fragment is not None
    assert fragment.metadata["safeguard_min_required"] == 1
    assert fragment.ownership.blocks == frozenset({1, 5})
    assert fragment.ownership.edges == frozenset({(1, 2)})
    assert fragment.modifications == [
        RedirectGoto(from_serial=1, old_target=2, new_target=3),
        ConvertToGoto(block_serial=5, goto_target=4),
    ]


def test_bad_while_loop_strategy_plans_duplicate_and_redirect() -> None:
    cfg = FlowGraph(
        blocks={
            0: _block(0, (8, 9), (), block_type=4, start_ea=0x1000),
            2: _block(2, (3, 4), (5,), block_type=4, start_ea=0x1002),
            3: _block(3, (), (2, 5), block_type=2),
            4: _block(4, (), (2, 5), block_type=2),
            5: _block(5, (2,), (8, 9), start_ea=0x1005),
            8: _block(8, (5,), (0,), start_ea=0x1008),
            9: _block(9, (5,), (0,), start_ea=0x1009),
        },
        entry_serial=0,
        func_ea=0x1000,
        metadata={
            BAD_WHILE_LOOP_EDITS_METADATA_KEY: [
                {
                    "kind": "duplicate_and_redirect",
                    "dispatcher_entry": 2,
                    "source_serial": 5,
                    "per_pred_targets": [
                        {"pred_serial": 8, "target_serial": 3},
                        {"pred_serial": 9, "target_serial": 4},
                    ],
                }
            ]
        },
    )

    fragment = BadWhileLoopStrategy().plan(
        AnalysisSnapshot(mba=object(), flow_graph=cfg),
    )

    assert fragment is not None
    assert fragment.ownership.blocks == frozenset({5})
    assert fragment.ownership.edges == frozenset({(8, 5), (9, 5)})
    assert fragment.modifications == [
        DuplicateAndRedirect(
            source_serial=5,
            per_pred_targets=((8, 3), (9, 4)),
        )
    ]


def test_bad_while_loop_strategy_plans_side_effect_replay_candidate() -> None:
    replay_candidate = bad_while_loop_side_effect_replay_candidate(
        dispatcher_entry=2,
        source_serial=1,
        target_serial=3,
        captured_body=_captured_body(source_serial=1),
        dispatcher_internal_serials=(2,),
    )
    assert replay_candidate is not None
    cfg = FlowGraph(
        blocks={
            0: _block(0, (1,), (), start_ea=0x1000),
            1: _block(1, (2,), (0,), start_ea=0x1001),
            2: _block(2, (3, 4), (1,), block_type=4),
            3: _block(3, (), (2,), block_type=2),
            4: _block(4, (), (2,), block_type=2),
        },
        entry_serial=0,
        func_ea=0x1000,
        metadata={
            CLEANUP_SIDE_EFFECT_REPLAY_METADATA_KEY: (replay_candidate,),
        },
    )

    fragment = BadWhileLoopStrategy().plan(
        AnalysisSnapshot(mba=object(), flow_graph=cfg),
    )

    assert fragment is not None
    assert fragment.ownership.blocks == frozenset({1})
    assert fragment.ownership.edges == frozenset({(1, 2)})
    assert fragment.modifications == [
        InsertBlock(
            pred_serial=1,
            succ_serial=3,
            old_target_serial=2,
            captured_body=replay_candidate.captured_body,
        )
    ]


def test_bad_while_loop_strategy_plans_conditional_duplicates() -> None:
    cfg = FlowGraph(
        blocks={
            0: _block(0, (8, 9), (), block_type=4, start_ea=0x1000),
            2: _block(2, (3, 4), (6,), block_type=4, start_ea=0x1002),
            3: _block(3, (), (2, 6), block_type=2),
            4: _block(4, (), (2,), block_type=2),
            6: _block(6, (2, 4), (8, 9), block_type=4, start_ea=0x1006),
            8: _block(8, (6,), (0,), start_ea=0x1008),
            9: _block(9, (6,), (0,), start_ea=0x1009),
        },
        entry_serial=0,
        func_ea=0x1000,
        metadata={
            BAD_WHILE_LOOP_EDITS_METADATA_KEY: [
                {
                    "kind": "duplicate_conditional_redirect",
                    "dispatcher_entry": 2,
                    "source_serial": 6,
                    "pred_serial": 8,
                    "conditional_target": 3,
                    "fallthrough_target": 4,
                },
                {
                    "kind": "duplicate_conditional_redirect",
                    "dispatcher_entry": 2,
                    "source_serial": 6,
                    "pred_serial": 9,
                    "conditional_target": 3,
                    "fallthrough_target": 4,
                },
            ]
        },
    )

    fragment = BadWhileLoopStrategy().plan(
        AnalysisSnapshot(mba=object(), flow_graph=cfg),
    )

    assert fragment is not None
    assert fragment.ownership.blocks == frozenset({6})
    assert fragment.ownership.edges == frozenset({(8, 6), (9, 6)})
    assert fragment.modifications == [
        DuplicateBlock(
            source_block=6,
            target_block=None,
            pred_serial=8,
            conditional_target=3,
            fallthrough_target=4,
        ),
        DuplicateBlock(
            source_block=6,
            target_block=None,
            pred_serial=9,
            conditional_target=3,
            fallthrough_target=4,
        ),
    ]


def test_bad_while_loop_strategy_plans_create_conditional_redirect() -> None:
    cfg = FlowGraph(
        blocks={
            0: _block(0, (1,), (), start_ea=0x1000),
            1: _block(1, (2,), (0,), start_ea=0x1001),
            2: _block(2, (12,), (1,), block_type=4, start_ea=0x1002),
            3: _block(3, (), (12,), block_type=2),
            4: _block(4, (), (12,), block_type=2),
            12: _block(12, (3, 4), (2,), block_type=4, start_ea=0x100C),
        },
        entry_serial=0,
        func_ea=0x1000,
        metadata={
            BAD_WHILE_LOOP_EDITS_METADATA_KEY: [
                {
                    "kind": "create_conditional_redirect",
                    "dispatcher_entry": 2,
                    "source_serial": 1,
                    "ref_block": 12,
                    "conditional_target": 3,
                    "fallthrough_target": 4,
                }
            ]
        },
    )

    fragment = BadWhileLoopStrategy().plan(
        AnalysisSnapshot(mba=object(), flow_graph=cfg),
    )

    assert fragment is not None
    assert fragment.ownership.blocks == frozenset({1})
    assert fragment.ownership.edges == frozenset({(1, 2)})
    assert fragment.modifications == [
        CreateConditionalRedirect(
            source_block=1,
            ref_block=12,
            conditional_target=3,
            fallthrough_target=4,
            old_target_serial=2,
        )
    ]


def test_bad_while_loop_strategy_rejects_conditional_duplicate_without_dispatcher_edge() -> None:
    cfg = FlowGraph(
        blocks={
            0: _block(0, (7,), (), start_ea=0x1000),
            2: _block(2, (3, 4), (), block_type=4, start_ea=0x1002),
            3: _block(3, (), (2, 6), block_type=2),
            4: _block(4, (), (2, 6), block_type=2),
            6: _block(6, (3, 4), (7,), block_type=4, start_ea=0x1006),
            7: _block(7, (6,), (0,), start_ea=0x1007),
        },
        entry_serial=0,
        func_ea=0x1000,
        metadata={
            BAD_WHILE_LOOP_EDITS_METADATA_KEY: [
                {
                    "kind": "duplicate_conditional_redirect",
                    "dispatcher_entry": 2,
                    "source_serial": 6,
                    "pred_serial": 7,
                    "conditional_target": 3,
                    "fallthrough_target": 4,
                }
            ]
        },
    )

    assert extract_bad_while_loop_edits(cfg) == ()
    assert BadWhileLoopStrategy().plan(
        AnalysisSnapshot(mba=object(), flow_graph=cfg),
    ) is None


def test_bad_while_loop_strategy_drops_invalid_metadata() -> None:
    cfg = FlowGraph(
        blocks={
            0: _block(0, (1,), (), start_ea=0x1000),
            1: _block(1, (9,), (0,), start_ea=0x1001),
            2: _block(2, (3, 4), (5,), block_type=4),
            3: _block(3, (), (2,), block_type=2),
            4: _block(4, (), (2,), block_type=2),
            5: _block(5, (2,), (), block_type=1, start_ea=0x1005),
        },
        entry_serial=0,
        func_ea=0x1000,
        metadata={
            BAD_WHILE_LOOP_EDITS_METADATA_KEY: [
                {
                    "kind": "redirect_goto",
                    "dispatcher_entry": 2,
                    "from_serial": 1,
                    "new_target": 3,
                },
                {
                    "kind": "convert_to_goto",
                    "dispatcher_entry": 2,
                    "block_serial": 5,
                    "goto_target": 99,
                },
                {
                    "kind": "redirect_goto",
                    "dispatcher_entry": 2,
                    "from_serial": 5,
                    "new_target": 5,
                },
                {
                    "kind": "duplicate_and_redirect",
                    "dispatcher_entry": 2,
                    "source_serial": 5,
                    "per_pred_targets": [
                        {"pred_serial": 1, "target_serial": 3},
                        {"pred_serial": 5, "target_serial": 4},
                    ],
                },
            ]
        },
    )

    assert extract_bad_while_loop_edits(cfg) == ()
    assert BadWhileLoopStrategy().plan(
        AnalysisSnapshot(mba=object(), flow_graph=cfg),
    ) is None


def test_build_bad_while_loop_modifications_emits_expected_shapes() -> None:
    modifications = build_bad_while_loop_modifications(
        (
            BadWhileLoopGotoRedirect(dispatcher_entry=2, from_serial=1, new_target=3),
            BadWhileLoopGotoConversion(dispatcher_entry=2, block_serial=5, goto_target=4),
            BadWhileLoopDuplicateRedirect(
                dispatcher_entry=2,
                source_serial=6,
                per_pred_targets=((7, 3), (8, 4)),
            ),
            BadWhileLoopConditionalDuplicate(
                dispatcher_entry=2,
                source_serial=9,
                pred_serial=10,
                conditional_target=3,
                fallthrough_target=4,
            ),
            BadWhileLoopConditionalRedirect(
                dispatcher_entry=2,
                source_serial=11,
                ref_block=12,
                conditional_target=3,
                fallthrough_target=4,
            ),
        )
    )

    assert modifications == [
        RedirectGoto(from_serial=1, old_target=2, new_target=3),
        ConvertToGoto(block_serial=5, goto_target=4),
        DuplicateAndRedirect(source_serial=6, per_pred_targets=((7, 3), (8, 4))),
        DuplicateBlock(
            source_block=9,
            target_block=None,
            pred_serial=10,
            conditional_target=3,
            fallthrough_target=4,
        ),
        CreateConditionalRedirect(
            source_block=11,
            ref_block=12,
            conditional_target=3,
            fallthrough_target=4,
            old_target_serial=2,
        ),
    ]


def test_build_bad_while_loop_modifications_rejects_unknown_edit_shape() -> None:
    class UnknownBadWhileLoopEdit:
        pass

    with pytest.raises(TypeError, match="Unsupported BadWhileLoop edit"):
        build_bad_while_loop_modifications((UnknownBadWhileLoopEdit(),))


def test_collect_live_bad_while_loop_analysis_builds_duplicate_and_redirect(
    monkeypatch,
) -> None:
    from d810.evaluator.hexrays_microcode import tracker as tracker_module
    from d810.optimizers.microcode.flow.flattening import (
        unflattener_badwhile_loop as legacy_module,
    )

    source_block = SimpleNamespace(
        serial=5,
        predset=[8, 9],
        nsucc=lambda: 1,
        succ=lambda _idx: 2,
        tail=SimpleNamespace(opcode=0x111),
    )
    dispatcher_entry_blk = SimpleNamespace(
        serial=2,
        predset=[5],
        nsucc=lambda: 0,
        succ=lambda _idx: (_ for _ in ()).throw(IndexError),
    )
    target_left = SimpleNamespace(serial=3, nsucc=lambda: 0, tail=None)
    target_right = SimpleNamespace(serial=4, nsucc=lambda: 0, tail=None)
    dispatcher_info = SimpleNamespace(
        entry_block=SimpleNamespace(
            blk=dispatcher_entry_blk,
            use_before_def_list=(),
        ),
        dispatcher_internal_blocks=[SimpleNamespace(serial=2)],
        emulate_dispatcher_with_father_history=lambda history, **_kwargs: (
            (target_left, ()) if history == "left" else (target_right, ())
        ),
    )

    class FakeBadWhileLoop:
        def __init__(self) -> None:
            self.dispatcher_list = [dispatcher_info]
            self.mba = None

        def retrieve_all_dispatchers(self) -> None:
            return None

        def get_dispatcher_father_histories(self, *_args, **_kwargs):
            return ["left", "right"]

        def check_if_histories_are_resolved(self, histories) -> bool:
            return bool(histories)

        def _filter_dependency_safe_copies(self, *_args, **_kwargs):
            return ()

    mba = SimpleNamespace(
        maturity=1,
        get_mblock=lambda serial: source_block if serial == 5 else None,
    )

    monkeypatch.setattr(legacy_module, "BadWhileLoop", FakeBadWhileLoop)
    monkeypatch.setattr(
        tracker_module,
        "get_block_with_multiple_predecessors",
        lambda histories: (
            source_block,
            {8: ["left"], 9: ["right"]},
        ),
    )
    monkeypatch.setattr(
        tracker_module,
        "get_all_possibles_values",
        lambda histories, *_args, **_kwargs: (
            ((0x10,), (0x20,))
            if list(histories) == ["left", "right"]
            else ((0x10,),)
            if list(histories) == ["left"]
            else ((0x20,),)
        ),
    )
    monkeypatch.setattr(
        tracker_module,
        "check_if_all_values_are_found",
        lambda *_args, **_kwargs: True,
    )

    analysis = collect_live_bad_while_loop_analysis(
        mba,
        allowed_maturities=(1,),
    )

    assert analysis.edits == (
        BadWhileLoopDuplicateRedirect(
            dispatcher_entry=2,
            source_serial=5,
            per_pred_targets=((8, 3), (9, 4)),
        ),
    )
    assert analysis.follow_up == ()


def test_collect_live_bad_while_loop_analysis_captures_duplicate_group_replay_live(
    monkeypatch,
) -> None:
    from d810.evaluator.hexrays_microcode import tracker as tracker_module
    from d810.optimizers.microcode.flow.flattening import (
        unflattener_badwhile_loop as legacy_module,
    )

    source_block = SimpleNamespace(
        serial=5,
        predset=[8, 9],
        nsucc=lambda: 1,
        succ=lambda _idx: 2,
        tail=SimpleNamespace(opcode=0x111),
    )
    dispatcher_entry_blk = SimpleNamespace(
        serial=2,
        predset=[5],
        nsucc=lambda: 0,
        succ=lambda _idx: (_ for _ in ()).throw(IndexError),
    )
    target_left = SimpleNamespace(serial=3, nsucc=lambda: 0, tail=None)
    target_right = SimpleNamespace(serial=4, nsucc=lambda: 0, tail=None)
    left_insn = SimpleNamespace(opcode=0x77)
    right_insn = SimpleNamespace(opcode=0x78)
    dispatcher_info = SimpleNamespace(
        entry_block=SimpleNamespace(
            blk=dispatcher_entry_blk,
            use_before_def_list=(),
        ),
        dispatcher_internal_blocks=[SimpleNamespace(serial=2)],
        emulate_dispatcher_with_father_history=lambda history, **_kwargs: (
            (target_left, (left_insn,))
            if history == "left"
            else (target_right, (right_insn,))
        ),
    )

    class FakeBadWhileLoop:
        def __init__(self) -> None:
            self.dispatcher_list = [dispatcher_info]
            self.mba = None

        def retrieve_all_dispatchers(self) -> None:
            return None

        def get_dispatcher_father_histories(self, *_args, **_kwargs):
            return ["left", "right"]

        def check_if_histories_are_resolved(self, histories) -> bool:
            return bool(histories)

        def _filter_dependency_safe_copies(self, _source, copied_side_effects):
            return tuple(copied_side_effects)

    captured: list[tuple[int, tuple[object, ...]]] = []

    def _capture(source_serial: int, instructions):
        captured.append((source_serial, tuple(instructions)))
        return _captured_body(source_serial)

    mba = SimpleNamespace(
        maturity=1,
        get_mblock=lambda serial: source_block if serial == 5 else None,
    )

    monkeypatch.setattr(legacy_module, "BadWhileLoop", FakeBadWhileLoop)
    monkeypatch.setattr(
        tracker_module,
        "get_block_with_multiple_predecessors",
        lambda histories: (
            source_block,
            {8: ["left"], 9: ["right"]},
        ),
    )
    monkeypatch.setattr(
        tracker_module,
        "get_all_possibles_values",
        lambda histories, *_args, **_kwargs: (
            ((0x10,), (0x20,))
            if list(histories) == ["left", "right"]
            else ((0x10,),)
            if list(histories) == ["left"]
            else ((0x20,),)
        ),
    )
    monkeypatch.setattr(
        tracker_module,
        "check_if_all_values_are_found",
        lambda *_args, **_kwargs: True,
    )

    analysis = collect_live_bad_while_loop_analysis(
        mba,
        allowed_maturities=(1,),
        side_effect_capture=_capture,
    )

    assert captured == [(5, (left_insn,)), (5, (right_insn,))]
    assert analysis.edits == ()
    assert len(analysis.duplicate_replay_candidates) == 1
    candidate = analysis.duplicate_replay_candidates[0]
    assert [
        (row.pred_serial, row.target_serial)
        for row in candidate.per_pred_replays
    ] == [(8, 3), (9, 4)]
    assert analysis.follow_up == (
        BadWhileLoopFollowUp(
            dispatcher_entry=2,
            from_serial=5,
            category=BAD_WHILE_LOOP_DUPLICATE_AND_REDIRECT,
            reason="duplicate_group_copied_side_effects",
            target_serial=3,
        ),
    )


def test_collect_live_bad_while_loop_analysis_rejects_duplicate_group_call_replay(
    monkeypatch,
) -> None:
    from d810.evaluator.hexrays_microcode import tracker as tracker_module
    from d810.optimizers.microcode.flow.flattening import (
        unflattener_badwhile_loop as legacy_module,
    )

    source_block = SimpleNamespace(
        serial=5,
        predset=[8, 9],
        nsucc=lambda: 1,
        succ=lambda _idx: 2,
        tail=SimpleNamespace(opcode=0x111),
    )
    dispatcher_entry_blk = SimpleNamespace(
        serial=2,
        predset=[5],
        nsucc=lambda: 0,
        succ=lambda _idx: (_ for _ in ()).throw(IndexError),
    )
    target_left = SimpleNamespace(serial=3, nsucc=lambda: 0, tail=None)
    target_right = SimpleNamespace(serial=4, nsucc=lambda: 0, tail=None)
    left_insn = SimpleNamespace(opcode=0x77)
    right_insn = SimpleNamespace(opcode=0x78)
    dispatcher_info = SimpleNamespace(
        entry_block=SimpleNamespace(
            blk=dispatcher_entry_blk,
            use_before_def_list=(),
        ),
        dispatcher_internal_blocks=[SimpleNamespace(serial=2)],
        emulate_dispatcher_with_father_history=lambda history, **_kwargs: (
            (target_left, (left_insn,))
            if history == "left"
            else (target_right, (right_insn,))
        ),
    )

    class FakeBadWhileLoop:
        def __init__(self) -> None:
            self.dispatcher_list = [dispatcher_info]
            self.mba = None

        def retrieve_all_dispatchers(self) -> None:
            return None

        def get_dispatcher_father_histories(self, *_args, **_kwargs):
            return ["left", "right"]

        def check_if_histories_are_resolved(self, histories) -> bool:
            return bool(histories)

        def _filter_dependency_safe_copies(self, _source, copied_side_effects):
            return tuple(copied_side_effects)

    captured: list[tuple[int, tuple[object, ...]]] = []

    def _capture(source_serial: int, instructions):
        captured_instructions = tuple(instructions)
        captured.append((source_serial, captured_instructions))
        return _captured_body(
            source_serial,
            contains_call=captured_instructions == (right_insn,),
        )

    mba = SimpleNamespace(
        maturity=1,
        get_mblock=lambda serial: source_block if serial == 5 else None,
    )

    monkeypatch.setattr(legacy_module, "BadWhileLoop", FakeBadWhileLoop)
    monkeypatch.setattr(
        tracker_module,
        "get_block_with_multiple_predecessors",
        lambda histories: (
            source_block,
            {8: ["left"], 9: ["right"]},
        ),
    )
    monkeypatch.setattr(
        tracker_module,
        "get_all_possibles_values",
        lambda histories, *_args, **_kwargs: (
            ((0x10,), (0x20,))
            if list(histories) == ["left", "right"]
            else ((0x10,),)
            if list(histories) == ["left"]
            else ((0x20,),)
        ),
    )
    monkeypatch.setattr(
        tracker_module,
        "check_if_all_values_are_found",
        lambda *_args, **_kwargs: True,
    )

    analysis = collect_live_bad_while_loop_analysis(
        mba,
        allowed_maturities=(1,),
        side_effect_capture=_capture,
    )

    assert captured == [(5, (left_insn,)), (5, (right_insn,))]
    assert analysis.edits == ()
    assert analysis.duplicate_replay_candidates == ()
    assert analysis.follow_up == (
        BadWhileLoopFollowUp(
            dispatcher_entry=2,
            from_serial=5,
            category=BAD_WHILE_LOOP_DUPLICATE_AND_REDIRECT,
            reason="duplicate_group_copied_side_effects_contains_call",
            target_serial=4,
        ),
    )


def test_collect_live_bad_while_loop_analysis_records_duplicate_dependency_diagnostic(
    monkeypatch,
) -> None:
    import ida_hexrays

    from d810.evaluator.hexrays_microcode import tracker as tracker_module
    from d810.optimizers.microcode.flow.flattening import (
        unflattener_badwhile_loop as legacy_module,
    )

    missing_reg = SimpleNamespace(
        t=ida_hexrays.mop_r,
        size=4,
        r=3,
        dstr=lambda: "r3.4",
    )
    source_block = SimpleNamespace(
        serial=5,
        predset=[8, 9],
        nsucc=lambda: 1,
        succ=lambda _idx: 2,
        tail=SimpleNamespace(opcode=0x111),
    )
    dispatcher_entry_blk = SimpleNamespace(
        serial=2,
        predset=[5],
        nsucc=lambda: 0,
        succ=lambda _idx: (_ for _ in ()).throw(IndexError),
    )
    target_left = SimpleNamespace(serial=3, nsucc=lambda: 0, tail=None)
    target_right = SimpleNamespace(serial=4, nsucc=lambda: 0, tail=None)
    left_insn = SimpleNamespace(opcode=0x77, ea=0x2001, display="mov r3.4, eax.4")
    right_insn = SimpleNamespace(opcode=0x78, ea=0x2002, display="mov r3.4, ecx.4")
    dispatcher_info = SimpleNamespace(
        entry_block=SimpleNamespace(
            blk=dispatcher_entry_blk,
            use_before_def_list=(),
        ),
        dispatcher_internal_blocks=[SimpleNamespace(serial=2)],
        emulate_dispatcher_with_father_history=lambda history, **_kwargs: (
            (target_left, (left_insn,))
            if history == "left"
            else (target_right, (right_insn,))
        ),
    )

    class FakeBadWhileLoop:
        def __init__(self) -> None:
            self.dispatcher_list = [dispatcher_info]
            self.mba = None

        def retrieve_all_dispatchers(self) -> None:
            return None

        def get_dispatcher_father_histories(self, *_args, **_kwargs):
            return ["left", "right"]

        def check_if_histories_are_resolved(self, histories) -> bool:
            return bool(histories)

        def _filter_dependency_safe_copies(self, *_args, **_kwargs):
            return ()

        def _collect_block_liveins_and_defs(self, _blk):
            return (), ()

        def _collect_instruction_uses_defs(self, _insn):
            return (missing_reg,), ()

    mba = SimpleNamespace(
        maturity=1,
        get_mblock=lambda serial: source_block if serial == 5 else None,
    )

    monkeypatch.setattr(legacy_module, "BadWhileLoop", FakeBadWhileLoop)
    monkeypatch.setattr(
        tracker_module,
        "get_block_with_multiple_predecessors",
        lambda histories: (
            source_block,
            {8: ["left"], 9: ["right"]},
        ),
    )
    monkeypatch.setattr(
        tracker_module,
        "get_all_possibles_values",
        lambda histories, *_args, **_kwargs: (
            ((0x10,), (0x20,))
            if list(histories) == ["left", "right"]
            else ((0x10,),)
            if list(histories) == ["left"]
            else ((0x20,),)
        ),
    )
    monkeypatch.setattr(
        tracker_module,
        "check_if_all_values_are_found",
        lambda *_args, **_kwargs: True,
    )

    analysis = collect_live_bad_while_loop_analysis(
        mba,
        allowed_maturities=(1,),
    )

    assert analysis.edits == ()
    assert analysis.duplicate_replay_candidates == ()
    assert analysis.follow_up == (
        BadWhileLoopFollowUp(
            dispatcher_entry=2,
            from_serial=5,
            category=BAD_WHILE_LOOP_DUPLICATE_AND_REDIRECT,
            reason="duplicate_group_copied_side_effects_not_dependency_safe",
            target_serial=3,
        ),
    )
    assert len(analysis.dependency_diagnostics) == 1
    diagnostic = analysis.dependency_diagnostics[0]
    assert diagnostic["category"] == BAD_WHILE_LOOP_DUPLICATE_AND_REDIRECT
    assert diagnostic["reason"] == (
        "duplicate_group_copied_side_effects_not_dependency_safe"
    )
    assert diagnostic["source_serial"] == 5
    assert diagnostic["target_serial"] == 3
    assert diagnostic["final_bucket"] == "reg_or_lvar_needs_capture"

class _DiagnosticRule:
    def __init__(self, uses: tuple[object, ...]) -> None:
        self._uses = uses

    def _collect_block_liveins_and_defs(self, _blk):
        return (), ()

    def _collect_instruction_uses_defs(self, _insn):
        return self._uses, ()


class _DiagnosticDefinitionBackend:
    def __init__(
        self,
        sites: tuple[DefinitionSiteEvidence, ...] = (),
        sccp_value: object | None = None,
    ) -> None:
        self._sites = sites
        self._sccp_value = sccp_value

    def reaching_defs_for_stkvar(self, *_args, **_kwargs):
        return self._sites

    def run_sccp_overlay(self, _mba):
        return {"value": self._sccp_value}

    def lookup_sccp_stkvar(self, overlay, **_kwargs):
        return overlay["value"]


def _dependency_diagnostic_for(
    missing_mop: object,
    *,
    backend: _DiagnosticDefinitionBackend | None = None,
    opcode: int = 0x77,
    predset: tuple[int, ...] = (4, 6),
) -> dict[str, object]:
    source_blk = SimpleNamespace(serial=5, predset=list(predset))
    insn = SimpleNamespace(opcode=opcode, ea=0x2000, display="copied side effect")
    return build_bad_while_loop_dependency_diagnostic(
        mba=SimpleNamespace(),
        rule=_DiagnosticRule((missing_mop,)),
        source_blk=source_blk,
        dispatcher_entry=2,
        source_serial=5,
        target_serial=7,
        category=BAD_WHILE_LOOP_INSERT_BLOCK,
        reason="copied_side_effects_not_dependency_safe",
        copied_instructions=(insn,),
        dependency_safe_copies=(),
        definition_backend=backend or _DiagnosticDefinitionBackend(),
    )


def test_dependency_diagnostic_buckets_stack_unique_def_chain() -> None:
    import ida_hexrays

    missing_stack = SimpleNamespace(
        t=ida_hexrays.mop_S,
        size=4,
        s=SimpleNamespace(off=0x7BC),
        dstr=lambda: "stk_7bc.4",
    )
    diagnostic = _dependency_diagnostic_for(
        missing_stack,
        backend=_DiagnosticDefinitionBackend(
            (DefinitionSiteEvidence(block_serial=12, insn_ea=0x4010),),
            sccp_value=0x4C77464F,
        ),
    )

    assert diagnostic["final_bucket"] == "stack_unique_def_chain_capturable"
    missing_use = diagnostic["missing_uses"][0]
    assert missing_use["reaching_def_count"] == 1
    assert missing_use["sccp_value"] == 0x4C77464F
    assert missing_use["capture_status"] == "capturable"


def test_dependency_diagnostic_buckets_stack_ambiguous_defs() -> None:
    import ida_hexrays

    missing_stack = SimpleNamespace(
        t=ida_hexrays.mop_S,
        size=4,
        s=SimpleNamespace(off=0x7BC),
        dstr=lambda: "stk_7bc.4",
    )
    diagnostic = _dependency_diagnostic_for(
        missing_stack,
        backend=_DiagnosticDefinitionBackend(
            (
                DefinitionSiteEvidence(block_serial=12, insn_ea=0x4010),
                DefinitionSiteEvidence(block_serial=13, insn_ea=0x4020),
            ),
        ),
    )

    assert diagnostic["final_bucket"] == "stack_ambiguous_defs"
    assert diagnostic["missing_uses"][0]["capture_status"] == "ambiguous_defs"


def test_dependency_diagnostic_buckets_register_and_lvar_needs_capture() -> None:
    import ida_hexrays

    missing_reg = SimpleNamespace(
        t=ida_hexrays.mop_r,
        size=4,
        r=3,
        dstr=lambda: "r3.4",
    )
    reg_diagnostic = _dependency_diagnostic_for(missing_reg, predset=(4,))

    assert reg_diagnostic["final_bucket"] == "reg_single_pred_def"

    missing_lvar = SimpleNamespace(
        t=ida_hexrays.mop_l,
        size=4,
        l=SimpleNamespace(idx=2),
        dstr=lambda: "lv2.4",
    )
    lvar_diagnostic = _dependency_diagnostic_for(missing_lvar)

    assert lvar_diagnostic["final_bucket"] == "reg_or_lvar_needs_capture"


def test_dependency_diagnostic_buckets_memory_alias_unknown() -> None:
    import ida_hexrays

    missing_global = SimpleNamespace(
        t=ida_hexrays.mop_v,
        size=4,
        g=0x401000,
        dstr=lambda: "global_401000.4",
    )
    diagnostic = _dependency_diagnostic_for(missing_global)

    assert diagnostic["final_bucket"] == "memory_or_alias_unknown"
    assert diagnostic["missing_uses"][0]["capture_status"] == "alias_unknown"


def test_dependency_diagnostic_buckets_call_or_payload_invalid() -> None:
    import ida_hexrays

    missing_reg = SimpleNamespace(
        t=ida_hexrays.mop_r,
        size=4,
        r=3,
        dstr=lambda: "r3.4",
    )
    diagnostic = _dependency_diagnostic_for(
        missing_reg,
        opcode=ida_hexrays.m_call,
    )

    assert diagnostic["final_bucket"] == "call_or_payload_invalid"
