"""Runtime tests for the safe BadWhileLoop engine strategy subset."""
from __future__ import annotations

from types import SimpleNamespace

import pytest

from d810.ir.flowgraph import BlockSnapshot, FlowGraph, InsnSnapshot
from d810.transforms.graph_modification import (
    ConvertToGoto,
    CreateConditionalRedirect,
    DuplicateBlock,
    DuplicateReplayAndRedirect,
    InsertBlock,
    RedirectGoto,
)
from d810.transforms.materialization_payload import (
    CapturedBlockBody,
    CapturedBlockBodySummary,
)
from d810.evaluator.hexrays_microcode.definition_rescue_backend import (
    DefinitionSiteEvidence,
)
from d810.transforms.cleanup_evidence import (
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
    extract_bad_while_loop_edits,
    extract_bad_while_loop_follow_up,
    serialize_bad_while_loop_edits,
    serialize_bad_while_loop_follow_up,
)
from d810.backends.hexrays.evidence.bad_while_loop_dependency_diagnostics import (
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


class _DiagnosticDefinitionBackend:
    def __init__(
        self,
        reaching_defs: tuple[DefinitionSiteEvidence, ...] = (),
        *,
        sccp_value: object | None = None,
    ) -> None:
        self._reaching_defs = reaching_defs
        self._sccp_value = sccp_value

    def reaching_defs_for_stkvar(
        self,
        _mba: object,
        _block_serial: int,
        _stkoff: int,
        _size: int,
    ) -> tuple[DefinitionSiteEvidence, ...]:
        return self._reaching_defs

    def run_sccp_overlay(self, _mba: object) -> object:
        return object()

    def lookup_sccp_stkvar(
        self,
        _overlay: object,
        *,
        stkoff: int,
        size: int,
    ) -> object | None:
        return self._sccp_value


def _dependency_diagnostic_for(
    missing_uses: object,
    *,
    backend: _DiagnosticDefinitionBackend | None = None,
    predset: tuple[int, ...] = (),
    opcode: int = 0x77,
) -> dict[str, object]:
    if not isinstance(missing_uses, tuple):
        missing_uses = (missing_uses,)
    source_blk = SimpleNamespace(liveins=(), defs=(), predset=predset)
    copied_instruction = SimpleNamespace(
        opcode=opcode,
        ea=0x4010,
        uses=missing_uses,
        defs=(),
        dstr=lambda: "copy",
    )
    return build_bad_while_loop_dependency_diagnostic(
        mba=SimpleNamespace(),
        rule=SimpleNamespace(),
        source_blk=source_blk,
        dispatcher_entry=2,
        source_serial=5,
        target_serial=7,
        category="test",
        reason="missing dependency",
        copied_instructions=(copied_instruction,),
        dependency_safe_copies=(),
        definition_backend=backend or _DiagnosticDefinitionBackend(),
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


def test_bad_while_loop_strategy_defers_duplicate_and_redirect_without_replay_proof() -> None:
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

    assert fragment is None


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


def test_dependency_diagnostic_does_not_mark_mixed_stack_memory_capturable() -> None:
    import ida_hexrays

    missing_stack = SimpleNamespace(
        t=ida_hexrays.mop_S,
        size=4,
        s=SimpleNamespace(off=0x7BC),
        dstr=lambda: "stk_7bc.4",
    )
    missing_global = SimpleNamespace(
        t=ida_hexrays.mop_v,
        size=4,
        g=0x401000,
        dstr=lambda: "global_401000.4",
    )
    diagnostic = _dependency_diagnostic_for(
        (missing_stack, missing_global),
        backend=_DiagnosticDefinitionBackend(
            (DefinitionSiteEvidence(block_serial=12, insn_ea=0x4010),),
        ),
    )

    assert diagnostic["final_bucket"] == "memory_or_alias_unknown"
    assert [row["capture_status"] for row in diagnostic["missing_uses"]] == [
        "capturable",
        "alias_unknown",
    ]


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
