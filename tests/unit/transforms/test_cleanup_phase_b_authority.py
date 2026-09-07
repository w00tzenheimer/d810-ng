"""Cleanup diagnostic provenance must never grant from the DAG arbiter."""

from types import SimpleNamespace
from dataclasses import replace

from d810.ir.flowgraph import BlockSnapshot, FlowGraph
from d810.transforms.cleanup_evidence import (
    CleanupProofState,
    build_bad_while_loop_follow_up_proofs,
    reclassify_bad_while_loop_follow_ups,
)


def _cfg():
    return FlowGraph(
        blocks={
            1: BlockSnapshot(
                serial=1,
                start_ea=0x1010,
                block_type=1,
                flags=0,
                insn_snapshots=(),
                preds=(),
                succs=(2,),
            ),
            2: BlockSnapshot(
                serial=2,
                start_ea=0x1020,
                block_type=1,
                flags=0,
                insn_snapshots=(),
                preds=(1,),
                succs=(3,),
            ),
            3: BlockSnapshot(
                serial=3,
                start_ea=0x1030,
                block_type=1,
                flags=0,
                insn_snapshots=(),
                succs=(),
                preds=(2,),
            ),
        },
        entry_serial=1,
        func_ea=0x1000,
    )


def _row():
    return dict(
        dispatcher_entry=2,
        from_serial=1,
        category="duplicate_and_redirect",
        reason="unresolved_histories",
        target_serial=3,
    )


def _dag():
    return SimpleNamespace(
        canonical_target_for=lambda *_: 3, conflicts_for_source=lambda *_: ()
    )


def test_dag_only_target_cannot_promote_cleanup():
    rows = reclassify_bad_while_loop_follow_ups((_row(),), _cfg(), dag_authority=_dag())
    assert rows[0].proof_state is not CleanupProofState.PROVEN


def test_dag_only_target_cannot_mint_follow_up_proof():
    assert build_bad_while_loop_follow_up_proofs(
        _cfg(), (_row(),), dag_authority=_dag()
    ) == ((), ())


def test_follow_up_proof_cannot_replay_at_same_serial_in_another_function():
    cfg = _cfg()
    proofs, _ = build_bad_while_loop_follow_up_proofs(
        cfg,
        (_row(),),
        range_intervals=(SimpleNamespace(lo=0, hi=10, target_block=3),),
        state_constants_by_source={1: 5},
    )
    assert len(proofs) == 1
    rows = reclassify_bad_while_loop_follow_ups(
        (_row(),),
        replace(cfg, func_ea=0x2000),
        target_proofs=proofs,
    )
    assert rows[0].proof_state is not CleanupProofState.PROVEN


def test_follow_up_proof_cannot_replay_after_native_anchor_changes():
    cfg = _cfg()
    proofs, _ = build_bad_while_loop_follow_up_proofs(
        cfg,
        (_row(),),
        range_intervals=(SimpleNamespace(lo=0, hi=10, target_block=3),),
        state_constants_by_source={1: 5},
    )
    blocks = dict(cfg.blocks)
    blocks[1] = replace(blocks[1], start_ea=0x3000)
    rows = reclassify_bad_while_loop_follow_ups(
        (_row(),),
        replace(cfg, blocks=blocks),
        target_proofs=proofs,
    )
    assert rows[0].proof_state is not CleanupProofState.PROVEN
