import sqlite3

from d810.analyses.control_flow.minimal_state_recovery import (
    StateWriteTransition,
    TransitionProof,
)
from d810.ir.flowgraph import (
    BlockSnapshot,
    FlowGraph,
    InsnKind,
    InsnSnapshot,
    MopSnapshot,
    OperandKind,
)
from tools.scripts.rhad_investigation.preopt_transition_manifest import (
    PreoptManifestBoundaryAbstentionReason,
    PreoptTransitionManifestRow,
    build_transition_manifest,
    load_transition_manifest,
    persist_transition_manifest,
    plan_preopt_manifest_boundaries,
    select_timed_replay_transition_manifest,
    select_replay_transition_manifest,
)


def _manifest_row(
    *,
    capture_index: int = 1,
    write_site_ea: int = 0x401020,
    next_state: int | None = 0xAABBCCDD,
    target_handler_ea: int | None = 0x402000,
    is_return: bool = False,
    trusted: bool = True,
    status: str = "resolved",
    proof_kind: str = "global_fold",
    via_block_ea: int | None = None,
) -> PreoptTransitionManifestRow:
    return PreoptTransitionManifestRow(
        capture_index=capture_index,
        source_block_serial=7,
        source_block_ea=write_site_ea,
        write_site_ea=write_site_ea,
        via_block_serial=None if via_block_ea is None else 8,
        via_block_ea=via_block_ea,
        next_state=next_state,
        target_handler_serial=(
            None if target_handler_ea is None else 9
        ),
        target_handler_ea=target_handler_ea,
        is_return=is_return,
        branch_arm=None,
        oracle_kind="abstract_fixpoint",
        proof_kind=proof_kind,
        trusted=trusted,
        status=status,
        reason=proof_kind,
    )


def _block(
    serial: int,
    start_ea: int,
    instruction_ea: int,
    *,
    state_register: int | None = None,
) -> BlockSnapshot:
    destination = (
        None
        if state_register is None
        else MopSnapshot(reg=state_register, kind=OperandKind.REGISTER)
    )
    return BlockSnapshot(
        serial=serial,
        block_type=1,
        succs=(),
        preds=(),
        flags=0,
        start_ea=start_ea,
        insn_snapshots=(
            InsnSnapshot(
                opcode=1,
                ea=instruction_ea,
                operands=(),
                d=destination,
                kind=InsnKind.MOV,
            ),
        ),
    )


def test_manifest_rebinds_imported_blocks_and_state_write_sites_to_native_eas() -> None:
    graph = FlowGraph(
        blocks={
            7: _block(7, 0xF0001000, 0xF0001010, state_register=20),
            9: _block(9, 0xF0002000, 0xF0002010),
        },
        entry_serial=7,
        func_ea=0x401000,
    )
    transitions = (
        StateWriteTransition(
            write_block=7,
            next_state=None,
            target_handler=None,
            is_return=True,
            branch_arm=None,
            proof=TransitionProof(
                oracle_kind="abstract_fixpoint",
                kind="unresolved",
                trusted=False,
                reason="state did not fold",
            ),
        ),
    )

    rows = build_transition_manifest(
        graph,
        transitions,
        instruction_origins={0xF0001010: 0x402010},
        state_var_reg=20,
        capture_index=3,
    )

    assert len(rows) == 1
    row = rows[0]
    assert row.source_block_serial == 7
    assert row.source_block_ea == 0x402010
    assert row.write_site_ea == 0x402010
    assert row.target_handler_serial is None
    assert row.target_handler_ea is None
    assert row.status == "unresolved"
    assert row.reason == "state did not fold"
    assert row.capture_index == 3


def test_manifest_persistence_keeps_every_block_serial_paired_with_an_ea(
    tmp_path,
) -> None:
    graph = FlowGraph(
        blocks={
            4: _block(4, 0x403000, 0x403004, state_register=20),
            8: _block(8, 0x404000, 0x404004),
        },
        entry_serial=4,
        func_ea=0x403000,
    )
    rows = build_transition_manifest(
        graph,
        (
            StateWriteTransition(
                write_block=4,
                next_state=0x12345678,
                target_handler=8,
                is_return=False,
                branch_arm=1,
                proof=TransitionProof(
                    oracle_kind="abstract_fixpoint",
                    kind="global_fold",
                    trusted=True,
                ),
            ),
        ),
        instruction_origins={},
        state_var_reg=20,
        capture_index=1,
    )
    database = tmp_path / "diag.sqlite3"

    persist_transition_manifest(database, rows)

    with sqlite3.connect(database) as connection:
        persisted = connection.execute(
            """
            SELECT source_block_serial, source_block_ea_hex,
                   target_handler_serial, target_handler_ea_hex,
                   write_site_ea_hex, status
            FROM preopt_transition_manifest
            """
        ).fetchone()
    assert persisted == (
        4,
        "0x403000",
        8,
        "0x404000",
        "0x403004",
        "resolved",
    )
    assert load_transition_manifest(database) == rows


def test_replay_planner_accepts_only_trusted_resolved_nonreturn_rows() -> None:
    plan = plan_preopt_manifest_boundaries(
        (
            _manifest_row(),
            _manifest_row(is_return=True),
            _manifest_row(
                write_site_ea=0x401030,
                trusted=False,
                status="unresolved",
                next_state=None,
                target_handler_ea=None,
            ),
        ),
        state_register=20,
    )

    assert len(plan.direct) == 1
    assert plan.direct[0].source_ea == 0x401020
    assert plan.direct[0].target_ea == 0x402000
    assert plan.direct[0].state_constant == 0xAABBCCDD
    assert plan.direct[0].state_register == 20
    assert plan.direct[0].requires_literal_state_write is False
    assert plan.direct[0].via_ea is None
    assert plan.abstentions == ()


def test_replay_planner_deduplicates_proofs_but_abstains_on_semantic_conflict() -> None:
    plan = plan_preopt_manifest_boundaries(
        (
            _manifest_row(proof_kind="global_fold"),
            _manifest_row(proof_kind="multi_entry_global_fold"),
            _manifest_row(
                write_site_ea=0x401040,
                next_state=1,
                target_handler_ea=0x403000,
            ),
            _manifest_row(
                write_site_ea=0x401040,
                next_state=2,
                target_handler_ea=0x404000,
            ),
        ),
        state_register=20,
    )

    assert tuple(row.source_ea for row in plan.direct) == (0x401020,)
    assert len(plan.abstentions) == 1
    assert plan.abstentions[0].source_ea == 0x401040
    assert (
        plan.abstentions[0].reason
        is PreoptManifestBoundaryAbstentionReason.CONFLICTING_TRANSITIONS
    )


def test_replay_planner_preserves_proven_via_block_anchor() -> None:
    plan = plan_preopt_manifest_boundaries(
        (_manifest_row(via_block_ea=0x401080),),
        state_register=20,
    )

    assert plan.direct[0].via_ea == 0x401080


def test_replay_capture_selection_prefers_trusted_resolved_nonreturn_coverage() -> None:
    unresolved_heavy = tuple(
        _manifest_row(
            capture_index=1,
            write_site_ea=0x401000 + index,
            trusted=False,
            status="unresolved",
            next_state=None,
            target_handler_ea=None,
        )
        for index in range(5)
    )
    replay_heavy = (
        _manifest_row(capture_index=2, write_site_ea=0x402010),
        _manifest_row(capture_index=2, write_site_ea=0x402020),
    )

    selected = select_replay_transition_manifest(
        (unresolved_heavy, replay_heavy)
    )

    assert selected == replay_heavy


def test_external_replay_waits_for_a_local_capture_timing_token() -> None:
    external = (_manifest_row(capture_index=7),)

    assert select_timed_replay_transition_manifest((), external) == ()


def test_external_replay_replaces_contents_only_after_local_capture() -> None:
    local = ((_manifest_row(capture_index=1),),)
    external = (_manifest_row(capture_index=7),)

    assert select_timed_replay_transition_manifest(local, external) == external


def test_timed_replay_falls_back_to_best_local_capture() -> None:
    weaker = (
        _manifest_row(
            capture_index=1,
            trusted=False,
            status="unresolved",
            next_state=None,
            target_handler_ea=None,
        ),
    )
    stronger = (_manifest_row(capture_index=2),)

    assert (
        select_timed_replay_transition_manifest(
            (weaker, stronger),
            (),
        )
        == stronger
    )
