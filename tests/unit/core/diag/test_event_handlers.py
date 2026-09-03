"Tests for the SQLite event handlers (Phase 3).\n\nVerify that with handlers installed on the bus and a connected diag DB,\nthe observation events from preanalysis/cfg/hexrays emit rows in the expected\ntables. The mapping ``SnapshotRef.key -> snapshots.id`` is driven by\nthe :class:`CaptureMbaSnapshotRequested` handler.\n"

from __future__ import annotations
from d810.core.diag import create_diag_database

import json
import sqlite3
from unittest.mock import patch

import pytest

from d810.core.observability_cfg import (
    observe_cfg_provenance,
    observe_cfg_provenance_latest,
    observe_watch_block_transition,
)
from d810.core.diag.event_handlers import (
    install_diag_event_handlers,
    is_installed,
    uninstall_diag_event_handlers,
)
from d810.core.observability import (
    SnapshotRef,
    emit,
    has_subscribers,
    new_snapshot_key,
    reset_diagnostic_bus,
)
from d810.core.observability_events import (
    CaptureMbaSnapshotRequested,
    DagObserved,
    DiagnosticSessionObserved,
    FrontendNormalizationPlanIntentObserved,
    InputIdentityResolutionObserved,
    ModificationsObserved,
    MutationPlanObserved,
    EmulatorGapObserved,
    MutationReceiptObserved,
    PassContractEvidencePublished,
    SemanticOutputVerifiedObserved,
    StateWriteResolutionObserved,
    HostDecompilationOutcome,
    HostDecompilationOutcomeKind,
    HostDecompilationOutcomeObserved,
    Z3PredicateProofObserved,
)
from d810.core.z3_proof import Z3ProofAbstentionReason, Z3ProofStatus
import d810.core.observability_events as observability_events
from d810.core.observability_models import (
    BlockSnapshot,
    DagEdge,
    DagNode,
    Modification,
)
from d810.core.observability_preanalysis import (
    observe_branch_witness_decisions,
    observe_branch_ownership_proofs,
    observe_exit_path_shortcut_decisions,
    observe_fact_observation,
    observe_dag,
    observe_modifications,
    observe_reachability,
    observe_state_dispatcher_rows,
    observe_state_transition_dispatch_resolutions,
)
from d810.analyses.value_flow.observation import FactObservation
from d810.transforms.cfg_transaction import TransactionAttemptId
from d810.transforms.unflatten_authority import model as authority_model
from d810.transforms.unflatten_authority.diagnostics import phase_observation
from d810.transforms.unflatten_authority.ids import authority_id


def request_capture_mba_snapshot(
    *,
    blocks,
    label: str,
    func_ea: int,
    maturity: str,
    phase: str,
    maturity_json: str | None = None,
) -> SnapshotRef | None:
    """Test-side request_capture wrapper that does not import hexrays.

    Mirrors what the real hexrays.observability helper does so the
    handler tests verify the end-to-end shape without crossing the
    unit-tests-no-hexrays boundary.
    """
    if not has_subscribers(CaptureMbaSnapshotRequested):
        return None
    snap = SnapshotRef(
        key=new_snapshot_key(),
        func_ea=int(func_ea),
        label=label,
        maturity=maturity,
        phase=phase,
        maturity_json=maturity_json,
    )
    emit(CaptureMbaSnapshotRequested(snapshot=snap, blocks=tuple(blocks)))
    return snap


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def fake_conn():
    """In-memory SQLite with the diag schema populated."""
    conn = create_diag_database(":memory:").connection()
    return conn


@pytest.fixture(autouse=True)
def _bus_and_handlers(fake_conn):
    """Install handlers with the fake conn standing in for get_diag_db()."""
    reset_diagnostic_bus()

    def fake_get_diag_db(_func_ea: int = 0, *_, **__):
        return fake_conn

    with patch(
        "d810.core.diag.event_handlers.get_diag_conn",
        new=fake_get_diag_db,
    ):
        install_diag_event_handlers()
        yield
        uninstall_diag_event_handlers()
    reset_diagnostic_bus()


def _make_snap_blocks() -> list[BlockSnapshot]:
    return [
        BlockSnapshot(
            serial=0,
            block_type=1,
            type_name="BLT_NWAY",
            start_ea=0x100,
        ),
    ]


def test_host_decompilation_outcome_value_objects_validate_contract():
    rendered = HostDecompilationOutcome(
        kind=HostDecompilationOutcomeKind.RENDERED,
        source="hxe_func_printed",
        cfunc_available=True,
    )
    assert rendered.failure_code is None

    failed = HostDecompilationOutcome(
        kind=HostDecompilationOutcomeKind.FAILED,
        source="headless_decompile",
        cfunc_available=False,
        failure_code=50057,
        failure_ea=0x7FFB159EABD0,
        failure_description="internal error 50057",
    )
    assert failed.failure_code == 50057

    code_less_failed = HostDecompilationOutcome(
        kind=HostDecompilationOutcomeKind.FAILED,
        source="headless_decompile",
        cfunc_available=False,
    )
    assert code_less_failed.failure_code is None

    invalid = (
        dict(kind=HostDecompilationOutcomeKind.RENDERED, source="render", cfunc_available=False),
        dict(kind=HostDecompilationOutcomeKind.FAILED, source="failed", cfunc_available=True, failure_code=1),
        dict(kind=HostDecompilationOutcomeKind.RENDERED, source="", cfunc_available=True),
        dict(kind=HostDecompilationOutcomeKind.FAILED, source="failed", cfunc_available=False, failure_code=1, failure_ea=-1),
        dict(kind=HostDecompilationOutcomeKind.FAILED, source="failed", cfunc_available=False, failure_code=0),
        dict(kind=HostDecompilationOutcomeKind.ABANDONED, source="abandoned", cfunc_available=False, failure_code=1),
    )
    for kwargs in invalid:
        with pytest.raises((TypeError, ValueError)):
            HostDecompilationOutcome(**kwargs)


def test_host_decompilation_outcome_is_persisted_once_and_conflicts_are_diagnostic(
    fake_conn,
):
    session = DiagnosticSessionObserved(
        session_id="host-session",
        func_ea=0x401000,
        top_level_epoch=1,
        native_key_json="{}",
        status="active",
        timestamp=1.0,
    )
    emit(session)
    rendered = HostDecompilationOutcomeObserved(
        session_id="host-session",
        func_ea=0x401000,
        outcome=HostDecompilationOutcome(
            kind=HostDecompilationOutcomeKind.RENDERED,
            source="hxe_func_printed",
            cfunc_available=True,
        ),
        timestamp=2.0,
    )
    emit(rendered)
    emit(
        HostDecompilationOutcomeObserved(
            session_id="host-session",
            func_ea=0x401000,
            outcome=rendered.outcome,
            # Delivery time is not part of semantic duplicate identity.
            timestamp=999.0,
        )
    )
    assert fake_conn.execute(
        "SELECT session_id,func_ea_hex,func_ea_i64,outcome,source,cfunc_available,"
        "failure_code,failure_ea_hex,failure_ea_i64,failure_description,event_id "
        "FROM host_decompilation_outcomes"
    ).fetchall() == [
        (
            "host-session",
            "0x0000000000401000",
            0x401000,
            "rendered",
            "hxe_func_printed",
            1,
            None,
            None,
            None,
            "",
            2,
        )
    ]
    assert fake_conn.execute(
        "SELECT diagnostic_error_count FROM diagnostic_sessions "
        "WHERE session_id='host-session'"
    ).fetchone() == (0,)

    conflicting = HostDecompilationOutcomeObserved(
        session_id="host-session",
        func_ea=0x401000,
        outcome=HostDecompilationOutcome(
            kind=HostDecompilationOutcomeKind.FAILED,
            source="headless_decompile",
            cfunc_available=False,
            failure_code=50057,
            failure_description="internal error 50057",
        ),
        timestamp=3.0,
    )
    emit(conflicting)
    assert fake_conn.execute(
        "SELECT COUNT(*),outcome,source,failure_code,failure_description "
        "FROM host_decompilation_outcomes"
    ).fetchone() == (1, "rendered", "hxe_func_printed", None, "")
    assert fake_conn.execute(
        "SELECT diagnostic_error_count FROM diagnostic_sessions "
        "WHERE session_id='host-session'"
    ).fetchone() == (1,)
    assert fake_conn.execute(
        "SELECT event_kind FROM lifecycle_events "
        "WHERE session_id='host-session' AND event_kind='diagnostic_error'"
    ).fetchone() == ("diagnostic_error",)


def test_host_decompilation_outcome_preserves_none_vs_empty_description_conflict(
    fake_conn,
):
    emit(
        DiagnosticSessionObserved(
            session_id="description-session",
            func_ea=0x401000,
            top_level_epoch=1,
            native_key_json="{}",
            status="active",
            timestamp=1.0,
        )
    )
    emit(
        HostDecompilationOutcomeObserved(
            session_id="description-session",
            func_ea=0x401000,
            outcome=HostDecompilationOutcome(
                kind=HostDecompilationOutcomeKind.ABANDONED,
                source="plugin_stop",
                cfunc_available=False,
            ),
            timestamp=2.0,
        )
    )
    emit(
        HostDecompilationOutcomeObserved(
            session_id="description-session",
            func_ea=0x401000,
            outcome=HostDecompilationOutcome(
                kind=HostDecompilationOutcomeKind.ABANDONED,
                source="plugin_stop",
                cfunc_available=False,
                failure_description="",
            ),
            timestamp=2.0,
        )
    )

    assert fake_conn.execute(
        "SELECT COUNT(*) FROM host_decompilation_outcomes "
        "WHERE session_id='description-session'"
    ).fetchone() == (1,)
    assert fake_conn.execute(
        "SELECT diagnostic_error_count FROM diagnostic_sessions "
        "WHERE session_id='description-session'"
    ).fetchone() == (1,)


# ---------------------------------------------------------------------------
# Install / uninstall
# ---------------------------------------------------------------------------


def test_install_is_idempotent():
    assert is_installed()
    # A second install should not crash.
    install_diag_event_handlers()
    assert is_installed()


def test_input_identity_resolution_is_durable_in_the_session_timeline(fake_conn):
    emit(
        InputIdentityResolutionObserved(
            session_id="identity-session",
            func_ea=0x401000,
            status="recovered_local_only",
            provenance="recovered_from_d810_attestation",
            mismatch_field=None,
            external_evidence_allowed=False,
            database_uuid="attested-db",
        )
    )

    row = fake_conn.execute(
        "SELECT event_kind,payload_json FROM lifecycle_events "
        "WHERE session_id='identity-session'"
    ).fetchone()

    assert row is not None
    assert row[0] == "input_identity_resolution"
    assert json.loads(row[1]) == {
        "database_uuid": "attested-db",
        "external_evidence_allowed": False,
        "mismatch_field": None,
        "provenance": "recovered_from_d810_attestation",
        "status": "recovered_local_only",
    }


def test_z3_predicate_proof_receipt_is_queryable_in_the_lifecycle_timeline(
    fake_conn,
):
    emit(
        Z3PredicateProofObserved(
            session_id="z3-session",
            func_ea=0x401000,
            transform_id="z-3-setz-generic",
            operation="prove_equal",
            max_expression_nodes=7,
            proof_timeout_ms=13,
            observed_expression_nodes=8,
            elapsed_ms=2.5,
            status=Z3ProofStatus.ABSTAINED,
            reason=Z3ProofAbstentionReason.NODE_LIMIT,
            timestamp=4.0,
        )
    )

    row = fake_conn.execute(
        "SELECT event_kind,provider,phase,correlation_id,payload_json "
        "FROM lifecycle_events WHERE session_id='z3-session'"
    ).fetchone()

    assert row is not None
    assert row[:4] == (
        "z3_predicate_proof",
        "d810.mba:z-3-setz-generic",
        "proof",
        "z-3-setz-generic:prove_equal",
    )
    assert json.loads(row[4]) == {
        "elapsed_ms": 2.5,
        "max_expression_nodes": 7,
        "observed_expression_nodes": 8,
        "operation": "prove_equal",
        "proof_timeout_ms": 13,
        "reason": "node_limit",
        "status": "abstained",
        "transform_id": "z-3-setz-generic",
    }


def test_uninstall_clears_install_flag():
    uninstall_diag_event_handlers()
    assert not is_installed()


def test_typed_frontend_normalization_intent_is_queryable(fake_conn):
    emit(
        FrontendNormalizationPlanIntentObserved(
            session_id="session-1",
            func_ea=0x180001000,
            evidence_generation=4,
            work_item_id="work-item-4",
            plan_id="plan-4",
            atomic_group_id="group-4",
            publication_revision=2,
            block_count=3,
            operation_count=2,
            imported_block_count=1,
            native_body_count=2,
            published_operation_ids=("op-1",),
            selected_obligation_ids=("obl-1",),
            remaining_obligation_ids=("obl-2",),
            unreachable_obligation_ids=(),
            complete_plan_json='{"plan_id":"plan-4","blocks":[],"operations":[]}',
        )
    )

    assert fake_conn.execute(
        "SELECT plan_id, evidence_generation "
        "FROM frontend_normalization_plan_intents"
    ).fetchone() == ("plan-4", 4)
    assert fake_conn.execute(
        "SELECT event_kind, payload_json FROM lifecycle_events"
    ).fetchone() == ("frontend_normalization_plan_intent", "{}")


def test_semantic_output_verification_requires_an_explicit_typed_event(fake_conn):
    emit(
        SemanticOutputVerifiedObserved(
            session_id="session-1",
            func_ea=0x180001000,
            verifier_id="verifier:fixture",
            witness_id="verifier:fixture:1",
            summary="Reference and candidate outputs matched.",
            native_anchor_ea=0x180001000,
            evidence_generation=5,
        )
    )

    assert fake_conn.execute(
        "SELECT verifier_id, witness_id, native_anchor_ea_i64 "
        "FROM semantic_output_verdicts"
    ).fetchone() == ("verifier:fixture", "verifier:fixture:1", 0x180001000)


def test_pass_contract_evidence_receipt_is_queryable(fake_conn):
    emit(
        PassContractEvidencePublished(
            session_id="session-1",
            func_ea=0x180001000,
            evidence_generation=5,
            maturity="ir.canonical",
            pass_id="resolve-native-indirect-transfers",
            evidence_token="ir.branch_target",
            native_anchor_eas=(0x180001020, 0x180001030),
            summary="Two native indirect transfers were recovered.",
        )
    )

    assert fake_conn.execute(
        "SELECT pass_id,evidence_token,evidence_generation,maturity,"
        "native_anchor_eas_json FROM pass_contract_evidence_publications"
    ).fetchone() == (
        "resolve-native-indirect-transfers",
        "ir.branch_target",
        5,
        "ir.canonical",
        "[6442455072,6442455088]",
    )
    assert fake_conn.execute(
        "SELECT event_kind,correlation_id FROM lifecycle_events"
    ).fetchone() == ("pass_contract_evidence", "ir.branch_target")


def test_terminal_session_materializes_one_closed_case(fake_conn):
    native_key = '{"function_fingerprint":"sha256:fixture"}'
    emit(
        DiagnosticSessionObserved(
            session_id="session-1",
            func_ea=0x180001000,
            top_level_epoch=1,
            native_key_json=native_key,
            status="active",
            timestamp=1.0,
        )
    )
    assert fake_conn.execute(
        "SELECT COUNT(*) FROM deobfuscation_cases"
    ).fetchone() == (0,)

    emit(
        DiagnosticSessionObserved(
            session_id="session-1",
            func_ea=0x180001000,
            top_level_epoch=1,
            native_key_json=native_key,
            status="finished",
            timestamp=2.0,
        )
    )
    assert fake_conn.execute(
        "SELECT closed_status, verdict_level FROM deobfuscation_cases"
    ).fetchone() == ("finished", "c0_environment")

    emit(
        DiagnosticSessionObserved(
            session_id="session-1",
            func_ea=0x180001000,
            top_level_epoch=1,
            native_key_json=native_key,
            status="finished",
            timestamp=3.0,
        )
    )
    assert fake_conn.execute(
        "SELECT COUNT(*) FROM deobfuscation_cases"
    ).fetchone() == (1,)


# ---------------------------------------------------------------------------
# CaptureMbaSnapshotRequested
# ---------------------------------------------------------------------------


def test_capture_inserts_snapshots_row_and_binds_mapping(fake_conn):
    snap = request_capture_mba_snapshot(
        blocks=_make_snap_blocks(),
        label="MMAT_GLBOPT1_post_d810",
        func_ea=0x401000,
        maturity="MMAT_GLBOPT1",
        phase="post_d810",
    )
    assert snap is not None

    rows = fake_conn.execute(
        "SELECT label, maturity, phase, block_count FROM snapshots"
    ).fetchall()
    assert len(rows) == 1
    assert rows[0] == ("MMAT_GLBOPT1_post_d810", "MMAT_GLBOPT1", "post_d810", 1)


def test_capture_persists_maturity_json(fake_conn):
    maturity_json = json.dumps(
        {
            "ir": "GLOBAL_ANALYZED",
            "snapshot_form": "OPTIMIZED_IR",
            "provider": "hexrays",
            "provider_id": 4,
            "provider_name": "MMAT_GLBOPT1",
        }
    )
    snap = request_capture_mba_snapshot(
        blocks=_make_snap_blocks(),
        label="MMAT_GLBOPT1_post_d810",
        func_ea=0x401000,
        maturity="MMAT_GLBOPT1",
        phase="post_d810",
        maturity_json=maturity_json,
    )
    assert snap is not None

    row = fake_conn.execute(
        "SELECT s.maturity, sm.maturity_json "
        "FROM snapshots s "
        "JOIN snapshot_maturity sm ON sm.snapshot_id=s.id"
    ).fetchone()
    assert row[0] == "MMAT_GLBOPT1"
    assert json.loads(row[1]) == json.loads(maturity_json)


def test_followup_event_writes_under_correct_snapshot_id(fake_conn):
    snap = request_capture_mba_snapshot(
        blocks=_make_snap_blocks(),
        label="L",
        func_ea=1,
        maturity="MMAT_GLBOPT1",
        phase="post_d810",
    )
    assert snap is not None

    nodes = [
        DagNode(state=0x10, state_hex="0x10", entry_block=5, classification="X"),
    ]
    edges = [
        DagEdge(
            edge_id=0,
            source_state=0x10,
            target_state=0x20,
            edge_kind="TRANSITION",
        ),
    ]
    observe_dag(snap, nodes, edges)

    dag_rows = fake_conn.execute(
        "SELECT snapshot_id, state_hex, classification FROM state_cfg_nodes"
    ).fetchall()
    assert len(dag_rows) == 1
    assert dag_rows[0][1] == "0x0000000000000010"
    assert dag_rows[0][2] == "X"


def test_observe_modifications_writes_to_modifications_table(fake_conn):
    snap = request_capture_mba_snapshot(
        blocks=_make_snap_blocks(),
        label="L",
        func_ea=1,
        maturity="M",
        phase="post_d810",
    )
    assert snap is not None

    mods = [
        Modification(mod_index=0, mod_type="goto_redirect", source_block=5),
        Modification(mod_index=1, mod_type="insert_block", target_block=9),
    ]
    observe_modifications(snap, mods)

    rows = fake_conn.execute(
        "SELECT mod_index, mod_type FROM snapshot_modifications ORDER BY mod_index"
    ).fetchall()
    assert rows == [(0, "goto_redirect"), (1, "insert_block")]


def test_reachability_translates_frozensets_to_classification_rows(fake_conn):
    snap = request_capture_mba_snapshot(
        blocks=_make_snap_blocks(),
        label="L",
        func_ea=1,
        maturity="M",
        phase="post_d810",
    )
    assert snap is not None

    observe_reachability(
        snap,
        all_serials=[0, 1, 2],
        reachable=[0, 1],
        condition_chain_serials=[],
        gutted=[2],
        claimed_sources=[1],
    )

    rows = fake_conn.execute(
        "SELECT serial, is_reachable, is_gutted, in_claimed "
        "FROM block_classification ORDER BY serial"
    ).fetchall()
    assert rows == [
        (0, 1, 0, 0),
        (1, 1, 0, 1),
        (2, 0, 1, 0),
    ]


def test_event_without_snapshot_mapping_is_a_noop(fake_conn):
    # No capture happened; emit a DagObserved with a snapshot whose key
    # was never bound. Should not raise, should not write rows.
    snap = SnapshotRef(key="stale-key", func_ea=1, label="L", maturity="M", phase="p")
    emit(DagObserved(snapshot=snap, nodes=(), edges=()))

    rows = fake_conn.execute("SELECT COUNT(*) FROM state_cfg_nodes").fetchone()
    assert rows[0] == 0


def test_state_dispatcher_rows_buffer_until_snapshot(fake_conn):
    observe_state_dispatcher_rows(
        func_ea=0x401000,
        maturity="MMAT_GLBOPT1",
        dispatcher_entry_block=2,
        dispatcher_kind="CONDITION_CHAIN",
        rows=[
            {
                "state_const": 0x89407346,
                "target_block": 3,
                "compare_block": None,
                "branch_kind": "handler_state_map",
                "confidence": 1.0,
            }
        ],
    )

    pre_rows = fake_conn.execute(
        "SELECT COUNT(*) FROM state_dispatcher_rows"
    ).fetchone()
    assert pre_rows[0] == 0

    request_capture_mba_snapshot(
        blocks=_make_snap_blocks(),
        label="L",
        func_ea=0x401000,
        maturity="MMAT_GLBOPT1",
        phase="pre_d810",
    )

    row = fake_conn.execute(
        "SELECT state_const_hex, target_block, compare_block, branch_kind "
        "FROM state_dispatcher_rows"
    ).fetchone()
    assert row == (
        "0x0000000089407346",
        3,
        None,
        "handler_state_map",
    )


def test_canonical_authority_phase_fact_persists_with_stable_correlation(fake_conn):
    """The canonical phase fact reaches the DB with its stable correlation."""
    func_ea = 0x401000
    verdict = authority_model.UnflattenAuthorityVerdict(
        accepted=False,
        phase=authority_model.UnflattenAuthorityPhase.PROJECTED_PREFLIGHT,
        reason=authority_model.UnflattenAuthorityReason.PROJECTED_BINDING_FAILED,
        authority_id=authority_id("diag-canonical-authority"),
        binding_id=None,
        case_id=None,
        candidate_fingerprint=authority_id("diag-canonical-candidate"),
        safety_case=None,
        failed_obligations=(),
    )
    attempt = TransactionAttemptId(
        authority_id("diag-canonical-plan"),
        authority_id("diag-canonical-session"),
        3,
        authority_id("diag-canonical-attempt"),
    )
    observation = phase_observation(
        verdict,
        maturity="MMAT_GLBOPT1",
        source_ea=func_ea,
        correlation=attempt,
    )

    snapshot = request_capture_mba_snapshot(
        blocks=_make_snap_blocks(),
        label="unflatten_authority_projected_preflight",
        func_ea=func_ea,
        maturity="MMAT_GLBOPT1",
        phase="unknown",
    )
    assert snapshot is not None
    observe_fact_observation(snapshot, func_ea, (observation,))

    snapshot = fake_conn.execute(
        "SELECT label, maturity, phase FROM snapshots"
    ).fetchone()
    assert snapshot == (
        "unflatten_authority_projected_preflight",
        "MMAT_GLBOPT1",
        "unknown",
    )
    row = fake_conn.execute(
        "SELECT fact_id, kind, semantic_key, phase, source_ea_i64, payload "
        "FROM fact_observations"
    ).fetchone()
    assert row is not None
    assert row[:5] == (
        observation.fact_id,
        "unflatten_authority_phase",
        observation.semantic_key,
        "projected_preflight",
        func_ea,
    )
    payload = json.loads(row[5])
    assert payload["authority_id"] == verdict.authority_id
    assert payload["plan_id"] == attempt.plan_id
    assert payload["session_id"] == attempt.session_id
    assert payload["attempt_id"] == attempt.attempt_id
    assert payload["generation"] == attempt.generation


def test_optblock_callback_exception_persists_typed_traceback_and_anchor(fake_conn):
    """A top-level callback failure must survive as a queryable typed fact."""
    event_type = getattr(
        observability_events,
        "OptblockCallbackExceptionObserved",
        None,
    )
    assert event_type is not None, "optblock callback failures need a typed event"
    request_capture_mba_snapshot(
        blocks=_make_snap_blocks(),
        label="callback_failure_capture",
        func_ea=0x7FF859C06F60,
        maturity="MMAT_GLBOPT1",
        phase="post_d810",
    )
    emit(
        event_type(
            func_ea=0x7FF859C06F60,
            maturity="MMAT_GLBOPT1",
            block_serial=45,
            block_ea=0x7FF859C07656,
            error_type="TypeError",
            error_message="PatchPlan lowering requires bound transaction authority",
            traceback_text=(
                "Traceback (most recent call last):\\n"
                "TypeError: PatchPlan lowering requires bound transaction authority"
            ),
        )
    )

    row = fake_conn.execute(
        "SELECT fact_id, kind, semantic_key, maturity, phase, source_block, "
        "source_ea_i64, payload, evidence FROM fact_observations"
    ).fetchone()
    assert row[0].startswith(
        "optblock-callback-exception:func=0x7ff859c06f60:"
        "maturity=MMAT_GLBOPT1:blk45@0x7ff859c07656:TypeError:occurrence="
    )
    assert row[1:7] == (
        "OptblockCallbackException",
        "optblock_callback_exception:blk45@0x7ff859c07656:TypeError",
        "MMAT_GLBOPT1",
        "optblock_callback",
        45,
        0x7FF859C07656,
    )
    payload = json.loads(row[7])
    assert payload["block_anchor"] == "blk45@0x7ff859c07656"
    assert payload["error_type"] == "TypeError"
    assert payload["occurrence_id"]
    assert "requires bound transaction authority" in payload["traceback_text"]
    assert json.loads(row[8]) == [
        "blk45@0x7ff859c07656",
        "optblock_callback_exception",
    ]


def test_optblock_callback_exception_occurrences_do_not_overwrite_each_other(
    fake_conn,
):
    """Same-anchor callback failures retain each independently published trace."""
    request_capture_mba_snapshot(
        blocks=_make_snap_blocks(),
        label="callback_failure_occurrences",
        func_ea=0x7FF859C06F60,
        maturity="MMAT_GLBOPT1",
        phase="post_d810",
    )
    event_type = observability_events.OptblockCallbackExceptionObserved
    for message in ("first callback failure", "second callback failure"):
        emit(
            event_type(
                func_ea=0x7FF859C06F60,
                maturity="MMAT_GLBOPT1",
                block_serial=45,
                block_ea=0x7FF859C07656,
                error_type="TypeError",
                error_message=message,
                traceback_text=f"TypeError: {message}",
            )
        )

    rows = fake_conn.execute(
        "SELECT fact_id, payload FROM fact_observations "
        "WHERE kind='OptblockCallbackException' ORDER BY fact_id"
    ).fetchall()
    assert len(rows) == 2
    payloads = [json.loads(row[1]) for row in rows]
    assert {payload["error_message"] for payload in payloads} == {
        "first callback failure",
        "second callback failure",
    }
    assert len({payload["occurrence_id"] for payload in payloads}) == 2


def test_state_transition_dispatch_resolutions_write_under_snapshot(fake_conn):
    snap = request_capture_mba_snapshot(
        blocks=_make_snap_blocks(),
        label="L",
        func_ea=0x401000,
        maturity="MMAT_GLBOPT1",
        phase="pre_d810",
    )
    assert snap is not None

    observe_state_transition_dispatch_resolutions(
        snap,
        [
            {
                "fact_id": "state_transition_anchor:blk=100",
                "source_block_serial": 100,
                "source_state_const_hex": "0x89407346",
                "resolved_next_block_serial": 76,
                "resolved_next_state_const_hex": "0x0000000010743c4c",
                "resolved_next_state_const_u64": 0x10743C4C,
                "resolution_kind": "ollvm_state_dispatcher_map",
                "resolution_reason": "resolved_exact_state",
                "resolution_maturity": "MMAT_GLBOPT1",
            },
        ],
    )

    row = fake_conn.execute(
        "SELECT fact_id, resolved_next_block_serial, resolution_kind "
        "FROM state_transition_dispatch_resolutions"
    ).fetchone()
    assert row == (
        "state_transition_anchor:blk=100",
        76,
        "ollvm_state_dispatcher_map",
    )


def test_state_transition_dispatch_resolutions_normalize_u64(fake_conn):
    snap = request_capture_mba_snapshot(
        blocks=_make_snap_blocks(),
        label="L",
        func_ea=0x401000,
        maturity="MMAT_GLBOPT1",
        phase="pre_d810",
    )
    assert snap is not None

    observe_state_transition_dispatch_resolutions(
        snap,
        [
            {
                "fact_id": "state_transition_anchor:blk=100",
                "source_block_serial": 100,
                "source_state_const_hex": "0xffffffffffffffff",
                "resolved_next_block_serial": 76,
                "resolved_next_state_const_hex": "0xffffffffffffff80",
                "resolved_next_state_const_u64": 0xFFFFFFFFFFFFFF80,
                "resolution_kind": "ollvm_state_dispatcher_map",
                "resolution_reason": "resolved_exact_state",
                "resolution_maturity": "MMAT_GLBOPT1",
            },
        ],
    )

    row = fake_conn.execute(
        "SELECT source_state_const_hex, resolved_next_state_const_hex, "
        "resolved_next_state_const_u64 "
        "FROM state_transition_dispatch_resolutions"
    ).fetchone()
    assert row == (
        "0xffffffffffffffff",
        "0xffffffffffffff80",
        -128,
    )


def test_branch_ownership_proofs_write_under_snapshot(fake_conn):
    snap = request_capture_mba_snapshot(
        blocks=_make_snap_blocks(),
        label="L",
        func_ea=0x401000,
        maturity="MMAT_GLBOPT1",
        phase="pre_d810",
    )
    assert snap is not None

    observe_branch_ownership_proofs(
        snap,
        [
            {
                "proof_id": "branch_ownership:edge=1",
                "proof_kind": "OBFUSCATION_RESIDUE_ARM",
                "trusted": True,
                "reason": "trusted_opaque_branch_provenance",
                "source_block": 100,
                "branch_arm": 0,
                "source_state": 0x10,
                "target_state": 0x20,
                "target_entry": 76,
                "predicate_block": 100,
                "dispatcher_entry_block": 2,
                "oracle_kind": "explicit_opaque_provenance",
                "evidence": {"edge_kind": "CONDITIONAL_TRANSITION"},
                "payload": {"profile_name": "ollvm_state_map"},
            },
        ],
    )

    row = fake_conn.execute(
        "SELECT proof_kind, trusted, target_entry, oracle_kind "
        "FROM branch_ownership_proofs"
    ).fetchone()
    assert row == ("OBFUSCATION_RESIDUE_ARM", 1, 76, "explicit_opaque_provenance")


def test_branch_witness_decisions_buffer_until_snapshot(fake_conn):
    observe_branch_witness_decisions(
        func_ea=0x401000,
        rows=[
            {
                "state": 0x10,
                "dispatcher_entry_block": 1,
                "compare_block": 2,
                "predicate": "eq",
                "compare_const": 0x10,
                "selected_successor": 4,
                "rejected_successors": (3,),
                "target_block": 4,
                "proof_kind": "static_equality_chain",
                "outcome": "accepted",
                "evidence": "validated_against_current_cfg",
            }
        ],
    )

    pre_rows = fake_conn.execute(
        "SELECT COUNT(*) FROM branch_witness_decisions"
    ).fetchone()
    assert pre_rows[0] == 0

    request_capture_mba_snapshot(
        blocks=_make_snap_blocks(),
        label="L",
        func_ea=0x401000,
        maturity="MMAT_GLBOPT1",
        phase="pre_d810",
    )

    row = fake_conn.execute(
        "SELECT state_hex, compare_block, selected_successor, "
        "rejected_successors_json, outcome, evidence "
        "FROM branch_witness_decisions"
    ).fetchone()
    assert row[:3] == ("0x0000000000000010", 2, 4)
    assert json.loads(row[3]) == [3]
    assert row[4:] == ("accepted", "validated_against_current_cfg")


def test_exit_path_shortcut_decisions_buffer_until_snapshot(fake_conn):
    observe_exit_path_shortcut_decisions(
        func_ea=0x401000,
        rows=[
            {
                "source_block": 0,
                "old_target": 2,
                "shortcut_target": 5,
                "witness_compare_blocks": (2,),
                "exit_path_blocks": (2,),
                "rejected_successors": (3,),
                "outcome": "rejected",
                "reason": "exit_path_liveness_unsafe",
                "live_definitions": ({"kind": "reg", "value": 8},),
            }
        ],
    )

    pre_rows = fake_conn.execute(
        "SELECT COUNT(*) FROM exit_path_shortcut_decisions"
    ).fetchone()
    assert pre_rows[0] == 0

    request_capture_mba_snapshot(
        blocks=_make_snap_blocks(),
        label="L",
        func_ea=0x401000,
        maturity="MMAT_GLBOPT1",
        phase="pre_d810",
    )

    row = fake_conn.execute(
        "SELECT source_block, shortcut_target, witness_compare_blocks_json, "
        "exit_path_blocks_json, rejected_successors_json, outcome, reason, "
        "live_definitions_json FROM exit_path_shortcut_decisions"
    ).fetchone()
    assert row[:2] == (0, 5)
    assert json.loads(row[2]) == [2]
    assert json.loads(row[3]) == [2]
    assert json.loads(row[4]) == [3]
    assert row[5:7] == ("rejected", "exit_path_liveness_unsafe")
    assert json.loads(row[7]) == [{"kind": "reg", "value": 8}]


def test_capture_handler_short_circuits_when_no_conn():
    """If get_diag_db returns None, handler must no-op without raising."""

    def no_conn(_ea: int = 0, *_, **__):
        return None

    reset_diagnostic_bus()
    with patch(
        "d810.core.diag.event_handlers.get_diag_conn",
        new=no_conn,
    ):
        install_diag_event_handlers()
        snap = request_capture_mba_snapshot(
            blocks=_make_snap_blocks(),
            label="L",
            func_ea=1,
            maturity="M",
            phase="post_d810",
        )
        # Subscriber WAS installed, so request_capture returned a ref;
        # but the handler couldn't get a conn so it no-op'd. The
        # follow-on event is then unmapped.
        assert snap is not None
        # No mapping -> follow-on does nothing.
        observe_modifications(snap, [Modification(mod_index=0, mod_type="x")])
        uninstall_diag_event_handlers()


# ---------------------------------------------------------------------------
# CFG provenance
# ---------------------------------------------------------------------------


def test_cfg_provenance_buffers_until_next_capture(fake_conn):
    # Emit some provenance events first.
    observe_cfg_provenance(
        pass_name="cfg_mutations",
        action="DELETE",
        block_serial=42,
        reason="dead block",
    )
    observe_cfg_provenance(
        pass_name="cfg_mutations",
        action="REDIRECT_EDGE",
        block_serial=10,
        target_serial=20,
        block_label="blk[10]@0x401010",
        block_ea=0x401010,
        target_label="blk[20]@0x401020",
        target_ea=0x401020,
    )

    # No rows yet — they're buffered.
    pre_rows = fake_conn.execute("SELECT COUNT(*) FROM cfg_provenance").fetchone()
    assert pre_rows[0] == 0

    # Capture flushes.
    request_capture_mba_snapshot(
        blocks=_make_snap_blocks(),
        label="L",
        func_ea=1,
        maturity="M",
        phase="post_d810",
    )

    rows = fake_conn.execute(
        "SELECT pass_name, action, block_serial, target_serial "
        "FROM cfg_provenance ORDER BY rowid"
    ).fetchall()
    assert rows == [
        ("cfg_mutations", "DELETE", 42, None),
        ("cfg_mutations", "REDIRECT_EDGE", 10, 20),
    ]

    detail = fake_conn.execute(
        """
        SELECT block_label, block_ea_hex, block_ea_i64,
               target_label, target_ea_hex, target_ea_i64, extra_json
        FROM cfg_provenance
        WHERE action='REDIRECT_EDGE'
        """
    ).fetchone()
    assert detail[:6] == (
        "blk[10]@0x401010",
        "0x0000000000401010",
        0x401010,
        "blk[20]@0x401020",
        "0x0000000000401020",
        0x401020,
    )
    assert '"block_label": "blk[10]@0x401010"' in detail[6]
    assert '"target_label": "blk[20]@0x401020"' in detail[6]


def test_cfg_provenance_normalizes_unsigned_eas_before_insert(fake_conn):
    observe_cfg_provenance(
        pass_name="cfg_mutations",
        action="REDIRECT_EDGE",
        block_serial=10,
        target_serial=20,
        block_ea=0xFFFFFFFFFFFFFFFF,
        target_ea=0xFFFFFFFFFFFFFF80,
        reason="badaddr_like_edge",
    )

    request_capture_mba_snapshot(
        blocks=_make_snap_blocks(),
        label="L",
        func_ea=1,
        maturity="M",
        phase="post_d810",
    )

    detail = fake_conn.execute(
        """
        SELECT block_ea_hex, block_ea_i64, target_ea_hex, target_ea_i64
        FROM cfg_provenance
        WHERE action='REDIRECT_EDGE'
        """
    ).fetchone()
    assert detail == (
        "0xffffffffffffffff",
        -1,
        "0xffffffffffffff80",
        -128,
    )


def test_cfg_provenance_latest_writes_to_current_function_snapshot(fake_conn):
    request_capture_mba_snapshot(
        blocks=_make_snap_blocks(),
        label="L",
        func_ea=0x401000,
        maturity="M",
        phase="post_d810",
    )

    observe_cfg_provenance_latest(
        func_ea=0x401000,
        pass_name="EmulatedDispatcherUnflattener",
        action="VETO_REDIRECT",
        block_serial=42,
        target_serial=99,
        reason="direct_use_def_severance",
        extra={"orphaned_use_count": 3},
    )

    rows = fake_conn.execute(
        "SELECT pass_name, action, block_serial, target_serial, reason, "
        "extra_json FROM cfg_provenance"
    ).fetchall()
    assert len(rows) == 1
    assert rows[0][:5] == (
        "EmulatedDispatcherUnflattener",
        "VETO_REDIRECT",
        42,
        99,
        "direct_use_def_severance",
    )
    assert '"orphaned_use_count": 3' in rows[0][5]


def test_cfg_provenance_latest_appends_sequence(fake_conn):
    request_capture_mba_snapshot(
        blocks=_make_snap_blocks(),
        label="L",
        func_ea=0x401000,
        maturity="M",
        phase="post_d810",
    )

    for block_serial in (42, 43):
        observe_cfg_provenance_latest(
            func_ea=0x401000,
            pass_name="EmulatedDispatcherUnflattener",
            action="VETO_REDIRECT",
            block_serial=block_serial,
            target_serial=99,
            reason="direct_use_def_severance",
        )

    rows = fake_conn.execute(
        "SELECT seq, block_serial FROM cfg_provenance ORDER BY seq"
    ).fetchall()
    assert rows == [(0, 42), (1, 43)]


def test_watch_block_transition_event_writes_immediately(fake_conn):
    # The watch-transition handler does not need a SnapshotRef; it uses
    # func_ea directly and writes through snapshot_watch_transition.
    observe_watch_block_transition(
        func_ea=0x401000,
        apply_session_id="apply_test",
        mod_index=5,
        mod_type="RedirectGoto",
        phase="post_apply",
        block_serial=12,
        prev_type_name="BLT_NWAY",
        prev_succs=(13, 14),
        prev_preds=(11,),
        now_type_name="BLT_1WAY",
        now_succs=(13,),
        now_preds=(11,),
    )

    rows = fake_conn.execute(
        "SELECT mod_type, block_serial, prev_type_name, now_type_name "
        "FROM watch_block_transitions"
    ).fetchall()
    assert rows == [("RedirectGoto", 12, "BLT_NWAY", "BLT_1WAY")]


# ---------------------------------------------------------------------------
# Handler exception safety (bus catches)
# ---------------------------------------------------------------------------


def test_handler_exception_is_swallowed_by_bus(fake_conn, caplog):
    # Force the snapshot insert to fail and verify the bus swallows.
    snap = request_capture_mba_snapshot(
        blocks=_make_snap_blocks(),
        label="L",
        func_ea=1,
        maturity="M",
        phase="post_d810",
    )
    assert snap is not None

    # Emit a modifications event with a Modification missing the
    # required fields by manipulating the SQL execution surface:
    # easier path: close the connection so subsequent writes raise.
    fake_conn.close()
    # Must not raise.
    emit(
        ModificationsObserved(
            snapshot=snap,
            modifications=(Modification(mod_index=0, mod_type="goto_redirect"),),
        )
    )


# ---------------------------------------------------------------------------
# Terminal unflatten candidate outcome (ticket d81-rhu6)
# ---------------------------------------------------------------------------


def _unflat_outcome(**overrides):
    from d810.core.observability_events import UnflattenCandidateOutcomeObserved

    kwargs = dict(
        session_id="unflat-session",
        func_ea=0x7FFB0EB06E50,
        maturity="MMAT_GLBOPT1",
        graph_fingerprint="flowgraph-topology-epoch-v1:abc",
        candidate_identity="DispatcherCandidateIdentity(blk=330)",
        attempt=1,
        disposition="not_submitted_safe_bail",
        reason="residual_dispatcher_corridor",
        plan_id="plan-7",
        handlers_recovered=85,
        handlers_total=85,
        dag_nodes=59,
        dag_edges=20,
        coverage_covered=0,
        coverage_residual=158,
        unresolved_anchors=((330, 0x7FFB0EB15239),),
        committed_batches_before=0,
        next_hint="python -m d810.diagnostics unflat-why --db D --func 0x7ffb0eb06e50",
    )
    kwargs.update(overrides)
    return UnflattenCandidateOutcomeObserved(**kwargs)


def test_unflat_candidate_outcome_writes_lifecycle_and_outcome_rows(fake_conn):
    emit(_unflat_outcome())

    kind, maturity, correlation, payload = fake_conn.execute(
        "SELECT event_kind,maturity,correlation_id,payload_json "
        "FROM lifecycle_events WHERE event_kind='unflat_candidate_outcome'"
    ).fetchone()
    assert kind == "unflat_candidate_outcome"
    assert maturity == "MMAT_GLBOPT1"
    assert correlation == (
        "flowgraph-topology-epoch-v1:abc:DispatcherCandidateIdentity(blk=330):1"
    )
    body = json.loads(payload)
    assert body["disposition"] == "not_submitted_safe_bail"
    assert body["reason"] == "residual_dispatcher_corridor"
    assert body["plan_id"] == "plan-7"
    assert body["handlers"] == [85, 85]
    assert body["dag"] == [59, 20]
    assert body["coverage"] == [0, 158]
    assert body["unresolved_anchors"] == [[330, 0x7FFB0EB15239]]
    assert body["committed_batches_before"] == 0
    assert body["next"].startswith("python -m d810.diagnostics unflat-why")

    rows = fake_conn.execute(
        "SELECT func_ea_hex,maturity,graph_fingerprint,candidate_identity,attempt,"
        "disposition,reason,plan_id,handlers_recovered,handlers_total,dag_nodes,"
        "dag_edges,coverage_covered,coverage_residual,committed_batches_before,"
        "unresolved_anchors_json,next_hint FROM unflatten_candidate_outcomes"
    ).fetchall()
    assert len(rows) == 1
    row = rows[0]
    assert row[0] == "0x00007ffb0eb06e50"
    assert row[1] == "MMAT_GLBOPT1"
    assert row[4] == 1
    assert row[5] == "not_submitted_safe_bail"
    assert row[6] == "residual_dispatcher_corridor"
    assert row[7] == "plan-7"
    assert row[8:15] == (85, 85, 59, 20, 0, 158, 0)
    assert json.loads(row[15]) == [[330, 0x7FFB0EB15239]]


def test_unflat_candidate_outcome_records_are_append_only(fake_conn):
    emit(_unflat_outcome(attempt=1))
    emit(_unflat_outcome(attempt=2, disposition="exhausted", reason="all_excluded"))
    rows = fake_conn.execute(
        "SELECT attempt,disposition FROM unflatten_candidate_outcomes ORDER BY attempt"
    ).fetchall()
    assert rows == [(1, "not_submitted_safe_bail"), (2, "exhausted")]


def test_unflat_candidate_outcome_persists_a_maturity_no_callback_class(fake_conn):
    emit(
        _unflat_outcome(
            func_ea=0x7FFB0F2726E0,
            disposition="maturity_no_callbacks",
            reason="hexrays_delivered_no_optblock_callback",
            graph_fingerprint="",
            candidate_identity="",
            attempt=0,
            plan_id=None,
            handlers_recovered=None,
            handlers_total=None,
            dag_nodes=None,
            dag_edges=None,
            coverage_covered=None,
            coverage_residual=None,
            unresolved_anchors=(),
        )
    )
    row = fake_conn.execute(
        "SELECT disposition,reason,plan_id,handlers_total,unresolved_anchors_json "
        "FROM unflatten_candidate_outcomes"
    ).fetchone()
    assert row == (
        "maturity_no_callbacks",
        "hexrays_delivered_no_optblock_callback",
        None,
        None,
        "[]",
    )


def test_unflat_candidate_outcome_persists_the_poisoned_class(fake_conn):
    emit(
        _unflat_outcome(
            disposition="poisoned_restart_required",
            reason="structural_accounting:source_catalog_block",
            committed_batches_before=7,
        )
    )
    row = fake_conn.execute(
        "SELECT disposition,reason,committed_batches_before "
        "FROM unflatten_candidate_outcomes"
    ).fetchone()
    assert row == (
        "poisoned_restart_required",
        "structural_accounting:source_catalog_block",
        7,
    )


# ---------------------------------------------------------------------------
# State-write resolution facts (ticket d81-qt4v, slice 4)
# ---------------------------------------------------------------------------


def _state_write_resolution(**overrides):
    kwargs = dict(
        func_ea=0x7FFB0EB06E50,
        block_serial=330,
        block_ea=0x7FFB0EB15239,
        corridor=(355, 397),
        outcome="abstain",
        cause="no_def_within_hop_bound",
        reason="emulator+history could not resolve state-var write",
        store_cells=0,
        folded_value=None,
        def_sites=((329, 0x7FFB0EB1520A), (398, 0x7FFB0EB0BCF7)),
        contributed_to_unresolved_transition=True,
        maturity="MMAT_GLBOPT1",
        session_id="sess-1",
    )
    kwargs.update(overrides)
    return StateWriteResolutionObserved(**kwargs)


def test_state_write_resolution_writes_lifecycle_and_fact_rows(fake_conn):
    emit(_state_write_resolution())

    kind, maturity, correlation, payload = fake_conn.execute(
        "SELECT event_kind,maturity,correlation_id,payload_json "
        "FROM lifecycle_events WHERE event_kind='state_write_resolution'"
    ).fetchone()
    assert kind == "state_write_resolution"
    assert maturity == "MMAT_GLBOPT1"
    assert correlation == "330:355>397"
    body = json.loads(payload)
    assert body["kind"] == "StateWriteResolutionFact"
    assert body["cause"] == "no_def_within_hop_bound"
    assert body["outcome"] == "abstain"
    assert body["corridor"] == [355, 397]
    assert body["def_sites"] == [[329, 0x7FFB0EB1520A], [398, 0x7FFB0EB0BCF7]]
    assert body["contributed_to_unresolved_transition"] is True

    row = fake_conn.execute(
        "SELECT func_ea_hex,block_serial,block_ea_hex,corridor,outcome,cause,"
        "store_cells,folded_value_hex,def_sites_json,"
        "contributed_to_unresolved_transition,maturity "
        "FROM state_write_resolutions"
    ).fetchone()
    assert row[0] == "0x00007ffb0eb06e50"
    assert row[1] == 330
    assert row[3] == "355>397"
    assert row[4] == "abstain"
    assert row[5] == "no_def_within_hop_bound"
    assert row[6] == 0
    assert row[7] is None
    assert json.loads(row[8]) == [[329, 0x7FFB0EB1520A], [398, 0x7FFB0EB0BCF7]]
    assert row[9] == 1
    assert row[10] == "MMAT_GLBOPT1"


def test_state_write_resolution_persists_a_resolved_corridor(fake_conn):
    emit(
        _state_write_resolution(
            corridor=(329,),
            outcome="exact_result",
            cause="resolved",
            reason="",
            store_cells=2,
            folded_value=0x4BCC8BEE,
            def_sites=(),
            contributed_to_unresolved_transition=False,
        )
    )
    row = fake_conn.execute(
        "SELECT corridor,outcome,cause,folded_value_hex,folded_value_i64,"
        "contributed_to_unresolved_transition FROM state_write_resolutions"
    ).fetchone()
    assert row == (
        "329",
        "exact_result",
        "resolved",
        "0x000000004bcc8bee",
        0x4BCC8BEE,
        0,
    )


def test_state_write_resolution_rows_are_append_only(fake_conn):
    emit(
        _state_write_resolution(
            corridor=(329,),
            cause="resolved",
            outcome="exact_result",
            folded_value=1,
            contributed_to_unresolved_transition=False,
        )
    )
    emit(
        _state_write_resolution(
            corridor=(355, 398),
            cause="resolved",
            outcome="exact_result",
            folded_value=2,
            contributed_to_unresolved_transition=False,
        )
    )
    emit(_state_write_resolution(corridor=(355, 397)))
    rows = fake_conn.execute(
        "SELECT corridor,cause FROM state_write_resolutions ORDER BY rowid"
    ).fetchall()
    assert rows == [
        ("329", "resolved"),
        ("355>398", "resolved"),
        ("355>397", "no_def_within_hop_bound"),
    ]


# ---------------------------------------------------------------------------
# Emulator gap facts (ticket d81-c6n7, slice 5)
# ---------------------------------------------------------------------------


def _emulator_gap(**overrides):
    kwargs = dict(
        func_ea=0x7FFB0EB06E50,
        cause="stack_slot_in_aliased_memory",
        site_ea=0x7FFB0EB0CAB7,
        block_serial=236,
        occurrences=12,
        detail="ldx ss.2, %var_3A0.8",
        def_sites=((236, 0x7FFB0EB0CAB7),),
        maturity="MMAT_GLBOPT1",
        attempt=2,
        session_id="sess-1",
    )
    kwargs.update(overrides)
    return EmulatorGapObserved(**kwargs)


def test_emulator_gap_writes_lifecycle_and_fact_rows(fake_conn):
    emit(_emulator_gap())

    kind, maturity, correlation, payload = fake_conn.execute(
        "SELECT event_kind,maturity,correlation_id,payload_json "
        "FROM lifecycle_events WHERE event_kind='emulator_gap'"
    ).fetchone()
    assert kind == "emulator_gap"
    assert maturity == "MMAT_GLBOPT1"
    assert correlation == "2:stack_slot_in_aliased_memory:0x00007ffb0eb0cab7"
    body = json.loads(payload)
    assert body["kind"] == "EmulatorGapFact"
    assert body["cause"] == "stack_slot_in_aliased_memory"
    assert body["occurrences"] == 12
    assert body["block_serial"] == 236
    assert body["def_sites"] == [[236, 0x7FFB0EB0CAB7]]

    row = fake_conn.execute(
        "SELECT func_ea_hex,cause,site_ea_hex,site_ea_i64,block_serial,"
        "occurrences,detail,def_sites_json,maturity,attempt FROM emulator_gaps"
    ).fetchone()
    assert row[0] == "0x00007ffb0eb06e50"
    assert row[1] == "stack_slot_in_aliased_memory"
    assert row[2] == "0x00007ffb0eb0cab7"
    assert row[3] == 0x7FFB0EB0CAB7
    assert row[4] == 236
    assert row[5] == 12
    assert row[6] == "ldx ss.2, %var_3A0.8"
    assert json.loads(row[7]) == [[236, 0x7FFB0EB0CAB7]]
    assert row[8] == "MMAT_GLBOPT1"
    assert row[9] == 2


def test_emulator_gap_rows_are_append_only_per_attempt(fake_conn):
    emit(_emulator_gap(attempt=1, occurrences=3))
    emit(_emulator_gap(attempt=2, occurrences=4))
    emit(
        _emulator_gap(
            attempt=2,
            cause="unsupported_call_operand",
            site_ea=0x7FFB0EB0BCF7,
            occurrences=1,
        )
    )
    rows = fake_conn.execute(
        "SELECT attempt,cause,occurrences FROM emulator_gaps ORDER BY rowid"
    ).fetchall()
    assert rows == [
        (1, "stack_slot_in_aliased_memory", 3),
        (2, "stack_slot_in_aliased_memory", 4),
        (2, "unsupported_call_operand", 1),
    ]
