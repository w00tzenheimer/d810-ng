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
    MutationReceiptObserved,
    PassContractEvidencePublished,
    SemanticOutputVerifiedObserved,
)
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
    observe_dag,
    observe_modifications,
    observe_reachability,
    observe_state_dispatcher_rows,
    observe_state_transition_dispatch_resolutions,
    observe_unflatten_dispatcher_corridor_coverage,
)
from d810.analyses.value_flow.observation import FactObservation
from d810.transforms.dispatcher_corridor_coverage import (
    DISPATCHER_CORRIDOR_COVERAGE_METADATA,
    DISPATCHER_REMOVAL_PREFLIGHT_PROOF_METADATA,
    DispatcherBlockAnchor,
    DispatcherCorridorCoverageValidation,
    DispatcherRemovalPreflightProof,
    DispatcherRemovalPreflightValidation,
    RetiredDispatcherInfrastructure,
    collect_unflatten_dispatcher_outcome_observations_from_metadata,
)


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


def test_unflatten_dispatcher_corridor_coverage_buffers_then_persists_typed_fact(
    fake_conn,
):
    """A residual corridor must survive the event bus into the diagnostic DB."""
    observe_unflatten_dispatcher_corridor_coverage(
        func_ea=0x7FF859C06F60,
        observations=(
            FactObservation(
                fact_id=(
                    "unflatten-dispatcher-corridor:residual:"
                    "blk45@0x7ff859c07656->blk123@0x7ff859c08d35"
                    "->blk3@0x7ff859c070c0->blk4@0x7ff859c070c4"
                ),
                kind="UnflattenDispatcherCorridorCoverage",
                semantic_key="unflatten_dispatcher_corridor:residual",
                maturity="MMAT_GLBOPT1",
                phase="lower_state_machine",
                confidence=1.0,
                source_block=45,
                source_ea=0x7FF859C07656,
                payload={
                    "coverage": "residual",
                    "completion_status": "partial_residual_dispatcher",
                    "state_merge": {
                        "serial": 123,
                        "ea": 0x7FF859C08D35,
                        "label": "blk123@0x7ff859c08d35",
                    },
                    "path": [
                        {"serial": 45, "ea": 0x7FF859C07656},
                        {"serial": 123, "ea": 0x7FF859C08D35},
                        {"serial": 3, "ea": 0x7FF859C070C0},
                        {"serial": 4, "ea": 0x7FF859C070C4},
                    ],
                },
                evidence=(
                    "blk45@0x7ff859c07656",
                    "blk123@0x7ff859c08d35",
                    "blk3@0x7ff859c070c0",
                    "blk4@0x7ff859c070c4",
                ),
            ),
        ),
    )

    assert fake_conn.execute("SELECT COUNT(*) FROM fact_observations").fetchone() == (0,)

    request_capture_mba_snapshot(
        blocks=_make_snap_blocks(),
        label="unflat_recovery_status",
        func_ea=0x7FF859C06F60,
        maturity="MMAT_GLBOPT1",
        phase="post_pipeline",
    )

    row = fake_conn.execute(
        "SELECT kind, source_block, source_ea_i64, payload "
        "FROM fact_observations"
    ).fetchone()
    assert row[:3] == (
        "UnflattenDispatcherCorridorCoverage",
        45,
        0x7FF859C07656,
    )
    payload = json.loads(row[3])
    assert payload["coverage"] == "residual"
    assert payload["completion_status"] == "partial_residual_dispatcher"
    assert payload["state_merge"] == {
        "ea": 0x7FF859C08D35,
        "label": "blk123@0x7ff859c08d35",
        "serial": 123,
    }
    assert payload["path"][-1] == {"ea": 0x7FF859C070C4, "serial": 4}


def test_terminal_outcome_flushes_pending_after_callback_snapshot(fake_conn):
    """A callback-created snapshot must not strand a pending plan outcome."""
    func_ea = 0x7FF859C06F60
    pending = FactObservation(
        fact_id="unflatten-corridor:plan-a:pending",
        kind="UnflattenDispatcherCorridorCoverage",
        semantic_key="unflatten_dispatcher_corridor:plan-a",
        maturity="MMAT_GLBOPT1",
        phase="lower_state_machine",
        confidence=1.0,
        source_block=45,
        source_ea=0x7FF859C07656,
        payload={
            "application_status": "pending",
            "coverage": "pending",
            "plan_id": "plan-a",
        },
        evidence=("blk45@0x7ff859c07656",),
    )
    final = FactObservation(
        fact_id="unflatten-corridor:plan-a:rejected",
        kind="UnflattenDispatcherCorridorCoverage",
        semantic_key="unflatten_dispatcher_corridor:plan-a",
        maturity="MMAT_GLBOPT1",
        phase="patch_transaction",
        confidence=1.0,
        source_block=45,
        source_ea=0x7FF859C07656,
        payload={
            "application_status": "rejected_preflight",
            "coverage": "residual",
            "plan_id": "plan-a",
        },
        evidence=("blk45@0x7ff859c07656",),
    )
    observe_unflatten_dispatcher_corridor_coverage(
        func_ea=func_ea,
        observations=(pending,),
    )
    event_type = observability_events.OptblockCallbackExceptionObserved
    emit(
        event_type(
            func_ea=func_ea,
            maturity="MMAT_GLBOPT1",
            block_serial=45,
            block_ea=0x7FF859C07656,
            error_type="RuntimeError",
            error_message="callback snapshot first",
            traceback_text="RuntimeError: callback snapshot first",
        )
    )
    observe_unflatten_dispatcher_corridor_coverage(
        func_ea=func_ea,
        observations=(final,),
    )

    rows = fake_conn.execute(
        "SELECT fact_id, payload FROM fact_observations "
        "WHERE kind='UnflattenDispatcherCorridorCoverage' ORDER BY fact_id"
    ).fetchall()
    assert [row[0] for row in rows] == [
        "unflatten-corridor:plan-a:pending",
        "unflatten-corridor:plan-a:rejected",
    ]
    assert {json.loads(row[1])["application_status"] for row in rows} == {
        "pending",
        "rejected_preflight",
    }


def test_dispatcher_outcome_fact_ids_are_scoped_by_plan_id(fake_conn):
    """Two plan attempts at one snapshot must not overwrite each other."""
    metadata = {
        "function_ea": 0x401000,
        "dispatcher": {"serial": 2, "ea": 0x401080, "label": "blk2@0x401080"},
        "enumeration_complete": True,
        "covered_corridors": [],
        "residual_corridors": [],
    }
    request_capture_mba_snapshot(
        blocks=_make_snap_blocks(),
        label="scoped_outcomes",
        func_ea=0x401000,
        maturity="MMAT_GLBOPT1",
        phase="post_d810",
    )
    for plan_id in ("plan-one", "plan-two"):
        observe_unflatten_dispatcher_corridor_coverage(
            func_ea=0x401000,
            observations=collect_unflatten_dispatcher_outcome_observations_from_metadata(
                {DISPATCHER_CORRIDOR_COVERAGE_METADATA: metadata},
                maturity="MMAT_GLBOPT1",
                phase="lower_state_machine",
                plan_id=plan_id,
            ),
        )

    rows = fake_conn.execute(
        "SELECT fact_id, payload FROM fact_observations "
        "WHERE kind='UnflattenDispatcherCorridorCoverageSummary' ORDER BY fact_id"
    ).fetchall()
    assert len(rows) == 2
    assert {json.loads(row[1])["plan_id"] for row in rows} == {
        "plan-one",
        "plan-two",
    }
    assert all("plan=" in row[0] for row in rows)


def test_dispatcher_outcome_retry_attempts_persist_separate_terminal_rows(fake_conn):
    """Same-plan terminal retries retain both reasons at one SQLite snapshot."""
    metadata = {
        "function_ea": 0x401000,
        "dispatcher": {"serial": 2, "ea": 0x401080, "label": "blk2@0x401080"},
        "enumeration_complete": True,
        "covered_corridors": [],
        "residual_corridors": [],
    }
    request_capture_mba_snapshot(
        blocks=_make_snap_blocks(),
        label="retry_attempt_outcomes",
        func_ea=0x401000,
        maturity="MMAT_GLBOPT1",
        phase="post_d810",
    )
    for attempt_id, reason in (
        ("retry-attempt-one", "binding retry one"),
        ("retry-attempt-two", "binding retry two"),
    ):
        observe_unflatten_dispatcher_corridor_coverage(
            func_ea=0x401000,
            observations=collect_unflatten_dispatcher_outcome_observations_from_metadata(
                {DISPATCHER_CORRIDOR_COVERAGE_METADATA: metadata},
                maturity="MMAT_GLBOPT1",
                phase="patch_transaction",
                application_status="rejected_clean",
                outcome_reason=reason,
                plan_id="immutable-retry-plan",
                attempt_id=attempt_id,
            ),
        )

    rows = fake_conn.execute(
        "SELECT fact_id, payload FROM fact_observations "
        "WHERE kind='UnflattenDispatcherCorridorCoverageSummary' ORDER BY fact_id"
    ).fetchall()
    assert len(rows) == 2
    payloads = [json.loads(row[1]) for row in rows]
    assert {payload["plan_id"] for payload in payloads} == {"immutable-retry-plan"}
    assert {payload["attempt_id"] for payload in payloads} == {
        "retry-attempt-one",
        "retry-attempt-two",
    }
    assert {payload["outcome_reason"] for payload in payloads} == {
        "binding retry one",
        "binding retry two",
    }
    assert all("plan=immutable-retry-plan:attempt=retry-attempt-" in row[0] for row in rows)


def test_unflatten_persistence_failure_is_logged_not_silently_dropped(monkeypatch):
    """Closed/unavailable diagnostic connections remain observable failures."""
    from d810.core.diag import event_handlers

    logged = []
    monkeypatch.setattr(
        event_handlers,
        "get_diag_conn",
        lambda _func_ea: (_ for _ in ()).throw(sqlite3.ProgrammingError("closed")),
    )
    monkeypatch.setattr(
        event_handlers,
        "_logger",
        type("_Logger", (), {"exception": lambda *_args, **_kwargs: logged.append(1)})(),
    )
    event_handlers._handle_unflatten_dispatcher_corridor_coverage(
        observability_events.UnflattenDispatcherCorridorCoverageObserved(
            func_ea=0x401000,
            observations=(
                FactObservation(
                    fact_id="closed-db",
                    kind="UnflattenDispatcherCorridorCoverage",
                    semantic_key="closed-db",
                    maturity="MMAT_GLBOPT1",
                    phase="patch_transaction",
                    confidence=1.0,
                    payload={"application_status": "rejected_preflight"},
                    evidence=(),
                ),
            ),
        )
    )
    assert logged == [1]


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


@pytest.mark.parametrize(
    ("application_status", "outcome_reason", "expected_coverage"),
    (
        (
            "rejected_preflight",
            "entry=entry reachability collapsed",
            "residual",
        ),
        (
            "poisoned_restart_required",
            "observed reachability rejected: terminal=; entry=entry reachability collapsed",
            "residual",
        ),
        ("applied", None, "covered"),
    ),
)
def test_unflatten_dispatcher_terminal_outcome_persists_pending_and_final_status(
    fake_conn,
    application_status,
    outcome_reason,
    expected_coverage,
):
    """A final transaction outcome must not depend on a later MBA capture."""
    source = {"serial": 45, "ea": 0x7FF859C07656, "label": "blk45@0x7ff859c07656"}
    merge = {"serial": 123, "ea": 0x7FF859C08D35, "label": "blk123@0x7ff859c08d35"}
    feeder = {"serial": 3, "ea": 0x7FF859C070C0, "label": "blk3@0x7ff859c070c0"}
    dispatcher = {"serial": 4, "ea": 0x7FF859C070C4, "label": "blk4@0x7ff859c070c4"}
    handler = {"serial": 121, "ea": 0x7FF859C08B37, "label": "blk121@0x7ff859c08b37"}
    terminal = {"serial": 34, "ea": 0x7FF859C0747A, "label": "blk34@0x7ff859c0747a"}
    plan_metadata = {
        DISPATCHER_CORRIDOR_COVERAGE_METADATA: {
            "function_ea": 0x7FF859C06F60,
            "dispatcher": dispatcher,
            "enumeration_complete": True,
            "covered_corridors": [
                {
                    "source": source,
                    "state_merge": merge,
                    "dispatcher_feeder": feeder,
                    "dispatcher": dispatcher,
                    "path": [source, merge, feeder, dispatcher],
                }
            ],
            "residual_corridors": [],
        },
        DISPATCHER_REMOVAL_PREFLIGHT_PROOF_METADATA: {
            "function_ea": 0x7FF859C06F60,
            "dispatcher": dispatcher,
            "proof_status": "accepted",
            "reason": "typed_dispatcher_infrastructure_removed",
            "authoritative_handlers": [handler],
            "post_reachable_handlers": [handler],
            "pre_reachable_terminals": [terminal],
            "post_reachable_terminals": [terminal],
            "retired_infrastructure": [
                {"role": "comparison_dispatcher", "anchor": dispatcher},
                {"role": "dispatcher_feeder", "anchor": feeder},
                {"role": "state_merge", "anchor": merge},
            ],
            "lost_blocks": [merge, feeder, dispatcher],
            "state_plumbing": [feeder],
            "producer_safety": {
                "fragment_atomic": True,
                "non_state_use_def_veto": True,
                "non_state_use_def_checked": True,
                "non_state_use_def_severances_zero": True,
            },
            "coverage_enumeration_complete": True,
            "residual_corridor_count": 0,
        },
    }
    observed_validation = None
    projected_validation = None
    if application_status in {
        "rejected_preflight",
        "poisoned_restart_required",
    }:
        merge_anchor = DispatcherBlockAnchor(serial=123, ea=0x7FF859C08D35)
        feeder_anchor = DispatcherBlockAnchor(serial=3, ea=0x7FF859C070C0)
        dispatcher_anchor = DispatcherBlockAnchor(serial=4, ea=0x7FF859C070C4)
        handler_anchor = DispatcherBlockAnchor(serial=121, ea=0x7FF859C08B37)
        terminal_anchor = DispatcherBlockAnchor(serial=34, ea=0x7FF859C0747A)
        rejected_validation = DispatcherRemovalPreflightValidation(
            passed=False,
            reason="dispatcher_removal_proof_drift",
            proof=DispatcherRemovalPreflightProof(
                function_ea=0x7FF859C06F60,
                dispatcher=dispatcher_anchor,
                authoritative_handlers=(handler_anchor,),
                post_reachable_handlers=(),
                pre_reachable_terminals=(terminal_anchor,),
                post_reachable_terminals=(terminal_anchor,),
                retired_infrastructure=(
                    RetiredDispatcherInfrastructure(
                        role="state_merge",
                        anchor=merge_anchor,
                    ),
                    RetiredDispatcherInfrastructure(
                        role="dispatcher_feeder",
                        anchor=feeder_anchor,
                    ),
                    RetiredDispatcherInfrastructure(
                        role="comparison_dispatcher",
                        anchor=dispatcher_anchor,
                    ),
                ),
                lost_blocks=frozenset({3, 4, 123}),
                    lost_block_anchors=(
                    feeder_anchor,
                    dispatcher_anchor,
                        merge_anchor,
                    ),
                    state_plumbing=(feeder_anchor,),
                    producer_safety=(
                        ("fragment_atomic", True),
                        ("non_state_use_def_veto", True),
                        ("non_state_use_def_checked", True),
                        ("non_state_use_def_severances_zero", True),
                ),
                coverage_enumeration_complete=True,
                residual_corridor_count=0,
                passed=False,
                reason="authoritative_handler_lost",
            ),
        )
        if application_status == "rejected_preflight":
            projected_validation = rejected_validation
        else:
            observed_validation = rejected_validation

    observe_unflatten_dispatcher_corridor_coverage(
        func_ea=0x7FF859C06F60,
        observations=collect_unflatten_dispatcher_outcome_observations_from_metadata(
            plan_metadata,
            maturity="MMAT_GLBOPT1",
            phase="lower_state_machine",
        ),
    )
    assert fake_conn.execute("SELECT COUNT(*) FROM fact_observations").fetchone() == (0,)

    if application_status == "poisoned_restart_required":
        emit(
            DiagnosticSessionObserved(
                session_id="diag-test-session",
                func_ea=0x7FF859C06F60,
                top_level_epoch=0,
                native_key_json="{}",
                status="active",
            )
        )
        emit(
            MutationPlanObserved(
                session_id="diag-test-session",
                func_ea=0x7FF859C06F60,
                mutation_batch_id="diag-test-attempt",
                mutation_kind="block_replace",
                planned_operation_count=62,
                mba_generation=0,
                evidence_generation=0,
                maturity="MMAT_GLBOPT1",
                description="PatchPlan diag-test-attempt",
            )
        )
        emit(
            MutationReceiptObserved(
                session_id="diag-test-session",
                func_ea=0x7FF859C06F60,
                mutation_batch_id="diag-test-attempt",
                mutation_kind="block_replace",
                pre_generation=0,
                post_generation=0,
                planned_operation_count=62,
                applied_operation_count=62,
                evidence_generation=0,
                maturity="MMAT_GLBOPT1",
                outcome="aborted",
                description="PatchPlan diag-test-attempt",
                reason=outcome_reason,
            )
        )

    observe_unflatten_dispatcher_corridor_coverage(
        func_ea=0x7FF859C06F60,
        observations=collect_unflatten_dispatcher_outcome_observations_from_metadata(
            plan_metadata,
            maturity="MMAT_GLBOPT1",
            phase="patch_transaction",
            application_status=application_status,
            outcome_reason=outcome_reason,
            observed_validation=observed_validation,
            projected_validation=projected_validation,
        ),
    )

    snapshot = fake_conn.execute(
        "SELECT label, block_count, maturity, phase FROM snapshots"
    ).fetchone()
    assert snapshot == (
        f"unflatten_dispatcher_outcome:{application_status}",
        0,
        "MMAT_GLBOPT1",
        "post_d810",
    )
    rows = fake_conn.execute(
        "SELECT kind, payload FROM fact_observations ORDER BY fact_id"
    ).fetchall()
    assert {row[0] for row in rows} == {
        "UnflattenDispatcherCorridorCoverage",
        "UnflattenDispatcherCorridorCoverageSummary",
        "UnflattenDispatcherRemovalPreflightProof",
    }
    payloads = [json.loads(row[1]) for row in rows]
    final_corridor = next(
        payload
        for payload in payloads
        if payload.get("application_status") == application_status
        and payload.get("state_merge") is not None
    )
    assert final_corridor["coverage"] == expected_coverage
    assert final_corridor["state_merge"] == merge
    final_proof = next(
        payload
        for payload in payloads
        if payload.get("application_status") == application_status
        and payload.get("retired_infrastructure")
    )
    assert {entry["anchor"]["serial"] for entry in final_proof["retired_infrastructure"]} == {
        3,
        4,
        123,
    }
    if application_status in {"rejected_preflight", "poisoned_restart_required"}:
        validation_key = (
            "projected_validation"
            if application_status == "rejected_preflight"
            else "observed_validation"
        )
        assert final_proof[validation_key] == {
            "validation_status": "rejected",
            "reason": "dispatcher_removal_proof_drift",
            "proof": {
                "function_ea": 0x7FF859C06F60,
                "dispatcher": dispatcher,
                "proof_status": "rejected",
                "reason": "authoritative_handler_lost",
                "authoritative_handlers": [handler],
                "post_reachable_handlers": [],
                "pre_reachable_terminals": [terminal],
                "post_reachable_terminals": [terminal],
                "retired_infrastructure": [
                    {"role": "state_merge", "anchor": merge},
                    {"role": "dispatcher_feeder", "anchor": feeder},
                    {"role": "comparison_dispatcher", "anchor": dispatcher},
                ],
                "lost_blocks": [feeder, dispatcher, merge],
                "state_plumbing": [feeder],
                "producer_safety": {
                    "fragment_atomic": True,
                    "non_state_use_def_veto": True,
                    "non_state_use_def_checked": True,
                    "non_state_use_def_severances_zero": True,
                },
                "coverage_enumeration_complete": True,
                "residual_corridor_count": 0,
            },
        }
    if application_status == "poisoned_restart_required":
        assert fake_conn.execute(
            "SELECT mutation_kind, planned_operation_count, "
            "applied_operation_count, outcome, reason FROM mutation_receipts"
        ).fetchone() == (
            "block_replace",
            62,
            62,
            "aborted",
            outcome_reason,
        )
    assert any(
        payload.get("application_status") == "pending"
        and payload.get("coverage") == "pending"
        for payload in payloads
    )


def test_missing_dispatcher_removal_proof_persists_validation_only_fact(fake_conn):
    """A missing proof verdict remains queryable without invented proof inputs."""
    source = {"serial": 45, "ea": 0x7FF859C07656, "label": "blk45@0x7ff859c07656"}
    dispatcher = {"serial": 4, "ea": 0x7FF859C070C4, "label": "blk4@0x7ff859c070c4"}
    plan_metadata = {
        DISPATCHER_CORRIDOR_COVERAGE_METADATA: {
            "function_ea": 0x7FF859C06F60,
            "dispatcher": dispatcher,
            "enumeration_complete": True,
            "covered_corridors": [
                {
                    "source": source,
                    "state_merge": None,
                    "dispatcher_feeder": source,
                    "dispatcher": dispatcher,
                    "path": [source, dispatcher],
                }
            ],
            "residual_corridors": [],
        }
    }
    projected_validation = DispatcherRemovalPreflightValidation(
        passed=False,
        reason="dispatcher_removal_proof_missing",
    )
    projected_coverage_validation = DispatcherCorridorCoverageValidation(
        passed=True,
        reason="dispatcher_corridor_coverage_matches_observed",
    )

    observe_unflatten_dispatcher_corridor_coverage(
        func_ea=0x7FF859C06F60,
        observations=collect_unflatten_dispatcher_outcome_observations_from_metadata(
            plan_metadata,
            maturity="MMAT_GLBOPT1",
            phase="patch_transaction",
            application_status="rejected_preflight",
            outcome_reason="dispatcher_removal=dispatcher_removal_proof_missing",
            projected_validation=projected_validation,
            projected_coverage_validation=projected_coverage_validation,
            plan_id="missing-proof-plan",
            attempt_id="missing-proof-attempt",
        ),
    )

    row = fake_conn.execute(
        "SELECT source_block, source_ea_i64, payload FROM fact_observations "
        "WHERE kind='UnflattenDispatcherRemovalPreflightProof'"
    ).fetchone()
    assert row is not None
    assert row[:2] == (4, 0x7FF859C070C4)
    payload = json.loads(row[2])
    assert payload["validation_only"] is True
    assert payload["raw_proof_present"] is False
    assert payload["dispatcher"] == dispatcher
    assert payload["projected_validation"] == {
        "validation_status": "rejected",
        "reason": "dispatcher_removal_proof_missing",
        "proof": None,
    }
    assert "authoritative_handlers" not in payload


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


def test_use_def_severance_observations_persist_exact_anchors_without_overwrite(
    fake_conn,
):
    """Each heuristic severance keeps its complete source/target/use evidence."""
    func_ea = 0x7FF85A850000
    source = {
        "serial": 45,
        "ea": 0x7FF85A852A00,
        "label": "blk45@0x7ff85a852a00",
    }
    old_target = {
        "serial": 46,
        "ea": 0x7FF85A852A10,
        "label": "blk46@0x7ff85a852a10",
    }
    new_target = {
        "serial": 47,
        "ea": 0x7FF85A852A20,
        "label": "blk47@0x7ff85a852a20",
    }
    use = {
        "serial": 88,
        "ea": 0x7FF85A853300,
        "label": "blk88@0x7ff85a853300",
    }
    use_instruction_ea = 0x7FF85A8533AA
    violations = [
        {
            "source": source,
            "old_target": old_target,
            "new_target": new_target,
            "stack_offset": 0x70 + index,
            "stack_size": 4,
            "use": use,
            "use_instruction_ea": use_instruction_ea,
        }
        for index in range(3)
    ]
    plan_metadata = {
        DISPATCHER_CORRIDOR_COVERAGE_METADATA: {
            "function_ea": func_ea,
            "dispatcher": {
                "serial": 2,
                "ea": 0x7FF85A850100,
                "label": "blk2@0x7ff85a850100",
            },
            "enumeration_complete": True,
            "covered_corridors": [],
            "residual_corridors": [],
        },
        "use_def_severance_audit": {
            "function_ea": func_ea,
            "executed": True,
            "clean": False,
            "severance_count": 3,
            "failure_reason": None,
            "enforced": False,
            "enforcement_enabled": False,
            "enforcement_status": "heuristic_observed",
            "violations": violations,
        },
    }
    request_capture_mba_snapshot(
        blocks=_make_snap_blocks(),
        label="use_def_severances",
        func_ea=func_ea,
        maturity="MMAT_GLBOPT1",
        phase="post_d810",
    )

    observe_unflatten_dispatcher_corridor_coverage(
        func_ea=func_ea,
        observations=collect_unflatten_dispatcher_outcome_observations_from_metadata(
            plan_metadata,
            maturity="MMAT_GLBOPT1",
            phase="lower_state_machine",
            plan_id="use-def-plan",
            attempt_id="use-def-attempt",
        ),
    )

    rows = fake_conn.execute(
        "SELECT fact_id, payload FROM fact_observations "
        "WHERE kind='UnflattenUseDefSeverance' ORDER BY fact_id"
    ).fetchall()
    assert len(rows) == 3
    assert len({row[0] for row in rows}) == 3
    payloads = [json.loads(row[1]) for row in rows]
    assert all(payload["source"] == source for payload in payloads)
    assert all(payload["old_target"]["serial"] is not None for payload in payloads)
    assert all(payload["old_target"]["ea"] is not None for payload in payloads)
    assert all(payload["new_target"]["serial"] is not None for payload in payloads)
    assert all(payload["new_target"]["ea"] is not None for payload in payloads)
    assert all(payload["use"] == use for payload in payloads)
    assert {payload["use_instruction_ea"] for payload in payloads} == {
        use_instruction_ea
    }
    assert {payload["enforcement_status"] for payload in payloads} == {
        "heuristic_observed"
    }
    assert {payload["stack_offset"] for payload in payloads} == {0x70, 0x71, 0x72}
    assert all(payload["stack_size"] == 4 for payload in payloads)
    summary = fake_conn.execute(
        "SELECT payload FROM fact_observations "
        "WHERE kind='UnflattenUseDefSeveranceSummary'"
    ).fetchone()
    assert summary is not None
    assert json.loads(summary[0])["severance_count"] == 3


def test_partial_use_def_severance_persists_safety_unavailable(fake_conn):
    """Partial evidence is durable without claiming an authoritative veto."""
    func_ea = 0x401000
    request_capture_mba_snapshot(
        blocks=_make_snap_blocks(),
        label="partial_use_def_severance",
        func_ea=func_ea,
        maturity="MMAT_GLBOPT1",
        phase="post_d810",
    )
    observe_unflatten_dispatcher_corridor_coverage(
        func_ea=func_ea,
        observations=collect_unflatten_dispatcher_outcome_observations_from_metadata(
            {
                "use_def_severance_audit": {
                    "function_ea": func_ea,
                    "executed": False,
                    "clean": False,
                    "severance_count": 1,
                    "failure_reason": "query_failed:LookupError",
                    "enforced": True,
                    "enforcement_enabled": True,
                    "violations": [
                        {
                            "source": {
                                "serial": 1,
                                "ea": 0x401100,
                                "label": "blk1@0x401100",
                            },
                            "old_target": {
                                "serial": 2,
                                "ea": 0x401200,
                                "label": "blk2@0x401200",
                            },
                            "new_target": {
                                "serial": 3,
                                "ea": 0x401300,
                                "label": "blk3@0x401300",
                            },
                            "stack_offset": 0x70,
                            "stack_size": 4,
                            "use": {
                                "serial": 4,
                                "ea": 0x401400,
                                "label": "blk4@0x401400",
                            },
                            "use_instruction_ea": 0x4014AA,
                        }
                    ],
                }
            },
            maturity="MMAT_GLBOPT1",
            phase="lower_state_machine",
        ),
    )

    rows = fake_conn.execute(
        "SELECT kind, payload FROM fact_observations "
        "WHERE kind IN ('UnflattenUseDefSeverance', "
        "'UnflattenUseDefSeveranceSummary') ORDER BY fact_id"
    ).fetchall()
    assert len(rows) == 2
    payloads = [json.loads(row[1]) for row in rows]
    assert {payload["enforcement_status"] for payload in payloads} == {
        "safety_unavailable"
    }
    assert {payload["severance_count"] for payload in payloads} == {1}
    violation_payloads = [
        payload
        for (kind, _), payload in zip(rows, payloads)
        if kind == "UnflattenUseDefSeverance"
    ]
    assert [payload["use_instruction_ea"] for payload in violation_payloads] == [
        0x4014AA
    ]


def test_use_def_observation_clears_serial_when_anchor_ea_is_missing(fake_conn):
    """A serial without its EA is not persisted as a falsely stable anchor."""
    func_ea = 0x401000
    request_capture_mba_snapshot(
        blocks=_make_snap_blocks(),
        label="missing_use_def_ea",
        func_ea=func_ea,
        maturity="MMAT_GLBOPT1",
        phase="post_d810",
    )
    observe_unflatten_dispatcher_corridor_coverage(
        func_ea=func_ea,
        observations=collect_unflatten_dispatcher_outcome_observations_from_metadata(
            {
                "use_def_severance_audit": {
                    "function_ea": func_ea,
                    "executed": True,
                    "clean": False,
                    "severance_count": 1,
                    "enforced": True,
                    "violations": [
                        {
                            "source": {"serial": 45, "ea": None, "label": "unknown"},
                            "old_target": {"serial": 46, "ea": 0x4020},
                            "new_target": {"serial": 47, "ea": 0x4030},
                            "stack_offset": 0x70,
                            "stack_size": 4,
                            "use": {"serial": 88, "ea": 0x4040},
                        }
                    ],
                }
            },
            maturity="MMAT_GLBOPT1",
            phase="lower_state_machine",
        ),
    )
    row = fake_conn.execute(
        "SELECT payload FROM fact_observations "
        "WHERE kind='UnflattenUseDefSeverance'"
    ).fetchone()
    assert row is not None
    assert json.loads(row[0])["source"]["serial"] is None
