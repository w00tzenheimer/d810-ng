from __future__ import annotations

from d810.core.diag import (
    close_diag_session,
    get_diag_conn,
    open_diag_session,
)
from d810.core.events import EventEmitter
from d810.core.observability import emit, reset_diagnostic_bus
from d810.core.observability_events import DiagnosticSessionObserved
from d810.core.settings import configure_settings, get_settings
from d810.hexrays.ir.mba_identity_index import MbaBlockIdentityIndex
from d810.hexrays.mutation.mba_mutation_events import (
    MbaCfgTransactionAuthorityObserved,
    MbaMutationGateway,
    StructuralMutationKind,
)
from d810.manager.manager import D810Manager
from d810.transforms.cfg_transaction import PlanBlockRef, TransactionAttemptId
from tests.native_preanalysis import make_native_key


def test_gateway_creation_witness_reaches_diagnostic_database(tmp_path) -> None:
    native_key = make_native_key(function_rva=0xC8B0)
    emitter = EventEmitter()
    emitter.on(
        MbaCfgTransactionAuthorityObserved,
        D810Manager._on_cfg_transaction_authority,
    )
    reset_diagnostic_bus()
    previous_diag_snapshots = get_settings().diag_snapshots
    configure_settings(diag_snapshots=True)
    open_diag_session(0x40C8B0, log_dir=str(tmp_path))
    conn = get_diag_conn(0x40C8B0, log_dir=str(tmp_path))
    assert conn is not None
    try:
        emit(
            DiagnosticSessionObserved(
                "runtime-session",
                0x40C8B0,
                1,
                "{}",
                "active",
            )
        )
        index = MbaBlockIdentityIndex.from_bindings(
            session_id="runtime-session",
            generation=4,
            bindings=(),
            native_key=native_key,
        )
        gateway = MbaMutationGateway(
            session_id="runtime-session",
            function_ea=0x40C8B0,
            maturity=1,
            generation=4,
            identity_index=index,
            event_emitter=emitter,
            native_key=native_key,
        )
        attempt = TransactionAttemptId(
            plan_id="runtime-plan",
            session_id="runtime-session",
            generation=4,
            attempt_id="runtime-attempt",
        )
        plan_ref = PlanBlockRef("runtime-plan", "created-block")
        gateway.begin_batch(
            StructuralMutationKind.BLOCK_INSERT,
            serial_quantity=0,
            transaction_attempt=attempt,
            patch_plan_refs=(plan_ref,),
        )
        reservation = gateway.reserve_plan_block(attempt, plan_ref)

        assert conn.execute(
            "SELECT current_phase,mutation_started FROM cfg_transaction_attempts "
            "WHERE plan_id=? AND attempt_id=?",
            ("runtime-plan", "runtime-attempt"),
        ).fetchone() == ("bound", 0)
        assert conn.execute(
            "SELECT requested_insertion_serial,returned_serial,state "
            "FROM cfg_creation_witnesses WHERE plan_id=? AND attempt_id=?",
            ("runtime-plan", "runtime-attempt"),
        ).fetchone() == (None, None, "reserved")

        gateway._record_cfg_mutation_started()
        receipt = gateway.bind_reserved_plan_block(
            attempt,
            plan_ref,
            insertion_serial=0,
            returned_serial=0,
        )
        gateway.commit()

        assert receipt.logical_version is reservation.logical_version
        assert conn.execute(
            "SELECT current_phase,mutation_started,poisoned "
            "FROM cfg_transaction_attempts WHERE plan_id=? AND attempt_id=?",
            ("runtime-plan", "runtime-attempt"),
        ).fetchone() == ("committed", 1, 0)
        assert conn.execute(
            "SELECT provenance,reserved_handle_token,logical_proxy_token,"
            "requested_insertion_serial,returned_serial,state "
            "FROM cfg_creation_witnesses WHERE plan_id=? AND attempt_id=?",
            ("runtime-plan", "runtime-attempt"),
        ).fetchone() == (
            "created_synthetic",
            reservation.logical_version.handle.token,
            reservation.logical_version.version_id.proxy_token,
            0,
            0,
            "committed",
        )
    finally:
        close_diag_session()
        configure_settings(diag_snapshots=previous_diag_snapshots)
        reset_diagnostic_bus()
