from __future__ import annotations

from dataclasses import replace

import pytest

from d810.backends.ida.idb_preparation.gateway import PreparationRunReceipt
from d810.capabilities.idb_preparation import (
    PreparationRunRequest,
    PreparationScriptDescriptor,
    PreparationState,
    PreparationTransactionId,
    PreparationTransactionRecord,
    PreparationTypeDelta,
    SerializedTypeSnapshot,
)
from d810.core.execution_journal import DecompilationSessionId, ExecutionAttemptId
from d810.manager.pre_hexrays_preparation import (
    PreHexPreparationController,
    PreparationMode,
)

pytestmark = pytest.mark.pure_python


def _script(script_id: str = "normalize") -> PreparationScriptDescriptor:
    return PreparationScriptDescriptor(
        script_id=script_id,
        display_name=script_id,
        path=f"/tmp/{script_id}.py",
        source_sha256="a" * 64,
        enabled=True,
        portable=True,
    )


def _record(
    script: PreparationScriptDescriptor,
    *,
    function_ea: int = 0x401000,
) -> PreparationTransactionRecord:
    return PreparationTransactionRecord(
        transaction_id=PreparationTransactionId.new(),
        database_identity="idb-a",
        anchor_function_ea=function_ea,
        script_id=script.script_id,
        script_path=script.path,
        script_source_sha256=script.source_sha256,
        authorizing_attempt_id=ExecutionAttemptId.new(
            session=DecompilationSessionId.new(), sequence=1
        ),
        state=PreparationState.IDB_PREPARED,
        created_at=1.0,
        updated_at=2.0,
    )


class _Gateway:
    def __init__(self) -> None:
        self.requests: list[
            tuple[PreparationRunRequest, tuple[PreparationTypeDelta, ...]]
        ] = []
        self.matches: dict[str, bool] = {}

    def run(
        self,
        request: PreparationRunRequest,
        *,
        type_proposals: tuple[PreparationTypeDelta, ...] = (),
    ) -> PreparationRunReceipt:
        self.requests.append((request, type_proposals))
        return PreparationRunReceipt(
            transaction_id=PreparationTransactionId.new(),
            state=PreparationState.IDB_PREPARED,
            type_deltas=type_proposals,
        )

    def transaction_matches_after_image(
        self, transaction_id: PreparationTransactionId
    ) -> bool:
        return self.matches.get(transaction_id.value, True)


def _controller(
    *,
    gateway: _Gateway,
    scripts: tuple[PreparationScriptDescriptor, ...] = (),
    prepared: tuple[PreparationTransactionRecord, ...] = (),
    proposals=(),
    transaction_types=None,
    acknowledged=None,
    discover_type_proposals=None,
) -> PreHexPreparationController:
    type_script = _script("d810-global-const-types")
    return PreHexPreparationController(
        database_identity="idb-a",
        scripts=scripts,
        gateway=gateway,
        prepared_records=lambda identity: prepared,
        transaction_type_deltas=(transaction_types or (lambda transaction_id: ())),
        discover_type_proposals=(discover_type_proposals or (lambda function_ea: None)),
        pending_type_proposals=lambda: tuple(proposals),
        acknowledge_type_proposals=(acknowledged or (lambda values: None)),
        type_step_descriptor=type_script,
    )


def test_runs_enabled_scripts_once_in_declared_order() -> None:
    gateway = _Gateway()
    controller = _controller(
        gateway=gateway,
        scripts=(_script("first"), _script("second")),
    )

    receipt = controller.prepare(0x401000, PreparationMode.AUTOMATIC)

    assert receipt.ok
    assert [request.script.script_id for request, _ in gateway.requests] == [
        "first",
        "second",
    ]


def test_reuses_only_exact_live_applied_script_receipt() -> None:
    script = _script()
    exact = _record(script)
    gateway = _Gateway()
    controller = _controller(
        gateway=gateway,
        scripts=(script,),
        prepared=(exact,),
    )

    receipt = controller.prepare(0x401000, PreparationMode.AUTOMATIC)

    assert receipt.ok
    assert receipt.reused_transaction_ids == (exact.transaction_id,)
    assert gateway.requests == []

    changed = replace(script, source_sha256="b" * 64)
    changed_controller = _controller(
        gateway=gateway,
        scripts=(changed,),
        prepared=(exact,),
    )
    changed_controller.prepare(0x401000, PreparationMode.AUTOMATIC)
    assert gateway.requests[-1][0].script is changed


def test_stale_applied_receipt_fails_closed_without_running_script() -> None:
    script = _script()
    exact = _record(script)
    gateway = _Gateway()
    gateway.matches[exact.transaction_id.value] = False
    controller = _controller(
        gateway=gateway,
        scripts=(script,),
        prepared=(exact,),
    )

    receipt = controller.prepare(0x401000, PreparationMode.AUTOMATIC)

    assert not receipt.ok
    assert "diverged" in (receipt.failure_reason or "")
    assert gateway.requests == []


def test_pending_types_use_transaction_lane_and_ack_only_after_success() -> None:
    before = SerializedTypeSnapshot.absent()
    after = SerializedTypeSnapshot.from_parts(b"const", b"fields", b"comments")
    proposal = type(
        "Proposal",
        (),
        {
            "function_ea": 0x401000,
            "type_delta": PreparationTypeDelta(0x500000, before, after),
        },
    )()
    acknowledged: list[tuple[object, ...]] = []
    gateway = _Gateway()
    controller = _controller(
        gateway=gateway,
        proposals=(proposal,),
        acknowledged=lambda values: acknowledged.append(tuple(values)),
    )

    receipt = controller.prepare(0x401000, PreparationMode.PREPARE_ONLY)

    assert receipt.ok
    assert len(gateway.requests) == 1
    request, deltas = gateway.requests[0]
    assert request.script.script_id == "d810-global-const-types"
    assert deltas == (proposal.type_delta,)
    assert acknowledged == [(proposal,)]


def test_static_type_discovery_runs_before_pending_proposals_are_consumed() -> None:
    before = SerializedTypeSnapshot.absent()
    after = SerializedTypeSnapshot.from_parts(b"const", b"fields", b"comments")
    proposal = type(
        "Proposal",
        (),
        {
            "function_ea": 0x401000,
            "type_delta": PreparationTypeDelta(0x500000, before, after),
        },
    )()
    proposals: list[object] = []
    discoveries: list[int] = []
    gateway = _Gateway()

    def discover(function_ea: int) -> None:
        discoveries.append(function_ea)
        proposals.append(proposal)

    controller = _controller(
        gateway=gateway,
        proposals=proposals,
        discover_type_proposals=discover,
    )

    receipt = controller.prepare(0x401000, PreparationMode.AUTOMATIC)

    assert receipt.ok
    assert discoveries == [0x401000]
    assert len(gateway.requests) == 1
    assert gateway.requests[0][1] == (proposal.type_delta,)


def test_generated_retry_does_not_reenter_controller() -> None:
    gateway = _Gateway()
    controller = _controller(gateway=gateway, scripts=(_script(),))

    controller.prepare(0x401000, PreparationMode.AUTOMATIC)
    # The manager owns retry scheduling; it does not call prepare() again.
    assert len(gateway.requests) == 1
