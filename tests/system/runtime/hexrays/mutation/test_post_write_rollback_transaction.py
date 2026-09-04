"""A completed post-write rollback closes as an exact recorded failure.

A guard that rejects *after* the preflight bound it has sibling writes behind
it.  When a pre-apply snapshot exists the modifier restores the MBA, and the
transaction that authorized those writes must then close as
``ROLLED_BACK_CLEAN``: an exact, recorded failure that leaves the CFG
generation usable.

It did not.  ``_record_snapshot_rollback`` aborted the gateway from inside the
modifier, so the transaction was already closed when its authority - the
translator - handed over the accounting it still owed (coalesced supersessions,
preflight drops).  ``record_coalesced_supersessions`` calls ``_require_active``
and raised, the rollback never completed through the path that claims to be
clean, and no ``ROLLED_BACK_CLEAN`` phase was ever recorded.  The system
acceptance did not catch it because sub_7FFB0E398850 never rolled back.

Closing now belongs to one owner.  The modifier reports a ``RollbackOutcome``
and returns; the translator hands over every accounting term and then records
the typed failure and closes.  The realization inventory the receipt satisfies
is::

    applied + superseded + preflight_dropped + rolled_back == planned

and a completed rollback contributes ``rolled_back == planned`` with
``applied == 0``: a snapshot restores the pre-apply MBA, so every planned step
is undone, including the ones that never ran.

System-runtime tier because ``deferred_modifier`` and ``ir_translator`` both
import ``ida_hexrays`` at module level; the gateway, the identity index and the
disposition vocabulary are pure Python, so the only fixture is a stub MBA.
"""

from __future__ import annotations

from types import SimpleNamespace

import pytest

from d810.core.events import EventEmitter
from d810.hexrays.ir.mba_identity_index import MbaBlockIdentityIndex
from d810.hexrays.mutation import deferred_modifier as dm
from d810.hexrays.mutation.guarded_removal_binding import (
    GuardedRemovalPlanDisposition,
    decide_post_write_guard_rejection,
)
from d810.hexrays.mutation.ir_translator import IDAIRTranslator
from d810.hexrays.mutation.mba_mutation_events import (
    MbaCfgTransactionAuthorityObserved,
    MbaMutationAborted,
    MbaMutationGateway,
    StructuralMutationKind,
)
from d810.transforms.cfg_transaction import (
    CfgGenerationPoisoned,
    CfgTransactionPhase,
    TransactionAttemptId,
)
from tests.native_preanalysis import make_native_key

pytestmark = pytest.mark.ida_required

NATIVE_KEY = make_native_key()
PLANNED_OPERATIONS = 3


class _Recorder:
    """Capture every transaction phase and every batch closure."""

    def __init__(self) -> None:
        self.emitter = EventEmitter()
        self.phases: list[MbaCfgTransactionAuthorityObserved] = []
        self.aborted: list[MbaMutationAborted] = []
        self.emitter.on(MbaCfgTransactionAuthorityObserved, self.phases.append)
        self.emitter.on(MbaMutationAborted, self.aborted.append)

    def count(self, phase: CfgTransactionPhase) -> int:
        return sum(1 for event in self.phases if event.phase is phase)


def _realizing_gateway(recorder: _Recorder) -> MbaMutationGateway:
    """Open one typed patch transaction that has crossed the write boundary."""
    index = MbaBlockIdentityIndex.from_bindings(
        session_id="rollback-session",
        generation=3,
        bindings=(),
        native_key=NATIVE_KEY,
    )
    gateway = MbaMutationGateway(
        generation=3,
        session_id="rollback-session",
        identity_index=index,
        event_emitter=recorder.emitter,
        native_key=NATIVE_KEY,
    )
    attempt = TransactionAttemptId(
        plan_id="plan-rollback",
        session_id=index.session_id,
        generation=index.generation,
        attempt_id="attempt-rollback",
    )
    gateway.begin_batch(
        StructuralMutationKind.BLOCK_REPLACE,
        serial_quantity=1,
        planned_operation_count=PLANNED_OPERATIONS,
        transaction_attempt=attempt,
        patch_plan_id=attempt.plan_id,
    )
    gateway.begin_patch_realization(attempt, plan_refs=())
    return gateway


def _modifier(gateway: MbaMutationGateway, *, snapshot: object | None):
    """Build the production modifier around a stub MBA and an open gateway."""
    modifier = dm.DeferredGraphModifier.__new__(dm.DeferredGraphModifier)
    modifier.mba = SimpleNamespace(qty=7)
    modifier.modifications = [object()] * PLANNED_OPERATIONS
    modifier.verify_failed = False
    modifier.transaction_complete = True
    modifier.plan_refusal_reason = None
    modifier.rollback_outcome = None
    modifier.last_apply_phase = None
    modifier.last_apply_subphase = None
    modifier.event_emitter = None
    modifier._superseded_count = 0
    modifier._preflight_dropped_instruction_ops = 0
    modifier._pre_snapshot = snapshot
    modifier._mutation_gateway = gateway
    return modifier


def _restore_stub(modifier, restored: list[object]):
    """Stand in for the IDA-level snapshot restore, recording that it ran."""

    def _restore(snapshot: object) -> bool:
        restored.append(snapshot)
        modifier.mba.qty = 1
        return True

    return _restore


def test_rollback_leaves_the_typed_transaction_open_for_its_authority() -> None:
    """The modifier must not close a transaction it does not own.

    This is the defect verbatim: the accounting hand-over runs immediately
    after apply and needs the batch still active.
    """
    recorder = _Recorder()
    gateway = _realizing_gateway(recorder)
    modifier = _modifier(gateway, snapshot=object())
    modifier._restore_from_snapshot = _restore_stub(modifier, [])

    modifier._record_snapshot_rollback("post-apply verify failure")

    assert gateway.active is True
    gateway.record_coalesced_supersessions(0)


def test_post_write_guard_rollback_closes_as_one_rolled_back_clean_failure() -> None:
    """modifier -> gateway -> translator completes without raising."""
    recorder = _Recorder()
    gateway = _realizing_gateway(recorder)
    snapshot = object()
    modifier = _modifier(gateway, snapshot=snapshot)
    restored: list[object] = []
    modifier._restore_from_snapshot = _restore_stub(modifier, restored)

    verdict = decide_post_write_guard_rejection(
        description="remove insn @0x401010",
        live_mutation_started=True,
        rollback_available=True,
    )
    assert verdict.disposition is GuardedRemovalPlanDisposition.ROLL_BACK_PLAN

    modifier._settle_post_write_guard_rejection(verdict, applied_before_rejection=2)

    rollback = IDAIRTranslator._hand_over_realization_accounting(gateway, modifier)
    assert rollback is not None and rollback.operation_count == PLANNED_OPERATIONS

    IDAIRTranslator._fail_patch_attempt(
        gateway,
        RuntimeError(modifier.plan_refusal_reason),
        failure_phase="backend_apply",
        rollback=rollback,
    )

    assert recorder.count(CfgTransactionPhase.ROLLED_BACK_CLEAN) == 1
    assert recorder.count(CfgTransactionPhase.POISONED_RESTART_REQUIRED) == 0
    assert gateway.active is False
    failure = gateway.transaction_failure
    assert failure is not None
    assert failure.phase is CfgTransactionPhase.ROLLED_BACK_CLEAN
    assert failure.live_mutation_started is True

    # The generation survives an exact rollback: nothing has to be rebuilt.
    gateway.identity_index.require_generation_usable()

    # The MBA is back at its pre-apply shape, restored from the snapshot the
    # modifier captured before the batch wrote anything.
    assert restored == [snapshot]
    assert modifier.mba.qty == 1

    # applied + superseded + preflight_dropped + rolled_back == planned
    assert len(recorder.aborted) == 1
    closure = recorder.aborted[0]
    assert closure.planned_operation_count == PLANNED_OPERATIONS
    assert closure.applied_operation_count == 0
    assert closure.rollback_attempted is True
    assert closure.rollback_succeeded is True
    assert (
        closure.applied_operation_count
        + gateway._superseded_operation_count
        + gateway._preflight_dropped_operation_count
        + gateway._rolled_back_operation_count
        == closure.planned_operation_count
    )
    assert gateway._rolled_back_operation_count == PLANNED_OPERATIONS


def test_post_write_guard_rejection_without_a_snapshot_poisons_the_generation() -> None:
    """The mirror case: nothing can undo the writes, so the generation dies."""
    recorder = _Recorder()
    gateway = _realizing_gateway(recorder)
    modifier = _modifier(gateway, snapshot=None)

    verdict = decide_post_write_guard_rejection(
        description="remove insn @0x401010",
        live_mutation_started=True,
        rollback_available=False,
    )
    assert verdict.disposition is GuardedRemovalPlanDisposition.POISON_GENERATION

    modifier._settle_post_write_guard_rejection(verdict, applied_before_rejection=2)

    assert modifier.verify_failed is True
    rollback = IDAIRTranslator._hand_over_realization_accounting(gateway, modifier)
    assert rollback is None

    with pytest.raises(CfgGenerationPoisoned):
        IDAIRTranslator._fail_patch_attempt(
            gateway,
            RuntimeError(modifier.plan_refusal_reason),
            failure_phase="backend_apply",
            rollback=rollback,
        )

    assert recorder.count(CfgTransactionPhase.POISONED_RESTART_REQUIRED) == 1
    assert recorder.count(CfgTransactionPhase.ROLLED_BACK_CLEAN) == 0
    assert gateway.active is False
    with pytest.raises(Exception):
        gateway.identity_index.require_generation_usable()


def test_a_partial_rollback_term_is_not_a_legal_closure() -> None:
    """A rollback undoes the whole plan or it is not a rollback."""
    recorder = _Recorder()
    gateway = _realizing_gateway(recorder)

    with pytest.raises(ValueError, match="whole plan"):
        gateway.record_completed_rollback(rolled_back_operation_count=1)
