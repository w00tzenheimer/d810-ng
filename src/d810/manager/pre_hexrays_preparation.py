"""Manager-owned orchestration for reversible pre-Hex-Rays preparation."""

from __future__ import annotations

import enum
from dataclasses import dataclass

from d810.backends.ida.idb_preparation.gateway import PreparationRunReceipt
from d810.capabilities.idb_preparation import (
    PreparationRunRequest,
    PreparationScriptDescriptor,
    PreparationState,
    PreparationTransactionId,
    PreparationTransactionRecord,
    PreparationTypeDelta,
)
from d810.core.execution_journal import DecompilationSessionId, ExecutionAttemptId
from d810.core.typing import Callable, Protocol
from d810.passes.constant_simplification_options import ConstantPreparationOptions

__all__ = [
    "PreHexPreparationController",
    "PreparationBatchReceipt",
    "PreparationMode",
    "PreparationStatusSnapshot",
]


class PreparationMode(str, enum.Enum):
    AUTOMATIC = "automatic"
    PREPARE_ONLY = "prepare_only"


class PreparationGateway(Protocol):
    def run(
        self,
        request: PreparationRunRequest,
        *,
        type_proposals: tuple[PreparationTypeDelta, ...] = (),
    ) -> PreparationRunReceipt: ...

    def transaction_matches_after_image(
        self,
        transaction_id: PreparationTransactionId,
    ) -> bool: ...


class PendingTypeProposal(Protocol):
    function_ea: int

    @property
    def type_delta(self) -> PreparationTypeDelta: ...


@dataclass(frozen=True, slots=True)
class PreparationBatchReceipt:
    function_ea: int
    mode: PreparationMode
    run_receipts: tuple[PreparationRunReceipt, ...] = ()
    reused_transaction_ids: tuple[PreparationTransactionId, ...] = ()
    failure_reason: str | None = None

    @property
    def ok(self) -> bool:
        return self.failure_reason is None and all(
            receipt.ok for receipt in self.run_receipts
        )


@dataclass(frozen=True, slots=True)
class PreparationStatusSnapshot:
    """Portable proposal/transaction state for the preparation lane."""

    pending: tuple[str, ...] = ()
    applied: tuple[str, ...] = ()
    conflicting: tuple[str, ...] = ()
    restored: tuple[str, ...] = ()
    pending_reason: str | None = None

    @property
    def pending_count(self) -> int:
        return len(self.pending)

    @property
    def applied_count(self) -> int:
        return len(self.applied)

    @property
    def conflicting_count(self) -> int:
        return len(self.conflicting)

    @property
    def restored_count(self) -> int:
        return len(self.restored)

    @property
    def pending_identities(self) -> tuple[str, ...]:
        return self.pending

    @property
    def applied_identities(self) -> tuple[str, ...]:
        return self.applied

    @property
    def conflicting_identities(self) -> tuple[str, ...]:
        return self.conflicting

    @property
    def restored_identities(self) -> tuple[str, ...]:
        return self.restored


PreparedRecordProvider = Callable[[str], tuple[PreparationTransactionRecord, ...]]
TransactionTypeDeltaProvider = Callable[
    [PreparationTransactionId], tuple[PreparationTypeDelta, ...]
]
PendingTypeProposalProvider = Callable[[], tuple[PendingTypeProposal, ...]]
TypeProposalDiscovery = Callable[[int], object]
ProposalAcknowledgement = Callable[[tuple[PendingTypeProposal, ...]], None]


class PreHexPreparationController:
    """Run each exact preparation step before native analysis or Hex-Rays."""

    def __init__(
        self,
        *,
        database_identity: str,
        scripts: tuple[PreparationScriptDescriptor, ...],
        gateway: PreparationGateway,
        prepared_records: PreparedRecordProvider,
        transaction_type_deltas: TransactionTypeDeltaProvider,
        discover_type_proposals: TypeProposalDiscovery,
        pending_type_proposals: PendingTypeProposalProvider,
        acknowledge_type_proposals: ProposalAcknowledgement,
        type_step_descriptor: PreparationScriptDescriptor,
        preparation_options: ConstantPreparationOptions | None = None,
    ) -> None:
        if not isinstance(database_identity, str) or not database_identity.strip():
            raise ValueError("database_identity must be non-empty")
        self._database_identity = database_identity
        self._scripts = tuple(scripts)
        self._gateway = gateway
        self._prepared_records = prepared_records
        self._transaction_type_deltas = transaction_type_deltas
        self._discover_type_proposals = discover_type_proposals
        self._pending_type_proposals = pending_type_proposals
        self._acknowledge_type_proposals = acknowledge_type_proposals
        self._type_step_descriptor = type_step_descriptor
        self._preparation_options = (
            preparation_options
            if preparation_options is not None
            else ConstantPreparationOptions()
        )
        if not isinstance(self._preparation_options, ConstantPreparationOptions):
            raise TypeError(
                "preparation_options must be ConstantPreparationOptions"
            )

    @property
    def database_identity(self) -> str:
        return self._database_identity

    @property
    def scripts(self) -> tuple[PreparationScriptDescriptor, ...]:
        return self._scripts

    @property
    def preparation_options(self) -> ConstantPreparationOptions:
        return self._preparation_options

    def configure_preparation_options(
        self,
        preparation_options: ConstantPreparationOptions,
    ) -> None:
        """Update policy only at a manager-owned runtime boundary."""

        if not isinstance(preparation_options, ConstantPreparationOptions):
            raise TypeError(
                "preparation_options must be ConstantPreparationOptions"
            )
        self._preparation_options = preparation_options

    @staticmethod
    def _type_identity(function_ea: int, item_ea: int) -> str:
        return f"function=0x{int(function_ea):X}:item=0x{int(item_ea):X}"

    @classmethod
    def _proposal_identity(cls, proposal: PendingTypeProposal) -> str:
        try:
            function_ea = int(proposal.function_ea)
            item_ea = int(proposal.type_delta.item_ea)
        except (AttributeError, TypeError, ValueError):
            return repr(proposal)
        return cls._type_identity(function_ea, item_ea)

    def status_snapshot(self) -> PreparationStatusSnapshot:
        """Return durable proposal/transaction truth without mutating state."""

        try:
            proposals = tuple(self._pending_type_proposals())
        except Exception:
            proposals = ()
        pending = tuple(
            sorted(
                {
                    self._proposal_identity(proposal)
                    for proposal in proposals
                }
            )
        )
        applied: list[str] = []
        conflicting: list[str] = []
        restored: list[str] = []
        try:
            records = self._prepared_records(self._database_identity)
        except Exception:
            records = ()
        for record in records:
            try:
                type_deltas = self._transaction_type_deltas(record.transaction_id)
            except Exception:
                type_deltas = ()
            if not type_deltas:
                continue
            identities = tuple(
                self._type_identity(record.anchor_function_ea, delta.item_ea)
                for delta in type_deltas
            )
            if record.state is PreparationState.RESTORED:
                restored.extend(identities)
                continue
            if record.state is PreparationState.IDB_PREPARED:
                try:
                    matches = bool(
                        self._gateway.transaction_matches_after_image(
                            record.transaction_id
                        )
                    )
                except Exception:
                    matches = False
                (applied if matches else conflicting).extend(identities)
                continue
            if record.state in {
                PreparationState.RESTORING,
                PreparationState.RESTORE_FAILED,
                PreparationState.RECOVERY_REQUIRED,
                PreparationState.FAILED,
                PreparationState.REJECTED,
            }:
                conflicting.extend(identities)
        return PreparationStatusSnapshot(
            pending=pending,
            applied=tuple(sorted(applied)),
            conflicting=tuple(sorted(conflicting)),
            restored=tuple(sorted(restored)),
            pending_reason=("next preparation round" if pending else None),
        )

    # Short alias for manager/UI ports that call the value a status snapshot.
    preparation_status = status_snapshot

    @staticmethod
    def _record_matches_script(
        record: PreparationTransactionRecord,
        *,
        function_ea: int,
        descriptor: PreparationScriptDescriptor,
    ) -> bool:
        return (
            record.state is PreparationState.IDB_PREPARED
            and record.anchor_function_ea == function_ea
            and record.script_id == descriptor.script_id
            and record.script_path == descriptor.path
            and record.script_source_sha256 == descriptor.source_sha256
        )

    def _exact_records(
        self,
        records: tuple[PreparationTransactionRecord, ...],
        *,
        function_ea: int,
        descriptor: PreparationScriptDescriptor,
        type_deltas: tuple[PreparationTypeDelta, ...] = (),
    ) -> tuple[PreparationTransactionRecord, ...]:
        matches: list[PreparationTransactionRecord] = []
        for record in records:
            if not self._record_matches_script(
                record,
                function_ea=function_ea,
                descriptor=descriptor,
            ):
                continue
            if self._transaction_type_deltas(record.transaction_id) != type_deltas:
                continue
            matches.append(record)
        return tuple(matches)

    def _reuse_exact(
        self,
        candidates: tuple[PreparationTransactionRecord, ...],
    ) -> PreparationTransactionId | None:
        for record in candidates:
            if self._gateway.transaction_matches_after_image(record.transaction_id):
                return record.transaction_id
        return None

    @staticmethod
    def _request(
        *,
        database_identity: str,
        function_ea: int,
        descriptor: PreparationScriptDescriptor,
        session_id: DecompilationSessionId,
        sequence: int,
    ) -> PreparationRunRequest:
        return PreparationRunRequest(
            database_identity=database_identity,
            anchor_function_ea=function_ea,
            script=descriptor,
            authorizing_attempt_id=ExecutionAttemptId.new(
                session=session_id,
                sequence=sequence,
            ),
        )

    def prepare(
        self,
        function_ea: int,
        mode: PreparationMode = PreparationMode.AUTOMATIC,
    ) -> PreparationBatchReceipt:
        if isinstance(function_ea, bool) or not isinstance(function_ea, int):
            raise TypeError("function_ea must be an int")
        if function_ea < 0:
            raise ValueError("function_ea must be non-negative")
        if not isinstance(mode, PreparationMode):
            raise TypeError("mode must be a PreparationMode")

        # Whole-item constness is answerable from IDA function items, data
        # references, segment permissions, write xrefs, and live types.  Run
        # that discovery before Hex-Rays only when the independent preparation
        # stage is enabled.  Microcode-only bounded-table proposals remain
        # queued by the observation subscriber for the next natural round.
        if self._preparation_options.enabled:
            self._discover_type_proposals(function_ea)

        records = self._prepared_records(self._database_identity)
        run_receipts: list[PreparationRunReceipt] = []
        reused: list[PreparationTransactionId] = []
        session_id = DecompilationSessionId.new()
        sequence = 0

        proposals = (
            tuple(
                proposal
                for proposal in self._pending_type_proposals()
                if int(proposal.function_ea) == function_ea
            )
            if self._preparation_options.enabled
            else ()
        )
        if proposals:
            type_deltas = tuple(
                sorted(
                    (proposal.type_delta for proposal in proposals),
                    key=lambda delta: delta.item_ea,
                )
            )
            exact = self._exact_records(
                records,
                function_ea=function_ea,
                descriptor=self._type_step_descriptor,
                type_deltas=type_deltas,
            )
            reused_id = self._reuse_exact(exact)
            if reused_id is not None:
                reused.append(reused_id)
                self._acknowledge_type_proposals(proposals)
            elif exact:
                return PreparationBatchReceipt(
                    function_ea=function_ea,
                    mode=mode,
                    failure_reason=(
                        "applied type preparation diverged from its exact after-image; "
                        "restore or reconcile it before continuing"
                    ),
                )
            else:
                sequence += 1
                receipt = self._gateway.run(
                    self._request(
                        database_identity=self._database_identity,
                        function_ea=function_ea,
                        descriptor=self._type_step_descriptor,
                        session_id=session_id,
                        sequence=sequence,
                    ),
                    type_proposals=type_deltas,
                )
                run_receipts.append(receipt)
                if not receipt.ok:
                    return PreparationBatchReceipt(
                        function_ea=function_ea,
                        mode=mode,
                        run_receipts=tuple(run_receipts),
                        reused_transaction_ids=tuple(reused),
                        failure_reason=receipt.failure_reason
                        or f"type preparation ended in {receipt.state.value}",
                    )
                self._acknowledge_type_proposals(proposals)

        for descriptor in self._scripts:
            if not descriptor.enabled:
                continue
            exact = self._exact_records(
                records,
                function_ea=function_ea,
                descriptor=descriptor,
            )
            reused_id = self._reuse_exact(exact)
            if reused_id is not None:
                reused.append(reused_id)
                continue
            if exact:
                return PreparationBatchReceipt(
                    function_ea=function_ea,
                    mode=mode,
                    run_receipts=tuple(run_receipts),
                    reused_transaction_ids=tuple(reused),
                    failure_reason=(
                        f"applied preparation {descriptor.script_id!r} diverged "
                        "from its exact after-image; restore or reconcile it before "
                        "continuing"
                    ),
                )
            sequence += 1
            receipt = self._gateway.run(
                self._request(
                    database_identity=self._database_identity,
                    function_ea=function_ea,
                    descriptor=descriptor,
                    session_id=session_id,
                    sequence=sequence,
                )
            )
            run_receipts.append(receipt)
            if not receipt.ok:
                return PreparationBatchReceipt(
                    function_ea=function_ea,
                    mode=mode,
                    run_receipts=tuple(run_receipts),
                    reused_transaction_ids=tuple(reused),
                    failure_reason=receipt.failure_reason
                    or f"preparation ended in {receipt.state.value}",
                )

        return PreparationBatchReceipt(
            function_ea=function_ea,
            mode=mode,
            run_receipts=tuple(run_receipts),
            reused_transaction_ids=tuple(reused),
        )
