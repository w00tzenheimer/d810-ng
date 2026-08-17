"""Journal-owned apply, restore, and startup recovery for IDB preparation."""

from __future__ import annotations

from dataclasses import dataclass

from d810.backends.hexrays.native_patch_lifecycle import (
    CallerDiscovery,
    CfuncCacheInvalidator,
    ControlledRedoDecompiler,
    controlled_redo,
    invalidate_target_and_callers,
)
from d810.backends.ida.idb_preparation.patch_ledger import derive_patch_delta
from d810.backends.ida.idb_preparation.recovery import (
    PreparationBytePosition,
    classify_preparation_byte,
)
from d810.backends.ida.idb_preparation.script_runner import PreparationScriptContext
from d810.backends.ida.native_patch.reanalysis import (
    FunctionReanalyzer,
    ReanalysisReceipt,
    reanalyze_and_wait,
)
from d810.capabilities.idb_preparation import (
    PreparationByteDelta,
    PreparationPatchRow,
    PreparationRunRequest,
    PreparationScriptDescriptor,
    PreparationState,
    PreparationTransactionId,
    PreparationTransactionStore,
    PreparationTypeDelta,
    SerializedTypeSnapshot,
)
from d810.core.typing import Callable, Protocol

__all__ = [
    "IdaPreparationByteWriter",
    "IdbPreparationGateway",
    "PreparationCfuncRefreshReceipt",
    "PreparationRestoreReceipt",
    "PreparationRunReceipt",
]


class PreparationPatchLedger(Protocol):
    def capture(self) -> tuple[PreparationPatchRow, ...]: ...


class PreparationScriptRunner(Protocol):
    def run(
        self,
        descriptor: PreparationScriptDescriptor,
        context: PreparationScriptContext,
    ) -> None: ...


class PreparationByteWriter(Protocol):
    def read_byte(self, ea: int) -> int | None: ...
    def patch_bytes(self, ea: int, data: bytes) -> None: ...
    def patch_byte(self, ea: int, value: int) -> None: ...
    def revert_byte(self, ea: int) -> None: ...


class PreparationTypeMetadata(Protocol):
    def capture(self, item_ea: int) -> SerializedTypeSnapshot: ...

    def apply(
        self,
        item_ea: int,
        expected_before: SerializedTypeSnapshot,
        replacement: SerializedTypeSnapshot,
    ) -> None: ...

    def restore(
        self,
        item_ea: int,
        expected_after: SerializedTypeSnapshot,
        original: SerializedTypeSnapshot,
    ) -> None: ...


NativeActiveRangeProvider = Callable[[str], tuple[tuple[int, int], ...]]
FunctionOwnerResolver = Callable[[int], int | None]


@dataclass(frozen=True, slots=True)
class PreparationCfuncRefreshReceipt:
    function_ea: int
    invalidated_eas: tuple[int, ...]
    erased_eas: tuple[int, ...]
    refresh_deferred_to_requested_decompile: bool
    controlled_redo_function_eas: tuple[int, ...] = ()


@dataclass(frozen=True, slots=True)
class PreparationRunReceipt:
    transaction_id: PreparationTransactionId
    state: PreparationState
    byte_deltas: tuple[PreparationByteDelta, ...] = ()
    type_deltas: tuple[PreparationTypeDelta, ...] = ()
    affected_function_eas: tuple[int, ...] = ()
    reanalysis_receipts: tuple[ReanalysisReceipt, ...] = ()
    refresh_receipts: tuple[PreparationCfuncRefreshReceipt, ...] = ()
    failure_reason: str | None = None

    @property
    def ok(self) -> bool:
        return self.state is PreparationState.IDB_PREPARED


@dataclass(frozen=True, slots=True)
class PreparationRestoreReceipt:
    transaction_id: PreparationTransactionId
    state: PreparationState
    restored_eas: tuple[int, ...] = ()
    interference_eas: tuple[int, ...] = ()
    interference_type_eas: tuple[int, ...] = ()
    controlled_redo_function_eas: tuple[int, ...] = ()
    failure_reason: str | None = None

    @property
    def ok(self) -> bool:
        return self.state is PreparationState.RESTORED


class IdbPreparationGateway:
    """The sole transaction authority for preparation script byte changes."""

    def __init__(
        self,
        *,
        journal: PreparationTransactionStore,
        patch_ledger: PreparationPatchLedger,
        script_runner: PreparationScriptRunner,
        byte_writer: PreparationByteWriter,
        current_database_identity: str,
        native_active_ranges: NativeActiveRangeProvider,
        function_owner: FunctionOwnerResolver,
        reanalyzer: FunctionReanalyzer,
        cache_invalidator: CfuncCacheInvalidator,
        caller_discovery: CallerDiscovery,
        redo_decompiler: ControlledRedoDecompiler,
        type_metadata: PreparationTypeMetadata | None = None,
    ) -> None:
        if (
            not isinstance(current_database_identity, str)
            or not current_database_identity.strip()
        ):
            raise ValueError("current_database_identity must be non-empty")
        self._journal = journal
        self._patch_ledger = patch_ledger
        self._script_runner = script_runner
        self._byte_writer = byte_writer
        self._current_database_identity = current_database_identity
        self._native_active_ranges = native_active_ranges
        self._function_owner = function_owner
        self._reanalyzer = reanalyzer
        self._cache_invalidator = cache_invalidator
        self._caller_discovery = caller_discovery
        self._redo_decompiler = redo_decompiler
        self._type_metadata = type_metadata

    @staticmethod
    def _overlaps(ea: int, ranges: tuple[tuple[int, int], ...]) -> bool:
        return any(start_ea <= ea < end_ea for start_ea, end_ea in ranges)

    def _affected_functions(
        self,
        deltas: tuple[PreparationByteDelta, ...],
        noted_ranges: set[tuple[int, int]],
        noted_functions: set[int],
    ) -> tuple[int, ...]:
        functions = set(noted_functions)
        candidate_eas = {delta.ea for delta in deltas}
        for start_ea, end_ea in noted_ranges:
            candidate_eas.update({start_ea, end_ea - 1})
        for ea in candidate_eas:
            owner = self._function_owner(ea)
            if owner is not None:
                functions.add(int(owner))
        return tuple(sorted(functions))

    def _reanalyze_and_invalidate(
        self,
        function_eas: tuple[int, ...],
        *,
        redo_existing: bool,
    ) -> tuple[
        tuple[ReanalysisReceipt, ...],
        tuple[PreparationCfuncRefreshReceipt, ...],
        tuple[int, ...],
    ]:
        reanalysis: list[ReanalysisReceipt] = []
        refresh: list[PreparationCfuncRefreshReceipt] = []
        redone: list[int] = []
        for function_ea in function_eas:
            reanalysis.append(
                reanalyze_and_wait(function_ea, reanalyzer=self._reanalyzer)
            )
            invalidation = invalidate_target_and_callers(
                function_ea,
                invalidator=self._cache_invalidator,
                discovery=self._caller_discovery,
            )
            erased_eas = tuple(
                ea for ea, erased in sorted(invalidation.erased.items()) if erased
            )
            redo_eas: list[int] = []
            if redo_existing:
                for ea in erased_eas:
                    controlled_redo(ea, decompiler=self._redo_decompiler)
                    redo_eas.append(ea)
                    redone.append(ea)
            refresh.append(
                PreparationCfuncRefreshReceipt(
                    function_ea=function_ea,
                    invalidated_eas=tuple(sorted(invalidation.invalidated_eas)),
                    erased_eas=erased_eas,
                    refresh_deferred_to_requested_decompile=bool(erased_eas)
                    and not redo_existing,
                    controlled_redo_function_eas=tuple(redo_eas),
                )
            )
        return tuple(reanalysis), tuple(refresh), tuple(sorted(set(redone)))

    def run(
        self,
        request: PreparationRunRequest,
        *,
        type_proposals: tuple[PreparationTypeDelta, ...] = (),
    ) -> PreparationRunReceipt:
        if request.database_identity != self._current_database_identity:
            raise ValueError("preparation request targets a foreign database")

        baseline = self._patch_ledger.capture()
        transaction = self._journal.prepare(request, baseline)
        transaction_id = transaction.transaction_id
        # Read ownership only after prepare atomically acquires the database
        # execution lease.  Reading it before lease acquisition would allow a
        # transaction reaching IDB_PREPARED in between to disappear from this
        # run's conflict snapshot.
        prior_preparation_ranges = self._journal.active_byte_ranges(
            self._current_database_identity
        )
        prior_type_items = frozenset(
            self._journal.active_type_items(self._current_database_identity)
        )
        native_ranges = self._native_active_ranges(self._current_database_identity)
        ordered_type_proposals = tuple(
            sorted(type_proposals, key=lambda proposal: proposal.item_ea)
        )
        if len({proposal.item_ea for proposal in ordered_type_proposals}) != len(
            ordered_type_proposals
        ):
            record = self._journal.transition(
                transaction_id,
                PreparationState.REJECTED,
                note="duplicate type proposal item",
            )
            return PreparationRunReceipt(
                transaction_id=transaction_id,
                state=record.state,
                failure_reason="duplicate type proposal item",
            )
        conflicting_type_eas = tuple(
            proposal.item_ea
            for proposal in ordered_type_proposals
            if proposal.item_ea in prior_type_items
        )
        if conflicting_type_eas:
            record = self._journal.transition(
                transaction_id,
                PreparationState.REJECTED,
                note="type item owned by an active preparation transaction",
            )
            return PreparationRunReceipt(
                transaction_id=transaction_id,
                state=record.state,
                type_deltas=ordered_type_proposals,
                failure_reason="type item owned by an active preparation transaction",
            )
        if ordered_type_proposals and self._type_metadata is None:
            record = self._journal.transition(
                transaction_id,
                PreparationState.REJECTED,
                note="type metadata adapter unavailable",
            )
            return PreparationRunReceipt(
                transaction_id=transaction_id,
                state=record.state,
                type_deltas=ordered_type_proposals,
                failure_reason="type metadata adapter unavailable",
            )
        noted_ranges: set[tuple[int, int]] = set()
        noted_functions: set[int] = set()

        def _note_function(function_ea: int) -> None:
            noted_functions.add(function_ea)
            self._journal.record_affected_functions(transaction_id, (function_ea,))

        def _note_range(start_ea: int, end_ea: int) -> None:
            noted_ranges.add((start_ea, end_ea))
            for ea in (start_ea, end_ea - 1):
                owner = self._function_owner(ea)
                if owner is not None:
                    _note_function(int(owner))

        def _patch_bytes(ea: int, data: bytes) -> None:
            _note_range(ea, ea + len(data))
            self._byte_writer.patch_bytes(ea, data)

        context = PreparationScriptContext(
            function_ea=request.anchor_function_ea,
            patch_bytes_callback=_patch_bytes,
            note_range_callback=_note_range,
            note_function_callback=_note_function,
        )

        self._journal.transition(transaction_id, PreparationState.SCRIPT_RUNNING)
        script_error: BaseException | None = None
        if ordered_type_proposals:
            self._journal.record_type_deltas(transaction_id, ordered_type_proposals)
            _note_function(request.anchor_function_ea)
            try:
                assert self._type_metadata is not None
                for proposal in ordered_type_proposals:
                    self._type_metadata.apply(
                        proposal.item_ea,
                        proposal.before,
                        proposal.after,
                    )
            except BaseException as error:
                script_error = error
        if script_error is None:
            try:
                self._script_runner.run(request.script, context)
            except BaseException as error:
                script_error = error

        self._journal.transition(transaction_id, PreparationState.CAPTURE_PENDING)
        try:
            after = self._patch_ledger.capture()
        except BaseException as error:
            record = self._journal.transition(
                transaction_id,
                PreparationState.RECOVERY_REQUIRED,
                note=f"post-script patch capture failed: {error}",
            )
            return PreparationRunReceipt(
                transaction_id=transaction_id,
                state=record.state,
                failure_reason=f"post-script patch capture failed: {error}",
                type_deltas=ordered_type_proposals,
            )

        deltas = derive_patch_delta(baseline, after)
        try:
            self._journal.record_byte_deltas(transaction_id, deltas)
        except BaseException as error:
            durable_deltas = self._journal.byte_deltas(transaction_id)
            if not durable_deltas:
                record = self._journal.transition(
                    transaction_id,
                    PreparationState.RECOVERY_REQUIRED,
                    note=f"delta persistence failed: {error}",
                )
                return PreparationRunReceipt(
                    transaction_id=transaction_id,
                    state=record.state,
                    byte_deltas=deltas,
                    type_deltas=ordered_type_proposals,
                    failure_reason=f"delta persistence failed: {error}",
                )
            affected_functions = self._affected_functions(
                durable_deltas, noted_ranges, noted_functions
            )
            self._journal.record_affected_functions(transaction_id, affected_functions)
            self._journal.transition(
                transaction_id,
                PreparationState.ROLLING_BACK,
                note=f"post-delta failure: {error}",
            )
            restored = self._restore_in_current_lane(
                transaction_id, failure_reason=str(error)
            )
            return PreparationRunReceipt(
                transaction_id=transaction_id,
                state=restored.state,
                byte_deltas=durable_deltas,
                type_deltas=ordered_type_proposals,
                affected_function_eas=affected_functions,
                failure_reason=str(error),
            )

        if script_error is not None and not deltas and not ordered_type_proposals:
            record = self._journal.transition(
                transaction_id,
                PreparationState.FAILED,
                note=f"script failed before writes: {script_error}",
            )
            return PreparationRunReceipt(
                transaction_id=transaction_id,
                state=record.state,
                failure_reason=str(script_error),
            )

        conflict_reason = None
        for delta in deltas:
            if self._overlaps(delta.ea, native_ranges):
                conflict_reason = (
                    f"byte {delta.ea:#x} overlaps an active native-patch range"
                )
                break
            if self._overlaps(delta.ea, prior_preparation_ranges):
                conflict_reason = (
                    f"byte {delta.ea:#x} overlaps an active preparation transaction"
                )
                break

        if script_error is not None or conflict_reason is not None:
            reason = str(script_error) if script_error is not None else conflict_reason
            self._journal.transition(
                transaction_id, PreparationState.ROLLING_BACK, note=reason
            )
            restored = self._restore_in_current_lane(
                transaction_id, failure_reason=reason
            )
            return PreparationRunReceipt(
                transaction_id=transaction_id,
                state=restored.state,
                byte_deltas=deltas,
                type_deltas=ordered_type_proposals,
                failure_reason=reason,
            )

        affected_functions = self._affected_functions(
            deltas, noted_ranges, noted_functions
        )
        self._journal.record_affected_functions(transaction_id, affected_functions)
        self._journal.transition(transaction_id, PreparationState.CAPTURED)
        self._journal.transition(transaction_id, PreparationState.ANALYSIS_PENDING)
        try:
            reanalysis, refresh, _ = self._reanalyze_and_invalidate(
                affected_functions,
                redo_existing=False,
            )
        except BaseException as error:
            self._journal.transition(
                transaction_id,
                PreparationState.ROLLING_BACK,
                note=f"analysis failed: {error}",
            )
            restored = self._restore_in_current_lane(
                transaction_id, failure_reason=f"analysis failed: {error}"
            )
            return PreparationRunReceipt(
                transaction_id=transaction_id,
                state=restored.state,
                byte_deltas=deltas,
                type_deltas=ordered_type_proposals,
                affected_function_eas=affected_functions,
                failure_reason=f"analysis failed: {error}",
            )

        record = self._journal.transition(transaction_id, PreparationState.IDB_PREPARED)
        return PreparationRunReceipt(
            transaction_id=transaction_id,
            state=record.state,
            byte_deltas=deltas,
            type_deltas=ordered_type_proposals,
            affected_function_eas=affected_functions,
            reanalysis_receipts=reanalysis,
            refresh_receipts=refresh,
        )

    def _positions(
        self, transaction_id: PreparationTransactionId
    ) -> dict[int, PreparationBytePosition]:
        rows = {row.ea: row for row in self._patch_ledger.capture()}
        return {
            delta.ea: classify_preparation_byte(
                delta, rows, self._byte_writer.read_byte
            )
            for delta in self._journal.byte_deltas(transaction_id)
        }

    def _type_positions(
        self, transaction_id: PreparationTransactionId
    ) -> dict[int, PreparationBytePosition]:
        deltas = self._journal.type_deltas(transaction_id)
        if not deltas:
            return {}
        if self._type_metadata is None:
            return {delta.item_ea: PreparationBytePosition.NEITHER for delta in deltas}
        positions: dict[int, PreparationBytePosition] = {}
        for delta in deltas:
            live = self._type_metadata.capture(delta.item_ea)
            if live == delta.before:
                position = PreparationBytePosition.BEFORE
            elif live == delta.after:
                position = PreparationBytePosition.AFTER
            else:
                position = PreparationBytePosition.NEITHER
            positions[delta.item_ea] = position
        return positions

    def restore(
        self, transaction_id: PreparationTransactionId
    ) -> PreparationRestoreReceipt:
        record = self._journal.get(transaction_id)
        if record is None:
            raise KeyError(f"unknown preparation transaction {transaction_id.value}")
        if record.database_identity != self._current_database_identity:
            return PreparationRestoreReceipt(
                transaction_id=transaction_id,
                state=record.state,
                failure_reason="transaction belongs to a foreign database",
            )
        if record.state is not PreparationState.IDB_PREPARED:
            return PreparationRestoreReceipt(
                transaction_id=transaction_id,
                state=record.state,
                failure_reason=f"transaction is not restorable from {record.state.value}",
            )

        positions = self._positions(transaction_id)
        type_positions = self._type_positions(transaction_id)
        interference = tuple(
            sorted(
                ea
                for ea, position in positions.items()
                if position is not PreparationBytePosition.AFTER
            )
        )
        if interference:
            return PreparationRestoreReceipt(
                transaction_id=transaction_id,
                state=record.state,
                interference_eas=interference,
                failure_reason="live patch state diverged from transaction after-image",
            )
        type_interference = tuple(
            sorted(
                ea
                for ea, position in type_positions.items()
                if position is not PreparationBytePosition.AFTER
            )
        )
        if type_interference:
            return PreparationRestoreReceipt(
                transaction_id=transaction_id,
                state=record.state,
                interference_type_eas=type_interference,
                failure_reason="live type state diverged from transaction after-image",
            )
        self._journal.transition(transaction_id, PreparationState.RESTORING)
        return self._restore_in_current_lane(transaction_id)

    def _restore_in_current_lane(
        self,
        transaction_id: PreparationTransactionId,
        *,
        failure_reason: str | None = None,
    ) -> PreparationRestoreReceipt:
        positions = self._positions(transaction_id)
        type_positions = self._type_positions(transaction_id)
        interference = tuple(
            sorted(
                ea
                for ea, position in positions.items()
                if position is PreparationBytePosition.NEITHER
            )
        )
        if interference:
            record = self._journal.transition(
                transaction_id,
                PreparationState.RESTORE_FAILED,
                note="live patch state matches neither before nor after",
            )
            return PreparationRestoreReceipt(
                transaction_id=transaction_id,
                state=record.state,
                interference_eas=interference,
                failure_reason="live patch state matches neither before nor after",
            )
        type_interference = tuple(
            sorted(
                ea
                for ea, position in type_positions.items()
                if position is PreparationBytePosition.NEITHER
            )
        )
        if type_interference:
            record = self._journal.transition(
                transaction_id,
                PreparationState.RESTORE_FAILED,
                note="live type state matches neither before nor after",
            )
            return PreparationRestoreReceipt(
                transaction_id=transaction_id,
                state=record.state,
                interference_type_eas=type_interference,
                failure_reason="live type state matches neither before nor after",
            )

        deltas = self._journal.byte_deltas(transaction_id)
        restored_eas: list[int] = []
        try:
            for delta in deltas:
                if positions[delta.ea] is PreparationBytePosition.BEFORE:
                    continue
                if delta.restore_with_revert:
                    self._byte_writer.revert_byte(delta.ea)
                else:
                    self._byte_writer.patch_byte(delta.ea, delta.restore_value)
                restored_eas.append(delta.ea)

            type_deltas = self._journal.type_deltas(transaction_id)
            if type_deltas:
                assert self._type_metadata is not None
                for delta in type_deltas:
                    if type_positions[delta.item_ea] is PreparationBytePosition.BEFORE:
                        continue
                    self._type_metadata.restore(
                        delta.item_ea,
                        delta.after,
                        delta.before,
                    )

            after_positions = self._positions(transaction_id)
            unrestored = tuple(
                sorted(
                    ea
                    for ea, position in after_positions.items()
                    if position is not PreparationBytePosition.BEFORE
                )
            )
            if unrestored:
                raise RuntimeError(
                    "restore readback did not reproduce the exact before-image at "
                    + ", ".join(f"{ea:#x}" for ea in unrestored)
                )
            unrestored_types = tuple(
                sorted(
                    ea
                    for ea, position in self._type_positions(transaction_id).items()
                    if position is not PreparationBytePosition.BEFORE
                )
            )
            if unrestored_types:
                raise RuntimeError(
                    "type restore did not reproduce exact before-image at "
                    + ", ".join(f"{ea:#x}" for ea in unrestored_types)
                )

            function_eas = self._journal.affected_functions(transaction_id)
            _, _, redone = self._reanalyze_and_invalidate(
                function_eas,
                redo_existing=True,
            )
            record = self._journal.transition(
                transaction_id, PreparationState.RESTORED, note=failure_reason
            )
            return PreparationRestoreReceipt(
                transaction_id=transaction_id,
                state=record.state,
                restored_eas=tuple(restored_eas),
                controlled_redo_function_eas=redone,
                failure_reason=failure_reason,
            )
        except BaseException as error:
            current = self._journal.get(transaction_id)
            assert current is not None
            if current.state in {
                PreparationState.RESTORING,
                PreparationState.ROLLING_BACK,
            }:
                current = self._journal.transition(
                    transaction_id,
                    PreparationState.RESTORE_FAILED,
                    note=f"restore failed: {error}",
                )
            return PreparationRestoreReceipt(
                transaction_id=transaction_id,
                state=current.state,
                restored_eas=tuple(restored_eas),
                failure_reason=f"restore failed: {error}",
            )

    def _capture_recovery_deltas(
        self, transaction_id: PreparationTransactionId
    ) -> tuple[PreparationByteDelta, ...]:
        baseline = self._journal.baseline_rows(transaction_id)
        observed = derive_patch_delta(baseline, self._patch_ledger.capture())
        durable = self._journal.byte_deltas(transaction_id)
        if durable and durable != observed:
            raise RuntimeError(
                "durable byte delta disagrees with live recovery capture"
            )
        if not durable:
            self._journal.record_byte_deltas(transaction_id, observed)
        affected = tuple(
            sorted(
                {
                    owner
                    for delta in observed
                    if (owner := self._function_owner(delta.ea)) is not None
                }
            )
        )
        self._journal.record_affected_functions(transaction_id, affected)
        return observed

    def recover_startup(self) -> tuple[PreparationRestoreReceipt, ...]:
        receipts: list[PreparationRestoreReceipt] = []
        for record in self._journal.recoverable(self._current_database_identity):
            transaction_id = record.transaction_id
            try:
                if record.state is PreparationState.PREPARED:
                    terminal = self._journal.transition(
                        transaction_id,
                        PreparationState.REJECTED,
                        note="startup discarded preparation that never ran",
                    )
                    receipts.append(
                        PreparationRestoreReceipt(
                            transaction_id=transaction_id,
                            state=terminal.state,
                            failure_reason="preparation never entered script execution",
                        )
                    )
                    continue
                if record.state is PreparationState.SCRIPT_RUNNING:
                    record = self._journal.transition(
                        transaction_id, PreparationState.CAPTURE_PENDING
                    )
                if record.state in {
                    PreparationState.CAPTURE_PENDING,
                    PreparationState.RECOVERY_REQUIRED,
                }:
                    self._capture_recovery_deltas(transaction_id)
                    record = self._journal.transition(
                        transaction_id, PreparationState.ROLLING_BACK
                    )
                elif record.state in {
                    PreparationState.CAPTURED,
                    PreparationState.ANALYSIS_PENDING,
                }:
                    record = self._journal.transition(
                        transaction_id, PreparationState.ROLLING_BACK
                    )
                elif record.state is PreparationState.RESTORE_FAILED:
                    record = self._journal.transition(
                        transaction_id, PreparationState.RESTORING
                    )
                receipts.append(self._restore_in_current_lane(transaction_id))
            except BaseException as error:
                current = self._journal.get(transaction_id)
                assert current is not None
                if (
                    current.state is not PreparationState.RECOVERY_REQUIRED
                    and current.state
                    in {
                        PreparationState.SCRIPT_RUNNING,
                        PreparationState.CAPTURE_PENDING,
                        PreparationState.CAPTURED,
                        PreparationState.ANALYSIS_PENDING,
                    }
                ):
                    current = self._journal.transition(
                        transaction_id,
                        PreparationState.RECOVERY_REQUIRED,
                        note=f"startup recovery failed: {error}",
                    )
                receipts.append(
                    PreparationRestoreReceipt(
                        transaction_id=transaction_id,
                        state=current.state,
                        failure_reason=f"startup recovery failed: {error}",
                    )
                )
        return tuple(receipts)


class IdaPreparationByteWriter:
    """Live IDA patched-byte writer with mandatory readback."""

    def read_byte(self, ea: int) -> int | None:
        import ida_bytes

        if not ida_bytes.is_loaded(ea):
            return None
        return int(ida_bytes.get_byte(ea)) & 0xFF

    def patch_bytes(self, ea: int, data: bytes) -> None:
        import ida_bytes

        ida_bytes.patch_bytes(ea, data)
        if bytes(ida_bytes.get_bytes(ea, len(data)) or b"") != data:
            raise RuntimeError(f"IDA patch readback failed at {ea:#x}")

    def patch_byte(self, ea: int, value: int) -> None:
        import ida_bytes

        ida_bytes.patch_byte(ea, value)
        if self.read_byte(ea) != value:
            raise RuntimeError(f"IDA patch-byte readback failed at {ea:#x}")

    def revert_byte(self, ea: int) -> None:
        import ida_bytes

        ida_bytes.revert_byte(ea)
