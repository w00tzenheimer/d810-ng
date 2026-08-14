"""Runtime proof for the first manager-routed native writer."""

from __future__ import annotations

import uuid

import pytest

pytestmark = [pytest.mark.requires_ida, pytest.mark.runtime, pytest.mark.hexrays]

ida_bytes = pytest.importorskip("ida_bytes")
ida_funcs = pytest.importorskip("ida_funcs")
ida_nalt = pytest.importorskip("ida_nalt")
idautils = pytest.importorskip("idautils")

from d810.backends.hexrays.native_patch_lifecycle import (  # noqa: E402
    IdaCallerDiscovery,
    IdaCfuncCacheInvalidator,
    IdaControlledRedoDecompiler,
)
from d810.backends.ida.native_patch.capture import IdaLiveDatabaseReader  # noqa: E402
from d810.backends.ida.native_patch.gateway import (  # noqa: E402
    IdaNativeByteWriter,
    NativePatchGateway,
)
from d810.backends.ida.native_patch.indirect_label_plan import (  # noqa: E402
    IndirectLabelPlanRequest,
    build_indirect_label_metadata_plan,
)
from d810.backends.ida.native_patch.journal import SQLiteNativePatchJournal  # noqa: E402
from d810.backends.ida.native_patch.metadata import IdaMetadataActionExecutor  # noqa: E402
from d810.backends.ida.native_patch.reanalysis import (  # noqa: E402
    IdaFunctionExtentRestorer,
    IdaFunctionReanalyzer,
)
from d810.core.execution_journal import (  # noqa: E402
    DecompilationSessionId,
    ExecutionAttemptStatus,
    ExecutionDomain,
)
from d810.core.execution_journal_store import ExecutionJournalStore  # noqa: E402
from d810.capabilities.native_patch import NativePatchTransactionId  # noqa: E402
from d810.core.persistence import SQLiteOptimizationStorage  # noqa: E402
from d810.transforms.native_patch_plan import NativeMetadataActionKind  # noqa: E402
from d810.hexrays.preanalysis.indirect_jump_labels import (  # noqa: E402
    IndirectLabelMaterializationPlan,
    IndirectLabelMaterializationResult,
    NativePatchPlanRequest,
)
from d810.manager.native_writer_migration import (  # noqa: E402
    ManagerOwnedNativePatchRequestExecutor,
    PreparedNativePatchRequest,
)


def test_disabled_native_writer_request_does_not_lower_or_apply() -> None:
    calls: list[object] = []
    request = NativePatchPlanRequest(
        materialization=IndirectLabelMaterializationPlan(
            function_ea=0x1000,
            label_start=0x1010,
            label_end=0x1020,
            table_address=0x2000,
            table_count=1,
            target_eas=(0x1010,),
        ),
        dispatch_jump_ea=0x1008,
        switch_start_ea=None,
        install_switch_info=False,
        state_base=1,
        state_var_stkoff=None,
    )
    executor = ManagerOwnedNativePatchRequestExecutor(
        gateway=object(),  # disabled policy must make this unreachable
        user_enabled=lambda _request: False,
        execution_journal=object(),  # disabled policy must make this unreachable
        parent_attempt_for_request=lambda proposal: calls.append(proposal),
        build_plan=lambda proposal, attempt_id: calls.append((proposal, attempt_id)),
    )

    result = executor(request)

    assert calls == []
    assert not result.success
    assert result.reason == "native_patch_policy_disabled"


def _first_non_successor_target(function_ea: int) -> tuple[int, int]:
    """Find two item heads whose source has no existing edge to the target."""
    metadata = IdaMetadataActionExecutor()
    function = ida_funcs.get_func(function_ea)
    assert function is not None
    source_ea = int(function.start_ea)
    current = metadata.read_state(NativeMetadataActionKind.UPDATE_XREF, source_ea)
    existing_targets = {
        int(row.partition("@")[0], 16)
        for row in current.removeprefix("cref3:").split(",")
        if row
    }
    candidate = int(ida_bytes.next_head(source_ea, int(function.end_ea)))
    while candidate < int(function.end_ea):
        if candidate not in existing_targets:
            return source_ea, candidate
        next_candidate = int(ida_bytes.next_head(candidate, int(function.end_ea)))
        if next_candidate <= candidate:
            break
        candidate = next_candidate
    pytest.skip("no in-function target without an existing source xref")


def test_enabled_request_applies_real_metadata_plan_and_records_child_effects(
    copy_of_idb, tmp_path
) -> None:
    """The migrated path reaches live IDA only through the authorized gateway."""
    function_ea = next(int(ea) for ea in idautils.Functions())
    source_ea, target_ea = _first_non_successor_target(function_ea)
    function = ida_funcs.get_func(function_ea)
    assert function is not None
    request = NativePatchPlanRequest(
        materialization=IndirectLabelMaterializationPlan(
            function_ea=function_ea,
            label_start=target_ea,
            label_end=int(function.end_ea),
            table_address=0,
            table_count=1,
            target_eas=(target_ea,),
        ),
        dispatch_jump_ea=source_ea,
        switch_start_ea=None,
        install_switch_info=False,
        state_base=0,
        state_var_stkoff=None,
    )
    native_journal = SQLiteNativePatchJournal(tmp_path / "native-patch.sqlite")
    execution_journal = ExecutionJournalStore(tmp_path / "execution.sqlite")
    certificate_store = SQLiteOptimizationStorage(":memory:")
    try:
        gateway = NativePatchGateway(
            journal=native_journal,
            reader=IdaLiveDatabaseReader(),
            writer=IdaNativeByteWriter(),
            decode_replacement=lambda _ea, _data: (_ for _ in ()).throw(
                RuntimeError("metadata-only plan attempted byte decoding")
            ),
            reanalyzer=IdaFunctionReanalyzer(),
            extent_restorer=IdaFunctionExtentRestorer(),
            metadata_executor=IdaMetadataActionExecutor(),
            cache_invalidator=IdaCfuncCacheInvalidator(),
            caller_discovery=IdaCallerDiscovery(),
            redo_decompiler=IdaControlledRedoDecompiler(),
            certificate_store=certificate_store,
            d810_version="native-writer-migration-system-test",
        )
        session = DecompilationSessionId.new()
        parent = execution_journal.begin_attempt(
            session,
            stage_id="hexrays_preanalysis",
            domain=ExecutionDomain.HOOK,
        )

        def build_plan(proposal, attempt_id):
            plan = build_indirect_label_metadata_plan(
                IndirectLabelPlanRequest(
                    function_ea=proposal.materialization.function_ea,
                    label_start=proposal.materialization.label_start,
                    label_end=proposal.materialization.label_end,
                    table_address=proposal.materialization.table_address,
                    table_count=proposal.materialization.table_count,
                    target_eas=proposal.materialization.target_eas,
                    dispatch_jump_ea=proposal.dispatch_jump_ea,
                    switch_start_ea=proposal.switch_start_ea,
                    install_switch_info=proposal.install_switch_info,
                    state_base=proposal.state_base,
                    state_var_stkoff=proposal.state_var_stkoff,
                ),
                authorizing_attempt_id=attempt_id,
            )
            assert plan.database_identity.input_file_hash == (
                ida_nalt.retrieve_input_file_sha256().hex()
            )
            uuid.UUID(plan.database_identity.idb_uuid)
            metadata = IdaMetadataActionExecutor()

            def observe_result():
                success = all(
                    metadata.read_state(action.kind, action.ea) == action.expected_after
                    for action in plan.operations[0].metadata_actions
                )
                return IndirectLabelMaterializationResult(
                    function_ea=proposal.materialization.function_ea,
                    table_address=proposal.materialization.table_address,
                    table_count=proposal.materialization.table_count,
                    label_start=proposal.materialization.label_start,
                    label_end=proposal.materialization.label_end,
                    target_count=len(proposal.materialization.target_eas),
                    materialized_target_count=(
                        len(proposal.materialization.target_eas) if success else 0
                    ),
                    dispatch_jump_ea=proposal.dispatch_jump_ea,
                    jump_xref_count=sum(
                        action.kind is NativeMetadataActionKind.UPDATE_XREF
                        for action in plan.operations[0].metadata_actions
                    ),
                    switch_info_installed=proposal.install_switch_info,
                    appended_tail=False,
                    success=success,
                    reason="materialized" if success else "metadata_mismatch",
                )

            return PreparedNativePatchRequest(plan=plan, observe_result=observe_result)

        executor = ManagerOwnedNativePatchRequestExecutor(
            gateway=gateway,
            user_enabled=lambda _request: True,
            execution_journal=execution_journal,
            parent_attempt_for_request=lambda _proposal: parent.attempt_id,
            build_plan=build_plan,
        )
        result = executor(request)

        assert result.success
        # The second request observes a stable already-normalized end state.
        # It must reach certificate reuse instead of failing during lowering
        # because there is no longer an xref delta to apply.
        second = executor(request)
        assert second.success
        attempts = execution_journal.attempts_for_session(session)
        assert len(attempts) == 3
        child = attempts[-2]
        assert child.parent_attempt_id == parent.attempt_id
        assert child.status is ExecutionAttemptStatus.COMPLETED
        assert [effect.kind for effect in child.effect_refs] == [
            "native_patch_proposal",
            "native_patch_preflight",
            "native_patch_diagnostic_snapshot",
            "native_patch_transaction",
            "native_patch_reanalysis",
            "native_patch_certificate",
        ]
        child_effects = {effect.kind: effect.ref_id for effect in child.effect_refs}
        assert (
            child_effects["native_patch_preflight"]
            != child_effects["native_patch_proposal"]
        )
        assert (
            certificate_store.get_native_patch_blob(
                "native_patch_preflight_receipt",
                child_effects["native_patch_preflight"],
            )
            is not None
        )
        assert (
            certificate_store.get_native_patch_blob(
                "native_patch_diagnostic_snapshot",
                child_effects["native_patch_diagnostic_snapshot"],
            )
            is not None
        )
        rerun = attempts[-1]
        assert rerun.status is ExecutionAttemptStatus.ABSTAINED
        assert [effect.kind for effect in rerun.effect_refs] == [
            "native_patch_proposal",
            "native_patch_preflight",
            "native_patch_diagnostic_snapshot",
            "native_patch_certificate",
        ]
        rerun_effects = {effect.kind: effect.ref_id for effect in rerun.effect_refs}
        assert (
            certificate_store.get_native_patch_blob(
                "native_patch_preflight_receipt",
                rerun_effects["native_patch_preflight"],
            )
            is not None
        )

        # Explicit restore must undo the actual manager-routed metadata
        # mutation and revoke the certificate that made the second request a
        # no-rerun abstention.
        transaction_id = NativePatchTransactionId(
            child_effects["native_patch_transaction"]
        )
        applied_actions = native_journal.metadata_actions(transaction_id)
        restored = gateway.restore(transaction_id)
        assert restored.ok
        metadata = IdaMetadataActionExecutor()
        for action in applied_actions:
            assert metadata.read_state(
                NativeMetadataActionKind(action.kind), action.ea
            ) == (action.recorded_before)
    finally:
        execution_journal.close()
        native_journal.close()
