"""Production-path Stage C apply/certificate/restore acceptance oracle."""

from __future__ import annotations

import copy

import pytest

pytestmark = [
    pytest.mark.requires_ida,
    pytest.mark.runtime,
    pytest.mark.hexrays,
    pytest.mark.e2e,
]

ida_bytes = pytest.importorskip("ida_bytes")
ida_hexrays = pytest.importorskip("ida_hexrays")
idaapi = pytest.importorskip("idaapi")
idautils = pytest.importorskip("idautils")
idc = pytest.importorskip("idc")

from d810.backends.hexrays.ctree_fingerprint import fingerprint_ctree  # noqa: E402
from d810.capabilities.native_patch import (  # noqa: E402
    NativeJournalState,
    NativePatchTransactionId,
)
from d810.core.execution_journal import (  # noqa: E402
    ExecutionAttemptStatus,
)
from d810.manager.manager import d810_hooks_suppressed  # noqa: E402
from d810.testing.runner import _resolve_test_project_index  # noqa: E402


def _function_ea(function_name: str = "lab_stage_c_explicit_dispatch") -> int:
    ea = int(idc.get_name_ea_simple(function_name))
    if ea == int(idaapi.BADADDR):
        ea = int(idc.get_name_ea_simple("_" + function_name))
    return ea


def _function_bytes(function_ea: int) -> tuple[tuple[int, bytes], ...]:
    return tuple(
        (
            int(start_ea),
            bytes(ida_bytes.get_bytes(int(start_ea), int(end_ea - start_ea))),
        )
        for start_ea, end_ea in idautils.Chunks(function_ea)
    )


def _changed_eas(
    inherited: tuple[tuple[int, bytes], ...],
    current: tuple[tuple[int, bytes], ...],
) -> frozenset[int]:
    inherited_bytes = {
        start_ea + offset: byte
        for start_ea, content in inherited
        for offset, byte in enumerate(content)
    }
    current_bytes = {
        start_ea + offset: byte
        for start_ea, content in current
        for offset, byte in enumerate(content)
    }
    assert inherited_bytes.keys() == current_bytes.keys()
    return frozenset(
        ea for ea, byte in inherited_bytes.items() if current_bytes[ea] != byte
    )


def _enable_stage_c(config: dict) -> dict:
    enabled = copy.deepcopy(config)
    enabled["native_patch_enabled"] = True
    pipeline = enabled.get("pipeline_v2")
    assert isinstance(pipeline, list)
    lower = [item for item in pipeline if item.get("pass_id") == "lower_state_machine"]
    assert len(lower) == 1
    lower[0].setdefault("options", {})["native_cfg_persistence"] = True
    return enabled


class TestStageCNativeCfgNormalization:
    binary_name = "restructuring_lab.dll"

    def test_manager_owned_apply_and_exact_restore(
        self,
        copy_of_idb,
        d810_state,
    ) -> None:
        with d810_state() as state:
            project_index = _resolve_test_project_index(
                state, "default_unflattening_ollvm.json"
            )
            state.load_project(project_index)
            function_ea = _function_ea()
            assert function_ea != int(idaapi.BADADDR)
            # A fresh disposable IDB has no durable database UUID until its
            # first manager-owned decompilation session records the input
            # attestation.  Exercise that normal first-session lifecycle, then
            # restart below so the destructive gateway is IDB-scoped.
            with d810_hooks_suppressed(state.manager):
                attested_cfunc = idaapi.decompile(
                    function_ea, flags=idaapi.DECOMP_NO_CACHE
                )
            assert attested_cfunc is not None

            state.stop_d810()
            inherited_bytes = _function_bytes(function_ea)
            inherited_cfunc = idaapi.decompile(
                function_ea, flags=idaapi.DECOMP_NO_CACHE
            )
            assert inherited_cfunc is not None
            inherited_ctree = fingerprint_ctree(inherited_cfunc)

            project = state.current_project
            assert project is not None
            prior_config = dict(state.manager.config)
            configured = _enable_stage_c(dict(project.additional_configuration))
            project.additional_configuration.clear()
            project.additional_configuration.update(configured)
            state.manager.configure(**configured)
            state.start_d810()
            was_opted_in = state.manager.is_native_patch_opted_in(function_ea)
            state.manager.set_native_patch_opted_in(
                function_addr=function_ea,
                enabled=True,
            )
            transaction_id = None
            try:
                prior_attempt_ids = {
                    attempt.attempt_id
                    for attempt in state.manager._native_patch_execution_journal.attempts_for_function(
                        function_ea
                    )
                }
                result = state.manager.decompile_with_native_preanalysis(
                    function_ea,
                    lambda: idaapi.decompile(function_ea, flags=idaapi.DECOMP_NO_CACHE),
                    lambda: ida_hexrays.mark_cfunc_dirty(function_ea),
                )
                assert result is not None
                attempts = tuple(
                    attempt
                    for attempt in state.manager._native_patch_execution_journal.attempts_for_function(
                        function_ea
                    )
                    if attempt.stage_id == "stage_c_native_cfg_normalizer"
                    and attempt.attempt_id not in prior_attempt_ids
                )
                assert len(attempts) == 1
                attempt = attempts[0]
                assert attempt.status is ExecutionAttemptStatus.COMPLETED, (
                    attempt.reason_code
                )
                transaction_effects = tuple(
                    effect
                    for effect in attempt.effect_refs
                    if effect.kind == "native_patch_transaction"
                )
                assert len(transaction_effects) == 1
                cfg_effects = tuple(
                    effect
                    for effect in attempt.effect_refs
                    if effect.kind == "native_cfg_postcondition"
                )
                assert len(cfg_effects) == 1
                transaction_id = NativePatchTransactionId(transaction_effects[0].ref_id)
                journal = state.manager._native_patch_journal
                record = journal.get(transaction_id)
                assert record is not None
                assert record.state is NativeJournalState.CERTIFIED
                planned_bytes = journal.operation_bytes(transaction_id)
                operation_ids = {item.operation_id for item in planned_bytes}
                assert len(operation_ids) >= 2
                current_bytes = _function_bytes(function_ea)
                changed_eas = _changed_eas(inherited_bytes, current_bytes)
                assert changed_eas
                assert changed_eas <= {item.ea for item in planned_bytes}
                certificate_link = state.manager._native_patch_gateway._certificate_store.get_native_patch_blob(
                    "certificate_transaction", transaction_id.value
                )
                assert certificate_link is not None
                certificate_payload = state.manager._native_patch_gateway._certificate_store.get_native_patch_blob(
                    "certificate", certificate_link["certificate_key"]
                )
                assert certificate_payload is not None
                assert (
                    certificate_payload["observed_native_cfg_fingerprint"]
                    == (certificate_payload["target_cfg_fingerprint"])
                )
                cfg_receipt = state.manager._native_patch_gateway._certificate_store.get_native_patch_blob(
                    "native_cfg_postcondition_receipt", cfg_effects[0].ref_id
                )
                assert cfg_receipt is not None
                assert (
                    cfg_receipt["observed_native_cfg_fingerprint"]
                    == (cfg_receipt["expected_native_cfg_fingerprint"])
                )
                assert cfg_receipt["live_flowchart_fingerprint"]
                assert not any(
                    item.stage_id == "native_dead_edge_normalizer"
                    and item.attempt_id not in prior_attempt_ids
                    for item in state.manager._native_patch_execution_journal.attempts_for_function(
                        function_ea
                    )
                )

                # The certified bytes must independently reproduce the result
                # under a forced fresh decompile with every D810 optimizer
                # suppressed. A cached controlled-redo cfunc is not evidence.
                with d810_hooks_suppressed(state.manager):
                    independently_validated_cfunc = idaapi.decompile(
                        function_ea, flags=idaapi.DECOMP_NO_CACHE
                    )
                assert independently_validated_cfunc is not None
                assert fingerprint_ctree(result) == fingerprint_ctree(
                    independently_validated_cfunc
                )
                assert _function_bytes(function_ea) == current_bytes

                restore = state.manager._native_patch_gateway.restore(transaction_id)
                assert restore.ok, restore
                restored_record = journal.get(transaction_id)
                assert restored_record is not None
                assert restored_record.state is NativeJournalState.RESTORED
                assert (
                    state.manager._native_patch_gateway._certificate_store.get_native_patch_blob(
                        "certificate_transaction", transaction_id.value
                    )
                    is None
                )
                transaction_id = None
                assert _function_bytes(function_ea) == inherited_bytes
                with d810_hooks_suppressed(state.manager):
                    restored_cfunc = idaapi.decompile(
                        function_ea, flags=idaapi.DECOMP_NO_CACHE
                    )
                assert restored_cfunc is not None
                assert fingerprint_ctree(restored_cfunc) == inherited_ctree
            finally:
                if transaction_id is not None:
                    state.manager._native_patch_gateway.restore(transaction_id)
                if not was_opted_in:
                    state.manager.set_native_patch_opted_in(
                        function_addr=function_ea,
                        enabled=False,
                    )
                state.manager.configure(**prior_config)
