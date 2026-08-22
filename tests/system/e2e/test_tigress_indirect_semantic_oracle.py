"""Live semantic oracle gate for ``tigress_flatten_indirect``."""

from __future__ import annotations

import json
import os
import platform
from pathlib import Path

import pytest

import idaapi
import idc

from d810.core.execution_journal import ExecutionAttemptStatus
from d810.manager.native_normalization import NativeNormalizationOutcome


def _get_default_binary() -> str:
    override = os.environ.get("D810_TEST_BINARY")
    if override:
        return override
    return (
        "libobfuscated.dylib" if platform.system() == "Darwin" else "libobfuscated.dll"
    )


def _get_func_ea(name: str) -> int:
    ea = idc.get_name_ea_simple(name)
    if ea == idaapi.BADADDR:
        ea = idc.get_name_ea_simple("_" + name)
    return ea


def _diag_db_path(diag_conn, *, func_ea: int) -> Path:
    diag_conn.commit()
    for row in diag_conn.execute("PRAGMA database_list"):
        if row[1] == "main" and row[2]:
            return Path(row[2])

    from d810.core.diag import find_latest_diag_db_path

    latest = find_latest_diag_db_path(func_ea)
    assert latest is not None, "tigress_flatten_indirect oracle requires a diag DB path"
    return latest


def _applied_redirect_edges(diag_conn) -> set[tuple[int, int, int]]:
    rows = diag_conn.execute(
        """
        SELECT block_serial, target_serial, extra_json
        FROM cfg_provenance
        WHERE action = 'REDIRECT_EDGE'
        """
    ).fetchall()
    edges: set[tuple[int, int, int]] = set()
    for source_block, target_block, raw_extra in rows:
        try:
            extra = json.loads(raw_extra or "{}")
        except json.JSONDecodeError:
            continue
        old_target = extra.get("old_target")
        if old_target is None:
            continue
        edges.add((int(source_block), int(target_block), int(old_target)))
    return edges


def _derive_live_repaired_handoffs(report: dict, diag_conn) -> dict[int, int]:
    target_block_by_state = {
        int(transfer["state"]): int(transfer["target_block"])
        for transfer in report.get("transfers", ())
        if int(transfer.get("target_block", -1)) >= 0
    }
    applied_edges = _applied_redirect_edges(diag_conn)
    handoffs: dict[int, int] = {}
    for transfer in report.get("transfers", ()):
        state = int(transfer["state"])
        for exit_path in transfer.get("terminal_paths", ()):
            next_state = exit_path.get("last_state")
            if next_state is None:
                continue
            next_state = int(next_state)
            target_block = target_block_by_state.get(next_state)
            if target_block is None:
                continue
            path = tuple(int(block) for block in exit_path.get("path", ()))
            writes = tuple(exit_path.get("writes", ()))
            if len(path) < 2 or not writes:
                continue
            old_target = int(path[-1])
            write_block = int(writes[-1]["block"])
            if (write_block, target_block, old_target) in applied_edges:
                handoffs[state] = next_state
    return handoffs


@pytest.fixture(scope="class")
def libobfuscated_setup(ida_database, configure_hexrays, setup_libobfuscated_funcs):
    if not idaapi.init_hexrays_plugin():
        pytest.skip("Hex-Rays decompiler plugin not available")
    return ida_database


class TestTigressIndirectSemanticOracle:
    """Live semantic-equivalence gate for the StateMachineCffUnflattener path."""

    binary_name = _get_default_binary()

    def test_tigress_indirect_oracle(
        self,
        libobfuscated_setup,
        d810_state,
        pseudocode_to_string,
        request,
    ):
        """Ground-truth gate for the StateMachineCffUnflattener (state-machine CFF)
        path over the Tigress indirect jump-table dispatcher.

        Exercises ``default_unflattening_tigress_indirect.json`` — the sole,
        unconditional CFF unflattener — and asserts the emitted pseudocode is
        semantically equivalent to the reference ``test_function_original`` via
        the shared indirect oracle (llr-yyti).
        """
        func_name = "tigress_flatten_indirect"
        func_ea = _get_func_ea(func_name)
        if func_ea == idaapi.BADADDR:
            pytest.skip(f"{func_name} not found")

        from d810.core.settings import configure_settings, reset_settings

        configure_settings(
            diag_snapshots=True,
            capture_post_maturity=idaapi.MMAT_GLBOPT1,
        )
        request.addfinalizer(reset_settings)

        with d810_state() as state:
            with state.for_project("default_unflattening_tigress_indirect.json"):
                state.stats.reset()
                # This oracle requires lifting normalization before CFF recovery:
                # the target labels are otherwise absent from Hex-Rays' MBA.
                # Exercise the explicit enabled path rather than treating a
                # policy-disabled abstention as a semantic unflattening failure.
                project = state.current_project
                assert project is not None
                runtime_config = project.additional_configuration
                prior_enabled = runtime_config.get("native_patch_enabled")
                had_prior_enabled = "native_patch_enabled" in runtime_config
                prior_manager_config = dict(state.manager.config)
                runtime_config["native_patch_enabled"] = True
                try:
                    # ``d810_state`` starts its default project before this
                    # scoped profile is selected. Recreate the manager so this
                    # profile's explicit compatibility executor is active.
                    state.stop_d810()
                    state.manager.configure(
                        **{**prior_manager_config, "native_patch_enabled": True}
                    )
                    from d810.backends.hexrays.native_preanalysis_key import (
                        resolve_native_preanalysis_identity,
                    )

                    # Seed the durable database identity before manager startup;
                    # the destructive gateway deliberately refuses to install
                    # without it.  Doing this afterwards would create no writer
                    # and a broad exception could mislabel that lifecycle failure
                    # as a safe plan abstention.
                    identity = resolve_native_preanalysis_identity(
                        func_ea, profile_config={}
                    )
                    assert identity.native_key is not None
                    state.start_d810()
                    was_opted_in = state.manager.is_native_patch_opted_in(func_ea)
                    state.manager.set_native_patch_opted_in(
                        function_addr=func_ea,
                        enabled=True,
                    )
                    try:
                        with state.manager.arm_native_materialization_certificate_reuse(
                            func_ea
                        ):
                            cfunc = idaapi.decompile(
                                func_ea, flags=idaapi.DECOMP_NO_CACHE
                            )
                        assert cfunc is not None, (
                            f"Decompilation of {func_name} with d810 (unflatten) failed"
                        )
                        materialization_receipt = (
                            state.manager.inspect_native_materialization_receipt(func_ea)
                        )
                        assert len(materialization_receipt.attempts) == 2
                        first_receipt, second_receipt = materialization_receipt.attempts
                        first_attempt = first_receipt.attempt
                        first_normalization = first_receipt.normalization
                        first_certificate = materialization_receipt.certificate
                        assert first_attempt.status is ExecutionAttemptStatus.COMPLETED
                        assert first_normalization.apply_receipt is not None
                        assert first_normalization.apply_receipt.ok
                        assert first_certificate is not None
                        assert first_certificate.schema_version == 4

                        second_attempt = second_receipt.attempt
                        second_normalization = second_receipt.normalization
                        second_certificate = second_normalization.certificate
                        assert second_attempt.status is ExecutionAttemptStatus.ABSTAINED
                        assert second_normalization.outcome is NativeNormalizationOutcome.ALREADY_NORMALIZED
                        assert second_normalization.apply_receipt is None
                        assert second_certificate is not None
                        assert second_certificate.schema_version == 4
                        assert second_certificate.certificate_id == (
                            first_certificate.certificate_id
                        )
                        assert first_normalization.apply_receipt.transaction_id
                        assert second_attempt.parent_attempt_id == first_attempt.parent_attempt_id
                        assert materialization_receipt.plan_hash == first_certificate.native_plan_hash
                        assert materialization_receipt.semantic_plan_hash == (
                            first_certificate.semantic_plan_hash
                        )
                        assert materialization_receipt.metadata_target_fingerprint == (
                            first_certificate.metadata_target_fingerprint
                        )
                        code_after = pseudocode_to_string(cfunc.get_pseudocode())
                        block_rules_fired = {
                            name
                            for name, counts in state.stats.cfg_rule_usages.items()
                            if any(count > 0 for count in counts)
                        }
                        native_materialization_attempts = tuple(
                            receipt.attempt for receipt in materialization_receipt.attempts
                        )
                        attempt_diagnostics = tuple(
                            {
                                "status": attempt.status.value,
                                "reason_code": attempt.reason_code,
                                "details": dict(attempt.details),
                                "effects": tuple(
                                    {
                                        "kind": effect.kind,
                                        "ref_id": effect.ref_id,
                                    }
                                    for effect in attempt.effect_refs
                                ),
                            }
                            for attempt in native_materialization_attempts
                        )
                        assert native_materialization_attempts, (
                            "current-session native materialization attempt is missing; "
                            f"attempts={attempt_diagnostics!r}"
                        )
                        assert first_attempt.status is ExecutionAttemptStatus.COMPLETED, (
                            "current-session native materialization did not complete; "
                            f"attempts={attempt_diagnostics!r}"
                        )
                        first_effects = {
                            effect.kind: effect.ref_id
                            for effect in first_attempt.effect_refs
                        }
                        second_effects = {
                            effect.kind: effect.ref_id
                            for effect in second_attempt.effect_refs
                        }
                        assert {
                            "native_patch_transaction",
                            "native_patch_certificate",
                        } <= first_effects.keys(), (
                            "current-session materialization was not APPLIED through "
                            f"the canonical gateway; attempts={attempt_diagnostics!r}"
                        )
                        assert first_effects["native_patch_transaction"] == (
                            first_normalization.apply_receipt.transaction_id.value
                        )
                        assert second_normalization.reason == (
                            "native_plan_hash matches an existing applied certificate"
                        )
                        assert second_effects.get("native_patch_certificate") == (
                            first_certificate.certificate_id
                        )
                        assert sum(
                            "native_patch_transaction" in {
                                effect.kind for effect in attempt.effect_refs
                            }
                            for attempt in native_materialization_attempts
                        ) == 1
                        assert sum(
                            "native_patch_reanalysis" in {
                                effect.kind for effect in attempt.effect_refs
                            }
                            for attempt in native_materialization_attempts
                        ) == 1
                        assert "native_patch_transaction" not in second_effects
                        assert "native_patch_reanalysis" not in second_effects

                        certificate_payload = first_certificate
                        materialized_item_eas = {
                            int(ea)
                            for kind, ea, expected_after in (
                                certificate_payload.metadata_postconditions
                            )
                            if kind == "recreate_item"
                            and str(expected_after).startswith("item-xrefs:v2:")
                        }
                        assert len(materialized_item_eas) == 31, (
                            "canonical certificate does not prove all 31 unique "
                            f"materialized label items: {sorted(materialized_item_eas)!r}"
                        )
                    finally:
                        if not was_opted_in:
                            state.manager.set_native_patch_opted_in(
                                function_addr=func_ea,
                                enabled=False,
                            )
                finally:
                    state.manager.configure(**prior_manager_config)
                    if had_prior_enabled:
                        runtime_config["native_patch_enabled"] = prior_enabled
                    else:
                        runtime_config.pop("native_patch_enabled", None)

        from d810.core.diag import get_diag_conn
        from d810.diagnostics.indirect_state_transfer_map import extract_transfer_map
        from tests.system.e2e.tigress.tigress_indirect_semantic_oracle import (
            evaluate_tigress_indirect_semantic_oracle,
            inputs_from_transfer_report,
            render_tigress_indirect_semantic_oracle_report,
        )

        diag_conn = get_diag_conn(func_ea)
        assert diag_conn is not None, (
            "tigress_flatten_indirect unflatten oracle requires a diag DB"
        )
        # unflatten applies its CFG rewrite through the DEFERRED modifier, so
        # ``optimize()`` returns 0 and ``cfg_rule_usages`` never records
        # ``StateMachineCffUnflattener`` even though the pipeline ran (unlike the
        # synchronous emulated engine). The deferred-safe "did unflatten unflatten"
        # signal is the REDIRECT_EDGE provenance it writes to the diag DB.
        applied_redirects = _applied_redirect_edges(diag_conn)
        assert applied_redirects, (
            "unflatten applied no REDIRECT_EDGE provenance (pipeline did not "
            "unflatten); canonical native materialization diagnostics="
            f"{attempt_diagnostics!r}; cfg_rule_usages fired={sorted(block_rules_fired)}"
        )
        db_path = _diag_db_path(diag_conn, func_ea=func_ea)
        report = extract_transfer_map(db_path)
        # unflatten may resolve handoffs without REDIRECT_EDGE old_target provenance;
        # feed whatever provenance exists (do NOT hard-require it) so the oracle
        # reports the true semantic verdict rather than erroring on plumbing.
        repaired_handoffs = _derive_live_repaired_handoffs(report, diag_conn)
        inputs = inputs_from_transfer_report(
            report,
            initial_state=0x22,
            repaired_handoffs=repaired_handoffs,
            pseudocode=code_after,
            func_name=func_name,
        )
        result = evaluate_tigress_indirect_semantic_oracle(inputs)
        oracle_report = render_tigress_indirect_semantic_oracle_report(
            result,
            func_name=func_name,
        )

        artifact_dir = Path(os.environ.get("D810_DUMP_DIR", ".tmp"))
        artifact_dir.mkdir(parents=True, exist_ok=True)
        (artifact_dir / "tigress_indirect_unflat_after.c").write_text(
            code_after, encoding="utf-8"
        )
        (artifact_dir / "tigress_indirect_unflat_transfer_map.json").write_text(
            json.dumps(report, indent=2, sort_keys=True), encoding="utf-8"
        )
        (artifact_dir / "tigress_indirect_unflat_oracle.md").write_text(
            oracle_report, encoding="utf-8"
        )

        print(f"\n=== tigress unflatten ORACLE ===\n{oracle_report}")
        print(f"=== tigress unflatten repaired_handoffs: {repaired_handoffs} ===")

        checks_by_name = {check.name: check for check in result.checks}
        required_checks = {
            "terminal_states",
            "conditional_states",
            "state_0x11_handoff_target",
            "state_0x16_handoff_target",
            "table_invariant_proved",
            "no_unresolved_states",
            "no_raw_indirect_jump",
        }
        assert required_checks <= checks_by_name.keys(), (
            "semantic oracle omitted required Tigress checks: "
            f"missing={sorted(required_checks - checks_by_name.keys())!r}; "
            f"report={oracle_report}"
        )
        assert all(
            checks_by_name[name].passed for name in required_checks
        ), oracle_report
        assert result.passed, oracle_report
