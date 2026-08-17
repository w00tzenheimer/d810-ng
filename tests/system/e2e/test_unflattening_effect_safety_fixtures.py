"""Exact IDA regressions for the two OLLVM unflattening safety fixtures.

These are deliberately separate from ``DeobfuscationCase``.  Target B cannot
be decompiled by Hex-Rays in the D810-off baseline, so the generic runner's
before/after contract is the wrong oracle for it.  The tests below use the
committed MASM source as the raw-call oracle and exercise the production
D810-enabled decompile directly.  Both targets additionally inspect the
diagnostic receipt emitted by the transaction boundary; a pretty pseudocode
rendering alone is not evidence that the CFG rewrite committed.
"""

from __future__ import annotations

import os
import json
import sqlite3
import time
from pathlib import Path

import idc
import idautils
import ida_funcs
import idaapi
import ida_hexrays
import pytest


ROOT = Path(__file__).parents[3]
MASM_DIR = ROOT / "samples" / "src" / "masm"
TARGET_SIZES = {
    # The source labels describe the original IDB image range (A: 0x17e06,
    # B: 0x1796c).  ml64/link.exe may change instruction encodings and padding
    # in the standalone PE, so the materialized IDA extents below are the
    # post-link ranges.  They include the terminal return/trap bytes; using
    # the source-image offsets here would truncate both functions before their
    # terminal blocks and make Hex-Rays report a lost reachable terminal.
    "sub_7FF8569F0540": 0x17E3C,
    "sub_7FF8568132D0": 0x1799B,
}


def _resolve_fixture_ea(function: str) -> int:
    """Resolve a fixture export without depending on IDA's name decoration."""
    ea = idc.BADADDR
    for alias in (function, f"_{function}"):
        ea = idc.get_name_ea_simple(alias)
        if ea != idc.BADADDR:
            break
    if ea == idc.BADADDR:
        for named_ea, name in idautils.Names():
            if name.lstrip("_") == function:
                ea = int(named_ea)
                break
    if ea == idc.BADADDR:
        binary = os.environ.get("D810_TEST_BINARY", "<unknown>")
        pytest.fail(f"missing exported function in {binary}: {function}")
    # Standalone ml64 exports do not carry the original IDA function table.
    # Auto-analysis normally discovers A, but B's opaque dispatcher has no
    # inbound xref and is therefore left as an exported address only.  Create
    # the function explicitly for this fixture before asking Hex-Rays for its
    # boundary; this is equivalent to the source IDB's existing function mark.
    if ida_funcs.get_func(int(ea)) is None:
        end_ea = int(ea) + TARGET_SIZES[function]
        assert ida_funcs.add_func(int(ea), end_ea), (
            f"could not materialize function 0x{ea:x}-0x{end_ea:x}"
        )
        idaapi.auto_wait()
    materialized = ida_funcs.get_func(int(ea))
    assert materialized is not None, f"IDA function missing at 0x{ea:x}"
    assert int(materialized.start_ea) == int(ea)
    assert int(materialized.end_ea) == int(ea) + TARGET_SIZES[function], (
        f"fixture function extent drifted for {function}: "
        f"0x{int(materialized.start_ea):x}-0x{int(materialized.end_ea):x}, "
        f"expected 0x{int(ea):x}-0x{int(ea) + TARGET_SIZES[function]:x}"
    )
    return int(ea)


def _diagnostic_rows(
    function_ea: int,
    *,
    path: Path | None = None,
) -> tuple[Path, list[tuple[str, dict]]]:
    """Return the latest typed D810 diagnostic payloads for *function_ea*."""
    from d810.core.diag import find_latest_diag_db_path

    path = path or find_latest_diag_db_path(int(function_ea))
    if path is None:
        pytest.fail(
            "D810 diagnostic snapshot missing; run this gate with "
            "--enable-diag-snapshot"
        )
    with sqlite3.connect(path) as conn:
        rows = conn.execute(
            "SELECT kind,payload FROM fact_observations "
            "WHERE func_ea_i64=? AND kind IN ("
            "'UnflattenDispatcherCorridorCoverageSummary',"
            "'UnflattenDispatcherRemovalPreflightProof') "
            "ORDER BY rowid",
            (int(function_ea),),
        ).fetchall()
    decoded: list[tuple[str, dict]] = []
    for kind, raw_payload in rows:
        payload = json.loads(raw_payload)
        assert isinstance(payload, dict), (kind, type(payload).__name__)
        decoded.append((str(kind), payload))
    return path, decoded


def _assert_committed_transaction(
    function_ea: int,
    *,
    started_after: float | None = None,
) -> tuple[Path, list[dict]]:
    """Require one non-poisoned committed mutation and accepted coverage proof."""
    from d810.core.diag import find_latest_diag_db_path

    path = find_latest_diag_db_path(int(function_ea))
    if path is None:
        pytest.fail(
            "D810 diagnostic snapshot missing; run this gate with "
            "--enable-diag-snapshot"
        )
    with sqlite3.connect(path) as conn:
        receipts = conn.execute(
            "SELECT r.mutation_batch_id,r.planned_operation_count,"
            "r.applied_operation_count,r.outcome,r.reason "
            "FROM mutation_receipts r JOIN lifecycle_events e "
            "ON e.event_id=r.event_id WHERE e.func_ea_i64=?",
            (int(function_ea),),
        ).fetchall()
        attempts = conn.execute(
            "SELECT current_phase,mutation_started,poisoned "
            "FROM cfg_transaction_attempts WHERE func_ea_i64=?",
            (int(function_ea),),
        ).fetchall()
        session = conn.execute(
            "SELECT started_at,finished_at,status FROM diagnostic_sessions "
            "WHERE func_ea_i64=? ORDER BY started_at DESC LIMIT 1",
            (int(function_ea),),
        ).fetchone()
    committed = [
        {
            "batch_id": str(batch_id),
            "planned": int(planned),
            "applied": int(applied),
            "outcome": str(outcome),
            "reason": str(reason),
        }
        for batch_id, planned, applied, outcome, reason in receipts
        if str(outcome) == "committed"
    ]
    assert committed, f"no committed mutation receipt for 0x{function_ea:x}: {receipts!r}"
    assert any(
        phase == "committed" and int(started) == 1 and int(poisoned) == 0
        for phase, started, poisoned in attempts
    ), f"transaction did not reach clean commit for 0x{function_ea:x}: {attempts!r}"
    assert all(item["planned"] == item["applied"] for item in committed)
    assert session is not None, f"diagnostic session missing for 0x{function_ea:x}"
    assert session[2] == "finished", session
    assert session[1] is not None, session
    if started_after is not None:
        assert float(session[0]) >= float(started_after), (
            f"selected stale diagnostic session for 0x{function_ea:x}: "
            f"started_at={session[0]} test_started_after={started_after}"
        )
    return path, committed


def _assert_corridor_acceptance(function_ea: int, path: Path) -> None:
    """Require accepted, transaction-owned corridor coverage after commit.

    The removal preflight can conservatively reject a *projected* comparison
    corridor while the transaction still accepts the observed corridor
    coverage and commits a complete redirect batch.  The latter is the stable
    acceptance contract for this exact fixture: it is tied to the applied
    plan/attempt, enumerates every corridor, and leaves no residual corridor.
    """
    deadline = time.monotonic() + 10.0
    last_rows: list[tuple[str, str]] = []
    while True:
        with sqlite3.connect(path) as conn:
            rows = conn.execute(
                "SELECT kind,payload FROM fact_observations "
                "WHERE func_ea_i64=? AND kind='UnflattenDispatcherCorridorCoverageSummary' "
                "ORDER BY rowid",
                (int(function_ea),),
            ).fetchall()
            attempts = conn.execute(
                "SELECT plan_id,attempt_id,current_phase,mutation_started,poisoned "
                "FROM cfg_transaction_attempts WHERE func_ea_i64=?",
                (int(function_ea),),
            ).fetchall()
            receipts = conn.execute(
                "SELECT r.mutation_batch_id,r.outcome,e.session_id "
                "FROM mutation_receipts r JOIN lifecycle_events e "
                "ON e.event_id=r.event_id WHERE e.func_ea_i64=?",
                (int(function_ea),),
            ).fetchall()
        last_rows = rows
        committed_attempts = {
            (str(plan_id), str(attempt_id))
            for plan_id, attempt_id, phase, started, poisoned in attempts
            if phase == "committed" and int(started) == 1 and int(poisoned) == 0
        }
        committed_batches = {
            str(batch_id)
            for batch_id, outcome, _session_id in receipts
            if str(outcome) == "committed"
        }
        accepted = []
        for _kind, raw_payload in rows:
            payload = json.loads(raw_payload)
            plan_id = str(payload.get("plan_id"))
            attempt_id = payload.get("attempt_id")
            identity = (plan_id, str(attempt_id))
            if payload.get("application_status") != "applied":
                continue
            if identity not in committed_attempts or str(attempt_id) not in committed_batches:
                continue
            validation = payload.get("observed_coverage_validation") or {}
            observed = validation.get("observed_coverage") or {}
            if (
                validation.get("validation_status") == "accepted"
                and validation.get("reason")
                == "dispatcher_corridor_coverage_matches_observed"
                and payload.get("enumeration_complete") is True
                and payload.get("residual_corridors") == []
                and observed.get("enumeration_complete") is True
                and observed.get("residual_corridors") == []
            ):
                accepted.append(
                    {
                        "plan_id": plan_id,
                        "attempt_id": str(attempt_id),
                        "reason": validation["reason"],
                    }
                )
        if accepted:
            return
        if time.monotonic() >= deadline:
            break
        # Fact observations are flushed by the transaction finalizer. Poll
        # with a bounded backoff rather than baking in a fixed sleep/race.
        elapsed = max(0.0, 10.0 - (deadline - time.monotonic()))
        time.sleep(min(0.05 + elapsed * 0.05, 0.25))
    assert False, (
        f"transaction-owned corridor coverage acceptance missing for "
        f"0x{function_ea:x}; committed_attempts={committed_attempts!r} "
        f"committed_batches={committed_batches!r} rows={last_rows!r}"
    )


def _fixture_or_skip(function: str) -> str:
    binary = os.environ.get("D810_TEST_BINARY", "")
    if binary != "unflattening_effect_safety.dll":
        pytest.skip(
            "exact safety PE fixture is selected with "
            "D810_TEST_BINARY=unflattening_effect_safety.dll"
        )
    source_path = MASM_DIR / f"{function}.asm"
    if not source_path.is_file():
        pytest.fail(f"missing committed MASM fixture: {source_path}")
    _resolve_fixture_ea(function)
    return source_path.read_text()


def _decompile_with_d810(state, function_ea: int):
    """Use the production restart-aware D810 decompile lifecycle."""
    manager = getattr(state, "manager", None)
    decompiled = idaapi.decompile(function_ea, flags=idaapi.DECOMP_NO_CACHE)
    controlled_decompile = getattr(
        manager,
        "decompile_with_native_preanalysis",
        None,
    )
    lifecycle = getattr(manager, "decompilation_lifecycle", None)
    has_pending_restart = getattr(
        lifecycle,
        "has_pending_generated_restart",
        None,
    )
    if (
        callable(controlled_decompile)
        and callable(has_pending_restart)
        and has_pending_restart(function_ea)
    ):
        decompiled = controlled_decompile(
            function_ea,
            lambda: idaapi.decompile(
                function_ea,
                flags=idaapi.DECOMP_NO_CACHE,
            ),
            lambda: idaapi.mark_cfunc_dirty(function_ea, False),
        )
    if decompiled is None:
        # Keep the pre-MMAT failure visible for fixtures that cannot enter the
        # D810 callback pipeline.  This is diagnostic-only; callers still fail
        # on None rather than treating a Hex-Rays failure as a D810 success.
        failure = ida_hexrays.hexrays_failure_t()
        function = ida_funcs.get_func(function_ea)
        direct = None
        if function is not None:
            direct = ida_hexrays.decompile_func(
                function,
                failure,
                int(ida_hexrays.DECOMP_NO_CACHE),
            )
        start = "<no-function>" if function is None else f"0x{int(function.start_ea):x}"
        end = "<no-function>" if function is None else f"0x{int(function.end_ea):x}"
        print(
            "[EFFECT-SAFETY] pre-MMAT decompile failure: "
            f"func=0x{function_ea:x} "
            f"start={start} "
            f"end={end} "
            f"direct_result={direct is not None} "
            f"code={int(failure.code)} "
            f"errea=0x{int(failure.errea):x} "
            f"desc={failure.desc()!r}"
        )
        if direct is not None:
            decompiled = direct
    return decompiled


def _enable_exact_diagnostics(request) -> None:
    """Make the exact fixture own a fresh, post-GLBOPT2 diagnostic snapshot."""
    from d810.core.settings import configure_settings, reset_settings

    configure_settings(
        diag_snapshots=True,
        capture_post_maturity=idaapi.MMAT_GLBOPT2,
    )
    request.addfinalizer(reset_settings)


class TestUnflatteningEffectSafetyFixtures:
    binary_name = "unflattening_effect_safety.dll"

    def test_target_a_ida_fixture_contains_memcpy_and_materialized_dispatcher(
        self,
        ida_database,
    ):
        source = _fixture_or_skip("sub_7FF8569F0540")

        assert "PUBLIC sub_7FF8569F0540" in source
        assert "EXTERN memcpy:PROC" in source
        assert "call memcpy" in source
        assert "CONST SEGMENT" in source
        assert "jmp loc_7FF8569F0600" in source

    def test_target_b_ida_fixture_contains_lock_effect_and_typed_int3(
        self,
        ida_database,
    ):
        source = _fixture_or_skip("sub_7FF8568132D0")

        assert "PUBLIC sub_7FF8568132D0" in source
        assert "call qword ptr [__imp_RtlAcquireSRWLockExclusive]" in source
        assert "EXTERN Eidolon_UpdateSharedStateIfSentinelMatches:PROC" in source
        assert "int 3" in source
        assert "CONST SEGMENT" in source


class TestUnflatteningEffectSafetyDecompilation:
    """Exact after-only IDA oracles for the two effectful OLLVM dispatchers."""

    binary_name = "unflattening_effect_safety.dll"

    def test_target_a_after_preserves_memcpy_effect_and_commits(
        self,
        ida_database,
        configure_hexrays,
        d810_state,
        pseudocode_to_string,
        request,
    ):
        _enable_exact_diagnostics(request)
        source = _fixture_or_skip("sub_7FF8569F0540")
        function_ea = _resolve_fixture_ea("sub_7FF8569F0540")
        assert "EXTERN memcpy:PROC" in source
        assert "call memcpy" in source

        with d810_state() as state:
            with state.for_project("default_unflattening_ollvm.json"):
                state.stats.reset()
                state.start_d810()
                started_after = time.time()
                decompiled = _decompile_with_d810(state, function_ea)
        assert decompiled is not None, "D810-enabled target A decompilation failed"
        code_after = pseudocode_to_string(decompiled.get_pseudocode())
        assert "while ( 1 )" not in code_after
        assert "while (1)" not in code_after
        assert "0xEE1BCAD" in code_after or "0xee1bcad" in code_after
        # Hex-Rays materializes the imported MASM slot as this memory call in
        # the fixture runtime.  The source assertion above binds the slot to
        # memcpy; the state anchor binds the rendered call to its corridor.
        assert "MEMORY[0x200000000]" in code_after

        path, committed = _assert_committed_transaction(
            function_ea,
            started_after=started_after,
        )
        _assert_corridor_acceptance(function_ea, path)
        print(
            f"[EFFECT-SAFETY A] ea=0x{function_ea:x} "
            f"committed={committed} pseudocode_bytes={len(code_after)}"
        )
    def test_target_b_after_preserves_srw_lock_effect_and_commits(
        self,
        ida_database,
        configure_hexrays,
        d810_state,
        pseudocode_to_string,
        request,
    ):
        _enable_exact_diagnostics(request)
        source = _fixture_or_skip("sub_7FF8568132D0")
        function_ea = _resolve_fixture_ea("sub_7FF8568132D0")
        assert "EXTERN __imp_RtlAcquireSRWLockExclusive:PROC" in source
        assert "call qword ptr [__imp_RtlAcquireSRWLockExclusive]" in source
        assert "int 3" in source
        assert "4595D682h" in source or "4593588Ch" in source

        # This is intentionally after-only: Hex-Rays cannot establish the
        # D810-off baseline for this exact fixture, but the D810-enabled
        # transaction must still produce a safe, useful decompilation.
        with d810_state() as state:
            with state.for_project("default_unflattening_ollvm.json"):
                state.stats.reset()
                state.start_d810()
                started_after = time.time()
                decompiled = _decompile_with_d810(state, function_ea)
        assert decompiled is not None, "D810-enabled target B decompilation failed"
        code_after = pseudocode_to_string(decompiled.get_pseudocode())
        # B contains legitimate bounded buffer/hash loops.  The old blanket
        # ``while (1)`` assertion rejected those loops even after the dispatcher
        # was removed.  Exact12 measured 31 LABEL_ occurrences and 17 goto
        # LABEL_ transfers, versus the flattened baseline's 179/111.  Keep a
        # generous regression ceiling while asserting the state constants
        # that identify the flattened dispatcher are gone.
        normalized = code_after.lower()
        for dispatcher_state in (
            "0x27c4381e",
            "0x379d0a55",
            "0x2a469b64",
            "0x2a492993",
        ):
            assert dispatcher_state not in normalized
        assert code_after.count("LABEL_") < 48
        assert code_after.count("goto LABEL_") < 32
        assert "MEMORY[0x200000000]" in code_after

        path, committed = _assert_committed_transaction(
            function_ea,
            started_after=started_after,
        )
        _assert_corridor_acceptance(function_ea, path)
        assert "__debugbreak()" in code_after
        print(
            f"[EFFECT-SAFETY B] ea=0x{function_ea:x} "
            f"committed={committed} pseudocode_bytes={len(code_after)}"
        )
