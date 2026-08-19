"""Stage A demonstration: a native patch that persists a proven deobfuscation.

This is the acceptance test for
``d810.backends.ida.native_patch.dead_edge_oracle`` (the branch-direction
proof source the P0 counterexample in
``_gitless/REVERSIBLE-NATIVE-PATCHES.md`` says the pipeline was missing).
Every assertion mirrors the demonstration chain the report's Stage A
prescribes, in order:

1. ``baseline_off``  = pseudocode with d810 stopped.
2. ``baseline_on``   = pseudocode with d810 started.
3. Guard: ``baseline_off != baseline_on`` -- otherwise this function is not
   a deobfuscation target and the rest of the chain proves nothing.
4. The oracle derives a dead edge from d810's OWN live single-trip-loop
   analysis (Z3-proved), independently cross-checked against a live native
   decode. The candidate is turned into a ``NativePatchPlan`` and applied
   through the existing gateway (``d810.backends.ida.native_patch.gateway``)
   -- this test never calls ``ida_bytes.patch_byte`` directly.
5. ``patched_off``   = pseudocode with d810 stopped again, after the patch.
6. Assert ``patched_off == baseline_on`` (or report the diff and require it
   is strictly closer to ``baseline_on`` than ``baseline_off`` was).
7. Assert the patch is semantics-preserving: emulate the actual patched
   native bytes (Unicorn -- ground truth independent of how Hex-Rays renders
   them) for several concrete inputs and assert the returned value is
   ``a1 + 10`` in every case.
8. Restore through the gateway; assert the post-restore pseudocode reverts
   to ``baseline_off``.

Ground truth for this specific function (``dead_edge_oracle_fixture.dll``,
``single_iteration_simple`` @ ``0x180011390``), established by direct
disassembly and a Docker dump run with the ``bogus_loops.json`` project
before this test was written:

    0x1800113ac  cmp  eax, 1234h
    0x1800113b1  jnz  loc_1800113C8      (observer's wrong candidate site)
    0x1800113b3  [body: result += 10; state = 5678h]
    0x1800113c6  jmp  loc_1800113A8      (the oracle's site -- an
                                           unconditional jmp the conditional-
                                           only observer never proposes)
    0x1800113c8  [return result]

d810's own ``SingleTripLoopPeelRule`` (project ``bogus_loops.json``), when
allowed to mutate live MBA, redirects exactly this edge: latch block's
back-edge (tail ea ``0x1800113c6``) from the header (``0x1800113a8``) to the
loop's proven-unique exit (``0x1800113c8``). This test asks the oracle for
the same fact without letting the live MBA mutation happen, and persists it
as native bytes instead.
"""

from __future__ import annotations

import contextlib
import difflib
import re

import pytest

pytestmark = [
    pytest.mark.requires_ida,
    pytest.mark.runtime,
    pytest.mark.hexrays,
    pytest.mark.e2e,
]

ida_bytes = pytest.importorskip("ida_bytes")
ida_funcs = pytest.importorskip("ida_funcs")
ida_hexrays = pytest.importorskip("ida_hexrays")
ida_segment = pytest.importorskip("ida_segment")
idaapi = pytest.importorskip("idaapi")
idc = pytest.importorskip("idc")

from d810.backends.hexrays.native_patch_lifecycle import (  # noqa: E402
    IdaCallerDiscovery,
    IdaCfuncCacheInvalidator,
    IdaControlledRedoDecompiler,
)
from d810.backends.ida.native_patch.capture import (  # noqa: E402
    IdaLiveDatabaseReader,
)
from d810.backends.ida.native_patch.dead_edge_oracle import (  # noqa: E402
    DeadEdgeAction,
    build_dead_edge_semantic_plan,
    find_dead_edges,
    generate_pre_lvars_microcode,
)
from d810.backends.ida.native_patch.encoder import MinimalX86BranchEncoder  # noqa: E402
from d810.backends.ida.native_patch.gateway import (  # noqa: E402
    IdaNativeByteWriter,
    NativePatchGateway,
)
from d810.backends.ida.native_patch.issuer import (  # noqa: E402
    NativePatchIssuerRegistry,
    dead_edge_semantic_issuers,
)
from d810.backends.ida.native_patch.journal import SQLiteNativePatchJournal  # noqa: E402
from d810.backends.ida.native_patch.reanalysis import (  # noqa: E402
    IdaFunctionExtentRestorer,
    IdaFunctionFlowRestorer,
    IdaFunctionReanalyzer,
)
from d810.capabilities.native_patch import NativePatchTransactionId  # noqa: E402
from d810.core.execution_journal import (  # noqa: E402
    DecompilationSessionId,
    ExecutionAttemptId,
    ExecutionAttemptStatus,
)
from d810.core.persistence import SQLiteOptimizationStorage  # noqa: E402
from d810.manager.manager import d810_hooks_suppressed  # noqa: E402
from d810.testing.runner import _resolve_test_project_index  # noqa: E402

FUNCTION_NAME = "single_iteration_simple"
PROJECT_NAME = "bogus_loops.json"

# Ground truth, asserted (not assumed) below -- as offsets from the function
# entry, never absolute EAs.
#
# This test uses a dedicated binary because rebuilding the shared
# ``libobfuscated.dll`` changes unrelated MASM fixtures. Offsets still pin the
# exact instruction while allowing the dedicated PE to be relocated without
# silently drifting onto a different candidate.
EXPECTED_SITE_OFFSET = 0x36
EXPECTED_CURRENT_TARGET_OFFSET = 0x18
EXPECTED_PROPOSED_TARGET_OFFSET = 0x38


_PRIVATE_FIXTURE_SIGNATURES = {
    "single_iteration_simple": bytes.fromhex(
        "4883ec10894c240c8b44240c89442408c744240434120000"
        "8b4424043d3412000075158b44240883c00a89442408"
        "c744240478560000ebe08b4424084883c410c3"
    ),
    "fake_jump_opaque_predicate": bytes.fromhex(
        "4883ec108954240c894c24088b4424080344240c89442404"
        "8b44240883e8010faf44240883e001890424833c2400750c"
        "8b442404d1e089442404eb096b4424040389442404"
        "8b4424044883c410c3"
    ),
}


def _find_unique_executable_signature(signature: bytes) -> int:
    matches: list[int] = []
    segment = ida_segment.get_first_seg()
    while segment is not None:
        if int(segment.perm) & int(ida_segment.SEGPERM_EXEC):
            contents = bytes(
                ida_bytes.get_bytes(
                    int(segment.start_ea),
                    int(segment.end_ea - segment.start_ea),
                )
                or b""
            )
            offset = contents.find(signature)
            while offset >= 0:
                matches.append(int(segment.start_ea) + offset)
                offset = contents.find(signature, offset + 1)
        segment = ida_segment.get_next_seg(int(segment.start_ea))
    assert len(matches) == 1, (
        "private fixture signature must resolve uniquely; "
        f"found {len(matches)} matches"
    )
    return matches[0]


def _get_func_ea(name: str) -> int:
    ea = idc.get_name_ea_simple(name)
    if ea == idaapi.BADADDR:
        ea = idc.get_name_ea_simple("_" + name)
    if ea == idaapi.BADADDR and name in _PRIVATE_FIXTURE_SIGNATURES:
        ea = _find_unique_executable_signature(_PRIVATE_FIXTURE_SIGNATURES[name])
        function = ida_funcs.get_func(ea)
        if function is None:
            assert ida_funcs.add_func(ea, ea + len(_PRIVATE_FIXTURE_SIGNATURES[name]))
            idaapi.auto_wait()
            function = ida_funcs.get_func(ea)
        assert function is not None and int(function.start_ea) == int(ea)
        assert idaapi.set_name(ea, name, idaapi.SN_NOCHECK)
    return ea


def _decompile_text(pseudocode_to_string, func_ea: int) -> str:
    cfunc = idaapi.decompile(func_ea, flags=idaapi.DECOMP_NO_CACHE)
    assert cfunc is not None, f"failed to decompile {func_ea:#x}"
    return pseudocode_to_string(cfunc.get_pseudocode())


def _similarity(a: str, b: str) -> float:
    return difflib.SequenceMatcher(None, a, b).ratio()


@contextlib.contextmanager
def _fresh_journal(tmp_path):
    tmp_path.mkdir(parents=True, exist_ok=True)
    journal = SQLiteNativePatchJournal(tmp_path / "journal.db")
    try:
        yield journal
    finally:
        journal.close()


def _build_gateway(journal, *, database_identity: str) -> NativePatchGateway:
    return NativePatchGateway(
        journal=journal,
        reader=IdaLiveDatabaseReader(),
        writer=IdaNativeByteWriter(),
        decode_replacement=MinimalX86BranchEncoder().decode,
        reanalyzer=IdaFunctionReanalyzer(),
        extent_restorer=IdaFunctionExtentRestorer(),
        flow_restorer=IdaFunctionFlowRestorer(),
        cache_invalidator=IdaCfuncCacheInvalidator(),
        caller_discovery=IdaCallerDiscovery(),
        redo_decompiler=IdaControlledRedoDecompiler(),
        certificate_store=SQLiteOptimizationStorage(":memory:"),
        issuer_registry=NativePatchIssuerRegistry(dead_edge_semantic_issuers()),
        current_database_identity=database_identity,
        d810_version="dead-edge-semantic-oracle-demo",
    )


def _build_plan_from_candidates(function_ea: int, candidates):
    """Exercise the production Stage B issuer, not a test-owned contract."""
    return build_dead_edge_semantic_plan(
        function_ea,
        tuple(candidates),
        authorizing_attempt_id=ExecutionAttemptId.new(
            session=DecompilationSessionId.new(), sequence=1
        ),
    )


def _emulate_patched_function(func_ea: int, func_end_ea: int, a1: int) -> int:
    """Execute the CURRENT native bytes of ``[func_ea, func_end_ea)`` under
    Unicorn and return EAX at return -- ground truth independent of how
    Hex-Rays renders the function, matching this repository's own
    encoder-oracle convention (see
    ``tests/unit/backends/ida/native_patch/test_encoder_unicorn_oracle.py``).
    """
    from unicorn import UC_ARCH_X86, UC_MODE_64, Uc
    from unicorn.x86_const import UC_X86_REG_EAX, UC_X86_REG_RCX, UC_X86_REG_RSP

    code = ida_bytes.get_bytes(func_ea, func_end_ea - func_ea)
    assert code is not None

    page = func_ea & ~0xFFF
    page_size = ((func_end_ea - page) // 0x1000 + 2) * 0x1000
    stack_base = 0x00F00000
    stack_size = 0x10000

    emu = Uc(UC_ARCH_X86, UC_MODE_64)
    emu.mem_map(page, page_size)
    emu.mem_write(func_ea, code)
    emu.mem_map(stack_base, stack_size)

    stack_top = stack_base + stack_size - 0x1000
    return_sentinel = page + page_size - 8
    emu.mem_write(stack_top, return_sentinel.to_bytes(8, "little"))
    emu.reg_write(UC_X86_REG_RSP, stack_top)
    emu.reg_write(UC_X86_REG_RCX, a1 & 0xFFFFFFFF)

    emu.emu_start(func_ea, return_sentinel)
    return emu.reg_read(UC_X86_REG_EAX) & 0xFFFFFFFF


def _emulate_range_safely(func_ea: int, func_end_ea: int):
    """Emulate over several inputs, or return None if the function cannot run.

    Used to compare behaviour before and after a patch on functions whose
    contract is not known by hand. A function that faults under Unicorn (it
    calls out, touches unmapped memory, ...) produces no evidence either way,
    so this reports that rather than inventing a result.
    """
    try:
        import unicorn  # noqa: F401
    except ImportError:
        return None
    results = []
    for a1 in (0, 1, 5, 0x7FFFFFFF, 0xFFFFFFFF):
        try:
            results.append(_emulate_patched_function(func_ea, func_end_ea, a1))
        except Exception:
            return None
    return tuple(results)


class TestDeadEdgeOracleDemonstration:
    binary_name = "dead_edge_oracle_fixture.dll"

    def test_manager_owned_stage_b_is_reachable_and_restorable(
        self, copy_of_idb, d810_state, pseudocode_to_string
    ) -> None:
        """The normal manager decompile path owns semantic plan issuance."""
        with d810_state() as state:
            project_index = _resolve_test_project_index(state, PROJECT_NAME)
            state.load_project(project_index)
            func_ea = _get_func_ea(FUNCTION_NAME)
            assert func_ea != idaapi.BADADDR, f"{FUNCTION_NAME} not found"

            state.stop_d810()
            baseline_off = _decompile_text(pseudocode_to_string, func_ea)

            project = state.current_project
            assert project is not None
            runtime_config = project.additional_configuration
            had_prior_enabled = "native_patch_enabled" in runtime_config
            prior_enabled = runtime_config.get("native_patch_enabled")
            prior_manager_config = dict(state.manager.config)
            runtime_config["native_patch_enabled"] = True
            state.manager.configure(
                **{**prior_manager_config, "native_patch_enabled": True}
            )

            from d810.backends.hexrays.native_preanalysis_key import (
                resolve_native_preanalysis_identity,
            )

            identity = resolve_native_preanalysis_identity(func_ea, profile_config={})
            assert identity.native_key is not None
            state.start_d810()
            assert state.manager._dead_edge_normalizer is not None
            assert state.manager._native_patch_gateway is not None

            was_opted_in = state.manager.is_native_patch_opted_in(func_ea)
            state.manager.set_native_patch_opted_in(
                function_addr=func_ea,
                enabled=True,
            )
            try:
                execution_journal = state.manager._native_patch_execution_journal
                prior_attempt_ids = {
                    attempt.attempt_id
                    for attempt in execution_journal.attempts_for_function(func_ea)
                }
                cfunc = state.manager.decompile_with_native_preanalysis(
                    func_ea,
                    lambda: idaapi.decompile(
                        func_ea,
                        flags=idaapi.DECOMP_NO_CACHE,
                    ),
                    lambda: ida_hexrays.mark_cfunc_dirty(func_ea),
                )
                assert cfunc is not None
                attempts = tuple(
                    attempt
                    for attempt in execution_journal.attempts_for_function(func_ea)
                    if attempt.stage_id == "native_dead_edge_normalizer"
                    and attempt.attempt_id not in prior_attempt_ids
                )
                assert len(attempts) == 1
                attempt = attempts[0]
                assert attempt.status is ExecutionAttemptStatus.COMPLETED
                transaction_effects = tuple(
                    effect
                    for effect in attempt.effect_refs
                    if effect.kind == "native_patch_transaction"
                )
                assert len(transaction_effects) == 1
                transaction_id = NativePatchTransactionId(
                    value=transaction_effects[0].ref_id
                )

                with d810_hooks_suppressed(state.manager):
                    patched_off = _decompile_text(pseudocode_to_string, func_ea)
                assert patched_off != baseline_off
                restore = state.manager._native_patch_gateway.restore(transaction_id)
                assert restore.ok, restore
                with d810_hooks_suppressed(state.manager):
                    reverted_off = _decompile_text(pseudocode_to_string, func_ea)
                assert reverted_off == baseline_off
            finally:
                if not was_opted_in:
                    state.manager.set_native_patch_opted_in(
                        function_addr=func_ea,
                        enabled=False,
                    )
                state.manager.configure(**prior_manager_config)
                if had_prior_enabled:
                    runtime_config["native_patch_enabled"] = prior_enabled
                else:
                    runtime_config.pop("native_patch_enabled", None)

    def test_native_patch_persists_proven_deobfuscation(
        self, copy_of_idb, d810_state, pseudocode_to_string, tmp_path
    ) -> None:
        with d810_state() as state:
            project_index = _resolve_test_project_index(state, PROJECT_NAME)
            state.load_project(project_index)

            func_ea = _get_func_ea(FUNCTION_NAME)
            assert func_ea != idaapi.BADADDR, f"{FUNCTION_NAME} not found"
            IdaFunctionReanalyzer().reanalyze_function(func_ea)

            # --- Step 1: baseline_off ------------------------------------
            state.stop_d810()
            baseline_off = _decompile_text(pseudocode_to_string, func_ea)

            # --- Step 2: baseline_on --------------------------------------
            state.start_d810()
            baseline_on = _decompile_text(pseudocode_to_string, func_ea)

            print(f"[dead-edge-demo] baseline_off:\n{baseline_off}")
            print(f"[dead-edge-demo] baseline_on:\n{baseline_on}")

            # --- Step 3: guard ---------------------------------------------
            assert baseline_off != baseline_on, (
                f"{FUNCTION_NAME} is not a deobfuscation target under "
                f"{PROJECT_NAME} -- this test would prove nothing"
            )

            # --- Step 4a: derive the dead edge from the oracle -------------
            # Generate fresh pre-LVARS microcode with d810 OFF: the loop's
            # back-edge is still present (SingleTripLoopPeel has not mutated
            # it live) and the guard is still a raw stack operand the
            # recognizer understands -- see
            # ``generate_pre_lvars_microcode``'s docstring for why
            # ``cfunc.mba`` (final maturity) does not work here.
            state.stop_d810()
            off_mba = generate_pre_lvars_microcode(func_ea)
            assert off_mba is not None

            candidates, abstentions = find_dead_edges(off_mba, function_ea=func_ea)
            print(f"[dead-edge-demo] candidates: {[c.describe() for c in candidates]}")
            print(f"[dead-edge-demo] abstentions: {abstentions}")
            assert len(candidates) == 1, (
                f"expected exactly one proven dead edge, got {len(candidates)}: "
                f"{candidates}"
            )
            candidate = candidates[0]

            # Ground truth, as offsets from the entry -- see the constants.
            assert candidate.site_ea - func_ea == EXPECTED_SITE_OFFSET
            assert candidate.mnemonic == "jmp"
            assert candidate.action is DeadEdgeAction.RETARGET
            assert (
                candidate.current_target_ea - func_ea == EXPECTED_CURRENT_TARGET_OFFSET
            )
            assert (
                candidate.proposed_target_ea - func_ea
                == EXPECTED_PROPOSED_TARGET_OFFSET
            )
            # The observer's shortlist (conditional branches only) never
            # proposes this site at all -- confirm the oracle's site is not
            # even representable as a *conditional*-branch observation.
            from d810.backends.ida.native_patch.observation import observe_function

            observation = observe_function(func_ea)
            assert observation is not None
            assert candidate.site_ea not in {b.site_ea for b in observation.branches}, (
                "the oracle's site must not already be on the conditional-"
                "branch-only observer's shortlist"
            )

            plan = _build_plan_from_candidates(func_ea, [candidate])

            # --- Step 4b: apply through the existing gateway ---------------
            with _fresh_journal(tmp_path) as journal:
                gateway = _build_gateway(
                    journal, database_identity=plan.database_identity.idb_uuid
                )
                apply_receipt = gateway.apply(plan)
                assert apply_receipt.ok, apply_receipt.rejection_reasons

                # --- Step 5: patched_off ------------------------------------
                state.stop_d810()
                patched_off = _decompile_text(pseudocode_to_string, func_ea)
                print(f"[dead-edge-demo] patched_off:\n{patched_off}")

                # --- Step 6: patched_off == baseline_on, or strictly closer -
                if patched_off != baseline_on:
                    diff = "\n".join(
                        difflib.unified_diff(
                            baseline_on.splitlines(),
                            patched_off.splitlines(),
                            fromfile="baseline_on",
                            tofile="patched_off",
                            lineterm="",
                        )
                    )
                    print(f"[dead-edge-demo] patched_off != baseline_on, diff:\n{diff}")
                    sim_to_on = _similarity(patched_off, baseline_on)
                    sim_to_off = _similarity(patched_off, baseline_off)
                    assert sim_to_on > sim_to_off, (
                        "patched_off must be strictly closer to baseline_on "
                        f"than to baseline_off (to_on={sim_to_on:.3f}, "
                        f"to_off={sim_to_off:.3f})"
                    )

                # --- Step 7: semantics-preserving -----------------------------
                # Textual: the return expression must still add 10 to a1.
                assert re.search(r"a1\s*\+\s*(?:0x[aA]\b|10\b)", patched_off), (
                    f"patched_off lost the '+10': {patched_off!r}"
                )

                # Ground truth: emulate the ACTUAL patched native bytes.
                unicorn = pytest.importorskip("unicorn")
                del unicorn
                func = ida_funcs.get_func(func_ea)
                for a1 in (0, 1, 5, 0x7FFFFFFF, 0xFFFFFFFF):
                    got = _emulate_patched_function(
                        int(func.start_ea), int(func.end_ea), a1
                    )
                    expected = (a1 + 10) & 0xFFFFFFFF
                    assert got == expected, (
                        f"patched function is not semantics-preserving for "
                        f"a1={a1:#x}: got {got:#x}, expected {expected:#x}"
                    )

                # --- Step 8: restore and assert it reverts --------------------
                restore_receipt = gateway.restore(apply_receipt.transaction_id)
                assert restore_receipt.ok, restore_receipt

            state.stop_d810()
            reverted_off = _decompile_text(pseudocode_to_string, func_ea)
            print(f"[dead-edge-demo] reverted_off:\n{reverted_off}")
            assert reverted_off == baseline_off, (
                "post-restore pseudocode (d810 stopped) must revert to "
                "baseline_off exactly"
            )

    def test_opaque_predicate_native_authorization_abstains_on_unsupported_width(
        self, copy_of_idb, d810_state, pseudocode_to_string
    ) -> None:
        """D810 may simplify these predicates, but native issuance must abstain."""
        with d810_state() as state:
            project_index = _resolve_test_project_index(state, PROJECT_NAME)
            state.load_project(project_index)

            function_name = "fake_jump_opaque_predicate"
            func_ea = _get_func_ea(function_name)
            assert func_ea != idaapi.BADADDR
            IdaFunctionReanalyzer().reanalyze_function(func_ea)

            state.stop_d810()
            baseline_off = _decompile_text(pseudocode_to_string, func_ea)
            func = ida_funcs.get_func(func_ea)
            start_ea, end_ea = int(func.start_ea), int(func.end_ea)
            bytes_before = bytes(ida_bytes.get_bytes(start_ea, end_ea - start_ea))
            state.start_d810()
            baseline_on = _decompile_text(pseudocode_to_string, func_ea)
            assert baseline_off != baseline_on

            state.stop_d810()
            off_mba = generate_pre_lvars_microcode(func_ea)
            assert off_mba is not None
            candidates, abstentions = find_dead_edges(off_mba, function_ea=func_ea)
            assert all(
                candidate.proof_kind != "z3_opaque_predicate"
                for candidate in candidates
            )
            assert [
                item.reason
                for item in abstentions
                if item.proof_kind == "z3_opaque_predicate"
            ] == ["UNSUPPORTED_COMPARISON_WIDTH:left=1,right=1"]
            assert (
                bytes(ida_bytes.get_bytes(start_ea, end_ea - start_ea)) == bytes_before
            )

    def test_width_safe_opaque_predicate_applies_and_restores_losslessly(
        self, copy_of_idb, d810_state, pseudocode_to_string, tmp_path
    ) -> None:
        """Retain native round-trip coverage on predicates modeled exactly."""
        with d810_state() as state:
            project_index = _resolve_test_project_index(state, PROJECT_NAME)
            state.load_project(project_index)
            actions_seen: set[DeadEdgeAction] = set()

            for function_name in ("test_opaque_predicate",):
                func_ea = _get_func_ea(function_name)
                assert func_ea != idaapi.BADADDR
                IdaFunctionReanalyzer().reanalyze_function(func_ea)

                state.stop_d810()
                baseline_off = _decompile_text(pseudocode_to_string, func_ea)
                state.start_d810()
                baseline_on = _decompile_text(pseudocode_to_string, func_ea)
                assert baseline_off != baseline_on

                state.stop_d810()
                off_mba = generate_pre_lvars_microcode(func_ea)
                assert off_mba is not None
                candidates, abstentions = find_dead_edges(off_mba, function_ea=func_ea)
                opaque = tuple(
                    candidate
                    for candidate in candidates
                    if candidate.proof_kind == "z3_opaque_predicate"
                )
                assert opaque, abstentions
                actions_seen.update(candidate.action for candidate in opaque)

                func = ida_funcs.get_func(func_ea)
                start_ea, end_ea = int(func.start_ea), int(func.end_ea)
                bytes_before = bytes(ida_bytes.get_bytes(start_ea, end_ea - start_ea))
                before_emulation = _emulate_range_safely(start_ea, end_ea)
                plan = _build_plan_from_candidates(func_ea, opaque)

                with _fresh_journal(tmp_path / function_name) as journal:
                    gateway = _build_gateway(
                        journal,
                        database_identity=plan.database_identity.idb_uuid,
                    )
                    apply_receipt = gateway.apply(plan)
                    assert apply_receipt.ok, apply_receipt.rejection_reasons
                    state.stop_d810()
                    patched_off = _decompile_text(pseudocode_to_string, func_ea)
                    assert _similarity(patched_off, baseline_on) > _similarity(
                        patched_off, baseline_off
                    )
                    if before_emulation is not None:
                        assert (
                            _emulate_range_safely(start_ea, end_ea) == before_emulation
                        )
                    restore_receipt = gateway.restore(apply_receipt.transaction_id)
                    assert restore_receipt.ok, restore_receipt

                assert (
                    bytes(ida_bytes.get_bytes(start_ea, end_ea - start_ea))
                    == bytes_before
                )
                state.stop_d810()
                assert _decompile_text(pseudocode_to_string, func_ea) == baseline_off

            assert DeadEdgeAction.FORCE_TAKEN in actions_seen

    def test_manager_stage_b_makes_zero_writes_for_unsupported_width(
        self, copy_of_idb, d810_state, monkeypatch
    ) -> None:
        """The production pass records an abstention and never opens a transaction."""
        function_name = "fake_jump_opaque_predicate"
        with d810_state() as state:
            project_index = _resolve_test_project_index(state, PROJECT_NAME)
            state.load_project(project_index)
            func_ea = _get_func_ea(function_name)
            assert func_ea != idaapi.BADADDR
            IdaFunctionReanalyzer().reanalyze_function(func_ea)

            state.stop_d810()
            func = ida_funcs.get_func(func_ea)
            start_ea, end_ea = int(func.start_ea), int(func.end_ea)
            bytes_before = bytes(ida_bytes.get_bytes(start_ea, end_ea - start_ea))

            project = state.current_project
            assert project is not None
            runtime_config = project.additional_configuration
            had_prior_enabled = "native_patch_enabled" in runtime_config
            prior_enabled = runtime_config.get("native_patch_enabled")
            prior_manager_config = dict(state.manager.config)
            runtime_config["native_patch_enabled"] = True
            state.manager.configure(
                **{**prior_manager_config, "native_patch_enabled": True}
            )
            from d810.backends.hexrays.native_preanalysis_key import (
                resolve_native_preanalysis_identity,
            )

            identity = resolve_native_preanalysis_identity(func_ea, profile_config={})
            assert identity.native_key is not None

            import d810.backends.ida.native_patch.dead_edge_oracle as oracle_module
            from d810.hexrays.hooks.optimization_suppression import (
                d810_optimization_is_suppressed,
            )

            discover = oracle_module.find_dead_edges_for_function
            discovery_suppression: list[bool] = []

            def _discover_with_suppression_witness(function_ea: int):
                discovery_suppression.append(d810_optimization_is_suppressed())
                return discover(function_ea)

            monkeypatch.setattr(
                oracle_module,
                "find_dead_edges_for_function",
                _discover_with_suppression_witness,
            )
            state.start_d810()
            assert state.manager._dead_edge_normalizer is not None
            was_opted_in = state.manager.is_native_patch_opted_in(func_ea)
            state.manager.set_native_patch_opted_in(
                function_addr=func_ea,
                enabled=True,
            )
            assert state.manager.is_native_patch_opted_in(func_ea)
            execution_journal = state.manager._native_patch_execution_journal
            prior_attempt_ids = {
                attempt.attempt_id
                for attempt in execution_journal.attempts_for_function(func_ea)
            }
            try:
                cfunc = state.manager.decompile_with_native_preanalysis(
                    func_ea,
                    lambda: idaapi.decompile(
                        func_ea,
                        flags=idaapi.DECOMP_NO_CACHE,
                    ),
                    lambda: ida_hexrays.mark_cfunc_dirty(func_ea),
                )
                assert cfunc is not None
                new_attempts = tuple(
                    attempt
                    for attempt in execution_journal.attempts_for_function(func_ea)
                    if attempt.attempt_id not in prior_attempt_ids
                    and attempt.stage_id == "native_dead_edge_normalizer"
                )
                assert len(new_attempts) == 1
                attempt = new_attempts[0]
                assert attempt.status is ExecutionAttemptStatus.ABSTAINED
                assert attempt.reason_code == "NO_PROVEN_DEAD_EDGES"
                assert discovery_suppression == [True]
                assert (
                    state.manager.decompilation_lifecycle.current_session(func_ea)
                    is None
                )
                parent = execution_journal.get_attempt(attempt.parent_attempt_id)
                assert parent is not None
                assert parent.status is ExecutionAttemptStatus.COMPLETED
                assert all(
                    effect.kind != "native_patch_transaction"
                    for effect in attempt.effect_refs
                )
                assert (
                    bytes(ida_bytes.get_bytes(start_ea, end_ea - start_ea))
                    == bytes_before
                )
            finally:
                if not was_opted_in:
                    state.manager.set_native_patch_opted_in(
                        function_addr=func_ea,
                        enabled=False,
                    )
                state.manager.configure(**prior_manager_config)
                if had_prior_enabled:
                    runtime_config["native_patch_enabled"] = prior_enabled
                else:
                    runtime_config.pop("native_patch_enabled", None)
