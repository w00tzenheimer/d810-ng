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

Ground truth for this specific function (``libobfuscated.dll``,
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
import hashlib
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
ida_ida = pytest.importorskip("ida_ida")
idaapi = pytest.importorskip("idaapi")
idc = pytest.importorskip("idc")

from d810.backends.hexrays.native_patch_lifecycle import (  # noqa: E402
    IdaCallerDiscovery,
    IdaCfuncCacheInvalidator,
    IdaControlledRedoDecompiler,
)
from d810.backends.ida.native_patch.capture import (  # noqa: E402
    IdaLiveDatabaseReader,
    capture_range_evidence,
)
from d810.backends.ida.native_patch.dead_edge_oracle import (  # noqa: E402
    find_dead_edges,
    generate_pre_lvars_microcode,
)
from d810.backends.ida.native_patch.encoder import MinimalX86BranchEncoder  # noqa: E402
from d810.backends.ida.native_patch.gateway import (  # noqa: E402
    IdaNativeByteWriter,
    NativePatchGateway,
)
from d810.backends.ida.native_patch.journal import SQLiteNativePatchJournal  # noqa: E402
from d810.backends.ida.native_patch.origin_mapper import (  # noqa: E402
    correlate_native_span,
    ida_decoded_range_reader,
)
from d810.backends.ida.native_patch.reanalysis import IdaFunctionReanalyzer  # noqa: E402
from d810.core.execution_journal import (  # noqa: E402
    DecompilationSessionId,
    ExecutionAttemptId,
)
from d810.core.persistence import SQLiteOptimizationStorage  # noqa: E402
from d810.ir.native_origin import NativeOriginCoverage  # noqa: E402
from d810.testing.runner import _resolve_test_project_index  # noqa: E402
from d810.transforms.native_patch_lowering import lower_direct_edge  # noqa: E402
from d810.transforms.native_patch_plan import (  # noqa: E402
    NativeAddressRange,
    NativeDatabaseIdentity,
    NativeFunctionIdentity,
    NativePatchPlan,
)

FUNCTION_NAME = "single_iteration_simple"
PROJECT_NAME = "bogus_loops.json"

# Ground truth recorded in the module docstring, asserted (not assumed) below.
EXPECTED_SITE_EA = 0x1800113C6
EXPECTED_CURRENT_TARGET_EA = 0x1800113A8
EXPECTED_PROPOSED_TARGET_EA = 0x1800113C8


def _get_func_ea(name: str) -> int:
    ea = idc.get_name_ea_simple(name)
    if ea == idaapi.BADADDR:
        ea = idc.get_name_ea_simple("_" + name)
    return ea


def _bitness() -> int:
    return 64 if ida_ida.inf_is_64bit() else 32


def _decompile_text(pseudocode_to_string, func_ea: int) -> str:
    cfunc = idaapi.decompile(func_ea, flags=idaapi.DECOMP_NO_CACHE)
    assert cfunc is not None, f"failed to decompile {func_ea:#x}"
    return pseudocode_to_string(cfunc.get_pseudocode())


def _similarity(a: str, b: str) -> float:
    return difflib.SequenceMatcher(None, a, b).ratio()


@contextlib.contextmanager
def _fresh_journal(tmp_path):
    journal = SQLiteNativePatchJournal(tmp_path / "journal.db")
    try:
        yield journal
    finally:
        journal.close()


def _build_gateway(journal) -> NativePatchGateway:
    return NativePatchGateway(
        journal=journal,
        reader=IdaLiveDatabaseReader(),
        writer=IdaNativeByteWriter(),
        decode_replacement=MinimalX86BranchEncoder().decode,
        reanalyzer=IdaFunctionReanalyzer(),
        cache_invalidator=IdaCfuncCacheInvalidator(),
        caller_discovery=IdaCallerDiscovery(),
        redo_decompiler=IdaControlledRedoDecompiler(),
        certificate_store=SQLiteOptimizationStorage(":memory:"),
        d810_version="stage-a-dead-edge-oracle-demo",
    )


def _build_plan_from_candidate(function_ea: int, candidate):
    """Turn one oracle-derived :class:`DeadEdgeCandidate` into a
    ``NativePatchPlan``, through the existing lowering + capture machinery --
    never a hand-written byte write.
    """
    start_ea, end_ea = candidate.site_ea, candidate.site_ea + candidate.site_size

    current_bytes = ida_bytes.get_bytes(start_ea, end_ea - start_ea) or b""
    origin_span = correlate_native_span(
        start_ea,
        end_ea,
        ida_decoded_range_reader(),
        expected_bytes_hash=hashlib.sha256(current_bytes).hexdigest(),
    )
    assert origin_span.coverage is NativeOriginCoverage.COMPLETE, origin_span.coverage

    capture_outcome = capture_range_evidence(
        IdaLiveDatabaseReader(),
        NativeAddressRange(start_ea, end_ea),
        function_ea=function_ea,
    )
    assert capture_outcome.ok, capture_outcome.reason

    lowering = lower_direct_edge(
        operation_id="stage-a-dead-edge-oracle-op",
        origin_span=origin_span,
        target_ea=candidate.proposed_target_ea,
        known_instruction_heads=frozenset({candidate.proposed_target_ea}),
        capture=capture_outcome.evidence,
        provider=MinimalX86BranchEncoder(),
        provider_id="minimal-x86",
        provider_version="1",
        bitness=_bitness(),
    )
    assert lowering.ok, lowering.reason

    func = ida_funcs.get_func(function_ea)
    proof_hash = hashlib.sha256(candidate.describe().encode("utf-8")).hexdigest()

    plan = NativePatchPlan(
        plan_id="stage-a-dead-edge-oracle-plan",
        schema_version=1,
        # Section 6.2: persisting a semantic simplification already decided
        # by a named D810 pass's live analysis (SingleTripLoopPeel's own
        # recognizer/prover), not merely exposing already-proven native
        # evidence pre-lift. Stage B (routing through a registered pass
        # issuer carrying a plan hash) is a follow-on; this plan is built
        # directly from the oracle's output, labelled as such via issuer_id.
        patch_class="semantic_deobfuscation",
        database_identity=NativeDatabaseIdentity(
            idb_uuid="stage-a-dead-edge-oracle",
            input_file_hash="stage-a-dead-edge-oracle",
            processor="metapc",
            bitness=_bitness(),
            image_base=idaapi.get_imagebase(),
            database_path_hash="stage-a-dead-edge-oracle",
        ),
        function_identity=NativeFunctionIdentity(
            entry_ea=function_ea,
            chunk_ranges=(NativeAddressRange(int(func.start_ea), int(func.end_ea)),),
            inherited_bytes_hash="stage-a-dead-edge-oracle",
        ),
        inherited_function_fingerprint="stage-a-dead-edge-oracle-fp",
        target_cfg_fingerprint="stage-a-dead-edge-oracle-cfg",
        native_origin_map_fingerprint="stage-a-dead-edge-oracle-origin",
        architecture="x86",
        bitness=_bitness(),
        endianness="little",
        processor="metapc",
        issuer_id="stage_a.dead_edge_oracle:single_trip_loop_peel",
        proof_id=(
            f"single_trip_loop_peel:header={candidate.header_block_serial}:"
            f"latch={candidate.latch_block_serial}:exit={candidate.exit_block_serial}"
        ),
        proof_hash=proof_hash,
        provenance=(candidate.proof_kind, candidate.proof_reason),
        operations=(lowering.operation,),
        fallback_policy="no_patch",
        authorizing_attempt_id=ExecutionAttemptId.new(
            session=DecompilationSessionId.new(), sequence=1
        ),
    )
    return plan


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


class TestDeadEdgeOracleDemonstration:
    binary_name = "libobfuscated.dll"

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

            # Ground truth recorded in the module docstring.
            assert candidate.site_ea == EXPECTED_SITE_EA
            assert candidate.mnemonic == "jmp"
            assert candidate.current_target_ea == EXPECTED_CURRENT_TARGET_EA
            assert candidate.proposed_target_ea == EXPECTED_PROPOSED_TARGET_EA
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

            plan = _build_plan_from_candidate(func_ea, candidate)

            # --- Step 4b: apply through the existing gateway ---------------
            with _fresh_journal(tmp_path) as journal:
                gateway = _build_gateway(journal)
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
