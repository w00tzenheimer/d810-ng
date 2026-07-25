"""Regression baselines for Hodur unflattening pseudocode metrics.

These tests lock in the expected AFTER-deobfuscation pseudocode metrics
(statements, returns, whiles, gotos, ifs, calls) for Hodur-unflattened
functions.  Metrics are AST-based via IDA ctree (count_ast_statements over
the decompiler AST) to avoid sensitivity to cosmetic differences like
function signature wrapping, return type formatting, or whitespace.  The
ctree counter is environment-independent and includes calls to undeclared
functions that libclang would drop.

Any change to the metrics indicates a regression or improvement that
must be reviewed.

Run with:
    pytest tests/system/e2e/test_hodur_baselines.py -v -s

Requires IDA Pro with Hex-Rays (auto-marked by e2e conftest).
"""

from __future__ import annotations

import os
import platform
from pathlib import Path

import pytest

import idaapi
import idc

from tests.system.ctree_comparator import (
    count_ast_statements as ctree_count_ast_statements,
)

from d810.analyses.control_flow.return_frontier_artifacts import (
    ReturnFrontierArtifactEdgeProof,
    ReturnFrontierArtifactPriors,
)
from d810.passes.function_priors import FunctionAnalysisPriors


def _get_func_ea(name: str) -> int:
    """Get function address by name or hex address string.

    Handles named symbols, macOS underscore prefix, and hex addresses.
    """
    ea = idc.get_name_ea_simple(name)
    if ea == idaapi.BADADDR:
        ea = idc.get_name_ea_simple("_" + name)
    if ea == idaapi.BADADDR and name.startswith("0x"):
        try:
            ea = int(name, 16)
            if not idaapi.get_func(ea):
                ea = idaapi.BADADDR
        except ValueError:
            pass
    return ea


def _get_default_binary() -> str:
    """Get default binary name based on platform, with env var override."""
    override = os.environ.get("D810_TEST_BINARY")
    if override:
        return override
    return (
        "libobfuscated.dylib" if platform.system() == "Darwin" else "libobfuscated.dll"
    )


# Baseline expectations: (function_name, project_json, expected_ast_stats)
# Keys: statements, returns, whiles, gotos, ifs, calls
# These are IDA-ctree counts (ctree_count_ast_statements),
# immune to cosmetic formatting differences and environment rendering variants.
HODUR_BASELINES = [
    pytest.param(
        "hodur_func",
        "hodur_flag2_s1a.json",
        # unflatten back-edge unflatten (conditional/equality-chain migration, ticket
        # llr-28ht). hodur_func is a pure CONDITION_CHAIN dispatcher; its
        # exact state->handler map IS routed through emit_minimal_unflatten just
        # like sub_7FFD. Counts from IDA ctree (includes calls to sub_* helpers
        # that libclang would drop). Old libclang baseline was:
        # {statements:39, returns:3, whiles:0, gotos:1, ifs:8} (no calls key).
        # ctree baseline (captured 2026-06-25):
        # statements:94, returns:3, whiles:0, gotos:1, ifs:11, calls:32
        {
            "statements": 94,
            "returns": 3,
            "whiles": 0,
            "gotos": 1,
            "ifs": 11,
            "calls": 32,
        },
        id="hodur_func",
    ),
    pytest.param(
        "sub_7FFD3338C040",
        "hodur_flag2_s1a.json",
        # unflatten back-edge unflatten on the corrected MASM sample (all 9 work-calls
        # preserved, dispatcher removed, semantically == _gitless reference).
        # Counts from IDA ctree (env-independent). Old libclang baseline was:
        # {statements:95, returns:4, whiles:0, gotos:4, ifs:22} (no calls key).
        # ctree baseline after GLBOPT return-carrier corruption cleanup
        # (captured 2026-06-29): two dead return-register constant writes are
        # gone, including the rendered LOBYTE helper call.
        {
            "statements": 186,
            "returns": 4,
            "whiles": 0,
            "gotos": 4,
            "ifs": 23,
            "calls": 9,
        },
        id="sub_7FFD3338C040",
    ),
]

SUB_7FFD_KNOWN_IMPOSSIBLE_RETURN_CONSTANTS = ("0xC5FB34A1D9A6E315",)
SUB_7FFD_RETURN_ARTIFACT_EDGE_PROOFS = (
    ReturnFrontierArtifactEdgeProof(
        source_block=27,
        artifact_block=28,
        old_target_block=92,
        continuation_block=29,
        proof_ids=(
            "sub7ffd_return_frontier_artifact",
            "layout:source27_artifact28_continuation29",
        ),
    ),
)
SUB_7FFD_FUNCTION_PRIORS = FunctionAnalysisPriors(
    return_frontier_artifacts=(
        ReturnFrontierArtifactPriors.from_known_impossible_return_constants(
            SUB_7FFD_KNOWN_IMPOSSIBLE_RETURN_CONSTANTS
        ).with_impossible_return_artifact_edges(SUB_7FFD_RETURN_ARTIFACT_EDGE_PROOFS)
    ),
)


def _configure_sub7ffd_function_priors(ctx, func_ea: int) -> None:
    """Inject sub7FFD-only function priors through ProjectContext."""
    ctx.add_function_priors(func_ea, SUB_7FFD_FUNCTION_PRIORS)
    assert ctx.function_priors(func_ea) == SUB_7FFD_FUNCTION_PRIORS
    assert (
        ctx.state.manager.function_analysis_priors_for_ea(func_ea)
        == SUB_7FFD_FUNCTION_PRIORS
    )


def _sub7ffd_work_call_count(code: str) -> int:
    """Count preserved obfuscation work calls across IDA naming variants."""
    memory_calls = code.count("MEMORY[0x180000000]")
    image_base_calls = code.count("_ImageBase(")
    return memory_calls + image_base_calls


@pytest.fixture(scope="class")
def libobfuscated_setup(ida_database, configure_hexrays, setup_libobfuscated_funcs):
    """Setup fixture for libobfuscated Hodur tests."""
    if not idaapi.init_hexrays_plugin():
        pytest.skip("Hex-Rays decompiler plugin not available")
    return ida_database


class TestHodurBaselines:
    """Regression baselines for Hodur-unflattened function metrics.

    Each parametrized case decompiles a function with its Hodur project
    configuration and asserts that the AFTER pseudocode AST metrics match
    the locked-in baseline values.
    """

    binary_name = _get_default_binary()

    @pytest.mark.parametrize(
        "func_name,project_config,expected_stats",
        HODUR_BASELINES,
    )
    def test_hodur_baseline(
        self,
        func_name: str,
        project_config: str,
        expected_stats: dict,
        libobfuscated_setup,
        d810_state,
        pseudocode_to_string,
        request,
    ):
        """Assert AFTER pseudocode AST metrics match the locked-in baseline."""
        func_ea = _get_func_ea(func_name)
        if func_ea == idaapi.BADADDR:
            pytest.skip(f"Function '{func_name}' not found in binary")

        if project_config == "hodur_flag2_s1a.json":
            from d810.core.settings import configure_settings, reset_settings

            configure_settings(
                diag_snapshots=True,
                capture_post_maturity=idaapi.MMAT_GLBOPT1,
            )
            request.addfinalizer(reset_settings)
            # unflatten back-edge unflatten path (hodur_flag2_s1a.json). Drives both the
            # comparison-condition-chain sub_7FFD and the equality-chain hodur_func through
            # emit_minimal_unflatten. Replaces the legacy HodurUnflattener (which
            # collapses sub_7FFD to a stub + INTERR 50877 on the corrected MASM
            # sample) and the emulated dispatcher engine (hodur_func).
        with d810_state() as state:
            with state.for_project(project_config) as ctx:
                if func_name == "sub_7FFD3338C040":
                    _configure_sub7ffd_function_priors(ctx, func_ea)
                state.stats.reset()
                state.start_d810()
                cfunc = idaapi.decompile(func_ea, flags=idaapi.DECOMP_NO_CACHE)
                assert cfunc is not None, (
                    f"Decompilation of '{func_name}' with d810 failed"
                )
                code_after = pseudocode_to_string(cfunc.get_pseudocode())

        actual = ctree_count_ast_statements(cfunc)

        # Print diagnostics before asserting
        print(f"\n=== HODUR BASELINE: {func_name} ===")
        print(f"  Project:  {project_config}")
        print(f"  Expected: {expected_stats}")
        print(f"  Actual:   {actual}")

        if func_name == "sub_7FFD3338C040":
            assert "return 0;" not in code_after, (
                "sub_7FFD3338C040 return-carrier regression: "
                "the AFTER pseudocode returns 0 instead of the reference constant"
            )
            assert "return 0xC5FB34A1D9A6E315uLL;" not in code_after, (
                "sub_7FFD3338C040 return-carrier regression: "
                "the AFTER pseudocode returns a pool-qword/state-guard artifact"
            )
            # unflatten emits ``result = 0x5644...; ...; return result;`` rather than a
            # literal ``return 0x5644...;`` — assert the value is present.
            assert "0x5644FD01B1049C4BLL" in code_after, (
                "sub_7FFD3338C040 return-carrier regression: "
                "the AFTER pseudocode no longer returns 0x5644FD01B1049C4B"
            )
            assert "LOBYTE(result) = 0xB5;" not in code_after, (
                "sub_7FFD3338C040 return-carrier corruption regression: "
                "the byte-exit path still overwrites the true carrier with 0xB5"
            )
            assert "0x4F409D9CACFE95CLL" not in code_after, (
                "sub_7FFD3338C040 return-carrier corruption regression: "
                "the six-byte exit path still returns a folded foreign constant"
            )
            # The unflatten back-edge unflatten does not build the legacy StateDag /
            # region-DAG preanalysis, so the region-oracle guardrail is N/A. Guard
            # instead on obfuscation-work preservation: every 0x180000000 work
            # call must survive (the corrected sample has 9, incl. the recovered
            # 0x4D handler that the legacy path dropped).  IDA may render that
            # target as MEMORY[0x180000000] or as the local _ImageBase symbol.
            n_work_calls = _sub7ffd_work_call_count(code_after)
            assert n_work_calls == 9, (
                "sub_7FFD3338C040 work-call regression: expected 9 obfuscation "
                f"calls in AFTER pseudocode, found {n_work_calls}"
            )

        # Show per-metric diff for any mismatches
        if actual == expected_stats:
            return

        diffs = {}
        for metric in expected_stats:
            expected_val = expected_stats[metric]
            actual_val = actual.get(metric, 0)
            if actual_val != expected_val:
                diffs[metric] = (expected_val, actual_val, actual_val - expected_val)

        if diffs:
            diff_lines = []
            for metric, (exp, act, delta) in diffs.items():
                diff_lines.append(
                    f"  {metric}: expected={exp} actual={act} delta={delta:+d}"
                )
            diff_msg = "\n".join(diff_lines)
            pytest.fail(f"{func_name}: AST metric regression:\n{diff_msg}")


# ---------------------------------------------------------------------------
# Corridor-preservation regression
# ---------------------------------------------------------------------------
# Locks the topology fix from commit 36e3436d.  When the corridor-preserve
# gate is on, the byte-emit terminal cascade in sub_7FFD3338C040 must:
#   * not collapse to the bogus paired pattern
#         if ((v & 7) == 0) break;
#         if ((v & 7) == 1) return <CONST>;
#     that we shipped before the corridor detector existed.
#   * preserve the for-loop byte-emit step driven by the folded MBA
#     equality check (`== 0xFFFFFFFFFFFFFF02uLL`).
#   * preserve all 9 callees.

# Block serials of the byte-emitter cascade as identified in the trace +
# detector work (commit 36e3436d).  These are the user-named cascade
# blocks that must be inside the protected side_effect_corridors set.
SUB_7FFD_CASCADE_BLOCKS: tuple[int, ...] = (
    101,
    103,
    111,
    118,
    132,
    161,
    163,
    217,
)


class TestSub7FFDCorridorPreservationRegression:
    """Regression: byte-emitter terminal cascade must remain protected.

    With ``D810_HODUR_PRESERVE_TERMINAL_BYTE_CORRIDORS=1`` (the gate
    landed by commit 0d125ea1's corridor lineage), the AFTER pseudocode
    of sub_7FFD3338C040 must NOT regress to the bogus terminal pair we
    shipped before commit 36e3436d.
    """

    binary_name = _get_default_binary()

    def test_sub_7FFD_no_bogus_terminal_pair_with_gate(
        self,
        libobfuscated_setup,
        d810_state,
        pseudocode_to_string,
        request,
    ):
        """AFTER must not contain the paired ``(v & 7) == 0`` break +
        ``(v & 7) == 1`` return-constant pattern that signals a
        collapsed cascade.

        Also positively asserts the folded MBA equality check
        ``== 0xFFFFFFFFFFFFFF02uLL`` is present (the for-loop guard
        from the preserved cascade body).
        """
        import os

        func_ea = _get_func_ea("sub_7FFD3338C040")
        if func_ea == idaapi.BADADDR:
            pytest.skip("sub_7FFD3338C040 not found")

        # unflatten back-edge unflatten path: the legacy HodurUnflattener collapses
        # sub_7FFD to a stub + INTERR 50877 on the corrected MASM sample, whereas
        # unflatten preserves the byte-emit cascade (incl. the ``== 0xFFFFFFFFFFFFFF02``
        # for-loop guard) and all 9 callees.
        _prev_env = {
            k: os.environ.get(k)
            for k in ("D810_HODUR_PRESERVE_TERMINAL_BYTE_CORRIDORS",)
        }
        os.environ["D810_HODUR_PRESERVE_TERMINAL_BYTE_CORRIDORS"] = "1"

        def _restore_gate() -> None:
            for k, v in _prev_env.items():
                if v is None:
                    os.environ.pop(k, None)
                else:
                    os.environ[k] = v

        request.addfinalizer(_restore_gate)

        with d810_state() as state:
            with state.for_project("hodur_flag2_s1a.json") as ctx:
                _configure_sub7ffd_function_priors(ctx, func_ea)
                state.stats.reset()
                state.start_d810()
                cfunc = idaapi.decompile(func_ea, flags=idaapi.DECOMP_NO_CACHE)
                if cfunc is None:
                    pytest.fail("sub_7FFD3338C040 decompile returned None")
                code_after = pseudocode_to_string(cfunc.get_pseudocode())

        # The bogus terminal pattern: a paired (v & 7) == 0 break check
        # immediately followed by (v & 7) == 1 returning a constant.
        # Detect via co-occurrence of the two equality checks AND the
        # constant return shape that historically showed up.
        bogus_break = "(v & 7) == 0" in code_after or "& 7) == 0\n" in code_after
        bogus_return_const = "(v & 7) == 1" in code_after or "& 7) == 1\n" in code_after
        # Be conservative: only fail when BOTH pieces of the bogus pair
        # are present.  A single occurrence of "& 7) ==" can be
        # legitimate cascade discrimination.
        if bogus_break and bogus_return_const:
            pytest.fail(
                "Bogus paired terminal `(v & 7) == 0` break + "
                "`(v & 7) == 1` return regression detected — corridor "
                "preservation gate is on but the cascade collapsed.  "
                "See commit 36e3436d for the topology fix."
            )

        # Positive: the MBA-folded byte-emit guard must remain.  This
        # is the for-loop's equality check produced by the preserved
        # cascade's MBA computation.
        assert "0xFFFFFFFFFFFFFF02" in code_after, (
            "MBA-folded byte-emit equality check (== 0xFFFFFFFFFFFFFF02) "
            "is missing from AFTER pseudocode — the preserved cascade's "
            "for-loop guard regressed."
        )
        # The unflatten back-edge output writes the zeroing cascade as 8 a5-relative
        # OWORD stores (a5+0x50 .. a5+0xC0) — the same payload the legacy path
        # rendered against the global ``unk_180019E95``, now parameter-relative
        # (matching the _gitless reference).
        zeroing_count = code_after.count("(_OWORD *)(a5 + 0x")
        assert zeroing_count >= 8, (
            "zeroing-cascade regressed: expected >= 8 a5-relative OWORD "
            f"stores, got {zeroing_count}."
        )

        # All 9 obfuscation callees must survive (incl. the recovered 0x4D
        # handler the legacy path dropped on the corrupted sample).
        n_calls = _sub7ffd_work_call_count(code_after)
        assert n_calls == 9, (
            f"work-call regression: expected 9 obfuscation calls, found {n_calls}."
        )
