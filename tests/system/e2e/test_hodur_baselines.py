"""Regression baselines for Hodur unflattening pseudocode metrics.

These tests lock in the expected AFTER-deobfuscation pseudocode metrics
(statements, returns, whiles, gotos, ifs) for Hodur-unflattened functions.
Metrics are AST-based (via libclang CodeComparator) to avoid sensitivity
to cosmetic differences like function signature wrapping, return type
formatting, or whitespace.

Any change to the metrics indicates a regression or improvement that
must be reviewed.

Run with:
    pytest tests/system/e2e/test_hodur_baselines.py -v -s

Requires IDA Pro with Hex-Rays and libclang (auto-marked by e2e conftest).
"""

from __future__ import annotations

import os
import platform
from pathlib import Path

import pytest

import idaapi
import idc

from d810.analyses.control_flow.return_frontier_artifacts import (
    ReturnFrontierArtifactEdgeProof,
    ReturnFrontierArtifactPriors,
)
from d810.analyses.control_flow.terminal_tail_priors import (
    TerminalTailCascadeEgressPriors,
    TerminalTailContinuationBridgePrior,
    TerminalTailEntryFrontierPriors,
    TerminalTailEqualityFrontierPriors,
    TerminalTailRowTargetOverride,
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
# Keys: statements, returns, whiles, gotos, ifs
# These are AST-based counts from CodeComparator.count_ast_statements(),
# immune to cosmetic formatting differences.
HODUR_BASELINES = [
    pytest.param(
        "hodur_func",
        "example_libobfuscated.json",
        {"statements": 39, "returns": 3, "whiles": 0, "gotos": 1, "ifs": 8},
        id="hodur_func",
    ),
    pytest.param(
        "sub_7FFD3338C040",
        "hodur_flag2.json",
        {"statements": 103, "returns": 8, "whiles": 1, "gotos": 10, "ifs": 19},
        id="sub_7FFD3338C040",
    ),
]

SUB_7FFD_KNOWN_IMPOSSIBLE_RETURN_CONSTANTS = (
    "0xC5FB34A1D9A6E315",
)
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
SUB_7FFD_TERMINAL_TAIL_CASCADE_EGRESS_PRIORS = (
    TerminalTailCascadeEgressPriors(
        byte_indices=(1, 2, 5),
        split_byte_indices=(3,),
        row_target_overrides=(
            TerminalTailRowTargetOverride(
                byte_index=2,
                target_entry_byte_index=3,
            ),
        ),
        continuation_bridges=(
            TerminalTailContinuationBridgePrior(
                continuation_byte_index=3,
                source_byte_index=4,
                target_store_guard_byte_index=5,
                max_depth=8,
            ),
        ),
        equality_frontier=TerminalTailEqualityFrontierPriors(
            return_frontier_byte_index=2,
            row_byte_indices=(2, 3),
            shared_store_guard_byte_indices=(3, 5),
        ),
        entry_frontier=TerminalTailEntryFrontierPriors(first_byte_index=1),
    )
)
SUB_7FFD_FUNCTION_PRIORS = FunctionAnalysisPriors(
    return_frontier_artifacts=(
        ReturnFrontierArtifactPriors.from_known_impossible_return_constants(
            SUB_7FFD_KNOWN_IMPOSSIBLE_RETURN_CONSTANTS
        ).with_impossible_return_artifact_edges(
            SUB_7FFD_RETURN_ARTIFACT_EDGE_PROOFS
        )
    ),
    terminal_tail_cascade_egress=SUB_7FFD_TERMINAL_TAIL_CASCADE_EGRESS_PRIORS,
)


def _configure_sub7ffd_function_priors(ctx, func_ea: int) -> None:
    """Inject sub7FFD-only function priors through ProjectContext."""
    ctx.add_function_priors(func_ea, SUB_7FFD_FUNCTION_PRIORS)
    assert ctx.function_priors(func_ea) == SUB_7FFD_FUNCTION_PRIORS
    assert (
        ctx.state.manager.function_analysis_priors_for_ea(func_ea)
        == SUB_7FFD_FUNCTION_PRIORS
    )


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
        code_comparator,
        request,
    ):
        """Assert AFTER pseudocode AST metrics match the locked-in baseline."""
        assert code_comparator is not None, (
            "libclang required for AST-based baseline metrics"
        )

        func_ea = _get_func_ea(func_name)
        if func_ea == idaapi.BADADDR:
            pytest.skip(f"Function '{func_name}' not found in binary")

        if func_name == "sub_7FFD3338C040":
            from d810.core.settings import configure_settings, reset_settings

            configure_settings(
                diag_snapshots=True,
                capture_post_maturity=idaapi.MMAT_GLBOPT1,
            )
            request.addfinalizer(reset_settings)

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

        actual = code_comparator.count_ast_statements(code_after)

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
            assert "return 0x5644FD01B1049C4BLL;" in code_after, (
                "sub_7FFD3338C040 return-carrier regression: "
                "the AFTER pseudocode no longer returns 0x5644FD01B1049C4B"
            )
            from d810.core.diag import get_diag_conn
            from tests.system.e2e.hodur.sub7ffd_region_oracle_runner import (
                render_region_oracle_report,
            )

            diag_conn = get_diag_conn(func_ea)
            if diag_conn is None:
                pytest.fail("sub7FFD region oracle requires a diag DB")
            report = render_region_oracle_report(
                diag_conn,
                func_ea_hex=f"0x{func_ea:016x}",
                func_name=func_name,
            )
            if "Status:" in report:
                pytest.fail(
                    "sub7FFD region oracle did not produce an active report; "
                    "the semantic guardrail is inactive:\n"
                    f"{report}"
                )
            artifact_dir = Path(os.environ.get("D810_DUMP_DIR", ".tmp"))
            artifact_dir.mkdir(parents=True, exist_ok=True)
            report_path = artifact_dir / "sub7ffd_region_oracle.md"
            report_path.write_text(report)
            print(f"\n=== SUB7FFD REGION ORACLE: {report_path} ===")
            print(report)

        # Show per-metric diff for any mismatches
        diffs = {}
        for metric in expected_stats:
            expected_val = expected_stats[metric]
            actual_val = actual.get(metric, 0)
            if actual_val != expected_val:
                diffs[metric] = (expected_val, actual_val, actual_val - expected_val)

        if diffs:
            diff_lines = []
            for metric, (exp, act, delta) in diffs.items():
                diff_lines.append(f"  {metric}: expected={exp} actual={act} delta={delta:+d}")
            diff_msg = "\n".join(diff_lines)
            pytest.fail(
                f"{func_name}: AST metric regression:\n{diff_msg}"
            )


# Key semantic markers that must appear in the rendered linearized state
# program. Symbol names and data references are asserted against AFTER
# pseudocode below because the semantic_reference_like renderer may abstract
# those operands.
SUB_7FFD_SEMANTIC_MARKERS = [
    "STATE_0D64F20E__blk130_h130_s0B2FECE0",
    "STATE_6D207773",
    "STATE_09EB3381",
]


class TestSemanticReferenceRegression:
    """Regression: semantic_reference_like program must exist at GLBOPT1/post_d810.

    This prevents silent regression of Hodur's semantic recovery quality.
    The rendered linearized state program is the primary semantic artifact —
    if it loses handler bodies or API calls, the unflattening regressed.
    """

    binary_name = _get_default_binary()

    def test_sub_7FFD_semantic_reference_exists(
        self,
        libobfuscated_setup,
        d810_state,
        request,
    ):
        """sub_7FFD must produce a semantic_reference_like program with key markers."""
        func_ea = _get_func_ea("sub_7FFD3338C040")
        if func_ea == idaapi.BADADDR:
            pytest.skip("sub_7FFD3338C040 not found")

        # Enable diagnostic snapshots + post-D810 rendered program capture at GLBOPT1
        from d810.core.settings import configure_settings, reset_settings
        configure_settings(diag_snapshots=True, capture_post_maturity=idaapi.MMAT_GLBOPT1)
        request.addfinalizer(reset_settings)

        with d810_state() as state:
            with state.for_project("hodur_flag2.json") as ctx:
                _configure_sub7ffd_function_priors(ctx, func_ea)
                state.stats.reset()
                state.start_d810()
                cfunc = idaapi.decompile(func_ea, flags=idaapi.DECOMP_NO_CACHE)
                if cfunc is None:
                    pytest.fail("sub_7FFD3338C040 decompile returned None")

        # Find the diag DB created during decompilation
        from d810.core.diag import (
            active_diag_db,
            diag_models_on,
            get_diag_conn,
        )
        from d810.diagnostics.query import rendered_program_text

        diag_conn = get_diag_conn(func_ea)
        if diag_conn is None:
            pytest.fail(
                "sub_7FFD3338C040 semantic-reference guard requires a diag DB; "
                "the semantic guardrail is inactive"
            )

        # Find GLBOPT1/post_d810 snapshot
        snap_id = None
        for row in diag_conn.execute("SELECT id, label FROM snapshots"):
            if "GLBOPT1" in row[1] and "post_d810" in row[1]:
                snap_id = row[0]
                break

        assert snap_id is not None, (
            "No MMAT_GLBOPT1/post_d810 snapshot found in diag DB"
        )

        # rendered_program_text uses the ORM; bind the Models to the reopened
        # diag DB (active_diag_db(), backing diag_conn) for the read -- the
        # write path no longer leaves a process-global bind.
        with diag_models_on(active_diag_db()):
            program = rendered_program_text(
                diag_conn, snap_id, "semantic_reference_like"
            )
        assert program is not None and len(program) > 100, (
            f"semantic_reference_like program missing or too short "
            f"(snap_id={snap_id}, len={len(program) if program else 0})"
        )

        # Check key semantic markers
        for marker in SUB_7FFD_SEMANTIC_MARKERS:
            assert marker in program, (
                f"Semantic marker '{marker}' missing from rendered program — "
                f"handler body may have been lost during unflattening"
            )

        diag_conn.close()


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
    101, 103, 111, 118, 132, 161, 163, 217,
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

        prior_gate = os.environ.get(
            "D810_HODUR_PRESERVE_TERMINAL_BYTE_CORRIDORS", ""
        )
        os.environ["D810_HODUR_PRESERVE_TERMINAL_BYTE_CORRIDORS"] = "1"

        def _restore_gate() -> None:
            if prior_gate:
                os.environ[
                    "D810_HODUR_PRESERVE_TERMINAL_BYTE_CORRIDORS"
                ] = prior_gate
            else:
                os.environ.pop(
                    "D810_HODUR_PRESERVE_TERMINAL_BYTE_CORRIDORS", None
                )

        request.addfinalizer(_restore_gate)

        with d810_state() as state:
            with state.for_project("hodur_flag2.json") as ctx:
                _configure_sub7ffd_function_priors(ctx, func_ea)
                state.stats.reset()
                state.start_d810()
                cfunc = idaapi.decompile(
                    func_ea, flags=idaapi.DECOMP_NO_CACHE
                )
                if cfunc is None:
                    pytest.fail(
                        "sub_7FFD3338C040 decompile returned None"
                    )
                code_after = pseudocode_to_string(cfunc.get_pseudocode())

        # The bogus terminal pattern: a paired (v & 7) == 0 break check
        # immediately followed by (v & 7) == 1 returning a constant.
        # Detect via co-occurrence of the two equality checks AND the
        # constant return shape that historically showed up.
        bogus_break = "(v & 7) == 0" in code_after or "& 7) == 0\n" in code_after
        bogus_return_const = (
            "(v & 7) == 1" in code_after or "& 7) == 1\n" in code_after
        )
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
        assert "unk_180019E95" in code_after, (
            "Data reference unk_180019E95 is missing from AFTER pseudocode — "
            "the preserved cascade body regressed."
        )

        # The callee auto-name moves when libobfuscated.dll is rebuilt, so
        # key this guard to the stable zeroing-cascade payload instead.
        zeroing_call_count = code_after.count("&unk_180019E95, 0x10)")
        assert zeroing_call_count >= 8, (
            "zeroing-cascade call count regressed: expected >= 8 "
            f"stable payload calls, got {zeroing_call_count}.  "
            "Corridor preservation may be rejecting mods that the cascade "
            "needs."
        )
