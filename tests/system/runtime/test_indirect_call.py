"""System tests for IndirectCallResolver (the copycat project Phase 6).

Tests that IndirectCallResolver correctly detects indirect call
instructions (m_icall / m_call with register targets), locates the
associated function pointer table, traces the index and sub-offset,
and replaces the indirect call with a direct m_call in real IDA Pro
microcode.

These tests require IDA Pro with Hex-Rays decompiler and exercise the
optimizer against real binaries -- no mocks.

Sample requirements:
    A binary containing functions with indirect calls through function
    pointer tables (e.g., Hikari-style vtable obfuscation with
    sub-offset encoding).  The libobfuscated sample does not currently
    contain such patterns.  These tests are structured and ready to run
    once an appropriate sample is added.
"""

from __future__ import annotations

import os
import platform
from types import SimpleNamespace

import pytest

from d810.testing.cases import DeobfuscationCase
from d810.testing.runner import run_deobfuscation_test
from d810.optimizers.microcode.flow.jumps.indirect_call import IndirectCallResolver


def _get_default_binary() -> str:
    """Get default binary name based on platform, with env var override."""
    override = os.environ.get("D810_TEST_BINARY")
    if override:
        return override
    return (
        "libobfuscated.dylib" if platform.system() == "Darwin" else "libobfuscated.dll"
    )


# ---------------------------------------------------------------------------
# Test cases
# ---------------------------------------------------------------------------
# IndirectCallResolver handles m_icall and m_call-with-register-target
# instructions by locating the associated function pointer table,
# tracing the index computation (via register/stack variable tracking),
# extracting any sub-offset encoding, computing the target EA, and
# replacing the indirect call with a direct m_call.
#
# This pattern appears in Hikari-obfuscated binaries with vtable
# obfuscation.  The libobfuscated sample does not contain these
# patterns, so tests are marked as needing a dedicated sample.
# ---------------------------------------------------------------------------

INDIRECT_CALL_CASES = [
    DeobfuscationCase(
        function="indirect_call_vtable_sub",
        description=(
            "Function with indirect call through a function pointer table "
            "using sub-offset encoding.  IndirectCallResolver should trace "
            "the index, extract the sub-offset, compute the target, and "
            "convert m_icall to m_call."
        ),
        project="default_indirect_resolution.json",
        must_change=True,
        # IDA 9.4 renders this as a direct call before D810 sees the nested
        # MMAT_CALLS m_icall. Require the real CFG patch instead of accepting a
        # renderer-level visual no-op.
        allow_unchanged_pseudocode_if_rules_fired=True,
        check_stats=True,
        required_rules=["IndirectCallResolver"],
    ),
    DeobfuscationCase(
        function="indirect_call_register_target",
        description=(
            "Function with m_call using a register target (computed from "
            "table lookup).  IndirectCallResolver should resolve the "
            "register value and replace with a direct call."
        ),
        project="default_indirect_resolution.json",
        must_change=True,
        check_stats=True,
        required_rules=["IndirectCallResolver"],
    ),
    DeobfuscationCase(
        function="indirect_call_hikari_mov_sub",
        description=(
            "Hikari-style indirect call pattern: mov+ldx+sub+icall.  "
            "IndirectCallResolver should detect the full pattern chain "
            "and resolve the target function."
        ),
        project="default_indirect_resolution.json",
        must_change=True,
        # See indirect_call_vtable_sub: the actual microcode mutation is the
        # oracle when the renderer has already made the direct call visible.
        allow_unchanged_pseudocode_if_rules_fired=True,
        check_stats=True,
        required_rules=["IndirectCallResolver"],
    ),
]


@pytest.fixture(scope="class")
def libobfuscated_setup(ida_database, configure_hexrays, setup_libobfuscated_funcs):
    """Setup fixture for libobfuscated tests -- runs once per class."""
    import idaapi

    if not idaapi.init_hexrays_plugin():
        pytest.skip("Hex-Rays decompiler plugin not available")
    return ida_database


class TestIndirectCallResolver:
    """System tests for IndirectCallResolver using real IDA Pro decompilation.

    IndirectCallResolver detects indirect calls (m_icall or m_call
    with register/computed targets), locates the function pointer
    table, traces index computation through register and stack variable
    assignments, extracts sub-offset encoding, and replaces the
    indirect call with a direct m_call to the resolved target.
    """

    binary_name = _get_default_binary()

    @staticmethod
    def _calls_maturity_mba(function_name: str):
        import ida_funcs
        import ida_hexrays
        import idc

        func_ea = idc.get_name_ea_simple(function_name)
        func = ida_funcs.get_func(func_ea)
        assert func is not None, f"function {function_name!r} is missing"
        ranges = ida_hexrays.mba_ranges_t(func)
        failure = ida_hexrays.hexrays_failure_t()
        mba = ida_hexrays.gen_microcode(
            ranges,
            failure,
            None,
            ida_hexrays.DECOMP_NO_WAIT,
            ida_hexrays.MMAT_CALLS,
        )
        assert mba is not None, failure.desc()
        return mba

    @staticmethod
    def _indirect_callees(mba, resolver):
        """Return the indirect callees currently materialized in *mba*."""
        candidates = []
        for serial in range(mba.qty):
            block = mba.get_mblock(serial)
            owner = block.head
            while owner is not None:
                candidates.extend(
                    candidate
                    for candidate in resolver._call_candidates(owner)
                    if resolver._is_indirect_call(candidate)
                )
                owner = owner.next
        return candidates

    @pytest.mark.ida_required
    @pytest.mark.parametrize(
        "function_name",
        ("indirect_call_vtable_sub", "indirect_call_hikari_mov_sub"),
    )
    def test_calls_maturity_indirect_callee_rewrites_to_direct_call(
        self,
        function_name,
        libobfuscated_setup,
    ):
        """A computed MMAT_CALLS callee must produce one native patch."""
        mba = self._calls_maturity_mba(function_name)
        resolver = IndirectCallResolver()
        before = self._indirect_callees(mba, resolver)
        assert len(before) == 1, "fixture must preserve one indirect MMAT_CALLS callee"

        patches = sum(
            resolver.optimize(mba.get_mblock(serial)) for serial in range(mba.qty)
        )

        assert patches == 1
        assert not self._indirect_callees(mba, resolver)

    @pytest.mark.ida_required
    def test_config_v2_activates_indirect_call_resolver(
        self,
        libobfuscated_setup,
        d810_state,
    ):
        """The config-v2 bridge must retain the resolver's live hook rule."""
        with d810_state() as state:
            import ida_hexrays
            import idc

            state.load_project(
                state.project_manager.index("default_indirect_resolution.json")
            )

            assert "IndirectCallResolver" in [
                rule.name for rule in state.current_blk_rules
            ]
            state.start_d810()
            assert "IndirectCallResolver" in [
                rule.name for rule in state.manager.block_optimizer.cfg_rules
            ]
            report = state.manager.get_effective_execution_report(
                idc.get_name_ea_simple("indirect_call_vtable_sub")
            )
            assert any(
                decision.pass_id == "indirect-call-resolver"
                and decision.active
                for decision in report.decisions
            )
            assert any(
                stage.implementation is not None
                and stage.pass_id == "indirect-call-resolver"
                for stage in state.manager.execution_scope_service.active_stages(
                    project_name=report.project_name,
                    idb_key=report.idb_key,
                    func_ea=report.function_ea,
                    pipeline="flow",
                    maturity=ida_hexrays.MMAT_CALLS,
                )
            )

    @pytest.mark.ida_required
    @pytest.mark.parametrize("case", INDIRECT_CALL_CASES, ids=lambda c: c.test_id)
    def test_indirect_call_resolver(
        self,
        case,
        libobfuscated_setup,
        d810_state,
        pseudocode_to_string,
        code_comparator,
        capture_stats,
        load_expected_stats,
    ):
        """Verify IndirectCallResolver resolves indirect calls."""
        run_deobfuscation_test(
            case=case,
            d810_state=d810_state,
            pseudocode_to_string=pseudocode_to_string,
            code_comparator=code_comparator,
            capture_stats=capture_stats,
            load_expected_stats=load_expected_stats,
        )


# ---------------------------------------------------------------------------
# Attribute and constant verification tests
# ---------------------------------------------------------------------------


class TestIndirectCallResolverAttributes:
    """Verify IndirectCallResolver class attributes with real IDA constants."""

    binary_name = _get_default_binary()

    @pytest.mark.ida_required
    def test_multiple_nested_indirect_calls_are_ambiguous(
        self, libobfuscated_setup
    ):
        """A shared carrier with two nested calls must never pick one child."""
        import ida_hexrays

        owner = SimpleNamespace(opcode=ida_hexrays.m_mov)
        nested_first = SimpleNamespace(opcode=ida_hexrays.m_icall)
        nested_second = SimpleNamespace(opcode=ida_hexrays.m_icall)

        assert IndirectCallResolver._has_ambiguous_nested_indirect_calls(
            (owner, nested_first, nested_second)
        )

    @pytest.mark.ida_required
    def test_name(self, libobfuscated_setup):
        assert IndirectCallResolver.NAME == "IndirectCallResolver"

    @pytest.mark.ida_required
    def test_description_mentions_indirect_call(self, libobfuscated_setup):
        from d810.optimizers.microcode.flow.jumps.indirect_call import (
            IndirectCallResolver,
        )

        assert "indirect call" in IndirectCallResolver.DESCRIPTION.lower()

    @pytest.mark.ida_required
    def test_uses_deferred_cfg_is_true(self, libobfuscated_setup):
        from d810.optimizers.microcode.flow.jumps.indirect_call import (
            IndirectCallResolver,
        )

        assert IndirectCallResolver.USES_DEFERRED_CFG is True

    @pytest.mark.ida_required
    def test_max_table_entries(self, libobfuscated_setup):
        from d810.optimizers.microcode.flow.jumps.indirect_call import (
            IndirectCallResolver,
        )

        assert IndirectCallResolver.MAX_TABLE_ENTRIES == 512

    @pytest.mark.ida_required
    def test_default_entry_size(self, libobfuscated_setup):
        from d810.optimizers.microcode.flow.jumps.indirect_call import (
            IndirectCallResolver,
        )

        assert IndirectCallResolver.DEFAULT_ENTRY_SIZE == 8

    @pytest.mark.ida_required
    def test_min_sub_offset(self, libobfuscated_setup):
        from d810.optimizers.microcode.flow.jumps.indirect_call import (
            IndirectCallResolver,
        )

        assert IndirectCallResolver.MIN_SUB_OFFSET == 0x10000

    @pytest.mark.ida_required
    def test_max_sub_offset(self, libobfuscated_setup):
        from d810.optimizers.microcode.flow.jumps.indirect_call import (
            IndirectCallResolver,
        )

        assert IndirectCallResolver.MAX_SUB_OFFSET == 0x1000000

    @pytest.mark.ida_required
    def test_safe_maturities_uses_real_constants(self, libobfuscated_setup):
        """SAFE_MATURITIES should contain real IDA maturity values."""
        from d810.optimizers.microcode.flow.jumps.indirect_call import (
            IndirectCallResolver,
        )

        assert isinstance(IndirectCallResolver.SAFE_MATURITIES, list)
        for mat in IndirectCallResolver.SAFE_MATURITIES:
            assert isinstance(mat, int)


# ---------------------------------------------------------------------------
# Module-level constant tests
# ---------------------------------------------------------------------------


class TestModuleConstants:
    """Verify module-level constants with real IDA imports."""

    binary_name = _get_default_binary()

    @pytest.mark.ida_required
    def test_max_table_entries_module_level(self, libobfuscated_setup):
        from d810.optimizers.microcode.flow.jumps.indirect_call import MAX_TABLE_ENTRIES

        assert MAX_TABLE_ENTRIES == 512

    @pytest.mark.ida_required
    def test_default_entry_size_module_level(self, libobfuscated_setup):
        from d810.optimizers.microcode.flow.jumps.indirect_call import (
            DEFAULT_ENTRY_SIZE,
        )

        assert DEFAULT_ENTRY_SIZE == 8

    @pytest.mark.ida_required
    def test_min_sub_offset_module_level(self, libobfuscated_setup):
        from d810.optimizers.microcode.flow.jumps.indirect_call import MIN_SUB_OFFSET

        assert MIN_SUB_OFFSET == 0x10000

    @pytest.mark.ida_required
    def test_max_sub_offset_module_level(self, libobfuscated_setup):
        from d810.optimizers.microcode.flow.jumps.indirect_call import MAX_SUB_OFFSET

        assert MAX_SUB_OFFSET == 0x1000000
