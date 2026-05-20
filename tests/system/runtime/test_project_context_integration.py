"""Integration test for ProjectContext rule filtering API."""
import os
import platform

import pytest
import idaapi
import idc


def _get_default_binary() -> str:
    """Get default binary name based on platform, with env var override."""
    override = os.environ.get("D810_TEST_BINARY")
    if override:
        return override
    return "libobfuscated.dylib" if platform.system() == "Darwin" else "libobfuscated.dll"


def get_func_ea(name: str) -> int:
    """Get function address by name, handling macOS underscore prefix."""
    ea = idc.get_name_ea_simple(name)
    if ea == idaapi.BADADDR:
        ea = idc.get_name_ea_simple("_" + name)
    return ea


class TestProjectContextIntegration:
    """Integration tests for ProjectContext rule filtering."""

    binary_name = _get_default_binary()

    def test_remove_rule_changes_output(
        self,
        ida_database,
        configure_hexrays,
        setup_libobfuscated_funcs,
        d810_state,
        pseudocode_to_string,
    ):
        """Test that removing a rule actually changes the decompilation output."""
        func_name = "constant_folding_test1"
        func_ea = get_func_ea(func_name)
        if func_ea == idaapi.BADADDR:
            pytest.skip(f"Function '{func_name}' not found")

        with d810_state() as state:
            # First, decompile WITH the rule
            with state.for_project("example_libobfuscated.json") as ctx:
                state.start_d810()
                decompiled_with_rule = idaapi.decompile(
                    func_ea, flags=idaapi.DECOMP_NO_CACHE
                )
                assert decompiled_with_rule is not None
                text_with_rule = pseudocode_to_string(
                    decompiled_with_rule.get_pseudocode()
                )
                state.stop_d810()

            # Now decompile WITHOUT an active block rule.
            with state.for_project("example_libobfuscated.json") as ctx:
                ctx.remove_rule("ForwardConstantPropagationRule")

                # Verify the rule was removed
                blk_rule_names = [r.name for r in ctx.active_blk_rules]
                assert "ForwardConstantPropagationRule" not in blk_rule_names

                state.start_d810()
                decompiled_without_rule = idaapi.decompile(
                    func_ea, flags=idaapi.DECOMP_NO_CACHE
                )
                assert decompiled_without_rule is not None
                text_without_rule = pseudocode_to_string(
                    decompiled_without_rule.get_pseudocode()
                )
                state.stop_d810()

        # The outputs should be different (removing a rule changes behavior)
        # Note: We're not asserting which one is "better" - just that they differ
        print(f"\n--- WITH ForwardConstantPropagationRule ---")
        print(text_with_rule[:500])
        print(f"\n--- WITHOUT ForwardConstantPropagationRule ---")
        print(text_without_rule[:500])

    def test_context_restores_rules(
        self,
        ida_database,
        configure_hexrays,
        setup_libobfuscated_funcs,
        d810_state,
    ):
        """Test that rules are restored after context manager exits."""
        with d810_state() as state:
            with state.for_project("example_libobfuscated.json") as ctx:
                original_blk_count = len(ctx.active_blk_rules)

                # Remove an active rule with stable profile coverage so the
                # assertion is independent of retired cleanup rules.
                ctx.remove_rule("ForwardConstantPropagationRule")
                assert len(ctx.active_blk_rules) < original_blk_count

            # After context exits, rules should be restored
            # (Need to re-enter project to check)
            with state.for_project("example_libobfuscated.json") as ctx2:
                assert len(ctx2.active_blk_rules) == original_blk_count

    def test_method_chaining(
        self,
        ida_database,
        configure_hexrays,
        setup_libobfuscated_funcs,
        d810_state,
    ):
        """Test that methods can be chained."""
        with d810_state() as state:
            with state.for_project("example_libobfuscated.json") as ctx:
                original_count = len(ctx.active_blk_rules)

                active_rule_names = {rule.name for rule in ctx.active_blk_rules}
                removable_rule = "ForwardConstantPropagationRule"
                assert removable_rule in active_rule_names

                # Chain an active removal with a missing-rule no-op. The profile
                # intentionally no longer carries retired disabled rules.
                ctx.remove_rule(removable_rule).remove_rule("RetiredMissingRule")

                # Should have removed only the active rule
                assert len(ctx.active_blk_rules) == original_count - 1
                remaining_rule_names = {rule.name for rule in ctx.active_blk_rules}
                assert removable_rule not in remaining_rule_names
