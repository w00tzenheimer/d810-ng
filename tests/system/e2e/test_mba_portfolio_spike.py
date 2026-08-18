"""Native config-v2 receipt for the ordered core MBA portfolio spike."""

from __future__ import annotations

import ida_hexrays
import pytest


_CHAIN_RULE_NAMES = ("XorChain", "AndChain", "OrChain", "ArithmeticChain")


@pytest.mark.usefixtures("configure_hexrays")
class TestMbaPortfolioSpike:
    """The existing hook executes the declared portfolio; no master pass exists."""

    binary_name = "libobfuscated.dll"

    def test_activates_chain_catalogue_then_egglog(self, ida_database, d810_state) -> None:
        with d810_state() as state:
            state.load_project(
                state.project_manager.index("mba_portfolio_spike.json")
            )

            assert state.last_pipeline_v2_hook_pass_ids == (
                "mba-simplify",
                "mba-egraph",
            )
            names = tuple(rule.name for rule in state.current_ins_rules)
            assert names[: len(_CHAIN_RULE_NAMES)] == _CHAIN_RULE_NAMES
            assert names[-1] == "EgglogOptimizer"
            assert all(
                not getattr(rule, "uses_structural_matching", False)
                for rule in state.current_ins_rules
                if rule.name not in {*_CHAIN_RULE_NAMES, "EgglogOptimizer"}
            )
            egglog = state.current_ins_rules[-1]
            assert egglog.maturities == [ida_hexrays.MMAT_GLBOPT1]
            assert egglog.max_degree == 1
            assert egglog.time_budget_ms > 3

    def test_legacy_projects_keep_registry_instruction_order(
        self, ida_database, d810_state
    ) -> None:
        """Config-v2 scheduling must not alter the legacy hook contract."""

        with d810_state() as state:
            legacy_project = state.project_manager.get("flatfold.json")
            state._activate_runtime_project(
                project_index=state.project_manager.index("flatfold.json"),
                source_project=legacy_project,
                runtime_project=legacy_project,
                default_selection=None,
            )

            configured_names = {
                rule.name
                for rule in state.current_project.ins_rules
                if rule.is_activated
            }
            expected = tuple(
                rule.name
                for rule in state.known_ins_rules
                if rule.name in configured_names
            )
            assert state.last_pipeline_v2_hook_mode is None
            assert tuple(rule.name for rule in state.current_ins_rules) == expected
