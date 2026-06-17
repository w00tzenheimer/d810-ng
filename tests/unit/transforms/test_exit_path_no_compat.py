"""Acceptance tests that terminal-corridor compatibility APIs are gone."""
from __future__ import annotations

import importlib
import importlib.util

import pytest


@pytest.mark.parametrize(
    "module_name",
    [
        "d810.transforms.corridor_liveness_policy",
        "d810.analyses.control_flow.terminal_corridor_discovery",
        "d810.transforms.terminal_corridor_emission",
        "d810.transforms.terminal_corridor_planning",
    ],
)
def test_terminal_corridor_module_shims_are_removed(module_name: str) -> None:
    assert importlib.util.find_spec(module_name) is None


@pytest.mark.parametrize(
    ("module_name", "symbol_name"),
    [
        (
            "d810.transforms.exit_path_liveness_policy",
            "CorridorShortcutDecision",
        ),
        (
            "d810.transforms.exit_path_liveness_policy",
            "corridor_blocks_live_violations",
        ),
        (
            "d810.transforms.exit_path_liveness_policy",
            "evaluate_corridor_shortcut",
        ),
        (
            "d810.analyses.control_flow.exit_path_effect_discovery",
            "TerminalCorridorGroup",
        ),
        (
            "d810.analyses.control_flow.exit_path_effect_discovery",
            "TerminalCorridorDiscoveryResult",
        ),
        (
            "d810.analyses.control_flow.exit_path_effect_discovery",
            "discover_terminal_corridor_group",
        ),
        (
            "d810.transforms.exit_path_effect_emission",
            "DirectTerminalLoweringExecutionPlan",
        ),
        (
            "d810.transforms.exit_path_effect_emission",
            "plan_state_terminal_corridor_lowerings",
        ),
        (
            "d810.core.observability_events",
            "CorridorShortcutDecisionsObserved",
        ),
        (
            "d810.core.observability_recon",
            "observe_corridor_shortcut_decisions",
        ),
        (
            "d810.core.diag.snapshot",
            "snapshot_corridor_shortcut_decisions",
        ),
        (
            "d810.core.diag.models",
            "CorridorShortcutDecision",
        ),
        (
            "d810.transforms.graph_modification",
            "DirectTerminalLoweringKind",
        ),
        (
            "d810.transforms.graph_modification",
            "DirectTerminalLoweringSite",
        ),
        (
            "d810.transforms.graph_modification",
            "DirectTerminalLoweringGroup",
        ),
        (
            "d810.transforms.plan",
            "PatchDirectTerminalLoweringGroup",
        ),
    ],
)
def test_terminal_corridor_public_symbol_aliases_are_removed(
    module_name: str,
    symbol_name: str,
) -> None:
    module = importlib.import_module(module_name)
    assert not hasattr(module, symbol_name)
