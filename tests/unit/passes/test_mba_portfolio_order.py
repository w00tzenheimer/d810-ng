"""Config-v2 ordering contract for the bounded MBA portfolio spike."""

from __future__ import annotations

import json
from pathlib import Path

from d810.core.config import ProjectConfiguration
from d810.passes.pipeline_v2_hook_bridge import pipeline_v2_hook_activation


_ROOT = Path(__file__).resolve().parents[3]
_CONFIG = _ROOT / "src/d810/conf/mba_portfolio_spike.json"

_CHAIN_IMPLEMENTATIONS = (
    "XorChain",
    "AndChain",
    "OrChain",
    "ArithmeticChain",
)


def _project() -> ProjectConfiguration:
    return ProjectConfiguration(
        path=_CONFIG,
        **json.loads(_CONFIG.read_text(encoding="utf-8")),
    )


def test_portfolio_spike_declares_fast_path_then_opt_in_egglog() -> None:
    project = _project()

    assert [
        entry["pass_id"]
        for entry in project.additional_configuration["pipeline_v2"]
    ] == ["mba-simplify", "mba-egglog"]
    assert "mba-solve" not in project.additional_configuration["pipeline_v2"]


def test_hook_activation_keeps_chain_before_catalogue_before_egglog() -> None:
    activation = pipeline_v2_hook_activation(_project())

    assert activation.configured_pass_ids == ("mba-simplify", "mba-egglog")
    implementation_names = tuple(rule.name for rule in activation.instruction_rules)
    assert implementation_names[: len(_CHAIN_IMPLEMENTATIONS)] == _CHAIN_IMPLEMENTATIONS
    assert implementation_names[-1] == "EgglogOptimizer"
    assert all(
        name not in _CHAIN_IMPLEMENTATIONS
        for name in implementation_names[len(_CHAIN_IMPLEMENTATIONS) : -1]
    )
    assert len(implementation_names) > len(_CHAIN_IMPLEMENTATIONS) + 1


def test_portfolio_spike_loads_without_a_solver_extension() -> None:
    """The checked-in core profile never resolves the optional mba-solve stage."""

    activation = pipeline_v2_hook_activation(_project())

    assert activation.enabled is True
    assert all(rule.name != "CobraSolveRule" for rule in activation.instruction_rules)
