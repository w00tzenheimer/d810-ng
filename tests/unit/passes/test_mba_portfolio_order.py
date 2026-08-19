"""Config-v2 ordering contract for the bounded MBA portfolio spike."""

from __future__ import annotations

import json
from pathlib import Path

from d810.core.config import ProjectConfiguration
from d810.core.plugins import PassImplementationCandidate
from d810.passes.mba_simplify import mba_simplify_pass_registry
from d810.passes.pipeline_v2_hook_bridge import pipeline_v2_hook_activation


_ROOT = Path(__file__).resolve().parents[3]
_CONFIG = _ROOT / "src/d810/conf/mba_portfolio_spike.json"
_TELEMETRY_CONFIG = _ROOT / "src/d810/conf/mba_portfolio_telemetry_3ms.json"
_DEEP_CONFIG = _ROOT / "src/d810/conf/mba_portfolio_deep.json"

_CHAIN_IMPLEMENTATIONS = (
    "XorChain",
    "AndChain",
    "OrChain",
    "ArithmeticChain",
)


def _project(path: Path = _CONFIG) -> ProjectConfiguration:
    return ProjectConfiguration(
        path=path,
        **json.loads(path.read_text(encoding="utf-8")),
    )


def _patch_egraph_extension(monkeypatch, rule_name: str = "EgglogOptimizer") -> None:
    candidate = PassImplementationCandidate(
        pass_id="mba-egraph",
        backend_name="egglog",
        backend_origin="test-extension",
        rule_modules=("test_extension.rule",),
        rule_name=rule_name,
    )

    class _Registry:
        def require_unique_implementation(self, pass_id, *, install_hint):
            assert str(pass_id) == "mba-egraph"
            assert install_hint == "pip install d810-egglog"
            return candidate

        def activate_implementation(self, selected):
            assert selected is candidate

    monkeypatch.setattr("d810.backends.registry", lambda: _Registry())


def test_portfolio_spike_declares_fast_path_then_opt_in_egglog() -> None:
    project = _project()

    assert [
        entry["pass_id"] for entry in project.additional_configuration["pipeline_v2"]
    ] == ["mba-simplify", "mba-egraph"]
    assert "mba-solve" not in project.additional_configuration["pipeline_v2"]
    fast_options = project.additional_configuration["pipeline_v2"][0]["options"]
    assert fast_options["generate_commutative_permutations"] is False
    egglog_options = project.additional_configuration["pipeline_v2"][1]["options"]
    assert egglog_options["cross_block_constant_preparation"] is True
    assert egglog_options["time_budget_ms"] == 250
    assert egglog_options["function_time_budget_ms"] == 1_000
    assert egglog_options["residual_only"] is True


def test_hook_activation_keeps_chain_before_catalogue_before_egglog(
    monkeypatch,
) -> None:
    _patch_egraph_extension(monkeypatch)
    activation = pipeline_v2_hook_activation(_project())

    assert activation.configured_pass_ids == ("mba-simplify", "mba-egraph")
    implementation_names = tuple(rule.name for rule in activation.instruction_rules)
    assert implementation_names[: len(_CHAIN_IMPLEMENTATIONS)] == _CHAIN_IMPLEMENTATIONS
    assert implementation_names[-1] == "EgglogOptimizer"
    assert all(
        name not in _CHAIN_IMPLEMENTATIONS
        for name in implementation_names[len(_CHAIN_IMPLEMENTATIONS) : -1]
    )
    assert len(implementation_names) > len(_CHAIN_IMPLEMENTATIONS) + 1


def test_portfolio_spike_loads_without_a_solver_extension(monkeypatch) -> None:
    """The checked-in core profile never resolves the optional mba-solve stage."""

    _patch_egraph_extension(monkeypatch)
    activation = pipeline_v2_hook_activation(_project())

    assert activation.enabled is True
    assert all(rule.name != "CobraSolveRule" for rule in activation.instruction_rules)


def test_hodur_certificate_is_registered_but_not_a_portfolio_fast_path() -> None:
    """Config-v2 activates only explicit transforms, never all registered rules."""

    registry = mba_simplify_pass_registry()
    registered_ids = registry.transform_ids_for("mba-simplify")

    assert "sub-complement-mask-hodur-1" in registered_ids
    for path in (_CONFIG, _TELEMETRY_CONFIG, _DEEP_CONFIG):
        transforms = _project(path).additional_configuration["pipeline_v2"][0][
            "options"
        ]["transforms"]
        assert "sub-complement-mask-hodur-1" not in transforms


def test_telemetry_profile_keeps_the_same_order_but_never_enables_egglog(
    monkeypatch,
) -> None:
    """Three milliseconds is a separate measurement lane, never an optimizer SLA."""

    _patch_egraph_extension(monkeypatch)
    activation = pipeline_v2_hook_activation(_project(_TELEMETRY_CONFIG))

    assert activation.configured_pass_ids == ("mba-simplify", "mba-egraph")
    egglog_options = _project(_TELEMETRY_CONFIG).additional_configuration[
        "pipeline_v2"
    ][1]["options"]
    assert egglog_options["time_budget_ms"] == 3
    assert egglog_options["max_degree"] == 1
    assert "cross_block_constant_preparation" not in egglog_options


def test_deep_profile_is_explicitly_bounded_and_never_the_default_lane(
    monkeypatch,
) -> None:
    _patch_egraph_extension(monkeypatch)
    project = _project(_DEEP_CONFIG)
    activation = pipeline_v2_hook_activation(project)
    egglog_options = project.additional_configuration["pipeline_v2"][1]["options"]

    assert activation.configured_pass_ids == ("mba-simplify", "mba-egraph")
    assert egglog_options["time_budget_ms"] == 500
    assert egglog_options["function_time_budget_ms"] == 5_000
    assert egglog_options["max_degree"] == 2
    assert egglog_options["residual_only"] is True
    assert egglog_options["families"] == [
        "add",
        "and",
        "bnot",
        "mul",
        "neg",
        "or",
        "sub",
        "xor",
    ]
