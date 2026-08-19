"""Backend-neutral ordering contracts for the opt-in MBA portfolio."""

from __future__ import annotations

from pathlib import Path

from d810.core.config import ProjectConfiguration
from d810.core.plugins import PassImplementationCandidate
from d810.passes.pipeline_v2_hook_bridge import pipeline_v2_hook_activation


_CHAIN_IMPLEMENTATIONS = (
    "XorChain",
    "AndChain",
    "OrChain",
    "ArithmeticChain",
)


def _project() -> ProjectConfiguration:
    return ProjectConfiguration(
        path=Path("portfolio-fixture.json"),
        additional_configuration={
            "pipeline_v2_mode": "config-v2",
            "pipeline_v2": [
                {
                    "pass_id": "mba-simplify",
                    "options": {
                        "generate_commutative_permutations": False,
                        "transforms": [
                            "xor-chain",
                            "and-chain",
                            "or-chain",
                            "arithmetic-chain",
                        ],
                    },
                },
                {
                    "pass_id": "mba-egraph",
                    "options": {
                        "families": ["add"],
                        "maturities": ["GLOBAL_ANALYZED"],
                        "max_leaves": 2,
                        "max_operator_nodes": 10,
                        "max_degree": 1,
                        "saturation_rounds": 2,
                        "max_eclasses": 64,
                        "max_enodes": 128,
                        "max_rule_firings": 32,
                        "time_budget_ms": 250,
                        "function_time_budget_ms": 1000,
                        "residual_only": True,
                        "require_proof": True,
                    },
                },
            ],
        },
    )


def _patch_egraph_extension(monkeypatch) -> None:
    candidate = PassImplementationCandidate(
        pass_id="mba-egraph",
        backend_name="egglog",
        backend_origin="test-extension",
        rule_modules=("test_extension.rule",),
        rule_name="EgglogOptimizer",
    )

    class _Registry:
        def require_unique_implementation(self, pass_id, *, install_hint):
            assert str(pass_id) == "mba-egraph"
            assert install_hint == "d810-egglog"
            return candidate

        def activate_implementation(self, selected):
            assert selected is candidate

    monkeypatch.setattr("d810.backends.registry", lambda: _Registry())


def test_portfolio_activation_keeps_fast_path_before_opt_in_egglog(monkeypatch):
    _patch_egraph_extension(monkeypatch)
    activation = pipeline_v2_hook_activation(_project())

    assert activation.configured_pass_ids == ("mba-simplify", "mba-egraph")
    names = tuple(rule.name for rule in activation.instruction_rules)
    assert names[: len(_CHAIN_IMPLEMENTATIONS)] == _CHAIN_IMPLEMENTATIONS
    assert names[-1] == "EgglogOptimizer"


def test_portfolio_fast_path_does_not_enable_structural_matching(monkeypatch):
    _patch_egraph_extension(monkeypatch)
    activation = pipeline_v2_hook_activation(_project())

    assert all(
        not getattr(rule, "uses_structural_matching", False)
        for rule in activation.instruction_rules
        if rule.name != "EgglogOptimizer"
    )
