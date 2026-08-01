from __future__ import annotations

from types import SimpleNamespace

from d810.analyses.value_flow.contract_evidence import contract_evidence_payload
from d810.manager.workbench_recipe_analysis import collect_recipe_preflight_facts


class _ReconRuntime:
    def __init__(self, fact_view: object) -> None:
        self.fact_view = fact_view
        self.calls: list[tuple[str, object]] = []

    def capture_maturity_facts(self, target, **kwargs):
        self.calls.append(("capture", (target, kwargs)))
        return SimpleNamespace(invoked=True)

    def validated_fact_view(self, function_ea, provider_level):
        self.calls.append(("view", (function_ea, provider_level)))
        return self.fact_view


def test_recipe_analysis_builds_read_only_preflight_facts_from_live_capture():
    observation = SimpleNamespace(
        kind="role.dispatcher",
        payload=contract_evidence_payload("branch_targets"),
    )
    fact_view = SimpleNamespace(active_observations=(observation,))
    runtime = _ReconRuntime(fact_view)
    target = object()
    provider_phase = SimpleNamespace(provider_level=5)

    facts = collect_recipe_preflight_facts(
        runtime,
        function_ea=0x401000,
        target=target,
        provider_phase=provider_phase,
    )

    assert facts.graph is target
    assert facts.has_analysis("domtree")
    assert facts.has_fact("role.dispatcher")
    assert facts.has_evidence("ir.branch_target")
    assert runtime.calls == [
        (
            "capture",
            (
                target,
                {
                    "func_ea": 0x401000,
                    "provider_phase": provider_phase,
                    "phase": "recipe_preflight",
                },
            ),
        ),
        ("view", (0x401000, 5)),
    ]


def test_recipe_analysis_requires_the_mutation_free_recon_runtime():
    try:
        collect_recipe_preflight_facts(
            None,
            function_ea=0x401000,
            target=object(),
            provider_phase=SimpleNamespace(provider_level=5),
        )
    except RuntimeError as exc:
        assert "Recon runtime" in str(exc)
    else:
        raise AssertionError("missing recon runtime must block recipe analysis")
