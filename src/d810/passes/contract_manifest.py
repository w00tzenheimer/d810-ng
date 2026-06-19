"""Diagnostic manifests for native pass contracts."""
from __future__ import annotations

from collections.abc import Iterable

from d810.passes.pass_pipeline import PassSpec


def pass_contract_manifest(spec: PassSpec) -> dict[str, object]:
    """Render one ``PassSpec`` using the direct native contract YAML shape."""
    contract = spec.contract.to_dict()
    return {
        "pass": spec.pass_id,
        "scope": contract["scope"],
        "maturity": contract["maturity"],
        "requires": contract["requires"],
        "outputs": contract["outputs"],
        "preserves": contract["preserves"],
        "invalidates": contract["invalidates"],
        "safety": contract["safety"],
        "runtime": {
            "granularity": spec.granularity.value,
            "requirements": {
                "required": sorted(spec.requirements.required),
            },
            "analyses": {
                "required": sorted(spec.analyses.required),
                "provided": sorted(spec.analyses.provided),
            },
            "preservation": {
                "all_preserved": spec.preservation.all_preserved,
                "kept": sorted(spec.preservation.kept),
            },
            "scheduler_policy": spec.scheduler_policy.value,
            "backend_route": spec.backend_route.value,
            "safety_policy": {
                "name": spec.safety_policy.name,
                "golden_required": spec.safety_policy.golden_required,
            },
        },
    }


def pipeline_contract_manifest(
    specs: Iterable[PassSpec],
) -> tuple[dict[str, object], ...]:
    """Render a pass pipeline as ordered native contract manifest items."""
    return tuple(pass_contract_manifest(spec) for spec in specs)
