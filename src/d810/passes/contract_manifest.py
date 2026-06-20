"""Diagnostic manifests for native pass contracts."""
from __future__ import annotations

from collections.abc import Iterable

from d810.passes.contract_preflight import (
    PassContractPreflightResult,
    PipelineContractPreflightResult,
)
from d810.passes.driver import PassContractDiagnostic
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


def _sorted_strings(values: Iterable[str]) -> list[str]:
    return sorted(str(value) for value in values)


def pass_contract_diagnostic_manifest(
    diagnostic: PassContractDiagnostic,
) -> dict[str, object]:
    """Render one structured contract diagnostic using stable list fields."""
    return {
        "pass": diagnostic.pass_id,
        "namespace": diagnostic.namespace,
        "missing": _sorted_strings(diagnostic.missing),
        "undeclared": _sorted_strings(diagnostic.undeclared),
        "available": _sorted_strings(diagnostic.available),
        "detail": diagnostic.detail,
    }


def pass_contract_preflight_manifest(
    spec: PassSpec,
    result: PassContractPreflightResult,
) -> dict[str, object]:
    """Render a pass contract manifest plus already-computed preflight status."""
    if result.pass_id != spec.pass_id:
        raise ValueError(
            f"preflight result pass_id {result.pass_id!r} does not match "
            f"spec pass_id {spec.pass_id!r}"
        )
    manifest = pass_contract_manifest(spec)
    manifest["preflight"] = {
        "satisfied": result.satisfied,
        "declared_output_facts": _sorted_strings(result.declared_output_facts),
        "declared_output_evidence": _sorted_strings(
            result.declared_output_evidence
        ),
        "diagnostics": [
            pass_contract_diagnostic_manifest(diagnostic)
            for diagnostic in result.diagnostics
        ],
    }
    return manifest


def pipeline_contract_preflight_manifest(
    specs: Iterable[PassSpec],
    result: PipelineContractPreflightResult,
) -> tuple[dict[str, object], ...]:
    """Render ordered pass contract manifests with preflight status attached."""
    specs_tuple = tuple(specs)
    if len(specs_tuple) != len(result.results):
        raise ValueError(
            "pipeline preflight result length does not match spec length: "
            f"{len(result.results)} results for {len(specs_tuple)} specs"
        )
    return tuple(
        pass_contract_preflight_manifest(spec, pass_result)
        for spec, pass_result in zip(specs_tuple, result.results)
    )
