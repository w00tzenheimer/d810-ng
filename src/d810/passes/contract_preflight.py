"""Read-only preflight checks for native pass contracts."""
from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass

from d810.passes.driver import PassContractDiagnostic
from d810.passes.pass_pipeline import PassSpec


@dataclass(frozen=True)
class PassContractPreflightResult:
    """Contract preflight outcome for one pass spec."""

    pass_id: str
    diagnostics: tuple[PassContractDiagnostic, ...] = ()
    satisfied: bool = True
    declared_output_facts: tuple[str, ...] = ()
    declared_output_evidence: tuple[str, ...] = ()


@dataclass(frozen=True)
class PipelineContractPreflightResult:
    """Contract preflight outcome for an ordered pass pipeline."""

    results: tuple[PassContractPreflightResult, ...]
    diagnostics: tuple[PassContractDiagnostic, ...] = ()
    satisfied: bool = True


def _available_names(facts, method_name: str) -> tuple[str, ...]:
    method = getattr(facts, method_name, None)
    if not callable(method):
        return ()
    return tuple(str(name) for name in method())


def _requirement_diagnostic(
    *,
    spec: PassSpec,
    namespace: str,
    missing: Iterable[str],
    facts,
    available_method_name: str,
    extra_available: Iterable[str] = (),
) -> PassContractDiagnostic:
    available = set(_available_names(facts, available_method_name))
    available.update(str(name) for name in extra_available)
    return PassContractDiagnostic(
        pass_id=spec.pass_id,
        namespace=namespace,
        missing=tuple(sorted(str(name) for name in missing)),
        available=tuple(sorted(available)),
    )


def _has_with_overlay(
    facts,
    method_name: str,
    name: str,
    *,
    fact_overlay: frozenset[str],
    evidence_overlay: frozenset[str],
) -> bool:
    if method_name == "has_fact" and name in fact_overlay:
        return True
    if method_name == "has_evidence" and name in evidence_overlay:
        return True
    method = getattr(facts, method_name, None)
    return bool(callable(method) and method(name))


def _diagnose_missing_requirements(
    spec: PassSpec,
    facts,
    *,
    fact_overlay: frozenset[str],
    evidence_overlay: frozenset[str],
) -> tuple[PassContractDiagnostic, ...]:
    contract = spec.contract
    diagnostics: list[PassContractDiagnostic] = []

    if contract.requires.analyses:
        method = getattr(facts, "has_analysis", None)
        if not callable(method):
            diagnostics.append(
                PassContractDiagnostic(
                    pass_id=spec.pass_id,
                    namespace="requires.analyses",
                    missing=tuple(sorted(contract.requires.analyses)),
                    detail="facts view does not support has_analysis",
                )
            )
        else:
            missing = tuple(
                sorted(
                    name
                    for name in contract.requires.analyses
                    if not method(name)
                )
            )
            if missing:
                diagnostics.append(
                    _requirement_diagnostic(
                        spec=spec,
                        namespace="requires.analyses",
                        missing=missing,
                        facts=facts,
                        available_method_name="available_analyses",
                    )
                )

    if contract.requires.facts.required:
        method = getattr(facts, "has_fact", None)
        missing = tuple(
            sorted(
                name
                for name in contract.requires.facts.required
                if not _has_with_overlay(
                    facts,
                    "has_fact",
                    name,
                    fact_overlay=fact_overlay,
                    evidence_overlay=evidence_overlay,
                )
            )
        )
        if missing:
            if not callable(method):
                diagnostics.append(
                    PassContractDiagnostic(
                        pass_id=spec.pass_id,
                        namespace="requires.facts.required",
                        missing=missing,
                        available=tuple(sorted(fact_overlay)),
                        detail="facts view does not support has_fact",
                    )
                )
            else:
                diagnostics.append(
                    _requirement_diagnostic(
                        spec=spec,
                        namespace="requires.facts.required",
                        missing=missing,
                        facts=facts,
                        available_method_name="available_facts",
                        extra_available=fact_overlay,
                    )
                )

    if contract.requires.evidence:
        method = getattr(facts, "has_evidence", None)
        missing = tuple(
            sorted(
                name
                for name in contract.requires.evidence
                if not _has_with_overlay(
                    facts,
                    "has_evidence",
                    name,
                    fact_overlay=fact_overlay,
                    evidence_overlay=evidence_overlay,
                )
            )
        )
        if missing:
            if not callable(method):
                diagnostics.append(
                    PassContractDiagnostic(
                        pass_id=spec.pass_id,
                        namespace="requires.evidence",
                        missing=missing,
                        available=tuple(sorted(evidence_overlay)),
                        detail="facts view does not support has_evidence",
                    )
                )
            else:
                diagnostics.append(
                    _requirement_diagnostic(
                        spec=spec,
                        namespace="requires.evidence",
                        missing=missing,
                        facts=facts,
                        available_method_name="available_evidence",
                        extra_available=evidence_overlay,
                    )
                )

    return tuple(diagnostics)


def preflight_pass_contract(
    spec: PassSpec,
    facts,
    *,
    _declared_fact_overlay: frozenset[str] = frozenset(),
    _declared_evidence_overlay: frozenset[str] = frozenset(),
) -> PassContractPreflightResult:
    """Check one pass contract without constructing or running its pass."""
    diagnostics = _diagnose_missing_requirements(
        spec,
        facts,
        fact_overlay=frozenset(str(name) for name in _declared_fact_overlay),
        evidence_overlay=frozenset(str(name) for name in _declared_evidence_overlay),
    )
    declared_output_facts = tuple(sorted(spec.contract.outputs.facts))
    declared_output_evidence = tuple(sorted(spec.contract.outputs.evidence))
    return PassContractPreflightResult(
        pass_id=spec.pass_id,
        diagnostics=diagnostics,
        satisfied=not diagnostics,
        declared_output_facts=declared_output_facts,
        declared_output_evidence=declared_output_evidence,
    )


def preflight_pipeline_contract(
    specs: Iterable[PassSpec],
    facts,
    *,
    include_declared_outputs: bool = True,
) -> PipelineContractPreflightResult:
    """Check an ordered pipeline without executing pass bodies.

    When ``include_declared_outputs`` is true, declared fact outputs from
    satisfied earlier specs are added to a local overlay for later requirements.
    This is only a static declaration check; it does not prove those passes will
    actually publish the facts at runtime.
    """
    fact_overlay: frozenset[str] = frozenset()
    evidence_overlay: frozenset[str] = frozenset()
    results: list[PassContractPreflightResult] = []
    diagnostics: list[PassContractDiagnostic] = []

    for spec in specs:
        result = preflight_pass_contract(
            spec,
            facts,
            _declared_fact_overlay=fact_overlay,
            _declared_evidence_overlay=evidence_overlay,
        )
        results.append(result)
        diagnostics.extend(result.diagnostics)
        if include_declared_outputs and result.satisfied:
            fact_overlay = fact_overlay | frozenset(result.declared_output_facts)
            evidence_overlay = evidence_overlay | frozenset(
                result.declared_output_evidence
            )

    return PipelineContractPreflightResult(
        results=tuple(results),
        diagnostics=tuple(diagnostics),
        satisfied=not diagnostics,
    )
