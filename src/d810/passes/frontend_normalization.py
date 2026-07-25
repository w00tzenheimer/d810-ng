"""Generic early pass tier for faithful frontend normalization."""

from __future__ import annotations

from d810.analyses.control_flow.frontend_normalization import (
    FrontendNormalizationEvidence,
    plan_detached_semantic_closure_import,
)
from d810.capabilities.frontend_normalization import (
    FrontendNormalizationEvidenceCapability,
)
from d810.capabilities.semantic_routes import (
    SemanticRouteReferenceOracleCapability,
)
from d810.core.semantic_route_oracle import ReferenceRouteOracleSelection
from d810.ir.maturity import IRMaturity
from d810.passes.pass_pipeline import (
    AnalysisContract,
    BackendRoute,
    MaturityRange,
    PassContract,
    PassOutputs,
    PassPreserves,
    PassRequires,
    PassResult,
    PassScope,
    PassSpec,
    PreservedAnalyses,
    default,
    no_caps,
)
from d810.transforms.frontend_normalization import (
    plan_frontend_normalization_generation,
)


FRONTEND_NORMALIZATION_EVIDENCE = "frontend_normalization_evidence"
DETACHED_SEMANTIC_CLOSURE_IMPORT = "detached_semantic_closure_import"
FRONTEND_NORMALIZATION_GENERATION_PLAN = "frontend_normalization_generation_plan"
NATIVE_INDIRECT_TRANSFER_EVIDENCE = "ir.branch_target"

_EARLY_MATURITY = MaturityRange(
    min=IRMaturity.CANONICAL,
    max=IRMaturity.CANONICAL,
    preferred=IRMaturity.CANONICAL,
)


def _contract(
    *,
    requires_analyses: frozenset[str] = frozenset(),
    outputs_evidence: frozenset[str] = frozenset(),
    preserves_analyses: frozenset[str] = frozenset(),
) -> PassContract:
    return PassContract(
        scope=PassScope.FUNCTION,
        maturity=_EARLY_MATURITY,
        requires=PassRequires(analyses=requires_analyses),
        outputs=PassOutputs(evidence=outputs_evidence),
        preserves=PassPreserves(analyses=preserves_analyses),
    )


class ResolveNativeIndirectTransfers:
    """Publish one provider-neutral generation of native transfer evidence."""

    name = "resolve_native_indirect_transfers"

    def run(self, ctx) -> PassResult:
        provider = ctx.capabilities.optional(FrontendNormalizationEvidenceCapability)
        if provider is None:
            return PassResult()
        evidence = provider.evidence_for(int(ctx.source.func_ea))
        if evidence is None:
            return PassResult()
        if not isinstance(evidence, FrontendNormalizationEvidence):
            raise TypeError(
                "frontend normalization capability returned non-portable evidence"
            )
        return PassResult(
            analysis_outputs={FRONTEND_NORMALIZATION_EVIDENCE: evidence},
            evidence_outputs={NATIVE_INDIRECT_TRANSFER_EVIDENCE: evidence},
        )


class ImportDetachedSemanticClosure:
    """Derive the complete portable body-availability request.

    The request is a durable planning product.  The following gateway slice
    consumes it to stage native body blocks and root publication in one
    FragmentPlan transaction; this pass does not expose append-only live blocks.
    """

    name = "import_detached_semantic_closure"

    def run(self, ctx) -> PassResult:
        evidence = ctx.facts.get_analysis(
            FRONTEND_NORMALIZATION_EVIDENCE,
            None,
        )
        if evidence is None:
            return PassResult()
        if not isinstance(evidence, FrontendNormalizationEvidence):
            raise TypeError("frontend normalization analysis has the wrong type")
        oracle_provider = ctx.capabilities.optional(
            SemanticRouteReferenceOracleCapability
        )
        selection = (
            None
            if oracle_provider is None
            else oracle_provider.reference_oracle_scope_for(
                int(ctx.graph.func_ea),
                evidence.native_key,
            )
        )
        if selection is not None and not isinstance(
            selection,
            ReferenceRouteOracleSelection,
        ):
            raise TypeError(
                "semantic route reference oracle returned an invalid fragment scope"
            )
        request = plan_detached_semantic_closure_import(
            ctx.graph,
            evidence,
            reference_routes=(() if selection is None else selection.routes),
        )
        if request is None:
            return PassResult()
        return PassResult(
            analysis_outputs={DETACHED_SEMANTIC_CLOSURE_IMPORT: request},
        )


class NormalizeComputedBranch:
    """Publish a complete direct or two-arm branch normalization fragment."""

    name = "normalize_computed_branch"

    def run(self, ctx) -> PassResult:
        evidence = ctx.facts.get_analysis(
            FRONTEND_NORMALIZATION_EVIDENCE,
            None,
        )
        if evidence is None:
            return PassResult()
        if not isinstance(evidence, FrontendNormalizationEvidence):
            raise TypeError("frontend normalization analysis has the wrong type")
        import_request = ctx.facts.get_analysis(
            DETACHED_SEMANTIC_CLOSURE_IMPORT,
            None,
        )
        generation_plan = plan_frontend_normalization_generation(
            ctx.graph,
            evidence,
            detached_import_request=import_request,
        )
        if generation_plan is None:
            return PassResult()
        return PassResult(
            fragment_plan=generation_plan.work_item_plan,
            preserved=PreservedAnalyses.preserving(
                {
                    FRONTEND_NORMALIZATION_EVIDENCE,
                    DETACHED_SEMANTIC_CLOSURE_IMPORT,
                }
            ),
            analysis_outputs={
                FRONTEND_NORMALIZATION_GENERATION_PLAN: generation_plan,
            },
        )


def standard_frontend_normalization_passes() -> tuple[PassSpec, ...]:
    """Return the generic early normalization tier in semantic order."""
    preserve_frontend_evidence = frozenset(
        {
            FRONTEND_NORMALIZATION_EVIDENCE,
            DETACHED_SEMANTIC_CLOSURE_IMPORT,
        }
    )
    return (
        PassSpec(
            ResolveNativeIndirectTransfers.name,
            ResolveNativeIndirectTransfers,
            no_caps,
            default,
            maturity_gates=frozenset({IRMaturity.CANONICAL}),
            analyses=AnalysisContract(
                provided=frozenset({FRONTEND_NORMALIZATION_EVIDENCE}),
            ),
            backend_route=BackendRoute.ANALYSIS_ONLY,
            contract=_contract(
                outputs_evidence=frozenset({NATIVE_INDIRECT_TRANSFER_EVIDENCE})
            ),
        ),
        PassSpec(
            ImportDetachedSemanticClosure.name,
            ImportDetachedSemanticClosure,
            no_caps,
            default,
            maturity_gates=frozenset({IRMaturity.CANONICAL}),
            analyses=AnalysisContract(
                required=frozenset({FRONTEND_NORMALIZATION_EVIDENCE}),
                provided=frozenset({DETACHED_SEMANTIC_CLOSURE_IMPORT}),
            ),
            backend_route=BackendRoute.ANALYSIS_ONLY,
            contract=_contract(
                requires_analyses=frozenset({FRONTEND_NORMALIZATION_EVIDENCE})
            ),
        ),
        PassSpec(
            NormalizeComputedBranch.name,
            NormalizeComputedBranch,
            no_caps,
            default,
            maturity_gates=frozenset({IRMaturity.CANONICAL}),
            analyses=AnalysisContract(
                required=frozenset({FRONTEND_NORMALIZATION_EVIDENCE}),
                provided=frozenset({FRONTEND_NORMALIZATION_GENERATION_PLAN}),
            ),
            preservation=PreservedAnalyses.preserving(preserve_frontend_evidence),
            backend_route=BackendRoute.FRAGMENT_PUBLICATION,
            contract=_contract(
                requires_analyses=frozenset({FRONTEND_NORMALIZATION_EVIDENCE}),
                preserves_analyses=preserve_frontend_evidence,
            ),
        ),
    )


__all__ = [
    "DETACHED_SEMANTIC_CLOSURE_IMPORT",
    "FRONTEND_NORMALIZATION_EVIDENCE",
    "FRONTEND_NORMALIZATION_GENERATION_PLAN",
    "NATIVE_INDIRECT_TRANSFER_EVIDENCE",
    "ImportDetachedSemanticClosure",
    "NormalizeComputedBranch",
    "ResolveNativeIndirectTransfers",
    "standard_frontend_normalization_passes",
]
