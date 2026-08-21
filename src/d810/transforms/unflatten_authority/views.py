"""Read-only projections from an evaluator-owned safety case.

This module intentionally accepts no graph, plan, projection, or callback.  A
view is a pure tuple projection over the immutable case and its index.
"""

from __future__ import annotations

from dataclasses import dataclass

from . import model


VIEW_GRAPH_TRAVERSALS = 0


@dataclass(frozen=True, slots=True)
class ViewMetrics:
    index_folds: int
    view_graph_traversals: int
    preparation_metrics: model.PreparationBuildMetrics | None = None


def obligation_states(case: model.SemanticSafetyCase) -> tuple[tuple[model.ObligationKey, model.ObligationState], ...]:
    _check_case(case)
    return tuple((cell.key, cell.state) for cell in case.obligation_index.cells)


def failed_obligations(case: model.SemanticSafetyCase) -> tuple[model.FailedObligation, ...]:
    _check_case(case)
    return tuple(
        model.FailedObligation(cell.key, cell.state)
        for cell in case.obligation_index.cells
        if cell.state is not model.ObligationState.SATISFIED
    )


def evidence_ids(case: model.SemanticSafetyCase) -> tuple[str, ...]:
    _check_case(case)
    return tuple(item.evidence_id for item in case.evidence)


def justification_ids(case: model.SemanticSafetyCase) -> tuple[str, ...]:
    _check_case(case)
    return tuple(item.justification_id for item in case.justifications)


def view_metrics(case: model.SemanticSafetyCase, preparation_metrics: model.PreparationBuildMetrics | None = None) -> ViewMetrics:
    _check_case(case)
    if preparation_metrics is not None:
        raise TypeError("views cannot accept unrelated preparation metrics")
    return ViewMetrics(
        index_folds=case.phase_metrics.index_folds,
        view_graph_traversals=case.phase_metrics.view_graph_traversals,
        preparation_metrics=case.phase_metrics.preparation_metrics,
    )


def _check_case(case: model.SemanticSafetyCase) -> None:
    if type(case) is not model.SemanticSafetyCase:
        raise TypeError("view requires SemanticSafetyCase")


# Stable descriptive aliases used by compatibility consumers.
loss_view = failed_obligations
coverage_view = obligation_states
diagnostic_view = evidence_ids


__all__ = [
    "VIEW_GRAPH_TRAVERSALS", "ViewMetrics", "obligation_states",
    "failed_obligations", "evidence_ids", "justification_ids", "view_metrics",
    "loss_view", "coverage_view", "diagnostic_view",
]
