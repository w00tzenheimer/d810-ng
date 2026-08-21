"""Graph-free evaluator views."""

from __future__ import annotations

from d810.transforms.unflatten_authority import views


def test_views_export_read_only_case_projections() -> None:
    assert views.VIEW_GRAPH_TRAVERSALS == 0
    assert callable(views.obligation_states)
    assert callable(views.failed_obligations)
    assert callable(views.evidence_ids)
