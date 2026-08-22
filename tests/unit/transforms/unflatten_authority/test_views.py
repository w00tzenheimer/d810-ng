"""Graph-free evaluator views."""

from __future__ import annotations

from d810.transforms.unflatten_authority import views


def test_views_export_read_only_case_projections() -> None:
    assert views.VIEW_GRAPH_TRAVERSALS == 0
    assert callable(views.obligation_states)
    assert callable(views.failed_obligations)
    assert callable(views.evidence_ids)
    assert callable(views.exact_effect_loss_view)
    assert views.ExactEffectLossView.__dataclass_params__ is not None
    assert "case" in __import__("inspect").signature(views.exact_effect_loss_view).parameters
