from __future__ import annotations

from types import SimpleNamespace

from d810.core.execution_scope import ExecutionScopeService


def test_apply_hints_replaces_prior_function_state() -> None:
    service = ExecutionScopeService()
    first = service.apply_hints(
        SimpleNamespace(
            func_ea=0x1000,
            recommended_inferences=(),
            suppress_stages=("first",),
        )
    )
    second = service.apply_hints(
        SimpleNamespace(
            func_ea=0x1000,
            recommended_inferences=(),
            suppress_stages=(),
        )
    )

    assert first.stages_suppressed == ("first",)
    assert second.stages_suppressed == ()
    assert second.cache_invalidated is True
