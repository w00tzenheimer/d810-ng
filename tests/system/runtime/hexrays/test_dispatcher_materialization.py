"""Runtime contracts for coordinator-owned dispatcher mutation batches."""

from __future__ import annotations

from types import SimpleNamespace

from d810.hexrays.mutation import dispatcher_materialization as materialization


def test_scheduled_dispatcher_modifications_use_a_gateway_transaction(
    monkeypatch,
) -> None:
    transaction = object()
    gateway = SimpleNamespace(new_transaction=lambda: transaction)
    observed: dict[str, object] = {}

    class _Modifier:
        verify_failed = False

        def __init__(self, mba, *, mutation_gateway) -> None:
            observed["mba"] = mba
            observed["mutation_gateway"] = mutation_gateway
            self.modifications = []

        def apply(self, **kwargs) -> int:
            observed["apply"] = kwargs
            return len(self.modifications)

    monkeypatch.setattr(materialization, "DeferredGraphModifier", _Modifier)
    mba = object()
    changes = (object(), object())

    result = materialization.apply_scheduled_deferred_modifications(
        mba=mba,
        mutation_gateway=gateway,
        modifications=changes,
        verify_each_mod=True,
        rollback_on_verify_failure=True,
        continue_on_verify_failure=False,
    )

    assert observed["mba"] is mba
    assert observed["mutation_gateway"] is transaction
    assert observed["apply"] == {
        "run_optimize_local": True,
        "run_deep_cleaning": False,
        "verify_each_mod": True,
        "rollback_on_verify_failure": True,
        "continue_on_verify_failure": False,
    }
    assert result.applied_count == 2
    assert not result.verify_failed
