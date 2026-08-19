from __future__ import annotations

from types import SimpleNamespace

from d810.hexrays.hooks.safe_point_coordinator import (
    HexRaysSafePointCoordinator,
    SafePointDisposition,
    SafePointKey,
)


def _key(
    *,
    session_id: str = "session-a",
    function_ea: int = 0x401000,
    mba: object | None = None,
    maturity: int = 6,
    generation: int = 1,
    stage_id: str = "d810.pass_pipeline",
) -> SafePointKey:
    return SafePointKey.from_mba(
        session_id=session_id,
        function_ea=function_ea,
        mba=mba if mba is not None else SimpleNamespace(),
        maturity=maturity,
        generation=generation,
        stage_id=stage_id,
    )


def test_key_contains_all_native_epoch_identity_components() -> None:
    mba = SimpleNamespace()
    key = _key(mba=mba)

    assert key.session_id == "session-a"
    assert key.function_ea == 0x401000
    assert key.mba_identity == id(mba)
    assert key.maturity == 6
    assert key.generation == 1
    assert key.stage_id == "d810.pass_pipeline"
    assert key.mba_id == id(mba)
    assert key.native_generation == 1


def test_same_key_is_claimed_once() -> None:
    coordinator = HexRaysSafePointCoordinator()
    key = _key()
    calls: list[str] = []

    first = coordinator.run(key, lambda: calls.append("first") or 0)
    second = coordinator.run(key, lambda: calls.append("second") or 1)

    assert first.disposition is SafePointDisposition.ABSTAINED
    assert first.claimed is True
    assert second.disposition is SafePointDisposition.ABSTAINED
    assert second.claimed is False
    assert calls == ["first"]


def test_new_generation_maturity_mba_or_stage_can_be_claimed() -> None:
    coordinator = HexRaysSafePointCoordinator()
    mba_a = SimpleNamespace()
    mba_b = SimpleNamespace()

    results = [
        coordinator.run(_key(mba=mba_a), lambda: 0),
        coordinator.run(_key(mba=mba_a, generation=2), lambda: 0),
        coordinator.run(_key(mba=mba_a, maturity=7), lambda: 0),
        coordinator.run(_key(mba=mba_b), lambda: 0),
        coordinator.run(_key(mba=mba_a, stage_id="other-stage"), lambda: 0),
    ]

    assert all(result.claimed for result in results)


def test_mutation_disposition_requires_stale_pointer_barrier() -> None:
    coordinator = HexRaysSafePointCoordinator()
    result = coordinator.run(_key(), lambda: 2)

    assert result.disposition is SafePointDisposition.MUTATED
    assert result.mutation_count == 2
    assert result.requires_stale_pointer_barrier is True


def test_analysis_only_result_allows_hosted_lane_to_continue() -> None:
    coordinator = HexRaysSafePointCoordinator()
    result = coordinator.run(
        _key(),
        lambda: SimpleNamespace(
            applied_count=0,
            facts_published=True,
        ),
    )

    assert result.disposition is SafePointDisposition.ANALYSIS_ONLY
    assert result.mutation_count == 0
    assert result.allows_hosted_lane is True


def test_reset_allows_current_key_to_be_claimed_again() -> None:
    coordinator = HexRaysSafePointCoordinator()
    key = _key()

    coordinator.run(key, lambda: 0)
    coordinator.reset()
    result = coordinator.run(key, lambda: 0)

    assert result.claimed is True
