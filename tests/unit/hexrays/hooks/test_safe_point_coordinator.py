from __future__ import annotations

from types import SimpleNamespace

import pytest

from d810.hexrays.hooks.safe_point_coordinator import (
    HexRaysSafePointCoordinator,
    OwnedStageOutcome,
    SafePointDisposition,
    SafePointKey,
)
from d810.hexrays.ir.native_identity import (
    NativeIdentityKind,
    native_object_identity,
)


class _SwigProxy:
    """One SWIG proxy over a fixed C++ address, as ``mblock_t.mba`` returns."""

    def __init__(self, pointer: int) -> None:
        self.this = pointer


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
    assert key.mba_identity == native_object_identity(mba)
    assert key.maturity == 6
    assert key.generation == 1
    assert key.stage_id == "d810.pass_pipeline"
    assert key.mba_id == key.mba_identity
    assert key.native_generation == 1


def test_key_is_not_the_python_id_of_the_proxy() -> None:
    """``id`` names the wrapper; the key must name the ``mba_t``."""

    mba = _SwigProxy(0x7F0000001000)
    key = _key(mba=mba)

    assert key.mba_identity.kind is NativeIdentityKind.NATIVE_POINTER
    assert key.mba_identity.value == 0x7F0000001000
    assert key.mba_identity.value != id(mba)


def test_two_proxies_for_one_mba_share_one_safe_point_key() -> None:
    first = _key(mba=_SwigProxy(0x7F0000001000))
    second = _key(mba=_SwigProxy(0x7F0000001000))

    assert first == second
    assert hash(first) == hash(second)


def test_two_proxies_for_one_mba_are_claimed_once() -> None:
    coordinator = HexRaysSafePointCoordinator()
    calls: list[str] = []

    first = coordinator.run(
        _key(mba=_SwigProxy(0x7F0000001000)),
        lambda: calls.append("first") or OwnedStageOutcome.abstained(),
    )
    second = coordinator.run(
        _key(mba=_SwigProxy(0x7F0000001000)),
        lambda: calls.append("second") or OwnedStageOutcome.abstained(),
    )

    assert first.claimed is True
    assert second.claimed is False
    assert calls == ["first"]


def test_distinct_native_pointers_are_distinct_keys() -> None:
    first = _key(mba=_SwigProxy(0x7F0000001000))
    second = _key(mba=_SwigProxy(0x7F0000002000))

    assert first != second


def test_key_rejects_a_raw_integer_identity() -> None:
    with pytest.raises(TypeError):
        SafePointKey(
            session_id="session-a",
            function_ea=0x401000,
            mba_identity=0x7F0000001000,  # type: ignore[arg-type]
            maturity=6,
            generation=1,
            stage_id="d810.pass_pipeline",
        )


def test_same_key_is_claimed_once() -> None:
    coordinator = HexRaysSafePointCoordinator()
    key = _key()
    calls: list[str] = []

    first = coordinator.run(
        key, lambda: calls.append("first") or OwnedStageOutcome.abstained()
    )
    second = coordinator.run(
        key, lambda: calls.append("second") or OwnedStageOutcome.mutated(1)
    )

    assert first.disposition is SafePointDisposition.ABSTAINED
    assert first.claimed is True
    assert second.disposition is SafePointDisposition.ABSTAINED
    assert second.claimed is False
    assert calls == ["first"]


def test_new_generation_maturity_mba_or_stage_can_be_claimed() -> None:
    coordinator = HexRaysSafePointCoordinator()
    mba_a = SimpleNamespace()
    mba_b = SimpleNamespace()

    abstain = OwnedStageOutcome.abstained
    results = [
        coordinator.run(_key(mba=mba_a), abstain),
        coordinator.run(_key(mba=mba_a, generation=2), abstain),
        coordinator.run(_key(mba=mba_a, maturity=7), abstain),
        coordinator.run(_key(mba=mba_b), abstain),
        coordinator.run(_key(mba=mba_a, stage_id="other-stage"), abstain),
    ]

    assert all(result.claimed for result in results)


def test_mutation_disposition_requires_stale_pointer_barrier() -> None:
    coordinator = HexRaysSafePointCoordinator()
    result = coordinator.run(_key(), lambda: OwnedStageOutcome.mutated(2))

    assert result.disposition is SafePointDisposition.MUTATED
    assert result.mutation_count == 2
    assert result.requires_stale_pointer_barrier is True


def test_analysis_only_result_allows_hosted_lane_to_continue() -> None:
    coordinator = HexRaysSafePointCoordinator()
    result = coordinator.run(_key(), OwnedStageOutcome.analysis_only)

    assert result.disposition is SafePointDisposition.ANALYSIS_ONLY
    assert result.mutation_count == 0
    assert result.allows_hosted_lane is True


def test_reset_allows_current_key_to_be_claimed_again() -> None:
    coordinator = HexRaysSafePointCoordinator()
    key = _key()

    coordinator.run(key, OwnedStageOutcome.abstained)
    coordinator.reset()
    result = coordinator.run(key, OwnedStageOutcome.abstained)

    assert result.claimed is True


@pytest.mark.parametrize(
    "value",
    [
        0,
        1,
        True,
        None,
        "mutated",
        SimpleNamespace(applied_count=3),
        SimpleNamespace(mutations=1),
        SimpleNamespace(total=2),
        SimpleNamespace(facts_published=True),
        {"applied_count": 4},
        SafePointDisposition.MUTATED,
    ],
)
def test_untyped_stage_outcome_is_rejected(value) -> None:
    """An unknown outcome must fail closed, never read as no-mutation."""

    coordinator = HexRaysSafePointCoordinator()

    with pytest.raises(TypeError):
        coordinator.run(_key(), lambda: value)


def test_rejected_outcome_still_retains_the_claim() -> None:
    """A failing callback cannot retry the same native epoch."""

    coordinator = HexRaysSafePointCoordinator()
    key = _key()

    with pytest.raises(TypeError):
        coordinator.run(key, lambda: 1)

    assert coordinator.claim(key) is False


def test_failed_claim_cannot_be_read_as_a_successful_abstention() -> None:
    coordinator = HexRaysSafePointCoordinator()
    key = _key()
    assert coordinator.has_failed_claims is False
    with pytest.raises(TypeError):
        coordinator.run(key, lambda: None)
    assert coordinator.has_failed_claims is True

    with pytest.raises(RuntimeError, match="failed"):
        coordinator.require_usable(key)
    with pytest.raises(RuntimeError, match="failed"):
        coordinator.run(key, OwnedStageOutcome.abstained)

    coordinator.reset()
    assert coordinator.has_failed_claims is False
    coordinator.require_usable(key)
    assert coordinator.run(key, OwnedStageOutcome.abstained).claimed


@pytest.mark.parametrize("changed", ["session_id", "mba", "maturity", "generation"])
def test_failed_claim_is_scoped_to_its_native_epoch(changed) -> None:
    coordinator = HexRaysSafePointCoordinator()
    mba = SimpleNamespace(this=0x1000)
    kwargs = dict(session_id="s", mba=mba, maturity=5, generation=0)
    failed_key = _key(**kwargs)
    with pytest.raises(TypeError):
        coordinator.run(failed_key, lambda: None)

    kwargs[changed] = {
        "session_id": "new-session",
        "mba": SimpleNamespace(this=0x2000),
        "maturity": 6,
        "generation": 1,
    }[changed]
    new_key = _key(**kwargs)
    coordinator.require_usable(new_key)
    assert coordinator.run(new_key, OwnedStageOutcome.abstained).claimed


def test_owned_stage_outcome_from_applied_count() -> None:
    assert OwnedStageOutcome.from_applied_count(0) == OwnedStageOutcome.abstained()
    assert OwnedStageOutcome.from_applied_count(3) == OwnedStageOutcome.mutated(3)
    assert (
        OwnedStageOutcome.from_applied_count(0, facts_published=True)
        == OwnedStageOutcome.analysis_only()
    )


def test_owned_stage_outcome_rejects_inconsistent_counts() -> None:
    with pytest.raises(ValueError):
        OwnedStageOutcome(
            disposition=SafePointDisposition.MUTATED,
            mutation_count=0,
        )
    with pytest.raises(ValueError):
        OwnedStageOutcome(
            disposition=SafePointDisposition.ANALYSIS_ONLY,
            mutation_count=1,
        )
    with pytest.raises(ValueError):
        OwnedStageOutcome.from_applied_count(-1)
    with pytest.raises(TypeError):
        OwnedStageOutcome(disposition="mutated", mutation_count=1)  # type: ignore[arg-type]


def test_owned_stage_outcome_rejects_a_boolean_count() -> None:
    with pytest.raises(TypeError):
        OwnedStageOutcome.from_applied_count(True)  # type: ignore[arg-type]
