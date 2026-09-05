from __future__ import annotations

from types import SimpleNamespace

import pytest

from d810.hexrays.hooks.safe_point_coordinator import (
    HexRaysSafePointCoordinator,
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
        lambda: calls.append("first") or 0,
    )
    second = coordinator.run(
        _key(mba=_SwigProxy(0x7F0000001000)),
        lambda: calls.append("second") or 0,
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
