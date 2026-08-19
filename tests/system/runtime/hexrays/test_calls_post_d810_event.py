"""Runtime contract for the post-D810 CALLS observation seam."""

from __future__ import annotations

from types import SimpleNamespace
from pathlib import Path

import ida_hexrays
import pytest

from d810.core.decompilation_session import DecompilationEvent
from d810.hexrays.hooks.optblock_adapter import BlockOptimizerManager


class _Emitter:
    def __init__(self) -> None:
        self.events: list[tuple[object, tuple[object, ...]]] = []

    def emit(self, event, *args) -> None:
        self.events.append((event, args))


class _Lifecycle:
    def __init__(self, generation: int = 3) -> None:
        self.generation = int(generation)

    def current_mba_generation(self, *, function_ea: int) -> int:
        assert int(function_ea) == 0x401000
        return self.generation


def _manager(*, maturity: int, generation: int = 3):
    manager = object.__new__(BlockOptimizerManager)
    manager.event_emitter = _Emitter()
    manager._decompilation_lifecycle = _Lifecycle(generation)
    manager.optimize = lambda _blk: 0
    mba = SimpleNamespace(
        entry_ea=0x401000,
        maturity=int(maturity),
    )
    block = SimpleNamespace(mba=mba)
    return manager, block, mba


def test_calls_post_d810_emits_once_for_one_mba_generation() -> None:
    manager, block, mba = _manager(maturity=ida_hexrays.MMAT_CALLS)

    assert manager._optimize_block_and_emit(block) == 0
    assert manager._optimize_block_and_emit(block) == 0

    assert manager.event_emitter.events == [
        (
            DecompilationEvent.HEXRAYS_CALLS_POST_D810,
            (mba, ida_hexrays.MMAT_CALLS),
        )
    ]
    assert manager._calls_post_d810_last_emitted == (
        0x401000,
        3,
        ida_hexrays.MMAT_CALLS,
    )


def test_calls_post_d810_emits_again_for_a_new_mba_generation() -> None:
    manager, block, mba = _manager(maturity=ida_hexrays.MMAT_CALLS)

    manager._optimize_block_and_emit(block)
    manager._decompilation_lifecycle.generation = 4
    manager._optimize_block_and_emit(block)

    assert [event for event, _args in manager.event_emitter.events] == [
        DecompilationEvent.HEXRAYS_CALLS_POST_D810,
        DecompilationEvent.HEXRAYS_CALLS_POST_D810,
    ]
    assert manager._calls_post_d810_last_emitted == (
        0x401000,
        4,
        ida_hexrays.MMAT_CALLS,
    )


@pytest.mark.parametrize(
    "maturity",
    (
        ida_hexrays.MMAT_PREOPTIMIZED,
        ida_hexrays.MMAT_LOCOPT,
        ida_hexrays.MMAT_GLBOPT1,
        ida_hexrays.MMAT_GLBOPT2,
    ),
)
def test_calls_post_d810_rejects_other_live_maturities(maturity: int) -> None:
    manager, block, _mba = _manager(maturity=maturity)

    manager._optimize_block_and_emit(block)

    assert manager.event_emitter.events == []


def test_calls_post_d810_does_not_emit_after_optimize_exception() -> None:
    manager, block, _mba = _manager(maturity=ida_hexrays.MMAT_CALLS)

    def fail(_blk):
        raise RuntimeError("optimizer failed")

    manager.optimize = fail

    with pytest.raises(RuntimeError, match="optimizer failed"):
        manager._optimize_block_and_emit(block)

    assert manager.event_emitter.events == []


@pytest.mark.parametrize("lifecycle", (None, SimpleNamespace()))
def test_calls_post_d810_abstains_without_a_native_bound_generation(
    lifecycle,
) -> None:
    manager, block, _mba = _manager(maturity=ida_hexrays.MMAT_CALLS)
    if lifecycle is not None:
        lifecycle.current_mba_generation = lambda *, function_ea: 0
    manager._decompilation_lifecycle = lifecycle

    manager._optimize_block_and_emit(block)

    assert manager.event_emitter.events == []
    assert getattr(manager, "_calls_post_d810_last_emitted", None) is None


def test_event_key_is_distinct_from_legacy_post_d810_capture() -> None:
    assert DecompilationEvent.HEXRAYS_CALLS_POST_D810 is not (
        DecompilationEvent.POST_D810_CAPTURE
    )


def test_global_const_observer_is_wired_only_to_calls_post_d810() -> None:
    manager_source = (
        Path(__file__).resolve().parents[4] / "src/d810/manager/manager.py"
    ).read_text(encoding="utf-8")
    observer = "self._ensure_post_d810_runtime().observe_global_const_types"
    assert (
        "DecompilationEvent.POST_D810_CAPTURE,\n"
        f"            {observer},"
    ) not in manager_source
    assert (
        "DecompilationEvent.HEXRAYS_CALLS_POST_D810,\n"
        f"            {observer},"
    ) in manager_source
