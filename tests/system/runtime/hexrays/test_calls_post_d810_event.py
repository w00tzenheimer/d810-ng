"""Runtime contract for maturity-wide post-D810 CALLS observation."""

from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace

import ida_hexrays

from d810.core.decompilation_session import DecompilationEvent
class _Instruction:
    def __init__(self, ea: int) -> None:
        self.ea = ea
        self.next = None


class _Block:
    def __init__(self, instruction: _Instruction) -> None:
        self.head = instruction


class _Mba:
    def __init__(self, *blocks: _Block, maturity: int) -> None:
        self._blocks = blocks
        self.qty = len(blocks)
        self.entry_ea = 0x401000
        self.maturity = int(maturity)

    def get_mblock(self, serial: int) -> _Block:
        return self._blocks[serial]


def test_global_const_observer_runs_once_after_complete_calls_maturity() -> None:
    """The maturity transition, not the first CALLS block, is the seam."""

    from d810.backends.hexrays.global_const_observer import GlobalConstObserver
    from d810.core.events import EventEmitter
    from d810.manager.post_d810_runtime import HexRaysPostD810Runtime
    from d810.passes.constant_simplification_options import (
        ConstantPreparationOptions,
    )

    discovered: list[int] = []
    queued: list[int] = []
    observer = GlobalConstObserver(
        preparation_options=ConstantPreparationOptions(
            enabled=True,
            discover_bounded_tables=True,
        ),
        database_identity="runtime-test",
        calls_maturity=ida_hexrays.MMAT_CALLS,
        discover=lambda instruction: discovered.append(instruction.ea)
        or SimpleNamespace(instruction_ea=instruction.ea),
        queue=lambda access, *, function_ea: queued.append(
            int(access.instruction_ea)
        )
        or SimpleNamespace(queued_count=1),
        pending_proposals=lambda: (),
    )
    runtime = HexRaysPostD810Runtime(
        preanalysis_runtime=None,
        block_optimizer=SimpleNamespace(),
        global_const_observer=observer,
        mba_generation_provider=lambda function_ea: 7,
    )
    emitter = EventEmitter()
    emitter.on(DecompilationEvent.POST_D810_CAPTURE, runtime.observe_global_const_types)

    # Two blocks represent the complete CALLS callback stream.  No observer
    # callback occurs at either block boundary; the adapter no longer owns a
    # block-local CALLS event.
    mba = _Mba(
        _Block(_Instruction(0x401010)),
        _Block(_Instruction(0x401020)),
        maturity=ida_hexrays.MMAT_CALLS,
    )
    assert discovered == []
    assert queued == []

    # POST_D810_CAPTURE is emitted once when Hex-Rays transitions away from
    # CALLS, after all CALLS blocks have been optimized.
    emitter.emit(DecompilationEvent.POST_D810_CAPTURE, mba, ida_hexrays.MMAT_CALLS)

    assert discovered == [0x401010, 0x401020]
    assert queued == [0x401010, 0x401020]
    assert observer.pending_reason == "next preparation round"


def test_global_const_observer_ignores_non_calls_capture() -> None:
    from d810.backends.hexrays.global_const_observer import GlobalConstObserver
    from d810.core.events import EventEmitter
    from d810.manager.post_d810_runtime import HexRaysPostD810Runtime
    from d810.passes.constant_simplification_options import (
        ConstantPreparationOptions,
    )

    discovered: list[int] = []
    observer = GlobalConstObserver(
        preparation_options=ConstantPreparationOptions(
            enabled=True,
            discover_bounded_tables=True,
        ),
        database_identity="runtime-test",
        calls_maturity=ida_hexrays.MMAT_CALLS,
        discover=lambda instruction: discovered.append(instruction.ea),
        pending_proposals=lambda: (),
    )
    runtime = HexRaysPostD810Runtime(
        preanalysis_runtime=None,
        block_optimizer=SimpleNamespace(),
        global_const_observer=observer,
        mba_generation_provider=lambda function_ea: 7,
    )
    emitter = EventEmitter()
    emitter.on(DecompilationEvent.POST_D810_CAPTURE, runtime.observe_global_const_types)

    mba = _Mba(
        _Block(_Instruction(0x401010)),
        maturity=ida_hexrays.MMAT_LOCOPT,
    )
    emitter.emit(DecompilationEvent.POST_D810_CAPTURE, mba, ida_hexrays.MMAT_LOCOPT)

    assert discovered == []


def test_global_const_observer_is_wired_to_maturity_wide_post_capture() -> None:
    manager_source = (
        Path(__file__).resolve().parents[4] / "src/d810/manager/manager.py"
    ).read_text(encoding="utf-8")
    observer = "self._ensure_post_d810_runtime().observe_global_const_types"
    assert (
        "DecompilationEvent.POST_D810_CAPTURE,\n"
        f"            {observer},"
    ) in manager_source
    assert (
        "DecompilationEvent.HEXRAYS_CALLS_POST_D810,\n"
        f"            {observer},"
    ) not in manager_source

    adapter_source = (
        Path(__file__).resolve().parents[4]
        / "src/d810/hexrays/hooks/optblock_adapter.py"
    ).read_text(encoding="utf-8")
    assert "_emit_calls_post_d810_if_needed" not in adapter_source
    assert "_calls_post_d810_last_emitted" not in adapter_source
