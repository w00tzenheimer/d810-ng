"""Runtime-shape contract for the first actual GENERATED optinsn callback."""

from __future__ import annotations

from types import SimpleNamespace

import ida_hexrays
import pytest

from d810.core.decompilation_session import DecompilationEvent
from d810.hexrays.hooks.optinsn_adapter import InstructionOptimizerManager


class _GeneratedLifecycle:
    def __init__(
        self,
        *,
        native_preanalysis_depth: int = 0,
        missing_port: str | None = None,
    ) -> None:
        self.session = SimpleNamespace(
            native_preanalysis_depth=native_preanalysis_depth,
        )
        self.missing_port = missing_port
        self.emitted = False
        self.calls: list[tuple[object, ...]] = []
        self.identity_index = object()
        self.mutation_gateway = object()
        self.materializer = object()

    def current_session(self, function_ea: int):
        self.calls.append(("session", function_ea))
        if self.missing_port == "session":
            return None
        return self.session

    def generated_ready_was_emitted(self, *, function_ea: int) -> bool:
        self.calls.append(("already-emitted", function_ea))
        return self.emitted

    def mark_generated_ready_emitted(
        self,
        *,
        function_ea: int,
        microcode_modified: bool,
    ) -> None:
        self.calls.append(("mark-emitted", function_ea, microcode_modified))
        self.emitted = True

    def build_current_mba_identity_index(self, *, function_ea: int, mba: object):
        self.calls.append(("index", function_ea, mba))
        if self.missing_port == "identity_index":
            return None
        return self.identity_index

    def new_current_mba_mutation_gateway(
        self,
        *,
        function_ea: int,
        maturity: int,
    ):
        self.calls.append(("gateway", function_ea, maturity))
        if self.missing_port == "mutation_gateway":
            return None
        return self.mutation_gateway

    def new_semantic_native_body_materializer(
        self,
        *,
        function_ea: int,
        mba: object,
    ):
        self.calls.append(("materializer", function_ea, mba))
        if self.missing_port == "materializer":
            return None
        return self.materializer


class _Emitter:
    def __init__(self, *, modified: bool) -> None:
        self.modified = modified
        self.events: list[tuple[object, dict[str, object]]] = []

    def emit(self, event: object, *args: object, **kwargs: object) -> None:
        assert not args
        self.events.append((event, kwargs))
        decision = kwargs["decision"]
        assert isinstance(decision, dict)
        decision["microcode_modified"] = self.modified


def _manager(
    lifecycle: _GeneratedLifecycle,
    emitter: _Emitter,
) -> InstructionOptimizerManager:
    manager = InstructionOptimizerManager.__new__(InstructionOptimizerManager)
    manager._decompilation_lifecycle = lifecycle
    manager.event_emitter = emitter
    manager.current_maturity = ida_hexrays.MMAT_GENERATED
    manager.current_blk_serial = None
    return manager


def _mba(maturity: int) -> SimpleNamespace:
    def _forbidden_build_graph() -> None:
        raise AssertionError("actual GENERATED publication must stay graph-free")

    return SimpleNamespace(
        entry_ea=0x40A560,
        maturity=maturity,
        qty=9,
        build_graph=_forbidden_build_graph,
    )


def _invoke(
    manager: InstructionOptimizerManager,
    mba: SimpleNamespace,
) -> bool:
    manager.current_maturity = mba.maturity
    block = SimpleNamespace(mba=mba, serial=7, start=0x40A5F0)
    instruction = SimpleNamespace(ea=0x40A5F0, opcode=ida_hexrays.m_mov)
    return manager.log_info_on_input(block, instruction)


def test_actual_generated_callback_emits_complete_live_ports_and_returns_modified() -> (
    None
):
    lifecycle = _GeneratedLifecycle()
    emitter = _Emitter(modified=True)
    manager = _manager(lifecycle, emitter)
    mba = _mba(ida_hexrays.MMAT_GENERATED)

    assert _invoke(manager, mba)
    assert len(emitter.events) == 1
    event, payload = emitter.events[0]
    assert event is DecompilationEvent.HEXRAYS_GENERATED_READY
    assert payload["function_ea"] == 0x40A560
    assert payload["mba"] is mba
    assert payload["decision"] == {
        "request_redo": False,
        "session": lifecycle.session,
        "identity_index": lifecycle.identity_index,
        "mutation_gateway": lifecycle.mutation_gateway,
        "semantic_native_body_materializer": lifecycle.materializer,
        "microcode_modified": True,
    }
    assert lifecycle.calls[-1] == ("mark-emitted", 0x40A560, True)

    assert not _invoke(manager, mba)
    assert len(emitter.events) == 1


def test_zero_maturity_callback_does_not_claim_actual_generated() -> None:
    lifecycle = _GeneratedLifecycle()
    emitter = _Emitter(modified=True)
    manager = _manager(lifecycle, emitter)

    assert not _invoke(manager, _mba(ida_hexrays.MMAT_ZERO))
    assert emitter.events == []
    assert lifecycle.calls == []


def test_native_preanalysis_recursion_cannot_publish_generated_fragment() -> None:
    lifecycle = _GeneratedLifecycle(native_preanalysis_depth=1)
    emitter = _Emitter(modified=True)
    manager = _manager(lifecycle, emitter)

    assert not _invoke(manager, _mba(ida_hexrays.MMAT_GENERATED))
    assert emitter.events == []
    assert lifecycle.calls == [("session", 0x40A560)]


@pytest.mark.parametrize(
    "missing_port",
    ("session", "identity_index", "mutation_gateway", "materializer"),
)
def test_generated_publication_requires_every_manager_owned_live_port(
    missing_port: str,
) -> None:
    lifecycle = _GeneratedLifecycle(missing_port=missing_port)
    emitter = _Emitter(modified=True)
    manager = _manager(lifecycle, emitter)

    assert not _invoke(manager, _mba(ida_hexrays.MMAT_GENERATED))
    assert emitter.events == []
    assert not lifecycle.emitted
    assert lifecycle.calls
