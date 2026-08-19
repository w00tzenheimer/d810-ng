from __future__ import annotations

from types import SimpleNamespace

import pytest

from d810.backends.hexrays import global_const_observer as observer_module
from d810.backends.hexrays.global_const_observer import GlobalConstObserver
from d810.passes.constant_simplification_options import ConstantPreparationOptions

pytestmark = pytest.mark.pure_python


class _Instruction:
    def __init__(self, ea: int) -> None:
        self.ea = ea
        self.next: _Instruction | None = None


class _Block:
    def __init__(self, *instructions: _Instruction) -> None:
        self.head = instructions[0] if instructions else None
        for left, right in zip(instructions, instructions[1:]):
            left.next = right


class _Mba:
    def __init__(self, *blocks: _Block, entry_ea: int = 0x401000) -> None:
        self._blocks = blocks
        self.qty = len(blocks)
        self.entry_ea = entry_ea
        self.this = 7

    def get_mblock(self, serial: int) -> _Block:
        return self._blocks[serial]


def _access(instruction: _Instruction) -> SimpleNamespace:
    return SimpleNamespace(
        item_head=0x500000 + instruction.ea,
        item_end=0x500020 + instruction.ea,
        element_size=4,
        element_count=8,
        instruction_ea=instruction.ea,
    )


def _observer(*, enabled: bool = True, discover: bool = True) -> GlobalConstObserver:
    return GlobalConstObserver(
        preparation_options=ConstantPreparationOptions(
            enabled=enabled,
            discover_bounded_tables=discover,
        ),
        database_identity="idb-a",
        calls_maturity=17,
    )


def test_disabled_preparation_does_not_observe_or_queue(monkeypatch) -> None:
    instruction = _Instruction(1)
    calls: list[object] = []
    monkeypatch.setattr(
        observer_module,
        "discover_dynamic_global_table_access",
        lambda value: calls.append(value) or _access(value),
    )
    observer = _observer(enabled=False)

    assert observer.observe(_Mba(_Block(instruction)), 17) is None
    assert calls == []
    assert observer.pending_reason is None


def test_disabled_dynamic_discovery_does_not_observe_or_queue(monkeypatch) -> None:
    instruction = _Instruction(1)
    calls: list[object] = []
    monkeypatch.setattr(
        observer_module,
        "discover_dynamic_global_table_access",
        lambda value: calls.append(value) or _access(value),
    )
    observer = _observer(discover=False)

    observer.observe(_Mba(_Block(instruction)), 17)

    assert calls == []


def test_only_exact_calls_maturity_is_observed(monkeypatch) -> None:
    instruction = _Instruction(1)
    calls: list[object] = []
    monkeypatch.setattr(
        observer_module,
        "discover_dynamic_global_table_access",
        lambda value: calls.append(value) or _access(value),
    )
    observer = _observer()

    observer.observe(_Mba(_Block(instruction)), 18)

    assert calls == []


def test_calls_traversal_is_deterministic_and_queues_exact_accesses(monkeypatch) -> None:
    first = _Instruction(1)
    second = _Instruction(2)
    third = _Instruction(3)
    queued: list[tuple[object, int]] = []
    monkeypatch.setattr(
        observer_module,
        "discover_dynamic_global_table_access",
        lambda value: _access(value),
    )
    monkeypatch.setattr(
        observer_module,
        "annotate_global_table_access",
        lambda access, *, function_ea: queued.append((access, function_ea))
        or SimpleNamespace(changed_count=1),
    )
    observer = _observer()

    observer.observe(_Mba(_Block(first, second), _Block(third)), 17)

    assert [access.instruction_ea for access, _ in queued] == [1, 2, 3]
    assert [function_ea for _, function_ea in queued] == [0x401000] * 3
    assert observer.pending_reason == "next preparation round"


def test_duplicate_event_is_deduplicated_for_same_function_generation(monkeypatch) -> None:
    instruction = _Instruction(1)
    queued: list[object] = []
    monkeypatch.setattr(
        observer_module,
        "discover_dynamic_global_table_access",
        lambda value: _access(value),
    )
    monkeypatch.setattr(
        observer_module,
        "annotate_global_table_access",
        lambda access, *, function_ea: queued.append(access)
        or SimpleNamespace(changed_count=1),
    )
    observer = _observer()
    mba = _Mba(_Block(instruction))

    observer.observe(mba, 17)
    observer.observe(mba, 17)

    assert len(queued) == 1


def test_queue_failure_abstains_without_restart_or_mutation(monkeypatch) -> None:
    instruction = _Instruction(1)
    monkeypatch.setattr(
        observer_module,
        "discover_dynamic_global_table_access",
        lambda value: _access(value),
    )
    monkeypatch.setattr(
        observer_module,
        "annotate_global_table_access",
        lambda access, *, function_ea: (_ for _ in ()).throw(RuntimeError("queue")),
    )
    observer = _observer()

    assert observer.observe(_Mba(_Block(instruction)), 17) is None
    assert observer.pending_reason is None
    assert observer.restart_requested is False
