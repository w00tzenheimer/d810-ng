"""Tests for Hodur-compatible state-machine evidence adapters."""
from __future__ import annotations

from types import SimpleNamespace

from d810.optimizers.microcode.flow.flattening.hodur import state_machine_adapters


class _HandlerMap:
    handler_state_map = {10: 100, 20: 200}
    dispatcher_serial = 5
    dispatcher_blocks = (5, 6)
    state_var_stkoff = 32

    def resolve_target(self, state: int) -> int | None:
        return {100: 10, 200: 20}.get(state)


class _StateDispatcherMap:
    dispatcher_entry_block = 5

    def to_dispatcher_handler_map(self) -> _HandlerMap:
        return _HandlerMap()


def test_detect_switch_table_state_machine_builds_hodur_compatible_model(
    monkeypatch,
) -> None:
    calls: list[object] = []
    state_var = object()

    monkeypatch.setattr(
        state_machine_adapters,
        "analyze_switch_table_dispatcher",
        lambda mba: SimpleNamespace(
            state_dispatcher_map=_StateDispatcherMap(),
            state_var_mop=state_var,
        ),
    )

    def _evaluate_handler_paths(mba, **kwargs):
        calls.append((mba, kwargs))
        if kwargs["entry_serial"] == 10:
            return [SimpleNamespace(final_state=200, exit_block=11)]
        return [SimpleNamespace(final_state=None, exit_block=21)]

    monkeypatch.setattr(
        state_machine_adapters,
        "evaluate_handler_paths",
        _evaluate_handler_paths,
    )

    result = state_machine_adapters.detect_switch_table_state_machine("mba")

    assert result is not None
    assert result.state_dispatcher_map.dispatcher_entry_block == 5
    state_machine = result.state_machine
    assert state_machine.mba == "mba"
    assert state_machine.state_var is state_var
    assert state_machine.state_constants == {100, 200}
    assert sorted(state_machine.handlers) == [100, 200]
    assert len(state_machine.transitions) == 1
    assert state_machine.transitions[0].from_state == 100
    assert state_machine.transitions[0].to_state == 200
    assert state_machine.transitions[0].from_block == 11
    assert [call[1]["entry_serial"] for call in calls] == [10, 20]
