from __future__ import annotations

import contextlib
from types import SimpleNamespace

import pytest

from d810.testing.cases import DeobfuscationCase
from d810.testing.runner import run_deobfuscation_test


class _Cfunc:
    def __init__(self, code: str) -> None:
        self._code = code

    def get_pseudocode(self):
        return self._code


class _State:
    def __init__(self) -> None:
        self.stop_calls = 0
        self.start_calls = 0
        self.stats = SimpleNamespace()
        self.loaded_projects: list[int] = []
        self.project_manager = SimpleNamespace()
        self.current_project = object()
        self.current_ins_rules = [object()]

    def load_project(self, index: int) -> None:
        self.loaded_projects.append(index)

    def stop_d810(self) -> None:
        self.stop_calls += 1

    def start_d810(self) -> None:
        self.start_calls += 1


def test_runner_disables_named_passes_in_the_function_recipe(monkeypatch) -> None:
    from d810.testing import runner

    state = _State()
    draft = SimpleNamespace(
        passes=(
            SimpleNamespace(item_id="item-1-mba", pass_id="mba-solve"),
            SimpleNamespace(item_id="item-2-cfg", pass_id="state-machine-cff"),
        )
    )
    disabled: list[tuple[str, bool]] = []
    state.create_active_workbench_recipe_draft = lambda _ea: draft

    def set_enabled(candidate, item_id, enabled):
        assert candidate is draft
        disabled.append((item_id, enabled))
        return candidate

    state.set_workbench_recipe_pass_enabled = set_enabled

    @contextlib.contextmanager
    def activate(candidate):
        assert candidate is draft
        yield

    state.activate_workbench_recipe = activate
    monkeypatch.setattr(runner, "get_binary_suffix", lambda: ".dll")
    monkeypatch.setattr(runner, "get_func_ea", lambda _name: 0x401000)
    monkeypatch.setattr(
        runner.idaapi,
        "decompile",
        lambda _ea, *, flags: _Cfunc("after"),
    )

    run_deobfuscation_test(
        DeobfuscationCase(
            function="call-preservation",
            project="",
            disabled_pass_ids=("mba-solve",),
            must_change=False,
            check_stats=False,
        ),
        _state_context(state),
        lambda pseudocode: str(pseudocode),
    )

    assert disabled == [("item-1-mba", False)]


def _state_context(state: _State):
    @contextlib.contextmanager
    def enter():
        yield state

    return enter


@pytest.mark.parametrize(
    ("case", "codes", "expected_decompiles", "expected_stops"),
    (
        (
            DeobfuscationCase(
                function="after_only",
                project="",
                must_change=False,
                check_stats=False,
                deobfuscated_contains=["after"],
            ),
            ("after",),
            1,
            0,
        ),
        (
            DeobfuscationCase(
                function="must_change",
                project="",
                must_change=True,
                check_stats=False,
            ),
            ("before", "after"),
            2,
            1,
        ),
    ),
)
def test_runner_only_decompiles_a_baseline_when_the_case_consumes_it(
    monkeypatch,
    case,
    codes,
    expected_decompiles,
    expected_stops,
) -> None:
    from d810.testing import runner

    state = _State()
    decompile_calls: list[tuple[int, int]] = []
    results = iter(codes)
    monkeypatch.setattr(runner, "get_binary_suffix", lambda: ".dll")
    monkeypatch.setattr(runner, "get_func_ea", lambda _name: 0x401000)

    def decompile(ea, *, flags):
        decompile_calls.append((ea, flags))
        return _Cfunc(next(results))

    monkeypatch.setattr(runner.idaapi, "decompile", decompile)

    run_deobfuscation_test(
        case,
        _state_context(state),
        lambda pseudocode: str(pseudocode),
    )

    assert len(decompile_calls) == expected_decompiles
    assert state.stop_calls == expected_stops
    assert state.start_calls == 1


def test_database_capture_forces_the_before_decompile(monkeypatch) -> None:
    from d810.testing import runner

    state = _State()
    codes = iter(("before", "after"))
    capture = SimpleNamespace(record=lambda **kwargs: setattr(capture, "row", kwargs))
    monkeypatch.setattr(runner, "get_binary_suffix", lambda: ".dll")
    monkeypatch.setattr(runner, "get_func_ea", lambda _name: 0x401000)
    monkeypatch.setattr(
        runner.idaapi,
        "decompile",
        lambda _ea, *, flags: _Cfunc(next(codes)),
    )

    run_deobfuscation_test(
        DeobfuscationCase(
            function="capture",
            project="",
            must_change=False,
            check_stats=False,
        ),
        _state_context(state),
        lambda pseudocode: str(pseudocode),
        db_capture=capture,
    )

    assert state.stop_calls == 1
    assert capture.row["code_before"] == "before"
    assert capture.row["code_after"] == "after"


def test_runner_none_project_preserves_selected_project_and_rule_identity(
    monkeypatch,
) -> None:
    """Selected-state callers must not reactivate a fresh rule population."""
    from d810.testing import runner

    state = _State()
    original_project = state.current_project
    original_rules = state.current_ins_rules
    monkeypatch.setattr(runner, "get_binary_suffix", lambda: ".dll")
    monkeypatch.setattr(runner, "get_func_ea", lambda _name: 0x401000)
    monkeypatch.setattr(runner.idaapi, "decompile", lambda _ea, *, flags: _Cfunc("after"))

    run_deobfuscation_test(
        DeobfuscationCase(
            function="selected",
            project=None,
            must_change=False,
            check_stats=False,
        ),
        _state_context(state),
        lambda pseudocode: str(pseudocode),
    )

    assert state.loaded_projects == []
    assert state.current_project is original_project
    assert state.current_ins_rules is original_rules


def test_runner_default_project_still_loads_default_configuration(monkeypatch) -> None:
    from d810.testing import runner

    state = _State()
    resolved: list[str] = []
    monkeypatch.setattr(runner, "get_binary_suffix", lambda: ".dll")
    monkeypatch.setattr(runner, "get_func_ea", lambda _name: 0x401000)
    monkeypatch.setattr(runner.idaapi, "decompile", lambda _ea, *, flags: _Cfunc("after"))

    def resolve(_state, project_name: str) -> int:
        resolved.append(project_name)
        return 7

    monkeypatch.setattr(runner, "_resolve_test_project_index", resolve)
    run_deobfuscation_test(
        DeobfuscationCase(
            function="default",
            must_change=False,
            check_stats=False,
        ),
        _state_context(state),
        lambda pseudocode: str(pseudocode),
    )

    assert resolved == ["default_instruction_only.json"]
    assert state.loaded_projects == [7]


def test_runner_opens_runtime_capture_window_immediately_before_after_decompile(
    monkeypatch,
) -> None:
    from d810.testing import runner

    state = _State()
    events: list[str] = []
    monkeypatch.setattr(runner, "get_binary_suffix", lambda: ".dll")
    monkeypatch.setattr(runner, "get_func_ea", lambda _name: 0x401000)

    def decompile(_ea, *, flags):
        events.append("decompile")
        return _Cfunc("after")

    monkeypatch.setattr(runner.idaapi, "decompile", decompile)

    run_deobfuscation_test(
        DeobfuscationCase(
            function="capture-window",
            project="",
            must_change=False,
            check_stats=False,
        ),
        _state_context(state),
        lambda pseudocode: str(pseudocode),
        prepare_runtime_state=lambda live_state: events.append(
            "prepare" if live_state is state else "wrong-state"
        ),
        capture_runtime_state=lambda live_state: events.append(
            "capture" if live_state is state else "wrong-state"
        ),
    )

    assert events == ["prepare", "decompile", "capture"]
