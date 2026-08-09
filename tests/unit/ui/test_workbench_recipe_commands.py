from __future__ import annotations

import sys
from types import ModuleType, SimpleNamespace
import dataclasses

from d810.core.pass_editor_spec import PassEditorSpec
from d810.manager.workbench_recipe_models import PassCatalogEntry
from d810.passes.state_machine_options import (
    StateMachineCffFamily,
    StateMachineCffOptions,
    StateMachineRecoveryStrategy,
)
from d810.ui.workbench_recipe_logic import CanvasAddError
from d810.ui.workbench_recipe_commands import WorkbenchRecipeAdapter


def _draft():
    return SimpleNamespace(
        function_ea=0x401000,
        function_fingerprint="sha256:abc",
        workbench_generation=8,
        draft_id="draft",
        revision=2,
        passes=(),
    )


def _adapter(state, *, entry_ea=0x401000, maturity=5):
    original_widget = object()
    stable_widget = object()
    mba = SimpleNamespace(maturity=maturity)
    vdui = SimpleNamespace(
        ct=stable_widget,
        cfunc=SimpleNamespace(entry_ea=entry_ea, mba=mba),
    )
    shim = SimpleNamespace(get_widget_vdui=lambda widget: vdui)
    snapshot = SimpleNamespace(function=SimpleNamespace(ea=0x401000))
    return (
        WorkbenchRecipeAdapter(
            state,
            shim,
            SimpleNamespace(widget=original_widget),
            snapshot,
        ),
        mba,
        stable_widget,
    )


def test_recipe_adapter_returns_the_case_captured_with_its_snapshot():
    case = object()
    adapter = WorkbenchRecipeAdapter(
        SimpleNamespace(),
        SimpleNamespace(get_widget_vdui=lambda widget: None),
        SimpleNamespace(widget=object()),
        SimpleNamespace(case=case),
    )

    assert adapter.case() is case


def test_reset_catalog_and_edits_delegate_to_state_then_revalidate():
    draft = _draft()
    edited = SimpleNamespace(**{**draft.__dict__, "revision": 3})
    validation = object()
    events: list[object] = []
    state = SimpleNamespace(
        get_workbench_recipe_catalog=lambda: ("catalog",),
        create_workbench_recipe_draft=lambda snapshot: (
            events.append(("reset", snapshot)) or draft
        ),
        validate_workbench_recipe=lambda candidate, facts=None: (
            events.append(("validate", candidate, facts)) or validation
        ),
        add_workbench_recipe_pass=lambda candidate, pass_id: (
            events.append(("add", candidate, pass_id)) or edited
        ),
    )
    adapter, _, _ = _adapter(state)

    assert adapter.catalog() == ("catalog",)
    assert adapter.reset() == (draft, validation)
    assert adapter.add_pass(draft, "jump-fixer") == (edited, validation)
    assert [event[0] for event in events] == ["reset", "validate", "add", "validate"]


def test_analyze_uses_current_microcode_and_retains_fact_view_for_future_edits():
    draft = _draft()
    facts = object()
    validations: list[object] = []
    state = SimpleNamespace(
        analyze_workbench_recipe=lambda **kwargs: (
            validations.append(("analyze", kwargs)) or facts
        ),
        validate_workbench_recipe=lambda candidate, facts=None: (
            validations.append(("validate", candidate, facts)) or "valid"
        ),
    )
    adapter, mba, stable_widget = _adapter(state)

    result = adapter.analyze(draft)
    repeated = adapter.validate(draft)

    assert result == "valid"
    assert repeated == "valid"
    assert validations[0][1]["target"] is mba
    assert validations[0][1]["function_ea"] == 0x401000
    assert validations[0][1]["provider_phase"].provider_level == 5
    assert validations[1] == ("validate", draft, facts)
    assert validations[2] == ("validate", draft, facts)
    assert adapter._widget is stable_widget


def test_analyze_rejects_widget_that_navigated_to_another_function():
    state = SimpleNamespace(
        analyze_workbench_recipe=lambda **kwargs: (_ for _ in ()).throw(
            AssertionError("wrong function must not be analyzed")
        )
    )
    adapter, _, _ = _adapter(state, entry_ea=0x402000)

    try:
        adapter.analyze(_draft())
    except RuntimeError as exc:
        assert "different function" in str(exc)
    else:
        raise AssertionError("navigated widget must block recipe analysis")


def test_apply_once_reuses_recipe_aware_deobfuscation_action_exactly_once(monkeypatch):
    draft = _draft()
    action_calls: list[object] = []

    class FakeAction:
        def __init__(self, state, ida_modules) -> None:
            action_calls.append((state, ida_modules))

        def execute_with_recipe(self, ctx, candidate) -> int:
            action_calls.append((ctx, candidate))
            return 1

    module = ModuleType("d810.ui.actions.deobfuscate_this")
    module.DeobfuscateThisFunction = FakeAction
    monkeypatch.setitem(sys.modules, module.__name__, module)

    state_calls: list[object] = []

    def execute(request, candidate, validation, *, lifecycle):
        state_calls.append((request, candidate, validation))
        assert lifecycle(candidate) is True
        return "applied"

    state = SimpleNamespace(execute_workbench_apply_recipe_once=execute)
    adapter, _, _ = _adapter(state)

    result = adapter.apply_once(draft, "validation")

    assert result == "applied"
    assert len(state_calls) == 1
    assert action_calls[1][1] is draft


def test_save_and_current_state_use_generation_safe_state_facades():
    draft = _draft()
    requests: list[object] = []
    manager = SimpleNamespace(started=True)
    state = SimpleNamespace(
        manager=manager,
        workbench_recipe_request_is_current=lambda request: (
            requests.append(request) or True
        ),
        execute_workbench_save_function_recipe=lambda request, candidate, validation: (
            request,
            candidate,
            validation,
        ),
    )
    adapter, _, _ = _adapter(state)

    assert adapter.engine_started() is True
    assert adapter.is_current(draft) is True
    result = adapter.save_function(draft, "validation")

    assert result[1:] == (draft, "validation")
    assert requests[0].command == "recipe_status"
    assert result[0].command == "save_function_recipe"


def test_state_cff_threshold_edit_uses_the_typed_state_facade_once():
    draft = _draft()
    calls: list[object] = []
    current = StateMachineCffOptions(
        min_state_constant=0x10000,
        family=StateMachineCffFamily.TIGRESS_INDIRECT,
        recovery_strategy=StateMachineRecoveryStrategy.REDUCED_PRODUCT,
    )
    state = SimpleNamespace(
        get_workbench_recipe_state_cff_options=lambda candidate: (
            calls.append(("get", candidate)) or current
        ),
        replace_workbench_recipe_state_cff_options=lambda candidate, options: (
            calls.append((candidate, options)) or "updated"
        ),
        validate_workbench_recipe=lambda candidate, facts=None: (
            calls.append(("validate", candidate, facts)) or "validation"
        ),
    )
    adapter, _, _ = _adapter(state)

    updated, validation = adapter.replace_state_cff_options(draft, 0x8000)

    assert updated == "updated"
    assert validation == "validation"
    assert calls[0] == ("get", draft)
    assert calls[1][0] is draft
    assert calls[1][1] == dataclasses.replace(current, min_state_constant=0x8000)
    assert calls[2] == ("validate", "updated", None)


def _canvas_catalog() -> tuple[PassCatalogEntry, ...]:
    return (
        PassCatalogEntry(
            "recover-dispatcher",
            "Recover dispatcher",
            "{}",
            "{}",
            "function",
            "ir.local.optimized",
            "mutation_backend",
            "default",
            (),
            (),
            True,
            PassEditorSpec.summary(),
        ),
    )


def test_canvas_add_rejects_wrong_stage_without_changing_draft_revision():
    draft = _draft()
    calls: list[object] = []
    state = SimpleNamespace(
        get_workbench_recipe_catalog=lambda: _canvas_catalog(),
        add_workbench_recipe_pass=lambda *args: calls.append(args),
    )
    adapter, _, _ = _adapter(state)

    try:
        adapter.add_canvas_pass(draft, "ir.global.analyzed", "recover-dispatcher")
    except CanvasAddError as exc:
        assert exc.code == "pass-not-legal-at-stage"
    else:
        raise AssertionError("wrong-stage additions must be rejected")

    assert draft.revision == 2
    assert calls == []


def test_canvas_add_delegates_valid_addition_to_existing_validation_path():
    draft = _draft()
    edited = SimpleNamespace(**{**draft.__dict__, "revision": 3})
    calls: list[object] = []
    validation = object()
    state = SimpleNamespace(
        get_workbench_recipe_catalog=lambda: _canvas_catalog(),
        add_workbench_recipe_pass=lambda candidate, pass_id: (
            calls.append(("add", candidate, pass_id)) or edited
        ),
        validate_workbench_recipe=lambda candidate, facts=None: (
            calls.append(("validate", candidate, facts)) or validation
        ),
    )
    adapter, _, _ = _adapter(state)

    assert adapter.add_canvas_pass(
        draft, "ir.local.optimized", "recover-dispatcher"
    ) == (edited, validation)
    assert calls == [
        ("add", draft, "recover-dispatcher"),
        ("validate", edited, None),
    ]


def test_canvas_add_rejects_duplicate_exclusive_pass_without_calling_state():
    draft = SimpleNamespace(
        **{
            **_draft().__dict__,
            "passes": (SimpleNamespace(pass_id="recover-dispatcher"),),
        }
    )
    calls: list[object] = []
    state = SimpleNamespace(
        get_workbench_recipe_catalog=lambda: _canvas_catalog(),
        add_workbench_recipe_pass=lambda *args: calls.append(args),
    )
    adapter, _, _ = _adapter(state)

    try:
        adapter.add_canvas_pass(draft, "ir.local.optimized", "recover-dispatcher")
    except CanvasAddError as exc:
        assert exc.code == "duplicate-exclusive-pass"
    else:
        raise AssertionError("duplicate canvas additions must be rejected")

    assert calls == []
