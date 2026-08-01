from __future__ import annotations

import contextlib
from types import SimpleNamespace

from d810.ui.actions import deobfuscate_this as action_module


def _validation(*, satisfied: bool):
    diagnostics = () if satisfied else (SimpleNamespace(message="missing evidence"),)
    return SimpleNamespace(satisfied=satisfied, diagnostics=diagnostics)


def test_explicit_recipe_is_revalidated_activated_and_decompiled_once(monkeypatch):
    events: list[object] = []
    draft = SimpleNamespace(function_ea=0x401000)
    mba = SimpleNamespace(maturity=5)
    cfunc = SimpleNamespace(entry_ea=0x401000, mba=mba)
    vdui = SimpleNamespace(
        cfunc=cfunc,
        refresh_view=lambda force: events.append(("refresh", force)),
    )

    @contextlib.contextmanager
    def activate(candidate):
        events.append(("enter", candidate))
        try:
            yield
        finally:
            events.append(("exit", candidate))

    state = SimpleNamespace(
        analyze_workbench_recipe=lambda **kwargs: events.append(("analyze", kwargs))
        or object(),
        validate_workbench_recipe=lambda candidate, facts=None: events.append(
            ("validate", candidate, facts)
        )
        or _validation(satisfied=True),
        activate_workbench_recipe=activate,
        create_saved_workbench_recipe_draft=lambda **kwargs: (_ for _ in ()).throw(
            AssertionError("explicit apply must not load a saved recipe")
        ),
    )
    shim = SimpleNamespace(get_widget_vdui=lambda widget: vdui)
    monkeypatch.setattr(
        action_module, "prepare_detached_handler_snippets", lambda *args, **kwargs: 0
    )
    action = action_module.DeobfuscateThisFunction(
        state,
        ida_modules={"idaapi": shim},
    )

    result = action.execute_with_recipe(SimpleNamespace(widget=object()), draft)

    assert result == 1
    assert [event[0] for event in events] == [
        "analyze",
        "validate",
        "enter",
        "refresh",
        "exit",
    ]


def test_blocked_recipe_reports_diagnostic_without_activation_or_refresh(monkeypatch):
    warnings: list[str] = []
    mba = SimpleNamespace(maturity=5)
    vdui = SimpleNamespace(
        cfunc=SimpleNamespace(entry_ea=0x401000, mba=mba),
        refresh_view=lambda force: (_ for _ in ()).throw(
            AssertionError("blocked recipe must not refresh")
        ),
    )
    state = SimpleNamespace(
        analyze_workbench_recipe=lambda **kwargs: object(),
        validate_workbench_recipe=lambda draft, facts=None: _validation(
            satisfied=False
        ),
        activate_workbench_recipe=lambda draft: (_ for _ in ()).throw(
            AssertionError("blocked recipe must not activate")
        ),
    )
    shim = SimpleNamespace(
        get_widget_vdui=lambda widget: vdui,
        warning=lambda message: warnings.append(message),
    )
    action = action_module.DeobfuscateThisFunction(
        state,
        ida_modules={"idaapi": shim},
    )

    result = action.execute_with_recipe(
        SimpleNamespace(widget=object()),
        SimpleNamespace(function_ea=0x401000),
    )

    assert result == 0
    assert warnings and "missing evidence" in warnings[0]
