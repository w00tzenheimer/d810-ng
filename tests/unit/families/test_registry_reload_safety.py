from __future__ import annotations

import sys
from types import ModuleType

import pytest
import d810.families.registry as family_registry


def test_registered_families_resolves_the_current_base_after_module_reload(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class CurrentFamily:
        name = "current"
        selection_priority = 0

    class HigherPriorityFamily:
        name = "higher"
        selection_priority = 100

    class CurrentBase:
        @classmethod
        def all(cls) -> list[type[CurrentFamily] | type[HigherPriorityFamily]]:
            return [CurrentFamily, HigherPriorityFamily]

    current_base_module = ModuleType("d810.families.state_machine_cff.base")
    current_base_module.StateMachineCffFamily = CurrentBase
    monkeypatch.setitem(
        sys.modules,
        "d810.families.state_machine_cff.base",
        current_base_module,
    )

    families = family_registry.registered_families()

    assert [family.name for family in families] == ["higher", "current"]
    assert isinstance(families[1], CurrentFamily)
