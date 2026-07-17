from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace

from d810.ui.config_v2_editing_commands import ConfigV2EditingAdapter


def test_adapter_delegates_every_edit_to_state_and_revalidates() -> None:
    draft = SimpleNamespace(revision=0)
    edited = SimpleNamespace(revision=1)
    validation = object()
    recipe = object()
    events: list[object] = []
    state = SimpleNamespace(
        get_config_v2_serializer_manifest=lambda: ("manifest",),
        get_workbench_recipe_catalog=lambda: ("catalog",),
        create_config_v2_project_draft=lambda destination: events.append(
            ("create", destination)
        )
        or draft,
        materialize_recipe_as_config_v2=lambda candidate, value: events.append(
            ("materialize", candidate, value)
        )
        or edited,
        validate_config_v2_project_draft=lambda candidate: events.append(
            ("validate", candidate)
        )
        or validation,
        set_config_v2_description=lambda candidate, value: events.append(
            ("description", candidate, value)
        )
        or edited,
        add_config_v2_pass=lambda candidate, pass_id, index=None: events.append(
            ("add", candidate, pass_id, index)
        )
        or edited,
        remove_config_v2_pass=lambda candidate, index: events.append(
            ("remove", candidate, index)
        )
        or edited,
        reorder_config_v2_pass=lambda candidate, index, new_index: events.append(
            ("reorder", candidate, index, new_index)
        )
        or edited,
        set_config_v2_pass_rules=lambda candidate, **kwargs: events.append(
            ("rules", candidate, kwargs)
        )
        or edited,
        set_config_v2_routing_override=lambda candidate, **kwargs: events.append(
            ("routing", candidate, kwargs)
        )
        or edited,
        save_and_reload_config_v2_project=lambda candidate, checked: events.append(
            ("save", candidate, checked)
        )
        or "saved",
    )
    destination = Path("/tmp/profile.json")
    adapter = ConfigV2EditingAdapter(state, destination=destination, recipe=recipe)

    assert adapter.manifest() == ("manifest",)
    assert adapter.catalog() == ("catalog",)
    assert adapter.reset() == (edited, validation)
    assert adapter.set_description(draft, "new") == (edited, validation)
    assert adapter.add_pass(draft, "jump-fixer", index=1) == (edited, validation)
    assert adapter.remove_pass(draft, 0) == (edited, validation)
    assert adapter.reorder_pass(draft, 0, 1) == (edited, validation)
    assert adapter.set_pass_rules(
        draft,
        pass_index=0,
        include=("A",),
        exclude=("B",),
        options={"x": 1},
    ) == (edited, validation)
    assert adapter.set_routing_override(
        draft,
        prefer={"approov": 5},
        require=None,
        deny=("tigress",),
    ) == (edited, validation)
    assert adapter.save(edited, validation) == "saved"
    assert events[:3] == [
        ("create", destination),
        ("materialize", draft, recipe),
        ("validate", edited),
    ]
    assert sum(event[0] == "validate" for event in events) == 7
    assert events[-1] == ("save", edited, validation)
