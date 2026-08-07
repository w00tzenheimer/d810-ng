from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace

from d810.manager.config_v2_edit_models import ConfigV2ProjectDraft
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
        create_config_v2_project_draft=lambda destination: (
            events.append(("create", destination)) or draft
        ),
        materialize_recipe_as_config_v2=lambda candidate, value: (
            events.append(("materialize", candidate, value)) or edited
        ),
        validate_config_v2_project_draft=lambda candidate: (
            events.append(("validate", candidate)) or validation
        ),
        set_config_v2_description=lambda candidate, value: (
            events.append(("description", candidate, value)) or edited
        ),
        add_config_v2_pass=lambda candidate, pass_id, index=None: (
            events.append(("add", candidate, pass_id, index)) or edited
        ),
        remove_config_v2_pass=lambda candidate, index: (
            events.append(("remove", candidate, index)) or edited
        ),
        reorder_config_v2_pass=lambda candidate, index, new_index: (
            events.append(("reorder", candidate, index, new_index)) or edited
        ),
        set_config_v2_pass_options=lambda candidate, **kwargs: (
            events.append(("options", candidate, kwargs)) or edited
        ),
        set_config_v2_pass_transforms=lambda candidate, **kwargs: (
            events.append(("transforms", candidate, kwargs)) or edited
        ),
        set_config_v2_routing_override=lambda candidate, **kwargs: (
            events.append(("routing", candidate, kwargs)) or edited
        ),
        replace_config_v2_document=lambda candidate, document: (
            events.append(("document", candidate, document)) or edited
        ),
        save_and_reload_config_v2_project=lambda candidate, checked: (
            events.append(("save", candidate, checked)) or "saved"
        ),
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
    assert adapter.set_pass_options(
        draft,
        pass_index=0,
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


def test_adapter_set_pass_transforms_delegates_once_then_revalidates_once() -> None:
    draft = SimpleNamespace(revision=0)
    edited = SimpleNamespace(revision=1)
    validation = object()
    events: list[object] = []
    state = SimpleNamespace(
        set_config_v2_pass_transforms=lambda candidate, **kwargs: (
            events.append(("transforms", candidate, kwargs)) or edited
        ),
        validate_config_v2_project_draft=lambda candidate: (
            events.append(("validate", candidate)) or validation
        ),
    )
    adapter = ConfigV2EditingAdapter(state, destination=Path("/tmp/profile.json"))

    assert adapter.set_pass_transforms(
        draft,
        pass_index=0,
        transform_ids=("add-xor-1",),
    ) == (edited, validation)
    assert events == [
        (
            "transforms",
            draft,
            {"pass_index": 0, "transform_ids": ("add-xor-1",)},
        ),
        ("validate", edited),
    ]


def test_adapter_replace_document_delegates_once_then_revalidates_once() -> None:
    draft = SimpleNamespace(revision=0)
    edited = SimpleNamespace(revision=1)
    validation = object()
    document = {"description": "new"}
    events: list[object] = []
    state = SimpleNamespace(
        replace_config_v2_document=lambda candidate, value: (
            events.append(("document", candidate, value)) or edited
        ),
        validate_config_v2_project_draft=lambda candidate: (
            events.append(("validate", candidate)) or validation
        ),
    )
    adapter = ConfigV2EditingAdapter(state, destination=Path("/tmp/profile.json"))

    assert adapter.replace_document(draft, document) == (edited, validation)
    assert events == [("document", draft, document), ("validate", edited)]


def test_adapter_load_view_creates_and_validates_an_ordinary_draft() -> None:
    draft = SimpleNamespace(revision=0)
    validation = object()
    recipe = object()
    events: list[object] = []
    state = SimpleNamespace(
        create_config_v2_project_draft=lambda destination: (
            events.append(("create", destination)) or draft
        ),
        validate_config_v2_project_draft=lambda candidate: (
            events.append(("validate", candidate)) or validation
        ),
        materialize_recipe_as_config_v2=lambda candidate, value: (
            events.append(("materialize", candidate, value)) or draft
        ),
    )
    destination = Path("/tmp/profile.json")
    adapter = ConfigV2EditingAdapter(state, destination=destination, recipe=recipe)

    assert adapter.load_view() == (draft, validation)
    assert events == [("create", destination), ("validate", draft)]


def test_adapter_retargets_a_draft_and_revalidates_without_reloading() -> None:
    draft = ConfigV2ProjectDraft(
        draft_id="draft",
        revision=0,
        source_path=Path("/tmp/source.json"),
        destination_path=Path("/tmp/old.json"),
        source_sha256="source-hash",
        original_document_json="{}",
        document_json="{}",
    )
    validation = object()
    events: list[object] = []
    state = SimpleNamespace(
        validate_config_v2_project_draft=lambda candidate: (
            events.append(("validate", candidate)) or validation
        ),
    )
    adapter = ConfigV2EditingAdapter(state, destination=Path("/tmp/old.json"))

    retargeted, actual_validation = adapter.retarget(
        draft,
        Path("/tmp/new.json"),
    )

    assert retargeted.destination_path == Path("/tmp/new.json").resolve()
    assert actual_validation is validation
    assert len(events) == 1
