from __future__ import annotations

from d810.core.project import (
    ProjectLifecycleEvent,
    ProjectLifecyclePayload,
    clear_project_lifecycle_for_tests,
    emit_project_reloading,
    register_project_reload_cleanup,
    subscribe_project_lifecycle,
)


def setup_function():
    clear_project_lifecycle_for_tests()


def teardown_function():
    clear_project_lifecycle_for_tests()


def test_project_reload_runs_named_cleanups_once_per_registration():
    calls: list[str] = []

    register_project_reload_cleanup("state", lambda: calls.append("first"))
    register_project_reload_cleanup("state", lambda: calls.append("replacement"))

    emit_project_reloading(old_project_name="old", new_project_name="new")

    assert calls == ["replacement"]


def test_project_reload_emits_payload_after_cleanups():
    calls: list[object] = []

    register_project_reload_cleanup("state", lambda: calls.append("cleanup"))

    def _on_reload(payload: ProjectLifecyclePayload) -> None:
        calls.append(payload)

    subscribe_project_lifecycle(ProjectLifecycleEvent.PROJECT_RELOADING, _on_reload)

    emit_project_reloading(old_project_name="old", new_project_name="new")

    assert calls[0] == "cleanup"
    payload = calls[1]
    assert isinstance(payload, ProjectLifecyclePayload)
    assert payload.reason is ProjectLifecycleEvent.PROJECT_RELOADING
    assert payload.old_project_name == "old"
    assert payload.new_project_name == "new"
