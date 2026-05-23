"""Unit coverage for the headless facade.

The lifecycle tests use fakes instead of mocked IDA modules. Real Hex-Rays
hook installation belongs in system/runtime tests.
"""

from __future__ import annotations

import pathlib
from types import SimpleNamespace

import pytest


class FakeConfig:
    def __init__(self, *, config_path=None, ida_user_dir=None):
        self.config_path = config_path
        self.ida_user_dir = ida_user_dir


class FakeProject:
    def __init__(self, name: str):
        self.path = pathlib.Path(name)


class FakeProjectManager:
    def __init__(self, names: list[str]):
        self._names = list(names)

    def project_names(self) -> list[str]:
        return list(self._names)

    def index(self, name: str) -> int:
        return self._names.index(name)


class FakeState:
    def __init__(self, project_names: list[str] | None = None):
        names = project_names or ["default_instruction_only.json", "default_unflattening_ollvm.json"]
        self.project_manager = FakeProjectManager(names)
        self.manager = SimpleNamespace(started=False)
        self.current_project = FakeProject(names[0])
        self.current_ins_rules = [object(), object()]
        self.current_blk_rules = [object()]
        self.load_calls = []
        self.load_project_calls = []
        self.start_count = 0
        self.stop_count = 0

    def load(self, *, gui=True, d810_config=None):
        self.load_calls.append({"gui": gui, "d810_config": d810_config})

    def load_project(self, index: int):
        self.load_project_calls.append(index)
        self.current_project = FakeProject(self.project_manager.project_names()[index])
        return self.current_project

    def start_d810(self):
        self.start_count += 1
        self.manager.started = True

    def stop_d810(self):
        self.stop_count += 1
        self.manager.started = False


@pytest.fixture(autouse=True)
def reset_headless_state():
    import d810.headless as headless

    headless._state = None
    headless._configured = False
    yield
    headless._state = None
    headless._configured = False


def test_get_headless_api_returns_module():
    import d810

    api = d810.get_headless_api()

    assert api.__name__ == "d810.headless"
    assert callable(api.configure)


def test_status_initial_state():
    from d810 import headless

    assert headless.status() == {
        "configured": False,
        "started": False,
        "project": None,
        "ins_rules": 0,
        "blk_rules": 0,
    }


def test_start_requires_configure_first():
    from d810 import headless

    with pytest.raises(RuntimeError, match="not configured"):
        headless.start()


def test_stop_without_state_is_noop():
    from d810 import headless

    headless.stop()


def test_configure_loads_state_without_gui_and_selects_project(monkeypatch, tmp_path):
    from d810 import headless

    state = FakeState()
    registry_loads = []

    monkeypatch.setattr(headless, "_make_config", lambda **kwargs: FakeConfig(**kwargs))
    monkeypatch.setattr(headless, "_make_state", lambda: state)
    monkeypatch.setattr(headless, "load_optimizer_registries", lambda: registry_loads.append("loaded"))

    headless.configure(
        project="default_unflattening_ollvm.json",
        config_dir=tmp_path,
        ida_user_dir=tmp_path / "ida-user",
    )

    assert registry_loads == ["loaded"]
    assert len(state.load_calls) == 1
    assert state.load_calls[0]["gui"] is False
    config = state.load_calls[0]["d810_config"]
    assert config.config_path == tmp_path / "options.json"
    assert config.ida_user_dir == tmp_path / "ida-user"
    assert state.load_project_calls == [1]
    assert headless.status()["project"] == "default_unflattening_ollvm.json"


def test_configure_rejects_both_config_path_and_config_dir(tmp_path):
    from d810 import headless

    with pytest.raises(ValueError, match="either config_path or config_dir"):
        headless.configure(config_path=tmp_path / "options.json", config_dir=tmp_path)


def test_configure_rejects_unknown_project(monkeypatch):
    from d810 import headless

    monkeypatch.setattr(headless, "_make_config", lambda **kwargs: FakeConfig(**kwargs))
    monkeypatch.setattr(headless, "_make_state", lambda: FakeState(["known.json"]))
    monkeypatch.setattr(headless, "load_optimizer_registries", lambda: None)

    with pytest.raises(ValueError, match="missing.json"):
        headless.configure(project="missing.json")


def test_start_installs_hooks_when_hexrays_available(monkeypatch):
    from d810 import headless

    state = FakeState()
    monkeypatch.setattr(headless, "_make_config", lambda **kwargs: FakeConfig(**kwargs))
    monkeypatch.setattr(headless, "_make_state", lambda: state)
    monkeypatch.setattr(headless, "load_optimizer_registries", lambda: None)
    monkeypatch.setattr(headless, "_ensure_hexrays", lambda: True)

    headless.configure()
    headless.start()
    headless.start()

    assert state.start_count == 1
    assert headless.status()["started"] is True


def test_start_requires_hexrays(monkeypatch):
    from d810 import headless

    state = FakeState()
    monkeypatch.setattr(headless, "_make_config", lambda **kwargs: FakeConfig(**kwargs))
    monkeypatch.setattr(headless, "_make_state", lambda: state)
    monkeypatch.setattr(headless, "load_optimizer_registries", lambda: None)
    monkeypatch.setattr(headless, "_ensure_hexrays", lambda: False)

    headless.configure()

    with pytest.raises(RuntimeError, match="Hex-Rays"):
        headless.start()


def test_stop_removes_installed_hooks(monkeypatch):
    from d810 import headless

    state = FakeState()
    monkeypatch.setattr(headless, "_make_config", lambda **kwargs: FakeConfig(**kwargs))
    monkeypatch.setattr(headless, "_make_state", lambda: state)
    monkeypatch.setattr(headless, "load_optimizer_registries", lambda: None)
    monkeypatch.setattr(headless, "_ensure_hexrays", lambda: True)

    headless.configure()
    headless.start()
    headless.stop()
    headless.stop()

    assert state.stop_count == 1
    assert headless.status()["started"] is False


def test_load_optimizer_registries_uses_reloader_with_ui_skipped(monkeypatch):
    from d810 import headless

    calls = []
    fake_package = SimpleNamespace(__name__="d810")
    fake_reloader = SimpleNamespace(
        reload_package=lambda package, **kwargs: calls.append((package, kwargs))
    )

    def fake_import_module(name):
        if name == "d810":
            return fake_package
        if name == "d810._vendor.ida_reloader":
            return fake_reloader
        raise AssertionError(name)

    monkeypatch.setattr(headless.importlib, "import_module", fake_import_module)

    headless.load_optimizer_registries(suppress_errors=True)

    assert calls == [
        (
            fake_package,
            {
                "skip": ["d810.core.registry", "d810._vendor", "d810.headless", "d810.ui"],
                "suppress_errors": True,
            },
        )
    ]
