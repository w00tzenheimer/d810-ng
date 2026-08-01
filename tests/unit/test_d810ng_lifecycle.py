"""Behavioral contract for the outer IDA plugin lifecycle."""

from __future__ import annotations

import importlib.util
import sys
from contextlib import contextmanager
from pathlib import Path
from types import ModuleType

import pytest


ROOT = Path(__file__).resolve().parents[2]
PLUGIN_PATH = ROOT / "src" / "d810ng.py"


def _load_plugin_module(
    monkeypatch: pytest.MonkeyPatch,
    *,
    initially_loaded: bool,
    initially_started: bool,
) -> tuple[ModuleType, list[str]]:
    events: list[str] = []

    class CoreState:
        def __init__(self) -> None:
            self.loaded = initially_loaded
            self.manager = type("Manager", (), {"started": initially_started})()

        def is_loaded(self) -> bool:
            events.append("core-is-loaded")
            return self.loaded

        def load(self) -> None:
            events.append("core-load")
            self.loaded = True

        def start_d810(self) -> None:
            events.append("core-start")
            self.manager.started = True

    core = CoreState()

    class ReloadablePluginBase:
        def __init__(self, **kwargs: object) -> None:
            self.plugin = core
            self.base_package_name = str(kwargs["base_package_name"])

        def late_init(self) -> None:
            events.append("base-late-init")

        @contextmanager
        def plugin_setup_reload(self):
            events.append("base-reload-enter")
            core.loaded = False
            core.manager.started = False
            yield
            core.loaded = True
            events.append("base-reload-exit")

    idaapi = ModuleType("idaapi")
    idaapi.UI_Hooks = type("UI_Hooks", (), {})
    idaapi.action_handler_t = type("action_handler_t", (), {})
    idaapi.plugin_t = type("plugin_t", (), {})
    idaapi.PLFM_386 = 1
    idaapi.PLFM_ARM = 2
    idaapi.PLFM_PPC = 3
    idaapi.PLFM_MIPS = 4
    idaapi.PLFM_RISCV = 5
    idaapi.PLUGIN_PROC = 1
    idaapi.PLUGIN_MOD = 2
    idaapi.PLUGIN_SKIP = 0
    idaapi.PLUGIN_OK = 1

    ida_kernwin = ModuleType("ida_kernwin")
    ida_kernwin.action_ctx_base_t = type("action_ctx_base_t", (), {})

    ida_hexrays = ModuleType("ida_hexrays")
    d810 = ModuleType("d810")
    d810.__version__ = "test-version"

    reloader = ModuleType("d810._vendor.ida_reloader")
    reloader.ReloadablePluginBase = ReloadablePluginBase
    reloader.reload_package = lambda *_args, **_kwargs: events.append(
        "reload-package"
    )

    typing_module = ModuleType("d810.core.typing")
    typing_module.override = lambda function: function

    for name, module in (
        ("idaapi", idaapi),
        ("ida_kernwin", ida_kernwin),
        ("ida_hexrays", ida_hexrays),
        ("d810", d810),
        ("d810._vendor.ida_reloader", reloader),
        ("d810.core.typing", typing_module),
    ):
        monkeypatch.setitem(sys.modules, name, module)

    spec = importlib.util.spec_from_file_location("d810ng_lifecycle_test", PLUGIN_PATH)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module, events


@pytest.mark.parametrize(
    ("initially_loaded", "initially_started", "expected_events"),
    (
        (
            False,
            False,
            [
                "base-late-init",
                "core-is-loaded",
                "core-load",
                "core-is-loaded",
                "core-start",
            ],
        ),
        (True, False, ["base-late-init", "core-is-loaded", "core-start"]),
        (True, True, ["base-late-init", "core-is-loaded"]),
    ),
)
def test_late_init_starts_core_exactly_when_needed(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    initially_loaded: bool,
    initially_started: bool,
    expected_events: list[str],
) -> None:
    module, events = _load_plugin_module(
        monkeypatch,
        initially_loaded=initially_loaded,
        initially_started=initially_started,
    )

    plugin = module.D810Plugin()
    plugin.late_init()

    assert events == expected_events
    assert capsys.readouterr().out == "D810 initialized (version test-version)\n"


@pytest.mark.parametrize(
    ("initially_started", "expected_tail"),
    (
        (
            True,
            [
                "base-reload-enter",
                "reload-package",
                "base-reload-exit",
                "core-is-loaded",
                "core-start",
            ],
        ),
        (
            False,
            ["base-reload-enter", "reload-package", "base-reload-exit"],
        ),
    ),
)
def test_reload_restores_the_previous_started_state(
    monkeypatch: pytest.MonkeyPatch,
    initially_started: bool,
    expected_tail: list[str],
) -> None:
    module, events = _load_plugin_module(
        monkeypatch,
        initially_loaded=True,
        initially_started=initially_started,
    )

    plugin = module.D810Plugin()
    plugin.reload()

    assert events == expected_tail
