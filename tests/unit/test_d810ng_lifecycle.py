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
    load_succeeds: bool = True,
    prematurely_import_extension: bool = False,
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
            self.loaded = load_succeeds

        def start_d810(self) -> None:
            events.append("core-start")
            self.manager.started = True

    core = CoreState()

    class ReloadablePluginBase:
        def __init__(self, **kwargs: object) -> None:
            self.plugin = core
            self.base_package_name = str(kwargs["base_package_name"])
            self._ok_code = int(kwargs["ok_code"])

        def init(self) -> int:
            return self._ok_code

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
    idaapi.PLUGIN_KEEP = 2
    idaapi.ph = type("processor_t", (), {"id": idaapi.PLFM_386})()

    ida_kernwin = ModuleType("ida_kernwin")
    ida_kernwin.action_ctx_base_t = type("action_ctx_base_t", (), {})
    ida_kernwin.get_kernel_version = lambda: "9.4"

    ida_hexrays = ModuleType("ida_hexrays")
    d810 = ModuleType("d810")
    d810.__version__ = "test-version"

    reloader = ModuleType("d810._vendor.ida_reloader")
    reloader.ReloadablePluginBase = ReloadablePluginBase
    def reload_package(*_args, **_kwargs) -> None:
        events.append("reload-package")
        if prematurely_import_extension:
            monkeypatch.setitem(
                sys.modules,
                "d810_cobra.rules.cobra_solve",
                ModuleType("d810_cobra.rules.cobra_solve"),
            )

    reloader.reload_package = reload_package
    def evict_module_prefixes(prefixes) -> tuple[str, ...]:
        prefixes = tuple(prefixes)
        events.append("evict:" + ",".join(prefixes))
        evicted = tuple(
            module_name
            for module_name in tuple(sys.modules)
            if any(
                module_name == prefix or module_name.startswith(prefix + ".")
                for prefix in prefixes
            )
        )
        for module_name in evicted:
            monkeypatch.delitem(sys.modules, module_name)
        return evicted

    reloader.evict_module_prefixes = evict_module_prefixes

    typing_module = ModuleType("d810.core.typing")
    typing_module.override = lambda function: function
    backends = ModuleType("d810.backends")

    class BackendRegistry:
        def extension_reload_module_prefixes(self) -> tuple[str, ...]:
            events.append("snapshot-extension-prefixes")
            return ("d810_cobra", "d810_egglog")

    backends.registry = lambda: BackendRegistry()

    for name, module in (
        ("idaapi", idaapi),
        ("ida_kernwin", ida_kernwin),
        ("ida_hexrays", ida_hexrays),
        ("d810", d810),
        ("d810._vendor.ida_reloader", reloader),
        ("d810.backends", backends),
        ("d810.core.typing", typing_module),
    ):
        monkeypatch.setitem(sys.modules, name, module)

    spec = importlib.util.spec_from_file_location("d810ng_lifecycle_test", PLUGIN_PATH)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module, events


def test_init_keeps_plugin_alive_until_ready_to_run(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    module, events = _load_plugin_module(
        monkeypatch,
        initially_loaded=False,
        initially_started=False,
    )

    plugin = module.D810Plugin()

    assert plugin.init() == module.idaapi.PLUGIN_KEEP
    assert events == []


@pytest.mark.parametrize(
    ("initially_loaded", "initially_started"),
    ((False, False), (True, False), (True, True)),
)
def test_late_init_leaves_core_state_unchanged(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    initially_loaded: bool,
    initially_started: bool,
) -> None:
    module, events = _load_plugin_module(
        monkeypatch,
        initially_loaded=initially_loaded,
        initially_started=initially_started,
    )

    plugin = module.D810Plugin()
    plugin.late_init()

    assert events == ["base-late-init"]
    assert capsys.readouterr().out == "D810 available (version test-version)\n"


@pytest.mark.parametrize(
    ("initially_loaded", "initially_started", "expected_events"),
    (
        (False, False, ["core-is-loaded", "core-load", "core-is-loaded", "core-start"]),
        (True, False, ["core-is-loaded", "core-start"]),
        (True, True, ["core-is-loaded"]),
    ),
)
def test_shortcut_starts_core_only_when_needed(
    monkeypatch: pytest.MonkeyPatch,
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
    plugin.run(0)
    plugin.run(0)

    assert events == expected_events + ["core-is-loaded"]


def test_shortcut_does_not_start_when_no_project_loads(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    module, events = _load_plugin_module(
        monkeypatch,
        initially_loaded=False,
        initially_started=False,
        load_succeeds=False,
    )

    module.D810Plugin().run(0)

    assert events == ["core-is-loaded", "core-load", "core-is-loaded"]


@pytest.mark.parametrize(
    ("initially_started", "expected_tail"),
    (
        (
            True,
            [
                "snapshot-extension-prefixes",
                "base-reload-enter",
                "evict:d810_cobra,d810_egglog",
                "reload-package",
                "base-reload-exit",
                "core-is-loaded",
                "core-start",
            ],
        ),
        (
            False,
            [
                "snapshot-extension-prefixes",
                "base-reload-enter",
                "evict:d810_cobra,d810_egglog",
                "reload-package",
                "base-reload-exit",
            ],
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


def test_reload_action_enters_plugin_lifecycle_once(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    module, events = _load_plugin_module(
        monkeypatch,
        initially_loaded=True,
        initially_started=True,
    )

    plugin = module.D810Plugin()
    assert plugin.activate(None) == 1

    assert events == [
        "snapshot-extension-prefixes",
        "base-reload-enter",
        "evict:d810_cobra,d810_egglog",
        "reload-package",
        "base-reload-exit",
        "core-is-loaded",
        "core-start",
    ]


def test_reload_rejects_extension_imported_before_core_reload_finishes(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    module, events = _load_plugin_module(
        monkeypatch,
        initially_loaded=True,
        initially_started=True,
        prematurely_import_extension=True,
    )

    plugin = module.D810Plugin()
    with pytest.raises(
        module.ExtensionReloadOrderingError,
        match="d810_cobra.rules.cobra_solve",
    ):
        plugin.reload()

    assert events == [
        "snapshot-extension-prefixes",
        "base-reload-enter",
        "evict:d810_cobra,d810_egglog",
        "reload-package",
    ]
