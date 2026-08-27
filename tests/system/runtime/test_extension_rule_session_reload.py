"""D810 and extension identity regressions across a real reload session."""

from __future__ import annotations

import importlib
import sys
from pathlib import Path


_EXTENSION = "fake_d810_reload_extension"
_RULE_NAME = "FakeReloadRule"

_EXTENSION_SOURCE = """
from d810.optimizers.microcode.instructions.handler import InstructionOptimizationRule


class FakeReloadRule(InstructionOptimizationRule):
    name = "FakeReloadRule"

    def check_and_replace(self, _blk, _ins):
        return None


class Activation:
    def __init__(self):
        self.close_calls = 0

    def create_implementation(self, implementation_id):
        if implementation_id != "FakeReloadRule":
            raise ValueError(implementation_id)
        return FakeReloadRule()

    def capability_offers(self):
        return ()

    def close(self):
        self.close_calls += 1


class Plugin:
    def __init__(self):
        self.activations = []

    def activate(self, _context):
        activation = Activation()
        self.activations.append(activation)
        return activation


PLUGIN = Plugin()
"""


def _write_extension(tmp_path: Path) -> None:
    package = tmp_path / _EXTENSION
    package.mkdir()
    (package / "__init__.py").write_text(_EXTENSION_SOURCE, encoding="utf-8")


def _manifest_and_spec(*, manifest_type, spec_type):
    manifest = manifest_type(
        name=_EXTENSION,
        api_version=1,
        provides=f"{_EXTENSION}:PLUGIN",
        implements={"external-pass": _RULE_NAME},
    )
    return spec_type(
        name=_EXTENSION,
        origin="fake-reload-extension",
        load_manifest=lambda: manifest,
        reload_modules=(_EXTENSION,),
    )


def test_fake_extension_rule_and_d810_classes_are_fresh_after_reload(
    tmp_path, monkeypatch
):
    _write_extension(tmp_path)
    monkeypatch.syspath_prepend(str(tmp_path))

    import d810
    from d810._vendor.ida_reloader import evict_module_prefixes, reload_package
    from d810.core.plugins import BackendManifest, BackendRegistry, BackendSpec
    from d810.optimizers.microcode.instructions.handler import (
        InstructionOptimizationRule,
    )

    old_spec = _manifest_and_spec(manifest_type=BackendManifest, spec_type=BackendSpec)
    old_registry = BackendRegistry(source=lambda: (old_spec,))
    old_candidate = old_registry.require_unique_implementation(
        "external-pass", install_hint="fake-reload-extension"
    )
    old_activation = old_registry.activate(old_candidate.backend_name)
    old_rule = old_registry.activate_implementation(old_candidate)
    old_extension_module = sys.modules[_EXTENSION]
    old_rule_type = type(old_rule)
    old_base_type = InstructionOptimizationRule
    assert old_rule_type.__module__ == _EXTENSION
    assert old_rule_type is not old_base_type
    assert old_base_type.find(_RULE_NAME) is old_rule_type

    old_registry.close_activations()
    assert old_activation.close_calls == 1
    assert old_registry._implementation_instances == {}
    evicted = evict_module_prefixes(old_registry.extension_reload_module_prefixes())
    assert _EXTENSION in evicted
    assert _EXTENSION not in sys.modules

    reload_package(
        d810,
        skip=["d810.core.registry", "d810._vendor"],
        suppress_errors=False,
    )

    new_plugins = importlib.import_module("d810.core.plugins")
    new_handler = importlib.import_module(
        "d810.optimizers.microcode.instructions.handler"
    )
    new_manifest = new_plugins.BackendManifest(
        name=_EXTENSION,
        api_version=1,
        provides=f"{_EXTENSION}:PLUGIN",
        implements={"external-pass": _RULE_NAME},
    )
    new_spec = new_plugins.BackendSpec(
        name=_EXTENSION,
        origin="fake-reload-extension",
        load_manifest=lambda: new_manifest,
        reload_modules=(_EXTENSION,),
    )
    new_registry = new_plugins.BackendRegistry(source=lambda: (new_spec,))
    new_candidate = new_registry.require_unique_implementation(
        "external-pass", install_hint="fake-reload-extension"
    )
    new_activation = new_registry.activate(new_candidate.backend_name)
    new_rule = new_registry.activate_implementation(new_candidate)
    new_extension_module = sys.modules[_EXTENSION]

    assert new_rule is not old_rule
    assert type(new_rule) is not old_rule_type
    assert type(new_rule).__module__ == _EXTENSION
    assert new_handler.InstructionOptimizationRule is not old_base_type
    assert type(new_rule) is not new_handler.InstructionOptimizationRule
    assert new_activation is not old_activation
    assert new_extension_module is not old_extension_module
    assert old_rule not in tuple(
        instance
        for instances in old_registry._implementation_instances.values()
        for instance in instances
    )
    assert old_rule not in tuple(
        instance
        for instances in new_registry._implementation_instances.values()
        for instance in instances
    )

    new_registry.close_activations()
