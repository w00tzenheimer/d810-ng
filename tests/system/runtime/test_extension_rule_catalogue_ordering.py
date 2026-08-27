"""Runtime regressions for declaration-only external implementations."""

from __future__ import annotations

from d810.core.plugins import (
    PLUGIN_API_VERSION,
    BackendManifest,
    BackendRegistry,
    BackendSpec,
)


class _Activation:
    def __init__(self, factory):
        self.factory = factory
        self.factory_calls: list[str] = []
        self.close_calls = 0

    def create_implementation(self, implementation_id: str):
        self.factory_calls.append(implementation_id)
        return self.factory()

    def capability_offers(self):
        return ()

    def close(self):
        self.close_calls += 1


class _Plugin:
    def __init__(self, activation):
        self.activation = activation

    def activate(self, _context):
        return self.activation


def _registry(activation):
    plugin = _Plugin(activation)
    manifest = BackendManifest(
        name="external",
        api_version=PLUGIN_API_VERSION,
        provides=lambda: plugin,
        implements={"external-pass": "ExternalRule"},
    )
    return BackendRegistry(
        source=lambda: (
            BackendSpec(
                name="external",
                origin="external-wheel",
                load_manifest=lambda: manifest,
            ),
        )
    )


def test_manifest_import_is_inert_and_does_not_create_an_implementation():
    created: list[object] = []
    activation = _Activation(lambda: created.append(object()) or created[-1])
    registry = _registry(activation)

    candidates = registry.implementation_candidates_for("external-pass")

    assert len(candidates) == 1
    assert activation.factory_calls == []
    assert created == []


def test_only_explicitly_selected_candidate_calls_its_factory():
    activation = _Activation(object)
    registry = _registry(activation)
    candidate = registry.require_unique_implementation(
        "external-pass", install_hint="external-package"
    )

    implementation = registry.activate_implementation(candidate)

    assert implementation is not None
    assert activation.factory_calls == ["ExternalRule"]


def test_reload_closes_old_d810_instance_before_creating_a_fresh_one():
    created: list[object] = []

    def factory():
        instance = object()
        created.append(instance)
        return instance

    activation = _Activation(factory)
    registry = _registry(activation)
    candidate = registry.require_unique_implementation(
        "external-pass", install_hint="external-package"
    )
    old_instance = registry.activate_implementation(candidate)

    registry.close_activations()
    registry.discover(force=True)
    new_instance = registry.activate_implementation(candidate)

    assert old_instance is not new_instance
    assert len(created) == 2
    assert activation.close_calls == 1
    assert registry.implementation_is_active(candidate)
    assert registry._implementation_instances[candidate] == [new_instance]
