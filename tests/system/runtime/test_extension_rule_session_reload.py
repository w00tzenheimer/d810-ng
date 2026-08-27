"""Reload-session ownership regressions for explicit plugin factories."""

from __future__ import annotations

from d810.core.plugins import (
    PLUGIN_API_VERSION,
    BackendManifest,
    BackendRegistry,
    BackendSpec,
)


class _Activation:
    def __init__(self):
        self.created: list[object] = []
        self.close_calls = 0

    def create_implementation(self, _implementation_id: str):
        implementation = object()
        self.created.append(implementation)
        return implementation

    def capability_offers(self):
        return ()

    def close(self):
        self.close_calls += 1


def test_reload_session_drops_old_d810_implementation_ownership():
    activation = _Activation()
    plugin = type(
        "Plugin",
        (),
        {"activate": lambda self, _context: activation},
    )()
    manifest = BackendManifest(
        name="external",
        api_version=PLUGIN_API_VERSION,
        provides=lambda: plugin,
        implements={"external-pass": "ExternalRule"},
    )
    registry = BackendRegistry(
        source=lambda: (
            BackendSpec(
                name="external",
                origin="external-wheel",
                load_manifest=lambda: manifest,
            ),
        )
    )
    candidate = registry.require_unique_implementation(
        "external-pass", install_hint="external-package"
    )
    old_instance = registry.activate_implementation(candidate)

    registry.close_activations()
    registry.discover(force=True)
    new_instance = registry.activate_implementation(candidate)

    assert old_instance is not new_instance
    assert activation.close_calls == 1
    assert registry._implementation_instances[candidate] == [new_instance]
