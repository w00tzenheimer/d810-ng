"""Explicit implementation-factory activation for external backends."""

from __future__ import annotations

import pytest

from d810.core.plugins import (
    PLUGIN_API_VERSION,
    BackendManifest,
    BackendRegistry,
    BackendSpec,
    PassImplementationMisdeclared,
    PassImplementationUnavailable,
)


class _Activation:
    def __init__(self, implementation=object(), error=None) -> None:
        self.implementation = implementation
        self.error = error
        self.implementation_ids: list[str] = []

    def create_implementation(self, implementation_id: str):
        self.implementation_ids.append(implementation_id)
        if self.error is not None:
            raise self.error
        return self.implementation

    def capability_offers(self):
        return ()

    def release_implementation(self, implementation):
        del implementation

    def close(self):
        return None


class _Plugin:
    def __init__(
        self, activation: _Activation, probe_reason: str | None = None
    ) -> None:
        self.activation = activation
        self.probe_reason = probe_reason

    def activate(self, _context):
        return self.activation

    def d810_backend_probe(self):
        return self.probe_reason


def _registry(plugin, *, implementation_id="ExternalRule"):
    manifest = BackendManifest(
        name="external",
        api_version=PLUGIN_API_VERSION,
        provides=lambda: plugin,
        implements={"external-pass": implementation_id},
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


def test_factory_is_not_called_until_selected_implementation_activation():
    activation = _Activation()
    registry = _registry(_Plugin(activation))

    candidate = registry.require_unique_implementation(
        "external-pass", install_hint="external-package"
    )
    assert activation.implementation_ids == []

    assert registry.activate_implementation(candidate) is activation.implementation
    assert activation.implementation_ids == ["ExternalRule"]


def test_unavailable_backend_never_calls_implementation_factory():
    activation = _Activation()
    registry = _registry(
        _Plugin(activation, probe_reason="native extension not built"),
    )
    candidate = registry.require_unique_implementation(
        "external-pass", install_hint="external-package"
    )
    with pytest.raises(PassImplementationUnavailable):
        registry.activate_implementation(candidate)

    assert activation.implementation_ids == []


def test_factory_reuse_is_rejected_without_discarding_existing_activation():
    activation = _Activation()
    registry = _registry(_Plugin(activation))
    candidate = registry.require_unique_implementation(
        "external-pass", install_hint="external-package"
    )
    registry.activate_implementation(candidate)

    with pytest.raises(PassImplementationMisdeclared, match="reused"):
        registry.activate_implementation(candidate)

    assert activation.implementation_ids == ["ExternalRule", "ExternalRule"]
    assert registry.implementation_is_active(candidate)
