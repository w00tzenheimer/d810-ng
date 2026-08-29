"""Runtime regressions for declaration-only external implementations."""

from __future__ import annotations

from d810.core.plugins import (
    PLUGIN_API_VERSION,
    BackendManifest,
    BackendRegistry,
    BackendSpec,
    PluginCapabilityOffer,
    PluginFunctionContext,
)


class _Activation:
    def __init__(self, factory, offers=()):
        self.factory = factory
        self.offers = tuple(offers)
        self.factory_calls: list[str] = []
        self.close_calls = 0

    def create_implementation(self, implementation_id: str):
        self.factory_calls.append(implementation_id)
        return self.factory()

    def capability_offers(self):
        return self.offers

    def release_implementation(self, implementation):
        del implementation

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


def test_host_resolves_fake_offer_with_fresh_callback_context():
    class Capability:
        pass

    contexts: list[PluginFunctionContext] = []

    def make_capability(context: PluginFunctionContext):
        contexts.append(context)
        return Capability()

    activation = _Activation(
        object,
        offers=(PluginCapabilityOffer(Capability, make_capability),),
    )
    registry = _registry(activation)
    registry.activate("external")
    first_source = object()
    second_source = object()

    assert isinstance(
        registry.resolve_capability(
            Capability, source=first_source, identity="first-session"
        ),
        Capability,
    )
    assert isinstance(
        registry.resolve_capability(
            Capability, source=second_source, identity="second-session"
        ),
        Capability,
    )
    assert [(context.source, context.identity) for context in contexts] == [
        (first_source, "first-session"),
        (second_source, "second-session"),
    ]
