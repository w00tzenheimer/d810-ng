"""Unit tests for the API 1 plugin manifest and activation contract."""

import unittest

from d810.core.plugins import (
    PLUGIN_API_VERSION,
    BackendManifest,
    BackendRegistry,
    BackendSpec,
    BackendStatus,
    BackendUnavailable,
    ENTRY_POINT_GROUP,
    ManifestError,
    PluginActivationContext,
    PluginCapabilityOffer,
    PluginFunctionContext,
    format_report,
    has_defects,
    manifest_of,
    offers_capability,
)


class Recorder:
    def __init__(self, result=None, raises=None):
        self.result = result if result is not None else object()
        self.raises = raises
        self.calls = 0

    def __call__(self):
        self.calls += 1
        if self.raises is not None:
            raise self.raises
        return self.result


class TestManifest(unittest.TestCase):
    def test_manifest_accepts_dependency_free_requirements(self):
        manifest = manifest_of(
            {
                "name": "example",
                "api_version": 1,
                "provides": "example.plugin:PLUGIN",
                "requires": ("d810.mba.residual-observation.v1",),
                "implements": {"mba-solve": "example-solve"},
            }
        )
        self.assertEqual(
            manifest.requires, ("d810.mba.residual-observation.v1",)
        )
        self.assertEqual(manifest.implements, {"mba-solve": "example-solve"})

    def test_manifest_defaults_to_no_requirements(self):
        manifest = BackendManifest("example", PLUGIN_API_VERSION, "pkg:PLUGIN")
        self.assertEqual(manifest.requires, ())

    def test_manifest_default_implementation_map_is_immutable_and_local(self):
        first = BackendManifest("first", PLUGIN_API_VERSION, "pkg:first")
        second = BackendManifest("second", PLUGIN_API_VERSION, "pkg:second")
        self.assertEqual(first.implements, {})
        self.assertIsNot(first.implements, second.implements)
        with self.assertRaises(TypeError):
            first.implements["pass"] = "impl"  # type: ignore[index]

    def test_manifest_accepts_object_without_importing_d810(self):
        class Declared:
            name = "example"
            api_version = 1
            provides = "pkg:PLUGIN"
            requires = ("d810.example.v1",)
            implements = {"pass": "implementation"}

        manifest = manifest_of(Declared)
        self.assertEqual(manifest.requires, ("d810.example.v1",))

    def test_manifest_rejects_duplicate_requirements(self):
        with self.assertRaisesRegex(ManifestError, "unique"):
            manifest_of(
                {
                    "name": "example",
                    "api_version": 1,
                    "provides": "pkg:PLUGIN",
                    "requires": ("d810.example.v1", "d810.example.v1"),
                }
            )

    def test_manifest_rejects_malformed_requirement_ids(self):
        for value in ("d810.example.v1", ("",), ("not-dotted",), (1,)):
            with self.subTest(value=value), self.assertRaises(ManifestError):
                manifest_of(
                    {
                        "name": "example",
                        "api_version": 1,
                        "provides": "pkg:PLUGIN",
                        "requires": value,
                    }
                )

    def test_manifest_rejects_removed_rules_and_capabilities(self):
        for key, value in (("rules", ("pkg.rules",)), ("capabilities", ())):
            with self.subTest(key=key), self.assertRaises(ManifestError):
                manifest_of(
                    {
                        "name": "example",
                        "api_version": 1,
                        "provides": "pkg:PLUGIN",
                        key: value,
                    }
                )

    def test_manifest_rejects_malformed_implementation_ids(self):
        for implements in ({"": "impl"}, {"pass": ""}, {1: "impl"}):
            with self.subTest(implements=implements), self.assertRaises(
                ManifestError
            ):
                manifest_of(
                    {
                        "name": "example",
                        "api_version": 1,
                        "provides": "pkg:PLUGIN",
                        "implements": implements,
                    }
                )

    def test_manifest_does_not_resolve_provides(self):
        load = Recorder()
        manifest_of(
            {
                "name": "example",
                "api_version": 1,
                "provides": load,
            }
        )
        self.assertEqual(load.calls, 0)


class TestOffer(unittest.TestCase):
    def test_offer_factory_receives_function_context(self):
        class Thing:
            pass

        seen = []

        def factory(context: PluginFunctionContext):
            seen.append(context)
            return Thing()

        offer = PluginCapabilityOffer(Thing, factory)
        context = PluginFunctionContext("source", "identity", object())
        self.assertIsInstance(offer.factory(context), Thing)
        self.assertIs(seen[0], context)

    def test_offers_capability_decorator_preserves_context_factory(self):
        class Thing:
            pass

        @offers_capability(Thing)
        def factory(context: PluginFunctionContext):
            return Thing()

        self.assertIsInstance(factory, PluginCapabilityOffer)
        self.assertIsInstance(
            factory.factory(PluginFunctionContext(None, None, object())), Thing
        )


class FakeHost:
    def __init__(self, available=()):
        self.available = set(available)

    def require(self, capability):
        return capability

    def optional(self, capability):
        return None

    def validate(self, requirements):
        for requirement in requirements:
            if requirement not in self.available:
                raise BackendUnavailable(f"missing host capability: {requirement}")


class FakeActivation:
    def __init__(self, *, offers=(), close_error=None):
        self.offers = tuple(offers)
        self.close_error = close_error
        self.close_calls = 0

    def create_implementation(self, implementation_id):
        return object()

    def capability_offers(self):
        return self.offers

    def close(self):
        self.close_calls += 1
        if self.close_error is not None:
            raise self.close_error


class FakePlugin:
    def __init__(self, activation):
        self.activation = activation
        self.activate_calls = []

    def activate(self, context):
        self.activate_calls.append(context)
        return self.activation


def registry_for(plugin, *, requires=(), host=None, name="example"):
    manifest = {
        "name": name,
        "api_version": PLUGIN_API_VERSION,
        "provides": lambda: plugin,
        "requires": requires,
        "implements": {"mba-solve": "example-solve"},
    }
    return BackendRegistry(
        source=lambda: [
            BackendSpec(
                name=name,
                origin="example 1.0",
                load_manifest=lambda: manifest,
            )
        ],
        host=host,
    )


class TestActivation(unittest.TestCase):
    def test_activation_validates_requirements_and_calls_plugin_once(self):
        plugin = FakePlugin(FakeActivation())
        reg = registry_for(
            plugin,
            requires=("d810.example.v1",),
            host=FakeHost(("d810.example.v1",)),
        )
        activation = reg.activate("example")
        self.assertIs(activation, plugin.activation)
        self.assertEqual(len(plugin.activate_calls), 1)
        self.assertIsInstance(plugin.activate_calls[0], PluginActivationContext)
        self.assertEqual(plugin.activate_calls[0].identity.name, "example")

        self.assertIs(reg.activate("example"), activation)
        self.assertEqual(len(plugin.activate_calls), 1)

    def test_activation_rejects_missing_requirement_before_loading_plugin(self):
        plugin = FakePlugin(FakeActivation())
        reg = registry_for(
            plugin,
            requires=("d810.missing.v1",),
            host=FakeHost(),
        )
        with self.assertRaisesRegex(BackendUnavailable, "missing host capability"):
            reg.activate("example")
        self.assertEqual(plugin.activate_calls, [])

    def test_invalid_activation_surface_closes_partial_activation(self):
        partial = FakeActivation(offers=("not-an-offer",))
        plugin = FakePlugin(partial)
        reg = registry_for(plugin)
        with self.assertRaises(ManifestError):
            reg.activate("example")
        self.assertEqual(partial.close_calls, 1)

    def test_close_activations_is_idempotent_and_continues_after_error(self):
        first = FakeActivation(close_error=RuntimeError("first close failed"))
        second = FakeActivation()
        first_plugin = FakePlugin(first)
        second_plugin = FakePlugin(second)
        reg = registry_for(first_plugin, name="first")
        reg2 = registry_for(second_plugin, name="second")
        reg.activate("first")
        reg2.activate("second")
        reg._activated.update(reg2._activated)

        reg.close_activations()
        reg.close_activations()
        self.assertEqual(first.close_calls, 1)
        self.assertEqual(second.close_calls, 1)


class TestDiscovery(unittest.TestCase):
    def test_discovery_is_lazy_and_status_is_reportable(self):
        load = Recorder()
        reg = BackendRegistry(
            source=lambda: [
                BackendSpec(
                    name="example",
                    origin="test",
                    load_manifest=lambda: BackendManifest(
                        "example", PLUGIN_API_VERSION, load
                    ),
                )
            ]
        )
        self.assertEqual(reg.names(), ["example"])
        self.assertEqual(load.calls, 0)
        self.assertEqual(reg.info("example").status, BackendStatus.NOT_LOADED)
        self.assertEqual(reg.probe("example").status, BackendStatus.AVAILABLE)
        self.assertEqual(load.calls, 1)

    def test_group_has_no_version(self):
        self.assertEqual(ENTRY_POINT_GROUP, "d810.backends")

    def test_format_report_empty_and_health(self):
        self.assertEqual(format_report([]), "no backends registered")
        info = BackendRegistry(source=lambda: []).report()
        self.assertFalse(has_defects(info))


if __name__ == "__main__":
    unittest.main()
