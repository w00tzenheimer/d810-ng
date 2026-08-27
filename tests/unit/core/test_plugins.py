"""Unit tests for the API 1 plugin manifest and activation contract."""

import unittest
import threading

from d810.capabilities import PluginCapabilityAccessError, PluginHostCapabilityRegistry
from d810.core.plugins import (
    PLUGIN_API_VERSION,
    BackendInfo,
    BackendManifest,
    BackendRegistry,
    BackendSpec,
    BackendStatus,
    BackendUnavailable,
    ENTRY_POINT_GROUP,
    ManifestError,
    PassImplementationAmbiguous,
    PassImplementationCandidate,
    PassImplementationMisdeclared,
    PassImplementationMissing,
    PluginActivationContext,
    PluginCapabilityOffer,
    PluginFunctionContext,
    format_report,
    has_defects,
    manifest_of,
    offers_capability,
)
from d810.core.typing import Protocol, runtime_checkable


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


def spec(name, load, *, api_version=PLUGIN_API_VERSION, origin="test"):
    manifest = BackendManifest(name=name, api_version=api_version, provides=load)
    return BackendSpec(name=name, origin=origin, load_manifest=lambda: manifest)


def registry(specs=(), builtins=()):
    return BackendRegistry(builtins=tuple(builtins), source=lambda: list(specs))


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
        self.assertEqual(manifest.requires, ("d810.mba.residual-observation.v1",))
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
            with self.subTest(implements=implements), self.assertRaises(ManifestError):
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


class ProtocolOnlyHost:
    def require(self, capability):
        return capability

    def optional(self, capability):
        return None


class FakeActivation:
    def __init__(self, *, offers=(), close_error=None):
        self.offers = tuple(offers)
        self.close_error = close_error
        self.close_calls = 0
        self.implementation_ids = []
        self.implementation = object()

    def create_implementation(self, implementation_id):
        self.implementation_ids.append(implementation_id)
        return self.implementation

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


@runtime_checkable
class DeclaredHostService(Protocol):
    def run(self) -> str: ...


@runtime_checkable
class UndeclaredHostService(Protocol):
    def inspect(self) -> str: ...


class DeclaredHostServiceImpl:
    def run(self):
        return "declared"


class UndeclaredHostServiceImpl:
    def inspect(self):
        return "undeclared"


def registry_for(plugin, *, requires=(), host=None, name="example"):
    manifest = {
        "name": name,
        "api_version": PLUGIN_API_VERSION,
        "provides": lambda: plugin,
        "requires": requires,
        "implements": {"mba-solve": "example-solve"},
    }
    view_factory = getattr(host, "view_for", None) if host is not None else None
    if view_factory is None and host is not None:

        def view_factory(_requirements):
            return host

    return BackendRegistry(
        source=lambda: [
            BackendSpec(
                name=name,
                origin="example 1.0",
                load_manifest=lambda: manifest,
            )
        ],
        host=host,
        requirement_validator=getattr(host, "validate", None),
        host_view_factory=view_factory,
    )


class TestActivation(unittest.TestCase):
    def test_selected_implementation_is_created_by_declared_factory(self):
        activation = FakeActivation()
        plugin = FakePlugin(activation)
        manifest = BackendManifest(
            name="example",
            api_version=PLUGIN_API_VERSION,
            provides=lambda: plugin,
            implements={"example-pass": "example-implementation"},
        )
        reg = BackendRegistry(
            source=lambda: [
                BackendSpec(
                    name="example",
                    origin="example-wheel",
                    load_manifest=lambda: manifest,
                )
            ],
            host_view_factory=lambda _requirements: FakeHost(),
            requirement_validator=lambda _requirements: None,
        )

        candidate = reg.require_unique_implementation(
            "example-pass", install_hint="example-package"
        )

        implementation = reg.activate_implementation(candidate)

        self.assertIs(implementation, activation.implementation)
        self.assertEqual(activation.implementation_ids, ["example-implementation"])

    def test_plugin_rule_services_preserve_activation_identity_and_host_view(self):
        activation = FakeActivation()
        plugin = FakePlugin(activation)
        host = FakeHost()
        manifest = BackendManifest(
            name="example",
            api_version=PLUGIN_API_VERSION,
            provides=lambda: plugin,
            implements={"example-pass": "example-implementation"},
        )
        reg = BackendRegistry(
            source=lambda: [
                BackendSpec(
                    name="example",
                    origin="example-wheel",
                    load_manifest=lambda: manifest,
                )
            ],
            host_view_factory=lambda _requirements: host,
            requirement_validator=lambda _requirements: None,
        )
        candidate = reg.require_unique_implementation(
            "example-pass", install_hint="example-package"
        )
        reg.activate_implementation(candidate)

        services = reg.plugin_rule_services(candidate)

        self.assertEqual(services.plugin.name, "example")
        self.assertEqual(services.plugin.origin, "example-wheel")
        self.assertIs(services.host, host)

    def test_declared_factory_must_not_reuse_an_implementation_instance(self):
        activation = FakeActivation()
        plugin = FakePlugin(activation)
        manifest = BackendManifest(
            name="example",
            api_version=PLUGIN_API_VERSION,
            provides=lambda: plugin,
            implements={"example-pass": "example-implementation"},
        )
        reg = BackendRegistry(
            source=lambda: [
                BackendSpec(
                    name="example",
                    origin="example-wheel",
                    load_manifest=lambda: manifest,
                )
            ],
            host_view_factory=lambda _requirements: FakeHost(),
            requirement_validator=lambda _requirements: None,
        )
        candidate = reg.require_unique_implementation(
            "example-pass", install_hint="example-package"
        )
        reg.activate_implementation(candidate)

        with self.assertRaises(PassImplementationMisdeclared):
            reg.activate_implementation(candidate)

    def test_factory_rejects_candidate_for_undeclared_implementation_id(self):
        activation = FakeActivation()
        plugin = FakePlugin(activation)
        manifest = BackendManifest(
            name="example",
            api_version=PLUGIN_API_VERSION,
            provides=lambda: plugin,
            implements={"example-pass": "declared-implementation"},
        )
        reg = BackendRegistry(
            source=lambda: [
                BackendSpec(
                    name="example",
                    origin="example-wheel",
                    load_manifest=lambda: manifest,
                )
            ],
            host_view_factory=lambda _requirements: FakeHost(),
            requirement_validator=lambda _requirements: None,
        )
        undeclared = PassImplementationCandidate(
            pass_id="example-pass",
            backend_name="example",
            backend_origin="example-wheel",
            rule_modules=(),
            rule_name="not-declared",
        )

        with self.assertRaises(PassImplementationMisdeclared):
            reg.activate_implementation(undeclared)

        self.assertEqual(activation.implementation_ids, [])

    def test_close_activations_except_retains_project_owned_activation(self):
        activation = FakeActivation()
        plugin = FakePlugin(activation)
        manifest = BackendManifest(
            name="example",
            api_version=PLUGIN_API_VERSION,
            provides=lambda: plugin,
        )
        reg = BackendRegistry(
            source=lambda: [
                BackendSpec(
                    name="example",
                    origin="example-wheel",
                    load_manifest=lambda: manifest,
                )
            ],
            host_view_factory=lambda _requirements: FakeHost(),
            requirement_validator=lambda _requirements: None,
        )
        retained = reg.activate("example")

        reg.close_activations_except((retained,))

        self.assertEqual(activation.close_calls, 0)
        self.assertIs(reg.activate("example"), retained)
        reg.close_activations()
        self.assertEqual(activation.close_calls, 1)

    def test_host_view_factory_can_read_registry_without_deadlock(self):
        plugin = FakePlugin(FakeActivation())
        host = ProtocolOnlyHost()

        def view_factory(_requirements):
            read_complete = threading.Event()

            def read_registry():
                reg.info("example")
                read_complete.set()

            reader = threading.Thread(target=read_registry)
            reader.start()
            self.assertTrue(
                read_complete.wait(timeout=1),
                "registry read blocked while host view was constructed",
            )
            reader.join(timeout=1)
            return host

        reg = BackendRegistry(
            source=lambda: [
                BackendSpec(
                    name="example",
                    origin="example 1.0",
                    load_manifest=lambda: {
                        "name": "example",
                        "api_version": PLUGIN_API_VERSION,
                        "provides": lambda: plugin,
                    },
                )
            ],
            host=host,
            requirement_validator=lambda _requirements: None,
            host_view_factory=view_factory,
        )

        reg.activate("example")

    def test_activation_rejects_host_without_explicit_view_factory(self):
        plugin = FakePlugin(FakeActivation())
        host = ProtocolOnlyHost()
        reg = BackendRegistry(
            source=lambda: [
                BackendSpec(
                    name="example",
                    origin="example 1.0",
                    load_manifest=lambda: {
                        "name": "example",
                        "api_version": PLUGIN_API_VERSION,
                        "provides": lambda: plugin,
                    },
                )
            ],
            host=host,
            requirement_validator=lambda _requirements: None,
        )

        with self.assertRaisesRegex(BackendUnavailable, "host view factory"):
            reg.activate("example")
        self.assertEqual(plugin.activate_calls, [])

    def test_activation_context_scopes_registered_host_services_to_manifest(self):
        plugin = FakePlugin(FakeActivation())
        host = PluginHostCapabilityRegistry()
        declared = DeclaredHostServiceImpl()
        host.register("example.declared.v1", DeclaredHostService, declared)
        host.register(
            "example.undeclared.v1", UndeclaredHostService, UndeclaredHostServiceImpl()
        )
        reg = registry_for(
            plugin,
            requires=("example.declared.v1",),
            host=host,
        )

        reg.activate("example")

        scoped_host = plugin.activate_calls[0].host
        self.assertIs(scoped_host.require(DeclaredHostService), declared)
        self.assertIsNone(scoped_host.optional(UndeclaredHostService))
        with self.assertRaisesRegex(PluginCapabilityAccessError, "not declared"):
            scoped_host.require(UndeclaredHostService)

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

    def test_activation_uses_the_settled_fallback_manifest_and_plugin(self):
        preferred_plugin = FakePlugin(FakeActivation())
        builtin_plugin = FakePlugin(FakeActivation())
        preferred_manifest = {
            "name": "example",
            "api_version": PLUGIN_API_VERSION,
            "provides": lambda: (_ for _ in ()).throw(
                ImportError("preferred binding missing")
            ),
        }
        builtin_manifest = {
            "name": "example",
            "api_version": PLUGIN_API_VERSION,
            "provides": lambda: builtin_plugin,
        }
        reg = BackendRegistry(
            source=lambda: [
                BackendSpec(
                    name="example",
                    origin="preferred 1.0",
                    load_manifest=lambda: preferred_manifest,
                )
            ],
            builtins=(
                BackendSpec(
                    name="example",
                    origin="builtin",
                    load_manifest=lambda: builtin_manifest,
                ),
            ),
        )

        activation = reg.activate("example")

        self.assertIs(activation, builtin_plugin.activation)
        self.assertEqual(len(preferred_plugin.activate_calls), 0)
        self.assertEqual(builtin_plugin.activate_calls[0].identity.origin, "builtin")

    def test_protocol_only_host_cannot_satisfy_string_requirements(self):
        plugin = FakePlugin(FakeActivation())
        reg = registry_for(
            plugin,
            requires=("d810.example.v1",),
            host=ProtocolOnlyHost(),
        )

        info = reg.probe("example")

        self.assertEqual(info.status, BackendStatus.UNAVAILABLE)
        self.assertIn("validator", info.reason)
        self.assertEqual(plugin.activate_calls, [])

    def test_requirement_validator_defect_is_broken(self):
        plugin = FakePlugin(FakeActivation())

        def broken_validator(requirements):
            raise RuntimeError("validator defect")

        reg = BackendRegistry(
            source=lambda: [
                BackendSpec(
                    name="example",
                    origin="example 1.0",
                    load_manifest=lambda: {
                        "name": "example",
                        "api_version": PLUGIN_API_VERSION,
                        "provides": lambda: plugin,
                        "requires": ("d810.example.v1",),
                    },
                )
            ],
            requirement_validator=broken_validator,
        )

        info = reg.probe("example")

        self.assertEqual(info.status, BackendStatus.BROKEN)
        self.assertIn("validator defect", info.reason)
        self.assertEqual(plugin.activate_calls, [])

    def test_concurrent_activation_is_once_only_and_close_waits_for_it(self):
        plugin = FakePlugin(FakeActivation())
        entered = threading.Barrier(2)
        release = threading.Event()
        calls = []
        original_activate = plugin.activate

        def blocked_activate(context):
            calls.append(context)
            entered.wait(timeout=2)
            self.assertTrue(release.wait(timeout=2))
            return original_activate(context)

        plugin.activate = blocked_activate
        reg = registry_for(plugin)
        results = []
        errors = []

        def activate():
            try:
                results.append(reg.activate("example"))
            except BaseException as exc:  # pragma: no cover - assertion aid
                errors.append(exc)

        first = threading.Thread(target=activate)
        second = threading.Thread(target=activate)
        first.start()
        entered.wait(timeout=2)
        second.start()
        self.assertFalse(reg._activated)
        self.assertEqual(len(calls), 1)
        closed = threading.Event()

        def close():
            reg.close_activations()
            closed.set()

        closer = threading.Thread(target=close)
        closer.start()
        self.assertFalse(closed.wait(timeout=0.05))
        release.set()
        first.join(timeout=2)
        second.join(timeout=2)
        closer.join(timeout=2)

        self.assertFalse(first.is_alive() or second.is_alive() or closer.is_alive())
        self.assertEqual(errors, [])
        self.assertEqual(len(results), 2)
        self.assertIs(results[0], results[1])
        self.assertEqual(len(calls), 1)
        self.assertEqual(plugin.activation.close_calls, 1)

        reg.close_activations()
        self.assertEqual(plugin.activation.close_calls, 1)
        self.assertFalse(reg._activated)
        self.assertEqual(reg.capability_offers(), ())

        old_activation = plugin.activation
        fresh_activation = FakeActivation()
        plugin.activation = fresh_activation
        plugin.activate = original_activate
        reactivated = reg.activate("example")
        self.assertIs(reactivated, fresh_activation)
        self.assertIsNot(reactivated, old_activation)

    def test_activation_and_close_callbacks_can_read_registry(self):
        plugin = FakePlugin(FakeActivation())
        reg = registry_for(plugin)
        activation_entered = threading.Event()
        activation_errors = []
        original_activate = plugin.activate

        def activate(context):
            activation_entered.set()
            worker_done = threading.Event()

            def read_registry():
                try:
                    reg.info("example")
                except BaseException as exc:  # pragma: no cover - assertion aid
                    activation_errors.append(exc)
                finally:
                    worker_done.set()

            worker = threading.Thread(target=read_registry)
            worker.start()
            if not worker_done.wait(timeout=1):
                activation_errors.append(
                    AssertionError("registry read blocked during activation")
                )
            worker.join(timeout=1)
            return original_activate(context)

        plugin.activate = activate
        activation_thread = threading.Thread(target=lambda: reg.activate("example"))
        activation_thread.start()
        self.assertTrue(activation_entered.wait(timeout=2))
        activation_thread.join(timeout=2)
        self.assertFalse(activation_thread.is_alive())
        self.assertEqual(activation_errors, [])

        close_errors = []
        original_close = plugin.activation.close

        def close():
            worker_done = threading.Event()

            def read_registry():
                try:
                    reg.info("example")
                except BaseException as exc:  # pragma: no cover - assertion aid
                    close_errors.append(exc)
                finally:
                    worker_done.set()

            worker = threading.Thread(target=read_registry)
            worker.start()
            if not worker_done.wait(timeout=1):
                close_errors.append(
                    AssertionError("registry read blocked during close")
                )
            worker.join(timeout=1)
            original_close()

        plugin.activation.close = close
        reg.close_activations()
        self.assertEqual(close_errors, [])
        self.assertEqual(plugin.activation.close_calls, 1)

    def test_forced_rediscovery_closes_live_activation_before_reset(self):
        plugin = FakePlugin(FakeActivation())
        reg = registry_for(plugin)
        reg.activate("example")

        reg.discover(force=True)

        self.assertEqual(plugin.activation.close_calls, 1)
        reg.close_activations()
        self.assertEqual(plugin.activation.close_calls, 1)

    def test_forced_rediscovery_close_callback_can_wait_for_registry_read(self):
        plugin = FakePlugin(FakeActivation())
        reg = registry_for(plugin)
        reg.activate("example")
        close_errors = []
        readers = []
        original_close = plugin.activation.close

        def close():
            read_complete = threading.Event()

            def read_registry():
                try:
                    reg.info("example")
                except BaseException as exc:  # pragma: no cover - assertion aid
                    close_errors.append(exc)
                finally:
                    read_complete.set()

            reader = threading.Thread(target=read_registry)
            readers.append(reader)
            reader.start()
            if not read_complete.wait(timeout=1):
                close_errors.append(
                    AssertionError(
                        "registry read blocked during forced rediscovery close"
                    )
                )
            original_close()

        plugin.activation.close = close
        force_thread = threading.Thread(target=lambda: reg.discover(force=True))
        force_thread.start()
        force_thread.join(timeout=2)
        for reader in readers:
            reader.join(timeout=1)

        self.assertFalse(force_thread.is_alive())
        self.assertTrue(readers)
        self.assertFalse(any(reader.is_alive() for reader in readers))
        self.assertEqual(close_errors, [])
        self.assertEqual(plugin.activation.close_calls, 1)
        reg.close_activations()
        self.assertEqual(plugin.activation.close_calls, 1)


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


class TestHealthRegression(unittest.TestCase):
    def info(self, status):
        return BackendInfo(
            name="x", status=status, origin="test", api_version=PLUGIN_API_VERSION
        )

    def test_absent_optional_dependency_is_not_a_defect(self):
        for status in (
            BackendStatus.AVAILABLE,
            BackendStatus.UNAVAILABLE,
            BackendStatus.NOT_LOADED,
        ):
            self.assertFalse(has_defects([self.info(status)]), status)

    def test_broken_and_incompatible_are_defects(self):
        for status in (BackendStatus.BROKEN, BackendStatus.INCOMPATIBLE):
            self.assertTrue(has_defects([self.info(status)]), status)

    def test_one_defect_among_healthy_backends_still_counts(self):
        self.assertTrue(
            has_defects(
                [self.info(BackendStatus.AVAILABLE), self.info(BackendStatus.BROKEN)]
            )
        )


class TestFormatReportRegression(unittest.TestCase):
    def test_report_names_status_origin_and_reason(self):
        text = format_report(
            [
                BackendInfo(
                    name="cobra",
                    status=BackendStatus.UNAVAILABLE,
                    origin="builtin",
                    api_version=PLUGIN_API_VERSION,
                    reason="native binding not built",
                )
            ]
        )
        for fragment in ("cobra", "unavailable", "builtin", "binding"):
            self.assertIn(fragment, text)

    def test_report_surfaces_shadowing(self):
        text = format_report(
            [
                BackendInfo(
                    name="cobra",
                    status=BackendStatus.AVAILABLE,
                    origin="d810-cobra 1.0",
                    api_version=PLUGIN_API_VERSION,
                    shadowed=("builtin",),
                )
            ]
        )
        self.assertIn("shadows", text)
        self.assertIn("builtin", text)

    def test_report_explains_a_fallback(self):
        text = format_report(
            [
                BackendInfo(
                    name="cobra",
                    status=BackendStatus.AVAILABLE,
                    origin="builtin",
                    api_version=PLUGIN_API_VERSION,
                    rejected=(("d810-cobra 0.1", "built for API v99"),),
                )
            ]
        )
        for fragment in ("d810-cobra 0.1", "v99", "rejected"):
            self.assertIn(fragment, text)


class TestPassImplementationRegression(unittest.TestCase):
    def test_declarations_wait_for_force_rediscovery_publication(self):
        phase = ["old"]
        force_entered = threading.Event()
        release_force = threading.Event()

        def source():
            return [
                BackendSpec(
                    name="example",
                    origin=f"{phase[0]}-origin",
                    load_manifest=lambda: self.manifest({"mba-solve": "ExampleRule"}),
                )
            ]

        reg = BackendRegistry(source=source)
        self.assertEqual(
            reg.implementation_declarations_for("mba-solve")[0][0].backend_origin,
            "old-origin",
        )
        phase[0] = "new"
        original_close = reg._close_activations_impl

        def paused_close():
            force_entered.set()
            self.assertTrue(release_force.wait(timeout=1))
            original_close()

        reg._close_activations_impl = paused_close
        force_thread = threading.Thread(target=lambda: reg.discover(force=True))
        force_thread.start()
        self.assertTrue(force_entered.wait(timeout=1))

        result = []

        def read_declarations():
            result.extend(reg.implementation_declarations_for("mba-solve"))

        reader = threading.Thread(target=read_declarations)
        reader.start()
        reader.join(timeout=0.05)

        release_force.set()
        force_thread.join(timeout=1)
        reader.join(timeout=1)
        self.assertFalse(reader.is_alive())
        self.assertEqual(result[0][0].backend_origin, "new-origin")

    def test_declaration_manifest_loader_can_read_registry_without_deadlock(self):
        reg_holder = {}
        manifest = self.manifest({"mba-solve": "ExampleRule"})

        def load_manifest():
            read_complete = threading.Event()

            def read_registry():
                reg_holder["registry"].info("example")
                read_complete.set()

            reader = threading.Thread(target=read_registry)
            reader.start()
            self.assertTrue(
                read_complete.wait(timeout=1),
                "registry read blocked while manifest loaded",
            )
            reader.join(timeout=1)
            return manifest

        reg = BackendRegistry(
            source=lambda: [
                BackendSpec(
                    name="example",
                    origin="example-wheel",
                    load_manifest=load_manifest,
                )
            ]
        )
        reg_holder["registry"] = reg

        declarations = reg.implementation_declarations_for("mba-solve")

        self.assertEqual(len(declarations), 1)

    def manifest(self, implements, *, provides=None):
        return BackendManifest(
            name="cobra",
            api_version=PLUGIN_API_VERSION,
            provides=provides if provides is not None else Recorder(result=object()),
            implements=implements,
        )

    def test_declared_implementation_is_found_by_pass_id(self):
        reg = registry(
            [
                BackendSpec(
                    name="cobra",
                    origin="test",
                    load_manifest=lambda: self.manifest(
                        {"mba-solve": "CobraSolveRule"}
                    ),
                )
            ]
        )
        self.assertEqual(reg.implementation_for("mba-solve"), "CobraSolveRule")

    def test_no_extension_means_no_implementation(self):
        self.assertIsNone(registry().implementation_for("mba-solve"))

    def test_unrelated_pass_id_is_not_matched(self):
        reg = registry(
            [
                BackendSpec(
                    name="cobra",
                    origin="test",
                    load_manifest=lambda: self.manifest(
                        {"mba-solve": "CobraSolveRule"}
                    ),
                )
            ]
        )
        self.assertIsNone(reg.implementation_for("unflatten"))

    def test_duck_typed_manifest_may_declare_implementations(self):
        raw = {
            "name": "cobra",
            "api_version": 1,
            "provides": Recorder(result=object()),
            "implements": {"mba-solve": "CobraSolveRule"},
        }
        reg = registry(
            [BackendSpec(name="cobra", origin="test", load_manifest=lambda: raw)]
        )
        self.assertEqual(reg.implementation_for("mba-solve"), "CobraSolveRule")

    def test_malformed_implementation_ids_are_rejected(self):
        for implements in (
            {1: "Rule"},
            {"": "Rule"},
            {"mba-egraph": object()},
            {"mba-egraph": ""},
        ):
            with self.subTest(implements=implements):
                manifest = self.manifest(implements)
                reg = registry(
                    [
                        BackendSpec(
                            name="cobra",
                            origin="test",
                            load_manifest=lambda manifest=manifest: manifest,
                        )
                    ]
                )
                with self.assertRaises(PassImplementationMisdeclared):
                    reg.implementation_candidates_for("mba-egraph")

    def test_resolution_does_not_import_the_backend(self):
        load = Recorder(result=object())
        manifest = self.manifest({"mba-solve": "CobraSolveRule"}, provides=load)
        reg = registry(
            [BackendSpec(name="cobra", origin="test", load_manifest=lambda: manifest)]
        )
        reg.implementation_for("mba-solve")
        self.assertEqual(load.calls, 0)

    def test_incompatible_backend_contributes_no_implementation(self):
        manifest = BackendManifest(
            name="cobra",
            api_version=PLUGIN_API_VERSION - 1,
            provides=Recorder(result=object()),
            implements={"mba-solve": "CobraSolveRule"},
        )
        reg = registry(
            [BackendSpec(name="cobra", origin="test", load_manifest=lambda: manifest)]
        )
        self.assertIsNone(reg.implementation_for("mba-solve"))

    def test_first_compatible_declaration_remains_the_legacy_answer(self):
        first = self.manifest({"mba-solve": "FirstSolver"})
        second = self.manifest({"mba-solve": "SecondSolver"})
        reg = registry(
            [
                BackendSpec(
                    name="first", origin="first-origin", load_manifest=lambda: first
                ),
                BackendSpec(
                    name="second", origin="second-origin", load_manifest=lambda: second
                ),
            ]
        )
        self.assertEqual(reg.implementation_for("mba-solve"), "FirstSolver")

    def test_compatible_manifest_produces_an_immutable_candidate(self):
        manifest = self.manifest({"mba-egraph": "EgglogOptimizer"})
        reg = registry(
            [
                BackendSpec(
                    name="cobra",
                    origin="d810-cobra 1.0",
                    load_manifest=lambda: manifest,
                )
            ]
        )
        self.assertEqual(
            reg.implementation_candidates_for("mba-egraph"),
            (
                PassImplementationCandidate(
                    pass_id="mba-egraph",
                    backend_name="cobra",
                    backend_origin="d810-cobra 1.0",
                    rule_modules=(),
                    rule_name="EgglogOptimizer",
                ),
            ),
        )

    def test_incompatible_manifest_is_ignored_without_resolving_provides(self):
        load = Recorder(result=object())
        manifest = BackendManifest(
            name="cobra",
            api_version=PLUGIN_API_VERSION - 1,
            provides=load,
            implements={"mba-egraph": "EgglogOptimizer"},
        )
        reg = registry(
            [BackendSpec(name="cobra", origin="old", load_manifest=lambda: manifest)]
        )
        self.assertEqual(reg.implementation_candidates_for("mba-egraph"), ())
        self.assertEqual(load.calls, 0)

    def test_two_compatible_declarations_are_ambiguous_in_deterministic_order(self):
        first = self.manifest({"mba-egraph": "FirstRule"})
        second = self.manifest({"mba-egraph": "SecondRule"})
        reg = registry(
            [
                BackendSpec(
                    name="zeta", origin="z-origin", load_manifest=lambda: second
                ),
                BackendSpec(
                    name="acme", origin="a-origin", load_manifest=lambda: first
                ),
            ]
        )
        with self.assertRaises(PassImplementationAmbiguous) as ctx:
            reg.require_unique_implementation("mba-egraph", install_hint="d810-egglog")
        self.assertEqual(
            [candidate.backend_origin for candidate in ctx.exception.candidates],
            ["a-origin", "z-origin"],
        )

    def test_no_declaration_reports_install_hint(self):
        with self.assertRaises(PassImplementationMissing) as ctx:
            registry().require_unique_implementation(
                "mba-egraph", install_hint="d810-egglog"
            )
        self.assertIn("install d810-egglog", str(ctx.exception))

    def test_candidate_read_does_not_probe_or_resolve_backend(self):
        probe_calls = []

        class Backend:
            @staticmethod
            def d810_backend_probe():
                probe_calls.append("probe")
                return None

        load = Recorder(result=Backend)
        manifest = self.manifest({"mba-egraph": "EgglogOptimizer"}, provides=load)
        reg = registry(
            [BackendSpec(name="cobra", origin="test", load_manifest=lambda: manifest)]
        )
        reg.implementation_candidates_for("mba-egraph")
        self.assertEqual(probe_calls, [])
        self.assertEqual(load.calls, 0)

    def test_manifest_info_classifies_failures_without_loading_backend(self):
        cases = (
            (ImportError("binding missing"), BackendStatus.UNAVAILABLE),
            (RuntimeError("manifest exploded"), BackendStatus.BROKEN),
        )
        for error, expected in cases:
            with self.subTest(expected=expected):
                reg = registry(
                    [
                        BackendSpec(
                            name="cobra",
                            origin="test",
                            load_manifest=lambda error=error: (_ for _ in ()).throw(
                                error
                            ),
                        )
                    ]
                )
                info = reg.implementation_manifest_info("cobra")
                self.assertEqual(info.status, expected)
                self.assertEqual(reg.info("cobra").status, BackendStatus.NOT_LOADED)

    def test_manifest_info_classifies_incompatible_without_loading_backend(self):
        load = Recorder(result=object())
        manifest = BackendManifest(
            name="cobra",
            api_version=PLUGIN_API_VERSION - 1,
            provides=load,
            implements={"mba-egraph": "EgglogOptimizer"},
        )
        reg = registry(
            [BackendSpec(name="cobra", origin="old", load_manifest=lambda: manifest)]
        )
        info = reg.implementation_manifest_info("cobra")
        self.assertEqual(info.status, BackendStatus.INCOMPATIBLE)
        self.assertEqual(load.calls, 0)

    def test_implementation_is_ready_only_after_exact_candidate_activation(self):
        activation = FakeActivation()
        plugin = FakePlugin(activation)
        manifest = self.manifest(
            {"mba-egraph": "EgglogOptimizer"}, provides=lambda: plugin
        )
        reg = BackendRegistry(
            source=lambda: (
                BackendSpec(
                    name="cobra", origin="test", load_manifest=lambda: manifest
                ),
            ),
            host_view_factory=lambda _requirements: FakeHost(),
            requirement_validator=lambda _requirements: None,
        )
        candidate = reg.require_unique_implementation(
            "mba-egraph", install_hint="d810-egglog"
        )
        reg.probe("cobra")
        self.assertFalse(reg.implementation_is_active(candidate))
        self.assertIs(reg.activate_implementation(candidate), activation.implementation)
        self.assertTrue(reg.implementation_is_active(candidate))


class TestLegacyDiscoveryRegressionContinued(unittest.TestCase):
    def test_empty_source_yields_no_backends(self):
        self.assertEqual(registry().names(), [])

    def test_discovery_does_not_import_the_target(self):
        load = Recorder()
        reg = registry([spec("acme", load)])
        self.assertEqual(reg.names(), ["acme"])
        self.assertEqual(load.calls, 0)

    def test_discovery_is_cached_until_forced(self):
        calls = []

        def source():
            calls.append(1)
            return []

        reg = BackendRegistry(builtins=(), source=source)
        reg.discover()
        reg.discover()
        self.assertEqual(len(calls), 1)
        reg.discover(force=True)
        self.assertEqual(len(calls), 2)

    def test_builtins_present_with_no_entry_points(self):
        load = Recorder()
        reg = registry(builtins=[spec("hexrays", load, origin="builtin")])
        self.assertEqual(reg.names(), ["hexrays"])
        self.assertEqual(reg.info("hexrays").origin, "builtin")

    def test_reload_prefixes_include_unavailable_provider_without_reprobe(self):
        load = Recorder(raises=ImportError("native binding unavailable"))
        manifest = BackendManifest(
            name="acme",
            api_version=PLUGIN_API_VERSION,
            provides=load,
            reload_modules=("acme_runtime",),
        )
        backend = BackendSpec(
            name="acme",
            origin="acme-dist",
            load_manifest=lambda: manifest,
            reload_modules=("company.acme_manifest",),
        )
        reg = registry([backend])
        self.assertEqual(reg.probe("acme").status, BackendStatus.UNAVAILABLE)
        self.assertEqual(
            reg.extension_reload_module_prefixes(),
            ("acme_runtime", "company.acme_manifest"),
        )
        self.assertEqual(load.calls, 1)

    def test_load_returns_object_and_caches_it(self):
        sentinel = object()
        load = Recorder(result=sentinel)
        reg = registry([spec("acme", load)])
        self.assertIs(reg.load("acme"), sentinel)
        self.assertIs(reg.load("acme"), sentinel)
        self.assertEqual(load.calls, 1)

    def test_unknown_name_raises_from_load_and_is_none_from_optional(self):
        reg = registry()
        with self.assertRaises(BackendUnavailable):
            reg.load("nope")
        self.assertIsNone(reg.optional("nope"))

    def test_info_on_unknown_name_raises_keyerror(self):
        with self.assertRaises(KeyError):
            registry().info("nope")

    def test_import_error_is_unavailable_not_broken(self):
        reg = registry([spec("z3", Recorder(raises=ImportError("no z3")))])
        info = reg.probe("z3")
        self.assertEqual(info.status, BackendStatus.UNAVAILABLE)
        self.assertIn("z3", info.reason)

    def test_other_exception_is_broken(self):
        reg = registry([spec("acme", Recorder(raises=AttributeError("typo")))])
        self.assertEqual(reg.probe("acme").status, BackendStatus.BROKEN)

    def test_failure_never_escapes_optional(self):
        reg = registry(
            [
                spec("a", Recorder(raises=ImportError("gone"))),
                spec("b", Recorder(raises=RuntimeError("boom"))),
            ]
        )
        self.assertIsNone(reg.optional("a"))
        self.assertIsNone(reg.optional("b"))

    def test_load_raises_with_underlying_cause_attached(self):
        cause = ImportError("libcobra missing")
        reg = registry([spec("cobra", Recorder(raises=cause))])
        with self.assertRaises(BackendUnavailable) as ctx:
            reg.load("cobra")
        self.assertIs(ctx.exception.__cause__, cause)

    def test_broken_plugin_does_not_break_probe_all(self):
        reg = registry(
            [
                spec("good", Recorder()),
                spec("bad", Recorder(raises=RuntimeError("boom"))),
            ]
        )
        by_name = {i.name: i.status for i in reg.probe_all()}
        self.assertEqual(by_name["good"], BackendStatus.AVAILABLE)
        self.assertEqual(by_name["bad"], BackendStatus.BROKEN)

    def test_source_explosion_degrades_to_builtins(self):
        def source():
            raise RuntimeError("corrupt dist-info")

        reg = BackendRegistry(
            builtins=(spec("hexrays", Recorder(), origin="builtin"),),
            source=source,
        )
        self.assertEqual(reg.names(), ["hexrays"])

    def test_incompatible_version_rejected_without_resolving_backend(self):
        load = Recorder()
        reg = registry([spec("old", load, api_version=PLUGIN_API_VERSION - 1)])
        info = reg.probe("old")
        self.assertEqual(info.status, BackendStatus.INCOMPATIBLE)
        self.assertEqual(load.calls, 0)
        self.assertIn(str(PLUGIN_API_VERSION), info.reason)
        self.assertIn("old", {i.name for i in reg.report()})

    def test_incompatible_backend_is_not_loadable(self):
        reg = registry([spec("old", Recorder(), api_version=0)])
        self.assertIsNone(reg.optional("old"))
        with self.assertRaises(BackendUnavailable):
            reg.load("old")

    def test_version_is_unknown_until_probed(self):
        reg = registry([spec("acme", Recorder())])
        self.assertIsNone(reg.info("acme").api_version)
        self.assertEqual(reg.probe("acme").api_version, PLUGIN_API_VERSION)

    def test_probe_hook_returning_reason_marks_unavailable(self):
        class Backend:
            @staticmethod
            def d810_backend_probe():
                return "native binding unavailable"

        reg = registry([spec("cobra", Recorder(result=Backend))])
        info = reg.probe("cobra")
        self.assertEqual(info.status, BackendStatus.UNAVAILABLE)
        self.assertIn("native", info.reason)

    def test_probe_hook_returning_none_marks_available(self):
        class Backend:
            @staticmethod
            def d810_backend_probe():
                return None

        reg = registry([spec("cobra", Recorder(result=Backend))])
        self.assertEqual(reg.probe("cobra").status, BackendStatus.AVAILABLE)
        self.assertIs(reg.optional("cobra"), Backend)

    def test_probe_hook_raising_is_broken(self):
        class Backend:
            @staticmethod
            def d810_backend_probe():
                raise ValueError("bad probe")

        reg = registry([spec("acme", Recorder(result=Backend))])
        self.assertEqual(reg.probe("acme").status, BackendStatus.BROKEN)

    def test_probe_all_returns_ground_truth_for_every_backend(self):
        reg = registry(
            [
                spec("good", Recorder()),
                spec("missing", Recorder(raises=ImportError("nope"))),
            ]
        )
        by_name = {i.name: i.status for i in reg.probe_all()}
        self.assertEqual(
            by_name,
            {"good": BackendStatus.AVAILABLE, "missing": BackendStatus.UNAVAILABLE},
        )

    def test_entry_point_overrides_builtin_and_conflict_is_reported(self):
        builtin = Recorder()
        external = Recorder()
        reg = registry(
            specs=[spec("cobra", external, origin="d810-cobra 1.0")],
            builtins=[spec("cobra", builtin, origin="builtin")],
        )
        self.assertIs(reg.load("cobra"), external.result)
        self.assertEqual(builtin.calls, 0)
        info = reg.info("cobra")
        self.assertEqual(info.origin, "d810-cobra 1.0")
        self.assertEqual(info.shadowed, ("builtin",))

    def test_unusable_entry_point_falls_back_to_builtin(self):
        in_tree = Recorder()
        reg = registry(
            specs=[spec("cobra", Recorder(), api_version=99, origin="ext 0.1")],
            builtins=[spec("cobra", in_tree, origin="builtin")],
        )
        self.assertIs(reg.load("cobra"), in_tree.result)
        info = reg.info("cobra")
        self.assertEqual(info.status, BackendStatus.AVAILABLE)
        self.assertEqual(info.origin, "builtin")

    def test_falling_back_surfaces_rejected_candidate(self):
        reg = registry(
            specs=[spec("cobra", Recorder(), api_version=99, origin="ext 0.1")],
            builtins=[spec("cobra", Recorder(), origin="builtin")],
        )
        info = reg.probe("cobra")
        self.assertEqual([origin for origin, _ in info.rejected], ["ext 0.1"])
        self.assertIn("v99", info.rejected[0][1])
        self.assertTrue(has_defects([info]))

    def test_fallback_does_not_report_itself_as_shadowed(self):
        reg = registry(
            specs=[spec("cobra", Recorder(), api_version=99, origin="ext 0.1")],
            builtins=[spec("cobra", Recorder(), origin="builtin")],
        )
        info = reg.probe("cobra")
        self.assertEqual(info.origin, "builtin")
        self.assertEqual(info.shadowed, ())

    def test_all_candidates_unusable_reports_last_failure(self):
        reg = registry(
            specs=[spec("cobra", Recorder(), api_version=99, origin="ext 0.1")],
            builtins=[
                spec(
                    "cobra",
                    Recorder(raises=ImportError("no _cobra")),
                    origin="builtin",
                )
            ],
        )
        info = reg.probe("cobra")
        self.assertEqual(info.status, BackendStatus.UNAVAILABLE)
        self.assertIn("_cobra", info.reason)
        self.assertEqual([o for o, _ in info.rejected], ["ext 0.1"])

    def test_report_is_sorted_and_typed(self):
        reg = registry([spec("zeta", Recorder()), spec("alpha", Recorder())])
        report = reg.report()
        self.assertEqual([i.name for i in report], ["alpha", "zeta"])
        self.assertTrue(all(isinstance(i, BackendInfo) for i in report))

    def test_report_does_not_import_unloaded_backends(self):
        load = Recorder()
        registry([spec("acme", load)]).report()
        self.assertEqual(load.calls, 0)


class TestBuiltinBackendsRegression(unittest.TestCase):
    EXPECTED = {
        "mba.z3",
        "emulation.triton",
        "emulation.unicorn",
        "ast.z3",
        "llvm",
    }

    def make(self):
        from d810.backends import BUILTIN_BACKENDS

        return BackendRegistry(builtins=BUILTIN_BACKENDS, source=lambda: [])

    def test_expected_backends_are_registered(self):
        self.assertEqual(set(self.make().names()), self.EXPECTED)

    def test_no_builtin_is_broken(self):
        broken = [
            (info.name, info.reason)
            for info in self.make().probe_all()
            if info.status is BackendStatus.BROKEN
        ]
        self.assertEqual(broken, [])

    def test_every_builtin_settles_with_a_reason_when_unusable(self):
        for info in self.make().probe_all():
            with self.subTest(backend=info.name):
                self.assertNotEqual(info.status, BackendStatus.NOT_LOADED)
                if info.status is BackendStatus.UNAVAILABLE:
                    self.assertTrue(info.reason)


if __name__ == "__main__":
    unittest.main()
