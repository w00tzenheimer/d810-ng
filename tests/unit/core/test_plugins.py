"""Tests for the d810 backend plugin protocol.

The protocol exists so an out-of-tree distribution (e.g. ``d810-cobra``)
can supply a backend without d810 knowing its name at build time, while the
in-tree backends keep working in the deployment d810 actually ships in: a
symlink into a source checkout, where installed dist metadata may describe a
*different version* than the code being executed.

That deployment is why builtins are a static table and entry points are an
additive overlay -- see ``test_builtins_present_with_no_entry_points``.
"""

import unittest

from d810.core.plugins import (
    PLUGIN_API_VERSION,
    BackendInfo,
    BackendRegistry,
    BackendSpec,
    BackendStatus,
    BackendManifest,
    BackendUnavailable,
    ENTRY_POINT_GROUP,
    ManifestError,
    PassImplementationAmbiguous,
    PassImplementationCandidate,
    PassImplementationMisdeclared,
    PassImplementationMissing,
    PluginCapabilityOffer,
    format_report,
    has_defects,
    manifest_of,
    offers_capability,
)


class Recorder:
    """A load thunk that records whether it ran, and can fail on demand."""

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
    """A discovered backend whose manifest is already resolvable.

    ``provides`` accepts a callable as well as an import string so tests can
    hand over a Recorder without going through the import machinery.
    """
    manifest = BackendManifest(name=name, api_version=api_version, provides=load)
    return BackendSpec(name=name, origin=origin, load_manifest=lambda: manifest)


def registry(specs=(), builtins=()):
    """A registry whose discovery source is injected, so no packages install."""
    return BackendRegistry(builtins=tuple(builtins), source=lambda: list(specs))


class TestGroupNaming(unittest.TestCase):
    def test_group_carries_no_version(self):
        # The group name is stable forever; the version is declared by the
        # extension's manifest. Encoding it here would churn the group on every
        # protocol bump and force every extension author to notice.
        self.assertEqual(ENTRY_POINT_GROUP, "d810.backends")
        self.assertNotIn("v1", ENTRY_POINT_GROUP)


class TestDiscovery(unittest.TestCase):
    def test_empty_source_yields_no_backends(self):
        self.assertEqual(registry().names(), [])

    def test_discovery_does_not_import_the_target(self):
        load = Recorder()
        reg = registry([spec("acme", load)])
        self.assertEqual(reg.names(), ["acme"])
        self.assertEqual(load.calls, 0, "discovery must not import the plugin")
        self.assertEqual(reg.info("acme").status, BackendStatus.NOT_LOADED)

    def test_discovery_is_cached_until_forced(self):
        calls = []

        def source():
            calls.append(1)
            return []

        reg = BackendRegistry(builtins=(), source=source)
        reg.discover()
        reg.discover()
        self.assertEqual(len(calls), 1, "30ms scan must not repeat")
        reg.discover(force=True)
        self.assertEqual(len(calls), 2)

    def test_builtins_present_with_no_entry_points(self):
        # d810 runs as a symlinked plugin where dist metadata may be absent or
        # stale. Builtins must not depend on it.
        load = Recorder()
        reg = registry(specs=[], builtins=[spec("hexrays", load, origin="builtin")])
        self.assertEqual(reg.names(), ["hexrays"])
        self.assertEqual(reg.info("hexrays").origin, "builtin")

    def test_reload_prefixes_include_an_unavailable_provider_without_reprobe(self):
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
        self.assertEqual(load.calls, 1)

        self.assertEqual(
            reg.extension_reload_module_prefixes(),
            ("acme_runtime", "company.acme_manifest"),
        )
        self.assertEqual(load.calls, 1, "reload discovery must not reprobe provides")


class TestLoading(unittest.TestCase):
    def test_load_returns_the_object_and_caches_it(self):
        sentinel = object()
        load = Recorder(result=sentinel)
        reg = registry([spec("acme", load)])
        self.assertIs(reg.load("acme"), sentinel)
        self.assertIs(reg.load("acme"), sentinel)
        self.assertEqual(load.calls, 1, "load must be memoised")
        self.assertEqual(reg.info("acme").status, BackendStatus.AVAILABLE)

    def test_unknown_name_raises_from_load_and_is_none_from_optional(self):
        reg = registry()
        with self.assertRaises(BackendUnavailable):
            reg.load("nope")
        self.assertIsNone(reg.optional("nope"))

    def test_info_on_unknown_name_raises_keyerror(self):
        with self.assertRaises(KeyError):
            registry().info("nope")


class TestFailureClassification(unittest.TestCase):
    """A missing optional dep and a buggy plugin are NOT the same event.

    The hand-rolled ``try/except ImportError`` pattern this replaces collapses
    them, which is how a backend that raises AttributeError on import gets
    silently reported as "not installed".
    """

    def test_import_error_is_unavailable_not_broken(self):
        load = Recorder(raises=ImportError("no module named 'z3'"))
        reg = registry([spec("z3", load)])
        info = reg.probe("z3")
        self.assertEqual(info.status, BackendStatus.UNAVAILABLE)
        self.assertIn("z3", info.reason)

    def test_other_exception_is_broken(self):
        load = Recorder(raises=AttributeError("typo in plugin"))
        reg = registry([spec("acme", load)])
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

    def test_load_raises_with_the_underlying_cause_attached(self):
        cause = ImportError("libcobra missing")
        reg = registry([spec("cobra", Recorder(raises=cause))])
        with self.assertRaises(BackendUnavailable) as ctx:
            reg.load("cobra")
        self.assertIs(ctx.exception.__cause__, cause)

    def test_a_broken_plugin_does_not_break_probe_all(self):
        # A third-party plugin exploding must degrade only itself. Anything
        # else means one bad install takes the whole plugin down.
        reg = registry(
            [
                spec("good", Recorder()),
                spec("bad", Recorder(raises=RuntimeError("boom"))),
            ]
        )
        by_name = {i.name: i.status for i in reg.probe_all()}
        self.assertEqual(by_name["good"], BackendStatus.AVAILABLE)
        self.assertEqual(by_name["bad"], BackendStatus.BROKEN)

    def test_a_source_that_explodes_degrades_to_builtins(self):
        # importlib.metadata can raise on a corrupt dist-info in site-packages.
        def source():
            raise RuntimeError("corrupt dist-info")

        reg = BackendRegistry(
            builtins=(spec("hexrays", Recorder(), origin="builtin"),), source=source
        )
        self.assertEqual(reg.names(), ["hexrays"])


class TestVersionGate(unittest.TestCase):
    """The version is declared by the extension's manifest, not the group name.

    The manifest is contractually cheap to import, so reading it costs a
    dataclass literal -- and the heavy half (native extension, z3, ...) is
    never touched for a plugin we are about to reject.
    """

    def test_incompatible_version_rejected_without_resolving_the_backend(self):
        load = Recorder()
        reg = registry([spec("old", load, api_version=PLUGIN_API_VERSION - 1)])
        info = reg.probe("old")
        self.assertEqual(info.status, BackendStatus.INCOMPATIBLE)
        self.assertEqual(load.calls, 0, "heavy half must never be resolved")
        self.assertIn(str(PLUGIN_API_VERSION), info.reason)
        # Reported, not silently dropped: a user with a stale plugin installed
        # needs to be told, not left wondering why nothing happens.
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


class TestManifest(unittest.TestCase):
    """A manifest may be declared with or without importing d810.

    ``BackendManifest`` gives a typed declaration; a plain mapping or any
    object with the three fields works identically, so an extension that wants
    no import-time dependency on d810 can have one. Both are supported because
    supporting both costs one coercion function.
    """

    def test_default_implementation_maps_are_immutable_and_instance_local(self):
        first = BackendManifest("first", PLUGIN_API_VERSION, "pkg:first")
        second = BackendManifest("second", PLUGIN_API_VERSION, "pkg:second")

        self.assertEqual(first.implements, {})
        self.assertEqual(second.implements, {})
        self.assertIsNot(first.implements, second.implements)
        with self.assertRaises(TypeError):
            first.implements["mba-egraph"] = "EgglogOptimizer"  # type: ignore[index]

    def test_plain_dict_is_a_valid_manifest(self):
        got = manifest_of({"name": "acme", "api_version": 1, "provides": "pkg:obj"})
        self.assertEqual((got.name, got.api_version, got.provides),
                         ("acme", 1, "pkg:obj"))

    def test_plain_manifest_accepts_explicit_reload_module_prefixes(self):
        got = manifest_of(
            {
                "name": "acme",
                "api_version": 1,
                "provides": "pkg:obj",
                "reload_modules": ("company.d810", "acme_runtime"),
            }
        )
        self.assertEqual(
            got.reload_modules,
            ("company.d810", "acme_runtime"),
        )

    def test_any_object_with_the_fields_is_a_valid_manifest(self):
        class Declared:
            name = "acme"
            api_version = 1
            provides = "pkg:obj"

        self.assertEqual(manifest_of(Declared).api_version, 1)

    def test_manifest_missing_api_version_is_broken_with_a_clear_reason(self):
        bad = BackendSpec(
            name="acme",
            origin="test",
            load_manifest=lambda: {"name": "acme", "provides": "pkg:obj"},
        )
        info = BackendRegistry(source=lambda: [bad]).probe("acme")
        self.assertEqual(info.status, BackendStatus.BROKEN)
        self.assertIn("api_version", info.reason)

    def test_manifest_that_fails_to_import_is_unavailable(self):
        bad = BackendSpec(
            name="acme",
            origin="test",
            load_manifest=Recorder(raises=ImportError("no d810_backend_acme")),
        )
        info = BackendRegistry(source=lambda: [bad]).probe("acme")
        self.assertEqual(info.status, BackendStatus.UNAVAILABLE)
        self.assertIn("d810_backend_acme", info.reason)

    def test_manifest_is_not_imported_during_discovery(self):
        load_manifest = Recorder(
            result=BackendManifest("acme", PLUGIN_API_VERSION, lambda: object())
        )
        reg = BackendRegistry(
            source=lambda: [
                BackendSpec(name="acme", origin="test", load_manifest=load_manifest)
            ]
        )
        self.assertEqual(reg.names(), ["acme"])
        reg.report()
        self.assertEqual(load_manifest.calls, 0, "discovery and report stay free")
        reg.probe("acme")
        self.assertEqual(load_manifest.calls, 1)


class TestBackendProbeHook(unittest.TestCase):
    """A backend that imports but cannot work must be able to say so.

    This is the CoBRA case exactly: the Python package imports fine while the
    compiled ``_cobra`` extension is absent, which today shows up only as a
    private module flag and produces a wheel that installs and silently does
    nothing.
    """

    def test_probe_hook_returning_reason_marks_unavailable(self):
        class Backend:
            @staticmethod
            def d810_backend_probe():
                return "native _cobra extension not built"

        reg = registry([spec("cobra", Recorder(result=Backend))])
        info = reg.probe("cobra")
        self.assertEqual(info.status, BackendStatus.UNAVAILABLE)
        self.assertIn("_cobra", info.reason)
        self.assertIsNone(reg.optional("cobra"))

    def test_probe_hook_returning_none_marks_available(self):
        class Backend:
            @staticmethod
            def d810_backend_probe():
                return None

        reg = registry([spec("cobra", Recorder(result=Backend))])
        self.assertEqual(reg.probe("cobra").status, BackendStatus.AVAILABLE)
        self.assertIs(reg.optional("cobra"), Backend)

    def test_probe_hook_raising_is_broken_not_a_crash(self):
        class Backend:
            @staticmethod
            def d810_backend_probe():
                raise ValueError("bad probe")

        reg = registry([spec("acme", Recorder(result=Backend))])
        self.assertEqual(reg.probe("acme").status, BackendStatus.BROKEN)

    def test_backend_without_probe_hook_is_available_once_imported(self):
        reg = registry([spec("plain", Recorder(result=object()))])
        self.assertEqual(reg.probe("plain").status, BackendStatus.AVAILABLE)

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


class TestShadowing(unittest.TestCase):
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

    def test_no_conflict_means_no_shadowed_entry(self):
        reg = registry([spec("acme", Recorder())])
        self.assertEqual(reg.info("acme").shadowed, ())

    def test_unusable_entry_point_falls_back_to_the_builtin(self):
        """A stale third-party plugin must not disable a working builtin.

        Found by installing a real dist declaring api_version 99: it won the
        name, failed the version gate, and took cobra down with it.
        """
        in_tree = Recorder()
        reg = registry(
            specs=[spec("cobra", Recorder(), api_version=99, origin="ext 0.1")],
            builtins=[spec("cobra", in_tree, origin="builtin")],
        )
        self.assertIs(reg.load("cobra"), in_tree.result)

        info = reg.info("cobra")
        self.assertEqual(info.status, BackendStatus.AVAILABLE)
        self.assertEqual(info.origin, "builtin")

    def test_falling_back_still_surfaces_the_rejected_candidate(self):
        # Degrading silently would be the same class of bug as the wheel that
        # installs cleanly and simplifies nothing.
        reg = registry(
            specs=[spec("cobra", Recorder(), api_version=99, origin="ext 0.1")],
            builtins=[spec("cobra", Recorder(), origin="builtin")],
        )
        info = reg.probe("cobra")
        self.assertEqual([origin for origin, _ in info.rejected], ["ext 0.1"])
        self.assertIn("v99", info.rejected[0][1])
        self.assertTrue(has_defects([info]), "a rejected candidate is a defect")

    def test_fallback_does_not_report_itself_as_shadowed(self):
        # "available  builtin (shadows builtin)" -- shadowed must be relative to
        # whichever candidate actually settled, not a fixed offset.
        reg = registry(
            specs=[spec("cobra", Recorder(), api_version=99, origin="ext 0.1")],
            builtins=[spec("cobra", Recorder(), origin="builtin")],
        )
        info = reg.probe("cobra")
        self.assertEqual(info.origin, "builtin")
        self.assertEqual(info.shadowed, (), "nothing remains below the builtin")

    def test_a_healthy_backend_has_no_rejected_candidates(self):
        reg = registry([spec("acme", Recorder())])
        info = reg.probe("acme")
        self.assertEqual(info.rejected, ())
        self.assertFalse(has_defects([info]))

    def test_all_candidates_unusable_reports_the_last_failure_and_lists_the_rest(self):
        reg = registry(
            specs=[spec("cobra", Recorder(), api_version=99, origin="ext 0.1")],
            builtins=[
                spec("cobra", Recorder(raises=ImportError("no _cobra")),
                     origin="builtin")
            ],
        )
        info = reg.probe("cobra")
        self.assertEqual(info.status, BackendStatus.UNAVAILABLE)
        self.assertIn("_cobra", info.reason)
        self.assertEqual([o for o, _ in info.rejected], ["ext 0.1"])


class TestReport(unittest.TestCase):
    def test_report_is_sorted_and_typed(self):
        reg = registry([spec("zeta", Recorder()), spec("alpha", Recorder())])
        report = reg.report()
        self.assertEqual([i.name for i in report], ["alpha", "zeta"])
        self.assertTrue(all(isinstance(i, BackendInfo) for i in report))

    def test_report_does_not_import_unloaded_backends(self):
        load = Recorder()
        reg = registry([spec("acme", load)])
        reg.report()
        self.assertEqual(load.calls, 0, "report must stay cheap")


class TestPluginCapabilityOffer(unittest.TestCase):
    """A backend declares which capability Protocols it can satisfy.

    Typed, not stringly: the offer carries the Protocol *class*, so a type
    checker verifies at the plugin author's site that the factory returns
    something of that type. An earlier draft used import strings for laziness --
    unnecessary, because a closure defers the heavy import just as well while
    staying checkable.
    """

    def test_offer_carries_the_protocol_and_a_factory(self):
        class Thing:
            pass

        def make(source):
            return Thing()

        offer = PluginCapabilityOffer(Thing, make)
        self.assertIs(offer.capability, Thing)
        self.assertIs(offer.factory, make)

    def test_offers_capability_builds_an_equivalent_offer(self):
        """The curried form is what plugin authors should use.

        Verified with pyright that bare ``PluginCapabilityOffer(Cap, factory)``
        does NOT flag a factory returning the wrong type -- C is solved from
        both arguments and widens to a union. Currying pins C from the
        capability, so the factory is checked. Runtime shape must match.
        """

        class Thing:
            pass

        def make(source):
            return Thing()

        offer = offers_capability(Thing)(make)
        self.assertIsInstance(offer, PluginCapabilityOffer)
        self.assertIs(offer.capability, Thing)
        self.assertIs(offer.factory, make)

    def test_offers_capability_works_as_a_decorator(self):
        class Thing:
            pass

        @offers_capability(Thing)
        def make(source):
            return Thing()

        self.assertIsInstance(make, PluginCapabilityOffer)
        self.assertIs(make.capability, Thing)

    def test_manifest_defaults_to_no_offers(self):
        manifest = BackendManifest("acme", PLUGIN_API_VERSION, "pkg:obj")
        self.assertEqual(manifest.capabilities, ())

    def test_manifest_carries_offers_through_coercion(self):
        class Thing:
            pass

        offer = PluginCapabilityOffer(Thing, lambda source: Thing())
        got = manifest_of(
            {
                "name": "acme",
                "api_version": PLUGIN_API_VERSION,
                "provides": "pkg:obj",
                "capabilities": [offer],
            }
        )
        self.assertEqual(got.capabilities, (offer,))

    def test_a_non_offer_in_capabilities_is_a_manifest_error(self):
        # Catch it at declaration, not deep inside a pass.
        with self.assertRaises(ManifestError) as ctx:
            manifest_of(
                {
                    "name": "acme",
                    "api_version": PLUGIN_API_VERSION,
                    "provides": "pkg:obj",
                    "capabilities": ["d810.capabilities.x:Y"],
                }
            )
        self.assertIn("PluginCapabilityOffer", str(ctx.exception))

    def test_the_factory_is_not_called_at_declaration_time(self):
        class Thing:
            pass

        factory = Recorder(result=Thing())
        manifest = BackendManifest(
            "acme", PLUGIN_API_VERSION, "pkg:obj",
            capabilities=(PluginCapabilityOffer(Thing, factory),),
        )
        self.assertEqual(factory.calls, 0, "the heavy import must stay deferred")
        self.assertEqual(len(manifest.capabilities), 1)


class TestRegistryCapabilityOffers(unittest.TestCase):
    def make(self, *, api_version=PLUGIN_API_VERSION, offers=()):
        class Backend:
            pass

        manifest = BackendManifest(
            name="acme",
            api_version=api_version,
            provides=lambda: Backend,
            capabilities=tuple(offers),
        )
        return BackendRegistry(
            source=lambda: [
                BackendSpec(name="acme", origin="test", load_manifest=lambda: manifest)
            ]
        )

    def test_offers_come_only_from_usable_backends(self):
        class Thing:
            pass

        offer = PluginCapabilityOffer(Thing, lambda source: Thing())
        self.assertEqual(self.make(offers=[offer]).capability_offers(), (offer,))

    def test_an_incompatible_backend_offers_nothing(self):
        class Thing:
            pass

        offer = PluginCapabilityOffer(Thing, lambda source: Thing())
        reg = self.make(api_version=PLUGIN_API_VERSION + 1, offers=[offer])
        self.assertEqual(reg.capability_offers(), ())

    def test_an_unusable_backend_offers_nothing(self):
        """The case that actually exercises the usability gate.

        An INCOMPATIBLE backend is rejected before its manifest is even
        recorded, so it would yield no offers regardless. A version-compatible
        backend whose probe reports it cannot run DOES get its manifest read --
        only the usability check keeps its capabilities out of the pipeline.
        """

        class Thing:
            pass

        class Backend:
            @staticmethod
            def d810_backend_probe():
                return "native half missing"

        offer = PluginCapabilityOffer(Thing, lambda source: Thing())
        manifest = BackendManifest(
            name="acme",
            api_version=PLUGIN_API_VERSION,
            provides=lambda: Backend,
            capabilities=(offer,),
        )
        reg = BackendRegistry(
            source=lambda: [
                BackendSpec(name="acme", origin="test", load_manifest=lambda: manifest)
            ]
        )
        self.assertEqual(reg.probe("acme").status, BackendStatus.UNAVAILABLE)
        self.assertEqual(reg.capability_offers(), ())

    def test_no_offers_is_an_empty_tuple_not_none(self):
        self.assertEqual(self.make().capability_offers(), ())


class TestHealth(unittest.TestCase):
    """Which states are a *defect* vs a normal deployment fact.

    This is the rule a CI health check keys off, so it lives beside the status
    model rather than in whatever tool happens to print it.
    """

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
                [
                    self.info(BackendStatus.AVAILABLE),
                    self.info(BackendStatus.BROKEN),
                ]
            )
        )


class TestFormatReport(unittest.TestCase):
    def test_report_names_status_origin_and_reason(self):
        text = format_report(
            [
                BackendInfo(
                    name="cobra",
                    status=BackendStatus.UNAVAILABLE,
                    origin="builtin",
                    api_version=PLUGIN_API_VERSION,
                    reason="native _cobra extension not built",
                )
            ]
        )
        for fragment in ("cobra", "unavailable", "builtin", "_cobra"):
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

    def test_empty_report_is_not_a_crash(self):
        self.assertIsInstance(format_report([]), str)

    def test_report_explains_a_fallback(self):
        # has_defects() makes the CLI exit 1 here, so the text must say why.
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


class TestBuiltinBackends(unittest.TestCase):
    """Every in-tree backend registers, so the protocol cannot rot.

    One registered backend would exercise one code path; these keep the whole
    thing honest and turn six hand-rolled ``X_AVAILABLE`` flags into one
    reportable surface.
    """

    #: ``cobra`` is deliberately NOT here: it ships as the separate
    #: distribution ``d810-cobra`` and arrives via the entry point, so
    #: asserting it as a builtin would fail on any machine without that package
    #: installed -- and pass for the wrong reason on one that has it.
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
        """BROKEN means a defect, and flips `d810cli backends` to exit 1.

        An absent optional dependency must classify as UNAVAILABLE; anything
        reaching BROKEN here is an in-tree bug, not a deployment fact.
        """
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
                    self.assertTrue(info.reason, "UNAVAILABLE needs a reason")

    def test_probe_hooks_agree_with_the_legacy_flags(self):
        """Backwards compatible: the old flags stay and remain authoritative.

        Only backends importable outside IDA are checked here; ``ast.z3`` needs
        ``ida_hexrays`` to import at all.
        """
        import importlib

        cases = [
            ("d810.backends.mba.z3", "Z3_INSTALLED"),
            ("d810.backends.emulation.triton", "TRITON_AVAILABLE"),
            ("d810.backends.emulation.unicorn", "UNICORN_AVAILABLE"),
        ]
        for target, flag in cases:
            module = importlib.import_module(target)
            with self.subTest(backend=target):
                self.assertTrue(
                    callable(getattr(module, "d810_backend_probe", None)),
                    f"{target} must expose the protocol hook",
                )
                usable = module.d810_backend_probe() is None
                self.assertIs(usable, getattr(module, flag))

    def test_unavailable_dependency_is_named_in_the_reason(self):
        """"unavailable" with no dependency name is useless to a user."""
        import importlib

        for target, dep in [
            ("d810.backends.emulation.triton", "triton"),
            ("d810.backends.emulation.unicorn", "unicorn"),
            ("d810.backends.mba.z3", "z3"),
        ]:
            module = importlib.import_module(target)
            reason = module.d810_backend_probe()
            if reason is not None:
                with self.subTest(backend=target):
                    self.assertIn(dep, reason.lower())


class TestExtensionRuleModules(unittest.TestCase):
    """A backend must be able to contribute optimizer rules from its own package.

    d810 loads rules by scanning ``d810.optimizers.__path__`` and letting
    ``Registrant`` self-register on import. That scan is path-scoped, so a rule
    shipped by an installed extension is never imported and never registers --
    the backend reports ``available`` while its pass silently does nothing,
    which is indistinguishable from the pass simply not firing.

    Manifests therefore declare their rule modules, and the registry hands back
    only those belonging to backends that actually probed AVAILABLE: importing
    the rule module of a backend whose binding is missing would register a rule
    that cannot work.
    """

    def test_available_backend_contributes_its_rule_modules(self):
        manifest = BackendManifest(
            name="cobra",
            api_version=PLUGIN_API_VERSION,
            provides=Recorder(result=object()),
            rules=("acme_ext.rules.solve",),
        )
        reg = registry(
            [BackendSpec(name="cobra", origin="test", load_manifest=lambda: manifest)]
        )
        self.assertEqual(reg.rule_modules(), ("acme_ext.rules.solve",))

    def test_unavailable_backend_contributes_nothing(self):
        class Backend:
            @staticmethod
            def d810_backend_probe():
                return "native extension not built"

        manifest = BackendManifest(
            name="cobra",
            api_version=PLUGIN_API_VERSION,
            provides=Recorder(result=Backend),
            rules=("acme_ext.rules.solve",),
        )
        reg = registry(
            [BackendSpec(name="cobra", origin="test", load_manifest=lambda: manifest)]
        )
        self.assertEqual(reg.rule_modules(), ())

    def test_rules_are_optional_and_default_empty(self):
        """Backends that ship no rules must not have to say so."""
        reg = registry([spec("plain", Recorder(result=object()))])
        self.assertEqual(reg.rule_modules(), ())

    def test_duck_typed_manifest_may_declare_rules(self):
        """An extension must not need to import BackendManifest to do this."""
        raw = {
            "name": "cobra",
            "api_version": PLUGIN_API_VERSION,
            "provides": Recorder(result=object()),
            "rules": ["acme_ext.rules.solve"],
        }
        reg = registry(
            [BackendSpec(name="cobra", origin="test", load_manifest=lambda: raw)]
        )
        self.assertEqual(reg.rule_modules(), ("acme_ext.rules.solve",))


class TestPassImplementations(unittest.TestCase):
    """Which rule implements a pass is the EXTENSION's declaration, not d810's.

    d810 derives a pass's ``allowed_rule_names`` from its stage descriptors, and
    a rule outside that allowlist is skipped at dispatch. Naming the class in
    d810 -- ``MBA_SOLVE_IMPLEMENTATION = "CobraSolveRule"`` -- meant core code
    hardcoding one vendor's class, so d810 could not host a second solver and
    the extraction left the coupling behind.

    Read from the manifest, which the registry already parses to gate versions,
    so this costs no extra import: the backend's heavy half stays untouched.
    """

    def manifest(self, implements, *, rules=(), provides=None):
        return BackendManifest(
            name="cobra",
            api_version=PLUGIN_API_VERSION,
            provides=provides if provides is not None else Recorder(result=object()),
            rules=rules,
            implements=implements,
        )

    def test_declared_implementation_is_found_by_pass_id(self):
        reg = registry(
            [
                BackendSpec(
                    name="cobra",
                    origin="test",
                    load_manifest=lambda: self.manifest({"mba-solve": "CobraSolveRule"}),
                )
            ]
        )
        self.assertEqual(reg.implementation_for("mba-solve"), "CobraSolveRule")

    def test_no_extension_means_no_implementation(self):
        """d810 alone ships no solver, and must say so rather than guess."""
        self.assertIsNone(registry().implementation_for("mba-solve"))

    def test_unrelated_pass_id_is_not_matched(self):
        reg = registry(
            [
                BackendSpec(
                    name="cobra",
                    origin="test",
                    load_manifest=lambda: self.manifest({"mba-solve": "CobraSolveRule"}),
                )
            ]
        )
        self.assertIsNone(reg.implementation_for("unflatten"))

    def test_duck_typed_manifest_may_declare_implementations(self):
        raw = {
            "name": "cobra",
            "api_version": PLUGIN_API_VERSION,
            "provides": Recorder(result=object()),
            "implements": {"mba-solve": "CobraSolveRule"},
        }
        reg = registry(
            [BackendSpec(name="cobra", origin="test", load_manifest=lambda: raw)]
        )
        self.assertEqual(reg.implementation_for("mba-solve"), "CobraSolveRule")

    def test_typed_and_mapping_manifests_reject_malformed_implementations(self):
        malformed = (
            ("non-string pass id", {1: "Rule"}),
            ("empty pass id", {"": "Rule"}),
            ("non-string rule name", {"mba-egraph": object()}),
            ("empty rule name", {"mba-egraph": ""}),
        )
        for label, implements in malformed:
            for kind in ("typed", "mapping"):
                with self.subTest(label=label, kind=kind):
                    if kind == "typed":
                        manifest = BackendManifest(
                            name="cobra",
                            api_version=PLUGIN_API_VERSION,
                            provides=Recorder(result=object()),
                            rules=("acme.rules.egraph",),
                            implements=implements,
                        )
                    else:
                        manifest = {
                            "name": "cobra",
                            "api_version": PLUGIN_API_VERSION,
                            "provides": Recorder(result=object()),
                            "rules": ("acme.rules.egraph",),
                            "implements": implements,
                        }
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
        """The whole point of manifest indirection: no heavy half, no IDA."""
        load = Recorder(result=object())
        manifest = BackendManifest(
            name="cobra",
            api_version=PLUGIN_API_VERSION,
            provides=load,
            implements={"mba-solve": "CobraSolveRule"},
        )
        reg = registry(
            [BackendSpec(name="cobra", origin="test", load_manifest=lambda: manifest)]
        )
        reg.implementation_for("mba-solve")
        self.assertEqual(load.calls, 0, "reading a manifest must not import the backend")

    def test_an_incompatible_backend_contributes_no_implementation(self):
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

    def test_first_compatible_mba_solve_declaration_remains_the_legacy_answer(self):
        """The strict mba-egraph path must not change mba-solve semantics."""
        first = self.manifest({"mba-solve": "FirstSolver"})
        second = self.manifest({"mba-solve": "SecondSolver"})
        reg = registry(
            [
                BackendSpec(name="first", origin="first-origin", load_manifest=lambda: first),
                BackendSpec(name="second", origin="second-origin", load_manifest=lambda: second),
            ]
        )

        self.assertEqual(reg.implementation_for("mba-solve"), "FirstSolver")

    def test_compatible_manifest_produces_an_immutable_candidate(self):
        manifest = self.manifest(
            {"mba-egraph": "EgglogOptimizer"},
            rules=("acme.rules.first", "acme.rules.second"),
        )
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
                    rule_modules=("acme.rules.first", "acme.rules.second"),
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
            rules=("acme.rules.solve",),
            implements={"mba-egraph": "EgglogOptimizer"},
        )
        reg = registry(
            [BackendSpec(name="cobra", origin="old", load_manifest=lambda: manifest)]
        )

        self.assertEqual(reg.implementation_candidates_for("mba-egraph"), ())
        self.assertEqual(load.calls, 0)

    def test_two_compatible_declarations_are_ambiguous_in_deterministic_order(self):
        first = self.manifest(
            {"mba-egraph": "FirstRule"},
            rules=("first.rules",),
        )
        second = self.manifest(
            {"mba-egraph": "SecondRule"},
            rules=("second.rules",),
        )
        reg = registry(
            [
                BackendSpec(name="zeta", origin="z-origin", load_manifest=lambda: second),
                BackendSpec(name="acme", origin="a-origin", load_manifest=lambda: first),
            ]
        )

        with self.assertRaises(PassImplementationAmbiguous) as ctx:
            reg.require_unique_implementation("mba-egraph", install_hint="d810-egglog")

        self.assertEqual(
            [candidate.backend_origin for candidate in ctx.exception.candidates],
            ["a-origin", "z-origin"],
        )
        self.assertIn("a-origin", str(ctx.exception))
        self.assertIn("z-origin", str(ctx.exception))

    def test_no_declaration_reports_install_hint(self):
        with self.assertRaises(PassImplementationMissing) as ctx:
            registry().require_unique_implementation(
                "mba-egraph", install_hint="d810-egglog"
            )

        self.assertIn("install d810-egglog", str(ctx.exception))

    def test_implementation_without_rule_modules_is_misdeclared(self):
        manifest = self.manifest({"mba-egraph": "EgglogOptimizer"})
        reg = registry(
            [BackendSpec(name="cobra", origin="test", load_manifest=lambda: manifest)]
        )

        with self.assertRaises(PassImplementationMisdeclared):
            reg.implementation_candidates_for("mba-egraph")

    def test_typed_manifest_with_malformed_rules_is_misdeclared(self):
        """Runtime callers can bypass dataclass annotations; validate anyway."""
        manifest = BackendManifest(
            name="cobra",
            api_version=PLUGIN_API_VERSION,
            provides=Recorder(result=object()),
            rules="bad",
            implements={"mba-egraph": "EgglogOptimizer"},
        )
        reg = registry(
            [BackendSpec(name="cobra", origin="test", load_manifest=lambda: manifest)]
        )

        with self.assertRaises(PassImplementationMisdeclared):
            reg.require_unique_implementation("mba-egraph", install_hint="d810-egglog")

    def test_duck_typed_manifest_with_non_iterable_rules_is_misdeclared(self):
        raw = {
            "name": "cobra",
            "api_version": PLUGIN_API_VERSION,
            "provides": Recorder(result=object()),
            "rules": 42,
            "implements": {"mba-egraph": "EgglogOptimizer"},
        }
        reg = registry(
            [BackendSpec(name="cobra", origin="test", load_manifest=lambda: raw)]
        )

        with self.assertRaises(PassImplementationMisdeclared):
            reg.require_unique_implementation("mba-egraph", install_hint="d810-egglog")

    def test_candidate_read_does_not_probe_or_resolve_backend(self):
        probe_calls = []

        class Backend:
            @staticmethod
            def d810_backend_probe():
                probe_calls.append("probe")
                return None

        load = Recorder(result=Backend)
        manifest = self.manifest(
            {"mba-egraph": "EgglogOptimizer"},
            rules=("acme.rules",),
            provides=load,
        )
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
            rules=("json",),
            implements={"mba-egraph": "EgglogOptimizer"},
        )
        reg = registry(
            [BackendSpec(name="cobra", origin="old", load_manifest=lambda: manifest)]
        )

        info = reg.implementation_manifest_info("cobra")

        self.assertEqual(info.status, BackendStatus.INCOMPATIBLE)
        self.assertEqual(load.calls, 0)

    def test_implementation_is_ready_only_after_exact_candidate_activation(self):
        manifest = self.manifest(
            {"mba-egraph": "EgglogOptimizer"},
            rules=("json",),
            provides=lambda: object(),
        )
        reg = BackendRegistry(
            source=lambda: (
                BackendSpec(
                    name="cobra",
                    origin="test",
                    load_manifest=lambda: manifest,
                ),
            ),
            registration_lookup=lambda _candidate: object(),
        )
        candidate = reg.require_unique_implementation(
            "mba-egraph", install_hint="d810-egglog"
        )
        reg.probe("cobra")
        self.assertFalse(reg.implementation_is_active(candidate))

        reg.activate_implementation(candidate)

        self.assertTrue(reg.implementation_is_active(candidate))

    def test_failed_reactivation_revokes_previous_activation_evidence(self):
        registered = {"value": object()}
        manifest = self.manifest(
            {"mba-egraph": "EgglogOptimizer"},
            rules=("json",),
            provides=lambda: object(),
        )
        reg = BackendRegistry(
            source=lambda: (
                BackendSpec(
                    name="cobra",
                    origin="test",
                    load_manifest=lambda: manifest,
                ),
            ),
            registration_lookup=lambda _candidate: registered["value"],
        )
        candidate = reg.require_unique_implementation(
            "mba-egraph", install_hint="d810-egglog"
        )
        reg.activate_implementation(candidate)
        self.assertTrue(reg.implementation_is_active(candidate))

        registered["value"] = None
        with self.assertRaises(PassImplementationMisdeclared):
            reg.activate_implementation(candidate)

        self.assertFalse(reg.implementation_is_active(candidate))
        self.assertIn("not registered", reg.implementation_failure(candidate) or "")

        registered["value"] = object()
        reg.activate_implementation(candidate)
        self.assertIsNone(reg.implementation_failure(candidate))

    def test_registration_availability_is_read_only_activation_evidence(self):
        registered = {"value": object()}
        manifest = self.manifest(
            {"mba-solve": "CobraSolveRule"},
            rules=("json",),
            provides=lambda: object(),
        )
        reg = BackendRegistry(
            source=lambda: (
                BackendSpec(
                    name="cobra",
                    origin="test",
                    load_manifest=lambda: manifest,
                ),
            ),
            registration_lookup=lambda _candidate: registered["value"],
        )
        candidate = reg.require_unique_implementation(
            "mba-solve", install_hint="d810-cobra"
        )

        self.assertTrue(reg.implementation_registration_available(candidate))
        self.assertFalse(reg.implementation_is_active(candidate))
        registered["value"] = None
        self.assertFalse(reg.implementation_registration_available(candidate))

    def test_rule_module_failure_evidence_is_recoverable_per_module(self):
        manifest = self.manifest(
            {"mba-solve": "CobraSolveRule"},
            rules=("acme.first", "acme.second"),
            provides=lambda: object(),
        )
        reg = BackendRegistry(
            source=lambda: (
                BackendSpec(
                    name="cobra",
                    origin="test",
                    load_manifest=lambda: manifest,
                ),
            ),
            registration_lookup=lambda _candidate: object(),
        )
        candidate = reg.require_unique_implementation(
            "mba-solve", install_hint="d810-cobra"
        )
        reg.probe("cobra")

        reg.record_rule_module_result(
            "acme.first", ModuleNotFoundError("native binding missing")
        )
        self.assertIn("native binding missing", reg.implementation_failure(candidate) or "")

        reg.record_rule_module_result("acme.first", None)
        self.assertIsNone(reg.implementation_failure(candidate))

    def test_strict_activation_clears_prior_normal_loader_failure(self):
        manifest = self.manifest(
            {"mba-egraph": "EgglogOptimizer"},
            rules=("json",),
            provides=lambda: object(),
        )
        reg = BackendRegistry(
            source=lambda: (
                BackendSpec(
                    name="cobra",
                    origin="test",
                    load_manifest=lambda: manifest,
                ),
            ),
            registration_lookup=lambda _candidate: object(),
        )
        candidate = reg.require_unique_implementation(
            "mba-egraph", install_hint="d810-egglog"
        )
        reg.probe("cobra")
        reg.record_rule_module_result("json", ModuleNotFoundError("stale failure"))
        self.assertIsNotNone(reg.implementation_failure(candidate))

        reg.activate_implementation(candidate)

        self.assertTrue(reg.implementation_is_active(candidate))
        self.assertIsNone(reg.implementation_failure(candidate))

    def test_normal_loader_finalization_classifies_missing_registration(self):
        registered = {"value": None}
        manifest = self.manifest(
            {"mba-solve": "CobraSolveRule"},
            rules=("json",),
            provides=lambda: object(),
        )
        reg = BackendRegistry(
            source=lambda: (
                BackendSpec(
                    name="cobra",
                    origin="test",
                    load_manifest=lambda: manifest,
                ),
            ),
            registration_lookup=lambda _candidate: registered["value"],
        )
        candidate = reg.require_unique_implementation(
            "mba-solve", install_hint="d810-cobra"
        )
        reg.probe("cobra")
        reg.record_rule_module_result("json", None)

        reg.finalize_rule_module_loading()
        self.assertIn("not registered", reg.implementation_failure(candidate) or "")

        registered["value"] = object()
        reg.finalize_rule_module_loading()
        self.assertIsNone(reg.implementation_failure(candidate))

    def test_normal_loader_does_not_validate_unavailable_backend_registration(self):
        manifest = self.manifest(
            {"mba-solve": "CobraSolveRule"},
            rules=("acme.rules",),
            provides=lambda: (_ for _ in ()).throw(ImportError("binding missing")),
        )
        reg = BackendRegistry(
            source=lambda: (
                BackendSpec(
                    name="cobra",
                    origin="test",
                    load_manifest=lambda: manifest,
                ),
            ),
            registration_lookup=lambda _candidate: None,
        )
        candidate = reg.require_unique_implementation(
            "mba-solve", install_hint="d810-cobra"
        )
        self.assertEqual(reg.rule_modules(), ())

        reg.finalize_rule_module_loading()

        self.assertEqual(reg.info("cobra").status, BackendStatus.UNAVAILABLE)
        self.assertIsNone(reg.implementation_failure(candidate))


if __name__ == "__main__":
    unittest.main()
