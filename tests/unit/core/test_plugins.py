"""Tests for the d810 backend plugin protocol.

The protocol exists so an out-of-tree distribution (e.g. ``d810-backend-cobra``)
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
    format_report,
    has_defects,
    manifest_of,
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

    def test_plain_dict_is_a_valid_manifest(self):
        got = manifest_of({"name": "acme", "api_version": 1, "provides": "pkg:obj"})
        self.assertEqual((got.name, got.api_version, got.provides),
                         ("acme", 1, "pkg:obj"))

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
            specs=[spec("cobra", external, origin="d810-backend-cobra 1.0")],
            builtins=[spec("cobra", builtin, origin="builtin")],
        )
        self.assertIs(reg.load("cobra"), external.result)
        self.assertEqual(builtin.calls, 0)

        info = reg.info("cobra")
        self.assertEqual(info.origin, "d810-backend-cobra 1.0")
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
                    origin="d810-backend-cobra 1.0",
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
                    rejected=(("d810-backend-cobra 0.1", "built for API v99"),),
                )
            ]
        )
        for fragment in ("d810-backend-cobra 0.1", "v99", "rejected"):
            self.assertIn(fragment, text)


class TestBuiltinCobraBackend(unittest.TestCase):
    """The protocol against a real backend, not a fake.

    Builtins-only (``source`` returns nothing) so the result does not depend on
    what happens to be pip-installed on the machine running the suite.
    """

    def make(self):
        from d810.backends import BUILTIN_BACKENDS

        return BackendRegistry(builtins=BUILTIN_BACKENDS, source=lambda: [])

    def test_cobra_is_registered_without_any_installed_metadata(self):
        self.assertIn("cobra", self.make().names())

    def test_cobra_declares_a_probe_hook(self):
        from d810.backends.cobra import solve

        self.assertTrue(callable(getattr(solve, "d810_backend_probe", None)))

    def test_cobra_probe_reflects_native_binding_availability(self):
        from d810.backends.cobra import solve

        reason = solve.d810_backend_probe()
        if solve.binding_available():
            self.assertIsNone(reason)
        else:
            # Must name the missing piece. "unavailable" with no reason is the
            # failure this protocol exists to eliminate.
            self.assertIn("_cobra", reason)

    def test_cobra_status_is_definite_and_explained(self):
        info = self.make().probe("cobra")
        self.assertIn(
            info.status,
            {BackendStatus.AVAILABLE, BackendStatus.UNAVAILABLE},
            f"unexpected status {info.status} ({info.reason})",
        )
        if info.status is BackendStatus.UNAVAILABLE:
            self.assertTrue(info.reason, "UNAVAILABLE must carry a reason")

    def test_registry_agrees_with_the_module_flag(self):
        from d810.backends.cobra import solve

        info = self.make().probe("cobra")
        self.assertEqual(info.usable, solve.binding_available())

    def test_missing_extension_is_reported_not_silent(self):
        """The fresh-worktree / D810_BUILD_COBRA=0 case, forced.

        A checkout without the compiled ``.so`` (it is gitignored) currently
        looks identical to a working one until you notice nothing was
        simplified. Asserted here rather than left to whichever machine runs
        the suite.
        """
        from unittest import mock

        from d810.backends.cobra import solve

        with mock.patch.object(solve, "_BINDING_AVAILABLE", False), mock.patch.object(
            solve, "_BINDING_ERROR", "No module named 'd810.backends.cobra._cobra'"
        ):
            info = self.make().probe("cobra")

        self.assertEqual(info.status, BackendStatus.UNAVAILABLE)
        self.assertIn("_cobra", info.reason)
        self.assertIn("D810_BUILD_COBRA=1", info.reason)
        self.assertFalse(info.usable)


if __name__ == "__main__":
    unittest.main()
