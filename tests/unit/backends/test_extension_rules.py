"""``load_extension_rules`` imports optimizer rules shipped by extensions.

d810 loads its own rules by scanning ``d810.optimizers.__path__``. That scan is
path-scoped, so a rule living inside an installed extension package is never
imported and never registers -- the backend probes ``available`` while its pass
is silently absent, which looks exactly like a pass that ran and matched
nothing. These tests cover the seam that closes that gap.

The rule modules here are written to disk and imported for real. An earlier
version planted them in ``sys.modules`` first, which made every assertion pass
even with the ``import_module`` call deleted: importing an already-imported
module is a no-op that proves nothing.
"""

from __future__ import annotations

import sys
import textwrap
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory

from d810.backends import load_extension_rules
from d810.core.plugins import (
    PLUGIN_API_VERSION,
    BackendManifest,
    BackendRegistry,
    BackendSpec,
    PassImplementationMisdeclared,
    PassImplementationUnavailable,
)


class _FakeRegistry:
    def __init__(self, modules):
        self._modules = tuple(modules)
        self.calls = 0
        self.results = []
        self.finalized = 0

    def rule_modules(self):
        self.calls += 1
        return self._modules

    def extension_reload_module_prefixes(self):
        return self._modules

    def record_rule_module_result(self, module_name, error):
        self.results.append((module_name, error))

    def finalize_rule_module_loading(self):
        self.finalized += 1


class TestLoadExtensionRules(unittest.TestCase):
    def setUp(self):
        self._tmp = TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.root = Path(self._tmp.name)
        sys.path.insert(0, str(self.root))
        self.addCleanup(sys.path.remove, str(self.root))
        self._planted: list[str] = []

    def tearDown(self):
        for name in self._planted:
            sys.modules.pop(name, None)

    def write_rule(self, name: str, body: str = "") -> Path:
        """A real module on disk whose import has an observable side effect."""
        marker = self.root / f"{name}.marker"
        source = textwrap.dedent(
            f"""
            import pathlib
            {body}
            # Written at import time: the only proof the module actually ran.
            _marker = pathlib.Path({str(marker)!r})
            _marker.write_text(_marker.read_text() + "imported" if _marker.exists() else "imported")
            """
        )
        (self.root / f"{name}.py").write_text(source)
        self._planted.append(name)
        return marker

    def registry_for(self, backend, *, origin, rule_module, rule_name, lookup):
        manifest = BackendManifest(
            name=origin,
            api_version=PLUGIN_API_VERSION,
            provides=lambda: backend,
            rules=(rule_module,),
            implements={"mba-egraph": rule_name},
        )
        return BackendRegistry(
            source=lambda: [
                BackendSpec(
                    name=origin,
                    origin=origin,
                    load_manifest=lambda: manifest,
                )
            ],
            registration_lookup=lookup,
        )

    def _patch_registry(self, fake) -> None:
        import d810.backends

        original = d810.backends.registry
        d810.backends.registry = lambda: fake
        self.addCleanup(setattr, d810.backends, "registry", original)

    def test_declared_rule_module_is_imported(self):
        """The whole point: an extension's rule module actually gets imported."""
        marker = self.write_rule("acme_ext_rule_ok")
        fake = _FakeRegistry(["acme_ext_rule_ok"])
        self._patch_registry(fake)

        self.assertFalse(marker.exists(), "precondition: not imported yet")
        load_extension_rules()

        self.assertTrue(
            marker.exists(),
            "load_extension_rules did not import the declared rule module",
        )
        self.assertEqual(fake.results, [("acme_ext_rule_ok", None)])
        self.assertEqual(fake.finalized, 1)

    def test_a_rule_that_fails_to_import_does_not_break_startup(self):
        """An extension is optional by construction; d810 must start without it.

        Letting this propagate would take the entire optimizer catalogue down
        with one bad extension -- every rule, not just the extension's.
        """
        fake = _FakeRegistry(["acme_ext.module.that.does.not.exist"])
        self._patch_registry(fake)

        load_extension_rules()  # must not raise
        self.assertEqual(fake.results[0][0], "acme_ext.module.that.does.not.exist")
        self.assertIsInstance(fake.results[0][1], ModuleNotFoundError)

    def test_a_rule_that_raises_on_import_is_contained(self):
        """Not just ImportError: a rule whose module body throws is contained too."""
        self.write_rule("acme_ext_rule_raises", body="raise RuntimeError('boom')")
        self._patch_registry(_FakeRegistry(["acme_ext_rule_raises"]))

        load_extension_rules()  # must not raise

    def test_one_broken_rule_does_not_stop_the_others(self):
        marker = self.write_rule("acme_ext_rule_second")
        self._patch_registry(
            _FakeRegistry(["acme_ext.busted", "acme_ext_rule_second"])
        )

        load_extension_rules()

        self.assertTrue(
            marker.exists(),
            "a broken rule earlier in the list suppressed a later good one",
        )

    def test_no_extensions_is_not_an_error(self):
        fake = _FakeRegistry([])
        self._patch_registry(fake)

        load_extension_rules()

        self.assertEqual(fake.calls, 1)

    def test_activation_probes_before_importing_rule_module(self):
        probe_marker = self.root / "probe.marker"
        rule_marker = self.write_rule(
            "acme_ext_rule_ordered",
            body=(
                f"if not pathlib.Path({str(probe_marker)!r}).exists():\n"
                "                raise RuntimeError('rule imported before probe')"
            ),
        )

        class Backend:
            @staticmethod
            def d810_backend_probe():
                probe_marker.write_text("probed")
                return None

        looked_up = []
        reg = self.registry_for(
            Backend,
            origin="cobra",
            rule_module="acme_ext_rule_ordered",
            rule_name="EgglogOptimizer",
            lookup=lambda candidate: looked_up.append(candidate.rule_name) or object(),
        )
        candidate = reg.implementation_candidates_for("mba-egraph")[0]

        self.assertFalse(rule_marker.exists())
        reg.activate_implementation(candidate)

        self.assertEqual(looked_up, ["EgglogOptimizer"])
        self.assertEqual(rule_marker.read_text(), "imported")

    def test_unavailable_probe_prevents_rule_import(self):
        rule_marker = self.write_rule("acme_ext_rule_unavailable")

        class Backend:
            @staticmethod
            def d810_backend_probe():
                return "native extension not built"

        reg = self.registry_for(
            Backend,
            origin="cobra",
            rule_module="acme_ext_rule_unavailable",
            rule_name="EgglogOptimizer",
            lookup=lambda candidate: object(),
        )
        candidate = reg.implementation_candidates_for("mba-egraph")[0]

        with self.assertRaises(PassImplementationUnavailable):
            reg.activate_implementation(candidate)

        self.assertFalse(rule_marker.exists())

    def test_successful_rule_module_import_is_idempotent(self):
        rule_marker = self.write_rule("acme_ext_rule_idempotent")

        class Backend:
            @staticmethod
            def d810_backend_probe():
                return None

        reg = self.registry_for(
            Backend,
            origin="cobra",
            rule_module="acme_ext_rule_idempotent",
            rule_name="EgglogOptimizer",
            lookup=lambda candidate: object(),
        )
        candidate = reg.implementation_candidates_for("mba-egraph")[0]

        reg.activate_implementation(candidate)
        reg.activate_implementation(candidate)

        self.assertEqual(rule_marker.read_text(), "imported")

    def test_imported_module_without_registered_class_is_misdeclared(self):
        rule_marker = self.write_rule("acme_ext_rule_unregistered")

        class Backend:
            @staticmethod
            def d810_backend_probe():
                return None

        reg = self.registry_for(
            Backend,
            origin="cobra",
            rule_module="acme_ext_rule_unregistered",
            rule_name="EgglogOptimizer",
            lookup=lambda candidate: None,
        )
        candidate = reg.implementation_candidates_for("mba-egraph")[0]

        with self.assertRaises(PassImplementationMisdeclared):
            reg.activate_implementation(candidate)

        self.assertTrue(rule_marker.exists())

    def test_startup_loading_probes_every_contributor_before_importing_rules(self):
        solve_probe = self.root / "solve.probe"
        egraph_probe = self.root / "egraph.probe"
        solve_rule = self.write_rule(
            "acme_ext_rule_solve",
            body=(
                f"if not pathlib.Path({str(solve_probe)!r}).exists():\n"
                "                raise RuntimeError('solve rule imported before probe')"
            ),
        )
        egraph_rule = self.write_rule(
            "acme_ext_rule_egraph",
            body=(
                f"if not pathlib.Path({str(egraph_probe)!r}).exists():\n"
                "                raise RuntimeError('egraph rule imported before probe')"
            ),
        )

        class SolveBackend:
            @staticmethod
            def d810_backend_probe():
                solve_probe.write_text("probed")
                return None

        class EgraphBackend:
            @staticmethod
            def d810_backend_probe():
                egraph_probe.write_text("probed")
                return None

        solve_manifest = BackendManifest(
            name="solve",
            api_version=PLUGIN_API_VERSION,
            provides=lambda: SolveBackend,
            rules=("acme_ext_rule_solve",),
            implements={"mba-solve": "CobraSolveRule"},
        )
        egraph_manifest = BackendManifest(
            name="egraph",
            api_version=PLUGIN_API_VERSION,
            provides=lambda: EgraphBackend,
            rules=("acme_ext_rule_egraph",),
            implements={"mba-egraph": "EgglogOptimizer"},
        )
        real = BackendRegistry(
            source=lambda: [
                BackendSpec(
                    name="solve",
                    origin="solve",
                    load_manifest=lambda: solve_manifest,
                ),
                BackendSpec(
                    name="egraph",
                    origin="egraph",
                    load_manifest=lambda: egraph_manifest,
                ),
            ]
        )
        self._patch_registry(real)

        load_extension_rules()

        self.assertEqual(solve_rule.read_text(), "imported")
        self.assertEqual(egraph_rule.read_text(), "imported")
        # Re-running startup catalogue construction must not execute either
        # module body again.
        load_extension_rules()
        self.assertEqual(solve_rule.read_text(), "imported")
        self.assertEqual(egraph_rule.read_text(), "imported")


if __name__ == "__main__":
    unittest.main()
