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


class _FakeRegistry:
    def __init__(self, modules):
        self._modules = tuple(modules)
        self.calls = 0

    def rule_modules(self):
        self.calls += 1
        return self._modules


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
            pathlib.Path({str(marker)!r}).write_text("imported")
            """
        )
        (self.root / f"{name}.py").write_text(source)
        self._planted.append(name)
        return marker

    def _patch_registry(self, fake) -> None:
        import d810.backends

        original = d810.backends.registry
        d810.backends.registry = lambda: fake
        self.addCleanup(setattr, d810.backends, "registry", original)

    def test_declared_rule_module_is_imported(self):
        """The whole point: an extension's rule module actually gets imported."""
        marker = self.write_rule("acme_ext_rule_ok")
        self._patch_registry(_FakeRegistry(["acme_ext_rule_ok"]))

        self.assertFalse(marker.exists(), "precondition: not imported yet")
        load_extension_rules()

        self.assertTrue(
            marker.exists(),
            "load_extension_rules did not import the declared rule module",
        )

    def test_a_rule_that_fails_to_import_does_not_break_startup(self):
        """An extension is optional by construction; d810 must start without it.

        Letting this propagate would take the entire optimizer catalogue down
        with one bad extension -- every rule, not just the extension's.
        """
        self._patch_registry(_FakeRegistry(["acme_ext.module.that.does.not.exist"]))

        load_extension_rules()  # must not raise

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


if __name__ == "__main__":
    unittest.main()
