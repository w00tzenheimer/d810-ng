"""Prove that an installed d810-cobra is the working mba-solve backend.

A compiled extension can import and still be mis-wired, and a pure-Python
fallback can satisfy every import in this file's first line, so the checks
below end in a real known-answer solve plus a proof of equivalence.  The same
program runs in three places: the image bake step, the image build script's
verification table, and any manual triage of a baked image.

The solve is only reachable where ``d810`` itself is importable.
``d810_cobra.solve`` imports ``d810.core`` at module scope, and
``d810_cobra.prove`` needs a ``z3`` that only ``import d810`` puts on
``sys.path``, so a wheel installed into an image that deliberately carries no
d810 -- it is mounted at run time, and installing it would shadow the mounted
tree -- can be proven identical but not exercised.  That case is declared, not
inferred: see ``D810_COBRA_REQUIRE_SOLVE``.

Imports follow from that, and the split is deliberate rather than lazy.
``d810_cobra`` and ``d810_cobra._cobra`` are bound at module scope, as the
project requires: at the pinned revision the package ``__init__`` reaches only
``d810_cobra.expr`` and ``d810_cobra.probe``, neither of which imports d810, so
they load in an image that carries none.  ``d810_cobra.solve`` does
(``solve.py`` line 19, ``from d810.core import getLogger``), so hoisting it
would make this file fail to import in exactly the environment the reduced
mode exists for.  Those three names therefore stay inside
``_prove_known_answer_solve`` -- a documented exception, not a silent one, and
nothing else in this file may import inside a function.

Environment:

``D810_COBRA_EXPECT_VERSION``
    Distribution version the installed d810-cobra must report.
``D810_COBRA_EXPECT_ARCH``
    Machine name (``aarch64`` / ``x86_64``) that must appear in the compiled
    extension's filename.  A wheel for the wrong architecture cannot import,
    but an image assembled by hand can still carry the wrong one alongside a
    stale build, and the filename is what distinguishes them.

Both are optional: without them the identity assertions are skipped and only
the behaviour is proven.

``D810_COBRA_REQUIRE_SOLVE``
    ``0`` selects the reduced check for an environment without d810: manifest,
    compiled extension and identity, no solve.  It is not a way to silence a
    failing solve -- the reduced mode ASSERTS that d810 is genuinely absent, so
    setting it anywhere the solve could have run is itself an error.  Defaults
    to ``1``.
"""

from __future__ import annotations

import importlib.metadata
import importlib.util
import os
import sys
import sysconfig

import d810_cobra
import d810_cobra._cobra

EXPECT_VERSION = os.environ.get("D810_COBRA_EXPECT_VERSION", "")
EXPECT_ARCH = os.environ.get("D810_COBRA_EXPECT_ARCH", "")
REQUIRE_SOLVE = os.environ.get("D810_COBRA_REQUIRE_SOLVE", "1") != "0"


def _prove_known_answer_solve() -> None:
    """Run the solve the mba-solve backend exists to run, and prove it."""
    from d810_cobra.expr import parse_cobra_output
    from d810_cobra.prove import ProofResult, prove_equivalent
    from d810_cobra.solve import SolveStatus, binding_available, solve_signature

    assert binding_available(), "the compiled binding is not available"

    tree = parse_cobra_output("(x0 | x1) - (x0 & x1)", ["a", "b"])
    solved = solve_signature(tree, ["a", "b"], 32)
    assert solved.status is SolveStatus.SOLVED and solved.tree is not None, solved
    assert (
        prove_equivalent(tree, solved.tree, ["a", "b"], 32) is ProofResult.PROVED
    ), "the known-answer solve is not equivalent to its input"


def main() -> int:
    # The reduced mode describes an environment, so it has to be true of the
    # environment, and it is checked FIRST: otherwise the flag would be a way
    # to pass a broken backend anywhere, which is the failure mode a
    # verification program exists to prevent.
    if not REQUIRE_SOLVE:
        assert importlib.util.find_spec("d810") is None, (
            "D810_COBRA_REQUIRE_SOLVE=0 claims d810 is unavailable, but it is "
            "importable here; run the full verification instead"
        )

    manifest = d810_cobra.MANIFEST
    assert manifest["api_version"] == 1, manifest
    assert manifest["implements"] == {"mba-solve": "cobra-solve"}, manifest

    if REQUIRE_SOLVE:
        _prove_known_answer_solve()

    version = importlib.metadata.version("d810-cobra")
    if EXPECT_VERSION:
        assert version == EXPECT_VERSION, (version, EXPECT_VERSION)

    binary = os.path.realpath(d810_cobra._cobra.__file__)
    if EXPECT_ARCH:
        assert EXPECT_ARCH in os.path.basename(binary), (binary, EXPECT_ARCH)
    # An extension imported from a build tree or a mounted source checkout is
    # not the installed artifact this image claims to carry.
    site_dirs = [
        os.path.realpath(sysconfig.get_paths()[key]) for key in ("purelib", "platlib")
    ]
    assert any(binary.startswith(site + os.sep) for site in site_dirs), (
        binary,
        site_dirs,
    )

    if REQUIRE_SOLVE:
        print(f"d810-cobra {version} verified: {binary}")
    else:
        print(
            f"d810-cobra {version} installed: {binary} "
            "(manifest + extension + identity; no solve, d810 is not installed here)"
        )
    return 0


if __name__ == "__main__":
    sys.exit(main())
