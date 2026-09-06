"""Prove that an installed d810-cobra is the working mba-solve backend.

A compiled extension can import and still be mis-wired, and a pure-Python
fallback can satisfy every import in this file's first line, so the checks
below end in a real known-answer solve plus a proof of equivalence.  The same
program runs in three places: the image bake step, the image build script's
verification table, and any manual triage of a baked image.

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

The d810_cobra imports are at module level, as the project's style requires.
That means this file cannot be imported where d810-cobra is absent -- which is
every environment except inside the built image, and the only place it is ever
run. Failing at import there is the correct outcome anyway: an image that
cannot import the backend has nothing to verify. Its callers therefore treat
it as a program, not a module, and its tests read it as text.
"""

from __future__ import annotations

import importlib.metadata
import os
import sys
import sysconfig

import d810_cobra
import d810_cobra._cobra
from d810_cobra.expr import parse_cobra_output
from d810_cobra.prove import ProofResult, prove_equivalent
from d810_cobra.solve import SolveStatus, binding_available, solve_signature

EXPECT_VERSION = os.environ.get("D810_COBRA_EXPECT_VERSION", "")
EXPECT_ARCH = os.environ.get("D810_COBRA_EXPECT_ARCH", "")


def main() -> int:
    manifest = d810_cobra.MANIFEST
    assert manifest["api_version"] == 1, manifest
    assert manifest["implements"] == {"mba-solve": "cobra-solve"}, manifest
    assert binding_available(), "the compiled binding is not available"

    tree = parse_cobra_output("(x0 | x1) - (x0 & x1)", ["a", "b"])
    solved = solve_signature(tree, ["a", "b"], 32)
    assert solved.status is SolveStatus.SOLVED and solved.tree is not None, solved
    assert (
        prove_equivalent(tree, solved.tree, ["a", "b"], 32) is ProofResult.PROVED
    ), "the known-answer solve is not equivalent to its input"

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

    print(f"d810-cobra {version} verified: {binary}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
