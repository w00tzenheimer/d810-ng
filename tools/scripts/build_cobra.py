#!/usr/bin/env python3
"""Build the CoBRA static libs that d810's mba-solve binding links against.

Cross-platform on purpose. The shell version this replaces could not run on
Windows -- cibuildwheel's default shell there is not bash -- and Python is the
one interpreter guaranteed present everywhere this needs to work: the manylinux
container, macOS runners, Windows runners, and a contributor's checkout.

Produces the layout ``setup.py`` expects under the CoBRA root::

    build-deps/install/{lib*,include}/   abseil + highway
    build/lib/core/{libcobra-core.a,cobra-core.lib}

NO LLVM, NO Z3:

* The LLVM pass plugin is irrelevant to d810 and pulls in a multi-gigabyte
  dependency. ``COBRA_BUILD_LLVM_PASS=OFF`` is what makes this build tractable
  at all.
* Z3 is linked on the *Python* side. Letting CMake discover a system Z3 here
  would bake a second, possibly different, Z3 into the binding -- two Z3s in
  one process is not a situation anyone should have to debug.
  ``CMAKE_DISABLE_FIND_PACKAGE_Z3`` is belt-and-braces on top of
  ``COBRA_ENABLE_Z3=OFF``.

Usage:
    python tools/scripts/build_cobra.py [--root DIR] [--jobs N] [--force]
"""

from __future__ import annotations

import argparse
import os
import shutil
import subprocess
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
DEFAULT_ROOT = REPO_ROOT / "third_party" / "cobra"

#: Names the core static library can have. MSVC drops the "lib" prefix and uses
#: .lib; Unix toolchains use libfoo.a. Checking only one shape silently
#: "succeeds" on the other platform with nothing built.
CORE_LIB_NAMES = ("libcobra-core.a", "cobra-core.lib")

#: Windows must build these deps with MSVC, not MinGW.
#:
#: cibuildwheel compiles the extension with MSVC, and setup.py force-loads the
#: abseil archives with /WHOLEARCHIVE:, which only consumes MSVC-style
#: absl_*.lib. A MinGW toolchain emits libabsl_*.a instead -- and even if the
#: glob were widened, MinGW's C++ ABI does not match an MSVC-built .pyd, so the
#: result would fail at import rather than at link.
#:
#: `-G Ninja` with no compiler pinned takes whatever is first in PATH. On the
#: GitHub Windows runner that is C:/mingw64/bin/cc.exe, so the deps built
#: cleanly in the wrong toolchain and the wheel build then refused them:
#:
#:   RuntimeError: no abseil archives matched 'absl_*.lib' ...
#:   refusing to build a broken binding.
#:
#: Pinning cl here makes a missing MSVC environment fail at configure with a
#: clear "compiler not found", instead of quietly producing archives that
#: cannot be linked. The workflow supplies that environment (msvc-dev-cmd);
#: this is the assertion that it actually did.
MSVC_ARGS: tuple[str, ...] = (
    ("-DCMAKE_C_COMPILER=cl", "-DCMAKE_CXX_COMPILER=cl")
    if sys.platform == "win32"
    else ()
)


def fail(message: str) -> "NoReturn":  # type: ignore[valid-type]
    print(f"error: {message}", file=sys.stderr)
    raise SystemExit(1)


def run(cmd: list[str], *, cwd: Path) -> None:
    print(f"==> {' '.join(cmd)}", flush=True)
    result = subprocess.run(cmd, cwd=str(cwd))
    if result.returncode != 0:
        fail(f"command failed with exit {result.returncode}: {' '.join(cmd)}")


def find_core_lib(build_dir: Path) -> Path | None:
    for name in CORE_LIB_NAMES:
        for candidate in build_dir.rglob(name):
            return candidate
    return None


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=DEFAULT_ROOT,
                        help="CoBRA source root (default: third_party/cobra)")
    parser.add_argument("--jobs", type=int, default=os.cpu_count() or 2)
    parser.add_argument("--force", action="store_true",
                        help="rebuild even if outputs already exist")
    args = parser.parse_args()

    root: Path = args.root.resolve()

    if not (root / "CMakeLists.txt").is_file():
        fail(
            f"no CoBRA source at {root}\n\n"
            "The submodule is not checked out. Either:\n"
            "    git submodule update --init --recursive\n"
            "or point COBRA_ROOT at your own CoBRA build tree and skip this "
            "script entirely."
        )

    # Check the toolchain up front. A missing compiler surfaces from CMake as a
    # wall of configure output; this is one actionable line instead.
    for tool in ("cmake", "ninja"):
        if shutil.which(tool) is None:
            fail(
                f"{tool} is required to build CoBRA from source and was not "
                f"found on PATH.\n"
                "In CI this is installed by CIBW_BEFORE_ALL; locally, install "
                "it or set COBRA_ROOT to a prebuilt tree."
            )

    deps_prefix = root / "build-deps" / "install"
    core_build = root / "build"

    # Dependencies first: CoBRA's own CMakeLists expects them installed.
    #
    # dependencies/ is an ExternalProject *superbuild*: each dep runs its own
    # configure/build/install as part of the default target. There is no
    # aggregate `install` target, and asking for one fails the whole step with
    # "ninja: error: unknown target 'install'" -- which is what it did on every
    # platform. The step is continue-on-error, so that surfaced only as
    # D810_BUILD_COBRA=0 and a wheel shipping _cobra.pyx with no compiled
    # binding, green. dependencies/CMakeLists.txt documents the correct
    # invocation in its own header: `cmake --build build-deps`.
    #
    # The prefix comes from COBRA_INSTALL_PREFIX (superbuild.cmake), which is
    # what gets forwarded to every ExternalProject. CMAKE_INSTALL_PREFIX is not
    # read here; it only appeared to work because COBRA_INSTALL_PREFIX defaults
    # to ${CMAKE_BINARY_DIR}/install, which is the same path. Set the one that
    # is actually authoritative.
    if args.force or not deps_prefix.is_dir():
        run(
            [
                "cmake", "-S", "dependencies", "-B", "build-deps", "-G", "Ninja",
                "-DCMAKE_BUILD_TYPE=Release",
                "-DCOBRA_BUILD_LLVM_PASS=OFF",
                "-DCOBRA_ENABLE_Z3=OFF",
                f"-DCOBRA_INSTALL_PREFIX={deps_prefix}",
                *MSVC_ARGS,
            ],
            cwd=root,
        )
        run(["cmake", "--build", "build-deps", "-j", str(args.jobs)], cwd=root)
    else:
        print(f"==> deps already present at {deps_prefix} (use --force to rebuild)")

    if args.force or find_core_lib(core_build) is None:
        run(
            [
                "cmake", "-S", ".", "-B", "build", "-G", "Ninja",
                "-DCMAKE_BUILD_TYPE=Release",
                "-DCOBRA_BUILD_LLVM_PASS=OFF",
                "-DCOBRA_ENABLE_Z3=OFF",
                "-DCMAKE_DISABLE_FIND_PACKAGE_Z3=ON",
                f"-DCMAKE_PREFIX_PATH={deps_prefix}",
                *MSVC_ARGS,
            ],
            cwd=root,
        )
        run(["cmake", "--build", "build", "--target", "cobra-core",
             "-j", str(args.jobs)], cwd=root)
    else:
        print("==> cobra-core already built (use --force to rebuild)")

    # Verify rather than assume. A configure that "succeeded" while producing no
    # library would otherwise be discovered much later, as a link error in
    # setup.py or -- worse -- an importable extension with missing symbols.
    core = find_core_lib(core_build)
    if core is None:
        fail(
            f"cobra-core static library not produced under {core_build}\n"
            f"(looked for: {', '.join(CORE_LIB_NAMES)})"
        )

    print(f"==> cobra-core: {core}")
    print(f"==> COBRA_ROOT={root}")

    # Emit for GitHub Actions when running there, so the caller does not have to
    # re-derive the path.
    output = os.environ.get("GITHUB_OUTPUT")
    if output:
        with open(output, "a", encoding="utf-8") as handle:
            handle.write(f"root={root}\n")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
