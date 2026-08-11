"""Installer for isolated optional speedups dependencies."""

from __future__ import annotations

import dataclasses
import subprocess
import sys
from collections.abc import Callable, Sequence

from d810.speedups import bootstrap

__all__ = [
    "SOLVER_SUPPORT_PACKAGES",
    "SolverSupportResult",
    "get_speedups_dir",
    "ensure_speedups_on_path",
    "install_solver_support",
    "install_speedups",
]

SPEEDUPS_PACKAGES = ["z3-solver>=4.13,<4.15.5"]

#: What "solver support" means today. Aliased rather than duplicated: two z3
#: pins that could drift would mean two native libz3 builds reachable in one
#: process, and the Python wrapper must match the library it loads.
SOLVER_SUPPORT_PACKAGES = SPEEDUPS_PACKAGES

get_speedups_dir = bootstrap.get_speedups_dir
ensure_speedups_on_path = bootstrap.ensure_speedups_on_path


def install_speedups(packages: list[str] | None = None) -> None:
    """Install optional dependencies into the private speedups directory."""

    speedups_dir = get_speedups_dir()
    speedups_dir.mkdir(parents=True, exist_ok=True)
    pkg_list = packages or SPEEDUPS_PACKAGES
    cmd = [
        sys.executable,
        "-m",
        "pip",
        "install",
        "--target",
        str(speedups_dir),
        *pkg_list,
    ]
    subprocess.run(cmd, check=True)


@dataclasses.dataclass(frozen=True)
class SolverSupportResult:
    """Outcome of trying to make solver proofs work.

    Frozen because it crosses a UI boundary and is logged; a caller editing it
    in flight would make the report disagree with what happened.
    """

    ok: bool
    already_present: bool
    message: str


def _default_solver_probe() -> bool:
    """Is a usable z3 importable right now?

    Puts the speedups directory on ``sys.path`` first, so this answers a
    question about the environment rather than about import order.
    """
    bootstrap.ensure_speedups_on_path()
    try:
        import z3  # noqa: F401, PLC0415
    except Exception:  # noqa: BLE001 - absence is an answer, not an error
        return False
    return True


def install_solver_support(
    *,
    probe: Callable[[], bool] = _default_solver_probe,
    installer: Callable[[Sequence[str]], None] | None = None,
) -> SolverSupportResult:
    """Ensure z3 is available for the mba-solve proof gate, and report.

    Shared by the workbench action and the solver backend's opt-in bootstrap so
    the remedy exists once. ``probe`` and ``installer`` are injected so tests
    never reach the network.

    Never raises. Both callers are places where an exception is worse than a
    message: one is a UI handler, the other runs during rule configuration on
    the decompiler's thread, where an escaping exception crosses into Hex-Rays
    C++ and takes the process down.
    """
    if probe():
        return SolverSupportResult(
            ok=True,
            already_present=True,
            message="Solver support is already available; nothing to install.",
        )

    run = installer if installer is not None else install_speedups
    try:
        run(SOLVER_SUPPORT_PACKAGES)
    except Exception as exc:  # noqa: BLE001 - see docstring
        return SolverSupportResult(
            ok=False,
            already_present=False,
            message=(
                f"Could not install solver support: {exc}. "
                f"Install it manually with the 'install-speedups' command."
            ),
        )

    # Anything that cached "z3 is absent" must be able to notice otherwise, or
    # this session keeps skipping every rewrite until IDA restarts and a
    # successful install looks like it did nothing. Bumped before the probe so
    # the probe itself sees a fresh generation.
    bootstrap.invalidate_optional_dependency_cache()

    # pip exiting 0 is not proof that z3 imports: a wheel can land for the wrong
    # interpreter, or the native libz3 can fail to load. Confirm before
    # reporting success, or the user goes back to a pass that still applies
    # nothing.
    if not probe():
        return SolverSupportResult(
            ok=False,
            already_present=False,
            message=(
                "Installation reported success but z3 still cannot be "
                "imported. Try the 'install-speedups' command directly to see "
                "the installer output."
            ),
        )
    return SolverSupportResult(
        ok=True,
        already_present=False,
        message=(
            f"Installed solver support into {get_speedups_dir()}. "
            f"Proof-gated MBA rewrites are now available."
        ),
    )


def main() -> None:
    install_speedups()


if __name__ == "__main__":
    main()
