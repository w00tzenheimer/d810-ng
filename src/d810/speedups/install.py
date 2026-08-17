"""Bootstrap native speedups and isolated solver dependencies."""

from __future__ import annotations

import dataclasses
import ctypes
import importlib.machinery
import importlib.util
import os
import pathlib
import subprocess
import sys
from collections.abc import Callable, Sequence

from d810.speedups import bootstrap

__all__ = [
    "SOLVER_SUPPORT_PACKAGES",
    "REQUIRED_NATIVE_EXTENSIONS",
    "NativeSpeedupsProbe",
    "SolverSupportResult",
    "SpeedupsBootstrapResult",
    "bootstrap_speedups",
    "build_native_speedups",
    "find_source_checkout",
    "get_speedups_dir",
    "ensure_speedups_on_path",
    "install_solver_support",
    "install_speedups",
    "inspect_native_extensions",
    "probe_native_speedups",
]

SPEEDUPS_PACKAGES = ["z3-solver>=4.13,<4.15.5"]

#: What "solver support" means today. Aliased rather than duplicated: two z3
#: pins that could drift would mean two native libz3 builds reachable in one
#: process, and the Python wrapper must match the library it loads.
SOLVER_SUPPORT_PACKAGES = SPEEDUPS_PACKAGES

REQUIRED_NATIVE_EXTENSIONS = (
    "d810.speedups.c_simd",
    "d810.speedups.expr.c_ast",
    "d810.speedups.optimizers.c_pattern_match",
)

get_speedups_dir = bootstrap.get_speedups_dir
ensure_speedups_on_path = bootstrap.ensure_speedups_on_path


@dataclasses.dataclass(frozen=True)
class NativeSpeedupsProbe:
    """Result of importing the native sentinel in a fresh interpreter."""

    ok: bool
    detail: str


@dataclasses.dataclass(frozen=True)
class SpeedupsBootstrapResult:
    """User-facing outcome of the native and solver bootstrap."""

    ok: bool
    native_built: bool
    restart_required: bool
    message: str


def find_source_checkout(
    module_path: pathlib.Path = pathlib.Path(__file__),
) -> pathlib.Path | None:
    """Find an editable source checkout containing the extension builder."""

    resolved_module = module_path.resolve()
    for parent in resolved_module.parents:
        owned_module = parent / "src" / "d810" / "speedups" / "install.py"
        if (
            (parent / "pyproject.toml").is_file()
            and (parent / "setup.py").is_file()
            and owned_module.is_file()
            and owned_module.resolve() == resolved_module
        ):
            return parent
    return None


def build_native_speedups(
    source_root: pathlib.Path,
    *,
    executable: str = sys.executable,
    environ: dict[str, str] | None = None,
    runner: Callable[..., subprocess.CompletedProcess] = subprocess.run,
) -> None:
    """Build the checkout's Cython extensions for the invoking interpreter."""

    build_environment = dict(os.environ if environ is None else environ)
    build_environment["D810_BUILD_SPEEDUPS"] = "1"
    runner(
        [
            executable,
            "-m",
            "pip",
            "install",
            "-e",
            f"{source_root}[speedups]",
            "--no-build-isolation",
        ],
        check=True,
        env=build_environment,
    )


def inspect_native_extensions(
    *,
    find_spec: Callable[[str], object | None] = importlib.util.find_spec,
    loader: Callable[[str], object] = ctypes.PyDLL,
) -> NativeSpeedupsProbe:
    """Verify every core extension is loadable and exports its own initializer."""

    origins: list[str] = []
    extension_suffixes = tuple(importlib.machinery.EXTENSION_SUFFIXES)
    for module_name in REQUIRED_NATIVE_EXTENSIONS:
        try:
            spec = find_spec(module_name)
        except Exception as exc:  # noqa: BLE001 - probe failures are diagnostics
            return NativeSpeedupsProbe(False, f"{module_name}: {exc}")
        origin = getattr(spec, "origin", None)
        if not isinstance(origin, str) or not origin.endswith(extension_suffixes):
            return NativeSpeedupsProbe(
                False,
                f"{module_name}: no compatible native extension found",
            )
        try:
            library = loader(origin)
        except (OSError, ImportError) as exc:
            return NativeSpeedupsProbe(False, f"{module_name}: {exc}")
        initializer = f"PyInit_{module_name.rsplit('.', 1)[-1]}"
        if getattr(library, initializer, None) is None:
            return NativeSpeedupsProbe(
                False,
                f"{module_name}: missing {initializer} in {origin}",
            )
        origins.append(origin)
    return NativeSpeedupsProbe(True, ", ".join(origins))


def probe_native_speedups(
    *,
    executable: str = sys.executable,
    runner: Callable[..., subprocess.CompletedProcess] = subprocess.run,
) -> NativeSpeedupsProbe:
    """Import the native sentinel in a fresh process to avoid stale caches."""

    code = """\
import sys
from d810.speedups.install import inspect_native_extensions

result = inspect_native_extensions()
print(result.detail, file=sys.stdout if result.ok else sys.stderr)
raise SystemExit(0 if result.ok else 1)
"""
    completed = runner(
        [executable, "-c", code],
        capture_output=True,
        text=True,
        check=False,
    )
    if completed.returncode != 0:
        detail = (completed.stderr or completed.stdout or "import failed").strip()
        return NativeSpeedupsProbe(False, detail)
    return NativeSpeedupsProbe(
        True,
        (completed.stdout or "native extension imported").strip(),
    )


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
    state_changed: bool = False


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
            state_changed=False,
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
            state_changed=True,
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
            state_changed=True,
        )
    return SolverSupportResult(
        ok=True,
        already_present=False,
        message=(
            f"Installed solver support into {get_speedups_dir()}. "
            f"Proof-gated MBA rewrites are now available."
        ),
        state_changed=True,
    )


def bootstrap_speedups(
    *,
    source_root: pathlib.Path | None,
    native_builder: Callable[[pathlib.Path], None] = build_native_speedups,
    solver_installer: Callable[[], SolverSupportResult] = install_solver_support,
    native_probe: Callable[[], NativeSpeedupsProbe] = probe_native_speedups,
) -> SpeedupsBootstrapResult:
    """Build native speedups, install solver support, and verify the result."""

    native_built = False
    if source_root is not None:
        try:
            native_builder(source_root)
        except Exception as exc:  # noqa: BLE001 - CLI must explain build failures
            return SpeedupsBootstrapResult(
                ok=False,
                native_built=False,
                restart_required=True,
                message=(
                    f"Native speedup build failed: {exc}. Native extension "
                    "files may have changed. Restart IDA before using D810."
                ),
            )
        native_built = True

    solver_result = solver_installer()
    if not solver_result.ok:
        restart_required = native_built or solver_result.state_changed
        if native_built:
            restart_message = " Restart IDA to activate the completed native build."
        elif solver_result.state_changed:
            restart_message = " Restart IDA because solver components may have changed."
        else:
            restart_message = ""
        return SpeedupsBootstrapResult(
            ok=False,
            native_built=native_built,
            restart_required=restart_required,
            message=f"{solver_result.message}{restart_message}",
        )

    probe_result = native_probe()
    if not probe_result.ok:
        restart_required = native_built or not solver_result.already_present
        source_detail = (
            "No editable source checkout was found. " if source_root is None else ""
        )
        restart_message = (
            " Restart IDA to activate the components that were installed."
            if restart_required
            else ""
        )
        return SpeedupsBootstrapResult(
            ok=False,
            native_built=native_built,
            restart_required=restart_required,
            message=(
                f"{solver_result.message} {source_detail}"
                f"Native speedup verification failed: {probe_result.detail}."
                f"{restart_message}"
            ),
        )

    restart_required = native_built or not solver_result.already_present
    restart_message = " Restart IDA to activate them." if restart_required else ""
    return SpeedupsBootstrapResult(
        ok=True,
        native_built=native_built,
        restart_required=restart_required,
        message=(
            f"Native speedups verified at {probe_result.detail}. "
            f"{solver_result.message}{restart_message}"
        ),
    )


def main() -> None:
    result = bootstrap_speedups(source_root=find_source_checkout())
    stream = sys.stdout if result.ok else sys.stderr
    print(result.message, file=stream)
    if not result.ok:
        raise SystemExit(1)


if __name__ == "__main__":
    main()
