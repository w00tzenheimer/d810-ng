from __future__ import annotations

import subprocess
import importlib.machinery
from pathlib import Path
from types import SimpleNamespace

from d810.speedups import install


def test_native_build_opts_in_and_uses_the_invoking_interpreter():
    calls: list[tuple[list[str], dict[str, object]]] = []

    def run(command, **kwargs):
        calls.append((command, kwargs))
        return subprocess.CompletedProcess(command, 0)

    install.build_native_speedups(
        Path("/checkout"),
        executable="/ida/python",
        environ={"PRESERVE_ME": "yes"},
        runner=run,
    )

    assert calls == [
        (
            [
                "/ida/python",
                "-m",
                "pip",
                "install",
                "-e",
                "/checkout[speedups]",
                "--no-build-isolation",
            ],
            {
                "check": True,
                "env": {
                    "PRESERVE_ME": "yes",
                    "D810_BUILD_SPEEDUPS": "1",
                },
            },
        )
    ]


def test_native_probe_uses_a_fresh_interpreter_and_reports_import_failure():
    calls: list[tuple[list[str], dict[str, object]]] = []

    def run(command, **kwargs):
        calls.append((command, kwargs))
        return subprocess.CompletedProcess(
            command,
            1,
            stdout="",
            stderr="ModuleNotFoundError: d810.speedups.c_simd",
        )

    result = install.probe_native_speedups(
        executable="/ida/python",
        runner=run,
    )

    assert result.ok is False
    assert "ModuleNotFoundError" in result.detail
    command, kwargs = calls[0]
    assert command[:2] == ["/ida/python", "-c"]
    assert "inspect_native_extensions" in command[2]
    assert kwargs == {"capture_output": True, "text": True, "check": False}


def test_native_inspection_requires_each_modules_own_initializer():
    suffix = importlib.machinery.EXTENSION_SUFFIXES[0]
    origins = {
        name: f"/native/{name.rsplit('.', 1)[-1]}{suffix}"
        for name in install.REQUIRED_NATIVE_EXTENSIONS
    }

    def find_spec(name):
        return SimpleNamespace(origin=origins[name])

    def load(_origin):
        return SimpleNamespace(PyInit_c_simd=object())

    result = install.inspect_native_extensions(find_spec=find_spec, loader=load)

    assert result.ok is False
    assert "PyInit_c_ast" in result.detail


def test_native_inspection_accepts_loadable_extensions_with_matching_initializers():
    suffix = importlib.machinery.EXTENSION_SUFFIXES[0]
    origins = {
        name: f"/native/{name.rsplit('.', 1)[-1]}{suffix}"
        for name in install.REQUIRED_NATIVE_EXTENSIONS
    }

    def find_spec(name):
        return SimpleNamespace(origin=origins[name])

    def load(origin):
        module_name = Path(origin).name.split(".", 1)[0]
        return SimpleNamespace(**{f"PyInit_{module_name}": object()})

    result = install.inspect_native_extensions(find_spec=find_spec, loader=load)

    assert result.ok is True
    assert all(origin in result.detail for origin in origins.values())


def test_native_inspection_reports_dynamic_loader_failures():
    suffix = importlib.machinery.EXTENSION_SUFFIXES[0]

    def find_spec(name):
        module_name = name.rsplit(".", 1)[-1]
        return SimpleNamespace(origin=f"/native/{module_name}{suffix}")

    def load(origin):
        raise OSError(f"cannot load {origin}")

    result = install.inspect_native_extensions(find_spec=find_spec, loader=load)

    assert result.ok is False
    assert "cannot load" in result.detail


def test_bootstrap_builds_installs_solver_and_then_verifies():
    events: list[str] = []

    result = install.bootstrap_speedups(
        source_root=Path("/checkout"),
        native_builder=lambda _root: events.append("build"),
        solver_installer=lambda: (
            events.append("solver")
            or install.SolverSupportResult(
                ok=True,
                already_present=False,
                message="solver installed",
            )
        ),
        native_probe=lambda: (
            events.append("probe")
            or install.NativeSpeedupsProbe(
                ok=True,
                detail="/checkout/src/d810/speedups/c_simd.cpython-313-darwin.so",
            )
        ),
    )

    assert result.ok is True
    assert result.native_built is True
    assert result.restart_required is True
    assert events == ["build", "solver", "probe"]
    assert "solver installed" in result.message
    assert "restart ida" in result.message.lower()


def test_bootstrap_accepts_an_installed_wheel_without_a_source_checkout():
    events: list[str] = []

    result = install.bootstrap_speedups(
        source_root=None,
        native_builder=lambda _root: events.append("build"),
        solver_installer=lambda: install.SolverSupportResult(
            ok=True,
            already_present=True,
            message="solver already present",
        ),
        native_probe=lambda: install.NativeSpeedupsProbe(
            ok=True,
            detail="/site-packages/d810/speedups/c_simd.cpython-313-darwin.so",
        ),
    )

    assert result.ok is True
    assert result.native_built is False
    assert result.restart_required is False
    assert events == []


def test_installed_wheel_solver_install_still_requires_an_ida_restart():
    result = install.bootstrap_speedups(
        source_root=None,
        native_builder=lambda _root: None,
        solver_installer=lambda: install.SolverSupportResult(
            ok=True,
            already_present=False,
            message="solver installed",
        ),
        native_probe=lambda: install.NativeSpeedupsProbe(
            ok=True,
            detail="/site-packages/d810/speedups/c_simd.cpython-313-darwin.so",
        ),
    )

    assert result.ok is True
    assert result.restart_required is True
    assert "restart ida" in result.message.lower()


def test_bootstrap_fails_closed_when_native_build_fails():
    solver_called = False

    def build(_root):
        raise subprocess.CalledProcessError(1, ["pip"])

    def install_solver():
        nonlocal solver_called
        solver_called = True
        return install.SolverSupportResult(True, True, "unexpected")

    result = install.bootstrap_speedups(
        source_root=Path("/checkout"),
        native_builder=build,
        solver_installer=install_solver,
        native_probe=lambda: install.NativeSpeedupsProbe(True, "unexpected"),
    )

    assert result.ok is False
    assert solver_called is False
    assert result.native_built is False
    assert result.restart_required is True
    assert "native speedup build failed" in result.message.lower()
    assert "may have changed" in result.message.lower()
    assert "restart ida" in result.message.lower()


def test_bootstrap_does_not_claim_success_when_fresh_import_fails():
    result = install.bootstrap_speedups(
        source_root=Path("/checkout"),
        native_builder=lambda _root: None,
        solver_installer=lambda: install.SolverSupportResult(
            ok=True,
            already_present=True,
            message="solver already present",
        ),
        native_probe=lambda: install.NativeSpeedupsProbe(
            ok=False,
            detail="wrong platform extension",
        ),
    )

    assert result.ok is False
    assert "wrong platform extension" in result.message


def test_native_build_followed_by_solver_failure_still_requests_restart():
    result = install.bootstrap_speedups(
        source_root=Path("/checkout"),
        native_builder=lambda _root: None,
        solver_installer=lambda: install.SolverSupportResult(
            ok=False,
            already_present=False,
            message="solver install failed",
        ),
        native_probe=lambda: install.NativeSpeedupsProbe(True, "unexpected"),
    )

    assert result.ok is False
    assert result.restart_required is True
    assert "solver install failed" in result.message
    assert "restart ida" in result.message.lower()


def test_solver_post_install_validation_failure_requests_restart_for_a_wheel():
    result = install.bootstrap_speedups(
        source_root=None,
        native_builder=lambda _root: None,
        solver_installer=lambda: install.SolverSupportResult(
            ok=False,
            already_present=False,
            message="solver files installed but validation failed",
            state_changed=True,
        ),
        native_probe=lambda: install.NativeSpeedupsProbe(True, "unexpected"),
    )

    assert result.ok is False
    assert result.restart_required is True
    assert "solver files installed" in result.message
    assert "restart ida" in result.message.lower()
    assert "native build" not in result.message.lower()


def test_solver_change_followed_by_native_probe_failure_requests_restart():
    result = install.bootstrap_speedups(
        source_root=None,
        native_builder=lambda _root: None,
        solver_installer=lambda: install.SolverSupportResult(
            ok=True,
            already_present=False,
            message="solver installed",
        ),
        native_probe=lambda: install.NativeSpeedupsProbe(
            ok=False,
            detail="native import failed",
        ),
    )

    assert result.ok is False
    assert result.restart_required is True
    assert "solver installed" in result.message
    assert "native import failed" in result.message
    assert "restart ida" in result.message.lower()


def test_source_checkout_discovery_requires_the_build_files(tmp_path):
    source_file = tmp_path / "src" / "d810" / "speedups" / "install.py"
    source_file.parent.mkdir(parents=True)
    source_file.touch()

    assert install.find_source_checkout(source_file) is None

    (tmp_path / "pyproject.toml").touch()
    (tmp_path / "setup.py").touch()

    assert install.find_source_checkout(source_file) == tmp_path


def test_source_checkout_discovery_rejects_an_unrelated_outer_project(tmp_path):
    installed_module = (
        tmp_path
        / ".venv"
        / "lib"
        / "python3.13"
        / "site-packages"
        / "d810"
        / "speedups"
        / "install.py"
    )
    installed_module.parent.mkdir(parents=True)
    installed_module.touch()
    (tmp_path / "pyproject.toml").touch()
    (tmp_path / "setup.py").touch()

    assert install.find_source_checkout(installed_module) is None
