#!/usr/bin/env python3
"""
Run d810 tests via Docker: either docker-compose (unit/integration/all) or
a single image (system tests / pseudocode dump). Cross-platform (macOS, Linux, Windows).
Python 3.11+.

This script inlines the logic of run_system_tests_docker.sh and test_with_docker.sh;
it does not call those scripts.

Usage:
  Compose (test_with_docker.sh):  docker_tests.py unit [service]
                                 docker_tests.py integration [service]
                                 docker_tests.py all [service]
  Image (run_system_tests_docker.sh):  docker_tests.py system [--worktree REL]
                                       docker_tests.py dump [OPTIONS] [-- PYTEST_ARGS ...]

Environment: D810_REPO_ROOT, D810_WORKTREE_ROOT, D810_DOCKER_IMAGE,
             D810_NO_CYTHON, D810_TEST_BINARY
"""

from __future__ import annotations

import argparse
import os
import shlex
import shutil
import subprocess
import sys
from pathlib import Path

# Container paths and commands (system_dump_mode; match run_system_tests_docker.sh)
_IDA_APP = "/app/ida"
_IDA_PYTHON = f"{_IDA_APP}/python"
_WORK = "/work"
_VENV_PIP = f"{_IDA_APP}/.venv/bin/pip"
_VENV_PYTHON = f"{_IDA_APP}/.venv/bin/python"
_PYTHONPATH_VAL = f"{_WORK}/src:{_IDA_PYTHON}"
_EXPORT_IDA = (
    f"export IDA_PREFIX={_IDA_APP} IDA_INSTALL_DIR={_IDA_APP} "
    f"D810_LIBCLANG_PATH={_IDA_APP}/libclang.so PYTHONPATH={_PYTHONPATH_VAL}:$PYTHONPATH"
)
_PIP_INSTALL = f"{_VENV_PIP} install -e .[dev] -q"
_SPEEDUPS = f"{_VENV_PYTHON} -m d810.speedups.install"
_PYTEST_SYSTEM = f"{_VENV_PYTHON} -m pytest tests/system -v"
_PYTEST_DUMP = f"{_VENV_PYTHON} -m pytest -s tests/system/e2e/test_dump_function_pseudocode.py"
_WORK_TMP = f"{_WORK}/.tmp"


def get_repo_root() -> Path:
    root = os.environ.get("D810_REPO_ROOT")
    if root:
        return Path(root).resolve()
    try:
        out = subprocess.run(
            ["git", "rev-parse", "--show-toplevel"],
            capture_output=True,
            text=True,
            check=True,
            timeout=10,
        )
        return Path(out.stdout.strip()).resolve()
    except (subprocess.CalledProcessError, FileNotFoundError, subprocess.TimeoutExpired):
        pass
    print("ERROR: Not inside a git repo and D810_REPO_ROOT not set.", file=sys.stderr)
    sys.exit(1)


def run(
    cmd: list[str],
    cwd: Path | None = None,
    env: dict[str, str] | None = None,
    stdout: int | None = None,
    stderr: int | None = None,
) -> int:
    env = {**os.environ, **(env or {})}
    return subprocess.run(
        cmd,
        cwd=cwd,
        env=env,
        stdout=stdout or sys.stdout,
        stderr=stderr or sys.stderr,
    ).returncode


def compose_mode(
    repo_root: Path,
    test_type: str,
    service: str,
) -> int:
    compose_file = repo_root / "docker-compose.yml"
    if not compose_file.is_file():
        print("ERROR: docker-compose.yml not found", file=sys.stderr)
        return 1
    env_file = repo_root / ".env"
    if not env_file.is_file():
        print("Creating .env file...")
        env_file.touch()

    print("======================================================================")
    print("D810-NG Docker Test Runner (compose)")
    print("======================================================================")
    print(f"Service:    {service}")
    print(f"Test Type:  {test_type}")
    print("======================================================================")

    unit_script = """
set -e
pip install -e .[dev]

# Run unit tests (no IDA required)
echo '========================================='
echo 'Running unit tests (no IDA required)...'
echo '========================================='
PYTHONPATH=src pytest tests/unit/ -v --tb=short
"""

    integration_script = """
set -e
pip install -e .[dev]

# Check if test binary exists
if [ ! -f samples/bins/libobfuscated.dll ]; then
  echo 'Test binary not found, skipping integration tests'
  exit 0
fi

# Run integration tests with pytest
echo ''
echo '========================================='
echo 'Running integration tests with pytest...'
echo '========================================='
pytest tests/system -v --tb=short --cov=src/d810 --cov-report=term-missing --cov-report=html --cov-report=xml --cov-append
"""

    def run_compose(script: str, title: str) -> int:
        print()
        print("=========================================")
        print(title)
        print("=========================================")
        return run(
            [
                "docker",
                "compose",
                "run",
                "--rm",
                "--entrypoint",
                "bash",
                service,
                "-c",
                script.strip(),
            ],
            cwd=repo_root,
        )

    if test_type == "unit":
        rc = run_compose(unit_script, "Running Unit Tests...")
    elif test_type == "integration":
        rc = run_compose(integration_script, "Running Integration Tests...")
    else:
        rc_unit = run_compose(unit_script, "Running Unit Tests...")
        rc_int = run_compose(integration_script, "Running Integration Tests...")
        if rc_unit != 0 or rc_int != 0:
            print()
            print("SOME TESTS FAILED", file=sys.stderr)
            return 1
        rc = 0

    print()
    print("=========================================")
    print("Docker Logs")
    print("=========================================")
    run(["docker", "compose", "logs", "--tail=50"], cwd=repo_root)

    if rc == 0:
        print()
        print("======================================================================")
        print("ALL TESTS PASSED")
        print("======================================================================")
    return rc


def _volume_arg(host_path: Path, container_path: str) -> str:
    return f"{host_path.resolve()}:{container_path}"


def system_dump_mode(
    repo_root: Path,
    command: str,
    worktree_rel: str | None,
    dump_function: str | None,
    dump_maturity: str | None,
    dump_project: str | None,
    dump_out: str | None,
    mount_logs: bool,
    extra_pytest: list[str],
) -> int:
    worktree_root = os.environ.get("D810_WORKTREE_ROOT", ".worktrees")
    work_dir = repo_root
    if worktree_rel:
        work_dir = repo_root / worktree_root / worktree_rel
        if not work_dir.is_dir():
            print(f"ERROR: Worktree not found: {work_dir}", file=sys.stderr)
            return 1

    work_dir = work_dir.resolve()
    docker_image = os.environ.get("D810_DOCKER_IMAGE", "idapro-9.3")
    env_no_cython = os.environ.get("D810_NO_CYTHON", "1")
    env_test_binary = os.environ.get("D810_TEST_BINARY", "libobfuscated.dll")

    docker_args = [
        "docker",
        "run",
        "--rm",
        "-v",
        _volume_arg(work_dir, _WORK),
        "-w",
        _WORK,
    ]

    for key, val in (
        ("IDA_PREFIX", _IDA_APP),
        ("IDA_INSTALL_DIR", _IDA_APP),
        ("D810_LIBCLANG_PATH", f"{_IDA_APP}/libclang.so"),
        ("PYTHONPATH", _PYTHONPATH_VAL),
        ("D810_NO_CYTHON", env_no_cython),
        ("D810_TEST_BINARY", env_test_binary),
    ):
        docker_args.extend(["-e", f"{key}={val}"])

    if mount_logs:
        logs_dir = work_dir / ".tmp" / "logs"
        logs_dir.mkdir(parents=True, exist_ok=True)
        docker_args.extend(["-v", _volume_arg(logs_dir, "/root/.idapro/logs")])

    if command == "system":
        inner = (
            f"{_EXPORT_IDA} && "
            f"{_PIP_INSTALL} && "
            f"{_SPEEDUPS} && "
            f"D810_NO_CYTHON={env_no_cython} D810_TEST_BINARY={env_test_binary} {_PYTEST_SYSTEM}"
        )
        docker_args.extend(["--entrypoint", "/bin/bash", docker_image, "-lc", inner])
        return run(docker_args)

    # dump
    dump_args = []
    if dump_function:
        dump_args.extend(["--dump-function-pseudocode", dump_function])
    if dump_maturity:
        dump_args.extend(["--dump-microcode-maturity", dump_maturity])
    if dump_project:
        dump_args.extend(["--dump-project", dump_project])
    dump_args.extend(extra_pytest)
    dump_args.append("-v")

    log_path = None
    if dump_out:
        (work_dir / ".tmp").mkdir(parents=True, exist_ok=True)
        log_path = work_dir / ".tmp" / dump_out
        log_path.write_text("", encoding="utf-8")

    cmd_parts = [
        _EXPORT_IDA,
        _PIP_INSTALL,
        _SPEEDUPS,
    ]
    pytest_inner = (
        f"D810_NO_CYTHON={env_no_cython} D810_TEST_BINARY={env_test_binary} {_PYTEST_DUMP} "
        + " ".join(shlex.quote(a) for a in dump_args)
    )
    if log_path is not None:
        log_in_container = f"{_WORK_TMP}/{dump_out}"
        cmd_parts.append(f': > "{log_in_container}"')
        cmd_parts.append(f'{pytest_inner} > "{log_in_container}" 2>&1')
    else:
        cmd_parts.append(pytest_inner)

    inner = " && ".join(cmd_parts)
    docker_args.extend(["--entrypoint", "/bin/bash", docker_image, "-lc", inner])
    return run(docker_args)


def main() -> int:
    extra_pytest = []
    if "--" in sys.argv:
        sep = sys.argv.index("--")
        extra_pytest = sys.argv[sep + 1 :]
        sys.argv = sys.argv[:sep]

    parser = argparse.ArgumentParser(
        description="Run d810 tests via Docker (compose or single image).",
        epilog="Compose: unit | integration | all + optional service. Image: system | dump + options.",
    )
    parser.add_argument(
        "command",
        choices=["unit", "integration", "all", "system", "dump"],
        help="unit/integration/all = compose; system/dump = single image",
    )
    parser.add_argument(
        "service_or_worktree",
        nargs="?",
        default=None,
        help="For compose: idapro-tests or idapro-tests-9.2. For system: not used (use --worktree).",
    )
    parser.add_argument("--worktree", "-w", metavar="REL", help="Worktree path under WORKTREE_ROOT")
    parser.add_argument("--function", "-f", metavar="NAME", help="--dump-function-pseudocode (dump only)")
    parser.add_argument("--maturity", "-m", metavar="LIST", help="--dump-microcode-maturity (dump only)")
    parser.add_argument("--project", "-p", metavar="NAME", help="--dump-project (dump only)")
    parser.add_argument("--out", "-o", metavar="FILE", help="Redirect dump output to .tmp/FILE (dump only)")
    parser.add_argument("--logs", "-l", action="store_true", help="Mount .tmp/logs at /root/.idapro/logs")
    parser.add_argument("extra", nargs="*", default=[], help="Extra args for pytest (dump only; put after --)")

    args = parser.parse_args()
    if extra_pytest:
        args.extra = extra_pytest

    if shutil.which("docker") is None:
        print("ERROR: docker not found in PATH", file=sys.stderr)
        return 1

    repo_root = get_repo_root()

    if args.command in ("unit", "integration", "all"):
        service = args.service_or_worktree or "idapro-tests"
        if service not in ("idapro-tests", "idapro-tests-9.2"):
            print("ERROR: Invalid service. Must be 'idapro-tests' or 'idapro-tests-9.2'", file=sys.stderr)
            return 1
        return compose_mode(repo_root, args.command, service)

    return system_dump_mode(
        repo_root,
        args.command,
        worktree_rel=args.worktree,
        dump_function=args.function,
        dump_maturity=args.maturity,
        dump_project=args.project,
        dump_out=args.out,
        mount_logs=args.logs,
        extra_pytest=args.extra,
    )


if __name__ == "__main__":
    sys.exit(main() or 0)
