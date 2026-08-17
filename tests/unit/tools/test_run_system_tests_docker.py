import os
import shutil
import subprocess
from pathlib import Path

import pytest


REPO_ROOT = Path(__file__).resolve().parents[3]
DOCKER_RUNNER = REPO_ROOT / "tools" / "scripts" / "run_system_tests_docker.sh"
RUNTIME_LABEL = "dev-emulation-z3-v1"


def _make_harness(tmp_path: Path) -> tuple[Path, Path]:
    script = tmp_path / "tools" / "scripts" / DOCKER_RUNNER.name
    script.parent.mkdir(parents=True, exist_ok=True)
    shutil.copy2(DOCKER_RUNNER, script)

    bin_dir = tmp_path / "bin"
    bin_dir.mkdir(exist_ok=True)
    docker_log = tmp_path / "docker.log"
    docker = bin_dir / "docker"
    docker.write_text(
        """#!/usr/bin/env bash
set -eu
printf '%s\\n' "$*" >> "$DOCKER_LOG"
if [ "${1:-}" = image ] && [ "${2:-}" = inspect ]; then
  printf '%s\\n' "${MOCK_DOCKER_LABEL:-}"
fi
if [ "${1:-}" = run ]; then
  exit "${MOCK_DOCKER_RUN_EXIT:-0}"
fi
""",
        encoding="utf-8",
    )
    docker.chmod(0o755)
    return script, docker_log


def _run(
    tmp_path: Path,
    *args: str,
    label: str = "",
    no_cython: str = "1",
    image: str | None = "test-runtime-image",
    dotenv: str | None = None,
    extra_env: dict[str, str] | None = None,
) -> tuple[subprocess.CompletedProcess[str], list[str]]:
    script, docker_log = _make_harness(tmp_path)
    if dotenv is not None:
        (tmp_path / ".env").write_text(dotenv, encoding="utf-8")
    env = os.environ.copy()
    env.pop("D810_DOCKER_IMAGE", None)
    env.pop("D810_API_TOKEN", None)
    env.update(
        {
            "PATH": f"{tmp_path / 'bin'}:{env['PATH']}",
            "DOCKER_LOG": str(docker_log),
            "MOCK_DOCKER_LABEL": label,
            "D810_REPO_ROOT": str(tmp_path),
            "D810_NO_CYTHON": no_cython,
        }
    )
    if image is not None:
        env["D810_DOCKER_IMAGE"] = image
    if extra_env is not None:
        env.update(extra_env)
    result = subprocess.run(
        [str(script), *args],
        check=False,
        capture_output=True,
        text=True,
        env=env,
    )
    calls = (
        docker_log.read_text(encoding="utf-8").splitlines()
        if docker_log.exists()
        else []
    )
    return result, calls


def _container_run(calls: list[str]) -> str:
    runs = [call for call in calls if call.startswith("run ")]
    assert len(runs) == 1, calls
    return runs[0]


@pytest.mark.parametrize(
    "args",
    [
        ("system",),
        ("test",),
        ("dump",),
        ("shell",),
        ("exec", "--", "true"),
    ],
)
def test_baked_runtime_validates_dependencies_in_every_mode(
    tmp_path: Path,
    args: tuple[str, ...],
) -> None:
    result, calls = _run(tmp_path, *args, label=RUNTIME_LABEL)

    assert result.returncode == 0, result.stderr
    assert any(call.startswith("image inspect ") for call in calls)
    command = _container_run(calls)
    assert "from d810.speedups import bootstrap" in command
    assert "import pytest, unicorn, z3, egglog" in command
    assert "/app/ida/.venv/bin/python -c" in command
    assert "z3.get_version()" in command
    assert "command -v git" in command
    assert ".[dev,emulation,egraph]" in command
    assert "d810.speedups.install" in command
    assert "baked runtime dependencies detected" in command
    assert "baked runtime is stale" in command


def test_unlabeled_runtime_keeps_dependency_setup(tmp_path: Path) -> None:
    result, calls = _run(tmp_path, "exec", "--", "true")

    assert result.returncode == 0, result.stderr
    command = _container_run(calls)
    assert ".[dev,emulation,egraph]" in command
    assert "d810.speedups.install" in command


def test_reports_docker_completion_and_preserves_failure_status(tmp_path: Path) -> None:
    success, _ = _run(tmp_path, "exec", "--", "true")

    assert success.returncode == 0, success.stderr
    assert (
        "[docker] starting container; native speedup builds may take several minutes"
        in success.stdout
    )
    assert "[docker] container completed successfully (exit=0)" in success.stdout

    failed, _ = _run(
        tmp_path,
        "exec",
        "--",
        "true",
        extra_env={"MOCK_DOCKER_RUN_EXIT": "23"},
    )

    assert failed.returncode == 23
    assert "[docker] container failed with exit status 23" in failed.stderr


def test_baked_runtime_preserves_native_cython_build(tmp_path: Path) -> None:
    result, calls = _run(
        tmp_path,
        "exec",
        "--",
        "true",
        label=RUNTIME_LABEL,
        no_cython="0",
    )

    assert result.returncode == 0, result.stderr
    command = _container_run(calls)
    assert ".[dev,emulation,egraph]" in command
    assert "command -v git" in command
    assert "D810_BUILD_SPEEDUPS=1" in command
    assert "DEBUG=1 D810_BUILD_SPEEDUPS=1" not in command
    assert "pip install -e .[speedups]" in command


def test_cython_profile_build_enables_cython_tracing_only_for_native_mode(
    tmp_path: Path,
) -> None:
    result, calls = _run(
        tmp_path,
        "exec",
        "--",
        "true",
        label=RUNTIME_LABEL,
        no_cython="0",
        extra_env={"D810_CYTHON_PROFILE": "1"},
    )

    assert result.returncode == 0, result.stderr
    command = _container_run(calls)
    assert "DEBUG=1 D810_BUILD_SPEEDUPS=1" in command
    assert "D810_CYTHON_PROFILE=1" in command
    assert "profile build failed" not in command


def test_cython_profile_rejects_pure_python_mode(tmp_path: Path) -> None:
    result, calls = _run(
        tmp_path,
        "exec",
        "--",
        "true",
        extra_env={"D810_CYTHON_PROFILE": "1"},
    )

    assert result.returncode != 0
    assert calls == []
    assert "D810_CYTHON_PROFILE=1 requires D810_NO_CYTHON=0" in result.stderr


def test_native_profile_mode_adds_only_required_capabilities_and_tools(
    tmp_path: Path,
) -> None:
    result, calls = _run(
        tmp_path,
        "exec",
        "--",
        "true",
        label=RUNTIME_LABEL,
        extra_env={"D810_NATIVE_PROFILE": "1"},
    )

    assert result.returncode == 0, result.stderr
    command = _container_run(calls)
    assert "--cap-add=PERFMON" in command
    assert "--cap-add=SYS_PTRACE" in command
    assert "--security-opt=seccomp=unconfined" in command
    assert "--privileged" not in command
    assert "apt-get install -y --no-install-recommends linux-perf" in command
    assert "/app/ida/.venv/bin/pip install -q py-spy" in command
    assert "D810_NATIVE_PROFILE=1" in command


def test_native_profile_mode_is_opt_in_and_validated(tmp_path: Path) -> None:
    normal, normal_calls = _run(tmp_path / "normal", "exec", "--", "true")
    assert normal.returncode == 0, normal.stderr
    normal_command = _container_run(normal_calls)
    assert "--cap-add=PERFMON" not in normal_command
    assert "linux-perf" not in normal_command
    assert "py-spy" not in normal_command

    invalid, invalid_calls = _run(
        tmp_path / "invalid",
        "exec",
        "--",
        "true",
        extra_env={"D810_NATIVE_PROFILE": "yes"},
    )
    assert invalid.returncode != 0
    assert invalid_calls == []
    assert "D810_NATIVE_PROFILE must be 0 or 1" in invalid.stderr


def test_baked_runtime_preserves_llvm_provisioning(tmp_path: Path) -> None:
    result, calls = _run(
        tmp_path,
        "exec",
        "--enable-llvm-opt",
        "--",
        "true",
        label=RUNTIME_LABEL,
    )

    assert result.returncode == 0, result.stderr
    command = _container_run(calls)
    assert "apt-get install -y --no-install-recommends llvm" in command
    assert ".[dev,emulation,egraph]" in command
    assert "command -v git" in command


def test_dotenv_image_overrides_hardcoded_default(tmp_path: Path) -> None:
    result, calls = _run(
        tmp_path,
        "exec",
        "--",
        "true",
        label=RUNTIME_LABEL,
        image=None,
        dotenv="D810_DOCKER_IMAGE=dotenv-runtime-image\n",
    )

    assert result.returncode == 0, result.stderr
    assert "source=.env, overrides default=idapro-9.4" in result.stdout
    command = _container_run(calls)
    assert "dotenv-runtime-image" in command
    assert "D810_TEST_RUNTIME_IMAGE=dotenv-runtime-image" in command
    assert "D810_TEST_RUNTIME_IMAGE_ID=" in command


def test_process_environment_overrides_dotenv(tmp_path: Path) -> None:
    result, calls = _run(
        tmp_path,
        "exec",
        "--",
        "true",
        label=RUNTIME_LABEL,
        image="exported-runtime-image",
        dotenv="D810_DOCKER_IMAGE=dotenv-runtime-image\n",
    )

    assert result.returncode == 0, result.stderr
    assert "source=process environment" in result.stdout
    assert "overrides .env=dotenv-runtime-image" in result.stdout
    assert "exported-runtime-image" in _container_run(calls)


def test_override_trace_redacts_sensitive_values(tmp_path: Path) -> None:
    result, _calls = _run(
        tmp_path,
        "exec",
        "--",
        "true",
        dotenv="D810_API_TOKEN=dotenv-secret\n",
        extra_env={"D810_API_TOKEN": "exported-secret"},
    )

    assert result.returncode == 0, result.stderr
    assert "D810_API_TOKEN=<redacted>" in result.stdout
    assert "overrides .env=<redacted>" in result.stdout
    assert "dotenv-secret" not in result.stdout
    assert "exported-secret" not in result.stdout


def test_malformed_dotenv_fails_with_line_number(tmp_path: Path) -> None:
    result, _calls = _run(
        tmp_path,
        "exec",
        "--",
        "true",
        dotenv="this is not an assignment\n",
    )

    assert result.returncode != 0
    assert ".env:1: malformed entry" in result.stderr


def test_explicit_empty_image_does_not_fall_back_to_dotenv(tmp_path: Path) -> None:
    result, calls = _run(
        tmp_path,
        "exec",
        "--",
        "true",
        image="",
        dotenv="D810_DOCKER_IMAGE=dotenv-runtime-image\n",
    )

    assert result.returncode != 0
    assert calls == []
    assert "source=process environment" in result.stdout
    assert "D810_DOCKER_IMAGE is set but empty" in result.stderr
