import json
import os
import shutil
import subprocess
from pathlib import Path

import pytest


REPO_ROOT = Path(__file__).resolve().parents[3]
LAUNCHER = REPO_ROOT / "tools" / "scripts" / "run_ida_gui_docker.sh"
GUI_IMAGE = "test-gui-image"
WORKTREE_NAME = "truthful-config-v2-project-ui"


def _write_checkout(path: Path) -> None:
    (path / "src").mkdir(parents=True, exist_ok=True)
    (path / "ida-plugin.json").write_text(
        '{"plugin": {"entryPoint": "src/d810ng.py"}}\n',
        encoding="utf-8",
    )
    (path / "src" / "d810ng.py").write_text(
        "def PLUGIN_ENTRY():\n    return None\n",
        encoding="utf-8",
    )


def _parse_docker_calls(path: Path) -> list[list[str]]:
    if not path.exists():
        return []
    calls: list[list[str]] = []
    for line in path.read_text(encoding="utf-8").splitlines():
        if line == "CALL":
            calls.append([])
        else:
            assert line.startswith("ARG="), line
            calls[-1].append(line.removeprefix("ARG="))
    return calls


def _run(
    tmp_path: Path,
    *args: str,
    extra_env: dict[str, str] | None = None,
) -> tuple[subprocess.CompletedProcess[str], list[list[str]], dict[str, Path]]:
    if not LAUNCHER.is_file():
        pytest.fail(f"launcher missing: {LAUNCHER}")

    repo = tmp_path / "repo"
    _write_checkout(repo)
    worktree = repo / ".worktrees" / WORKTREE_NAME
    _write_checkout(worktree)
    alternate_worktree = repo / ".claude" / "worktrees" / "agent-ui"
    _write_checkout(alternate_worktree)
    outside = repo / "outside"
    _write_checkout(outside)

    samples = repo / "samples" / "bins"
    samples.mkdir(parents=True)
    (samples / "database with space.i64").write_text("sample", encoding="utf-8")

    ida_user = tmp_path / "ida-user"
    ida_user.mkdir()
    (ida_user / "idapro.hexlic").write_text("license", encoding="utf-8")
    d810_config = ida_user / "cfg" / "d810"
    d810_config.mkdir(parents=True)
    d810_logs = ida_user / "logs"
    d810_logs.mkdir()
    (d810_config / "options.json").write_text(
        json.dumps({"log_dir": str(d810_logs)}) + "\n",
        encoding="utf-8",
    )

    script = tmp_path / "run_ida_gui_docker.sh"
    shutil.copy2(LAUNCHER, script)
    script.chmod(0o755)

    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    docker_log = tmp_path / "docker.log"
    docker = bin_dir / "docker"
    docker.write_text(
        """#!/usr/bin/env bash
set -eu
{
  printf 'CALL\\n'
  for arg in "$@"; do
    printf 'ARG=%s\\n' "$arg"
  done
} >> "$DOCKER_LOG"
if [ "${1:-}" = image ] && [ "${2:-}" = inspect ]; then
  [ "${MOCK_IMAGE_EXISTS:-1}" = 1 ]
fi
""",
        encoding="utf-8",
    )
    docker.chmod(0o755)

    xhost = bin_dir / "xhost"
    xhost.write_text(
        """#!/usr/bin/env bash
set -eu
[ "${MOCK_XHOST_FAIL:-0}" = 0 ] || exit 1
printf '%s\\n' 'access control enabled, only authorized clients can connect'
printf '%s\\n' "${MOCK_XHOST_ACCESS:-INET:localhost}"
""",
        encoding="utf-8",
    )
    xhost.chmod(0o755)

    env = os.environ.copy()
    for name in (
        "D810_REPO_ROOT",
        "D810_WORKTREE_ROOT",
        "D810_GUI_DOCKER_IMAGE",
        "D810_DOCKER_MEMORY",
        "D810_IDA_USER_DIR",
        "D810_GUI_DISPLAY",
        "D810_XHOST_BIN",
        "MOCK_IMAGE_EXISTS",
        "MOCK_XHOST_FAIL",
        "MOCK_XHOST_ACCESS",
        "D810_DEBUG_LOGGING",
        "D810_DIAG_SNAPSHOT",
        "D810_FACT_LIFECYCLE",
    ):
        env.pop(name, None)
    env.update(
        {
            "PATH": f"{bin_dir}:{env['PATH']}",
            "DOCKER_LOG": str(docker_log),
            "D810_REPO_ROOT": str(repo),
            "D810_GUI_DOCKER_IMAGE": GUI_IMAGE,
            "D810_IDA_USER_DIR": str(ida_user),
            "D810_XHOST_BIN": str(xhost),
        }
    )
    if extra_env:
        env.update(extra_env)

    result = subprocess.run(
        [str(script), *args],
        check=False,
        capture_output=True,
        text=True,
        env=env,
    )
    paths = {
        "repo": repo,
        "worktree": worktree,
        "alternate_worktree": alternate_worktree,
        "outside": outside,
        "samples": samples,
        "ida_user": ida_user,
        "d810_config": d810_config,
        "d810_logs": d810_logs,
    }
    return result, _parse_docker_calls(docker_log), paths


def _assert_pair(args: list[str], flag: str, value: str) -> None:
    assert any(
        args[index] == flag and args[index + 1] == value
        for index in range(len(args) - 1)
    ), (flag, value, args)


def test_default_launch_mounts_root_checkout_portable_d810_state_and_samples(
    tmp_path: Path,
) -> None:
    result, calls, paths = _run(tmp_path)

    assert result.returncode == 0, result.stderr
    assert calls[0] == ["image", "inspect", GUI_IMAGE]
    run = calls[1]
    assert run[:2] == ["run", "--rm"]
    _assert_pair(run, "--memory", "4g")
    _assert_pair(run, "-w", "/work")
    for value in (
        "MODE=x11",
        "DISPLAY=host.docker.internal:0",
        "LIBGL_ALWAYS_SOFTWARE=1",
        "PYTHONPATH=/root/.idapro/plugins/d810/src:/app/ida/python",
    ):
        _assert_pair(run, "-e", value)
    for value in (
        f"{paths['repo']}:/work",
        f"{paths['d810_config']}:/root/.idapro/cfg/d810",
        f"{paths['d810_logs']}:/root/.idapro/logs",
        f"{paths['d810_logs']}:{paths['d810_logs']}",
        f"{paths['repo']}:/root/.idapro/plugins/d810",
        f"{paths['samples']}:/samples/bins:ro",
    ):
        _assert_pair(run, "-v", value)
    assert f"{paths['ida_user']}:/root/.idapro" not in run
    _assert_pair(run, "--entrypoint", "/app/ida/entrypoint.sh")
    assert run[-1] == GUI_IMAGE
    assert f"checkout:  {paths['repo']}" in result.stdout
    assert f"d810 cfg:  {paths['d810_config']}" in result.stdout
    assert f"d810 logs: {paths['d810_logs']}" in result.stdout


def test_worktree_launch_copies_sample_database_and_preserves_other_ida_arguments(
    tmp_path: Path,
) -> None:
    result, calls, paths = _run(
        tmp_path,
        "-w",
        WORKTREE_NAME,
        "--",
        "-A",
        "/samples/bins/database with space.i64",
    )

    assert result.returncode == 0, result.stderr
    run = calls[-1]
    _assert_pair(run, "-v", f"{paths['worktree']}:/work")
    _assert_pair(
        run,
        "-v",
        f"{paths['worktree']}:/root/.idapro/plugins/d810",
    )
    copies = list((paths["worktree"] / ".tmp" / "ida-gui").glob("*.i64"))
    assert len(copies) == 1
    assert copies[0].read_text(encoding="utf-8") == "sample"
    assert (paths["samples"] / "database with space.i64").read_text(
        encoding="utf-8"
    ) == "sample"
    image_index = run.index(GUI_IMAGE)
    assert run[image_index + 1 :] == [
        "-A",
        f"/work/.tmp/ida-gui/{copies[0].name}",
    ]


def test_system_runner_compatible_runtime_options_are_forwarded(tmp_path: Path) -> None:
    result, calls, _paths = _run(
        tmp_path,
        "-l",
        "--enable-debug-logging",
        "--enable-diag-snapshot",
        "--disable-fact-lifecycle",
        extra_env={"D810_DOCKER_MEMORY": "6g", "D810_CUSTOM_GUI_TEST": "yes"},
    )

    assert result.returncode == 0, result.stderr
    run = calls[-1]
    _assert_pair(run, "--memory", "6g")
    for value in (
        "D810_DEBUG_LOGGING=1",
        "D810_DIAG_SNAPSHOT=1",
        "D810_FACT_LIFECYCLE=0",
        "D810_CUSTOM_GUI_TEST=yes",
    ):
        _assert_pair(run, "-e", value)
    assert "logs:     persistent D810 logs enabled (-l compatibility)" in result.stdout


def test_alternate_worktree_root_is_honored(tmp_path: Path) -> None:
    result, calls, paths = _run(
        tmp_path,
        "-w",
        "agent-ui",
        extra_env={"D810_WORKTREE_ROOT": ".claude/worktrees"},
    )

    assert result.returncode == 0, result.stderr
    _assert_pair(calls[-1], "-v", f"{paths['alternate_worktree']}:/work")


def test_missing_worktree_fails_before_docker(tmp_path: Path) -> None:
    result, calls, paths = _run(tmp_path, "-w", "missing")

    assert result.returncode != 0
    assert str(paths["repo"] / ".worktrees" / "missing") in result.stderr
    assert calls == []


def test_worktree_escape_is_rejected(tmp_path: Path) -> None:
    result, calls, _paths = _run(tmp_path, "-w", "../outside")

    assert result.returncode != 0
    assert "escapes worktree root" in result.stderr
    assert calls == []


def test_checkout_without_plugin_descriptor_is_rejected(tmp_path: Path) -> None:
    invalid = tmp_path / "invalid-checkout"
    (invalid / "src").mkdir(parents=True)
    (invalid / "src" / "d810ng.py").write_text("", encoding="utf-8")
    result, calls, _paths = _run(
        tmp_path / "run",
        extra_env={"D810_REPO_ROOT": str(invalid)},
    )

    assert result.returncode != 0
    assert "ida-plugin.json" in result.stderr
    assert calls == []


def test_unavailable_xquartz_prints_recovery_commands(tmp_path: Path) -> None:
    result, calls, _paths = _run(
        tmp_path,
        extra_env={"MOCK_XHOST_FAIL": "1"},
    )

    assert result.returncode != 0
    assert "open -a XQuartz" in result.stderr
    assert "/opt/X11/bin/xhost +localhost" in result.stderr
    assert calls == []


def test_xquartz_without_localhost_authorization_is_rejected(
    tmp_path: Path,
) -> None:
    result, calls, _paths = _run(
        tmp_path,
        extra_env={"MOCK_XHOST_ACCESS": "SI:localuser:test"},
    )

    assert result.returncode != 0
    assert "localhost is not authorized" in result.stderr
    assert calls == []


def test_missing_gui_image_fails_before_docker_run(tmp_path: Path) -> None:
    result, calls, _paths = _run(
        tmp_path,
        extra_env={"MOCK_IMAGE_EXISTS": "0"},
    )

    assert result.returncode != 0
    assert GUI_IMAGE in result.stderr
    assert calls == [["image", "inspect", GUI_IMAGE]]


def test_help_documents_worktrees_state_and_sample_mount(tmp_path: Path) -> None:
    result, calls, _paths = _run(tmp_path, "--help")

    assert result.returncode == 0, result.stderr
    assert "-w, --worktree" in result.stdout
    assert "D810_WORKTREE_ROOT" in result.stdout
    assert "D810_IDA_USER_DIR" in result.stdout
    assert "--enable-debug-logging" in result.stdout
    assert "--enable-diag-snapshot" in result.stdout
    assert "--disable-fact-lifecycle" in result.stdout
    assert "copy" in result.stdout.lower()
    assert "/samples/bins" in result.stdout
    assert calls == []
