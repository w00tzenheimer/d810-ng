import getpass
import hashlib
import os
import re
import shutil
import subprocess
import zipfile
from pathlib import Path

import pytest

from d810.core.typing import NamedTuple

from tests.cobra_published_identity import (
    PUBLISHED_IDENTITY_FILE,
    published_identity,
)


REPO_ROOT = Path(__file__).resolve().parents[3]
DOCKER_RUNNER = REPO_ROOT / "tools" / "scripts" / "run_system_tests_docker.sh"
RUNTIME_LABEL = "dev-emulation-z3-v1"
# Derived, never re-declared: docker/cobra-bake/published_identity is the one
# place these values are written down, and the runner reads the same file. A
# second copy here is how a wheel rotation passes its own file's tests while
# disagreeing with the runner it is testing.
PUBLISHED_IDENTITY = PUBLISHED_IDENTITY_FILE
_IDENTITY = published_identity()
COBRA_WHEEL_VERSION = _IDENTITY.version
COBRA_WHEEL_AARCH64_NAME = _IDENTITY.wheels["aarch64"].filename
COBRA_WHEEL_AARCH64_SHA256 = _IDENTITY.wheels["aarch64"].sha256
COBRA_WHEEL_X86_64_NAME = _IDENTITY.wheels["x86_64"].filename
COBRA_WHEEL_X86_64_SHA256 = _IDENTITY.wheels["x86_64"].sha256
COBRA_WHEEL_PREFLIGHT_AARCH64_SHA256 = (
    "b71d40e45146004a968a96a1b17493b16ac04f2a98e41c12a1f87a38ddf3ab25"
)
COBRA_WHEEL_PUBLISHED_DIR = "0.1.5-published"
COBRA_WHEEL_PREFLIGHT_DIR = "0.1.5-preflight"
COBRA_WHEEL_TAG_COMMIT = _IDENTITY.tag_commit
COBRA_WHEEL_CORE_COMMIT = _IDENTITY.core_commit
COBRA_WHEEL_CONTAINER_DIR = "/opt/d810-cobra-wheel"
# The runner refuses to run unless `docker image inspect --format '{{.Id}}'`
# yields a real digest, so the fake engine has to answer with one.
FAKE_IMAGE_ID = "sha256:" + "1f" * 32


def _cobra_wheel(directory: str, name: str) -> Path | None:
    """Return a stored CoBRA wheel path, or None when it is not available.

    The wheels are preserved outside git under ``_gitless/``, which exists in
    the main checkout but not in every worktree, so look upward from this
    checkout instead of hard-coding a host path.
    """
    if os.environ.get("D810_TEST_HIDE_COBRA_WHEELS"):
        # Simulate a checkout without the out-of-git wheel directory, which is
        # what CI sees. Without this there is no way to prove locally that the
        # fixture fallback is the one exercised there.
        return None
    for base in (REPO_ROOT, *REPO_ROOT.parents):
        candidate = base / "_gitless" / "resource" / "cobra-wheels" / directory / name
        if candidate.is_file():
            return candidate
    return None


def _recorded_wheel(name: str) -> Path | None:
    """Return the PUBLISHED wheel, which is the only accepted identity."""
    return _cobra_wheel(COBRA_WHEEL_PUBLISHED_DIR, name)


COBRA_FIXTURE_DIR = Path(__file__).resolve().parent / "fixtures" / "cobra-wheel-harness"
COBRA_FIXTURE_WHEELS = {
    "aarch64": (
        "d810_cobra-0.1.5-cp313-cp313-harness_fixture_aarch64.whl",
        "bd5889898fa82481bdcf1e06c89f2559469bd76308fbcd9729c2e0bbfac4856b",
    ),
    "x86_64": (
        "d810_cobra-0.1.5-cp313-cp313-harness_fixture_x86_64.whl",
        "43a2d7272d320c75d3212e53b5592a6f914a234a618eccc9932063896f7ee882",
    ),
}
COBRA_PUBLISHED_WHEELS = {
    "aarch64": (COBRA_WHEEL_AARCH64_NAME, COBRA_WHEEL_AARCH64_SHA256),
    "x86_64": (COBRA_WHEEL_X86_64_NAME, COBRA_WHEEL_X86_64_SHA256),
}


class WheelUnderTest(NamedTuple):
    """A wheel the runner will accept, and the environment that names it."""

    path: Path
    name: str
    sha256: str
    #: The word the runner prints for this identity: a fixture must never read
    #: as a published artifact.
    identity: str
    env: dict[str, str]


def _wheel_under_test(arch: str = "aarch64") -> WheelUnderTest:
    """The published wheel when it is present, else the committed fixture.

    The published wheels are megabytes and live outside git, so on a checkout
    without them every positive wheel-mode test used to skip - and a skipped
    test cannot notice that the directory it needs has been deleted. The
    fixture is a real, valid .whl with a recorded hash; the runner accepts it
    only when D810_COBRA_HARNESS_WHEEL_SHA256 names it, and says loudly that
    it is not a production artifact.
    """
    name, sha256 = COBRA_PUBLISHED_WHEELS[arch]
    published = _recorded_wheel(name)
    if published is not None:
        return WheelUnderTest(
            path=published,
            name=name,
            sha256=sha256,
            identity="published",
            env={
                "D810_COBRA_WHEEL": str(published),
                "D810_COBRA_WHEEL_SHA256": sha256,
            },
        )
    name, sha256 = COBRA_FIXTURE_WHEELS[arch]
    fixture = COBRA_FIXTURE_DIR / name
    assert fixture.is_file(), fixture
    return WheelUnderTest(
        path=fixture,
        name=name,
        sha256=sha256,
        identity="harness-fixture",
        env={
            "D810_COBRA_WHEEL": str(fixture),
            "D810_COBRA_WHEEL_SHA256": sha256,
            "D810_COBRA_HARNESS_WHEEL_SHA256": sha256,
        },
    )
MANIFEST_ALLOWLIST = REPO_ROOT / "tools" / "scripts" / "remote_manifest_extra.txt"


def _make_harness(
    tmp_path: Path,
    repo_root: Path | None = None,
) -> tuple[Path, Path]:
    root = repo_root if repo_root is not None else tmp_path
    script = root / "tools" / "scripts" / DOCKER_RUNNER.name
    script.parent.mkdir(parents=True, exist_ok=True)
    shutil.copy2(DOCKER_RUNNER, script)
    # The runner reads its allowlist from beside itself.
    shutil.copy2(MANIFEST_ALLOWLIST, script.parent / MANIFEST_ALLOWLIST.name)
    # ... and every accepted CoBRA identity from the one tracked source, two
    # levels up. A harness that omitted it would exercise a runner that has no
    # published wheel table at all.
    staged_identity = root / PUBLISHED_IDENTITY.relative_to(REPO_ROOT)
    staged_identity.parent.mkdir(parents=True, exist_ok=True)
    shutil.copy2(PUBLISHED_IDENTITY, staged_identity)

    bin_dir = tmp_path / "bin"
    bin_dir.mkdir(exist_ok=True)
    docker_log = tmp_path / "docker.log"
    docker = bin_dir / "docker"
    docker.write_text(
        """#!/usr/bin/env bash
set -eu
printf 'docker-host %s\\n' "${DOCKER_HOST:-}" >> "$DOCKER_LOG"
printf '%s\\n' "$*" >> "$DOCKER_LOG"
if [ "${1:-}" = info ]; then
  printf '%s %s\\n' "${MOCK_DOCKER_OSTYPE:-linux}" "${MOCK_DOCKER_ARCH:-x86_64}"
  exit 0
fi
if [ "${1:-}" = volume ] && [ "${2:-}" = inspect ]; then
  case "${3:-}" in
    d810-work-*|d810-cobra-*)
      if [ -z "${MOCK_WORK_VOLUME_EXISTS:-}" ]; then
        printf 'Error response from daemon: get %s: no such volume\\n' "${3:-}" >&2
        exit 1
      fi
      printf '[]\\n'
      exit 0
      ;;
  esac
  if [ -n "${MOCK_DOCKER_VOLUME_MISSING:-}" ]; then
    printf 'Error response from daemon: get %s: no such volume\\n' "${3:-}" >&2
    exit 1
  fi
  printf '[]\\n'
  exit 0
fi
if [ "${1:-}" = volume ] && [ "${2:-}" = create ]; then
  if [ -n "${MOCK_WORK_VOLUME_CREATE_FAILS:-}" ]; then
    printf 'Error response from daemon: cannot create volume\\n' >&2
    exit 1
  fi
  exit 0
fi
if [ "${1:-}" = image ] && [ "${2:-}" = inspect ]; then
  if [ -n "${MOCK_DOCKER_IMAGE_MISSING:-}" ]; then
    printf 'Error response from daemon: No such image\\n' >&2
    exit 1
  fi
  case "$*" in
    *'{{.Id}}'*)
      if [ -n "${MOCK_DOCKER_IMAGE_ID_FAILS:-}" ]; then
        printf 'Error response from daemon: No such image\\n' >&2
        exit 1
      fi
      printf '%s\\n' "${MOCK_DOCKER_IMAGE_ID-@FAKE_IMAGE_ID@}"
      exit 0
      ;;
    *'org.d810.cobra.version'*)
      # The baked-CoBRA labels are read in ONE inspect, as a |-joined row, and
      # a remote engine is a different machine with its own copy of the tag.
      if [ -n "${DOCKER_HOST:-}" ]; then
        printf '%s\\n' "${MOCK_DOCKER_REMOTE_COBRA_LABELS-${MOCK_DOCKER_COBRA_LABELS:-||||}}"
      else
        printf '%s\\n' "${MOCK_DOCKER_COBRA_LABELS:-||||}"
      fi
      exit 0
      ;;
  esac
  printf '%s\\n' "${MOCK_DOCKER_LABEL:-}"
fi
if [ "${1:-}" = version ]; then
  if [ -n "${DOCKER_HOST:-}" ]; then
    printf '%s\\n' "${MOCK_DOCKER_REMOTE_SERVER_ARCH:-${MOCK_DOCKER_SERVER_ARCH:-arm64}}"
  else
    printf '%s\\n' "${MOCK_DOCKER_SERVER_ARCH:-arm64}"
  fi
fi
if [ "${1:-}" = run ]; then
  case "$*" in
    *"--entrypoint /bin/date"*)
      for arg in "$@"; do
        printf 'run-arg %s\n' "$arg" >> "$DOCKER_LOG"
      done
      if [ -n "${MOCK_ENGINE_CLOCK_FAILS:-}" ]; then
        exit 1
      fi
      if [ -n "${MOCK_ENGINE_CLOCK_OFFSET:-}" ]; then
        printf '%s\n' "$(( $(/bin/date -u +%s) + MOCK_ENGINE_CLOCK_OFFSET ))"
      else
        /bin/date -u +%s
      fi
      exit 0
      ;;
  esac
  if [ -n "${MOCK_DOCKER_EXPECT_SOURCE_FILE:-}" ]; then
    source_mount=""
    for arg in "$@"; do
      case "$arg" in
        *:/opt/d810-cobra-source:ro) source_mount="${arg%:/opt/d810-cobra-source:ro}" ;;
      esac
    done
    test -n "$source_mount"
    test "$(cat "$source_mount/$MOCK_DOCKER_EXPECT_SOURCE_FILE")" = "$MOCK_DOCKER_EXPECT_SOURCE_CONTENT"
  fi
  for arg in "$@"; do
    printf 'run-arg %s\n' "$arg" >> "$DOCKER_LOG"
  done
  if [ -n "${MOCK_DOCKER_EVALUATE_OUTPUT_REDIR:-}" ]; then
    inner="${!#}"
    case "$inner" in
      *"/work/.tmp/"*)
        redirection="${inner##*> }"
        (cd "$MOCK_DOCKER_EVALUATE_OUTPUT_REDIR" && bash -c "true > $redirection") || true
        ;;
    esac
  fi
  case "$*" in
    *dst=/probe*) exit "${MOCK_DOCKER_PROBE_EXIT:-0}" ;;
  esac
  exit "${MOCK_DOCKER_RUN_EXIT:-0}"
fi
""".replace("@FAKE_IMAGE_ID@", FAKE_IMAGE_ID),
        encoding="utf-8",
    )
    docker.chmod(0o755)

    # The runner grants a .tmp-scoped ACL on the Mac before launching; record
    # every invocation so tests can prove what it touched, then defer to the
    # real chmod for the ordinary mode changes the script also makes.
    chmod_stub = bin_dir / "chmod"
    chmod_stub.write_text(
        """#!/usr/bin/env bash
set -eu
printf '%s\n' "$*" >> "${CHMOD_LOG:-/dev/null}"
case "${1:-}" in
  +a|-a#)
    if [ -n "${MOCK_CHMOD_ACL_FAIL_TARGET:-}" ] && [ "${!#}" = "$MOCK_CHMOD_ACL_FAIL_TARGET" ]; then
      exit 1
    fi
    exit "${MOCK_CHMOD_ACL_EXIT:-0}"
    ;;
esac
exec /bin/chmod "$@"
""",
        encoding="utf-8",
    )
    chmod_stub.chmod(0o755)

    uname_stub = bin_dir / "uname"
    uname_stub.write_text(
        """#!/usr/bin/env bash
set -eu
if [ "${1:-}" = "-s" ] && [ -n "${MOCK_UNAME_S:-}" ]; then
  printf '%s\n' "$MOCK_UNAME_S"
  exit 0
fi
exec /usr/bin/uname "$@"
""",
        encoding="utf-8",
    )
    uname_stub.chmod(0o755)
    return script, docker_log


def _run(
    tmp_path: Path,
    *args: str,
    label: str = "",
    no_cython: str | None = "1",
    image: str | None = "test-runtime-image",
    dotenv: str | None = None,
    extra_env: dict[str, str] | None = None,
    mock_git: str | None = None,
    repo_root: Path | None = None,
    allowlist: str | None = None,
) -> tuple[subprocess.CompletedProcess[str], list[str]]:
    root = repo_root if repo_root is not None else tmp_path
    script, docker_log = _make_harness(tmp_path, repo_root)
    if allowlist is not None:
        (script.parent / MANIFEST_ALLOWLIST.name).write_text(allowlist, encoding="utf-8")
    if mock_git is not None:
        git = tmp_path / "bin" / "git"
        git.write_text(mock_git, encoding="utf-8")
        git.chmod(0o755)
    if dotenv is not None:
        (root / ".env").write_text(dotenv, encoding="utf-8")
    env = os.environ.copy()
    env.pop("D810_DOCKER_IMAGE", None)
    env.pop("D810_API_TOKEN", None)
    env.pop("D810_BUILD_SPEEDUPS", None)
    env.pop("D810_EGGLOG_ROOT", None)
    env.pop("D810_COBRA_ROOT", None)
    env.pop("D810_COBRA_WHEEL", None)
    env.pop("D810_COBRA_WHEEL_SHA256", None)
    env.pop("D810_REMOTE_DOCKER_HOST", None)
    env.pop("D810_REMOTE_VOLUME", None)
    env.pop("D810_REMOTE_SHARE_ROOT", None)
    env.pop("D810_REMOTE_SMB_USER", None)
    env.pop("DOCKER_HOST", None)
    # A Docker-hosted pytest already carries its outer runner's receipts.
    # The harness must derive new receipts from its own mocked engine.
    for receipt_key in (
        "D810_TEST_RUNTIME_IMAGE",
        "D810_TEST_RUNTIME_IMAGE_ID",
        "D810_TEST_COBRA_SOURCE_MODE",
        "D810_TEST_COBRA_TAG_COMMIT",
        "D810_TEST_COBRA_WHEEL_SHA256",
        "D810_TEST_ENGINE_CLOCK_OFFSET",
    ):
        env.pop(receipt_key, None)
    env.update(
        {
            "PATH": f"{tmp_path / 'bin'}:{env['PATH']}",
            "DOCKER_LOG": str(docker_log),
            "CHMOD_LOG": str(tmp_path / "chmod.log"),
            "MOCK_DOCKER_LABEL": label,
            # Model the macOS share host even when pytest runs in Linux Docker.
            "MOCK_UNAME_S": "Darwin",
            "D810_REPO_ROOT": str(root),
        }
    )
    env.pop("D810_NO_CYTHON", None)
    if no_cython is not None:
        env["D810_NO_CYTHON"] = no_cython
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


def _runs(calls: list[str]) -> list[str]:
    return [call for call in calls if call.startswith("run ")]


def _probe_run(calls: list[str]) -> str:
    runs = [call for call in _runs(calls) if "dst=/probe" in call]
    assert len(runs) == 1, calls
    return runs[0]


def _workload_runs(calls: list[str]) -> list[str]:
    """Runs that are neither preflight probe: the actual work.

    Preflight legitimately starts read-only containers (the volume probe and
    the engine-clock reading), so "nothing ran" means no WORKLOAD ran.
    """
    return [
        call
        for call in _runs(calls)
        if "dst=/probe" not in call and "--entrypoint /bin/date" not in call
    ]


def _clock_run(calls: list[str]) -> str | None:
    """The one-shot container that reads the engine clock in preflight."""
    runs = [call for call in _runs(calls) if "--entrypoint /bin/date" in call]
    assert len(runs) <= 1, calls
    return runs[0] if runs else None


def _remote_container_run(calls: list[str]) -> str:
    """The one workload container, ignoring the preflight probes."""
    runs = [
        call
        for call in _runs(calls)
        if "dst=/probe" not in call and "--entrypoint /bin/date" not in call
    ]
    assert len(runs) == 1, calls
    return runs[0]


def _chmod_calls(tmp_path: Path) -> list[str]:
    log = tmp_path / "chmod.log"
    return log.read_text(encoding="utf-8").splitlines() if log.exists() else []


def _work_volume_name(worktree_dir: Path) -> str:
    digest = hashlib.sha256(str(worktree_dir).encode()).hexdigest()[:8]
    return f"d810-work-{worktree_dir.name}-{digest}"


def _docker_hosts(calls: list[str]) -> list[str]:
    prefix = "docker-host "
    return [call[len(prefix) :] for call in calls if call.startswith(prefix)]


def _docker_calls(calls: list[str]) -> list[str]:
    """The docker argument lines, without the DOCKER_HOST bookkeeping entries."""
    return [call for call in calls if not call.startswith("docker-host ")]


def _share_layout(tmp_path: Path) -> tuple[Path, Path]:
    """A fake SMB share root holding the repo, mirroring the Mac layout."""
    share = tmp_path / "share"
    repo = share / "d810"
    (repo / "src").mkdir(parents=True)
    (repo / "tests").mkdir()
    return share, repo


def _git_stub(common_dir: Path) -> str:
    return f"""#!/usr/bin/env bash
set -eu
for arg in "$@"; do
  if [ "$arg" = "--git-common-dir" ]; then
    printf '%s\\n' '{common_dir}'
    exit 0
  fi
done
exit 1
"""


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
    assert "import pytest, unicorn, z3;" in command
    assert "import pytest, unicorn, z3, egglog" not in command
    assert "/app/ida/.venv/bin/python -c" in command
    assert "z3.get_version()" in command
    assert "command -v git" in command
    assert ".[dev,emulation]" in command
    assert ".[dev,emulation,egraph]" not in command
    assert "d810.speedups.install" in command
    assert "d810.speedups.install --solver-only" in command
    assert "baked runtime dependencies detected" in command
    assert "baked runtime is stale" in command


def test_unlabeled_runtime_keeps_dependency_setup(tmp_path: Path) -> None:
    result, calls = _run(tmp_path, "exec", "--", "true")

    assert result.returncode == 0, result.stderr
    command = _container_run(calls)
    assert ".[dev,emulation]" in command
    assert ".[dev,emulation,egraph]" not in command
    assert "d810.speedups.install" in command
    assert "d810.speedups.install --solver-only" in command


def test_system_mode_uses_fresh_interpreter_batches(tmp_path: Path) -> None:
    result, calls = _run(tmp_path, "system", "--", "-q")

    assert result.returncode == 0, result.stderr
    command = _container_run(calls)
    assert "tools/scripts/run_system_test_batches.py" in command
    assert "tests/system" in command
    assert "--batch-size 20" in command
    assert "pytest tests/system -v" not in command
    # Default invocation must stay byte-identical to before --start-batch
    # existed: no flag at all when the caller does not pass one.
    assert "--start-batch" not in command


def test_start_batch_reaches_the_batcher_command(tmp_path: Path) -> None:
    result, calls = _run(tmp_path, "system", "--start-batch", "7", "--", "-q")

    assert result.returncode == 0, result.stderr
    command = _container_run(calls)
    assert "run_system_test_batches.py" in command
    assert re.search(r"--batch-size 20 --start-batch 7 --log-dir", command)
    # The flag must land before the '--' pytest separator, not after it.
    assert command.index("--start-batch 7") < command.index(" -- ")


def test_start_batch_reaches_the_batcher_command_in_remote_mode(
    tmp_path: Path,
) -> None:
    share, repo = _share_layout(tmp_path)

    result, calls = _run(
        tmp_path,
        "system",
        "--remote",
        REMOTE_HOST,
        "--start-batch",
        "3",
        "--",
        "-q",
        repo_root=repo,
        extra_env=_remote_env(share),
    )

    assert result.returncode == 0, result.stderr
    command = _remote_container_run(calls)
    assert "run_system_test_batches.py" in command
    assert "--start-batch 3" in command
    assert command.index("--start-batch 3") < command.index(" -- ")


@pytest.mark.parametrize("bad_value", ["0", "", "abc", "7;x"])
def test_start_batch_rejects_non_positive_integers(
    tmp_path: Path,
    bad_value: str,
) -> None:
    # bad_value is passed as a real argv element (including the empty-string
    # case), never interpolated into a shell string, so this also proves the
    # value cannot be used for injection.
    args = ("system", "--start-batch", bad_value, "--", "-q")

    result, calls = _run(tmp_path, *args)

    assert result.returncode == 2, result.stderr
    assert "--start-batch" in result.stderr
    assert calls == []


def test_start_batch_refused_outside_system_mode(tmp_path: Path) -> None:
    result, calls = _run(tmp_path, "test", "--start-batch", "7", "--", "-q")

    assert result.returncode == 2, result.stderr
    assert "--start-batch" in result.stderr
    assert "system" in result.stderr
    assert calls == []


def test_core_mode_does_not_mount_or_forward_extension_root(
    tmp_path: Path,
) -> None:
    result, calls = _run(tmp_path, "exec", "--", "true")

    assert result.returncode == 0, result.stderr
    command = _container_run(calls)
    assert "/opt/d810-egglog" not in command
    assert "D810_EGGLOG_ROOT=" not in command
    assert "egglog" not in command
    assert "-p no:cacheprovider" not in command


def test_core_mode_installs_the_pinned_cobra_plugin_source(
    tmp_path: Path,
) -> None:
    """A legacy image package must not satisfy the API-1 backend contract."""
    result, calls = _run(tmp_path, "exec", "--", "true")

    assert result.returncode == 0, result.stderr
    command = _container_run(calls)
    assert "https://github.com/w00tzenheimer/d810-CoBRA.git" in command
    assert "3b3c406270f1efd8e222f0b05040ae4e074b27d5" in command
    assert "env -u GIT_DIR -u GIT_COMMON_DIR git clone" in command
    assert 'env -u GIT_DIR -u GIT_COMMON_DIR git -C "$COBRA_BUILD_DIR" submodule update --init --recursive --depth=1' in command
    assert '"api_version"] == 1' in command
    assert '"implements"] == {"mba-solve": "cobra-solve"}' in command


@pytest.mark.parametrize("root", ["relative/cobra", "missing-cobra"])
def test_invalid_cobra_root_fails_before_docker(
    tmp_path: Path,
    root: str,
) -> None:
    result, calls = _run(
        tmp_path,
        "exec",
        "--",
        "true",
        extra_env={"D810_COBRA_ROOT": root},
    )

    assert result.returncode != 0
    assert calls == []
    assert "D810_COBRA_ROOT" in result.stderr


def test_mismatched_cobra_root_fails_before_docker(
    tmp_path: Path,
) -> None:
    extension_root = tmp_path / "cobra extension"
    extension_root.mkdir()

    result, calls = _run(
        tmp_path,
        "exec",
        "--",
        "true",
        extra_env={"D810_COBRA_ROOT": str(extension_root)},
    )

    assert result.returncode != 0
    assert calls == []
    assert "must be d810-cobra 3b3c406270f1efd8e222f0b05040ae4e074b27d5" in result.stderr


def test_dirty_pinned_cobra_root_fails_before_docker(tmp_path: Path) -> None:
    extension_root = tmp_path / "cobra extension"
    (extension_root / "third_party" / "cobra").mkdir(parents=True)
    expected_parent = "3b3c406270f1efd8e222f0b05040ae4e074b27d5"
    expected_core = "72f616f822f538a0cfbea3c880f9d1e68bb9a8f1"
    mock_git = f"""#!/usr/bin/env bash
set -eu
if [[ \"$*\" == *\"rev-parse HEAD\"* ]]; then
  case \"$*\" in
    *third_party/cobra*) printf '%s\\n' '{expected_core}' ;;
    *) printf '%s\\n' '{expected_parent}' ;;
  esac
elif [[ \"$*\" == *\"status --porcelain=v1 --untracked-files=all\"* ]]; then
  printf '%s\\n' ' M src/d810_cobra/__init__.py'
fi
"""

    result, calls = _run(
        tmp_path,
        "exec",
        "--",
        "true",
        extra_env={"D810_COBRA_ROOT": str(extension_root)},
        mock_git=mock_git,
    )

    assert result.returncode != 0
    assert calls == []
    assert "D810_COBRA_ROOT must be clean" in result.stderr


def test_pinned_cobra_root_disables_git_replacement_refs(tmp_path: Path) -> None:
    extension_root = tmp_path / "cobra extension"
    (extension_root / "third_party" / "cobra").mkdir(parents=True)
    expected_parent = "3b3c406270f1efd8e222f0b05040ae4e074b27d5"
    expected_core = "72f616f822f538a0cfbea3c880f9d1e68bb9a8f1"
    replacement_parent = "1111111111111111111111111111111111111111"
    replacement_core = "2222222222222222222222222222222222222222"
    mock_git = f"""#!/usr/bin/env bash
set -eu
if [[ \"$*\" == *\"rev-parse HEAD\"* ]]; then
  if [[ \"${{GIT_NO_REPLACE_OBJECTS:-}}\" == 1 ]]; then
    case \"$*\" in
      *third_party/cobra*) printf '%s\\n' '{expected_core}' ;;
      *) printf '%s\\n' '{expected_parent}' ;;
    esac
  else
    case \"$*\" in
      *third_party/cobra*) printf '%s\\n' '{replacement_core}' ;;
      *) printf '%s\\n' '{replacement_parent}' ;;
    esac
  fi
elif [[ \"$*\" == *\"archive --format=tar\"* ]]; then
  tar -cf - --files-from /dev/null
fi
"""

    result, calls = _run(
        tmp_path,
        "exec",
        "--",
        "true",
        extra_env={"D810_COBRA_ROOT": str(extension_root)},
        mock_git=mock_git,
    )

    assert result.returncode == 0, result.stderr
    assert any("/opt/d810-cobra-source:ro" in call for call in calls)


@pytest.mark.parametrize("docker_exit", [0, 23])
def test_pinned_cobra_root_materializes_the_canonical_tree_and_cleans_temp(
    tmp_path: Path,
    docker_exit: int,
) -> None:
    extension_root = tmp_path / "cobra extension"
    (extension_root / "third_party" / "cobra").mkdir(parents=True)
    temp_root = tmp_path / ".tmp"
    preexisting = temp_root / "cobra-source.preexisting"
    preexisting.mkdir(parents=True)
    git_log = tmp_path / "git.log"
    expected_parent = "3b3c406270f1efd8e222f0b05040ae4e074b27d5"
    expected_core = "72f616f822f538a0cfbea3c880f9d1e68bb9a8f1"
    mock_git = f"""#!/usr/bin/env bash
set -eu
printf 'replace=%s args=%s\\n' "${{GIT_NO_REPLACE_OBJECTS:-}}" "$*" >> "$GIT_LOG"
if [[ \"$*\" == *\"rev-parse HEAD\"* ]]; then
  case \"$*\" in
    *third_party/cobra*) printf '%s\\n' '{expected_core}' ;;
    *) printf '%s\\n' '{expected_parent}' ;;
  esac
elif [[ \"$*\" == *\"archive --format=tar\"* ]]; then
  tar -cf - --files-from /dev/null
fi
"""
    before = set(temp_root.glob("cobra-source.*"))

    extra_env = {
        "D810_COBRA_ROOT": str(extension_root),
        "GIT_LOG": str(git_log),
    }
    if docker_exit:
        extra_env["MOCK_DOCKER_RUN_EXIT"] = str(docker_exit)
    result, calls = _run(
        tmp_path,
        "exec",
        "--",
        "true",
        extra_env=extra_env,
        mock_git=mock_git,
    )

    assert result.returncode == docker_exit
    git_calls = git_log.read_text(encoding="utf-8")
    assert "replace=1 args=-C" in git_calls
    assert "ls-tree -rz" in git_calls
    assert "checkout-index" not in git_calls
    assert "archive --format=tar" not in git_calls
    assert set(temp_root.glob("cobra-source.*")) == before
    assert preexisting.is_dir()
    assert any("/opt/d810-cobra-source:ro" in call for call in calls)


def test_pinned_cobra_root_materializes_canonical_blobs_without_smudge_filters(
    tmp_path: Path,
) -> None:
    extension_root = tmp_path / "cobra extension"
    (extension_root / "third_party" / "cobra").mkdir(parents=True)
    git_log = tmp_path / "git.log"
    expected_parent = "3b3c406270f1efd8e222f0b05040ae4e074b27d5"
    expected_core = "72f616f822f538a0cfbea3c880f9d1e68bb9a8f1"
    table_blob = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
    mock_git = f"""#!/usr/bin/env bash
set -eu
printf 'args=%s\\n' "$*" >> "$GIT_LOG"
if [[ \"$*\" == *\"rev-parse HEAD\"* ]]; then
  case \"$*\" in
    *third_party/cobra*) printf '%s\\n' '{expected_core}' ;;
    *) printf '%s\\n' '{expected_parent}' ;;
  esac
elif [[ \"$*\" == *\"ls-tree -rz\"* ]] && [[ \"$*\" != *\"third_party/cobra\"* ]]; then
  printf '100644 blob {table_blob}\\tsrc/d810_cobra/table.py\\0'
elif [[ \"$*\" == *\"cat-file blob {table_blob}\"* ]]; then
  printf '%s' 'canonical table bytes'
elif [[ \"$*\" == *\"checkout-index\"* ]]; then
  printf '%s' 'smudged table bytes'
fi
"""

    result, calls = _run(
        tmp_path,
        "exec",
        "--",
        "true",
        extra_env={
            "D810_COBRA_ROOT": str(extension_root),
            "GIT_LOG": str(git_log),
            "MOCK_DOCKER_EXPECT_SOURCE_FILE": "src/d810_cobra/table.py",
            "MOCK_DOCKER_EXPECT_SOURCE_CONTENT": "canonical table bytes",
        },
        mock_git=mock_git,
    )

    assert result.returncode == 0, result.stderr
    git_calls = git_log.read_text(encoding="utf-8")
    assert "ls-tree -rz" in git_calls
    assert f"cat-file blob {table_blob}" in git_calls
    assert "checkout-index" not in git_calls
    assert any("/opt/d810-cobra-source:ro" in call for call in calls)


def test_recorded_cobra_wheel_replaces_the_in_container_source_build(
    tmp_path: Path,
) -> None:
    """A verified recorded wheel installs directly; nothing is compiled."""
    under_test = _wheel_under_test()
    container_path = f"{COBRA_WHEEL_CONTAINER_DIR}/{under_test.name}"

    result, calls = _run(tmp_path, "exec", "--", "true", extra_env=under_test.env)

    assert result.returncode == 0, result.stderr
    command = _container_run(calls)
    assert (
        "/app/ida/.venv/bin/pip install --no-deps --force-reinstall "
        f"--no-cache-dir -q '{container_path}'"
    ) in command
    assert "sha256sum -c -" in command
    assert under_test.sha256 in command
    assert '"implements"] == {"mba-solve": "cobra-solve"}' in command
    assert (
        f'importlib.metadata.version("d810-cobra") == "{COBRA_WHEEL_VERSION}"'
        in command
    )
    for compiled in ("git clone", "submodule update", "build_cobra.py", "cmake"):
        assert compiled not in command
    assert any(call == f"run-arg {under_test.path}:{container_path}:ro" for call in calls)
    assert "/opt/d810-cobra-source" not in command
    assert "/opt/d810-cobra-cache" not in command
    assert "D810_COBRA_WHEEL=" not in command
    assert not list((tmp_path / ".tmp").glob("cobra-source.*"))
    assert not (tmp_path / ".tmp" / "cobra-linux").exists()


def test_recorded_cobra_wheel_reports_its_verified_provenance(
    tmp_path: Path,
) -> None:
    under_test = _wheel_under_test()

    result, _ = _run(tmp_path, "exec", "--", "true", extra_env=under_test.env)

    assert result.returncode == 0, result.stderr
    assert f"extension: d810-cobra (wheel {under_test.name})" in result.stdout
    assert (
        f"cobra wheel: {under_test.path} -> {COBRA_WHEEL_CONTAINER_DIR}/"
        f"{under_test.name} (read-only) {under_test.identity} sha256 "
        f"{under_test.sha256}; d810-cobra {COBRA_WHEEL_VERSION} tag "
        f"v{COBRA_WHEEL_VERSION} "
    ) in result.stdout
    assert "cobra cache:" not in result.stdout
    if under_test.identity == "published":
        assert (
            f"{COBRA_WHEEL_TAG_COMMIT} core {COBRA_WHEEL_CORE_COMMIT}"
        ) in result.stdout
    else:
        # A fixture names no release, and must not borrow one.
        assert "harness-fixture" in result.stdout
        assert COBRA_WHEEL_TAG_COMMIT not in result.stdout


def test_cobra_wheel_without_its_hash_fails_before_docker(tmp_path: Path) -> None:
    result, calls = _run(
        tmp_path,
        "exec",
        "--",
        "true",
        extra_env={"D810_COBRA_WHEEL": str(tmp_path / COBRA_WHEEL_AARCH64_NAME)},
    )

    assert result.returncode != 0
    assert calls == []
    assert "D810_COBRA_WHEEL_SHA256" in result.stderr


def test_cobra_wheel_hash_without_its_path_fails_before_docker(
    tmp_path: Path,
) -> None:
    result, calls = _run(
        tmp_path,
        "exec",
        "--",
        "true",
        extra_env={"D810_COBRA_WHEEL_SHA256": COBRA_WHEEL_AARCH64_SHA256},
    )

    assert result.returncode != 0
    assert calls == []
    assert "D810_COBRA_WHEEL" in result.stderr


@pytest.mark.parametrize(
    "wheel",
    ["relative/d810_cobra.whl", "/nonexistent/d810_cobra.whl"],
)
def test_unusable_cobra_wheel_path_fails_before_docker(
    tmp_path: Path,
    wheel: str,
) -> None:
    result, calls = _run(
        tmp_path,
        "exec",
        "--",
        "true",
        extra_env={
            "D810_COBRA_WHEEL": wheel,
            "D810_COBRA_WHEEL_SHA256": COBRA_WHEEL_AARCH64_SHA256,
        },
    )

    assert result.returncode != 0
    assert calls == []
    assert "D810_COBRA_WHEEL must be an absolute path" in result.stderr


def test_malformed_cobra_wheel_hash_fails_before_docker(tmp_path: Path) -> None:
    wheel = tmp_path / COBRA_WHEEL_AARCH64_NAME
    wheel.write_bytes(b"not the recorded wheel")

    result, calls = _run(
        tmp_path,
        "exec",
        "--",
        "true",
        extra_env={
            "D810_COBRA_WHEEL": str(wheel),
            "D810_COBRA_WHEEL_SHA256": "NOTAHASH",
        },
    )

    assert result.returncode != 0
    assert calls == []
    assert "D810_COBRA_WHEEL_SHA256 must be 64 lowercase hex" in result.stderr


def test_cobra_wheel_content_mismatch_fails_before_docker(tmp_path: Path) -> None:
    """The recorded name must not admit content the recorded hash rejects."""
    wheel = tmp_path / COBRA_WHEEL_AARCH64_NAME
    wheel.write_bytes(b"not the recorded wheel")

    result, calls = _run(
        tmp_path,
        "exec",
        "--",
        "true",
        extra_env={
            "D810_COBRA_WHEEL": str(wheel),
            "D810_COBRA_WHEEL_SHA256": COBRA_WHEEL_AARCH64_SHA256,
        },
    )

    assert result.returncode != 0
    assert calls == []
    assert "sha256 mismatch" in result.stderr


def test_unrecorded_cobra_wheel_fails_before_docker(tmp_path: Path) -> None:
    """A self-consistent hash is not enough: the artifact must be recorded."""
    wheel = tmp_path / "d810_cobra-9.9.9-cp313-cp313-manylinux_2_28_aarch64.whl"
    wheel.write_bytes(b"a locally built wheel nobody recorded")
    digest = hashlib.sha256(wheel.read_bytes()).hexdigest()

    result, calls = _run(
        tmp_path,
        "exec",
        "--",
        "true",
        extra_env={
            "D810_COBRA_WHEEL": str(wheel),
            "D810_COBRA_WHEEL_SHA256": digest,
        },
    )

    assert result.returncode != 0
    assert calls == []
    assert "not a recorded d810-cobra wheel" in result.stderr


@pytest.mark.parametrize(
    ("bad_name", "expected"),
    [
        (
            "cobra.whl",
            "basename must be d810_cobra-<version>-cp313-cp313-<platform>.whl",
        ),
        (
            "d810_cobra-0.1.5-cp312-cp312-manylinux_2_28_aarch64.whl",
            "basename must be d810_cobra-<version>-cp313-cp313-<platform>.whl",
        ),
        (
            "d810_cobra-9.9.9-cp313-cp313-manylinux_2_28_aarch64.whl",
            "basename declares version 9.9.9 but the recorded wheel is 0.1.5",
        ),
        (
            "d810_cobra-0.1.5-cp313-cp313-manylinux_2_28_x86_64.whl",
            "platform tag manylinux_2_28_x86_64 does not carry the recorded "
            "architecture aarch64",
        ),
    ],
)
def test_misnamed_recorded_cobra_wheel_fails_before_docker(
    tmp_path: Path,
    bad_name: str,
    expected: str,
) -> None:
    """pip reads the basename, so it must not contradict the recorded hash.

    These checks sit after the recorded-hash gate, so only the real recorded
    bytes can reach them.
    """
    wheel = _recorded_wheel(COBRA_WHEEL_AARCH64_NAME)
    if wheel is None:
        pytest.skip(f"recorded wheel {COBRA_WHEEL_AARCH64_NAME} is unavailable")
    renamed = tmp_path / bad_name
    shutil.copy2(wheel, renamed)

    result, calls = _run(
        tmp_path,
        "exec",
        "--",
        "true",
        extra_env={
            "D810_COBRA_WHEEL": str(renamed),
            "D810_COBRA_WHEEL_SHA256": COBRA_WHEEL_AARCH64_SHA256,
        },
    )

    assert result.returncode != 0
    assert calls == []
    assert expected in result.stderr


def test_unreadable_cobra_wheel_is_not_reported_as_a_missing_hasher(
    tmp_path: Path,
) -> None:
    """An unreadable file and an absent hasher are different diagnoses."""
    if os.geteuid() == 0:
        pytest.skip("root ignores the read permission bit")
    wheel = tmp_path / COBRA_WHEEL_AARCH64_NAME
    wheel.write_bytes(b"bytes that must never be hashed")
    wheel.chmod(0o000)

    try:
        result, calls = _run(
            tmp_path,
            "exec",
            "--",
            "true",
            extra_env={
                "D810_COBRA_WHEEL": str(wheel),
                "D810_COBRA_WHEEL_SHA256": COBRA_WHEEL_AARCH64_SHA256,
            },
        )
    finally:
        wheel.chmod(0o644)

    assert result.returncode != 0
    assert calls == []
    assert f"D810_COBRA_WHEEL is not readable: {wheel}" in result.stderr
    assert "sha256sum is on PATH" not in result.stderr


@pytest.mark.parametrize(
    ("variable", "other"),
    [
        ("D810_COBRA_WHEEL", "D810_COBRA_WHEEL_SHA256"),
        ("D810_COBRA_WHEEL_SHA256", "D810_COBRA_WHEEL"),
    ],
)
def test_empty_cobra_wheel_variable_blames_itself(
    tmp_path: Path,
    variable: str,
    other: str,
) -> None:
    """Emptiness must not be reported as the other variable being missing."""
    result, calls = _run(tmp_path, "exec", "--", "true", extra_env={variable: ""})

    assert result.returncode != 0
    assert calls == []
    assert f"ERROR: {variable} is set but empty" in result.stderr
    assert f"{other} requires" not in result.stderr


def test_preflight_cobra_wheel_is_refused_as_unrecorded(tmp_path: Path) -> None:
    """Same filename, same size, different bytes: only the hash separates them."""
    preflight = _cobra_wheel(COBRA_WHEEL_PREFLIGHT_DIR, COBRA_WHEEL_AARCH64_NAME)
    if preflight is None:
        pytest.skip(f"preflight wheel {COBRA_WHEEL_AARCH64_NAME} is unavailable")
    published = _recorded_wheel(COBRA_WHEEL_AARCH64_NAME)
    if published is not None:
        assert preflight.name == published.name
        assert preflight.stat().st_size == published.stat().st_size
        assert preflight.read_bytes() != published.read_bytes()

    result, calls = _run(
        tmp_path,
        "exec",
        "--",
        "true",
        extra_env={
            "D810_COBRA_WHEEL": str(preflight),
            "D810_COBRA_WHEEL_SHA256": COBRA_WHEEL_PREFLIGHT_AARCH64_SHA256,
        },
    )

    assert result.returncode != 0
    assert calls == []
    assert "not a recorded d810-cobra wheel" in result.stderr


def test_cobra_wheel_and_cobra_root_are_mutually_exclusive(tmp_path: Path) -> None:
    result, calls = _run(
        tmp_path,
        "exec",
        "--",
        "true",
        extra_env={
            "D810_COBRA_WHEEL": str(tmp_path / COBRA_WHEEL_AARCH64_NAME),
            "D810_COBRA_WHEEL_SHA256": COBRA_WHEEL_AARCH64_SHA256,
            "D810_COBRA_ROOT": str(tmp_path),
        },
    )

    assert result.returncode != 0
    assert calls == []
    assert (
        "D810_COBRA_WHEEL and D810_COBRA_ROOT are mutually exclusive" in result.stderr
    )


def test_cobra_wheel_architecture_must_match_the_docker_engine(
    tmp_path: Path,
) -> None:
    """A native wheel for the wrong engine must never reach a container."""
    under_test = _wheel_under_test()

    result, calls = _run(
        tmp_path,
        "exec",
        "--",
        "true",
        extra_env={**under_test.env, "MOCK_DOCKER_SERVER_ARCH": "amd64"},
    )

    assert result.returncode != 0
    assert _docker_calls(calls) == ["version --format {{.Server.Arch}}"]
    assert "aarch64 wheel but the Docker engine is x86_64" in result.stderr


def test_unknown_docker_engine_architecture_rejects_the_cobra_wheel(
    tmp_path: Path,
) -> None:
    under_test = _wheel_under_test()

    result, calls = _run(
        tmp_path,
        "exec",
        "--",
        "true",
        extra_env={**under_test.env, "MOCK_DOCKER_SERVER_ARCH": "riscv64"},
    )

    assert result.returncode != 0
    assert _docker_calls(calls) == ["version --format {{.Server.Arch}}"]
    assert "known Docker engine architecture" in result.stderr


@pytest.mark.parametrize("root", ["relative/extension", "missing-extension"])
def test_invalid_extension_root_fails_before_docker(
    tmp_path: Path,
    root: str,
) -> None:
    result, calls = _run(
        tmp_path,
        "exec",
        "--",
        "true",
        extra_env={"D810_EGGLOG_ROOT": root},
    )

    assert result.returncode != 0
    assert calls == []
    assert "D810_EGGLOG_ROOT" in result.stderr


def test_extension_mode_mounts_installs_and_probes_once(tmp_path: Path) -> None:
    extension_root = tmp_path / "extension"
    extension_root.mkdir()

    result, calls = _run(
        tmp_path,
        "exec",
        "--",
        "true",
        extra_env={"D810_EGGLOG_ROOT": str(extension_root)},
    )

    assert result.returncode == 0, result.stderr
    command = _container_run(calls)
    mount = f"{extension_root}:/opt/d810-egglog:ro"
    assert calls.count(f"run-arg {mount}") == 1
    assert "find /opt/d810-egglog/dist" not in command
    assert 'cp -a /opt/d810-egglog/. "$EXTENSION_BUILD_DIR/"' in command
    assert 'pip install "$EXTENSION_BUILD_DIR[test]" --no-deps -q' in command
    assert 'pip install -r "$EXTENSION_BUILD_DIR/requirements.txt" -q' in command
    assert "tomllib" in command
    assert "optional-dependencies" in command
    assert "d810-ng" in command
    assert "pip install -e '/opt/d810-egglog" not in command
    assert "egglog>=" not in command
    assert "egglog<" not in command
    assert "import d810_egglog, egglog" in command
    assert f"D810_EGGLOG_ROOT={extension_root}" not in command


def test_extension_install_uses_current_source_not_stale_wheel(
    tmp_path: Path,
) -> None:
    extension_root = tmp_path / "extension"
    (extension_root / "dist").mkdir(parents=True)
    (extension_root / "dist" / "d810_egglog-0.0.0-stale.whl").write_bytes(
        b"stale wheel"
    )

    result, calls = _run(
        tmp_path,
        "exec",
        "--",
        "true",
        extra_env={"D810_EGGLOG_ROOT": str(extension_root)},
    )

    assert result.returncode == 0, result.stderr
    command = _container_run(calls)
    assert "find /opt/d810-egglog/dist" not in command
    assert 'cp -a /opt/d810-egglog/. "$EXTENSION_BUILD_DIR/"' in command
    assert 'pip install "$EXTENSION_BUILD_DIR[test]" --no-deps -q' in command


def test_extension_dependencies_come_from_copied_metadata(
    tmp_path: Path,
) -> None:
    extension_root = tmp_path / "extension"
    extension_root.mkdir()

    result, calls = _run(
        tmp_path,
        "exec",
        "--",
        "true",
        extra_env={"D810_EGGLOG_ROOT": str(extension_root)},
    )

    assert result.returncode == 0, result.stderr
    command = _container_run(calls)
    assert "tomllib" in command
    assert "optional-dependencies" in command
    assert "requirements.txt" in command
    assert 'pip install -r "$EXTENSION_BUILD_DIR/requirements.txt" -q' in command
    assert "d810-ng" in command
    assert "egglog>=" not in command
    assert "egglog<" not in command


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
def test_extension_mounts_once_in_every_docker_mode(
    tmp_path: Path,
    args: tuple[str, ...],
) -> None:
    extension_root = tmp_path / "extension"
    extension_root.mkdir()

    result, calls = _run(
        tmp_path,
        *args,
        extra_env={"D810_EGGLOG_ROOT": str(extension_root)},
    )

    assert result.returncode == 0, result.stderr
    mount = f"{extension_root}:/opt/d810-egglog:ro"
    assert calls.count(f"run-arg {mount}") == 1


def test_extension_pytest_disables_read_only_cache_provider(tmp_path: Path) -> None:
    extension_root = tmp_path / "extension"
    extension_root.mkdir()

    result, calls = _run(
        tmp_path,
        "test",
        "--",
        "/opt/d810-egglog/tests/unit/test_manifest.py",
        "-q",
        extra_env={"D810_EGGLOG_ROOT": str(extension_root)},
    )

    assert result.returncode == 0, result.stderr
    command = _container_run(calls)
    assert "-p no:cacheprovider" in command


def test_extension_path_with_spaces_remains_one_mount_argument(tmp_path: Path) -> None:
    extension_root = tmp_path / "extension repo with spaces"
    extension_root.mkdir()

    result, calls = _run(
        tmp_path,
        "exec",
        "--",
        "true",
        extra_env={"D810_EGGLOG_ROOT": str(extension_root)},
    )

    assert result.returncode == 0, result.stderr
    mount = f"{extension_root}:/opt/d810-egglog:ro"
    assert calls.count(f"run-arg {mount}") == 1


def test_out_still_targets_bare_work_tmp_filename(tmp_path: Path) -> None:
    result, calls = _run(tmp_path, "test", "-o", "rendered.log", "--", "true")

    assert result.returncode == 0, result.stderr
    command = _container_run(calls)
    assert "/work/.tmp/rendered.log" in command
    assert "/work/.tmp//rendered.log" not in command


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
    assert ".[dev,emulation]" in command
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
    assert ".[dev,emulation]" in command
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


@pytest.mark.parametrize("no_cython", [None, "0"])
def test_native_speedups_build_cleans_extensions_and_fails_closed(
    tmp_path: Path,
    no_cython: str | None,
) -> None:
    result, calls = _run(tmp_path, "test", "--", "-q", no_cython=no_cython)

    assert result.returncode == 0, result.stderr
    command = _container_run(calls)
    assert "find src/d810/speedups -type f" in command
    assert "-name '*-linux-gnu.so'" in command
    assert "-name '*.so'" not in command
    assert "-name '*.pyd'" not in command
    assert "D810_BUILD_SPEEDUPS=1" in command
    assert "D810_NO_CYTHON=0" in command
    assert "falling back to pure-Python" not in command
    assert "|| echo" not in command
    assert command.index("find src/d810/speedups -type f") < command.index(
        "D810_BUILD_SPEEDUPS=1"
    ) < command.rindex("pytest")


def test_python_mode_cleans_extensions_without_building(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("D810_BUILD_SPEEDUPS", "1")
    result, calls = _run(tmp_path, "test", "--", "-q", no_cython="1")

    assert result.returncode == 0, result.stderr
    command = _container_run(calls)
    cleanup = command.index("find src/d810/speedups -type f")
    disabled = command.index("native build disabled by D810_NO_CYTHON=1")
    assert cleanup < disabled
    assert "D810_BUILD_SPEEDUPS=1" not in command
    assert disabled < command.rindex("pytest")
    assert "d810.speedups.install --solver-only" in command


def test_container_cleanup_preserves_foreign_platform_extensions(
    tmp_path: Path,
) -> None:
    result, calls = _run(tmp_path, "test", "--", "-q", no_cython="0")

    assert result.returncode == 0, result.stderr
    command = _container_run(calls)
    assert "-name '*-linux-gnu.so'" in command
    assert "-name '*-darwin.so'" not in command
    assert "-name '*.pyd'" not in command


REMOTE_HOST = "runner.example"


def _remote_env(share: Path, **extra: str) -> dict[str, str]:
    env = {
        "D810_REMOTE_SHARE_ROOT": str(share),
        "D810_REMOTE_SMB_USER": "share-account",
    }
    env.update(extra)
    return env


def test_remote_mode_requires_local_share_configuration(tmp_path: Path) -> None:
    share, repo = _share_layout(tmp_path)

    result, calls = _run(
        tmp_path,
        "exec",
        "--remote",
        REMOTE_HOST,
        "--",
        "true",
        repo_root=repo,
        extra_env={"D810_REMOTE_SHARE_ROOT": str(share)},
    )

    assert result.returncode != 0
    assert calls == []
    assert "D810_REMOTE_SMB_USER" in result.stderr


def test_bare_remote_uses_dotenv_without_leaking_identifiers(tmp_path: Path) -> None:
    share, repo = _share_layout(tmp_path)
    secret_host = "private-runner.example"
    secret_share = "//private-files.example/project"
    secret_user = "private-share-account"
    dotenv = (
        f"D810_REMOTE_DOCKER_HOST={secret_host}\n"
        f"D810_REMOTE_SMB_SHARE={secret_share}\n"
        f"D810_REMOTE_SHARE_ROOT={share}\n"
        f"D810_REMOTE_SMB_USER={secret_user}\n"
    )

    result, calls = _run(
        tmp_path,
        "exec",
        "--remote",
        "--",
        "true",
        repo_root=repo,
        dotenv=dotenv,
    )

    assert result.returncode == 0, result.stderr
    assert calls
    assert secret_host not in result.stdout
    assert secret_share not in result.stdout
    assert secret_user not in result.stdout
    assert str(share) not in result.stdout
    assert str(repo) not in result.stdout
    assert "remote:   configured engine" in result.stdout
    container = _remote_container_run(calls)
    assert "D810_REMOTE_DOCKER_HOST" not in container
    assert "D810_REMOTE_SMB_SHARE" not in container
    assert "D810_REMOTE_SMB_USER" not in container
    assert "D810_REMOTE_SHARE_ROOT" not in container


def test_remote_mode_replaces_every_bind_mount_with_a_volume_subpath(
    tmp_path: Path,
) -> None:
    share, repo = _share_layout(tmp_path)
    (repo / ".git").mkdir()
    egglog = share / "d810-egglog"
    egglog.mkdir()

    result, calls = _run(
        tmp_path,
        "exec",
        "--remote",
        REMOTE_HOST,
        "-l",
        "--",
        "true",
        repo_root=repo,
        extra_env=_remote_env(share, D810_EGGLOG_ROOT=str(egglog)),
        mock_git=_git_stub(repo / ".git"),
    )

    assert result.returncode == 0, result.stderr
    assert "run-arg -v" not in calls
    expected = [
        f"type=volume,src={_work_volume_name(repo)},dst=/work",
        "type=volume,src=idapro,dst=/work-src,volume-subpath=d810,readonly",
        "type=volume,src=idapro,dst=/work/.tmp,volume-subpath=d810/.tmp",
        "type=volume,src=idapro,dst=/d810-git,volume-subpath=d810/.git,readonly",
        "type=volume,src=idapro,dst=/opt/d810-egglog,"
        "volume-subpath=d810-egglog,readonly",
    ]
    for spec in expected:
        assert calls.count(f"run-arg {spec}") == 1, (spec, calls)
    # -l must NOT put live SQLite writers on cifs: the logs directory lives on
    # the work volume and is staged to .tmp/logs when the inner shell exits
    assert not [call for call in calls if "dst=/root/.idapro/logs" in call]
    # the CoBRA cache is an engine volume in remote mode, never the SMB share
    assert not [call for call in calls if "dst=/opt/d810-cobra-cache,volume-subpath" in call]
    assert [
        call for call in calls
        if call.startswith("run-arg type=volume,src=d810-cobra-")
        and call.endswith(",dst=/opt/d810-cobra-cache")
    ]
    # the workload mounts, the cobra cache, plus the read-only preflight probe
    assert calls.count("run-arg --mount") == len(expected) + 2
    # source is never writable, and only .tmp is
    assert "run-arg type=volume,src=idapro,dst=/work-src,volume-subpath=d810" not in calls


def test_remote_mode_mounts_the_worktree_subpath(tmp_path: Path) -> None:
    share, repo = _share_layout(tmp_path)
    (repo / ".worktrees" / "perf-review" / "src").mkdir(parents=True)

    result, calls = _run(
        tmp_path,
        "exec",
        "--remote",
        REMOTE_HOST,
        "-w",
        "perf-review",
        "--",
        "true",
        repo_root=repo,
        extra_env=_remote_env(share),
    )

    assert result.returncode == 0, result.stderr
    assert (
        calls.count(
            "run-arg type=volume,src=idapro,dst=/work-src,"
            "volume-subpath=d810/.worktrees/perf-review,readonly"
        )
        == 1
    )
    assert (
        calls.count(
            "run-arg type=volume,src=idapro,dst=/work/.tmp,"
            "volume-subpath=d810/.worktrees/perf-review/.tmp"
        )
        == 1
    )
    work_volume = _work_volume_name(repo / ".worktrees" / "perf-review")
    assert calls.count(f"run-arg type=volume,src={work_volume},dst=/work") == 1


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
def test_remote_mode_uses_volume_mounts_in_every_docker_mode(
    tmp_path: Path,
    args: tuple[str, ...],
) -> None:
    share, repo = _share_layout(tmp_path)

    result, calls = _run(
        tmp_path,
        args[0],
        "--remote",
        REMOTE_HOST,
        *args[1:],
        repo_root=repo,
        extra_env=_remote_env(share),
    )

    assert result.returncode == 0, result.stderr
    assert "run-arg -v" not in calls
    assert (
        calls.count(
            "run-arg type=volume,src=idapro,dst=/work-src,volume-subpath=d810,readonly"
        )
        == 1
    )
    assert calls.count(f"run-arg type=volume,src={_work_volume_name(repo)},dst=/work") == 1
    _remote_container_run(calls)


def test_remote_mode_probes_the_worktree_before_the_workload_container(
    tmp_path: Path,
) -> None:
    share, repo = _share_layout(tmp_path)

    result, calls = _run(
        tmp_path,
        "exec",
        "--remote",
        REMOTE_HOST,
        "--",
        "true",
        repo_root=repo,
        extra_env=_remote_env(share),
    )

    assert result.returncode == 0, result.stderr
    probe = _probe_run(calls)
    assert (
        "type=volume,src=idapro,dst=/probe,volume-subpath=d810,readonly" in probe
    )
    assert "test -d /probe/src && test -d /probe/tests" in probe
    runs = _runs(calls)
    assert runs.index(probe) < runs.index(_remote_container_run(calls))


def test_remote_mode_sends_every_docker_call_to_the_ssh_host(
    tmp_path: Path,
) -> None:
    share, repo = _share_layout(tmp_path)

    result, calls = _run(
        tmp_path,
        "exec",
        "--remote",
        REMOTE_HOST,
        "--",
        "true",
        repo_root=repo,
        extra_env=_remote_env(share),
    )

    assert result.returncode == 0, result.stderr
    hosts = _docker_hosts(calls)
    assert hosts
    assert set(hosts) == {f"ssh://{REMOTE_HOST}"}


def test_remote_host_env_var_needs_opt_in_and_the_flag_wins(tmp_path: Path) -> None:
    share, repo = _share_layout(tmp_path)

    result, calls = _run(
        tmp_path,
        "exec",
        "--",
        "true",
        repo_root=repo,
        extra_env=_remote_env(share, D810_REMOTE_DOCKER_HOST="env.example"),
    )
    assert result.returncode == 0, result.stderr
    assert set(_docker_hosts(calls)) == {""}

    (tmp_path / "docker.log").unlink()
    result, calls = _run(
        tmp_path,
        "exec",
        "--remote",
        "--",
        "true",
        repo_root=repo,
        extra_env=_remote_env(share, D810_REMOTE_DOCKER_HOST="env.example"),
    )
    assert result.returncode == 0, result.stderr
    assert set(_docker_hosts(calls)) == {"ssh://env.example"}
    assert "-e D810_REMOTE_DOCKER_HOST=env.example" not in _remote_container_run(calls)

    (tmp_path / "docker.log").unlink()
    result, calls = _run(
        tmp_path,
        "exec",
        "--remote",
        "flag.example",
        "--",
        "true",
        repo_root=repo,
        extra_env=_remote_env(share, D810_REMOTE_DOCKER_HOST="env.example"),
    )
    assert result.returncode == 0, result.stderr
    assert set(_docker_hosts(calls)) == {"ssh://flag.example"}


def test_remote_volume_name_is_configurable(tmp_path: Path) -> None:
    share, repo = _share_layout(tmp_path)

    result, calls = _run(
        tmp_path,
        "exec",
        "--remote",
        REMOTE_HOST,
        "--",
        "true",
        repo_root=repo,
        extra_env=_remote_env(share, D810_REMOTE_VOLUME="other-share"),
    )

    assert result.returncode == 0, result.stderr
    assert (
        calls.count(
            "run-arg type=volume,src=other-share,dst=/work-src,volume-subpath=d810,readonly"
        )
        == 1
    )
    assert "-e D810_REMOTE_VOLUME=other-share" not in _remote_container_run(calls)


def test_remote_mode_fails_closed_when_the_volume_is_missing(
    tmp_path: Path,
) -> None:
    share, repo = _share_layout(tmp_path)

    result, calls = _run(
        tmp_path,
        "exec",
        "--remote",
        REMOTE_HOST,
        "--",
        "true",
        repo_root=repo,
        extra_env=_remote_env(share, MOCK_DOCKER_VOLUME_MISSING="1"),
    )

    assert result.returncode != 0
    assert "volume" in result.stderr
    assert "idapro" in result.stderr
    assert _runs(calls) == []


def test_remote_mode_fails_closed_on_a_non_linux_engine(tmp_path: Path) -> None:
    share, repo = _share_layout(tmp_path)

    result, calls = _run(
        tmp_path,
        "exec",
        "--remote",
        REMOTE_HOST,
        "--",
        "true",
        repo_root=repo,
        extra_env=_remote_env(share, MOCK_DOCKER_OSTYPE="windows"),
    )

    assert result.returncode != 0
    assert "linux" in result.stderr
    assert "windows" in result.stderr
    assert _runs(calls) == []


def test_remote_mode_fails_closed_when_the_image_is_absent(tmp_path: Path) -> None:
    share, repo = _share_layout(tmp_path)

    result, calls = _run(
        tmp_path,
        "exec",
        "--remote",
        REMOTE_HOST,
        "--",
        "true",
        repo_root=repo,
        extra_env=_remote_env(share, MOCK_DOCKER_IMAGE_MISSING="1"),
    )

    assert result.returncode != 0
    assert "test-runtime-image" in result.stderr
    assert _runs(calls) == []


def test_remote_mode_rejects_a_worktree_outside_the_share_root(
    tmp_path: Path,
) -> None:
    share, repo = _share_layout(tmp_path)
    outside = tmp_path / "outside"
    outside.mkdir()

    result, calls = _run(
        tmp_path,
        "exec",
        "--remote",
        REMOTE_HOST,
        "--",
        "true",
        repo_root=repo,
        extra_env=_remote_env(outside),
    )

    assert result.returncode != 0
    assert str(repo) in result.stderr
    assert str(outside) in result.stderr
    assert _runs(calls) == []


def test_remote_mode_rejects_an_extension_root_outside_the_share_root(
    tmp_path: Path,
) -> None:
    share, repo = _share_layout(tmp_path)
    egglog = tmp_path / "outside-egglog"
    egglog.mkdir()

    result, calls = _run(
        tmp_path,
        "exec",
        "--remote",
        REMOTE_HOST,
        "--",
        "true",
        repo_root=repo,
        extra_env=_remote_env(share, D810_EGGLOG_ROOT=str(egglog)),
    )

    assert result.returncode != 0
    assert str(egglog) in result.stderr
    assert _workload_runs(calls) == []


def test_remote_mode_rejects_a_git_dir_outside_the_share_root(
    tmp_path: Path,
) -> None:
    share, repo = _share_layout(tmp_path)
    git_dir = tmp_path / "outside-git"
    git_dir.mkdir()

    result, calls = _run(
        tmp_path,
        "exec",
        "--remote",
        REMOTE_HOST,
        "--",
        "true",
        repo_root=repo,
        extra_env=_remote_env(share),
        mock_git=_git_stub(git_dir),
    )

    assert result.returncode != 0
    assert str(git_dir) in result.stderr
    assert _workload_runs(calls) == []


@pytest.mark.parametrize("share_root", ["relative/share", "missing-share"])
def test_remote_mode_rejects_an_unusable_share_root(
    tmp_path: Path,
    share_root: str,
) -> None:
    _share, repo = _share_layout(tmp_path)

    result, calls = _run(
        tmp_path,
        "exec",
        "--remote",
        REMOTE_HOST,
        "--",
        "true",
        repo_root=repo,
        extra_env={
            "D810_REMOTE_SHARE_ROOT": share_root,
            "D810_REMOTE_SMB_USER": "share-account",
        },
    )

    assert result.returncode != 0
    assert "D810_REMOTE_SHARE_ROOT" in result.stderr
    assert _runs(calls) == []


def test_remote_flag_requires_a_host_argument(tmp_path: Path) -> None:
    _share, repo = _share_layout(tmp_path)

    result, calls = _run(tmp_path, "exec", "--remote", repo_root=repo)

    assert result.returncode != 0
    assert "--remote" in result.stderr
    assert _runs(calls) == []


def test_remote_mode_allows_one_run_per_worktree(tmp_path: Path) -> None:
    share, repo = _share_layout(tmp_path)
    lock = repo / ".tmp" / "remote-run.lock"
    lock.mkdir(parents=True)
    (lock / "owner").write_text("pid=4242 started=2026-01-01T00:00:00Z\n", encoding="utf-8")

    result, calls = _run(
        tmp_path,
        "exec",
        "--remote",
        REMOTE_HOST,
        "--",
        "true",
        repo_root=repo,
        extra_env=_remote_env(share),
    )

    assert result.returncode != 0
    assert "pid=4242" in result.stderr
    assert str(lock) in result.stderr
    assert _workload_runs(calls) == []
    assert lock.is_dir()


def test_remote_lock_is_released_after_a_run(tmp_path: Path) -> None:
    share, repo = _share_layout(tmp_path)

    result, calls = _run(
        tmp_path,
        "exec",
        "--remote",
        REMOTE_HOST,
        "--",
        "true",
        repo_root=repo,
        extra_env=_remote_env(share),
    )

    assert result.returncode == 0, result.stderr
    assert _remote_container_run(calls)
    assert not (repo / ".tmp" / "remote-run.lock").exists()


def test_remote_lock_is_released_when_the_container_fails(tmp_path: Path) -> None:
    share, repo = _share_layout(tmp_path)

    result, _calls = _run(
        tmp_path,
        "exec",
        "--remote",
        REMOTE_HOST,
        "--",
        "true",
        repo_root=repo,
        extra_env=_remote_env(share, MOCK_DOCKER_RUN_EXIT="23"),
    )

    assert result.returncode == 23
    assert not (repo / ".tmp" / "remote-run.lock").exists()


def test_remote_mode_fails_closed_when_the_probe_cannot_see_the_worktree(
    tmp_path: Path,
) -> None:
    share, repo = _share_layout(tmp_path)

    result, calls = _run(
        tmp_path,
        "exec",
        "--remote",
        REMOTE_HOST,
        "--",
        "true",
        repo_root=repo,
        extra_env=_remote_env(share, MOCK_DOCKER_PROBE_EXIT="1"),
    )

    assert result.returncode != 0
    assert "not reachable through volume idapro" in result.stderr
    assert _workload_runs(calls) == []
    assert _probe_run(calls) in calls
    assert not (repo / ".tmp" / "remote-run.lock").exists()


def test_local_mode_never_uses_a_volume_mount_or_docker_host(
    tmp_path: Path,
) -> None:
    result, calls = _run(tmp_path, "exec", "--", "true")

    assert result.returncode == 0, result.stderr
    command = _container_run(calls)
    assert "--mount" not in command
    assert "type=volume" not in command
    assert "run-arg -v" in calls
    assert f"run-arg {tmp_path}:/work" in calls
    assert set(_docker_hosts(calls)) == {""}
    assert not (tmp_path / ".tmp" / "remote-run.lock").exists()


def test_remote_mode_keeps_the_out_file_under_work_tmp(tmp_path: Path) -> None:
    share, repo = _share_layout(tmp_path)

    result, calls = _run(
        tmp_path,
        "test",
        "--remote",
        REMOTE_HOST,
        "-o",
        "remote-ollvm.txt",
        "--",
        "-q",
        repo_root=repo,
        extra_env=_remote_env(share),
    )

    assert result.returncode == 0, result.stderr
    command = _remote_container_run(calls)
    assert "/work/.tmp/remote-ollvm.txt" in command
    assert "/work/.tmp//remote-ollvm.txt" not in command
    assert (repo / ".tmp").is_dir()


def test_remote_mode_reports_the_engine_and_volume_in_the_plan(
    tmp_path: Path,
) -> None:
    share, repo = _share_layout(tmp_path)

    result, _calls = _run(
        tmp_path,
        "exec",
        "--remote",
        REMOTE_HOST,
        "--",
        "true",
        repo_root=repo,
        extra_env=_remote_env(share, MOCK_DOCKER_ARCH="amd64"),
    )

    assert result.returncode == 0, result.stderr
    assert "remote:   configured engine" in result.stdout
    assert REMOTE_HOST not in result.stdout
    assert "linux/amd64" in result.stdout
    assert "volume:   idapro" in result.stdout
    assert "share root: configured" in result.stdout
    assert str(share) not in result.stdout
    assert "subpath:  d810" in result.stdout


def test_remote_mode_mounts_the_pinned_cobra_source_read_only(
    tmp_path: Path,
) -> None:
    import re

    share, repo = _share_layout(tmp_path)
    cobra_root = share / "d810-cobra"
    (cobra_root / "third_party" / "cobra").mkdir(parents=True)
    expected_parent = "3b3c406270f1efd8e222f0b05040ae4e074b27d5"
    expected_core = "72f616f822f538a0cfbea3c880f9d1e68bb9a8f1"
    mock_git = f"""#!/usr/bin/env bash
set -eu
if [[ "$*" == *"rev-parse HEAD"* ]]; then
  case "$*" in
    *third_party/cobra*) printf '%s\\n' '{expected_core}' ;;
    *) printf '%s\\n' '{expected_parent}' ;;
  esac
fi
"""

    result, calls = _run(
        tmp_path,
        "exec",
        "--remote",
        REMOTE_HOST,
        "--",
        "true",
        repo_root=repo,
        extra_env=_remote_env(share, D810_COBRA_ROOT=str(cobra_root)),
        mock_git=mock_git,
    )

    assert result.returncode == 0, result.stderr
    pattern = re.compile(
        r"^run-arg type=volume,src=idapro,dst=/opt/d810-cobra-source,"
        r"volume-subpath=d810/\.tmp/cobra-source\.[A-Za-z0-9]{6}/source,readonly$"
    )
    assert [call for call in calls if pattern.match(call)], calls
    assert "run-arg -v" not in calls


def _wheel_on_share(share: Path, under_test: WheelUnderTest) -> WheelUnderTest:
    """Copy the wheel under test into the share root, byte-for-byte.

    Remote mode refuses any mount outside the share, so the wheel a remote run
    installs has to live there; the sha256 gate then still applies.
    """
    destination = share / "wheels" / under_test.name
    destination.parent.mkdir(parents=True, exist_ok=True)
    shutil.copy2(under_test.path, destination)
    return under_test._replace(
        path=destination,
        env={**under_test.env, "D810_COBRA_WHEEL": str(destination)},
    )


def test_remote_mode_checks_the_cobra_wheel_against_the_remote_engine(
    tmp_path: Path,
) -> None:
    """The wheel must match the engine that runs it, not this machine.

    --remote points DOCKER_HOST at another architecture, so an x86_64 wheel is
    the correct choice for an amd64 remote engine even on an arm64 Mac.
    """
    share, repo = _share_layout(tmp_path)
    under_test = _wheel_on_share(share, _wheel_under_test("x86_64"))

    result, calls = _run(
        tmp_path,
        "exec",
        "--remote",
        REMOTE_HOST,
        "--",
        "true",
        repo_root=repo,
        extra_env=_remote_env(
            share,
            **under_test.env,
            MOCK_DOCKER_SERVER_ARCH="arm64",
            MOCK_DOCKER_REMOTE_SERVER_ARCH="amd64",
        ),
    )

    assert result.returncode == 0, result.stderr
    assert "wheel but the Docker engine is" not in result.stderr
    assert _runs(calls)
    # The architecture probe itself has to be addressed to the remote engine.
    hosts = _docker_hosts(calls)
    versions = [
        index
        for index, call in enumerate(_docker_calls(calls))
        if call.startswith("version ")
    ]
    assert versions, calls
    assert all(hosts[index] == f"ssh://{REMOTE_HOST}" for index in versions), calls


def test_remote_mode_rejects_a_wheel_that_only_matches_the_local_engine(
    tmp_path: Path,
) -> None:
    """An aarch64 wheel is wrong for an amd64 remote engine, Mac or not."""
    share, repo = _share_layout(tmp_path)
    under_test = _wheel_on_share(share, _wheel_under_test("aarch64"))

    result, calls = _run(
        tmp_path,
        "exec",
        "--remote",
        REMOTE_HOST,
        "--",
        "true",
        repo_root=repo,
        extra_env=_remote_env(
            share,
            **under_test.env,
            MOCK_DOCKER_SERVER_ARCH="arm64",
            MOCK_DOCKER_REMOTE_SERVER_ARCH="amd64",
        ),
    )

    assert result.returncode != 0
    assert "aarch64 wheel but the Docker engine is x86_64" in result.stderr
    # preflight's read-only probes may have run; no workload container did
    assert _workload_runs(calls) == []
    # Failing closed before the lock leaves nothing to clean up.
    assert not (repo / ".tmp" / "remote-run.lock").exists()


def test_remote_mode_grants_a_tmp_scoped_acl_only(tmp_path: Path) -> None:
    """The share account must never gain write access to source, .git or root."""
    share, repo = _share_layout(tmp_path)
    (repo / ".tmp" / "logs").mkdir(parents=True)
    (repo / ".tmp" / "cobra-linux").mkdir(parents=True)

    result, _calls = _run(
        tmp_path,
        "exec",
        "--remote",
        REMOTE_HOST,
        "--",
        "true",
        repo_root=repo,
        extra_env=_remote_env(share),
    )

    assert result.returncode == 0, result.stderr
    acl_calls = [call for call in _chmod_calls(tmp_path) if call.startswith("+a ")]
    assert acl_calls
    targets = [call.rsplit(" ", 1)[-1] for call in acl_calls]
    tmp_root = str(repo / ".tmp")
    for target in targets:
        assert target == tmp_root or target.startswith(tmp_root + "/"), target
    assert str(repo / "src") not in targets
    assert str(repo / ".git") not in targets
    assert str(share) not in targets
    assert any(target == tmp_root for target in targets)
    assert any(target.endswith("/.tmp/logs") for target in targets)
    assert not any(target.endswith("/.tmp/cobra-linux") for target in targets)
    assert any("share-account allow" in call for call in acl_calls)
    assert any("file_inherit,directory_inherit" in call for call in acl_calls)
    # the invoking user needs an inheritable ACE too, or the container's own
    # -o capture comes back unreadable (it is created 0600 by the share account)
    assert any(f"{getpass.getuser()} allow" in call for call in acl_calls)


def test_remote_acl_user_follows_the_smb_account(tmp_path: Path) -> None:
    share, repo = _share_layout(tmp_path)

    result, _calls = _run(
        tmp_path,
        "exec",
        "--remote",
        REMOTE_HOST,
        "--",
        "true",
        repo_root=repo,
        extra_env=_remote_env(share, D810_REMOTE_SMB_USER="otheruser"),
    )

    assert result.returncode == 0, result.stderr
    acl_calls = [call for call in _chmod_calls(tmp_path) if call.startswith("+a ")]
    assert acl_calls and any("otheruser allow" in call for call in acl_calls)


def test_remote_mode_fails_closed_when_the_acl_cannot_be_applied(
    tmp_path: Path,
) -> None:
    share, repo = _share_layout(tmp_path)

    result, calls = _run(
        tmp_path,
        "exec",
        "--remote",
        REMOTE_HOST,
        "--",
        "true",
        repo_root=repo,
        extra_env=_remote_env(share, MOCK_CHMOD_ACL_EXIT="1"),
    )

    assert result.returncode != 0
    assert "could not grant" in result.stderr
    assert _workload_runs(calls) == []


def test_remote_mode_fails_closed_when_required_logs_acl_cannot_be_applied(
    tmp_path: Path,
) -> None:
    """Finalized remote artifacts are staged into .tmp/logs, so it is required."""
    share, repo = _share_layout(tmp_path)
    logs = repo / ".tmp" / "logs"
    logs.mkdir(parents=True)

    result, calls = _run(
        tmp_path,
        "exec",
        "--remote",
        REMOTE_HOST,
        "--",
        "true",
        repo_root=repo,
        extra_env=_remote_env(share, MOCK_CHMOD_ACL_FAIL_TARGET=str(logs)),
    )

    assert result.returncode != 0
    assert f"could not grant share-account access to {logs}" in result.stderr
    assert _workload_runs(calls) == []


def test_remote_mode_rejects_a_logs_symlink_before_acls_or_workload_docker(
    tmp_path: Path,
) -> None:
    share, repo = _share_layout(tmp_path)
    logs = repo / ".tmp" / "logs"
    logs.parent.mkdir()
    logs.symlink_to("../src")

    result, calls = _run(
        tmp_path,
        "exec",
        "--remote",
        REMOTE_HOST,
        "--",
        "true",
        repo_root=repo,
        extra_env=_remote_env(share),
    )

    assert result.returncode != 0
    assert "real directory" in result.stderr
    assert not any(str(repo / "src") in call for call in _chmod_calls(tmp_path))
    assert _workload_runs(calls) == []


def test_remote_mode_rejects_a_tmp_symlink_before_acls_or_workload_docker(
    tmp_path: Path,
) -> None:
    share, repo = _share_layout(tmp_path)
    tmp_link = repo / ".tmp"
    tmp_link.symlink_to("src")

    result, calls = _run(
        tmp_path,
        "exec",
        "--remote",
        REMOTE_HOST,
        "--",
        "true",
        repo_root=repo,
        extra_env=_remote_env(share),
    )

    assert result.returncode != 0
    assert "real directory" in result.stderr
    assert not any(str(repo / "src") in call for call in _chmod_calls(tmp_path))
    assert not (repo / "src" / "logs").exists()
    assert _workload_runs(calls) == []


@pytest.mark.parametrize("output", ["", ".", "..", "../victim.txt", "nested/out.txt"])
def test_output_requires_a_bare_filename_before_remote_side_effects(
    tmp_path: Path, output: str
) -> None:
    """A traversal must not delete a sibling before remote setup begins."""
    share, repo = _share_layout(tmp_path)
    victim = repo / "victim.txt"
    victim.write_text("must survive\n", encoding="utf-8")

    result, calls = _run(
        tmp_path,
        "test",
        "--remote",
        REMOTE_HOST,
        "-o",
        output,
        "--",
        "-q",
        repo_root=repo,
        extra_env=_remote_env(share),
    )

    assert result.returncode != 0
    assert "bare filename" in result.stderr
    assert victim.read_text(encoding="utf-8") == "must survive\n"
    assert not (repo / ".tmp").exists()
    assert calls == []


def test_output_flag_requires_a_value_before_remote_side_effects(tmp_path: Path) -> None:
    share, repo = _share_layout(tmp_path)

    result, calls = _run(
        tmp_path,
        "test",
        "--remote",
        REMOTE_HOST,
        "-o",
        repo_root=repo,
        extra_env=_remote_env(share),
    )

    assert result.returncode != 0
    assert "bare filename" in result.stderr
    assert not (repo / ".tmp").exists()
    assert calls == []


def test_local_mode_rejects_an_invalid_output_before_docker(tmp_path: Path) -> None:
    victim = tmp_path / "victim.txt"
    victim.write_text("must survive\n", encoding="utf-8")

    result, calls = _run(tmp_path, "test", "-o", "../victim.txt", "--", "-q")

    assert result.returncode != 0
    assert "bare filename" in result.stderr
    assert victim.read_text(encoding="utf-8") == "must survive\n"
    assert calls == []


def test_output_filename_metacharacters_remain_literal_in_the_container_shell(
    tmp_path: Path,
) -> None:
    share, repo = _share_layout(tmp_path)
    marker = tmp_path / "injected"
    filename = "$(touch injected) report.txt"

    result, calls = _run(
        tmp_path,
        "test",
        "--remote",
        REMOTE_HOST,
        "-o",
        filename,
        "--",
        "-q",
        repo_root=repo,
        extra_env=_remote_env(
            share, MOCK_DOCKER_EVALUATE_OUTPUT_REDIR=str(tmp_path)
        ),
    )

    assert result.returncode == 0, result.stderr
    assert not marker.exists()
    assert "/work/.tmp/" in _remote_container_run(calls)


def test_remote_mode_requires_a_darwin_host(tmp_path: Path) -> None:
    share, repo = _share_layout(tmp_path)

    result, calls = _run(
        tmp_path,
        "exec",
        "--remote",
        REMOTE_HOST,
        "--",
        "true",
        repo_root=repo,
        extra_env=_remote_env(share, MOCK_UNAME_S="Linux"),
    )

    assert result.returncode != 0
    assert "Darwin" in result.stderr
    assert calls == []
    assert _chmod_calls(tmp_path) == []


def test_local_mode_applies_no_acl(tmp_path: Path) -> None:
    result, _calls = _run(tmp_path, "exec", "--", "true")

    assert result.returncode == 0, result.stderr
    assert [call for call in _chmod_calls(tmp_path) if call.startswith("+a ")] == []


def test_remote_mode_mirrors_source_into_the_work_volume(tmp_path: Path) -> None:
    share, repo = _share_layout(tmp_path)

    result, calls = _run(
        tmp_path,
        "exec",
        "--remote",
        REMOTE_HOST,
        "--",
        "true",
        repo_root=repo,
        extra_env=_remote_env(share),
    )

    assert result.returncode == 0, result.stderr
    command = _remote_container_run(calls)
    # an immutable archive built on the Mac from one explicit manifest
    assert re.search(
        r"tar -C /work -xf '/work/\.tmp/remote-src\.[A-Za-z0-9]{6}/source\.tar'",
        command,
    ), command
    assert "tar -C /work-src" not in command
    # the destination is emptied first, so the mirror is exact - except for the
    # read-write .tmp mount and the retained run store
    assert (
        "find /work -mindepth 1 -maxdepth 1 ! -name .tmp ! -name runs -exec rm -rf {} +"
        in command
    )
    assert "set -o pipefail" in command


def test_manifest_excludes_ignored_files_and_build_output(tmp_path: Path) -> None:
    """Ignored content is neither tested source nor covered by the digest."""
    share, repo = _share_layout(tmp_path)
    (repo / ".env").write_text("D810_API_TOKEN=secret\n", encoding="utf-8")
    manifest_log = tmp_path / "manifest.log"
    # Only the files that MUST be archived exist; the excluded ones do not, so
    # any leak through the filter makes tar fail closed instead of passing.
    for relative in ("src/d810/x.py", "tests/t.py", "samples/bins/libobfuscated.dll",
                     "untracked.py"):
        target = repo / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text("content\n", encoding="utf-8")

    git_stub = f"""#!/usr/bin/env bash
set -eu
printf '%s\\n' "$*" >> '{manifest_log}'
for arg in "$@"; do
  if [ "$arg" = "--git-common-dir" ]; then exit 1; fi
done
case "$*" in
  *"ls-files --others --exclude-standard -z"*)
    printf 'untracked.py\\0'
    ;;
  *"ls-files -z"*)
    printf 'src/d810/x.py\\0tests/t.py\\0samples/bins/libobfuscated.dll\\0'
    printf 'src/d810/speedups/x.so\\0build/artifact.o\\0src/d810/__pycache__/x.pyc\\0'
    ;;
  *"check-ignore"*) exit 0 ;;
esac
"""

    result, calls = _run(
        tmp_path,
        "exec",
        "--remote",
        REMOTE_HOST,
        "--",
        "true",
        repo_root=repo,
        extra_env=_remote_env(share),
        mock_git=git_stub,
    )

    assert result.returncode == 0, result.stderr
    manifests = list((repo / ".tmp").glob("remote-manifest.*"))
    # the manifest is cleaned up on exit, so read what the run recorded instead
    assert not manifests
    logged = manifest_log.read_text(encoding="utf-8")
    assert "ls-files -z" in logged
    assert "ls-files --others --exclude-standard -z" in logged
    command = _remote_container_run(calls)
    # nothing walks the source tree, so ignored files cannot be swept in
    assert "tar -C /work-src" not in command
    assert ".env" not in command


def test_allowlist_entries_are_validated(tmp_path: Path) -> None:
    share, repo = _share_layout(tmp_path)

    result, calls = _run(
        tmp_path,
        "exec",
        "--remote",
        REMOTE_HOST,
        "--",
        "true",
        repo_root=repo,
        extra_env=_remote_env(share),
        allowlist="missing-file.txt\n",
    )

    assert result.returncode != 0
    assert "allowlisted path does not exist" in result.stderr
    assert _workload_runs(calls) == []


def test_allowlist_refuses_dotenv(tmp_path: Path) -> None:
    share, repo = _share_layout(tmp_path)
    (repo / ".env").write_text("D810_API_TOKEN=secret\n", encoding="utf-8")

    result, calls = _run(
        tmp_path,
        "exec",
        "--remote",
        REMOTE_HOST,
        "--",
        "true",
        repo_root=repo,
        extra_env=_remote_env(share),
        allowlist=".env\n",
    )

    assert result.returncode != 0
    assert "never list .env" in result.stderr
    assert _workload_runs(calls) == []


def test_allowlist_refuses_a_tracked_path(tmp_path: Path) -> None:
    share, repo = _share_layout(tmp_path)
    (repo / "tracked.txt").write_text("x\n", encoding="utf-8")
    git_stub = """#!/usr/bin/env bash
set -eu
case "$*" in
  *check-ignore*) exit 1 ;;
  *--git-common-dir*) exit 1 ;;
esac
"""

    result, calls = _run(
        tmp_path,
        "exec",
        "--remote",
        REMOTE_HOST,
        "--",
        "true",
        repo_root=repo,
        extra_env=_remote_env(share),
        mock_git=git_stub,
        allowlist="tracked.txt\n",
    )

    assert result.returncode != 0
    assert "not ignored by git" in result.stderr
    assert _workload_runs(calls) == []


def test_plan_reports_the_allowlist(tmp_path: Path) -> None:
    share, repo = _share_layout(tmp_path)

    result, _calls = _run(
        tmp_path,
        "exec",
        "--remote",
        REMOTE_HOST,
        "--",
        "true",
        repo_root=repo,
        extra_env=_remote_env(share),
    )

    assert result.returncode == 0, result.stderr
    assert "allowlist:  none" in result.stdout
    assert "tracked + untracked-not-ignored, ignored content excluded" in result.stdout


def test_remote_sync_sentinel_gates_reuse_on_the_source_digest(
    tmp_path: Path,
) -> None:
    share, repo = _share_layout(tmp_path)

    result, calls = _run(
        tmp_path,
        "exec",
        "--remote",
        REMOTE_HOST,
        "--",
        "true",
        repo_root=repo,
        extra_env=_remote_env(share),
    )

    assert result.returncode == 0, result.stderr
    command = _remote_container_run(calls)
    digests = re.findall(r"__digest='([0-9a-f]{16})'", command)
    assert digests, command
    digest = digests[0]
    # reuse only on an exact digest match, sentinel cleared before mirroring,
    # and written only after the mirror completed
    assert f"[ -f '/work/.d810-sync-ok' ] && [ \"$(cat '/work/.d810-sync-ok')\" = \"$__digest\" ]" in command
    assert "rm -f '/work/.d810-sync-ok'" in command
    assert command.index("tar -C /work -xf ") < command.index(
        "> '/work/.d810-sync-ok'"
    )
    assert digest in result.stdout


def test_archive_digest_is_immune_to_edits_after_materialization(
    tmp_path: Path,
) -> None:
    """The digest names the archived bytes, not whatever the tree holds later."""
    share, repo = _share_layout(tmp_path)
    payload = repo / "src" / "payload.py"
    payload.write_text("original\n", encoding="utf-8")
    kept = tmp_path / "kept"
    kept.mkdir()

    git_stub = """#!/usr/bin/env bash
set -eu
for arg in "$@"; do
  if [ "$arg" = "--git-common-dir" ]; then exit 1; fi
done
case "$*" in
  *"ls-files --others --exclude-standard -z"*) : ;;
  *"ls-files -z"*) printf 'src/payload.py\\0' ;;
esac
"""
    # The mock docker copies the archive aside, then the source is mutated.
    docker_extra = f"""
if [ "${{1:-}}" = run ]; then
  for arg in "$@"; do
    case "$arg" in
      *remote-src.*) : ;;
    esac
  done
fi
"""

    result, calls = _run(
        tmp_path,
        "exec",
        "--remote",
        REMOTE_HOST,
        "--",
        "true",
        repo_root=repo,
        extra_env=_remote_env(share),
        mock_git=git_stub,
    )
    assert result.returncode == 0, result.stderr
    first_digest = re.search(r"source digest: ([0-9a-f]{16})", result.stdout)
    assert first_digest, result.stdout

    payload.write_text("mutated after the archive was built\n", encoding="utf-8")
    result_two, _calls = _run(
        tmp_path,
        "exec",
        "--remote",
        REMOTE_HOST,
        "--",
        "true",
        repo_root=repo,
        extra_env=_remote_env(share),
        mock_git=git_stub,
    )
    second_digest = re.search(r"source digest: ([0-9a-f]{16})", result_two.stdout)
    assert second_digest

    # content changed -> digest changed; the first run's archive still named
    # the bytes it captured, and the container extracts that archive only
    assert first_digest.group(1) != second_digest.group(1)
    command = _remote_container_run(_runs(calls) and calls)
    assert "source.tar" in command


def test_archive_digest_ignores_mtime_only_changes(tmp_path: Path) -> None:
    share, repo = _share_layout(tmp_path)
    (repo / "src" / "payload.py").write_text("stable\n", encoding="utf-8")
    git_stub = """#!/usr/bin/env bash
set -eu
for arg in "$@"; do
  if [ "$arg" = "--git-common-dir" ]; then exit 1; fi
done
case "$*" in
  *"ls-files --others --exclude-standard -z"*) : ;;
  *"ls-files -z"*) printf 'src/payload.py\\0' ;;
esac
"""

    first, _ = _run(
        tmp_path, "exec", "--remote", REMOTE_HOST, "--", "true",
        repo_root=repo, extra_env=_remote_env(share), mock_git=git_stub,
    )
    os.utime(repo / "src" / "payload.py", (0, 0))
    second, _ = _run(
        tmp_path, "exec", "--remote", REMOTE_HOST, "--", "true",
        repo_root=repo, extra_env=_remote_env(share), mock_git=git_stub,
    )

    assert first.returncode == 0 and second.returncode == 0
    digests = [
        re.search(r"source digest: ([0-9a-f]{16})", output.stdout).group(1)
        for output in (first, second)
    ]
    assert digests[0] == digests[1]


def test_remote_plan_reports_the_source_digest_and_work_volume(
    tmp_path: Path,
) -> None:
    share, repo = _share_layout(tmp_path)

    result, _calls = _run(
        tmp_path,
        "exec",
        "--remote",
        REMOTE_HOST,
        "--",
        "true",
        repo_root=repo,
        extra_env=_remote_env(share),
    )

    assert result.returncode == 0, result.stderr
    assert "source digest: " in result.stdout
    assert f"work volume: {_work_volume_name(repo)} (created" in result.stdout
    assert "share user: configured" in result.stdout
    assert "read-only at /work-src" in result.stdout


def test_work_volume_is_labelled_and_path_unique(tmp_path: Path) -> None:
    share, repo = _share_layout(tmp_path)
    (repo / ".worktrees" / "wt" / "src").mkdir(parents=True)
    other_root = share / "other"
    (other_root / ".worktrees" / "wt" / "src").mkdir(parents=True)

    result, calls = _run(
        tmp_path,
        "exec",
        "--remote",
        REMOTE_HOST,
        "-w",
        "wt",
        "--",
        "true",
        repo_root=repo,
        extra_env=_remote_env(share),
    )

    assert result.returncode == 0, result.stderr
    create = [call for call in calls if call.startswith("volume create ")]
    assert len(create) == 2  # the source copy and the CoBRA build cache
    assert "--label d810.role=work" in create[0]
    assert "--label d810.role=cobra-cache" in create[1]
    assert "--label d810.credential_volume=idapro" in create[0]
    assert "--label d810.worktree=wt" in create[0]
    assert "--label d810.share_root_digest=" in create[0]
    first = _work_volume_name(repo / ".worktrees" / "wt")
    second = _work_volume_name(other_root / ".worktrees" / "wt")
    assert first != second
    assert create[0].endswith(first)
    assert create[1].endswith(first.replace("d810-work-", "d810-cobra-", 1))


def test_existing_work_volume_is_reused_not_recreated(tmp_path: Path) -> None:
    share, repo = _share_layout(tmp_path)

    result, calls = _run(
        tmp_path,
        "exec",
        "--remote",
        REMOTE_HOST,
        "--",
        "true",
        repo_root=repo,
        extra_env=_remote_env(share, MOCK_WORK_VOLUME_EXISTS="1"),
    )

    assert result.returncode == 0, result.stderr
    assert not [call for call in calls if call.startswith("volume create ")]
    assert "(existing, retained source copy)" in result.stdout
    assert "cobra cache volume: d810-cobra-" in result.stdout


def test_work_volume_creation_failure_fails_closed(tmp_path: Path) -> None:
    share, repo = _share_layout(tmp_path)

    result, calls = _run(
        tmp_path,
        "exec",
        "--remote",
        REMOTE_HOST,
        "--",
        "true",
        repo_root=repo,
        extra_env=_remote_env(share, MOCK_WORK_VOLUME_CREATE_FAILS="1"),
    )

    assert result.returncode != 0
    assert "could not create work volume" in result.stderr
    assert _workload_runs(calls) == []


def test_remote_lock_still_guards_the_shared_tmp(tmp_path: Path) -> None:
    """The mirror removed the source-build reason, not the .tmp collision."""
    share, repo = _share_layout(tmp_path)
    lock = repo / ".tmp" / "remote-run.lock"
    lock.mkdir(parents=True)

    result, calls = _run(
        tmp_path,
        "exec",
        "--remote",
        REMOTE_HOST,
        "--",
        "true",
        repo_root=repo,
        extra_env=_remote_env(share),
    )

    assert result.returncode != 0
    assert "already owns this worktree" in result.stderr
    assert _workload_runs(calls) == []


def _worktree_git_stub(common: Path, worktree_git: Path) -> str:
    return f"""#!/usr/bin/env bash
set -eu
case "$*" in
  *--git-common-dir*) printf '%s\\n' '{common}'; exit 0 ;;
  *--git-dir*) printf '%s\\n' '{worktree_git}'; exit 0 ;;
  *"ls-files --others --exclude-standard -z"*) exit 0 ;;
  *"ls-files -z"*) exit 0 ;;
esac
exit 1
"""


def test_cobra_acquisition_escapes_both_git_environment_pins(
    tmp_path: Path,
) -> None:
    """GIT_COMMON_DIR left set makes git clone write to the read-only mount."""
    result, calls = _run(tmp_path, "exec", "--", "true")

    assert result.returncode == 0, result.stderr
    command = _container_run(calls)
    assert "env -u GIT_DIR -u GIT_COMMON_DIR git clone" in command
    assert "env -u GIT_DIR git" not in command.replace(
        "env -u GIT_DIR -u GIT_COMMON_DIR git", ""
    )


def test_remote_worktree_git_identity_points_at_the_tested_worktree(
    tmp_path: Path,
) -> None:
    """GIT_DIR=/d810-git alone resolves the MAIN checkout's HEAD."""
    share, repo = _share_layout(tmp_path)
    common = repo / ".git"
    worktree_git = common / "worktrees" / "wt"
    worktree_git.mkdir(parents=True)
    (repo / ".worktrees" / "wt" / "src").mkdir(parents=True)

    result, calls = _run(
        tmp_path,
        "exec",
        "--remote",
        REMOTE_HOST,
        "-w",
        "wt",
        "--",
        "true",
        repo_root=repo,
        extra_env=_remote_env(share),
        mock_git=_worktree_git_stub(common, worktree_git),
    )

    assert result.returncode == 0, result.stderr
    # the per-worktree git dir lives inside the common mount, so no second
    # mount is needed and the relative commondir ("../..") still resolves
    assert not [call for call in calls if "d810-git-worktree" in call]
    assert (
        calls.count(
            "run-arg type=volume,src=idapro,dst=/d810-git,"
            "volume-subpath=d810/.git,readonly"
        )
        == 1
    )
    command = _remote_container_run(calls)
    assert "GIT_DIR=/d810-git/worktrees/wt " in command
    assert "GIT_COMMON_DIR=" not in command.replace("-u GIT_COMMON_DIR", "")


def test_remote_repo_root_keeps_the_plain_common_dir_form(tmp_path: Path) -> None:
    share, repo = _share_layout(tmp_path)
    common = repo / ".git"
    common.mkdir()

    result, calls = _run(
        tmp_path,
        "exec",
        "--remote",
        REMOTE_HOST,
        "--",
        "true",
        repo_root=repo,
        extra_env=_remote_env(share),
        mock_git=_worktree_git_stub(common, common),
    )

    assert result.returncode == 0, result.stderr
    command = _remote_container_run(calls)
    assert "GIT_DIR=/d810-git " in command
    assert "/d810-git/worktrees" not in command


def test_local_mode_git_identity_is_unchanged(tmp_path: Path) -> None:
    """Local behaviour must stay byte-identical; the same defect is reported."""
    share, repo = _share_layout(tmp_path)
    common = repo / ".git"
    worktree_git = common / "worktrees" / "wt"
    worktree_git.mkdir(parents=True)
    (repo / ".worktrees" / "wt" / "src").mkdir(parents=True)

    result, calls = _run(
        tmp_path,
        "exec",
        "-w",
        "wt",
        "--",
        "true",
        repo_root=repo,
        mock_git=_worktree_git_stub(common, worktree_git),
    )

    assert result.returncode == 0, result.stderr
    command = _container_run(calls)
    assert "GIT_DIR=/d810-git " in command
    assert "/d810-git/worktrees" not in command


def test_stale_capture_is_removed_so_the_new_one_inherits_the_acl(
    tmp_path: Path,
) -> None:
    """A capture owned by the share account cannot be re-ACLed from here."""
    share, repo = _share_layout(tmp_path)
    capture = repo / ".tmp" / "out.txt"
    capture.parent.mkdir(parents=True)
    capture.write_text("stale capture\n", encoding="utf-8")

    result, calls = _run(
        tmp_path,
        "test",
        "--remote",
        REMOTE_HOST,
        "-o",
        "out.txt",
        "--",
        "-q",
        repo_root=repo,
        extra_env=_remote_env(share),
    )

    assert result.returncode == 0, result.stderr
    assert not capture.exists()
    assert not [
        call for call in _chmod_calls(tmp_path) if call.endswith("/.tmp/out.txt")
    ]
    assert "/work/.tmp/out.txt" in _remote_container_run(calls)


def test_stale_capture_symlink_is_removed_without_touching_its_target(
    tmp_path: Path,
) -> None:
    share, repo = _share_layout(tmp_path)
    capture = repo / ".tmp" / "out.txt"
    capture.parent.mkdir(parents=True)
    capture.symlink_to(tmp_path / "missing-capture-target.txt")

    result, calls = _run(
        tmp_path,
        "test",
        "--remote",
        REMOTE_HOST,
        "-o",
        "out.txt",
        "--",
        "-q",
        repo_root=repo,
        extra_env=_remote_env(share),
    )

    assert result.returncode == 0, result.stderr
    assert not capture.is_symlink()
    assert "/work/.tmp/out.txt" in _remote_container_run(calls)


def test_acl_failure_on_the_tmp_root_still_fails_closed(tmp_path: Path) -> None:
    share, repo = _share_layout(tmp_path)

    result, calls = _run(
        tmp_path,
        "exec",
        "--remote",
        REMOTE_HOST,
        "--",
        "true",
        repo_root=repo,
        extra_env=_remote_env(share, MOCK_CHMOD_ACL_EXIT="1"),
    )

    assert result.returncode != 0
    assert "could not grant" in result.stderr
    assert _workload_runs(calls) == []


def test_remote_mode_exports_a_run_id_for_database_keying(tmp_path: Path) -> None:
    """PIDs restart at 1 per container, so pid-keyed names can collide."""
    share, repo = _share_layout(tmp_path)

    result, calls = _run(
        tmp_path,
        "exec",
        "--remote",
        REMOTE_HOST,
        "--",
        "true",
        repo_root=repo,
        extra_env=_remote_env(share),
    )

    assert result.returncode == 0, result.stderr
    command = _remote_container_run(calls)
    match = re.search(r"-e D810_RUN_ID=(\S+)", command)
    assert match, command
    assert re.fullmatch(r"\d{8}T\d{6}Z-\d+-[0-9a-f]{6}", match.group(1))
    assert "run id:   " in result.stdout


def test_local_mode_does_not_set_a_run_id(tmp_path: Path) -> None:
    result, calls = _run(tmp_path, "exec", "--", "true")

    assert result.returncode == 0, result.stderr
    assert "D810_RUN_ID" not in _container_run(calls)


def test_remote_logs_are_staged_from_the_work_volume_at_exit(tmp_path: Path) -> None:
    """Live SQLite writers must never sit on the cifs mount."""
    share, repo = _share_layout(tmp_path)

    result, calls = _run(
        tmp_path,
        "exec",
        "--remote",
        REMOTE_HOST,
        "-l",
        "--",
        "true",
        repo_root=repo,
        extra_env=_remote_env(share),
    )

    assert result.returncode == 0, result.stderr
    assert not [call for call in calls if "dst=/root/.idapro/logs" in call]
    command = _remote_container_run(calls)
    assert "RUN_LOGS=/work/runs/$D810_RUN_ID/logs" in command
    assert "STAGE_DEST=/work/.tmp/logs/$D810_RUN_ID" in command
    assert 'ln -sfn "$RUN_LOGS" /root/.idapro/logs' in command
    # the trap fires on failure too, and reports how long the copy took
    assert "trap 'set +e;" in command
    assert "' EXIT" in command
    assert 'cp -a "$RUN_LOGS"/. "$STAGE_DEST"/' in command
    assert "[artifacts] staged" in command
    # exec would replace the shell and lose the trap
    assert 'exec "$@"' not in command
    assert '"$@"' in command
    assert "staged to .tmp/logs/" in result.stdout


@pytest.mark.parametrize(
    "flag", ["-l", "--logs", "--enable-debug-logging", "--enable-diag-snapshot"]
)
def test_remote_artifact_flags_request_the_exit_copy_to_the_share(
    tmp_path: Path,
    flag: str,
) -> None:
    """Each artifact-bearing flag asks for the finished logs on the share."""
    share, repo = _share_layout(tmp_path)

    result, calls = _run(
        tmp_path,
        "exec",
        "--remote",
        REMOTE_HOST,
        flag,
        "--",
        "true",
        repo_root=repo,
        extra_env=_remote_env(share),
    )

    assert result.returncode == 0, result.stderr
    command = _remote_container_run(calls)
    assert 'ln -sfn "$RUN_LOGS" /root/.idapro/logs' in command
    assert "STAGE_DEST=/work/.tmp/logs/$D810_RUN_ID" in command
    assert 'cp -a "$RUN_LOGS"/. "$STAGE_DEST"/' in command
    assert "staged to .tmp/logs/" in result.stdout


def test_remote_without_artifact_flags_redirects_but_does_not_stage(
    tmp_path: Path,
) -> None:
    """The redirect is unconditional; the share copy is not."""
    share, repo = _share_layout(tmp_path)

    result, calls = _run(
        tmp_path,
        "exec",
        "--remote",
        REMOTE_HOST,
        "--",
        "true",
        repo_root=repo,
        extra_env=_remote_env(share),
    )

    assert result.returncode == 0, result.stderr
    command = _remote_container_run(calls)
    # the work-volume redirect stays, so no live SQLite writer reaches cifs
    assert "RUN_LOGS=/work/runs/$D810_RUN_ID/logs" in command
    assert 'ln -sfn "$RUN_LOGS" /root/.idapro/logs' in command
    # nothing is copied to, or created on, the share
    assert "STAGE_DEST" not in command
    assert 'cp -a "$RUN_LOGS"' not in command
    assert "[artifacts] staged" not in command
    assert "/work/.tmp/logs/" not in command
    assert "trap " not in command
    assert (
        "work volume, retained; use the artifacts subcommand to copy"
        in result.stdout
    )
    assert "staged to .tmp/logs/" not in result.stdout


def test_remote_sync_wipe_spares_the_run_store(tmp_path: Path) -> None:
    """A digest change must not destroy runs whose logs were never staged."""
    share, repo = _share_layout(tmp_path)

    result, calls = _run(
        tmp_path,
        "exec",
        "--remote",
        REMOTE_HOST,
        "--",
        "true",
        repo_root=repo,
        extra_env=_remote_env(share),
    )

    assert result.returncode == 0, result.stderr
    command = _remote_container_run(calls)
    assert (
        "find /work -mindepth 1 -maxdepth 1 ! -name .tmp ! -name runs -exec rm -rf {} +"
        in command
    )


def test_remote_run_store_is_bounded(tmp_path: Path) -> None:
    """The wipe no longer prunes it, so the run store needs its own bound."""
    share, repo = _share_layout(tmp_path)

    result, calls = _run(
        tmp_path,
        "exec",
        "--remote",
        REMOTE_HOST,
        "--",
        "true",
        repo_root=repo,
        extra_env=_remote_env(share, D810_REMOTE_RUN_RETENTION="3"),
    )

    assert result.returncode == 0, result.stderr
    command = _remote_container_run(calls)
    assert "__runs_keep=3" in command
    assert "ls -1 /work/runs 2>/dev/null | sort | head -n -$__runs_keep" in command


def test_local_mode_still_mounts_logs_directly(tmp_path: Path) -> None:
    result, calls = _run(tmp_path, "exec", "-l", "--", "true")

    assert result.returncode == 0, result.stderr
    assert [call for call in calls if call.endswith(":/root/.idapro/logs")]
    command = _container_run(calls)
    assert "RUN_LOGS=" not in command
    assert 'exec "$@"' in command


def test_artifacts_lists_retained_runs(tmp_path: Path) -> None:
    share, repo = _share_layout(tmp_path)

    result, calls = _run(
        tmp_path,
        "artifacts",
        "--remote",
        REMOTE_HOST,
        repo_root=repo,
        extra_env=_remote_env(share),
    )

    assert result.returncode == 0, result.stderr
    command = _remote_container_run(calls)
    assert "ls -1 /work/runs" in command
    # listing must not pay for the dependency setup
    assert "pip install" not in command
    assert "COBRA_BUILD_DIR" not in command
    assert f"type=volume,src={_work_volume_name(repo)},dst=/work" in command


def test_artifacts_copies_one_run_back_to_the_share(tmp_path: Path) -> None:
    share, repo = _share_layout(tmp_path)

    result, calls = _run(
        tmp_path,
        "artifacts",
        "--remote",
        REMOTE_HOST,
        "--run",
        "20260905T120000Z-1234-abcdef",
        repo_root=repo,
        extra_env=_remote_env(share),
    )

    assert result.returncode == 0, result.stderr
    command = _remote_container_run(calls)
    assert "test -d '/work/runs/20260905T120000Z-1234-abcdef'" in command
    assert (
        "cp -a '/work/runs/20260905T120000Z-1234-abcdef/.' "
        "'/work/.tmp/remote-runs/20260905T120000Z-1234-abcdef/'" in command
    )
    assert "type=volume,src=idapro,dst=/work/.tmp,volume-subpath=d810/.tmp" in command
    assert f"{repo}/.tmp/remote-runs/20260905T120000Z-1234-abcdef" in result.stdout


def test_artifacts_requires_remote_mode(tmp_path: Path) -> None:
    result, calls = _run(tmp_path, "artifacts")

    assert result.returncode != 0
    assert "remote-mode command" in result.stderr
    assert _runs(calls) == []


def test_run_flag_requires_an_identifier(tmp_path: Path) -> None:
    share, repo = _share_layout(tmp_path)

    result, calls = _run(
        tmp_path,
        "artifacts",
        "--remote",
        REMOTE_HOST,
        "--run",
        repo_root=repo,
        extra_env=_remote_env(share),
    )

    assert result.returncode != 0
    assert "--run requires a RUN_ID" in result.stderr
    assert _runs(calls) == []


@pytest.mark.parametrize(
    "run_id",
    [
        ".",
        "..",
        "../../etc",
        "sub/dir",
        "/absolute",
        "trailing/",
        "quote'; touch /tmp/pwned; '",
        "spaced id",
        "semi;colon",
        "dollar$var",
    ],
)
def test_run_flag_refuses_anything_but_a_bare_run_id(
    tmp_path: Path,
    run_id: str,
) -> None:
    """The id is interpolated into a container command between two fixed dirs."""
    share, repo = _share_layout(tmp_path)

    result, calls = _run(
        tmp_path,
        "artifacts",
        "--remote",
        REMOTE_HOST,
        "--run",
        run_id,
        repo_root=repo,
        extra_env=_remote_env(share),
    )

    assert result.returncode != 0
    assert "--run must be one bare run id" in result.stderr
    assert _runs(calls) == []
    assert _docker_calls(calls) == []


def test_run_flag_accepts_a_real_run_id(tmp_path: Path) -> None:
    """The ids the runner mints are exactly the accepted shape."""
    share, repo = _share_layout(tmp_path)
    run_id = "20260905T101112Z-4321-abc123"

    result, calls = _run(
        tmp_path,
        "artifacts",
        "--remote",
        REMOTE_HOST,
        "--run",
        run_id,
        repo_root=repo,
        extra_env=_remote_env(share),
    )

    assert result.returncode == 0, result.stderr
    command = _remote_container_run(calls)
    assert f"test -d '/work/runs/{run_id}'" in command
    copy = f"cp -a '/work/runs/{run_id}/.' '/work/.tmp/remote-runs/{run_id}/'"
    assert copy in command


@pytest.mark.parametrize(
    "flags",
    [
        ("-l",),
        ("--enable-diag-snapshot",),
        ("-l", "--enable-diag-snapshot", "--enable-debug-logging"),
    ],
)
def test_remote_mode_never_routes_a_log_writer_onto_cifs(
    tmp_path: Path,
    flags: tuple[str, ...],
) -> None:
    """No SQLite writer may land on the share, whatever the diagnostics flags."""
    share, repo = _share_layout(tmp_path)

    result, calls = _run(
        tmp_path,
        "exec",
        "--remote",
        REMOTE_HOST,
        *flags,
        "--",
        "true",
        repo_root=repo,
        extra_env=_remote_env(share),
    )

    assert result.returncode == 0, result.stderr
    cifs_mounts = [
        call
        for call in calls
        if call.startswith("run-arg type=volume,src=idapro,")
    ]
    assert cifs_mounts, calls
    for mount in cifs_mounts:
        assert "dst=/root/.idapro/logs" not in mount, mount
    # the only writable cifs mount is .tmp itself
    writable = [mount for mount in cifs_mounts if "readonly" not in mount]
    assert {
        mount.split("dst=")[1].split(",")[0] for mount in writable
    } == {"/work/.tmp"}
    command = _remote_container_run(calls)
    assert 'ln -sfn "$RUN_LOGS" /root/.idapro/logs' in command


def test_remote_mode_mounts_the_published_wheel_through_the_volume(
    tmp_path: Path,
) -> None:
    """Wheel mode and remote mode compose: same gates, remote-shaped mount."""
    under_test = _wheel_under_test()

    share, repo = _share_layout(tmp_path)
    # The wheel has to live under the share root: remote mounts address bytes
    # through the volume, and nothing outside the share is reachable there.
    wheel_dir = share / "_gitless" / "resource" / "cobra-wheels" / "0.1.5-published"
    wheel_dir.mkdir(parents=True)
    wheel = wheel_dir / under_test.name
    shutil.copy2(under_test.path, wheel)

    result, calls = _run(
        tmp_path,
        "exec",
        "--remote",
        REMOTE_HOST,
        "--",
        "true",
        repo_root=repo,
        extra_env=_remote_env(
            share,
            **{**under_test.env, "D810_COBRA_WHEEL": str(wheel)},
            MOCK_DOCKER_SERVER_ARCH="arm64",
        ),
    )

    assert result.returncode == 0, result.stderr

    container_path = f"{COBRA_WHEEL_CONTAINER_DIR}/{under_test.name}"
    relative = wheel.relative_to(share)
    wheel_mounts = [
        call
        for call in calls
        if call.startswith("run-arg type=volume,src=idapro,")
        and f"dst={container_path}" in call
    ]
    assert wheel_mounts == [
        "run-arg type=volume,src=idapro,"
        f"dst={container_path},volume-subpath={relative},readonly"
    ], calls

    # No local bind mount survives remote mode, for the wheel or anything else.
    assert "run-arg -v" not in calls
    assert not [call for call in calls if call == f"run-arg -v {wheel}:{container_path}:ro"]

    # Every published-wheel gate still runs inside the container.
    command = _remote_container_run(calls)
    assert (
        f"printf '%s  %s\\n' '{under_test.sha256}' "
        f"'{container_path}' | sha256sum -c -"
    ) in command
    assert f"pip install --no-deps --force-reinstall --no-cache-dir -q '{container_path}'" in command
    assert 'manifest["api_version"] == 1' in command
    assert "import d810_cobra._cobra" in command
    assert "solved.status is SolveStatus.SOLVED" in command
    # A wheel run needs no build cache, remote or not.
    assert "/opt/d810-cobra-cache" not in command


def test_remote_mode_refuses_a_symlinked_wheel(tmp_path: Path) -> None:
    """A link could name share bytes while pointing somewhere the engine cannot see."""
    under_test = _wheel_under_test()

    share, repo = _share_layout(tmp_path)
    real = tmp_path / "outside" / under_test.name
    real.parent.mkdir()
    shutil.copy2(under_test.path, real)
    link_dir = share / "wheels"
    link_dir.mkdir()
    link = link_dir / under_test.name
    link.symlink_to(real)

    result, calls = _run(
        tmp_path,
        "exec",
        "--remote",
        REMOTE_HOST,
        "--",
        "true",
        repo_root=repo,
        extra_env=_remote_env(
            share,
            **{**under_test.env, "D810_COBRA_WHEEL": str(link)},
            MOCK_DOCKER_SERVER_ARCH="arm64",
        ),
    )

    assert result.returncode != 0
    assert "cannot resolve the host path" in result.stderr
    assert _workload_runs(calls) == []


def test_remote_mode_refuses_a_wheel_outside_the_share(tmp_path: Path) -> None:
    under_test = _wheel_under_test()

    share, repo = _share_layout(tmp_path)
    outside = tmp_path / "outside"
    outside.mkdir()
    wheel = outside / under_test.name
    shutil.copy2(under_test.path, wheel)

    result, _ = _run(
        tmp_path,
        "exec",
        "--remote",
        REMOTE_HOST,
        "--",
        "true",
        repo_root=repo,
        extra_env=_remote_env(
            share,
            **{**under_test.env, "D810_COBRA_WHEEL": str(wheel)},
            MOCK_DOCKER_SERVER_ARCH="arm64",
        ),
    )

    assert result.returncode != 0
    assert "must live under the SMB share root" in result.stderr or (
        "live under the SMB share root" in result.stderr
    )


def test_a_worktree_without_its_own_dotenv_reads_the_main_checkout(
    tmp_path: Path,
) -> None:
    """Machine settings live in the main checkout's ignored .env, one level up."""
    main = tmp_path / "main"
    (main / ".git").mkdir(parents=True)
    (main / "src").mkdir()
    (main / "tests").mkdir()
    (main / ".env").write_text(
        "D810_DOCKER_IMAGE=dotenv-runtime-image\n", encoding="utf-8"
    )
    worktree = main / ".worktrees" / "feature"
    (worktree / "src").mkdir(parents=True)
    (worktree / "tests").mkdir()
    assert not (worktree / ".env").exists()

    script, docker_log = _make_harness(tmp_path, worktree)
    git = tmp_path / "bin" / "git"
    git.write_text(
        f"""#!/usr/bin/env bash
set -eu
if [ "${{1:-}}" = "rev-parse" ]; then
  for arg in "$@"; do
    case "$arg" in
      --show-toplevel) printf '%s\\n' '{worktree}'; exit 0 ;;
      --git-common-dir) printf '%s\\n' '{main}/.git'; exit 0 ;;
    esac
  done
fi
exit 0
""",
        encoding="utf-8",
    )
    git.chmod(0o755)

    env = os.environ.copy()
    for name in (
        "D810_REPO_ROOT",
        "D810_DOCKER_IMAGE",
        "D810_EGGLOG_ROOT",
        "D810_COBRA_ROOT",
        "D810_COBRA_WHEEL",
        "D810_COBRA_WHEEL_SHA256",
        "D810_REMOTE_DOCKER_HOST",
        "D810_REMOTE_VOLUME",
        "D810_REMOTE_SHARE_ROOT",
        "DOCKER_HOST",
    ):
        env.pop(name, None)
    env.update(
        {
            "PATH": f"{tmp_path / 'bin'}:{env['PATH']}",
            "DOCKER_LOG": str(docker_log),
            "CHMOD_LOG": str(tmp_path / "chmod.log"),
            "MOCK_DOCKER_LABEL": "",
            "D810_NO_CYTHON": "1",
        }
    )
    result = subprocess.run(
        [str(script), "exec", "--", "true"],
        check=False,
        capture_output=True,
        text=True,
        cwd=str(worktree),
        env=env,
    )

    assert result.returncode == 0, result.stderr
    calls = docker_log.read_text(encoding="utf-8")
    assert "dotenv-runtime-image" in calls, calls


def test_a_worktree_with_its_own_dotenv_still_wins(tmp_path: Path) -> None:
    """The fallback must not override a worktree that configured itself."""
    main = tmp_path / "main"
    (main / ".git").mkdir(parents=True)
    (main / ".env").write_text("D810_DOCKER_IMAGE=main-image\n", encoding="utf-8")
    worktree = main / ".worktrees" / "feature"
    (worktree / "src").mkdir(parents=True)
    (worktree / "tests").mkdir()
    (worktree / ".env").write_text(
        "D810_DOCKER_IMAGE=worktree-image\n", encoding="utf-8"
    )

    script, docker_log = _make_harness(tmp_path, worktree)
    git = tmp_path / "bin" / "git"
    git.write_text(
        f"""#!/usr/bin/env bash
set -eu
if [ "${{1:-}}" = "rev-parse" ]; then
  for arg in "$@"; do
    case "$arg" in
      --show-toplevel) printf '%s\\n' '{worktree}'; exit 0 ;;
      --git-common-dir) printf '%s\\n' '{main}/.git'; exit 0 ;;
    esac
  done
fi
exit 0
""",
        encoding="utf-8",
    )
    git.chmod(0o755)

    env = os.environ.copy()
    for name in ("D810_REPO_ROOT", "D810_DOCKER_IMAGE", "DOCKER_HOST"):
        env.pop(name, None)
    env.update(
        {
            "PATH": f"{tmp_path / 'bin'}:{env['PATH']}",
            "DOCKER_LOG": str(docker_log),
            "CHMOD_LOG": str(tmp_path / "chmod.log"),
            "MOCK_DOCKER_LABEL": "",
            "D810_NO_CYTHON": "1",
        }
    )
    result = subprocess.run(
        [str(script), "exec", "--", "true"],
        check=False,
        capture_output=True,
        text=True,
        cwd=str(worktree),
        env=env,
    )

    assert result.returncode == 0, result.stderr
    calls = docker_log.read_text(encoding="utf-8")
    assert "worktree-image" in calls, calls
    assert "main-image" not in calls, calls


def test_image_id_failure_is_fatal_before_any_container(tmp_path: Path) -> None:
    """An unresolvable id would name no image in the receipt and the marker."""
    result, calls = _run(
        tmp_path,
        "exec",
        "--",
        "true",
        extra_env={"MOCK_DOCKER_IMAGE_ID_FAILS": "1"},
    )

    assert result.returncode != 0
    assert "cannot resolve the image id of test-runtime-image" in result.stderr
    assert "the local Docker engine" in result.stderr
    assert "keyed by this id" in result.stderr
    # nothing may start, and no marker or receipt may be computed
    assert _runs(calls) == []
    assert not [call for call in calls if call.startswith("create ")]
    assert not [call for call in calls if "linux-cobra-core-v2" in call]


def test_image_id_failure_is_fatal_in_local_mode_when_the_image_is_absent(
    tmp_path: Path,
) -> None:
    """Local mode has no image preflight, so this is the only guard there."""
    result, calls = _run(
        tmp_path,
        "exec",
        "--",
        "true",
        extra_env={"MOCK_DOCKER_IMAGE_MISSING": "1"},
    )

    assert result.returncode != 0
    assert "cannot resolve the image id of test-runtime-image" in result.stderr
    assert _runs(calls) == []


def test_image_id_empty_is_fatal_before_any_container(tmp_path: Path) -> None:
    """An empty id is as unusable as a failed inspect, and just as silent."""
    result, calls = _run(
        tmp_path,
        "exec",
        "--",
        "true",
        extra_env={"MOCK_DOCKER_IMAGE_ID": ""},
    )

    assert result.returncode != 0
    assert "cannot resolve the image id of test-runtime-image" in result.stderr
    assert "<empty>" in result.stderr
    assert _runs(calls) == []
    assert not [call for call in calls if call.startswith("create ")]
    assert not [call for call in calls if "linux-cobra-core-v2" in call]


def test_image_id_that_is_not_a_digest_is_fatal(tmp_path: Path) -> None:
    """The historical fallback wrote the literal 'unknown' into both stores."""
    result, calls = _run(
        tmp_path,
        "exec",
        "--",
        "true",
        extra_env={"MOCK_DOCKER_IMAGE_ID": "unknown"},
    )

    assert result.returncode != 0
    assert "cannot resolve the image id of test-runtime-image" in result.stderr
    assert "unknown" in result.stderr
    assert _runs(calls) == []


def test_remote_image_id_failure_names_the_remote_engine_not_a_host(
    tmp_path: Path,
) -> None:
    """The diagnostic must place the engine without leaking a hostname."""
    share, repo = _share_layout(tmp_path)

    result, _ = _run(
        tmp_path,
        "exec",
        "--remote",
        REMOTE_HOST,
        "--",
        "true",
        repo_root=repo,
        extra_env=_remote_env(share, MOCK_DOCKER_IMAGE_ID="unknown"),
    )

    assert result.returncode != 0
    assert "the configured remote engine" in result.stderr
    assert REMOTE_HOST not in result.stderr


@pytest.mark.parametrize(
    "args",
    [
        ("exec", "--", "true"),
        ("system",),
        ("test",),
    ],
)
def test_no_emitted_command_ever_carries_an_unknown_image_id(
    tmp_path: Path,
    args: tuple[str, ...],
) -> None:
    """Neither the cache marker nor the receipt may name a placeholder image."""
    result, calls = _run(tmp_path, *args)

    assert result.returncode == 0, result.stderr
    command = _container_run(calls)
    source_key = command.split("COBRA_SOURCE_KEY=")[1].split("'")[1]
    assert source_key.endswith(f":{FAKE_IMAGE_ID}"), source_key
    assert "unknown" not in source_key
    assert "linux-cobra-core-v2:" in command
    receipt = command.split("D810_TEST_RUNTIME_IMAGE_ID=")[1].split()[0]
    assert receipt == FAKE_IMAGE_ID, receipt


@pytest.mark.parametrize("account", ["ac/count", "ac count", "ac.count]"])
def test_remote_smb_user_must_be_safe_for_acl_matching(
    tmp_path: Path,
    account: str,
) -> None:
    """The account is interpolated verbatim into the ACL sed expressions."""
    share, repo = _share_layout(tmp_path)

    result, calls = _run(
        tmp_path,
        "exec",
        "--remote",
        REMOTE_HOST,
        "--",
        "true",
        repo_root=repo,
        extra_env=_remote_env(share, D810_REMOTE_SMB_USER=account),
    )

    assert result.returncode != 0
    assert "D810_REMOTE_SMB_USER must match" in result.stderr
    assert _runs(calls) == []


def _split_top_level(command: str) -> tuple[list[str], list[str]]:
    """Split a bash command string into its top-level terms and separators.

    Quotes, ``{ }`` groups, subshells and command substitutions are opaque, so
    what comes back is exactly the chain the container shell would evaluate.
    """
    terms: list[str] = []
    separators: list[str] = []
    depth = 0
    quote: str | None = None
    current = ""
    index = 0
    while index < len(command):
        character = command[index]
        if quote == '"' and character == "\\":
            current += command[index : index + 2]
            index += 2
            continue
        if quote is not None:
            current += character
            if character == quote:
                quote = None
            index += 1
            continue
        if character in "'\"":
            quote = character
            current += character
            index += 1
            continue
        if character in "{(":
            depth += 1
        elif character in "})":
            depth -= 1
        if depth == 0:
            if command.startswith("&&", index) or command.startswith("||", index):
                terms.append(current.strip())
                separators.append(command[index : index + 2])
                current = ""
                index += 2
                continue
            if character == ";":
                terms.append(current.strip())
                separators.append(";")
                current = ""
                index += 1
                continue
        current += character
        index += 1
    if current.strip():
        terms.append(current.strip())
    return terms, separators


def _inner_command(container_run: str) -> str:
    marker = " -lc "
    assert marker in container_run, container_run
    return container_run.split(marker, 1)[1]


WORKLOAD_INVOCATIONS = (
    "run_system_test_batches.py",
    "-m pytest",
)


@pytest.mark.parametrize(
    "args",
    [
        ("system", "-o", "out.txt"),
        ("system",),
        ("test", "-o", "out.txt"),
        ("test",),
        ("dump", "-o", "out.txt"),
        ("dump",),
    ],
)
@pytest.mark.parametrize("remote", [False, True])
def test_setup_is_a_hard_precondition_for_the_workload(
    tmp_path: Path,
    args: tuple[str, ...],
    remote: bool,
) -> None:
    """A failed setup must never leave pytest to report the container status."""
    if remote:
        share, repo = _share_layout(tmp_path)
        result, calls = _run(
            tmp_path,
            *args,
            "--remote",
            REMOTE_HOST,
            repo_root=repo,
            extra_env=_remote_env(share),
        )
        command = _remote_container_run(calls)
    else:
        result, calls = _run(tmp_path, *args)
        command = _container_run(calls)

    assert result.returncode == 0, result.stderr
    terms, separators = _split_top_level(_inner_command(command))
    assert terms, command
    # a ';' here would detach the workload from setup, which is the defect:
    # the container then exits with pytest's status whatever setup did
    assert ";" not in separators, (separators, command)
    # the only '||' allowed is a stage guard, which re-raises the stage's status
    for position, separator in enumerate(separators):
        if separator == "||":
            assert terms[position + 1].startswith("{ __d810_stage_status=$?;"), (
                terms[position + 1]
            )
            assert "exit $__d810_stage_status" in terms[position + 1]
    assert any(
        invocation in terms[-1] for invocation in WORKLOAD_INVOCATIONS
    ), terms[-1]
    # the workload is the LAST term, so nothing runs after a failed stage
    for term in terms[:-1]:
        assert not any(
            invocation in term for invocation in WORKLOAD_INVOCATIONS
        ), term


@pytest.mark.parametrize(
    "args",
    [("system", "-o", "out.txt"), ("test", "-o", "out.txt"), ("dump", "-o", "out.txt")],
)
def test_a_failing_stage_stops_the_chain_and_keeps_its_own_status(
    tmp_path: Path,
    args: tuple[str, ...],
) -> None:
    """Run the emitted chain for real, failing one stage at a time."""
    share, repo = _share_layout(tmp_path)
    result, calls = _run(
        tmp_path,
        *args,
        "--remote",
        REMOTE_HOST,
        repo_root=repo,
        extra_env=_remote_env(share),
    )
    assert result.returncode == 0, result.stderr
    terms, separators = _split_top_level(_inner_command(_remote_container_run(calls)))
    # a guarded stage is one unit: "{ stage; } || { name it; exit its status; }"
    units: list[str] = []
    for position, term in enumerate(terms):
        if position and separators[position - 1] == "||":
            units[-1] = f"{units[-1]} || {term}"
        else:
            units.append(term)
    terms = units
    marker = tmp_path / "workload-ran"

    for index in range(len(terms) - 1):
        marker.unlink(missing_ok=True)
        model = []
        for position in range(len(terms)):
            if position == index:
                model.append("( exit 42 )")
            elif position == len(terms) - 1:
                model.append(f"touch {marker}")
            else:
                model.append("true")
        completed = subprocess.run(
            ["bash", "-c", " && ".join(model)],
            check=False,
            capture_output=True,
            text=True,
        )
        assert completed.returncode == 42, (index, terms[index])
        assert not marker.exists(), terms[index]


@pytest.mark.parametrize(
    "stage",
    ["source-sync", "artifact-staging", "extensions", "native-extension-build"],
)
def test_each_setup_stage_names_itself_and_exits_with_its_own_status(
    tmp_path: Path,
    stage: str,
) -> None:
    """The real emitted guard, run against a body that fails with a known code."""
    share, repo = _share_layout(tmp_path)
    result, calls = _run(
        tmp_path,
        "test",
        "--remote",
        REMOTE_HOST,
        repo_root=repo,
        extra_env=_remote_env(share),
    )
    assert result.returncode == 0, result.stderr
    command = _inner_command(_remote_container_run(calls))

    needle = f'|| {{ __d810_stage_status=$?; printf "[setup] ERROR: stage {stage} failed'
    start = command.find(needle)
    assert start != -1, command
    guard = command[start : command.index("}", command.index("exit $__d810_stage_status", start)) + 1]

    completed = subprocess.run(
        ["bash", "-c", f"( exit 42 ) {guard}; touch {tmp_path / 'after'}"],
        check=False,
        capture_output=True,
        text=True,
    )

    assert completed.returncode == 42, completed
    assert f"stage {stage} failed (exit 42); tests not started" in completed.stderr
    assert not (tmp_path / "after").exists()


def test_cobra_toolchain_provisioning_fails_closed(tmp_path: Path) -> None:
    """apt failures were swallowed and the key came back from c++ alone."""
    result, calls = _run(tmp_path, "exec", "--", "true")

    assert result.returncode == 0, result.stderr
    command = _container_run(calls)
    # apt output is kept so the real cause is visible
    assert "apt-get update > /tmp/d810-cobra-apt.log 2>&1" in command
    assert (
        "apt-get install -y --no-install-recommends cmake ninja-build "
        "build-essential >> /tmp/d810-cobra-apt.log 2>&1" in command
    )
    # each tool is re-checked AFTER provisioning, and a miss aborts
    assert "for __cobra_tool in cmake ninja c++; do" in command
    assert "tail -n 20 /tmp/d810-cobra-apt.log" in command
    assert "ERROR: CoBRA toolchain provisioning failed" in command
    assert "a skewed engine clock makes apt reject repository signatures" in command
    # the key is derived only once the three tools are known to be present
    provision = command.index("__cobra_missing")
    assert provision < command.index("COBRA_TOOLCHAIN_KEY=$(cmake --version")
    assert command.index("COBRA_TOOLCHAIN_KEY=$(cmake --version") < command.index(
        "build_cobra.py"
    )


def test_cobra_toolchain_guard_aborts_before_the_source_build(tmp_path: Path) -> None:
    """Run the emitted guard for real with the tools absent."""
    result, calls = _run(tmp_path, "exec", "--", "true")
    assert result.returncode == 0, result.stderr
    command = _container_run(calls)

    start = command.index("__cobra_missing=''")
    end = command.index("fi; }", start) + len("fi;")
    guard = command[start:end]
    log = tmp_path / "apt.log"
    log.write_text("E: Release file is not valid yet\n", encoding="utf-8")
    guard = guard.replace("/tmp/d810-cobra-apt.log", str(log))
    marker = tmp_path / "source-build-ran"
    # a PATH with the ordinary utilities but no compiler toolchain
    toolless = tmp_path / "toolless-bin"
    toolless.mkdir()
    for utility in ("tail", "touch", "cat"):
        located = shutil.which(utility)
        assert located is not None, utility
        (toolless / utility).symlink_to(located)

    completed = subprocess.run(
        [shutil.which("bash") or "/bin/bash", "-c", f"{{ {guard} }} && touch {marker}"],
        check=False,
        capture_output=True,
        text=True,
        env={"PATH": str(toolless)},
    )

    assert completed.returncode == 1, completed
    assert "CoBRA toolchain provisioning failed" in completed.stderr
    assert "Release file is not valid yet" in completed.stderr
    assert not marker.exists()


NATIVE_PROBE_IMPORT = (
    "from d810.speedups.install import inspect_native_extensions"
)
NATIVE_FALLBACK_LINE = "[speedups] native extension: NOT LOADED (python fallback)"


@pytest.mark.parametrize("no_cython", ["1", ""])
def test_a_python_fallback_run_says_so_but_still_runs(
    tmp_path: Path,
    no_cython: str,
) -> None:
    """Without an explicit request the fallback is allowed - but never silent."""
    result, calls = _run(tmp_path, "exec", "--", "true", no_cython=no_cython or "1")

    assert result.returncode == 0, result.stderr
    command = _container_run(calls)
    assert NATIVE_PROBE_IMPORT in command
    assert f"|| echo '{NATIVE_FALLBACK_LINE}'" in command
    # tolerant: no abort on a failed probe
    assert "refusing to run the tests in the Python fallback" not in command


def test_an_explicit_native_request_refuses_the_python_fallback(
    tmp_path: Path,
) -> None:
    """D810_NO_CYTHON=0 is a request; a fallback answers a different question."""
    result, calls = _run(tmp_path, "exec", "--", "true", no_cython="0")

    assert result.returncode == 0, result.stderr
    command = _container_run(calls)
    assert NATIVE_PROBE_IMPORT in command
    assert f"echo '{NATIVE_FALLBACK_LINE}' >&2" in command
    assert (
        "ERROR: D810_NO_CYTHON=0 asked for the native extension but none could "
        "be loaded; refusing to run the tests in the Python fallback" in command
    )
    # the abort precedes the workload, which is the last top-level term
    terms, _ = _split_top_level(_inner_command(command))
    assert "refusing to run the tests" not in terms[-1]


def test_the_native_probe_aborts_an_explicit_request_for_real(
    tmp_path: Path,
) -> None:
    """Run the emitted required-probe guard with a probe that reports failure."""
    result, calls = _run(tmp_path, "exec", "--", "true", no_cython="0")
    assert result.returncode == 0, result.stderr
    command = _container_run(calls)

    start = command.index("{ /app/ida/.venv/bin/python -c 'from d810.speedups")
    end = command.index("exit 1; }; }", start) + len("exit 1; }; }")
    guard = command[start:end]
    # stand in for the container interpreter with one that reports no extension
    guard = guard.replace(
        command[command.index("/app/ida/.venv/bin/python", start) : command.index(
            " -c 'from d810.speedups", start
        )],
        "false --",
    )
    marker = tmp_path / "tests-ran"

    completed = subprocess.run(
        [shutil.which("bash") or "/bin/bash", "-c", f"{guard} && touch {marker}"],
        check=False,
        capture_output=True,
        text=True,
    )

    assert completed.returncode == 1, completed
    assert NATIVE_FALLBACK_LINE in completed.stderr
    assert "refusing to run the tests in the Python fallback" in completed.stderr
    assert not marker.exists()


def test_engine_clock_within_tolerance_is_reported_and_accepted(
    tmp_path: Path,
) -> None:
    share, repo = _share_layout(tmp_path)

    result, calls = _run(
        tmp_path,
        "exec",
        "--remote",
        REMOTE_HOST,
        "--",
        "true",
        repo_root=repo,
        extra_env=_remote_env(share, MOCK_ENGINE_CLOCK_OFFSET="3"),
    )

    assert result.returncode == 0, result.stderr
    assert "engine clock offset:" in result.stdout
    assert _clock_run(calls) is not None
    # the measured offset travels with the run's provenance receipt
    assert "D810_TEST_ENGINE_CLOCK_OFFSET=" in _remote_container_run(calls)


def test_a_skewed_engine_clock_aborts_before_the_workload(tmp_path: Path) -> None:
    """apt rejects repository signatures against a skewed clock."""
    share, repo = _share_layout(tmp_path)

    result, calls = _run(
        tmp_path,
        "exec",
        "--remote",
        REMOTE_HOST,
        "--",
        "true",
        repo_root=repo,
        extra_env=_remote_env(share, MOCK_ENGINE_CLOCK_OFFSET="-755"),
    )

    assert result.returncode != 0
    assert "exceeds the 120s tolerance" in result.stderr
    assert "resync the engine VM clock" in result.stderr
    assert "hwclock -s" in result.stderr
    assert _workload_runs(calls) == []


def test_a_timing_leg_holds_the_engine_clock_to_five_seconds(tmp_path: Path) -> None:
    """Every duration a profiling leg reports is measured against that clock."""
    share, repo = _share_layout(tmp_path)

    result, calls = _run(
        tmp_path,
        "exec",
        "--remote",
        REMOTE_HOST,
        "--",
        "true",
        repo_root=repo,
        extra_env=_remote_env(
            share, MOCK_ENGINE_CLOCK_OFFSET="30", D810_NATIVE_PROFILE="1"
        ),
    )

    assert result.returncode != 0
    assert "exceeds the 5s tolerance" in result.stderr
    assert _workload_runs(calls) == []


def test_the_clock_check_can_be_downgraded_to_a_warning(tmp_path: Path) -> None:
    share, repo = _share_layout(tmp_path)

    result, calls = _run(
        tmp_path,
        "exec",
        "--remote",
        REMOTE_HOST,
        "--",
        "true",
        repo_root=repo,
        extra_env=_remote_env(
            share,
            MOCK_ENGINE_CLOCK_OFFSET="-755",
            D810_REMOTE_SKIP_CLOCK_CHECK="1",
        ),
    )

    assert result.returncode == 0, result.stderr
    assert "WARNING: engine clock offset" in result.stderr
    assert "D810_REMOTE_SKIP_CLOCK_CHECK=1" in result.stderr
    assert _remote_container_run(calls)


def test_an_unreadable_engine_clock_fails_closed(tmp_path: Path) -> None:
    share, repo = _share_layout(tmp_path)

    result, calls = _run(
        tmp_path,
        "exec",
        "--remote",
        REMOTE_HOST,
        "--",
        "true",
        repo_root=repo,
        extra_env=_remote_env(share, MOCK_ENGINE_CLOCK_FAILS="1"),
    )

    assert result.returncode != 0
    assert "cannot read the remote engine clock" in result.stderr
    assert _workload_runs(calls) == []

def test_a_profiling_leg_without_perf_is_not_a_valid_leg(tmp_path: Path) -> None:
    """perf's absence used to return py-spy's status and pass."""
    result, calls = _run(
        tmp_path,
        "exec",
        "--",
        "true",
        no_cython="0",
        extra_env={"D810_NATIVE_PROFILE": "1"},
    )

    assert result.returncode == 0, result.stderr
    command = _container_run(calls)
    assert (
        "ERROR: D810_NATIVE_PROFILE=1 but perf is not available; a profiling "
        "leg without a profiler is not a valid leg" in command
    )
    terms, separators = _split_top_level(_inner_command(command))
    assert ";" not in separators
    # the perf check must be a precondition, never a trailing observation
    assert "perf --version" not in terms[-1]


def test_the_perf_guard_aborts_for_real_when_perf_is_absent(tmp_path: Path) -> None:
    result, calls = _run(
        tmp_path,
        "exec",
        "--",
        "true",
        no_cython="0",
        extra_env={"D810_NATIVE_PROFILE": "1"},
    )
    assert result.returncode == 0, result.stderr
    command = _container_run(calls)

    start = command.index("{ perf --version ||")
    end = command.index("; }; }", start) + len("; }; }")
    guard = command[start:end]
    marker = tmp_path / "profiled"

    completed = subprocess.run(
        [shutil.which("bash") or "/bin/bash", "-c", f"{guard} && touch {marker}"],
        check=False,
        capture_output=True,
        text=True,
        env={"PATH": str(tmp_path / "empty-bin")},
    )

    assert completed.returncode == 1, completed
    assert "a profiling leg without a profiler is not a valid leg" in completed.stderr
    assert not marker.exists()


@pytest.mark.parametrize(
    "retention",
    ["0", "", "abc", "5; rm -rf /", "05", "-1", " 7", "7 "],
)
def test_run_retention_must_be_a_positive_integer(
    tmp_path: Path,
    retention: str,
) -> None:
    """It is the operand of 'head -n -N' inside the container payload."""
    share, repo = _share_layout(tmp_path)

    result, calls = _run(
        tmp_path,
        "exec",
        "--remote",
        REMOTE_HOST,
        "--",
        "true",
        repo_root=repo,
        extra_env=_remote_env(share, D810_REMOTE_RUN_RETENTION=retention),
    )

    assert result.returncode == 2, result.stderr
    assert "D810_REMOTE_RUN_RETENTION must be a positive integer" in result.stderr
    # refused before any docker contact, so nothing could act on the value
    assert _docker_calls(calls) == []


def test_a_valid_run_retention_reaches_the_payload_unchanged(
    tmp_path: Path,
) -> None:
    share, repo = _share_layout(tmp_path)

    result, calls = _run(
        tmp_path,
        "exec",
        "--remote",
        REMOTE_HOST,
        "--",
        "true",
        repo_root=repo,
        extra_env=_remote_env(share, D810_REMOTE_RUN_RETENTION="7"),
    )

    assert result.returncode == 0, result.stderr
    assert "__runs_keep=7;" in _remote_container_run(calls)


def test_run_retention_defaults_to_twenty(tmp_path: Path) -> None:
    share, repo = _share_layout(tmp_path)

    result, calls = _run(
        tmp_path,
        "exec",
        "--remote",
        REMOTE_HOST,
        "--",
        "true",
        repo_root=repo,
        extra_env=_remote_env(share),
    )

    assert result.returncode == 0, result.stderr
    assert "__runs_keep=20;" in _remote_container_run(calls)


# ---------------------------------------------------------------------------
# Baked CoBRA: the image already carries the published wheel
# ---------------------------------------------------------------------------
COBRA_PARENT_PIN = _IDENTITY.parent_commit


def _baked_labels(
    version: str = COBRA_WHEEL_VERSION,
    sha256: str = COBRA_WHEEL_AARCH64_SHA256,
    tag: str = COBRA_WHEEL_TAG_COMMIT,
    core: str = COBRA_WHEEL_CORE_COMMIT,
    parent: str = COBRA_PARENT_PIN,
) -> str:
    """The org.d810.cobra.* row the runner reads in one `image inspect`."""
    return "|".join((version, sha256, tag, core, parent))


def test_baked_cobra_image_installs_nothing_and_still_proves_the_backend(
    tmp_path: Path,
) -> None:
    """The labels are the image's claim; the known-answer solve is the proof."""
    result, calls = _run(
        tmp_path,
        "exec",
        "--",
        "true",
        extra_env={"MOCK_DOCKER_COBRA_LABELS": _baked_labels()},
    )

    assert result.returncode == 0, result.stderr
    command = _container_run(calls)
    # Nothing is installed, cloned, compiled or hashed on the way in.
    for installed in (
        "pip install --no-deps --force-reinstall",
        "sha256sum -c -",
        "git clone",
        "build_cobra.py",
        "cmake",
        "/opt/d810-cobra-wheel",
        "/opt/d810-cobra-source",
        "/opt/d810-cobra-cache",
    ):
        assert installed not in command, installed
    # ... but the full contract is still proven inside the container.
    assert '"implements"] == {"mba-solve": "cobra-solve"}' in command
    assert "import d810_cobra._cobra" in command
    assert "prove_equivalent(tree, solved.tree" in command
    assert (
        f'importlib.metadata.version("d810-cobra") == "{COBRA_WHEEL_VERSION}"' in command
    )
    assert not (tmp_path / ".tmp" / "cobra-linux").exists()


def test_baked_cobra_verification_is_a_hard_setup_precondition(
    tmp_path: Path,
) -> None:
    """A failed verification must stop the run, not hand over to pytest."""
    result, calls = _run(
        tmp_path,
        "exec",
        "--",
        "true",
        extra_env={"MOCK_DOCKER_COBRA_LABELS": _baked_labels()},
    )

    assert result.returncode == 0, result.stderr
    command = _container_run(calls)
    assert "stage extensions failed" in command
    assert "; pytest" not in command


def test_baked_cobra_is_named_in_the_preamble(tmp_path: Path) -> None:
    result, _calls = _run(
        tmp_path,
        "exec",
        "--",
        "true",
        extra_env={"MOCK_DOCKER_COBRA_LABELS": _baked_labels()},
    )

    assert result.returncode == 0, result.stderr
    assert (
        "extension: d810-cobra (baked "
        f"{COBRA_WHEEL_VERSION} {COBRA_WHEEL_AARCH64_SHA256[:12]} "
        f"tag {COBRA_WHEEL_TAG_COMMIT[:7]})"
    ) in result.stdout
    assert COBRA_WHEEL_AARCH64_SHA256 in result.stdout
    assert COBRA_WHEEL_TAG_COMMIT in result.stdout
    assert "nothing installed, verification still enforced" in result.stdout


def test_baked_cobra_identity_reaches_the_provenance_receipt(
    tmp_path: Path,
) -> None:
    """A receipt has to name the artifact its measurements were produced by."""
    result, calls = _run(
        tmp_path,
        "exec",
        "--",
        "true",
        extra_env={"MOCK_DOCKER_COBRA_LABELS": _baked_labels()},
    )

    assert result.returncode == 0, result.stderr
    command = _container_run(calls)
    assert f"D810_TEST_COBRA_WHEEL_SHA256={COBRA_WHEEL_AARCH64_SHA256}" in command
    assert f"D810_TEST_COBRA_TAG_COMMIT={COBRA_WHEEL_TAG_COMMIT}" in command
    assert "D810_TEST_COBRA_SOURCE_MODE=baked" in command


def test_source_built_cobra_records_no_published_identity(tmp_path: Path) -> None:
    """A compiled backend has no published hash; the receipt must not invent one."""
    result, calls = _run(tmp_path, "exec", "--", "true")

    assert result.returncode == 0, result.stderr
    command = _container_run(calls)
    assert "D810_TEST_COBRA_WHEEL_SHA256" not in command
    assert "D810_TEST_COBRA_TAG_COMMIT" not in command


def test_incomplete_baked_labels_are_an_error_not_a_rebuild(tmp_path: Path) -> None:
    """Half a claim is the state that would hide an install that never happened."""
    result, calls = _run(
        tmp_path,
        "exec",
        "--",
        "true",
        extra_env={
            "MOCK_DOCKER_COBRA_LABELS": _baked_labels(sha256="", core=""),
        },
    )

    assert result.returncode != 0
    assert "label set is incomplete" in result.stderr
    assert "org.d810.cobra.wheel_sha256" in result.stderr
    assert "org.d810.cobra.core_commit" in result.stderr
    assert _workload_runs(calls) == []


def test_unpublished_baked_wheel_hash_is_refused(tmp_path: Path) -> None:
    """The preflight wheels share the published filenames, not their bytes."""
    result, calls = _run(
        tmp_path,
        "exec",
        "--",
        "true",
        extra_env={
            "MOCK_DOCKER_COBRA_LABELS": _baked_labels(
                sha256=COBRA_WHEEL_PREFLIGHT_AARCH64_SHA256
            ),
        },
    )

    assert result.returncode != 0
    assert COBRA_WHEEL_PREFLIGHT_AARCH64_SHA256 in result.stderr
    assert "not a published d810-cobra wheel" in result.stderr
    assert _workload_runs(calls) == []


def test_baked_labels_must_agree_with_the_published_record(tmp_path: Path) -> None:
    """A label set can be complete and still describe the wrong release."""
    result, calls = _run(
        tmp_path,
        "exec",
        "--",
        "true",
        extra_env={"MOCK_DOCKER_COBRA_LABELS": _baked_labels(tag="0" * 40)},
    )

    assert result.returncode != 0
    assert "labels disagree with the published record" in result.stderr
    assert _workload_runs(calls) == []


def test_baked_parent_commit_must_equal_the_runner_pin(tmp_path: Path) -> None:
    """A baked run and a source run must describe the same upstream code."""
    stale_parent = "1" * 40
    result, calls = _run(
        tmp_path,
        "exec",
        "--",
        "true",
        extra_env={"MOCK_DOCKER_COBRA_LABELS": _baked_labels(parent=stale_parent)},
    )

    assert result.returncode != 0
    assert stale_parent in result.stderr
    assert COBRA_PARENT_PIN in result.stderr
    assert "this runner pins" in result.stderr
    assert _workload_runs(calls) == []


def test_explicit_wheel_outranks_a_baked_image(tmp_path: Path) -> None:
    """An operator naming a wheel means it, whatever the image carries."""
    under_test = _wheel_under_test()

    result, calls = _run(
        tmp_path,
        "exec",
        "--",
        "true",
        extra_env={**under_test.env, "MOCK_DOCKER_COBRA_LABELS": _baked_labels()},
    )

    assert result.returncode == 0, result.stderr
    assert f"extension: d810-cobra (wheel {under_test.name})" in result.stdout
    assert "baked" not in result.stdout
    command = _container_run(calls)
    assert "sha256sum -c -" in command


def test_explicit_cobra_root_outranks_a_baked_image(tmp_path: Path) -> None:
    """The mounted-pinned development path must not be silently discarded."""
    result, _calls = _run(
        tmp_path,
        "exec",
        "--",
        "true",
        extra_env={
            "D810_COBRA_ROOT": str(tmp_path / "absent-cobra-checkout"),
            "MOCK_DOCKER_COBRA_LABELS": _baked_labels(),
        },
    )

    # It fails on the checkout, which proves the baked image never took over.
    assert result.returncode != 0
    assert "D810_COBRA_ROOT must be an absolute existing directory" in result.stderr


def test_remote_mode_reads_the_baked_labels_from_the_remote_engine(
    tmp_path: Path,
) -> None:
    """--remote runs on another machine, whose copy of the tag may differ."""
    share, repo = _share_layout(tmp_path)

    result, calls = _run(
        tmp_path,
        "exec",
        "--remote",
        REMOTE_HOST,
        "--",
        "true",
        repo_root=repo,
        extra_env=_remote_env(
            share,
            MOCK_DOCKER_COBRA_LABELS="||||",
            MOCK_DOCKER_REMOTE_COBRA_LABELS=_baked_labels(
                sha256=COBRA_WHEEL_X86_64_SHA256
            ),
            # The x86_64 wheel is the correct one for that engine.
            MOCK_DOCKER_REMOTE_SERVER_ARCH="amd64",
        ),
    )

    assert result.returncode == 0, result.stderr
    assert (
        f"extension: d810-cobra (baked {COBRA_WHEEL_VERSION} "
        f"{COBRA_WHEEL_X86_64_SHA256[:12]}"
    ) in result.stdout
    command = _remote_container_run(calls)
    assert "git clone" not in command
    # Every label inspect has to be addressed to the engine that will run it.
    hosts = _docker_hosts(calls)
    inspects = [
        index
        for index, call in enumerate(_docker_calls(calls))
        if "org.d810.cobra.version" in call
    ]
    assert inspects, calls
    assert all(hosts[index] == f"ssh://{REMOTE_HOST}" for index in inspects), calls


def test_remote_mode_ignores_a_baked_label_set_that_only_exists_locally(
    tmp_path: Path,
) -> None:
    """The Mac's image of the same tag says nothing about the remote engine's."""
    share, repo = _share_layout(tmp_path)

    result, calls = _run(
        tmp_path,
        "exec",
        "--remote",
        REMOTE_HOST,
        "--",
        "true",
        repo_root=repo,
        extra_env=_remote_env(
            share,
            MOCK_DOCKER_COBRA_LABELS=_baked_labels(),
            MOCK_DOCKER_REMOTE_COBRA_LABELS="||||",
        ),
    )

    assert result.returncode == 0, result.stderr
    assert "baked" not in result.stdout
    assert "git clone" in _remote_container_run(calls)


# ---------------------------------------------------------------------------
# The harness fixture wheel
# ---------------------------------------------------------------------------
def test_the_fixture_wheels_are_the_recorded_bytes() -> None:
    """A fixture whose hash drifts silently stops testing the hash gate."""
    for arch, (name, sha256) in COBRA_FIXTURE_WHEELS.items():
        path = COBRA_FIXTURE_DIR / name
        assert path.is_file(), path
        assert hashlib.sha256(path.read_bytes()).hexdigest() == sha256, arch


def test_the_fixture_wheels_are_valid_wheels_that_say_they_are_fixtures() -> None:
    """pip reads the basename and the dist-info; a reader must see the notice."""
    for name, _sha256 in COBRA_FIXTURE_WHEELS.values():
        with zipfile.ZipFile(COBRA_FIXTURE_DIR / name) as archive:
            assert archive.testzip() is None
            members = set(archive.namelist())
            assert "d810_cobra-0.1.5.dist-info/METADATA" in members
            assert "d810_cobra-0.1.5.dist-info/HARNESS-FIXTURE.txt" in members
            notice = archive.read(
                "d810_cobra-0.1.5.dist-info/HARNESS-FIXTURE.txt"
            ).decode()
        assert "not a d810-cobra release artifact" in notice
        assert "harness_fixture" in name


def test_the_fixture_wheel_is_refused_without_the_harness_variable(
    tmp_path: Path,
) -> None:
    """The fixture is not an identity the runner carries; it has to be named."""
    name, sha256 = COBRA_FIXTURE_WHEELS["aarch64"]

    result, calls = _run(
        tmp_path,
        "exec",
        "--",
        "true",
        extra_env={
            "D810_COBRA_WHEEL": str(COBRA_FIXTURE_DIR / name),
            "D810_COBRA_WHEEL_SHA256": sha256,
        },
    )

    assert result.returncode != 0
    assert calls == []
    assert "not a recorded d810-cobra wheel" in result.stderr


def test_the_harness_variable_admits_only_the_hash_it_names(tmp_path: Path) -> None:
    """It is one extra identity, not an escape hatch for any wheel."""
    name, sha256 = COBRA_FIXTURE_WHEELS["aarch64"]
    other = COBRA_FIXTURE_WHEELS["x86_64"][1]

    result, calls = _run(
        tmp_path,
        "exec",
        "--",
        "true",
        extra_env={
            "D810_COBRA_WHEEL": str(COBRA_FIXTURE_DIR / name),
            "D810_COBRA_WHEEL_SHA256": sha256,
            "D810_COBRA_HARNESS_WHEEL_SHA256": other,
        },
    )

    assert result.returncode != 0
    assert calls == []
    assert "not a recorded d810-cobra wheel" in result.stderr


def test_a_harness_fixture_run_never_reads_as_a_published_one(
    tmp_path: Path,
) -> None:
    """The word in the preamble is the whole point of the fixture identity."""
    name, sha256 = COBRA_FIXTURE_WHEELS["aarch64"]

    result, calls = _run(
        tmp_path,
        "exec",
        "--",
        "true",
        extra_env={
            "D810_COBRA_WHEEL": str(COBRA_FIXTURE_DIR / name),
            "D810_COBRA_WHEEL_SHA256": sha256,
            "D810_COBRA_HARNESS_WHEEL_SHA256": sha256,
        },
    )

    assert result.returncode == 0, result.stderr
    assert "TEST HARNESS fixture" in result.stderr
    assert f"(read-only) harness-fixture sha256 {sha256}" in result.stdout
    assert "published sha256" not in result.stdout
    # It borrows no release identity.
    assert COBRA_WHEEL_TAG_COMMIT not in result.stdout
    assert "harness-fixture" in result.stdout
    command = _container_run(calls)
    # The wheel still goes through every container-side gate.
    assert sha256 in command
    assert "sha256sum -c -" in command
    assert "git clone" not in command
    # A wrapper-only variable must not reach the workload.
    assert "D810_COBRA_HARNESS_WHEEL_SHA256" not in command


def test_the_wheel_under_test_falls_back_to_the_fixture(tmp_path: Path) -> None:
    """On a checkout without the out-of-git wheels, wheel mode still runs."""
    os.environ["D810_TEST_HIDE_COBRA_WHEELS"] = "1"
    try:
        under_test = _wheel_under_test()
    finally:
        del os.environ["D810_TEST_HIDE_COBRA_WHEELS"]

    assert under_test.identity == "harness-fixture"
    assert under_test.path.is_file()

    result, calls = _run(tmp_path, "exec", "--", "true", extra_env=under_test.env)

    assert result.returncode == 0, result.stderr
    assert f"extension: d810-cobra (wheel {under_test.name})" in result.stdout
    assert under_test.sha256 in _container_run(calls)


def test_a_baked_wheel_for_the_wrong_engine_is_refused_before_any_container(
    tmp_path: Path,
) -> None:
    """The in-container assertion is a backstop, not the gate.

    Reaching it would mean a setup container was started for a wheel that
    could never have imported; the wheel path already refuses at the cheap
    `docker version` stage, and a baked image's recorded hash names its
    architecture just as precisely.
    """
    result, calls = _run(
        tmp_path,
        "exec",
        "--",
        "true",
        extra_env={
            "MOCK_DOCKER_COBRA_LABELS": _baked_labels(),
            "MOCK_DOCKER_SERVER_ARCH": "amd64",
        },
    )

    assert result.returncode != 0
    assert "aarch64 wheel but the Docker engine is x86_64" in result.stderr
    assert "baked into" in result.stderr
    assert _workload_runs(calls) == []


def test_an_unknown_engine_architecture_refuses_a_baked_image(
    tmp_path: Path,
) -> None:
    result, calls = _run(
        tmp_path,
        "exec",
        "--",
        "true",
        extra_env={
            "MOCK_DOCKER_COBRA_LABELS": _baked_labels(),
            "MOCK_DOCKER_SERVER_ARCH": "riscv64",
        },
    )

    assert result.returncode != 0
    assert "known Docker engine architecture" in result.stderr
    assert _workload_runs(calls) == []


def test_remote_mode_refuses_a_baked_image_built_for_the_local_engine(
    tmp_path: Path,
) -> None:
    """The Mac's architecture says nothing about the engine that will run it."""
    share, repo = _share_layout(tmp_path)

    result, calls = _run(
        tmp_path,
        "exec",
        "--remote",
        REMOTE_HOST,
        "--",
        "true",
        repo_root=repo,
        extra_env=_remote_env(
            share,
            MOCK_DOCKER_COBRA_LABELS="||||",
            # An aarch64 wheel baked into the image the amd64 remote will run.
            MOCK_DOCKER_REMOTE_COBRA_LABELS=_baked_labels(),
            MOCK_DOCKER_SERVER_ARCH="arm64",
            MOCK_DOCKER_REMOTE_SERVER_ARCH="amd64",
        ),
    )

    assert result.returncode != 0
    assert "aarch64 wheel but the Docker engine is x86_64" in result.stderr
    assert _workload_runs(calls) == []
    # Failing closed before the lock leaves nothing to clean up.
    assert not (repo / ".tmp" / "remote-run.lock").exists()


def test_remote_mode_accepts_a_baked_image_matching_the_remote_engine(
    tmp_path: Path,
) -> None:
    """The x86_64 wheel is the right one there, and the local arch is irrelevant."""
    share, repo = _share_layout(tmp_path)

    result, calls = _run(
        tmp_path,
        "exec",
        "--remote",
        REMOTE_HOST,
        "--",
        "true",
        repo_root=repo,
        extra_env=_remote_env(
            share,
            MOCK_DOCKER_COBRA_LABELS="||||",
            MOCK_DOCKER_REMOTE_COBRA_LABELS=_baked_labels(
                sha256=COBRA_WHEEL_X86_64_SHA256
            ),
            MOCK_DOCKER_SERVER_ARCH="arm64",
            MOCK_DOCKER_REMOTE_SERVER_ARCH="amd64",
        ),
    )

    assert result.returncode == 0, result.stderr
    assert "wheel but the Docker engine is" not in result.stderr
    assert "git clone" not in _remote_container_run(calls)


# ---------------------------------------------------------------------------
# Cost-aware packing and N-way container sharding (system mode)
# ---------------------------------------------------------------------------


def _batcher_runs(calls: list[str]) -> list[str]:
    return [call for call in _runs(calls) if "run_system_test_batches.py" in call]


def test_system_mode_default_asks_for_neither_a_plan_nor_shards(
    tmp_path: Path,
) -> None:
    result, calls = _run(tmp_path, "system", "--", "-q")

    assert result.returncode == 0, result.stderr
    command = _container_run(calls)
    assert "--plan" not in command
    assert "--cost-ledger" not in command
    assert "--shard-count" not in command
    assert "--shard-index" not in command
    assert "--log-dir /root/.idapro/logs/d810_logs " in command


def test_lane_plan_reaches_the_batcher_with_a_default_cost_ledger(
    tmp_path: Path,
) -> None:
    result, calls = _run(tmp_path, "system", "--plan", "lane", "--", "-q")

    assert result.returncode == 0, result.stderr
    command = _container_run(calls)
    assert "--plan lane" in command
    assert "/root/.idapro/logs/d810_logs/system_batches.jsonl" in command
    assert command.index("--plan lane") < command.index(" -- ")


def test_lane_threshold_reaches_the_batcher(tmp_path: Path) -> None:
    result, calls = _run(
        tmp_path, "system", "--plan", "lane", "--lane-threshold-seconds", "45", "--", "-q"
    )

    assert result.returncode == 0, result.stderr
    assert "--lane-threshold-seconds 45" in _container_run(calls)


def test_plan_rejects_an_unknown_mode(tmp_path: Path) -> None:
    result, calls = _run(tmp_path, "system", "--plan", "magic", "--", "-q")

    assert result.returncode == 2, result.stdout
    assert "--plan" in result.stderr
    assert calls == []


def test_cost_ledger_is_repeatable_and_overrides_the_default(tmp_path: Path) -> None:
    result, calls = _run(
        tmp_path,
        "system",
        "--plan",
        "cost",
        "--cost-ledger",
        "/work/.tmp/a.jsonl",
        "--cost-ledger",
        "/work/.tmp/b.jsonl",
        "--",
        "-q",
    )

    assert result.returncode == 0, result.stderr
    command = _container_run(calls)
    assert "--cost-ledger /work/.tmp/a.jsonl" in command
    assert "--cost-ledger /work/.tmp/b.jsonl" in command


def test_cost_ledger_rejects_a_relative_path(tmp_path: Path) -> None:
    result, calls = _run(tmp_path, "system", "--cost-ledger", "a.jsonl", "--", "-q")

    assert result.returncode == 2, result.stdout
    assert "--cost-ledger" in result.stderr
    assert calls == []


def test_shards_one_matches_unsharded_command_except_owned_tempdir(tmp_path: Path) -> None:
    plain, plain_calls = _run(tmp_path, "system", "--", "-q")
    assert plain.returncode == 0, plain.stderr
    # The harness appends to one docker log per tmp_path, so compare the last
    # container each invocation started.
    result, calls = _run(tmp_path, "system", "--shards", "1", "--", "-q")
    assert result.returncode == 0, result.stderr

    def arguments_without_temp_mount(log: list[str]) -> tuple[list[str], Path]:
        last_run = max(i for i, line in enumerate(log) if line.startswith("run "))
        arguments: list[str] = []
        for line in log[last_run + 1 :]:
            if line.startswith("run-arg "):
                arguments.append(line.removeprefix("run-arg "))
            elif arguments:
                # Preserve newlines in the shell script argument.
                arguments[-1] += "\n" + line

        mounts = [i for i, arg in enumerate(arguments) if arg.endswith(":/d810-test-tmp")]
        assert len(mounts) == 1
        index = mounts[0]
        assert index > 0 and arguments[index - 1] == "-v"
        source, destination = arguments[index].rsplit(":", 1)
        assert destination == "/d810-test-tmp"
        host_tmp = Path(source)
        assert host_tmp.is_absolute()
        assert host_tmp.parent.resolve() == Path("/tmp").resolve()
        assert host_tmp.name.startswith("d810-test-tmp.")
        assert tmp_path.resolve() not in host_tmp.resolve().parents
        assert not host_tmp.exists(), "runner-owned temporary files must be cleaned on exit"
        del arguments[index - 1 : index + 1]
        return arguments, host_tmp

    plain_arguments, plain_tempdir = arguments_without_temp_mount(plain_calls)
    shard_arguments, shard_tempdir = arguments_without_temp_mount(calls)
    assert plain_tempdir != shard_tempdir
    assert plain_arguments == shard_arguments


def test_shards_prewarms_once_then_runs_one_container_per_shard(
    tmp_path: Path,
) -> None:
    result, calls = _run(
        tmp_path, "system", "--plan", "lane", "--shards", "3", "--", "-q"
    )

    assert result.returncode == 0, result.stderr
    batchers = _batcher_runs(calls)
    assert len(batchers) == 3
    # The prewarm container is a separate run that does the dependency setup
    # and no tests, so the concurrent shards never race on the editable
    # install, the CoBRA cache or (in remote mode) the /work mirror.
    prewarm = [
        call
        for call in _runs(calls)
        if "shards-prewarm" in call and "run_system_test_batches.py" not in call
    ]
    assert len(prewarm) == 1
    for shard_index in range(3):
        assert any(
            f"--shard-index {shard_index} --shard-count 3" in call for call in batchers
        )
        assert any(
            f"--log-dir /root/.idapro/logs/d810_logs/shard-{shard_index}" in call
            for call in batchers
        )


def test_shards_give_every_container_its_own_capture_file(tmp_path: Path) -> None:
    result, calls = _run(
        tmp_path, "system", "--shards", "2", "-o", "sharded.txt", "--", "-q"
    )

    assert result.returncode == 0, result.stderr
    batchers = _batcher_runs(calls)
    assert len(batchers) == 2
    assert any("/work/.tmp/shard0-sharded.txt" in call for call in batchers)
    assert any("/work/.tmp/shard1-sharded.txt" in call for call in batchers)


def test_shards_give_every_container_its_own_run_id(tmp_path: Path) -> None:
    result, calls = _run(tmp_path, "system", "--shards", "2", "--", "-q")

    assert result.returncode == 0, result.stderr
    run_ids = set()
    for call in _batcher_runs(calls):
        match = re.search(r"D810_RUN_ID=(\S+)", call)
        assert match is not None, call
        run_ids.add(match.group(1))
    assert len(run_ids) == 2


@pytest.mark.parametrize("bad_value", ["0", "", "abc", "2;x", "-1"])
def test_shards_rejects_non_positive_integers(tmp_path: Path, bad_value: str) -> None:
    result, calls = _run(tmp_path, "system", "--shards", bad_value, "--", "-q")

    assert result.returncode == 2, result.stdout
    assert "--shards" in result.stderr
    assert calls == []


def test_shards_refused_outside_system_mode(tmp_path: Path) -> None:
    result, calls = _run(tmp_path, "test", "--shards", "2", "--", "-q")

    assert result.returncode == 2, result.stdout
    assert "--shards" in result.stderr
    assert calls == []


def test_start_batch_with_shards_requires_naming_the_shard(tmp_path: Path) -> None:
    result, calls = _run(
        tmp_path, "system", "--shards", "3", "--start-batch", "5", "--", "-q"
    )

    assert result.returncode == 2, result.stdout
    assert "--only-shard" in result.stderr
    assert calls == []


def test_only_shard_resumes_exactly_one_shard_of_the_plan(tmp_path: Path) -> None:
    result, calls = _run(
        tmp_path,
        "system",
        "--shards",
        "3",
        "--only-shard",
        "1",
        "--start-batch",
        "5",
        "--",
        "-q",
    )

    assert result.returncode == 0, result.stderr
    batchers = _batcher_runs(calls)
    assert len(batchers) == 1
    assert "--shard-index 1 --shard-count 3" in batchers[0]
    assert "--start-batch 5" in batchers[0]


def test_only_shard_must_be_inside_the_shard_count(tmp_path: Path) -> None:
    result, calls = _run(
        tmp_path, "system", "--shards", "2", "--only-shard", "2", "--", "-q"
    )

    assert result.returncode == 2, result.stdout
    assert "--only-shard" in result.stderr
    assert calls == []


def test_only_shard_requires_shards(tmp_path: Path) -> None:
    result, calls = _run(tmp_path, "system", "--only-shard", "0", "--", "-q")

    assert result.returncode == 2, result.stdout
    assert "--only-shard" in result.stderr
    assert calls == []


def test_fast_lanes_reaches_the_batcher(tmp_path: Path) -> None:
    result, calls = _run(
        tmp_path, "system", "--plan", "lane", "--fast-lanes", "2", "--", "-q"
    )

    assert result.returncode == 0, result.stderr
    assert "--fast-lanes 2" in _container_run(calls)


def test_fast_lane_budget_reaches_the_batcher(tmp_path: Path) -> None:
    result, calls = _run(
        tmp_path,
        "system",
        "--plan",
        "lane",
        "--fast-lane-budget-seconds",
        "540",
        "--",
        "-q",
    )

    assert result.returncode == 0, result.stderr
    assert "--fast-lane-budget-seconds 540" in _container_run(calls)


@pytest.mark.parametrize("bad_value", ["0", "", "abc", "2;x"])
def test_fast_lanes_rejects_non_positive_integers(
    tmp_path: Path, bad_value: str
) -> None:
    result, calls = _run(tmp_path, "system", "--fast-lanes", bad_value, "--", "-q")

    assert result.returncode == 2, result.stdout
    assert "--fast-lanes" in result.stderr
    assert calls == []


def test_fast_lanes_refused_outside_system_mode(tmp_path: Path) -> None:
    result, calls = _run(tmp_path, "test", "--fast-lanes", "2", "--", "-q")

    assert result.returncode == 2, result.stdout
    assert "--fast-lanes" in result.stderr
    assert calls == []


@pytest.mark.parametrize("mode", ["system", "test", "exec"])
@pytest.mark.parametrize("docker_status", [0, 7])
def test_local_runner_mounts_external_temporary_storage(
    tmp_path: Path, mode: str, docker_status: int
) -> None:
    result, calls = _run(
        tmp_path, mode, "--", "true" if mode == "exec" else "-q",
        extra_env={"MOCK_DOCKER_RUN_EXIT": str(docker_status)},
    )
    assert result.returncode == docker_status, result.stderr
    command = _container_run(calls)
    assert "TMPDIR=/d810-test-tmp" in command
    mount = next(line.removeprefix("run-arg ") for line in calls
                 if line.startswith("run-arg ") and line.endswith(":/d810-test-tmp"))
    host_tmp = Path(mount.rsplit(":", 1)[0])
    assert tmp_path.resolve() not in host_tmp.resolve().parents
    assert not host_tmp.exists(), "runner-owned temporary files must be cleaned on exit"
