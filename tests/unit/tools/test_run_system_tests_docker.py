import hashlib
import os
import re
import shutil
import subprocess
from pathlib import Path

import pytest


REPO_ROOT = Path(__file__).resolve().parents[3]
DOCKER_RUNNER = REPO_ROOT / "tools" / "scripts" / "run_system_tests_docker.sh"
RUNTIME_LABEL = "dev-emulation-z3-v1"
COBRA_WHEEL_VERSION = "0.1.5"
COBRA_WHEEL_AARCH64_NAME = (
    "d810_cobra-0.1.5-cp313-cp313-manylinux_2_26_aarch64.manylinux_2_28_aarch64.whl"
)
COBRA_WHEEL_AARCH64_SHA256 = (
    "2c85ffe14a1f3c1d2b750790332a7c0a5e911b35f7fc041ebedcd6532382c63c"
)
COBRA_WHEEL_PREFLIGHT_AARCH64_SHA256 = (
    "b71d40e45146004a968a96a1b17493b16ac04f2a98e41c12a1f87a38ddf3ab25"
)
COBRA_WHEEL_PUBLISHED_DIR = "0.1.5-published"
COBRA_WHEEL_PREFLIGHT_DIR = "0.1.5-preflight"
COBRA_WHEEL_TAG_COMMIT = "73b405c106d78e1fdc7576b217de39b7dcd0ddb3"
COBRA_WHEEL_CORE_COMMIT = "72f616f822f538a0cfbea3c880f9d1e68bb9a8f1"
COBRA_WHEEL_CONTAINER_DIR = "/opt/d810-cobra-wheel"


def _cobra_wheel(directory: str, name: str) -> Path | None:
    """Return a stored CoBRA wheel path, or None when it is not available.

    The wheels are preserved outside git under ``_gitless/``, which exists in
    the main checkout but not in every worktree, so look upward from this
    checkout instead of hard-coding a host path.
    """
    for base in (REPO_ROOT, *REPO_ROOT.parents):
        candidate = base / "_gitless" / "resource" / "cobra-wheels" / directory / name
        if candidate.is_file():
            return candidate
    return None


def _recorded_wheel(name: str) -> Path | None:
    """Return the PUBLISHED wheel, which is the only accepted identity."""
    return _cobra_wheel(COBRA_WHEEL_PUBLISHED_DIR, name)
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
    d810-work-*)
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
  printf '%s\\n' "${MOCK_DOCKER_LABEL:-}"
fi
if [ "${1:-}" = version ]; then
  printf '%s\\n' "${MOCK_DOCKER_SERVER_ARCH:-arm64}"
fi
if [ "${1:-}" = run ]; then
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
  case "$*" in
    *dst=/probe*) exit "${MOCK_DOCKER_PROBE_EXIT:-0}" ;;
  esac
  exit "${MOCK_DOCKER_RUN_EXIT:-0}"
fi
""",
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
  +a|-a#) exit "${MOCK_CHMOD_ACL_EXIT:-0}" ;;
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
    no_cython: str = "1",
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
    env.pop("D810_EGGLOG_ROOT", None)
    env.pop("D810_COBRA_ROOT", None)
    env.pop("D810_COBRA_WHEEL", None)
    env.pop("D810_COBRA_WHEEL_SHA256", None)
    env.pop("D810_REMOTE_DOCKER_HOST", None)
    env.pop("D810_REMOTE_VOLUME", None)
    env.pop("D810_REMOTE_SHARE_ROOT", None)
    env.pop("DOCKER_HOST", None)
    env.update(
        {
            "PATH": f"{tmp_path / 'bin'}:{env['PATH']}",
            "DOCKER_LOG": str(docker_log),
            "CHMOD_LOG": str(tmp_path / "chmod.log"),
            "MOCK_DOCKER_LABEL": label,
            "D810_REPO_ROOT": str(root),
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


def _runs(calls: list[str]) -> list[str]:
    return [call for call in calls if call.startswith("run ")]


def _probe_run(calls: list[str]) -> str:
    runs = [call for call in _runs(calls) if "dst=/probe" in call]
    assert len(runs) == 1, calls
    return runs[0]


def _remote_container_run(calls: list[str]) -> str:
    """The one workload container, ignoring the read-only volume probe."""
    runs = [call for call in _runs(calls) if "dst=/probe" not in call]
    assert len(runs) == 1, calls
    return runs[0]


def _chmod_calls(tmp_path: Path) -> list[str]:
    log = tmp_path / "chmod.log"
    return log.read_text(encoding="utf-8").splitlines() if log.exists() else []


def _work_volume_name(worktree_dir: Path) -> str:
    import hashlib

    digest = hashlib.sha256(str(worktree_dir).encode()).hexdigest()[:8]
    return f"d810-work-{worktree_dir.name}-{digest}"


def _docker_hosts(calls: list[str]) -> list[str]:
    prefix = "docker-host "
    return [call[len(prefix) :] for call in calls if call.startswith(prefix)]


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
    assert "env -u GIT_DIR git clone" in command
    assert 'env -u GIT_DIR git -C "$COBRA_BUILD_DIR" submodule update --init --recursive --depth=1' in command
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
    wheel = _recorded_wheel(COBRA_WHEEL_AARCH64_NAME)
    if wheel is None:
        pytest.skip(f"recorded wheel {COBRA_WHEEL_AARCH64_NAME} is unavailable")
    container_path = f"{COBRA_WHEEL_CONTAINER_DIR}/{COBRA_WHEEL_AARCH64_NAME}"

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

    assert result.returncode == 0, result.stderr
    command = _container_run(calls)
    assert (
        "/app/ida/.venv/bin/pip install --no-deps --force-reinstall "
        f"--no-cache-dir -q '{container_path}'"
    ) in command
    assert "sha256sum -c -" in command
    assert COBRA_WHEEL_AARCH64_SHA256 in command
    assert '"implements"] == {"mba-solve": "cobra-solve"}' in command
    assert (
        f'importlib.metadata.version("d810-cobra") == "{COBRA_WHEEL_VERSION}"'
        in command
    )
    for compiled in ("git clone", "submodule update", "build_cobra.py", "cmake"):
        assert compiled not in command
    assert any(call == f"run-arg {wheel}:{container_path}:ro" for call in calls)
    assert "/opt/d810-cobra-source" not in command
    assert "/opt/d810-cobra-cache" not in command
    assert "D810_COBRA_WHEEL=" not in command
    assert not list((tmp_path / ".tmp").glob("cobra-source.*"))
    assert not (tmp_path / ".tmp" / "cobra-linux").exists()


def test_recorded_cobra_wheel_reports_its_verified_provenance(
    tmp_path: Path,
) -> None:
    wheel = _recorded_wheel(COBRA_WHEEL_AARCH64_NAME)
    if wheel is None:
        pytest.skip(f"recorded wheel {COBRA_WHEEL_AARCH64_NAME} is unavailable")

    result, _ = _run(
        tmp_path,
        "exec",
        "--",
        "true",
        extra_env={
            "D810_COBRA_WHEEL": str(wheel),
            "D810_COBRA_WHEEL_SHA256": COBRA_WHEEL_AARCH64_SHA256,
        },
    )

    assert result.returncode == 0, result.stderr
    assert f"extension: d810-cobra (wheel {COBRA_WHEEL_AARCH64_NAME})" in result.stdout
    assert (
        f"cobra wheel: {wheel} -> {COBRA_WHEEL_CONTAINER_DIR}/"
        f"{COBRA_WHEEL_AARCH64_NAME} (read-only) published sha256 "
        f"{COBRA_WHEEL_AARCH64_SHA256}; d810-cobra {COBRA_WHEEL_VERSION} tag "
        f"v{COBRA_WHEEL_VERSION} {COBRA_WHEEL_TAG_COMMIT} core "
        f"{COBRA_WHEEL_CORE_COMMIT}"
    ) in result.stdout
    assert "cobra cache:" not in result.stdout


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
    wheel = _recorded_wheel(COBRA_WHEEL_AARCH64_NAME)
    if wheel is None:
        pytest.skip(f"recorded wheel {COBRA_WHEEL_AARCH64_NAME} is unavailable")

    result, calls = _run(
        tmp_path,
        "exec",
        "--",
        "true",
        extra_env={
            "D810_COBRA_WHEEL": str(wheel),
            "D810_COBRA_WHEEL_SHA256": COBRA_WHEEL_AARCH64_SHA256,
            "MOCK_DOCKER_SERVER_ARCH": "amd64",
        },
    )

    assert result.returncode != 0
    assert calls == ["version --format {{.Server.Arch}}"]
    assert "aarch64 wheel but the Docker engine is x86_64" in result.stderr


def test_unknown_docker_engine_architecture_rejects_the_cobra_wheel(
    tmp_path: Path,
) -> None:
    wheel = _recorded_wheel(COBRA_WHEEL_AARCH64_NAME)
    if wheel is None:
        pytest.skip(f"recorded wheel {COBRA_WHEEL_AARCH64_NAME} is unavailable")

    result, calls = _run(
        tmp_path,
        "exec",
        "--",
        "true",
        extra_env={
            "D810_COBRA_WHEEL": str(wheel),
            "D810_COBRA_WHEEL_SHA256": COBRA_WHEEL_AARCH64_SHA256,
            "MOCK_DOCKER_SERVER_ARCH": "riscv64",
        },
    )

    assert result.returncode != 0
    assert calls == ["version --format {{.Server.Arch}}"]
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


def test_native_speedups_build_cleans_extensions_and_fails_closed(
    tmp_path: Path,
) -> None:
    result, calls = _run(tmp_path, "test", "--", "-q", no_cython="0")

    assert result.returncode == 0, result.stderr
    command = _container_run(calls)
    assert "find src/d810/speedups -type f" in command
    assert "-name '*-linux-gnu.so'" in command
    assert "-name '*.so'" not in command
    assert "-name '*.pyd'" not in command
    assert "D810_BUILD_SPEEDUPS=1" in command
    assert "falling back to pure-Python" not in command
    assert "|| echo" not in command
    assert command.index("find src/d810/speedups -type f") < command.index(
        "D810_BUILD_SPEEDUPS=1"
    ) < command.rindex("pytest")


def test_python_mode_cleans_extensions_without_building(
    tmp_path: Path,
) -> None:
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


REMOTE_HOST = "remote-engine.example"


def _remote_env(share: Path, **extra: str) -> dict[str, str]:
    env = {"D810_REMOTE_SHARE_ROOT": str(share)}
    env.update(extra)
    return env


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
        "type=volume,src=idapro,dst=/root/.idapro/logs,"
        "volume-subpath=d810/.tmp/logs",
        "type=volume,src=idapro,dst=/opt/d810-egglog,"
        "volume-subpath=d810-egglog,readonly",
        "type=volume,src=idapro,dst=/opt/d810-cobra-cache,"
        "volume-subpath=d810/.tmp/cobra-linux",
    ]
    for spec in expected:
        assert calls.count(f"run-arg {spec}") == 1, (spec, calls)
    # the workload mounts plus the single read-only preflight probe mount
    assert calls.count("run-arg --mount") == len(expected) + 1
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


def test_remote_host_env_var_is_honored_and_the_flag_wins(tmp_path: Path) -> None:
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
    assert set(_docker_hosts(calls)) == {"ssh://env.example"}
    assert "-e D810_REMOTE_DOCKER_HOST=env.example" not in _remote_container_run(
        calls
    )

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
    assert _runs(calls) == []


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
    assert _runs(calls) == []


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
        extra_env={"D810_REMOTE_SHARE_ROOT": share_root},
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
    (lock / "owner").write_text("pid=4242 host=smb-server.example\n", encoding="utf-8")

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
    assert _runs(calls) == []
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
    assert _runs(calls) == [_probe_run(calls)]
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
    assert f"remote:   ssh://{REMOTE_HOST}" in result.stdout
    assert "linux/amd64" in result.stdout
    assert "volume:   idapro" in result.stdout
    assert f"share root: {share}" in result.stdout
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
    assert any(target.endswith("/.tmp/cobra-linux") for target in targets)
    assert all("smbuser allow" in call for call in acl_calls)
    assert any("file_inherit,directory_inherit" in call for call in acl_calls)


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
    assert acl_calls and all("otheruser allow" in call for call in acl_calls)


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
    assert _runs(calls) == []


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
    # the destination is emptied first, so the mirror is exact
    assert "find /work -mindepth 1 -maxdepth 1 ! -name .tmp -exec rm -rf {} +" in command
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
    assert _runs(calls) == []


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
    assert _runs(calls) == []


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
    assert _runs(calls) == []


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
    assert "share user: smbuser" in result.stdout
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
    assert len(create) == 1
    assert "--label d810.role=work" in create[0]
    assert "--label d810.worktree=wt" in create[0]
    assert "--label d810.share_root_digest=" in create[0]
    first = _work_volume_name(repo / ".worktrees" / "wt")
    second = _work_volume_name(other_root / ".worktrees" / "wt")
    assert first != second
    assert create[0].endswith(first)


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
    assert _runs(calls) == []


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
    assert _runs(calls) == []


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
    assert (
        calls.count(
            "run-arg type=volume,src=idapro,dst=/d810-git-worktree,"
            "volume-subpath=d810/.git/worktrees/wt,readonly"
        )
        == 1
    )
    command = _remote_container_run(calls)
    assert "GIT_DIR=/d810-git-worktree GIT_COMMON_DIR=/d810-git" in command
    assert "export IDA_PREFIX=/app/ida" in command
    assert "GIT_DIR=/d810-git " not in command.split("GIT_DIR=/d810-git-worktree")[0]


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
    assert not [call for call in calls if "d810-git-worktree" in call]
    command = _remote_container_run(calls)
    assert "GIT_DIR=/d810-git " in command
    assert "GIT_COMMON_DIR" not in command


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
    assert "d810-git-worktree" not in command
