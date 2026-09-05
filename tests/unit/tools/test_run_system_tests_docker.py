import hashlib
import os
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
COBRA_WHEEL_PREFLIGHT_DIR = "0.1.5"
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
    mock_git: str | None = None,
) -> tuple[subprocess.CompletedProcess[str], list[str]]:
    script, docker_log = _make_harness(tmp_path)
    if mock_git is not None:
        git = tmp_path / "bin" / "git"
        git.write_text(mock_git, encoding="utf-8")
        git.chmod(0o755)
    if dotenv is not None:
        (tmp_path / ".env").write_text(dotenv, encoding="utf-8")
    env = os.environ.copy()
    env.pop("D810_DOCKER_IMAGE", None)
    env.pop("D810_API_TOKEN", None)
    env.pop("D810_EGGLOG_ROOT", None)
    env.pop("D810_COBRA_ROOT", None)
    env.pop("D810_COBRA_WHEEL", None)
    env.pop("D810_COBRA_WHEEL_SHA256", None)
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
