"""Architecture-aware tagging in the IDA image build script.

``build_ida_images.sh`` lives beside the licensed IDA installers, outside git,
so it cannot be reviewed through a diff. What it does to *tags*, however, is
destructive and shared: a docker tag holds exactly one image, so building the
amd64 IDA 9.4 installer re-points ``idapro-9.4-speedups:{cli,x11,latest}`` at
amd64 images and the arm64 images that held those names keep only their ids.

These tests drive the real script with ``--dry-run`` and a fake ``docker`` on
PATH, in a throwaway tree that mimics the repository layout the script expects.
They assert three things:

* the default tags are exactly what they always were,
* ``--tag-arch-suffix`` produces the shapes the amd64 9.4 images already use
  (``:cli-amd64``, ``:x11-amd64``, ``:amd64-latest``) and touches nothing else,
* without either flag, a cross-architecture build is refused with exit 2
  *before* anything is built.

The script itself is untracked; when it is absent (a fresh clone, a worktree
without ``_gitless/``) every test here skips rather than failing.
"""

from __future__ import annotations

import os
import shutil
import subprocess
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[3]
BUILDER = REPO_ROOT / "_gitless" / "resource" / "build_ida_images.sh"
REAL_COBRA_IDENTITY = REPO_ROOT / "docker" / "cobra-bake" / "cobra_identity.sh"

pytestmark = pytest.mark.skipif(
    not BUILDER.is_file(),
    reason=f"untracked image build script not present at {BUILDER}",
)

IDA_VERSION = "9.4"
SPEEDUPS_REPO = f"idapro-{IDA_VERSION}-speedups"
VANILLA_REPO = f"idapro-{IDA_VERSION}"

# e_machine, ELF header byte 18 (little endian). The script reads exactly these
# two bytes to decide the platform, so a 64-byte stub is a sufficient installer.
E_MACHINE = {"amd64": b"\x3e\x00", "arm64": b"\xb7\x00"}

# The stub below stands in for docker/cobra-bake/cobra_identity.sh. Only the
# names the build script actually uses are provided; a drift test asserts they
# still exist in the tracked file.
COBRA_IDENTITY_STUB = """\
COBRA_BAKE_VERSION=0.0.0-stub
COBRA_BAKE_TAG_COMMIT=tagstub
COBRA_BAKE_CORE_COMMIT=corestub
COBRA_BAKE_PARENT_COMMIT=parentstub
cobra_bake_arch_for_platform() {
  case "$1" in
    linux/arm64|arm64|aarch64) echo aarch64 ;;
    linux/amd64|amd64|x86_64)  echo x86_64 ;;
    *) return 1 ;;
  esac
}
cobra_bake_wheel_for_arch() { echo "d810_cobra-0.0.0-$1.whl"; }
cobra_bake_sha256_for_arch() { echo "shastub-$1"; }
cobra_bake_label_mismatch() { return 0; }
cobra_bake_labels_absent() { return 0; }
"""

COBRA_IDENTITY_NAMES = (
    "COBRA_BAKE_VERSION",
    "COBRA_BAKE_TAG_COMMIT",
    "COBRA_BAKE_CORE_COMMIT",
    "COBRA_BAKE_PARENT_COMMIT",
    "cobra_bake_arch_for_platform",
    "cobra_bake_sha256_for_arch",
    "cobra_bake_label_mismatch",
    "cobra_bake_labels_absent",
)

STAGE_STUB = """\
#!/usr/bin/env bash
set -eu
mkdir -p "$1/cobra-bake"
echo "[cobra-bake] staged (stub) for $2"
"""

# A fake docker. `image inspect --format {{.Architecture}} REF` answers from a
# table file, which is how the guard learns what the existing tag holds; every
# other invocation is logged and succeeds, printing "0" so the numeric probes
# in the verify table parse.
FAKE_DOCKER = """\
#!/usr/bin/env bash
echo "docker $*" >> "$FAKE_DOCKER_LOG"
if [ "${1:-}" = "image" ] && [ "${2:-}" = "inspect" ]; then
  ref="${@: -1}"
  if [ -f "$FAKE_DOCKER_ARCH_TABLE" ]; then
    while read -r tag arch; do
      [ -n "$tag" ] || continue
      if [ "$tag" = "$ref" ]; then echo "$arch"; exit 0; fi
    done < "$FAKE_DOCKER_ARCH_TABLE"
  fi
  echo "Error: No such image: $ref" >&2
  exit 1
fi
echo 0
exit 0
"""


def _write(path: Path, text: str, *, executable: bool = False) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text)
    if executable:
        path.chmod(0o755)


def _tree(tmp_path: Path, installer_arch: str, existing: dict[str, str]) -> Path:
    """A throwaway repo root holding the real script and stubbed neighbours."""
    root = tmp_path / "repo"
    resource = root / "_gitless" / "resource"
    version_dir = resource / IDA_VERSION
    version_dir.mkdir(parents=True)

    script = resource / "build_ida_images.sh"
    shutil.copy(BUILDER, script)
    script.chmod(0o755)

    installer = version_dir / f"ida{IDA_VERSION}.run"
    header = bytearray(b"\x7fELF" + b"\x00" * 60)
    header[18:20] = E_MACHINE[installer_arch]
    installer.write_bytes(bytes(header))
    for name in ("idakeygen.py", "idareggen.py", "entrypoint.sh"):
        _write(version_dir / name, "# stub\n")

    _write(
        resource / "Dockerfile.slim",
        f"ARG IDA_VERSION={IDA_VERSION}\n"
        "ADD ./_gitless/resource/${IDA_VERSION} /app/resource\n",
    )

    bake = root / "docker" / "cobra-bake"
    _write(bake / "cobra_identity.sh", COBRA_IDENTITY_STUB)
    _write(bake / "stage_cobra_bake_context.sh", STAGE_STUB, executable=True)
    _write(bake / "verify_cobra_install.py", "print('stub')\n")

    _write(root / "bin" / "docker", FAKE_DOCKER, executable=True)
    _write(
        root / "arch-table",
        "".join(f"{tag} {arch}\n" for tag, arch in existing.items()),
    )
    (root / "src").mkdir()
    return root


def _run(
    root: Path, *args: str, timeout: int = 120
) -> subprocess.CompletedProcess[str]:
    env = dict(os.environ)
    env["PATH"] = f"{root / 'bin'}{os.pathsep}{env['PATH']}"
    env["FAKE_DOCKER_LOG"] = str(root / "docker.log")
    env["FAKE_DOCKER_ARCH_TABLE"] = str(root / "arch-table")
    return subprocess.run(
        [
            "bash",
            str(root / "_gitless" / "resource" / "build_ida_images.sh"),
            "-f",
            str(root / "_gitless" / "resource" / "Dockerfile.slim"),
            *args,
        ],
        cwd=root,
        env=env,
        capture_output=True,
        text=True,
        check=False,
        timeout=timeout,
    )


def _dry_run(
    tmp_path: Path,
    *args: str,
    installer_arch: str = "amd64",
    existing: dict[str, str] | None = None,
) -> subprocess.CompletedProcess[str]:
    root = _tree(tmp_path, installer_arch, existing or {})
    return _run(root, "--only", "speedups", "--dry-run", *args)


def _tags_built(stdout: str) -> list[str]:
    """Every `-t <ref>` the dry run would pass to docker build."""
    tags: list[str] = []
    for line in stdout.splitlines():
        parts = line.split()
        for i, part in enumerate(parts):
            if part == "-t" and i + 1 < len(parts):
                tags.append(parts[i + 1])
    return tags


def _tag_aliases(stdout: str) -> list[tuple[str, str]]:
    """Every `docker tag <src> <dst>` the dry run would perform."""
    aliases: list[tuple[str, str]] = []
    for line in stdout.splitlines():
        parts = line.split()
        if parts[:2] == ["docker", "tag"] and len(parts) == 4:
            aliases.append((parts[2], parts[3]))
    return aliases


# ---------------------------------------------------------------------------
# Default behaviour is unchanged
# ---------------------------------------------------------------------------


def test_default_tags_are_the_plain_ones(tmp_path: Path) -> None:
    result = _dry_run(tmp_path)
    assert result.returncode == 0, result.stderr
    assert _tags_built(result.stdout) == [
        f"{SPEEDUPS_REPO}:cli",
        f"{SPEEDUPS_REPO}:x11",
    ]
    # Both repos are always visited; the tag only moves when its cli image
    # exists, which is what the pre-existing script did too.
    assert _tag_aliases(result.stdout) == [
        (f"{VANILLA_REPO}:cli", f"{VANILLA_REPO}:latest"),
        (f"{SPEEDUPS_REPO}:cli", f"{SPEEDUPS_REPO}:latest"),
    ]


def test_default_tags_carry_no_architecture(tmp_path: Path) -> None:
    """The suffix mechanism is opt-in; nothing leaks into the old shapes."""
    result = _dry_run(tmp_path)
    assert result.returncode == 0, result.stderr
    for tag in _tags_built(result.stdout):
        assert "amd64" not in tag and "arm64" not in tag


# ---------------------------------------------------------------------------
# --tag-arch-suffix
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("flag", ["--tag-arch-suffix", "--arch-tags"])
def test_suffixed_tags_match_the_existing_amd64_convention(
    tmp_path: Path, flag: str
) -> None:
    """The remote engine's images are :amd64-latest and :x11-amd64 already."""
    result = _dry_run(tmp_path, flag, installer_arch="amd64")
    assert result.returncode == 0, result.stderr
    assert _tags_built(result.stdout) == [
        f"{SPEEDUPS_REPO}:cli-amd64",
        f"{SPEEDUPS_REPO}:x11-amd64",
    ]
    assert _tag_aliases(result.stdout) == [
        (f"{VANILLA_REPO}:cli-amd64", f"{VANILLA_REPO}:amd64-latest"),
        (f"{SPEEDUPS_REPO}:cli-amd64", f"{SPEEDUPS_REPO}:amd64-latest"),
    ]


def test_suffixed_tags_follow_the_arm64_installer(tmp_path: Path) -> None:
    result = _dry_run(tmp_path, "--tag-arch-suffix", installer_arch="arm64")
    assert result.returncode == 0, result.stderr
    assert _tags_built(result.stdout) == [
        f"{SPEEDUPS_REPO}:cli-arm64",
        f"{SPEEDUPS_REPO}:x11-arm64",
    ]
    assert _tag_aliases(result.stdout) == [
        (f"{VANILLA_REPO}:cli-arm64", f"{VANILLA_REPO}:arm64-latest"),
        (f"{SPEEDUPS_REPO}:cli-arm64", f"{SPEEDUPS_REPO}:arm64-latest"),
    ]


def test_suffixed_build_never_writes_a_plain_tag(tmp_path: Path) -> None:
    """The whole point: the arm64 :cli/:x11/:latest must survive an amd64 build."""
    result = _dry_run(
        tmp_path,
        "--tag-arch-suffix",
        existing={f"{SPEEDUPS_REPO}:latest": "arm64"},
    )
    assert result.returncode == 0, result.stderr
    written = set(_tags_built(result.stdout)) | {
        dst for _, dst in _tag_aliases(result.stdout)
    }
    assert written.isdisjoint(
        {
            f"{SPEEDUPS_REPO}:cli",
            f"{SPEEDUPS_REPO}:x11",
            f"{SPEEDUPS_REPO}:latest",
        }
    )


def test_suffix_covers_both_repos(tmp_path: Path) -> None:
    root = _tree(tmp_path, "amd64", {})
    result = _run(root, "--tag-arch-suffix", "--dry-run")
    assert result.returncode == 0, result.stderr
    assert _tags_built(result.stdout) == [
        f"{VANILLA_REPO}:cli-amd64",
        f"{VANILLA_REPO}:x11-amd64",
        f"{SPEEDUPS_REPO}:cli-amd64",
        f"{SPEEDUPS_REPO}:x11-amd64",
    ]
    assert _tag_aliases(result.stdout) == [
        (f"{VANILLA_REPO}:cli-amd64", f"{VANILLA_REPO}:amd64-latest"),
        (f"{SPEEDUPS_REPO}:cli-amd64", f"{SPEEDUPS_REPO}:amd64-latest"),
    ]


# ---------------------------------------------------------------------------
# The cross-architecture guard
# ---------------------------------------------------------------------------


def test_cross_arch_build_is_refused_before_building(tmp_path: Path) -> None:
    root = _tree(tmp_path, "amd64", {f"{SPEEDUPS_REPO}:latest": "arm64"})
    result = _run(root, "--only", "speedups")
    assert result.returncode == 2, (result.returncode, result.stdout, result.stderr)
    assert "arm64" in result.stderr and "amd64" in result.stderr
    assert "--tag-arch-suffix" in result.stderr
    assert "--allow-arch-overwrite" in result.stderr
    # Nothing was built, and no tag was moved.
    log = (root / "docker.log").read_text()
    assert "docker build" not in log
    assert "docker tag" not in log


def test_cross_arch_guard_also_covers_the_vanilla_repo(tmp_path: Path) -> None:
    root = _tree(tmp_path, "amd64", {f"{VANILLA_REPO}:latest": "arm64"})
    result = _run(root, "--only", "vanilla", "--dry-run")
    assert result.returncode == 2, (result.returncode, result.stdout, result.stderr)
    assert VANILLA_REPO in result.stderr


def test_same_arch_is_not_a_collision(tmp_path: Path) -> None:
    result = _dry_run(tmp_path, existing={f"{SPEEDUPS_REPO}:latest": "amd64"})
    assert result.returncode == 0, result.stderr
    assert "collision" not in result.stderr


def test_absent_tag_is_not_a_collision(tmp_path: Path) -> None:
    result = _dry_run(tmp_path, existing={})
    assert result.returncode == 0, result.stderr
    assert "collision" not in result.stderr


def test_suffix_option_bypasses_the_guard(tmp_path: Path) -> None:
    result = _dry_run(
        tmp_path,
        "--tag-arch-suffix",
        existing={f"{SPEEDUPS_REPO}:latest": "arm64"},
    )
    assert result.returncode == 0, result.stderr
    assert "collision" not in result.stderr


def test_allow_arch_overwrite_proceeds_with_a_loud_warning(tmp_path: Path) -> None:
    result = _dry_run(
        tmp_path,
        "--allow-arch-overwrite",
        existing={f"{SPEEDUPS_REPO}:latest": "arm64"},
    )
    assert result.returncode == 0, result.stderr
    assert "WARNING" in result.stdout
    assert "arm64" in result.stdout and "amd64" in result.stdout
    # It really does take the plain tags.
    assert _tags_built(result.stdout) == [
        f"{SPEEDUPS_REPO}:cli",
        f"{SPEEDUPS_REPO}:x11",
    ]


# ---------------------------------------------------------------------------
# The verification table has to follow the tags it just produced
# ---------------------------------------------------------------------------


def test_verify_table_judges_suffixed_tags_by_variant_not_spelling(
    tmp_path: Path,
) -> None:
    """`:x11-amd64` is still an x11 image.

    The table used to read the expectations out of the tag (``*:x11``), which a
    suffixed tag no longer matches -- an x11 image would then be checked as a
    cli one and its missing GUI libraries would pass. The fake docker reports 0
    x11 packages, so the x11 row must complain that it wanted 1 and the cli row
    must not mention x11libs at all. The run ends non-zero because the stub
    docker satisfies nothing else; only the table is under test here.
    """
    root = _tree(tmp_path, "amd64", {})
    result = _run(root, "--only", "speedups", "--tag-arch-suffix")
    rows = {
        line.split()[0]: line
        for line in result.stdout.splitlines()
        if line.strip().startswith(f"{SPEEDUPS_REPO}:")
    }
    assert set(rows) == {
        f"{SPEEDUPS_REPO}:cli-amd64",
        f"{SPEEDUPS_REPO}:x11-amd64",
    }, result.stdout
    assert "x11libs(want 1)" in rows[f"{SPEEDUPS_REPO}:x11-amd64"]
    assert "x11libs" not in rows[f"{SPEEDUPS_REPO}:cli-amd64"]


# ---------------------------------------------------------------------------
# Documentation and stub drift
# ---------------------------------------------------------------------------


def test_help_documents_both_flags(tmp_path: Path) -> None:
    root = _tree(tmp_path, "amd64", {})
    result = _run(root, "--help")
    assert result.returncode == 0, result.stderr
    assert "--tag-arch-suffix" in result.stdout
    assert "--arch-tags" in result.stdout
    assert "--allow-arch-overwrite" in result.stdout
    assert "amd64-latest" in result.stdout
    assert "x11-amd64" in result.stdout


def test_cobra_identity_stub_matches_the_tracked_interface() -> None:
    """These tests stub cobra_identity.sh; the stub must not drift from it."""
    if not REAL_COBRA_IDENTITY.is_file():  # pragma: no cover - tracked file
        pytest.skip(f"{REAL_COBRA_IDENTITY} is missing")
    real = REAL_COBRA_IDENTITY.read_text()
    missing = [name for name in COBRA_IDENTITY_NAMES if name not in real]
    assert not missing, f"stubbed names no longer exist in cobra_identity.sh: {missing}"
