"""The tracked half of the d810-cobra image bake.

The IDA image Dockerfile and its build script live outside git, beside the
licensed installers. Everything they rely on to identify the baked wheel is in
``docker/cobra-bake/`` and is exercised here, so a change to the published
identity cannot land unreviewed and unverified.
"""

from __future__ import annotations

import hashlib
import subprocess
from pathlib import Path

import pytest

from tests.cobra_published_identity import (
    PUBLISHED_IDENTITY_FILE,
    published_identity,
)

REPO_ROOT = Path(__file__).resolve().parents[3]
BAKE_DIR = REPO_ROOT / "docker" / "cobra-bake"
IDENTITY = BAKE_DIR / "cobra_identity.sh"
STAGE_SCRIPT = BAKE_DIR / "stage_cobra_bake_context.sh"
FRAGMENT = BAKE_DIR / "Dockerfile.cobra-bake.fragment"
VERIFIER = BAKE_DIR / "verify_cobra_install.py"
DOCKER_RUNNER = REPO_ROOT / "tools" / "scripts" / "run_system_tests_docker.sh"

# Derived, never re-declared. published_identity is the single source; every
# expectation below is what that file says, so a rotation cannot be half-done.
_IDENTITY = published_identity()
PUBLISHED_AARCH64_SHA256 = _IDENTITY.wheels["aarch64"].sha256
PUBLISHED_X86_64_SHA256 = _IDENTITY.wheels["x86_64"].sha256
TAG_COMMIT = _IDENTITY.tag_commit
CORE_COMMIT = _IDENTITY.core_commit
PARENT_COMMIT = _IDENTITY.parent_commit
VERSION = _IDENTITY.version
AARCH64_WHEEL = _IDENTITY.wheels["aarch64"].filename
X86_64_WHEEL = _IDENTITY.wheels["x86_64"].filename
# Built before the release: same filename, same size, different bytes. It is
# written out here on purpose -- it must never be readable from the identity.
PREFLIGHT_AARCH64_SHA256 = (
    "b71d40e45146004a968a96a1b17493b16ac04f2a98e41c12a1f87a38ddf3ab25"
)


def _identity(snippet: str) -> subprocess.CompletedProcess[str]:
    """Run a snippet with docker/cobra-bake/cobra_identity.sh sourced."""
    return subprocess.run(
        ["bash", "-c", f'set -eu; . "{IDENTITY}"; {snippet}'],
        check=False,
        capture_output=True,
        text=True,
    )


def _impostor_wheel(path: Path) -> str:
    """Write non-published bytes at ``path`` and report their real hash."""
    path.write_bytes(b"not the published wheel")
    return hashlib.sha256(path.read_bytes()).hexdigest()


@pytest.mark.parametrize(
    ("platform", "arch"),
    [
        ("linux/arm64", "aarch64"),
        ("linux/amd64", "x86_64"),
        ("arm64", "aarch64"),
        ("amd64", "x86_64"),
        ("aarch64", "aarch64"),
        ("x86_64", "x86_64"),
    ],
)
def test_platform_maps_to_the_wheel_architecture(platform: str, arch: str) -> None:
    result = _identity(f'cobra_bake_arch_for_platform "{platform}"')
    assert result.returncode == 0, result.stderr
    assert result.stdout.strip() == arch


def test_unknown_platform_is_refused_rather_than_defaulted() -> None:
    """A guessed architecture bakes a wheel that cannot import at run time."""
    result = _identity('cobra_bake_arch_for_platform "linux/riscv64" || echo REFUSED')
    assert result.returncode == 0, result.stderr
    assert result.stdout.strip() == "REFUSED"


@pytest.mark.parametrize(
    ("arch", "wheel", "sha256"),
    [
        ("aarch64", AARCH64_WHEEL, PUBLISHED_AARCH64_SHA256),
        ("x86_64", X86_64_WHEEL, PUBLISHED_X86_64_SHA256),
    ],
)
def test_published_wheel_name_and_hash_per_architecture(
    arch: str,
    wheel: str,
    sha256: str,
) -> None:
    result = _identity(
        f'cobra_bake_wheel_for_arch "{arch}"; cobra_bake_sha256_for_arch "{arch}"'
    )
    assert result.returncode == 0, result.stderr
    assert result.stdout.split() == [wheel, sha256]




def test_matching_labels_are_accepted() -> None:
    result = _identity(
        "cobra_bake_label_mismatch aarch64 " + VERSION + " "
        f"{PUBLISHED_AARCH64_SHA256} {TAG_COMMIT} {CORE_COMMIT} {PARENT_COMMIT}"
    )
    assert result.returncode == 0, result.stdout + result.stderr
    assert result.stdout == ""


def test_preflight_hash_is_never_an_accepted_label() -> None:
    """The preflight wheels are provenance evidence, not an identity."""
    result = _identity(
        "cobra_bake_label_mismatch aarch64 " + VERSION + " "
        f"{PREFLIGHT_AARCH64_SHA256} {TAG_COMMIT} {CORE_COMMIT} {PARENT_COMMIT}"
    )
    assert result.returncode == 1
    assert "wheel_sha256(want" in result.stdout


def test_wrong_architecture_hash_is_a_label_mismatch() -> None:
    """The x86_64 hash on an arm64 image would install and fail to import."""
    result = _identity(
        "cobra_bake_label_mismatch aarch64 " + VERSION + " "
        f"{PUBLISHED_X86_64_SHA256} {TAG_COMMIT} {CORE_COMMIT} {PARENT_COMMIT}"
    )
    assert result.returncode == 1
    assert "wheel_sha256(want" in result.stdout


@pytest.mark.parametrize(
    ("position", "field"),
    [(2, "version"), (4, "tag_commit"), (5, "core_commit"), (6, "parent_commit")],
)
def test_each_label_field_is_compared(position: int, field: str) -> None:
    args = [
        "aarch64",
        VERSION,
        PUBLISHED_AARCH64_SHA256,
        TAG_COMMIT,
        CORE_COMMIT,
        PARENT_COMMIT,
    ]
    args[position - 1] = "wrong"
    result = _identity("cobra_bake_label_mismatch " + " ".join(args))
    assert result.returncode == 1
    assert f"{field}(want" in result.stdout


def test_empty_label_set_is_absent_not_mismatched() -> None:
    """A vanilla image carries five empty labels and must not be a failure."""
    absent = _identity('cobra_bake_labels_absent "" "" "" "" ""')
    assert absent.returncode == 0
    no_value = _identity('cobra_bake_labels_absent "<no value>" "" "" "" ""')
    assert no_value.returncode == 0


def test_partial_label_set_is_not_absent() -> None:
    result = _identity(f'cobra_bake_labels_absent "{VERSION}" "" "" "" ""')
    assert result.returncode == 1


def _stage(context: Path, arch: str, source_dir: Path) -> subprocess.CompletedProcess:
    return subprocess.run(
        [str(STAGE_SCRIPT), str(context), arch, str(source_dir)],
        check=False,
        capture_output=True,
        text=True,
    )


def test_staging_refuses_bytes_that_are_not_the_published_wheel(
    tmp_path: Path,
) -> None:
    """The filename is not the identity; the hash is."""
    source = tmp_path / "wheels"
    source.mkdir()
    context = tmp_path / "ctx"
    context.mkdir()
    actual = _impostor_wheel(source / AARCH64_WHEEL)

    result = _stage(context, "linux/arm64", source)

    assert result.returncode != 0
    assert actual in result.stderr
    assert PUBLISHED_AARCH64_SHA256 in result.stderr
    assert not (context / "cobra-bake").exists()


def test_staging_reports_a_missing_wheel_by_name(tmp_path: Path) -> None:
    source = tmp_path / "wheels"
    source.mkdir()
    context = tmp_path / "ctx"
    context.mkdir()

    result = _stage(context, "x86_64", source)

    assert result.returncode != 0
    assert X86_64_WHEEL in result.stderr


def test_staging_refuses_an_unsupported_architecture(tmp_path: Path) -> None:
    context = tmp_path / "ctx"
    context.mkdir()
    result = _stage(context, "linux/riscv64", tmp_path)
    assert result.returncode != 0
    assert "unsupported architecture/platform" in result.stderr


def test_staging_refuses_a_missing_context(tmp_path: Path) -> None:
    result = _stage(tmp_path / "absent", "aarch64", tmp_path)
    assert result.returncode != 0
    assert "no such build context" in result.stderr


def test_fragment_declares_every_label_and_build_argument() -> None:
    fragment = FRAGMENT.read_text()
    fields = ("version", "wheel_sha256", "tag_commit", "core_commit", "parent_commit")
    for field in fields:
        assert f'LABEL org.d810.cobra.{field}="${{COBRA_' in fragment
    for arg in (
        "COBRA_VERSION",
        "COBRA_WHEEL_SHA256",
        "COBRA_TAG_COMMIT",
        "COBRA_CORE_COMMIT",
        "COBRA_PARENT_COMMIT",
    ):
        assert f'ARG {arg}=""' in fragment
        assert f'test -n "${{{arg}}}"' in fragment


def test_fragment_installs_a_wheel_and_compiles_nothing() -> None:
    fragment = FRAGMENT.read_text()
    assert "sha256sum -c SHA256SUMS" in fragment
    assert "--no-deps" in fragment
    assert "verify_cobra_install.py" in fragment
    for compiled in ("git clone", "build_cobra.py", "cmake", "submodule"):
        assert compiled not in fragment


def test_verifier_proves_behaviour_not_just_import() -> None:
    """An importable but mis-wired binding must not pass."""
    source = VERIFIER.read_text()
    assert "prove_equivalent" in source
    assert "ProofResult.PROVED" in source
    assert "SolveStatus.SOLVED" in source
    assert '"mba-solve": "cobra-solve"' in source
    assert 'manifest["api_version"] == 1' in source
    assert "import d810_cobra._cobra" in source
    # No lazy imports: the d810_cobra names are bound at module level, which is
    # also what makes an image that cannot import the backend fail immediately.
    body = source[source.index("def main()") :]
    assert "import " not in body


def test_no_untracked_host_paths_leak_into_the_bake_assets() -> None:
    """These files are reviewed in git; they must not name a host checkout."""
    for path in (IDENTITY, STAGE_SCRIPT, FRAGMENT, PUBLISHED_IDENTITY_FILE, VERIFIER):
        text = path.read_text()
        assert "/Users/" not in text, path
        assert "/home/" not in text, path


# ---------------------------------------------------------------------------
# One source of truth: the bake, the runner and the tests must agree
# ---------------------------------------------------------------------------
def _runner_identity_block() -> str:
    """The runner's own identity-loading code, verbatim.

    Extracted rather than reimplemented: the point of the check is that the
    lines the runner actually executes produce the published table, so a
    future edit that re-hardcodes a hash there fails here.
    """
    source = DOCKER_RUNNER.read_text(encoding="utf-8")
    start = source.index('COBRA_IDENTITY_FILE="')
    end = source.index("\n_cobra_load_published_identity\n", start) + len(
        "\n_cobra_load_published_identity\n"
    )
    return source[start:end]


def _runner_published_table() -> tuple[str, str, list[str]]:
    """Run the runner's loader and report what it accepted."""
    block = _runner_identity_block()
    program = (
        "set -euo pipefail\n"
        + block
        + '\nprintf "revision %s\\n" "$COBRA_SOURCE_REVISION"'
        + '\nprintf "core %s\\n" "$COBRA_CORE_SOURCE_REVISION"'
        + '\nwhile read -r digest record; do printf "wheel %s %s\\n" '
        '"$digest" "$record"; done <<< "$COBRA_RECORDED_WHEELS"\n'
    )
    result = subprocess.run(
        ["bash", "-c", program, str(DOCKER_RUNNER)],
        check=False,
        capture_output=True,
        text=True,
    )
    assert result.returncode == 0, result.stderr
    revision = core = ""
    wheels = []
    for line in result.stdout.splitlines():
        key, _, value = line.partition(" ")
        if key == "revision":
            revision = value
        elif key == "core":
            core = value
        elif key == "wheel":
            wheels.append(value)
    return revision, core, wheels


def _runner_loader_with_identity(identity_file: Path) -> subprocess.CompletedProcess:
    """Run the runner's loader against a chosen identity file."""
    block = _runner_identity_block().replace(
        'COBRA_IDENTITY_FILE="$(cd "$(dirname "$0")/../.." && pwd -P)'
        '/docker/cobra-bake/published_identity"',
        f'COBRA_IDENTITY_FILE="{identity_file}"',
    )
    assert str(identity_file) in block
    return subprocess.run(
        ["bash", "-c", "set -euo pipefail\n" + block, str(DOCKER_RUNNER)],
        check=False,
        capture_output=True,
        text=True,
    )


def _bake_loader_with_identity(
    tmp_path: Path,
    identity_file: Path | None,
) -> subprocess.CompletedProcess:
    """Source cobra_identity.sh beside a chosen (or absent) identity file.

    The module resolves the file from its own location, so the seam is a
    directory rather than an environment variable: nothing in production can
    be pointed at a forged identity.
    """
    staged = tmp_path / "bake"
    staged.mkdir(exist_ok=True)
    (staged / IDENTITY.name).write_bytes(IDENTITY.read_bytes())
    if identity_file is not None:
        (staged / "published_identity").write_bytes(identity_file.read_bytes())
    return subprocess.run(
        ["bash", "-c", f'. "{staged / IDENTITY.name}"'],
        check=False,
        capture_output=True,
        text=True,
    )


def test_the_runner_accepts_exactly_the_published_identity() -> None:
    """The runner must not carry a table of its own."""
    revision, core, wheels = _runner_published_table()

    assert revision == PARENT_COMMIT
    assert core == CORE_COMMIT
    assert sorted(wheels) == sorted(
        [
            f"{PUBLISHED_AARCH64_SHA256} {VERSION}|aarch64|{TAG_COMMIT}|{CORE_COMMIT}",
            f"{PUBLISHED_X86_64_SHA256} {VERSION}|x86_64|{TAG_COMMIT}|{CORE_COMMIT}",
        ]
    )
    assert not [wheel for wheel in wheels if PREFLIGHT_AARCH64_SHA256 in wheel]


def test_the_bake_and_the_runner_read_the_same_file() -> None:
    """Two readers, one file: neither may keep a private copy."""
    shell = _identity(
        'printf "%s %s %s %s %s %s\\n" "$COBRA_BAKE_VERSION" '
        '"$COBRA_BAKE_TAG_COMMIT" "$COBRA_BAKE_CORE_COMMIT" '
        '"$COBRA_BAKE_PARENT_COMMIT" "$COBRA_BAKE_SHA256_AARCH64" '
        '"$COBRA_BAKE_SHA256_X86_64"'
    )
    assert shell.returncode == 0, shell.stderr
    assert shell.stdout.split() == [
        VERSION,
        TAG_COMMIT,
        CORE_COMMIT,
        PARENT_COMMIT,
        PUBLISHED_AARCH64_SHA256,
        PUBLISHED_X86_64_SHA256,
    ]

    # Same values, reached through the runner's independent parser.
    revision, _core, wheels = _runner_published_table()
    assert revision == PARENT_COMMIT
    assert [wheel.split()[0] for wheel in sorted(wheels)] == sorted(
        [PUBLISHED_AARCH64_SHA256, PUBLISHED_X86_64_SHA256]
    )

    # And no reader may re-declare a value: the literals must appear ONLY in
    # the identity file. This is what fails when one copy is edited alone.
    for literal in (
        PUBLISHED_AARCH64_SHA256,
        PUBLISHED_X86_64_SHA256,
        TAG_COMMIT,
        CORE_COMMIT,
        PARENT_COMMIT,
    ):
        for reader in (IDENTITY, DOCKER_RUNNER, STAGE_SCRIPT):
            assert literal not in reader.read_text(encoding="utf-8"), (
                reader,
                literal,
            )


def test_a_malformed_identity_file_fails_closed_in_both_readers(
    tmp_path: Path,
) -> None:
    """A half-read table would compare artifacts against values nobody wrote."""
    broken = tmp_path / "published_identity"
    broken.write_text(
        f"aarch64 not-a-hash {VERSION} {TAG_COMMIT} {CORE_COMMIT} "
        f"{PARENT_COMMIT} wheel.whl\n",
        encoding="utf-8",
    )

    shell = _bake_loader_with_identity(tmp_path, broken)
    assert shell.returncode != 0
    assert "malformed row" in shell.stderr

    runner = _runner_loader_with_identity(broken)
    assert runner.returncode != 0
    assert "malformed row" in runner.stderr

    with pytest.raises(ValueError, match="is not a sha256"):
        published_identity(broken)


def test_a_missing_identity_file_fails_closed_in_both_readers(
    tmp_path: Path,
) -> None:
    """No identity means no artifact can be checked; that is not a warning."""
    shell = _bake_loader_with_identity(tmp_path, None)
    assert shell.returncode != 0
    assert "unreadable" in shell.stderr

    runner = _runner_loader_with_identity(tmp_path / "absent")
    assert runner.returncode != 0
    assert "unreadable" in runner.stderr
