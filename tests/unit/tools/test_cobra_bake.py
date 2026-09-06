"""The tracked half of the d810-cobra image bake.

The IDA image Dockerfile and its build script live outside git, beside the
licensed installers. Everything they rely on to identify the baked wheel is in
``docker/cobra-bake/`` and is exercised here, so a change to the published
identity cannot land unreviewed and unverified.
"""

from __future__ import annotations

import hashlib
import os
import subprocess
import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[3]
BAKE_DIR = REPO_ROOT / "docker" / "cobra-bake"
IDENTITY = BAKE_DIR / "cobra_identity.sh"
STAGE_SCRIPT = BAKE_DIR / "stage_cobra_bake_context.sh"
FRAGMENT = BAKE_DIR / "Dockerfile.cobra-bake.fragment"
SHA256SUMS = BAKE_DIR / "SHA256SUMS.published"
VERIFIER = BAKE_DIR / "verify_cobra_install.py"

PUBLISHED_AARCH64_SHA256 = (
    "2c85ffe14a1f3c1d2b750790332a7c0a5e911b35f7fc041ebedcd6532382c63c"
)
PUBLISHED_X86_64_SHA256 = (
    "352133fd4f91227518714735b463b978760650b5f30c71f5276c0bccb90cb72c"
)
# Built before the release: same filename, same size, different bytes.
PREFLIGHT_AARCH64_SHA256 = (
    "b71d40e45146004a968a96a1b17493b16ac04f2a98e41c12a1f87a38ddf3ab25"
)
TAG_COMMIT = "73b405c106d78e1fdc7576b217de39b7dcd0ddb3"
CORE_COMMIT = "72f616f822f538a0cfbea3c880f9d1e68bb9a8f1"
PARENT_COMMIT = "3b3c406270f1efd8e222f0b05040ae4e074b27d5"
AARCH64_WHEEL = (
    "d810_cobra-0.1.5-cp313-cp313-manylinux_2_26_aarch64.manylinux_2_28_aarch64.whl"
)
X86_64_WHEEL = (
    "d810_cobra-0.1.5-cp313-cp313-manylinux_2_27_x86_64.manylinux_2_28_x86_64.whl"
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


def test_sha256sums_file_matches_the_shell_identity() -> None:
    """`sha256sum -c` inside the image and the build script must agree."""
    recorded = {
        line.split()[1]: line.split()[0]
        for line in SHA256SUMS.read_text().splitlines()
        if line.strip()
    }
    assert recorded == {
        AARCH64_WHEEL: PUBLISHED_AARCH64_SHA256,
        X86_64_WHEEL: PUBLISHED_X86_64_SHA256,
    }


def test_matching_labels_are_accepted() -> None:
    result = _identity(
        "cobra_bake_label_mismatch aarch64 0.1.5 "
        f"{PUBLISHED_AARCH64_SHA256} {TAG_COMMIT} {CORE_COMMIT} {PARENT_COMMIT}"
    )
    assert result.returncode == 0, result.stdout + result.stderr
    assert result.stdout == ""


def test_preflight_hash_is_never_an_accepted_label() -> None:
    """The preflight wheels are provenance evidence, not an identity."""
    result = _identity(
        "cobra_bake_label_mismatch aarch64 0.1.5 "
        f"{PREFLIGHT_AARCH64_SHA256} {TAG_COMMIT} {CORE_COMMIT} {PARENT_COMMIT}"
    )
    assert result.returncode == 1
    assert "wheel_sha256(want" in result.stdout


def test_wrong_architecture_hash_is_a_label_mismatch() -> None:
    """The x86_64 hash on an arm64 image would install and fail to import."""
    result = _identity(
        "cobra_bake_label_mismatch aarch64 0.1.5 "
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
        "0.1.5",
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
    result = _identity('cobra_bake_labels_absent "0.1.5" "" "" "" ""')
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


def test_verifier_defaults_to_requiring_the_solve() -> None:
    """A caller who sets nothing gets the strongest check."""
    source = VERIFIER.read_text()
    assert 'os.environ.get("D810_COBRA_REQUIRE_SOLVE", "1") != "0"' in source


def test_reduced_mode_refuses_an_environment_that_could_have_solved() -> None:
    """``D810_COBRA_REQUIRE_SOLVE=0`` declares an environment; it must hold.

    Without this the flag would silence a failing backend everywhere instead of
    describing the one place -- an image with no d810 -- where the solve cannot
    run at all.
    """
    env = dict(os.environ)
    env["D810_COBRA_REQUIRE_SOLVE"] = "0"
    env["PYTHONPATH"] = str(REPO_ROOT / "src")
    result = subprocess.run(
        [sys.executable, str(VERIFIER)],
        check=False,
        capture_output=True,
        text=True,
        env=env,
        cwd=REPO_ROOT,
    )
    assert result.returncode != 0
    assert "claims d810 is unavailable, but it is importable" in result.stderr
    # It has to fail on the declaration, before it ever looks at d810_cobra:
    # a missing d810_cobra would otherwise mask the disarmed check.
    assert "No module named 'd810_cobra'" not in result.stderr


def test_bake_step_runs_the_reduced_check_and_says_why() -> None:
    """The image carries no d810, so the fragment cannot ask for the solve."""
    fragment = FRAGMENT.read_text()
    assert "D810_COBRA_REQUIRE_SOLVE=0" in fragment
    assert "d810_cobra.solve imports d810.core" in fragment


def test_readme_documents_where_the_solve_is_enforced() -> None:
    readme = (BAKE_DIR / "README.md").read_text()
    assert "D810_COBRA_REQUIRE_SOLVE" in readme
    assert "PYTHONPATH=/d810-src" in readme


def test_no_untracked_host_paths_leak_into_the_bake_assets() -> None:
    """These files are reviewed in git; they must not name a host checkout."""
    for path in (IDENTITY, STAGE_SCRIPT, FRAGMENT, SHA256SUMS, VERIFIER):
        text = path.read_text()
        assert "/Users/" not in text, path
        assert "/home/" not in text, path
