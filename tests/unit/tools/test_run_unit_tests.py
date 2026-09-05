"""Dry-run coverage for tools/scripts/run_unit_tests.sh.

Ticket d81-4tsd, review 1 (C1): the wrapper aborted with an "unbound
variable" error under macOS's bash 3.2 (/bin/bash) for every
argument-free invocation, including the documented serial command,
because it referenced an empty EXTRA_ARGS array directly under
`set -u`. These tests invoke the script through its own shebang (no
explicit `bash ...` prefix), so they exercise whatever interpreter the
shebang actually selects on this host, and assert on the exact resolved
`pytest` command via --dry-run rather than running the (expensive) suite
itself.

Re-review 1: review-1's fix classified positionals by filesystem
existence (`[ -e ... ]`), which still let an option VALUE that happened
to collide with a real repo path (e.g. "-k tests", "-k docs") drop
tests/unit. The classifier was rewritten to walk EXTRA_ARGS by option
grammar (a token consumed as a preceding option's value is never
positional, regardless of what it names); the cases below cover that
walk plus the --dry-run display's shell-quoting fix (a multi-word value
must survive as one argument, not four) and the -n/--dist
missing-value guards.
"""

from __future__ import annotations

import os
import subprocess
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[3]
SCRIPT = REPO_ROOT / "tools" / "scripts" / "run_unit_tests.sh"


def _env_without_pythonpath() -> dict[str, str]:
    # Drop any PYTHONPATH inherited from the outer pytest process (this
    # test file is itself normally run with PYTHONPATH=src:tests set) so
    # the resolved command asserted below does not depend on how this
    # test was invoked -- the script appends its own "src:tests" ahead of
    # whatever PYTHONPATH it is handed.
    return {k: v for k, v in os.environ.items() if k != "PYTHONPATH"}


def _dry_run(*args: str) -> subprocess.CompletedProcess[str]:
    if not SCRIPT.is_file():
        pytest.fail(f"wrapper missing: {SCRIPT}")
    return subprocess.run(
        [str(SCRIPT), *args, "--dry-run"],
        cwd=REPO_ROOT,
        capture_output=True,
        text=True,
        check=False,
        env=_env_without_pythonpath(),
    )


def _run_raw(*args: str) -> subprocess.CompletedProcess[str]:
    """Invoke the script with exactly these arguments, no --dry-run added.

    Used for the missing-value cases: appending --dry-run would supply a
    (wrong) value to a flag that is supposed to have none left.
    """
    if not SCRIPT.is_file():
        pytest.fail(f"wrapper missing: {SCRIPT}")
    return subprocess.run(
        [str(SCRIPT), *args],
        cwd=REPO_ROOT,
        capture_output=True,
        text=True,
        check=False,
        env=_env_without_pythonpath(),
    )


def test_no_args_resolves_to_serial_tests_unit() -> None:
    """The documented "serial behaviour is unchanged" invocation."""
    result = _dry_run()
    assert result.returncode == 0, result.stderr
    assert result.stdout.strip() == (
        "PYTHONPATH=src:tests pyenv exec python -m pytest "
        "-p no:cacheprovider tests/unit"
    )


def test_n4_resolves_to_dist_load_with_tests_unit() -> None:
    result = _dry_run("-n", "4")
    assert result.returncode == 0, result.stderr
    assert result.stdout.strip() == (
        "PYTHONPATH=src:tests pyenv exec python -m pytest "
        "-p no:cacheprovider tests/unit -n 4 --dist load"
    )


def test_positional_path_replaces_tests_unit_default() -> None:
    """A caller-named target must not be unioned with tests/unit."""
    result = _dry_run("tests/unit/core/test_plugins.py")
    assert result.returncode == 0, result.stderr
    assert result.stdout.strip() == (
        "PYTHONPATH=src:tests pyenv exec python -m pytest "
        "-p no:cacheprovider tests/unit/core/test_plugins.py"
    )


def test_k_expr_value_is_not_mistaken_for_a_positional_target() -> None:
    """Review 1, I3: a flag's bare VALUE is not a path.

    "-k foo" previously dropped tests/unit because "foo" does not start
    with "-" either, which let pytest's testpaths = ["tests"] fall back
    to collecting tests/system too.
    """
    result = _dry_run("-k", "foo")
    assert result.returncode == 0, result.stderr
    assert result.stdout.strip() == (
        "PYTHONPATH=src:tests pyenv exec python -m pytest "
        "-p no:cacheprovider tests/unit -k foo"
    )


@pytest.mark.parametrize("expr", ["docs", "tests", "conftest.py"])
def test_k_expr_colliding_with_a_real_repo_path_is_still_a_value(
    expr: str,
) -> None:
    """Re-review 1: filesystem-existence classification is not enough.

    "docs", "tests" and "conftest.py" all name real top-level entries in
    this repo. -k's argument is always its value, regardless of whether
    it happens to also be a real path -- classification must be by
    option grammar, not by what `[ -e ... ]` reports.
    """
    result = _dry_run("-k", expr)
    assert result.returncode == 0, result.stderr
    assert result.stdout.strip() == (
        "PYTHONPATH=src:tests pyenv exec python -m pytest "
        f"-p no:cacheprovider tests/unit -k {expr}"
    )


def test_k_multiword_expr_survives_as_one_shell_quoted_argument() -> None:
    """Re-review 1 minor: the dry-run display must preserve word boundaries."""
    result = _dry_run("-k", "a or b")
    assert result.returncode == 0, result.stderr
    assert result.stdout.strip() == (
        "PYTHONPATH=src:tests pyenv exec python -m pytest "
        r"-p no:cacheprovider tests/unit -k a\ or\ b"
    )


def test_glued_n4_is_never_positional() -> None:
    """"-n4" (pytest-xdist's glued short form) starts with "-": pass
    through untouched, do not let it consume a following token either."""
    result = _dry_run("-n4")
    assert result.returncode == 0, result.stderr
    assert result.stdout.strip() == (
        "PYTHONPATH=src:tests pyenv exec python -m pytest "
        "-p no:cacheprovider tests/unit -n4"
    )


def test_glued_dist_equals_value_is_never_positional() -> None:
    """"--dist=loadfile" is one token; it must not consume the next one.

    review-1 M2 (out of scope for this round): the "=" form is not routed
    through the script's own DIST variable, so its own "-n"-driven
    "--dist load" default is still emitted ahead of the pass-through
    "--dist=loadfile" (pytest takes the last value; harmless but noisy).
    What this test asserts is the part in scope here: tests/unit stays,
    and "loadfile" is never swallowed as a positional or as another
    option's value.
    """
    result = _dry_run("-n", "4", "--dist=loadfile")
    assert result.returncode == 0, result.stderr
    assert result.stdout.strip() == (
        "PYTHONPATH=src:tests pyenv exec python -m pytest "
        "-p no:cacheprovider tests/unit -n 4 --dist load --dist=loadfile"
    )


def test_positional_after_a_valued_long_option_is_still_detected() -> None:
    """"--maxfail 3 tests/unit/core": "3" is --maxfail's value, and
    "tests/unit/core" is the real target that must replace the default."""
    result = _dry_run("--maxfail", "3", "tests/unit/core")
    assert result.returncode == 0, result.stderr
    assert result.stdout.strip() == (
        "PYTHONPATH=src:tests pyenv exec python -m pytest "
        "-p no:cacheprovider --maxfail 3 tests/unit/core"
    )


def test_n_with_no_value_is_a_usage_error_not_a_crash() -> None:
    result = _run_raw("-n")
    assert result.returncode == 2, (result.stdout, result.stderr)
    assert "unbound variable" not in result.stderr
    assert "-n/--numprocesses requires a value" in result.stderr


def test_dist_with_no_value_is_a_usage_error_not_a_crash() -> None:
    result = _run_raw("--dist")
    assert result.returncode == 2, (result.stdout, result.stderr)
    assert "unbound variable" not in result.stderr
    assert "--dist requires a value" in result.stderr
