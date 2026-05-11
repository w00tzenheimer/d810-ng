"""Unit tests for ``python -m d810.diagnostics dump-after``.

Covers the pure ``extract_after_pseudocode`` / ``render_after_pseudocode``
helpers plus the end-to-end CLI invocation with synthetic dump text.
"""
from __future__ import annotations

import subprocess
import sys
from pathlib import Path

import pytest

from d810.diagnostics.dump_after import (
    END_MARKER_PREFIX,
    START_MARKER,
    extract_after_pseudocode,
    render_after_pseudocode,
)


REPO_ROOT = Path(__file__).resolve().parents[3]


SAMPLE_DUMP = """\
=== BEFORE ===
__int64 hodur_func()
{
  // pre-recovery
}

--- AFTER ---
__int64 hodur_func()
{
  return 0;
}

=== STATS: ===
duration: 1.2s
""".splitlines()


def _make_dump(tmp_path: Path, body: str, name: str = "dump.txt") -> Path:
    path = tmp_path / name
    path.write_text(body)
    return path


# ---------------------------------------------------------------------------
# extract_after_pseudocode
# ---------------------------------------------------------------------------


def test_extract_after_pseudocode_returns_inclusive_start_exclusive_end():
    start, end = extract_after_pseudocode(SAMPLE_DUMP)
    body = SAMPLE_DUMP[start:end]
    assert body[0] == "__int64 hodur_func()"
    assert body[-1] == ""
    assert all(not line.startswith(END_MARKER_PREFIX) for line in body)


def test_extract_after_pseudocode_handles_truncated_dump():
    truncated = SAMPLE_DUMP[: SAMPLE_DUMP.index("=== STATS: ===")]
    start, end = extract_after_pseudocode(truncated)
    assert end == len(truncated)
    assert truncated[start] == "__int64 hodur_func()"


def test_extract_after_pseudocode_raises_when_marker_missing():
    with pytest.raises(ValueError) as exc_info:
        extract_after_pseudocode(["just some preamble", "more"])
    assert START_MARKER in str(exc_info.value)


def test_extract_after_pseudocode_picks_last_marker_when_repeated():
    """Some dumps embed the marker inside earlier sections. The parser
    is intentionally greedy in one direction (last marker before STATS)
    so the second occurrence wins."""
    lines = [
        "preamble",
        "--- AFTER ---",  # first (in a quoted log line)
        "noise A",
        "--- AFTER ---",  # second (the real one)
        "real body",
        "=== STATS: ===",
        "tail",
    ]
    start, end = extract_after_pseudocode(lines)
    assert lines[start - 1] == "--- AFTER ---"
    assert lines[start] == "real body"
    assert end == lines.index("=== STATS: ===")


# ---------------------------------------------------------------------------
# render_after_pseudocode
# ---------------------------------------------------------------------------


def test_render_after_pseudocode_returns_body_only_by_default():
    rendered = render_after_pseudocode(SAMPLE_DUMP, line_numbers=False)
    assert rendered[0] == "__int64 hodur_func()"
    assert any("return 0;" in line for line in rendered)
    assert all(not line.startswith("=== STATS:") for line in rendered)


def test_render_after_pseudocode_emits_one_based_line_numbers():
    rendered = render_after_pseudocode(SAMPLE_DUMP, line_numbers=True)
    # The first AFTER body line is index 7 in SAMPLE_DUMP (1-based = 8).
    first_label = "8: __int64 hodur_func()"
    assert rendered[0] == first_label


# ---------------------------------------------------------------------------
# End-to-end CLI: `python -m d810.diagnostics dump-after`
# ---------------------------------------------------------------------------


def _run_cli(*args: str) -> subprocess.CompletedProcess:
    env_path = str(REPO_ROOT / "src")
    return subprocess.run(
        [sys.executable, "-m", "d810.diagnostics", "dump-after", *args],
        capture_output=True,
        text=True,
        env={"PYTHONPATH": env_path, "PATH": ""},
        cwd=str(REPO_ROOT),
    )


def test_cli_emits_after_body_for_valid_dump(tmp_path: Path):
    dump = _make_dump(tmp_path, "\n".join(SAMPLE_DUMP) + "\n")
    result = _run_cli(str(dump))
    assert result.returncode == 0, result.stderr
    assert "__int64 hodur_func()" in result.stdout
    assert "return 0;" in result.stdout
    assert "=== STATS:" not in result.stdout


def test_cli_emits_line_numbers_with_dash_n(tmp_path: Path):
    dump = _make_dump(tmp_path, "\n".join(SAMPLE_DUMP) + "\n")
    result = _run_cli(str(dump), "-n")
    assert result.returncode == 0, result.stderr
    assert "8: __int64 hodur_func()" in result.stdout


def test_cli_reports_missing_marker_with_exit_code_one(tmp_path: Path):
    dump = _make_dump(tmp_path, "no marker here\n")
    result = _run_cli(str(dump))
    assert result.returncode == 1
    assert START_MARKER in result.stdout


def test_cli_reports_missing_file(tmp_path: Path):
    missing = tmp_path / "does-not-exist.txt"
    result = _run_cli(str(missing))
    assert result.returncode == 1
    assert "dump file not found" in result.stdout
