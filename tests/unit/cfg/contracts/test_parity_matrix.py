"""CI parity gate: verify parity_matrix.json is consistent with invariants.py.

Asserts:
- Every code with disposition="mapped" has a corresponding CFG_XXXXX_ constant
  in invariants.py (grepped from source text).
- No codes are missing a valid disposition.
- Summary counts are printed for each disposition category.
"""
from __future__ import annotations

import json
import re
from pathlib import Path

import pytest

_REPO_ROOT = Path(__file__).resolve().parents[4]
_MATRIX_PATH = _REPO_ROOT / "src" / "d810" / "cfg" / "contracts" / "parity_matrix.json"
_INVARIANTS_PATH = _REPO_ROOT / "src" / "d810" / "cfg" / "contracts" / "invariants.py"

_VALID_DISPOSITIONS = {
    "mapped",
    "planned",
    "blocked_by_api",
    "native_oracle",
    "native_oracle_limited",
    "native_oracle_deferred",
}


def _load_matrix() -> dict:
    with _MATRIX_PATH.open() as fh:
        return json.load(fh)


def _extract_invariant_constants() -> set[str]:
    """Return all CFG_XXXXX_ constants found in invariants.py source text."""
    source = _INVARIANTS_PATH.read_text(encoding="utf-8")
    return set(re.findall(r'CFG_\d+_\w+', source))


@pytest.fixture(scope="module")
def matrix() -> dict:
    return _load_matrix()


@pytest.fixture(scope="module")
def invariant_constants() -> set[str]:
    return _extract_invariant_constants()


def test_matrix_file_exists():
    assert _MATRIX_PATH.exists(), f"parity_matrix.json not found at {_MATRIX_PATH}"


def test_invariants_file_exists():
    assert _INVARIANTS_PATH.exists(), f"invariants.py not found at {_INVARIANTS_PATH}"


def test_matrix_has_required_fields(matrix):
    assert matrix.get("sdk_version"), "sdk_version missing"
    assert matrix.get("sdk_source"), "sdk_source missing"
    assert matrix.get("scope"), "scope missing"
    assert isinstance(matrix.get("codes"), list), "codes must be a list"
    assert len(matrix["codes"]) > 0, "codes list is empty"


def test_codes_sorted_by_number(matrix):
    codes = [entry["code"] for entry in matrix["codes"]]
    assert codes == sorted(codes), "codes are not sorted by code number"


def test_all_dispositions_are_valid(matrix):
    for entry in matrix["codes"]:
        code = entry["code"]
        disp = entry.get("disposition")
        assert disp in _VALID_DISPOSITIONS, (
            f"Code {code} has invalid disposition {disp!r}; "
            f"must be one of {_VALID_DISPOSITIONS}"
        )


def test_mapped_codes_have_constant_in_invariants(matrix, invariant_constants):
    """Every disposition=mapped entry must have a CFG_XXXXX_ constant in invariants.py."""
    missing: list[int] = []
    for entry in matrix["codes"]:
        if entry.get("disposition") != "mapped":
            continue
        code_num = entry["code"]
        pattern = f"CFG_{code_num}_"
        matched = any(c.startswith(pattern) for c in invariant_constants)
        if not matched:
            missing.append(code_num)

    assert not missing, (
        f"The following disposition=mapped codes have no CFG_XXXXX_ constant in "
        f"invariants.py: {missing}"
    )


def test_summary_counts(matrix, capsys):
    """Print disposition summary and assert all entries have a known disposition."""
    counts: dict[str, int] = {}
    for entry in matrix["codes"]:
        disp = entry.get("disposition", "UNKNOWN")
        counts[disp] = counts.get(disp, 0) + 1

    total = sum(counts.values())
    with capsys.disabled():
        print(f"\nParity matrix summary ({total} total codes):")
        for disp in sorted(counts):
            print(f"  {disp}: {counts[disp]}")

    assert "UNKNOWN" not in counts, "Some entries are missing a disposition field"
    assert total == len(matrix["codes"]), "Count mismatch"
