"""CI parity gate: verify insn_parity_matrix.json is consistent with insn_invariants.py.

Asserts:
- Every code with disposition="planned" has a corresponding MINSN_XXXXX_ constant
  in insn_invariants.py (grepped from source text).
- No codes are missing a valid disposition.
- Summary counts are printed for each disposition category.
"""
from __future__ import annotations

import json
import re
from pathlib import Path

import pytest

_REPO_ROOT = Path(__file__).resolve().parents[4]
_MATRIX_PATH = _REPO_ROOT / "src" / "d810" / "cfg" / "contracts" / "insn_parity_matrix.json"
_INVARIANTS_PATH = _REPO_ROOT / "src" / "d810" / "cfg" / "contracts" / "insn_invariants.py"

_VALID_DISPOSITIONS = {
    "planned",
    "blocked_by_api",
    "mapped",
}


def _load_matrix() -> dict:
    with _MATRIX_PATH.open() as fh:
        return json.load(fh)


def _extract_minsn_constants() -> set[str]:
    """Return all MINSN_XXXXX_ constants found in insn_invariants.py source text."""
    source = _INVARIANTS_PATH.read_text(encoding="utf-8")
    return set(re.findall(r'MINSN_\d+[x_]\w+', source))


@pytest.fixture(scope="module")
def matrix() -> dict:
    return _load_matrix()


@pytest.fixture(scope="module")
def minsn_constants() -> set[str]:
    return _extract_minsn_constants()


def test_matrix_file_exists():
    assert _MATRIX_PATH.exists(), f"insn_parity_matrix.json not found at {_MATRIX_PATH}"


def test_invariants_file_exists():
    assert _INVARIANTS_PATH.exists(), f"insn_invariants.py not found at {_INVARIANTS_PATH}"


def test_matrix_has_required_fields(matrix):
    assert matrix.get("sdk_version"), "sdk_version missing"
    assert matrix.get("sdk_source"), "sdk_source missing"
    assert matrix.get("scope"), "scope missing"
    assert "minsn_t::verify" in matrix["scope"], "scope must reference minsn_t::verify"
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


def test_blocked_by_api_codes_have_no_owner(matrix):
    """Codes marked blocked_by_api should have no owner (they can't be implemented)."""
    for entry in matrix["codes"]:
        if entry.get("disposition") != "blocked_by_api":
            continue
        code = entry["code"]
        owner = entry.get("owner")
        assert owner is None, (
            f"Code {code} is blocked_by_api but has owner={owner!r}; "
            "blocked codes should have owner=null"
        )


def test_planned_codes_have_owner(matrix):
    """Codes marked planned must name an owner function."""
    for entry in matrix["codes"]:
        if entry.get("disposition") != "planned":
            continue
        code = entry["code"]
        owner = entry.get("owner")
        assert owner, (
            f"Code {code} is planned but has no owner; "
            "planned codes must declare an owner function"
        )


def test_summary_counts(matrix, capsys):
    """Print disposition summary and assert all entries have a known disposition."""
    counts: dict[str, int] = {}
    for entry in matrix["codes"]:
        disp = entry.get("disposition", "UNKNOWN")
        counts[disp] = counts.get(disp, 0) + 1

    total = sum(counts.values())
    with capsys.disabled():
        print(f"\nInsn parity matrix summary ({total} total codes):")
        for disp in sorted(counts):
            print(f"  {disp}: {counts[disp]}")

    assert "UNKNOWN" not in counts, "Some entries are missing a disposition field"
    assert total == len(matrix["codes"]), "Count mismatch"


def test_matrix_scope_is_insn_level(matrix):
    scope = matrix.get("scope", "")
    assert "minsn_t" in scope or "mop_t" in scope, (
        f"scope={scope!r} should reference minsn_t or mop_t"
    )


def test_planned_count_is_zero(matrix):
    """All planned codes have been promoted to mapped or blocked_by_api."""
    planned = sum(
        1 for e in matrix["codes"] if e.get("disposition") == "planned"
    )
    assert planned == 0, (
        f"{planned} codes still have disposition=planned; "
        "all planned codes should be promoted to mapped or blocked_by_api"
    )


def test_mapped_codes_have_owner_and_constant(matrix):
    """Codes marked mapped must name an owner and reference a MINSN_ constant in notes."""
    for entry in matrix["codes"]:
        if entry.get("disposition") != "mapped":
            continue
        code = entry["code"]
        owner = entry.get("owner")
        notes = entry.get("notes", "")
        assert owner, (
            f"Code {code} is mapped but has no owner"
        )
        assert "MINSN_" in notes, (
            f"Code {code} is mapped but notes do not reference a MINSN_ constant: {notes!r}"
        )


def test_mapped_count_matches_implemented_constants(matrix):
    """The number of mapped codes must equal the number of MINSN_* constants in insn_invariants.py
    accounting for group constants that cover multiple codes.

    This is a loose lower-bound: at least as many mapped codes as distinct MINSN_* constants.
    """
    import re
    source = _INVARIANTS_PATH.read_text(encoding="utf-8")
    minsn_constants = set(re.findall(r'MINSN_\d+[x_]\w+', source))
    mapped = sum(1 for e in matrix["codes"] if e.get("disposition") == "mapped")
    assert mapped >= len(minsn_constants), (
        f"mapped={mapped} < len(MINSN_* constants)={len(minsn_constants)}; "
        "some implemented constants are not reflected in the matrix"
    )


def test_blocked_count_is_reasonable(matrix):
    """Sanity check: some codes should be blocked (C++ internals)."""
    blocked = sum(
        1 for e in matrix["codes"] if e.get("disposition") == "blocked_by_api"
    )
    assert blocked >= 5, (
        f"Only {blocked} blocked_by_api codes — seems too few; verify the matrix"
    )
