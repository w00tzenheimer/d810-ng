"""Unit tests for the behavioral semantic-equivalence oracle.

Pure Python (no IDA): drives the compile-and-diff oracle with hand-written
"AFTER pseudocode" strings so we can prove it does what ``must_change`` cannot --
catch a semantically WRONG deobfuscation.  The canonical regression is ticket
d81-c733: an OLLVM conditional dispatcher that d810 folded to
``return 3 * (a1 - 5) / 2`` (the whole ``if`` dropped) while still passing
``must_change``.  The oracle must reject exactly that.
"""
from __future__ import annotations

import pytest

from d810.testing.semantic_equivalence import (
    check_semantic_equivalence,
    extract_reference_body,
    find_c_compiler,
    pseudocode_to_c_function,
)

# The reference source function high_fan_in_pattern computes, for input>0:
#   ((2*input + 10) / 2)  and for input<=0: (3*(input-5) / 2).
_REFERENCE_SOURCE = """
int high_fan_in_pattern(int input)
{
    int state = 0, result = 0;
    while (state != 0xFF) {
        switch (state) {
            case 0: result += input; state = (input > 0) ? 1 : 2; break;
            case 1: result *= 2; state = 3; break;
            case 2: result -= 5; state = 4; break;
            case 3: result += 10; state = 5; break;
            case 4: result *= 3; state = 5; break;
            case 5: result /= 2; state = 6; break;
            case 6: result += 1; state = 7; break;
            case 7: result -= 1; state = 0xFF; break;
            default: state = 0xFF; break;
        }
    }
    return result;
}
"""

# The CORRECT deobfuscation: the if/else diamond that reconverges (what d810 now
# emits after the d81-c733 fix).  IDA renders it with `__fastcall`, an `a1`
# parameter, and casts.
_CORRECT_AFTER = """
__int64 __fastcall high_fan_in_pattern(int a1)
{
    int v2; // [rsp+Ch] [rbp-Ch]
    if ( a1 <= 0 )
        v2 = 3 * (a1 - 5);
    else
        v2 = 2 * a1 + 0xA;
    return (unsigned int)(v2 / 2);
}
"""

# The MISCOMPILE (the reverted d81-c733 fix): the conditional dropped, only the
# a1<=0 arm survived.  Passes `must_change` but is semantically wrong.
_MISCOMPILED_AFTER = """
__int64 __fastcall high_fan_in_pattern(int a1)
{
    return (unsigned int)(3 * (a1 - 5) / 2);
}
"""

requires_cc = pytest.mark.skipif(
    find_c_compiler() is None, reason="no host C compiler for semantic oracle"
)


def test_extract_reference_body_finds_function():
    body = extract_reference_body(_REFERENCE_SOURCE, "high_fan_in_pattern")
    assert body is not None
    assert body.startswith("int high_fan_in_pattern(int input)")
    assert body.rstrip().endswith("}")
    # brace-balanced extraction, not a greedy run-on
    assert body.count("{") == body.count("}")


def test_extract_reference_body_missing_returns_none():
    assert extract_reference_body(_REFERENCE_SOURCE, "no_such_function") is None


def test_pseudocode_to_c_function_normalizes_signature_and_param():
    c = pseudocode_to_c_function(_CORRECT_AFTER, "high_fan_in_pattern")
    assert "unsigned deob(int input)" in c
    assert "__fastcall" not in c
    assert "a1" not in c  # the parameter was renamed to `input`
    assert "input" in c


@requires_cc
def test_oracle_accepts_correct_deobfuscation():
    ok, detail = check_semantic_equivalence(
        _CORRECT_AFTER, "high_fan_in_pattern", _REFERENCE_SOURCE
    )
    assert ok is True, detail
    assert "SEMANTIC_OK" in detail


@requires_cc
def test_oracle_rejects_the_d81_c733_miscompile():
    # The whole point: `must_change` accepted this; the oracle must not.
    ok, detail = check_semantic_equivalence(
        _MISCOMPILED_AFTER, "high_fan_in_pattern", _REFERENCE_SOURCE
    )
    assert ok is False, f"oracle wrongly accepted the miscompile: {detail}"
    assert "SEMANTIC_FAIL" in detail
    assert "MISMATCH" in detail


@requires_cc
def test_oracle_reports_missing_reference_as_failure_not_skip():
    ok, detail = check_semantic_equivalence(
        _CORRECT_AFTER, "not_in_source", _REFERENCE_SOURCE
    )
    assert ok is False
    assert "not found" in detail


def test_oracle_signals_unavailable_when_no_compiler():
    ok, detail = check_semantic_equivalence(
        _CORRECT_AFTER, "high_fan_in_pattern", _REFERENCE_SOURCE, compiler=None
    ) if find_c_compiler() is None else (None, "skipped: compiler present")
    if find_c_compiler() is None:
        assert ok is None
        assert "no C compiler" in detail
    else:
        pytest.skip("compiler present; unavailable path exercised only without one")
