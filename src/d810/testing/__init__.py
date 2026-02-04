"""D810 Testing Framework.

This package provides a data-driven testing framework for deobfuscation tests.
Instead of writing repetitive test code, tests are defined as dataclasses
that specify inputs, expected outputs, and assertions.

Example usage::

    from d810.testing import DeobfuscationCase, run_deobfuscation_test

    CASES = [
        DeobfuscationCase(
            function="test_chained_add",
            obfuscated_contains=["0xFFFFFFEF"],
            expected_code='''
                __int64 __fastcall test_chained_add(__int64 a1) {
                    return 2 * a1[1] + 0x33;
                }
            ''',
            required_rules=["ArithmeticChain"],
        ),
    ]

    @pytest.mark.parametrize("case", CASES, ids=lambda c: c.function)
    def test_deobfuscation(case, d810_state, ...):
        run_deobfuscation_test(case, d810_state, ...)
"""

from .cases import DeobfuscationCase, BinaryOverride
from .runner import run_deobfuscation_test
from .assertions import (
    assert_contains,
    assert_not_contains,
    assert_code_equivalent,
    assert_rules_fired,
)

__all__ = [
    "DeobfuscationCase",
    "BinaryOverride",
    "run_deobfuscation_test",
    "assert_contains",
    "assert_not_contains",
    "assert_code_equivalent",
    "assert_rules_fired",
]
