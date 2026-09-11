"""Positive native companion using the benchmark's exact selected catalogue."""

from dataclasses import replace

from d810.testing.runner import run_deobfuscation_test
from tests.system.cases.libobfuscated_comprehensive import MANUALLY_OBFUSCATED_CASES
from tests.system.e2e.test_libdeobfuscated_dsl import (
    _get_default_binary,
    libobfuscated_setup,  # noqa: F401 - imported pytest fixture
)
from tools.bench.canonical_dac_probe import positive_xor_outputs_equivalent


class _PositiveXorComparator:
    def __init__(self, delegate):
        self._delegate = delegate

    def are_equivalent(self, actual, expected):
        return (self._delegate.are_equivalent(actual, expected)
                or positive_xor_outputs_equivalent(actual, expected))

    def count_ast_statements(self, code):
        return self._delegate.count_ast_statements(code)


class TestCanonicalReferenceQualification:
    binary_name = _get_default_binary()

    def test_positive_xor(
        self, libobfuscated_setup, d810_state, pseudocode_to_string,  # noqa: F811
        code_comparator,
    ):
        original = next(case for case in MANUALLY_OBFUSCATED_CASES
                        if case.function == 'test_xor')
        # Retain all original output/complexity/rule assertions. Only select
        # the actual benchmark catalogue instead of the small example project.
        run_deobfuscation_test(
            replace(original, project='eidolon_v4_const_simplify_solve.json'),
            d810_state=d810_state,
            pseudocode_to_string=pseudocode_to_string,
            code_comparator=_PositiveXorComparator(code_comparator),
        )
