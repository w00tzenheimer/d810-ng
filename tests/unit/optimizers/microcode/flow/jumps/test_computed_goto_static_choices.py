"""Pure normalization tests for native conditional state-choice evidence."""

from d810.analyses.control_flow.native_compare import (
    normalize_register_compare_predicate,
    swapped_x86_condition_code,
)


def test_register_compare_normalizes_constant_left_operand() -> None:
    assert normalize_register_compare_predicate(
        left_mreg=8,
        left_values=frozenset({65}),
        right_mreg=12,
        right_values=None,
    ) == (12, 65, True)
    assert swapped_x86_condition_code(15) == 12


def test_register_compare_normalizes_constant_right_operand() -> None:
    assert normalize_register_compare_predicate(
        left_mreg=12,
        left_values=None,
        right_mreg=8,
        right_values=frozenset({48}),
    ) == (12, 48, False)


def test_register_compare_abstains_without_unique_constant_side() -> None:
    assert (
        normalize_register_compare_predicate(
            left_mreg=8,
            left_values=frozenset({1}),
            right_mreg=12,
            right_values=frozenset({2}),
        )
        is None
    )
    assert (
        normalize_register_compare_predicate(
            left_mreg=8,
            left_values=None,
            right_mreg=12,
            right_values=None,
        )
        is None
    )
