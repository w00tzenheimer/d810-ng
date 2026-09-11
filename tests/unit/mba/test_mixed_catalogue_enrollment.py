"""A mixed snapshot binds excluded rules without treating them as canonical."""

import pytest
import json

from d810.mba.certified_catalogue import build_certified_catalogue_snapshot
from d810.mba.dsl import DynamicConst
from d810.mba.rules.cst import CstSimplificationRule8
from d810.mba.rules.predicates import PredFFRule1
from d810.mba.rules.division import UnsignedMagicModulo3Rule


def snapshot():
    return build_certified_catalogue_snapshot(
        (CstSimplificationRule8(), PredFFRule1()),
        compiler_version='mixed-enrollment-regression',
        runtime_semantics_digest='a' * 64,
    )


def test_typed_constraint_and_dynamic_legacy_rule_form_authorizable_partition():
    result = snapshot()
    assert result.structural_authorizable
    assert [rule.name for rule in result.rules_in_declaration_order] == [
        'CstSimplificationRule8', 'PredFFRule1',
    ]
    for width in (8, 16, 32, 64):
        assert result.canonical_status_by_rule_width[(0, width)] == 'eligible'
        assert result.canonical_status_by_rule_width[(1, width)] == 'unsupported'
        assert (0, width) in result.canonical_templates_by_rule_width
        assert (1, width) not in result.canonical_templates_by_rule_width
    assert all(1 not in ids for ids in result.canonical_rule_ids_by_root_shape.values())


def test_typed_comparison_change_invalidates_partition_evidence(monkeypatch):
    baseline = snapshot()
    rule = CstSimplificationRule8
    monkeypatch.setattr(rule, 'CONSTRAINTS', [rule.CONSTRAINTS[0],
                       (rule.c_1 & ~rule.c_2) == rule.c_1])
    changed = snapshot()
    assert baseline.structural_authorizable and changed.structural_authorizable
    assert changed.fingerprint != baseline.fingerprint


@pytest.mark.parametrize('replacement', [
    DynamicConst('val_ff', lambda context: 0, size_from='x_0'),
    DynamicConst('val_ff', lambda context: 0, size_from='another_operand'),
])
def test_excluded_dynamic_semantics_remain_bound(monkeypatch, replacement):
    baseline = snapshot()
    monkeypatch.setattr(PredFFRule1, '_dsl_replacement', replacement)
    changed = snapshot()
    assert changed.structural_authorizable
    assert changed.fingerprint != baseline.fingerprint


def test_recursive_legacy_helper_is_fingerprinted_without_losing_exclusion():
    result = build_certified_catalogue_snapshot(
        (UnsignedMagicModulo3Rule(),), compiler_version='recursive-legacy-test',
        runtime_semantics_digest='a' * 64,
    )
    assert result.structural_authorizable
    assert set(result.canonical_status_by_rule_width.values()) == {'unsupported'}


def test_mutable_data_cycle_still_rejects_authorization():
    rule = PredFFRule1()
    cyclic = []
    cyclic.append(cyclic)
    rule.config = {'cyclic': cyclic}
    result = build_certified_catalogue_snapshot((rule,), compiler_version='data-cycle-test')
    assert not result.structural_authorizable


_RECURSIVE_LIMIT = 0


def _recursive_helper(value, step=1):
    return _recursive_helper(value - step) if value > _RECURSIVE_LIMIT else value


def _mutual_left(value):
    return _mutual_right(value - 1) if value else 0


def _mutual_right(value):
    return _mutual_left(value - 1) if value else 1


def function_payload(function):
    from d810.mba.certified_catalogue import _SemanticFingerprintState, _semantic_value
    state = _SemanticFingerprintState(set())
    result = _semantic_value(function, state)
    assert state.structural_authorizable
    assert not state.active_ids and not state.active_functions
    return json.dumps(result, sort_keys=True)


@pytest.mark.parametrize('function', [_recursive_helper, _mutual_left])
def test_recursive_function_payload_is_deterministic(function):
    first = function_payload(function)
    assert first == function_payload(function)
    assert 'function_backref' in first


def test_recursive_function_defaults_and_globals_remain_bound(monkeypatch):
    original = function_payload(_recursive_helper)
    monkeypatch.setattr(_recursive_helper, '__defaults__', (2,))
    changed_default = function_payload(_recursive_helper)
    assert changed_default != original
    monkeypatch.setitem(_recursive_helper.__globals__, '_RECURSIVE_LIMIT', 5)
    assert function_payload(_recursive_helper) != changed_default


def test_recursive_function_closure_value_remains_bound():
    def factory(limit):
        def recursive(value):
            return recursive(value - 1) if value > limit else value
        return recursive
    assert function_payload(factory(1)) != function_payload(factory(2))


def test_recursive_function_code_remains_bound(monkeypatch):
    original = function_payload(_recursive_helper)
    monkeypatch.setattr(_recursive_helper, '__code__', _mutual_right.__code__)
    assert function_payload(_recursive_helper) != original
