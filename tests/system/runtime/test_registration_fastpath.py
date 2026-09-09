"""Native import coverage for lazy pattern registration caches."""

from types import SimpleNamespace

import pytest

from d810.optimizers.microcode.instructions.pattern_matching.handler import PatternStorage


def pattern(signature):
    return SimpleNamespace(get_depth_signature=signature, get_pattern=lambda: "subject")


def test_registration_does_not_allocate_matching_caches():
    storage = PatternStorage()
    subject = pattern(lambda depth: ["add"] if depth == 1 else ["N"])
    first, second = object(), object()
    storage.add_pattern_for_rule(subject, first)
    storage.add_pattern_for_rule(subject, second)
    child = storage.next_layer_patterns[("add",)]
    assert storage._match_cache is None
    assert child._match_cache is None
    assert [entry.rule for entry in child.rule_resolved] == [first, second]


@pytest.mark.parametrize("signature", [[], ["N"], ["N", "N"]])
def test_terminal_signatures_preserve_registration_order(signature):
    storage = PatternStorage()
    subject = pattern(lambda _depth: signature)
    first, second = object(), object()
    storage.add_pattern_for_rule(subject, first)
    storage.add_pattern_for_rule(subject, second)
    assert [entry.rule for entry in storage.rule_resolved] == [first, second]
    assert not storage.next_layer_patterns


def test_lookup_allocates_once_and_registration_invalidates(monkeypatch):
    storage = PatternStorage()
    subject = pattern(lambda _depth: ["N"])
    calls = []

    def explore(*_args):
        calls.append(True)
        return list(storage.rule_resolved)

    monkeypatch.setattr(storage, "explore_one_level", explore)
    assert storage.get_matching_rule_pattern_info(subject) == []
    cache = storage._match_cache
    assert cache is not None
    assert storage.get_matching_rule_pattern_info(subject) == []
    assert len(calls) == 1
    rule = object()
    storage.add_pattern_for_rule(subject, rule)
    result = storage.get_matching_rule_pattern_info(subject)
    assert [entry.rule for entry in result] == [rule]
    result.clear()
    assert len(storage.get_matching_rule_pattern_info(subject)) == 1
    assert storage._match_cache is cache
    assert len(calls) == 2
