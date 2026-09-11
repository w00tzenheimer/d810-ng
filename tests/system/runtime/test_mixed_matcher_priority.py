"""Cross-path scheduling must preserve the selected rule's priority."""

from collections import Counter
from types import SimpleNamespace

import pytest

from d810.optimizers.microcode.instructions.pattern_matching import handler
from d810.optimizers.microcode.instructions.pattern_matching.handler import (
    RulePatternInfo,
)
from d810.mba.typed_term import TypedBvTerm
from tests.system.runtime.support.pattern_optimizer import bare_pattern_optimizer

ROOT_BUDGET = handler._CANONICAL_FALLBACK_COMPARISON_BUDGET


def test_earlier_canonical_rule_precedes_later_raw_hit(monkeypatch):
    optimizer = bare_pattern_optimizer()
    attempts = []
    leaf = TypedBvTerm(None, 32, leaf_key=("mop", "x"))
    lowered = SimpleNamespace(term=TypedBvTerm("add", 32, children=(leaf, leaf)))

    class Earlier:
        name = "Earlier"
        maturities = [7]
        canonical_fallback_enabled = True
        uses_structural_matching = True
        canonical_fallback_declaration_index = 0

        def check_pattern_and_replace(self, *_args):
            attempts.append("earlier-raw-miss")
            return None

        def prepare_structural_candidate(self, *_args, **_kwargs):
            return lowered

        def match_structural_and_replace(self, *_args, **_kwargs):
            attempts.append("earlier-canonical-hit")
            return "earlier-result"

    class Later:
        name = "Later"
        maturities = [7]
        canonical_fallback_enabled = False
        canonical_fallback_declaration_index = 1

        def check_pattern_and_replace(self, *_args):
            attempts.append("later-raw-hit")
            return "later-result"

    earlier, later = Earlier(), Later()
    optimizer._rule_registration_order = {id(earlier): 0, id(later): 1}
    optimizer._canonical_fallback_registration_order = [earlier]
    optimizer._get_candidates = lambda _ast: [
        RulePatternInfo(earlier, object()),
        RulePatternInfo(later, object()),
    ]
    optimizer._canonical_fallback_rules_by_root_shape = {("add", 32, 2): [earlier]}
    optimizer._canonical_fallback_rules_for = lambda _shape: (earlier,)
    monkeypatch.setattr(handler, "format_minsn_t", lambda _value: "instruction")
    instruction = SimpleNamespace(
        d=SimpleNamespace(size=4), ea=0x401000, _print=lambda: "instruction"
    )
    result = optimizer._try_matches(
        None,
        instruction,
        object(),
        allowed_rule_names=None,
        scheduled_rule_names=None,
        source_label="mixed-priority",
    )
    assert result == "earlier-result"
    assert attempts == ["earlier-raw-miss", "earlier-canonical-hit"]


class ScheduledRule:
    """Boundary double; registration and handler scheduling remain production."""

    maturities = [7]
    pattern_candidates = ()
    canonical_fallback_root_shapes = ()

    def __init__(
        self, name, events, *, canonical=False, raw=None, fallback=None, comparisons=0
    ):
        self.name = name
        self.events = events
        self.canonical_fallback_enabled = canonical
        self.canonical_fallback_root_shapes = (("add", 32, 2),) if canonical else ()
        self.raw = raw
        self.fallback = fallback
        self.canonical_fallback_comparisons = comparisons

    def check_pattern_and_replace(self, _pattern, _candidate):
        self.events.append((self.name, "raw"))
        if isinstance(self.raw, Exception):
            raise self.raw
        return self.raw

    def prepare_structural_candidate(self, *_args, **_kwargs):
        self.events.append(("lower",))
        leaf = TypedBvTerm(None, 32, leaf_key=("mop", "x"))
        return SimpleNamespace(term=TypedBvTerm("add", 32, children=(leaf, leaf)))

    def record_attempt_error(self, _error):
        if self.canonical_fallback_enabled:
            self._last_provider_outcome = SimpleNamespace(
                status=SimpleNamespace(value="error")
            )

    def match_structural_and_replace(self, _candidate, **kwargs):
        self.events.append((self.name, "canonical", kwargs["comparison_budget"]))
        if isinstance(self.fallback, Exception):
            raise self.fallback
        return self.fallback


def _registered_optimizer(monkeypatch, rules, raw_rules=None):
    optimizer = bare_pattern_optimizer(
        rules=set(),
        maturities=[7],
        _generation=0,
        _canonical_fallback_rules_by_root_shape={},
        _canonical_fallback_feasibility_counts=Counter(),
    )
    for rule in rules:
        assert optimizer._add_rule_internal(rule)
    canonical = [rule for rule in rules if rule.canonical_fallback_enabled]
    optimizer._canonical_fallback_rules_by_root_shape = {("add", 32, 2): canonical}
    optimizer._get_candidates = lambda _ast: [
        RulePatternInfo(rule, object())
        for rule in (rules if raw_rules is None else raw_rules)
    ]
    monkeypatch.setattr(handler, "format_minsn_t", lambda _value: "instruction")
    return optimizer


def _match(optimizer):
    return optimizer._try_matches(
        None,
        SimpleNamespace(
            d=SimpleNamespace(size=4), ea=0x401000, _print=lambda: "instruction"
        ),
        object(),
        allowed_rule_names=None,
        scheduled_rule_names=None,
        source_label="mixed-schedule",
    )


def test_non_dsl_rule_keeps_registration_priority_and_raw_hit_is_lazy(monkeypatch):
    events = []
    # Names deliberately reverse lexical order, and the DSL-local index would
    # incorrectly put the canonical rule before the traditional rule.
    legacy = ScheduledRule("Zulu", events, raw="legacy-result")
    canonical = ScheduledRule(
        "Alpha", events, canonical=True, fallback="canonical-result"
    )
    canonical.canonical_fallback_declaration_index = 0
    optimizer = _registered_optimizer(monkeypatch, [legacy, canonical])
    assert _match(optimizer) == "legacy-result"
    assert events == [("Zulu", "raw")]


def test_canonical_rule_without_raw_shape_candidate_precedes_later_raw(monkeypatch):
    events = []
    first = ScheduledRule("first", events, canonical=True, fallback="first-result")
    later = ScheduledRule("later", events, raw="later-result")
    optimizer = _registered_optimizer(monkeypatch, [first, later], raw_rules=[later])
    assert _match(optimizer) == "first-result"
    assert events == [("lower",), ("first", "canonical", ROOT_BUDGET)]


def test_root_budget_and_lowering_are_shared_across_interleaved_rules(monkeypatch):
    events = []
    first = ScheduledRule("first", events, canonical=True, comparisons=7)
    middle = ScheduledRule("traditional", events)
    last = ScheduledRule("last", events, canonical=True, fallback="last-result")
    optimizer = _registered_optimizer(monkeypatch, [first, middle, last])
    assert _match(optimizer) == "last-result"
    assert events == [
        ("first", "raw"),
        ("lower",),
        ("first", "canonical", ROOT_BUDGET),
        ("traditional", "raw"),
        ("last", "raw"),
        ("last", "canonical", ROOT_BUDGET - 7),
    ]


@pytest.mark.parametrize("failure", ["raw", "canonical", "budget"])
def test_terminal_attempt_never_advances_to_later_raw_rule(monkeypatch, failure):
    events = []
    first = ScheduledRule(
        "first",
        events,
        canonical=True,
        raw=RuntimeError("raw failure") if failure == "raw" else None,
        fallback=RuntimeError("fallback failure") if failure == "canonical" else None,
        comparisons=ROOT_BUDGET if failure == "budget" else 0,
    )
    later = ScheduledRule("later", events, raw="must-not-run")
    optimizer = _registered_optimizer(monkeypatch, [first, later])
    assert _match(optimizer) is None
    assert not any(event[0] == "later" for event in events)
    assert sum(event == ("lower",) for event in events) == (failure != "raw")


def test_unregistered_mixed_rule_fails_visibly(monkeypatch):
    events = []
    rule = ScheduledRule("unregistered", events, canonical=True)
    optimizer = _registered_optimizer(monkeypatch, [rule])
    optimizer._rule_registration_order.clear()
    with pytest.raises(RuntimeError, match="registered rule order"):
        _match(optimizer)
    assert events == []


def test_raw_permutations_remain_ordered_before_same_rule_fallback(monkeypatch):
    events = []
    first = ScheduledRule("first", events, canonical=True, fallback="fallback-result")
    optimizer = _registered_optimizer(monkeypatch, [first], raw_rules=[first, first])
    assert _match(optimizer) == "fallback-result"
    assert events == [
        ("first", "raw"),
        ("first", "raw"),
        ("lower",),
        ("first", "canonical", ROOT_BUDGET),
    ]


def test_project_reload_rebuilds_order_for_same_rule_occurrences(monkeypatch):
    events = []
    first = ScheduledRule("first", events, canonical=True, fallback="first-result")
    second = ScheduledRule("second", events, raw="second-result")
    optimizer = _registered_optimizer(monkeypatch, [first, second])
    optimizer._provider_finalized_rules = set()
    optimizer.reset_rules()
    assert optimizer._add_rule_internal(second)
    assert optimizer._add_rule_internal(first)
    optimizer._canonical_fallback_rules_by_root_shape = {("add", 32, 2): [first]}
    assert _match(optimizer) == "second-result"
    assert events == [("second", "raw")]


def test_attempt_cleanup_and_callbacks_survive_cross_path_scheduling(monkeypatch):
    events = []
    rule = ScheduledRule("first", events, canonical=True, fallback="result")
    rule.bind_match_context = lambda *_args: events.append(("bind",))
    rule.clear_match_context = lambda: events.append(("clear",))
    rule.finalize_provider_observation = lambda _context, **kwargs: events.append(
        ("finalize", kwargs["reason"])
    )
    optimizer = _registered_optimizer(monkeypatch, [rule])
    optimizer._provider_finalized_rules = set()
    optimizer._run_later_callback = lambda _rule, _maturity: events.append(
        ("callback",)
    )
    assert _match(optimizer) == "result"
    assert optimizer._pending_replacement_rule is rule
    assert events == [
        ("bind",),
        ("first", "raw"),
        ("callback",),
        ("clear",),
        ("finalize", "provider_terminal"),
        ("lower",),
        ("bind",),
        ("first", "canonical", ROOT_BUDGET),
        ("callback",),
        ("clear",),
    ]


@pytest.mark.parametrize("storage_route", ["legacy", "indexed-fallback"])
@pytest.mark.parametrize("mixed", [False, True], ids=["legacy-order", "mixed-order"])
def test_mixed_order_explicitly_normalizes_overlapping_storage_candidates(
    monkeypatch, storage_route, mixed
):
    """Opt-in registration precedence is not historical trie traversal order."""
    events = []
    storage_calls = []
    first = ScheduledRule("A", events, raw="A-result")
    second = ScheduledRule("B", events, raw="B-result")
    unrelated = ScheduledRule("unrelated", events, canonical=True)
    optimizer = _registered_optimizer(monkeypatch, [first, second, unrelated])
    # Restore the real handler dispatcher; only its storage boundary is doubled.
    del optimizer._get_candidates
    optimizer._use_legacy_storage = storage_route == "legacy"
    optimizer._use_indexed_legacy_fallback = True

    def indexed_candidates(_subject):
        storage_calls.append("indexed")
        return []

    def legacy_candidates(_subject):
        storage_calls.append("legacy")
        # Signature/trie traversal can differ from A-before-B registration.
        return [RulePatternInfo(second, object()), RulePatternInfo(first, object())]

    optimizer._indexed_storage = SimpleNamespace(get_candidates=indexed_candidates)
    optimizer.pattern_storage = SimpleNamespace(
        get_matching_rule_pattern_info=legacy_candidates
    )
    optimizer._canonical_fallback_rules_by_root_shape = (
        {("sub", 32, 2): [unrelated]} if mixed else {}
    )
    optimizer._canonical_fallback_registration_order = [unrelated] if mixed else []

    assert _match(optimizer) == ("A-result" if mixed else "B-result")
    assert events == [("A" if mixed else "B", "raw")]
    assert storage_calls == (
        ["legacy"] if storage_route == "legacy" else ["indexed", "legacy"]
    )
