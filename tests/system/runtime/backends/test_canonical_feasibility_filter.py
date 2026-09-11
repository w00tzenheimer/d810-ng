from __future__ import annotations

from types import SimpleNamespace

import pytest

pytest.importorskip("ida_hexrays")

import d810.backends.mba.ida as ida_backend  # noqa: E402
from d810.backends.mba.ida import (  # noqa: E402
    IDAPatternAdapter,
    attach_selected_certified_catalogue_snapshot,
)
from d810.mba.ac_matching import prepare_canonical_template_facts  # noqa: E402
from d810.mba.canonical_pattern import compile_canonical_pattern  # noqa: E402
from d810.mba.dsl import Const, Var  # noqa: E402
from d810.mba.rules._base import VerifiableRule  # noqa: E402
from d810.mba.rules.bnot import BnotXor_FactorRule_1  # noqa: E402
from d810.mba.typed_term import TypedBvTerm  # noqa: E402
from d810.optimizers.microcode.instructions.pattern_matching import (  # noqa: E402
    handler,
)
from d810.optimizers.microcode.instructions.pattern_matching.handler import (  # noqa: E402
    PatternOptimizer,
    RulePatternInfo,
)
from tests.system.runtime.support.pattern_optimizer import (  # noqa: E402
    bare_pattern_optimizer,
)
from tests.system.runtime.backends.test_widened_boolean_island import (  # noqa: E402
    _materialize,
    _source_state,
    _witness_ast,
)


def _term(operation: str = "add") -> TypedBvTerm:
    return TypedBvTerm(
        operation,
        32,
        children=(
            TypedBvTerm(None, 32, leaf_key=("test", "x")),
            TypedBvTerm(None, 32, leaf_key=("test", "y")),
        ),
    )


def _template(pattern, *, declaration_index=0):
    return compile_canonical_pattern(
        SimpleNamespace(
            pattern=pattern,
            replacement=pattern,
            source_name=f"FeasibilityRule{declaration_index}",
            aliases=(),
            family="test",
            proof_widths=(32,),
            guarded=False,
            constraints=(),
        ),
        width=32,
        declaration_index=declaration_index,
    )


def _run(optimizer: PatternOptimizer, test_ast=None, instruction=None):
    return optimizer._try_matches(
        None,
        instruction
        or SimpleNamespace(d=SimpleNamespace(size=4), ea=0x401000),
        object() if test_ast is None else test_ast,
        allowed_rule_names=None,
        scheduled_rule_names=None,
        source_label="feasibility-test",
    )


def test_default_off_constructs_no_facts() -> None:
    calls = []

    class Rule:
        name = "control"
        maturities = (7,)
        canonical_fallback_comparisons = 0
        canonical_fallback_budget_exhausted = False

        def canonical_feasibility_template_facts(self, _width):
            raise AssertionError("control mode must not construct template facts")

        def match_structural_and_replace(self, *_args, **_kwargs):
            calls.append("matcher")
            return None

    rule = Rule()
    optimizer = bare_pattern_optimizer(
        _get_candidates=lambda _candidate: [],
        _use_canonical_fallback_feasibility_filter=False,
    )
    optimizer._iter_match_schedule = lambda *_args, **_kwargs: iter(
        [(None, rule, SimpleNamespace(term=_term()), 1)]
    )

    assert _run(optimizer) is None
    assert calls == ["matcher"]
    assert not hasattr(optimizer, "_canonical_fallback_feasibility_counts")


def test_filter_never_runs_before_successful_raw_match(monkeypatch) -> None:
    class RawRule:
        name = "raw-first"
        maturities = (7,)

        def check_pattern_and_replace(self, _pattern, _candidate):
            return "raw-replacement"

    raw = RawRule()
    optimizer = bare_pattern_optimizer(
        _get_candidates=lambda _candidate: [],
        _use_canonical_fallback_feasibility_filter=True,
    )
    optimizer._iter_match_schedule = lambda *_args, **_kwargs: iter(
        [(RulePatternInfo(raw, object()), None, None, 0)]
    )
    monkeypatch.setattr(
        handler,
        "prepare_canonical_candidate_facts",
        lambda _candidate: pytest.fail("raw success must bypass fallback facts"),
    )

    assert _run(optimizer) == "raw-replacement"


def test_fake_rules_cover_rejection_ordering_and_shared_budget_mechanics(
    monkeypatch,
) -> None:
    x, y = Var("x"), Var("y")
    impossible = prepare_canonical_template_facts(_template(x ^ y))
    survivor = prepare_canonical_template_facts(_template(x + y, declaration_index=1))
    events = []

    class Rule:
        canonical_fallback_enabled = True
        maturities = (7,)

        def __init__(self, name, facts, consumed, replacement=None):
            self.name = name
            self.facts = facts
            self.consumed = consumed
            self.replacement = replacement
            self.canonical_fallback_comparisons = 99
            self.canonical_fallback_budget_exhausted = True
            self.budgets = []

        def bind_structural_match_context(self, *_args):
            self.canonical_fallback_comparisons = 0
            self.canonical_fallback_budget_exhausted = False
            events.append((self.name, "bind"))

        def clear_match_context(self):
            events.append((self.name, "clear"))

        def canonical_feasibility_template_facts(self, _width):
            return self.facts, False

        def record_canonical_feasibility_rejection(self, **kwargs):
            assert self.canonical_fallback_comparisons == 0
            assert self.canonical_fallback_budget_exhausted is False
            events.append((self.name, "rejected", kwargs))

        def match_structural_and_replace(
            self, *_args, attempted_rule_count, comparison_budget, **_kwargs
        ):
            self.budgets.append((attempted_rule_count, comparison_budget))
            self.canonical_fallback_comparisons = self.consumed
            return self.replacement

    rejected = Rule("rejected", impossible, 240)
    proof_rejected = Rule("proof-rejected", survivor, 250)
    proof_accepted = Rule("proof-accepted", survivor, 6, "replacement")
    rules = (rejected, proof_rejected, proof_accepted)
    optimizer = bare_pattern_optimizer(
        _get_candidates=lambda _candidate: [],
        _use_canonical_fallback_feasibility_filter=True,
    )
    lowering = SimpleNamespace(term=_term())
    optimizer._iter_match_schedule = lambda *_args, **_kwargs: iter(
        (None, rule, lowering, len(rules)) for rule in rules
    )
    constructions = 0
    original_prepare = handler.prepare_canonical_candidate_facts

    def counted_prepare(candidate):
        nonlocal constructions
        constructions += 1
        return original_prepare(candidate)

    monkeypatch.setattr(handler, "prepare_canonical_candidate_facts", counted_prepare)

    assert _run(optimizer) == "replacement"
    assert constructions == 1
    assert rejected.budgets == []
    assert proof_rejected.budgets == [(1, 256)]
    assert proof_accepted.budgets == [(2, 6)]
    assert ("rejected", "clear") in events
    counts = optimizer.canonical_fallback_feasibility_counts
    assert counts["candidate_fact_constructions"] == 1
    assert counts["rejected_candidates"] == 1
    assert counts["surviving_candidates"] == 2


def _exercise_real_adapters_reclaiming_measured_budget(
    monkeypatch,
) -> None:
    """Filtering makes a real proven survivor reachable after a real refusal.

    The reduced cap is test policy derived from actual matcher work. Production's
    root cap remains 256; this test does not claim a natural 256-comparison case.
    """

    monkeypatch.setattr(VerifiableRule, "registry", dict(VerifiableRule.registry))
    y = Var("y")
    missing = Const("missing", 0x13579BDF)

    class ImpossibleBnotXorRule(VerifiableRule):
        PATTERN = missing ^ ~y
        REPLACEMENT = PATTERN

    class RefusedBnotXorRule(BnotXor_FactorRule_1):
        REPLACEMENT = Const("unsound_one", 1)

    def build_sequence():
        instruction, source = _materialize(
            _witness_ast("bnot-xor", predicate_register=56)
        )
        adapters = (
            IDAPatternAdapter(ImpossibleBnotXorRule()),
            IDAPatternAdapter(RefusedBnotXorRule()),
            IDAPatternAdapter(BnotXor_FactorRule_1()),
        )
        snapshot, _ = attach_selected_certified_catalogue_snapshot(adapters)
        for adapter in adapters:
            # These two test-local probes are not parity-authorized rules. The
            # shared snapshot still enforces the production root-bucket check.
            adapter._structural_matching_enabled = True
            adapter._attempt_destination_size = 4
            assert adapter._certified_catalogue_snapshot is snapshot
        lowering = adapters[-1].prepare_structural_candidate(
            source, destination_size=4
        )
        assert lowering is not None
        assert lowering.term is not None
        return instruction, source, adapters, lowering

    original_prove = ida_backend.prove_native_ast_equivalence
    proof_verdicts = []

    def recording_proof(original, replacement, *, width):
        verdict = original_prove(original, replacement, width=width)
        proof_verdicts.append(verdict)
        return verdict

    monkeypatch.setattr(
        ida_backend,
        "prove_native_ast_equivalence",
        recording_proof,
    )

    probe_instruction, probe_source, probe_adapters, probe_lowering = build_sequence()
    probe_source_state = _source_state(probe_source)
    probe_results = []
    probe_costs = []
    for attempted, adapter in enumerate(probe_adapters, start=1):
        probe_results.append(
            adapter.match_structural_and_replace(
                probe_source,
                bucket_size=len(probe_adapters),
                attempted_rule_count=attempted,
                comparison_budget=256,
                lowering=probe_lowering,
                lowering_provided=True,
            )
        )
        probe_costs.append(adapter.canonical_fallback_comparisons)

    impossible_cost, refusal_cost, survivor_cost = probe_costs
    assert probe_results[0] is None
    assert probe_results[1] is None
    assert probe_results[2] is not None
    assert min(probe_costs) > 0
    assert proof_verdicts == [False, True]
    assert _source_state(probe_source) == probe_source_state
    assert probe_instruction is not None

    # OFF spends the impossible miss and leaves the survivor one comparison
    # short. ON rejects that miss before the matcher and reaches real emission.
    local_budget = impossible_cost + refusal_cost + survivor_cost - 1
    assert local_budget < 256
    monkeypatch.setattr(
        handler,
        "_CANONICAL_FALLBACK_COMPARISON_BUDGET",
        local_budget,
    )

    mode_results = {}
    for filter_enabled in (False, True):
        instruction, source, adapters, lowering = build_sequence()
        source_state = _source_state(source)
        budgets = []
        proof_verdicts.clear()
        for adapter in adapters:
            original_match = adapter.match_structural_and_replace

            def recording_match(*args, _adapter=adapter, _match=original_match, **kwargs):
                budgets.append((_adapter.name, kwargs["comparison_budget"]))
                return _match(*args, **kwargs)

            monkeypatch.setattr(
                adapter,
                "match_structural_and_replace",
                recording_match,
            )

        optimizer = bare_pattern_optimizer(
            _get_candidates=lambda _candidate: [],
            _use_canonical_fallback_feasibility_filter=filter_enabled,
        )
        optimizer._iter_match_schedule = lambda *_args, **_kwargs: iter(
            (None, adapter, lowering, len(adapters)) for adapter in adapters
        )

        result = _run(optimizer, source, instruction)
        mode_results[filter_enabled] = (
            result,
            tuple(budgets),
            tuple(proof_verdicts),
            adapters,
            optimizer,
        )
        assert _source_state(source) == source_state

    off_result, off_budgets, off_proofs, off_adapters, _ = mode_results[False]
    assert off_result is None
    assert off_budgets == (
        (off_adapters[0].name, local_budget),
        (off_adapters[1].name, local_budget - impossible_cost),
        (off_adapters[2].name, survivor_cost - 1),
    )
    assert off_proofs == (False,)
    assert off_adapters[0].canonical_fallback_comparisons == impossible_cost
    assert off_adapters[1].canonical_fallback_comparisons == refusal_cost
    assert off_adapters[2].canonical_fallback_budget_exhausted is True

    on_result, on_budgets, on_proofs, on_adapters, on_optimizer = mode_results[True]
    assert on_result is not None
    assert on_budgets == (
        (on_adapters[1].name, local_budget),
        (on_adapters[2].name, local_budget - refusal_cost),
    )
    assert on_proofs == (False, True)
    assert on_adapters[0].canonical_fallback_comparisons == 0
    assert on_adapters[0]._canonical_fallback_stop_reason == "feasibility_rejected"
    assert on_adapters[0]._shadow_native_equivalence_verdict is None
    counts = on_optimizer.canonical_fallback_feasibility_counts
    assert counts["rejected_candidates"] == 1
    assert counts["surviving_candidates"] == 2


@pytest.mark.usefixtures("ida_database")
class TestCanonicalFeasibilityNativeProof:
    binary_name = "libobfuscated.dll"

    def test_real_adapters_reclaim_measured_budget_for_proof_gated_survivor(
        self, monkeypatch
    ) -> None:
        _exercise_real_adapters_reclaiming_measured_budget(monkeypatch)


def test_adapter_facts_follow_exact_template_occurrence() -> None:
    x, y = Var("x"), Var("y")
    adapter = IDAPatternAdapter(SimpleNamespace(name="facts", maturities=(7,)))
    first_template = _template(x + y)
    adapter._shadow_canonical_templates = {32: first_template}

    first, first_constructed = adapter.canonical_feasibility_template_facts(32)
    again, again_constructed = adapter.canonical_feasibility_template_facts(32)
    adapter._shadow_canonical_templates[32] = _template(x ^ y, declaration_index=1)
    replacement, replacement_constructed = adapter.canonical_feasibility_template_facts(
        32
    )

    assert first_constructed is True
    assert again_constructed is False
    assert again is first
    assert replacement_constructed is True
    assert replacement is not first


def test_snapshot_replacement_invalidates_template_facts(monkeypatch) -> None:
    x, y = Var("x"), Var("y")
    rule = SimpleNamespace(
        name="reload-facts",
        pattern=x + y,
        replacement=x,
        proof_widths=(32,),
        maturities=(7,),
    )
    adapter = IDAPatternAdapter(rule)
    adapter._certified_catalogue_snapshot = object()
    adapter._certified_catalogue_rule_id = 0
    adapter._canonical_feasibility_template_facts = {32: (object(), object())}
    monkeypatch.setattr(
        ida_backend,
        "_snapshot_rule_widths_are_structurally_eligible",
        lambda *_args: True,
    )

    adapter.attach_certified_catalogue_snapshot(
        SimpleNamespace(canonical_rule_ids_by_root_shape={}),
        0,
        object(),
        None,
        None,
        None,
    )

    assert adapter._canonical_feasibility_template_facts == {}


def test_rejection_publishes_current_reason_then_clears_context() -> None:
    x, y = Var("x"), Var("y")
    rule = SimpleNamespace(
        name="feasibility-rejected",
        description="feasibility-rejected",
        pattern=x ^ y,
        replacement=x,
        maturities=[7],
    )
    adapter = IDAPatternAdapter(rule)
    adapter._canonical_fallback_enabled = True
    adapter._structural_matching_enabled = True
    adapter._shadow_canonical_templates = {32: _template(x ^ y)}
    adapter.begin_provider_outcome_capture()
    optimizer = bare_pattern_optimizer(
        _get_candidates=lambda _candidate: [],
        _use_canonical_fallback_feasibility_filter=True,
    )
    optimizer._iter_match_schedule = lambda *_args, **_kwargs: iter(
        [(None, adapter, SimpleNamespace(term=_term()), 1)]
    )

    assert _run(optimizer) is None
    terminal = adapter.provider_outcomes()[-1]
    assert terminal.matcher is not None
    assert terminal.matcher.comparisons == 0
    assert terminal.matcher.stop_reason == "feasibility_rejected"
    assert terminal.metadata["structural_dispatch"] == {
        "bucket_size": 1,
        "attempted_rule_count": 0,
    }
    assert terminal.metadata["canonical_feasibility"] == {
        "predicate_comparisons": 1,
        "matcher_comparisons": 0,
    }
    assert adapter._attempt_input_ast is None
    assert adapter._attempt_instruction is None
    assert rule._current_blk is None
    assert rule._current_ins is None
    assert rule._runtime_constant_evaluator is None
