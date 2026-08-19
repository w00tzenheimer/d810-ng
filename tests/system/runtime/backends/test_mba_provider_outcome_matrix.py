"""Runtime matrix for one outcome per MBA provider attempt.

These checks exercise the native adapter boundaries but deliberately never
apply a replacement.  Outcome publication must therefore be independent of
the rule-fired statistics path.
"""

from __future__ import annotations

from types import SimpleNamespace

import ida_hexrays
import pytest

from d810.mba.egraph_contracts import (
    EgraphExtractionReceipt,
    EgraphSkipReason,
)
from d810.backends.mba.ida import IDAPatternAdapter
from d810.mba.provider_outcome import ProviderOutcomeStatus
from d810.optimizers.microcode.instructions.chain.handler import (
    ChainSimplificationRule,
)
from d810.optimizers.microcode.instructions.chain import handler as chain_handler
from d810.optimizers.microcode.instructions.egraph.egglog_handler import (
    EgglogOptimizer,
)


def test_egglog_attempt_matrix_retains_one_final_row_per_skip_or_proof_result() -> None:
    handler = EgglogOptimizer()
    handler.begin_provider_outcome_capture()
    receipts = (
        EgraphExtractionReceipt(skip_reason=EgraphSkipReason.RUNTIME_UNAVAILABLE),
        EgraphExtractionReceipt(skip_reason=EgraphSkipReason.TIME_BUDGET),
        EgraphExtractionReceipt(skip_reason=EgraphSkipReason.PROOF_FAILED),
        EgraphExtractionReceipt(input_cost=(4, 7), extracted_cost=(4, 7)),
    )

    for receipt in receipts:
        handler._begin_provider_attempt()
        handler._record_extraction_receipt(receipt)

    assert [outcome.status for outcome in handler.provider_outcomes()] == [
        ProviderOutcomeStatus.UNAVAILABLE,
        ProviderOutcomeStatus.OVER_BUDGET,
        ProviderOutcomeStatus.PROOF_FAILED,
        ProviderOutcomeStatus.UNCHANGED,
    ]

    handler._begin_provider_attempt()
    handler._record_extraction_receipt(
        EgraphExtractionReceipt(input_cost=(4, 7), extracted_cost=(2, 3))
    )
    handler._record_extraction_receipt(
        EgraphExtractionReceipt(skip_reason=EgraphSkipReason.PROOF_FAILED)
    )
    assert len(handler.provider_outcomes()) == 5
    assert handler.provider_outcomes()[-1].status is ProviderOutcomeStatus.PROOF_FAILED


def test_egglog_candidate_is_only_applied_after_outer_mutation_acceptance() -> None:
    handler = EgglogOptimizer()
    handler.begin_provider_outcome_capture()
    handler._begin_provider_attempt()
    handler._record_extraction_receipt(
        EgraphExtractionReceipt(input_cost=(4, 7), extracted_cost=(2, 3))
    )

    assert handler.provider_outcomes()[-1].status is ProviderOutcomeStatus.IMPROVED

    handler.record_mutation_accepted()

    assert handler.provider_outcomes()[-1].status is ProviderOutcomeStatus.APPLIED


def test_direct_catalogue_nonmatch_is_published_without_rule_fired_statistics(
    monkeypatch,
) -> None:
    class Rule:
        name = "direct"
        CANONICAL_NAME = "direct"
        ALIASES = ()

    adapter = IDAPatternAdapter(Rule())
    adapter.begin_provider_outcome_capture()
    input_ast = SimpleNamespace(is_node=lambda: False)
    monkeypatch.setattr(
        "d810.backends.mba.ida.minsn_to_ast", lambda _instruction: input_ast
    )
    monkeypatch.setattr(adapter, "_profile_fingerprint", lambda _ast: "direct-island")
    instruction = SimpleNamespace(d=SimpleNamespace(size=4))

    adapter.bind_match_context(None, instruction)
    adapter.clear_match_context()

    assert [outcome.status for outcome in adapter.provider_outcomes()] == [
        ProviderOutcomeStatus.UNCHANGED
    ]
    assert adapter.provider_outcomes()[0].fingerprint == "direct-island"


def test_arithmetic_chain_arity_follows_add_sub_and_neg_flattening() -> None:
    def leaf() -> SimpleNamespace:
        return SimpleNamespace(t=-1)

    nested_subtraction = SimpleNamespace(
        t=ida_hexrays.mop_d,
        d=SimpleNamespace(opcode=ida_hexrays.m_sub, l=leaf(), r=leaf()),
    )
    instruction = SimpleNamespace(l=leaf(), r=nested_subtraction)

    assert ChainSimplificationRule._flattened_arity(instruction, ida_hexrays.m_add) == 3


def test_structural_chain_nonmatch_is_an_explicit_provider_row(monkeypatch) -> None:
    class Rule(ChainSimplificationRule):
        def check_and_replace(self, blk, ins):
            del blk, ins
            return None

    rule = Rule()
    rule.begin_provider_outcome_capture()
    instruction = SimpleNamespace(
        d=SimpleNamespace(size=4),
        l=SimpleNamespace(t=-1),
        r=SimpleNamespace(t=-1),
    )
    profile = SimpleNamespace(
        fingerprint="chain-island",
        operator_count=1,
        total_node_count=3,
    )
    monkeypatch.setattr(rule, "_read_native_chain_profile", lambda _ins: profile)

    rule._begin_chain_attempt()
    rule._publish_chain_result(instruction, None, opcode=ida_hexrays.m_add)

    outcome = rule.provider_outcomes()[0]
    assert outcome.status is ProviderOutcomeStatus.UNCHANGED
    assert outcome.fingerprint == "chain-island"
    assert outcome.metadata["rules_applied"] == 0


def test_structural_chain_observation_reads_the_shared_native_view(monkeypatch) -> None:
    class Rule(ChainSimplificationRule):
        def check_and_replace(self, blk, ins):
            del blk, ins
            return None

    rule = Rule()
    rule.begin_provider_outcome_capture()
    instruction = SimpleNamespace(
        d=SimpleNamespace(size=4),
        l=SimpleNamespace(t=-1),
        r=SimpleNamespace(t=-1),
    )
    profile = SimpleNamespace(
        fingerprint="native-chain-island",
        operator_count=2,
        total_node_count=5,
    )
    direct_reads: list[tuple[object, int]] = []

    class NativeView:
        @classmethod
        def from_instruction(cls, ins, *, destination_size):
            direct_reads.append((ins, destination_size))
            return SimpleNamespace(view=object(), profile=profile)

    monkeypatch.setattr(chain_handler, "NativeMbaTermView", NativeView)
    assert not hasattr(chain_handler, "minsn_to_ast")

    rule._begin_chain_attempt()
    rule._publish_chain_result(instruction, None, opcode=ida_hexrays.m_add)

    outcome = rule.provider_outcomes()[0]
    assert direct_reads == [(instruction, 4)]
    assert outcome.fingerprint == "native-chain-island"
    assert outcome.input_cost == (2, 5)


def test_structural_chain_candidate_is_only_applied_after_outer_mutation_acceptance(
    monkeypatch,
) -> None:
    class Rule(ChainSimplificationRule):
        def check_and_replace(self, blk, ins):
            del blk, ins
            return None

    rule = Rule()
    rule.begin_provider_outcome_capture()
    instruction = SimpleNamespace(
        d=SimpleNamespace(size=4),
        l=SimpleNamespace(t=-1),
        r=SimpleNamespace(t=-1),
    )
    profile = SimpleNamespace(
        fingerprint="chain-island",
        operator_count=2,
        total_node_count=4,
    )
    monkeypatch.setattr(rule, "_read_native_chain_profile", lambda _ins: profile)

    rule._begin_chain_attempt()
    rule._publish_chain_result(instruction, instruction, opcode=ida_hexrays.m_add)
    assert rule.provider_outcomes()[-1].status is ProviderOutcomeStatus.IMPROVED

    rule.record_mutation_accepted()
    assert rule.provider_outcomes()[-1].status is ProviderOutcomeStatus.APPLIED


def test_structural_chain_runtime_error_retains_exact_profile_and_one_error_row(
    monkeypatch,
) -> None:
    class Rule(ChainSimplificationRule):
        def check_and_replace(self, blk, ins):
            del blk, ins
            return None

    rule = Rule()
    rule.begin_provider_outcome_capture()
    instruction = SimpleNamespace(d=SimpleNamespace(size=4))
    profile = SimpleNamespace(
        fingerprint="chain-exact-island",
        operator_count=1,
        total_node_count=3,
    )
    monkeypatch.setattr(rule, "_read_native_chain_profile", lambda _ins: profile)

    rule._begin_chain_attempt()
    with pytest.raises(RuntimeError, match="chain failure"):
        rule._run_chain_attempt(
            instruction,
            opcode=ida_hexrays.m_add,
            simplify=lambda: (_ for _ in ()).throw(RuntimeError("chain failure")),
        )

    assert len(rule.provider_outcomes()) == 1
    outcome = rule.provider_outcomes()[0]
    assert outcome.status is ProviderOutcomeStatus.ERROR
    assert outcome.fingerprint == "chain-exact-island"
    assert outcome.refusal_reason == "RuntimeError"
