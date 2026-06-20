"""Native contract evidence token extraction tests."""
from __future__ import annotations

import pytest

from d810.analyses.value_flow.contract_evidence import (
    CONTRACT_EVIDENCE_TOKENS,
    ContractEvidenceToken,
    contract_evidence_payload,
    contract_evidence_tokens,
)
from d810.analyses.value_flow.observation import FactObservation
from d810.analyses.value_flow.projection import project_value_flow_facts


def _observation(
    *,
    kind: str = "GenericFact",
    payload=None,
    evidence=(),
) -> FactObservation:
    return FactObservation(
        fact_id="fact:1",
        kind=kind,
        semantic_key="semantic:1",
        maturity="MMAT_GLBOPT1",
        phase="pre_d810",
        confidence=1.0,
        payload=payload or {},
        evidence=evidence,
    )


def test_public_contract_evidence_vocabulary_matches_native_yaml_names():
    assert CONTRACT_EVIDENCE_TOKENS == frozenset(
        {
            "state_variable_writes",
            "dispatcher_predicates",
            "branch_targets",
            "ir.memory_def.candidate",
            "ir.branch_cond.candidate",
            "ir.induction_var.candidate",
        }
    )


def test_payload_contract_evidence_tokens_are_canonical_contract_tokens():
    observation = _observation(
        payload=contract_evidence_payload(
            ContractEvidenceToken.STATE_VARIABLE_WRITES,
            "dispatcher_predicates",
        ),
        evidence=("mov #1, %var_10.4",),
    )

    assert contract_evidence_tokens(observation) == frozenset(
        {"state_variable_writes", "dispatcher_predicates"}
    )


def test_contract_evidence_payload_rejects_unknown_tokens():
    with pytest.raises(ValueError, match="unknown contract evidence token"):
        contract_evidence_payload("typo_token")


def test_ollvm_candidate_contract_evidence_uses_canonical_public_names():
    observation = _observation(
        payload=contract_evidence_payload(
            ContractEvidenceToken.MEMORY_DEF_CANDIDATE,
            "ir.branch_cond.candidate",
            "ir.induction_var.candidate",
        ),
        evidence=("LOCAL_WORKING_STORE_CANDIDATE",),
    )

    assert contract_evidence_tokens(observation) == frozenset(
        {
            "ir.memory_def.candidate",
            "ir.branch_cond.candidate",
            "ir.induction_var.candidate",
        }
    )


def test_raw_diagnostic_evidence_is_not_a_contract_token():
    observation = _observation(evidence=("dispatcher_predicates", "mov #1, %var_10.4"))

    assert contract_evidence_tokens(observation) == frozenset()


def test_state_write_anchor_fact_provides_state_variable_write_token():
    observation = _observation(
        kind="StateWriteAnchorFact",
        evidence=("mov #1, %var_10.4",),
    )

    assert contract_evidence_tokens(observation) == frozenset(
        {"state_variable_writes"}
    )


def test_projected_state_write_fact_carries_explicit_contract_token_metadata():
    anchor = _observation(
        kind="StateWriteAnchorFact",
        payload={
            "state_var_stkoff": 0x10,
            "state_const_hex": "0x1",
            "instruction_index": 0,
        },
        evidence=("mov #1, %var_10.4",),
    )

    (projected,) = project_value_flow_facts((anchor,))

    assert projected.kind == "StateWriteFact"
    assert projected.payload["contract_evidence_tokens"] == [
        "state_variable_writes"
    ]
    assert contract_evidence_tokens(projected) == frozenset(
        {"state_variable_writes"}
    )
