"""Tests for concrete generic carrier fact families."""
from __future__ import annotations

import pytest

from d810.recon.facts.carrier import (
    CALL_RESULT_CARRIER_FACT_KIND,
    CARRIER_STORE_PROMOTION_FACT_KIND,
    EXPRESSION_CARRIER_FACT_KIND,
    INDUCTION_CARRIER_FACT_KIND,
    LIFECYCLE_PRODUCTION_PROVEN,
    LOCAL_STORAGE_SCALARIZATION_FACT_KIND,
    LOOP_PREDICATE_CARRIER_FACT_KIND,
    OBSERVABLE_STORE_FACT_KIND,
    SAME_CARRIER_ALIAS_FACT_KIND,
    SIDE_EFFECT_CORRIDOR_FACT_KIND,
    STATE_TRANSITION_CARRIER_FACT_KIND,
    STATE_VARIABLE_WRITE_FACT_KIND,
    TERMINAL_MATERIALIZATION_FACT_KIND,
    CALL_SIDE_EFFECT_ANCHOR_FACT_KIND,
    production_carrier_fact,
    project_carrier_fact_families,
)
from d810.recon.facts.model import FactObservation


def _fact(
    *,
    fact_id: str,
    kind: str,
    payload: dict[str, object],
    source_block: int | None = 10,
    source_ea: int | None = 0x180010000,
    confidence: float = 0.9,
) -> FactObservation:
    return FactObservation(
        fact_id=fact_id,
        kind=kind,
        semantic_key=f"{kind}:{fact_id}",
        maturity="MMAT_GLBOPT1",
        phase="pre_d810",
        confidence=confidence,
        source_block=source_block,
        source_ea=source_ea,
        block_fingerprint=f"blk[{source_block}].0:op_1",
        mop_signature=f"{kind}:signature",
        payload=payload,
        evidence=("synthetic evidence",),
    )


def test_hodur_and_ollvm_emit_same_observable_store_fact_family() -> None:
    hodur_byte_store = _fact(
        fact_id="hodur-byte-2",
        kind="TerminalByteEmitterFact",
        payload={
            "byte_index": 2,
            "destination_buffer_expression": "[ds:v51+2]",
            "insn_index": 3,
        },
        source_block=42,
        source_ea=0x180015005,
    )
    ollvm_output_store = _fact(
        fact_id="ollvm-output-store",
        kind="OllvmSemanticCarrierFact",
        payload={
            "role": "ARG_OUTPUT_STORE_CANDIDATE",
            "carrier_token": "%var_30",
            "instruction_index": 7,
            "instruction_ea": 0x18000F00D,
            "instruction_dstr": "stx [ds.4:%var_30.8], %var_88.4",
        },
        source_block=11,
        source_ea=0x18000F00D,
        confidence=0.78,
    )

    projected = project_carrier_fact_families((hodur_byte_store, ollvm_output_store))
    observable = [fact for fact in projected if fact.kind == OBSERVABLE_STORE_FACT_KIND]

    assert len(observable) == 2
    assert {
        fact.payload["producer_kinds"][0] for fact in observable
    } == {"TerminalByteEmitterFact", "OllvmSemanticCarrierFact"}
    assert all(production_carrier_fact(fact, OBSERVABLE_STORE_FACT_KIND) for fact in observable)
    assert all(fact.payload["lifecycle_status"] == LIFECYCLE_PRODUCTION_PROVEN for fact in observable)
    assert "capabilities" not in observable[0].payload


@pytest.mark.parametrize(
    ("kind", "payload", "expected_kind"),
    [
        (
            "InductionCarrierFact",
            {"dest_stkoff": 0x30, "step": 1, "insn_index": 2},
            INDUCTION_CARRIER_FACT_KIND,
        ),
        (
            "LoopCarrierFact",
            {
                "carrier_var_token": "%var_30",
                "predicate_instruction_index": 4,
                "classification": "LOOP_CARRIER_WRITER_OUTSIDE_SCC",
            },
            LOOP_PREDICATE_CARRIER_FACT_KIND,
        ),
        (
            "ReturnCarrierFact",
            {
                "return_slot_stkoff": 0x8,
                "carrier_class": "stack_identity_carrier",
                "insn_index": 5,
            },
            TERMINAL_MATERIALIZATION_FACT_KIND,
        ),
        (
            "ReturnFrontierFact",
            {
                "return_block": 99,
                "carrier_fact_ids": ["return-carrier-1"],
                "frontier_blocks": [70, 80],
            },
            TERMINAL_MATERIALIZATION_FACT_KIND,
        ),
        (
            "TerminalByteEmitterFact",
            {
                "destination_buffer_expression": "[ds:v51+2]",
                "byte_index": 2,
                "insn_index": 3,
            },
            OBSERVABLE_STORE_FACT_KIND,
        ),
        (
            "ByteEmitCorridorFact",
            {
                "destinations": ["[ds:v51+2]"],
                "member_fact_ids": ["byte-2"],
                "byte_indexes": [2],
            },
            SIDE_EFFECT_CORRIDOR_FACT_KIND,
        ),
        (
            "StateWriteAnchorFact",
            {
                "state_var_stkoff": 0x3C,
                "state_const_hex": "0x0000000042",
                "instruction_index": 6,
            },
            STATE_VARIABLE_WRITE_FACT_KIND,
        ),
        (
            "StateTransitionAnchorFact",
            {
                "dest_var_signature": "mop_S:0x3c:4",
                "source_state_const_hex": "0x00000001",
                "next_state_const_hex": "0x00000002",
                "instruction_index": 7,
            },
            STATE_TRANSITION_CARRIER_FACT_KIND,
        ),
        (
            "CallAnchorFact",
            {"call_target": "strncmp", "call_kind": "direct_call", "insn_index": 8},
            CALL_SIDE_EFFECT_ANCHOR_FACT_KIND,
        ),
    ],
)
def test_projects_existing_source_fact_families_to_generic_families(
    kind: str,
    payload: dict[str, object],
    expected_kind: str,
) -> None:
    concrete = _fact(fact_id=f"{kind}:1", kind=kind, payload=payload)

    (projected,) = project_carrier_fact_families((concrete,))

    assert projected.kind == expected_kind
    assert projected.payload["producer_fact_ids"][0] == concrete.fact_id
    assert projected.payload["expression_class"]
    assert projected.payload["observable_effect"] is not None
    assert projected.payload["source_identity"]["producer_kind"] == kind
    assert "capabilities" not in projected.payload


def test_unanchored_ollvm_oracle_fact_does_not_emit_generic_authority() -> None:
    ollvm_output_store = _fact(
        fact_id="ollvm-output-store",
        kind="OllvmSemanticCarrierFact",
        payload={
            "role": "ARG_OUTPUT_STORE_CANDIDATE",
            "carrier_token": "%var_30",
            "instruction_index": 7,
        },
        source_block=None,
        source_ea=None,
    )

    assert project_carrier_fact_families((ollvm_output_store,)) == ()


def test_exact_arg_and_local_store_candidates_emit_two_store_families() -> None:
    output_store = _fact(
        fact_id="ollvm-output-store",
        kind="OllvmSemanticCarrierFact",
        payload={
            "role": "LOCAL_WORKING_STORE_CANDIDATE",
            "carrier_token": "%var_390",
            "instruction_index": 7,
            "instruction_ea": 0x18000F00D,
            "instruction_dstr": "stx [ds.4:%var_390.8], %var_88.4",
        },
        source_block=11,
        source_ea=0x18000F00D,
        confidence=0.78,
    )

    projected = project_carrier_fact_families((output_store,))
    by_kind = {fact.kind: fact for fact in projected}

    assert OBSERVABLE_STORE_FACT_KIND in by_kind
    assert CARRIER_STORE_PROMOTION_FACT_KIND in by_kind
    assert production_carrier_fact(by_kind[OBSERVABLE_STORE_FACT_KIND], OBSERVABLE_STORE_FACT_KIND)
    assert production_carrier_fact(by_kind[CARRIER_STORE_PROMOTION_FACT_KIND], CARRIER_STORE_PROMOTION_FACT_KIND)
    assert by_kind[OBSERVABLE_STORE_FACT_KIND].payload["source_identity"]["source_ea_hex"] == "0x000000018000f00d"
    assert by_kind[CARRIER_STORE_PROMOTION_FACT_KIND].payload["details"]["proof_family"] == (
        "observable_output_store_carrier_promotion"
    )
    assert by_kind[OBSERVABLE_STORE_FACT_KIND].payload["anchor_locator"]["requires_live_revalidation"] is True
    assert by_kind[OBSERVABLE_STORE_FACT_KIND].payload["anchor_locator"]["instruction_text_sha1"]
    assert by_kind[OBSERVABLE_STORE_FACT_KIND].payload["storage_overlap_proof"]["partial_overlap"] is False


@pytest.mark.parametrize(
    "role",
    ("ARG_OUTPUT_STORE_CANDIDATE", "LOCAL_WORKING_STORE_CANDIDATE"),
)
def test_exact_arg_and_local_store_candidates_keep_carrier_store_promotion(
    role: str,
) -> None:
    output_store = _fact(
        fact_id=f"ollvm-store-{role}",
        kind="OllvmSemanticCarrierFact",
        payload={
            "role": role,
            "carrier_token": "%var_390",
            "instruction_index": 7,
            "instruction_ea": 0x18000F00D,
            "instruction_dstr": "stx [ds.4:%var_390.8], %var_88.4",
        },
        source_block=11,
        source_ea=0x18000F00D,
        confidence=0.78,
    )

    kinds = {fact.kind for fact in project_carrier_fact_families((output_store,))}

    assert OBSERVABLE_STORE_FACT_KIND in kinds
    assert CARRIER_STORE_PROMOTION_FACT_KIND in kinds


def test_ollvm_alias_expression_loop_and_store_proofs_emit_concrete_families() -> None:
    accumulator = _fact(
        fact_id="ollvm-accumulator",
        kind="OllvmSemanticCarrierFact",
        payload={
            "role": "ACCUMULATOR_CARRIER",
            "carrier_token": "%var_378",
            "instruction_index": 3,
            "instruction_ea": 0x18000F123,
            "instruction_dstr": "add %var_378.4, #5.4*%var_390.4, %var_378.4",
            "same_carrier_alias_proof": True,
            "multiply_add_base_token": "%var_18",
            "multiply_add_same_base_alias_tokens": ("%var_390",),
        },
        source_block=10,
        source_ea=0x18000F123,
    )
    loop_index = _fact(
        fact_id="ollvm-loop-index",
        kind="OllvmSemanticCarrierFact",
        payload={
            "role": "LOOP_INDEX_CARRIER",
            "carrier_token": "%var_398",
            "instruction_index": 4,
            "instruction_ea": 0x18000F200,
            "instruction_dstr": "setb [ds.2:%var_398.8].4, #0x64.4, %var_3A1.1",
        },
        source_block=12,
        source_ea=0x18000F200,
    )
    indirect_store = _fact(
        fact_id="ollvm-indirect-store",
        kind="OllvmSemanticCarrierFact",
        payload={
            "role": "INDIRECT_STORE_CANDIDATE",
            "carrier_token": "%var_390",
            "instruction_index": 5,
            "instruction_ea": 0x18000F300,
            "instruction_dstr": "stx [ds.4:%var_390.8], %var_90.4",
        },
        source_block=13,
        source_ea=0x18000F300,
    )

    kinds = {fact.kind for fact in project_carrier_fact_families((
        accumulator,
        loop_index,
        indirect_store,
    ))}

    assert EXPRESSION_CARRIER_FACT_KIND in kinds
    assert LOCAL_STORAGE_SCALARIZATION_FACT_KIND in kinds
    assert SAME_CARRIER_ALIAS_FACT_KIND in kinds
    assert LOOP_PREDICATE_CARRIER_FACT_KIND in kinds
    assert CARRIER_STORE_PROMOTION_FACT_KIND in kinds


def test_accumulator_without_local_base_does_not_emit_scalarization_authority() -> None:
    accumulator = _fact(
        fact_id="ollvm-accumulator-no-base",
        kind="OllvmSemanticCarrierFact",
        payload={
            "role": "ACCUMULATOR_CARRIER",
            "carrier_token": "%var_378",
            "instruction_index": 3,
            "instruction_ea": 0x18000F123,
            "instruction_opcode_name": "m_add",
            "instruction_dstr": "add %var_378.4, #5.4*%var_390.4, %var_378.4",
        },
        source_block=10,
        source_ea=0x18000F123,
    )

    projected = project_carrier_fact_families((accumulator,))
    kinds = {fact.kind for fact in projected}

    assert LOCAL_STORAGE_SCALARIZATION_FACT_KIND not in kinds
    assert EXPRESSION_CARRIER_FACT_KIND in kinds


def test_loop_index_carrier_does_not_authorize_local_scalarization() -> None:
    loop_index = _fact(
        fact_id="ollvm-loop-index",
        kind="OllvmSemanticCarrierFact",
        payload={
            "role": "LOOP_INDEX_CARRIER",
            "carrier_token": "%var_398",
            "local_base_token": "%var_398",
            "instruction_index": 4,
            "instruction_ea": 0x18000F200,
            "instruction_dstr": "setb [ds.2:%var_398.8].4, #0x64.4, %var_3A1.1",
        },
        source_block=12,
        source_ea=0x18000F200,
    )

    projected = project_carrier_fact_families((loop_index,))
    kinds = {fact.kind for fact in projected}

    assert LOOP_PREDICATE_CARRIER_FACT_KIND in kinds
    assert LOCAL_STORAGE_SCALARIZATION_FACT_KIND not in kinds


def test_accumulator_scalarization_authority_is_named_by_proof_family() -> None:
    accumulator = _fact(
        fact_id="ollvm-accumulator",
        kind="OllvmSemanticCarrierFact",
        payload={
            "role": "ACCUMULATOR_CARRIER",
            "carrier_token": "%var_378",
            "local_base_token": "%var_18",
            "instruction_index": 3,
            "instruction_ea": 0x18000F123,
            "instruction_opcode_name": "m_add",
            "instruction_dstr": "add %var_378.4, #5.4*%var_390.4, %var_378.4",
        },
        source_block=10,
        source_ea=0x18000F123,
    )

    projected = project_carrier_fact_families((accumulator,))
    scalarization = [
        fact for fact in projected
        if fact.kind == LOCAL_STORAGE_SCALARIZATION_FACT_KIND
    ]

    assert len(scalarization) == 1
    assert scalarization[0].payload["details"]["proof_family"] == (
        "local_expression_storage_scalarization"
    )
    assert scalarization[0].payload["storage_overlap_proof"]["base_token"] == "%var_18"
    assert scalarization[0].payload["anchor_locator"]["carrier_token"] == "%var_378"


def test_call_result_oracle_fact_becomes_concrete_call_result_family() -> None:
    compare = _fact(
        fact_id="ollvm-password-result",
        kind="OllvmSemanticCarrierFact",
        payload={
            "role": "PASSWORD_COMPARE_RESULT",
            "carrier_token": "%var_58",
            "instruction_index": 3,
            "instruction_ea": 0x18000F123,
            "instruction_dstr": "call secret_compare => __int64 .8, %var_58.4",
        },
        source_block=10,
        source_ea=0x18000F123,
    )

    (projected,) = project_carrier_fact_families((compare,))

    assert projected.kind == CALL_RESULT_CARRIER_FACT_KIND
    assert projected.payload["storage_identity"] == "%var_58"
    assert projected.payload["expression_class"] == "call_result"


def test_projection_is_idempotent_for_existing_generic_fact() -> None:
    source = _fact(
        fact_id="hodur-byte-2",
        kind="TerminalByteEmitterFact",
        payload={
            "byte_index": 2,
            "destination_buffer_expression": "[ds:v51+2]",
            "insn_index": 3,
        },
        source_block=42,
        source_ea=0x180015005,
    )
    (generic_fact,) = project_carrier_fact_families((source,))

    (projected_again,) = project_carrier_fact_families((generic_fact,))

    assert projected_again is generic_fact
