"""Tests for concrete value-flow fact families."""
from __future__ import annotations

import pytest

from d810.analyses.value_flow import (
    CALL_RETURN_VALUE_FACT_TYPE,
    SCALAR_PROMOTION_FACT_TYPE,
    SYMBOLIC_EXPRESSION_FACT_TYPE,
    INDUCTION_VARIABLE_FACT_TYPE,
    LIFECYCLE_PRODUCTION_PROVEN,
    SCALAR_REPLACEMENT_FACT_TYPE,
    LOOP_PREDICATE_VALUE_FACT_TYPE,
    MEMORY_PHI_FACT_TYPE,
    MEMORY_USE_FACT_TYPE,
    MAY_ALIAS_FACT_TYPE,
    OBSERVABLE_MEMORY_DEF_FACT_TYPE,
    OBSERVABLE_OUTPUT_FACT_TYPE,
    POINTS_TO_FACT_TYPE,
    RETURN_VALUE_FACT_TYPE,
    MUST_ALIAS_FACT_TYPE,
    EFFECT_PATH_FACT_TYPE,
    STATE_TRANSITION_FACT_TYPE,
    STATE_WRITE_FACT_TYPE,
    MATERIALIZATION_POINT_FACT_TYPE,
    CALL_EFFECT_SUMMARY_FACT_TYPE,
    production_value_flow_fact,
    project_value_flow_facts,
)
from d810.families.state_machine_cff.ollvm_carrier_profile import (
    project_ollvm_value_flow_evidence,
)
from d810.analyses.value_flow.model import FactObservation


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
        kind="OllvmValueFlowEvidence",
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

    projected = (
        *project_value_flow_facts((hodur_byte_store,)),
        *project_ollvm_value_flow_evidence((ollvm_output_store,)),
    )
    observable = [fact for fact in projected if fact.kind == OBSERVABLE_MEMORY_DEF_FACT_TYPE]

    assert len(observable) == 2
    assert {
        fact.payload["producer_kinds"][0] for fact in observable
    } == {"TerminalByteEmitterFact", "OllvmValueFlowEvidence"}
    assert all(production_value_flow_fact(fact, OBSERVABLE_MEMORY_DEF_FACT_TYPE) for fact in observable)
    assert all(fact.payload["lifecycle_status"] == LIFECYCLE_PRODUCTION_PROVEN for fact in observable)
    assert "capabilities" not in observable[0].payload


@pytest.mark.parametrize(
    ("kind", "payload", "expected_kinds"),
    [
        (
            "InductionCarrierFact",
            {"dest_stkoff": 0x30, "step": 1, "insn_index": 2},
            {INDUCTION_VARIABLE_FACT_TYPE},
        ),
        (
            "LoopCarrierFact",
            {
                "carrier_var_token": "%var_30",
                "predicate_instruction_index": 4,
                "classification": "LOOP_CARRIER_WRITER_OUTSIDE_SCC",
            },
            {LOOP_PREDICATE_VALUE_FACT_TYPE},
        ),
        (
            "ReturnCarrierFact",
            {
                "return_slot_stkoff": 0x8,
                "carrier_class": "stack_identity_carrier",
                "insn_index": 5,
                "source_signature": "%var_20.8",
                "upstream_writer_block_serial": 17,
                "upstream_writer_insn_index": 2,
            },
            {MATERIALIZATION_POINT_FACT_TYPE, MEMORY_USE_FACT_TYPE, RETURN_VALUE_FACT_TYPE},
        ),
        (
            "ReturnFrontierFact",
            {
                "return_block": 99,
                "carrier_fact_ids": ["return-carrier-1"],
                "frontier_blocks": [70, 80],
                "writer_blocks": [55, 56],
            },
            {MATERIALIZATION_POINT_FACT_TYPE, MEMORY_PHI_FACT_TYPE},
        ),
        (
            "TerminalByteEmitterFact",
            {
                "destination_buffer_expression": "[ds:v51+2]",
                "byte_index": 2,
                "insn_index": 3,
            },
            {OBSERVABLE_MEMORY_DEF_FACT_TYPE, POINTS_TO_FACT_TYPE, OBSERVABLE_OUTPUT_FACT_TYPE},
        ),
        (
            "ByteEmitCorridorFact",
            {
                "destinations": ["[ds:v51+2]"],
                "member_fact_ids": ["byte-2"],
                "byte_indexes": [2],
            },
            {EFFECT_PATH_FACT_TYPE},
        ),
        (
            "StateWriteAnchorFact",
            {
                "state_var_stkoff": 0x3C,
                "state_const_hex": "0x0000000042",
                "instruction_index": 6,
            },
            {STATE_WRITE_FACT_TYPE},
        ),
        (
            "StateTransitionAnchorFact",
            {
                "dest_var_signature": "mop_S:0x3c:4",
                "source_state_const_hex": "0x00000001",
                "next_state_const_hex": "0x00000002",
                "instruction_index": 7,
            },
            {STATE_TRANSITION_FACT_TYPE},
        ),
        (
            "CallAnchorFact",
            {"call_target": "strncmp", "call_kind": "direct_call", "insn_index": 8},
            {CALL_EFFECT_SUMMARY_FACT_TYPE},
        ),
    ],
)
def test_projects_existing_source_fact_families_to_generic_families(
    kind: str,
    payload: dict[str, object],
    expected_kinds: set[str],
) -> None:
    concrete = _fact(fact_id=f"{kind}:1", kind=kind, payload=payload)

    projected = project_value_flow_facts((concrete,))
    projected_by_kind = {fact.kind: fact for fact in projected}

    assert expected_kinds <= set(projected_by_kind)
    for projected_fact in projected_by_kind.values():
        assert projected_fact.payload["producer_fact_ids"][0] == concrete.fact_id
        assert projected_fact.payload["expression_class"]
        assert projected_fact.payload["observable_effect"] is not None
        assert projected_fact.payload["source_identity"]["producer_kind"] == kind
        assert "capabilities" not in projected_fact.payload


def test_hodur_return_and_byte_evidence_project_to_standard_value_flow_families() -> None:
    """Hodur-backed producers already supply MemoryUse/Phi/PointsTo/ReturnValue."""

    return_slot = _fact(
        fact_id="return-carrier",
        kind="ReturnCarrierFact",
        payload={
            "return_slot_stkoff": 0x8,
            "carrier_class": "stack_identity_carrier",
            "source_signature": "%var_20.8",
            "upstream_writer_block_serial": 17,
            "upstream_writer_insn_index": 2,
        },
    )
    return_frontier = _fact(
        fact_id="return-frontier",
        kind="ReturnFrontierFact",
        payload={
            "return_block": 99,
            "carrier_fact_ids": ["return-carrier"],
            "frontier_blocks": [70, 80],
            "writer_blocks": [55, 56],
        },
    )
    byte_emit = _fact(
        fact_id="byte-emit",
        kind="TerminalByteEmitterFact",
        payload={
            "destination_buffer_expression": "[ds:v51+2]",
            "byte_index": 2,
            "insn_index": 3,
        },
    )

    projected = project_value_flow_facts((return_slot, return_frontier, byte_emit))
    kinds = {fact.kind for fact in projected}

    assert MEMORY_USE_FACT_TYPE in kinds
    assert MEMORY_PHI_FACT_TYPE in kinds
    assert POINTS_TO_FACT_TYPE in kinds
    assert RETURN_VALUE_FACT_TYPE in kinds
    assert OBSERVABLE_OUTPUT_FACT_TYPE in kinds


def test_generic_projection_ignores_raw_ollvm_profile_evidence() -> None:
    ollvm_output_store = _fact(
        fact_id="ollvm-output-store",
        kind="OllvmValueFlowEvidence",
        payload={
            "role": "ARG_OUTPUT_STORE_CANDIDATE",
            "carrier_token": "%var_30",
            "instruction_index": 7,
            "instruction_ea": 0x18000F00D,
            "instruction_dstr": "stx [ds.4:%var_30.8], %var_88.4",
        },
        source_block=11,
        source_ea=0x18000F00D,
    )

    assert project_value_flow_facts((ollvm_output_store,)) == ()


def test_unanchored_ollvm_oracle_fact_does_not_emit_profile_authority() -> None:
    ollvm_output_store = _fact(
        fact_id="ollvm-output-store",
        kind="OllvmValueFlowEvidence",
        payload={
            "role": "ARG_OUTPUT_STORE_CANDIDATE",
            "carrier_token": "%var_30",
            "instruction_index": 7,
        },
        source_block=None,
        source_ea=None,
    )

    assert project_ollvm_value_flow_evidence((ollvm_output_store,)) == ()


def test_exact_arg_and_local_store_candidates_emit_two_store_families() -> None:
    output_store = _fact(
        fact_id="ollvm-output-store",
        kind="OllvmValueFlowEvidence",
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

    projected = project_ollvm_value_flow_evidence((output_store,))
    by_kind = {fact.kind: fact for fact in projected}

    assert OBSERVABLE_MEMORY_DEF_FACT_TYPE in by_kind
    assert SCALAR_PROMOTION_FACT_TYPE in by_kind
    assert OBSERVABLE_OUTPUT_FACT_TYPE in by_kind
    assert production_value_flow_fact(by_kind[OBSERVABLE_MEMORY_DEF_FACT_TYPE], OBSERVABLE_MEMORY_DEF_FACT_TYPE)
    assert production_value_flow_fact(by_kind[SCALAR_PROMOTION_FACT_TYPE], SCALAR_PROMOTION_FACT_TYPE)
    assert production_value_flow_fact(by_kind[OBSERVABLE_OUTPUT_FACT_TYPE], OBSERVABLE_OUTPUT_FACT_TYPE)
    assert by_kind[OBSERVABLE_MEMORY_DEF_FACT_TYPE].payload["source_identity"]["source_ea_hex"] == "0x000000018000f00d"
    assert by_kind[SCALAR_PROMOTION_FACT_TYPE].payload["details"]["proof_family"] == (
        "observable_output_store_carrier_promotion"
    )
    assert by_kind[OBSERVABLE_OUTPUT_FACT_TYPE].payload["observable_effect"] == "output_store"
    assert by_kind[OBSERVABLE_MEMORY_DEF_FACT_TYPE].payload["anchor_locator"]["requires_live_revalidation"] is True
    assert by_kind[OBSERVABLE_MEMORY_DEF_FACT_TYPE].payload["anchor_locator"]["instruction_text_sha1"]
    assert by_kind[OBSERVABLE_MEMORY_DEF_FACT_TYPE].payload["storage_overlap_proof"]["partial_overlap"] is False


@pytest.mark.parametrize(
    "role",
    ("ARG_OUTPUT_STORE_CANDIDATE", "LOCAL_WORKING_STORE_CANDIDATE"),
)
def test_exact_arg_and_local_store_candidates_keep_carrier_store_promotion(
    role: str,
) -> None:
    output_store = _fact(
        fact_id=f"ollvm-store-{role}",
        kind="OllvmValueFlowEvidence",
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

    kinds = {fact.kind for fact in project_ollvm_value_flow_evidence((output_store,))}

    assert OBSERVABLE_MEMORY_DEF_FACT_TYPE in kinds
    assert SCALAR_PROMOTION_FACT_TYPE in kinds
    assert OBSERVABLE_OUTPUT_FACT_TYPE in kinds


def test_ollvm_alias_expression_loop_and_store_proofs_emit_concrete_families() -> None:
    accumulator = _fact(
        fact_id="ollvm-accumulator",
        kind="OllvmValueFlowEvidence",
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
        kind="OllvmValueFlowEvidence",
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
        kind="OllvmValueFlowEvidence",
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

    kinds = {fact.kind for fact in project_ollvm_value_flow_evidence((
        accumulator,
        loop_index,
        indirect_store,
    ))}

    assert SYMBOLIC_EXPRESSION_FACT_TYPE in kinds
    assert SCALAR_REPLACEMENT_FACT_TYPE in kinds
    assert MUST_ALIAS_FACT_TYPE in kinds
    assert LOOP_PREDICATE_VALUE_FACT_TYPE in kinds
    assert SCALAR_PROMOTION_FACT_TYPE in kinds


def test_local_working_pointer_emits_may_alias_evidence() -> None:
    local_pointer = _fact(
        fact_id="ollvm-local-pointer",
        kind="OllvmValueFlowEvidence",
        payload={
            "role": "LOCAL_WORKING_POINTER",
            "carrier_token": "%var_390",
            "local_base_token": "%var_18",
            "instruction_index": 6,
            "instruction_ea": 0x18000F111,
            "instruction_dstr": "mov &(%var_18).8, %var_390.8",
        },
        source_block=10,
        source_ea=0x18000F111,
    )

    kinds = {fact.kind for fact in project_ollvm_value_flow_evidence((local_pointer,))}

    assert MAY_ALIAS_FACT_TYPE in kinds
    assert SCALAR_REPLACEMENT_FACT_TYPE in kinds


def test_output_pointer_emits_points_to_fact_family() -> None:
    output_pointer = _fact(
        fact_id="ollvm-output-pointer",
        kind="OllvmValueFlowEvidence",
        payload={
            "role": "ARG_OUTPUT_POINTER",
            "carrier_token": "%var_30",
            "instruction_index": 2,
            "instruction_ea": 0x18000F010,
            "instruction_dstr": "mov arg_output, %var_30.8",
        },
        source_block=8,
        source_ea=0x18000F010,
    )

    projected = [
        fact
        for fact in project_ollvm_value_flow_evidence((output_pointer,))
        if fact.kind == POINTS_TO_FACT_TYPE
    ]

    assert len(projected) == 1
    assert projected[0].payload["storage_identity"] == "%var_30"
    assert projected[0].payload["expression_class"] == "argument_output_pointer"
    assert projected[0].payload["observable_effect"] == "output_buffer_pointer"
    assert projected[0].payload["details"]["proof_family"] == (
        "argument_output_pointer_identity"
    )
    assert projected[0].payload["anchor_locator"]["carrier_token"] == "%var_30"


def test_accumulator_without_local_base_does_not_emit_scalarization_authority() -> None:
    accumulator = _fact(
        fact_id="ollvm-accumulator-no-base",
        kind="OllvmValueFlowEvidence",
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

    projected = project_ollvm_value_flow_evidence((accumulator,))
    kinds = {fact.kind for fact in projected}

    assert SCALAR_REPLACEMENT_FACT_TYPE not in kinds
    assert SYMBOLIC_EXPRESSION_FACT_TYPE in kinds


def test_loop_index_carrier_does_not_authorize_local_scalarization() -> None:
    loop_index = _fact(
        fact_id="ollvm-loop-index",
        kind="OllvmValueFlowEvidence",
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

    projected = project_ollvm_value_flow_evidence((loop_index,))
    kinds = {fact.kind for fact in projected}

    assert LOOP_PREDICATE_VALUE_FACT_TYPE in kinds
    assert SCALAR_REPLACEMENT_FACT_TYPE not in kinds


def test_accumulator_scalarization_authority_is_named_by_proof_family() -> None:
    accumulator = _fact(
        fact_id="ollvm-accumulator",
        kind="OllvmValueFlowEvidence",
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

    projected = project_ollvm_value_flow_evidence((accumulator,))
    scalarization = [
        fact for fact in projected
        if fact.kind == SCALAR_REPLACEMENT_FACT_TYPE
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
        kind="OllvmValueFlowEvidence",
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

    (projected,) = project_ollvm_value_flow_evidence((compare,))

    assert projected.kind == CALL_RETURN_VALUE_FACT_TYPE
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
    generic_facts = project_value_flow_facts((source,))

    projected_again = project_value_flow_facts(generic_facts)

    assert projected_again == generic_facts
