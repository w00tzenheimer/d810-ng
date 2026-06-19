"""value-flow fact families used as production rewrite contracts.

The functions here adapt existing producer observations into concrete,
source-neutral fact kinds.  They intentionally avoid a catch-all capability
blob: consumers must ask for the exact fact family their mutation requires.

Fact rows remain serializable.  Live Hex-Rays objects are rehydrated and
validated at the mutation boundary from the exact source identity stored here.
"""
from __future__ import annotations

import hashlib

from d810.core.typing import Any, Iterable
from d810.analyses.value_flow.contract_evidence import (
    ContractEvidenceToken,
    contract_evidence_payload,
)
from d810.analyses.value_flow.observation import FactObservation, JsonMapping, canonical_json

LIFECYCLE_PRODUCTION_PROVEN = "production_proven"

OBSERVABLE_MEMORY_DEF_FACT_TYPE = "ObservableMemoryDefFact"
SCALAR_PROMOTION_FACT_TYPE = "ScalarPromotionFact"
MUST_ALIAS_FACT_TYPE = "MustAliasFact"
MAY_ALIAS_FACT_TYPE = "MayAliasFact"
SCALAR_REPLACEMENT_FACT_TYPE = "ScalarReplacementFact"
SYMBOLIC_EXPRESSION_FACT_TYPE = "SymbolicExpressionFact"
LOOP_PREDICATE_VALUE_FACT_TYPE = "LoopPredicateValueFact"
CALL_RETURN_VALUE_FACT_TYPE = "CallReturnValueFact"
INDUCTION_VARIABLE_FACT_TYPE = "InductionVariableFact"
MATERIALIZATION_POINT_FACT_TYPE = "MaterializationPointFact"
OBSERVABLE_OUTPUT_FACT_TYPE = "ObservableOutputFact"
MEMORY_USE_FACT_TYPE = "MemoryUseFact"
MEMORY_PHI_FACT_TYPE = "MemoryPhiFact"
POINTS_TO_FACT_TYPE = "PointsToFact"
RETURN_VALUE_FACT_TYPE = "ReturnValueFact"
STATE_WRITE_FACT_TYPE = "StateWriteFact"
STATE_TRANSITION_FACT_TYPE = "StateTransitionFact"
EFFECT_PATH_FACT_TYPE = "EffectPathFact"
CALL_EFFECT_SUMMARY_FACT_TYPE = "CallEffectSummaryFact"

VALUE_FLOW_FACT_TYPES = frozenset({
    OBSERVABLE_MEMORY_DEF_FACT_TYPE,
    SCALAR_PROMOTION_FACT_TYPE,
    MUST_ALIAS_FACT_TYPE,
    MAY_ALIAS_FACT_TYPE,
    SCALAR_REPLACEMENT_FACT_TYPE,
    SYMBOLIC_EXPRESSION_FACT_TYPE,
    LOOP_PREDICATE_VALUE_FACT_TYPE,
    CALL_RETURN_VALUE_FACT_TYPE,
    INDUCTION_VARIABLE_FACT_TYPE,
    MATERIALIZATION_POINT_FACT_TYPE,
    OBSERVABLE_OUTPUT_FACT_TYPE,
    MEMORY_USE_FACT_TYPE,
    MEMORY_PHI_FACT_TYPE,
    POINTS_TO_FACT_TYPE,
    RETURN_VALUE_FACT_TYPE,
    STATE_WRITE_FACT_TYPE,
    STATE_TRANSITION_FACT_TYPE,
    EFFECT_PATH_FACT_TYPE,
    CALL_EFFECT_SUMMARY_FACT_TYPE,
})

_SOURCE_PROVEN_KINDS = frozenset({
    "InductionCarrierFact",
    "LoopCarrierFact",
    "ReturnCarrierFact",
    "ReturnFrontierFact",
    "TerminalByteEmitterFact",
    "ByteEmitCorridorFact",
    "StateWriteAnchorFact",
    "StateTransitionAnchorFact",
    "CallAnchorFact",
})

def project_value_flow_facts(
    observations: Iterable[FactObservation],
) -> tuple[FactObservation, ...]:
    """Project producer observations into concrete value-flow facts."""

    projected: list[FactObservation] = []
    for observation in observations:
        if observation.kind in VALUE_FLOW_FACT_TYPES:
            projected.append(observation)
            continue
        projected.extend(_project_source_fact(observation))
    return tuple(projected)


def is_value_flow_fact(fact: object, kind: str | None = None) -> bool:
    """Return true when *fact* is one of the concrete value-flow families."""

    fact_kind = str(getattr(fact, "kind", "") or "")
    if kind is not None:
        return fact_kind == kind
    return fact_kind in VALUE_FLOW_FACT_TYPES


def production_value_flow_fact(fact: object, kind: str) -> bool:
    """Return true when *fact* is a production-proven value-flow row."""

    if not is_value_flow_fact(fact, kind):
        return False
    payload = getattr(fact, "payload", None)
    if not isinstance(payload, dict):
        return False
    return str(payload.get("lifecycle_status") or "") == LIFECYCLE_PRODUCTION_PROVEN


def exact_source_identity(fact: object) -> JsonMapping:
    """Return the serializable source identity for a value-flow fact."""

    payload = getattr(fact, "payload", None)
    if not isinstance(payload, dict):
        return {}
    source_identity = payload.get("source_identity")
    if not isinstance(source_identity, dict):
        return {}
    return source_identity


def _project_source_fact(observation: FactObservation) -> tuple[FactObservation, ...]:
    if observation.kind not in _SOURCE_PROVEN_KINDS:
        return ()
    payload = observation.payload
    producer_ids = _producer_fact_ids(observation)
    source_identity = _source_identity(observation, producer_ids=producer_ids)

    if observation.kind == "InductionCarrierFact":
        storage_kind, storage_identity = _storage_from_first_int(
            payload,
            ("dest_stkoff", "base_stkoff", "source_stkoff"),
            default_kind="token",
            default_identity=str(payload.get("dest_token") or payload.get("base_token") or "unknown"),
        )
        return (_make_fact(
            observation,
            kind=INDUCTION_VARIABLE_FACT_TYPE,
            semantic_key=f"induction:{storage_kind}:{storage_identity}",
            storage_kind=storage_kind,
            storage_identity=storage_identity,
            expression_class="affine_recurrence" if payload.get("step") is not None else "direct_copy",
            observable_effect="none",
            producer_fact_ids=producer_ids,
            source_identity=source_identity,
            details={
                "source_ontology": observation.kind,
                "producer_carrier_kind": payload.get("carrier_kind"),
            },
        ),)

    if observation.kind == "LoopCarrierFact":
        storage_kind, storage_identity = _storage_from_first_int(
            payload,
            ("carrier_stkoff",),
            default_kind="token",
            default_identity=str(payload.get("carrier_var_token") or "unknown"),
        )
        return (_make_fact(
            observation,
            kind=LOOP_PREDICATE_VALUE_FACT_TYPE,
            semantic_key=f"loop_predicate:{storage_kind}:{storage_identity}",
            storage_kind=storage_kind,
            storage_identity=storage_identity,
            expression_class="loop_predicate_carrier",
            observable_effect="none",
            producer_fact_ids=producer_ids,
            source_identity=source_identity,
            details={
                "source_ontology": observation.kind,
                "classification": payload.get("classification"),
            },
        ),)

    if observation.kind == "ReturnCarrierFact":
        storage_kind, storage_identity = _storage_from_first_int(
            payload,
            ("return_slot_stkoff",),
        )
        return (
            _make_fact(
                observation,
                kind=MATERIALIZATION_POINT_FACT_TYPE,
                semantic_key=f"terminal_return:{storage_kind}:{storage_identity}",
                storage_kind=storage_kind,
                storage_identity=storage_identity,
                expression_class=_return_expression_class(payload),
                observable_effect="return_value",
                producer_fact_ids=producer_ids,
                source_identity=source_identity,
                details={
                    "source_ontology": observation.kind,
                    "carrier_class": payload.get("carrier_class"),
                },
            ),
            _make_fact(
                observation,
                kind=MEMORY_USE_FACT_TYPE,
                semantic_key=f"return_slot_use:{storage_kind}:{storage_identity}",
                storage_kind=storage_kind,
                storage_identity=storage_identity,
                expression_class="return_slot_use",
                observable_effect="return_value",
                producer_fact_ids=producer_ids,
                source_identity=source_identity,
                details={
                    "source_ontology": observation.kind,
                    "source_signature": payload.get("source_signature"),
                    "carrier_class": payload.get("carrier_class"),
                },
            ),
            _make_fact(
                observation,
                kind=RETURN_VALUE_FACT_TYPE,
                semantic_key=f"return_value:{storage_kind}:{storage_identity}",
                storage_kind=storage_kind,
                storage_identity=storage_identity,
                expression_class=_return_expression_class(payload),
                observable_effect="return_value",
                producer_fact_ids=producer_ids,
                source_identity=source_identity,
                details={
                    "source_ontology": observation.kind,
                    "source_signature": payload.get("source_signature"),
                    "carrier_class": payload.get("carrier_class"),
                    "upstream_writer_block_serial": payload.get("upstream_writer_block_serial"),
                    "upstream_writer_insn_index": payload.get("upstream_writer_insn_index"),
                },
            ),
        )

    if observation.kind == "ReturnFrontierFact":
        producer_ids = _producer_fact_ids(
            observation,
            extra_ids=_string_list(payload.get("carrier_fact_ids")),
        )
        source_identity = _source_identity(observation, producer_ids=producer_ids)
        return (
            _make_fact(
                observation,
                kind=MATERIALIZATION_POINT_FACT_TYPE,
                semantic_key=f"terminal_return_frontier:{payload.get('return_block', 'unknown')}",
                storage_kind="block",
                storage_identity=f"return_block:{payload.get('return_block', 'unknown')}",
                expression_class="return_frontier",
                observable_effect="return_value",
                producer_fact_ids=producer_ids,
                producer_kinds=(observation.kind, "ReturnCarrierFact"),
                source_identity=source_identity,
                details={
                    "source_ontology": observation.kind,
                    "frontier_blocks": payload.get("frontier_blocks"),
                },
            ),
            _make_fact(
                observation,
                kind=MEMORY_PHI_FACT_TYPE,
                semantic_key=f"return_frontier_phi:{payload.get('return_block', 'unknown')}",
                storage_kind="block",
                storage_identity=f"return_block:{payload.get('return_block', 'unknown')}",
                expression_class="return_frontier_merge",
                observable_effect="return_value",
                producer_fact_ids=producer_ids,
                producer_kinds=(observation.kind, "ReturnCarrierFact"),
                source_identity=source_identity,
                details={
                    "source_ontology": observation.kind,
                    "frontier_blocks": payload.get("frontier_blocks"),
                    "writer_blocks": payload.get("writer_blocks"),
                    "carrier_semantic_keys": payload.get("carrier_semantic_keys"),
                },
            ),
        )

    if observation.kind == "TerminalByteEmitterFact":
        destination = str(payload.get("destination_buffer_expression") or "unknown")
        return (
            _make_fact(
                observation,
                kind=OBSERVABLE_MEMORY_DEF_FACT_TYPE,
                semantic_key=f"observable_store:{destination}",
                storage_kind="memory_expression",
                storage_identity=destination,
                expression_class="byte_transform",
                observable_effect="byte_store",
                producer_fact_ids=producer_ids,
                source_identity=source_identity,
                details={
                    "source_ontology": observation.kind,
                    "byte_index": payload.get("byte_index"),
                },
            ),
            _make_fact(
                observation,
                kind=POINTS_TO_FACT_TYPE,
                semantic_key=f"points_to:{destination}",
                storage_kind="memory_expression",
                storage_identity=destination,
                expression_class="destination_points_to",
                observable_effect="byte_store",
                producer_fact_ids=producer_ids,
                source_identity=source_identity,
                details={
                    "source_ontology": observation.kind,
                    "byte_index": payload.get("byte_index"),
                    "destination_buffer_expression": destination,
                },
            ),
            _make_fact(
                observation,
                kind=OBSERVABLE_OUTPUT_FACT_TYPE,
                semantic_key=f"observable_output:{destination}",
                storage_kind="memory_expression",
                storage_identity=destination,
                expression_class="byte_output",
                observable_effect="byte_store",
                producer_fact_ids=producer_ids,
                source_identity=source_identity,
                details={
                    "source_ontology": observation.kind,
                    "byte_index": payload.get("byte_index"),
                    "destination_buffer_expression": destination,
                },
            ),
        )

    if observation.kind == "ByteEmitCorridorFact":
        producer_ids = _producer_fact_ids(
            observation,
            extra_ids=_string_list(payload.get("member_fact_ids")),
        )
        return (_make_fact(
            observation,
            kind=EFFECT_PATH_FACT_TYPE,
            semantic_key=f"side_effect_corridor:{'|'.join(_string_list(payload.get('destinations'))) or 'unknown'}",
            storage_kind="memory_expression",
            storage_identity="|".join(_string_list(payload.get("destinations"))) or "unknown",
            expression_class="byte_emit_corridor",
            observable_effect="byte_store",
            producer_fact_ids=producer_ids,
            producer_kinds=(observation.kind, "TerminalByteEmitterFact"),
            source_identity=_source_identity(observation, producer_ids=producer_ids),
            details={
                "source_ontology": observation.kind,
                "byte_indexes": payload.get("byte_indexes"),
            },
        ),)

    if observation.kind == "StateWriteAnchorFact":
        storage_kind, storage_identity = _storage_from_first_int(
            payload,
            ("state_var_stkoff",),
        )
        return (_make_fact(
            observation,
            kind=STATE_WRITE_FACT_TYPE,
            semantic_key=f"state_write:{storage_kind}:{storage_identity}",
            storage_kind=storage_kind,
            storage_identity=storage_identity,
            expression_class="direct_state_write",
            observable_effect="state_write",
            producer_fact_ids=producer_ids,
            source_identity=source_identity,
            details={
                "source_ontology": observation.kind,
                "state_const_hex": payload.get("state_const_hex"),
            },
        ),)

    if observation.kind == "StateTransitionAnchorFact":
        storage_identity = str(
            payload.get("dest_var_signature")
            or payload.get("state_var_stkoff_hex")
            or payload.get("state_var_stkoff")
            or "unknown"
        )
        return (_make_fact(
            observation,
            kind=STATE_TRANSITION_FACT_TYPE,
            semantic_key=f"state_transition:{storage_identity}",
            storage_kind="state_variable_identity",
            storage_identity=storage_identity,
            expression_class="state_transition",
            observable_effect="state_write",
            producer_fact_ids=producer_ids,
            source_identity=source_identity,
            details={
                "source_ontology": observation.kind,
                "source_state_const_hex": payload.get("source_state_const_hex"),
                "next_state_const_hex": payload.get("next_state_const_hex"),
            },
        ),)

    if observation.kind == "CallAnchorFact":
        return (_make_fact(
            observation,
            kind=CALL_EFFECT_SUMMARY_FACT_TYPE,
            semantic_key=f"call_anchor:{payload.get('call_target', 'unknown')}",
            storage_kind="call_destination",
            storage_identity=str(payload.get("call_target") or "unknown"),
            expression_class="call_site",
            observable_effect="call_side_effect",
            producer_fact_ids=producer_ids,
            source_identity=source_identity,
            details={
                "source_ontology": observation.kind,
                "call_kind": payload.get("call_kind"),
            },
        ),)

    return ()


def _make_fact(
    observation: FactObservation,
    *,
    kind: str,
    semantic_key: str,
    storage_kind: str,
    storage_identity: str,
    expression_class: str,
    observable_effect: str,
    producer_fact_ids: tuple[str, ...],
    source_identity: JsonMapping,
    details: JsonMapping,
    producer_kinds: tuple[str, ...] | None = None,
    source_block: int | None = None,
    source_ea: int | None = None,
    instruction_index: int | None = None,
    anchor_locator: JsonMapping | None = None,
    storage_overlap_proof: JsonMapping | None = None,
) -> FactObservation:
    source_block = observation.source_block if source_block is None else source_block
    source_ea = observation.source_ea if source_ea is None else source_ea
    if instruction_index is None:
        instruction_index = _instruction_index(observation.payload)
    producer_kinds = producer_kinds or (observation.kind,)
    payload = {
        "storage_kind": storage_kind,
        "storage_identity": storage_identity,
        "source_block": source_block,
        "source_ea": source_ea,
        "source_ea_hex": _hex(source_ea),
        "instruction_index": instruction_index,
        "producer_fact_ids": list(producer_fact_ids),
        "producer_kinds": list(producer_kinds),
        "expression_class": expression_class,
        "observable_effect": observable_effect,
        "lifecycle_status": LIFECYCLE_PRODUCTION_PROVEN,
        "source_identity": dict(source_identity),
        "details": dict(details),
    }
    if kind == STATE_WRITE_FACT_TYPE:
        payload.update(
            contract_evidence_payload(ContractEvidenceToken.STATE_VARIABLE_WRITES)
        )
    if anchor_locator is not None:
        payload["anchor_locator"] = dict(anchor_locator)
    if storage_overlap_proof is not None:
        payload["storage_overlap_proof"] = dict(storage_overlap_proof)
    digest = hashlib.sha1(
        canonical_json({
            "kind": kind,
            "semantic_key": semantic_key,
            "storage_kind": storage_kind,
            "storage_identity": storage_identity,
            "source_block": source_block,
            "source_ea": source_ea,
            "instruction_index": instruction_index,
            "producer_fact_ids": list(producer_fact_ids),
        }).encode("utf-8")
    ).hexdigest()[:16]
    return FactObservation(
        fact_id=f"{semantic_key}:family={digest}",
        kind=kind,
        semantic_key=semantic_key,
        maturity=observation.maturity,
        phase=observation.phase,
        confidence=observation.confidence,
        source_block=source_block,
        source_ea=source_ea,
        block_fingerprint=f"{kind}:blk[{source_block}]",
        mop_signature=f"{kind}:{storage_kind}:{storage_identity}",
        payload=payload,
        evidence=observation.evidence,
    )


def _source_identity(
    observation: FactObservation,
    *,
    producer_ids: tuple[str, ...],
) -> dict[str, object]:
    return {
        "producer_kind": observation.kind,
        "producer_fact_ids": list(producer_ids),
        "source_block": observation.source_block,
        "source_ea": observation.source_ea,
        "source_ea_hex": _hex(observation.source_ea),
    }


def _producer_fact_ids(
    observation: FactObservation,
    *,
    extra_ids: tuple[str, ...] = (),
) -> tuple[str, ...]:
    ids = [str(observation.fact_id)]
    ids.extend(str(item) for item in extra_ids if item)
    return tuple(dict.fromkeys(ids))


make_projected_value_flow_fact = _make_fact
value_flow_source_identity = _source_identity
value_flow_producer_fact_ids = _producer_fact_ids


def _storage_from_first_int(
    payload: JsonMapping,
    keys: tuple[str, ...],
    *,
    default_kind: str = "stack_offset",
    default_identity: str = "unknown",
) -> tuple[str, str]:
    for key in keys:
        value = payload.get(key)
        if value is None:
            continue
        try:
            return "stack_offset", f"0x{int(value):x}"
        except Exception:
            return default_kind, str(value)
    return default_kind, default_identity


def _instruction_index(payload: JsonMapping) -> int | None:
    for key in ("instruction_index", "insn_index", "predicate_instruction_index"):
        value = payload.get(key)
        if value is None:
            continue
        try:
            return int(value)
        except Exception:
            return None
    return None


def _return_expression_class(payload: JsonMapping) -> str:
    carrier_class = str(payload.get("carrier_class") or "")
    if carrier_class:
        return carrier_class
    return "return_value_carrier"


def _string_list(value: object) -> tuple[str, ...]:
    if value is None:
        return ()
    if isinstance(value, (str, bytes)):
        return (str(value),)
    try:
        return tuple(str(item) for item in value)  # type: ignore[operator]
    except TypeError:
        return (str(value),)


def _hex(value: int | None) -> str | None:
    if value is None:
        return None
    return f"0x{int(value):016x}"


value_flow_hex = _hex


__all__ = [
    "CALL_RETURN_VALUE_FACT_TYPE",
    "CALL_EFFECT_SUMMARY_FACT_TYPE",
    "SCALAR_PROMOTION_FACT_TYPE",
    "SYMBOLIC_EXPRESSION_FACT_TYPE",
    "VALUE_FLOW_FACT_TYPES",
    "INDUCTION_VARIABLE_FACT_TYPE",
    "LIFECYCLE_PRODUCTION_PROVEN",
    "SCALAR_REPLACEMENT_FACT_TYPE",
    "LOOP_PREDICATE_VALUE_FACT_TYPE",
    "MAY_ALIAS_FACT_TYPE",
    "MEMORY_PHI_FACT_TYPE",
    "MEMORY_USE_FACT_TYPE",
    "OBSERVABLE_MEMORY_DEF_FACT_TYPE",
    "OBSERVABLE_OUTPUT_FACT_TYPE",
    "POINTS_TO_FACT_TYPE",
    "RETURN_VALUE_FACT_TYPE",
    "MUST_ALIAS_FACT_TYPE",
    "EFFECT_PATH_FACT_TYPE",
    "STATE_TRANSITION_FACT_TYPE",
    "STATE_WRITE_FACT_TYPE",
    "MATERIALIZATION_POINT_FACT_TYPE",
    "exact_source_identity",
    "is_value_flow_fact",
    "make_projected_value_flow_fact",
    "production_value_flow_fact",
    "project_value_flow_facts",
    "value_flow_hex",
    "value_flow_producer_fact_ids",
    "value_flow_source_identity",
]
