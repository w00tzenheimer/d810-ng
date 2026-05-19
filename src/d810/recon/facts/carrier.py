"""Generic carrier fact families used as production rewrite contracts.

The functions here adapt existing producer observations into concrete,
source-neutral fact kinds.  They intentionally avoid a catch-all capability
blob: consumers must ask for the exact fact family their mutation requires.

Fact rows remain serializable.  Live Hex-Rays objects are rehydrated and
validated at the mutation boundary from the exact source identity stored here.
"""
from __future__ import annotations

import hashlib
import re

from d810.core.typing import Any, Iterable
from d810.recon.facts.model import FactObservation, JsonMapping, canonical_json

LIFECYCLE_PRODUCTION_PROVEN = "production_proven"

OBSERVABLE_STORE_FACT_KIND = "ObservableMemoryDefFact"
CARRIER_STORE_PROMOTION_FACT_KIND = "ScalarPromotionFact"
SAME_CARRIER_ALIAS_FACT_KIND = "MustAliasFact"
LOCAL_STORAGE_SCALARIZATION_FACT_KIND = "ScalarReplacementFact"
EXPRESSION_CARRIER_FACT_KIND = "SymbolicExpressionFact"
LOOP_PREDICATE_CARRIER_FACT_KIND = "LoopPredicateValueFact"
CALL_RESULT_CARRIER_FACT_KIND = "CallReturnValueFact"
INDUCTION_CARRIER_FACT_KIND = "InductionVariableFact"
TERMINAL_MATERIALIZATION_FACT_KIND = "MaterializationPointFact"
STATE_VARIABLE_WRITE_FACT_KIND = "StateWriteFact"
STATE_TRANSITION_CARRIER_FACT_KIND = "StateTransitionFact"
SIDE_EFFECT_CORRIDOR_FACT_KIND = "EffectPathFact"
CALL_SIDE_EFFECT_ANCHOR_FACT_KIND = "CallEffectSummaryFact"

GENERIC_CARRIER_FACT_KINDS = frozenset({
    OBSERVABLE_STORE_FACT_KIND,
    CARRIER_STORE_PROMOTION_FACT_KIND,
    SAME_CARRIER_ALIAS_FACT_KIND,
    LOCAL_STORAGE_SCALARIZATION_FACT_KIND,
    EXPRESSION_CARRIER_FACT_KIND,
    LOOP_PREDICATE_CARRIER_FACT_KIND,
    CALL_RESULT_CARRIER_FACT_KIND,
    INDUCTION_CARRIER_FACT_KIND,
    TERMINAL_MATERIALIZATION_FACT_KIND,
    STATE_VARIABLE_WRITE_FACT_KIND,
    STATE_TRANSITION_CARRIER_FACT_KIND,
    SIDE_EFFECT_CORRIDOR_FACT_KIND,
    CALL_SIDE_EFFECT_ANCHOR_FACT_KIND,
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

_TOKEN_WIDTH_RE = re.compile(r"(?P<token>(?:%var_[0-9A-Fa-f]+|v\d+))\.(?P<size>\d+)")


def project_carrier_fact_families(
    observations: Iterable[FactObservation],
) -> tuple[FactObservation, ...]:
    """Project producer observations into concrete generic carrier facts."""

    projected: list[FactObservation] = []
    for observation in observations:
        if observation.kind in GENERIC_CARRIER_FACT_KINDS:
            projected.append(observation)
            continue
        if observation.kind == "OllvmValueFlowEvidence":
            projected.extend(_project_ollvm_oracle_fact(observation))
            continue
        projected.extend(_project_source_fact(observation))
    return tuple(projected)


def is_generic_carrier_fact(fact: object, kind: str | None = None) -> bool:
    """Return true when *fact* is one of the concrete carrier families."""

    fact_kind = str(getattr(fact, "kind", "") or "")
    if kind is not None:
        return fact_kind == kind
    return fact_kind in GENERIC_CARRIER_FACT_KINDS


def production_carrier_fact(fact: object, kind: str) -> bool:
    """Return true when *fact* is a production-proven concrete carrier row."""

    if not is_generic_carrier_fact(fact, kind):
        return False
    payload = getattr(fact, "payload", None)
    if not isinstance(payload, dict):
        return False
    return str(payload.get("lifecycle_status") or "") == LIFECYCLE_PRODUCTION_PROVEN


def exact_source_identity(fact: object) -> JsonMapping:
    """Return the serializable source identity for a concrete carrier fact."""

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
            kind=INDUCTION_CARRIER_FACT_KIND,
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
            kind=LOOP_PREDICATE_CARRIER_FACT_KIND,
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
        return (_make_fact(
            observation,
            kind=TERMINAL_MATERIALIZATION_FACT_KIND,
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
        ),)

    if observation.kind == "ReturnFrontierFact":
        producer_ids = _producer_fact_ids(
            observation,
            extra_ids=_string_list(payload.get("carrier_fact_ids")),
        )
        return (_make_fact(
            observation,
            kind=TERMINAL_MATERIALIZATION_FACT_KIND,
            semantic_key=f"terminal_return_frontier:{payload.get('return_block', 'unknown')}",
            storage_kind="block",
            storage_identity=f"return_block:{payload.get('return_block', 'unknown')}",
            expression_class="return_frontier",
            observable_effect="return_value",
            producer_fact_ids=producer_ids,
            producer_kinds=(observation.kind, "ReturnCarrierFact"),
            source_identity=_source_identity(observation, producer_ids=producer_ids),
            details={
                "source_ontology": observation.kind,
                "frontier_blocks": payload.get("frontier_blocks"),
            },
        ),)

    if observation.kind == "TerminalByteEmitterFact":
        return (_make_fact(
            observation,
            kind=OBSERVABLE_STORE_FACT_KIND,
            semantic_key=f"observable_store:{payload.get('destination_buffer_expression', 'unknown')}",
            storage_kind="memory_expression",
            storage_identity=str(payload.get("destination_buffer_expression") or "unknown"),
            expression_class="byte_transform",
            observable_effect="byte_store",
            producer_fact_ids=producer_ids,
            source_identity=source_identity,
            details={
                "source_ontology": observation.kind,
                "byte_index": payload.get("byte_index"),
            },
        ),)

    if observation.kind == "ByteEmitCorridorFact":
        producer_ids = _producer_fact_ids(
            observation,
            extra_ids=_string_list(payload.get("member_fact_ids")),
        )
        return (_make_fact(
            observation,
            kind=SIDE_EFFECT_CORRIDOR_FACT_KIND,
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
            kind=STATE_VARIABLE_WRITE_FACT_KIND,
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
            kind=STATE_TRANSITION_CARRIER_FACT_KIND,
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
            kind=CALL_SIDE_EFFECT_ANCHOR_FACT_KIND,
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


def _project_ollvm_oracle_fact(
    observation: FactObservation,
) -> tuple[FactObservation, ...]:
    payload = observation.payload
    role = str(payload.get("role") or "")
    token = _canonical_token(str(payload.get("carrier_token") or ""))
    producer_ids = _producer_fact_ids(observation)
    if token is None:
        return ()
    exact = _ollvm_exact_source_identity(observation, token=token)
    if exact is None:
        return ()

    if role in {
        "ARG_OUTPUT_STORE_CANDIDATE",
        "LOCAL_WORKING_STORE_CANDIDATE",
    }:
        extra_details = _ollvm_local_scalarization_details(payload)
        return (
            _ollvm_exact_fact(
                observation,
                exact=exact,
                kind=OBSERVABLE_STORE_FACT_KIND,
                semantic_key=f"observable_store:token:{token}",
                expression_class="output_store_carrier_proof",
                observable_effect="output_store",
                proof_family="observable_output_store_carrier",
                producer_ids=producer_ids,
                role=role,
                extra_details=extra_details,
            ),
            _ollvm_exact_fact(
                observation,
                exact=exact,
                kind=CARRIER_STORE_PROMOTION_FACT_KIND,
                semantic_key=f"carrier_store_promotion:token:{token}",
                expression_class="carrier_store_promotion_proof",
                observable_effect="output_store",
                proof_family="observable_output_store_carrier_promotion",
                producer_ids=producer_ids,
                role=role,
                extra_details=extra_details,
            ),
        )

    if role == "LOCAL_WORKING_POINTER":
        return (_ollvm_exact_fact(
            observation,
            exact=exact,
            kind=LOCAL_STORAGE_SCALARIZATION_FACT_KIND,
            semantic_key=f"local_storage_scalarization:token:{token}",
            expression_class="local_storage_scalarization_proof",
            observable_effect="none",
            proof_family="local_pointer_storage_scalarization",
            producer_ids=producer_ids,
            role=role,
            extra_details=_ollvm_local_scalarization_details(payload),
        ),)

    if role == "INDIRECT_STORE_CANDIDATE":
        return (_ollvm_exact_fact(
            observation,
            exact=exact,
            kind=CARRIER_STORE_PROMOTION_FACT_KIND,
            semantic_key=f"carrier_store_promotion:token:{token}",
            expression_class="carrier_store_promotion_proof",
            observable_effect="output_store",
            proof_family="observable_carrier_store",
            producer_ids=producer_ids,
            role=role,
        ),)

    if role == "LOOP_INDEX_CARRIER":
        return (_ollvm_exact_fact(
            observation,
            exact=exact,
            kind=LOOP_PREDICATE_CARRIER_FACT_KIND,
            semantic_key=f"loop_predicate:token:{token}",
            expression_class="loop_predicate_carrier_proof",
            observable_effect="none",
            proof_family="local_loop_predicate_carrier",
            producer_ids=producer_ids,
            role=role,
            extra_details=_ollvm_local_scalarization_details(payload),
        ),)

    if role == "PASSWORD_COMPARE_RESULT":
        return (_ollvm_exact_fact(
            observation,
            exact=exact,
            kind=CALL_RESULT_CARRIER_FACT_KIND,
            semantic_key=f"call_result:token:{token}",
            expression_class="call_result",
            observable_effect="branch_predicate",
            proof_family="call_result_predicate_carrier",
            producer_ids=producer_ids,
            role=role,
        ),)

    if role == "ACCUMULATOR_CARRIER":
        facts = []
        local_details = _ollvm_local_scalarization_details(payload)
        # Local scalarization is a mutation-authorizing proof.  It requires a
        # concrete local-base relation so the consumer can revalidate the live
        # anchor before queueing any rewrite.  Other accumulator facts stay
        # diagnostic/semantic even when the local-base proof is absent.
        if (
            local_details.get("local_base_token") is not None
            or local_details.get("multiply_add_base_token") is not None
        ):
            facts.append(_ollvm_exact_fact(
                observation,
                exact=exact,
                kind=LOCAL_STORAGE_SCALARIZATION_FACT_KIND,
                semantic_key=f"local_storage_scalarization:token:{token}",
                expression_class="local_storage_scalarization_proof",
                observable_effect="none",
                proof_family="local_expression_storage_scalarization",
                producer_ids=producer_ids,
                role=role,
                extra_details=local_details,
            ))
        facts.extend([
            _ollvm_exact_fact(
                observation,
                exact=exact,
                kind=EXPRESSION_CARRIER_FACT_KIND,
                semantic_key=f"expression_carrier:token:{token}",
                expression_class="semantic_expression_carrier_proof",
                observable_effect="none",
                proof_family="local_alias_expression_carrier",
                producer_ids=producer_ids,
                role=role,
            ),
            _ollvm_exact_fact(
                observation,
                exact=exact,
                kind=CARRIER_STORE_PROMOTION_FACT_KIND,
                semantic_key=f"carrier_store_promotion:token:{token}",
                expression_class="carrier_store_promotion_proof",
                observable_effect="carrier_store",
                proof_family="semantic_expression_store_promotion",
                producer_ids=producer_ids,
                role=role,
            ),
        ])
        alias = _ollvm_same_carrier_alias_fact(
            observation,
            exact=exact,
            token=token,
            producer_ids=producer_ids,
            role=role,
        )
        if alias is not None:
            facts.append(alias)
        return tuple(facts)

    return ()


def _ollvm_exact_fact(
    observation: FactObservation,
    *,
    exact: JsonMapping,
    kind: str,
    semantic_key: str,
    expression_class: str,
    observable_effect: str,
    proof_family: str,
    producer_ids: tuple[str, ...],
    role: str,
    extra_details: JsonMapping | None = None,
) -> FactObservation:
    token = str(exact["carrier_token"])
    source_block = int(exact["source_block"])
    source_ea = int(exact["instruction_ea"])
    instruction_index = int(exact["instruction_index"])
    source_identity = {
        **_source_identity(observation, producer_ids=producer_ids),
        "source_block": source_block,
        "source_ea": source_ea,
        "source_ea_hex": _hex(source_ea),
        "instruction_index": instruction_index,
    }
    details = {
        "source_ontology": observation.kind,
        "source_role": role,
        "fixture_specific": True,
        "proof_family": proof_family,
        "proof_basis": [
            "exact_source_block",
            "exact_instruction_ea",
            "exact_instruction_index",
            "exact_instruction_text",
            "carrier_token_identity",
        ],
        "producer_payload_role": role,
        "carrier_token": token,
        "instruction_dstr": str(observation.payload.get("instruction_dstr") or ""),
    }
    if extra_details:
        details.update(extra_details)
    anchor_locator = _ollvm_anchor_locator(observation, exact=exact, token=token)
    overlap_proof = _ollvm_overlap_proof(
        payload=observation.payload,
        token=token,
        role=role,
        details=details,
    )
    return _make_fact(
        observation,
        kind=kind,
        semantic_key=semantic_key,
        storage_kind="token",
        storage_identity=token,
        source_block=source_block,
        source_ea=source_ea,
        instruction_index=instruction_index,
        expression_class=expression_class,
        observable_effect=observable_effect,
        producer_fact_ids=producer_ids,
        producer_kinds=(observation.kind,),
        source_identity=source_identity,
        details=details,
        anchor_locator=anchor_locator,
        storage_overlap_proof=overlap_proof,
    )


def _ollvm_same_carrier_alias_fact(
    observation: FactObservation,
    *,
    exact: JsonMapping,
    token: str,
    producer_ids: tuple[str, ...],
    role: str,
) -> FactObservation | None:
    payload = observation.payload
    if role != "ACCUMULATOR_CARRIER":
        return None
    if payload.get("same_carrier_alias_proof") is not True:
        return None
    alias_tokens = tuple(
        sorted(
            alias
            for alias in (
                _canonical_token(str(raw_alias))
                for raw_alias in (
                    payload.get("multiply_add_same_base_alias_tokens") or ()
                )
            )
            if alias is not None
        )
    )
    carrier_token = _canonical_token(token)
    if carrier_token is None or not alias_tokens:
        return None
    source_block = int(exact["source_block"])
    source_ea = int(exact["instruction_ea"])
    instruction_index = int(exact["instruction_index"])
    source_identity = {
        **_source_identity(observation, producer_ids=producer_ids),
        "source_block": source_block,
        "source_ea": source_ea,
        "source_ea_hex": _hex(source_ea),
        "instruction_index": instruction_index,
    }
    details = {
        "source_ontology": observation.kind,
        "source_role": role,
        "carrier_token": carrier_token,
        "alias_tokens": list(alias_tokens),
        "proof_family": "same_carrier_alias_identity",
        "instruction_dstr": str(payload.get("instruction_dstr") or ""),
    }
    return _make_fact(
        observation,
        kind=SAME_CARRIER_ALIAS_FACT_KIND,
        semantic_key=f"same_carrier_alias:{carrier_token}:{','.join(alias_tokens)}",
        storage_kind="token_pair",
        storage_identity=f"{carrier_token}->{','.join(alias_tokens)}",
        source_block=source_block,
        source_ea=source_ea,
        instruction_index=instruction_index,
        expression_class="same_carrier_alias",
        observable_effect="none",
        producer_fact_ids=producer_ids,
        producer_kinds=(observation.kind,),
        source_identity=source_identity,
        details=details,
        anchor_locator=_ollvm_anchor_locator(
            observation,
            exact=exact,
            token=carrier_token,
        ),
        storage_overlap_proof=_ollvm_overlap_proof(
            payload=payload,
            token=carrier_token,
            role=role,
            details=details,
        ),
    )


def _ollvm_local_scalarization_details(payload: JsonMapping) -> JsonMapping:
    """Return serializable alias-to-base details for local storage facts."""

    details: dict[str, object] = {}
    local_base = _canonical_token(str(payload.get("local_base_token") or ""))
    multiply_base = _canonical_token(str(payload.get("multiply_add_base_token") or ""))
    if local_base is not None:
        details["local_base_token"] = local_base
    if multiply_base is not None:
        details["multiply_add_base_token"] = multiply_base
    aliases = tuple(
        alias for alias in (
            _canonical_token(str(raw_alias))
            for raw_alias in (payload.get("multiply_add_same_base_alias_tokens") or ())
        )
        if alias is not None
    )
    if aliases:
        details["same_base_alias_tokens"] = aliases
    return details


def _instruction_text_digest(text: str) -> str:
    return hashlib.sha1(text.encode("utf-8", errors="replace")).hexdigest()[:16]


def _token_widths(text: str) -> dict[str, int]:
    widths: dict[str, int] = {}
    for match in _TOKEN_WIDTH_RE.finditer(text):
        token = _canonical_token(match.group("token"))
        if token is None:
            continue
        try:
            size = int(match.group("size"))
        except Exception:
            continue
        previous = widths.get(token)
        if previous is None or size > previous:
            widths[token] = size
    return widths


def _ollvm_anchor_locator(
    observation: FactObservation,
    *,
    exact: JsonMapping,
    token: str,
) -> JsonMapping:
    text = str(observation.payload.get("instruction_dstr") or "")
    opcode_name = str(observation.payload.get("instruction_opcode_name") or "")
    return {
        "requires_live_revalidation": True,
        "source_block": int(exact["source_block"]),
        "instruction_ea": int(exact["instruction_ea"]),
        "instruction_ea_hex": _hex(int(exact["instruction_ea"])),
        "instruction_index": int(exact["instruction_index"]),
        "instruction_opcode_name": opcode_name,
        "instruction_text_sha1": _instruction_text_digest(text),
        "instruction_dstr": text,
        "carrier_token": _canonical_token(token),
        "token_widths": _token_widths(text),
    }


def _ollvm_overlap_proof(
    *,
    payload: JsonMapping,
    token: str,
    role: str,
    details: JsonMapping,
) -> JsonMapping:
    token = _canonical_token(token) or str(token)
    text = str(payload.get("instruction_dstr") or "")
    token_widths = _token_widths(text)
    local_base = _canonical_token(str(details.get("local_base_token") or ""))
    multiply_base = _canonical_token(str(details.get("multiply_add_base_token") or ""))
    alias_tokens = tuple(
        alias for alias in (
            _canonical_token(str(raw_alias))
            for raw_alias in (details.get("alias_tokens") or details.get("same_base_alias_tokens") or ())
        )
        if alias is not None
    )
    proof_basis = "exact_token_and_width_signature"
    if local_base is not None or multiply_base is not None or alias_tokens:
        proof_basis = "same_local_pointer_base"
    return {
        "proof_status": "producer_checked",
        "proof_basis": proof_basis,
        "carrier_token": token,
        "base_token": local_base or multiply_base,
        "alias_tokens": list(alias_tokens),
        "token_widths": token_widths,
        "carrier_width_bytes": token_widths.get(token),
        "fully_included": True,
        "partial_overlap": False,
        "requires_live_mlist_revalidation": True,
        "source_role": role,
    }


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


def _ollvm_exact_source_identity(
    observation: FactObservation,
    *,
    token: str,
) -> JsonMapping | None:
    payload = observation.payload
    source_block = payload.get("source_block", observation.source_block)
    instruction_ea = payload.get("instruction_ea", observation.source_ea)
    instruction_index = payload.get("instruction_index")
    instruction_dstr = str(payload.get("instruction_dstr") or "")
    if source_block is None or instruction_ea is None or instruction_index is None:
        return None
    if not instruction_dstr:
        return None
    canonical = _canonical_token(token)
    if canonical is None or canonical not in _tokens(instruction_dstr):
        return None
    return {
        "carrier_token": canonical,
        "source_block": int(source_block),
        "instruction_ea": int(instruction_ea),
        "instruction_index": int(instruction_index),
    }


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


def _canonical_token(value: object) -> str | None:
    text = str(value or "").strip()
    if not text:
        return None
    if not text.startswith("%"):
        return text
    name = text.split(".", 1)[0]
    return name.upper().replace("%VAR_", "%var_")


_VAR_TOKEN_RE = re.compile(r"(?:%var_[0-9A-Fa-f]+|v\d+)")


def _tokens(text: str) -> frozenset[str]:
    return frozenset(
        canonical
        for canonical in (
            _canonical_token(match.group(0))
            for match in _VAR_TOKEN_RE.finditer(text)
        )
        if canonical is not None
    )


def _hex(value: int | None) -> str | None:
    if value is None:
        return None
    return f"0x{int(value):016x}"


__all__ = [
    "CALL_RESULT_CARRIER_FACT_KIND",
    "CALL_SIDE_EFFECT_ANCHOR_FACT_KIND",
    "CARRIER_STORE_PROMOTION_FACT_KIND",
    "EXPRESSION_CARRIER_FACT_KIND",
    "GENERIC_CARRIER_FACT_KINDS",
    "INDUCTION_CARRIER_FACT_KIND",
    "LIFECYCLE_PRODUCTION_PROVEN",
    "LOCAL_STORAGE_SCALARIZATION_FACT_KIND",
    "LOOP_PREDICATE_CARRIER_FACT_KIND",
    "OBSERVABLE_STORE_FACT_KIND",
    "SAME_CARRIER_ALIAS_FACT_KIND",
    "SIDE_EFFECT_CORRIDOR_FACT_KIND",
    "STATE_TRANSITION_CARRIER_FACT_KIND",
    "STATE_VARIABLE_WRITE_FACT_KIND",
    "TERMINAL_MATERIALIZATION_FACT_KIND",
    "exact_source_identity",
    "is_generic_carrier_fact",
    "production_carrier_fact",
    "project_carrier_fact_families",
]


# ---------------------------------------------------------------------------
# Value-flow rename compatibility surface.
#
# Canonical names live in ``d810.recon.facts.value_flow``. The carrier module
# remains as an import shim for old call sites, but the exported values are now
# canonical serialized fact types, not old carrier-era serialized kind strings.
# ---------------------------------------------------------------------------

OBSERVABLE_MEMORY_DEF_FACT_TYPE = OBSERVABLE_STORE_FACT_KIND
SCALAR_PROMOTION_FACT_TYPE = CARRIER_STORE_PROMOTION_FACT_KIND
MUST_ALIAS_FACT_TYPE = SAME_CARRIER_ALIAS_FACT_KIND
SCALAR_REPLACEMENT_FACT_TYPE = LOCAL_STORAGE_SCALARIZATION_FACT_KIND
SYMBOLIC_EXPRESSION_FACT_TYPE = EXPRESSION_CARRIER_FACT_KIND
LOOP_PREDICATE_VALUE_FACT_TYPE = LOOP_PREDICATE_CARRIER_FACT_KIND
CALL_RETURN_VALUE_FACT_TYPE = CALL_RESULT_CARRIER_FACT_KIND
INDUCTION_VARIABLE_FACT_TYPE = INDUCTION_CARRIER_FACT_KIND
MATERIALIZATION_POINT_FACT_TYPE = TERMINAL_MATERIALIZATION_FACT_KIND
STATE_WRITE_FACT_TYPE = STATE_VARIABLE_WRITE_FACT_KIND
STATE_TRANSITION_FACT_TYPE = STATE_TRANSITION_CARRIER_FACT_KIND
EFFECT_PATH_FACT_TYPE = SIDE_EFFECT_CORRIDOR_FACT_KIND
CALL_EFFECT_SUMMARY_FACT_TYPE = CALL_SIDE_EFFECT_ANCHOR_FACT_KIND

VALUE_FLOW_FACT_TYPES = GENERIC_CARRIER_FACT_KINDS

project_value_flow_facts = project_carrier_fact_families
is_value_flow_fact = is_generic_carrier_fact
production_value_flow_fact = production_carrier_fact

__all__ += [
    "CALL_EFFECT_SUMMARY_FACT_TYPE",
    "CALL_RETURN_VALUE_FACT_TYPE",
    "EFFECT_PATH_FACT_TYPE",
    "INDUCTION_VARIABLE_FACT_TYPE",
    "LOOP_PREDICATE_VALUE_FACT_TYPE",
    "MATERIALIZATION_POINT_FACT_TYPE",
    "MUST_ALIAS_FACT_TYPE",
    "OBSERVABLE_MEMORY_DEF_FACT_TYPE",
    "SCALAR_PROMOTION_FACT_TYPE",
    "SCALAR_REPLACEMENT_FACT_TYPE",
    "STATE_TRANSITION_FACT_TYPE",
    "STATE_WRITE_FACT_TYPE",
    "SYMBOLIC_EXPRESSION_FACT_TYPE",
    "VALUE_FLOW_FACT_TYPES",
    "is_value_flow_fact",
    "production_value_flow_fact",
    "project_value_flow_facts",
]
