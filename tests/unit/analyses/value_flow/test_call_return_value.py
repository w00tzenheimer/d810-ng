from __future__ import annotations

import pytest

from d810.analyses.data_flow.concolic.refs import LocationRef
from d810.analyses.data_flow.concolic.values import PrecisionStatus
from d810.analyses.value_flow import (
    CALL_RETURN_VALUE_FACT_TYPE,
    CallResultQuery,
    CallResultRefinementStatus,
    refine_call_result,
)
from d810.analyses.value_flow.model import (
    FactMapping,
    FactObservation,
    FactStatus,
    ValidatedFactView,
)

FUNCTION_EA = 0x4000
CALL_EA = 0x1000
CALLEE_EA = 0x2000
WIDTH = 32
RESULT_LOCATION = LocationRef.reg(0, 4)


def _observation(
    fact_id: str,
    envelope: dict,
    *,
    lifecycle_status: str = "production_proven",
) -> FactObservation:
    payload = {
        "storage_kind": "register",
        "source_ea": CALL_EA,
        "lifecycle_status": lifecycle_status,
        "source_identity": {"call_ea": CALL_EA},
        "details": {},
        "call_return_value": envelope,
    }
    return FactObservation(
        fact_id=fact_id,
        kind=CALL_RETURN_VALUE_FACT_TYPE,
        semantic_key=f"call-result:{fact_id}",
        maturity="MMAT_PREOPTIMIZED",
        phase="value-flow",
        confidence=1.0,
        source_ea=CALL_EA,
        payload=payload,
    )


def _view(*observations: FactObservation, stale_ids: tuple[str, ...] = ()) -> ValidatedFactView:
    mappings = tuple(
        FactMapping(
            source_fact_id=fact_id,
            source_maturity="MMAT_PREOPTIMIZED",
            target_maturity="MMAT_PREOPTIMIZED",
            status=FactStatus.STALE,
            confidence=1.0,
        )
        for fact_id in stale_ids
    )
    return ValidatedFactView(
        maturity="MMAT_PREOPTIMIZED",
        observations=observations,
        mappings=mappings,
    )


def _envelope(evidence: dict, **overrides: object) -> dict:
    result = {
        "schema_version": 1,
        "call_ea": CALL_EA,
        "callee_ea": CALLEE_EA,
        "result_width_bits": WIDTH,
        "argument_fingerprint": None,
        "evidence": evidence,
    }
    result.update(overrides)
    return result


def _query(**overrides: object) -> CallResultQuery:
    values = {
        "function_ea": FUNCTION_EA,
        "maturity": 3,
        "call_ea": CALL_EA,
        "callee_ea": CALLEE_EA,
        "result_location": RESULT_LOCATION,
        "result_width_bits": WIDTH,
    }
    values.update(overrides)
    return CallResultQuery(**values)


def test_no_evidence_returns_top():
    result = refine_call_result(_query(), _view())

    assert result.status is CallResultRefinementStatus.NO_EVIDENCE
    assert result.value.status is PrecisionStatus.TOP


def test_existing_carrier_fact_without_versioned_envelope_does_not_refine():
    observation = FactObservation(
        fact_id="carrier",
        kind=CALL_RETURN_VALUE_FACT_TYPE,
        semantic_key="carrier",
        maturity="MMAT_PREOPTIMIZED",
        phase="value-flow",
        confidence=1.0,
        payload={
            "storage_kind": "register",
            "source_ea": CALL_EA,
            "lifecycle_status": "production_proven",
            "source_identity": {"call_ea": CALL_EA},
            "details": {"carrier_class": "PASSWORD_COMPARE_RESULT"},
        },
    )

    result = refine_call_result(_query(), _view(observation))

    assert result.status is CallResultRefinementStatus.INVALID_EVIDENCE
    assert result.value.status is PrecisionStatus.TOP
    assert result.rejected_fact_ids == ("carrier",)


def test_exact_evidence_refines_to_concrete_value():
    observation = _observation("exact", _envelope({"kind": "exact", "value": 42}))

    result = refine_call_result(_query(), _view(observation))

    assert result.status is CallResultRefinementStatus.REFINED
    assert result.value.concrete == 42
    assert result.value.abstract.to_const() == 42
    assert result.used_fact_ids == ("exact",)


def test_known_bits_refines_reduced_product():
    observation = _observation(
        "bits",
        _envelope({"kind": "known_bits", "known_zero": 0xF0, "known_one": 0x05}),
    )

    result = refine_call_result(_query(), _view(observation))

    assert result.status is CallResultRefinementStatus.REFINED
    assert result.value.abstract.bits.zero == 0xF0
    assert result.value.abstract.bits.one == 0x05
    assert result.value.abstract.interval.is_top()


def test_wrapped_interval_refines_reduced_product():
    observation = _observation(
        "interval",
        _envelope({"kind": "wrapped_interval", "lo": 0xFFFFFFFE, "hi": 1}),
    )

    result = refine_call_result(_query(), _view(observation))

    assert result.status is CallResultRefinementStatus.REFINED
    assert result.value.abstract.interval.lo == 0xFFFFFFFE
    assert result.value.abstract.interval.hi == 1


def test_reduced_product_refines_both_components():
    observation = _observation(
        "product",
        _envelope(
            {
                "kind": "reduced_product",
                "known_zero": 0xFFFFFFF0,
                "known_one": 0x01,
                "lo": 1,
                "hi": 1,
            }
        ),
    )

    result = refine_call_result(_query(), _view(observation))

    assert result.status is CallResultRefinementStatus.REFINED
    assert result.value.abstract.to_const() == 1
    assert result.value.abstract.bits.zero == 0xFFFFFFFE
    assert result.value.abstract.bits.one == 0x01
    assert result.value.abstract.interval.to_const() == 1


def test_multiple_compatible_facts_meet():
    first = _observation(
        "first",
        _envelope({"kind": "known_bits", "known_zero": 0xF0, "known_one": 0x01}),
    )
    second = _observation(
        "second",
        _envelope({"kind": "known_bits", "known_zero": 0x0E, "known_one": 0x00}),
    )

    result = refine_call_result(_query(), _view(second, first))

    assert result.status is CallResultRefinementStatus.REFINED
    assert result.used_fact_ids == ("first", "second")
    assert result.value.abstract.bits.zero == 0xFE
    assert result.value.abstract.bits.one == 0x01


def test_stale_fact_is_ignored_even_when_exact():
    observation = _observation("stale", _envelope({"kind": "exact", "value": 42}))

    result = refine_call_result(_query(), _view(observation, stale_ids=("stale",)))

    assert result.status is CallResultRefinementStatus.NO_EVIDENCE
    assert result.value.status is PrecisionStatus.TOP


def test_non_production_fact_is_ignored():
    observation = _observation(
        "draft", _envelope({"kind": "exact", "value": 42}), lifecycle_status="draft"
    )

    result = refine_call_result(_query(), _view(observation))

    assert result.status is CallResultRefinementStatus.INVALID_EVIDENCE
    assert result.value.status is PrecisionStatus.TOP
    assert result.rejected_fact_ids == ("draft",)


def test_call_ea_width_callee_and_fingerprint_must_match():
    facts = (
        _observation("ea", _envelope({"kind": "exact", "value": 1}, call_ea=CALL_EA + 1)),
        _observation("width", _envelope({"kind": "exact", "value": 1}, result_width_bits=16)),
        _observation("callee", _envelope({"kind": "exact", "value": 1}, callee_ea=CALLEE_EA + 1)),
        _observation(
            "fingerprint",
            _envelope({"kind": "exact", "value": 1}, argument_fingerprint="different"),
        ),
    )

    result = refine_call_result(_query(argument_fingerprint="query"), _view(*facts))

    assert result.status is CallResultRefinementStatus.INCOMPATIBLE_EVIDENCE
    assert result.value.status is PrecisionStatus.TOP
    assert result.rejected_fact_ids == ("callee", "ea", "fingerprint", "width")


def test_fact_fingerprint_requires_same_query_fingerprint():
    observation = _observation(
        "fingerprint",
        _envelope({"kind": "exact", "value": 1}, argument_fingerprint="fact"),
    )

    result = refine_call_result(_query(argument_fingerprint="query"), _view(observation))

    assert result.status is CallResultRefinementStatus.INCOMPATIBLE_EVIDENCE
    assert result.value.status is PrecisionStatus.TOP


def test_absent_fact_fingerprint_is_allowed_for_exact_call_site():
    observation = _observation("site", _envelope({"kind": "exact", "value": 1}))

    result = refine_call_result(_query(argument_fingerprint="query"), _view(observation))

    assert result.status is CallResultRefinementStatus.REFINED
    assert result.value.concrete == 1


def test_conflicting_exact_facts_fail_open_to_top():
    first = _observation("first", _envelope({"kind": "exact", "value": 1}))
    second = _observation("second", _envelope({"kind": "exact", "value": 2}))

    result = refine_call_result(_query(), _view(first, second))

    assert result.status is CallResultRefinementStatus.CONFLICTING_EVIDENCE
    assert result.value.status is PrecisionStatus.TOP
    assert result.used_fact_ids == ("first", "second")


@pytest.mark.parametrize(
    ("label", "envelope"),
    [
        ("missing-schema", {"call_ea": CALL_EA, "callee_ea": CALLEE_EA, "result_width_bits": WIDTH, "argument_fingerprint": None, "evidence": {"kind": "exact", "value": 1}}),
        ("schema-two", _envelope({"kind": "exact", "value": 1}, schema_version=2)),
        ("unknown-envelope-key", _envelope({"kind": "exact", "value": 1}, unexpected=True)),
        ("unknown-evidence-key", _envelope({"kind": "exact", "value": 1, "extra": 2})),
        ("missing-variant-field", _envelope({"kind": "exact"})),
        ("unknown-evidence-kind", _envelope({"kind": "unknown", "value": 1})),
        ("overlapping-masks", _envelope({"kind": "known_bits", "known_zero": 1, "known_one": 1})),
        ("negative-value", _envelope({"kind": "exact", "value": -1})),
        ("overflow-value", _envelope({"kind": "exact", "value": 1 << WIDTH})),
        ("unsupported-width-zero", _envelope({"kind": "exact", "value": 1}, result_width_bits=0)),
        ("unsupported-width-one", _envelope({"kind": "exact", "value": 1}, result_width_bits=1)),
        ("unsupported-width-24", _envelope({"kind": "exact", "value": 1}, result_width_bits=24)),
        ("unsupported-width-256", _envelope({"kind": "exact", "value": 1}, result_width_bits=256)),
        ("boolean-schema", _envelope({"kind": "exact", "value": 1}, schema_version=True)),
        ("boolean-call-ea", _envelope({"kind": "exact", "value": 1}, call_ea=True)),
        ("boolean-callee-ea", _envelope({"kind": "exact", "value": 1}, callee_ea=True)),
        ("boolean-width", _envelope({"kind": "exact", "value": 1}, result_width_bits=True)),
        ("boolean-fact-value", _envelope({"kind": "exact", "value": True})),
        ("boolean-known-zero", _envelope({"kind": "known_bits", "known_zero": True, "known_one": 0})),
        ("boolean-known-one", _envelope({"kind": "known_bits", "known_zero": 0, "known_one": True})),
        ("boolean-lo", _envelope({"kind": "wrapped_interval", "lo": True, "hi": 1})),
        ("boolean-hi", _envelope({"kind": "wrapped_interval", "lo": 0, "hi": True})),
        ("boolean-product-zero", _envelope({"kind": "reduced_product", "known_zero": True, "known_one": 0, "lo": 0, "hi": 1})),
        ("boolean-product-one", _envelope({"kind": "reduced_product", "known_zero": 0, "known_one": True, "lo": 0, "hi": 1})),
        ("boolean-product-lo", _envelope({"kind": "reduced_product", "known_zero": 0, "known_one": 0, "lo": True, "hi": 1})),
        ("boolean-product-hi", _envelope({"kind": "reduced_product", "known_zero": 0, "known_one": 0, "lo": 0, "hi": True})),
    ],
)
def test_malformed_envelopes_fail_open(label: str, envelope: dict):
    observation = _observation(label, envelope)

    result = refine_call_result(_query(), _view(observation))

    assert result.status is CallResultRefinementStatus.INVALID_EVIDENCE
    assert result.value.status is PrecisionStatus.TOP
    assert result.rejected_fact_ids == (label,)
