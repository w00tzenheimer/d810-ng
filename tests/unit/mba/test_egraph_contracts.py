"""Tests for the backend-neutral e-graph contracts."""

from __future__ import annotations

import json
import math
from dataclasses import FrozenInstanceError, fields

import pytest

from d810.mba.egraph_contracts import (
    EgraphExtractionReceipt,
    EgraphSkipReason,
    MbaEgraphOptions,
)


def _receipt(**overrides: object) -> EgraphExtractionReceipt:
    values: dict[str, object] = {
        "input_cost": (8, 12),
        "extracted_cost": (4, 6),
        "degree": 1,
        "eclass_count": 3,
        "enode_count": 5,
        "rule_firings": 2,
        "elapsed_ms": 1.5,
        "selected_family": "add",
        "selected_source": "add.identity",
        "selected_aliases": ("add.alias",),
        "derivation_trace": (("add", "add.identity", ("add.alias",)),),
        "island_class": "linear_mba",
        "island_fingerprint": "fingerprint",
        "operator_count": 4,
        "distinct_leaf_count": 2,
        "nonlinear_product_count": 0,
        "blockers": (),
        "native_profile": {"width": 32, "nested": {"finite": 1.0}},
        "proof_mode": "shadow",
        "template_source_name": "add.identity",
        "template_fallback_reason": None,
        "template_proof_verdict": True,
        "legacy_proof_verdict": True,
        "template_proof_elapsed_ms": 0.25,
        "legacy_proof_elapsed_ms": 0.5,
        "native_matcher_backend": "python",
        "native_matcher_comparisons": 7,
        "native_matcher_lazy_swaps": 1,
        "native_fixed_binding_count": 0,
        "native_matcher_elapsed_ms": 0.75,
        "skip_reason": None,
        "canonicalizer_version": 1,
        "canonical_input_cost": (7, 11),
        "normalization_steps": ("flatten",),
        "execution_path": "fresh_saturation",
        "cache_status": "miss",
        "cache_key": "cache-key",
        "replayed_trace": (),
        "cache_lookup_elapsed_ms": 0.1,
        "replay_rebuild_elapsed_ms": 0.2,
        "replay_proof_elapsed_ms": 0.3,
        "egraph_work_units": 9,
        "replay_fallback_reason": None,
        "egraph_run_count": 1,
        "replay_saved_egraph_runs": 0,
        "backend": "egglog",
        "backend_version": "13.2.0",
    }
    values.update(overrides)
    return EgraphExtractionReceipt(**values)


def test_skip_reason_wire_values_are_backend_neutral() -> None:
    assert {reason.name: reason.value for reason in EgraphSkipReason} == {
        "RUNTIME_UNAVAILABLE": "runtime_unavailable",
        "NON_MBA_CANDIDATE": "non_mba_candidate",
        "UNSUPPORTED_WIDTH_SEMANTICS": "unsupported_width_semantics",
        "CANDIDATE_BUDGET": "candidate_budget",
        "TIME_BUDGET": "time_budget",
        "ECLASS_BUDGET": "eclass_budget",
        "ENODE_BUDGET": "enode_budget",
        "RULE_FIRING_BUDGET": "rule_firing_budget",
        "LOWERING_FAILED": "lowering_failed",
        "PROOF_FAILED": "proof_failed",
        "INTERNAL_ERROR": "internal_error",
    }


def test_options_are_frozen_and_validate_the_existing_public_budget() -> None:
    options = MbaEgraphOptions()
    assert options.max_leaves == 2
    assert options.max_operator_nodes == 10
    assert options.max_degree == 1
    assert options.saturation_rounds == 2
    assert options.max_eclasses == 64
    assert options.max_enodes == 128
    assert options.max_rule_firings == 32
    assert options.function_time_budget_ms is None
    assert options.families == ("add",)
    assert options.maturities == ("GLOBAL_OPTIMIZED",)
    with pytest.raises(FrozenInstanceError):
        options.max_degree = 2  # type: ignore[misc]

    with pytest.raises(ValueError, match="max_leaves"):
        MbaEgraphOptions(max_leaves=0)
    with pytest.raises(ValueError, match="max_degree"):
        MbaEgraphOptions(max_degree=3)
    with pytest.raises(ValueError, match="saturation_rounds"):
        MbaEgraphOptions(saturation_rounds=7)
    with pytest.raises(ValueError, match="require_proof"):
        MbaEgraphOptions(require_proof=False)
    with pytest.raises(ValueError, match="families"):
        MbaEgraphOptions(families=("add", "add"))
    with pytest.raises(ValueError, match="maturities"):
        MbaEgraphOptions(maturities=("NOT_A_MATURITY",))


def test_receipt_serializes_every_field_with_exact_keys_and_round_trips() -> None:
    receipt = _receipt()
    expected_keys = {item.name for item in fields(EgraphExtractionReceipt)}
    payload = receipt.to_dict()

    assert set(payload) == expected_keys
    assert json.loads(receipt.to_json()) == payload
    assert EgraphExtractionReceipt.from_dict(payload) == receipt
    assert EgraphExtractionReceipt.from_json(receipt.to_json()) == receipt
    assert payload["skip_reason"] is None
    assert payload["selected_aliases"] == ["add.alias"]
    assert payload["derivation_trace"] == [["add", "add.identity", ["add.alias"]]]
    assert payload["backend"] == "egglog"
    assert payload["backend_version"] == "13.2.0"


@pytest.mark.parametrize(
    ("field_name", "value"),
    [
        ("egraph_work_units", -1),
        ("egraph_run_count", -1),
        ("replay_saved_egraph_runs", -1),
        ("rule_firings", -1),
        ("eclass_count", -1),
        ("enode_count", -1),
        ("native_matcher_comparisons", -1),
        ("elapsed_ms", math.nan),
        ("template_proof_elapsed_ms", math.inf),
        ("native_matcher_elapsed_ms", -math.inf),
    ],
)
def test_receipt_rejects_negative_counts_and_non_finite_timings(
    field_name: str, value: object
) -> None:
    with pytest.raises(ValueError):
        _receipt(**{field_name: value})


def test_receipt_rejects_invalid_traces_and_backend_version_half_pairs() -> None:
    with pytest.raises(ValueError, match="derivation_trace"):
        _receipt(derivation_trace=(("add", "source"),))  # type: ignore[arg-type]
    with pytest.raises(ValueError, match="replayed_trace"):
        _receipt(replayed_trace=(("add", "source", ["alias"]),))  # type: ignore[arg-type]
    with pytest.raises(ValueError, match="backend"):
        _receipt(backend="egglog", backend_version=None)
    with pytest.raises(ValueError, match="backend"):
        _receipt(backend=None, backend_version="13.2.0")


def test_receipt_rejects_non_json_native_profile_values() -> None:
    with pytest.raises(ValueError, match="finite"):
        _receipt(native_profile={"elapsed": math.nan})
    with pytest.raises(ValueError, match="string keys"):
        _receipt(native_profile={1: "invalid"})  # type: ignore[dict-item]


def test_receipt_from_dict_rejects_missing_or_extra_json_keys() -> None:
    payload = _receipt().to_dict()
    with pytest.raises(ValueError, match="schema"):
        EgraphExtractionReceipt.from_dict({key: value for key, value in payload.items() if key != "backend"})
    with pytest.raises(ValueError, match="schema"):
        EgraphExtractionReceipt.from_dict({**payload, "unexpected": True})
