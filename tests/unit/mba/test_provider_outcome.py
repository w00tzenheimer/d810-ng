"""Tests for stable portable MBA provider telemetry."""

from __future__ import annotations

import json
import math

import pytest

from d810.mba.provider_outcome import (
    MatcherOutcomeMetadata,
    MbaProviderKind,
    MbaProviderOutcome,
    ProviderOutcomeStatus,
)


def test_outcome_serializes_stably_with_cost_proof_provenance_and_matcher_metadata() -> None:
    outcome = MbaProviderOutcome(
        provider=MbaProviderKind.CATALOGUE,
        status=ProviderOutcomeStatus.APPLIED,
        fingerprint="fixed-width-fingerprint",
        input_cost=(7, 12),
        output_cost=(2, 3),
        proof_verdict=True,
        elapsed_ms=1.25,
        source_provenance=("add.identity", "add.identity.alias"),
        refusal_reason=None,
        metadata={"rule_family": "ADD", "degree": 1},
        matcher=MatcherOutcomeMetadata(
            comparisons=7,
            lazy_swaps=1,
            flattened_arity=2,
            stop_reason="matched",
        ),
    )

    assert outcome.to_json() == outcome.to_json()
    assert json.loads(outcome.to_json()) == {
        "elapsed_ms": 1.25,
        "fingerprint": "fixed-width-fingerprint",
        "input_cost": [7, 12],
        "matcher": {
            "comparisons": 7,
            "flattened_arity": 2,
            "lazy_swaps": 1,
            "stop_reason": "matched",
        },
        "metadata": {"degree": 1, "rule_family": "ADD"},
        "output_cost": [2, 3],
        "proof_verdict": True,
        "provider": "catalogue",
        "refusal_reason": None,
        "source_provenance": ["add.identity", "add.identity.alias"],
        "status": "applied",
    }


@pytest.mark.parametrize("bad_float", [math.nan, math.inf, -math.inf])
def test_outcome_rejects_non_finite_elapsed_or_metadata_values(bad_float: float) -> None:
    with pytest.raises(ValueError, match="finite"):
        MbaProviderOutcome(
            provider=MbaProviderKind.EGGLOG,
            status=ProviderOutcomeStatus.OVER_BUDGET,
            fingerprint="fingerprint",
            elapsed_ms=bad_float,
        )

    with pytest.raises(ValueError, match="finite"):
        MbaProviderOutcome(
            provider=MbaProviderKind.EGGLOG,
            status=ProviderOutcomeStatus.OVER_BUDGET,
            fingerprint="fingerprint",
            elapsed_ms=0.0,
            metadata={"elapsed": bad_float},
        )


def test_outcome_rejects_non_string_metadata_keys_at_any_depth() -> None:
    with pytest.raises(ValueError, match="string keys"):
        MbaProviderOutcome(
            provider=MbaProviderKind.CATALOGUE,
            status=ProviderOutcomeStatus.UNCHANGED,
            fingerprint="fingerprint",
            elapsed_ms=0.0,
            metadata={1: "bad"},  # type: ignore[dict-item]
        )

    with pytest.raises(ValueError, match="string keys"):
        MbaProviderOutcome(
            provider=MbaProviderKind.CATALOGUE,
            status=ProviderOutcomeStatus.UNCHANGED,
            fingerprint="fingerprint",
            elapsed_ms=0.0,
            metadata={"nested": {1: "bad"}},  # type: ignore[dict-item]
        )

    with pytest.raises(ValueError, match="string keys"):
        MbaProviderOutcome(
            provider=MbaProviderKind.CATALOGUE,
            status=ProviderOutcomeStatus.UNCHANGED,
            fingerprint="fingerprint",
            elapsed_ms=0.0,
            metadata={"valid": 1, 2: "bad"},  # type: ignore[dict-item]
        )


def test_outcome_rejects_invalid_costs_and_non_string_provenance() -> None:
    with pytest.raises(ValueError, match="cost"):
        MbaProviderOutcome(
            provider=MbaProviderKind.CATALOGUE,
            status=ProviderOutcomeStatus.IMPROVED,
            fingerprint="fingerprint",
            input_cost=(1, -1),
            elapsed_ms=0.0,
        )

    with pytest.raises(ValueError, match="source_provenance"):
        MbaProviderOutcome(
            provider=MbaProviderKind.CATALOGUE,
            status=ProviderOutcomeStatus.IMPROVED,
            fingerprint="fingerprint",
            elapsed_ms=0.0,
            source_provenance=("good", 7),  # type: ignore[arg-type]
        )


def test_matcher_metadata_requires_nonnegative_counts_and_a_stable_stop_reason() -> None:
    with pytest.raises(ValueError, match="non-negative"):
        MatcherOutcomeMetadata(
            comparisons=-1,
            lazy_swaps=0,
            flattened_arity=2,
            stop_reason="matched",
        )

    with pytest.raises(ValueError, match="stop_reason"):
        MatcherOutcomeMetadata(
            comparisons=0,
            lazy_swaps=0,
            flattened_arity=2,
            stop_reason="",
        )
