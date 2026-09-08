"""The callback benchmark must distinguish a proof timeout from a defect."""

from types import SimpleNamespace

import pytest

from tests.system.runtime import bench_utils


def _probe(**overrides):
    values = dict(
        result=None,
        outcome=None,
        record={"lowerings": 1, "canonical_matches": 1, "proofs": 1, "emitters": 1},
        solver_checks=[{"result": "unknown", "reason_unknown": "timeout"}],
        native_unchanged=True,
        pending_replacement=None,
        fallback_comparisons=1,
        stop_reason="matched",
        proof_results=[False],
    )
    values.update(overrides)
    return bench_utils.validate_fallback_probe(**values)


def test_exact_timeout_refusal_is_a_bounded_callback_outcome():
    assert _probe() == "proof_timeout"


def test_timeout_never_hides_a_published_provider_error():
    with pytest.raises(AssertionError):
        _probe(outcome=SimpleNamespace(status="error"))


@pytest.mark.parametrize(
    "overrides",
    [
        {"solver_checks": []},
        {"solver_checks": [{"result": "sat", "reason_unknown": None}]},
        {"solver_checks": [{"result": "unknown", "reason_unknown": "canceled"}]},
        {"solver_checks": [{"result": "unsat", "reason_unknown": None}]},
        {"native_unchanged": False},
        {"pending_replacement": object()},
        {"fallback_comparisons": 0},
        {"fallback_comparisons": 65},
        {"stop_reason": "error:equivalence"},
        {"stop_reason": "error:matcher"},
        {"proof_results": [True]},
        {"proof_results": []},
        {"proof_results": [0]},
        {"result": object()},
        {"record": {"lowerings": 1, "canonical_matches": 1, "proofs": 0, "emitters": 1}},
    ],
)
def test_timeout_observation_never_excuses_other_failures(overrides):
    with pytest.raises(AssertionError):
        _probe(**overrides)


def test_success_requires_actual_unsat_and_canonical_match_receipt():
    matcher = SimpleNamespace(
        selection=SimpleNamespace(value="canonical_fallback"), fallback_comparisons=1
    )
    assert _probe(
        result=object(),
        outcome=SimpleNamespace(matcher=matcher),
        solver_checks=[{"result": "unsat", "reason_unknown": None}],
        proof_results=[True],
    ) == "proven"
    with pytest.raises(AssertionError):
        _probe(
            result=object(),
            solver_checks=[{"result": "unsat", "reason_unknown": None}],
            proof_results=[True],
        )
