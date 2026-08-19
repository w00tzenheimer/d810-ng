"""Portable contract tests for the real Egglog native corpus receipt."""

from __future__ import annotations

import pytest

from d810.mba.provider_outcome import MbaProviderOutcome, ProviderOutcomeStatus
from d810.mba.provider_routing import MbaProviderKind
from tests.system.e2e.egglog_native_corpus import (
    NativeEgglogCorpusEntry,
    build_native_egglog_attempt_receipt,
)


_STAGES = {
    "root_eligibility": 0.01,
    "native_preflight": 0.02,
    "egglog_extraction": 1.0,
    "ast_construction": 0.03,
    "native_z3": 2.0,
    "reconstruction": 0.04,
}


def _outcome(
    *,
    status: ProviderOutcomeStatus = ProviderOutcomeStatus.APPLIED,
    fingerprint: str = "candidate-a",
    sources: tuple[str, ...] = ("Add_HackersDelightRule_2", "Add_OllvmRule_3"),
    refusal_reason: str | None = None,
) -> MbaProviderOutcome:
    return MbaProviderOutcome(
        provider=MbaProviderKind.EGRAPH,
        status=status,
        fingerprint=fingerprint,
        source_provenance=sources,
        refusal_reason=refusal_reason,
        metadata={
            "stage_timings_ms": _STAGES,
            "proof_mode": "shadow",
            "template_proof_verdict": True,
            "legacy_proof_verdict": True,
        },
    )


def _entry() -> NativeEgglogCorpusEntry:
    return NativeEgglogCorpusEntry(
        corpus="egglog-add-spike",
        function="test_egglog_add_rules",
        project="egglog_add_spike.json",
        expected_sources=(("Add_HackersDelightRule_2", "Add_OllvmRule_3"),),
        expected_outcomes=("applied",),
    )


def test_real_corpus_receipt_keeps_every_attempt_and_exact_stage_schema() -> None:
    receipt = build_native_egglog_attempt_receipt(
        (_outcome(),),
        entry=_entry(),
    )

    assert receipt["schema_version"] == 3
    assert receipt["execution_count"] == 1
    assert receipt["candidate_identities"] == ["egglog-add-spike#1:candidate-a"]
    assert receipt["outcomes"] == {"applied": 1}
    assert receipt["source_names"] == [["Add_HackersDelightRule_2", "Add_OllvmRule_3"]]
    assert receipt["proof_attempt_count"] == 1
    assert receipt["proof_mode_counts"] == {"shadow": 1}
    assert receipt["stage_sample_counts"] == {name: 1 for name in _STAGES}
    assert receipt["attempts"][0]["template_proof_verdict"] is True
    assert receipt["attempts"][0]["legacy_proof_verdict"] is True


@pytest.mark.parametrize(
    "outcomes, match",
    [
        ((), "at least one live attempt"),
        ((_outcome(sources=()),), "source provenance"),
        (
            (
                _outcome(
                    status=ProviderOutcomeStatus.OVER_BUDGET,
                    refusal_reason=None,
                ),
            ),
            "structured refusal reason",
        ),
        (
            (
                MbaProviderOutcome(
                    provider=MbaProviderKind.EGRAPH,
                    status=ProviderOutcomeStatus.APPLIED,
                    fingerprint="candidate-a",
                    source_provenance=("Add_HackersDelightRule_2",),
                    metadata={"stage_timings_ms": {"unknown": 1.0}},
                ),
            ),
            "known stages",
        ),
    ],
)
def test_real_corpus_receipt_rejects_incomplete_evidence(
    outcomes: tuple[MbaProviderOutcome, ...], match: str
) -> None:
    with pytest.raises(ValueError, match=match):
        build_native_egglog_attempt_receipt(
            outcomes,
            entry=_entry(),
        )


def test_real_corpus_entry_rejects_non_live_or_incomplete_manifest_data() -> None:
    with pytest.raises(ValueError, match="corpus"):
        NativeEgglogCorpusEntry(
            corpus="",
            function="test_egglog_add_rules",
            project="egglog_add_spike.json",
            expected_sources=(("Add_HackersDelightRule_2",),),
            expected_outcomes=("applied",),
        )


def test_real_corpus_entry_allows_an_expected_structural_nonmatch() -> None:
    """A real-IDB profiling entry may intentionally require no mutation."""

    entry = NativeEgglogCorpusEntry(
        corpus="egglog-compiler-shapes",
        function="mba_shape_coefficient_01",
        project="mba_compiler_shape_egglog_profile.json",
        expected_sources=(),
        expected_outcomes=(),
    )

    receipt = build_native_egglog_attempt_receipt(
        (
            _outcome(
                status=ProviderOutcomeStatus.OVER_BUDGET,
                sources=(),
                refusal_reason="non_mba_candidate",
            ),
        ),
        entry=entry,
    )

    assert receipt["outcomes"] == {"over_budget": 1}
