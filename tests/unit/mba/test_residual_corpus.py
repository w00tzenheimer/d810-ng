"""Tests for portable MBA residual observations and corpus persistence."""

from __future__ import annotations

import json

import pytest

from d810.mba.differential_report import outcome_from_dict
from d810.mba.provider_outcome import (
    MbaProviderKind,
    MbaProviderOutcome,
    ProviderOutcomeStatus,
)
from d810.mba.residual_corpus import (
    MbaResidualCorpus,
    MbaResidualObservation,
    MbaResidualSource,
)
from d810.mba.typed_term import TypedBvTerm, term_fingerprint


def _term(width: int = 32, *, name: str = "x") -> TypedBvTerm:
    return TypedBvTerm(None, width, leaf_key=("register", name))


def _outcome(
    status: ProviderOutcomeStatus = ProviderOutcomeStatus.UNCHANGED,
    *,
    fingerprint: str = "candidate-1",
    input_cost: tuple[int, int] | None = (4, 7),
    output_cost: tuple[int, int] | None = (4, 7),
    provider: MbaProviderKind = MbaProviderKind.CATALOGUE,
    refusal_reason: str | None = "not_simplified",
    metadata: dict[str, object] | None = None,
) -> MbaProviderOutcome:
    return MbaProviderOutcome(
        provider=provider,
        status=status,
        fingerprint=fingerprint,
        input_cost=input_cost,
        output_cost=output_cost,
        refusal_reason=refusal_reason,
        metadata={} if metadata is None else metadata,
    )


def _source(
    *,
    case_id: str = "case-1",
    stratum: str = "unit",
    function_ea: int | None = 0x401000,
    instruction_ea: int | None = 0x401024,
    maturity: str | None = "MMAT_BUILT",
) -> MbaResidualSource:
    return MbaResidualSource(
        case_id=case_id,
        stratum=stratum,
        function_ea=function_ea,
        instruction_ea=instruction_ea,
        maturity=maturity,
    )


def _observation(
    *,
    term: TypedBvTerm | None = None,
    source: MbaResidualSource | None = None,
    outcomes: tuple[MbaProviderOutcome, ...] | None = None,
) -> MbaResidualObservation:
    return MbaResidualObservation(
        schema_version=1,
        source=_source() if source is None else source,
        canonical_term=_term() if term is None else term,
        outcomes=(_outcome(),) if outcomes is None else outcomes,
    )


@pytest.mark.parametrize(
    "status",
    (
        ProviderOutcomeStatus.UNCHANGED,
        ProviderOutcomeStatus.INELIGIBLE,
        ProviderOutcomeStatus.UNAVAILABLE,
        ProviderOutcomeStatus.OVER_BUDGET,
        ProviderOutcomeStatus.PROOF_FAILED,
        ProviderOutcomeStatus.RECONSTRUCTION_FAILED,
        ProviderOutcomeStatus.ERROR,
    ),
)
def test_unresolved_provider_statuses_are_retained(
    status: ProviderOutcomeStatus,
) -> None:
    observation = _observation(outcomes=(_outcome(status),))
    assert observation.outcomes[0].status is status
    assert observation.candidate_fingerprint == "candidate-1"


def test_empty_outcomes_are_rejected() -> None:
    with pytest.raises(ValueError, match="outcomes"):
        _observation(outcomes=())


def test_mismatched_candidate_fingerprints_are_rejected() -> None:
    with pytest.raises(ValueError, match="fingerprint"):
        _observation(
            outcomes=(
                _outcome(fingerprint="candidate-1"),
                _outcome(
                    fingerprint="candidate-2",
                    provider=MbaProviderKind.EGRAPH,
                ),
            )
        )


def test_applied_and_cheaper_improved_outcomes_are_rejected() -> None:
    with pytest.raises(ValueError, match="APPLIED|applied"):
        _observation(outcomes=(_outcome(ProviderOutcomeStatus.APPLIED),))
    with pytest.raises(ValueError, match="IMPROVED|cheaper"):
        _observation(
            outcomes=(
                _outcome(
                    ProviderOutcomeStatus.IMPROVED,
                    input_cost=(4, 7),
                    output_cost=(3, 6),
                ),
            )
        )


def test_unsupported_width_is_rejected() -> None:
    with pytest.raises(ValueError, match="width"):
        _observation(term=_term(24))


@pytest.mark.parametrize(
    "kwargs",
    (
        {"function_ea": -1},
        {"instruction_ea": -1},
        {"case_id": ""},
        {"stratum": ""},
        {"maturity": ""},
    ),
)
def test_malformed_source_anchors_are_rejected(kwargs: dict[str, object]) -> None:
    # Construction itself is the validation boundary for portable records.
    with pytest.raises(ValueError):
        source = _source(**kwargs)  # type: ignore[arg-type]
        MbaResidualObservation(1, source, _term(), (_outcome(),))


def test_duplicate_provider_rows_with_contradictory_terminal_states_are_rejected() -> (
    None
):
    with pytest.raises(ValueError, match="duplicate|terminal"):
        _observation(
            outcomes=(
                _outcome(ProviderOutcomeStatus.UNCHANGED),
                _outcome(
                    ProviderOutcomeStatus.PROOF_FAILED,
                    provider=MbaProviderKind.CATALOGUE,
                ),
            )
        )


def test_source_rendering_uses_uppercase_hex_but_wire_values_are_numeric() -> None:
    source = _source(function_ea=0x40AB, instruction_ea=0x40CD)
    assert source.function_ea == 0x40AB
    assert source.instruction_ea == 0x40CD
    assert "0x40AB" in source.identity
    assert "0x40CD" in source.identity
    assert source.to_dict()["function_ea"] == 0x40AB
    assert source.to_dict()["instruction_ea"] == 0x40CD


def test_corpus_deduplicates_terms_but_retains_sources_and_outcomes() -> None:
    first = _observation(source=_source(case_id="b", instruction_ea=0x20))
    second = _observation(
        source=_source(case_id="a", instruction_ea=0x10),
        outcomes=(
            _outcome(
                ProviderOutcomeStatus.OVER_BUDGET,
                provider=MbaProviderKind.EGRAPH,
                refusal_reason="time_budget",
                metadata={"budget": 10},
            ),
        ),
    )
    different = _observation(
        term=_term(name="y"),
        source=_source(case_id="c"),
    )

    corpus = MbaResidualCorpus()
    corpus.add(first)
    corpus.add(second)
    corpus.add(different)

    groups = corpus.groups
    assert len(groups) == 2
    same = next(
        group for group in groups if group.fingerprint == term_fingerprint(_term())
    )
    assert same.occurrence_count == 2
    assert [item.source.case_id for item in same.observations] == ["a", "b"]
    assert [item.outcomes[0].status for item in same.observations] == [
        ProviderOutcomeStatus.OVER_BUDGET,
        ProviderOutcomeStatus.UNCHANGED,
    ]


def test_corpus_round_trip_preserves_fingerprints_status_reasons_metadata_and_order() -> (
    None
):
    corpus = MbaResidualCorpus()
    corpus.add(
        _observation(
            source=_source(case_id="b"),
            outcomes=(_outcome(metadata={"z": [2, 1], "a": "kept"}),),
        )
    )
    corpus.add(
        _observation(
            source=_source(case_id="a"),
            outcomes=(
                _outcome(
                    ProviderOutcomeStatus.OVER_BUDGET,
                    refusal_reason="time_budget",
                    metadata={"elapsed": 12},
                ),
            ),
        )
    )
    encoded = corpus.to_dict()
    restored = MbaResidualCorpus.from_dict(json.loads(json.dumps(encoded)))

    assert restored.to_dict() == encoded
    assert restored.groups[0].fingerprint == term_fingerprint(_term())
    assert restored.groups[0].occurrence_count == 2
    assert (
        restored.groups[0].observations[0].outcomes[0].refusal_reason == "time_budget"
    )
    assert restored.groups[0].observations[0].outcomes[0].metadata["elapsed"] == 12


def test_default_mining_excludes_error_only_groups_but_corpus_retains_them() -> None:
    corpus = MbaResidualCorpus()
    corpus.add(
        _observation(
            term=_term(name="error"),
            outcomes=(_outcome(ProviderOutcomeStatus.ERROR, refusal_reason="bug"),),
        )
    )
    corpus.add(_observation())

    assert len(corpus.groups) == 2
    assert len(corpus.groups_for_mining()) == 1
    assert len(corpus.groups_for_mining(include_errors=True)) == 2


def test_corpus_decoder_uses_existing_provider_outcome_decoder(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls: list[dict[str, object]] = []

    def decode(data: dict[str, object]):
        calls.append(data)
        return outcome_from_dict(data)

    monkeypatch.setattr("d810.mba.residual_corpus.outcome_from_dict", decode)
    corpus = MbaResidualCorpus()
    corpus.add(_observation())
    MbaResidualCorpus.from_dict(corpus.to_dict())
    assert len(calls) == 1
