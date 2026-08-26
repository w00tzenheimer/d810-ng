"""Portable persistence for unresolved MBA provider observations."""

from __future__ import annotations

import json
from collections.abc import Iterable, Mapping
from dataclasses import dataclass

from d810.mba.differential_report import outcome_from_dict
from d810.mba.provider_outcome import MbaProviderOutcome, ProviderOutcomeStatus
from d810.mba.term_codec import typed_term_from_dict, typed_term_to_dict
from d810.mba.typed_term import TypedBvTerm, term_fingerprint


RESIDUAL_CORPUS_SCHEMA_VERSION = 1
RESIDUAL_CORPUS_METADATA_KEY = "mba_residual_corpus_v1"
_SUPPORTED_WIDTHS = frozenset({8, 16, 32, 64})
_OUTCOME_FIELDS = frozenset(
    {
        "provider",
        "status",
        "fingerprint",
        "input_cost",
        "output_cost",
        "proof_verdict",
        "elapsed_ms",
        "source_provenance",
        "refusal_reason",
        "metadata",
        "matcher",
    }
)


def _validate_term(term: object) -> TypedBvTerm:
    if type(term) is not TypedBvTerm:
        raise TypeError("canonical_term must be a TypedBvTerm")
    try:
        # Round-tripping through the established codec validates malformed
        # dataclass instances without creating a second term validator.
        decoded = typed_term_from_dict(typed_term_to_dict(term))
    except (TypeError, ValueError, KeyError) as exc:
        raise ValueError("canonical_term is malformed") from exc
    if decoded != term:
        raise ValueError("canonical_term is not canonically representable")
    if term.width not in _SUPPORTED_WIDTHS:
        raise ValueError("canonical_term width must be one of 8, 16, 32, or 64")
    return term


def _source_sort_key(source: "MbaResidualSource") -> tuple[object, ...]:
    return (
        source.case_id,
        source.stratum,
        -1 if source.function_ea is None else source.function_ea,
        -1 if source.instruction_ea is None else source.instruction_ea,
        "" if source.maturity is None else source.maturity,
    )


def _observation_sort_key(observation: "MbaResidualObservation") -> tuple[object, ...]:
    return (
        _source_sort_key(observation.source),
        json.dumps(
            [
                outcome.to_dict()
                for outcome in observation.outcomes
            ],
            allow_nan=False,
            ensure_ascii=True,
            separators=(",", ":"),
            sort_keys=True,
        ),
    )


def _decode_outcome(data: object) -> MbaProviderOutcome:
    """Decode one exact canonical provider-outcome wire row."""

    try:
        if not isinstance(data, Mapping):
            raise ValueError("provider outcome must be a mapping")
        if set(data) != _OUTCOME_FIELDS:
            raise ValueError("provider outcome has invalid fields")
        canonical = dict(data)
        outcome = outcome_from_dict(canonical)
        if outcome.to_dict() != canonical:
            raise ValueError("provider outcome is not canonical")
        return outcome
    except Exception as exc:
        raise ValueError(f"invalid residual provider outcome: {exc}") from exc


def source_identity(source: "MbaResidualSource") -> str:
    """Render stable source anchors with uppercase hexadecimal EAs."""

    function = "-" if source.function_ea is None else f"0x{source.function_ea:X}"
    instruction = (
        "-" if source.instruction_ea is None else f"0x{source.instruction_ea:X}"
    )
    maturity = "-" if source.maturity is None else source.maturity
    return (
        f"case={source.case_id} stratum={source.stratum} "
        f"function={function} instruction={instruction} maturity={maturity}"
    )


@dataclass(frozen=True, slots=True)
class MbaResidualSource:
    """Portable source anchors for one observed unresolved term."""

    case_id: str
    stratum: str
    function_ea: int | None
    instruction_ea: int | None
    maturity: str | None

    def __post_init__(self) -> None:
        for field_name in ("case_id", "stratum"):
            value = getattr(self, field_name)
            if type(value) is not str or not value:
                raise ValueError(f"{field_name} must be a non-empty string")
        for field_name in ("function_ea", "instruction_ea"):
            value = getattr(self, field_name)
            if value is not None and (type(value) is not int or value < 0):
                raise ValueError(f"{field_name} must be a non-negative integer or None")
        if self.maturity is not None and (
            type(self.maturity) is not str or not self.maturity
        ):
            raise ValueError("maturity must be a non-empty string or None")

    @property
    def identity(self) -> str:
        return source_identity(self)

    def to_dict(self) -> dict[str, object]:
        return {
            "case_id": self.case_id,
            "stratum": self.stratum,
            "function_ea": self.function_ea,
            "instruction_ea": self.instruction_ea,
            "maturity": self.maturity,
        }

    @classmethod
    def from_dict(cls, data: Mapping[str, object]) -> "MbaResidualSource":
        expected = {"case_id", "stratum", "function_ea", "instruction_ea", "maturity"}
        if set(data) != expected:
            raise ValueError("residual source has invalid fields")
        return cls(
            case_id=data["case_id"],  # type: ignore[arg-type]
            stratum=data["stratum"],  # type: ignore[arg-type]
            function_ea=data["function_ea"],  # type: ignore[arg-type]
            instruction_ea=data["instruction_ea"],  # type: ignore[arg-type]
            maturity=data["maturity"],  # type: ignore[arg-type]
        )


@dataclass(frozen=True, slots=True)
class MbaResidualObservation:
    """One actual unresolved provider observation."""

    schema_version: int
    source: MbaResidualSource
    canonical_term: TypedBvTerm
    outcomes: tuple[MbaProviderOutcome, ...]

    def __post_init__(self) -> None:
        if (
            self.schema_version != RESIDUAL_CORPUS_SCHEMA_VERSION
            or type(self.schema_version) is not int
        ):
            raise ValueError("unsupported residual observation schema version")
        if not isinstance(self.source, MbaResidualSource):
            raise TypeError("source must be an MbaResidualSource")
        term = _validate_term(self.canonical_term)
        if not isinstance(self.outcomes, tuple) or not self.outcomes:
            raise ValueError("outcomes must contain at least one provider outcome")
        if any(
            not isinstance(outcome, MbaProviderOutcome) for outcome in self.outcomes
        ):
            raise TypeError("outcomes must contain MbaProviderOutcome objects")
        fingerprints = {outcome.fingerprint for outcome in self.outcomes}
        if len(fingerprints) != 1:
            raise ValueError(
                "all residual outcomes must share one candidate fingerprint"
            )
        statuses_by_provider: dict[object, set[ProviderOutcomeStatus]] = {}
        for outcome in self.outcomes:
            statuses_by_provider.setdefault(outcome.provider, set()).add(outcome.status)
            if outcome.status is ProviderOutcomeStatus.APPLIED:
                raise ValueError("applied provider outcomes are not residuals")
            if (
                outcome.status is ProviderOutcomeStatus.IMPROVED
                and outcome.input_cost is not None
                and outcome.output_cost is not None
                and outcome.output_cost < outcome.input_cost
            ):
                raise ValueError(
                    "improved outcomes with a cheaper output are not residuals"
                )
        if any(len(statuses) > 1 for statuses in statuses_by_provider.values()):
            raise ValueError(
                "duplicate provider rows have contradictory terminal states"
            )
        object.__setattr__(self, "canonical_term", term)
        object.__setattr__(self, "outcomes", tuple(self.outcomes))

    @property
    def candidate_fingerprint(self) -> str:
        return self.outcomes[0].fingerprint

    def to_dict(self) -> dict[str, object]:
        return {
            "schema_version": self.schema_version,
            "source": self.source.to_dict(),
            "canonical_term": typed_term_to_dict(self.canonical_term),
            "outcomes": [outcome.to_dict() for outcome in self.outcomes],
        }

    @classmethod
    def from_dict(cls, data: Mapping[str, object]) -> "MbaResidualObservation":
        expected = {"schema_version", "source", "canonical_term", "outcomes"}
        if set(data) != expected:
            raise ValueError("residual observation has invalid fields")
        raw_outcomes = data["outcomes"]
        if not isinstance(raw_outcomes, list):
            raise ValueError("residual observation outcomes must be a list")
        return cls(
            schema_version=data["schema_version"],  # type: ignore[arg-type]
            source=MbaResidualSource.from_dict(data["source"]),  # type: ignore[arg-type]
            canonical_term=typed_term_from_dict(data["canonical_term"]),  # type: ignore[arg-type]
            outcomes=tuple(_decode_outcome(item) for item in raw_outcomes),
        )


@dataclass(frozen=True, slots=True)
class MbaResidualGroup:
    """All source occurrences of one canonical term fingerprint."""

    fingerprint: str
    canonical_term: TypedBvTerm
    observations: tuple[MbaResidualObservation, ...]

    def __post_init__(self) -> None:
        term = _validate_term(self.canonical_term)
        expected_fingerprint = term_fingerprint(term)
        if self.fingerprint != expected_fingerprint:
            raise ValueError("residual group fingerprint does not match canonical term")
        if not isinstance(self.observations, tuple) or not self.observations:
            raise ValueError("residual group must contain observations")
        if any(
            not isinstance(observation, MbaResidualObservation)
            or term_fingerprint(observation.canonical_term) != expected_fingerprint
            for observation in self.observations
        ):
            raise ValueError("residual group observations must share canonical term")
        object.__setattr__(self, "canonical_term", term)
        object.__setattr__(self, "observations", tuple(self.observations))

    @property
    def occurrence_count(self) -> int:
        return len(self.observations)

    def to_dict(self) -> dict[str, object]:
        return {
            "fingerprint": self.fingerprint,
            "canonical_term": typed_term_to_dict(self.canonical_term),
            "occurrence_count": self.occurrence_count,
            "observations": [
                observation.to_dict() for observation in self.observations
            ],
        }


class MbaResidualCorpus:
    """Insertion-preserving recorder with deterministic report materialization."""

    schema_version = RESIDUAL_CORPUS_SCHEMA_VERSION

    def __init__(self, observations: Iterable[MbaResidualObservation] = ()) -> None:
        self._observations: list[MbaResidualObservation] = []
        self.extend(observations)

    def add(self, observation: MbaResidualObservation) -> None:
        if not isinstance(observation, MbaResidualObservation):
            raise TypeError("observation must be an MbaResidualObservation")
        self._observations.append(observation)

    record = add
    add_observation = add

    def extend(self, observations: Iterable[MbaResidualObservation]) -> None:
        for observation in observations:
            self.add(observation)

    @property
    def observations(self) -> tuple[MbaResidualObservation, ...]:
        return tuple(self._observations)

    @property
    def groups(self) -> tuple[MbaResidualGroup, ...]:
        grouped: dict[str, tuple[TypedBvTerm, list[MbaResidualObservation]]] = {}
        for observation in self._observations:
            fingerprint = term_fingerprint(observation.canonical_term)
            entry = grouped.setdefault(fingerprint, (observation.canonical_term, []))
            if entry[0] != observation.canonical_term:
                raise ValueError("same residual fingerprint has conflicting terms")
            entry[1].append(observation)
        return tuple(
            MbaResidualGroup(
                fingerprint=fingerprint,
                canonical_term=term,
                observations=tuple(
                    sorted(observations, key=_observation_sort_key)
                ),
            )
            for fingerprint, (term, observations) in sorted(grouped.items())
        )

    def groups_for_mining(
        self, *, include_errors: bool = False
    ) -> tuple[MbaResidualGroup, ...]:
        if include_errors:
            return self.groups
        return tuple(
            group
            for group in self.groups
            if any(
                outcome.status is not ProviderOutcomeStatus.ERROR
                for observation in group.observations
                for outcome in observation.outcomes
            )
        )

    mining_groups = groups_for_mining
    select_for_mining = groups_for_mining

    def to_dict(self) -> dict[str, object]:
        return {
            "schema_version": RESIDUAL_CORPUS_SCHEMA_VERSION,
            "groups": [group.to_dict() for group in self.groups],
        }

    def to_json(self) -> str:
        return (
            json.dumps(
                self.to_dict(),
                allow_nan=False,
                ensure_ascii=True,
                indent=2,
                sort_keys=True,
            )
            + "\n"
        )

    @classmethod
    def from_dict(cls, data: Mapping[str, object]) -> "MbaResidualCorpus":
        if set(data) != {"schema_version", "groups"}:
            raise ValueError("residual corpus has invalid fields")
        if (
            type(data["schema_version"]) is not int
            or data["schema_version"] != RESIDUAL_CORPUS_SCHEMA_VERSION
        ):
            raise ValueError("unsupported residual corpus schema version")
        raw_groups = data["groups"]
        if not isinstance(raw_groups, list):
            raise ValueError("residual corpus groups must be a list")
        corpus = cls()
        seen: set[str] = set()
        for raw_group in raw_groups:
            if not isinstance(raw_group, Mapping):
                raise ValueError("residual corpus group must be a mapping")
            if set(raw_group) != {
                "fingerprint",
                "canonical_term",
                "occurrence_count",
                "observations",
            }:
                raise ValueError("residual group has invalid fields")
            raw_observations = raw_group["observations"]
            if not isinstance(raw_observations, list):
                raise ValueError("residual group observations must be a list")
            observations = tuple(
                MbaResidualObservation.from_dict(item)  # type: ignore[arg-type]
                for item in raw_observations
            )
            if type(raw_group["occurrence_count"]) is not int or (
                raw_group["occurrence_count"] != len(observations)
            ):
                raise ValueError("residual group occurrence_count is inconsistent")
            fingerprint = raw_group["fingerprint"]
            if type(fingerprint) is not str or fingerprint in seen:
                raise ValueError("residual group fingerprints must be unique strings")
            seen.add(fingerprint)
            canonical_term = typed_term_from_dict(raw_group["canonical_term"])  # type: ignore[arg-type]
            group = MbaResidualGroup(fingerprint, canonical_term, observations)
            corpus.extend(group.observations)
        return corpus

    @classmethod
    def from_json(cls, value: str) -> "MbaResidualCorpus":
        try:
            data = json.loads(value)
        except json.JSONDecodeError as exc:
            raise ValueError("invalid residual corpus JSON") from exc
        if not isinstance(data, Mapping):
            raise ValueError("residual corpus JSON must contain a mapping")
        return cls.from_dict(data)


__all__ = [
    "MbaResidualCorpus",
    "MbaResidualGroup",
    "MbaResidualObservation",
    "MbaResidualSource",
    "RESIDUAL_CORPUS_METADATA_KEY",
    "RESIDUAL_CORPUS_SCHEMA_VERSION",
    "source_identity",
]
