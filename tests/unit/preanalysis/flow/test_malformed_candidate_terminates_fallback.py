"""A present-but-unparsable evidence candidate must refuse, not fall through.

Second P1 of the d81-9q6e round-3 review.  Both adapters answered ``None``
for two very different situations:

* *no candidate was supplied* -- correct to continue to the next evidence
  source;
* *a candidate was supplied but could not be parsed* (a required field was
  missing, or a field held an unusable value) -- the row was silently
  skipped, so the weaker ``global_or_state_write`` provenance tag answered
  for it and granted ``DYNAMIC_STATE_WRITE``.

The second case is now terminal: the classification refuses, names the
malformed candidate, and never consults the weaker source.
"""

from __future__ import annotations

from types import SimpleNamespace

import pytest

from d810.analyses.control_flow.branch_ownership import (
    BranchOwnershipOracleKind,
    BranchOwnershipProofKind,
)
from d810.analyses.control_flow.transition_trust import (
    TransitionTrustKind,
    classify_transition_trust_for_explicit_conditional_bridge,
)

#: A provenance tag that grants on its own, so any fallthrough is visible.
_GRANTING_WEAKER_SOURCE = "global_or_state_write"

_TRUST_ROW: dict[str, object] = {
    "trusted": True,
    "reason": "typed_producer_says_so",
    "trust_kind": TransitionTrustKind.EXPLICIT_PRODUCER_TRUST.value,
    "producer": "an_oracle",
}

_OWNERSHIP_ROW: dict[str, object] = {
    "proof_id": "p0",
    "proof_kind": BranchOwnershipProofKind.REAL_DATA_DEPENDENT.value,
    "trusted": True,
    "reason": "ownership_says_so",
    "oracle_kind": BranchOwnershipOracleKind.MOPTRACKER.value,
}


def _transition(**kwargs: object) -> SimpleNamespace:
    values: dict[str, object] = {
        "is_conditional": True,
        "provenance_chain": [(1, 2)],
        "provenance_kind": _GRANTING_WEAKER_SOURCE,
    }
    values.update(kwargs)
    return SimpleNamespace(**values)


def _assert_weaker_source_not_consulted(result: object) -> None:
    assert getattr(result, "authorizes_explicit_conditional_bridge") is False
    assert getattr(result, "trust_kind_name") != (
        TransitionTrustKind.DYNAMIC_STATE_WRITE.value
    )
    assert getattr(result, "evidence").get("source") != "provenance_tag_adapter"


class TestTheWeakerSourceReallyGrants:
    """Control: without a malformed candidate the tag grants on its own."""

    def test_provenance_tag_alone_grants(self) -> None:
        result = classify_transition_trust_for_explicit_conditional_bridge(
            _transition()
        )

        assert result.authorizes_explicit_conditional_bridge is True
        assert result.trust_kind_name == TransitionTrustKind.DYNAMIC_STATE_WRITE.value


class TestMalformedTypedTrustRowIsTerminal:
    @pytest.mark.parametrize("missing", ["trusted", "reason"])
    @pytest.mark.parametrize("attr", ["transition_trust", "trust_result"])
    def test_reviewer_reproduction_incomplete_trust_row_does_not_fall_through(
        self, missing: str, attr: str
    ) -> None:
        row = {key: value for key, value in _TRUST_ROW.items() if key != missing}

        result = classify_transition_trust_for_explicit_conditional_bridge(
            _transition(**{attr: row})
        )

        _assert_weaker_source_not_consulted(result)
        assert "malformed" in result.reason

    def test_an_incomplete_row_in_metadata_is_terminal_too(self) -> None:
        row = {key: value for key, value in _TRUST_ROW.items() if key != "reason"}

        result = classify_transition_trust_for_explicit_conditional_bridge(
            _transition(metadata={"trust_result": row})
        )

        _assert_weaker_source_not_consulted(result)

    @pytest.mark.parametrize("value", [object(), "trusted", 7, [1, 2]])
    def test_an_unparsable_trust_candidate_is_terminal(self, value: object) -> None:
        result = classify_transition_trust_for_explicit_conditional_bridge(
            _transition(transition_trust=value)
        )

        _assert_weaker_source_not_consulted(result)


class TestMalformedBranchOwnershipRowIsTerminal:
    @pytest.mark.parametrize("missing", ["proof_id", "proof_kind", "reason"])
    @pytest.mark.parametrize(
        "attr", ["branch_ownership_proof", "branch_ownership"]
    )
    def test_reviewer_reproduction_incomplete_proof_does_not_fall_through(
        self, missing: str, attr: str
    ) -> None:
        row = {key: value for key, value in _OWNERSHIP_ROW.items() if key != missing}

        result = classify_transition_trust_for_explicit_conditional_bridge(
            _transition(**{attr: row})
        )

        _assert_weaker_source_not_consulted(result)
        assert "malformed" in result.reason

    def test_an_unusable_proof_kind_is_terminal(self) -> None:
        row = dict(_OWNERSHIP_ROW, proof_kind="NOT_A_PROOF_KIND")

        result = classify_transition_trust_for_explicit_conditional_bridge(
            _transition(branch_ownership_proof=row)
        )

        _assert_weaker_source_not_consulted(result)

    def test_an_incomplete_proof_in_metadata_is_terminal_too(self) -> None:
        row = {
            key: value for key, value in _OWNERSHIP_ROW.items() if key != "proof_id"
        }

        result = classify_transition_trust_for_explicit_conditional_bridge(
            _transition(metadata={"branch_ownership_proof": row})
        )

        _assert_weaker_source_not_consulted(result)

    @pytest.mark.parametrize("value", [object(), "proof", 7, [1, 2]])
    def test_an_unparsable_ownership_candidate_is_terminal(
        self, value: object
    ) -> None:
        result = classify_transition_trust_for_explicit_conditional_bridge(
            _transition(branch_ownership_proof=value)
        )

        _assert_weaker_source_not_consulted(result)
