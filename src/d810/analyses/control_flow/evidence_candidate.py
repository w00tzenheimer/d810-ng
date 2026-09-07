"""Tri-state result for parsing one evidence candidate at a trust boundary.

Round-3 review of d81-9q6e: the branch-ownership and typed-trust adapters both
answered ``None`` for two situations that must not be treated alike.

* *No candidate was supplied.*  Continuing to the next, weaker evidence source
  is correct.
* *A candidate was supplied but could not be parsed* -- a required field was
  missing, or a field held an unusable value.  The row was silently skipped, so
  a weaker source answered for it: an incomplete typed trust row fell through
  to the ``global_or_state_write`` provenance tag and was granted
  ``DYNAMIC_STATE_WRITE``.

A present-but-unparsable candidate is now :attr:`EvidenceCandidateState.MALFORMED`
and terminal: the consumer refuses and names the malformed candidate.  Only
:attr:`EvidenceCandidateState.ABSENT` may continue to the next source.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum

from d810.core.typing import Generic, TypeVar

ValueT = TypeVar("ValueT")


class EvidenceCandidateState(str, Enum):
    """Whether an evidence candidate was absent, unparsable, or parsed.

    ``ABSENT``
        No candidate was supplied.  The consumer may consult the next evidence
        source.

    ``MALFORMED``
        A candidate was supplied and could not be parsed.  The consumer must
        refuse; it may **not** consult a weaker source, because doing so lets
        an incomplete row buy a grant it could not earn.

    ``PARSED``
        The candidate parsed.  Its own verdict decides the outcome.
    """

    ABSENT = "absent"
    MALFORMED = "malformed"
    PARSED = "parsed"


@dataclass(frozen=True, slots=True)
class EvidenceCandidate(Generic[ValueT]):
    """One parsed-or-refused evidence candidate."""

    state: EvidenceCandidateState
    value: ValueT | None = None
    detail: str = ""

    @classmethod
    def absent(cls) -> EvidenceCandidate[ValueT]:
        return cls(EvidenceCandidateState.ABSENT)

    @classmethod
    def malformed(cls, detail: str) -> EvidenceCandidate[ValueT]:
        return cls(EvidenceCandidateState.MALFORMED, detail=detail)

    @classmethod
    def parsed(cls, value: ValueT) -> EvidenceCandidate[ValueT]:
        return cls(EvidenceCandidateState.PARSED, value=value)

    @property
    def is_absent(self) -> bool:
        return self.state is EvidenceCandidateState.ABSENT

    @property
    def is_malformed(self) -> bool:
        return self.state is EvidenceCandidateState.MALFORMED

    @property
    def is_parsed(self) -> bool:
        return self.state is EvidenceCandidateState.PARSED


__all__ = [
    "EvidenceCandidate",
    "EvidenceCandidateState",
]
