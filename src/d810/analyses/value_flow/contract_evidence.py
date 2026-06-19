"""Canonical contract evidence tokens for native pass contracts.

``FactObservation.evidence`` is raw diagnostic/provenance text: instruction
strings, source snippets, or proof breadcrumbs.  Native pass contracts must not
treat that text as a capability token.  Contract evidence is deliberate metadata
under the payload keys below, plus a small allowlisted projection from known
production fact families.
"""
from __future__ import annotations

from enum import Enum

from d810.core.typing import Mapping

CONTRACT_EVIDENCE_KEY = "contract_evidence"
CONTRACT_EVIDENCE_TOKENS_KEY = "contract_evidence_tokens"


class ContractEvidenceToken(str, Enum):
    """Stable public evidence vocabulary used by ``requires.evidence``."""

    STATE_VARIABLE_WRITES = "state_variable_writes"
    DISPATCHER_PREDICATES = "dispatcher_predicates"
    BRANCH_TARGETS = "branch_targets"


CONTRACT_EVIDENCE_TOKENS = frozenset(token.value for token in ContractEvidenceToken)


def contract_evidence_payload(*tokens: str | ContractEvidenceToken) -> dict[str, list[str]]:
    """Return the canonical payload fragment for explicitly published tokens."""
    return {
        CONTRACT_EVIDENCE_TOKENS_KEY: sorted(
            _canonical_tokens(tokens, strict=True)
        )
    }


def contract_evidence_tokens(observation: object) -> frozenset[str]:
    """Return canonical contract evidence tokens carried by ``observation``.

    Raw ``observation.evidence`` is intentionally ignored.  It remains useful as
    diagnostic provenance, but it is not a contract namespace.
    """
    tokens: set[str] = set()
    payload = getattr(observation, "payload", None)
    if isinstance(payload, Mapping):
        tokens.update(_tokens_from_payload(payload.get(CONTRACT_EVIDENCE_KEY)))
        tokens.update(_tokens_from_payload(payload.get(CONTRACT_EVIDENCE_TOKENS_KEY)))

    # Backward/producer compatibility: these production fact families are known
    # to represent state-variable writes even before every producer has payload
    # token metadata.
    if getattr(observation, "kind", None) in {"StateWriteAnchorFact", "StateWriteFact"}:
        tokens.add(ContractEvidenceToken.STATE_VARIABLE_WRITES.value)

    return frozenset(token for token in tokens if token in CONTRACT_EVIDENCE_TOKENS)


def _canonical_tokens(values, *, strict: bool = False) -> frozenset[str]:
    tokens = frozenset(
        token.value if isinstance(token, ContractEvidenceToken) else str(token)
        for token in values
        if token
    )
    if strict:
        unknown = sorted(token for token in tokens if token not in CONTRACT_EVIDENCE_TOKENS)
        if unknown:
            raise ValueError(f"unknown contract evidence token(s): {unknown}")
    return tokens


def _tokens_from_payload(value) -> frozenset[str]:
    if value is None:
        return frozenset()
    if isinstance(value, ContractEvidenceToken):
        return frozenset({value.value})
    if isinstance(value, str):
        return frozenset({value})
    if isinstance(value, Mapping):
        return frozenset(str(key) for key, enabled in value.items() if enabled)
    try:
        return frozenset(
            item.value if isinstance(item, ContractEvidenceToken) else str(item)
            for item in value
            if item
        )
    except TypeError:
        return frozenset({str(value)})


__all__ = [
    "CONTRACT_EVIDENCE_KEY",
    "CONTRACT_EVIDENCE_TOKENS",
    "CONTRACT_EVIDENCE_TOKENS_KEY",
    "ContractEvidenceToken",
    "contract_evidence_payload",
    "contract_evidence_tokens",
]
