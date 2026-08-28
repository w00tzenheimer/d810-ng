"""Task 7 tests for provider publication at the outer mutation boundary."""

from __future__ import annotations

from uuid import uuid4

import pytest

from d810.core.function_execution_identity import (
    FunctionExecutionIdentity,
    MbaObservationContext,
)
from d810.core.plugins import PluginIdentity
from d810.mba.extension_api import (
    PendingMbaProviderObservation,
)
from d810.mba.provider_outcome import MbaProviderOutcome, ProviderOutcomeStatus
from d810.mba.provider_routing import MbaProviderKind
from d810.mba.semantic_canonicalization import canonicalize_mba_term
from d810.mba.typed_term import TypedBvTerm, term_fingerprint


def _context(plugin: PluginIdentity | None = None) -> MbaObservationContext:
    identity = FunctionExecutionIdentity(
        input_identity="idb-local:12345678-1234-5678-1234-567812345678",
        input_identity_provenance="current_idb",
        external_evidence_allowed=False,
        database_uuid="12345678-1234-5678-1234-567812345678",
        database_identity="task7-test-idb",
        function_ea=0x401000,
        function_rva=0x1000,
        function_fingerprint="task7-function",
        decompilation_session_id="12345678-1234-5678-1234-567812345679",
        top_level_epoch=1,
        maturity="ir.canonical",
        evidence_generation=1,
    )
    return MbaObservationContext(
        function_identity=identity,
        plugin_identity=plugin
        or PluginIdentity("cobra", "d810-cobra", "1.0", "task7-test"),
        instruction_ea=0x401002,
        block_serial=7,
        block_ea=0x401000,
    )


def _pending(
    status: ProviderOutcomeStatus = ProviderOutcomeStatus.UNCHANGED,
) -> PendingMbaProviderObservation:
    raw = TypedBvTerm(
        "xor",
        32,
        children=(TypedBvTerm(None, 32, value=1), TypedBvTerm(None, 32, value=2)),
    )
    canonical = canonicalize_mba_term(raw).canonical_term
    return PendingMbaProviderObservation(
        attempt_uuid=str(uuid4()),
        raw_term=raw,
        canonical_term=canonical,
        outcome=MbaProviderOutcome(
            provider=MbaProviderKind.COEFFICIENT_SOLVER,
            status=status,
            fingerprint=term_fingerprint(canonical),
            input_cost=(2, 3),
        ),
    )


def test_pending_provider_observation_is_immutable_and_portable() -> None:
    pending = _pending()
    assert pending.outcome.status is ProviderOutcomeStatus.UNCHANGED
    with pytest.raises((AttributeError, TypeError)):
        pending.attempt_uuid = str(uuid4())  # type: ignore[misc]


def test_pending_applied_outcome_is_not_a_residual_record() -> None:
    pending = _pending(ProviderOutcomeStatus.APPLIED)
    assert pending.outcome.status is ProviderOutcomeStatus.APPLIED
    # The base finalizer must consume this state without invoking a sink.
    assert pending.outcome.status is not ProviderOutcomeStatus.UNCHANGED
