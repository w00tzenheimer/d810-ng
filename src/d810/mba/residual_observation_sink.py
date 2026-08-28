"""D810-owned host sink for portable MBA residual observations."""

from __future__ import annotations

import threading
from collections.abc import Mapping

from d810.core.logging import getLogger
from d810.core.plugins import PluginIdentity
from d810.mba.discovery_models import DiscoveryAttempt
from d810.mba.discovery_store import MbaDiscoveryStore
from d810.mba.extension_api import (
    MbaResidualObservationSink,
    MbaResidualReceipt,
    MbaResidualRecord,
)
from d810.mba.provider_routing import MbaProviderKind
from d810.mba.semantic_canonicalization import canonicalize_mba_term
from d810.mba.typed_term import term_fingerprint


logger = getLogger(__name__)

# This is deliberately the only provider identity policy used by the sink.
# The activation layer controls PluginIdentity; persistence only consumes the
# resulting policy decision.
_PLUGIN_PROVIDER_KINDS: Mapping[str, MbaProviderKind] = {
    "cobra": MbaProviderKind.COEFFICIENT_SOLVER,
    "d810-cobra": MbaProviderKind.COEFFICIENT_SOLVER,
    "egglog": MbaProviderKind.EGRAPH,
    "d810-egglog": MbaProviderKind.EGRAPH,
}


def provider_kind_for_plugin(identity: PluginIdentity) -> MbaProviderKind | None:
    """Return the host-authorized provider family for an activated plugin."""

    if not isinstance(identity, PluginIdentity):
        return None
    return _PLUGIN_PROVIDER_KINDS.get(identity.name)


class SqliteMbaResidualObservationSink(MbaResidualObservationSink):
    """Validate and translate residual records into the D810 discovery store."""

    def __init__(self, store: MbaDiscoveryStore) -> None:
        if not callable(getattr(store, "record_attempt", None)):
            raise TypeError("store must provide record_attempt(attempt)")
        self._store = store
        self._lock = threading.RLock()
        self._closed = False

    @staticmethod
    def _rejected(reason: str) -> MbaResidualReceipt:
        return MbaResidualReceipt("rejected", reason)

    def _validate(self, observation: MbaResidualRecord) -> DiscoveryAttempt:
        if not isinstance(observation, MbaResidualRecord):
            raise TypeError("observation must be an MbaResidualRecord")
        raw = observation.raw_term
        canonical = observation.canonical_term
        if raw.width != canonical.width or raw.width not in {8, 16, 32, 64}:
            raise ValueError("term_width_mismatch")
        canonical_view = canonicalize_mba_term(raw)
        if canonical_view.canonical_term != canonical:
            raise ValueError("canonical_term_mismatch")
        if term_fingerprint(canonical) != observation.outcome.fingerprint:
            raise ValueError("fingerprint_mismatch")
        if observation.outcome.status.value == "applied":
            raise ValueError("applied_not_residual")
        if observation.materialized:
            raise ValueError("materialized_not_residual")
        expected_provider = provider_kind_for_plugin(
            observation.context.plugin_identity
        )
        if expected_provider is None:
            raise ValueError("unknown_plugin_identity")
        if observation.outcome.provider is not expected_provider:
            raise ValueError("provider_plugin_mismatch")
        if (
            observation.candidate_cost is not None
            and observation.outcome.input_cost is not None
            and observation.candidate_cost != observation.outcome.input_cost
        ):
            raise ValueError("candidate_cost_mismatch")
        if (
            observation.replacement_cost is not None
            and observation.outcome.output_cost is not None
            and observation.replacement_cost != observation.outcome.output_cost
        ):
            raise ValueError("replacement_cost_mismatch")
        # The value object constructors enforce all identity/anchor invariants;
        # constructing the store model keeps those checks at this boundary too.
        return DiscoveryAttempt(
            attempt_uuid=observation.attempt_uuid,
            context=observation.context,
            raw_term=raw,
            canonical_term=canonical,
            outcome=observation.outcome,
            eligible_for_mining=observation.context.function_identity.external_evidence_allowed,
        )

    def record(self, observation: MbaResidualRecord) -> MbaResidualReceipt:
        """Record one observation without allowing errors through callbacks."""

        with self._lock:
            if self._closed:
                return self._rejected("closed")
            try:
                attempt = self._validate(observation)
            except (TypeError, ValueError) as exc:
                reason = str(exc) or "invalid_observation"
                return self._rejected(reason)
            try:
                receipt = self._store.record_attempt(attempt)
            except Exception:
                context = observation.context
                block = context.block_identity
                logger.exception(
                    "MBA residual observation storage failed plugin=%s instruction_ea=0x%X%s",
                    context.plugin_identity.name,
                    context.instruction_ea,
                    f" block={block}" if block is not None else "",
                )
                return self._rejected("storage_error")
            status = getattr(receipt, "status", None)
            status_value = getattr(status, "value", status)
            if status_value == "stored":
                return MbaResidualReceipt("stored")
            if status_value == "duplicate":
                return MbaResidualReceipt("duplicate")
            reason = getattr(receipt, "reason", None) or "store_refused"
            return self._rejected(str(reason))

    def close(self) -> None:
        with self._lock:
            if self._closed:
                return
            self._closed = True
            close = getattr(self._store, "close", None)
            if callable(close):
                close()


__all__ = [
    "SqliteMbaResidualObservationSink",
    "provider_kind_for_plugin",
]
