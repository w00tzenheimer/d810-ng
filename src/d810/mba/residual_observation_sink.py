"""D810-owned host sink for portable MBA residual observations."""

from __future__ import annotations

import threading
from collections.abc import Mapping
from dataclasses import replace

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

    @staticmethod
    def _eligible_for_mining(observation: MbaResidualRecord) -> bool:
        """Apply the host's portable residual eligibility policy."""
        return (
            observation.context.function_identity.external_evidence_allowed
            and observation.outcome.status.value != "error"
        )

    @staticmethod
    def _safe_log(observation: object, exc: BaseException) -> None:
        """Log callback failures without trusting malformed context objects."""
        try:
            context = getattr(observation, "context", None)
            plugin_identity = getattr(context, "plugin_identity", None)
            plugin = getattr(plugin_identity, "name", "<unknown>")
            instruction_ea = getattr(context, "instruction_ea", None)
            block = getattr(context, "block_identity", None)
            anchor = (
                f"0x{instruction_ea:X}"
                if isinstance(instruction_ea, int)
                else repr(instruction_ea)
            )
            block_text = f" block={block}" if block is not None else ""
            logger.exception(
                "MBA residual observation callback failed plugin=%s instruction_ea=%s%s",
                plugin,
                anchor,
                block_text,
            )
        except Exception:
            try:
                logger.exception("MBA residual observation callback failed")
            except Exception:
                pass

    def bind_activation(self, identity: PluginIdentity) -> MbaResidualObservationSink:
        """Return the only plugin-facing view of this host-owned sink."""
        if not isinstance(identity, PluginIdentity):
            raise TypeError("activation binding requires a PluginIdentity")
        return _ActivationScopedResidualSink(self, identity)

    def _validate(
        self,
        observation: MbaResidualRecord,
        activation_identity: PluginIdentity | None = None,
    ) -> DiscoveryAttempt:
        if not isinstance(observation, MbaResidualRecord):
            raise TypeError("observation must be an MbaResidualRecord")
        identity = observation.context.plugin_identity
        if activation_identity is not None and identity != activation_identity:
            raise ValueError("plugin_identity_mismatch")
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
        expected_provider = provider_kind_for_plugin(activation_identity or identity)
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
        outcome = observation.outcome
        if observation.candidate_cost is not None and outcome.input_cost is None:
            outcome = replace(outcome, input_cost=observation.candidate_cost)
        if observation.replacement_cost is not None and outcome.output_cost is None:
            outcome = replace(outcome, output_cost=observation.replacement_cost)
        # The value object constructors enforce all identity/anchor invariants;
        # constructing the store model keeps those checks at this boundary too.
        return DiscoveryAttempt(
            attempt_uuid=observation.attempt_uuid,
            context=observation.context,
            raw_term=raw,
            canonical_term=canonical,
            outcome=outcome,
            eligible_for_mining=self._eligible_for_mining(observation),
        )

    def _record(
        self,
        observation: MbaResidualRecord,
        activation_identity: PluginIdentity | None,
    ) -> MbaResidualReceipt:
        with self._lock:
            try:
                if self._closed:
                    return self._rejected("closed")
                attempt = self._validate(observation, activation_identity)
                receipt = self._store.record_attempt(attempt)
                status = getattr(receipt, "status", None)
                status_value = getattr(status, "value", status)
                if status_value == "stored":
                    return MbaResidualReceipt("stored")
                if status_value == "duplicate":
                    return MbaResidualReceipt("duplicate")
                reason = getattr(receipt, "reason", None) or "store_refused"
                return self._rejected(str(reason))
            except (TypeError, ValueError) as exc:
                reason = str(exc) or "invalid_observation"
                return self._rejected(reason)
            except Exception as exc:
                self._safe_log(observation, exc)
                return self._rejected("storage_error")

    def record(self, observation: MbaResidualRecord) -> MbaResidualReceipt:
        """Record one observation without allowing errors through callbacks."""
        return self._record(observation, None)

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


class _ActivationScopedResidualSink:
    """Minimal record-only facade bound to one host-created identity."""

    __slots__ = ("_sink", "_identity")

    def __init__(
        self, sink: SqliteMbaResidualObservationSink, identity: PluginIdentity
    ):
        self._sink = sink
        self._identity = identity

    def record(self, observation: MbaResidualRecord) -> MbaResidualReceipt:
        return self._sink._record(observation, self._identity)
