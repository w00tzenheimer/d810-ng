"""D810-owned host sink for portable MBA residual observations."""

from __future__ import annotations

import threading
from time import perf_counter
from collections.abc import Mapping
from dataclasses import replace

from d810.core.function_execution_identity import MbaObservationContext
from d810.core.logging import getLogger
from d810.core.plugins import PassImplementationCandidate, PluginIdentity
from d810.mba.discovery_models import DiscoveryAttempt
from d810.mba.discovery_store import MbaDiscoveryStore
from d810.mba.extension_api import (
    D810_MBA_RESIDUAL_OBSERVATION_CAPABILITY,
    MbaResidualObservationSink,
    MbaResidualReceipt,
    MbaResidualRecord,
)
from d810.mba.provider_routing import MbaProviderKind
from d810.mba.semantic_canonicalization import canonicalize_mba_term
from d810.mba.typed_term import TypedBvTerm, term_fingerprint


logger = getLogger(__name__)

#: Upper bound on the per-sink canonicalization memo.  One decompile of a
#: heavily obfuscated function observes a few hundred distinct terms.
_CANONICAL_VIEW_MEMO_LIMIT = 4096

# This is deliberately the only provider authorization policy used by the
# sink. It consumes the exact selected manifest implementation, never a plugin
# display name that another distribution could reuse.
_IMPLEMENTATION_PROVIDER_KINDS: Mapping[
    tuple[str, str, str], MbaProviderKind
] = {
    ("mba-solve", "cobra", "cobra-solve"): MbaProviderKind.COEFFICIENT_SOLVER,
    ("mba-egraph", "egglog", "egglog-optimizer"): MbaProviderKind.EGRAPH,
}


def provider_kind_for_implementation(
    candidate: PassImplementationCandidate,
) -> MbaProviderKind | None:
    """Return the provider family authorized by one exact manifest row."""

    if not isinstance(candidate, PassImplementationCandidate):
        return None
    return _IMPLEMENTATION_PROVIDER_KINDS.get(
        (candidate.pass_id, candidate.backend_name, candidate.rule_name)
    )


def _issue_activation_view(
    owner: object, identity: PluginIdentity
) -> MbaResidualObservationSink:
    """Freeze one identity-scoped, record-only view of *owner*."""
    if not isinstance(identity, PluginIdentity):
        raise TypeError("activation binding requires a PluginIdentity")
    return _ActivationScopedResidualSink(owner, identity)


def _issue_implementation_view(
    owner: object,
    activation_view: object,
    candidate: PassImplementationCandidate,
) -> MbaResidualObservationSink:
    """Narrow an owned activation view to one exact selected implementation."""
    if (
        not isinstance(activation_view, _ActivationScopedResidualSink)
        or activation_view._owner is not owner
    ):
        raise TypeError("implementation binding requires an owned activation view")
    return activation_view._bind_selected_implementation(candidate)


class MbaResidualSinkRelay:
    """The stable routing point one host lifecycle owns for its whole life.

    A capability view is frozen the moment a provider resolves it, so it must
    not name a sink *generation*: ``state.load_project()`` restarts the manager
    and closes that generation while the provider rule keeps recording into the
    view it already holds (d81-uncr).  Views therefore name this relay, and a
    restart only retargets the relay.

    The relay belongs to exactly one
    :class:`~d810.mba.residual_observation_lifecycle.MbaResidualObservationLifecycle`
    and is created with it; it is never a module-level or otherwise shared
    object.  That is what bounds the rebind: a view issued by lifecycle A can
    only ever reach a sink A installed, so once A is retired its views fail
    closed exactly like an unpublished sink, even while lifecycle B is running
    (d81-mcqr).
    """

    __slots__ = (
        "_lock",
        "_target",
        "_generations",
        "_closed",
        "_warned_closed",
        "_rebind_logged",
    )

    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._target: SqliteMbaResidualObservationSink | None = None
        self._generations = 0
        self._closed = False
        self._warned_closed = False
        self._rebind_logged = False

    # The three observers below deliberately read without the lock.  Recording
    # holds the relay lock for the whole store write, so a locking accessor
    # would make a diagnostic probe block behind provider traffic; a single
    # attribute read is atomic and always sees a fully installed generation.
    @property
    def target(self) -> "SqliteMbaResidualObservationSink | None":
        """Return the sink generation this relay routes to right now."""
        return self._target

    @property
    def closed(self) -> bool:
        """True once the owning lifecycle retired the relay for good."""
        return self._closed

    @property
    def generations(self) -> int:
        """Number of sinks installed so far, for restart-aware diagnostics."""
        return self._generations

    def install(self, sink: "SqliteMbaResidualObservationSink") -> None:
        """Atomically retarget: close the old generation, publish *sink*.

        The whole swap happens under the relay lock, and recording takes the
        same lock, so a record racing a restart lands wholly in the old or
        wholly in the new sink -- it is never rejected and never split.
        """
        if not isinstance(sink, SqliteMbaResidualObservationSink):
            raise TypeError("only a host-owned sink can back a residual relay")
        with self._lock:
            if self._closed:
                raise RuntimeError("a retired residual relay cannot be retargeted")
            previous = self._target
            if previous is sink:
                return
            self._target = sink
            self._generations += 1
            if previous is not None:
                previous.close()

    def retire(self) -> None:
        """Drop the current generation; views fail closed until reinstalled."""
        with self._lock:
            previous = self._target
            self._target = None
            if previous is not None:
                previous.close()

    def close(self) -> None:
        """Retire the relay permanently: no successor can ever be installed."""
        with self._lock:
            self._closed = True
            self.retire()

    def bind_activation(self, identity: PluginIdentity) -> MbaResidualObservationSink:
        """Return the only plugin-facing view routed by this relay."""
        return _issue_activation_view(self, identity)

    def bind_implementation(
        self,
        activation_view: object,
        candidate: PassImplementationCandidate,
    ) -> MbaResidualObservationSink:
        """Bind exact registry-selected authority without exposing a plugin API."""
        return _issue_implementation_view(self, activation_view, candidate)

    def record(self, observation: MbaResidualRecord) -> MbaResidualReceipt:
        """Record one observation into the generation this relay owns."""
        return self._record(observation, None)

    def _record(
        self,
        observation: MbaResidualRecord,
        activation_identity: PluginIdentity | None,
        expected_provider: MbaProviderKind | None = None,
    ) -> MbaResidualReceipt:
        with self._lock:
            target = self._target
            if target is None:
                self._warn_closed_once()
                return MbaResidualReceipt("rejected", "closed")
            if self._generations > 1:
                self._note_rebind_once()
            return target._record(
                observation,
                activation_identity,
                expected_provider,
            )

    def _note_rebind_once(self) -> None:
        """Make the orphan-and-rebind event visible once per relay."""
        if self._rebind_logged:
            return
        self._rebind_logged = True
        logger.info(
            "mba residual observation rebound capability=%s: a view bound before "
            "the manager restart now records into the replacement sink",
            D810_MBA_RESIDUAL_OBSERVATION_CAPABILITY,
        )

    def _warn_closed_once(self) -> None:
        """Name the capability the first time this relay loses an observation."""
        if self._warned_closed:
            return
        self._warned_closed = True
        logger.warning(
            "MBA residual observation dropped: capability %s has no open sink; "
            "every further observation from this view is rejected 'closed'",
            D810_MBA_RESIDUAL_OBSERVATION_CAPABILITY,
        )


class SqliteMbaResidualObservationSink(MbaResidualObservationSink):
    """Validate and translate residual records into the D810 discovery store."""

    def __init__(
        self,
        store: MbaDiscoveryStore,
        *,
        recording_enabled: bool = True,
    ) -> None:
        if not callable(getattr(store, "record_attempt", None)):
            raise TypeError("store must provide record_attempt(attempt)")
        if type(recording_enabled) is not bool:
            raise TypeError("recording_enabled must be a bool")
        self._store = store
        self._lock = threading.RLock()
        self._closed = False
        self._recording_enabled = recording_enabled
        # raw term -> canonical view.  The tamper check below re-derives the
        # canonical term the extension host already computed on capture; the
        # same raw term reaches this sink once per re-visit of the same
        # instruction, so memoizing keeps the check while paying for it once.
        self._canonical_views: dict[TypedBvTerm, object] = {}
        self._stored = 0
        self._duplicate = 0
        self._rejected_count = 0
        self._warned_closed = False

    def traffic(self) -> tuple[int, int, int]:
        """Return ``(stored, duplicate, rejected)`` this generation saw."""
        with self._lock:
            return (self._stored, self._duplicate, self._rejected_count)

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
            anchor = (
                f"0x{instruction_ea:X}"
                if isinstance(instruction_ea, int)
                else repr(instruction_ea)
            )
            block_text = ""
            if isinstance(context, MbaObservationContext):
                block_serial = context.block_serial
                block_ea = context.block_ea
                if isinstance(block_serial, int) and isinstance(block_ea, int):
                    block_text = f" block=blk{block_serial}@0x{block_ea:X}"
            logger.exception(
                "MBA residual observation callback failed plugin=%s instruction_ea=%s%s",
                plugin,
                anchor,
                block_text,
            )
        except BaseException:
            try:
                logger.exception("MBA residual observation callback failed")
            except BaseException:
                pass

    def bind_activation(self, identity: PluginIdentity) -> MbaResidualObservationSink:
        """Return the only plugin-facing view of this host-owned sink."""
        return _issue_activation_view(self, identity)

    def bind_implementation(
        self,
        activation_view: object,
        candidate: PassImplementationCandidate,
    ) -> MbaResidualObservationSink:
        """Bind exact registry-selected authority without exposing a plugin API."""
        return _issue_implementation_view(self, activation_view, candidate)

    def _canonical_view(self, raw: TypedBvTerm) -> object:
        """Return the memoized canonical view of one raw term."""

        view = self._canonical_views.get(raw)
        if view is None:
            view = canonicalize_mba_term(raw)
            if len(self._canonical_views) >= _CANONICAL_VIEW_MEMO_LIMIT:
                self._canonical_views.clear()
            self._canonical_views[raw] = view
        return view

    def _validate(
        self,
        observation: MbaResidualRecord,
        activation_identity: PluginIdentity | None = None,
        expected_provider: MbaProviderKind | None = None,
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
        canonical_view = self._canonical_view(raw)
        if canonical_view.canonical_term != canonical:
            raise ValueError("canonical_term_mismatch")
        if term_fingerprint(canonical) != observation.outcome.fingerprint:
            raise ValueError("fingerprint_mismatch")
        if observation.outcome.status.value == "applied":
            raise ValueError("applied_not_residual")
        if observation.materialized:
            raise ValueError("materialized_not_residual")
        if expected_provider is None:
            raise ValueError("implementation_authority_missing")
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
        expected_provider: MbaProviderKind | None = None,
    ) -> MbaResidualReceipt:
        # ``MbaProviderOutcome.elapsed_ms`` only wraps the provider's own
        # solve/prove.  Publishing is the other half of the per-attempt cost
        # and used to be invisible, so measure it here instead of inferring it
        # from wall-clock division after the fact.
        started = perf_counter() if logger.debug_on else None
        receipt = self._record_generation(
            observation, activation_identity, expected_provider
        )
        if started is not None:
            # ``uuid`` is logged so an acceptance run can prove the providers
            # really do mint a fresh one per attempt -- the whole reason the
            # attempt memo is keyed on the content and not on the row.
            logger.debug(
                "residual observation publish uuid=%s status=%s reason=%s "
                "harness_ms=%.3f",
                getattr(observation, "attempt_uuid", None),
                receipt.status,
                receipt.reason,
                (perf_counter() - started) * 1000.0,
            )
        return receipt

    def _record_generation(
        self,
        observation: MbaResidualRecord,
        activation_identity: PluginIdentity | None,
        expected_provider: MbaProviderKind | None = None,
    ) -> MbaResidualReceipt:
        """Record into this generation, or fail closed once it is closed.

        A sink never reaches past itself.  Rebinding a view that outlived a
        manager restart is the relay's job (:class:`MbaResidualSinkRelay`),
        which is owned by exactly one host lifecycle -- so a closed generation
        can only be succeeded by another generation of the *same* lifecycle.
        """
        with self._lock:
            if self._closed:
                self._rejected_count += 1
                self._warn_closed_once()
                return self._rejected("closed")
            return self._record_locked(
                observation,
                activation_identity,
                expected_provider,
            )

    def _warn_closed_once(self) -> None:
        """Name the capability the first time a session loses an observation."""
        if self._warned_closed:
            return
        self._warned_closed = True
        logger.warning(
            "MBA residual observation dropped: capability %s has no open sink; "
            "every further observation from this view is rejected 'closed'",
            D810_MBA_RESIDUAL_OBSERVATION_CAPABILITY,
        )

    def _record_locked(
        self,
        observation: MbaResidualRecord,
        activation_identity: PluginIdentity | None,
        expected_provider: MbaProviderKind | None = None,
    ) -> MbaResidualReceipt:
        try:
            if not self._recording_enabled:
                # Deliberately before validation: the point of the switch
                # is that no observation costs anything.
                self._rejected_count += 1
                return self._rejected("recording_disabled")
            attempt = self._validate(
                observation,
                activation_identity,
                expected_provider,
            )
            receipt = self._store.record_attempt(attempt)
            status = getattr(receipt, "status", None)
            status_value = getattr(status, "value", status)
            if status_value == "stored":
                self._stored += 1
                return MbaResidualReceipt("stored")
            if status_value == "duplicate":
                self._duplicate += 1
                return MbaResidualReceipt("duplicate")
            reason = getattr(receipt, "reason", None) or "store_refused"
            self._rejected_count += 1
            return self._rejected(str(reason))
        except (TypeError, ValueError) as exc:
            reason = str(exc) or "invalid_observation"
            self._rejected_count += 1
            return self._rejected(reason)
        except BaseException as exc:
            self._safe_log(observation, exc)
            self._rejected_count += 1
            return self._rejected("storage_error")

    def record(self, observation: MbaResidualRecord) -> MbaResidualReceipt:
        """Record one observation without allowing errors through callbacks."""
        return self._record(observation, None)

    def close(self) -> None:
        with self._lock:
            if self._closed:
                return
            self._closed = True
            # One INFO line, once per session: the duplicate fast path is only
            # worth its complexity if it actually hits at runtime, and that is
            # not observable from the stored rows alone.
            memo_stats = getattr(self._store, "attempt_memo_stats", None)
            if callable(memo_stats):
                stats = memo_stats()
                logger.info(
                    "mba attempt memo hits=%d misses=%d contents=%d clears=%d",
                    stats.hits,
                    stats.misses,
                    stats.contents,
                    stats.clears,
                )
            traffic = (self._stored, self._duplicate, self._rejected_count)
            close = getattr(self._store, "close", None)
            if callable(close):
                close()
        # A close that reports zero traffic is the d81-uncr signature: it means
        # the generation was orphaned before any provider reached it.  Records
        # this generation forwards to a successor are counted by the successor,
        # which is closed later, so every attempt is reported exactly once.
        logger.info(
            "mba residual observation sink close capability=%s stored=%d "
            "duplicate=%d rejected=%d",
            D810_MBA_RESIDUAL_OBSERVATION_CAPABILITY,
            *traffic,
        )


__all__ = [
    "MbaResidualSinkRelay",
    "SqliteMbaResidualObservationSink",
    "provider_kind_for_implementation",
]


class _ActivationScopedResidualSink:
    """Minimal record-only facade bound to one host-created identity.

    ``_owner`` is the relay of the issuing lifecycle in the hosted flow, and a
    standalone sink in the ad hoc/test flow.  Either way it is a fixed object
    chosen by the host at issue time, never resolved from process state.
    """

    __slots__ = ("_owner", "_identity")

    def __init__(self, owner: object, identity: PluginIdentity):
        self._owner = owner
        self._identity = identity

    def record(self, observation: MbaResidualRecord) -> MbaResidualReceipt:
        return self._owner._record(observation, self._identity)

    def _bind_selected_implementation(
        self, candidate: PassImplementationCandidate
    ) -> MbaResidualObservationSink:
        if not isinstance(candidate, PassImplementationCandidate):
            raise TypeError(
                "implementation binding requires a PassImplementationCandidate"
            )
        if (
            candidate.backend_name != self._identity.name
            or candidate.backend_origin != self._identity.origin
        ):
            raise ValueError("implementation_activation_mismatch")
        provider = provider_kind_for_implementation(candidate)
        if provider is None:
            raise ValueError("unknown_provider_implementation")
        return _ImplementationScopedResidualSink(
            self._owner,
            self._identity,
            provider,
        )


class _ImplementationScopedResidualSink:
    """Record-only facade carrying exact selected implementation authority."""

    __slots__ = ("_owner", "_identity", "_provider")

    def __init__(
        self,
        owner: object,
        identity: PluginIdentity,
        provider: MbaProviderKind,
    ) -> None:
        self._owner = owner
        self._identity = identity
        self._provider = provider

    def record(self, observation: MbaResidualRecord) -> MbaResidualReceipt:
        return self._owner._record(
            observation,
            self._identity,
            self._provider,
        )
