"""Manager-owned ordering for decompilation lifecycle work."""

from __future__ import annotations

from dataclasses import dataclass, field
import hashlib
import json
from d810.analyses.control_flow.native_preanalysis_session import (
    NativePreanalysisFacts,
    NativePreanalysisSessionState,
    ResolverEvidenceAttachment,
)
from d810.core import typing
from d810.core.decompilation_session import (
    DecompilationEvent,
    DecompilationSessionEvent,
)
from d810.core.logging import getLogger
from d810.core.input_identity_attestation import (
    InputIdentityResolution,
)
from d810.core.native_preanalysis_key import (
    NativePreanalysisKey,
    NativePreanalysisKeyMismatch,
)
from d810.core.provider_phase import ProviderPhaseSnapshot
from d810.core.observability import emit as emit_diagnostic
from d810.core.observability_events import (
    DiagnosticSessionObserved,
    EvidenceGenerationObserved,
    InputIdentityResolutionObserved,
)
from d810.capabilities.semantic_routes import SemanticRouteReferenceOracleCapability
from d810.manager.frontend_normalization import (
    SessionFrontendNormalizationPlanAuthority,
)

logger = getLogger("d810.decompilation_lifecycle")


@dataclass(frozen=True, slots=True)
class AttestedExternalOracleGate:
    """Allow SHA-bound route authority only after a verified identity verdict."""

    delegate: SemanticRouteReferenceOracleCapability | None
    identity_resolution: InputIdentityResolution

    def __post_init__(self) -> None:
        if not isinstance(self.identity_resolution, InputIdentityResolution):
            raise TypeError("external oracle gate requires an identity resolution")

    def reference_oracle_scope_for(self, function_ea, native_key):
        if not self.identity_resolution.external_evidence_allowed:
            return None
        delegate = self.delegate
        return (
            None
            if delegate is None
            else delegate.reference_oracle_scope_for(function_ea, native_key)
        )

    def reference_oracle_for(self, function_ea, native_key, rewrite_anchor_eas):
        if not self.identity_resolution.external_evidence_allowed:
            return None
        delegate = self.delegate
        return (
            None
            if delegate is None
            else delegate.reference_oracle_for(
                function_ea,
                native_key,
                rewrite_anchor_eas,
            )
        )


@dataclass(slots=True)
class DecompilationSessionContext:
    """Durable identity and typed resolver attachment for one session.

    This context deliberately contains no live Hex-Rays object.  Resolver
    state attaches through one named lifecycle port.
    """

    function_ea: int
    database_identity: str
    top_level_epoch: int
    native_key: NativePreanalysisKey
    input_identity_resolution: InputIdentityResolution | None = None
    native_preanalysis: NativePreanalysisSessionState = field(
        default_factory=NativePreanalysisSessionState
    )
    native_preanalysis_depth: int = 0
    current_mba_generation: int = 0
    current_mba_identity_index: object | None = None
    generated_ready_emitted_for_current_mba: bool = False
    rhad_generated_checksum_attempted_for_current_mba: bool = False
    rhad_generated_checksum_committed_for_current_mba: bool = False
    rhad_generated_checksum_observed_maturities: set[str] = field(default_factory=set)
    preopt_ready_emitted_for_current_mba: bool = False
    resolver_attachment: ResolverEvidenceAttachment | None = None
    frontend_normalization_plan_authority: SessionFrontendNormalizationPlanAuthority = (
        field(init=False)
    )

    def __post_init__(self) -> None:
        resolution = self.input_identity_resolution
        if resolution is not None and not isinstance(resolution, InputIdentityResolution):
            raise TypeError("session input identity resolution is invalid")
        if (
            resolution is not None
            and resolution.input_identity != self.native_key.input_identity
        ):
            raise ValueError("session native key disagrees with input identity resolution")
        self.frontend_normalization_plan_authority = (
            SessionFrontendNormalizationPlanAuthority(
                function_ea=int(self.function_ea),
                native_key=self.native_key,
            )
        )

    @property
    def identity_key(self) -> str:
        """Return the durable owner key for session-scoped live ports."""
        return (
            f"{self.database_identity}:0x{int(self.function_ea):X}:"
            f"{int(self.top_level_epoch)}"
        )

    @property
    def event(self) -> DecompilationSessionEvent:
        return DecompilationSessionEvent(
            function_ea=self.function_ea,
            database_identity=self.database_identity,
            top_level_epoch=self.top_level_epoch,
        )


@dataclass(frozen=True, slots=True)
class _SessionActivation:
    """One callback activation over a session that may already be nested.

    A callback can resume an outer function while Hex-Rays is recursively
    decompiling one of its children.  That resumed callback must see the
    original session evidence, but its structural completion must not release
    either the resumed owner or the child beneath it.
    """

    session: DecompilationSessionContext
    owns_session: bool


@dataclass(frozen=True, slots=True)
class FlowgraphReadyPayload:
    """Portable flowgraph capture input owned by the lifecycle coordinator."""

    flow_graph: typing.Any
    func_ea: int
    provider_phase: ProviderPhaseSnapshot
    snapshot: object | None


@dataclass(slots=True)
class DecompilationLifecycleCoordinator:
    """Own session boundaries and ordered preanalysis/analysis hand-off.

    Adapters receive this object by injection and never own collection,
    persistence, or session ordering.
    """

    preanalysis_runtime: typing.Any | None
    analysis_runtime: typing.Any | None
    execution_scope_service: typing.Any | None
    native_preanalysis_key_provider: typing.Callable[[int], typing.Any]
    event_emitter: typing.Any | None = None
    current_mba_identity_index_builder: typing.Callable[..., object | None] | None = (
        None
    )
    mba_mutation_gateway_factory: typing.Callable[..., object | None] | None = None
    semantic_native_body_materializer_factory: (
        typing.Callable[..., object | None] | None
    ) = None
    resolver_attachment_initializer: (
        typing.Callable[[DecompilationSessionContext], ResolverEvidenceAttachment]
        | None
    ) = None
    _active_sessions: list[_SessionActivation] = field(
        default_factory=list,
        init=False,
        repr=False,
    )
    _epochs_by_identity: dict[tuple[int, str], int] = field(
        default_factory=dict,
        init=False,
        repr=False,
    )

    @property
    def has_active_sessions(self) -> bool:
        return bool(self._active_sessions)

    @staticmethod
    def _observe_session(session: DecompilationSessionContext, status: str) -> None:
        emit_diagnostic(
            DiagnosticSessionObserved(
                session_id=session.identity_key,
                func_ea=int(session.function_ea),
                top_level_epoch=int(session.top_level_epoch),
                native_key_json=session.native_key.to_json(),
                status=status,
            )
        )
        resolution = session.input_identity_resolution
        if resolution is not None:
            emit_diagnostic(
                InputIdentityResolutionObserved(
                    session_id=session.identity_key,
                    func_ea=int(session.function_ea),
                    status=resolution.status.value,
                    provenance=resolution.provenance,
                    mismatch_field=resolution.mismatch_field,
                    external_evidence_allowed=resolution.external_evidence_allowed,
                    database_uuid=resolution.database_uuid,
                )
            )

    def _native_key_and_identity_resolution(
        self,
        function_ea: int,
    ) -> tuple[NativePreanalysisKey, InputIdentityResolution | None]:
        supplied = self.native_preanalysis_key_provider(int(function_ea))
        if isinstance(supplied, NativePreanalysisKey):
            return supplied, None
        native_key = getattr(supplied, "native_key", None)
        resolution = getattr(supplied, "identity_resolution", None)
        if not isinstance(resolution, InputIdentityResolution):
            raise TypeError("native preanalysis identity provider returned no resolution")
        if native_key is None:
            logger.warning(
                "D810 native mutation abstained for func=0x%x: input identity %s",
                int(function_ea),
                resolution.reason,
            )
            raise ValueError("input identity unavailable: " + resolution.reason)
        if not isinstance(native_key, NativePreanalysisKey):
            raise TypeError("native preanalysis identity provider returned an invalid key")
        if resolution.input_identity != native_key.input_identity:
            raise ValueError("native key disagrees with input identity resolution")
        return native_key, resolution

    def reobserve_active_diagnostic_session(self, function_ea: int) -> None:
        """Republish an active owner after the diagnostic sink is opened."""
        session = self.current_session(int(function_ea))
        if session is not None:
            self._observe_session(session, "active")

    @staticmethod
    def _observe_evidence_transition(session, transition) -> None:
        emit_diagnostic(
            EvidenceGenerationObserved(
                session_id=session.identity_key,
                func_ea=int(session.function_ea),
                operation=transition.operation,
                previous_generation=int(transition.previous_generation),
                resulting_generation=int(transition.resulting_generation),
                evidence_family=transition.evidence_family,
                outcome=transition.outcome,
                owner="native_preanalysis",
                reason=transition.reason,
            )
        )

    def ensure(
        self,
        key: NativePreanalysisKey,
        *,
        function_ea: int | None = None,
        database_identity: str | None = None,
    ) -> tuple[DecompilationSessionContext, bool]:
        """Ensure one coordinator-owned session for an exact portable key."""
        if not isinstance(key, NativePreanalysisKey):
            raise TypeError("session ensure requires a native preanalysis key")
        current = self.get(key)
        if current is not None:
            return current, False
        session, created = self.ensure_hexrays_session(
            function_ea=(key.function_rva if function_ea is None else int(function_ea)),
            database_identity=(
                key.input_identity
                if database_identity is None
                else str(database_identity)
            ),
        )
        if session.native_key != key:
            if created:
                self.finish_hexrays_session()
            raise NativePreanalysisKeyMismatch(
                key,
                session.native_key,
                key.mismatch_fields(session.native_key),
            )
        return session, created

    def get(self, key: NativePreanalysisKey) -> DecompilationSessionContext | None:
        """Return the innermost active session with this exact portable key."""
        if not isinstance(key, NativePreanalysisKey):
            raise TypeError("session lookup requires a native preanalysis key")
        for activation in reversed(self._active_sessions):
            if activation.session.native_key == key:
                return activation.session
        return None

    def merge_facts(
        self,
        key: NativePreanalysisKey,
        facts: NativePreanalysisFacts,
    ) -> bool:
        """Merge changed normalized evidence into its sole session authority."""
        session = self.get(key)
        if session is None:
            raise KeyError("native preanalysis session is not active")
        if not isinstance(facts, NativePreanalysisFacts):
            raise TypeError("fact merge requires NativePreanalysisFacts")
        state = session.native_preanalysis
        return state.merge_facts(key, facts)

    def _native_state_for_evidence_epoch(
        self,
        key: NativePreanalysisKey,
        evidence_epoch: int,
    ) -> NativePreanalysisSessionState:
        """Return the active authority after exact portable-epoch validation."""
        session = self.get(key)
        if session is None:
            raise KeyError("native preanalysis session is not active")
        current = int(session.native_preanalysis.evidence_generation)
        requested = int(evidence_epoch)
        if requested != current:
            raise ValueError(
                "lifecycle evidence epoch mismatch: "
                f"current={current} requested={requested}"
            )
        return session.native_preanalysis

    def mark_canonical_semantic_plan_ready(
        self,
        key: NativePreanalysisKey,
        evidence_epoch: int,
    ) -> bool:
        """Record canonical semantic planning for the exact normalized epoch."""
        return self._native_state_for_evidence_epoch(
            key,
            evidence_epoch,
        ).mark_canonical_semantic_plan_ready()

    def finish(self, key: NativePreanalysisKey) -> None:
        """Finish the innermost exact-key owner and release all live state."""
        session = self.get(key)
        if session is None:
            return
        if (
            not self._active_sessions
            or self._active_sessions[-1].session is not session
        ):
            raise RuntimeError("cannot finish a session beneath another active owner")
        while (
            self._active_sessions
            and self._active_sessions[-1].session is session
            and not self._active_sessions[-1].owns_session
        ):
            self.finish_hexrays_session()
        self.finish_hexrays_session()
        if self.get(key) is session:
            raise RuntimeError("session finish deferred by an active restart owner")

    def ensure_hexrays_session(
        self,
        *,
        function_ea: int,
        database_identity: str,
        callback_entry_ea: int | None = None,
    ) -> tuple[DecompilationSessionContext, bool]:
        """Return the active session or start exactly one top-level session.

        The boolean is true only when this call started the session.  Every
        Hex-Rays entrypoint may use this method as a defensive lazy fallback;
        a redo therefore retains its epoch and cannot reset evidence twice.
        """
        function_ea = int(function_ea)
        database_identity = str(database_identity)
        callback_entry_ea = (
            None if callback_entry_ea is None else int(callback_entry_ea)
        )
        if self._active_sessions:
            current = self._active_sessions[-1].session
            if (
                current.function_ea == function_ea
                and current.database_identity == database_identity
            ):
                # A manager-owned native preflight may itself invoke Hex-Rays
                # for detached snippets.  Its structural callback must close
                # only that callback activation, leaving the preflight owner
                # alive for the user-visible top-level decompile.  Internal
                # MBA entries likewise need a borrowed frame even when their
                # containing IDA function is the existing lifecycle owner.
                if callback_entry_ea is not None and (
                    current.native_preanalysis_depth > 0
                    or callback_entry_ea != function_ea
                ):
                    if (
                        current.native_preanalysis_depth > 0
                        and not self._active_sessions[-1].owns_session
                    ):
                        # MERR_REDO re-enters prolog for the same internal
                        # preflight decompile, but Hex-Rays emits only one
                        # matching structural completion.  Reuse the borrowed
                        # activation already protecting the owner.
                        return current, False
                    self._active_sessions.append(
                        _SessionActivation(session=current, owns_session=False)
                    )
                return current, False

        # Re-entering a parent while an IDA-owned nested decompilation is
        # active is not a new top-level decompilation and must not discard its
        # portable resolver evidence. Keep a borrowed activation so the
        # matching structural callback only closes this reentry frame.
        for activation in reversed(self._active_sessions):
            active = activation.session
            if (
                active.function_ea == function_ea
                and active.database_identity == database_identity
            ):
                self._active_sessions.append(
                    _SessionActivation(session=active, owns_session=False)
                )
                return active, False

        has_active_parent = bool(self._active_sessions)
        identity = (function_ea, database_identity)
        epoch = self._epochs_by_identity.get(identity, 0) + 1
        self._epochs_by_identity[identity] = epoch
        native_key, identity_resolution = self._native_key_and_identity_resolution(
            function_ea
        )
        session = DecompilationSessionContext(
            function_ea=function_ea,
            database_identity=database_identity,
            top_level_epoch=epoch,
            native_key=native_key,
            input_identity_resolution=identity_resolution,
        )
        session.native_preanalysis.event_observer = (
            lambda transition, owned_session=session: self._observe_evidence_transition(
                owned_session,
                transition,
            )
        )
        self._active_sessions.append(
            _SessionActivation(session=session, owns_session=True)
        )
        initializer = self.resolver_attachment_initializer
        if callable(initializer):
            try:
                attachment = initializer(session)
                if not isinstance(attachment, ResolverEvidenceAttachment):
                    raise TypeError(
                        "resolver attachment initializer returned an invalid port"
                    )
                session.resolver_attachment = attachment
            except Exception:
                self._active_sessions.pop()
                logger.exception(
                    "resolver attachment initialization failed for func=0x%x",
                    function_ea,
                )
                raise

        self._observe_session(session, "active")
        self._emit_session_event(DecompilationEvent.SESSION_STARTED, session.event)

        preanalysis_runtime = self.preanalysis_runtime
        if preanalysis_runtime is not None:
            try:
                preanalysis_runtime.begin_session(session.event)
            except Exception:
                logger.exception(
                    "preanalysis runtime session reset failed for func=0x%x",
                    function_ea,
                )
        analysis_runtime = self.analysis_runtime
        if analysis_runtime is not None:
            try:
                analysis_runtime.begin_session(
                    session.event,
                    preserve_active_session=has_active_parent,
                )
            except Exception:
                logger.exception(
                    "analysis runtime session reset failed for func=0x%x",
                    function_ea,
                )
        if self.execution_scope_service is not None:
            try:
                self.execution_scope_service.clear_hint_state(function_ea)
            except Exception:
                logger.exception(
                    "rule-scope hint reset failed for func=0x%x",
                    function_ea,
                )
        return session, True

    def current_session(self, function_ea: int) -> DecompilationSessionContext | None:
        """Return the innermost active session for ``function_ea``."""
        function_ea = int(function_ea)
        for activation in reversed(self._active_sessions):
            session = activation.session
            if session.function_ea == function_ea:
                return session
        return None

    def has_pending_generated_restart(self, function_ea: int) -> bool:
        """Return whether the active owner needs one controller follow-up."""
        session = self.current_session(int(function_ea))
        return bool(
            session is not None
            and session.native_preanalysis.has_pending_generated_restart
        )

    def generated_restart_consumed_count(self, function_ea: int) -> int:
        """Return how many staged restarts this session has actually consumed."""
        session = self.current_session(int(function_ea))
        if session is None:
            return 0
        return int(session.native_preanalysis.generated_restart_consumed_count)

    def has_exhausted_poison_restart(self, function_ea: int) -> bool:
        """Return whether poison recurred after this epoch's recovery retry."""
        session = self.current_session(int(function_ea))
        return bool(
            session is not None
            and session.native_preanalysis.has_exhausted_poison_restart
        )

    def begin_native_preanalysis(self, session: DecompilationSessionContext) -> None:
        """Reserve a session while its manager-owned preflight uses Hex-Rays.

        The caller owns the matching ``finish_native_preanalysis`` in a
        ``finally`` block.  This is a lifecycle boundary, not a resolver
        cache: it only protects the already-active session from callback-local
        structural completion.
        """
        if not any(
            activation.session is session for activation in self._active_sessions
        ):
            raise ValueError("native preanalysis requires an active session")
        session.native_preanalysis_depth += 1

    def finish_native_preanalysis(self, session: DecompilationSessionContext) -> None:
        """Release one manager-owned native-preanalysis reservation."""
        if session.native_preanalysis_depth <= 0:
            raise ValueError("native preanalysis reservation is not active")
        session.native_preanalysis_depth -= 1

    def bind_current_mba_identity_index(
        self,
        *,
        function_ea: int,
        index: object,
    ) -> object | None:
        """Attach one MBA-free, generation-local index to its active session."""
        session = self.current_session(int(function_ea))
        if session is None:
            return None
        session.current_mba_identity_index = index
        return index

    def begin_current_mba_generation(self, *, function_ea: int) -> None:
        """Invalidate live bindings and callback guards at flowchart entry."""
        session = self.current_session(int(function_ea))
        if session is None:
            return
        session.current_mba_generation += 1
        session.current_mba_identity_index = None
        session.generated_ready_emitted_for_current_mba = False
        session.rhad_generated_checksum_attempted_for_current_mba = False
        session.preopt_ready_emitted_for_current_mba = False

    def current_mba_generation(self, *, function_ea: int) -> int:
        """Return the active flowchart generation without exposing its session."""
        session = self.current_session(int(function_ea))
        return 0 if session is None else int(session.current_mba_generation)

    def current_evidence_generation(self, *, function_ea: int) -> int:
        """Return the portable evidence epoch owning the current MBA bindings."""
        session = self.current_session(int(function_ea))
        return (
            0
            if session is None
            else int(session.native_preanalysis.evidence_generation)
        )

    def mark_preopt_ready_emitted(
        self,
        *,
        function_ea: int,
        microcode_modified: bool = False,
    ) -> None:
        """Record that the PREOPT optimizer callback emitted for this MBA."""
        session = self.current_session(int(function_ea))
        if session is not None:
            session.preopt_ready_emitted_for_current_mba = True
            if microcode_modified:
                session.current_mba_identity_index = None
                attachment = session.resolver_attachment
                if attachment is not None:
                    attachment.invalidate_current_mba_binding()

    def mark_generated_ready_emitted(
        self,
        *,
        function_ea: int,
        microcode_modified: bool = False,
    ) -> None:
        """Record that the GENERATED optimizer callback emitted for this MBA."""
        del microcode_modified
        session = self.current_session(int(function_ea))
        if session is not None:
            session.generated_ready_emitted_for_current_mba = True
            # The GENERATED index is intentionally graph-free and therefore
            # authoritative only for this callback.  Even an abstaining
            # listener must not leave it cached for PREOPT/LOCOPT final
            # binding, whose source-maturity authority is different.
            session.current_mba_identity_index = None
            attachment = session.resolver_attachment
            if attachment is not None:
                attachment.invalidate_current_mba_binding()

    def generated_ready_was_emitted(self, *, function_ea: int) -> bool:
        """Return whether GENERATED publication already ran for this MBA."""
        session = self.current_session(int(function_ea))
        return bool(
            session is not None and session.generated_ready_emitted_for_current_mba
        )

    def preopt_ready_was_emitted(self, *, function_ea: int) -> bool:
        """Return whether PREOPT publication already ran for this MBA."""
        session = self.current_session(int(function_ea))
        return bool(
            session is not None and session.preopt_ready_emitted_for_current_mba
        )

    def build_current_mba_identity_index(
        self,
        *,
        function_ea: int,
        mba: object,
    ) -> object | None:
        """Lift and bind the current MBA without retaining the live object."""
        session = self.current_session(int(function_ea))
        if session is None:
            return None
        builder = self.current_mba_identity_index_builder
        if not callable(builder):
            return None
        try:
            index = builder(session=session, mba=mba)
        except Exception:
            logger.debug(
                "current MBA identity-index build failed for func=0x%x",
                int(function_ea),
                exc_info=True,
            )
            return None
        return self.bind_current_mba_identity_index(
            function_ea=int(function_ea),
            index=index,
        )

    def new_current_mba_mutation_gateway(
        self,
        *,
        function_ea: int,
        maturity: int,
    ) -> object | None:
        """Create one transaction gateway over the active MBA's live index.

        Structural modifiers receive this through manager-owned injection.  The
        coordinator deliberately does not retain an MBA: the index was built
        at the callback boundary and is invalidated together with its session.
        """
        session = self.current_session(int(function_ea))
        if session is None:
            return None
        index = session.current_mba_identity_index
        if index is None:
            return None
        factory = self.mba_mutation_gateway_factory
        if not callable(factory):
            return None
        try:
            return factory(
                session=session,
                identity_index=index,
                maturity=int(maturity),
                event_emitter=self.event_emitter,
            )
        except Exception:
            logger.debug(
                "current MBA mutation-gateway creation failed for func=0x%x",
                int(function_ea),
                exc_info=True,
            )
            return None

    def new_semantic_native_body_materializer(
        self,
        *,
        function_ea: int,
        mba: object,
    ) -> object | None:
        """Create the manager-owned native-body port for this live MBA."""
        session = self.current_session(int(function_ea))
        if session is None:
            return None
        factory = self.semantic_native_body_materializer_factory
        if not callable(factory):
            return None
        try:
            return factory(session=session, mba=mba)
        except Exception:
            logger.debug(
                "semantic native-body materializer creation failed for func=0x%x",
                int(function_ea),
                exc_info=True,
            )
            return None

    def capture_flowgraph(self, payload: FlowgraphReadyPayload) -> None:
        """Collect and persist portable flowgraph facts in their existing order."""
        self._publish_state_write_route_facts(payload)
        self._publish_materialized_transfer_facts(payload)
        self._publish_rebound_bootstrap_route_facts(payload)
        runtime = self.preanalysis_runtime
        if runtime is not None:
            try:
                runtime.capture_flowgraph(
                    payload.flow_graph,
                    func_ea=int(payload.func_ea),
                    provider_phase=payload.provider_phase,
                    snapshot=payload.snapshot,
                )
            except Exception:
                logger.exception(
                    "preanalysis fact capture failed for func=0x%x maturity=%s",
                    int(payload.func_ea),
                    payload.provider_phase.friendly_provider_level,
                )

    def _publish_state_write_route_facts(
        self,
        payload: FlowgraphReadyPayload,
    ) -> None:
        """Persist native state-write delivery authority on a real snapshot."""
        if payload.snapshot is None:
            return
        session = self.current_session(int(payload.func_ea))
        if session is None:
            return
        routes = session.native_preanalysis.pending_state_write_routes_for_publication()
        if not routes:
            return
        try:
            from d810.analyses.value_flow.observation import FactObservation
            from d810.core.observability import emit
            from d810.core.observability_events import FactObservationsObserved

            generation = int(session.native_preanalysis.evidence_generation)
            inventory_revision = int(
                session.native_preanalysis.state_write_route_inventory_revision
            )
            observations = []
            for route in routes:
                payload_row = route.diagnostic_payload(generation=generation)
                payload_row["inventory_revision"] = inventory_revision
                semantic_row = dict(payload_row)
                semantic_row.pop("generation", None)
                semantic_row.pop("inventory_revision", None)
                fingerprint = hashlib.sha256(
                    json.dumps(
                        semantic_row,
                        sort_keys=True,
                        separators=(",", ":"),
                    ).encode("utf-8")
                ).hexdigest()[:20]
                observations.append(
                    FactObservation(
                        fact_id=(
                            "state_write_route:"
                            f"generation={generation}:"
                            f"revision={inventory_revision}:proof={fingerprint}"
                        ),
                        kind="StateWriteRouteEvidenceFact",
                        semantic_key=f"state_write_route:proof={fingerprint}",
                        maturity=str(payload.provider_phase.friendly_provider_level),
                        phase="pre_d810",
                        confidence=1.0,
                        source_ea=int(route.source_write_ea),
                        payload=payload_row,
                        evidence=(
                            route.proof_kind.value,
                            route.delivery_kind.value,
                        ),
                    )
                )
            emit(
                FactObservationsObserved(
                    snapshot=payload.snapshot,
                    func_ea=int(payload.func_ea),
                    observations=tuple(observations),
                )
            )
            session.native_preanalysis.mark_state_write_routes_published(routes)
        except Exception:
            logger.debug(
                "state-write route diagnostic publication failed for func=0x%x",
                int(payload.func_ea),
                exc_info=True,
            )

    def _publish_rebound_bootstrap_route_facts(
        self,
        payload: FlowgraphReadyPayload,
    ) -> None:
        """Attach one rebound bootstrap proof to the next real diag snapshot.

        The route is session-owned portable evidence, while the snapshot is
        created later by the live optimizer boundary.  This bridge deliberately
        transports only anchor-based facts and has no dependency on the
        diagnostics implementation or any current-MBA serial.
        """
        if payload.snapshot is None:
            return
        session = self.current_session(int(payload.func_ea))
        if session is None:
            return
        routes = session.native_preanalysis.pending_rebound_bootstrap_routes()
        if not routes:
            return
        try:
            from d810.analyses.value_flow.observation import FactObservation
            from d810.core.observability import emit
            from d810.core.observability_events import FactObservationsObserved

            generation = int(session.native_preanalysis.evidence_generation)
            observations = tuple(
                FactObservation(
                    fact_id=(
                        "preopt_bootstrap_route:"
                        f"source=0x{route.source_anchor_ea:X}:"
                        f"state=0x{route.state:X}:"
                        f"handler=0x{route.handler_anchor_ea:X}:"
                        f"generation={generation}"
                    ),
                    kind="PreoptBootstrapRouteFact",
                    semantic_key=(
                        "preopt_bootstrap_route:"
                        f"source=0x{route.source_anchor_ea:X}:"
                        f"state=0x{route.state:X}:"
                        f"handler=0x{route.handler_anchor_ea:X}"
                    ),
                    maturity=str(payload.provider_phase.friendly_provider_level),
                    phase="pre_d810",
                    confidence=1.0,
                    source_ea=int(route.source_anchor_ea),
                    payload=route.diagnostic_payload(
                        generation=generation,
                        rebound=True,
                    ),
                    evidence=(route.proof_kind.value,),
                )
                for route in routes
            )
            emit(
                FactObservationsObserved(
                    snapshot=payload.snapshot,
                    func_ea=int(payload.func_ea),
                    observations=observations,
                )
            )
            session.native_preanalysis.mark_rebound_bootstrap_routes_published(routes)
        except Exception:
            logger.debug(
                "bootstrap-route diagnostic publication failed for func=0x%x",
                int(payload.func_ea),
                exc_info=True,
            )

    def _publish_materialized_transfer_facts(
        self,
        payload: FlowgraphReadyPayload,
    ) -> None:
        """Persist the complete portable resolver inventory once per epoch."""
        if payload.snapshot is None:
            return
        session = self.current_session(int(payload.func_ea))
        if session is None:
            return
        transfers = (
            session.native_preanalysis.pending_materialized_transfers_for_publication()
        )
        if not transfers:
            return
        try:
            from d810.analyses.value_flow.observation import FactObservation
            from d810.core.observability import emit
            from d810.core.observability_events import FactObservationsObserved

            generation = int(session.native_preanalysis.evidence_generation)
            inventory_revision = int(
                session.native_preanalysis.transfer_inventory_revision
            )
            observations = []
            for transfer in transfers:
                payload_row = transfer.diagnostic_payload(
                    generation=generation,
                    inventory_revision=inventory_revision,
                )
                semantic_row = dict(payload_row)
                semantic_row.pop("generation", None)
                semantic_row.pop("inventory_revision", None)
                fingerprint = hashlib.sha256(
                    json.dumps(
                        semantic_row,
                        sort_keys=True,
                        separators=(",", ":"),
                    ).encode("utf-8")
                ).hexdigest()[:20]
                observations.append(
                    FactObservation(
                        fact_id=(
                            "resolver_transfer:"
                            f"generation={generation}:"
                            f"revision={inventory_revision}:proof={fingerprint}"
                        ),
                        kind="ResolverTransferEvidenceFact",
                        semantic_key=f"resolver_transfer:proof={fingerprint}",
                        maturity=str(payload.provider_phase.friendly_provider_level),
                        phase="pre_d810",
                        confidence=1.0,
                        source_ea=int(transfer.source_jmp_ea),
                        payload=payload_row,
                        evidence=(str(transfer.resolver_kind),),
                    )
                )
            emit(
                FactObservationsObserved(
                    snapshot=payload.snapshot,
                    func_ea=int(payload.func_ea),
                    observations=tuple(observations),
                )
            )
            session.native_preanalysis.mark_materialized_transfers_published(transfers)
        except Exception:
            logger.debug(
                "resolver-transfer diagnostic publication failed for func=0x%x",
                int(payload.func_ea),
                exc_info=True,
            )

    def capture_ctree(
        self,
        cfunc: typing.Any,
        *,
        func_ea: int,
        provider_phase: ProviderPhaseSnapshot,
    ) -> None:
        """Collect ctree evidence without making the hook own a phase object."""
        runtime = self.preanalysis_runtime
        if runtime is None:
            return
        try:
            runtime.capture_ctree(
                cfunc,
                func_ea=int(func_ea),
                provider_phase=provider_phase,
            )
            session = self.current_session(int(func_ea))
            if session is not None:
                from d810.core.observability_events import LifecycleEventObserved

                emit_diagnostic(
                    LifecycleEventObserved(
                        session_id=session.identity_key,
                        func_ea=int(func_ea),
                        event_kind="ctree_captured",
                        provider=str(provider_phase.provider_name),
                        maturity=str(provider_phase.friendly_provider_level),
                        phase="ctree",
                        evidence_generation=int(
                            session.native_preanalysis.evidence_generation
                        ),
                        mba_generation_before=int(session.current_mba_generation),
                        mba_generation_after=int(session.current_mba_generation),
                        summary="captured live ctree evidence",
                        payload={
                            "provider_level": int(provider_phase.provider_level),
                        },
                    )
                )
        except Exception:
            logger.exception(
                "preanalysis ctree collection failed for func=0x%x maturity=%s",
                int(func_ea),
                provider_phase.friendly_provider_level,
            )

    def analyze_current_function(self, *, function_ea: int, source: str) -> None:
        """Derive hints and apply them through the manager-owned rule scope."""
        if self.analysis_runtime is None:
            return
        function_ea = int(function_ea)
        try:
            hints = self.analysis_runtime.analyze(function_ea)
        except Exception:
            logger.exception("analysis failed for func=0x%x", function_ea)
            return
        if hints is None or self.execution_scope_service is None:
            return
        try:
            apply_result = self.execution_scope_service.apply_hints(hints)
            self.analysis_runtime.record_execution_scope_outcome(
                func_ea=function_ea,
                hints=hints,
                apply_result=apply_result,
                source=source,
            )
        except Exception:
            logger.exception(
                "rule-scope hint application failed for func=0x%x", function_ea
            )

    def finish_hexrays_session(self) -> None:
        """Finish the innermost session and publish its typed observer event."""
        if not self._active_sessions:
            return None
        activation = self._active_sessions[-1]
        if activation.owns_session and activation.session.native_preanalysis_depth > 0:
            # A defensive guard for a preflight callback that did not receive
            # its borrowed activation. The manager releases the reservation
            # before the public top-level decompile can finish this owner.
            return None
        if activation.owns_session and (
            activation.session.native_preanalysis.has_pending_generated_restart
            or activation.session.native_preanalysis.has_exhausted_poison_restart
        ):
            # Retain the evidence owner until the manager drives the staged
            # MERR_REDO or refuses a terminally exhausted poisoned result.
            return None
        self._active_sessions.pop()
        if not activation.owns_session:
            return None
        session = activation.session
        attachment = session.resolver_attachment
        if attachment is not None:
            try:
                attachment.release_live_bindings()
            except Exception:
                logger.debug(
                    "session attachment cleanup failed for func=0x%x",
                    int(session.function_ea),
                    exc_info=True,
                )
        session.resolver_attachment = None
        session.current_mba_identity_index = None
        parent = self._active_sessions[-1].session if self._active_sessions else None
        preanalysis_runtime = self.preanalysis_runtime
        if preanalysis_runtime is not None:
            try:
                preanalysis_runtime.finish_session(session.event)
            except Exception:
                logger.exception(
                    "preanalysis runtime session finish failed for func=0x%x",
                    session.function_ea,
                )
        analysis_runtime = self.analysis_runtime
        if analysis_runtime is not None:
            try:
                analysis_runtime.finish_session(
                    session.event,
                    resume_event=(parent.event if parent is not None else None),
                )
            except Exception:
                logger.exception(
                    "analysis runtime session finish failed for func=0x%x",
                    session.function_ea,
                )
        self._observe_session(session, "finished")
        self._emit_session_event(DecompilationEvent.SESSION_FINISHED, session.event)
        return None

    def _emit_session_event(
        self,
        event: DecompilationEvent,
        payload: DecompilationSessionEvent,
    ) -> None:
        """Publish typed lifecycle events from their sole owning boundary."""
        emitter = self.event_emitter
        if emitter is None:
            return
        try:
            emitter.emit(event, payload)
        except Exception:
            logger.exception(
                "session event emission failed for event=%s func=0x%x",
                event.value,
                int(payload.function_ea),
            )
