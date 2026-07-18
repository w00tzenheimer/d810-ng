"""Manager-owned ordering for decompilation lifecycle work.

The coordinator is the only production caller of the legacy analysis runtime's
session methods while the runtime is being split into preanalysis and analysis
ports.  Adapters receive this object by injection; they never import it.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from d810.core import typing
from d810.core.decompilation_session import DecompilationSessionEvent
from d810.core.logging import getLogger
from d810.core.provider_phase import ProviderPhaseSnapshot

logger = getLogger("D810.decompilation_lifecycle")


@dataclass(slots=True)
class DecompilationSessionContext:
    """Durable identity and generic extension storage for one session.

    This context deliberately contains no live Hex-Rays object.  Resolver
    state will attach through ``extensions`` in the later session-state batch.
    """

    function_ea: int
    database_identity: str
    top_level_epoch: int
    extensions: dict[object, object] = field(default_factory=dict)

    @property
    def event(self) -> DecompilationSessionEvent:
        return DecompilationSessionEvent(
            function_ea=self.function_ea,
            database_identity=self.database_identity,
            top_level_epoch=self.top_level_epoch,
        )


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

    ``preanalysis_phase`` and ``analysis_runtime`` are temporary private
    delegation targets.  They must only be supplied by ``D810Manager`` and
    must not be imported or invoked directly by adapters.
    """

    preanalysis_phase: typing.Any | None
    analysis_runtime: typing.Any | None
    rule_scope_service: typing.Any | None
    _active_sessions: list[DecompilationSessionContext] = field(
        default_factory=list,
        init=False,
        repr=False,
    )
    _epochs_by_identity: dict[tuple[int, str], int] = field(
        default_factory=dict,
        init=False,
        repr=False,
    )

    def begin_hexrays_session(
        self,
        *,
        function_ea: int,
        database_identity: str,
    ) -> DecompilationSessionContext:
        """Begin a top-level session, reusing the active MERR_REDO session."""
        function_ea = int(function_ea)
        database_identity = str(database_identity)
        if self._active_sessions:
            current = self._active_sessions[-1]
            if (
                current.function_ea == function_ea
                and current.database_identity == database_identity
            ):
                return current

        has_active_parent = bool(self._active_sessions)
        identity = (function_ea, database_identity)
        epoch = self._epochs_by_identity.get(identity, 0) + 1
        self._epochs_by_identity[identity] = epoch
        session = DecompilationSessionContext(
            function_ea=function_ea,
            database_identity=database_identity,
            top_level_epoch=epoch,
        )
        self._active_sessions.append(session)

        runtime = self.analysis_runtime
        if runtime is None:
            return session
        try:
            did_reset = bool(
                runtime.reset_for_func(
                    function_ea,
                    preserve_active_session=has_active_parent,
                )
            )
        except Exception:
            logger.exception(
                "analysis runtime session reset failed for func=0x%x",
                function_ea,
            )
            return session
        if did_reset and self.rule_scope_service is not None:
            try:
                self.rule_scope_service.clear_hint_state(function_ea)
            except Exception:
                logger.exception(
                    "rule-scope hint reset failed for func=0x%x",
                    function_ea,
                )
        return session

    def current_session(self, function_ea: int) -> DecompilationSessionContext | None:
        """Return the innermost active session for ``function_ea``."""
        function_ea = int(function_ea)
        for session in reversed(self._active_sessions):
            if session.function_ea == function_ea:
                return session
        return None

    def capture_flowgraph(self, payload: FlowgraphReadyPayload) -> None:
        """Collect and persist portable flowgraph facts in their existing order."""
        phase = self.preanalysis_phase
        if phase is not None:
            try:
                phase.run_microcode_collectors(
                    payload.flow_graph,
                    func_ea=int(payload.func_ea),
                    provider_phase=payload.provider_phase,
                )
            except Exception:
                logger.exception(
                    "preanalysis flowgraph collection failed for func=0x%x maturity=%s",
                    int(payload.func_ea),
                    payload.provider_phase.friendly_provider_level,
                )

        runtime = self.analysis_runtime
        if runtime is not None:
            try:
                runtime.capture_maturity_facts(
                    payload.flow_graph,
                    func_ea=int(payload.func_ea),
                    provider_phase=payload.provider_phase,
                    phase="pre_d810",
                    snapshot=payload.snapshot,
                )
            except Exception:
                logger.exception(
                    "preanalysis fact capture failed for func=0x%x maturity=%s",
                    int(payload.func_ea),
                    payload.provider_phase.friendly_provider_level,
                )

    def capture_ctree(
        self,
        cfunc: typing.Any,
        *,
        func_ea: int,
        provider_phase: ProviderPhaseSnapshot,
    ) -> None:
        """Collect ctree evidence without making the hook own a phase object."""
        phase = self.preanalysis_phase
        if phase is None:
            return
        try:
            phase.run_ctree_collectors(
                cfunc,
                func_ea=int(func_ea),
                provider_phase=provider_phase,
            )
        except Exception:
            logger.exception(
                "preanalysis ctree collection failed for func=0x%x maturity=%s",
                int(func_ea),
                provider_phase.friendly_provider_level,
            )

    def analyze_current_function(self, *, function_ea: int, source: str) -> None:
        """Derive hints and apply them through the manager-owned rule scope."""
        if self.preanalysis_phase is None or self.analysis_runtime is None:
            return
        function_ea = int(function_ea)
        try:
            hints = self.analysis_runtime.analyze_and_persist(function_ea)
        except Exception:
            logger.exception("analysis failed for func=0x%x", function_ea)
            return
        if hints is None or self.rule_scope_service is None:
            return
        try:
            apply_result = self.rule_scope_service.apply_hints(hints)
            self.analysis_runtime.record_rule_scope_outcome(
                func_ea=function_ea,
                hints=hints,
                apply_result=apply_result,
                source=source,
            )
        except Exception:
            logger.exception("rule-scope hint application failed for func=0x%x", function_ea)

    def finish_hexrays_session(self) -> DecompilationSessionEvent | None:
        """Finish the innermost session and return its typed observer event."""
        if not self._active_sessions:
            return None
        session = self._active_sessions.pop()
        parent = self._active_sessions[-1] if self._active_sessions else None
        runtime = self.analysis_runtime
        if runtime is not None:
            try:
                runtime.mark_decompilation_finished(
                    resume_func_ea=(
                        parent.function_ea if parent is not None else None
                    ),
                )
            except Exception:
                logger.exception(
                    "analysis runtime session finish failed for func=0x%x",
                    session.function_ea,
                )
        return session.event
