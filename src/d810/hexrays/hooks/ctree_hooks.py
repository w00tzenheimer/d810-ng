"""Ctree-level optimization hooks.

Provides ``CtreeOptimizationRule`` (base class for all ctree rules)
and ``CtreeOptimizerManager`` (iterates rules at the right maturity).
"""

from __future__ import annotations

import abc

from d810.core.execution_journal import (
    ExecutionAttempt,
    ExecutionAttemptStatus,
    ExecutionDomain,
    ExecutionEffectRef,
)
from d810.core.execution_journal_store import (
    ExecutionJournalStore,
    TerminalExecutionAttempt,
)
from d810.core import getLogger, typing
from d810.analyses.control_flow.native_preanalysis_session import (
    NativeMutationBoundary,
)
from d810.core.provider_phase import ProviderPhaseSnapshot
from d810.core.registry import Registrant
from d810.core.stats import OptimizationStatistics

logger = getLogger("d810.optimizer")
HEXRAYS_CTREE_PROVIDER = "hexrays_ctree"

# ---------------------------------------------------------------------------
# IDA imports are optional for testing.
# ---------------------------------------------------------------------------
import ida_hexrays  # noqa: E402

_CTREE_MATURITY_NAMES = (
    "CMAT_ZERO",
    "CMAT_BUILT",
    "CMAT_TRANS1",
    "CMAT_NICE",
    "CMAT_TRANS2",
    "CMAT_CPA",
    "CMAT_TRANS3",
    "CMAT_CASTED",
    "CMAT_FINAL",
)
_CTREE_MATURITY_FALLBACKS = {
    0: "CMAT_ZERO",
    1: "CMAT_BUILT",
    2: "CMAT_TRANS1",
    3: "CMAT_NICE",
    4: "CMAT_TRANS2",
    5: "CMAT_CPA",
    6: "CMAT_TRANS3",
    7: "CMAT_CASTED",
    8: "CMAT_FINAL",
    60: "CMAT_FINAL",
}


def _ctree_maturity_to_string(maturity: int) -> str:
    maturity_value = int(maturity)
    for name in _CTREE_MATURITY_NAMES:
        value = getattr(ida_hexrays, name, None)
        if value is not None and int(value) == maturity_value:
            return name
    return _CTREE_MATURITY_FALLBACKS.get(
        maturity_value, f"Unknown ctree maturity: {maturity_value}"
    )


class CtreeOptimizationRule(Registrant, abc.ABC):
    """Base class for ctree-level optimization rules.

    Subclasses must implement ``optimize_ctree()`` which receives the
    decompiled function's ctree and returns the number of modifications
    made.

    Subclasses auto-register into ``CtreeOptimizationRule.registry``
    via the ``Registrant`` metaclass.
    """

    NAME = None
    DESCRIPTION = None

    def __init__(self) -> None:
        self.maturities: list = []
        self.config: dict = {}
        self.log_dir = None
        self.dump_intermediate_microcode = False

    def set_log_dir(self, log_dir):
        self.log_dir = log_dir

    def configure(self, kwargs):
        self.config = kwargs if kwargs is not None else {}

    @property
    def name(self):
        if self.NAME is not None:
            return self.NAME
        return self.__class__.__name__

    @property
    def description(self):
        if self.DESCRIPTION is not None:
            return self.DESCRIPTION
        return "No description available"

    @abc.abstractmethod
    def optimize_ctree(self, cfunc: typing.Any) -> int:
        """Optimize the ctree.

        :param cfunc: ``ida_hexrays.cfunc_t`` -- the decompiled function.
        :return: count of modifications made (0 means no change).
        """


class CtreeOptimizerManager:
    """Iterates ctree rules at the right decompiler maturity.

    Designed to be called from ``HexraysDecompilationHook.maturity()``.
    Only fires rules when the maturity reaches ``CMAT_FINAL``.
    """

    def __init__(
        self,
        stats: OptimizationStatistics,
        decompilation_lifecycle=None,
    ) -> None:
        logger.debug("Initializing CtreeOptimizerManager...")
        self.ctree_rules: list[CtreeOptimizationRule] = []
        self.stats: OptimizationStatistics = stats
        # Manager-owned lifecycle port.  The hook stays callback-local and
        # does not retain a phase or analysis runtime.
        self._decompilation_lifecycle = decompilation_lifecycle

    def configure(self, **kwargs) -> None:
        """Update optional dependencies after construction."""
        self._decompilation_lifecycle = kwargs.get(
            "decompilation_lifecycle",
            self._decompilation_lifecycle,
        )

    def add_rule(self, rule: CtreeOptimizationRule) -> None:
        """Register a ctree rule."""
        logger.info("Adding ctree rule %s", rule.name)
        self.ctree_rules.append(rule)

    def _execution_attempt_context(
        self,
        *,
        function_ea: int,
    ) -> tuple[ExecutionJournalStore | None, object | None, object | None]:
        """Return the active manager-owned journal/session/parent correlation."""
        lifecycle = self._decompilation_lifecycle
        if lifecycle is None:
            return None, None, None
        journal = getattr(lifecycle, "execution_journal", None)
        current_session = getattr(lifecycle, "current_session", None)
        if not isinstance(journal, ExecutionJournalStore) or not callable(
            current_session
        ):
            return None, None, None
        try:
            session = current_session(function_ea)
        except Exception:
            logger.debug(
                "ctree execution context unavailable for func=0x%x",
                function_ea,
                exc_info=True,
            )
            return None, None, None
        if session is None:
            return None, None, None
        session_id = getattr(session, "session_id", None)
        parent_attempt_id = getattr(session, "preanalysis_attempt_id", None)
        if session_id is None or parent_attempt_id is None:
            return None, None, None
        return journal, session_id, parent_attempt_id

    @staticmethod
    def _advance_rule_attempt(
        journal: ExecutionJournalStore | None,
        attempt: ExecutionAttempt | None,
        *,
        status: ExecutionAttemptStatus,
        reason_code: str | None = None,
        effect_refs: tuple[ExecutionEffectRef, ...] = (),
        details: dict[str, object] | None = None,
    ) -> None:
        """Record one terminal ctree outcome without masking the callback."""
        if journal is None or attempt is None:
            return
        try:
            journal.advance(
                attempt,
                status=status,
                reason_code=reason_code,
                effect_refs=effect_refs,
                details=details,
            )
        except Exception:
            logger.debug(
                "ctree execution journal advance failed for stage=%s",
                attempt.stage_id,
                exc_info=True,
            )

    @staticmethod
    def _record_terminal_attempts(
        journal: ExecutionJournalStore,
        session_id: object,
        parent_attempt_id: object,
        records: tuple[TerminalExecutionAttempt, ...],
    ) -> None:
        try:
            journal.record_terminal_attempts(
                session_id,
                parent_attempt_id=parent_attempt_id,
                records=records,
            )
        except Exception:
            logger.debug(
                "ctree execution journal terminal record failed",
                exc_info=True,
            )

    @staticmethod
    def _summarize_abstention(
        journal: ExecutionJournalStore,
        session_id: object,
        parent_attempt_id: object,
        *,
        stage_id: str,
        maturity: str,
    ) -> None:
        try:
            journal.summarize_callback_abstention(
                session_id,
                parent_attempt_id=parent_attempt_id,
                callback_kind="ctree",
                stage_id=stage_id,
                maturity=maturity,
                reason_code="no_modifications",
            )
        except Exception:
            logger.debug(
                "ctree execution journal callback summary failed",
                exc_info=True,
            )

    def on_maturity(self, cfunc: typing.Any, new_maturity: int) -> int:
        """Called when ctree maturity changes.

        Only processes rules at ``CMAT_FINAL``.

        :param cfunc: ``ida_hexrays.cfunc_t``
        :param new_maturity: the new maturity level
        :return: total number of patches applied
        """
        lifecycle = self._decompilation_lifecycle
        func_ea = int(getattr(cfunc, "entry_ea", 0) or 0)
        if lifecycle is not None:
            provider_phase = ProviderPhaseSnapshot(
                provider_name=HEXRAYS_CTREE_PROVIDER,
                provider_level=int(new_maturity),
                friendly_provider_level=_ctree_maturity_to_string(new_maturity),
            )
            lifecycle.capture_ctree(
                cfunc,
                func_ea=func_ea,
                provider_phase=provider_phase,
            )
            lifecycle.analyze_current_function(
                function_ea=func_ea,
                source="analyzed",
            )
            observe_quarantine = getattr(
                lifecycle,
                "observe_native_mutation_quarantine",
                None,
            )
            if callable(observe_quarantine) and observe_quarantine(
                function_ea=func_ea,
                maturity=int(new_maturity),
                boundary=NativeMutationBoundary.CTREE,
            ):
                return 0

        if ida_hexrays is not None and new_maturity != ida_hexrays.CMAT_FINAL:
            return 0

        total: int = 0
        maturity_detail = {"maturity": _ctree_maturity_to_string(new_maturity)}
        journal, session_id, parent_attempt_id = self._execution_attempt_context(
            function_ea=func_ea if lifecycle is not None else 0,
        )
        for rule in self.ctree_rules:
            attempt = None
            mutation_attempt = None
            if (
                journal is not None
                and session_id is not None
                and journal.callback_detail_is_full
            ):
                try:
                    attempt = journal.begin_attempt(
                        session_id,
                        parent_attempt_id=parent_attempt_id,
                        stage_id=f"ctree_rule:{rule.name}",
                        domain=ExecutionDomain.HOOK,
                    )
                except Exception:
                    logger.debug(
                        "ctree execution journal begin failed for rule=%s",
                        rule.name,
                        exc_info=True,
                    )
                try:
                    mutation_attempt = journal.begin_attempt(
                        session_id,
                        parent_attempt_id=(
                            attempt.attempt_id
                            if attempt is not None
                            else parent_attempt_id
                        ),
                        stage_id=f"ctree_mutation:{rule.name}",
                        domain=ExecutionDomain.MUTATION,
                    )
                except Exception:
                    logger.debug(
                        "ctree mutation journal begin failed for rule=%s",
                        rule.name,
                        exc_info=True,
                    )
            try:
                n = rule.optimize_ctree(cfunc)
                if n > 0:
                    logger.info("Ctree rule %s matched: %d patches", rule.name, n)
                    if self.stats is not None:
                        self.stats.record_cfg_rule_patches(rule.name, n)
                    total += n
                    details = {**maturity_detail, "patch_count": int(n)}
                    effects = ()
                    if mutation_attempt is not None:
                        effects = (
                            ExecutionEffectRef(
                                kind="ctree_edit",
                                ref_id=(
                                    f"{mutation_attempt.attempt_id.session.value}:"
                                    f"{mutation_attempt.attempt_id.sequence}"
                                ),
                                detail=details,
                            ),
                        )
                    self._advance_rule_attempt(
                        journal,
                        mutation_attempt,
                        status=ExecutionAttemptStatus.COMPLETED,
                        effect_refs=effects,
                        details=details,
                    )
                    self._advance_rule_attempt(
                        journal,
                        attempt,
                        status=ExecutionAttemptStatus.COMPLETED,
                        effect_refs=effects,
                        details=details,
                    )
                    if (
                        journal is not None
                        and session_id is not None
                        and attempt is None
                    ):
                        effect = ExecutionEffectRef(
                            kind="ctree_edit",
                            ref_id=f"ctree_rule:{rule.name}",
                            detail=details,
                        )
                        self._record_terminal_attempts(
                            journal,
                            session_id,
                            parent_attempt_id,
                            (
                                TerminalExecutionAttempt(
                                    stage_id=f"ctree_rule:{rule.name}",
                                    domain=ExecutionDomain.HOOK,
                                    status=ExecutionAttemptStatus.COMPLETED,
                                    effect_refs=(effect,),
                                    details=details,
                                ),
                                TerminalExecutionAttempt(
                                    stage_id=f"ctree_mutation:{rule.name}",
                                    domain=ExecutionDomain.MUTATION,
                                    status=ExecutionAttemptStatus.COMPLETED,
                                    effect_refs=(effect,),
                                    details=details,
                                    parent_record_index=0,
                                ),
                            ),
                        )
                else:
                    self._advance_rule_attempt(
                        journal,
                        mutation_attempt,
                        status=ExecutionAttemptStatus.ABSTAINED,
                        reason_code="no_modifications",
                        details={**maturity_detail, "patch_count": 0},
                    )
                    self._advance_rule_attempt(
                        journal,
                        attempt,
                        status=ExecutionAttemptStatus.ABSTAINED,
                        reason_code="no_modifications",
                        details={**maturity_detail, "patch_count": 0},
                    )
                    if (
                        journal is not None
                        and session_id is not None
                        and attempt is None
                    ):
                        self._summarize_abstention(
                            journal,
                            session_id,
                            parent_attempt_id,
                            stage_id=f"ctree_rule:{rule.name}",
                            maturity=str(maturity_detail["maturity"]),
                        )
            except Exception as exc:
                self._advance_rule_attempt(
                    journal,
                    mutation_attempt,
                    status=ExecutionAttemptStatus.FAILED,
                    reason_code=f"{type(exc).__name__}: {exc}",
                    details=maturity_detail,
                )
                self._advance_rule_attempt(
                    journal,
                    attempt,
                    status=ExecutionAttemptStatus.FAILED,
                    reason_code=f"{type(exc).__name__}: {exc}",
                    details=maturity_detail,
                )
                if journal is not None and session_id is not None and attempt is None:
                    reason_code = f"{type(exc).__name__}: {exc}"
                    self._record_terminal_attempts(
                        journal,
                        session_id,
                        parent_attempt_id,
                        (
                            TerminalExecutionAttempt(
                                stage_id=f"ctree_rule:{rule.name}",
                                domain=ExecutionDomain.HOOK,
                                status=ExecutionAttemptStatus.FAILED,
                                reason_code=reason_code,
                                details=maturity_detail,
                            ),
                            TerminalExecutionAttempt(
                                stage_id=f"ctree_mutation:{rule.name}",
                                domain=ExecutionDomain.MUTATION,
                                status=ExecutionAttemptStatus.FAILED,
                                reason_code=reason_code,
                                details=maturity_detail,
                                parent_record_index=0,
                            ),
                        ),
                    )
                logger.exception("Ctree rule %s failed", rule.name)
        return total
