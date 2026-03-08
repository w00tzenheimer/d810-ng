"""Ctree-level optimization hooks.

Provides ``CtreeOptimizationRule`` (base class for all ctree rules)
and ``CtreeOptimizerManager`` (iterates rules at the right maturity).
"""

from __future__ import annotations

import abc

from d810.core import getLogger, typing
from d810.core.registry import Registrant
from d810.core.stats import OptimizationStatistics

logger = getLogger("D810.optimizer")

# ---------------------------------------------------------------------------
# IDA imports are optional for testing.
# ---------------------------------------------------------------------------
import ida_hexrays


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
        recon_phase=None,
        recon_runtime=None,
    ) -> None:
        logger.debug("Initializing CtreeOptimizerManager...")
        self.ctree_rules: list[CtreeOptimizationRule] = []
        self.stats: OptimizationStatistics = stats
        # Optional ReconPhase - when set, fires ctree collectors at each
        # maturity level before ctree rules run. None means recon is disabled.
        self._recon_phase = recon_phase  # ReconPhase | None
        # Optional ReconAnalysisRuntime - set via configure(recon_runtime=...).
        # Used to eagerly analyze and persist hints after ctree collectors.
        self._recon_runtime = recon_runtime  # ReconAnalysisRuntime | None

    def configure(self, **kwargs) -> None:
        """Update optional dependencies after construction."""
        self._recon_phase = kwargs.get("recon_phase", self._recon_phase)
        self._recon_runtime = kwargs.get("recon_runtime", self._recon_runtime)

    def add_rule(self, rule: CtreeOptimizationRule) -> None:
        """Register a ctree rule."""
        logger.info("Adding ctree rule %s", rule.name)
        self.ctree_rules.append(rule)

    def on_maturity(self, cfunc: typing.Any, new_maturity: int) -> int:
        """Called when ctree maturity changes.

        Only processes rules at ``CMAT_FINAL``.

        :param cfunc: ``ida_hexrays.cfunc_t``
        :param new_maturity: the new maturity level
        :return: total number of patches applied
        """
        # Recon: fire ctree collectors at every maturity level (no-op when
        # _recon_phase is None - guarded for zero overhead when disabled).
        if self._recon_phase is not None:
            func_ea = int(getattr(cfunc, "entry_ea", 0) or 0)
            try:
                self._recon_phase.run_ctree_collectors(
                    cfunc,
                    func_ea=func_ea,
                    maturity=new_maturity,
                )
            except Exception:
                logger.exception(
                    "ReconPhase (ctree) failed at maturity %d", new_maturity
                )
            if self._recon_runtime is not None:
                try:
                    self._recon_runtime.analyze_and_persist(func_ea)
                except Exception:
                    logger.exception(
                        "ReconRuntime analyze_and_persist (ctree) failed for func=0x%x",
                        func_ea,
                    )

        if ida_hexrays is not None and new_maturity != ida_hexrays.CMAT_FINAL:
            return 0

        total: int = 0
        for rule in self.ctree_rules:
            try:
                n = rule.optimize_ctree(cfunc)
                if n > 0:
                    logger.info("Ctree rule %s matched: %d patches", rule.name, n)
                    if self.stats is not None:
                        self.stats.record_cfg_rule_patches(rule.name, n)
                    total += n
            except Exception:
                logger.exception("Ctree rule %s failed", rule.name)
        return total
