"""Ctree-level optimization hooks.

Provides ``CtreeOptimizationRule`` (base class for all ctree rules)
and ``CtreeOptimizerManager`` (iterates rules at the right maturity).
"""

from __future__ import annotations

import abc

from d810.core import getLogger, typing
from d810.core.provider_phase import ProviderPhaseSnapshot
from d810.core.registry import Registrant
from d810.core.stats import OptimizationStatistics

logger = getLogger("D810.optimizer")
HEXRAYS_CTREE_PROVIDER = "hexrays_ctree"

# ---------------------------------------------------------------------------
# IDA imports are optional for testing.
# ---------------------------------------------------------------------------
import ida_hexrays

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

    def on_maturity(self, cfunc: typing.Any, new_maturity: int) -> int:
        """Called when ctree maturity changes.

        Only processes rules at ``CMAT_FINAL``.

        :param cfunc: ``ida_hexrays.cfunc_t``
        :param new_maturity: the new maturity level
        :return: total number of patches applied
        """
        lifecycle = self._decompilation_lifecycle
        if lifecycle is not None:
            func_ea = int(getattr(cfunc, "entry_ea", 0) or 0)
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
