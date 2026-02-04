import abc
import warnings

import ida_hexrays
import idc

from d810.core import getLogger
from d810.optimizers.microcode.handler import DEFAULT_FLOW_MATURITIES, OptimizationRule
from d810.core import Registrant

logger = getLogger("D810.optimizer")


class FlowOptimizationRule(OptimizationRule, Registrant, abc.ABC):
    """Base class for flow optimization rules.

    CFG Modification Safety
    -----------------------
    Rules that modify the CFG directly (without DeferredGraphModifier) must declare
    their safe maturities via class attributes:

    - USES_DEFERRED_CFG: bool - True if rule uses DeferredGraphModifier for all CFG mods
    - SAFE_MATURITIES: list[int] | None - Maturities where direct CFG mods are safe.
      None means all maturities are safe (only valid if USES_DEFERRED_CFG=True).

    Example for a rule with direct CFG modifications::

        class MyRule(FlowOptimizationRule):
            USES_DEFERRED_CFG = False
            SAFE_MATURITIES = [ida_hexrays.MMAT_CALLS, ida_hexrays.MMAT_GLBOPT1]

    Example for a rule using deferred CFG patching::

        class MyRule(FlowOptimizationRule):
            USES_DEFERRED_CFG = True
            SAFE_MATURITIES = None  # Safe at any maturity

    If a rule is configured to run at maturities outside SAFE_MATURITIES, a warning
    is emitted at initialization time.
    """

    # CFG modification safety markers - subclasses should override
    USES_DEFERRED_CFG: bool = True  # Assume safe by default
    SAFE_MATURITIES: list[int] | None = None  # None = all maturities safe

    def __init__(self):
        super().__init__()
        self._current_maturity = ida_hexrays.MMAT_ZERO
        self.maturities = DEFAULT_FLOW_MATURITIES
        self.use_whitelist = False
        self.whitelisted_function_ea_list: list[int] = []
        self.use_blacklist = False
        self.blacklisted_function_ea_list: list[int] = []
        self._check_maturity_safety()

    def _check_maturity_safety(self) -> None:
        """Check if configured maturities are safe for this rule's CFG modification pattern.

        Emits a warning if:
        - Rule uses direct CFG modifications (USES_DEFERRED_CFG=False)
        - Rule is configured to run at maturities outside SAFE_MATURITIES
        """
        if self.USES_DEFERRED_CFG:
            return  # Safe at any maturity

        if self.SAFE_MATURITIES is None:
            # Direct CFG mods but no safe maturities declared - this is a bug
            warnings.warn(
                f"{self.__class__.__name__} uses direct CFG modifications "
                f"(USES_DEFERRED_CFG=False) but SAFE_MATURITIES is None. "
                f"Please declare SAFE_MATURITIES or migrate to DeferredGraphModifier.",
                UserWarning,
                stacklevel=3,
            )
            return

        unsafe_maturities = set(self.maturities) - set(self.SAFE_MATURITIES)
        if unsafe_maturities:
            maturity_names = {
                ida_hexrays.MMAT_ZERO: "MMAT_ZERO",
                ida_hexrays.MMAT_GENERATED: "MMAT_GENERATED",
                ida_hexrays.MMAT_PREOPTIMIZED: "MMAT_PREOPTIMIZED",
                ida_hexrays.MMAT_LOCOPT: "MMAT_LOCOPT",
                ida_hexrays.MMAT_CALLS: "MMAT_CALLS",
                ida_hexrays.MMAT_GLBOPT1: "MMAT_GLBOPT1",
                ida_hexrays.MMAT_GLBOPT2: "MMAT_GLBOPT2",
                ida_hexrays.MMAT_GLBOPT3: "MMAT_GLBOPT3",
                ida_hexrays.MMAT_LVARS: "MMAT_LVARS",
            }
            unsafe_names = [maturity_names.get(m, str(m)) for m in unsafe_maturities]
            safe_names = [maturity_names.get(m, str(m)) for m in self.SAFE_MATURITIES]
            warnings.warn(
                f"{self.__class__.__name__} uses direct CFG modifications but is "
                f"configured to run at unsafe maturities: {unsafe_names}. "
                f"Safe maturities are: {safe_names}. "
                f"This may cause crashes. Consider migrating to DeferredGraphModifier.",
                UserWarning,
                stacklevel=3,
            )

    @property
    def current_maturity(self):
        return self._current_maturity

    @current_maturity.setter
    def current_maturity(self, maturity_level):
        self._current_maturity = maturity_level

    @abc.abstractmethod
    def optimize(self, blk):
        """Perform the optimization on *blk* and return the number of changes."""
        raise NotImplementedError

    def configure(self, kwargs):
        super().configure(kwargs)
        self.use_whitelist = False
        self.whitelisted_function_ea_list = []
        self.use_blacklist = False
        self.blacklisted_function_ea_list = []
        if "whitelisted_functions" in self.config:
            self.use_whitelist = True
            for func_ea in self.config["whitelisted_functions"]:
                self.whitelisted_function_ea_list.append(int(func_ea, 16))
            func_name_list = [
                idc.get_func_name(ea) for ea in self.whitelisted_function_ea_list
            ]
            logger.info(
                "Whitelisted functions for {0}: {1} -> {2}".format(
                    self.__class__.__name__,
                    self.whitelisted_function_ea_list,
                    func_name_list,
                )
            )
        if "blacklisted_functions" in self.config:
            self.use_blacklist = True
            for func_ea in self.config["whitelisted_functions"]:
                self.blacklisted_function_ea_list.append(int(func_ea, 16))
            func_name_list = [
                idc.get_func_name(ea) for ea in self.blacklisted_function_ea_list
            ]
            logger.info(
                "Blacklisted functions for {0}: {1} -> {2}".format(
                    self.__class__.__name__,
                    self.blacklisted_function_ea_list,
                    func_name_list,
                )
            )
        if "dump_intermediate_microcode" in self.config:
            self.dump_intermediate_microcode = self.config[
                "dump_intermediate_microcode"
            ]
