from __future__ import annotations

import abc
import warnings
from enum import IntEnum
from d810.core.typing import TYPE_CHECKING

import ida_hexrays
import idc

from d810.core import getLogger, Registrant
from d810.hexrays.hexrays_formatters import maturity_to_string
from d810.optimizers.microcode.handler import ConfigParam, DEFAULT_FLOW_MATURITIES, OptimizationRule

logger = getLogger("D810.optimizer")

if TYPE_CHECKING:
    from d810.optimizers.microcode.flow.context import FlowMaturityContext


class FlowRulePriority(IntEnum):
    """Named priority gates for flow optimizers (higher runs earlier)."""

    PREPARE_CONSTANTS = 500
    PREDICATE_PREDECESSOR_FIX = 400
    UNFLATTEN = 300
    CLEANUP_JUMPS = 200
    DEFAULT = 100


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

    CATEGORY = "Control Flow"
    CONFIG_SCHEMA = OptimizationRule.CONFIG_SCHEMA + (
        ConfigParam("priority", int, int(FlowRulePriority.DEFAULT), "Execution priority (higher runs earlier)"),
        ConfigParam("whitelisted_functions", list, [], "Function EAs to process (hex strings)"),
        ConfigParam("blacklisted_functions", list, [], "Function EAs to skip (hex strings)"),
    )

    # CFG modification safety markers - subclasses should override
    USES_DEFERRED_CFG: bool = True  # Assume safe by default
    SAFE_MATURITIES: list[int] | None = None  # None = all maturities safe
    PRIORITY: int = int(FlowRulePriority.DEFAULT)
    REQUIRES_DISPATCHER_ANALYSIS: bool = False

    def __init__(self):
        super().__init__()
        self._current_maturity = ida_hexrays.MMAT_ZERO
        self.maturities = DEFAULT_FLOW_MATURITIES
        self.priority = self.PRIORITY
        self.flow_context: FlowMaturityContext | None = None
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
            unsafe_names = [maturity_to_string(m) for m in unsafe_maturities]
            safe_names = [maturity_to_string(m) for m in self.SAFE_MATURITIES]
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

    def set_flow_context(self, flow_context: FlowMaturityContext | None) -> None:
        self.flow_context = flow_context

    @abc.abstractmethod
    def optimize(self, blk):
        """Perform the optimization on *blk* and return the number of changes."""
        raise NotImplementedError

    @staticmethod
    def _parse_priority(raw_priority: object) -> int:
        """Parse priority from int/IntEnum/string enum name."""
        if isinstance(raw_priority, IntEnum):
            return int(raw_priority)
        if isinstance(raw_priority, int):
            return raw_priority
        if isinstance(raw_priority, str):
            text = raw_priority.strip()
            if text.isdigit():
                return int(text)
            enum_name = text.split(".")[-1].upper()
            if enum_name in FlowRulePriority.__members__:
                return int(FlowRulePriority[enum_name])
        raise ValueError(f"Unsupported priority value: {raw_priority!r}")

    def configure(self, kwargs):
        super().configure(kwargs)
        self.priority = int(self.PRIORITY)
        if "priority" in self.config:
            try:
                self.priority = self._parse_priority(self.config["priority"])
            except (TypeError, ValueError):
                logger.warning(
                    "Invalid priority %r for %s; falling back to default %d",
                    self.config["priority"],
                    self.__class__.__name__,
                    self.PRIORITY,
                )
                self.priority = self.PRIORITY
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
            for func_ea in self.config["blacklisted_functions"]:
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
