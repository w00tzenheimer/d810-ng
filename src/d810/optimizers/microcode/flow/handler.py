import abc

import ida_hexrays
import idc

from d810.conf.loggers import getLogger
from d810.optimizers.microcode.handler import DEFAULT_FLOW_MATURITIES, OptimizationRule
from d810.registry import Registrant

logger = getLogger("D810.optimizer")


class FlowOptimizationRule(OptimizationRule, Registrant, abc.ABC):
    def __init__(self):
        super().__init__()
        self._current_maturity = ida_hexrays.MMAT_ZERO
        self.maturities = DEFAULT_FLOW_MATURITIES
        self.use_whitelist = False
        self.whitelisted_function_ea_list: list[int] = []
        self.use_blacklist = False
        self.blacklisted_function_ea_list: list[int] = []

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
