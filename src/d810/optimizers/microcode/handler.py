import ida_hexrays

from d810.hexrays.hexrays_formatters import string_to_maturity

# Practical maturities - MMAT_GLBOPT3 is rarely/never called by Hex-Rays
# MMAT_GLBOPT2 is the latest practical maturity level for most operations
DEFAULT_INSTRUCTION_MATURITIES = [
    ida_hexrays.MMAT_LOCOPT,
    ida_hexrays.MMAT_CALLS,
    ida_hexrays.MMAT_GLBOPT1,
    ida_hexrays.MMAT_GLBOPT2,
    ida_hexrays.MMAT_LVARS,
]
DEFAULT_FLOW_MATURITIES = [ida_hexrays.MMAT_CALLS, ida_hexrays.MMAT_GLBOPT1]


class OptimizationRule:
    NAME = None
    DESCRIPTION = None

    def __init__(self):
        self.maturities = []
        self.config = {}
        self.log_dir = None
        self.dump_intermediate_microcode = False

    def set_log_dir(self, log_dir):
        self.log_dir = log_dir

    def configure(self, kwargs):
        self.config = kwargs if kwargs is not None else {}
        if "maturities" in self.config:
            self.maturities = [string_to_maturity(x) for x in self.config["maturities"]]
        if "dump_intermediate_microcode" in self.config:
            self.dump_intermediate_microcode = self.config[
                "dump_intermediate_microcode"
            ]

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
