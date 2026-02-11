from dataclasses import dataclass
from typing import Any

import ida_hexrays

from d810.hexrays.hexrays_formatters import string_to_maturity


@dataclass(frozen=True)
class ConfigParam:
    """Typed metadata for a single configuration parameter.

    Used by the UI to auto-generate proper editors for rule configuration.
    """

    name: str
    type: type  # bool, int, str, list, float, dict
    default: Any
    description: str
    choices: tuple | None = None  # for enum-like params

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
    CATEGORY: str = "General"
    CONFIG_SCHEMA: tuple[ConfigParam, ...] = (
        ConfigParam(
            "maturities",
            list,
            [],
            "Microcode maturity levels to run at",
            choices=(
                "MMAT_GENERATED",
                "MMAT_PREOPTIMIZED",
                "MMAT_LOCOPT",
                "MMAT_CALLS",
                "MMAT_GLBOPT1",
                "MMAT_GLBOPT2",
                "MMAT_GLBOPT3",
                "MMAT_LVARS",
            ),
        ),
        ConfigParam("dump_intermediate_microcode", bool, False, "Dump microcode for debugging"),
    )

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
