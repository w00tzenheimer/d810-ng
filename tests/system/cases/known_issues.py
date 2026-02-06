"""Known issues with IDA's decompiler on specific functions.

These functions cause segfaults in ida_hexrays.decompile_func and must be
skipped until the root cause is resolved (likely an IDA Pro native bug).
"""

SEGFAULT_FUNCTIONS = {
    "switch_case_ollvm_pattern",
    "high_fan_in_pattern",
    "while_switch_flattened",
    "tigress_minmaxarray",
    "AntiDebug_ExceptionFilter",
}
