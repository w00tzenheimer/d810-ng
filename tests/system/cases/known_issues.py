"""Known issues with IDA's decompiler on specific functions.

These functions cause segfaults in ida_hexrays.decompile_func and must be
skipped until the root cause is resolved (likely an IDA Pro native bug).
"""

SEGFAULT_FUNCTIONS = {
    "tigress_minmaxarray",  # Segfault in ida_hexrays.decompile_func during Tigress unflattening (INTERR 50863)
}
