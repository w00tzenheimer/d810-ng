"""IDA Hex-Rays microcode constants for IDA-free code paths.

Values sourced from ida_hexrays (IDA SDK 9.x) and verified against
the Cython binding at speedups/cythxr/sdk/hexrays.pxd.

This module exists so that portable_cfg, CFGPasses, and recon collectors
can reference IDA enum values without importing ida_hexrays.
"""

# mblock_type_t — block type classification
BLT_NONE = 0   # unknown
BLT_STOP = 1   # stops execution (last block)
BLT_0WAY = 2   # no successors (noret)
BLT_1WAY = 3   # unconditional jump
BLT_2WAY = 4   # conditional branch
BLT_NWAY = 5   # switch statement
BLT_XTRN = 6   # external block

# mopt_t — operand type classification
MOP_B = 7      # mop_b — block reference operand

# Instruction opcodes
M_GOTO = 55    # m_goto (0x37) — unconditional goto

__all__ = [
    "BLT_NONE",
    "BLT_STOP",
    "BLT_0WAY",
    "BLT_1WAY",
    "BLT_2WAY",
    "BLT_NWAY",
    "BLT_XTRN",
    "MOP_B",
    "M_GOTO",
]
