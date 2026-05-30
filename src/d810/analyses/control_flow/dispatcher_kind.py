"""Pure-data dispatcher type taxonomy.

Holds the ``DispatcherType`` enum alone -- a small, pure-data
carrier with no ``ida_hexrays`` dependency at module import time.
The canonical home for this enum; recon and optimizer code imports
from here directly (no re-export shim).
"""

from __future__ import annotations

from enum import Enum

__all__ = ["DispatcherType"]


class DispatcherType(Enum):
    """Classification of control-flow flattening dispatcher mechanisms.

    Different obfuscators use different dispatcher patterns. Identifying the type
    helps select the appropriate unflattening strategy and avoid techniques that
    cause cascading unreachability issues.
    """

    # Unknown or unclassified dispatcher pattern
    UNKNOWN = 0

    # Switch/jump table based dispatcher (jtbl instruction)
    # Used by: O-LLVM, Tigress (switch mode), commercial obfuscators
    # Pattern: Central switch statement dispatches to handler blocks
    # Characteristics: m_jtbl opcode, computed goto, single dispatcher block
    SWITCH_TABLE = 1

    # Conditional chain dispatcher (nested jnz/jz comparisons)
    # Used by: Hodur malware, various C2 frameworks, info stealers
    # Pattern: Nested while(1) loops with sequential state comparisons
    # Characteristics: No jtbl, many jnz/jz blocks, nested loop structure
    # Note: Requires special handling to avoid cascading unreachability
    CONDITIONAL_CHAIN = 2

    # Indirect jump dispatcher (computed address)
    # Used by: Tigress (indirect mode), some VM protectors
    # Pattern: Jump target computed from state variable
    # Characteristics: m_goto with mop_d destination, address arithmetic
    INDIRECT_JUMP = 3
