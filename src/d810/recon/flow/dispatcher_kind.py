"""Pure-data dispatcher type taxonomy.

Companion to ``d810.recon.flow.dispatcher_detection`` that holds the
``DispatcherType`` enum alone -- a small, pure-data carrier with no
``ida_hexrays`` dependency at module import time.

Axis-C slice B1c (the architectural split that *prepares* the future
B2 normalization of ``dispatcher_detection.py``): pulling the
``DispatcherType`` enum out of the larger live-IDA file gives the
two direct unit-test importers
(``test_predecessor_dispatcher_target``,
``test_dispatcher_discovery_facts``) a path that does not transit
``dispatcher_detection.py``.  The ``DispatcherCache`` chain through
``manager`` / ``fixpred_signals`` / ``snapshot_builder`` / ``family``
is intentionally NOT addressed by this slice -- moving
``DispatcherCache`` would conflate split-file work with the
normalization slice (B2) and bulk-move ~700 lines of analysis
machinery.  Those chains stay open until a separate B1a (caller-side
refactor) decides how the analysis orchestration should be owned.

Compatibility: ``DispatcherType`` is re-exported from
``dispatcher_detection`` so existing import paths keep working.  The
dependency direction is one-way:
``dispatcher_detection -> dispatcher_kind`` (downward), never the
reverse.
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
