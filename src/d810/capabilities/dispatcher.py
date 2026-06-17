"""LS11 C5: portable router-kind enum (ticket d81-mt50).

Lives in ``d810.capabilities`` (layer below cfg/analyses).
``capabilities -> cfg`` and ``capabilities -> analyses`` are UPWARD-FATAL;
``capabilities -> ir`` is the only legal structural dependency (precedent:
``capabilities/use_def_safety.py``).
"""
from __future__ import annotations

import enum

__all__ = ["RouterKind"]


class RouterKind(str, enum.Enum):
    SWITCH = "switch"
    EQUALITY_CHAIN = "equality_chain"
    CONDITION_CHAIN = "condition_chain"
    INDIRECT_TABLE = "indirect_table"
    UNKNOWN = "unknown"
