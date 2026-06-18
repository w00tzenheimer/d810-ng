"""LS11 C5: portable router-kind enum (ticket d81-mt50).

Lives in ``d810.capabilities`` (layer below cfg/analyses).
``capabilities -> cfg`` and ``capabilities -> analyses`` are UPWARD-FATAL;
``capabilities -> ir`` is the only legal structural dependency (precedent:
``capabilities/use_def_safety.py``).
"""
from __future__ import annotations

import enum

__all__ = ["RouterKind", "TableProvenance"]


class RouterKind(str, enum.Enum):
    TABLE = "table"
    EQUALITY_CHAIN = "equality_chain"
    CONDITION_CHAIN = "condition_chain"
    UNKNOWN = "unknown"


class TableProvenance(str, enum.Enum):
    """Origin of a table-backed dispatcher.

    ``RouterKind.TABLE`` says routing is table-backed.  This enum says which
    recovery/projection produced the table evidence.
    """

    SWITCH = "switch"
    INDIRECT_JUMP_TABLE = "indirect_jump_table"
    UNKNOWN = "unknown"
