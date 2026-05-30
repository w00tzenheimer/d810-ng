"""LS11 C5: portable router-kind enum + state-machine seed (ticket d81-mt50).

Lives in ``d810.capabilities`` (layer below cfg/analyses).  ``FunctionId`` /
``BlockRef`` / ``collector_analysis`` are ``Any``-typed because
``capabilities -> cfg`` and ``capabilities -> analyses`` are UPWARD-FATAL;
``capabilities -> ir`` is the only legal structural dependency (precedent:
``capabilities/use_def_safety.py``).
"""
from __future__ import annotations

import enum
from dataclasses import dataclass, field
from d810.core.typing import Any

__all__ = ["RouterKind", "StateMachineSeed"]


class RouterKind(str, enum.Enum):
    BST = "bst"
    SWITCH = "switch"
    EQUALITY_CHAIN = "equality_chain"
    CONDITION_CHAIN = "condition_chain"
    INDIRECT_TABLE = "indirect_table"
    UNKNOWN = "unknown"


@dataclass(frozen=True)
class StateMachineSeed:
    """Cheap pre-resolution inputs a DispatcherResolver consumes (design doc)."""

    function_id: Any  # FunctionId (cfg/ir) -- Any to stay below the layer line
    candidate_entries: tuple[Any, ...] = ()  # tuple[BlockRef, ...]
    collector_analysis: Any | None = None
    profile_name: str = ""
