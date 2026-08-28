"""Closed v12 diagnostic fixtures for the offline collector replays.

These helpers deliberately add provenance at the fixture boundary.  They do
not infer or repair production snapshots; every caller still supplies the
portable row and the block factory records the tail independently from that
row, matching the serializer contract used by :class:`DiagSourceLifter`.
"""

from __future__ import annotations

from d810.core.observability_models import (
    DIAG_PROVENANCE_VERSION,
    BlockSnapshot,
    InstructionSnapshot,
)
from d810.core.typing import Any


def diag_instruction(**fields: Any) -> InstructionSnapshot:
    """Construct an explicitly v12 instruction fixture."""
    fields.setdefault("raw_opcode", fields.get("opcode"))
    fields.setdefault("provenance_version", DIAG_PROVENANCE_VERSION)
    return InstructionSnapshot(**fields)


def diag_block(**fields: Any) -> BlockSnapshot:
    """Construct an explicitly v12 block with independently recorded tail."""
    instructions = list(fields.get("instructions", ()) or ())
    fields["instructions"] = instructions
    fields.setdefault("provenance_version", DIAG_PROVENANCE_VERSION)
    if instructions:
        missing = [
            name for name in ("tail_opcode", "raw_tail_opcode", "tail_kind")
            if fields.get(name) is None
        ]
        if missing:
            raise ValueError(
                "diag block lacks independent tail evidence: " + ", ".join(missing)
            )
    return BlockSnapshot(**fields)
