"""Backend-agnostic CFG modification intents.

GraphModification provides frozen dataclass representations of CFG modification
operations with no IDA dependency. These types capture modification intent
and can be mapped to DeferredGraphModifier operations.

The dataclasses in this module represent:
- Edge redirects (goto, conditional, fallthrough)
- Block creation with instruction insertion
- Edge removal
- Instruction NOPs

All types are frozen (immutable) to ensure modification intent integrity.

Mapping to DeferredGraphModifier
---------------------------------
These frozen types map to DeferredGraphModifier modification types:

- RedirectEdge       → BLOCK_GOTO_CHANGE or BLOCK_TARGET_CHANGE
- ConvertToGoto      → BLOCK_CONVERT_TO_GOTO
- InsertBlock        → BLOCK_CREATE_WITH_REDIRECT
- RemoveEdge         → (future use, not yet in DeferredGraphModifier)
- NopInstructions    → BLOCK_NOP_INSNS

Design Notes
------------
- All types are frozen (immutable) for snapshot integrity
- Serial numbers (int) are used instead of live block pointers
- Tuple fields (instructions, insn_eas) enforce immutability
- Union type (GraphModification) enables type discrimination via isinstance/match
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Union

# Import InsnSnapshot from Phase 3 (portable CFG layer)
from d810.hexrays.portable_cfg import InsnSnapshot


@dataclass(frozen=True)
class RedirectEdge:
    """Redirect an edge from one target to another.

    Maps to DeferredGraphModifier's BLOCK_GOTO_CHANGE (1-way blocks) or
    BLOCK_TARGET_CHANGE (2-way conditional blocks).

    Attributes:
        from_serial: Source block serial number.
        old_target: Current target block serial (for verification).
        new_target: New target block serial.

    Example:
        >>> mod = RedirectEdge(from_serial=10, old_target=20, new_target=30)
        >>> mod.from_serial
        10
        >>> mod.new_target
        30
    """
    from_serial: int
    old_target: int
    new_target: int


@dataclass(frozen=True)
class ConvertToGoto:
    """Convert a block's tail to an unconditional goto.

    Maps to DeferredGraphModifier's BLOCK_CONVERT_TO_GOTO.
    Typically used to simplify 2-way blocks to 1-way when one branch is dead.

    Attributes:
        block_serial: Block to convert to goto.
        goto_target: Target block for the unconditional goto.

    Example:
        >>> mod = ConvertToGoto(block_serial=15, goto_target=25)
        >>> mod.block_serial
        15
        >>> mod.goto_target
        25
    """
    block_serial: int
    goto_target: int


@dataclass(frozen=True)
class InsertBlock:
    """Insert a new block between pred and succ with given instructions.

    Maps to DeferredGraphModifier's BLOCK_CREATE_WITH_REDIRECT.
    Creates a new intermediate block containing the specified instructions
    and redirects pred → new_block → succ.

    Attributes:
        pred_serial: Predecessor block serial (edge source).
        succ_serial: Successor block serial (edge target).
        instructions: Tuple of instruction snapshots to place in new block.

    Example:
        >>> from d810.hexrays.mop_snapshot import MopSnapshot
        >>> insn1 = InsnSnapshot(opcode=0x01, ea=0x1000, operands=())
        >>> insn2 = InsnSnapshot(opcode=0x02, ea=0x1004, operands=())
        >>> mod = InsertBlock(pred_serial=5, succ_serial=10, instructions=(insn1, insn2))
        >>> len(mod.instructions)
        2
        >>> mod.pred_serial
        5
    """
    pred_serial: int
    succ_serial: int
    instructions: tuple[InsnSnapshot, ...]


@dataclass(frozen=True)
class RemoveEdge:
    """Remove an edge between two blocks.

    Future use - not yet implemented in DeferredGraphModifier.
    Reserved for explicit edge removal without replacement (e.g., dead code elimination).

    Attributes:
        from_serial: Source block serial.
        to_serial: Target block serial.

    Example:
        >>> mod = RemoveEdge(from_serial=10, to_serial=20)
        >>> mod.from_serial
        10
        >>> mod.to_serial
        20
    """
    from_serial: int
    to_serial: int


@dataclass(frozen=True)
class NopInstructions:
    """NOP specific instructions in a block by their EAs.

    Maps to DeferredGraphModifier's BLOCK_NOP_INSNS.
    Used to neutralize specific instructions without removing them from the block.

    Attributes:
        block_serial: Block containing the instructions.
        insn_eas: Tuple of instruction effective addresses to NOP.

    Example:
        >>> mod = NopInstructions(block_serial=10, insn_eas=(0x1000, 0x1004, 0x1008))
        >>> len(mod.insn_eas)
        3
        >>> 0x1000 in mod.insn_eas
        True
    """
    block_serial: int
    insn_eas: tuple[int, ...]


# Union type for type discrimination via isinstance() or match statement
GraphModification = Union[
    RedirectEdge,
    ConvertToGoto,
    InsertBlock,
    RemoveEdge,
    NopInstructions,
]


__all__ = [
    "RedirectEdge",
    "ConvertToGoto",
    "InsertBlock",
    "RemoveEdge",
    "NopInstructions",
    "GraphModification",
]
