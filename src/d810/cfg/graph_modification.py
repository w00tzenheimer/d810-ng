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

- RedirectGoto       -> BLOCK_GOTO_CHANGE (1-way blocks only)
- RedirectBranch     -> BLOCK_TARGET_CHANGE (2-way conditional blocks only)
- ConvertToGoto      -> BLOCK_CONVERT_TO_GOTO
- EdgeRedirectViaPredSplit -> EDGE_REDIRECT_VIA_PRED_SPLIT
- CreateConditionalRedirect -> BLOCK_CREATE_WITH_CONDITIONAL_REDIRECT
- DuplicateBlock     -> (future use, backend currently warns/skips)
- InsertBlock        -> BLOCK_CREATE_WITH_REDIRECT
- RemoveEdge         -> (future use, not yet in DeferredGraphModifier)
- NopInstructions    -> BLOCK_NOP_INSNS

Design Notes
------------
- All types are frozen (immutable) for snapshot integrity
- Serial numbers (int) are used instead of live block pointers
- Tuple fields (instructions, insn_eas) enforce immutability
- Union type (GraphModification) enables type discrimination via isinstance/match
- RedirectGoto is for 1-way (unconditional goto) blocks
- RedirectBranch is for 2-way (conditional branch) blocks
"""
from __future__ import annotations

import enum
from dataclasses import dataclass
from d810.core.typing import Union

# Import InsnSnapshot from Phase 3 (FlowGraph layer)
from d810.cfg.flowgraph import InsnSnapshot


@dataclass(frozen=True)
class RedirectGoto:
    """Redirect an edge from a 1-way (unconditional goto) block.

    Maps to DeferredGraphModifier's BLOCK_GOTO_CHANGE.
    Use this for blocks with exactly one successor (1-way blocks).

    Attributes:
        from_serial: Source block serial number (must be a 1-way block).
        old_target: Current target block serial (for verification).
        new_target: New target block serial.

    Example:
        >>> mod = RedirectGoto(from_serial=10, old_target=20, new_target=30)
        >>> mod.from_serial
        10
        >>> mod.new_target
        30
    """
    from_serial: int
    old_target: int
    new_target: int


@dataclass(frozen=True)
class RedirectBranch:
    """Redirect one branch edge of a 2-way (conditional) block.

    Maps to DeferredGraphModifier's BLOCK_TARGET_CHANGE.
    Use this for blocks with exactly two successors (2-way conditional blocks).

    Attributes:
        from_serial: Source block serial number (must be a 2-way block).
        old_target: Current branch target block serial to be replaced.
        new_target: New branch target block serial.

    Example:
        >>> mod = RedirectBranch(from_serial=10, old_target=20, new_target=30)
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
class EdgeRedirectViaPredSplit:
    """Clone source block path and redirect one predecessor edge via clone.

    Maps to DeferredGraphModifier's EDGE_REDIRECT_VIA_PRED_SPLIT.

    Attributes:
        src_block: Source block that is cloned for split redirection.
        old_target: Existing successor target on the source path.
        new_target: New successor target on the cloned path.
        via_pred: Predecessor whose edge to src_block is rewired to clone.
        rule_priority: Rule priority for conflict resolution.
    """

    src_block: int
    old_target: int
    new_target: int
    via_pred: int
    rule_priority: int = 550


@dataclass(frozen=True)
class CreateConditionalRedirect:
    """Create a conditional 2-way block by cloning a reference block.

    Maps to DeferredGraphModifier's BLOCK_CREATE_WITH_CONDITIONAL_REDIRECT.
    """

    source_block: int
    ref_block: int
    conditional_target: int
    fallthrough_target: int


@dataclass(frozen=True)
class DuplicateBlock:
    """Request duplication of a block and predecessor redirect.

    Backend support is intentionally deferred in Phase 1; translators should
    emit diagnostics and skip.
    """

    source_block: int
    target_block: int | None
    pred_serial: int | None = None
    patch_kind: str = ""


@dataclass(frozen=True)
class InsertBlock:
    """Insert a new block between pred and succ with given instructions.

    Maps to DeferredGraphModifier's BLOCK_CREATE_WITH_REDIRECT.
    Creates a new intermediate block containing the specified instructions
    and redirects pred -> new_block -> succ.

    Attributes:
        pred_serial: Predecessor block serial (edge source).
        succ_serial: Successor block serial (edge target).
        instructions: Tuple of instruction snapshots to place in new block.

    Example:
        >>> from d810.hexrays.ir.mop_snapshot import MopSnapshot
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

    Implemented via DeferredGraphModifier.queue_remove_edge().
    Used for explicit edge removal without replacement (e.g., dead code elimination).
    A 2-way block losing one edge becomes 1-way; a 1-way block becomes 0-way.

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


@dataclass(frozen=True)
class PrivateTerminalSuffix:
    """Clone a shared terminal epilogue suffix chain for one anchor block.

    Privatizes a linear suffix chain (interior blocks nsucc==1, final nsucc==0)
    so that each anchor gets its own copy of the shared epilogue. The original
    shared suffix remains intact for other users.

    Attributes:
        anchor_serial: Block whose edge into shared_entry_serial will be rewired
            to the cloned chain entry.
        shared_entry_serial: First block of the shared suffix chain.
        return_block_serial: Terminal stop/return block (last in the suffix chain).
        suffix_serials: Ordered tuple of block serials in the shared suffix chain,
            from shared_entry through return_block.
        reason: Diagnostic reason string.

    Example:
        >>> mod = PrivateTerminalSuffix(
        ...     anchor_serial=9,
        ...     shared_entry_serial=63,
        ...     return_block_serial=64,
        ...     suffix_serials=(63, 64),
        ... )
        >>> mod.anchor_serial
        9
        >>> mod.suffix_serials
        (63, 64)
    """
    anchor_serial: int
    shared_entry_serial: int
    return_block_serial: int
    suffix_serials: tuple[int, ...]
    reason: str = "terminal_return_shared_epilogue"


@dataclass(frozen=True)
class PrivateTerminalSuffixGroup:
    """Clone a shared terminal suffix chain for multiple anchor blocks atomically.

    Each anchor gets its own private copy of the suffix chain. All clones are
    created in one pass to avoid serial drift from sequential STOP relocation.
    """

    anchors: tuple[int, ...]
    shared_entry_serial: int
    return_block_serial: int
    suffix_serials: tuple[int, ...]
    reason: str = "terminal_return_shared_epilogue"


class DirectTerminalLoweringKind(str, enum.Enum):
    """Kind of direct terminal lowering to apply per anchor."""
    RETURN_CONST = "return_const"
    RETURN_FROM_SLOT = "return_from_slot"
    RETURN_FROM_REG = "return_from_reg"
    CLONE_MATERIALIZER = "clone_materializer"


@dataclass(frozen=True)
class DirectTerminalLoweringSite:
    """Per-anchor lowering specification."""
    anchor_serial: int
    kind: DirectTerminalLoweringKind
    const_value: int | None = None
    source_stkoff: int | None = None
    source_mreg: int | None = None
    materializer_serials: tuple[int, ...] = ()


@dataclass(frozen=True)
class DirectTerminalLoweringGroup:
    """Grouped direct terminal lowering for multiple anchors sharing the same suffix."""
    shared_entry_serial: int
    return_block_serial: int
    suffix_serials: tuple[int, ...]
    sites: tuple[DirectTerminalLoweringSite, ...]
    reason: str = "terminal_return_direct_lowering"


# Union type for type discrimination via isinstance() or match statement
GraphModification = Union[
    RedirectGoto,
    RedirectBranch,
    ConvertToGoto,
    EdgeRedirectViaPredSplit,
    CreateConditionalRedirect,
    DuplicateBlock,
    InsertBlock,
    RemoveEdge,
    NopInstructions,
    PrivateTerminalSuffix,
    PrivateTerminalSuffixGroup,
    DirectTerminalLoweringGroup,
]


__all__ = [
    "RedirectGoto",
    "RedirectBranch",
    "ConvertToGoto",
    "EdgeRedirectViaPredSplit",
    "CreateConditionalRedirect",
    "DuplicateBlock",
    "InsertBlock",
    "RemoveEdge",
    "NopInstructions",
    "PrivateTerminalSuffix",
    "PrivateTerminalSuffixGroup",
    "DirectTerminalLoweringKind",
    "DirectTerminalLoweringSite",
    "DirectTerminalLoweringGroup",
    "GraphModification",
]
