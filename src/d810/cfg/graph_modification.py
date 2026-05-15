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
- DuplicateAndRedirect -> (multi-pred duplication, maps to N x BLOCK_DUPLICATE_AND_REDIRECT)
- CloneConditionalAsGoto -> CLONE_CONDITIONAL_AS_GOTO
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
import os
import sys
from dataclasses import dataclass
from d810.core.typing import Union

from d810.core import logging

# Import InsnSnapshot from Phase 3 (FlowGraph layer)
from d810.cfg.flowgraph import InsnSnapshot
from d810.cfg.materialization_payload import CapturedBlockBody


# Construction tracer for graph mods. When
# ``D810_TRACE_REDIRECT_GOTO_CONSTRUCTION=1`` is set, every
# ``RedirectGoto(...)`` construction logs its args + the caller frame.
# Helps locate which of the ~20 direct-construction sites emitted a
# specific mod when a Mode 1 bug surfaces. Off by default because
# every RedirectGoto goes through this — the log volume is only
# manageable for targeted investigations.
_redirect_goto_tracer = logging.getLogger(
    "D810.cfg.graph_modification.redirect_goto_trace", logging.DEBUG
)
_TRACE_REDIRECT_GOTO = (
    os.environ.get("D810_TRACE_REDIRECT_GOTO_CONSTRUCTION", "").strip() == "1"
)
# Unified knob that turns on construction traces for every graph-mod type
# (RedirectGoto, RedirectBranch, DuplicateAndRedirect, ZeroStateWrite).
# ``D810_TRACE_REDIRECT_GOTO_CONSTRUCTION=1`` is an alias for backwards
# compat; new callers should use ``D810_TRACE_MOD_CONSTRUCTION=1``.
_TRACE_MOD_CONSTRUCTION = (
    _TRACE_REDIRECT_GOTO
    or os.environ.get("D810_TRACE_MOD_CONSTRUCTION", "").strip() == "1"
)


def _construction_caller() -> str:
    """Walk past ``_construction_caller`` + ``__post_init__`` +
    dataclass-generated ``__init__`` (filename ``<string>``) to find the
    first user frame. Returns ``"filename:func:line"`` or ``"<unknown>"``
    if the stack is shallower than expected.

    Depth model when called from ``__post_init__``:
      0: _construction_caller (this function)
      1: __post_init__ (graph_modification.py)
      2: <string> (dataclass-generated __init__)
      3: user caller site
    """
    # Start at depth=2 to skip both our helper and __post_init__.
    depth = 2
    try:
        frame = sys._getframe(depth)
    except ValueError:
        return "<unknown>"
    # Skip any number of consecutive <string> frames (dataclass internals).
    while frame is not None and frame.f_code.co_filename == "<string>":
        depth += 1
        try:
            frame = sys._getframe(depth)
        except ValueError:
            return "<unknown>"
    if frame is None:
        return "<unknown>"
    return (
        f"{frame.f_code.co_filename.rsplit('/', 1)[-1]}:"
        f"{frame.f_code.co_name}:{frame.f_lineno}"
    )


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

    def __post_init__(self) -> None:
        if not _TRACE_MOD_CONSTRUCTION:
            return
        _redirect_goto_tracer.info(
            "REDIRECT_GOTO_CONSTRUCTED from_serial=%s old=%s new=%s caller=%s",
            self.from_serial, self.old_target, self.new_target,
            _construction_caller(),
        )


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

    def __post_init__(self) -> None:
        if not _TRACE_MOD_CONSTRUCTION:
            return
        _redirect_goto_tracer.info(
            "REDIRECT_BRANCH_CONSTRUCTED from_serial=%s old=%s new=%s caller=%s",
            self.from_serial, self.old_target, self.new_target,
            _construction_caller(),
        )


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
        clone_until: Optional final block in a strict 1-way corridor clone.
            When set, the backend clones the corridor ``src_block .. clone_until``
            and retargets the final clone to ``new_target``.
        rule_priority: Rule priority for conflict resolution.
    """

    src_block: int
    old_target: int
    new_target: int
    via_pred: int
    clone_until: int | None = None
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
    instructions: tuple[InsnSnapshot, ...] = ()


@dataclass(frozen=True)
class DuplicateBlock:
    """Request duplication of a block and predecessor redirect.

    The duplicate keeps the source instructions and is wired to the redirected
    predecessor. For 1-way sources, ``target_block`` optionally overrides the
    clone successor. For 2-way conditional sources, leave ``target_block`` as
    ``None`` and optionally provide explicit ``conditional_target`` and
    ``fallthrough_target`` to retarget the cloned conditional shape.
    """

    source_block: int
    target_block: int | None
    pred_serial: int | None = None
    patch_kind: str = ""
    conditional_target: int | None = None
    fallthrough_target: int | None = None


@dataclass(frozen=True)
class CloneConditionalAsGoto:
    """Clone a 2-way conditional block as a 1-way goto for one predecessor.

    This models the legacy FixPredecessor apply shape exactly:

    1. clone ``source_block``
    2. clear inherited clone predecessors
    3. convert the clone to a goto targeting ``goto_target``
    4. redirect ``pred_serial`` from ``source_block`` to the clone

    It is intentionally distinct from ``RedirectGoto`` and ``DuplicateBlock``.
    The source conditional block remains conditional, while only the selected
    predecessor is redirected through the clone.
    """

    source_block: int
    pred_serial: int
    goto_target: int
    reason: str = "fix_predecessor_clone_as_goto"


@dataclass(frozen=True)
class InsertBlock:
    """Insert a new block between pred and succ with given instructions.

    Maps to DeferredGraphModifier's BLOCK_CREATE_WITH_REDIRECT.
    Creates a new intermediate block containing either legacy instruction
    snapshots or a backend-owned captured body
    and redirects pred -> new_block -> succ. By default, the existing edge
    being replaced is assumed to be ``pred -> succ``; callers may override
    that with ``old_target_serial`` when the new block should redirect a
    predecessor away from a different current successor.

    Attributes:
        pred_serial: Predecessor block serial (edge source).
        succ_serial: Final successor block serial for the inserted block.
        instructions: Legacy tuple of instruction snapshots to place in new block.
        captured_body: Opaque backend-owned body to place in the new block.
        old_target_serial: Existing successor edge being replaced. When unset,
            defaults to ``succ_serial``.

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
    instructions: tuple[InsnSnapshot, ...] = ()
    old_target_serial: int | None = None
    captured_body: CapturedBlockBody | None = None


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
class ZeroStateWrite:
    """Zero the source operand of a state variable write instruction.

    Instead of NOPing a ``m_mov #CONST, state_var`` instruction, replaces
    the source constant with ``#0``.  This kills the entry-state constant's
    liveness so IDA cannot propagate the stale value (e.g. to a ``return``).

    Attributes:
        block_serial: Block containing the instruction.
        insn_ea: Effective address of the ``m_mov`` instruction to zero.

    Example:
        >>> mod = ZeroStateWrite(block_serial=10, insn_ea=0x1000)
        >>> mod.block_serial
        10
    """
    block_serial: int
    insn_ea: int

    def __post_init__(self) -> None:
        if not _TRACE_MOD_CONSTRUCTION:
            return
        _redirect_goto_tracer.info(
            "ZERO_STATE_WRITE_CONSTRUCTED block=%s insn_ea=0x%x caller=%s",
            self.block_serial, self.insn_ea, _construction_caller(),
        )


@dataclass(frozen=True)
class PromoteOperandToScalar:
    """Promote a fused sub-instruction operand (mop_d) into its own
    standalone microcode instruction with a fresh scalar destination.

    LLVM-style mem2reg analog: extracts an embedded compute (e.g. the
    ``m_ldx`` carried inside an ``m_add``'s ``l`` operand) and binds
    its result to a fresh kreg so downstream passes see an explicit
    def-use chain. Used to defeat IDA's MMAT_LVARS DCE on fused
    load-add-store induction patterns where the load only appears as
    a sub-operand and gets eliminated.

    Maps to DeferredGraphModifier's INSN_PROMOTE_OPERAND_TO_SCALAR.

    Attributes:
        block_serial: Block containing the host instruction.
        host_ea: Effective address of the host instruction (the
            instruction whose operand will be hoisted).
        host_opcode: Microcode opcode of the host (m_add, m_sub, etc.) —
            used to disambiguate when multiple insns share an EA.
        operand_side: Which operand to promote: ``"l"`` or ``"r"``.

    Example:
        >>> mod = PromoteOperandToScalar(
        ...     block_serial=23, host_ea=0x180013d08, host_opcode=0x21,
        ...     operand_side="l",
        ... )
        >>> mod.operand_side
        'l'
    """
    block_serial: int
    host_ea: int
    host_opcode: int
    operand_side: str


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


@dataclass(frozen=True)
class ReorderBlocks:
    """Copy handler blocks to end of MBA in DFS order, then remap all serial
    references. Originals become isolated (no incoming edges) so IDA DCE
    removes them.

    dfs_block_order: tuple of block serials in desired output order (DFS traversal
    of handlers from entry state). Applied AFTER all other modifications in the same
    PlanFragment so goto redirects are visible in the remapping.

    non_2way_serials: subset of dfs_block_order excluding BLT_2WAY blocks.
    Pre-computed by the strategy (which has snapshot/mba access) so that downstream
    consumers (projector, edit simulator) know which blocks will actually be copied
    by the backend (Phase A skips BLT_2WAY).
    """
    dfs_block_order: tuple[int, ...]
    non_2way_serials: tuple[int, ...] = ()
    two_way_serials: tuple[int, ...] = ()   # handler-internal BLT_2WAY blocks to copy with trampoline


@dataclass(frozen=True)
class DuplicateAndRedirect:
    """Duplicate a shared block and redirect each predecessor to its copy.

    Used when a block has multiple predecessors that each need different
    redirect targets (e.g., multi-pred dispatcher exit blocks where each
    incoming path writes a different state value).

    The block is duplicated once per (pred_serial, target) pair. Each
    copy is redirected to its own target. The original block keeps the
    first predecessor.

    Attributes:
        source_serial: Block to duplicate.
        per_pred_targets: Ordered pairs of (pred_serial, target_serial).
            The first entry keeps the original block; subsequent entries
            get freshly duplicated copies.

    Example:
        >>> mod = DuplicateAndRedirect(
        ...     source_serial=42,
        ...     per_pred_targets=((10, 50), (20, 60)),
        ... )
        >>> mod.source_serial
        42
        >>> len(mod.per_pred_targets)
        2
    """
    source_serial: int
    per_pred_targets: tuple[tuple[int, int], ...]

    def __post_init__(self) -> None:
        if not _TRACE_MOD_CONSTRUCTION:
            return
        _redirect_goto_tracer.info(
            "DUPLICATE_AND_REDIRECT_CONSTRUCTED src=%s per_pred_targets=%s caller=%s",
            self.source_serial,
            list(self.per_pred_targets),
            _construction_caller(),
        )


@dataclass(frozen=True)
class PhaseCycleLowering:
    """Lower a resolved dispatcher phase as an explicit loop-shaped cluster.

    This primitive captures a loop phase that must remain recognizable as a
    header/body/latch subgraph rather than being lowered as independent
    edge-local inserts. It is intended for dispatcher phases where:

    - one role acts as the phase header/check,
    - one role acts as the body/latch update,
    - exits must flow into a single next phase,
    - the body carries an explicit backedge to the header.

    The current backend does not materialize this primitive yet. It exists to
    pin the missing contract at the graph-modification layer before production
    integration.
    """

    header_entries: tuple[int, ...]
    header_target: int
    body_entries: tuple[int, ...]
    body_target: int
    next_phase_entries: tuple[int, ...]
    next_phase_target: int
    terminal_entries: tuple[int, ...] = ()
    terminal_target: int | None = None
    state_roles: tuple[tuple[str, int], ...] = ()
    reason: str = "dispatcher_phase_cycle"


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
    CloneConditionalAsGoto,
    DuplicateAndRedirect,
    PhaseCycleLowering,
    InsertBlock,
    RemoveEdge,
    NopInstructions,
    ZeroStateWrite,
    PromoteOperandToScalar,
    PrivateTerminalSuffix,
    PrivateTerminalSuffixGroup,
    DirectTerminalLoweringGroup,
    ReorderBlocks,
]


__all__ = [
    "RedirectGoto",
    "RedirectBranch",
    "ConvertToGoto",
    "EdgeRedirectViaPredSplit",
    "CreateConditionalRedirect",
    "DuplicateBlock",
    "CloneConditionalAsGoto",
    "DuplicateAndRedirect",
    "PhaseCycleLowering",
    "InsertBlock",
    "RemoveEdge",
    "NopInstructions",
    "ZeroStateWrite",
    "PromoteOperandToScalar",
    "PrivateTerminalSuffix",
    "PrivateTerminalSuffixGroup",
    "DirectTerminalLoweringKind",
    "DirectTerminalLoweringSite",
    "DirectTerminalLoweringGroup",
    "ReorderBlocks",
    "GraphModification",
]
